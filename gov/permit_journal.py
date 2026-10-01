"""Event-sourced durable permit journal: HMAC-chained, append-only.

Wave-250 lane 3. Stdlib only.

Temporal-pattern ADAPT (temporalio/temporal, MIT -- a pattern
adaptation only, never Temporal's code or server): permits are
event-sourced. The permit lifecycle is an append-only event log --
``PERMIT_GRANTED``, ``PERMIT_USED``, ``PERMIT_EXPIRED``,
``PERMIT_REVOKED``, ``PERMIT_FINALIZED`` -- and the current state of
any permit is the replay of its events. The journal persists to a
JSONL file, so permit state survives process restarts with its full
history instead of riding the deployment's memory.

Two integrity layers, two threat models (documented honestly):

1. **Reliability layer** -- ``gov.durable_journal.Journal``: the
   POSIX-fcntl single-writer discipline, atomic fsync'd appends,
   torn-tail detection, and hash-bound snapshots/compaction. This is
   Temporal's threat model: crash safety, not adversaries.
2. **Adversarial layer** -- every permit event carries an
   HMAC-SHA256 MAC over its canonical bytes chained to the previous
   event's MAC (event N's MAC covers event N-1's MAC). Replay
   integrity rides the HMAC key, verified on every load; any
   mismatch fails closed. This is OUR threat model: the journal
   file is attacker-reachable storage.

Key ownership: the HMAC key is deployment-owned. Constructor
resolution order: explicit ``key`` kwarg > ``GOV_PERMIT_JOURNAL_KEY``
(hex) env > a fresh random 32-byte key. Durability ACROSS RESTARTS
requires the deployment to supply a STABLE key (kwarg or env); the
random-key fallback is for tests and single-process use only --
reopening with a different key fails closed
(``permit-journal-chain-broken``), which is the integrity property
working as designed. HMAC gives shared-secret authenticity, NOT
non-repudiation: anyone holding the key can forge events, so the
key's custody is the trust root (see the standing honest residual).

Compaction trust: :meth:`PermitJournal.take_snapshot` folds the
replayed permit states into a sidecar bound by a keyed snapshot MAC
over (journal tip, folded states, last event MAC); :meth:`compact`
rewrites the journal through the durable layer, whose
``SnapshotLoaded`` anchor binds the sidecar bytes. The snapshot MAC
proves a KEY HOLDER made the snapshot at the claimed tip; it does
NOT prove the fold is complete -- completeness is enforced by the
code path (the fold comes from the verified in-memory replay), and
an auditor re-verifies by replaying the archived pre-compaction
journal against the bound tip. Archive pre-compaction files; do
not delete them if you need that proof.

Timestamps: each event carries ``issued_at`` (ISO-8601 UTC wall
clock, human-readable) and ``mono_ns`` (``time.monotonic_ns()``).
Both are MAC'd. Ordering authority is the journal sequence number;
``mono_ns`` is only comparable within a single boot and is a
diagnostic, never an ordering claim.

Honest residual: clean prefix truncation (deleting whole trailing
records) is undetectable by hash chaining alone -- only torn tails
are detected. The snapshot's bound tip is the rollback detector
after a snapshot; before any snapshot, prefix truncation is
silent. Size the threat model accordingly.
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from . import durable_journal as _dj

__all__ = [
    "PermitJournal",
    "PermitJournalError",
    "PermitJournalCorrupted",
    "PermitJournalRefusal",
    "event_mac",
    "PERMIT_GRANTED",
    "PERMIT_USED",
    "PERMIT_EXPIRED",
    "PERMIT_REVOKED",
    "PERMIT_FINALIZED",
    "CHAIN_BROKEN_CODE",
    "CORRUPTED_CODE",
    "DUPLICATE_EVENT_CODE",
    "KEY_WEAK_CODE",
    "MISUSE_CODE",
    "SNAPSHOT_TAMPERED_CODE",
    "TRANSITION_ILLEGAL_CODE",
    "UNKNOWN_PERMIT_CODE",
    "WRITE_CONFLICT_CODE",
]

# ---------------------------------------------------------------------------
# Event vocabulary
# ---------------------------------------------------------------------------

PERMIT_GRANTED = "PERMIT_GRANTED"
PERMIT_USED = "PERMIT_USED"
PERMIT_EXPIRED = "PERMIT_EXPIRED"
PERMIT_REVOKED = "PERMIT_REVOKED"
PERMIT_FINALIZED = "PERMIT_FINALIZED"

_PERMIT_EVENT_TYPES = (
    PERMIT_GRANTED, PERMIT_USED, PERMIT_EXPIRED,
    PERMIT_REVOKED, PERMIT_FINALIZED,
)

_TERMINAL_EVENTS = (PERMIT_EXPIRED, PERMIT_REVOKED, PERMIT_FINALIZED)
_TERMINAL_STATES = ("expired", "revoked", "finalized")
_NON_TERMINAL_STATES = ("granted", "used")

# Machine decision codes emitted by this module (also registered in
# gov/decision_codes.py under domain "permit-journal").
CHAIN_BROKEN_CODE = "permit-journal-chain-broken"
CORRUPTED_CODE = "permit-journal-corrupted"
DUPLICATE_EVENT_CODE = "permit-journal-duplicate-event"
KEY_WEAK_CODE = "permit-journal-key-weak"
MISUSE_CODE = "permit-journal-misuse"
SNAPSHOT_TAMPERED_CODE = "permit-journal-snapshot-tampered"
TRANSITION_ILLEGAL_CODE = "permit-journal-transition-illegal"
UNKNOWN_PERMIT_CODE = "permit-journal-unknown-permit"
WRITE_CONFLICT_CODE = "permit-journal-write-conflict"

_KEY_ENV = "GOV_PERMIT_JOURNAL_KEY"
_KEY_MIN_BYTES = 16
_GENESIS_DOMAIN = b"PERMIT_JOURNAL:GENESIS:v1"

_EVENT_FIELDS = ("permit_id", "event_id", "event_type", "issued_at",
                 "mono_ns", "payload", "prev_mac", "mac")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PermitJournalError(Exception):
    """Base class for all permit-journal refusals. Carries ``code``."""

    code = MISUSE_CODE

    def __init__(self, code, detail):
        super(PermitJournalError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class PermitJournalCorrupted(PermitJournalError):
    """The journal failed integrity verification. Fail closed."""


class PermitJournalRefusal(PermitJournalError):
    """A write or query was refused (fail-closed, never guessed)."""


# ---------------------------------------------------------------------------
# Canonical bytes + MACs
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _genesis_mac(key):
    """The MAC that anchors the chain: key-bound, not a constant."""
    return hmac.new(key, _GENESIS_DOMAIN, hashlib.sha256).hexdigest()


def event_mac(key, permit_id, event_id, event_type, issued_at,
              mono_ns, payload, prev_mac):
    """Compute the HMAC-SHA256 for one permit event.

    The MAC binds the full canonical event bytes to ``prev_mac`` --
    the MAC of the previous permit event (or the key-bound genesis
    MAC for the first event). Deterministic: identical inputs give
    identical MACs.
    """
    return hmac.new(
        key,
        _canonical({"permit_id": permit_id, "event_id": event_id,
                    "event_type": event_type, "issued_at": issued_at,
                    "mono_ns": mono_ns, "payload": payload,
                    "prev_mac": prev_mac}),
        hashlib.sha256).hexdigest()


def _snapshot_mac(key, journal_tip, states, last_mac):
    """The keyed MAC binding a snapshot fold to the journal tip."""
    return hmac.new(
        key,
        _canonical({"journal_tip": journal_tip, "states": states,
                    "last_mac": last_mac}),
        hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------

def _resolve_key(key):
    if key is None:
        env = os.environ.get(_KEY_ENV)
        if env:
            try:
                key = bytes.fromhex(env.strip())
            except ValueError:
                raise PermitJournalRefusal(
                    KEY_WEAK_CODE,
                    "%s is not valid hex" % _KEY_ENV)
        else:
            # Single-process/tests fallback. Documented: NOT durable
            # across restarts unless the deployment re-supplies it.
            key = secrets.token_bytes(32)
    if not isinstance(key, (bytes, bytearray)) or len(key) < _KEY_MIN_BYTES:
        raise PermitJournalRefusal(
            KEY_WEAK_CODE,
            "key must be bytes of at least %d bytes" % _KEY_MIN_BYTES)
    return bytes(key)


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------

class PermitJournal:
    """An event-sourced, HMAC-chained, durable permit journal."""

    def __init__(self, path, key=None):
        self._path = os.path.abspath(path)
        self._key = _resolve_key(key)
        try:
            self._journal = _dj.Journal(self._path)
        except _dj.JournalCorrupted as exc:
            raise PermitJournalCorrupted(
                CORRUPTED_CODE,
                "underlying journal failed verification: %s" % exc)
        self._states = {}
        self._event_ids = set()
        self._running_mac = _genesis_mac(self._key)
        self._snapshot_last_mac = None
        self._rebuild()

    # ------------------------------------------------------------------
    # loading / verification
    # ------------------------------------------------------------------

    def _reload(self):
        """Re-verify the whole journal and rebuild state. Fail-closed."""
        try:
            self._journal = _dj.Journal(self._path)
        except _dj.JournalCorrupted as exc:
            raise PermitJournalCorrupted(
                CORRUPTED_CODE,
                "underlying journal failed verification: %s" % exc)
        self._states = {}
        self._event_ids = set()
        self._running_mac = _genesis_mac(self._key)
        self._snapshot_last_mac = None
        self._rebuild()

    def _rebuild(self):
        records = self._journal.records
        idx = 0
        if records and records[0].get("type") == "SnapshotLoaded":
            self._load_snapshot(records[0])
            idx = 1
        for rec in records[idx:]:
            if rec.get("type") in _PERMIT_EVENT_TYPES:
                self._verify_and_fold(rec)
            # System records (SnapshotTaken / SnapshotLoaded) are
            # sha256-verified by the durable layer; they carry no
            # permit-event MAC and are skipped by the HMAC chain.

    def _load_snapshot(self, anchor_rec):
        """Restore folded state from a verified snapshot sidecar."""
        body = anchor_rec.get("body") or {}
        sidecar = os.path.join(os.path.dirname(self._path),
                               body.get("snapshot_path", ""))
        try:
            with open(sidecar, "rb") as f:
                stored = json.loads(f.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise PermitJournalCorrupted(
                CORRUPTED_CODE,
                "snapshot sidecar unreadable: %s" % exc)
        snap_body = stored.get("body") or {}
        if snap_body.get("permit_journal") is not True:
            raise PermitJournalRefusal(
                MISUSE_CODE,
                "snapshot sidecar is not a permit-journal snapshot")
        for field in ("states", "last_mac", "snapshot_mac"):
            if field not in snap_body:
                raise PermitJournalCorrupted(
                    SNAPSHOT_TAMPERED_CODE,
                    "snapshot body missing %r" % field)
        expect = _snapshot_mac(self._key, stored.get("journal_tip"),
                               snap_body["states"], snap_body["last_mac"])
        if not hmac.compare_digest(snap_body["snapshot_mac"], expect):
            raise PermitJournalCorrupted(
                SNAPSHOT_TAMPERED_CODE,
                "snapshot MAC mismatch: the folded snapshot was not "
                "made by a key holder at the claimed tip")
        for pid, st in snap_body["states"].items():
            self._states[pid] = copy.deepcopy(st)
            self._event_ids.update(st.get("event_ids", []))
        self._snapshot_last_mac = snap_body["last_mac"]
        self._running_mac = snap_body["last_mac"]

    def _verify_and_fold(self, rec):
        body = rec.get("body")
        if not isinstance(body, dict):
            raise PermitJournalCorrupted(
                CHAIN_BROKEN_CODE, "permit event body is not a dict")
        for field in _EVENT_FIELDS:
            if field not in body:
                raise PermitJournalCorrupted(
                    CHAIN_BROKEN_CODE,
                    "permit event missing field %r" % field)
        if body["event_type"] != rec.get("type"):
            raise PermitJournalCorrupted(
                CHAIN_BROKEN_CODE,
                "event_type %r disagrees with record type %r" % (
                    body["event_type"], rec.get("type")))
        if not isinstance(body["payload"], dict):
            raise PermitJournalCorrupted(
                CHAIN_BROKEN_CODE, "permit event payload is not a dict")
        if body["event_id"] in self._event_ids:
            raise PermitJournalCorrupted(
                CHAIN_BROKEN_CODE,
                "duplicate event_id %r in the journal (replay?)"
                % (body["event_id"],))
        expect = event_mac(
            self._key, body["permit_id"], body["event_id"],
            body["event_type"], body["issued_at"], body["mono_ns"],
            body["payload"], self._running_mac)
        if body["prev_mac"] != self._running_mac or \
                not hmac.compare_digest(str(body["mac"]), expect):
            raise PermitJournalCorrupted(
                CHAIN_BROKEN_CODE,
                "HMAC chain break at event %r (permit %r): not made "
                "by a key holder or tampered after write" % (
                    body["event_id"], body["permit_id"]))
        self._event_ids.add(body["event_id"])
        self._fold_state(body)
        self._running_mac = str(body["mac"])

    def _fold_state(self, body):
        pid = body["permit_id"]
        etype = body["event_type"]
        st = self._states.get(pid)
        if st is None:
            st = {"state": "unknown", "granted": None,
                  "terminal": None, "terminal_event": None,
                  "uses": [], "event_ids": [], "n_events": 0}
            self._states[pid] = st
        st["event_ids"].append(body["event_id"])
        st["n_events"] += 1
        if etype == PERMIT_GRANTED:
            st["state"] = "granted"
            st["granted"] = {"payload": copy.deepcopy(body["payload"]),
                             "event_id": body["event_id"],
                             "issued_at": body["issued_at"]}
        elif etype == PERMIT_USED:
            st["state"] = "used"
            st["uses"].append({"payload": copy.deepcopy(body["payload"]),
                               "event_id": body["event_id"],
                               "issued_at": body["issued_at"]})
        else:  # terminal events
            st["state"] = {"PERMIT_EXPIRED": "expired",
                           "PERMIT_REVOKED": "revoked",
                           "PERMIT_FINALIZED": "finalized"}[etype]
            st["terminal"] = etype
            st["terminal_event"] = {
                "payload": copy.deepcopy(body["payload"]),
                "event_id": body["event_id"],
                "issued_at": body["issued_at"]}

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    def permit_state(self, permit_id):
        """Replay to the current state of ``permit_id``.

        Returns a copy: {"permit_id", "state", "granted", "terminal",
        "terminal_event", "uses", "event_ids", "n_events"}. Unknown
        permits report state "unknown" -- a query, never a refusal.
        """
        st = self._states.get(permit_id)
        if st is None:
            return {"permit_id": permit_id, "state": "unknown",
                    "granted": None, "terminal": None,
                    "terminal_event": None, "uses": [],
                    "event_ids": [], "n_events": 0}
        out = copy.deepcopy(st)
        out["permit_id"] = permit_id
        return out

    def permit_ids(self):
        """All permit ids seen in the journal, sorted."""
        return sorted(self._states)

    # ------------------------------------------------------------------
    # appending
    # ------------------------------------------------------------------

    def _check_transition(self, permit_id, event_type):
        st = self._states.get(permit_id)
        if event_type == PERMIT_GRANTED:
            if st is not None:
                raise PermitJournalRefusal(
                    TRANSITION_ILLEGAL_CODE,
                    "permit %r already has %d event(s); refusing "
                    "second grant" % (permit_id, st["n_events"]))
            return
        if st is None:
            raise PermitJournalRefusal(
                UNKNOWN_PERMIT_CODE,
                "no grant recorded for permit %r" % (permit_id,))
        if st["state"] in _TERMINAL_STATES:
            raise PermitJournalRefusal(
                TRANSITION_ILLEGAL_CODE,
                "permit %r is terminal (%s); refusing %s" % (
                    permit_id, st["state"], event_type))

    def _build_body(self, permit_id, event_type, payload, event_id,
                    issued_at):
        if not isinstance(permit_id, str) or not permit_id:
            raise PermitJournalRefusal(
                MISUSE_CODE, "permit_id must be a non-empty string")
        if not isinstance(payload, dict):
            raise PermitJournalRefusal(
                MISUSE_CODE, "payload must be a dict")
        if event_id is None:
            event_id = uuid.uuid4().hex
        if not isinstance(event_id, str) or not event_id:
            raise PermitJournalRefusal(
                MISUSE_CODE, "event_id must be a non-empty string")
        if issued_at is None:
            issued_at = datetime.now(timezone.utc).isoformat()
        if not isinstance(issued_at, str) or not issued_at:
            raise PermitJournalRefusal(
                MISUSE_CODE, "issued_at must be a non-empty string")
        body = {"permit_id": permit_id, "event_id": event_id,
                "event_type": event_type, "issued_at": issued_at,
                "mono_ns": time.monotonic_ns(), "payload": payload,
                "prev_mac": self._running_mac}
        try:
            body["mac"] = event_mac(
                self._key, permit_id, event_id, event_type, issued_at,
                body["mono_ns"], payload, self._running_mac)
        except (TypeError, ValueError) as exc:
            # F214: payload serialization is caller misuse, not a
            # bypass -- refuse with the machine-code contract instead
            # of letting a raw TypeError escape the public seam.
            raise PermitJournalRefusal(
                MISUSE_CODE,
                "payload is not JSON-serializable: %s" % (exc,))
        return body

    def _append(self, permit_id, event_type, payload, event_id=None,
                issued_at=None):
        self._check_transition(permit_id, event_type)
        if event_id is not None and event_id in self._event_ids:
            raise PermitJournalRefusal(
                DUPLICATE_EVENT_CODE,
                "event_id %r already recorded" % (event_id,))
        for _ in range(3):
            body = self._build_body(permit_id, event_type, payload,
                                    event_id, issued_at)
            if body["event_id"] in self._event_ids:
                raise PermitJournalRefusal(
                    DUPLICATE_EVENT_CODE,
                    "event_id %r already recorded"
                    % (body["event_id"],))
            tip = self._journal.tip

            def _tip_unchanged(records, _tip=tip):
                current = records[-1]["hash"] if records \
                    else _dj.GENESIS
                return current == _tip

            appended, _ = self._journal.append_if(
                [(event_type, body)], _tip_unchanged)
            if appended:
                self._event_ids.add(body["event_id"])
                self._fold_state(body)
                self._running_mac = body["mac"]
                return dict(body)
            # Another writer won the race: re-verify, rebuild, and
            # re-validate the transition against the new tail.
            self._reload()
            self._check_transition(permit_id, event_type)
        raise PermitJournalRefusal(
            WRITE_CONFLICT_CODE,
            "could not append %s for permit %r after 3 attempts; "
            "another writer holds the journal" % (event_type, permit_id))

    def grant(self, permit_id, payload, event_id=None, issued_at=None):
        """Record PERMIT_GRANTED. Refuses a second grant."""
        return self._append(permit_id, PERMIT_GRANTED, payload,
                            event_id, issued_at)

    def record_use(self, permit_id, payload, event_id=None,
                   issued_at=None):
        """Record PERMIT_USED. Refuses unknown or terminal permits."""
        return self._append(permit_id, PERMIT_USED, payload,
                            event_id, issued_at)

    def expire(self, permit_id, reason, event_id=None, issued_at=None):
        """Record PERMIT_EXPIRED (terminal)."""
        return self._append(permit_id, PERMIT_EXPIRED,
                            {"reason": reason}, event_id, issued_at)

    def revoke(self, permit_id, reason, revoked_by=None, event_id=None,
               issued_at=None):
        """Record PERMIT_REVOKED (terminal)."""
        payload = {"reason": reason}
        if revoked_by is not None:
            payload["revoked_by"] = revoked_by
        return self._append(permit_id, PERMIT_REVOKED, payload,
                            event_id, issued_at)

    def finalize(self, permit_id, receipt_digest, event_id=None,
                 issued_at=None):
        """Record PERMIT_FINALIZED (terminal)."""
        return self._append(
            permit_id, PERMIT_FINALIZED,
            {"receipt_digest": receipt_digest}, event_id, issued_at)

    # ------------------------------------------------------------------
    # snapshots / compaction
    # ------------------------------------------------------------------

    def _folded_states(self):
        out = {}
        for pid in sorted(self._states):
            st = self._states[pid]
            out[pid] = {
                "state": st["state"],
                "granted": copy.deepcopy(st["granted"]),
                "terminal": st["terminal"],
                "terminal_event": copy.deepcopy(st["terminal_event"]),
                "uses": copy.deepcopy(st["uses"]),
                "event_ids": sorted(st["event_ids"]),
                "n_events": st["n_events"],
            }
        return out

    def take_snapshot(self):
        """Fold the replayed states into a keyed snapshot sidecar.

        The sidecar binds (journal tip, folded states, last event
        MAC) under the snapshot MAC -- the "signature" on the
        snapshot record. Returns the durable layer's snapshot ref
        (with ``snapshot_path``). Operator-invoked; archive the
        pre-compaction journal if auditors must re-verify the fold.
        """
        states = self._folded_states()
        tip = self._journal.tip
        last_mac = self._running_mac
        body = {"permit_journal": True,
                "states": states,
                "last_mac": last_mac,
                "snapshot_mac": _snapshot_mac(self._key, tip, states,
                                              last_mac)}
        return self._journal.take_snapshot(body)

    def compact(self):
        """Snapshot, then rewrite keeping only post-snapshot records.

        Requires :meth:`take_snapshot` first (the durable layer
        raises otherwise). The HMAC chain continues across the
        snapshot boundary: the first kept event's ``prev_mac`` is
        checked against the snapshot's bound ``last_mac``.
        """
        self._journal.compact()
        self._reload()
