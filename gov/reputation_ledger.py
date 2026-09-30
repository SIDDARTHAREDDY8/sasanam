"""Deterministic, ledger-recomputable agent reputation (Wave-246 lane 7).

ADAPTED (patterns only) from the Kredent shape: reputation as a pure
function of a signed, hash-chained ledger -- anyone holding the ledger
can recompute any agent's score, with no hidden state.

Model
-----
* Subjects and reporters are identified by did:key identifiers
  (gov/agent_identity.py -- self-sovereign, key-derived).
* A reputation event is signed by its REPORTER's Ed25519 key; the
  ledger verifies the signature against the key resolved from the
  reporter's did:key id before appending. A reporter cannot speak for
  another reporter's key (reporter/key mismatch is refused).
* Entries form a hash chain: entry N commits to the digest of entry
  N-1 (genesis commits to a fixed genesis digest). Reordering,
  deletion, or silent modification breaks the chain on recompute.
* ``compute_reputation(entries, subject_did)`` is the pure scoring
  function: a fixed per-kind weight table, summed and clamped to
  [-100, 100]. ``ReputationLedger.reputation_for`` delegates to it, so
  "claimed" and "recomputed" are the same code path.

Event kinds (fixed weights):
    attestation-positive   +1
    attestation-negative   -2
    incident-confirmed     -5
    recovery-verified      +3
    checkpoint              0   (anchor / no-op, keeps the chain alive)

Fail-closed: malformed entries raise ReputationLedgerError (never an
accept); import_bytes re-validates the WHOLE chain including every
signature, so a tampered export is refused with
``reputation-ledger-tampered``.

HONEST RESIDUALS (never claimed away):
* Sybil: one operator can mint many did:key ids and self-vouch. The
  ledger makes vouching VISIBLE and recomputable; it does not make it
  scarce. Weighting reporters by stake/tenure is a deployment policy
  on top of this primitive, not part of it.
* The ledger is in-memory and single-writer here; durability and
  multi-writer consensus are deployment-owned (same boundary as the
  audit log's local store).
* "incident-confirmed" means a signed claim that an incident was
  confirmed, not proof the incident happened -- signed records prove
  signed claims.

$0 spend, synthetic/local only. Stdlib only. No network.
"""

import hashlib
import json

from . import agent_identity as _ai
from . import ed25519 as _ed

_GENESIS_DIGEST = hashlib.sha256(
    b"gov-reputation-ledger/v1\x00genesis").hexdigest()

_WEIGHTS = {
    "attestation-positive": 1,
    "attestation-negative": -2,
    "incident-confirmed": -5,
    "recovery-verified": 3,
    "checkpoint": 0,
}

_SCORE_MIN, _SCORE_MAX = -100, 100


class ReputationLedgerError(Exception):
    """Refused ledger operation. ``code`` is the taxonomy refusal code."""

    def __init__(self, code, detail=""):
        super(ReputationLedgerError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _canonical_bytes(obj):
    """Canonical JSON bytes. No default=str: non-JSON values are a
    malformed entry, never silently stringified."""
    try:
        return json.dumps(obj, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "entry is not JSON-canonical: %s" % exc)


def _event_digest(unsigned_event):
    """sha256 over the canonical unsigned event bytes."""
    return hashlib.sha256(_canonical_bytes(unsigned_event)).hexdigest()


def make_event(seq, subject_did, reporter_did, kind, detail, prev_digest):
    """Build an unsigned reputation event dict. Structural checks only;
    signature and chain checks happen at append/import."""
    return {
        "seq": seq,
        "subject": subject_did,
        "reporter": reporter_did,
        "kind": kind,
        "detail": detail,
        "prev": prev_digest,
    }


def sign_event(event, reporter_seed):
    """Sign an unsigned event with the reporter's 32-byte seed.

    Fail-closed: the seed's public key must resolve to the event's
    ``reporter`` did:key id, else ReputationLedgerError (the reporter
    cannot sign as someone else).
    """
    if not isinstance(reporter_seed, (bytes, bytearray)) \
            or len(reporter_seed) != 32:
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "reporter_seed must be 32 bytes")
    if not isinstance(event, dict) or "sig" in event:
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "event must be an unsigned dict")
    reporter = event.get("reporter")
    try:
        expected = _ai.resolve(_ed.publickey(bytes(reporter_seed)))
    except _ai.DidKeyError as exc:
        raise ReputationLedgerError("did-key-malformed",
                                    "reporter did: %s" % exc.detail)
    if reporter != expected:
        raise ReputationLedgerError(
            "did-key-binding-invalid",
            "seed does not match reporter did:key id")
    signed = dict(event)
    signed["sig"] = _ed.sign(bytes(reporter_seed),
                             _canonical_bytes(event)).hex()
    return signed


def _check_event_shape(event):
    if not isinstance(event, dict):
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "event must be a dict")
    for field in ("seq", "subject", "reporter", "kind", "detail",
                  "prev", "sig"):
        if field not in event:
            raise ReputationLedgerError("reputation-entry-malformed",
                                        "missing field %r" % (field,))
    if not isinstance(event["seq"], int) or event["seq"] < 0 \
            or isinstance(event["seq"], bool):
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "seq must be a non-negative int")
    if event["kind"] not in _WEIGHTS:
        raise ReputationLedgerError("reputation-event-kind-unknown",
                                    "unknown kind %r" % (event["kind"],))
    for id_field in ("subject", "reporter"):
        try:
            _ai.pubkey_from_did_key(event[id_field])
        except _ai.DidKeyError as exc:
            raise ReputationLedgerError(exc.code,
                                        "%s: %s" % (id_field, exc.detail))
    if not isinstance(event["prev"], str) or not isinstance(
            event["detail"], str):
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "prev/detail must be strings")
    try:
        sig = bytes.fromhex(event["sig"])
    except (ValueError, TypeError):
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "sig must be hex")
    if len(sig) != 64:
        raise ReputationLedgerError("reputation-entry-malformed",
                                    "sig must be 64 bytes")
    return sig


def _check_event_signature(event, sig):
    reporter_pub = _ai.pubkey_from_did_key(event["reporter"])
    unsigned = {k: v for k, v in event.items() if k != "sig"}
    if _ed.verify(reporter_pub, _canonical_bytes(unsigned), sig) is not True:
        raise ReputationLedgerError(
            "did-key-binding-invalid",
            "reporter signature does not verify")


def compute_reputation(entries, subject_did):
    """Pure scoring function: sum of fixed per-kind weights for the
    subject, clamped to [-100, 100]. No hidden state."""
    total = 0
    for event in entries:
        if not isinstance(event, dict):
            continue
        if event.get("subject") == subject_did:
            total += _WEIGHTS.get(event.get("kind"), 0)
    return max(_SCORE_MIN, min(_SCORE_MAX, total))


class ReputationLedger(object):
    """Append-only, hash-chained, signed reputation ledger."""

    def __init__(self):
        self._entries = []

    def entries(self):
        return [dict(e) for e in self._entries]

    def next_seq(self):
        return len(self._entries)

    def head_digest(self):
        if not self._entries:
            return _GENESIS_DIGEST
        return _event_digest(
            {k: v for k, v in self._entries[-1].items() if k != "sig"})

    def append(self, event):
        """Validate and append one signed event. Fail-closed."""
        sig = _check_event_shape(event)
        if event["seq"] != len(self._entries):
            raise ReputationLedgerError(
                "reputation-ledger-tampered",
                "seq %r does not extend head %d"
                % (event["seq"], len(self._entries)))
        if event["prev"] != self.head_digest():
            raise ReputationLedgerError(
                "reputation-ledger-tampered",
                "prev digest does not match head")
        _check_event_signature(event, sig)
        self._entries.append(dict(event))
        return self.head_digest()

    def reputation_for(self, subject_did):
        """Reputation is the pure function of the ledger -- claimed and
        recomputed are the same code path."""
        return compute_reputation(self._entries, subject_did)

    def export(self):
        """Canonical bytes of the full ledger (entries + head)."""
        return _canonical_bytes({"entries": self._entries,
                                 "head": self.head_digest()})

    @classmethod
    def import_bytes(cls, data):
        """Rebuild from exported bytes, re-validating the whole chain
        and every signature. Any tamper -> ReputationLedgerError."""
        if not isinstance(data, (bytes, bytearray)):
            raise ReputationLedgerError("reputation-entry-malformed",
                                        "import needs bytes")
        try:
            blob = json.loads(bytes(data).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReputationLedgerError("reputation-entry-malformed",
                                        "export is not JSON: %s" % exc)
        if not isinstance(blob, dict) or "entries" not in blob \
                or not isinstance(blob["entries"], list):
            raise ReputationLedgerError("reputation-entry-malformed",
                                        "export needs an entries list")
        ledger = cls()
        try:
            for event in blob["entries"]:
                ledger.append(event)
        except ReputationLedgerError as exc:
            # Any re-validation failure on import means the presented
            # ledger does not recompute: the ledger-level verdict is
            # tampered, with the specific failure preserved in detail.
            # (Direct append() still raises the specific code; import
            # is the whole-ledger verdict.)
            raise ReputationLedgerError(
                "reputation-ledger-tampered",
                "chain re-validation failed: %s" % exc.code)
        if "head" in blob and blob["head"] != ledger.head_digest():
            raise ReputationLedgerError("reputation-ledger-tampered",
                                        "exported head digest mismatch")
        return ledger
