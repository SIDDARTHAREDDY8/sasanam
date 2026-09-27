"""Cross-run intent ledger (wave-134, row-7 third half).

Row-7 residual: "no cross-run intent persistence." The attack shape:
run 1 grants an approval under one intent; run 2 records a user
countermand ("actually don't ever do that"); run 3 tries to consume
the still-valid grant. The wave-131 in-run re-validation cannot see
run 2's countermand because intent context is run-scoped.

This module persists intent verdicts (user messages -> intent labels)
per principal in a durable, tamper-evident, hash-chained ledger. At
the execution boundary the sweep consults the ledger: a countermand
recorded AFTER an approval's ``decided_at`` auto-revokes the grant
(revoker ``"intent-system"``) and the sweep refuses with
``approval_intent_changed`` -- the wave-131 in-run countermand path
extended across runs.

Public seams: ``IntentLedger``,
``IntentLedger.record_intent(principal, message, verdict, ts=None)``,
``IntentLedger.latest_countermands(principal, since)``,
``IntentLedger.messages_since(principal, since)``,
``IntentLedger.verify_chain()``, ``IntentLedger.save(path)``,
``IntentLedger.load(path)``.

Trust pattern adapted from ``gov/goals.py`` (not copied): header /
records / footer JSONL with a ``file_digest`` over the canonical
bytes, a ``chain_tip`` binding the file to the chain state, and a
per-record hash chain. Fail-closed: a damaged store is never silently
accepted as a clean history.

Countermand detection reuses the canonical detector
``gov.intent_slice._detect_countermand`` (same-package private reuse,
documented -- duplicating the redirect-signal rubric would risk
semantic drift, cf. gov/goal_audit.py's reuse of gov.goals._OPPOSES).
A record is a countermand when the stored verdict says so OR the
detector finds a redirect signal overlapping a prior turn of the same
principal.

Honest ceilings (documented, not hidden):
- The deterministic paraphrase-detection ceiling carries over
  cross-run: a paraphrased countermand the wave-129 judge cannot
  anchor executes (measured in evals/cross_run_intent_probes.py p5).
- Cross-run identity depends on a stable principal: a fresh
  principal per run defeats the ledger (same boundary as the drift
  lane's per-agent profiles).
- The ledger stores raw user message text locally. Like drift
  profiles, it is sensitive operational data: whoever holds the
  ledger file can read what the operator said. It never leaves the
  operator's store (no network, $0).
- The ledger records intent; it does not judge truth. A mistaken
  countermand revokes a legitimate approval -- the operator
  re-approves under the corrected intent.

$0 spend, stdlib only, deterministic.
"""

import hashlib
import json
from datetime import datetime, timezone

from .intent_slice import _detect_countermand

__all__ = [
    "IntentLedger",
    "IntentPersistenceError",
    "INTENT_LEDGER_VERSION",
]

INTENT_LEDGER_VERSION = "intent-ledger/1.0"

#: Verdict flags that mark a stored verdict as a countermand on their
#: own (the detector is the second, independent signal).
_COUNTERMAND_FLAGS = frozenset({"stale_intent", "countermand"})


class IntentPersistenceError(Exception):
    """Raised when the intent ledger cannot be saved or loaded."""


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_ts(ts):
    """Parse an ISO timestamp; None when unparseable (fail-safe)."""
    try:
        dt = datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _record_digest(record, prev_digest):
    body = {k: v for k, v in record.items() if k != "record_digest"}
    return _sha256_hex(_canonical(body) + prev_digest)


def _verdict_says_countermand(verdict):
    if not isinstance(verdict, dict):
        return False
    if verdict.get("countermand"):
        return True
    return verdict.get("flag") in _COUNTERMAND_FLAGS


class IntentLedger(object):
    """Durable per-principal intent ledger.

    ``audit`` is an optional callable taking one event dict; every
    recorded turn appends an ``intent_turn_recorded`` event (countermand
    turns are LOUD: ``intent_countermand_recorded``). When None, nothing
    is emitted -- the records are always inspectable on the object.
    """

    def __init__(self, audit=None):
        self._turns = []
        self._prev_digest = ""
        self.audit = audit

    def _loud(self, event):
        if self.audit is not None:
            try:
                self.audit(event)
            except Exception:
                pass

    def _principal_messages(self, principal):
        return [t.get("message", "") for t in self._turns
                if t.get("principal") == principal]

    def record_intent(self, principal, message, verdict=None, ts=None):
        """Record one user turn's intent verdict for ``principal``.

        ``message`` is the raw user message text (stored locally;
        sensitive operational data -- see module docstring).
        ``verdict`` is an optional judge verdict dict (stored
        opaquely); ``ts`` an optional ISO timestamp (defaults to now).

        ``is_countermand`` is computed from BOTH the verdict and the
        canonical redirect detector run against this principal's prior
        turns, so a caller that forgets to judge still gets the
        detector's signal and a caller with a richer verdict is not
        second-guessed.

        Fail-closed: empty principal/message raise ValueError; the
        record is hash-chained before it is returned.
        """
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("principal must be a non-empty string")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("message must be a non-empty string")
        if verdict is not None and not isinstance(verdict, dict):
            raise ValueError("verdict must be a dict or None")
        ts = ts if ts is not None else _utcnow_iso()
        if _parse_ts(ts) is None:
            raise ValueError("ts is not a parseable ISO timestamp: %r"
                             % (ts,))
        prior = self._principal_messages(principal)
        detected, _superseded = _detect_countermand(message, prior)
        is_countermand = bool(_verdict_says_countermand(verdict)
                              or detected)
        record = {
            "record_type": "intent_turn",
            "ledger_version": INTENT_LEDGER_VERSION,
            "principal": principal,
            "message": message,
            "verdict": verdict,
            "is_countermand": is_countermand,
            "detector_countermand": bool(detected),
            "verdict_countermand": bool(_verdict_says_countermand(verdict)),
            "ts": ts,
            "prev_record_digest": self._prev_digest,
        }
        record["record_digest"] = _record_digest(record, self._prev_digest)
        self._loud({
            "event": ("intent_countermand_recorded"
                      if is_countermand else "intent_turn_recorded"),
            "flag": ("intent_countermand" if is_countermand else None),
            "principal": principal,
            "is_countermand": is_countermand,
            "record_digest": record["record_digest"],
            "ts": ts,
        })
        self._turns.append(record)
        self._prev_digest = record["record_digest"]
        return record

    def latest_countermands(self, principal, since):
        """Countermand records for ``principal`` strictly after ``since``.

        ``since`` is an ISO timestamp (e.g. an approval's
        ``decided_at``). Unparseable ``since`` returns [] (fail-safe:
        without an ordering anchor no countermand can be attributed).
        Returns records oldest-first.
        """
        since_dt = _parse_ts(since)
        if since_dt is None:
            return []
        out = []
        for t in self._turns:
            if t.get("principal") != principal:
                continue
            if not t.get("is_countermand"):
                continue
            t_dt = _parse_ts(t.get("ts"))
            if t_dt is not None and t_dt > since_dt:
                out.append(t)
        return out

    def messages_since(self, principal, since):
        """Raw user messages for ``principal`` strictly after ``since``.

        Oldest-first. This is what the execution boundary feeds to the
        intent-slice judge as current intent context. Unparseable
        ``since`` returns [] (fail-safe).
        """
        since_dt = _parse_ts(since)
        if since_dt is None:
            return []
        out = []
        for t in self._turns:
            if t.get("principal") != principal:
                continue
            t_dt = _parse_ts(t.get("ts"))
            if t_dt is not None and t_dt > since_dt:
                out.append(t.get("message", ""))
        return out

    def messages_with_context(self, principal, since, prior=1):
        """User messages for ``principal``: up to ``prior`` messages at
        or before ``since``, then all messages strictly after ``since``.

        ``prior=None`` means ALL messages at or before ``since`` (no
        window truncation); ``prior=1`` (default) keeps only the last
        pre-``since`` turn. Oldest-first. The execution boundary feeds
        this to the intent-slice judge as current intent context: the
        judge's countermand detector anchors the LATEST message against
        PRIOR instructions, so the granting turn (recorded at or before
        the approval's ``decided_at``) must travel with the later turns
        -- a countermand alone has nothing to overlap. With
        ``prior=None`` the full pre-grant history travels, so an
        intervening chatter turn can never evict the granting
        instruction from the judge's window (F181). When the granting
        turn was never recorded, the context starts at the first known
        turn (a documented limitation: the detector cannot anchor
        against an instruction it never saw). Unparseable ``since``
        returns [] (fail-safe).
        """
        since_dt = _parse_ts(since)
        if since_dt is None:
            return []
        before, after = [], []
        for t in self._turns:
            if t.get("principal") != principal:
                continue
            t_dt = _parse_ts(t.get("ts"))
            if t_dt is None:
                continue
            (after if t_dt > since_dt else before).append(
                t.get("message", ""))
        n_prior = len(before) if prior is None else max(int(prior), 0)
        context = before[-n_prior:] if n_prior else []
        return context + after

    def verify_chain(self):
        """Verify the ledger hash chain. Returns (ok, reason)."""
        prev = ""
        for i, rec in enumerate(self._turns):
            if not isinstance(rec, dict):
                return False, "record %d is not a dict" % i
            if rec.get("prev_record_digest") != prev:
                return False, ("record %d linkage broken: "
                               "prev_record_digest mismatch" % i)
            if rec.get("ledger_version") != INTENT_LEDGER_VERSION:
                return False, ("record %d: unsupported ledger_version %r"
                               % (i, rec.get("ledger_version")))
            expect = _record_digest(rec, prev)
            if rec.get("record_digest") != expect:
                return False, ("record %d digest mismatch: payload "
                               "tampered" % i)
            prev = rec["record_digest"]
        return True, "%d records, chain intact" % len(self._turns)

    def save(self, path):
        """Persist the ledger to ``path`` (JSONL, tamper-evident).

        Layout mirrors gov/goals.py: header, one line per turn record
        in chain order, footer carrying ``file_digest`` (SHA-256 over
        the canonical header + records). The in-memory chain continues
        across ``load`` via the header's ``chain_tip``. Raises
        IntentPersistenceError on any I/O problem.
        """
        header = {
            "record_type": "intent_ledger_header",
            "ledger_version": INTENT_LEDGER_VERSION,
            "record_count": len(self._turns),
            "chain_tip": self._prev_digest,
            "saved_at": _utcnow_iso(),
        }
        lines = [_canonical(header)]
        for rec in self._turns:
            if not isinstance(rec, dict):
                raise IntentPersistenceError(
                    "cannot persist: record is not a dict")
            lines.append(_canonical(rec))
        footer = {
            "record_type": "intent_ledger_footer",
            "file_digest": _sha256_hex("\n".join(lines) + "\n"),
        }
        lines.append(_canonical(footer))
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as e:
            raise IntentPersistenceError(
                "cannot save intent ledger to %r: %s" % (path, e))

    @classmethod
    def load(cls, path, audit=None):
        """Load a ledger previously written by ``save``.

        Fail-closed: missing/unreadable file, malformed JSON, wrong
        record_type sequence, ``file_digest`` mismatch, ``chain_tip``
        mismatch, or a broken record chain all raise
        IntentPersistenceError -- a damaged store is never silently
        accepted as a clean history.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw_lines = [ln for ln in
                             (l.strip() for l in fh.read().splitlines())
                             if ln]
        except OSError as e:
            raise IntentPersistenceError(
                "cannot load intent ledger from %r: %s" % (path, e))
        if len(raw_lines) < 2:
            raise IntentPersistenceError(
                "intent ledger file %r is truncated (%d lines)"
                % (path, len(raw_lines)))
        try:
            objs = [json.loads(ln) for ln in raw_lines]
        except ValueError as e:
            raise IntentPersistenceError(
                "intent ledger file %r has malformed JSON: %s"
                % (path, e))
        header, records, footer = objs[0], objs[1:-1], objs[-1]
        if not isinstance(header, dict) or \
                header.get("record_type") != "intent_ledger_header":
            raise IntentPersistenceError(
                "intent ledger file %r: bad or missing header" % (path,))
        if not isinstance(footer, dict) or \
                footer.get("record_type") != "intent_ledger_footer":
            raise IntentPersistenceError(
                "intent ledger file %r: bad or missing footer" % (path,))
        if header.get("ledger_version") != INTENT_LEDGER_VERSION:
            raise IntentPersistenceError(
                "intent ledger file %r: unsupported ledger_version %r"
                % (path, header.get("ledger_version")))
        if header.get("record_count") != len(records):
            raise IntentPersistenceError(
                "intent ledger file %r: header claims %r records, "
                "found %d" % (path, header.get("record_count"),
                              len(records)))
        expect_digest = _sha256_hex(
            "\n".join(_canonical(o) for o in [header] + records) + "\n")
        if footer.get("file_digest") != expect_digest:
            raise IntentPersistenceError(
                "intent ledger file %r: file_digest mismatch -- the "
                "store was modified outside save()" % (path,))
        led = cls(audit=audit)
        led._turns = records
        led._prev_digest = (records[-1].get("record_digest", "")
                            if records else "")
        ok, reason = led.verify_chain()
        if not ok:
            raise IntentPersistenceError(
                "intent ledger file %r: record chain broken (%s)"
                % (path, reason))
        if header.get("chain_tip") != led._prev_digest:
            raise IntentPersistenceError(
                "intent ledger file %r: chain_tip does not match the "
                "stored chain -- records were added, removed, or "
                "reordered outside save()" % (path,))
        return led
