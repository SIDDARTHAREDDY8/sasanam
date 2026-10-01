"""Tamper-evident drift-report event schema.

The gate_hardening audit-scanner analog reports "what protect would
deny today" -- but it emits no structured drift events; drift
observation is report-only, and (as the wave-271 prospectus notes of
OPA) decision logs are telemetry, not a replayable/tamper-evident
audit mechanism.

This module closes that gap with an OPA-*shaped* but tamper-evident
drift event stream (clean-room pattern; no OPA code):

  - ``DriftReporter`` wraps any scanner exposing ``scan(requests)``
    (``gate_hardening.Gate.scan`` qualifies). ``record_baseline()``
    snapshots per-request decisions; ``rescan()`` replays the scan and
    emits one ``drift-detected`` event per newly-denying item
    (baseline ``allow`` -> now ``deny``), in deterministic
    ``request_id`` order. Each event carries the then/now decisions
    AND the gate digest, so the event answers "which policy set made
    the new decision".
  - Every event is appended to ``DriftLog``, a hash-chained,
    append-only log. Reordering, deletion, or edits break
    ``verify()`` fail-closed (``drift-log-corrupt``). The log is
    in-memory; durability is deployment-owned (persist via
    ``gov.durable_journal`` or the sink of your choice -- the chain is
    the portable part).

Event schema (``drift-detected``):
    {"seq", "ts", "event": "drift-detected", "request_id",
     "then_decision", "now_decision", "then_code", "now_code",
     "gate_digest", "prev_digest", "event_digest"}

Honest limits (read before citing a drift report as proof):
  - Drift is measured against the recorded baseline, not against
    ground truth. A baseline recorded after a bad policy change
    bakes the bad policy in.
  - The reporter observes decisions; it cannot distinguish a policy
    tightening from a policy *fix* -- "newly-denying" is an
    observation, not a verdict on intent.
  - ``gate_digest`` identifies the registered policy set of the
    scanner at scan time (``Gate.policy_digest``). A deployment that
    swaps scanners between baseline and rescan without updating the
    reporter gets "unknown".
  - ``verify()`` re-derives the chain over the records present: tail
    truncation (deleting trailing records) leaves a valid shorter
    chain. Persist the tip (final ``event_digest``) externally, or
    truncation is silent.

Stdlib only. Deterministic given explicit ``now``.
"""

import hashlib
import json
import re
import time

_HEX64_LEN = 64
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class DriftReportError(Exception):
    """Coded, fail-closed drift-report error. ``code`` is a machine
    code in the ``drift`` decision-code domain; ``detail`` is human
    text."""

    def __init__(self, code, detail):
        super(DriftReportError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


_GENESIS = "00" * 32


def _request_id(entry):
    """The scanner entry's request id, or a coded refusal. A
    non-string id (e.g. None) would make deterministic ordering
    raise TypeError; refuse it instead."""
    rid = entry.get("request_id", "?")
    if not isinstance(rid, str):
        raise DriftReportError(
            "drift-malformed",
            "scanner entry request_id must be a string, got %r"
            % (rid,))
    return rid


def gate_policy_digest(gate):
    """Digest identifying the scanner's registered policy set.

    Uses the scanner's public ``policy_digest()`` when available
    (``gate_hardening.Gate`` provides it); otherwise "unknown". A
    digest-shaped but non-hex value is also "unknown" -- a garbage
    digest is worse than an honest unknown.
    """
    fn = getattr(gate, "policy_digest", None)
    if callable(fn):
        digest = fn()
        if isinstance(digest, str) and _HEX64_RE.match(digest):
            return digest
    return "unknown"


class DriftLog(object):
    """In-memory hash-chained event log. ``append`` returns the stored
    record (with ``seq``, ``prev_digest``, ``event_digest``);
    ``verify`` re-derives the chain and raises
    ``DriftReportError("drift-log-corrupt")`` on any mismatch --
    interior deletion, reordering, or in-place edits are all
    detected. Tail truncation is NOT detected by verify() alone
    (persist the tip externally; see module honest limits)."""

    def __init__(self, *, now=None):
        self._now = now or time.time
        self._records = []
        self._tip = _GENESIS

    def append(self, event):
        if not isinstance(event, dict):
            raise DriftReportError(
                "drift-malformed", "event must be a dict")
        record = dict(event)
        record["seq"] = len(self._records)
        record["prev_digest"] = self._tip
        if "ts" not in record:
            record["ts"] = int(self._now())
        record["event_digest"] = _sha256_hex(_canonical(
            {k: v for k, v in record.items() if k != "event_digest"}))
        self._records.append(record)
        self._tip = record["event_digest"]
        return record

    def records(self):
        return list(self._records)

    def verify(self):
        """Re-derive the chain. Returns True; raises
        ``drift-log-corrupt`` on any break."""
        prev = _GENESIS
        for i, record in enumerate(self._records):
            if record.get("seq") != i:
                raise DriftReportError(
                    "drift-log-corrupt",
                    "record seq %r out of order (expected %d)"
                    % (record.get("seq"), i))
            if record.get("prev_digest") != prev:
                raise DriftReportError(
                    "drift-log-corrupt",
                    "record %d prev_digest does not chain "
                    "(log edited or truncated)" % (i,))
            recomputed = _sha256_hex(_canonical(
                {k: v for k, v in record.items()
                 if k != "event_digest"}))
            if recomputed != record.get("event_digest"):
                raise DriftReportError(
                    "drift-log-corrupt",
                    "record %d body does not hash to its event_digest "
                    "(tampered)" % (i,))
            prev = record["event_digest"]
        return True


class DriftReporter(object):
    """Baseline + rescan drift detection over a gate scanner.

    ``scanner`` exposes ``scan(requests)`` returning
    ``[{"request_id", "would", "code"}]`` (the
    ``gate_hardening.Gate.scan`` shape). ``gate_digest`` pins the
    policy-set identity carried on every event; when omitted it is
    derived from the scanner at each scan (so a policy change between
    baseline and rescan is visible ON the events).
    """

    def __init__(self, scanner, *, now=None, gate_digest=None):
        if not callable(getattr(scanner, "scan", None)):
            raise DriftReportError(
                "drift-malformed",
                "scanner must expose scan(requests)")
        if gate_digest is not None and not (
                isinstance(gate_digest, str)
                and _HEX64_RE.match(gate_digest)):
            raise DriftReportError(
                "drift-malformed",
                "gate_digest must be a 64-char lowercase hex digest")
        self._scanner = scanner
        self._now = now or time.time
        self._pinned_gate_digest = gate_digest
        self._log = DriftLog(now=self._now)
        self._baseline = None
        self._baseline_digest = None

    def _current_gate_digest(self):
        if self._pinned_gate_digest is not None:
            return self._pinned_gate_digest
        return gate_policy_digest(self._scanner)

    def record_baseline(self, requests):
        """Snapshot per-request decisions as the drift baseline. Emits
        a ``drift-baseline-updated`` event into the chain (the chain's
        context for everything that follows)."""
        scanned = self._scanner.scan(requests)
        baseline = {}
        for entry in scanned:
            rid = _request_id(entry)
            baseline[rid] = {"would": entry.get("would"),
                             "code": entry.get("code")}
        self._baseline = baseline
        self._baseline_digest = _sha256_hex(_canonical(
            {"gate_digest": self._current_gate_digest(),
             "decisions": sorted(
                 (rid, v["would"], v["code"])
                 for rid, v in baseline.items())}))
        self._log.append({
            "event": "drift-baseline-updated",
            "baseline_digest": self._baseline_digest,
            "gate_digest": self._current_gate_digest(),
            "items": len(baseline),
        })
        return {"baseline_digest": self._baseline_digest,
                "items": len(baseline)}

    def rescan(self, requests):
        """Re-run the scan and emit one ``drift-detected`` event per
        newly-denying item (baseline ``allow`` -> now ``deny``), in
        deterministic ``request_id`` order.

        A first call with no recorded baseline records the baseline
        and reports ``baseline_recorded: True`` (documented; a rescan
        never silently invents history).
        """
        baseline_recorded = False
        if self._baseline is None:
            self.record_baseline(requests)
            baseline_recorded = True
        gate_digest = self._current_gate_digest()
        scanned = self._scanner.scan(requests)
        newly_denying = []
        resolved = []
        for entry in sorted(scanned,
                            key=lambda e: _request_id(e)):
            rid = _request_id(entry)
            then = self._baseline.get(rid)
            if then is None:
                continue  # no baseline for this item: not drift
            now_would = entry.get("would")
            if then["would"] == "allow" and now_would == "deny":
                newly_denying.append({
                    "request_id": rid,
                    "then_decision": "allow",
                    "now_decision": "deny",
                    "then_code": then["code"],
                    "now_code": entry.get("code"),
                })
            elif then["would"] == "deny" and now_would == "allow":
                resolved.append(rid)
        for item in newly_denying:
            self._log.append({
                "event": "drift-detected",
                "request_id": item["request_id"],
                "then_decision": item["then_decision"],
                "now_decision": item["now_decision"],
                "then_code": item["then_code"],
                "now_code": item["now_code"],
                "gate_digest": gate_digest,
            })
        return {"newly_denying": newly_denying,
                "resolved": resolved,
                "scanned": len(scanned),
                "events": len(self._log.records()),
                "baseline_recorded": baseline_recorded}

    def events(self):
        """The chained drift-event records, oldest first."""
        return self._log.records()

    def verify_log(self):
        """Verify the drift-event chain. Returns True; raises
        ``drift-log-corrupt`` on tampering."""
        return self._log.verify()
