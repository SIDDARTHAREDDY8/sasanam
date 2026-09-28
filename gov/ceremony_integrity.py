"""Ceremony-integrity pre-verification for human approval decisions.

Deterministic rebuild of the awaithumans pre-verification *shape*
(re-check the human's answer; re-present the task with a reason on
failure) without their LLM verifier. Pure function of the decision
record + the decider's stated reason: no network, no model, $0.

Design rules (documented limits, not hidden):
- Gates REFUSE and re-present (the awaithumans loop shape): a bounced
  decision is not a denial of the action, it is a demand for a real
  reason. False positives cost a re-type, not a blocked action.
- Signals never gate: rubber-stamp streaks and copy-paste reasons are
  recorded as audit evidence, never as refusal grounds. A fast,
  terse, legitimate operator must never be blocked by statistics.
- A determined adversary defeats the gates with filler prose
  ("reviewed the diff, approving"). These gates catch careless
  rubber-stamping, not adversarial humans. The GAP-3 approver shield
  (challenge questions) remains the adversarial control on
  capture-tier records.

check_decision_reason(record, approved, reason)
    -> (passed: bool, code: str | None, human_message: str | None)
Codes: "reason_empty", "reason_contradicts_decision".

Wired into the product seam: ``ApprovalQueue.decide()`` calls
``check_decision_reason`` before the decision is recorded and the
receipt stamped. A failed check REFUSEs the decision (ValueError);
the record stays pending and the human re-submits with a real reason
-- the awaithumans re-presentation loop shape. The refusal and the
re-presentation context are chained audit events
(``ceremony_integrity_bounce`` + ``approval_decision_attempt``); the
pending record itself is never mutated (an F38 queue-time digest
covers it).
"""

from __future__ import annotations

import math
import re
import time
from datetime import datetime, timezone

# Denial language that contradicts an APPROVAL. Patterns are scoped to
# the approval act itself ("do not approve", "reject this") rather than
# bare sentiment words ("dangerous") so that a reason like
# "approved - verified the dangerous-looking filename is correct"
# does not fire.
_DENIAL_ON_APPROVE = (
    re.compile(r"\bdo\s+not\s+approve\b(?!\s+of\b)"),
    re.compile(r"\bdon'?t\s+approve\b(?!\s+of\b)"),
    re.compile(r"\bshould\s+not\s+be\s+approved?\b"),
    re.compile(r"\bmust\s+not\s+be\s+approved?\b"),
    re.compile(r"\bcannot\s+be\s+approved?\b"),
    re.compile(r"\breject\s+this\b"),
    re.compile(r"\bdeny\s+this\b"),
    re.compile(r"\btoo\s+(dangerous|risky|unsafe)\s+to\s+approve\b"),
    re.compile(r"\bunsafe\s+to\s+approve\b"),
    re.compile(r"\bdo\s+not\s+(run|execute)\b"),
    re.compile(r"\bdon'?t\s+(run|execute)\b"),
)

# Approval language that contradicts a REJECTION.
_APPROVAL_ON_REJECT = (
    re.compile(r"\bapprove\s+this\b"),
    re.compile(r"\bapproved[,.!]"),
    re.compile(r"\byes[,!]?\s+(approve|do\s+it|go\s+ahead|run\s+it)\b"),
    # "go ahead" as a noun phrase ("go ahead is premature") is not an
    # approval claim; only the bare/imperative use fires.
    re.compile(r"\bgo\s+ahead\b(?!\s+(is|was|seems)\b)"),
    re.compile(r"\bdo\s+it\b"),
    re.compile(r"\blooks\s+good[,!]\s+approv"),
)

_REASON_EMPTY = "reason_empty"
_REASON_CONTRADICTS = "reason_contradicts_decision"


def check_decision_reason(record, approved, reason):
    """Pre-verify a human's decision reason. Returns (passed, code, message).

    ``record`` is the pending approval record (used for context in the
    message only). ``approved`` is the decision direction. ``reason``
    is the decider's stated reason, verbatim.
    """
    text = reason if isinstance(reason, str) else ""
    stripped = text.strip()
    if not stripped:
        return (False, _REASON_EMPTY,
                "a decision reason is required: re-submit the decision "
                "with a non-empty reason describing what was reviewed")
    lowered = stripped.lower()
    if approved:
        for pat in _DENIAL_ON_APPROVE:
            if pat.search(lowered):
                return (False, _REASON_CONTRADICTS,
                        "the reason reads as a denial (%r) but the decision "
                        "is an approval: re-submit with a reason that "
                        "matches the decision" % pat.pattern)
    else:
        for pat in _APPROVAL_ON_REJECT:
            if pat.search(lowered):
                return (False, _REASON_CONTRADICTS,
                        "the reason reads as an approval (%r) but the "
                        "decision is a rejection: re-submit with a reason "
                        "that matches the decision" % pat.pattern)
    return (True, None, None)


def rubber_stamp_streak(decider_history, window=5):
    """Signal (never a gate): how many of the decider's last ``window``
    decisions were approvals with no rejection interleaved.

    ``decider_history`` is a list of (approved: bool) oldest-first.
    Returns the current approval streak length.
    """
    streak = 0
    for approved in reversed(decider_history[-window:]):
        if approved:
            streak += 1
        else:
            break
    return streak


def copypaste_reason(reason, decider_reasons, threshold=3):
    """Signal (never a gate): True when the decider's reason is identical
    (case/whitespace-insensitive) to at least ``threshold`` of their
    recent reasons. Identical boilerplate across distinct approvals is
    evidence of no-read rubber-stamping, not proof of it.
    """
    norm = (reason or "").strip().lower()
    if not norm:
        return False
    matches = sum(1 for r in decider_reasons
                  if (r or "").strip().lower() == norm)
    return matches >= threshold


# ------------------------------------------------------------------
# Wave-173: ceremony-timing telemetry + advisory rubber-stamp signals.
#
# Design input (no code copied): eval-kit GateEvent timing vocabulary
# (akaieuan/eval-kit, MIT) -- opened time, resolved time, latency,
# decider, explicit nullable/unobserved semantics, a consistency
# invariant -- and the automater.ai advisory-signal vocabulary (six
# fleet signals: sub-second latency cluster, approver dominance,
# after-hours approval, allow-list growth, terse tier-3 reason,
# approver stall / p90 above expiry).
#
# The decided record carries three timing fields:
#   review_opened_at   ISO-8601 timestamp, ms precision, server-local
#                      zone (same convention as decided_at/ts)
#   review_resolved_at ISO-8601 timestamp, ms precision
#   review_latency_ms  integer milliseconds of observed review time
# Explicit None on all three means UNOBSERVED: the instrument could
# not see when review began (CLI without a render seam, web UI after
# a server restart, any non-human path). Unobserved is never
# interpreted as clear/pass -- every signal reports "unobserved"
# when its inputs are missing, and inconsistent triples are
# "corrupt", never silently rounded into shape.
#
# Signals are ADVISORY ONLY: they never refuse, alter, or re-present
# a decision. They read decided records; they have no path back into
# ApprovalQueue.decide().

# Timing self-consistency: |resolved - opened - latency_ms| must be
# within this many milliseconds. Inconsistent records are corrupt.
TIMING_CONSISTENCY_TOL_MS = 1000.0

# Advisory-signal defaults (eval-kit / automater.ai vocabulary).
LATENCY_CLUSTER_THRESHOLD_MS = 1000
LATENCY_CLUSTER_MIN_TIMED = 5
LATENCY_CLUSTER_MIN_FRAC = 0.5
APPROVER_DOMINANCE_FRAC = 0.6
APPROVER_DOMINANCE_MIN_RECORDS = 5
AFTER_HOURS_LATE = 22      # 22:00-05:59 local is "after hours"
AFTER_HOURS_EARLY = 6
APPROVER_STALL_MIN_TIMED = 5
APPROVER_STALL_P90_THRESHOLD_MS = 300_000
TIER3_RISK_TIER = "critical"
ALLOW_LIST_GROWTH_THRESHOLD = 5
TERSE_REASONS = frozenset({"y", "yes", "ok", "lgtm", "approved"})


def _parse_iso(value):
    """Parse an ISO-8601 timestamp to epoch seconds; None if unusable.

    Naive timestamps are assumed UTC. Returns None (never raises) so
    callers can treat unparseable stamps as corrupt input, not crash.
    """
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def stamp_review_timing(review_opened_at):
    """Stamp the review-timing triple at decision time.

    ``review_opened_at`` is epoch seconds observed by the decision
    instrument (web UI render time, CLI render time), or None when
    the instrument could not observe review start.

    Returns (review_opened_at_iso, review_resolved_at_iso,
    review_latency_ms). Any unusable instrument input -- None,
    non-numeric, or a future timestamp (clock disagreement) -- fails
    SAFE to (None, None, None): an instrument that cannot see must
    not report success. Timestamps use the record's local-zone ISO
    convention at millisecond precision (second precision would eat
    the whole consistency tolerance in rounding).
    """
    now = time.time()
    if (review_opened_at is None
            or isinstance(review_opened_at, bool)
            or not isinstance(review_opened_at, (int, float))
            or review_opened_at > now):
        return (None, None, None)
    latency_ms = int(round((now - review_opened_at) * 1000))
    if latency_ms < 0:
        return (None, None, None)
    opened_dt = datetime.fromtimestamp(review_opened_at).astimezone()
    now_dt = datetime.fromtimestamp(now).astimezone()
    return (opened_dt.isoformat(timespec="milliseconds"),
            now_dt.isoformat(timespec="milliseconds"),
            latency_ms)


def check_review_timing_consistency(record):
    """Classify a decided record's review-timing triple.

    Returns:
      "unobserved" -- all three fields None/missing: the instrument
          could not see review start. Never interpreted as clear.
      "invalid"    -- a partial triple (some fields set, some null):
          no writer ever emits this; it means tampering or a buggy
          writer.
      "consistent" -- full triple with
          |resolved - opened - latency_ms| <= 1000 ms.
      "corrupt"    -- full triple that disagrees with itself beyond
          tolerance, negative latency, non-numeric latency, or
          unparseable timestamps. Never rounded into shape.
    """
    opened = record.get("review_opened_at")
    resolved = record.get("review_resolved_at")
    latency = record.get("review_latency_ms")
    if opened is None and resolved is None and latency is None:
        return "unobserved"
    if opened is None or resolved is None or latency is None:
        return "invalid"
    if isinstance(latency, bool) or not isinstance(latency, (int, float)):
        return "corrupt"
    if latency < 0:
        return "corrupt"
    t0 = _parse_iso(opened)
    t1 = _parse_iso(resolved)
    if t0 is None or t1 is None:
        return "corrupt"
    drift_ms = abs((t1 - t0) * 1000.0 - float(latency))
    if drift_ms <= TIMING_CONSISTENCY_TOL_MS:
        return "consistent"
    return "corrupt"


def _timed_latencies(records):
    """Observed latencies (ms) from records with a numeric triple."""
    out = []
    for r in records:
        lat = r.get("review_latency_ms")
        if isinstance(lat, bool):
            continue
        if isinstance(lat, (int, float)) and lat >= 0:
            out.append(float(lat))
    return out


def sig_latency_cluster_under_1s(records,
                                 threshold_ms=LATENCY_CLUSTER_THRESHOLD_MS,
                                 min_timed=LATENCY_CLUSTER_MIN_TIMED,
                                 min_frac=LATENCY_CLUSTER_MIN_FRAC):
    """Advisory: do sub-second decisions dominate the window?

    Flags when more than ``min_frac`` of at least ``min_timed``
    timed decisions resolved in under ``threshold_ms`` -- the
    rubber-stamp cluster shape. "unobserved" when fewer than
    ``min_timed`` records carry timing; unobserved is never clear.
    """
    lat = _timed_latencies(records)
    if len(lat) < min_timed:
        return ("unobserved",
                "%d timed records, need %d" % (len(lat), min_timed))
    fast = sum(1 for v in lat if v < threshold_ms)
    frac = fast / len(lat)
    note = ("%d of %d timed decisions (%d%%) resolved under %d ms"
            % (fast, len(lat), round(frac * 100), threshold_ms))
    if frac > min_frac:
        return ("flag", note)
    return ("clear", note)


def sig_approver_dominance(records,
                           frac=APPROVER_DOMINANCE_FRAC,
                           min_records=APPROVER_DOMINANCE_MIN_RECORDS):
    """Advisory: does one approver own the window?

    Flags when a single decider accounts for more than ``frac`` of
    attributed decisions. Timing-independent: dominance is about who
    decides, not how fast. "unobserved" below ``min_records``
    attributed decisions.
    """
    counts = {}
    for r in records:
        who = r.get("decided_by")
        if who:
            counts[who] = counts.get(who, 0) + 1
    total = sum(counts.values())
    if total < min_records:
        return ("unobserved",
                "%d attributed decisions, need %d" % (total, min_records))
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    share = top[1] / total
    note = ("%s decided %d of %d attributed decisions (%d%%)"
            % (top[0], top[1], total, round(share * 100)))
    if share > frac:
        return ("flag", note)
    return ("clear", note)


def sig_after_hours(records, tzinfo=None,
                    late_hour=AFTER_HOURS_LATE, early_hour=AFTER_HOURS_EARLY):
    """Advisory: were decisions resolved in the small hours?

    Flags when at least one timed decision resolved at hour >=
    ``late_hour`` or < ``early_hour`` in ``tzinfo`` (default: the
    timestamp's own zone, i.e. the server-local wall clock the
    record was stamped with). "unobserved" when no resolved time
    parses. Residual: without a session-start anchor the signal
    cannot distinguish a night-owl operator from a morning session
    dragged late -- it reports the hour, not the story.
    """
    late = 0
    timed = 0
    for r in records:
        t = _parse_iso(r.get("review_resolved_at"))
        if t is None:
            continue
        timed += 1
        dt = datetime.fromtimestamp(t, tz=timezone.utc)
        dt = dt.astimezone(tzinfo) if tzinfo is not None else dt.astimezone()
        if dt.hour >= late_hour or dt.hour < early_hour:
            late += 1
    if timed == 0:
        return ("unobserved", "no parseable review_resolved_at")
    note = ("%d of %d timed decisions resolved %02d:00-%02d:59"
            % (late, timed, late_hour, early_hour - 1))
    if late > 0:
        return ("flag", note)
    return ("clear", note)


def _p90(values):
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(math.ceil(0.9 * len(ordered))) - 1)
    return ordered[idx]


def sig_approver_stall(records,
                       p90_threshold_ms=APPROVER_STALL_P90_THRESHOLD_MS,
                       min_timed=APPROVER_STALL_MIN_TIMED):
    """Advisory: are agents stalling on slow review?

    Flags when the p90 observed review latency exceeds
    ``p90_threshold_ms`` -- agents waiting on the queue are stalling,
    not deciding. "unobserved" below ``min_timed`` timed records.
    """
    lat = _timed_latencies(records)
    if len(lat) < min_timed:
        return ("unobserved",
                "%d timed records, need %d" % (len(lat), min_timed))
    p90 = _p90(lat)
    note = ("p90 review latency %.0f ms vs %.0f ms threshold (%d timed)"
            % (p90, p90_threshold_ms, len(lat)))
    if p90 > p90_threshold_ms:
        return ("flag", note)
    return ("clear", note)


def sig_tier3_terse(records, tier=TIER3_RISK_TIER):
    """Advisory: terse in-band reasons on the highest-risk tier.

    Flags when at least one ``tier`` decision carries a bare terse
    reason ("ok", "lgtm", ...). Timing-independent: the reason and
    the risk tier are always on the record. "clear" when no
    tier-3 decision is terse (vacuously clear with no tier-3
    decisions at all).
    """
    hits = 0
    tiered = 0
    for r in records:
        if r.get("risk_tier") != tier:
            continue
        tiered += 1
        reason = (r.get("decision_reason") or "").strip().lower()
        if reason in TERSE_REASONS:
            hits += 1
    note = ("%d of %d %s-tier decisions carry a terse reason"
            % (hits, tiered, tier))
    if hits > 0:
        return ("flag", note)
    return ("clear", note)


def sig_allow_list_growth(allow_before, allow_after, days=7,
                          threshold=ALLOW_LIST_GROWTH_THRESHOLD):
    """Advisory: did the allow-list grow suspiciously fast?

    Pure function over caller-supplied allow-rule counts (e.g. from
    policy snapshots): flags when the allow-list grew by more than
    ``threshold`` rules in ``days`` days. Shrinkage or small drift
    is "clear".
    """
    try:
        before = int(allow_before)
        after = int(allow_after)
    except (TypeError, ValueError):
        return ("unobserved", "non-numeric allow-list counts")
    delta = after - before
    note = ("allow-list changed by %+d rules in %d days (%d -> %d)"
            % (delta, days, before, after))
    if delta > threshold:
        return ("flag", note)
    return ("clear", note)
