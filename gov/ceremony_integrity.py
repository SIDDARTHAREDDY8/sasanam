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

import re

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
