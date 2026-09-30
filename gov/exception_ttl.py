"""Operational exception declarations with a mandatory TTL (wave-242).

ADAPT of draft-wei-capability-language-core -00, section 8.5: Wei's
Resolve forbids holding a cached allow past its discharge horizon.
A Sasanam gate normally refuses an UNDECIDABLE verdict
(``gov/gate_outcomes.py`` ``gate_decide`` -> ``gate-undecidable``),
and ``gate_selfcheck`` declares a gate non-compliant when it allows
one. This module is the ONE legitimate exception path: a
time-bounded, declared, scope-bound exception a gate may consume when
it would otherwise refuse.

Fail-closed rules:

* ``declare_exception`` REQUIRES ``valid_until`` (epoch seconds, an
  int/float, never a bool). A missing or non-numeric horizon is a
  malformed declaration: ``gate-exception-malformed``.
* ``consume_exception`` only consumes a declaration that is live
  (``valid_until > now``) and scope-matching. An EXPIRED exception
  refuses ``gate-undecidable`` -- the proposal's exact wording: the
  expired exception no longer shields anything, so the underlying
  undecidable verdict is refused fail-closed.
* An exception never shields TAMPER: ``gate_decide_with_exception``
  still refuses ``gate-tampered`` for a TAMPER verdict even with a
  live exception.
* Malformed construction is reported as ``gate-exception-malformed``
  (a product refusal at the exception seam, not a programming error),
  because exceptions arrive from operators as data.

Deterministic: the clock arrives as an explicit ``now`` argument;
the module never reads time itself, so mid-flight horizon crossings
are testable (and auditable) rather than implicit.

What this does NOT do (honest boundaries):
- It does not verify the underlying evidence. Consuming an
  exception is an operator decision with a deadline, not a proof;
  the consumption receipt returned on allow-on-exception exists so
  the caller can bind it into the gate record.
- It does not change ``gate_outcomes.gate_decide`` or
  ``gate_selfcheck``: a gate that allows an undecidable verdict
  WITHOUT consuming a live exception is still non-compliant.
- Exception declarations are data, not policy: they declare who
  authorized the window (``reason``) and what it covers
  (``scope``), nothing more.

Stdlib only.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import gate_outcomes as _go

__all__ = [
    "declare_exception",
    "consume_exception",
    "gate_decide_with_exception",
    "ExceptionTTL",
]

GATE_EXCEPTION_MALFORMED = "gate-exception-malformed"


class ExceptionTTL(_go.GateOutcomeError):
    """An exception-path refusal carrying a machine taxonomy code.

    ``code`` is ``gate-exception-malformed`` (raised by this module)
    or one of the ``gov/gate_outcomes.py`` GATE_* constants. A
    ``GateOutcomeError`` subclass so gates treat it as a gate
    refusal, not a crash.
    """



def _is_horizon(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def declare_exception(valid_until=None, reason="", scope="", issued_at=0):
    """Declare an operational exception with a mandatory horizon.

    ``valid_until`` is REQUIRED (epoch seconds, numeric). ``reason``
    and ``scope`` are REQUIRED non-empty strings. Malformed
    declarations refuse ``gate-exception-malformed``.
    """
    if not _is_horizon(valid_until):
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "exception declaration requires a numeric valid_until "
            "horizon; got %r" % (valid_until,))
    if not isinstance(reason, str) or not reason:
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "exception declaration requires a non-empty reason string")
    if not isinstance(scope, str) or not scope:
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "exception declaration requires a non-empty scope string")
    if not _is_horizon(issued_at):
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "exception declaration issued_at must be numeric, got %r"
            % (issued_at,))
    return {
        "type": "gate-exception",
        "valid_until": valid_until,
        "reason": reason,
        "scope": scope,
        "issued_at": issued_at,
    }


def consume_exception(exception, now=None, scope=""):
    """Consume an exception declaration at a given time.

    Returns a consumption receipt dict when the declaration is live
    (``valid_until > now``) and covers ``scope``. An expired
    declaration refuses ``gate-undecidable`` (the exception no longer
    shields; the gate refuses fail-closed). A declaration that does
    not cover ``scope``, or is not a well-formed exception dict,
    likewise refuses: scope mismatch -> ``gate-undecidable``
    (nothing shields this gate), structural problems ->
    ``gate-exception-malformed``.
    """
    if not _is_horizon(now):
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "consume_exception requires a numeric now, got %r" % (now,))
    if not isinstance(exception, dict) or \
            exception.get("type") != "gate-exception":
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "not a gate-exception declaration: %r"
            % (type(exception).__name__,))
    horizon = exception.get("valid_until")
    if not _is_horizon(horizon):
        raise ExceptionTTL(
            GATE_EXCEPTION_MALFORMED,
            "exception declaration has no numeric valid_until: %r"
            % (horizon,))
    if exception.get("scope") != scope:
        raise _go.GateOutcomeError(
            _go.GATE_UNDECIDABLE,
            "exception covers scope %r, not %r; the exception does "
            "not shield this gate and it refuses fail-closed"
            % (exception.get("scope"), scope))
    if not horizon > now:
        raise _go.GateOutcomeError(
            _go.GATE_UNDECIDABLE,
            "exception horizon expired (valid_until %r, now %r); the "
            "exception no longer shields and the gate refuses "
            "fail-closed" % (horizon, now))
    return {
        "consumed": True,
        "scope": scope,
        "valid_until": horizon,
        "consumed_at": now,
        "reason": exception.get("reason", ""),
    }


def gate_decide_with_exception(verdict, exception, now=None, scope=""):
    """The gate seam with the exception path.

    PASS allows (returns True). TAMPER refuses ``gate-tampered``
    (an exception NEVER shields tamper). UNDECIDABLE consumes the
    exception: a live, scope-matching declaration returns a
    consumption receipt (the exception path); an expired or
    out-of-scope declaration refuses ``gate-undecidable``; a
    structurally malformed declaration refuses
    ``gate-exception-malformed``. ``exception=None`` is a
    non-exception gate: UNDECIDABLE refuses ``gate-undecidable``.
    """
    if not isinstance(verdict, _go.Verdict):
        raise ValueError("gate_decide_with_exception needs a Verdict, "
                         "got %r" % (type(verdict).__name__,))
    if verdict.outcome == _go.PASS:
        return True
    if verdict.outcome == _go.TAMPER:
        raise _go.GateOutcomeError(
            _go.GATE_TAMPERED,
            "the verifier reported that the evidence was tampered; "
            "an exception never shields tamper and the gate refuses")
    # verdict.outcome == UNDECIDABLE from here: the closed reason
    # vocabulary is still mandatory on the exception path.
    if verdict.reason not in _go.UNDECIDABLE_REASONS:
        raise _go.GateOutcomeError(
            _go.GATE_VERDICT_UNREASONED,
            "the verifier returned undecidable without a mandatory "
            "reason from the vocabulary; the gate contract refuses "
            "the verdict itself")
    if exception is None:
        raise _go.GateOutcomeError(
            _go.GATE_UNDECIDABLE,
            "the verifier could not verify the evidence (reason: %s); "
            "no exception was presented and the gate refuses "
            "fail-closed" % verdict.reason)
    return consume_exception(exception, now=now, scope=scope)
