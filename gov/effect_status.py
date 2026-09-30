#!/usr/bin/env python3
"""Portable effect statuses: what happened after the verdict.

ADAPT of the VEP-0006 direction (re-derived prose; nothing copied):
execution outcomes need a portable, closed vocabulary so an auditor
can tell — from the evidence alone — whether an action completed,
failed, was denied, was cancelled, timed out, and on which side of
acceptance the interruption landed.

The KEY RULE: a timeout or cancellation that occurred AFTER an
external executor may have accepted the work MUST NOT map to
``unknown``/``none``. It maps to
``timed-out-after-possible-effect`` / ``cancelled-after-possible-effect``.
Claiming ``unknown`` with ``executor_may_have_accepted=True`` refuses
``effect-status-ambiguous-refused``. This forces every caller to say
which side of acceptance the timeout landed on — relabeling a
post-acceptance timeout as "unknown" is how possible side effects
get erased from the record.

``unknown`` is only honest pre-acceptance (the executor never took
the work, and the caller genuinely does not know more). Malformed
observations refuse ``effect-status-invalid``.

:func:`capsule_from_effect` composes with gov/action_capsule.py: it
seals the attempt plus the portable effect status into a
digest-committed action capsule, so the status becomes auditor-grade
evidence. The capsule's own admitted/refused status reflects the gate
verdict (an executed action was admitted; a denied one refused with
its code); ``portable_status`` carries the EffectStatus.

A portable effect status is evidence, never authorization — like
every record in this repo, it describes what happened; it never
permits anything.

Stdlib only. No network. $0.
"""

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class EffectStatusError(Exception):
    """Base class for effect-status refusals. ``code`` is
    machine-readable."""

    code = "effect-status-refused"


class _Ambiguous(EffectStatusError):
    code = "effect-status-ambiguous-refused"


class _Invalid(EffectStatusError):
    code = "effect-status-invalid"


try:
    from . import action_capsule as _ac
except ImportError:  # standalone: action_capsule.py beside this file
    import action_capsule as _ac

# ----------------------------------------------------------------------
# Closed vocabularies.
# ----------------------------------------------------------------------

EFFECT_STATUSES = (
    "completed",
    "failed",
    "denied",
    "cancelled-before-execution",
    "cancelled-after-possible-effect",
    "timed-out-before-effect",
    "timed-out-after-possible-effect",
    "unknown",
)

# What a caller may report having observed. ``unknown`` is the only
# honest answer when the caller cannot distinguish; ``completed`` /
# ``failed`` / ``denied`` are terminal; ``cancelled`` and
# ``timed-out`` are interruptions whose meaning depends on which side
# of acceptance they landed on (see classify).
_OBSERVABLE_OUTCOMES = (
    "completed", "failed", "denied", "cancelled", "timed-out", "unknown",
)


# ----------------------------------------------------------------------
# Classification.
# ----------------------------------------------------------------------


def classify(observation):
    """Map an observation to a portable EffectStatus. Fail closed.

    ``observation`` is ``{"outcome": <one of _OBSERVABLE_OUTCOMES>,
    "executor_may_have_accepted": bool}``.

    * terminal outcomes (completed/failed/denied) pass through;
    * interruptions map to the before/after-possible-effect status
      according to ``executor_may_have_accepted``;
    * ``unknown`` with ``executor_may_have_accepted=True`` refuses
      ``effect-status-ambiguous-refused`` — after possible acceptance,
      "unknown" is not an honest classification;
    * anything malformed refuses ``effect-status-invalid``.
    """
    if not isinstance(observation, dict):
        raise _Invalid("observation must be a dict")
    outcome = observation.get("outcome")
    accepted = observation.get("executor_may_have_accepted")
    if outcome not in _OBSERVABLE_OUTCOMES:
        raise _Invalid(
            "outcome must be one of %r, got %r"
            % (_OBSERVABLE_OUTCOMES, outcome))
    if not isinstance(accepted, bool):
        raise _Invalid(
            "executor_may_have_accepted must be bool, got %r" % (accepted,))
    if outcome in ("completed", "failed", "denied"):
        return outcome
    if outcome == "timed-out":
        return ("timed-out-after-possible-effect" if accepted
                else "timed-out-before-effect")
    if outcome == "cancelled":
        return ("cancelled-after-possible-effect" if accepted
                else "cancelled-before-execution")
    # outcome == "unknown"
    if accepted:
        raise _Ambiguous(
            "unknown claimed after the executor may have accepted: "
            "reclassify as timed-out-after-possible-effect or "
            "cancelled-after-possible-effect instead")
    return "unknown"


# ----------------------------------------------------------------------
# Action-capsule composition.
# ----------------------------------------------------------------------

# How a portable EffectStatus maps onto the action capsule's own
# admitted/refused effect status. The capsule's status records the
# GATE verdict (was the attempt admitted?), while ``portable_status``
# records what actually happened. An executed-but-failed action was
# still admitted; a denied action was refused with its code.
_STATUS_TO_CAPSULE = {
    "completed": ("admitted", None),
    "failed": ("admitted", None),
    "timed-out-before-effect": ("admitted", None),
    "timed-out-after-possible-effect": ("admitted", None),
    "cancelled-before-execution": ("admitted", None),
    "cancelled-after-possible-effect": ("admitted", None),
    "unknown": ("admitted", None),
    "denied": ("refused", "action-denied"),
}


def capsule_from_effect(verdict_record, effect_status):
    """Seal an action capsule binding the portable effect status.

    ``verdict_record`` is ``{"attempt": {...}}`` (the attempt part;
    the effect is constructed here from the portable status).
    ``effect_status`` must be a member of :data:`EFFECT_STATUSES`;
    anything else refuses ``effect-status-invalid``.

    The ambiguous mapping is refused one seam earlier: use
    :func:`classify` on the raw observation to obtain the status,
    which refuses ``effect-status-ambiguous-refused`` for a
    post-acceptance ``unknown``. Seal only classified statuses (or
    ``unknown`` the caller can honestly defend pre-acceptance).

    The returned capsule's effect carries ``portable_status`` bound
    by digest alongside the evidence string, so an auditor can
    verify the claimed status without re-running the action.
    """
    if effect_status not in _STATUS_TO_CAPSULE:
        raise _Invalid(
            "effect_status must be one of %r, got %r"
            % (EFFECT_STATUSES, effect_status))
    if not isinstance(verdict_record, dict):
        raise _Invalid("verdict_record must be a dict")
    attempt = verdict_record.get("attempt")
    if not isinstance(attempt, dict) or not attempt:
        raise _Invalid("verdict_record.attempt must be a non-empty object")
    gate_status, code = _STATUS_TO_CAPSULE[effect_status]
    effect = {
        "status": gate_status,
        "portable_status": effect_status,
        "evidence": "effect-status:%s" % effect_status,
    }
    if code is not None:
        effect["code"] = code
    return _ac.seal_capsule({"attempt": attempt, "effect": effect})
