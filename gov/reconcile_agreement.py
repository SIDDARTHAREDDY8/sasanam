#!/usr/bin/env python3
"""Five-valued decision/effect agreement table for the reconcile stage.

ADAPT of the five-valued agreement-table direction (re-derived
prose; nothing copied from the draft): where
gov/decision_effect_agreement.py is the binary auditor predicate
(agree or refuse), the reconcile stage needs a five-valued
verdict — decision.reported x effect.observed — so that "denial
honored", "execution without decision", "unobservable effect
side", and "step never ran" are distinguished instead of
collapsed into one refusal.

The two closed axes:

    decision.reported  in {permitted, denied, none}
    effect.observed     in {occurred, absent, unobservable}

The 9-cell table:

    permitted x occurred     -> agree
    permitted x absent       -> disagree   (a promised execution
                                            never happened — fail
                                            closed, the worst case)
    permitted x unobservable -> indeterminate
    denied    x occurred     -> disagree   (execution despite denial
                                            — fail closed)
    denied    x absent       -> agree      (denial honored)
    denied    x unobservable -> one-sided  (the denial record stands
                                            alone; the effect side is
                                            unobservable — recorded
                                            as such, not hidden)
    none      x occurred     -> one-sided  (effect without a decision
                                            record)
    none      x absent       -> one-sided
    none      x unobservable -> one-sided

``not-exercised`` is the fifth verdict and is NOT a table cell:
a permitted decision whose step never ran (the single-use
reservation was consumed elsewhere, or the step was superseded)
is distinguishable from disagree (a promised execution that
never happened) only by superseding evidence.
:func:`not_exercised_verdict` requires digest-linked superseding
evidence — a bare claim is refused
``agreement-input-unmapped``.

Layering (honest): gov/decision_effect_agreement.check_agreement
is the byte-level auditor predicate (recomputed capsules,
re-derived digests). The table is the coarser reconcile verdict:
it answers "what does the decision/effect pairing MEAN?" as one
of five closed machine verdicts, over axis values an auditor
already established. The table never contradicts the predicate:
a pair the predicate refuses has no honest table inputs.

Every verdict is recomputable: the verdict record carries a
``table_digest`` that :func:`verify_table_verdict` re-derives
from the carried fields — surgical edits fail closed.
:func:`seal_table_verdict` seals the verdict into a NEW action
capsule (gov/action_capsule.py, untouched) as digest-linked
evidence, following the decision_effect_agreement sealing
discipline — the existing mechanism is reused by convention,
never modified.

Agreement verdicts are evidence, never authority: any
authority-shaped use refuses ``agreement-not-authorization``.

Stdlib only. No network. $0.
"""

import hashlib

try:
    from . import action_capsule as _ac
except ImportError:  # standalone: modules beside this file
    import action_capsule as _ac

RECONCILE_VERSION = 1

# ----------------------------------------------------------------------
# Closed axes and closed verdict vocabulary.
# ----------------------------------------------------------------------

_DECISION_REPORTED = ("permitted", "denied", "none")
_EFFECT_OBSERVED = ("occurred", "absent", "unobservable")

_AGREE = "agree"
_DISAGREE = "disagree"
_NOT_EXERCISED = "not-exercised"
_INDETERMINATE = "indeterminate"
_ONE_SIDED = "one-sided"

_VERDICTS = (_AGREE, _DISAGREE, _NOT_EXERCISED, _INDETERMINATE,
             _ONE_SIDED)

_TABLE = {
    ("permitted", "occurred"): _AGREE,
    ("permitted", "absent"): _DISAGREE,
    ("permitted", "unobservable"): _INDETERMINATE,
    ("denied", "occurred"): _DISAGREE,
    ("denied", "absent"): _AGREE,
    ("denied", "unobservable"): _ONE_SIDED,
    ("none", "occurred"): _ONE_SIDED,
    ("none", "absent"): _ONE_SIDED,
    ("none", "unobservable"): _ONE_SIDED,
}


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class ReconcileAgreementError(Exception):
    """Base class for reconcile-agreement refusals. ``code`` is
    machine-readable."""

    code = "agreement-input-unmapped"


class _InputUnmapped(ReconcileAgreementError):
    code = "agreement-input-unmapped"


class _NotAuthorization(ReconcileAgreementError):
    code = "agreement-not-authorization"


# ----------------------------------------------------------------------
# Shape gates.
# ----------------------------------------------------------------------

_HEX64 = set("0123456789abcdef")


def _require_digest(value, field):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX64:
        raise _InputUnmapped(
            "field %r must be a 64-char hex digest" % field)
    return value


def _require_axis(value, axis, field):
    if not isinstance(value, str) or value not in axis:
        raise _InputUnmapped(
            "field %r must be one of %r" % (field, list(axis)))
    return value


def _require_reason(value):
    if not isinstance(value, str) or not value.strip() \
            or len(value) > 128:
        raise _InputUnmapped(
            "reason must be a non-empty string of at most 128 chars")
    return value


# ----------------------------------------------------------------------
# Verdict digests (recomputed, never copied from a claim).
# ----------------------------------------------------------------------

_DOMAIN = "reconcile-agreement/v1"


def _table_digest(verdict, decision_reported, effect_observed):
    body = {
        "domain": _DOMAIN,
        "verdict": verdict,
        "decision_reported": decision_reported,
        "effect_observed": effect_observed,
    }
    return hashlib.sha256(_ac.canonical_json_bytes(body)).hexdigest()


def _not_exercised_digest(decision_digest, superseding_digest, reason):
    body = {
        "domain": _DOMAIN,
        "verdict": _NOT_EXERCISED,
        "decision_digest": decision_digest,
        "superseding_digest": superseding_digest,
        "reason": reason,
    }
    return hashlib.sha256(_ac.canonical_json_bytes(body)).hexdigest()


# ----------------------------------------------------------------------
# The table (pure function, no global state).
# ----------------------------------------------------------------------


def agreement_table(decision_reported, effect_observed):
    """Return the five-valued agreement verdict for the closed
    decision.reported x effect.observed axes.

    Any input outside the closed axes — unknown strings, wrong
    types, None — refuses ``agreement-input-unmapped``. The
    returned record ``{v, verdict, decision_reported,
    effect_observed, table_digest}`` is digest-bound: the digest is
    recomputed from the verdict and its axes, so a verifier
    holding the record re-derives it with
    :func:`verify_table_verdict` rather than trusting the claim.

    ``not-exercised`` is not a table cell; see
    :func:`not_exercised_verdict` for the evidence-bound path.
    """
    decision_reported = _require_axis(
        decision_reported, _DECISION_REPORTED, "decision_reported")
    effect_observed = _require_axis(
        effect_observed, _EFFECT_OBSERVED, "effect_observed")
    verdict = _TABLE[(decision_reported, effect_observed)]
    return {
        "v": RECONCILE_VERSION,
        "verdict": verdict,
        "decision_reported": decision_reported,
        "effect_observed": effect_observed,
        "table_digest": _table_digest(verdict, decision_reported,
                                      effect_observed),
    }


def not_exercised_verdict(decision_digest, superseding_digest, reason):
    """Bind a not-exercised verdict to digest-linked evidence.

    A permitted decision whose step never ran — the single-use
    reservation was consumed elsewhere, or the step was superseded
    — is evidence-distinguishable from disagree (a promised
    execution that never happened) ONLY when the superseding
    event is named by digest. A bare claim (non-digest evidence)
    refuses ``agreement-input-unmapped``.

    Honest boundary: the verdict commits to the digests; it does
    not independently prove the superseding record's contents —
    the auditor checks the superseding digest against their own
    reservation/consumption records.
    """
    decision_digest = _require_digest(decision_digest,
                                      "decision_digest")
    superseding_digest = _require_digest(superseding_digest,
                                         "superseding_digest")
    reason = _require_reason(reason)
    return {
        "v": RECONCILE_VERSION,
        "verdict": _NOT_EXERCISED,
        "decision_digest": decision_digest,
        "superseding_digest": superseding_digest,
        "reason": reason,
        "table_digest": _not_exercised_digest(decision_digest,
                                              superseding_digest,
                                              reason),
    }


def verify_table_verdict(verdict):
    """Recompute a verdict's digest from its carried fields.

    Refuses ``agreement-input-unmapped`` on any non-verdict input
    or any surgical edit (the recomputed digest no longer commits
    to the record). Returns the recomputed digest on success.
    """
    if not isinstance(verdict, dict):
        raise _InputUnmapped("verdict must be a dict")
    value = verdict.get("verdict")
    if value == _NOT_EXERCISED:
        decision_digest = _require_digest(
            verdict.get("decision_digest"), "decision_digest")
        superseding_digest = _require_digest(
            verdict.get("superseding_digest"), "superseding_digest")
        reason = _require_reason(verdict.get("reason"))
        recomputed = _not_exercised_digest(decision_digest,
                                           superseding_digest,
                                           reason)
    elif value in _VERDICTS:
        decision_reported = _require_axis(
            verdict.get("decision_reported"), _DECISION_REPORTED,
            "decision_reported")
        effect_observed = _require_axis(
            verdict.get("effect_observed"), _EFFECT_OBSERVED,
            "effect_observed")
        # The verdict must be the table's verdict for these axes:
        # a verdict record claiming agree for permitted x absent
        # is a forgery the recompute catches.
        if value != _TABLE[(decision_reported, effect_observed)]:
            raise _InputUnmapped(
                "verdict %r is not the table verdict for %r x %r"
                % (value, decision_reported, effect_observed))
        recomputed = _table_digest(value, decision_reported,
                                   effect_observed)
    else:
        raise _InputUnmapped(
            "verdict must be one of %r" % list(_VERDICTS))
    claimed = verdict.get("table_digest")
    if not isinstance(claimed, str) or claimed != recomputed:
        raise _InputUnmapped(
            "the verdict digest does not recompute from the "
            "carried fields")
    return recomputed


# ----------------------------------------------------------------------
# Sealed table-verdict evidence (digest-linked; action_capsule.py
# untouched; the decision_effect_agreement sealing discipline).
# ----------------------------------------------------------------------

_TABLE_ACTION = "reconcile-agreement-table"

_TABLE_ATTEMPT_FIELDS = ("verdict", "decision_reported",
                         "effect_observed", "table_digest")


def seal_table_verdict(decision_reported, effect_observed):
    """Seal a table verdict into a new action capsule.

    Runs :func:`agreement_table` first — unmapped inputs fail
    closed before any evidence is sealed. The capsule's attempt
    carries the verdict and its axes, and its effect carries the
    recomputed ``table_digest`` as evidence, so the sealed record
    is digest-linked and replayable by any verifier holding the
    bytes.
    """
    verdict = agreement_table(decision_reported, effect_observed)
    return _ac.seal_capsule({
        "attempt": {
            "action": _TABLE_ACTION,
            "verdict": verdict["verdict"],
            "decision_reported": verdict["decision_reported"],
            "effect_observed": verdict["effect_observed"],
            "table_digest": verdict["table_digest"],
        },
        "effect": {
            "status": "admitted",
            "evidence": verdict["table_digest"],
        },
    })


def table_digest_of(capsule):
    """Recompute the table digest from a sealed table-verdict capsule.

    Replays the capsule and re-derives the digest from the sealed
    attempt bytes — the value is recomputed, never copied from a
    claim. Tampering refuses with the original module codes, or
    ``agreement-input-unmapped`` when the sealed evidence no
    longer commits to the sealed attempt bytes.
    """
    body = _ac.verify_capsule(capsule)
    attempt = body.get("attempt")
    effect = body.get("effect")
    if not isinstance(attempt, dict) or not isinstance(effect, dict):
        raise _InputUnmapped("not a table-verdict capsule body")
    if attempt.get("action") != _TABLE_ACTION:
        raise _InputUnmapped("capsule is not a reconcile-agreement table")
    for field in _TABLE_ATTEMPT_FIELDS:
        if field not in attempt:
            raise _InputUnmapped(
                "table-verdict capsule attempt is missing %r" % field)
    value = _require_axis(
        attempt["verdict"], _VERDICTS, "verdict")
    decision_reported = _require_axis(
        attempt["decision_reported"], _DECISION_REPORTED,
        "decision_reported")
    effect_observed = _require_axis(
        attempt["effect_observed"], _EFFECT_OBSERVED,
        "effect_observed")
    if value != _TABLE[(decision_reported, effect_observed)]:
        raise _InputUnmapped(
            "sealed verdict %r is not the table verdict for %r x %r"
            % (value, decision_reported, effect_observed))
    recomputed = _table_digest(value, decision_reported,
                               effect_observed)
    if str(effect.get("evidence", "")) != recomputed:
        # The capsule itself replays, but its evidence field was
        # surgically edited to a digest that does not commit to the
        # sealed attempt bytes.
        raise _InputUnmapped(
            "the sealed table evidence does not match the "
            "recomputed table digest")
    return recomputed


# ----------------------------------------------------------------------
# Authority boundary.
# ----------------------------------------------------------------------


def deny_authority_use(artifact):
    """Refuse any attempt to use an agreement artifact as authority.

    An agreement verdict describes a past decision/effect pairing;
    it never authorizes anything. Accepts a table verdict or a
    not-exercised verdict (both verified by shape and digest
    recompute), or a sealed table-verdict capsule (replayed
    through gov/action_capsule.verify_capsule and confirmed to be
    a table-verdict capsule — tampering refuses with the original
    module codes). Malformed input refuses
    ``agreement-input-unmapped`` first, so this is also the safe
    seam to run any agreement-shaped input through.
    """
    if not isinstance(artifact, dict):
        raise _InputUnmapped("agreement artifact must be a dict")
    if "capsule_digest" in artifact and "jcs_json" in artifact:
        # Sealed table-verdict capsule: replay it and confirm it
        # is one. verify_capsule's own tamper errors propagate with
        # the original module codes (fail closed, honest).
        body = _ac.verify_capsule(artifact)
        attempt = body.get("attempt")
        if not isinstance(attempt, dict) or \
                attempt.get("action") != _TABLE_ACTION:
            raise _InputUnmapped(
                "capsule is not a reconcile-agreement table")
        for field in _TABLE_ATTEMPT_FIELDS:
            if field not in attempt:
                raise _InputUnmapped(
                    "table-verdict capsule attempt is missing %r"
                    % field)
    else:
        # A verdict record: verify by digest recompute. Any shape
        # or digest failure is an unmapped input, refused first.
        verify_table_verdict(artifact)
    raise _NotAuthorization(
        "agreement evidence describes a past decision/effect "
        "pairing; it never authorizes anything")
