#!/usr/bin/env python3
"""Decision-vs-effect agreement before acceptance.

ADAPT of the audit-record decision/effect agreement direction
(re-derived prose; nothing copied from the draft): an auditor must
never accept a decision/execution pair unless the decision side and
the effect side AGREE — on what was authorized, on what was
executed, and on the order they happened in. A decision without a
matching execution is not a failure; it is evidence of
non-execution. An execution without a decision is refused outright.

:func:`check_agreement` is a PURE function (no global state, no
registries): it recomputes both sides from their digests — the
gov/receipt_pairs.py discipline, claims are never trusted — and
fails closed on any disagreement:

* ``decision-effect-decision-drift``: the decision receipt's claimed
  decision digest does not match the digest recomputed from its
  verdict bytes (tampered bytes are caught by recomputation, never
  by trusting the claim);
* ``decision-effect-effect-drift``: the execution receipt's claimed
  effect status or effect digest does not match the observation
  re-classified through gov/effect_status.classify and re-sealed via
  gov/effect_status.capsule_from_effect;
* ``decision-effect-disagreement``: the recomputed ATTEMPT digest of
  the execution side does not equal the recomputed attempt digest of
  the decision side (what was executed is not what was decided), or
  the execution's backLink does not equal the recomputed decision
  digest (swapped effect);
* ``decision-effect-effect-absent``: a decision is presented with no
  execution record — absence is evidence of non-execution, not
  failure; the pair is never accepted on the decision alone;
* ``decision-effect-extra-effect``: an execution record is presented
  with no decision authorizing it;
* ``decision-effect-time-inversion``: the effect's timestamp
  precedes the decision's.

Layering (honest): gov/receipt_pairs.recompute_pair is the full
tamper re-verification seam (byte-identical verdict records,
re-derived chain). :func:`check_agreement` is the coarser auditor
predicate: it answers "do the decision and the effect agree?" as a
single boolean verdict plus a digest, usable BEFORE or WITHOUT the
full recompute, and over records an auditor collected
independently.

:func:`seal_agreement` seals a successful agreement verdict into a
NEW action capsule (gov/action_capsule.py, untouched) — the
agreement digest is digest-linked evidence that receipt-pair
chains, or the wave-229 checkpoint verifier, can fold into digest
lists as an additional acceptance predicate: the agreement is
usable as ``check_agreement(decision_record, effect_record)`` with
its returned ``agreement_digest`` carried in the checkpoint's
digest evidence.

Agreement evidence is evidence, never authorization: any
authority-shaped use refuses
``decision-effect-not-authorization``.

Stdlib only. No network. $0.
"""

import hashlib
import hmac
import math

try:
    from . import action_capsule as _ac
    from . import effect_status as _es
except ImportError:  # standalone: modules beside this file
    import action_capsule as _ac
    import effect_status as _es

AGREEMENT_VERSION = 1


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class AgreementError(Exception):
    """Base class for decision-effect agreement refusals. ``code`` is
    machine-readable."""

    code = "decision-effect-refused"


class _Malformed(AgreementError):
    code = "decision-effect-malformed"


class _DecisionDrift(AgreementError):
    code = "decision-effect-decision-drift"


class _EffectDrift(AgreementError):
    code = "decision-effect-effect-drift"


class _Disagreement(AgreementError):
    code = "decision-effect-disagreement"


class _EffectAbsent(AgreementError):
    code = "decision-effect-effect-absent"


class _ExtraEffect(AgreementError):
    code = "decision-effect-extra-effect"


class _TimeInversion(AgreementError):
    code = "decision-effect-time-inversion"


class _NotAuthorization(AgreementError):
    code = "decision-effect-not-authorization"


# ----------------------------------------------------------------------
# Shape gates.
# ----------------------------------------------------------------------

_HEX64 = set("0123456789abcdef")

_DECISION_KIND = "decision-receipt"
_EXECUTION_KIND = "execution-receipt"

_DECISION_REQUIRED = ("decision_digest", "verdict_record", "capsule",
                      "issued_at")
_EXECUTION_REQUIRED = ("decision_backlink", "verdict_record", "observation",
                       "effect_digest", "effect_status", "executed_at",
                       "capsule")


def _require_digest(value, field):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX64:
        raise _Malformed(
            "field %r must be a 64-char hex digest" % field)
    return value


def _require_timestamp(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Malformed(
            "field %r must be seconds-since-epoch, got %r"
            % (field, value))
    if not math.isfinite(value) or value < 0:
        raise _Malformed(
            "field %r must be a finite non-negative number, got %r"
            % (field, value))
    return float(value)


def _check_receipt_shape(receipt, kind, required):
    """Fail closed on any malformed receipt record."""
    if not isinstance(receipt, dict):
        raise _Malformed("receipt must be a dict")
    if receipt.get("kind") != kind:
        raise _Malformed(
            "expected kind %r, got %r" % (kind, receipt.get("kind")))
    for field in required:
        if field not in receipt:
            raise _Malformed(
                "receipt of kind %r is missing field %r" % (kind, field))


def _agreement_digest(decision_digest, effect_digest, issued_at,
                      executed_at):
    """Recompute the agreement digest; never copied from a claim.

    Timestamps are seconds-since-epoch floats, which have no
    canonical JSON encoding (the JCS gate refuses them), so they
    enter the digest as their repr() strings — deterministic within
    one interpreter, and identical on both the seal and verify
    sides because both recompute from the same values.
    """
    body = {
        "agreement": True,
        "decision_digest": decision_digest,
        "effect_digest": effect_digest,
        "issued_at": repr(issued_at),
        "executed_at": repr(executed_at),
    }
    return hashlib.sha256(_ac.canonical_json_bytes(body)).hexdigest()


# ----------------------------------------------------------------------
# The agreement predicate (pure function, no global state).
# ----------------------------------------------------------------------


def check_agreement(decision_receipt, execution_receipt):
    """Check that a decision and its execution agree; recompute,
    never trust.

    1. Absence: a decision with no execution record refuses
       ``decision-effect-effect-absent`` (absence is evidence of
       non-execution, never acceptance); an execution record with
       no decision refuses ``decision-effect-extra-effect``.
    2. Replay: each receipt's carried capsule is replayed through
       gov/action_capsule.verify_capsule — tampered capsule bytes
       refuse with the original module codes.
    3. Re-derive the decision digest from the carried verdict bytes
       via gov/action_capsule.seal_capsule; disagreement with the
       claim refuses ``decision-effect-decision-drift``.
    4. Re-classify the carried observation and re-seal the effect;
       a status or digest disagreement refuses
       ``decision-effect-effect-drift``.
    5. Binding and agreement: the execution's backLink must equal
       the recomputed decision digest, and the recomputed attempt
       digest of the execution side must equal the recomputed
       attempt digest of the decision side — otherwise
       ``decision-effect-disagreement``.
    6. Order: executed_at must be >= issued_at, else
       ``decision-effect-time-inversion``.

    Returns the RECOMPUTED agreement verdict ``{v, agreement,
    decision_digest, effect_digest, effect_status, issued_at,
    executed_at, agreement_digest}``; ``agreement_digest`` is a
    fresh SHA-256 derivation foldable into checkpoint digest lists
    as an additional acceptance predicate.
    """
    # 1. Absence and malformed gates (fail closed).
    # None has absence semantics; any other non-dict is malformed
    # input — never given the absence reading.
    if decision_receipt is None or execution_receipt is None:
        if decision_receipt is None and execution_receipt is None:
            raise _Malformed("nothing to agree on: both records absent")
        other = execution_receipt if decision_receipt is None \
            else decision_receipt
        if not isinstance(other, dict):
            raise _Malformed("records must be dicts")
        if decision_receipt is None:
            raise _ExtraEffect(
                "an execution record is presented with no decision "
                "authorizing it")
        raise _EffectAbsent(
            "the decision is presented with no execution record; "
            "absence is evidence of non-execution, never acceptance")
    if not isinstance(decision_receipt, dict) or \
            not isinstance(execution_receipt, dict):
        raise _Malformed("records must be dicts")
    _check_receipt_shape(decision_receipt, _DECISION_KIND,
                         _DECISION_REQUIRED)
    _check_receipt_shape(execution_receipt, _EXECUTION_KIND,
                         _EXECUTION_REQUIRED)

    # 2. Replay the carried capsules (tamper refuses here).
    _ac.verify_capsule(decision_receipt["capsule"])
    _ac.verify_capsule(execution_receipt["capsule"])

    # 3. Re-derive the decision digest from the verdict bytes.
    decision_record = decision_receipt["verdict_record"]
    if not isinstance(decision_record, dict):
        raise _Malformed("decision receipt must carry its verdict_record")
    resealed_decision = _ac.seal_capsule(decision_record)
    decision_digest = resealed_decision["verdict_digest"]
    claimed_decision = _require_digest(
        decision_receipt["decision_digest"], "decision_digest")
    if not hmac.compare_digest(decision_digest, claimed_decision):
        raise _DecisionDrift(
            "recomputed decision digest does not match the claim")
    # The carried capsule must commit to the same verdict bytes.
    if not hmac.compare_digest(
            str(decision_receipt["capsule"]["verdict_digest"]),
            decision_digest):
        raise _DecisionDrift(
            "the carried capsule does not commit to the carried "
            "verdict bytes")

    # 4. Re-classify the observation and re-derive the effect digest.
    execution_record = execution_receipt["verdict_record"]
    if not isinstance(execution_record, dict):
        raise _Malformed("execution receipt must carry its verdict_record")
    reclassified = _es.classify(execution_receipt["observation"])
    if reclassified != execution_receipt.get("effect_status"):
        raise _EffectDrift(
            "re-classified effect status does not match the claim")
    resealed_effect = _es.capsule_from_effect(execution_record,
                                              reclassified)
    effect_digest = resealed_effect["effect_digest"]
    claimed_effect = _require_digest(
        execution_receipt["effect_digest"], "effect_digest")
    if not hmac.compare_digest(effect_digest, claimed_effect):
        raise _EffectDrift(
            "recomputed effect digest does not match the claim")

    # 5. Binding: backLink, then attempt-digest agreement.
    backlink = _require_digest(
        execution_receipt["decision_backlink"], "decision_backlink")
    if not hmac.compare_digest(backlink, decision_digest):
        raise _Disagreement(
            "the execution's backLink does not equal the recomputed "
            "decision digest")
    decision_attempt = hashlib.sha256(_ac.canonical_json_bytes(
        decision_record["attempt"])).hexdigest()
    execution_attempt = hashlib.sha256(_ac.canonical_json_bytes(
        execution_record["attempt"])).hexdigest()
    if not hmac.compare_digest(decision_attempt, execution_attempt):
        raise _Disagreement(
            "what was executed is not what was decided: the "
            "recomputed attempt digests differ")

    # 6. Time ordering: the effect cannot precede the decision.
    issued_at = _require_timestamp(decision_receipt.get("issued_at"),
                                   "issued_at")
    executed_at = _require_timestamp(execution_receipt.get("executed_at"),
                                     "executed_at")
    if executed_at < issued_at:
        raise _TimeInversion(
            "executed_at %r precedes the decision issued_at %r"
            % (executed_at, issued_at))

    digest = _agreement_digest(decision_digest, effect_digest, issued_at,
                               executed_at)
    return {
        "v": AGREEMENT_VERSION,
        "agreement": True,
        "decision_digest": decision_digest,
        "effect_digest": effect_digest,
        "effect_status": reclassified,
        "issued_at": issued_at,
        "executed_at": executed_at,
        "agreement_digest": digest,
    }


# ----------------------------------------------------------------------
# Sealed agreement evidence (digest-linked; action_capsule.py untouched).
# ----------------------------------------------------------------------

_AGREEMENT_ACTION = "decision-effect-agreement"


def seal_agreement(decision_receipt, execution_receipt):
    """Seal a successful agreement verdict into a new action capsule.

    Runs :func:`check_agreement` first — disagreement fails closed
    before any evidence is sealed. The capsule's attempt carries the
    agreement's inputs (decision/effect digests, timestamps) and its
    effect carries the recomputed ``agreement_digest`` as evidence,
    so the sealed record is digest-linked and replayable by any
    verifier holding the bytes.
    """
    verdict = check_agreement(decision_receipt, execution_receipt)
    # Timestamps are floats: no canonical JSON encoding, so they
    # enter the capsule as repr() strings (same canonicalization
    # the digest is computed over). verify re-derives the digest
    # from these strings, never trusting the sealed evidence.
    return _ac.seal_capsule({
        "attempt": {
            "action": _AGREEMENT_ACTION,
            "decision_digest": verdict["decision_digest"],
            "effect_digest": verdict["effect_digest"],
            "issued_at": repr(verdict["issued_at"]),
            "executed_at": repr(verdict["executed_at"]),
        },
        "effect": {
            "status": "admitted",
            "evidence": verdict["agreement_digest"],
        },
    })


def agreement_digest_of(capsule):
    """Recompute the agreement digest from a sealed agreement capsule.

    Replays the capsule and re-derives the digest from the sealed
    attempt bytes — the value is recomputed, never copied from a
    claim. Tampering refuses with the original module codes.
    """
    body = _ac.verify_capsule(capsule)
    attempt = body.get("attempt")
    effect = body.get("effect")
    if not isinstance(attempt, dict) or not isinstance(effect, dict):
        raise _Malformed("not an agreement capsule body")
    if attempt.get("action") != _AGREEMENT_ACTION:
        raise _Malformed("capsule is not a decision-effect agreement")
    for field in ("decision_digest", "effect_digest", "issued_at",
                  "executed_at"):
        if field not in attempt:
            raise _Malformed(
                "agreement capsule attempt is missing %r" % field)
    decision_digest = _require_digest(attempt["decision_digest"],
                                      "decision_digest")
    effect_digest = _require_digest(attempt["effect_digest"],
                                    "effect_digest")
    # The attempt carries repr() timestamp strings (floats have no
    # canonical JSON encoding); the digest is re-derived from them.
    for field in ("issued_at", "executed_at"):
        if not isinstance(attempt[field], str):
            raise _Malformed(
                "agreement capsule attempt %r must be a timestamp "
                "string" % field)
    try:
        issued_at = _require_timestamp(float(attempt["issued_at"]),
                                       "issued_at")
        executed_at = _require_timestamp(float(attempt["executed_at"]),
                                         "executed_at")
    except (TypeError, ValueError):
        raise _Malformed(
            "agreement capsule attempt timestamps are not numeric "
            "strings") from None
    recomputed = _agreement_digest(decision_digest, effect_digest,
                                   issued_at, executed_at)
    if not hmac.compare_digest(str(effect.get("evidence", "")),
                               recomputed):
        # The capsule itself replays, but its evidence field was
        # surgically edited to a digest that does not commit to the
        # sealed attempt bytes. Generic refusal: the sealed evidence
        # is not what it claims to be.
        raise AgreementError(
            "the sealed agreement evidence does not match the "
            "recomputed agreement digest")
    return recomputed


# ----------------------------------------------------------------------
# Authority boundary.
# ----------------------------------------------------------------------


def deny_authority_use(agreement):
    """Refuse any attempt to use an agreement artifact as authority.

    Agreement evidence describes that a decision and its execution
    agreed; it never authorizes anything. Accepts either a
    well-formed agreement verdict (from :func:`check_agreement`) or
    a sealed agreement capsule (from :func:`seal_agreement`) — the
    capsule is replayed through gov/action_capsule.verify_capsule
    and confirmed to be an agreement capsule (tampering refuses
    with the original module codes). Malformed input refuses
    ``decision-effect-malformed`` first, so this is also the safe
    seam to run any agreement-shaped input through.
    """
    if not isinstance(agreement, dict):
        raise _Malformed("agreement artifact must be a dict")
    if "capsule_digest" in agreement and "jcs_json" in agreement:
        # Sealed agreement capsule: replay it and confirm it is
        # one. verify_capsule's own tamper errors propagate with
        # the original module codes (fail closed, honest).
        body = _ac.verify_capsule(agreement)
        attempt = body.get("attempt")
        if not isinstance(attempt, dict) or \
                attempt.get("action") != _AGREEMENT_ACTION:
            raise _Malformed("capsule is not a decision-effect agreement")
    elif agreement.get("agreement") is True and \
            agreement.get("v") == AGREEMENT_VERSION:
        _require_digest(agreement.get("agreement_digest"),
                        "agreement_digest")
    else:
        raise _Malformed("not a well-formed agreement artifact")
    raise _NotAuthorization(
        "agreement evidence describes a past agreement; it never "
        "authorizes anything")
