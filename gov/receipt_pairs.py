#!/usr/bin/env python3
"""Recomputable decision<->execution receipt pairs.

Re-derived pattern (the external receipt draft is not in this repo;
nothing copied): a decision receipt and an execution receipt are
bound by DIGEST, never by claim, and :func:`recompute_pair` RE-RUNS
every consistency check instead of trusting claimed fields.

* ``issue_decision_receipt(verdict_record, issued_at)`` seals the
  verdict into an action capsule (gov/action_capsule.py) and records
  its digest as the decision digest.
* ``issue_execution_receipt(verdict_record, observation,
  decision_receipt, executed_at)`` classifies the observation via
  gov/effect_status.classify, seals the effect capsule, and binds it
  to the decision receipt's digest as a backLink.
* ``bind(execution_receipt, decision_receipt)`` refuses
  ``receipt-pair-decision-mismatch`` when the backLink does not equal
  the decision digest. The pair is bound by digest, never by claim.
* ``recompute_pair(pair)`` re-runs everything: it re-seals the
  decision verdict record and compares the re-derived decision
  digest (drift -> ``receipt-pair-decision-drift``); it re-runs
  :func:`effect_status.classify` on the carried observation and
  compares the status AND re-derives the effect digest (drift ->
  ``receipt-pair-effect-drift``); it checks
  executed_at >= issued_at (inversion -> ``receipt-pair-time-inversion``).
  The summary it returns is RECOMPUTED, never asserted: ``pair_digest``
  is a fresh SHA-256 derivation, and the pair's two capsules are
  chained through gov/action_capsule.chain_capsules with an
  "acknowledges" link from the execution capsule to the decision
  capsule (tampered capsules refuse with the original module codes).

Receipts are evidence, never authorization. Presenting one as
authority refuses ``receipt-pair-not-authorization`` (see
:func:`deny_authority_use`). Authority-shaped fields smuggled into a
verdict record refuse at issuance via the action-capsule's own
``capsule-not-authorization``. Timestamps are seconds-since-epoch
numbers (never booleans); malformed receipts refuse
``receipt-pair-malformed``; unknown receipt fields refuse
``receipt-pair-unknown-field``.

Stdlib only. No network. $0.
"""

import hashlib
import math

try:
    from . import action_capsule as _ac
    from . import effect_status as _es
except ImportError:  # standalone: modules beside this file
    import action_capsule as _ac
    import effect_status as _es

RECEIPT_VERSION = 1


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class ReceiptPairError(Exception):
    """Base class for receipt-pair refusals. ``code`` is
    machine-readable."""

    code = "receipt-pair-refused"


class _Mismatch(ReceiptPairError):
    code = "receipt-pair-decision-mismatch"


class _DecisionDrift(ReceiptPairError):
    code = "receipt-pair-decision-drift"


class _EffectDrift(ReceiptPairError):
    code = "receipt-pair-effect-drift"


class _TimeInversion(ReceiptPairError):
    code = "receipt-pair-time-inversion"


class _NotAuthorization(ReceiptPairError):
    code = "receipt-pair-not-authorization"


class _Malformed(ReceiptPairError):
    code = "receipt-pair-malformed"


class _UnknownField(ReceiptPairError):
    code = "receipt-pair-unknown-field"


# ----------------------------------------------------------------------
# Shape gates.
# ----------------------------------------------------------------------


_DECISION_FIELDS = frozenset({
    "v", "kind", "decision_digest", "verdict", "verdict_record_digest",
    "verdict_record", "capsule", "issued_at",
})

_EXECUTION_FIELDS = frozenset({
    "v", "kind", "decision_backlink", "decision_issued_at", "effect_digest",
    "effect_capsule_digest", "effect_status", "observation",
    "verdict_record", "capsule", "executed_at",
})

_HEX64 = set("0123456789abcdef")


def _require_digest(value, field):
    if not isinstance(value, str) or len(value) != 64 \
            or set(value) - _HEX64:
        raise _Malformed(
            "receipt field %r must be a 64-char hex digest" % field)


def _require_timestamp(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Malformed(
            "receipt field %r must be seconds-since-epoch, got %r"
            % (field, value))
    if not math.isfinite(value) or value < 0:
        raise _Malformed(
            "receipt field %r must be a finite non-negative number, "
            "got %r" % (field, value))
    return float(value)


def _check_receipt_shape(receipt, kind, allowed):
    """Fail closed on any malformed or unknown receipt field."""
    if not isinstance(receipt, dict):
        raise _Malformed("receipt must be a dict")
    unknown = set(receipt.keys()) - allowed
    if unknown:
        raise _UnknownField(
            "unknown receipt fields: %s" % sorted(unknown))
    if receipt.get("v") != RECEIPT_VERSION:
        raise _Malformed(
            "receipt version must be %r, got %r"
            % (RECEIPT_VERSION, receipt.get("v")))
    if receipt.get("kind") != kind:
        raise _Malformed(
            "expected kind %r, got %r" % (kind, receipt.get("kind")))


def _verdict_label(verdict_record):
    effect = verdict_record["effect"]
    if effect.get("status") == "refused":
        return "refused:%s" % effect.get("code")
    return "admitted"


# ----------------------------------------------------------------------
# Issuance.
# ----------------------------------------------------------------------


def issue_decision_receipt(verdict_record, issued_at):
    """Seal a decision receipt from a verdict record.

    ``verdict_record`` is ``{"attempt": {...}, "effect": {...}}``;
    it is sealed via gov/action_capsule.seal_capsule (which refuses
    ``capsule-not-authorization`` for authority-shaped fields and
    fails closed on any malformed verdict). ``issued_at`` is
    seconds-since-epoch.

    Returns a decision receipt ``{v, kind, decision_digest, verdict,
    verdict_record_digest, verdict_record, capsule, issued_at}`` where
    ``decision_digest`` is the capsule's ``verdict_digest``.
    """
    issued = _require_timestamp(issued_at, "issued_at")
    if not isinstance(verdict_record, dict):
        raise _Malformed("verdict_record must be a dict")
    capsule = _ac.seal_capsule(verdict_record)
    return {
        "v": RECEIPT_VERSION,
        "kind": "decision-receipt",
        "decision_digest": capsule["verdict_digest"],
        "verdict": _verdict_label(verdict_record),
        "verdict_record_digest": capsule["capsule_digest"],
        "verdict_record": verdict_record,
        "capsule": capsule,
        "issued_at": issued,
    }


def issue_execution_receipt(verdict_record, observation, decision_receipt,
                            executed_at):
    """Seal an execution receipt bound by backLink to a decision receipt.

    ``observation`` is ``{"outcome": ..., "executor_may_have_accepted":
    bool}`` classified via gov/effect_status.classify (which refuses
    ``effect-status-ambiguous-refused`` for post-acceptance "unknown"
    and ``effect-status-invalid`` for malformed observations). The
    effect capsule is sealed via gov/effect_status.capsule_from_effect,
    binding the classified portable status by digest.
    ``decision_receipt`` must be a well-formed decision receipt; the
    backLink is its decision digest. ``executed_at`` is
    seconds-since-epoch.

    Returns an execution receipt ``{v, kind, decision_backlink,
    decision_issued_at, effect_digest, effect_capsule_digest, effect_status,
    observation, verdict_record, capsule, executed_at}``.
    """
    executed = _require_timestamp(executed_at, "executed_at")
    _check_receipt_shape(decision_receipt, "decision-receipt",
                         _DECISION_FIELDS)
    if not isinstance(verdict_record, dict):
        raise _Malformed("verdict_record must be a dict")
    status = _es.classify(observation)
    capsule = _es.capsule_from_effect(verdict_record, status)
    _require_digest(decision_receipt["decision_digest"], "decision_digest")
    return {
        "v": RECEIPT_VERSION,
        "kind": "execution-receipt",
        "decision_backlink": decision_receipt["decision_digest"],
        "decision_issued_at": decision_receipt["issued_at"],
        "effect_digest": capsule["effect_digest"],
        "effect_capsule_digest": capsule["capsule_digest"],
        "effect_status": status,
        "observation": observation,
        "verdict_record": verdict_record,
        "capsule": capsule,
        "executed_at": executed,
    }


# ----------------------------------------------------------------------
# Binding.
# ----------------------------------------------------------------------


def bind(execution_receipt, decision_receipt):
    """Bind an execution receipt to a decision receipt by digest.

    Refuses ``receipt-pair-decision-mismatch`` when the execution
    receipt's ``decision_backlink`` does not equal the decision
    receipt's ``decision_digest`` — the pair is bound by digest, never
    by claim. Returns the pair ``{v, pair_kind, decision_receipt,
    execution_receipt}``.
    """
    _check_receipt_shape(decision_receipt, "decision-receipt",
                         _DECISION_FIELDS)
    _check_receipt_shape(execution_receipt, "execution-receipt",
                         _EXECUTION_FIELDS)
    _require_digest(decision_receipt["decision_digest"], "decision_digest")
    _require_digest(execution_receipt["decision_backlink"],
                    "decision_backlink")
    if execution_receipt["decision_backlink"] != \
            decision_receipt["decision_digest"]:
        raise _Mismatch(
            "execution receipt backLink does not equal the decision "
            "receipt digest")
    return {
        "v": RECEIPT_VERSION,
        "pair_kind": "decision-execution-pair",
        "decision_receipt": decision_receipt,
        "execution_receipt": execution_receipt,
    }


# ----------------------------------------------------------------------
# Recomputation (the seam that refuses trust).
# ----------------------------------------------------------------------


def recompute_pair(pair):
    """Re-run every consistency check on a bound pair; trust nothing
    claimed.

    1. Re-bind: the backLink must equal the decision digest
       (``receipt-pair-decision-mismatch`` otherwise).
    2. Re-derive: re-seal the decision receipt's verdict record via
       gov/action_capsule.seal_capsule and compare the re-derived
       ``verdict_digest`` (and ``capsule_digest``) against the claims;
       mismatch refuses ``receipt-pair-decision-drift``. The
       execution receipt's verdict record must be byte-identical to
       the decision receipt's, or the same refusal fires.
    3. Re-classify: run gov/effect_status.classify on the carried
       observation and compare the status against the claim; re-seal
       the effect via gov/effect_status.capsule_from_effect and
       compare the effect digest against the claim. Either mismatch
       refuses ``receipt-pair-effect-drift``.
    4. Order: executed_at must be >= the decision issued_at, else
       ``receipt-pair-time-inversion``.

    Returns the RECOMPUTED summary ``{v, recomputed, pair_digest,
    decision_digest, verdict, effect_status, issued_at, executed_at,
    chain}`` where ``pair_digest`` is a fresh SHA-256 derivation (not
    copied from any receipt) and ``chain`` is the
    gov/action_capsule.chain_capsules commitment over the re-sealed
    capsules with an "acknowledges" link from the execution capsule
    to the decision capsule.
    """
    if not isinstance(pair, dict):
        raise _Malformed("pair must be a dict")
    decision = pair.get("decision_receipt")
    execution = pair.get("execution_receipt")
    if decision is None or execution is None:
        raise _Malformed(
            "pair must carry decision_receipt and execution_receipt")
    # 1. Re-bind (digest equality, unknown fields fail closed).
    bind(execution, decision)

    # 2. Re-derive the decision digest from the carried verdict record.
    verdict_record = decision.get("verdict_record")
    if not isinstance(verdict_record, dict):
        raise _Malformed("decision receipt must carry its verdict_record")
    resealed_decision = _ac.seal_capsule(verdict_record)
    if resealed_decision["verdict_digest"] != decision.get(
            "decision_digest") or resealed_decision["capsule_digest"] != \
            decision.get("verdict_record_digest"):
        raise _DecisionDrift(
            "re-derived decision digest does not match the claimed "
            "receipt values")
    exe_verdict_record = execution.get("verdict_record")
    if not isinstance(exe_verdict_record, dict):
        raise _Malformed("execution receipt must carry its verdict_record")
    if _ac.canonical_json_bytes(exe_verdict_record) != \
            _ac.canonical_json_bytes(verdict_record):
        raise _DecisionDrift(
            "execution receipt's verdict record differs from the "
            "decision receipt's")

    # 3. Re-classify the observation and re-derive the effect digest.
    observation = execution.get("observation")
    reclassified = _es.classify(observation)
    if reclassified != execution.get("effect_status"):
        raise _EffectDrift(
            "re-classified effect status %r does not match claimed %r"
            % (reclassified, execution.get("effect_status")))
    resealed_effect = _es.capsule_from_effect(exe_verdict_record,
                                              reclassified)
    if resealed_effect["effect_digest"] != execution.get("effect_digest") \
            or resealed_effect["capsule_digest"] != execution.get(
                "effect_capsule_digest"):
        raise _EffectDrift(
            "re-derived effect digests do not match the claimed values")

    # 4. Time ordering: effect cannot precede the decision it executed.
    issued_at = _require_timestamp(decision.get("issued_at"), "issued_at")
    executed_at = _require_timestamp(execution.get("executed_at"),
                                     "executed_at")
    if executed_at < issued_at:
        raise _TimeInversion(
            "executed_at %r precedes the decision issued_at %r"
            % (executed_at, issued_at))

    # The summary is recomputed from re-derived values, never copied.
    pair_digest = hashlib.sha256(
        (resealed_decision["verdict_digest"]
         + resealed_effect["effect_digest"]
         + reclassified
         + repr(executed_at)).encode("utf-8")).hexdigest()
    chain = _ac.chain_capsules(
        [resealed_decision, resealed_effect],
        links=[{"kind": "acknowledges",
                "target_capsule_digest": resealed_decision["capsule_digest"]}])
    return {
        "v": RECEIPT_VERSION,
        "recomputed": True,
        "pair_digest": pair_digest,
        "decision_digest": resealed_decision["verdict_digest"],
        "verdict": _verdict_label(verdict_record),
        "effect_status": reclassified,
        "issued_at": issued_at,
        "executed_at": executed_at,
        "chain": chain,
    }


# ----------------------------------------------------------------------
# Authority boundary.
# ----------------------------------------------------------------------


def deny_authority_use(receipt):
    """Refuse any attempt to use a receipt as authorization.

    Receipts are evidence, never authority: a well-formed receipt
    refuses ``receipt-pair-not-authorization``. Malformed or
    unknown-fielded receipts refuse their shape codes first, so this
    is also the safe seam to run any receipt-shaped input through.
    """
    if not isinstance(receipt, dict):
        raise _Malformed("receipt must be a dict")
    kind = receipt.get("kind")
    if kind == "decision-receipt":
        _check_receipt_shape(receipt, kind, _DECISION_FIELDS)
    elif kind == "execution-receipt":
        _check_receipt_shape(receipt, kind, _EXECUTION_FIELDS)
    else:
        raise _Malformed("unknown receipt kind: %r" % (kind,))
    raise _NotAuthorization(
        "receipts are evidence of what happened; they never authorize")
