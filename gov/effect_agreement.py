"""Decision-vs-effect agreement (W243-9, ADAPT -- pattern only, prose
re-derived).

The gilda -01 audit-record idea re-derived: an authorization decision
and the *observed effect* are recorded separately, and their agreement
is derived -- the engine never assumes what happened matches what was
authorized.

Protocol
--------
``record_decision(registry, action_id, decision, ...)`` canonicalizes
the decision mapping and stores its sha256 digest (the decision is
evidence of an authorization, not authority by itself).
``record_observed_effect(registry, action_id, effect, ...)``
canonicalizes the observed effect and stores its digest (the effect is
*caller-supplied observation* -- it proves a claim about what
happened, not what happened).
``compute_agreement(registry, action_id)`` returns one of:

* ``aligned`` -- the observed effect's action and params digest equal
  the decision's; the effect bytes digest to the recorded effect
  digest.
* ``contradicted`` -- an observed effect disagrees with the decision;
  fail-closed refusal ``effect-decision-contradicted``.
* ``unknown`` -- a decision with no observed effect; flagged
  ``effect-unobserved``, never silently assumed, never a pass.

Refusal vocabulary (domain ``effect-agreement``, all fail-closed):

* ``effect-decision-missing`` -- agreement computed with no recorded
  decision for the action id.
* ``effect-decision-contradicted`` -- the observed effect contradicts
  the recorded decision.
* ``effect-not-bound`` -- the stored effect bytes do not digest to the
  recorded effect digest (tampered or swapped observation); agreement
  cannot be computed.

Honest boundaries
-----------------
* The effect record is caller-supplied observation: digest binding
  detects *tampering with the record*, not a caller who consistently
  reports a lie. An aligned agreement proves the record is
  self-consistent, not that the effect really happened.
* Agreement is structural (action + params digest), not semantic: it
  cannot see effects the observer chose not to report.
* Malformed inputs (non-mappings, missing action, non-str shapes)
  fail closed; a bare ``True``/``False`` verdict is rejected.

Stdlib only. Deterministic: callers supply ``now``; no wall clock.
"""

import hashlib
import json

DECISION_DIGEST_LEN = 64          # sha256 hex

EFFECT_DECISION_MISSING = "effect-decision-missing"
EFFECT_DECISION_CONTRADICTED = "effect-decision-contradicted"
EFFECT_NOT_BOUND = "effect-not-bound"

ALIGNED = "aligned"
CONTRADICTED = "contradicted"
UNKNOWN = "unknown"

_FLAG_UNOBSERVED = "effect-unobserved"


class EffectAgreementError(Exception):
    """Fail-closed decision/effect agreement refusal. ``code`` is the
    vocabulary."""

    def __init__(self, code, detail=""):
        super(EffectAgreementError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def _canonical_bytes(obj):
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EffectAgreementError(
            "effect-decision-missing",
            "record is not JSON-canonicalizable: %s" % (exc,))
    return text.encode("utf-8")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _check_action_id(action_id):
    if isinstance(action_id, bool) or not isinstance(action_id, str) \
            or not action_id.strip():
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "action_id must be a non-empty string")
    return action_id


def _check_decision(decision):
    if not isinstance(decision, dict):
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "decision must be a mapping, got %r"
            % (type(decision).__name__,))
    action = decision.get("action")
    if isinstance(action, bool) or not isinstance(action, str) \
            or not action.strip():
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "decision.action must be a non-empty string")
    verdict = decision.get("verdict")
    if verdict is not None and (not isinstance(verdict, str)
                                or not verdict.strip()):
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "decision.verdict must be a non-empty string when present")
    return decision


def record_decision(registry, action_id, decision, decided_by=None,
                    now=None):
    """Record an authorization decision for ``action_id``.

    Returns the record ``{"action_id", "decision_bytes",
    "decision_digest", "decided_by", "recorded_at"}``. Raises
    ``EffectAgreementError`` on malformed input.
    """
    action_id = _check_action_id(action_id)
    _check_decision(decision)
    if decided_by is not None and not isinstance(decided_by, str):
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "decided_by must be a string when present")
    decision_bytes = _canonical_bytes(decision)
    record = {
        "action_id": action_id,
        "decision_bytes": decision_bytes,
        "decision_digest": _digest(decision_bytes),
        "decided_by": decided_by,
        "recorded_at": now,
        "effect_bytes": None,
        "effect_digest": None,
        "observed_at": None,
        "observer": None,
    }
    registry[action_id] = record
    return record


def _check_effect(effect):
    if not isinstance(effect, dict):
        raise EffectAgreementError(
            EFFECT_NOT_BOUND,
            "effect must be a mapping, got %r"
            % (type(effect).__name__,))
    action = effect.get("action")
    if isinstance(action, bool) or not isinstance(action, str) \
            or not action.strip():
        raise EffectAgreementError(
            EFFECT_NOT_BOUND,
            "effect.action must be a non-empty string")
    return effect


def record_observed_effect(registry, action_id, effect, observed_at=None,
                           observer=None):
    """Record the observed effect for ``action_id``.

    The effect is caller-supplied observation; this binds the supplied
    bytes to a digest so later tampering is detectable. It does not
    prove the observation is true. Returns the updated record.
    """
    action_id = _check_action_id(action_id)
    if action_id not in registry:
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "no decision recorded for %r" % (action_id,))
    _check_effect(effect)
    if observer is not None and not isinstance(observer, str):
        raise EffectAgreementError(
            EFFECT_NOT_BOUND,
            "observer must be a string when present")
    effect_bytes = _canonical_bytes(effect)
    record = registry[action_id]
    record["effect_bytes"] = effect_bytes
    record["effect_digest"] = _digest(effect_bytes)
    record["observed_at"] = observed_at
    record["observer"] = observer
    return record


def _action_of(canonical_bytes):
    return json.loads(canonical_bytes.decode("utf-8"))["action"]


def _params_digest_of(canonical_bytes):
    obj = json.loads(canonical_bytes.decode("utf-8"))
    params = obj.get("params", {})
    return _digest(_canonical_bytes(params))


def compute_agreement(registry, action_id):
    """Derive the decision/effect agreement for ``action_id``.

    Returns ``{"agreement", "decision_digest", "effect_digest",
    "flag"}``. ``agreement`` is ``aligned``, ``contradicted`` (raises),
    or ``unknown`` (flagged, never assumed). Raises
    ``EffectAgreementError`` when the effect bytes do not digest to
    the recorded digest.
    """
    action_id = _check_action_id(action_id)
    record = registry.get(action_id)
    if record is None:
        raise EffectAgreementError(
            EFFECT_DECISION_MISSING,
            "no decision recorded for %r" % (action_id,))
    result = {
        "agreement": UNKNOWN,
        "decision_digest": record["decision_digest"],
        "effect_digest": record["effect_digest"],
        "flag": None,
    }
    if record["effect_bytes"] is None:
        result["flag"] = _FLAG_UNOBSERVED
        return result
    if _digest(record["effect_bytes"]) != record["effect_digest"]:
        raise EffectAgreementError(
            EFFECT_NOT_BOUND,
            "effect bytes do not digest to the recorded effect digest")
    decision_action = _action_of(record["decision_bytes"])
    effect_action = _action_of(record["effect_bytes"])
    if effect_action != decision_action or \
            _params_digest_of(record["effect_bytes"]) != \
            _params_digest_of(record["decision_bytes"]):
        raise EffectAgreementError(
            EFFECT_DECISION_CONTRADICTED,
            "observed action %r disagrees with decided %r"
            % (effect_action, decision_action))
    result["agreement"] = ALIGNED
    return result
