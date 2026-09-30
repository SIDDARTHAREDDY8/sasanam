"""Forbid-overrides-permit policy-set combiner.

Wave-248 lane 6. Stdlib only.

Cedar-adapted guarantee (Apache-2.0, cedar-policy/cedar -- a pattern
adaptation only, never the Cedar language or engine): when a request
is evaluated against a SET of policies, the combination rule is
structural, never a convention:

  * any FORBID (deny) match  -> DENY, regardless of permits
  * PERMIT matches only       -> ALLOW (needs >= 1 permit, 0 forbids)
  * REQUIRE_APPROVAL matches  -> REQUIRE_APPROVAL (0 forbids)
  * no permits at all         -> DENY (default deny)

Rationale: gov/policy.py already evaluates deny-first WITHIN one
policy file (deny pass, then require_approval pass, then allow pass).
The gap is the POLICY SET: an operator policy, a deployment policy,
and a skill-manifest policy each decide the same request, and their
combination was implicit. Now it is the evaluator's rule, so a permit
buried in one policy cannot be smuggled past another policy's forbid
by ordering, flags, or structure.

Structural guarantee: ``combine()`` takes exactly ONE parameter --
the sequence of per-policy decisions. There is NO flag, option, mode,
priority, or ordering that can express "permit overrides forbid":
``inspect.signature(combine)`` shows a single positional parameter,
any keyword raises TypeError, and input order is irrelevant to the
verdict (verified by the red-first battery).

The combiner does NOT replace PolicyEngine: each PolicyDecision is
produced by a PolicyEngine (``evaluate()``) or a validated hand-built
equivalent. ``combine()`` only applies the forbid-overrides rule over
the set, reading each decision's FINAL effect (``effect``, not
``nominal_effect`` -- a ladder-demoted verdict is treated as the
verdict the engine actually enforced).

Trust model: the combiner sits on the OPERATOR boundary. Policies
are inputs to the evaluator; a policy (or skill manifest) is a
requirement, never a grant -- a manifest can forbid its own actions
but can never permit its way past the operator's forbid.
"""

from .decision_contract import Decision as _ContractDecision
from .policy import PolicyDecision as _PolicyDecision

__all__ = [
    "CombinerMisuseError",
    "CombinedDecision",
    "combine",
]

# Machine decision codes emitted by the combiner (also in
# gov/decision_codes.py under domain "policy-combine").
FORBID_OVERRIDES_CODE = "combine-forbid-overrides"
DEFAULT_DENY_CODE = "combine-default-deny"
MISUSE_CODE = "combine-misuse"

_VALID_EFFECTS = ("allow", "require_approval", "deny")


class CombinerMisuseError(ValueError):
    """The combiner's input was not a sequence of validated decisions.

    Fail-closed: anything that is not a PolicyDecision (or a
    decision_contract.Decision convertible via to_policy_decision())
    refuses rather than being silently bucketed. Carries the
    ``combine-misuse`` taxonomy code.
    """

    code = MISUSE_CODE

    def __init__(self, detail):
        super().__init__("combine-misuse: %s" % (detail,))
        self.detail = detail


def _as_policy_decision(obj):
    """Normalize one input to a PolicyDecision, or refuse."""
    if isinstance(obj, _PolicyDecision):
        dec = obj
    elif isinstance(obj, _ContractDecision):
        dec = obj.to_policy_decision()
    else:
        raise CombinerMisuseError(
            "expected PolicyDecision or Decision, got %s"
            % (type(obj).__name__,))
    if dec.effect not in _VALID_EFFECTS:
        # Hand-built decisions bypass engine validation; an unknown
        # effect must not silently fall into a bucket.
        raise CombinerMisuseError(
            "decision effect %r not in %s; refusing rather than "
            "guessing" % (dec.effect, list(_VALID_EFFECTS)))
    if not isinstance(dec.reason, str) or not dec.reason:
        raise CombinerMisuseError(
            "decision reason must be a non-empty string")
    return dec


def _policy_label(dec, index):
    """Deterministic label for a decision's policy (never empty)."""
    if dec.policy_id:
        return str(dec.policy_id)
    return "<policy-%d>" % (index,)


class CombinedDecision:
    """The verdict of combining one request's per-policy decisions.

    Immutable-ish value object: effect, reason, the refusal code (or
    None for non-refusals), the contributing policy ids per bucket,
    and the input decisions. ``to_policy_decision()`` re-enters the
    legacy seam as a single PolicyDecision with
    policy_id "policy_set".
    """

    def __init__(self, effect, reason, code, forbid_policy_ids,
                 approval_policy_ids, permit_policy_ids, decisions):
        if effect not in _VALID_EFFECTS:
            raise ValueError("CombinedDecision.effect must be one of %s"
                             % (list(_VALID_EFFECTS),))
        self.effect = effect
        self.reason = reason
        self.code = code
        self.forbid_policy_ids = tuple(forbid_policy_ids)
        self.approval_policy_ids = tuple(approval_policy_ids)
        self.permit_policy_ids = tuple(permit_policy_ids)
        self.decisions = tuple(decisions)

    def to_dict(self):
        return {
            "effect": self.effect,
            "reason": self.reason,
            "code": self.code,
            "forbid_policy_ids": list(self.forbid_policy_ids),
            "approval_policy_ids": list(self.approval_policy_ids),
            "permit_policy_ids": list(self.permit_policy_ids),
            "n_decisions": len(self.decisions),
        }

    def to_policy_decision(self):
        """Re-enter the legacy seam as one PolicyDecision."""
        return _PolicyDecision(
            self.effect, self.reason, policy_id="policy_set",
            matched_rules=["policy_set"])

    def __repr__(self):  # pragma: no cover - debugging aid
        return "CombinedDecision(effect=%r, code=%r, reason=%r)" % (
            self.effect, self.code, self.reason)


def combine(decisions):
    """Combine one request's per-policy decisions.

    Exactly one parameter -- the sequence of decisions. No flag,
    option, mode, or priority exists that could express
    "permit overrides forbid"; the rule below is unconditional.

    Combination (in fixed order, input order irrelevant):

    1. any decision with final effect "deny"      -> DENY
       (code combine-forbid-overrides; the reason names the
       forbidding policies and the overridden permit count)
    2. any decision with effect "require_approval" -> REQUIRE_APPROVAL
    3. any decision with effect "allow"            -> ALLOW
    4. otherwise (empty set, or no contributing decisions) -> DENY
       (code combine-default-deny)

    Each input must be a PolicyDecision (or a Decision convertible
    via to_policy_decision()); anything else raises
    CombinerMisuseError.
    """
    if isinstance(decisions, (str, bytes, bytearray, dict)):
        raise CombinerMisuseError(
            "decisions must be a sequence of decisions, not %s"
            % (type(decisions).__name__,))
    try:
        items = list(decisions)
    except TypeError:
        raise CombinerMisuseError(
            "decisions must be a sequence of decisions, not %s"
            % (type(decisions).__name__,))

    normalized = [_as_policy_decision(obj) for obj in items]

    forbids = []
    approvals = []
    permits = []
    for index, dec in enumerate(normalized):
        label = _policy_label(dec, index)
        if dec.effect == "deny":
            forbids.append(label)
        elif dec.effect == "require_approval":
            approvals.append(label)
        else:  # "allow" -- _as_policy_decision validated the domain
            permits.append(label)

    if forbids:
        # Rule 1: forbid overrides everything. Sorted for a
        # deterministic reason regardless of input order.
        forbids = sorted(set(forbids))
        reason = (
            "combine-forbid-overrides: forbid by %s overrides %d "
            "permit(s) and %d require_approval(s); denied"
            % (forbids, len(permits), len(approvals)))
        return CombinedDecision(
            "deny", reason, FORBID_OVERRIDES_CODE,
            forbids, sorted(set(approvals)), sorted(set(permits)),
            normalized)

    if approvals:
        approvals = sorted(set(approvals))
        reason = (
            "combine: require_approval by %s (no forbid matched); "
            "human approval required" % (approvals,))
        return CombinedDecision(
            "require_approval", reason, None,
            (), approvals, sorted(set(permits)), normalized)

    if permits:
        permits = sorted(set(permits))
        reason = (
            "combine: allow by %s (no forbid matched); allowed"
            % (permits,))
        return CombinedDecision(
            "allow", reason, None, (), (), permits, normalized)

    # Rule 4: no permits at all -- an empty set, or a set whose
    # decisions contributed nothing -- fails closed.
    reason = (
        "combine-default-deny: no policy in the set permitted the "
        "request (%d decision(s) combined); denied" % (len(normalized),))
    return CombinedDecision(
        "deny", reason, DEFAULT_DENY_CODE, (), (), (), normalized)
