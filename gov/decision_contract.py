"""Request/Decision+Diagnostics authorization contract.

Interface ideas adapted from ``cedar-policy/cedar``
(https://github.com/cedar-policy/cedar, Apache-2.0, Copyright Cedar
Contributors; the project is now under the Linux Foundation/CNCF):

  * ``is_authorized(Request{principal, action, resource, context})``
    returns ``Response{Decision, Diagnostics}`` — every authorization
    call takes a well-typed request and returns not just the verdict
    but structured diagnostics explaining WHY.
  * **forbid-overrides-permit**: a matching ``forbid`` policy denies no
    matter how many ``permit`` policies match or where the rules are
    declared; no matching policy at all is an implicit deny.

No Cedar code is reused (Cedar is Rust; this engine is a Python YAML
policy engine). The contract is reimplemented for ``gov/policy.py``.

This is a transparency refactor, NOT a behavior change. The engine
already evaluates deny-first with implicit deny; the contract makes
the request well-typed and the diagnostics explicit: every Decision
names the exact policy ids that fired, the ones that matched but lost
(shadowed), and the full evaluation trace. The verdict for any given
request is identical to the pre-contract engine — proven by the
canonical suite (``tests/run_tests.py``) and the differential probe in
``evals/cedar_contract_probes.py``.

Cedar mapping notes (honest deltas from upstream):

  * Cedar's ``Decision`` is binary (Allow/Deny). Our engine has a third
    verdict, ``require_approval`` (human-in-the-loop), which the
    contract preserves as a first-class effect rather than collapsing
    it: ``Decision.allowed`` is True only for ``effect == "allow"``.
  * Cedar's ``principal``/``action``/``resource`` are schema-typed
    entities. Here ``principal`` is the agent identity string,
    ``action`` is the tool name (``None`` only for non-tool-call
    evaluations such as harness-initiated platform egress), and
    ``resource`` is the target artifact (path/URL/destination) carried
    for auditor readability — it is informational, NOT a match key;
    matching still happens through the context signals.
  * Cedar ``Diagnostics`` carries the ``PolicyId``s that fired. Ours
    carries the deciding rule, every matched rule per effect (so a
    forbid that fired is always named, even when it was not the
    decider), and the evaluation trace.
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple


class ContractError(TypeError):
    """Raised when a Request is constructed with an invalid shape.

    The contract is typed on purpose: an authorization request with
    no principal or a non-mapping context fails loud at construction
    instead of silently evaluating against an untyped dict.
    """


def _derive_resource(args: Mapping[str, Any]) -> Optional[str]:
    """Best-effort target artifact for auditor readability.

    Informational only — never a match key. The engine matches on the
    context signals, exactly as before.
    """
    for key in ("path", "url", "destination", "package", "to"):
        value = args.get(key)
        if value:
            return str(value)
    return None


@dataclass(frozen=True)
class Request:
    """A well-typed authorization request.

    principal: the agent identity (``agent_id``) making the call.
    action:    the tool name (``read_file``, ``send_email``, ...), or
               None for non-tool-call evaluations (platform egress).
    resource:  the target artifact (path/URL/destination), informational.
    role:      the caller's role, used by role-keyed rules.
    args:      the tool arguments (what the engine matches ``path_*``
               keys against).
    context:   the match signals (counters, allowlist flags, taint
               bits, ...).
    """

    principal: str
    action: Optional[str]
    resource: Optional[str]
    role: Optional[str]
    args: Mapping[str, Any]
    context: Mapping[str, Any]

    def __post_init__(self):
        if not isinstance(self.principal, str) or not self.principal:
            raise ContractError(
                "Request.principal must be a non-empty string, got %r"
                % (self.principal,))
        if self.action is not None and (
                not isinstance(self.action, str) or not self.action):
            raise ContractError(
                "Request.action must be a tool-name string or None, got %r"
                % (self.action,))
        if not isinstance(self.args, Mapping):
            raise ContractError(
                "Request.args must be a mapping, got %r" % (self.args,))
        if not isinstance(self.context, Mapping):
            raise ContractError(
                "Request.context must be a mapping, got %r"
                % (self.context,))

    @classmethod
    def from_action(cls, action: Mapping[str, Any],
                    context: Optional[Mapping[str, Any]] = None) -> "Request":
        """Build a Request from the engine's legacy (action, context) pair.

        Fallbacks are explicit and documented, not silent:

          * principal falls back through ``agent_id`` -> ``agent`` ->
            ``"unknown"``. Platform-egress and harness probes are not
            agent-attributed; the Decision carries
            ``principal="unknown"`` so auditors see it. Values are
            taken from the action dict only -- nothing is promoted
            from the context, so the rebuilt action reaching _matches
            is identical to the original on every key _matches reads.
          * action is ``action["tool"]``, which is legitimately None
            for non-tool-call evaluations (``gov/platform_egress.py``
            passes ``tool=None`` and matches on context keys).
        """
        action = action or {}
        context = context or {}
        args = action.get("args") or {}
        if not isinstance(args, Mapping):
            raise ContractError(
                "action['args'] must be a mapping, got %r" % (args,))
        principal = action.get("agent_id") or action.get("agent") \
            or "unknown"
        return cls(
            principal=str(principal),
            action=action.get("tool"),
            resource=_derive_resource(args),
            role=action.get("role"),
            args=args,
            context=context,
        )

    def to_action(self) -> Dict[str, Any]:
        """Rebuild the legacy action dict for the match engine.

        Lossless for evaluation: ``PolicyEngine._matches`` only reads
        ``tool``, ``role``, ``agent_id`` and ``args``.
        """
        return {"tool": self.action, "role": self.role,
                "agent_id": self.principal, "args": dict(self.args)}


@dataclass(frozen=True)
class TraceEntry:
    """One step of the evaluation trace, in evaluation order."""
    effect: str      # "deny" | "require_approval" | "allow"
    rule_id: str
    matched: bool


@dataclass(frozen=True)
class RuleHit:
    """A rule that matched the request."""
    rule_id: str
    effect: str
    reason: str
    flag: Optional[str]
    declaration_index: int  # position in the policy rule list
    deciding: bool = False  # True iff this rule determined the verdict


@dataclass(frozen=True)
class Diagnostics:
    """Why the decision came out the way it did.

    forbid_hits / approval_hits / permit_hits name EVERY rule that
    matched (declaration order, decider first-flagged), so a forbid
    that fired is always named even when another rule decided, and a
    permit that lost to a forbid is named as shadowed rather than
    hidden. ``policy_ids`` is the Cedar-style flat set of ids that
    fired (deciding + shadowed).
    """

    deciding_rule: Optional[RuleHit]  # None only for implicit default_deny
    forbid_hits: Tuple[RuleHit, ...] = ()
    approval_hits: Tuple[RuleHit, ...] = ()
    permit_hits: Tuple[RuleHit, ...] = ()
    trace: Tuple[TraceEntry, ...] = ()
    policy_ids: frozenset = frozenset()

    @property
    def forbid_policy_ids(self) -> Tuple[str, ...]:
        return tuple(h.rule_id for h in self.forbid_hits)

    @property
    def shadowed_hits(self) -> Tuple[RuleHit, ...]:
        """Matched rules that did not decide the verdict."""
        return tuple(h for h in
                     (self.forbid_hits + self.approval_hits + self.permit_hits)
                     if not h.deciding)

    def to_dict(self) -> Dict[str, Any]:
        def _hit(h: RuleHit) -> Dict[str, Any]:
            return {"rule_id": h.rule_id, "effect": h.effect,
                    "reason": h.reason, "flag": h.flag,
                    "declaration_index": h.declaration_index,
                    "deciding": h.deciding}
        return {
            "deciding_rule": (_hit(self.deciding_rule)
                              if self.deciding_rule else None),
            "forbid_hits": [_hit(h) for h in self.forbid_hits],
            "approval_hits": [_hit(h) for h in self.approval_hits],
            "permit_hits": [_hit(h) for h in self.permit_hits],
            "trace": [{"effect": t.effect, "rule_id": t.rule_id,
                       "matched": t.matched} for t in self.trace],
            "policy_ids": sorted(self.policy_ids),
        }


# The verdict a Decision carries when no rule matched at all. A
# documented sentinel, not a hidden default (mirrors the engine's
# existing "default_deny" flag).
DEFAULT_DENY_ID = "default_deny"


@dataclass(frozen=True)
class Decision:
    """The authorization verdict plus its diagnostics.

    effect is the engine's native verdict ("allow" |
    "require_approval" | "deny"); ``allowed`` is True only for
    "allow". ``require_approval`` is preserved as a first-class
    verdict — the contract must not collapse the human-in-the-loop
    path into a binary.
    """

    effect: str
    allowed: bool
    reason: str
    policy_id: Optional[str]
    flag: Optional[str]
    diagnostics: Diagnostics
    request: Request

    def __post_init__(self):
        if self.effect not in ("allow", "require_approval", "deny"):
            raise ContractError(
                "Decision.effect must be allow/require_approval/deny, got %r"
                % (self.effect,))
        if self.allowed != (self.effect == "allow"):
            raise ContractError(
                "Decision.allowed must equal (effect == 'allow'); got "
                "allowed=%r for effect=%r" % (self.allowed, self.effect))

    def to_policy_decision(self):
        """Convert to the legacy PolicyDecision (compat shim).

        ``matched_rules`` keeps its exact legacy semantics: the
        deciding rule id, or ["default_deny"] for the implicit deny.
        Shadowed hits live in ``diagnostics``, not here.
        """
        # Lazy import: gov/policy.py imports this module at module
        # level, so a top-level import here would cycle.
        from .policy import PolicyDecision
        matched = ([self.policy_id] if self.policy_id
                   else [DEFAULT_DENY_ID])
        return PolicyDecision(self.effect, self.reason,
                              policy_id=self.policy_id, flag=self.flag,
                              matched_rules=matched,
                              diagnostics=self.diagnostics)

    def to_dict(self) -> Dict[str, Any]:
        return {"effect": self.effect, "allowed": self.allowed,
                "reason": self.reason, "policy_id": self.policy_id,
                "flag": self.flag,
                "diagnostics": self.diagnostics.to_dict(),
                "request": {"principal": self.request.principal,
                            "action": self.request.action,
                            "resource": self.request.resource,
                            "role": self.request.role}}
