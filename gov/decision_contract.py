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

# Wave-194 R1 (Cedar D1 steal): the Request carries a typed context
# schema. validate_context raises ContextTypeError (a TypeError) on a
# mistyped KNOWN attribute -- loud at the contract boundary, never
# silently coerced at match time. None stays the absence sentinel;
# unknown keys pass through for forward compatibility.
from .context_schema import ContextTypeError, validate_context
# Wave-198: the ladder mode vocabulary lives in gov/mode_ledger.py
# (stdlib-only, no import cycle); every boundary validates against
# the one tuple instead of repeating the literal.
from .mode_ledger import LADDER_MODES


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
        # Wave-194 R1: typed context attributes. A KNOWN signal with
        # the wrong type (domain_allowlisted="false", counters as
        # strings, ints for bools) is refused HERE -- the contract
        # boundary -- instead of being silently bool()/int()-coerced
        # in _matches. ContextTypeError is a TypeError, so existing
        # guards keep working; the message names the offending key.
        validate_context(self.context)

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
    # Wave-198 (graduation ladder): the rule's ladder mode when it
    # matched. "deny" is also the resting default for mode-absent
    # rules, so existing serialized shapes are unchanged.
    mode: str = "deny"

    def __post_init__(self):
        if self.mode not in LADDER_MODES:
            raise ContractError(
                "RuleHit.mode must be observe/warn/deny, got %r"
                % (self.mode,))


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
    # Wave-198 (graduation ladder): rules that matched but were in
    # observe mode when they matched. They are named here -- never
    # hidden -- but they carry no authority and appear in none of the
    # three effect buckets.
    observed_hits: Tuple[RuleHit, ...] = ()

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
            d = {"rule_id": h.rule_id, "effect": h.effect,
                 "reason": h.reason, "flag": h.flag,
                 "declaration_index": h.declaration_index,
                 "deciding": h.deciding}
            # Wave-198: mode is serialized only when it differs from
            # the resting default, so mode-absent policies keep their
            # byte-identical serialized shape.
            if h.mode != "deny":
                d["mode"] = h.mode
            return d
        out = {
            "deciding_rule": (_hit(self.deciding_rule)
                              if self.deciding_rule else None),
            "forbid_hits": [_hit(h) for h in self.forbid_hits],
            "approval_hits": [_hit(h) for h in self.approval_hits],
            "permit_hits": [_hit(h) for h in self.permit_hits],
            "trace": [{"effect": t.effect, "rule_id": t.rule_id,
                       "matched": t.matched} for t in self.trace],
            "policy_ids": sorted(self.policy_ids),
        }
        # Wave-198: observed_hits is serialized only when non-empty --
        # mode-absent policies keep their byte-identical shape.
        if self.observed_hits:
            out["observed_hits"] = [_hit(h) for h in self.observed_hits]
        return out


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
    # Wave-198 (graduation ladder): what the rule asked for (nominal)
    # vs what the ladder enforced (effect). Equal for deny-mode and
    # mode-absent rules; differ when a warn-mode rule's verdict is
    # demoted to allow. None normalizes to effect in __post_init__
    # (existing constructors that predate the ladder get
    # nominal == effect, which is the honest reading).
    nominal_effect: Optional[str] = None
    # The ladder mode of the deciding rule ("deny" is the resting
    # default for mode-absent rules).
    mode: str = "deny"
    # Operator telemetry strings for warn-mode decisions. Aggregated
    # into per-window digests by the executor; NEVER returned to the
    # agent as interrupts (R1 warn-fatigue).
    warnings: Tuple[str, ...] = ()
    # Wave-343 (per-policy observe->enforce rollout): the DEPLOYMENT
    # mode of the policy that produced this decision. Orthogonal to
    # the per-rule ladder ``mode`` above: a whole policy deployed in
    # observe evaluates for real but takes no enforcement action.
    # "enforce" is the resting default; "observe" is declared on
    # every record the deployment produces. Import cycle note:
    # gov/policy_observe.py imports this module, so the vocabulary
    # is spelled out here rather than imported.
    policy_mode: str = "enforce"

    def __post_init__(self):
        if self.effect not in ("allow", "require_approval", "deny"):
            raise ContractError(
                "Decision.effect must be allow/require_approval/deny, got %r"
                % (self.effect,))
        if self.allowed != (self.effect == "allow"):
            raise ContractError(
                "Decision.allowed must equal (effect == 'allow'); got "
                "allowed=%r for effect=%r" % (self.allowed, self.effect))
        nominal = self.effect if self.nominal_effect is None \
            else self.nominal_effect
        if nominal not in ("allow", "require_approval", "deny"):
            raise ContractError(
                "Decision.nominal_effect must be allow/require_approval/"
                "deny, got %r" % (self.nominal_effect,))
        if self.mode not in LADDER_MODES:
            raise ContractError(
                "Decision.mode must be observe/warn/deny, got %r"
                % (self.mode,))
        # The ladder invariant: the enforced effect is what "allowed"
        # mirrors; nominal_effect is what the rule asked for. An
        # observe-mode rule never decides, so mode == "observe" is
        # impossible here -- loud, not silent.
        if self.mode == "observe":
            raise ContractError(
                "Decision.mode cannot be 'observe': observe-mode rules "
                "record hits but never decide")
        for w in self.warnings:
            if not isinstance(w, str) or not w:
                raise ContractError(
                    "Decision.warnings entries must be non-empty strings, "
                    "got %r" % (w,))
        if self.policy_mode not in ("enforce", "observe"):
            raise ContractError(
                "Decision.policy_mode must be enforce/observe, got %r"
                % (self.policy_mode,))
        # Frozen dataclass: normalize via object.__setattr__.
        object.__setattr__(self, "nominal_effect", nominal)
        object.__setattr__(self, "warnings", tuple(self.warnings))

    def to_policy_decision(self):
        """Convert to the legacy PolicyDecision (compat shim).

        ``matched_rules`` keeps its exact legacy semantics: the
        deciding rule id, or ["default_deny"] for the implicit deny.
        Shadowed hits live in ``diagnostics``, not here. The ladder
        fields (nominal_effect / mode / warnings) ride along so
        downstream evidence (audit entries, BOMs) can bind them.
        """
        # Lazy import: gov/policy.py imports this module at module
        # level, so a top-level import here would cycle.
        from .policy import PolicyDecision
        matched = ([self.policy_id] if self.policy_id
                   else [DEFAULT_DENY_ID])
        return PolicyDecision(self.effect, self.reason,
                              policy_id=self.policy_id, flag=self.flag,
                              matched_rules=matched,
                              diagnostics=self.diagnostics,
                              nominal_effect=self.nominal_effect,
                              mode=self.mode,
                              warnings=self.warnings,
                              policy_mode=self.policy_mode)

    def to_dict(self) -> Dict[str, Any]:
        d = {"effect": self.effect, "allowed": self.allowed,
             "reason": self.reason, "policy_id": self.policy_id,
             "flag": self.flag,
             "diagnostics": self.diagnostics.to_dict(),
             "request": {"principal": self.request.principal,
                         "action": self.request.action,
                         "resource": self.request.resource,
                         "role": self.request.role}}
        # Wave-198: ladder fields are serialized only when they carry
        # information -- mode-absent policies keep their byte-identical
        # serialized shape.
        if self.mode != "deny" or self.nominal_effect != self.effect \
                or self.warnings:
            d["nominal_effect"] = self.nominal_effect
            d["mode"] = self.mode
            d["warnings"] = list(self.warnings)
        # Wave-343: per-policy deployment mode is serialized only when
        # it carries information -- enforce-mode decisions keep their
        # byte-identical serialized shape.
        if self.policy_mode == "observe":
            d["policy_mode"] = "observe"
        return d
