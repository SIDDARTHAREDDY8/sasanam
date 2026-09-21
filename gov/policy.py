"""Fail-closed policy engine.

Semantics (deny-by-default with forbid priority):

* Rules are evaluated in three passes: all ``deny`` rules first, then all
  ``require_approval`` rules, then all ``allow`` rules. Within a pass the
  first matching rule wins.
* If no rule matches, the action is DENIED (``default_deny``). An empty or
  missing policy file therefore fails closed.
* Every YAML policy is validated at load: unknown tools, unknown match keys,
  and invalid effects raise ``ValueError`` instead of being silently ignored.

Match keys (all optional; every listed key must hold for the rule to match):

  tool, role, agent, path_contains_any, path_outside_sandbox,
  min_external_calls, min_sends, min_writes, min_deletes,
  domain_allowlisted, carries_read_content, source_untrusted, when

``when`` is a list of ``{path, gte|lte|gt|lt|eq|neq}`` conditions resolved
against the evaluation context (e.g. ``counters.send_email``).

Roles: the policy may define ``roles: {<role>: [<tools...>, ...]}``. Any
tool not listed for the caller's role is rejected by the executor before
policy evaluation, regardless of what the rules say. Built-in defaults
cover the test/demo roles; an explicit ``roles`` section replaces them.
"""

from hashlib import sha256
from pathlib import Path

from .yamlmini import load as load_yaml

KNOWN_TOOLS = {"read_file", "write_file", "delete_file",
               "api_call", "http_post", "send_email"}

KNOWN_MATCH_KEYS = {
    "tool", "role", "agent",
    "path_contains_any", "path_outside_sandbox",
    "min_external_calls", "min_sends", "min_writes", "min_deletes",
    "domain_allowlisted", "carries_read_content", "source_untrusted",
    "when",
}

VALID_EFFECTS = {"deny", "require_approval", "allow"}

_EFFECT_RANK = {"deny": 2, "require_approval": 1, "allow": 0}

DEFAULT_ROLES = {
    "support": ["read_file", "send_email"],
    "coder": ["read_file", "write_file", "delete_file", "api_call"],
    "researcher": ["read_file", "api_call", "http_post", "send_email"],
    "scout": ["read_file", "api_call"],
    "triage": ["read_file", "write_file"],
    "builder": ["read_file", "write_file", "delete_file"],
    "publisher": ["read_file", "http_post", "send_email"],
    "approver": [],
    "orchestrator": [],
}


class PolicyDecision:
    def __init__(self, effect, reason, policy_id=None, flag=None):
        self.effect = effect          # "allow" | "require_approval" | "deny"
        self.reason = reason
        self.policy_id = policy_id
        self.flag = flag

    def to_dict(self):
        return {"effect": self.effect, "reason": self.reason,
                "policy_id": self.policy_id, "flag": self.flag}


def _resolve(path, context):
    cur = context
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _check_conditions(conds, context):
    for cond in conds or []:
        val = _resolve(cond.get("path", ""), context)
        for op in ("gte", "lte", "gt", "lt", "eq", "neq"):
            if op in cond:
                want = cond[op]
                if val is None:
                    return False
                if op == "gte" and not (val >= want):
                    return False
                if op == "lte" and not (val <= want):
                    return False
                if op == "gt" and not (val > want):
                    return False
                if op == "lt" and not (val < want):
                    return False
                if op == "eq" and not (val == want):
                    return False
                if op == "neq" and not (val != want):
                    return False
    return True


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class PolicyEngine:
    def __init__(self, yaml_path):
        self.yaml_path = Path(yaml_path)
        raw = self.yaml_path.read_bytes()
        self.policy_hash = sha256(raw).hexdigest()
        self.source_digest = self.policy_hash
        cfg = load_yaml(str(self.yaml_path)) or {}
        self.roles = {r: list(t) for r, t in (cfg.get("roles") or {}).items()}
        if not self.roles:
            self.roles = {r: list(t) for r, t in DEFAULT_ROLES.items()}
        self.rate_limit = cfg.get("rate_limit") or {}
        self.egress = cfg.get("egress") or {}
        self.approval_ttl_hours = (cfg.get("approvals") or {}).get("ttl_hours", 24)
        self.policies = []
        for i, rule in enumerate(cfg.get("policies") or []):
            self._validate_rule(rule, i)
            self.policies.append(rule)

    # ------------------------------------------------------------ validation

    def _validate_rule(self, rule, index):
        rule_id = rule.get("id", "rule-%d" % index)
        effect = rule.get("effect")
        if effect not in VALID_EFFECTS:
            raise ValueError("policy %s: invalid effect %r (must be one of %s)"
                             % (rule_id, effect, sorted(VALID_EFFECTS)))
        match = rule.get("match") or {}
        for key in match:
            if key not in KNOWN_MATCH_KEYS:
                raise ValueError("policy %s: unknown match key %r (known: %s)"
                                 % (rule_id, key, sorted(KNOWN_MATCH_KEYS)))
        for tool in _as_list(match.get("tool")):
            if tool not in KNOWN_TOOLS:
                raise ValueError("policy %s: unknown tool %r (known: %s)"
                                 % (rule_id, tool, sorted(KNOWN_TOOLS)))

    # ---------------------------------------------------------------- roles

    def role_allows(self, role, tool):
        """True iff *role* is permitted to invoke *tool* at all."""
        return tool in self.roles.get(role, [])

    # ------------------------------------------------------------ evaluation

    def evaluate(self, action, context=None):
        """Return a PolicyDecision. Fail-closed: no matching rule -> deny."""
        context = context or {}
        match_ctx = dict(context)
        match_ctx.setdefault("role", action.get("role"))
        match_ctx.setdefault("agent", action.get("agent_id"))

        def _first_match(effect):
            for rule in self.policies:
                if rule.get("effect") != effect:
                    continue
                if self._matches(rule.get("match") or {}, action, match_ctx):
                    return rule
            return None

        for effect in ("deny", "require_approval", "allow"):
            rule = _first_match(effect)
            if rule is not None:
                return PolicyDecision(
                    effect,
                    rule.get("reason", "Matched policy %s." % rule.get("id")),
                    policy_id=rule.get("id"),
                    flag=rule.get("flag"),
                )
        return PolicyDecision(
            "deny",
            "No policy matched; denied by default (fail-closed).",
            policy_id=None,
            flag="default_deny",
        )

    def _matches(self, match, action, context):
        tool = action.get("tool")
        if "tool" in match and tool not in _as_list(match["tool"]):
            return False
        if "role" in match and action.get("role") not in _as_list(match["role"]):
            return False
        if "agent" in match and action.get("agent_id") not in _as_list(match["agent"]):
            return False
        args = action.get("args") or {}
        if "path_contains_any" in match:
            path = str(args.get("path", ""))
            if not any(sub in path for sub in _as_list(match["path_contains_any"])):
                return False
        if "path_outside_sandbox" in match:
            if bool(context.get("path_outside_sandbox")) != bool(match["path_outside_sandbox"]):
                return False
        counters = context.get("counters") or {}
        if "min_external_calls" in match:
            if int(counters.get("api_call", 0)) < int(match["min_external_calls"]):
                return False
        if "min_sends" in match:
            sends = int(counters.get("send_email", 0)) + int(counters.get("http_post", 0))
            if sends < int(match["min_sends"]):
                return False
        if "min_writes" in match:
            if int(counters.get("write_file", 0)) < int(match["min_writes"]):
                return False
        if "min_deletes" in match:
            if int(counters.get("delete_file", 0)) < int(match["min_deletes"]):
                return False
        if "domain_allowlisted" in match:
            if bool(context.get("domain_allowlisted")) != bool(match["domain_allowlisted"]):
                return False
        if "carries_read_content" in match:
            if bool(context.get("carries_read_content")) != bool(match["carries_read_content"]):
                return False
        if "source_untrusted" in match:
            if bool(context.get("source_untrusted")) != bool(match["source_untrusted"]):
                return False
        if "when" in match:
            if not _check_conditions(match["when"], context):
                return False
        return True
