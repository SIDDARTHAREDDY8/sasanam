"""Policy engine: YAML-defined rules evaluated against each action.

evaluate(action, context) walks the policies in file order and returns the
first match. If nothing matches, the configured default applies (allow).

Match clauses supported:
  tool:                action tool name, or list of names
  path_contains_any:   list of substrings; any must appear (case-insensitive)
                       in the action's "path" argument
  path_outside_sandbox: true; matches when the resolved path escapes the run's
                       sandbox directory (computed by the executor into context)
  min_external_calls:  N; matches when context["api_calls"] >= N (rate guard)
"""

from dataclasses import dataclass
from pathlib import Path

from .yamlmini import load as load_yaml


@dataclass(frozen=True)
class PolicyDecision:
    effect: str  # "allow" | "deny" | "require_approval"
    reason: str
    policy_id: str | None
    flag: str | None = None


class PolicyEngine:
    def __init__(self, yaml_path):
        cfg = load_yaml(str(yaml_path))
        if not isinstance(cfg, dict) or "policies" not in cfg:
            raise ValueError("policy file must define a top-level 'policies' list")
        self.policies = cfg["policies"]
        self.defaults = cfg.get("defaults") or {}
        for rule in self.policies:
            if rule.get("effect") not in ("allow", "deny", "require_approval"):
                raise ValueError("policy %r has invalid effect" % (rule.get("id"),))

    def _matches(self, rule, action, context):
        match = rule.get("match") or {}
        tools = match.get("tool")
        if tools is not None:
            names = tools if isinstance(tools, list) else [tools]
            if action.get("tool") not in names:
                return False
        needles = match.get("path_contains_any")
        if needles:
            path = str((action.get("args") or {}).get("path", "")).lower()
            if not any(str(n).lower() in path for n in needles):
                return False
        if match.get("path_outside_sandbox"):
            if not context.get("path_outside_sandbox"):
                return False
        if "min_external_calls" in match:
            if int(context.get("api_calls", 0)) < int(match["min_external_calls"]):
                return False
        return True

    def evaluate(self, action, context=None):
        context = context or {}
        for rule in self.policies:
            if self._matches(rule, action, context):
                return PolicyDecision(
                    effect=rule["effect"],
                    reason=rule.get("reason", ""),
                    policy_id=rule.get("id"),
                    flag=rule.get("flag"),
                )
        return PolicyDecision(
            effect=self.defaults.get("effect", "allow"),
            reason=self.defaults.get("reason", "No policy matched."),
            policy_id=None,
        )
