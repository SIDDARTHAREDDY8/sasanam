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
  domain_allowlisted, carries_read_content, source_untrusted,
  read_sensitive, cross_run_campaign, when

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
    "read_sensitive", "cross_run_campaign",
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


def default_policy_path():
    """Filesystem path of the canonical default policy.

    The policy ships as package data (``gov/data/default.yaml``) inside the
    wheel and is resolved through ``importlib.resources`` when installed.
    When running from a source checkout, falls back to the repo-local
    ``policies/default.yaml``. There is exactly one canonical policy: a
    drift-guard test keeps the shipped copy byte-identical to the checkout
    copy, and the engine's policy hash pins whichever copy was loaded.
    """
    try:
        from importlib.resources import files
        candidate = files("gov") / "data" / "default.yaml"
        if isinstance(candidate, Path) and candidate.is_file():
            return candidate
    except (ImportError, OSError, TypeError, ValueError):
        pass
    return Path(__file__).resolve().parent.parent / "policies" / "default.yaml"


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
        self.auto_approve = self._normalize_auto_approve(
            cfg.get("auto_approve"))
        # F18: admin-controlled campaign allowlist — (principal,
        # registered_domain, param key set) tuples whose repetitive api_call
        # traffic is exempt from campaign QUEUEING (still ledgered).
        self.campaign_allowlist = self._normalize_campaign_allowlist(
            cfg.get("campaign_allowlist"))
        # F21: queue reasons that may never be batch-approved — security
        # items need an individual human decision, even via confirm_risky.
        self.batch_excluded_queue_reasons = self._normalize_batch_excluded(
            (cfg.get("approvals") or {}).get("batch_excluded_queue_reasons"))
        # F22: policy-configurable audit-log size guard.
        self.log_limits = self._normalize_log_limits(cfg.get("log_limits"))
        self.policies = []
        for i, rule in enumerate(cfg.get("policies") or []):
            self._validate_rule(rule, i)
            self.policies.append(rule)

    # ------------------------------------------------------------ validation
    @staticmethod
    def _normalize_campaign_allowlist(cfg):
        """Normalize the ``campaign_allowlist:`` section (F18).

        Each entry is a ``[principal, registered_domain, [param keys]]``
        tuple. Malformed entries raise ValueError (fail closed at load —
        a bad allowlist must not silently widen into a bypass). The
        empty section is the default: no exemptions.
        """
        if cfg is None:
            return ()
        if not isinstance(cfg, (list, tuple)):
            raise ValueError("campaign_allowlist must be a list of "
                             "[principal, domain, [keys]] entries")
        out = []
        for i, entry in enumerate(cfg):
            if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                raise ValueError(
                    "campaign_allowlist entry %d must be [principal, "
                    "registered_domain, [param keys]], got %r" % (i, entry))
            principal, domain, keys = entry
            if not isinstance(principal, str) or not principal.strip():
                raise ValueError(
                    "campaign_allowlist entry %d: principal must be a "
                    "non-empty string" % i)
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError(
                    "campaign_allowlist entry %d: registered_domain must be "
                    "a non-empty string" % i)
            if (not isinstance(keys, (list, tuple))
                    or not keys
                    or any(not isinstance(k, str) or not k
                           for k in keys)):
                raise ValueError(
                    "campaign_allowlist entry %d: param keys must be a "
                    "non-empty list of strings" % i)
            out.append((principal.strip(), domain.strip().lower(),
                        tuple(sorted(set(keys)))))
        return tuple(out)

    @staticmethod
    def _normalize_batch_excluded(cfg):
        """Normalize ``approvals.batch_excluded_queue_reasons`` (F21).

        Malformed sections raise ValueError (fail closed at load).
        """
        if cfg is None:
            return ()
        if (not isinstance(cfg, (list, tuple))
                or any(not isinstance(r, str) or not r.strip()
                       for r in cfg)):
            raise ValueError("approvals.batch_excluded_queue_reasons must "
                             "be a list of non-empty strings")
        return tuple(r.strip() for r in cfg)

    @staticmethod
    def _normalize_log_limits(cfg):
        """Normalize the ``log_limits:`` section (F22).

        Currently ``max_log_bytes``: once the action log reaches this
        size, appends raise and the executor refuses to act (fail
        closed). Malformed sections raise ValueError (fail closed at
        load). Absent section -> no guard.
        """
        if cfg is None:
            return {}
        if not isinstance(cfg, dict):
            raise ValueError("log_limits must be a mapping")
        out = {}
        if "max_log_bytes" in cfg:
            try:
                cap = int(cfg["max_log_bytes"])
            except (TypeError, ValueError):
                raise ValueError("log_limits.max_log_bytes must be an "
                                 "integer")
            if cap <= 0:
                raise ValueError("log_limits.max_log_bytes must be > 0")
            out["max_log_bytes"] = cap
        return out

    @staticmethod
    def _normalize_auto_approve(cfg):
        """Normalize the policy's ``auto_approve:`` section.

        Low-risk auto-approval is a loaded control, so the gate is
        explicit: the section must exist with ``enabled: true``; the risk
        cap defaults to 25 and is clamped to 0-100. Anything malformed
        normalizes to disabled (fail closed).
        """
        out = {"enabled": False, "max_risk_score": 25}
        if not isinstance(cfg, dict):
            return out
        if cfg.get("enabled") is True:
            try:
                cap = int(cfg.get("max_risk_score", 25))
            except (TypeError, ValueError):
                return out
            out["enabled"] = True
            out["max_risk_score"] = max(0, min(100, cap))
        return out


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
        if "read_sensitive" in match:
            if bool(context.get("read_sensitive")) != bool(match["read_sensitive"]):
                return False
        if "cross_run_campaign" in match:
            if bool(context.get("cross_run_campaign")) != bool(match["cross_run_campaign"]):
                return False
        if "when" in match:
            if not _check_conditions(match["when"], context):
                return False
        return True
