"""Fail-closed policy engine.

Semantics (deny-by-default with forbid priority):

* Rules are evaluated in three passes: all ``deny`` rules first, then all
  ``require_approval`` rules, then all ``allow`` rules. Within a pass the
  first matching rule wins.
* If no rule matches, the action is DENIED (``default_deny``). An empty or
  missing policy file therefore fails closed.
* Every YAML policy is validated at load: unknown tools, unknown match keys,
  invalid effects, unknown rule-level fields (F90: a misspelled ``match:``
  previously defaulted to {} and matched every action), unknown top-level
  keys, unknown ``approvals`` subkeys, and malformed ``when`` conditions
  (unknown operators, missing path, vacuous conditions) raise ``ValueError``
  instead of being silently ignored.

Match keys (all optional; every listed key must hold for the rule to match):

  tool, role, agent, path_contains_any, path_outside_sandbox,
  min_external_calls, min_sends, min_writes, min_deletes,
  domain_allowlisted, carries_read_content, source_untrusted,
  read_sensitive, cross_run_campaign, velocity_exceeded,
  high_entropy_payload, package_fetch, install_allowlisted,
  install_integrity_verified, when

``when`` is a list of ``{path, gte|lte|gt|lt|eq|neq}`` conditions resolved
against the evaluation context (e.g. ``counters.send_email``).

Roles: the policy may define ``roles: {<role>: [<tools...>, ...]}``. Any
tool not listed for the caller's role is rejected by the executor before
policy evaluation, regardless of what the rules say. Built-in defaults
cover the test/demo roles; an explicit ``roles`` section replaces them.
"""

from hashlib import sha256
from pathlib import Path

from .yamlmini import parse as parse_yaml
# D1-core: delegation/quorum section normalizers live in
# gov/approvals.py — the single source of truth, so the queue and the
# engine cannot drift apart. (No import cycle: approvals.py never
# imports policy.py at module level.)
from .approvals import (
    _normalize_authority_delegation_config,
    _normalize_delegation_config,
    _normalize_quorum_config,
)

KNOWN_TOOLS = {"read_file", "write_file", "delete_file",
               "api_call", "http_post", "send_email",
               # P7 (wave-27): the governed package-install tool — the
               # only sanctioned path for agent-runtime fetches.
               "install_package"}

KNOWN_MATCH_KEYS = {
    "tool", "role", "agent",
    "path_contains_any", "path_outside_sandbox",
    "min_external_calls", "min_sends", "min_writes", "min_deletes",
    "domain_allowlisted", "carries_read_content", "source_untrusted",
    "read_sensitive", "cross_run_campaign",
    # F99: keyword-free framed-secret signal for api_call payloads,
    # computed by ToolExecutor._context from the call's own params.
    "high_entropy_payload",
    # P7 (wave-27): raw registry fetch via api_call/http_post, plus the
    # governed-install gates for install_package — all computed by
    # ToolExecutor._context from gov/supplychain_install.py.
    "package_fetch", "install_allowlisted", "install_integrity_verified",
    # S5 (K-052): cross-run per-principal velocity signal, computed by
    # ToolExecutor._context for send/write/egress tools.
    "velocity_exceeded",
    # F110 (wave-34): harness-initiated platform egress (non-tool-call
    # uploads, the ZCode class). Set by gov/platform_egress.py when it
    # routes a collection upload through the policy engine; the
    # deny-platform-egress-unallowlisted rule below is the first egress
    # rule whose match block is NOT keyed on tool:.
    "platform_egress",
    # F111 (wave-34): identity-bound egress (GTG-50020 class). Set by
    # ToolExecutor._context for send/api_call tools when a credential
    # on the call is not bound to the provisioned session identity;
    # the credential_identity_mismatch rule denies + audits.
    "credential_identity_mismatch",
    "when",
}

VALID_EFFECTS = {"deny", "require_approval", "allow"}

# F90 (Wave 25) — the AGT scope-typo class: a misspelled field must be
# refused LOUDLY at load, never silently ignored or demoted. Rule-level
# fields, top-level sections, approvals subkeys, and ``when`` operators
# are all allowlisted; anything else raises ValueError. (The D3 Cedar
# export already refuses unknown rule fields — gov/policy_export.py
# ``_KNOWN_RULE_FIELDS``; the core engine now matches it, plus the
# top-level and approvals layers the export never sees.)
KNOWN_RULE_FIELDS = frozenset(
    {"id", "effect", "match", "reason", "description", "flag", "bridge",
     # Set programmatically by gov/dsl.apply_dsl BEFORE validation runs.
     "dsl_rule",
     # Stamped by apply_dsl AFTER validation; listed so a stamped rule
     # that is re-validated later is not rejected.
     "dsl_source_hash"})

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"version", "roles", "rate_limit", "egress", "approvals",
     "auto_approve", "campaign_allowlist", "delegation", "log_limits",
     "budgets", "run_limits", "velocity", "policies",
     "critical_windows"})

KNOWN_APPROVALS_KEYS = frozenset(
    {"ttl_hours", "batch_excluded_queue_reasons", "delegation", "quorum"})

KNOWN_WHEN_OPS = frozenset({"gte", "lte", "gt", "lt", "eq", "neq"})

_EFFECT_RANK = {"deny": 2, "require_approval": 1, "allow": 0}

DEFAULT_ROLES = {
    "support": ["read_file", "send_email"],
    "coder": ["read_file", "write_file", "delete_file", "api_call",
              # P7 (wave-27): governed installs ride with the roles that
              # already fetch over the network.
              "install_package"],
    "researcher": ["read_file", "api_call", "http_post", "send_email",
                   "install_package"],
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
    def __init__(self, effect, reason, policy_id=None, flag=None,
                 matched_rules=None):
        self.effect = effect          # "allow" | "require_approval" | "deny"
        self.reason = reason
        self.policy_id = policy_id
        self.flag = flag
        # Wave-79 (totality): the rules that fired, in evaluation order.
        # The engine evaluates deny -> require_approval -> allow with
        # first-match-wins per pass, so at most one rule determines the
        # verdict; the fail-closed default is the reserved sentinel
        # "default_deny" (documented, not hidden). Auto-derived from
        # policy_id unless explicitly passed.
        if matched_rules is None:
            matched_rules = [policy_id] if policy_id else ["default_deny"]
        self.matched_rules = list(matched_rules)

    def to_dict(self):
        return {"effect": self.effect, "reason": self.reason,
                "policy_id": self.policy_id, "flag": self.flag,
                "matched_rules": list(self.matched_rules)}


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
    def __init__(self, yaml_path, *, pinset=None, artifact_id=None):
        self.yaml_path = Path(yaml_path)
        if pinset is not None:
            # Wave-80: the forced load path. The policy file is read
            # through the digest gate (one read; the engine parses the
            # SAME bytes the pin verified — no verify/parse TOCTOU).
            # ``artifact_id`` names the pin (e.g. "policy:genesis").
            # WITHOUT a pinset the constructor keeps its legacy
            # behavior (unverified read — the documented wave-80
            # residual; see load_gate wiring). Callers that want the
            # guarantee use from_verified() or pass a pinset.
            if artifact_id is None:
                raise ValueError(
                    "artifact_id is required when pinset is given")
            from .load_gate import load_file_verified
            verified = load_file_verified(pinset, artifact_id,
                                          self.yaml_path)
            self.verified_artifact_id = artifact_id
            self.verified_digest = verified.digest
            raw = verified.data
        else:
            raw = self.yaml_path.read_bytes()
        self._init_from_bytes(raw, source_label=str(self.yaml_path))

    @classmethod
    def from_text(cls, text, source_label="<policy text>"):
        """Build an engine from in-memory YAML (the governed path).

        Wave-75: the governed policy-change path applies the *stored
        change artifact*, never a re-read of a file (the Plugin4Shell
        lesson — verify the artifact, not the reference). ``text`` is
        the exact buffer that was hashed into the change's
        ``policy_digest``; the F53 one-buffer rule applies here too.
        """
        if not isinstance(text, str):
            raise ValueError("policy text must be str, got %r"
                             % type(text).__name__)
        raw = text.encode("utf-8")
        engine = cls.__new__(cls)
        engine.yaml_path = None
        engine.verified_artifact_id = None
        engine.verified_digest = None
        engine._init_from_bytes(raw, source_label=source_label)
        return engine

    @classmethod
    def from_verified(cls, pinset, artifact_id, path, *, log=None):
        """Build an engine from a digest-verified policy file
        (wave-80 — the FORCED bootstrap-policy load path).

        The file is loaded through ``load_gate.load_file_verified``:
        one read, the bytes hashed against the pin, and the engine
        parses those EXACT bytes — the ref namespace never enters,
        and a file swap between check and parse is structurally
        impossible (there is only one read). ``artifact_id`` names
        the pin (e.g. ``"policy:genesis"``); unpinned or
        digest-mismatched files raise ``ArtifactRefused`` — there is
        no legacy fallback inside this constructor.

        The engine records ``verified_artifact_id`` /
        ``verified_digest`` so the bootstrap can pin the genesis
        record to the governed pin (see
        ``GovernedPolicyStore.bootstrap_from_verified``).
        """
        from .load_gate import load_file_verified
        verified = load_file_verified(pinset, artifact_id, path, log=log)
        engine = cls.__new__(cls)
        engine.yaml_path = Path(path)
        engine.verified_artifact_id = artifact_id
        engine.verified_digest = verified.digest
        engine._init_from_bytes(verified.data,
                                source_label=str(path))
        return engine

    def _init_from_bytes(self, raw, source_label):
        self.policy_hash = sha256(raw).hexdigest()
        self.source_digest = self.policy_hash
        # Wave-80: which (if any) governed pin this engine's bytes
        # were verified against. None on the legacy from_text /
        # unverified-constructor paths (documented residual).
        if not hasattr(self, "verified_artifact_id"):
            self.verified_artifact_id = None
        if not hasattr(self, "verified_digest"):
            self.verified_digest = None
        # F53 (R12): parse the SAME buffer the pin hashed. A second
        # read of the path here (the old load_yaml(str(path)) call)
        # re-opened a TOCTOU window: a policy-file writer winning the
        # race between the hash read and the parse read got the pin to
        # attest pristine bytes while the engine enforced attacker
        # bytes. One read, no window.
        cfg = parse_yaml(raw.decode("utf-8")) or {}
        # Wave-79 (totality): the policy version that names the rule set
        # on every decision record. The YAML `version:` top-level is the
        # source of truth; a missing version stamps "unversioned"
        # (honest, never blank — the schema requires a non-empty
        # string).
        self.policy_version = str(cfg.get("version", "unversioned"))
        # F90: unknown top-level sections are refused loudly. A misspelled
        # section (``bugets:`` for ``budgets:``) previously loaded
        # silently with the control unenforced — the exact shape of the
        # AGT scope-typo fail-open.
        unknown_top = sorted(k for k in cfg if k not in KNOWN_TOP_LEVEL_KEYS)
        if unknown_top:
            raise ValueError(
                "policy: unknown top-level key(s) %r (known: %s); "
                "refusing rather than silently ignoring"
                % (unknown_top, sorted(KNOWN_TOP_LEVEL_KEYS)))
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
        # D1-core: delegation/quorum policy sections. Normalized
        # fail-closed by gov/approvals.py's normalizers — an invalid
        # section raises ValueError HERE at load (never a silent
        # mis-shape). Absent delegation = disabled (opt-in); absent
        # quorum = None (no M-of-N gate).
        _approvals_cfg = cfg.get("approvals") or {}
        # F90: unknown approvals subkeys are refused loudly. A misspelled
        # ``batch_excluded_queue_reasons`` previously normalized to ()
        # silently, making security-flagged items batch-approvable.
        unknown_appr = sorted(
            k for k in _approvals_cfg if k not in KNOWN_APPROVALS_KEYS)
        if unknown_appr:
            raise ValueError(
                "policy approvals: unknown key(s) %r (known: %s); "
                "refusing rather than silently ignoring"
                % (unknown_appr, sorted(KNOWN_APPROVALS_KEYS)))
        self.approvals_delegation = _normalize_delegation_config(
            _approvals_cfg.get("delegation"))
        self.approvals_quorum = _normalize_quorum_config(
            _approvals_cfg.get("quorum"))
        # P10 (wave-24): TOP-LEVEL authority delegation (agent→agent
        # grants) — a different primitive from approvals.delegation
        # (D1-core human approval stewardship) above. Normalized
        # fail-closed by gov/approvals.py; absent = disabled (opt-in).
        self.authority_delegation = _normalize_authority_delegation_config(
            cfg.get("delegation"))
        # F22: policy-configurable audit-log size guard.
        self.log_limits = self._normalize_log_limits(cfg.get("log_limits"))
        # S2 (K-018): hard spend/token/action budgets. Absent section =
        # unenforced (never zero); malformed values fail the load.
        self.budgets = self._normalize_budgets(cfg.get("budgets"))
        # S4 (K-045): total-step budget per run. Absent = unenforced.
        self.run_limits = self._normalize_run_limits(cfg.get("run_limits"))
        # S5 (K-052): cross-run per-principal velocity thresholds.
        # Absent = guard disabled.
        self.velocity = self._normalize_velocity(cfg.get("velocity"))
        # S1: AgentSpec DSL provenance. apply_dsl() fills these in when a
        # DSL source is promoted; without a DSL they stay null and
        # behavior is unchanged.
        self.dsl_source_hash = None
        self.dsl_pinned = False
        self.dsl_rule_ids = ()
        self.policies = []
        for i, rule in enumerate(cfg.get("policies") or []):
            self._validate_rule(rule, i)
            self.policies.append(rule)
        # Wave-53 P1 (sterile cockpit): the ``critical_windows:`` block.
        # Absent = feature off (None). Present = validated fail-closed
        # HERE at load via gov/sterile.py's WindowPolicy — an invalid
        # block refuses the policy rather than half-applying at
        # runtime. The raw block is kept (the executor builds the
        # controller from it).
        _cw = cfg.get("critical_windows")
        self.critical_windows = _cw
        if _cw is not None:
            from .sterile import WindowPolicy  # local: sterile has no
            # policy import (no cycle)
            WindowPolicy(_cw)  # raises SterilePolicyError on invalid

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
    def _normalize_budgets(cfg):
        """Normalize the ``budgets:`` section (S2 / K-018).

        Keys: ``max_tokens_per_run`` (non-negative int),
        ``max_spend_per_run`` (non-negative number),
        ``max_actions_per_run`` (non-negative int),
        ``price_per_1k_tokens`` (non-negative number, optional — converts
        accrued tokens into spend when the adapter reports tokens only).
        Absent section -> {} (unenforced, never zero). Malformed values
        raise ValueError (fail closed at load: a misconfigured ceiling
        must never silently become "unlimited", and values are never
        silently coerced).
        """
        if cfg is None:
            return {}
        if not isinstance(cfg, dict):
            raise ValueError("budgets must be a mapping")
        _INT_KEYS = ("max_tokens_per_run", "max_actions_per_run")
        _NUM_KEYS = ("max_spend_per_run", "price_per_1k_tokens")
        for key in cfg:
            if key not in _INT_KEYS + _NUM_KEYS:
                raise ValueError("budgets: unknown key %r" % (key,))
        out = {}
        for key in _INT_KEYS:
            if key in cfg:
                v = cfg[key]
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    raise ValueError(
                        "budgets.%s must be a non-negative integer, got %r"
                        % (key, v))
                out[key] = v
        for key in _NUM_KEYS:
            if key in cfg:
                v = cfg[key]
                if (isinstance(v, bool) or not isinstance(v, (int, float))
                        or v < 0):
                    raise ValueError(
                        "budgets.%s must be a non-negative number, got %r"
                        % (key, v))
                out[key] = float(v)
        return out

    @staticmethod
    def _normalize_run_limits(cfg):
        """Normalize the ``run_limits:`` section (S4 / K-045).

        Currently ``max_tool_calls_per_run`` (non-negative int): total
        tool-call attempts per run. Absent section -> {} (unenforced).
        Malformed values raise ValueError (fail closed at load).
        """
        if cfg is None:
            return {}
        if not isinstance(cfg, dict):
            raise ValueError("run_limits must be a mapping")
        for key in cfg:
            if key != "max_tool_calls_per_run":
                raise ValueError("run_limits: unknown key %r" % (key,))
        out = {}
        if "max_tool_calls_per_run" in cfg:
            v = cfg["max_tool_calls_per_run"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(
                    "run_limits.max_tool_calls_per_run must be a "
                    "non-negative integer, got %r" % (v,))
            out["max_tool_calls_per_run"] = v
        return out

    @staticmethod
    def _normalize_velocity(cfg):
        """Normalize the ``velocity:`` section (S5 / K-052).

        Keys: ``window_secs`` (positive number; defaults to 24h when the
        section is present but the window is omitted),
        ``max_sends`` / ``max_writes`` (non-negative ints),
        ``max_egress_bytes`` (non-negative number). A threshold that is
        absent is unenforced for that dimension (never zero). Absent
        section -> {} (guard disabled). Malformed values raise
        ValueError (fail closed at load).
        """
        if cfg is None:
            return {}
        if not isinstance(cfg, dict):
            raise ValueError("velocity must be a mapping")
        for key in cfg:
            if key not in ("window_secs", "max_sends", "max_writes",
                           "max_egress_bytes"):
                raise ValueError("velocity: unknown key %r" % (key,))
        out = {}
        if "window_secs" in cfg:
            v = cfg["window_secs"]
            if (isinstance(v, bool) or not isinstance(v, (int, float))
                    or v <= 0):
                raise ValueError(
                    "velocity.window_secs must be a positive number, got %r"
                    % (v,))
            out["window_secs"] = float(v)
        else:
            # The section is configured but no window given: default to
            # the campaign window (24h) rather than a zero/meaningless
            # window. Absent *section* still means disabled.
            out["window_secs"] = 24.0 * 3600.0
        for key in ("max_sends", "max_writes"):
            if key in cfg:
                v = cfg[key]
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    raise ValueError(
                        "velocity.%s must be a non-negative integer, got %r"
                        % (key, v))
                out[key] = v
        if "max_egress_bytes" in cfg:
            v = cfg["max_egress_bytes"]
            if (isinstance(v, bool) or not isinstance(v, (int, float))
                    or v < 0):
                raise ValueError(
                    "velocity.max_egress_bytes must be a non-negative "
                    "number, got %r" % (v,))
            out[key] = v
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
        # F90: unknown rule-level fields are refused loudly. The AGT
        # scope-typo shape — ``macht:`` for ``match:`` on an allow rule —
        # previously loaded silently with ``match`` defaulting to {},
        # i.e. the rule matched EVERY action (deny->allow flip).
        if not isinstance(rule, dict):
            raise ValueError("policy rule %d: rule must be a mapping, got %r"
                             % (index, rule))
        unknown_fields = sorted(
            k for k in rule if k not in KNOWN_RULE_FIELDS)
        if unknown_fields:
            raise ValueError(
                "policy %s: unknown rule field(s) %r (known: %s); "
                "refusing rather than silently ignoring"
                % (rule_id, unknown_fields, sorted(KNOWN_RULE_FIELDS)))
        effect = rule.get("effect")
        if effect not in VALID_EFFECTS:
            raise ValueError("policy %s: invalid effect %r (must be one of %s)"
                             % (rule_id, effect, sorted(VALID_EFFECTS)))
        match = rule.get("match") or {}
        if not isinstance(match, dict):
            raise ValueError("policy %s: match must be a mapping, got %r"
                             % (rule_id, match))
        for key in match:
            if key not in KNOWN_MATCH_KEYS:
                raise ValueError("policy %s: unknown match key %r (known: %s)"
                                 % (rule_id, key, sorted(KNOWN_MATCH_KEYS)))
        for tool in _as_list(match.get("tool")):
            if tool not in KNOWN_TOOLS:
                raise ValueError("policy %s: unknown tool %r (known: %s)"
                                 % (rule_id, tool, sorted(KNOWN_TOOLS)))
        self._validate_when(rule_id, match.get("when"))

    @staticmethod
    def _validate_when(rule_id, when):
        """Validate ``when`` conditions fail-closed (F90).

        A typo'd operator (``gtte`` for ``gte``) previously matched no
        known op, making the condition vacuously TRUE — an allow rule
        gated on it then fired unconditionally. A missing ``path`` made
        the condition always FALSE, so a deny rule gated on it never
        fired. Both shapes now raise at load.
        """
        if when is None:
            return
        if not isinstance(when, list):
            raise ValueError("policy %s: when must be a list of conditions, "
                             "got %r" % (rule_id, when))
        for j, cond in enumerate(when):
            where = "policy %s: when[%d]" % (rule_id, j)
            if not isinstance(cond, dict):
                raise ValueError("%s: condition must be a mapping, got %r"
                                 % (where, cond))
            if not isinstance(cond.get("path"), str) or not cond["path"]:
                raise ValueError("%s: condition needs a non-empty string "
                                 "'path', got %r" % (where, cond.get("path")))
            ops = [op for op in cond if op != "path"]
            unknown_ops = sorted(op for op in ops if op not in KNOWN_WHEN_OPS)
            if unknown_ops:
                raise ValueError(
                    "%s: unknown operator(s) %r (known: %s); refusing "
                    "rather than treating the condition as vacuously true"
                    % (where, unknown_ops, sorted(KNOWN_WHEN_OPS)))
            if not ops:
                raise ValueError("%s: condition has no operator "
                                 "(vacuously true); refusing" % (where,))

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
        if "velocity_exceeded" in match:
            if bool(context.get("velocity_exceeded")) != bool(match["velocity_exceeded"]):
                return False
        # F110 (wave-34): harness-initiated platform egress. Same
        # bool-compare convention as the other signals; set by
        # gov/platform_egress.py, never by ToolExecutor._context.
        if "platform_egress" in match:
            if bool(context.get("platform_egress")) != bool(match["platform_egress"]):
                return False
        # F111 (wave-34): identity-bound egress. Same bool-compare
        # convention; set by ToolExecutor._context for send/api_call
        # tools via the run's CredentialManifest.
        if "credential_identity_mismatch" in match:
            if bool(context.get("credential_identity_mismatch")) != bool(match["credential_identity_mismatch"]):
                return False
        # P7 (wave-27): raw registry fetch, and the governed-install
        # gates. Same bool-compare convention as the other signals.
        if "package_fetch" in match:
            if bool(context.get("package_fetch")) != bool(match["package_fetch"]):
                return False
        if "install_allowlisted" in match:
            if bool(context.get("install_allowlisted")) != bool(match["install_allowlisted"]):
                return False
        if "install_integrity_verified" in match:
            if bool(context.get("install_integrity_verified")) != bool(match["install_integrity_verified"]):
                return False
        if "high_entropy_payload" in match:
            if bool(context.get("high_entropy_payload")) != bool(match["high_entropy_payload"]):
                return False
        if "when" in match:
            if not _check_conditions(match["when"], context):
                return False
        return True
