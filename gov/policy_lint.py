"""Policy linter: catch dead, shadowed, contradictory, and dangerous rules.

Run ``python -m gov.policy_lint policies/default.yaml`` (or the
``gov-policy-lint`` console script). Exits 0 when no findings, 1 otherwise.

Finding kinds and severities:

  error:
    unknown_tool        match.tool names a tool that does not exist
    unknown_match_key   match uses a key the engine does not understand
    unknown_role        match.role names a role the policy does not define
    invalid_effect      effect is not allow/deny/require_approval
    duplicate_rule_id   two rules share an id (breaks audit traceability)
    unreachable_rule    an allow/require_approval rule that can never fire
                        (e.g. its tool is in no role's allowlist, so the
                        executor rejects the action before policy evaluation)
    contradictory_rule  two rules with mutually-covering conditions but
                        different effects
    overly_broad_allow  (error variant) an allow rule with an EMPTY match:
                        it allows every action for every role

  warning:
    overly_broad_allow  allow on tool alone for a dangerous tool
                        (send_email/http_post/delete_file) with no other
                        constraints
    missing_deny_coverage
                        no deny rule covers a dangerous tool at all: with
                        deny-by-default this is not an immediate hole, but
                        an explicit deny with a flag is the auditable
                        control for exfiltration/destruction shapes
    egress_budget_absurd
                        rate_limit.max_egress_bytes_per_run is set so high
                        (>= 1 GiB) it cannot constrain any plausible run:
                        the knob is effectively "unlimited" without saying
                        so — lower it or remove it (the 256 KiB default
                        applies)

  error:
    invalid_egress_budget
                        rate_limit.max_egress_bytes_per_run is not a
                        positive integer (missing/non-integer/<=0): the
                        executor fails closed to the conservative default,
                        but the config is not what the deployer wrote

  error (D1-core, L1-L9: each mirrors the engine's fail-closed
  normalizer — the engine refuses to load the policy):
    delegation_invalid_shape
                        approvals.delegation is present but not a mapping
                        (L1)
    delegation_enabled_not_bool
                        approvals.delegation.enabled is not true/false
                        (L2: delegation is opt-in; no silent enable)
    delegation_max_hops_out_of_range
                        approvals.delegation.max_hops is not an int in
                        1..5 (L3)
    quorum_invalid_shape
                        approvals.quorum is present but not a mapping (L4)
    quorum_min_approvals_invalid
                        approvals.quorum.min_approvals is not an int >= 1
                        (L5)
    quorum_eligible_principals_invalid
                        approvals.quorum.eligible_principals is not a
                        non-empty list of unique non-empty strings (L6:
                        duplicates would let one human fill two vote slots)
    quorum_unreachable  approvals.quorum.min_approvals exceeds
                        len(eligible_principals) (L7): silent starvation
    quorum_deny_veto_not_true
                        approvals.quorum.deny_veto is present and not true
                        (L8): the one-deny veto is non-negotiable
    quorum_flags_invalid
                        approvals.quorum.flags is present but not a list
                        of non-empty strings (L9)

  warning (D1-core, L10: valid-but-dangerous, F30 pattern):
    delegation_long_chain
                        approvals.delegation.max_hops > 1: longer chains
                        let stewardship diffuse across approvers

  info:
    overly_broad_allow  allow on tool alone for a non-dangerous tool:
                        works, but consider constraining role/path

Design notes (from OPA/Cedar validation practice, applied to our simpler
YAML engine):

* The engine evaluates denies first (forbid priority), then
  require_approval, then allow. The linter mirrors that: a rule is
  "shadowed" only by a rule that is evaluated before it.
* Unknown names fail closed: a match on an unknown tool/role never matches
  anything the engine understands, so the rule is dead config.
"""

import json
import sys
from pathlib import Path

from .policy import (DEFAULT_ROLES, KNOWN_MATCH_KEYS, KNOWN_TOOLS,
                     VALID_EFFECTS, _EFFECT_RANK, _as_list)
from .yamlmini import load as yaml_load
# D1-core: shared delegation ceiling so the linter and the engine's
# fail-closed normalizer cannot drift apart.
from .approvals import DELEGATION_MAX_HOPS_CEILING
from .approvals import AUTHORITY_DELEGATION_MAX_DEPTH_CEILING

DANGEROUS_TOOLS = {"send_email", "http_post", "delete_file"}

# F33 (HARDENING-R8): an egress byte budget at or above this no longer
# constrains any plausible governed run — a single run legitimately
# moving a gigabyte of outbound tool payloads is not a governed run, it
# is a data pipeline. The threshold is deterministic and documented so
# the warning is reproducible, not a vibe.
_ABSURD_EGRESS_BYTES = 1 << 30  # 1 GiB


def _covers(sup, sub):
    """Implication check: is every action matched by *sub* also matched by
    *sup*? In other words, do *sub*'s conditions imply *sup*'s conditions?

    A key that *sup* constrains but *sub* does not is a coverage failure:
    *sub* matches actions with any value for that key, and *sup* does not
    match all of them.
    """
    for key, sup_val in sup.items():
        if key not in KNOWN_MATCH_KEYS:
            return False  # unknown semantics: do not claim coverage
        if key not in sub:
            return False  # sub leaves this unconstrained: cannot imply sup
        sub_val = sub[key]
        if key == "tool":
            if not (set(_as_list(sub_val)) <= set(_as_list(sup_val))):
                return False
        elif key in ("role", "agent"):
            if not (set(_as_list(sub_val)) <= set(_as_list(sup_val))):
                return False
        elif key == "path_contains_any":
            if set(_as_list(sup_val)) != set(_as_list(sub_val)):
                return False
        elif key in ("min_external_calls", "min_sends", "min_writes", "min_deletes"):
            # sub's higher threshold fires on a subset of sup's actions.
            if int(sub_val) < int(sup_val):
                return False
        elif key in ("path_outside_sandbox", "domain_allowlisted",
                     "carries_read_content", "source_untrusted",
                     # P7 (wave-27): the remaining boolean signals were
                     # missing from this group, so the lint treated them
                     # as unconstrained and reported false
                     # shadowed/contradictory pairs for rules that pin
                     # them to true vs false (e.g. the install_package
                     # allowlist/integrity gates).
                     "read_sensitive", "cross_run_campaign",
                     "velocity_exceeded", "high_entropy_payload",
                     "package_fetch", "install_allowlisted",
                     "install_integrity_verified"):
            if bool(sub_val) != bool(sup_val):
                return False
        elif key == "when":
            if sup_val != sub_val:
                return False
    return True


def _precedes(a, b, ia, ib):
    ra, rb = _EFFECT_RANK[a.get("effect")], _EFFECT_RANK[b.get("effect")]
    return ra > rb or (ra == rb and ia < ib)


def _policy_roles(cfg):
    """Role -> tool allowlist the engine would enforce (R2)."""
    roles = cfg.get("roles")
    if roles:
        return {r: list(t) for r, t in roles.items()}
    return {r: list(t) for r, t in DEFAULT_ROLES.items()}


def _rule_id(rule, i):
    return rule.get("id", "rule-%d" % i)


def _match_of(rule):
    """The rule's match mapping, or {} when absent/malformed.

    Malformed (non-mapping) matches are reported by the structural
    checks; every consumer below must use this helper so one bad rule
    cannot crash the lint run.
    """
    m = rule.get("match", None) or {}
    return m if isinstance(m, dict) else {}


def lint_file(path):
    """Return a list of finding dicts for the policy file at *path*."""
    cfg = yaml_load(str(Path(path))) or {}
    rules = cfg.get("policies") or []
    roles = _policy_roles(cfg)
    findings = []

    def add(kind, severity, rule_id, detail):
        findings.append({"kind": kind, "severity": severity,
                         "rule_id": rule_id, "detail": detail})

    # ---- structural checks ------------------------------------------------
    seen_ids = {}
    for i, rule in enumerate(rules):
        rid = _rule_id(rule, i)
        if rid in seen_ids:
            add("duplicate_rule_id", "error", rid,
                "rule id %r is also used by %s; ids must be unique for "
                "audit traceability" % (rid, seen_ids[rid]))
        else:
            seen_ids[rid] = "rule-%d" % i

        effect = rule.get("effect")
        if effect not in VALID_EFFECTS:
            add("invalid_effect", "error", rid,
                "effect %r is not one of %s" % (effect, sorted(VALID_EFFECTS)))
        match = _match_of(rule)
        raw_match = rule.get("match")
        if raw_match is not None and not isinstance(raw_match, dict):
            add("invalid_match", "error", rid,
                "match block is not a mapping (got %r); the engine cannot "
                "evaluate this rule" % (raw_match,))
        for tool in _as_list(match.get("tool")):
            if tool not in KNOWN_TOOLS:
                add("unknown_tool", "error", rid,
                    "tool %r does not exist (known: %s)"
                    % (tool, sorted(KNOWN_TOOLS)))
        for key in match:
            if key not in KNOWN_MATCH_KEYS:
                add("unknown_match_key", "error", rid,
                    "match key %r is not understood by the engine" % key)
        for role in _as_list(match.get("role")):
            if role not in roles:
                add("unknown_role", "error", rid,
                    "role %r is not defined in the policy's roles section "
                    "(known: %s)" % (role, sorted(roles)))

    # ---- auto_approve section ------------------------------------------------
    # Low-risk auto-approval is a loaded control: flag a section that looks
    # intended but would silently not fire (fail-closed normalization in
    # the engine means "almost enabled" is the same as "disabled").
    auto_cfg = cfg.get("auto_approve")
    if auto_cfg is not None:
        if not isinstance(auto_cfg, dict):
            add("invalid_auto_approve", "warning", "(policy)",
                "auto_approve section is not a mapping; the engine treats "
                "it as disabled")
        elif auto_cfg.get("enabled") not in (True, False, None):
            add("invalid_auto_approve", "warning", "(policy)",
                "auto_approve.enabled should be true/false; got %r "
                "(treated as disabled)" % (auto_cfg.get("enabled"),))
        elif auto_cfg.get("enabled") is True:
            try:
                cap = int(auto_cfg.get("max_risk_score", 25))
                if not 0 <= cap <= 100:
                    raise ValueError
            except (TypeError, ValueError):
                add("invalid_auto_approve", "warning", "(policy)",
                    "auto_approve.max_risk_score must be 0-100; got %r "
                    "(treated as disabled)"
                    % (auto_cfg.get("max_risk_score"),))
            else:
                # F30: a valid-but-dangerous cap. Warning, not error: the
                # deployer may intend it, but the risk must be named.
                if cap >= 90:
                    add("auto_approve_near_max_risk", "warning", "(policy)",
                        "auto_approve.enabled with max_risk_score=%d: "
                        "auto-approval covers near-maximum-risk actions, so "
                        "a queued campaign exfil fragment or a destructive "
                        "action would execute with no human in the loop. "
                        "Lower the cap or disable auto_approve." % cap)

    # ---- approvals.delegation / approvals.quorum sections (D1-core) --------
    # L1-L10: the linter mirrors the engine's fail-closed normalizers
    # (gov/approvals.py::_normalize_delegation_config /
    # _normalize_quorum_config) as advisory findings, so a broken
    # section is caught at lint time with a precise reason instead of
    # only at load time. Severities: anything the engine refuses to
    # load is an error; L10 (longer-than-default chains) is a warning
    # in the F30 valid-but-dangerous pattern.
    approvals_cfg = cfg.get("approvals") or {}
    if not isinstance(approvals_cfg, dict):
        add("approvals_invalid_shape", "error", "(policy)",
            "approvals section is not a mapping; the engine ignores it "
            "and delegation/quorum stay off")
    else:
        del_cfg = approvals_cfg.get("delegation")
        if del_cfg is not None:
            if not isinstance(del_cfg, dict):
                add("delegation_invalid_shape", "error", "(policy)",
                    "approvals.delegation must be a mapping when present "
                    "(L1); the engine refuses to load this policy")
            else:
                if ("enabled" in del_cfg
                        and not isinstance(del_cfg["enabled"], bool)):
                    add("delegation_enabled_not_bool", "error", "(policy)",
                        "approvals.delegation.enabled must be true/false, "
                        "got %r (L2: delegation is opt-in; the engine "
                        "refuses to load a non-bool rather than silently "
                        "enabling or disabling)" % (del_cfg["enabled"],))
                if "max_hops" in del_cfg:
                    hops = del_cfg["max_hops"]
                    if (isinstance(hops, bool)
                            or not isinstance(hops, int)
                            or not 1 <= hops
                            <= DELEGATION_MAX_HOPS_CEILING):
                        add("delegation_max_hops_out_of_range", "error",
                            "(policy)",
                            "approvals.delegation.max_hops must be an int "
                            "in 1..%d, got %r (L3); the engine refuses to "
                            "load this policy"
                            % (DELEGATION_MAX_HOPS_CEILING, hops))
                    elif hops > 1:
                        # L10: valid, but chains beyond one hop let an
                        # approver launder responsibility ("I just passed
                        # it on") and complicate forensics. Name the risk.
                        add("delegation_long_chain", "warning", "(policy)",
                            "approvals.delegation.max_hops=%d (L10): "
                            "delegation chains longer than one hop let "
                            "stewardship diffuse across approvers; keep "
                            "max_hops=1 unless the deployment genuinely "
                            "needs re-delegation" % hops)
        q_cfg = approvals_cfg.get("quorum")
        if q_cfg is not None:
            if not isinstance(q_cfg, dict):
                add("quorum_invalid_shape", "error", "(policy)",
                    "approvals.quorum must be a mapping when present "
                    "(L4); the engine refuses to load this policy")
            else:
                min_a = q_cfg.get("min_approvals")
                if (isinstance(min_a, bool)
                        or not isinstance(min_a, int) or min_a < 1):
                    add("quorum_min_approvals_invalid", "error", "(policy)",
                        "approvals.quorum.min_approvals must be an int >= "
                        "1, got %r (L5); the engine refuses to load this "
                        "policy" % (min_a,))
                eligible = q_cfg.get("eligible_principals")
                if (not isinstance(eligible, (list, tuple)) or not eligible
                        or any(not isinstance(p, str) or not p.strip()
                               for p in eligible)):
                    add("quorum_eligible_principals_invalid", "error",
                        "(policy)",
                        "approvals.quorum.eligible_principals must be a "
                        "non-empty list of non-empty strings (L6); the "
                        "engine refuses to load this policy")
                elif len({p.strip() for p in eligible}) != len(eligible):
                    add("quorum_eligible_principals_invalid", "error",
                        "(policy)",
                        "approvals.quorum.eligible_principals lists a "
                        "principal twice (L6): one human would fill two "
                        "vote slots; the engine refuses to load this "
                        "policy")
                elif (isinstance(min_a, int) and not isinstance(min_a, bool)
                        and min_a > len(eligible)):
                    # L7: an unreachable quorum is silent starvation —
                    # records queue that no vote pattern can ever decide.
                    add("quorum_unreachable", "error", "(policy)",
                        "approvals.quorum.min_approvals (%d) exceeds "
                        "len(eligible_principals) (%d) (L7): the quorum "
                        "can never be reached; the engine refuses to "
                        "load this policy" % (min_a, len(eligible)))
                if "deny_veto" in q_cfg and q_cfg["deny_veto"] is not True:
                    # L8: the one-deny veto is non-negotiable. An
                    # M-of-N scheme where dissent can be outvoted is a
                    # rubber-stamp amplifier, not a safety gate.
                    add("quorum_deny_veto_not_true", "error", "(policy)",
                        "approvals.quorum.deny_veto must be true or "
                        "absent, got %r (L8): the one-deny veto is "
                        "non-negotiable; the engine refuses to load this "
                        "policy" % (q_cfg["deny_veto"],))
                flags = q_cfg.get("flags")
                if (flags is not None
                        and (not isinstance(flags, (list, tuple))
                             or any(not isinstance(f, str) or not f.strip()
                                    for f in flags))):
                    add("quorum_flags_invalid", "error", "(policy)",
                        "approvals.quorum.flags must be a list of "
                        "non-empty strings when present (L9); the engine "
                        "refuses to load this policy")

    # ---- top-level delegation section (P10 authority delegation) -----------
    # Authority delegation (agent→agent grants) is a DIFFERENT primitive
    # from approvals.delegation (D1-core human approval stewardship)
    # above — the linter checks both, under distinct finding kinds.
    # The linter mirrors the engine's fail-closed normalizer
    # (gov/approvals.py::_normalize_authority_delegation_config) as
    # advisory findings: anything the engine refuses to load is an
    # error; unscoped_delegation: flag is a WARNING (the P10 residual:
    # framing claims without a grant execute labeled, not denied).
    auth_cfg = cfg.get("delegation")
    if auth_cfg is not None:
        if not isinstance(auth_cfg, dict):
            add("authority_delegation_invalid_shape", "error", "(policy)",
                "delegation must be a mapping when present; the engine "
                "refuses to load this policy")
        else:
            if ("enabled" in auth_cfg
                    and not isinstance(auth_cfg["enabled"], bool)):
                add("authority_delegation_enabled_not_bool", "error",
                    "(policy)",
                    "delegation.enabled must be true/false, got %r "
                    "(opt-in; the engine refuses to load a non-bool "
                    "rather than silently enabling or disabling)"
                    % (auth_cfg["enabled"],))
            for ttl_key in ("default_ttl_minutes", "max_ttl_minutes"):
                if ttl_key in auth_cfg:
                    ttl = auth_cfg[ttl_key]
                    if (isinstance(ttl, bool) or not isinstance(ttl, int)
                            or ttl < 1):
                        add("authority_delegation_ttl_invalid", "error",
                            "(policy)",
                            "delegation.%s must be a positive int, got %r; "
                            "the engine refuses to load this policy"
                            % (ttl_key, ttl))
            dflt = auth_cfg.get("default_ttl_minutes")
            maxt = auth_cfg.get("max_ttl_minutes")
            if (isinstance(dflt, int) and not isinstance(dflt, bool)
                    and isinstance(maxt, int) and not isinstance(maxt, bool)
                    and dflt > maxt):
                add("authority_delegation_ttl_invalid", "error", "(policy)",
                    "delegation.default_ttl_minutes (%d) exceeds "
                    "delegation.max_ttl_minutes (%d); the engine refuses "
                    "to load this policy" % (dflt, maxt))
            if "max_depth" in auth_cfg:
                depth = auth_cfg["max_depth"]
                if (isinstance(depth, bool) or not isinstance(depth, int)
                        or not 1 <= depth
                        <= AUTHORITY_DELEGATION_MAX_DEPTH_CEILING):
                    add("authority_delegation_max_depth_out_of_range",
                        "error", "(policy)",
                        "delegation.max_depth must be an int in 1..%d, "
                        "got %r; the engine refuses to load this policy"
                        % (AUTHORITY_DELEGATION_MAX_DEPTH_CEILING, depth))
            rpf = auth_cfg.get("require_provisioned_for")
            if (rpf is not None
                    and (not isinstance(rpf, (list, tuple))
                         or any(not isinstance(x, str) or not x.strip()
                                for x in rpf))):
                add("authority_delegation_require_provisioned_invalid",
                    "error", "(policy)",
                    "delegation.require_provisioned_for must be a list of "
                    "non-empty strings when present, got %r; the engine "
                    "refuses to load this policy" % (rpf,))
            mode = auth_cfg.get("unscoped_delegation")
            if mode is not None and mode not in ("flag", "deny"):
                add("authority_delegation_unscoped_invalid", "error",
                    "(policy)",
                    "delegation.unscoped_delegation must be 'flag' or "
                    "'deny', got %r; the engine refuses to load this "
                    "policy" % (mode,))
            elif mode == "flag" and auth_cfg.get("enabled") is True:
                # P10 residual: framing claims without a grant execute
                # under the acting agent's authority, labeled only.
                # Warning, not error: the deployer may intend it, but
                # the residual must be named. Fires only when the
                # feature is ENABLED: with enabled:false the flag
                # default is inert (label-only, no governed
                # alternative in play — spec §7 non-goal) and the
                # shipped default must stay warning-free per the
                # policy-lint regression gate.
                add("unscoped_delegation_flag_default", "warning",
                    "(policy)",
                    "delegation is enabled with "
                    "unscoped_delegation: 'flag': "
                    "on_behalf_of/delegated_by claims WITHOUT a grant id "
                    "execute under the acting agent's authority, labeled "
                    "only (the P10 residual). Set 'deny' to refuse such "
                    "calls before execution.")

    # ---- rate_limit section ------------------------------------------------
    # F33 (HARDENING-R8): the egress byte budget is a security control —
    # validate it like one. A missing key is fine (the engine's
    # conservative 256 KiB default applies); a malformed key is an error
    # because the executor silently falls back to the default, which is
    # not what the deployer wrote. An absurdly high key is a warning
    # (F30 pattern): possibly intentional, but the risk must be named.
    rl_cfg = cfg.get("rate_limit")
    if rl_cfg is not None:
        if not isinstance(rl_cfg, dict):
            add("invalid_rate_limit", "error", "(policy)",
                "rate_limit section is not a mapping; the engine ignores "
                "it and applies defaults")
        else:
            budget = rl_cfg.get("max_egress_bytes_per_run")
            if budget is not None:
                if (isinstance(budget, bool)
                        or not isinstance(budget, int) or budget <= 0):
                    add("invalid_egress_budget", "error", "(policy)",
                        "rate_limit.max_egress_bytes_per_run must be a "
                        "positive integer (bytes); got %r. The executor "
                        "fails closed to the conservative default, but "
                        "fix the config." % (budget,))
                elif budget >= _ABSURD_EGRESS_BYTES:
                    add("egress_budget_absurd", "warning", "(policy)",
                        "rate_limit.max_egress_bytes_per_run=%d (>= 1 GiB): "
                        "no plausible governed run moves this much outbound "
                        "payload, so the budget cannot bite — it is "
                        "'unlimited' without saying so. Lower it or remove "
                        "it (the 256 KiB default applies)." % budget)

    # ---- reachability: can this rule ever fire through the executor? ------
    # The executor rejects any tool not in the caller's role allowlist
    # BEFORE policy evaluation, so an allow/require_approval rule for a
    # tool no role may use is dead config. (A deny rule on such a tool is
    # harmless belt-and-braces: the action is already rejected.)
    union_tools = set()
    for tools in roles.values():
        union_tools.update(tools)
    for i, rule in enumerate(rules):
        rid = _rule_id(rule, i)
        effect = rule.get("effect")
        if effect not in ("allow", "require_approval"):
            continue
        match = _match_of(rule)
        tools = set(_as_list(match.get("tool"))) if "tool" in match else set(KNOWN_TOOLS)
        known = tools & KNOWN_TOOLS
        if known and not (known & union_tools):
            add("unreachable_rule", "error", rid,
                "effect %s can never fire: tool(s) %s are in no role's "
                "allowlist, so the executor rejects the action before "
                "policy evaluation" % (effect, sorted(known)))
            continue
        mroles = set(_as_list(match.get("role"))) if "role" in match else None
        if mroles is not None and not (mroles & set(roles)):
            add("unreachable_rule", "error", rid,
                "effect %s can never fire: match.role names only unknown "
                "roles %s" % (effect, sorted(mroles)))

    # ---- overly broad allows ---------------------------------------------
    for i, rule in enumerate(rules):
        rid = _rule_id(rule, i)
        if rule.get("effect") != "allow":
            continue
        match = _match_of(rule)
        if not match:
            add("overly_broad_allow", "error", rid,
                "allow rule with an EMPTY match allows EVERY action for "
                "every role. Add match constraints or delete this rule.")
            continue
        if set(match) == {"tool"}:
            tools = set(_as_list(match["tool"]))
            dangerous = tools & DANGEROUS_TOOLS
            if dangerous:
                add("overly_broad_allow", "warning", rid,
                    "allows dangerous tool(s) %s constrained by tool name "
                    "only: no role, path, or context limits. Any role "
                    "permitted the tool can use it freely."
                    % sorted(dangerous))
            else:
                add("overly_broad_allow", "info", rid,
                    "allow constrained by tool name only (%s): works, but "
                    "prefer constraining role and path/context too."
                    % sorted(tools))

    # ---- missing deny coverage for dangerous tools ------------------------
    for tool in sorted(DANGEROUS_TOOLS):
        covered = False
        cover_id = None
        for i, rule in enumerate(rules):
            if rule.get("effect") != "deny":
                continue
            match = _match_of(rule)
            if "tool" not in match or tool in _as_list(match.get("tool")):
                covered = True
                cover_id = _rule_id(rule, i)
                break
        if not covered:
            add("missing_deny_coverage", "warning", "(policy)",
                "no deny rule covers dangerous tool %r. Deny-by-default "
                "still fails closed, but add an explicit deny (with a "
                "flag) so exfiltration/destruction attempts are auditable."
                % tool)

    # ---- shadowed rules (evaluated-later, covered-conditions) -------------
    for i, rule in enumerate(rules):
        rid = _rule_id(rule, i)
        match = _match_of(rule)
        for j, other in enumerate(rules):
            if i == j:
                continue
            oid = _rule_id(other, j)
            if not _precedes(other, rule, j, i):
                continue
            if _covers(_match_of(other), match):
                add("shadowed_rule", "error", rid,
                    "never fires: %s (effect %s) is evaluated first and "
                    "matches a superset of its conditions"
                    % (oid, other.get("effect")))
                break

    # ---- contradictory rules ----------------------------------------------
    # Mutually-covering conditions with different effects: forbid priority
    # makes the deny win, but the pair is almost certainly a config bug
    # (the identical-match case is the most common instance).
    reported = set()
    for i, rule in enumerate(rules):
        for j in range(i + 1, len(rules)):
            other = rules[j]
            if rule.get("effect") == other.get("effect"):
                continue
            m1, m2 = _match_of(rule), _match_of(other)
            if _covers(m1, m2) and _covers(m2, m1):
                pair = tuple(sorted((_rule_id(rule, i), _rule_id(other, j))))
                if pair in reported:
                    continue
                reported.add(pair)
                detail = ("conditions mutually cover %s (%s) vs %s (%s); "
                          "forbid priority resolves this today, but the "
                          "overlap is almost certainly unintended")
                add("contradictory_rule", "error", _rule_id(rule, i),
                    detail % (pair[0], rule.get("effect"),
                              pair[1], other.get("effect")))

    # ---- top-level control sections (F18/F21/F22) -------------------------
    # These are policy, so they are linted like rules: malformed sections
    # are errors (the engine would refuse to load them); allowlist
    # entries are listed as info so reviewers see the exemptions.
    allowlist = cfg.get("campaign_allowlist")
    if allowlist is not None:
        if not isinstance(allowlist, list):
            add("malformed_campaign_allowlist", "error", "-",
                "campaign_allowlist must be a list of [principal, "
                "registered_domain, [param keys]] entries")
        else:
            for i, entry in enumerate(allowlist):
                eid = "campaign_allowlist[%d]" % i
                if (not isinstance(entry, (list, tuple)) or len(entry) != 3
                        or not isinstance(entry[0], str) or not entry[0]
                        or not isinstance(entry[1], str) or not entry[1]
                        or not isinstance(entry[2], (list, tuple))
                        or not entry[2]
                        or any(not isinstance(k, str) or not k
                               for k in entry[2])):
                    add("malformed_campaign_allowlist", "error", eid,
                        "entry must be [principal, registered_domain, "
                        "[non-empty param keys]], got %r" % (entry,))
                else:
                    # F30: wildcards are schema-valid today and
                    # runtime-inert (matching is exact-string), but the
                    # linter's silence would turn a future
                    # glob/prefix-matching change into a silent
                    # whole-domain exemption. Warning, not error.
                    for field, val in (
                            ("principal", entry[0]), ("domain", entry[1])):
                        if "*" in val or "?" in val:
                            add("campaign_allowlist_wildcard", "warning",
                                eid,
                                "campaign_allowlist %s %r contains a "
                                "wildcard: exact-string matching makes it "
                                "grant nothing today, but if matching ever "
                                "becomes glob/prefix-based this entry would "
                                "silently exempt a whole domain/principal. "
                                "Remove the wildcard or narrow the entry."
                                % (field, val))
                    for kval in entry[2]:
                        if "*" in kval or "?" in kval:
                            add("campaign_allowlist_wildcard", "warning",
                                eid,
                                "campaign_allowlist param key %r contains a "
                                "wildcard: exact-string matching makes it "
                                "grant nothing today, but if matching ever "
                                "becomes glob/prefix-based this entry would "
                                "silently exempt matching traffic. Remove "
                                "the wildcard or narrow the entry." % kval)
            if allowlist and not any(
                    f["kind"] == "malformed_campaign_allowlist"
                    for f in findings):
                add("campaign_allowlist_entries", "info", "-",
                    "%d exemption(s): %s" % (
                        len(allowlist),
                        ", ".join("%s@%s[%s]" % (e[0], e[1], ",".join(e[2]))
                                  for e in allowlist)))
    excluded = (cfg.get("approvals") or {}).get(
        "batch_excluded_queue_reasons")
    if excluded is not None:
        if (not isinstance(excluded, list)
                or any(not isinstance(r, str) or not r.strip()
                       for r in excluded)):
            add("malformed_batch_excluded_reasons", "error", "-",
                "approvals.batch_excluded_queue_reasons must be a list of "
                "non-empty strings")
        elif not excluded:
            # F30: an explicitly emptied exclusion list is schema-valid
            # but silently disables the F21 batch-exclusion control — a
            # likely misconfiguration. Warning, not error: an explicit
            # empty list is documented operator authority (see F24).
            add("empty_batch_excluded_reasons", "warning", "-",
                "approvals.batch_excluded_queue_reasons is EMPTY: this "
                "disables individual-review protection — batch approval "
                "can bulk-approve security items (campaign-queued exfil "
                "fragments, DLP blocks, break-glass records) without "
                "per-item human review. Restore the default list unless "
                "this is intended.")
    log_limits = cfg.get("log_limits")
    if log_limits is not None:
        if not isinstance(log_limits, dict):
            add("malformed_log_limits", "error", "-",
                "log_limits must be a mapping")
        elif "max_log_bytes" in log_limits:
            cap = log_limits["max_log_bytes"]
            if not isinstance(cap, int) or cap <= 0:
                add("malformed_log_limits", "error", "-",
                    "log_limits.max_log_bytes must be a positive integer")
    return findings


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m gov.policy_lint <policy.yaml>")
        print("       python -m gov.policy_lint --export-check <policy.yaml> [--strict]")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    if argv[0] == "--export-check":
        return _export_check_main(argv[1:])
    findings = lint_file(argv[0])
    for f in findings:
        sev = f.get("severity", "?")
        print("[%-7s] %-20s %-28s %s" % (sev, f["kind"], f["rule_id"],
                                         f["detail"]))
    if findings:
        n_err = sum(1 for f in findings if f.get("severity") == "error")
        n_warn = sum(1 for f in findings if f.get("severity") == "warning")
        print("%d finding(s): %d error(s), %d warning(s)"
              % (len(findings), n_err, n_warn))
        return 1
    print("no findings")
    return 0


def _export_check_main(argv):
    """``--export-check``: fail-closed translation dry-run (D3, A14).

    Runs gov/policy_export.py's translator over the policy and reports
    the outcome. Exits 0 when the policy translates cleanly, 1 when the
    exporter refuses (unmappable construct — loud, never silent).
    """
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m gov.policy_lint --export-check "
              "<policy.yaml> [--strict]")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    strict = "--strict" in argv[1:]
    policy_path = argv[0]
    try:
        from gov import policy_export
    except ImportError as e:
        print("export check FAILED: cannot import gov.policy_export (%s)"
              % e)
        return 1
    try:
        text = policy_export.translate(policy_path, format="auto",
                                       strict=strict)
    except policy_export.PolicyExportError as e:
        print("export check FAILED: %s" % e)
        return 1
    except (ValueError, OSError) as e:
        print("export check FAILED: %s" % e)
        return 1
    n_policies = text.count("\npermit (") + text.count("\nforbid (")
    fmt = "dogwood" if "when temporal" in text else "cedar"
    limitations = text.count("//   - ")
    print("export OK: translator v%s, format=%s, %d emitted policies, "
          "%d export limitation(s)"
          % (policy_export.TRANSLATOR_VERSION, fmt, n_policies,
             limitations))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
