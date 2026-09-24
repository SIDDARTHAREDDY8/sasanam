"""Fail-closed YAML v2 policy -> Cedar / Dogwood export.

D3 per workstreams/architect/ADJUDICATIONS.md A14: the engine
(``gov/policy.py``) is frozen at v2 semantics; this module is the
portability story — YAML policies translate to Cedar (stateless) or
Dogwood (stateful), the anti-lock-in answer to the enforcement plane AWS
monetizes. The D2 benchmark harness (A13) consumes
``translate_for_dogwood()`` under the single-translator rule: this module
is the one place translation lives; nothing else may re-implement it.

Mapping (binding per A14):

  deny               -> Cedar ``forbid``  (forbid-wins == deny-first)
  allow              -> Cedar ``permit``  (default-deny == default-deny)
  ``roles:`` allowlists -> ``forbid`` policies scoped on ``principal.role``
                       (the executor enforces these *before* policy
                       evaluation; the export encodes the same gate so
                       verdicts stay aligned)
  ``tool``           -> ``AgentCore::Action``
  ``match.role`` / ``match.agent``
                     -> ``principal.role`` / ``principal.agent`` conditions
  ``path_contains_any``, ``path_outside_sandbox``,
  ``domain_allowlisted``, ``carries_read_content``,
  ``source_untrusted``, ``read_sensitive``, ``when`` comparisons
                     -> typed ``context`` attributes under the documented
                        schema (docs/cedar-context-schema.md) that the
                        operator's gateway mapper must populate
  ``min_external_calls``, ``min_sends``, ``min_writes``, ``min_deletes``
                     -> Dogwood ``count_within`` temporal blocks
                        (Dogwood only — plain Cedar has no counters)
  ``cross_run_campaign``, ``velocity_exceeded``
                     -> Dogwood ``formerly`` blocks over operator-ledger
                        ``LedgerSignal`` events (Dogwood only)
  ``require_approval`` -> ERROR unless the rule carries a ``bridge:``
                        binding naming the D1-AWS approval action (A12's
                        ``emit_approval_event``), in which case a Dogwood
                        temporal ``permit`` gated on the bridge-produced
                        approval event.

Fail-closed contract (binding): the exporter NEVER silently permits and
NEVER silently drops. Any unmappable construct raises
:class:`PolicyExportError`. Plain-Cedar output REFUSES policies
containing stateful keys (it does not drop them).

Every export carries a header pinning the source policy's sha256, so
drift is detectable: re-export and compare bytes.

What this module does NOT do (honest limits — see docs/policy-export.md
for the full list): it does not prove semantic equivalence (validation
is verdict parity on a corpus via an in-repo reference evaluator, not
the real Dogwood interpreter — that loop is D2's job); it does not
verify that the operator's gateway mapper populates context attributes
honestly; it does not export operational sections (rate limits, budgets,
run limits, velocity config, egress values, approvals/delegation/quorum/
auto-approve, campaign allowlist, log limits, top-level delegation) —
those are listed as EXPORT LIMITATIONS in the header, never silently
dropped.
"""

from __future__ import annotations

import re
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

from .policy import KNOWN_TOOLS, PolicyEngine, _as_list
from .yamlmini import parse as parse_yaml

#: Translator version. Pinned in every export header; the D2 benchmark
#: (A13) voids results when the translator version changed since the run.
TRANSLATOR_VERSION = "1.0.0"


class PolicyExportError(Exception):
    """Loud failure for any unmappable construct.

    Raised instead of silently permitting, silently dropping, or
    weakening a rule. The message always names the rule and the
    offending construct.
    """


# ---------------------------------------------------------------------------
# Classification (binding per A14)
# ---------------------------------------------------------------------------

#: Match keys that are stateful: they read run/session/cross-run counters
#: or ledger signals. Plain Cedar cannot express them -> Dogwood only.
STATEFUL_KEYS = frozenset({
    "min_external_calls",
    "min_sends",
    "min_writes",
    "min_deletes",
    "cross_run_campaign",
    "velocity_exceeded",
})

#: Match keys with a stateless Cedar mapping (typed context attributes).
STATELESS_KEYS = frozenset({
    "tool",
    "role",
    "agent",
    "path_contains_any",
    "path_outside_sandbox",
    "domain_allowlisted",
    "carries_read_content",
    "source_untrusted",
    "read_sensitive",
    # F99: api_call payload entropy signal — stateless (computed from
    # the call's own params), so it exports as a plain Cedar context
    # attribute like read_sensitive.
    "high_entropy_payload",
    # P7 (wave-27): registry-fetch signal and governed-install gates —
    # stateless (computed from the call's own endpoint/name/version),
    # exported as plain Cedar context attributes.
    "package_fetch", "install_allowlisted", "install_integrity_verified",
    # F110 (wave-34): platform-mediated egress signal — stateless
    # (set per platform call by gov/platform_egress.py).
    "platform_egress",
    # F111 (wave-34): credential identity-binding signal — stateless
    # (computed from the call's own args plus the provisioned
    # session/manifest at call time).
    "credential_identity_mismatch",
    "when",
})

#: Fields a ``bridge:`` binding may correlate between the approval event
#: and the request. Fixed by the context schema (docs/cedar-context-schema.md).
BRIDGE_MATCH_FIELDS = frozenset({"path", "domain", "role", "agent"})

#: Top-level policy sections that are operational controls, not
#: authorization rules. They are NOT exported; when present and non-empty
#: they are listed as EXPORT LIMITATIONS in the header (loud, never
#: silent). ``--strict`` turns them into hard errors.
_OPERATIONAL_SECTIONS = (
    "rate_limit",
    "egress",
    "approvals",
    "auto_approve",
    "campaign_allowlist",
    "delegation",
    "log_limits",
    "budgets",
    "run_limits",
    "velocity",
)

_OPERATIONAL_NOTES = {
    "rate_limit": "executor-enforced per-run call/egress budgets; not an authorization rule",
    "egress": "domain allowlist values are mapper config for context.domain_allowlisted; the values themselves are not exported",
    "approvals": "queue TTL / delegation / quorum / batch-exclusion: approval-ceremony config, not authorization",
    "auto_approve": "low-risk auto-approval gate config for the queue, not authorization",
    "campaign_allowlist": "ledger exemption list for the campaign heuristic, not authorization",
    "delegation": "top-level authority-delegation grants (P10, wave-24): agent-to-agent grant primitive enforced by the delegation machinery, not the authorizer; not exported",
    "log_limits": "audit-log size guard, not authorization",
    "budgets": "executor-enforced spend/token/action budgets, not authorization",
    "run_limits": "executor-enforced step budget, not authorization",
    "velocity": "ledger threshold config behind the velocity_exceeded signal; the signal maps to a LedgerSignal event, the config does not export",
}

_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_WHEN_OPS = (("gte", ">="), ("lte", "<="), ("gt", ">"),
             ("lt", "<"), ("eq", "=="), ("neq", "!="))


# Top-level policy sections the translator understands. Anything else is
# refused (loud) rather than silently ignored: an unrecognized section
# might carry authorization semantics the export would drop.
_KNOWN_TOP_LEVEL = frozenset(
    ["version", "roles", "policies"] + list(_OPERATIONAL_SECTIONS))

# Rule fields the translator understands. ``bridge`` is exporter-only
# (the engine ignores it); ``description`` is free-text metadata like
# ``reason`` (used by policies/default.yaml).
_KNOWN_RULE_FIELDS = frozenset(
    {"id", "effect", "match", "reason", "description", "flag", "bridge"})


# ---------------------------------------------------------------------------
# Small emitters
# ---------------------------------------------------------------------------

def _cedar_str(value):
    """Render a Cedar string literal; loud on control characters."""
    if not isinstance(value, str):
        raise PolicyExportError(
            "cannot render %r as a Cedar string literal" % (value,))
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise PolicyExportError(
                "string %r contains control characters; refusing to emit"
                % (value,))
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def _bool_lit(value):
    return "true" if value else "false"


def _ttl_to_dogwood_duration(ttl_seconds, rule_id):
    """Map bridge ttl_seconds to a Dogwood duration literal.

    Dogwood's published syntax uses minute/hour windows (``30m``, ``1h``);
    sub-minute granularity is not grounded, so non-multiples of 60 fail
    loudly rather than rounding (rounding would silently widen or narrow
    the approval window).
    """
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise PolicyExportError(
            "rule %s: bridge.ttl_seconds must be an integer number of "
            "seconds, got %r" % (rule_id, ttl_seconds))
    if ttl_seconds <= 0:
        raise PolicyExportError(
            "rule %s: bridge.ttl_seconds must be positive, got %r"
            % (rule_id, ttl_seconds))
    if ttl_seconds % 3600 == 0:
        return "%dh" % (ttl_seconds // 3600)
    if ttl_seconds % 60 == 0:
        return "%dm" % (ttl_seconds // 60)
    raise PolicyExportError(
        "rule %s: bridge.ttl_seconds=%d is not a multiple of 60; Dogwood "
        "duration granularity is minutes/hours and the exporter will not "
        "silently round the approval window" % (rule_id, ttl_seconds))


def _validate_bridge(rule_id, bridge, effect):
    """Validate a rule's ``bridge:`` binding (D1-AWS approval action).

    The binding names the customer-configured approval action from A12's
    ``emit_approval_event(gateway, approval_action, session_id, principal,
    match_fields, decision_id)`` contract. Anything malformed fails
    loudly — a mis-shaped binding must never degrade into an unconditional
    permit.
    """
    if effect != "require_approval":
        raise PolicyExportError(
            "rule %s: a bridge: binding is only meaningful on "
            "require_approval rules (effect is %r)" % (rule_id, effect))
    if not isinstance(bridge, dict):
        raise PolicyExportError(
            "rule %s: bridge: must be a mapping with approval_action / "
            "ttl_seconds, got %r" % (rule_id, bridge))
    for key in bridge:
        if key not in ("approval_action", "ttl_seconds", "match_fields",
                       "gateway"):
            raise PolicyExportError(
                "rule %s: unknown bridge key %r (known: approval_action, "
                "ttl_seconds, match_fields, gateway)" % (rule_id, key))
    action = bridge.get("approval_action")
    if not isinstance(action, str) or not action.strip():
        raise PolicyExportError(
            "rule %s: bridge.approval_action must be a non-empty string "
            "naming the D1-AWS approval action, got %r" % (rule_id, action))
    duration = _ttl_to_dogwood_duration(bridge.get("ttl_seconds"), rule_id)
    match_fields = bridge.get("match_fields") or []
    if (not isinstance(match_fields, list)
            or any(not isinstance(f, str) or f not in BRIDGE_MATCH_FIELDS
                   for f in match_fields)):
        raise PolicyExportError(
            "rule %s: bridge.match_fields must be a list drawn from %s, "
            "got %r" % (rule_id, sorted(BRIDGE_MATCH_FIELDS), match_fields))
    return {
        "approval_action": action.strip(),
        "ttl_seconds": bridge.get("ttl_seconds"),
        "duration": duration,
        "match_fields": list(match_fields),
        # gateway endpoint is operator config (A12: refuses to run unless
        # explicitly configured); recorded for traceability only.
        "gateway": bridge.get("gateway"),
    }


# ---------------------------------------------------------------------------
# Match-key translation
# ---------------------------------------------------------------------------

def _when_conditions(rule_id, match):
    """Stateless ``when`` conjuncts for a rule's match dict.

    Note: ``tool`` is handled by _scope_action (scope constraint for a
    single tool, ``when`` disjunction for several), not here.
    """
    conds = []

    if "role" in match:
        roles = _as_list(match.get("role"))
        conds.append("(%s)" % " || ".join(
            "principal.role == %s" % _cedar_str(r) for r in roles) if roles
            else "false")

    if "agent" in match:
        agents = _as_list(match.get("agent"))
        conds.append("(%s)" % " || ".join(
            "principal.agent == %s" % _cedar_str(a) for a in agents) if agents
            else "false")

    if "path_contains_any" in match:
        subs = _as_list(match.get("path_contains_any"))
        if not subs:
            conds.append("false")
        else:
            # F146: the engine matches the declared path OR the
            # symlink-resolved target (context.path_resolved); the
            # export must carry both disjuncts or exported policies
            # would be weaker than the engine.
            conds.append("(%s)" % " || ".join(
                "(context.path.contains(%s) || context.path_resolved.contains(%s))"
                % (_cedar_str(s), _cedar_str(s)) for s in subs))

    for key in ("path_outside_sandbox", "domain_allowlisted",
                "carries_read_content", "source_untrusted", "read_sensitive",
                "high_entropy_payload",
                # P7 (wave-27): registry-fetch / governed-install gates.
                "package_fetch", "install_allowlisted",
                "install_integrity_verified",
                # F110/F111 (wave-34): platform egress and credential
                # identity signals export as plain boolean context
                # attributes.
                "platform_egress", "credential_identity_mismatch"):
        if key in match:
            conds.append("context.%s == %s"
                         % (key, _bool_lit(match[key])))

    if "when" in match:
        for cond in match.get("when") or []:
            conds.append(_when_comparison(rule_id, cond))

    for key in match:
        if key not in STATELESS_KEYS and key not in STATEFUL_KEYS:
            # The engine rejects unknown keys at load; this is belt-and-braces
            # so a future key can never slip through untranslated.
            raise PolicyExportError(
                "rule %s: match key %r has no export mapping" % (rule_id, key))
    return conds


def _when_comparison(rule_id, cond):
    """Translate one ``when: [{path, gte|lte|gt|lt|eq|neq}]`` condition."""
    if not isinstance(cond, dict):
        raise PolicyExportError(
            "rule %s: when conditions must be mappings, got %r"
            % (rule_id, cond))
    path = cond.get("path")
    if not isinstance(path, str) or not _PATH_RE.match(path):
        raise PolicyExportError(
            "rule %s: when path must be a dotted identifier path, got %r"
            % (rule_id, path))
    ops = [op for name, op in _WHEN_OPS if name in cond]
    found = [(name, sym) for name, sym in _WHEN_OPS if name in cond]
    if len(found) != 1:
        raise PolicyExportError(
            "rule %s: when condition needs exactly one of %s, got %r"
            % (rule_id, [n for n, _ in _WHEN_OPS], cond))
    name, sym = found[0]
    want = cond[name]
    if want is None:
        # Engine short-circuits: a missing path makes the condition False,
        # so `eq: null` can never match. Refuse rather than guess.
        raise PolicyExportError(
            "rule %s: when %s: null is unsatisfiable (the engine treats a "
            "missing path as non-match); remove the condition" % (rule_id, name))
    if isinstance(want, bool):
        lit = _bool_lit(want)
    elif isinstance(want, int):
        lit = str(want)
    elif isinstance(want, str):
        lit = _cedar_str(want)
    else:
        raise PolicyExportError(
            "rule %s: when %s supports bool/int/string literals, got %r"
            % (rule_id, name, want))
    return "context.%s %s %s" % (path, sym, lit)


def _temporal_conjuncts(rule_id, match):
    """Dogwood ``when temporal`` conjuncts for a rule's stateful keys."""
    conjuncts = []

    def _count_block(tool, threshold):
        return ("exists (n: Long). ((count_within(24h, "
                "AgentCore::Action::%s::request{ _ })) == n && n >= %d)"
                % (_cedar_str(tool), threshold))

    def _int_threshold(key):
        value = match[key]
        if isinstance(value, bool) or not isinstance(value, int) \
                or value < 0:
            raise PolicyExportError(
                "rule %s: %s must be a non-negative integer, got %r"
                % (rule_id, key, value))
        return value

    if "min_external_calls" in match:
        conjuncts.append(_count_block(
            "api_call", _int_threshold("min_external_calls")))
    if "min_writes" in match:
        conjuncts.append(_count_block(
            "write_file", _int_threshold("min_writes")))
    if "min_deletes" in match:
        conjuncts.append(_count_block(
            "delete_file", _int_threshold("min_deletes")))
    if "min_sends" in match:
        # Engine: min_sends counts send_email + http_post together.
        threshold = _int_threshold("min_sends")
        conjuncts.append(
            "exists (n1: Long). exists (n2: Long). ("
            "(count_within(24h, AgentCore::Action::\"send_email\"::request{ _ })) == n1 && "
            "(count_within(24h, AgentCore::Action::\"http_post\"::request{ _ })) == n2 && "
            "n1 + n2 >= %d)" % threshold)

    def _signal_block(signal_name, value):
        block = ("formerly within 24h "
                 "AgentCore::Action::\"LedgerSignal\"::response{ "
                 "output.signal: %s, output.value: true }"
                 % _cedar_str(signal_name))
        return block if value else "!(%s)" % block

    if "cross_run_campaign" in match:
        conjuncts.append(_signal_block(
            "cross_run_campaign", bool(match["cross_run_campaign"])))
    if "velocity_exceeded" in match:
        conjuncts.append(_signal_block(
            "velocity_exceeded", bool(match["velocity_exceeded"])))
    return conjuncts


def _scope_action(match):
    """Cedar scope action constraint for a rule; (scope, extra when-cond).

    A single tool goes in the scope (``action == AgentCore::Action::"x"``);
    several tools stay in a ``when`` disjunction (Cedar scopes cannot
    express ``||``); no ``tool`` key leaves the scope unconstrained. An
    empty tool list makes the rule unsatisfiable (``when { false }``),
    matching the engine, where ``tool not in []`` is always true.
    """
    tools = _as_list(match.get("tool")) if "tool" in match else None
    if tools is None:
        return "action", []
    if len(tools) == 1:
        return ("action == AgentCore::Action::%s" % _cedar_str(tools[0]), [])
    if not tools:
        return "action", ["false"]
    return ("action", ["(%s)" % " || ".join(
        "action == AgentCore::Action::%s" % _cedar_str(t) for t in tools)])


# ---------------------------------------------------------------------------
# Rule / policy assembly
# ---------------------------------------------------------------------------

def _rule_policy(rule, index, dogwood):
    rule_id = rule.get("id", "rule-%d" % index)
    effect = rule.get("effect")
    match = rule.get("match") or {}
    if not isinstance(match, dict):
        raise PolicyExportError(
            "rule %s: match must be a mapping" % (rule_id,))

    unknown_fields = sorted(k for k in rule if k not in _KNOWN_RULE_FIELDS)
    if unknown_fields:
        raise PolicyExportError(
            "rule %s: unknown field(s) %s; refusing rather than silently "
            "ignoring (known: %s)"
            % (rule_id, unknown_fields, sorted(_KNOWN_RULE_FIELDS)))

    stateful = sorted(k for k in match if k in STATEFUL_KEYS)
    if stateful and not dogwood:
        raise PolicyExportError(
            "rule %s: stateful match key(s) %s have no plain-Cedar "
            "equivalent; refusing plain-Cedar output (use Dogwood). The "
            "keys are NOT dropped." % (rule_id, stateful))

    if "bridge" in rule and rule["bridge"] is not None \
            and effect != "require_approval":
        raise PolicyExportError(
            "rule %s: bridge: is only meaningful on require_approval rules"
            % (rule_id,))

    lines = []
    lines.append("// " + "-" * 74)
    if effect == "require_approval":
        bridge = rule.get("bridge")
        if bridge is None:
            raise PolicyExportError(
                "rule %s: effect require_approval has no Cedar equivalent "
                "and no bridge: binding names a D1-AWS approval action; "
                "refusing to export (not silently permitting, not silently "
                "dropping)" % (rule_id,))
        bound = _validate_bridge(rule_id, bridge, effect)
        kind, arrow = "permit", "require_approval -> Dogwood temporal permit"
    elif effect == "deny":
        kind, arrow = "forbid", "deny -> forbid"
        bound = None
    elif effect == "allow":
        kind, arrow = "permit", "allow -> permit"
        bound = None
    else:  # pragma: no cover — the engine rejects invalid effects at load
        raise PolicyExportError(
            "rule %s: invalid effect %r" % (rule_id, effect))

    lines.append("// policy: %s [%s]" % (rule_id, arrow))
    reason = rule.get("reason")
    if reason:
        flag = rule.get("flag")
        lines.append("// %s%s" % (
            reason, " (flag: %s)" % flag if flag else ""))
    if bound is not None:
        lines.append(
            "// bridge: D1-AWS approval action %s, approval must be "
            "formerly within %s%s" % (
                _cedar_str(bound["approval_action"]), bound["duration"],
                (", match_fields=[%s]" % ", ".join(bound["match_fields"]))
                if bound["match_fields"] else ""))
        lines.append(
            "//   (A12 emit_approval_event(gateway, approval_action, "
            "session_id, principal, match_fields, decision_id); single-use "
            "is enforced by the D1 queue via decision_id, not by this "
            "policy — see docs/policy-export.md)")

    scope_action, extra_conds = _scope_action(match)
    conds = _when_conditions(rule_id, match) + extra_conds
    rule_temporals = _temporal_conjuncts(rule_id, match) if dogwood else []

    approval_temporal = None
    if bound is not None:
        fields = ["output.approved: true"]
        for f in bound["match_fields"]:
            fields.append("input.%s: context.input.%s" % (f, f))
        approval_temporal = (
            "formerly within %s AgentCore::Action::%s::response{ %s }"
            % (bound["duration"],
               _cedar_str(bound["approval_action"]),
               ", ".join(fields)))

    def _emit_block(kind_word, temporals):
        lines.append("%s (" % kind_word)
        lines.append("    principal is AgentCore::Principal,")
        lines.append("    %s," % scope_action)
        lines.append("    resource")
        lines.append(")")
        if conds:
            lines.append("when {")
            lines.append("    %s" % " &&\n    ".join(conds))
            lines.append("}")
        if temporals:
            lines.append("when temporal {")
            lines.append("    %s" % " &&\n    ".join(temporals))
            lines.append("}")
        lines[-1] += ";"

    if bound is not None:
        _emit_block("permit", rule_temporals + [approval_temporal])
        # F88 — forbid companion: deny until the bridged approval
        # arrives. The engine evaluates require_approval rules BEFORE
        # allow rules, so a require_approval match shadows any later
        # allow. Cedar has no pass order: without this companion, an
        # unconditional allow permit for the same tool would fire for a
        # request the engine queued for approval — a silent weakening.
        # The companion fires exactly when the RA rule matches and no
        # bridge approval event is present; forbid-wins does the rest.
        lines.append(
            "// policy: %s [require_approval -> forbid companion: deny "
            "until bridged approval]" % rule_id)
        lines.append(
            "//   (F88: without this, allow permits would shadow the "
            "approval gate)")
        _emit_block("forbid",
                    rule_temporals + ["!(%s)" % approval_temporal])
    else:
        _emit_block(kind, rule_temporals)
    return "\n".join(lines)


def _role_scope_policies(roles):
    """Encode the executor's role->tool allowlist as forbid policies.

    Includes a catch-all forbid for principals whose role is not in the
    policy at all (the executor rejects those before policy evaluation).
    """
    chunks = []
    names = sorted(roles)
    for role in names:
        tools = sorted(set(roles[role]))
        cond = "principal.role == %s" % _cedar_str(role)
        if tools:
            allow = " || ".join(
                "action == AgentCore::Action::%s" % _cedar_str(t)
                for t in tools)
            cond = "%s && !(%s)" % (cond, allow)
        chunks.append(
            "// role allowlist (executor-enforced): role \"%s\" may use: %s\n"
            "forbid (\n"
            "    principal is AgentCore::Principal,\n"
            "    action,\n"
            "    resource\n"
            ")\n"
            "when {\n"
            "    %s\n"
            "};" % (role, ", ".join(tools) if tools else "(no tools)",
                    cond))
    known = " || ".join(
        "principal.role == %s" % _cedar_str(r) for r in names)
    chunks.append(
        "// role allowlist: unknown roles may use nothing (the executor "
        "rejects them before policy evaluation)\n"
        "forbid (\n"
        "    principal is AgentCore::Principal,\n"
        "    action,\n"
        "    resource\n"
        ")\n"
        "when {\n"
        "    !(%s)\n"
        "};" % known)
    return chunks


def _limitations(cfg):
    """Operational sections present in the policy (loud, never silent)."""
    found = []
    for section in _OPERATIONAL_SECTIONS:
        value = cfg.get(section)
        if value is None:
            continue
        if isinstance(value, (dict, list)) and not value:
            continue
        if isinstance(value, bool) and not value:
            continue
        note = _OPERATIONAL_NOTES.get(section, "operational config")
        found.append((section, note))
    return found


def _load_cfg(policy_path):
    """Read + hash + parse the policy file (single read, F53-style).

    Reuses PolicyEngine for rule validation so the exporter can never
    accept a policy the engine would reject. The engine validates a
    temporary copy of the EXACT bytes that were hashed and translated,
    so a concurrent file change cannot slip unvalidated content through
    a second read.
    """
    path = Path(policy_path)
    raw = path.read_bytes()
    digest = sha256(raw).hexdigest()
    tmpdir = tempfile.mkdtemp(prefix="gov-export-validate-")
    try:
        tmp = Path(tmpdir) / "policy.yaml"
        tmp.write_bytes(raw)
        engine = PolicyEngine(tmp)  # validates rules; raises ValueError
    finally:
        try:
            tmp.unlink()
            Path(tmpdir).rmdir()
        except OSError:
            pass
    cfg = parse_yaml(raw.decode("utf-8")) or {}
    return cfg, digest, engine


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def translate(policy_path, format="auto", strict=False):
    """Translate a YAML v2 policy file to Cedar/Dogwood text.

    ``format``: ``"auto"`` (Cedar unless a stateful key forces Dogwood),
    ``"cedar"`` (refuses stateful policies), or ``"dogwood"``.
    ``strict``: turn EXPORT LIMITATIONS (non-empty operational sections)
    into hard errors instead of header notes.
    """
    if format not in ("auto", "cedar", "dogwood"):
        raise PolicyExportError(
            "unknown format %r (want auto|cedar|dogwood)" % (format,))
    cfg, digest, engine = _load_cfg(policy_path)

    # Fail-closed contract checks: the translator's input contract is
    # YAML policy v2, and anything it does not understand is refused
    # rather than silently ignored (the engine is lenient here; the
    # exporter is not, because a dropped section/field could carry
    # authorization semantics).
    if cfg.get("version") != 2:
        raise PolicyExportError(
            "translator contract is YAML policy v2: refusing policy with "
            "version %r (want `version: 2`)" % (cfg.get("version"),))
    unknown_sections = sorted(k for k in cfg if k not in _KNOWN_TOP_LEVEL)
    if unknown_sections:
        raise PolicyExportError(
            "unknown top-level section(s) %s; refusing rather than "
            "silently ignoring (known: %s)"
            % (unknown_sections, sorted(_KNOWN_TOP_LEVEL)))

    stateful_rules = [
        (rule.get("id", "rule-%d" % i),
         sorted(k for k in (rule.get("match") or {}) if k in STATEFUL_KEYS))
        for i, rule in enumerate(engine.policies)
    ]
    stateful_rules = [(rid, keys) for rid, keys in stateful_rules if keys]
    dogwood = (format == "dogwood"
               or (format == "auto" and bool(stateful_rules)))
    if format == "cedar" and stateful_rules:
        detail = "; ".join("%s: %s" % (rid, ",".join(keys))
                           for rid, keys in stateful_rules)
        raise PolicyExportError(
            "plain-Cedar output refused: policy contains stateful match "
            "keys (%s). Use format=dogwood. The keys are NOT dropped."
            % detail)

    limitations = _limitations(cfg)
    if strict and limitations:
        raise PolicyExportError(
            "strict mode: policy has non-exportable operational sections: "
            "%s" % ", ".join(s for s, _ in limitations))

    roles = {r: list(t) for r, t in engine.roles.items()}

    out = []
    out.append("// " + "=" * 74)
    out.append("// gov/policy_export.py — translator v%s (D3, A14)"
               % TRANSLATOR_VERSION)
    out.append("// Source policy : %s" % policy_path)
    out.append("// Source sha256 : %s" % digest)
    out.append("//   (drift detection: re-export and compare bytes)")
    out.append("// Target format : %s" % ("dogwood" if dogwood else "cedar"))
    out.append("// Rules         : %d (+%d role-allowlist forbids)"
               % (len(engine.policies), len(roles) + 1))
    out.append("// Deterministic : yes — no timestamps; identical input "
               "yields identical bytes")
    if limitations:
        out.append("// EXPORT LIMITATIONS — enforced OUTSIDE this artifact "
                   "(see docs/policy-export.md):")
        for section, note in limitations:
            out.append("//   - %s: %s" % (section, note))
    else:
        out.append("// EXPORT LIMITATIONS : none")
    out.append("// " + "=" * 74)
    out.append("")

    out.extend(_role_scope_policies(roles))
    out.append("")
    for i, rule in enumerate(engine.policies):
        out.append(_rule_policy(rule, i, dogwood))
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def translate_for_cedar(policy_path, strict=False):
    """Translate to plain Cedar; refuses stateful policies (loud)."""
    return translate(policy_path, format="cedar", strict=strict)


def translate_for_dogwood(policy_path, strict=False):
    """Translate to Dogwood (superset: handles stateful + bridged approvals).

    This is the single translator consumed by the D2 benchmark's Dogwood
    target (A13 single-translator rule): do not re-implement translation
    elsewhere.
    """
    return translate(policy_path, format="dogwood", strict=strict)


def translate_text(yaml_text, source_name="<inline>", format="auto",
                   strict=False):
    """Translate YAML text (convenience wrapper; same fail-closed rules)."""
    if not isinstance(yaml_text, str):
        raise PolicyExportError("yaml_text must be a string")
    tmpdir = tempfile.mkdtemp(prefix="gov-export-")
    try:
        path = Path(tmpdir) / (source_name if source_name.endswith(".yaml")
                               else "policy.yaml")
        path.write_text(yaml_text, encoding="utf-8")
        text = translate(str(path), format=format, strict=strict)
        # The header must name the caller's source, not the random temp
        # path — otherwise identical input would not yield identical
        # bytes and the determinism claim would be false.
        return text.replace("// Source policy : %s" % path,
                            "// Source policy : %s" % source_name, 1)
    finally:
        try:
            path.unlink()
            Path(tmpdir).rmdir()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m gov.policy_export --policy <policy.yaml> "
              "[--format auto|cedar|dogwood] [--out <file>] [--strict]")
        print("")
        print("Fail-closed YAML v2 -> Cedar/Dogwood export (D3, A14).")
        print("Refuses (exit 1) on any unmappable construct: stateful keys")
        print("in plain-Cedar output, require_approval without a bridge:")
        print("binding, malformed bridge bindings. Never silently permits,")
        print("never silently drops.")
        return 0 if argv and argv[0] in ("-h", "--help") else 2

    policy = None
    format_ = "auto"
    out_path = None
    strict = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--policy" and i + 1 < len(argv):
            policy, i = argv[i + 1], i + 2
        elif arg == "--format" and i + 1 < len(argv):
            format_, i = argv[i + 1], i + 2
        elif arg == "--out" and i + 1 < len(argv):
            out_path, i = argv[i + 1], i + 2
        elif arg == "--strict":
            strict, i = True, i + 1
        else:
            print("unknown argument: %s" % arg, file=sys.stderr)
            return 2
    if policy is None:
        print("missing required --policy <policy.yaml>", file=sys.stderr)
        return 2
    try:
        text = translate(policy, format=format_, strict=strict)
    except PolicyExportError as e:
        print("EXPORT ERROR: %s" % e, file=sys.stderr)
        return 1
    except (ValueError, OSError) as e:
        # Policy load/validation failures (engine) and unreadable files.
        print("EXPORT ERROR: %s" % e, file=sys.stderr)
        return 1
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
