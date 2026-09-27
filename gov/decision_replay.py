"""Decision-trace replay verifier (standard library only).

Protocol idea adapted from microsoft/agent-governance-toolkit
(https://github.com/microsoft/agent-governance-toolkit, MIT license,
Copyright (c) Microsoft Corporation): an authorization decision should
be re-verifiable from its recorded evidence alone, without the engine's
runtime state. No AGT code is reused -- only the protocol idea
(capture the decision inputs alongside the verdict; replay offline) is
adapted, reimplemented here for this engine's deny-first YAML policy
semantics.

This is the "sell evidence, not the engine" bet: an auditor extracts a
``decision_trace`` from a hash-chained audit-log verdict entry and
calls ``replay(trace, policy_bundle)`` on their own machine. The
replayer:

  1. re-verifies the trace's integrity binding (a tampered trace fails
     LOUD, naming the section that diverged -- never a silent
     different verdict);
  2. binds the supplied policy bundle to the trace's recorded rule set
     (a drifted policy bundle fails LOUD as policy drift);
  3. re-runs the deterministic policy evaluation over the bundle's
     rules with the trace's canonical inputs -- no executor, no
     network, no private runtime state;
  4. compares the recomputed verdict AND every rule's match outcome
     against the recorded ones (any divergence fails LOUD, naming
     the rule).

Trace schema (``trace_version: 1``):

  policy:    policy_hash (sha256 of the raw policy text, for log
             correlation), policy_version, rules_digest (sha256 over the
             canonical parsed rule list -- the replay binding),
             rule_count.
  request:   principal, action (tool), role, agent_id, resource
             (derived target, scrubbed unless it came from a file
             path), args (canonical; only ``path`` verbatim -- every
             other arg is a ``{"$digest": sha256}`` placeholder, never
             raw secrets / key material / PII / payload bytes),
             context (the engine's evaluation context, canonical).
  verdict:   the deterministic verdict (effect, policy_id, reason,
             flag, matched_rules).
  evaluation: the full per-rule evaluation trace (rule_id, effect,
             matched, declaration_index) plus the deciding/shadowed
             hits.
  post_verdict: the FINAL effect after post-policy layers (advisory
             tightening, tool-rating/deferred/breaker forcing), with
             the final policy_id/flag that already name the forcing
             layer. Replay requires the final effect to be either
             identical to the deterministic verdict or a monotonic
             tightening (allow < require_approval < deny) -- a
             loosening fails LOUD.
  integrity: per-section sha256 digests plus the envelope
             ``trace_digest`` binding them.

WHAT REPLAY DOES NOT PROVE (honest ceilings):

  * Recorded inputs only, not unrecorded ones. Replay trusts the
    captured context snapshot: a compromised executor could record a
    false-but-self-consistent trace. The hash-chained audit log
    detects post-hoc edits, not capture-time lies.
  * The replayer re-implements the engine's match semantics
    (``gov/policy.py`` ``_matches`` / ``_check_conditions`` /
    ``_resolve``). A semantic drift between the two is a bug, guarded
    by the differential tests in ``tests/test_decision_replay.py``.
  * Advisory-layer tightening is recorded, not recomputed: advisors
    are deployment plugins outside the deterministic core.
  * ``require_approval`` replays to ``require_approval``; the human's
    later decision is a separate audited event, not part of the
    trace.
  * The approved-sweep re-evaluation path
    (``ToolExecutor._execute_approved_locked``) does not yet capture
    traces -- only the primary ``call()`` verdict path does.

$0 spend. No network. Pure Python, no dependencies, no ``gov.*``
imports (the auditor must be able to run this without the repo).
"""

import hashlib
import json
import math

# The only trace schema version this replayer understands. Old trace +
# new policy -- or a trace from a future schema -- is an explicit
# version-mismatch failure, never a silently wrong verdict.
TRACE_VERSION = 1


# ---------------------------------------------------------------------------
# Errors: every failure mode is a named exception, never a silent
# different verdict.
# ---------------------------------------------------------------------------

class ReplayError(Exception):
    """Base class for all decision-replay failures."""


class TraceVersionError(ReplayError):
    """The trace's schema version is not supported by this replayer."""

    def __init__(self, trace_version):
        self.trace_version = trace_version
        super().__init__(
            "trace_version %r is not supported by this replayer "
            "(supports %r); refusing to guess at a verdict"
            % (trace_version, TRACE_VERSION))


class TraceTamperedError(ReplayError):
    """The trace's integrity binding does not recompute.

    ``section`` names which part diverged: one of "policy",
    "request", "verdict", "evaluation", "post_verdict", or "envelope".
    """

    def __init__(self, section, detail=""):
        self.section = section
        super().__init__(
            "decision trace integrity check failed in section %r%s; "
            "the trace was modified after capture -- refusing to replay"
            % (section, (": " + detail) if detail else ""))


class PolicyDriftError(ReplayError):
    """The supplied policy bundle is not the rule set that decided."""

    def __init__(self, detail):
        super().__init__(
            "policy bundle drift: %s; refusing to replay against a "
            "different policy than the one that decided" % detail)


class ReplayMismatchError(ReplayError):
    """Recomputation disagreed with the recorded verdict."""

    def __init__(self, detail):
        super().__init__(
            "replay mismatch: %s; the recorded verdict does not follow "
            "from the recorded inputs under the supplied policy" % detail)


class TraceSchemaError(ReplayError):
    """The trace (or bundle) is malformed."""


# ---------------------------------------------------------------------------
# Canonical serialization: the byte-stable foundation every digest and
# every comparison is built on.
# ---------------------------------------------------------------------------

def _canonical(obj):
    """Deterministic JSON text for JSON-plain values.

    dicts sort by key; tuples become lists; sets/frozensets sort by
    their canonical form; non-finite floats are refused (they have no
    stable text form). Anything else raises TypeError -- fail loud,
    never silently coerce.
    """
    if obj is None or isinstance(obj, (bool, int, str)):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise TypeError("non-finite float has no canonical form: %r"
                            % (obj,))
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    if isinstance(obj, dict):
        parts = []
        for key in sorted(obj.keys()):
            if not isinstance(key, str):
                raise TypeError("non-string dict key has no canonical "
                                "form: %r" % (key,))
            parts.append(_canonical(key) + ":" + _canonical(obj[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in obj) + "]"
    if isinstance(obj, (set, frozenset)):
        return "[" + ",".join(sorted(_canonical(v) for v in obj)) + "]"
    raise TypeError("no canonical form for %s" % type(obj).__name__)


def canonical(obj):
    """Public canonical serializer (see _canonical)."""
    return _canonical(obj)


def sha256_hex(text):
    """sha256 hex digest of UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest(value):
    """One-way digest placeholder for a value that must not be stored."""
    return {"$digest": sha256_hex(_canonical(value))}


def _plain(value):
    """Round-trip through the canonical form: JSON-plain deep copy.

    Normalizes tuples/sets to lists and rejects non-canonical values
    LOUD, so a policy bundle exported as JSON replays byte-identically.
    """
    return json.loads(_canonical(value))


# ---------------------------------------------------------------------------
# Scrubbing: digests and IDs only -- never raw secrets, key material,
# PII, or raw payload bytes.
#
# args are agent-supplied: only ``path`` is match-relevant to the
# policy engine (``path_contains_any``), so only ``path`` is kept
# verbatim and every other arg becomes a digest placeholder.
#
# context is engine-computed signals (bools, counters, resolved paths):
# it carries no raw secrets by construction. Bytes values (should never
# occur) are digested rather than stored.
# ---------------------------------------------------------------------------

def scrub_args(args):
    """Scrub tool args for the trace: ``path`` verbatim, rest digested."""
    if not isinstance(args, dict):
        raise TraceSchemaError("trace args must be a mapping, got %r"
                               % type(args).__name__)
    out = {}
    for key, value in args.items():
        if key == "path":
            out[key] = _plain(value)
        else:
            out[key] = _digest(value)
    return out


def scrub_context(context):
    """Canonicalize the evaluation context for the trace.

    Verbatim except for bytes values, which are digested. The context
    is engine-computed match signals -- no raw secrets by
    construction; ``when`` conditions resolve against these exact
    values, so they must round-trip faithfully.
    """
    if not isinstance(context, dict):
        raise TraceSchemaError("trace context must be a mapping, got %r"
                               % type(context).__name__)

    def _walk(value):
        if isinstance(value, bytes):
            return _digest(value)
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_walk(v) for v in value]
        return _plain(value)

    return _walk(context)


def _derive_resource(args):
    """Best-effort target artifact, scrubbed.

    Mirrors the engine's derivation order (path/url/destination/
    package/to) but only a file ``path`` or ``package`` name is kept
    verbatim -- URLs, destinations and recipients can carry PII or
    credential-bearing query strings, so they become digests.
    """
    if not isinstance(args, dict):
        return None
    for key in ("path", "package"):
        value = args.get(key)
        if value:
            return str(value)
    for key in ("url", "destination", "to"):
        value = args.get(key)
        if value:
            return _digest(value)
    return None


# ---------------------------------------------------------------------------
# Trace construction (called by the executor's capture hook; duck-typed
# so this module never imports gov.*).
# ---------------------------------------------------------------------------

def _need(obj, attr, what):
    try:
        return getattr(obj, attr)
    except AttributeError:
        raise TraceSchemaError(
            "cannot build trace: %s is missing attribute %r" % (what, attr))


def _hit_to_dict(hit):
    return {"rule_id": _need(hit, "rule_id", "RuleHit"),
            "effect": _need(hit, "effect", "RuleHit"),
            "reason": _need(hit, "reason", "RuleHit"),
            "flag": _need(hit, "flag", "RuleHit"),
            "declaration_index": _need(hit, "declaration_index",
                                       "RuleHit"),
            "deciding": bool(_need(hit, "deciding", "RuleHit"))}


def build_trace(*, decision, action, context, policy,
                final_effect=None, final_policy_id=None, final_flag=None):
    """Build a versioned decision trace from a typed engine Decision.

    ``decision``: the ``gov/decision_contract.py`` Decision (duck-typed).
    ``action``: the action dict the engine evaluated (tool/args/role/...).
    ``context``: the evaluation context the engine evaluated.
    ``policy``: the engine (duck-typed: policies/policy_version/policy_hash).
    ``final_*``: the post-policy-layer outcome (advisory tightening,
    tool-rating/deferred/breaker forcing); defaults to the deterministic
    verdict when no layer changed it.
    """
    request = _need(decision, "request", "Decision")
    diagnostics = _need(decision, "diagnostics", "Decision")
    rules = _plain(_need(policy, "policies", "policy engine"))
    if not isinstance(rules, list):
        raise TraceSchemaError("policy rules must be a list")

    deciding = _need(diagnostics, "deciding_rule", "Diagnostics")
    # The diagnostics trace is in PASS order (deny -> require_approval
    # -> allow), not declaration order. Recover each entry's TRUE
    # declaration index from the rule list in the same pass order --
    # fail LOUD if the trace does not cover exactly the pass-ordered
    # rules (a mislabeled index would silently corrupt replay).
    pass_order = []
    for _effect in ("deny", "require_approval", "allow"):
        for _i, _r in enumerate(rules):
            if isinstance(_r, dict) and _r.get("effect") == _effect:
                pass_order.append(_i)
    diag_trace = list(_need(diagnostics, "trace", "Diagnostics") or ())
    if len(diag_trace) != len(pass_order):
        raise TraceSchemaError(
            "cannot build trace: diagnostics trace has %d entries but "
            "the policy has %d pass-ordered rules"
            % (len(diag_trace), len(pass_order)))
    trace_entries = []
    for entry, decl_index in zip(diag_trace, pass_order):
        trace_entries.append({
            "effect": _need(entry, "effect", "TraceEntry"),
            "rule_id": _need(entry, "rule_id", "TraceEntry"),
            "matched": bool(_need(entry, "matched", "TraceEntry")),
            "declaration_index": decl_index,
        })

    policy_block = {
        "policy_hash": _need(policy, "policy_hash", "policy engine"),
        "policy_version": str(_need(policy, "policy_version",
                                    "policy engine")),
        "rules_digest": sha256_hex(_canonical(rules)),
        "rule_count": len(rules),
    }
    raw_args = (action or {}).get("args") or {}
    request_block = {
        "principal": _need(request, "principal", "Request"),
        "action": _need(request, "action", "Request"),
        "role": _need(request, "role", "Request"),
        "agent_id": (action or {}).get("agent_id"),
        "resource": _derive_resource(raw_args),
        "args": scrub_args(raw_args),
        "context": scrub_context(context or {}),
    }
    policy_id = _need(decision, "policy_id", "Decision")
    verdict_block = {
        "effect": _need(decision, "effect", "Decision"),
        "policy_id": policy_id,
        "reason": _need(decision, "reason", "Decision"),
        "flag": _need(decision, "flag", "Decision"),
        # Legacy matched_rules semantics: the deciding rule id, or the
        # documented default_deny sentinel for the implicit deny.
        "matched_rules": ([policy_id] if policy_id else ["default_deny"]),
    }
    evaluation_block = {
        "deciding_rule": (_hit_to_dict(deciding)
                          if deciding is not None else None),
        "forbid_hits": [_hit_to_dict(h) for h in
                        (_need(diagnostics, "forbid_hits", "Diagnostics")
                         or ())],
        "approval_hits": [_hit_to_dict(h) for h in
                          (_need(diagnostics, "approval_hits",
                                 "Diagnostics") or ())],
        "permit_hits": [_hit_to_dict(h) for h in
                        (_need(diagnostics, "permit_hits", "Diagnostics")
                         or ())],
        "trace": trace_entries,
    }
    deterministic_effect = verdict_block["effect"]
    post_block = {
        "final_effect": (final_effect if final_effect is not None
                         else deterministic_effect),
        "final_policy_id": final_policy_id,
        "final_flag": final_flag,
        "modified": bool(final_effect is not None
                         and final_effect != deterministic_effect),
    }

    sections = {
        "policy": sha256_hex(_canonical(policy_block)),
        "request": sha256_hex(_canonical(request_block)),
        "verdict": sha256_hex(_canonical(verdict_block)),
        "evaluation": sha256_hex(_canonical(evaluation_block)),
        "post_verdict": sha256_hex(_canonical(post_block)),
    }
    trace = {
        "trace_version": TRACE_VERSION,
        "policy": policy_block,
        "request": request_block,
        "verdict": verdict_block,
        "evaluation": evaluation_block,
        "post_verdict": post_block,
        "integrity": {
            "sections": sections,
            "trace_digest": sha256_hex(_canonical(
                {"trace_version": TRACE_VERSION, "sections": sections})),
        },
    }
    return trace


def policy_bundle_from_policy(policy):
    """Export the auditor-facing policy bundle from an engine.

    The bundle is JSON-plain (``json.dumps`` it for transport); the
    auditor passes it to ``replay()`` alongside the trace. The
    ``rules_digest`` binding is what ties the bundle to the trace --
    the raw-text ``policy_hash`` is carried for log correlation only.
    """
    rules = _plain(_need(policy, "policies", "policy engine"))
    return {
        "policy_version": str(_need(policy, "policy_version",
                                    "policy engine")),
        "policy_hash": _need(policy, "policy_hash", "policy engine"),
        "rules": rules,
        "rules_digest": sha256_hex(_canonical(rules)),
    }


# ---------------------------------------------------------------------------
# Integrity verification.
# ---------------------------------------------------------------------------

_SECTION_NAMES = ("policy", "request", "verdict", "evaluation",
                  "post_verdict")


def verify_integrity(trace):
    """Re-verify a trace's integrity binding. LOUD on any divergence."""
    if not isinstance(trace, dict):
        raise TraceSchemaError("trace must be a mapping, got %r"
                               % type(trace).__name__)
    version = trace.get("trace_version")
    if version != TRACE_VERSION:
        raise TraceVersionError(version)
    integrity = trace.get("integrity")
    if not isinstance(integrity, dict):
        raise TraceSchemaError("trace is missing its integrity block")
    recorded_sections = integrity.get("sections")
    if not isinstance(recorded_sections, dict):
        raise TraceSchemaError("trace integrity block has no sections")
    for name in _SECTION_NAMES:
        block = trace.get(name)
        if block is None:
            raise TraceTamperedError(
                name, "section is missing from the trace")
        recomputed = sha256_hex(_canonical(block))
        recorded = recorded_sections.get(name)
        if recorded != recomputed:
            raise TraceTamperedError(
                name,
                "recorded digest %s... != recomputed %s..."
                % (str(recorded)[:16], recomputed[:16]))
    envelope = {"trace_version": TRACE_VERSION,
                "sections": {n: recorded_sections.get(n)
                             for n in _SECTION_NAMES}}
    if integrity.get("trace_digest") != sha256_hex(_canonical(envelope)):
        raise TraceTamperedError("envelope", "trace_digest does not bind "
                                 "the section digests")
    return True


# ---------------------------------------------------------------------------
# The deterministic evaluation, re-implemented from gov/policy.py.
#
# This MUST stay semantically identical to PolicyEngine._matches,
# _check_conditions, _resolve, and PolicyEngine.decide()'s pass
# structure. Any drift is a bug; the differential tests in
# tests/test_decision_replay.py pin the two implementations together
# across tool/role/agent matching, path_contains_any (+path_resolved),
# every bool signal, counters, when-conditions, rule ordering, id-less
# rules, and the implicit default deny.
# ---------------------------------------------------------------------------

def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


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


_BOOL_SIGNALS = (
    "path_outside_sandbox",
    "domain_allowlisted",
    "carries_read_content",
    "source_untrusted",
    "read_sensitive",
    "read_classified",
    "artifact_unknown",
    "artifact_tampered",
    "artifact_restricted",
    "cross_run_campaign",
    "velocity_exceeded",
    "platform_egress",
    "credential_identity_mismatch",
    "package_fetch",
    "install_allowlisted",
    "install_integrity_verified",
    "high_entropy_payload",
)


def _matches(match, action, context):
    """Mirror of PolicyEngine._matches (see module docstring)."""
    tool = action.get("tool")
    if "tool" in match and tool not in _as_list(match["tool"]):
        return False
    if "role" in match and action.get("role") not in _as_list(match["role"]):
        return False
    if "agent" in match and action.get("agent_id") not in _as_list(
            match["agent"]):
        return False
    args = action.get("args") or {}
    if "path_contains_any" in match:
        path = str(args.get("path", ""))
        resolved = str(context.get("path_resolved") or "")
        subs = _as_list(match["path_contains_any"])
        if not any(sub in path or sub in resolved for sub in subs):
            return False
    for key in _BOOL_SIGNALS:
        if key in match:
            if bool(context.get(key)) != bool(match[key]):
                return False
    counters = context.get("counters") or {}
    if "min_external_calls" in match:
        if int(counters.get("api_call", 0)) < int(
                match["min_external_calls"]):
            return False
    if "min_sends" in match:
        sends = int(counters.get("send_email", 0)) + int(
            counters.get("http_post", 0))
        if sends < int(match["min_sends"]):
            return False
    if "min_writes" in match:
        if int(counters.get("write_file", 0)) < int(match["min_writes"]):
            return False
    if "min_deletes" in match:
        if int(counters.get("delete_file", 0)) < int(match["min_deletes"]):
            return False
    if "when" in match:
        if not _check_conditions(match["when"], context):
            return False
    return True


_DEFAULT_DENY_REASON = "No policy matched; denied by default (fail-closed)."
_DEFAULT_DENY_ID = "default_deny"


def _evaluate(rules, action, context):
    """Mirror of PolicyEngine.decide()'s verdict computation.

    Iterates in PASS order (deny -> require_approval -> allow), exactly
    like decide(): the per-rule list is in evaluation order and each
    entry carries the rule's TRUE declaration index. Returns
    (effect, policy_id, reason, flag, per_rule) where per_rule is a
    list of (declaration_index, display_rule_id, effect, matched).
    """
    per_rule = []
    matched_by_effect = {"deny": [], "require_approval": [],
                         "allow": []}
    for effect in ("deny", "require_approval", "allow"):
        for index, rule in enumerate(rules):
            if rule.get("effect") != effect:
                continue
            rule_id = rule.get("id", "rule-%d" % index)
            matched = _matches(rule.get("match") or {}, action, context)
            per_rule.append((index, rule_id, effect, matched))
            if matched:
                matched_by_effect[effect].append(index)
    deciding_index = None
    for effect in ("deny", "require_approval", "allow"):
        if matched_by_effect[effect]:
            deciding_index = matched_by_effect[effect][0]
            break
    if deciding_index is None:
        return ("deny", None, _DEFAULT_DENY_REASON, _DEFAULT_DENY_ID,
                per_rule)
    rule = rules[deciding_index]
    _idx, display_id, effect, _m = per_rule[
        [p[0] for p in per_rule].index(deciding_index)]
    reason = rule.get("reason", "Matched policy %s." % rule.get("id"))
    return (effect, rule.get("id"), reason, rule.get("flag"), per_rule)


_EFFECT_RANK = {"allow": 0, "require_approval": 1, "deny": 2}


# ---------------------------------------------------------------------------
# replay()
# ---------------------------------------------------------------------------

def _require_trace(trace):
    if not isinstance(trace, dict):
        raise TraceSchemaError("trace must be a mapping, got %r"
                               % type(trace).__name__)
    version = trace.get("trace_version")
    if version != TRACE_VERSION:
        raise TraceVersionError(version)
    for name in ("policy", "request", "verdict", "evaluation",
                 "post_verdict", "integrity"):
        if name not in trace:
            raise TraceSchemaError("trace is missing section %r" % name)
    return trace


def _require_bundle(policy_bundle):
    if not isinstance(policy_bundle, dict):
        raise TraceSchemaError("policy_bundle must be a mapping, got %r"
                               % type(policy_bundle).__name__)
    rules = policy_bundle.get("rules")
    if not isinstance(rules, list):
        raise TraceSchemaError("policy_bundle['rules'] must be a list")
    version = policy_bundle.get("policy_version")
    if not isinstance(version, str):
        raise TraceSchemaError(
            "policy_bundle['policy_version'] must be a string")
    return rules, version


def replay(trace, policy_bundle):
    """Replay a decision trace against a supplied policy bundle.

    Returns a result dict on success. Raises a named ReplayError on
    ANY divergence: TraceVersionError, TraceTamperedError (with the
    section), PolicyDriftError, ReplayMismatchError, or
    TraceSchemaError. Never silently returns a different verdict.
    """
    _require_trace(trace)
    # 1. The trace must be intact before anything else is trusted.
    verify_integrity(trace)

    # 2. The bundle must be the rule set that decided.
    rules, bundle_version = _require_bundle(policy_bundle)
    recorded_version = trace["policy"]["policy_version"]
    if bundle_version != recorded_version:
        raise PolicyDriftError(
            "policy_version drift: trace records %r, bundle supplies %r"
            % (recorded_version, bundle_version))
    bundle_digest = sha256_hex(_canonical(rules))
    recorded_digest = trace["policy"]["rules_digest"]
    if bundle_digest != recorded_digest:
        raise PolicyDriftError(
            "rules_digest drift: trace records %s..., bundle "
            "recomputes %s... -- the rule set changed since the verdict"
            % (str(recorded_digest)[:16], bundle_digest[:16]))

    # 3. Re-run the deterministic evaluation on the recorded inputs.
    request = trace["request"]
    action = {"tool": request.get("action"),
              "role": request.get("role"),
              "agent_id": request.get("agent_id"),
              "args": request.get("args") or {}}
    context = request.get("context") or {}
    effect, policy_id, reason, flag, per_rule = _evaluate(
        rules, action, context)

    # 4. The recomputation must agree with the record, rule by rule.
    recorded_verdict = trace["verdict"]
    if effect != recorded_verdict.get("effect"):
        raise ReplayMismatchError(
            "verdict effect diverged: recorded %r, recomputed %r"
            % (recorded_verdict.get("effect"), effect))
    if policy_id != recorded_verdict.get("policy_id"):
        raise ReplayMismatchError(
            "deciding rule diverged: recorded policy_id %r, recomputed %r"
            % (recorded_verdict.get("policy_id"), policy_id))
    recorded_trace = trace["evaluation"]["trace"]
    if len(recorded_trace) != len(per_rule):
        raise ReplayMismatchError(
            "evaluation trace length diverged: recorded %d rule "
            "evaluations, recomputed %d"
            % (len(recorded_trace), len(per_rule)))
    divergences = []
    for rec, (index, display_id, re_effect, re_matched) in zip(
            recorded_trace, per_rule):
        if rec.get("declaration_index") != index:
            divergences.append(
                "rule position %r: recorded declaration_index %r" %
                (index, rec.get("declaration_index")))
        if rec.get("rule_id") != display_id:
            divergences.append(
                "rule at index %d: recorded rule_id %r, recomputed %r" %
                (index, rec.get("rule_id"), display_id))
        if bool(rec.get("matched")) != bool(re_matched):
            divergences.append(
                "rule %r (%s, index %d): recorded matched=%r, "
                "recomputed matched=%r" %
                (display_id, re_effect, index, rec.get("matched"),
                 re_matched))
    if divergences:
        raise ReplayMismatchError(
            "%d rule-evaluation divergence(s): %s"
            % (len(divergences), "; ".join(divergences)))

    # 5. Post-policy layers may only tighten, never loosen.
    post = trace["post_verdict"]
    final_effect = post.get("final_effect")
    det_rank = _EFFECT_RANK.get(effect)
    fin_rank = _EFFECT_RANK.get(final_effect)
    if det_rank is None or fin_rank is None:
        raise TraceSchemaError(
            "unknown effect in trace: deterministic=%r final=%r"
            % (effect, final_effect))
    if fin_rank < det_rank:
        raise ReplayMismatchError(
            "post-verdict effect loosened the deterministic verdict: "
            "deterministic %r, final %r" % (effect, final_effect))

    return {
        "verdict": effect,
        "policy_id": policy_id,
        "reason": reason,
        "flag": flag,
        "final_effect": final_effect,
        "post_verdict_modified": bool(post.get("modified")),
        "rules_checked": len(per_rule),
        "trace_digest": trace["integrity"]["trace_digest"],
        "policy_version": recorded_version,
    }
