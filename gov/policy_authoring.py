"""Policy authoring layer: filters/actions vocabulary + harness dry-run.

Wave-253 lane 3. Stdlib only.

The cloud-custodian/cloud-custodian ADAPT (Apache-2.0 -- the authoring
VOCABULARY and the dry-run/structured-match UX only; no c7n code, and
c7n's cloud-resource model is NOT imported: our resources are tool
actions, not EC2 instances). Three mechanisms stolen:

1. **Filters/actions separation.** An authored policy selects with
   ``filters`` (composable with nested ``and``/``or``) and declares
   its consequence with ``actions`` -- a cleaner authoring model
   than mixed rule bodies. ``compile_authoring()`` lowers the
   authored YAML to the native policy YAML the engine already
   accepts, then round-trips it through ``PolicyEngine.from_text``
   so a compiled artifact that the engine would refuse is refused
   at compile time, never at enforcement time.
2. **Dry-run mode.** ``dry_run()`` evaluates a candidate authored
   policy against a harness's fixtures and reports what WOULD
   happen (per-fixture verdicts, current vs with-candidate) without
   any side effects -- the wave-251 ``policy_harness`` made
   interactive.
3. **Structured match outputs.** Dry-run records name WHICH rule
   matched (engine trace) and, for the authored candidate, WHICH
   filter matched and WHY -- the c7n match-record shape -- so an
   author can debug a rule instead of staring at a bare verdict.

Authored schema (version 1)::

    version: 1
    policies:
      - name: block-secret-reads
        description: "optional"
        filters:                      # AND semantics, non-empty
          - type: value-filter
            key: tool                 # tool | role | agent | path |
                                      # <context bool signal> | <min_*>
            op: in                    # eq | in | contains-any | gte
            value: [read_file]
          - type: and                 # nested composition
            filters: [...]
          - type: or                  # expands to one native rule
            filters: [...]            #   per branch (same actions)
        actions:                      # non-empty; one native rule per
          - type: deny                #   action (x or-branches)
            reason: "why"
            flag: "optional-flag"

Action types: ``deny`` -> deny, ``allow`` -> allow,
``require-approval`` -> require_approval. Unknown filter types,
action types, keys, or ops refuse fail-closed at compile time with
a ``policy-authoring-*`` machine code -- a misspelled authoring
construct can never silently compile to a weaker rule.
"""

import json
import os
from collections.abc import Mapping

from .policy import PolicyEngine, KNOWN_TOOLS
from .yamlmini import parse as _parse_yaml
from . import policy_combine
from .context_schema import checked_bool, checked_counter
from .decision_contract import Request
from .policy_harness import (
    _load_policies,
    HarnessError,
    MALFORMED_CODE as _HARNESS_MALFORMED,
)


__all__ = [
    "AuthoringError",
    "CompiledPolicy",
    "DryRunReport",
    "compile_authoring",
    "explain_candidate",
    "dry_run",
]


def _load_fixtures_lenient(fixtures_dir):
    """Load (name, action, context) sorted by name WITHOUT requiring
    expected/ outcomes. Dry-run previews; it does not grade. Fixture
    SHAPE is still validated fail-closed (malformed fixtures refuse);
    only the expected-outcome file is optional."""
    if not os.path.isdir(fixtures_dir):
        raise HarnessError(
            _HARNESS_MALFORMED,
            "fixtures dir %s missing" % (fixtures_dir,))
    out = []
    for name in sorted(os.listdir(fixtures_dir)):
        if not name.endswith(".json"):
            raise HarnessError(
                _HARNESS_MALFORMED,
                "fixtures/%s: expected *.json" % (name,))
        path = os.path.join(fixtures_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                fixture = json.load(fh)
        except (OSError, ValueError) as exc:
            raise HarnessError(
                _HARNESS_MALFORMED,
                "fixtures/%s unreadable: %s" % (name, exc))
        if not isinstance(fixture, dict):
            raise HarnessError(
                _HARNESS_MALFORMED,
                "fixtures/%s: top-level JSON must be an object"
                % (name,))
        action = fixture.get("action")
        if not isinstance(action, dict):
            raise HarnessError(
                _HARNESS_MALFORMED,
                "fixtures/%s: 'action' must be an object, got %r"
                % (name, action))
        context = fixture.get("context", {})
        if not isinstance(context, dict):
            raise HarnessError(
                _HARNESS_MALFORMED,
                "fixtures/%s: 'context' must be an object, got %r"
                % (name, context))
        out.append((name, action, context))
    if not out:
        raise HarnessError(
            _HARNESS_MALFORMED,
            "fixtures dir %s has no fixture files" % (fixtures_dir,))
    return out


# ------------------------------------------------------------------
# compile-time constants (codes, key registry)
# ------------------------------------------------------------------

# Machine decision codes emitted by this module (also in
# gov/decision_codes.py under domain "policy-authoring").
UNKNOWN_FILTER_CODE = "policy-authoring-unknown-filter"
UNKNOWN_ACTION_CODE = "policy-authoring-unknown-action"
UNKNOWN_OP_CODE = "policy-authoring-unknown-op"
MALFORMED_CODE = "policy-authoring-malformed"
CONFLICTING_CODE = "policy-authoring-conflicting-filters"
EMPTY_CODE = "policy-authoring-empty"
COMPILE_REFUSED_CODE = "policy-authoring-compile-refused"

_AUTHORING_VERSION = 1

# Context boolean signals the authoring layer exposes. Each maps
# 1:1 to a native match key with op eq.
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

# Counter floors: authoring key -> (native match key, context
# counter accessor). Mirrors gov/policy.py _matches.
_COUNTERS = (
    "min_external_calls",
    "min_sends",
    "min_writes",
    "min_deletes",
)

# key -> (ops, native-key-or-None). None native key means the key
# IS the native key (signals, counters).
_KEY_SPECS = {
    "tool": (("eq", "in"), "tool"),
    "role": (("eq", "in"), "role"),
    "agent": (("eq", "in"), "agent"),
    "path": (("contains-any",), "path_contains_any"),
}
for _sig in _BOOL_SIGNALS:
    _KEY_SPECS[_sig] = (("eq",), _sig)
for _ctr in _COUNTERS:
    _KEY_SPECS[_ctr] = (("gte",), _ctr)

_ACTION_EFFECTS = {
    "deny": "deny",
    "allow": "allow",
    "require-approval": "require_approval",
}


class AuthoringError(Exception):
    """The authored policy is unusable. Fail-closed: carries a
    policy-authoring-* machine code; the message leads with the code."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------
# value validation
# ------------------------------------------------------------------

def _is_str_list(value):
    return (isinstance(value, list) and value
            and all(isinstance(v, str) and v for v in value))


def _validate_value_filter(key, op, value):
    """Return the native (match_key, match_value) fragment."""
    spec = _KEY_SPECS.get(key)
    if spec is None:
        raise AuthoringError(
            UNKNOWN_FILTER_CODE,
            "unknown filter key %r (known: %s)"
            % (key, sorted(_KEY_SPECS)))
    ops, native_key = spec
    if op not in ops:
        raise AuthoringError(
            UNKNOWN_OP_CODE,
            "op %r not supported for key %r (supported: %s)"
            % (op, key, list(ops)))
    if key in ("tool", "role", "agent"):
        if op == "eq" and not isinstance(value, str):
            # eq is the single-value form; a list means "in" -- the
            # author said the wrong op, so refuse rather than guess.
            raise AuthoringError(
                MALFORMED_CODE,
                "key %r op 'eq': value must be a single string, got "
                "%r (use op 'in' for a list)" % (key, value))
        vals = [value] if isinstance(value, str) else value
        if not _is_str_list(vals):
            raise AuthoringError(
                MALFORMED_CODE,
                "key %r op %r: value must be a non-empty string or "
                "list of non-empty strings, got %r" % (key, op, value))
        if key == "tool":
            # Early, loud refusal: the engine round-trip would catch
            # this too, but the author deserves the key-level error.
            bad = [v for v in vals if v not in KNOWN_TOOLS]
            if bad:
                raise AuthoringError(
                    MALFORMED_CODE,
                    "key 'tool': unknown tools %r (known: %s)"
                    % (bad, sorted(KNOWN_TOOLS)))
        return native_key, list(vals)
    if key == "path":
        vals = [value] if isinstance(value, str) else value
        if not _is_str_list(vals):
            raise AuthoringError(
                MALFORMED_CODE,
                "key 'path' op 'contains-any': value must be a "
                "non-empty string or list of non-empty strings, "
                "got %r" % (value,))
        return native_key, list(vals)
    if key in _BOOL_SIGNALS:
        if not isinstance(value, bool):
            # Wave-194 R1: mistyped values are refused, never
            # coerced -- "true" (string) must not silently mean True.
            raise AuthoringError(
                MALFORMED_CODE,
                "signal %r op 'eq': value must be a boolean, got %r"
                % (key, value))
        return native_key, value
    # counters
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0:
        raise AuthoringError(
            MALFORMED_CODE,
            "counter %r op 'gte': value must be a non-negative "
            "integer, got %r" % (key, value))
    return native_key, value


# ------------------------------------------------------------------
# filter compilation: authored filters -> list of native match dicts
# (one dict per OR-branch; each dict is a full AND conjunction)
# ------------------------------------------------------------------

def _compile_filters(filters, where):
    """Return a list of (branch, native_match) pairs."""
    if not isinstance(filters, list) or not filters:
        raise AuthoringError(
            MALFORMED_CODE,
            "%s: 'filters' must be a non-empty list, got %r"
            % (where, filters))
    branches = [({}, [])]  # (native_match, plan_filters)
    for filt in filters:
        branches = _apply_filter(filt, branches, where)
    return branches


def _apply_filter(filt, branches, where):
    if not isinstance(filt, dict):
        raise AuthoringError(
            MALFORMED_CODE,
            "%s: filter must be a mapping, got %r" % (where, filt))
    ftype = filt.get("type")
    if ftype == "value-filter":
        key = filt.get("key")
        op = filt.get("op")
        if not isinstance(key, str) or not isinstance(op, str):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: value-filter needs string 'key' and 'op', "
                "got %r" % (where, filt))
        native_key, native_value = _validate_value_filter(
            key, op, filt.get("value"))
        plan = {"type": "value-filter", "key": key, "op": op,
                "value": filt.get("value")}
        out = []
        for match, plans in branches:
            if native_key in match:
                # AND of two constraints on the same key: merging
                # lists would be a UNION (weaker), contradicting the
                # author's AND. Refuse rather than weaken.
                raise AuthoringError(
                    CONFLICTING_CODE,
                    "%s: conflicting filters on key %r inside one "
                    "AND conjunction" % (where, native_key))
            new_match = dict(match)
            new_match[native_key] = native_value
            out.append((new_match, plans + [plan]))
        return out
    if ftype == "and":
        sub = _compile_filters(filt.get("filters"), where + "/and")
        # (A) AND (B or C) expands to (A and B) or (A and C): merge
        # every outer branch with every sub-branch. Same-key
        # conflicts still refuse -- an AND that weakens to a UNION
        # is never built silently.
        out = []
        for match, plans in branches:
            for b_match, b_plans in sub:
                merged = dict(match)
                for k in b_match:
                    if k in merged:
                        raise AuthoringError(
                            CONFLICTING_CODE,
                            "%s: conflicting filters on key %r inside "
                            "'and'" % (where, k))
                    merged[k] = b_match[k]
                out.append((merged, plans + b_plans))
        return out
    if ftype == "or":
        sub = filt.get("filters")
        if not isinstance(sub, list) or len(sub) < 2:
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: 'or' needs a list of at least 2 filters, got %r"
                % (where, sub))
        # Expand: each OR branch becomes its own native rule. Every
        # branch is compiled independently (nested and/or allowed).
        expanded = []
        for i, branch_filt in enumerate(sub):
            for b_match, b_plans in _compile_filters(
                    [branch_filt], "%s/or[%d]" % (where, i)):
                expanded.append((b_match, b_plans))
        out = []
        for match, plans in branches:
            for b_match, b_plans in expanded:
                merged = dict(match)
                for k in b_match:
                    if k in merged:
                        raise AuthoringError(
                            CONFLICTING_CODE,
                            "%s: conflicting filters on key %r "
                            "across 'or' branch" % (where, k))
                    merged[k] = b_match[k]
                out.append((merged, plans + b_plans))
        return out
    raise AuthoringError(
        UNKNOWN_FILTER_CODE,
        "%s: unknown filter type %r (known: value-filter, and, or)"
        % (where, ftype))


# ------------------------------------------------------------------
# action compilation
# ------------------------------------------------------------------

def _compile_actions(actions, where):
    if not isinstance(actions, list) or not actions:
        raise AuthoringError(
            MALFORMED_CODE,
            "%s: 'actions' must be a non-empty list, got %r"
            % (where, actions))
    out = []
    for act in actions:
        if not isinstance(act, dict):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: action must be a mapping, got %r" % (where, act))
        atype = act.get("type")
        if atype not in _ACTION_EFFECTS:
            raise AuthoringError(
                UNKNOWN_ACTION_CODE,
                "%s: unknown action type %r (known: %s)"
                % (where, atype, sorted(_ACTION_EFFECTS)))
        reason = act.get("reason", "")
        if not isinstance(reason, str):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: action 'reason' must be a string, got %r"
                % (where, reason))
        flag = act.get("flag")
        if flag is not None and not isinstance(flag, str):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: action 'flag' must be a string, got %r"
                % (where, flag))
        out.append({"type": atype, "effect": _ACTION_EFFECTS[atype],
                    "reason": reason, "flag": flag})
    return out


# ------------------------------------------------------------------
# native YAML emission (controlled shapes only)
# ------------------------------------------------------------------

def _emit_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # json double-quoting is valid YAML for plain scalars.
        return json.dumps(value)
    raise AssertionError("unemittable scalar %r" % (value,))


def _emit(obj, indent):
    pad = " " * indent
    if isinstance(obj, dict):
        lines = []
        for key, val in obj.items():
            if isinstance(val, (dict, list)):
                lines.append("%s%s:" % (pad, key))
                lines.extend(_emit(val, indent + 2))
            else:
                lines.append("%s%s: %s" % (pad, key,
                                           _emit_scalar(val)))
        return lines
    if isinstance(obj, list):
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append("%s-" % pad)
                lines.extend(_emit(item, indent + 2))
            else:
                lines.append("%s- %s" % (pad, _emit_scalar(item)))
        return lines
    raise AssertionError("unemittable %r" % (obj,))


# ------------------------------------------------------------------
# compile entry point
# ------------------------------------------------------------------

class CompiledPolicy:
    """The compiled artifact: native YAML text, a loaded engine, and
    per-rule authoring plans (for filter-level explanations)."""

    def __init__(self, source_label, native_text, engine, plans):
        self.source_label = source_label
        self.native_text = native_text
        self.engine = engine
        self.plans = tuple(plans)

    def rule_ids(self):
        return [p["rule_id"] for p in self.plans]


def compile_authoring(text, source_label="<authored text>"):
    """Compile authored filters/actions YAML to a native policy.

    Returns a CompiledPolicy. Fail-closed: any unknown construct,
    malformed shape, or engine round-trip refusal raises
    AuthoringError with a policy-authoring-* code.
    """
    if not isinstance(text, str):
        raise AuthoringError(
            MALFORMED_CODE,
            "authored policy text must be str, got %s"
            % type(text).__name__)
    try:
        doc = _parse_yaml(text)
    except Exception as exc:  # noqa: BLE001 - parser is fail-closed
        raise AuthoringError(
            MALFORMED_CODE, "unparseable authored YAML: %s" % (exc,))
    if not isinstance(doc, dict):
        raise AuthoringError(
            MALFORMED_CODE,
            "authored policy must be a mapping, got %s"
            % type(doc).__name__)
    version = doc.get("version")
    if version != _AUTHORING_VERSION and version != str(
            _AUTHORING_VERSION):
        raise AuthoringError(
            MALFORMED_CODE,
            "authored 'version' must be %r, got %r"
            % (_AUTHORING_VERSION, version))
    policies = doc.get("policies")
    if not isinstance(policies, list) or not policies:
        raise AuthoringError(
            EMPTY_CODE, "authored 'policies' must be a non-empty list")
    native_rules = []
    plans = []
    for i, pol in enumerate(policies):
        where = "policies[%d]" % i
        if not isinstance(pol, dict):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: policy must be a mapping, got %r" % (where, pol))
        name = pol.get("name")
        if not isinstance(name, str) or not name:
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: 'name' must be a non-empty string, got %r"
                % (where, name))
        description = pol.get("description", "")
        if not isinstance(description, str):
            raise AuthoringError(
                MALFORMED_CODE,
                "%s: 'description' must be a string, got %r"
                % (where, description))
        branches = _compile_filters(pol.get("filters"), where)
        actions = _compile_actions(pol.get("actions"), where)
        # One native rule per (action x or-branch). Suffix rule ids
        # only when expansion produced more than one rule, so the
        # common single-rule case keeps the author's name verbatim.
        combos = [(a, m, p) for a in actions for (m, p) in branches]
        for j, (action, match, fplans) in enumerate(combos):
            rule_id = name if len(combos) == 1 else "%s#%d" % (name,
                                                               j + 1)
            rule = {"id": rule_id}
            if description:
                rule["description"] = description
            rule["effect"] = action["effect"]
            if action["flag"] is not None:
                rule["flag"] = action["flag"]
            rule["match"] = match
            if action["reason"]:
                rule["reason"] = action["reason"]
            native_rules.append(rule)
            plans.append({"rule_id": rule_id,
                          "effect": action["effect"],
                          "filters": fplans,
                          "action": action["type"]})
    native_doc = {"version": 2, "policies": native_rules}
    lines = ["# Generated by gov/policy_authoring.py -- do not "
             "hand-edit.",
             "# Edit the authored source and recompile."]
    lines.extend(_emit(native_doc, 0))
    native_text = "\n".join(lines) + "\n"
    try:
        engine = PolicyEngine.from_text(
            native_text, source_label="authoring:" + source_label)
    except Exception as exc:  # noqa: BLE001 - engine is fail-closed
        raise AuthoringError(
            COMPILE_REFUSED_CODE,
            "compiled policy refused by PolicyEngine: %s" % (exc,))
    return CompiledPolicy(source_label, native_text, engine, plans)


# ------------------------------------------------------------------
# filter-level explanation (authoring-layer "why")
# ------------------------------------------------------------------

def _counter_value(native_key, context):
    """Counter read through the engine's own strict helper -- the
    explanation layer delegates typed reads to the engine's code so
    the explanation can never drift from enforcement semantics."""
    counters = context.get("counters") or {}
    if native_key == "min_external_calls":
        return checked_counter(counters, "api_call")
    if native_key == "min_sends":
        return (checked_counter(counters, "send_email")
                + checked_counter(counters, "http_post"))
    if native_key == "min_writes":
        return checked_counter(counters, "write_file")
    if native_key == "min_deletes":
        return checked_counter(counters, "delete_file")
    raise AssertionError("unknown counter %r" % (native_key,))


def _explain_one(plan_filter, action, context):
    """(matched, why) for one compiled filter plan entry."""
    key = plan_filter["key"]
    op = plan_filter["op"]
    value = plan_filter["value"]
    if key in ("tool", "role", "agent"):
        actual = action.get({"tool": "tool", "role": "role",
                             "agent": "agent_id"}[key])
        want = [value] if isinstance(value, str) else list(value)
        if op == "eq":
            # Compile guarantees a single string for eq.
            ok = actual == want[0]
            why = ("%s %r equals %r" % (key, actual, want[0])
                   if ok else
                   "%s %r does not equal %r" % (key, actual,
                                                want[0]))
        else:  # in
            ok = actual in want
            why = ("%s %r is in %r" % (key, actual, want)
                   if ok else
                   "%s %r is not in %r" % (key, actual, want))
        return ok, why
    if key == "path":
        args = action.get("args") or {}
        path = str(args.get("path", ""))
        # F146: the engine matches against the resolved target as
        # well as the declared path. Mirror that exactly -- the
        # explanation must never disagree with the engine trace.
        # Report only which policy-authored substrings matched --
        # never either raw path (both may carry secrets).
        resolved = str(context.get("path_resolved") or "")
        subs = [value] if isinstance(value, str) else list(value)
        hit = [s for s in subs if s in path]
        hit_resolved = [s for s in subs if s in resolved]
        ok = bool(hit or hit_resolved)
        if hit:
            why = "path contains %r" % (hit,)
        elif hit_resolved:
            why = "resolved target contains %r" % (hit_resolved,)
        else:
            why = "path contains none of %r" % (subs,)
        return ok, why
    if key in _BOOL_SIGNALS:
        # Engine's own strict read: None -> False, non-bool raises.
        actual = checked_bool(context, key)
        want = bool(value)  # compile guarantees a real bool
        ok = actual == want
        why = ("%s is %r, required %r" % (key, actual, want)
               if ok else
               "%s is %r, required %r -- mismatch" % (key, actual,
                                                      want))
        return ok, why
    # counters: op gte
    actual = _counter_value(key, context)
    ok = actual >= value
    why = ("%s count %d >= %d" % (key, actual, value)
           if ok else
           "%s count %d < %d" % (key, actual, value))
    return ok, why


def _normalize_action_context(action, context):
    """Engine-consistent input shapes for the explanation seam.

    The native engine's Request.from_action tolerates None via
    ``action or {}`` / ``context or {}`` and decides default_deny;
    the explanation layer mirrors that exactly so the why can
    never disagree with the verdict. Any other non-mapping shape
    is a caller error and is refused fail-closed with a machine
    code (this module's fixture-loader precedent) -- this makes
    the seam strictly more robust than the engine, which escapes
    raw AttributeError on truthy non-mapping actions.
    """
    if action is None:
        action = {}
    elif not isinstance(action, Mapping):
        raise AuthoringError(
            MALFORMED_CODE,
            "explain_candidate needs a mapping action, got %s"
            % type(action).__name__)
    if context is None:
        context = {}
    elif not isinstance(context, Mapping):
        raise AuthoringError(
            MALFORMED_CODE,
            "explain_candidate needs a mapping context, got %s"
            % type(context).__name__)
    return action, context


def explain_candidate(compiled, action, context):
    """Per-rule filter explanations for a compiled candidate.

    Returns a list of {"rule", "effect", "matched", "filters":
    [{"key", "op", "matched", "why"}]}. A rule matches iff every
    filter matches (AND); the authoring layer never weakens this.
    """
    if not isinstance(compiled, CompiledPolicy):
        raise AuthoringError(
            MALFORMED_CODE,
            "explain_candidate needs a CompiledPolicy, got %s"
            % type(compiled).__name__)
    action, context = _normalize_action_context(action, context)
    out = []
    for plan in compiled.plans:
        frecs = []
        matched = True
        for filt in plan["filters"]:
            ok, why = _explain_one(filt, action, context)
            frecs.append({"key": filt["key"], "op": filt["op"],
                          "matched": ok, "why": why})
            matched = matched and ok
        out.append({"rule": plan["rule_id"], "effect": plan["effect"],
                    "matched": matched, "filters": frecs})
    return out


# ------------------------------------------------------------------
# dry-run
# ------------------------------------------------------------------

def _trace_for(engine, action, context):
    """Per-rule (rule_id, effect, matched) from the engine's own
    decide() trace -- the authoritative rule-level "which matched"."""
    request = Request.from_action(action, context)
    decision = engine.decide(request, record_telemetry=False)
    return [{"rule": t.rule_id, "effect": t.effect,
             "matched": bool(t.matched)}
            for t in decision.diagnostics.trace]


def _deciding_rule(engine, action, context):
    """The deciding rule id from the engine trace (or default_deny)."""
    request = Request.from_action(action, context)
    decision = engine.decide(request, record_telemetry=False)
    hit = decision.diagnostics.deciding_rule
    return hit.rule_id if hit is not None else "default_deny"


class DryRunReport:
    """The deterministic result of one dry_run() call."""

    def __init__(self, harness_dir, candidate, fixtures):
        self.harness_dir = harness_dir
        self.candidate = candidate
        self.fixtures = tuple(fixtures)
        self.total = len(fixtures)
        self.changed = sum(1 for f in fixtures if f["changed"])

    def to_dict(self):
        return {
            "dry_run": True,
            "harness": self.harness_dir,
            "candidate": ({"rules": len(self.candidate.plans),
                           "rule_ids": self.candidate.rule_ids()}
                          if self.candidate is not None else None),
            "fixtures": [dict(f) for f in self.fixtures],
            "summary": {
                "total": self.total,
                "changed": self.changed,
                "would_deny": sum(
                    1 for f in self.fixtures
                    if (f["with_candidate"] or f["current"])
                    ["effect"] == "deny"),
                "would_allow": sum(
                    1 for f in self.fixtures
                    if (f["with_candidate"] or f["current"])
                    ["effect"] == "allow"),
                "would_require_approval": sum(
                    1 for f in self.fixtures
                    if (f["with_candidate"] or f["current"])
                    ["effect"] == "require_approval"),
            },
        }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"))


def dry_run(harness_dir, authoring_text=None):
    """Preview a policy set (plus an optional authored candidate)
    against a harness's fixtures. READ-ONLY: evaluates only, writes
    nothing, enforces nothing.

    Per fixture the report carries the current verdict, the
    with-candidate verdict (forbid-overrides-permit combination),
    whether the verdict changed, the engine's own per-rule trace
    for the existing set, and -- for the candidate -- per-filter
    match explanations. Fixture ``expected/`` files are NOT
    required: dry-run previews, it does not grade (fixture shape is
    still validated fail-closed).
    """
    policies = _load_policies(os.path.join(harness_dir, "policies"))
    fixtures = _load_fixtures_lenient(
        os.path.join(harness_dir, "fixtures"))
    candidate = None
    if authoring_text is not None:
        candidate = compile_authoring(
            authoring_text, source_label="dry-run-candidate")
    cand_engine = candidate.engine if candidate is not None else None
    records = []
    for name, action, context in fixtures:
        decisions = [engine.evaluate(action, context,
                                     record_telemetry=False)
                     for _pname, engine in policies]
        current = policy_combine.combine(decisions)
        current_rec = {"effect": current.effect, "code": current.code}
        current_matches = []
        for pname, engine in policies:
            for t in _trace_for(engine, action, context):
                current_matches.append({"policy": pname, **t})
        cand_rec = with_rec = cand_matches = None
        changed = False
        if cand_engine is not None:
            # evaluate() returns a PolicyDecision (effect/reason/
            # flag; no combiner code -- codes belong to the
            # combiner's CombinedDecision).
            cand_dec = cand_engine.evaluate(
                action, context, record_telemetry=False)
            cand_rec = {"effect": cand_dec.effect,
                        "reason": cand_dec.reason,
                        "deciding_rule": _deciding_rule(
                            cand_engine, action, context)}
            with_combined = policy_combine.combine(
                decisions + [cand_dec])
            with_rec = {"effect": with_combined.effect,
                        "code": with_combined.code}
            changed = with_combined.effect != current.effect
            cand_matches = explain_candidate(candidate, action,
                                             context)
        records.append({
            "fixture": name,
            "tool": action.get("tool"),
            "current": current_rec,
            "candidate": cand_rec,
            "with_candidate": with_rec,
            "changed": changed,
            "current_matches": current_matches,
            "candidate_matches": cand_matches,
        })
    return DryRunReport(harness_dir, candidate, records)
