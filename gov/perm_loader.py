"""PERM model-as-data loader (wave-200, Casbin ADAPT).

Casbin's PERM metamodel makes the access-control *model itself*
data: ``[request_definition]``, ``[policy_definition]``,
``[role_definition]``, ``[policy_effect]``, ``[matchers]``. The
wave-199 spike proved three things against casbin v3 source: (a) the
core is boolean -- a ``require_approval`` third verdict is NOT
first-class (policy ``eft=require_approval`` parses silently to
Indeterminate); (b) forbid-overrides-permit IS native
(``AllowAndDenyEffect``); (c) the model FILE is the crown jewel --
changing one ``[policy_effect]`` line inverts the discipline with
the deny line still sitting in the policy file, ignored (D2).

This module takes the PERM *discipline* and re-implements it
stdlib-only, with the spike's residuals fixed as data, not caller
protocol:

* Three ordered screens (deny / approval / allow) in ONE signed
  model document, with the screen ORDER and the verdict mapping in a
  ``[composition]`` section INSIDE the signed document (the spike's
  S2a residual: order was caller protocol).
* Effect vocabulary restricted to casbin's five known effect
  strings; anything else is refused at load. Four have narrow
  implemented semantics; ``subjectPriority`` is recognized but
  refused (the narrow engine has no subject hierarchy -- honest,
  loud, not silent).
* Matcher functions are named in the model but implemented by the
  engine's FIXED builtin registry (``glob``, ``regex``). An unknown
  function name is refused LOUD at load (the spike's D3 shape).
  Matcher *implementations* are code the model cannot pin -- the
  function-set digest is recorded (Decision BOM ``inputs.perm``) so
  the coupling is auditable, not invisible.
* Stateful conditions (velocity, approval state) are SNAPSHOT
  attributes: the caller computes them AT THE ENFORCEMENT BOUNDARY
  and passes them in the request. The model evaluates a frozen
  instant, which is auditable. TOCTOU between snapshot and
  enforcement is invisible to the model -- the snapshot MUST be
  taken at the enforcement boundary, not earlier. (Same split the
  Cedar lane needed, except here it lives in one document.)
* The model + policy ship as a SIGNED pack (``perm-model.yml`` +
  ``perm-policy.yml`` members) in their own trust domain
  (``sasanam-perm-model-signing/v1`` -- a rule-signing keyset can
  never mint a model pack). Activation composes with
  :class:`gov.pack_loader.PackLoader`: exact member enumeration,
  digest verification, monotonic version floor, expiry, threshold
  signatures. The model document gets pin-tier treatment: mint with
  threshold >= 2 (two distinct humans).
* Unsigned model -> refuse to load. Tampered model (D2 shape) ->
  refused by signature. Discipline inversion without a valid
  signature -> fails closed.

The model document is strict YAML (``gov.sigma_subset``): unknown
top-level keys, unknown matcher nodes, unknown schema columns, and
top-level ``not`` are all refused loud -- never silently ignored.
``decide()`` never returns allow on a malformed request.

$0 spend, synthetic/local deterministic only. No network.
"""

import copy
import fnmatch
import hashlib
import json
import re

from .sigma_subset import parse_yaml_subset, SigmaSubsetError
from . import rule_pack as _rp
from .pack_loader import PackLoader, PackActivationError, ActivePack

__all__ = [
    "PERM_MODEL_FORMAT",
    "PERM_POLICY_FORMAT",
    "PERM_MODEL_MEMBER",
    "PERM_POLICY_MEMBER",
    "MODEL_VERSION",
    "PermError",
    "FUNCTION_REGISTRY",
    "function_set_digest",
    "PermModel",
    "parse_perm_model",
    "parse_perm_policy",
    "compile_perm_model",
    "load_perm_from_active_pack",
    "mint_perm_pack",
    "new_perm_pack_loader",
]

#: Exact format tags (exact match at load).
PERM_MODEL_FORMAT = "sasanam-perm/v1"
PERM_POLICY_FORMAT = "sasanam-perm/v1"

#: Pack member ids for the model and the policy.
PERM_MODEL_MEMBER = "perm-model.yml"
PERM_POLICY_MEMBER = "perm-policy.yml"

#: Model document version understood by this loader.
MODEL_VERSION = 1

#: Verdict vocabulary.
VERDICTS = ("deny", "require_approval", "allow")

#: casbin's five known effect expressions (constant/*.go). The narrow
#: engine implements four; subjectPriority is recognized and refused
#: (no subject hierarchy in the narrow engine).
EFFECT_ALLOW_OVERRIDE = "some(where (p_eft == allow))"
EFFECT_DENY_OVERRIDE = "!some(where (p_eft == deny))"
EFFECT_ALLOW_AND_DENY = (
    "some(where (p_eft == allow)) && !some(where (p_eft == deny))")
EFFECT_PRIORITY = "priority(p_eft) || deny"
EFFECT_SUBJECT_PRIORITY = "subjectPriority(p_eft) || deny"
_KNOWN_EFFECTS = frozenset({
    EFFECT_ALLOW_OVERRIDE, EFFECT_DENY_OVERRIDE,
    EFFECT_ALLOW_AND_DENY, EFFECT_PRIORITY,
    EFFECT_SUBJECT_PRIORITY,
})

_SCHEMA_TYPES = ("str", "int", "bool", "eft")
_COL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_MODEL_TOP_KEYS = frozenset({
    "perm_model", "model_version", "description",
    "request_schema", "policy_schema", "matchers",
    "screens", "composition",
})
_POLICY_TOP_KEYS = frozenset({"perm_policy", "policies", "description"})
_COMPARE_OPS = ("eq", "neq", "gt", "gte", "lt", "lte")
_BOOL_OPS = ("and", "or")


class PermError(Exception):
    """Fail-closed PERM model violation (load or decide)."""


# ---------------------------------------------------------------------------
# Matcher function registry (engine-fixed; the model names, the engine
# provides -- casbin's AddFunction split, made auditable via the
# function-set digest).
# ---------------------------------------------------------------------------

def _fn_glob(value, pattern):
    # Call convention (shared with _fn_regex): the model passes
    # (value, pattern) -- the request/policy VALUE first, the
    # pattern second, matching casbin's keyMatch(r_val, p_pat)
    # order. fnmatchcase(name, pat) takes the name first.
    return fnmatch.fnmatchcase(str(value), str(pattern))


def _fn_regex(value, pattern):
    # pattern is precompiled at model load (invalid -> refuse).
    return pattern.search(str(value)) is not None


#: name -> (callable, arity, arg_spec). The model may only name these.
#: Both take ``(value, pattern)``: the request/policy VALUE first,
#: the pattern second (casbin keyMatch order). ``regex`` takes its
#: pattern as a MODEL LITERAL (precompiled at load); policy columns
#: may not smuggle patterns.
FUNCTION_REGISTRY = {
    "glob": (_fn_glob, 2),
    "regex": (_fn_regex, 2),
}

#: Registry version, bound into the function-set digest so a registry
#: change is a distinct auditable event from a model change.
# Bump this on ANY implementation change to a registry function:
# function_set_digest() binds (version, names), not code bytes, so
# the version bump is what makes implementation changes visible to
# auditors (see function_set_digest docstring for the honest claim).
_FUNCTION_REGISTRY_VERSION = 1


def function_set_digest():
    """sha256 over the canonical function-set descriptor.

    The model names matcher functions but cannot pin their
    implementations (spike S3.1); the digest records exactly which
    function set a decision ran under, and rides the Decision BOM.

    Honest claim: the digest binds (registry_version, function
    NAMES) -- it does NOT hash implementation bytes. An
    implementation change with no version bump is invisible to
    this digest. The binding discipline is: ANY change to a
    registry implementation bumps ``_FUNCTION_REGISTRY_VERSION``
    (a code-review-enforced rule, stated here so auditors know
    what the digest does and does not prove). The digest's job is
    cross-BOM change detection -- "did these two decisions run
    under the same declared function set?" -- not code identity.
    """
    descriptor = {
        "registry_version": _FUNCTION_REGISTRY_VERSION,
        "functions": sorted(FUNCTION_REGISTRY),
    }
    return hashlib.sha256(json.dumps(
        descriptor, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Strict parsing
# ---------------------------------------------------------------------------

def _parse_yaml(data, what):
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PermError("%s is not UTF-8: %s" % (what, exc))
    elif isinstance(data, str):
        text = data
    else:
        raise PermError("%s must be bytes or str" % what)
    try:
        doc = parse_yaml_subset(text)
    except SigmaSubsetError as exc:
        raise PermError("%s YAML refused: %s" % (what, exc))
    if not isinstance(doc, dict):
        raise PermError("%s must be a YAML mapping" % what)
    return doc


def _check_columns(schema, what):
    if not isinstance(schema, dict) or not schema:
        raise PermError("%s must be a non-empty mapping" % what)
    for col, typ in schema.items():
        if not isinstance(col, str) or not _COL_RE.match(col):
            raise PermError(
                "%s column %r is not a valid identifier" % (what, col))
        if typ not in _SCHEMA_TYPES:
            raise PermError(
                "%s column %r has unknown type %r (want one of %s)"
                % (what, col, typ, sorted(_SCHEMA_TYPES)))
    if len(set(schema)) != len(schema):
        raise PermError("%s has duplicate columns" % what)
    return dict(schema)


def _compile_operand(node, req_schema, pol_schema, where):
    """Compile a matcher operand to ("req"|"pol"|"lit", name/value, type)."""
    if isinstance(node, dict) and set(node) == {"req"}:
        col = node["req"]
        if col not in req_schema:
            raise PermError(
                "%s: unknown request column %r" % (where, col))
        return ("req", col, req_schema[col])
    if isinstance(node, dict) and set(node) == {"pol"}:
        col = node["pol"]
        if col not in pol_schema:
            raise PermError(
                "%s: unknown policy column %r" % (where, col))
        return ("pol", col, pol_schema[col])
    if isinstance(node, bool):
        return ("lit", node, "bool")
    if isinstance(node, int):
        return ("lit", node, "int")
    if isinstance(node, str):
        return ("lit", node, "str")
    raise PermError(
        "%s: operand %r is not a {req:}/{pol:}/literal" % (where, node))


def _operand_type_compatible(op, left, right, where):
    lt, rt = left[2], right[2]
    if op in ("gt", "gte", "lt", "lte"):
        if lt != "int" or rt != "int":
            raise PermError(
                "%s: %s needs int operands, got %s vs %s"
                % (where, op, lt, rt))
    elif lt != rt:
        raise PermError(
            "%s: %s needs same-type operands, got %s vs %s"
            % (where, op, lt, rt))


def _const_operand_value(operand):
    """(is_const, value) for a compiled operand. Literals are
    constant (a precompiled regex literal counts as its compiled
    pattern object -- ``_eval_matcher`` compares the same objects by
    identity, so the fold agrees with runtime); req/pol references
    are not."""
    kind, name, _typ = operand
    if kind == "lit":
        return True, name
    return False, None


def _const_eval(node):
    """(is_const, value): True when the compiled matcher node is
    provably constant -- it references no req/pol operand, so its
    truth value is fixed at load time. Used to refuse
    provably-never-true screen matchers (the silently-never-matching
    pack shape Cedar's validation docs warn about)."""
    kind = node[0]
    if kind == "and":
        vals = []
        for sub in node[1]:
            const, val = _const_eval(sub)
            if not const:
                return False, None
            vals.append(val)
        return True, all(vals)
    if kind == "or":
        vals = []
        for sub in node[1]:
            const, val = _const_eval(sub)
            if not const:
                return False, None
            vals.append(val)
        return True, any(vals)
    if kind == "not":
        const, val = _const_eval(node[1])
        return (True, not val) if const else (False, None)
    if kind in _COMPARE_OPS:
        lconst, lval = _const_operand_value(node[1])
        rconst, rval = _const_operand_value(node[2])
        if not (lconst and rconst):
            return False, None
        if kind == "eq":
            return True, lval == rval
        if kind == "neq":
            return True, lval != rval
        if kind == "gt":
            return True, lval > rval
        if kind == "gte":
            return True, lval >= rval
        if kind == "lt":
            return True, lval < rval
        return True, lval <= rval
    if kind == "call":
        _k, impl_name, args = node
        impl, _arity = FUNCTION_REGISTRY[impl_name]
        vals = []
        for arg in args:
            const, val = _const_operand_value(arg)
            if not const:
                return False, None
            vals.append(val)
        try:
            return True, bool(impl(*vals))
        except Exception:
            # A constant-fold failure is not a load failure: the
            # node simply is not provably constant (evaluation will
            # raise loudly per-row if the inputs are actually bad).
            return False, None
    return False, None


def _compile_matcher(node, req_schema, pol_schema, matchers, where,
                     _top=True):
    """Compile a matcher node to a nested tuple tree."""
    if not isinstance(node, dict) or len(node) != 1:
        raise PermError(
            "%s: matcher node must be a single-key mapping, got %r"
            % (where, node))
    key = next(iter(node))
    if key in _BOOL_OPS:
        subs = node[key]
        if not isinstance(subs, list) or not subs:
            raise PermError(
                "%s: %s needs a non-empty list" % (where, key))
        return (key, [_compile_matcher(s, req_schema, pol_schema,
                                      matchers, where, _top=False)
                      for s in subs])
    if key == "not":
        if _top:
            # capa's documented edge case, same discipline as
            # gov/capability_rules: top-level NOT is refused loud
            # instead of mis-evaluated.
            raise PermError(
                "%s: top-level 'not' is refused (negation must sit "
                "under and/or)" % where)
        return ("not", _compile_matcher(node[key], req_schema,
                                        pol_schema, matchers, where,
                                        _top=False))
    if key in _COMPARE_OPS:
        args = node[key]
        if not isinstance(args, list) or len(args) != 2:
            raise PermError(
                "%s: %s needs exactly 2 operands" % (where, key))
        left = _compile_operand(args[0], req_schema, pol_schema,
                                "%s/%s[0]" % (where, key))
        right = _compile_operand(args[1], req_schema, pol_schema,
                                 "%s/%s[1]" % (where, key))
        _operand_type_compatible(key, left, right, where)
        return (key, left, right)
    if key == "call":
        args = node[key]
        if not isinstance(args, list) or len(args) < 1:
            raise PermError("%s: call needs [func, arg, ...]" % where)
        func = args[0]
        if func not in matchers:
            # D3 shape: unknown matcher function -> loud refusal.
            raise PermError(
                "%s: unknown matcher function %r (known: %s)"
                % (where, func, sorted(matchers)))
        _impl, arity = FUNCTION_REGISTRY[matchers[func]]
        if len(args) - 1 != arity:
            raise PermError(
                "%s: matcher %r takes %d args, got %d"
                % (where, func, arity, len(args) - 1))
        compiled_args = []
        for i, a in enumerate(args[1:]):
            op = _compile_operand(a, req_schema, pol_schema,
                                  "%s/call[%d]" % (where, i))
            if op[0] == "lit" and op[2] != "str":
                raise PermError(
                    "%s: matcher %r args must be strings or "
                    "string columns" % (where, func))
            if op[0] != "lit" and op[2] != "str":
                raise PermError(
                    "%s: matcher %r arg %d must be a string column, "
                    "got %s" % (where, func, i, op[2]))
            compiled_args.append(op)
        if matchers[func] == "regex":
            # The regex pattern must be a MODEL LITERAL so it is
            # precompiled here (invalid -> refuse); policy columns
            # may not smuggle patterns. The pattern is the SECOND
            # call arg (value, pattern) -- the same convention as
            # glob.
            pat = compiled_args[1]
            if pat[0] != "lit":
                raise PermError(
                    "%s: regex pattern must be a model literal, not "
                    "a column reference" % where)
            try:
                compiled_pat = re.compile(pat[1])
            except re.error as exc:
                raise PermError(
                    "%s: invalid regex %r: %s" % (where, pat[1], exc))
            compiled_args[1] = ("lit", compiled_pat, "str")
        # Bake the REGISTRY impl name into the node (not the model's
        # local alias): evaluation is then pure -- no per-model
        # global, no silent registry swap. A registry change is a
        # distinct auditable event via function_set_digest().
        return ("call", matchers[func], compiled_args)
    raise PermError(
        "%s: unknown matcher node %r (want one of: %s)"
        % (where, key,
           sorted(list(_BOOL_OPS) + ["not"] + list(_COMPARE_OPS)
                  + ["call"])))


def parse_perm_model(data):
    """Strict-parse a PERM model document. Returns the validated
    model dict (with compiled matchers). Raises PermError loud."""
    doc = _parse_yaml(data, "perm model")
    unknown = set(doc) - _MODEL_TOP_KEYS
    if unknown:
        raise PermError(
            "perm model carries unknown top-level keys: %s"
            % sorted(unknown))
    if doc.get("perm_model") != PERM_MODEL_FORMAT:
        raise PermError(
            "perm_model format must be %r" % (PERM_MODEL_FORMAT,))
    version = doc.get("model_version")
    if (isinstance(version, bool) or not isinstance(version, int)
            or version != MODEL_VERSION):
        raise PermError(
            "model_version must be %d" % (MODEL_VERSION,))
    req_schema = _check_columns(doc.get("request_schema"),
                                "request_schema")
    for col, typ in req_schema.items():
        # The request validator only implements str|int|bool. An
        # 'eft'-typed request column would pass validation
        # unchecked (casbin-style silent trust); refuse at load.
        if typ not in ("str", "int", "bool"):
            raise PermError(
                "request_schema column %r has type %r: request "
                "columns must be str|int|bool (eft lives in the "
                "policy, never the request)" % (col, typ))
    pol_schema = _check_columns(doc.get("policy_schema"),
                                "policy_schema")
    if pol_schema.get("eft") != "eft":
        raise PermError(
            "policy_schema must declare an 'eft' column of type eft")
    matchers = doc.get("matchers")
    if not isinstance(matchers, dict) or not matchers:
        raise PermError("matchers must be a non-empty mapping")
    for name, impl in matchers.items():
        if not isinstance(name, str) or not _COL_RE.match(name):
            raise PermError("matcher name %r is not valid" % (name,))
        if impl not in FUNCTION_REGISTRY:
            raise PermError(
                "matcher %r names unknown implementation %r "
                "(known: %s)" % (name, impl,
                                  sorted(FUNCTION_REGISTRY)))
    screens = doc.get("screens")
    if not isinstance(screens, list) or not screens:
        raise PermError("screens must be a non-empty list")
    compiled_screens = []
    seen = set()
    for i, screen in enumerate(screens):
        where = "screens[%d]" % i
        if not isinstance(screen, dict):
            raise PermError("%s must be a mapping" % where)
        unknown_s = set(screen) - {"name", "effect", "matcher",
                                   "description"}
        if unknown_s:
            raise PermError(
                "%s carries unknown keys: %s" % (where,
                                                 sorted(unknown_s)))
        name = screen.get("name")
        if not isinstance(name, str) or not _COL_RE.match(name):
            raise PermError("%s name %r is not valid" % (where, name))
        if name in seen:
            raise PermError("duplicate screen name %r" % (name,))
        seen.add(name)
        effect = screen.get("effect")
        if effect not in _KNOWN_EFFECTS:
            raise PermError(
                "%s effect %r is not one of the known effect "
                "expressions" % (where, effect))
        if effect == EFFECT_SUBJECT_PRIORITY:
            raise PermError(
                "%s: subjectPriority effects are not supported by "
                "the narrow engine (no subject hierarchy)" % where)
        if "matcher" not in screen:
            raise PermError("%s is missing its matcher" % where)
        compiled = _compile_matcher(
            screen["matcher"], req_schema, pol_schema, matchers,
            "%s/matcher" % where)
        is_const, const_val = _const_eval(compiled)
        if is_const and const_val is False:
            # Wave-206 (Cedar ADAPT): a screen whose matcher is
            # provably never-true can never fire -- its policy rows
            # are silently dead. That is the never-matching-pack
            # shape Cedar's validation docs warn about (a typo'd
            # policy that "will have no impact" and is ignored). The
            # honest way to disable a screen is empty policy rows,
            # which keep the screen visible in the pack; a
            # constant-false matcher is refused loud at load.
            # (Constant-TRUE matchers are allowed: "match all" is the
            # pack author's explicit, digest-visible choice.)
            raise PermError(
                "%s: matcher is provably never-true (constant-folds "
                "to False) -- a screen that can never fire is refused; "
                "disable the screen with empty policy rows instead"
                % where)
        compiled_screens.append({
            "name": name,
            "effect": effect,
            "matcher": compiled,
            "description": screen.get("description", ""),
        })
    composition = doc.get("composition")
    if not isinstance(composition, dict):
        raise PermError("composition must be a mapping")
    unknown_c = set(composition) - {"default_verdict", "order",
                                    "description"}
    if unknown_c:
        raise PermError(
            "composition carries unknown keys: %s" % sorted(unknown_c))
    default_verdict = composition.get("default_verdict")
    if default_verdict not in VERDICTS:
        raise PermError(
            "composition default_verdict must be one of %s"
            % (list(VERDICTS),))
    order = composition.get("order")
    if not isinstance(order, list) or not order:
        raise PermError("composition order must be a non-empty list")
    compiled_order = []
    ordered = set()
    for i, entry in enumerate(order):
        where = "composition/order[%d]" % i
        if not isinstance(entry, dict):
            raise PermError("%s must be a mapping" % where)
        unknown_e = set(entry) - {"screen", "verdict", "invert"}
        if unknown_e:
            raise PermError(
                "%s carries unknown keys: %s" % (where,
                                                 sorted(unknown_e)))
        screen = entry.get("screen")
        if screen not in seen:
            raise PermError(
                "%s names unknown screen %r" % (where, screen))
        if screen in ordered:
            raise PermError(
                "%s: screen %r appears twice in the order" % (where,
                                                              screen))
        ordered.add(screen)
        verdict = entry.get("verdict")
        if verdict not in VERDICTS:
            raise PermError(
                "%s verdict must be one of %s"
                % (where, list(VERDICTS)))
        invert = entry.get("invert", False)
        if not isinstance(invert, bool):
            raise PermError("%s invert must be a bool" % where)
        compiled_order.append({"screen": screen, "verdict": verdict,
                               "invert": invert})
    if ordered != seen:
        raise PermError(
            "composition order must name every screen exactly once; "
            "missing: %s" % sorted(seen - ordered))
    return {
        "model_version": MODEL_VERSION,
        "description": doc.get("description", ""),
        "request_schema": req_schema,
        "policy_schema": pol_schema,
        "matchers": dict(matchers),
        "screens": compiled_screens,
        "composition": {
            "default_verdict": default_verdict,
            "order": compiled_order,
        },
    }


def parse_perm_policy(data, model):
    """Strict-parse a PERM policy document against a parsed model.

    Returns ``{screen_name: [row, ...]}`` with validated rows.
    Raises PermError loud."""
    doc = _parse_yaml(data, "perm policy")
    unknown = set(doc) - _POLICY_TOP_KEYS
    if unknown:
        raise PermError(
            "perm policy carries unknown top-level keys: %s"
            % sorted(unknown))
    if doc.get("perm_policy") != PERM_POLICY_FORMAT:
        raise PermError(
            "perm_policy format must be %r" % (PERM_POLICY_FORMAT,))
    policies = doc.get("policies")
    if not isinstance(policies, dict):
        raise PermError("policies must be a mapping")
    screen_names = [s["name"] for s in model["screens"]]
    unknown_screens = set(policies) - set(screen_names)
    if unknown_screens:
        raise PermError(
            "policies names unknown screens: %s"
            % sorted(unknown_screens))
    missing = set(screen_names) - set(policies)
    if missing:
        # Explicit, not omitted by accident: every screen needs its
        # policy entry (possibly an empty list).
        raise PermError(
            "policies is missing screens: %s" % sorted(missing))
    pol_schema = model["policy_schema"]
    out = {}
    for screen in screen_names:
        rows = policies[screen]
        if not isinstance(rows, list):
            raise PermError(
                "policies[%r] must be a list of rows" % (screen,))
        compiled_rows = []
        for i, row in enumerate(rows):
            where = "policies[%s][%d]" % (screen, i)
            if not isinstance(row, dict):
                raise PermError("%s must be a mapping" % where)
            if set(row) != set(pol_schema):
                raise PermError(
                    "%s must carry exactly the policy_schema "
                    "columns %s" % (where, sorted(pol_schema)))
            compiled = {}
            for col, typ in pol_schema.items():
                value = row[col]
                if typ == "str":
                    if not isinstance(value, str):
                        raise PermError(
                            "%s column %r must be a string" % (where,
                                                               col))
                elif typ == "int":
                    if (isinstance(value, bool)
                            or not isinstance(value, int)):
                        raise PermError(
                            "%s column %r must be an int" % (where,
                                                             col))
                elif typ == "bool":
                    if not isinstance(value, bool):
                        raise PermError(
                            "%s column %r must be a bool" % (where,
                                                             col))
                elif typ == "eft":
                    if value not in ("allow", "deny"):
                        # casbin silently maps anything else to
                        # Indeterminate (the D1 footgun); the strict
                        # loader refuses at load instead.
                        raise PermError(
                            "%s column 'eft' must be allow|deny, got "
                            "%r" % (where, value))
                compiled[col] = value
            compiled_rows.append(compiled)
        out[screen] = compiled_rows
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _resolve_operand(operand, request, row):
    kind, name, _typ = operand
    if kind == "req":
        return request[name]
    if kind == "pol":
        return row[name]
    value = name
    if isinstance(value, re.Pattern):
        return value
    return value


def _eval_matcher(node, request, row):
    kind = node[0]
    if kind == "and":
        return all(_eval_matcher(s, request, row) for s in node[1])
    if kind == "or":
        return any(_eval_matcher(s, request, row) for s in node[1])
    if kind == "not":
        return not _eval_matcher(node[1], request, row)
    if kind in _COMPARE_OPS:
        left = _resolve_operand(node[1], request, row)
        right = _resolve_operand(node[2], request, row)
        if kind == "eq":
            return left == right
        if kind == "neq":
            return left != right
        if kind == "gt":
            return left > right
        if kind == "gte":
            return left >= right
        if kind == "lt":
            return left < right
        return left <= right
    if kind == "call":
        _k, impl_name, args = node
        impl, _arity = FUNCTION_REGISTRY[impl_name]
        resolved = [_resolve_operand(a, request, row) for a in args]
        return bool(impl(*resolved))
    raise PermError("unknown compiled matcher node %r" % (kind,))


def _apply_effect(effect, matched_rows):
    """Narrow semantics for the known effect expressions.

    ``matched_rows``: policy rows whose matcher held, in policy
    order. Returns bool (the screen's effect value)."""
    efts = [row["eft"] for row in matched_rows]
    if effect == EFFECT_ALLOW_OVERRIDE:
        return "allow" in efts
    if effect == EFFECT_DENY_OVERRIDE:
        return "deny" not in efts
    if effect == EFFECT_ALLOW_AND_DENY:
        return "allow" in efts and "deny" not in efts
    if effect == EFFECT_PRIORITY:
        if not efts:
            return False
        return efts[0] == "allow"
    raise PermError("unsupported effect %r" % (effect,))


def _validate_request(request, req_schema):
    if not isinstance(request, dict):
        raise PermError("request must be a mapping")
    if set(request) != set(req_schema):
        raise PermError(
            "request must carry exactly the request_schema columns "
            "%s (got %s)" % (sorted(req_schema),
                             sorted(str(k) for k in request)))
    for col, typ in req_schema.items():
        value = request[col]
        if typ == "str":
            if not isinstance(value, str):
                raise PermError(
                    "request column %r must be a string" % (col,))
        elif typ == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise PermError(
                    "request column %r must be an int" % (col,))
        elif typ == "bool":
            if not isinstance(value, bool):
                raise PermError(
                    "request column %r must be a bool" % (col,))
    return dict(request)

class PermModel(object):
    """A compiled, signed PERM model + policy, ready to decide.

    Only built by :func:`compile_perm_model` /
    :func:`load_perm_from_active_pack` -- the constructor is not a
    trust boundary.
    """

    def __init__(self, model, policies, *, model_digest,
                 policy_digest):
        self._model = model
        self._policies = policies
        self._model_digest = model_digest
        self._policy_digest = policy_digest
        self._composition_digest = hashlib.sha256(
            json.dumps(model["composition"], sort_keys=True,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._function_set_digest = function_set_digest()
        self._screens = {s["name"]: s for s in model["screens"]}

    @property
    def model_digest(self):
        """sha256 hex over the exact model-document bytes."""
        return self._model_digest

    @property
    def policy_digest(self):
        """sha256 hex over the exact policy-document bytes."""
        return self._policy_digest

    @property
    def composition_digest(self):
        """sha256 over the canonical composition (screen order +
        verdict mapping)."""
        return self._composition_digest

    @property
    def function_set_digest(self):
        """Digest of the matcher function set this model ran under."""
        return self._function_set_digest

    @property
    def screen_names(self):
        return [s["name"] for s in self._model["screens"]]

    def bom_perm_section(self):
        """The ``inputs.perm`` section for the Decision BOM
        (all-or-none with the other digests)."""
        return {
            "model_digest": self._model_digest,
            "policy_digest": self._policy_digest,
            "composition_digest": self._composition_digest,
            "function_set_digest": self._function_set_digest,
        }

    def policy_row(self, screen_name, index):
        """The policy row dict at ``index`` of ``screen_name``'s policy
        list (indices stable within one pinned policy digest). Public
        accessor for diagnostics consumers -- the row dict is a copy,
        so callers cannot mutate the loaded pack."""
        try:
            rows = self._policies[screen_name]
        except KeyError:
            raise PermError("unknown screen %r" % (screen_name,))
        try:
            return copy.deepcopy(rows[index])
        except (IndexError, TypeError):
            raise PermError(
                "screen %r has no policy row %r" % (screen_name, index))

    def decide(self, request):
        """Render a verdict for one request.

        Returns ``(verdict, screen, detail)`` where verdict is one of
        ``deny`` / ``require_approval`` / ``allow``, screen is the
        deciding screen name (or ``"default"``), and detail carries
        ``matched_rows``. Fail-closed: a malformed request raises
        PermError -- decide NEVER returns allow on bad input.
        """
        verdict, screen, trace = self.decide_traced(request)
        if screen == "default":
            return (verdict, screen, {"matched_rows": 0})
        # decide_traced guarantees a deciding entry when screen !=
        # "default"; the None-default keeps the failure in-taxonomy
        # (PermError) instead of leaking StopIteration.
        deciding = next((t for t in trace if t["decided"]), None)
        if deciding is None:
            raise PermError(
                "decide_traced returned no deciding entry for a "
                "screen-fired verdict")
        return (verdict, screen, {"matched_rows": len(deciding["matched"])})

    def decide_traced(self, request):
        """Render a verdict with the full per-screen trace.

        Returns ``(verdict, screen, trace)``. ``trace`` has one entry
        per composition-order screen evaluated, in order::

            {"screen": name, "verdict": entry_verdict,
             "effect": effect_expression, "invert": bool,
             "matched": [{"index": row_index, "effect": row_eft}, ...],
             "effect_value": bool, "decided": bool}

        ``matched`` carries row indices into the screen's policy list
        (stable within one pinned policy digest) plus each row's
        ``eft``. The deciding entry has ``decided=True``; entries
        after it are absent. When no screen fires, screen is
        ``"default"`` and the trace covers every screen with
        ``decided=False``. Powers the decision+diagnostics contract
        (:mod:`gov.decision_diagnostics`): which rows determined the
        decision is traceable, never inferred.
        """
        req = _validate_request(request, self._model["request_schema"])
        composition = self._model["composition"]
        trace = []
        for entry in composition["order"]:
            screen = self._screens[entry["screen"]]
            matched = [
                {"index": i, "effect": row["eft"]}
                for i, row in enumerate(self._policies[screen["name"]])
                if _eval_matcher(screen["matcher"], req, row)]
            effect_value = _apply_effect(
                screen["effect"],
                [self._policies[screen["name"]][m["index"]]
                 for m in matched])
            decided = (effect_value != entry["invert"])
            trace.append({
                "screen": screen["name"],
                "verdict": entry["verdict"],
                "effect": screen["effect"],
                "invert": entry["invert"],
                "matched": matched,
                "effect_value": effect_value,
                "decided": decided,
            })
            if decided:
                return (entry["verdict"], screen["name"], trace)
        return (composition["default_verdict"], "default", trace)


def compile_perm_model(model_data, policy_data):
    """Strict-parse and compile a model + policy document pair.

    ``model_data`` / ``policy_data``: bytes or str of the YAML
    documents. Returns a :class:`PermModel`. Raises PermError loud
    on any malformed input -- an unsigned or malformed model never
    becomes a decider.
    """
    if isinstance(model_data, (bytearray, memoryview)):
        model_data = bytes(model_data)
    if isinstance(policy_data, (bytearray, memoryview)):
        policy_data = bytes(policy_data)
    model = parse_perm_model(model_data)
    policies = parse_perm_policy(policy_data, model)
    model_bytes = (model_data.encode("utf-8") if isinstance(
        model_data, str) else bytes(model_data))
    policy_bytes = (policy_data.encode("utf-8") if isinstance(
        policy_data, str) else bytes(policy_data))
    return PermModel(
        model, policies,
        model_digest=hashlib.sha256(model_bytes).hexdigest(),
        policy_digest=hashlib.sha256(policy_bytes).hexdigest())


def load_perm_from_active_pack(active):
    """Compile a PermModel from an activated PERM pack.

    ``active``: :class:`ActivePack` from a :class:`PackLoader`
    bound to the PERM trust domain. The pack must enumerate EXACTLY
    ``perm-model.yml`` + ``perm-policy.yml`` -- anything else is
    refused (the pack signature already binds the member set; this
    is the type check that the pack is a model pack, not merely a
    signed one).
    """
    if not isinstance(active, ActivePack):
        raise PermError("active must be an ActivePack")
    if (active.purpose != _rp.KEYSET_PURPOSE_PERM_PACK
            or active.format_tag != _rp.PERM_PACK_FORMAT):
        raise PermError(
            "PERM pack must come from the PERM trust domain "
            "(purpose %r, format %r); got purpose %r, format %r -- "
            "a detection-rule pack is never a model pack"
            % (_rp.KEYSET_PURPOSE_PERM_PACK, _rp.PERM_PACK_FORMAT,
               active.purpose, active.format_tag))
    if set(active.members) != {PERM_MODEL_MEMBER, PERM_POLICY_MEMBER}:
        raise PermError(
            "PERM pack must enumerate exactly %s + %s, got %s"
            % (PERM_MODEL_MEMBER, PERM_POLICY_MEMBER,
               sorted(active.members)))
    return compile_perm_model(active.member(PERM_MODEL_MEMBER),
                              active.member(PERM_POLICY_MEMBER))


def mint_perm_pack(keyset, signers, *, model_bytes, policy_bytes,
                   pack_version, issued_at, expires_at, threshold):
    """Mint a signed PERM model pack (operator-side).

    Members are exactly ``perm-model.yml`` + ``perm-policy.yml``.
    The pack is minted in the PERM trust domain
    (``KEYSET_PURPOSE_PERM_PACK`` / ``PERM_PACK_FORMAT``) -- a
    detection-rule keyset cannot mint it. Pin-tier treatment is
    ENFORCED: ``threshold >= 2`` (two distinct humans) is required;
    a threshold of 1 raises PermError rather than minting a
    single-human model pack.
    """
    if not isinstance(threshold, int) or threshold < 2:
        raise PermError(
            "PERM model packs require threshold >= 2 (two-human "
            "pin tier); got %r" % (threshold,))
    if isinstance(model_bytes, str):
        model_bytes = model_bytes.encode("utf-8")
    if isinstance(policy_bytes, str):
        policy_bytes = policy_bytes.encode("utf-8")
    rules = {
        PERM_MODEL_MEMBER: "sha256:" + hashlib.sha256(
            bytes(model_bytes)).hexdigest(),
        PERM_POLICY_MEMBER: "sha256:" + hashlib.sha256(
            bytes(policy_bytes)).hexdigest(),
    }
    return _rp.mint_rule_pack(
        keyset, signers, rules=rules, pack_version=pack_version,
        issued_at=issued_at, expires_at=expires_at, threshold=threshold,
        purpose=_rp.KEYSET_PURPOSE_PERM_PACK,
        format_tag=_rp.PERM_PACK_FORMAT)


def new_perm_pack_loader(keyset, pack_id="perm_model"):
    """A :class:`PackLoader` bound to the PERM trust domain."""
    return PackLoader(keyset, pack_id,
                      purpose=_rp.KEYSET_PURPOSE_PERM_PACK,
                      format_tag=_rp.PERM_PACK_FORMAT)
