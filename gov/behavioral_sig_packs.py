"""Behavioral-signature v2: Falco-format signature packs + stateful correlator.

Wave-267. ADAPT of the Falco rule discipline (wave-266 prospectus):
schema-validated signature packs as DATA (rule/macro/list), author-shaped
exception tuples, maturity graduation, append/override tuning that can
never edit a pack in place, enrichment-before-match, evidence-on-fire --
and, per Falco's key architectural lesson, a STATEFUL CORRELATOR *above*
the stateless predicates for burst / ratio / cross-session shapes (the
condition language is deliberately non-temporal; growing it into temporal
logic is an anti-pattern).

This module complements, not replaces, ``gov/behavioral_sigs.py``
(wave-175 hardcoded tables). Packs are deployment-authored data;
``behavioral_sigs.py`` remains the built-in hardcoded layer.

Trust model (cosign lesson: trust material required up front, fail
closed):

* ``load_pack`` requires non-empty ``trust_keys`` (``keyid -> ed25519
  pubkey bytes``) and at least one valid signature over the canonical
  pack bytes. Tampered, unsigned, or trustless loads refuse with
  ``behsig-pack-untrusted``. There is no unsigned path and no
  development escape hatch: unsigned packs are never loadable.
* Every pack pins the engine version it was written against
  (``engine_version``); a pack written for a different engine is
  refused with ``behsig-pack-malformed`` rather than evaluated
  against semantics it was not authored for.
* Schema violations refuse loudly with ``behsig-pack-malformed``.
  Unknown comparators, duplicate names, and bad shapes are pack-level
  refusals -- never silent passes.
* A rule referencing an enrichment field the engine does not know is
  DISABLED with a loud ``behsig-rule-disabled`` journal record; the
  rest of the pack still loads (skip-if-unknown analog). Unknown fields
  never silently pass and never silently drop a pack.

Tuning discipline (Falco append/override):

* Packs are immutable shipped artifacts. Deployments tune via a
  separate tuning document consumed by ``apply_tuning``.
* Tuning may ADD exception tuples, but only in shapes the rule author
  declared (the author defines which field/comparator tuples are
  exceptable; the deployment supplies values for those slots). A
  tuned-in exception on an unknown enrichment field -- or in a shape
  the author did not declare -- refuses with
  ``behsig-tuning-rejected``: exception fields are checked at tuning
  time exactly as at load time, so tuning can never silently suppress
  a rule.
* Tuning may move ``min_*`` params UP / ``max_*`` params DOWN (toward
  safety). Moving a ``min_*`` param below the author's floor, a
  ``max_*`` above the author's ceiling, tuning an unknown rule, or
  disabling a ``stable`` rule without a written justification refuses
  with ``behsig-tuning-rejected``.
* Applied tuning is journaled loudly as ``behsig-tuning-applied``.

Matching and evidence:

* ``enrich_event`` builds the closed agent-shape schema before any
  rule runs; ``match_pack`` refuses raw events loudly. Argument
  classification (``arg.class``) is a documented heuristic over key
  names and a small set of credential-word value markers.
* Evidence-on-fire (``PackAlert.capture``) is a TRAILING (pre-fire)
  window: at fire time the post-fire events have not happened yet.
  Post-fire context accrues in the correlator's per-actor event
  store; advisory digests cover the surrounding window on both sides.

Correlator doctrine (F248 doctrine: journaled advisory holds, never
silent denials):

* ``StatefulCorrelator`` consumes enriched events plus the pack's
  rule-fire records and maintains per-actor sliding windows: burst
  (raw event volume), fire-storm (rule-fire volume), slow-drip
  (distinct sessions sharing one identity key over a long window --
  exact key match, and the correlation it implies is explicitly
  approximate: shared keys can collide and actors can rotate keys),
  and ratio (export-class share of windowed events -- defeats benign
  padding).
* Correlator output is ADVISORY ONLY: a journaled
  ``behsig-correlator-advisory`` record (argument digests, never raw
  arguments) plus, when the deployment supplies a ``queue`` callable,
  a hold REQUEST the deployment's human-approval queue consumes. The
  request carries ``decision: "hold-request"`` -- it is never a denial
  and ``observe()`` never raises to block execution.

Stdlib only. Deterministic: no wall-clock reads inside matching (event
``ts`` values drive windows); dict iteration is insertion-ordered.
"""

import hashlib
import json
from collections import deque

from gov import ed25519

PACK_FORMAT = "sasanam.behavioral-sig-pack/v1"

# Engine version packs are written against. A pack pins the engine
# version it was authored for (``engine_version``); this engine
# refuses packs written for a different engine rather than evaluate
# them against semantics they were not authored for.
ENGINE_VERSION = "1"

_MATURITY_ORDER = {"sandbox": 0, "incubating": 1, "stable": 2}
_PRIORITIES = ("low", "medium", "high", "critical")
_COMPARATORS = ("eq", "ne", "gt", "gte", "lt", "lte", "in", "nin",
                "contains", "startswith")

# Enrichment schema: the closed set of fields a rule may reference.
# Enrichment-before-match -- rules NEVER see raw event text.
ENRICHED_FIELDS = frozenset({
    "ts",
    "actor_id",
    "principal",
    "session_id",
    "tool.name",
    "tool.action",
    "tool.target",
    "arg.class",
    "arg.digest",
    "raw.digest",
})

_CREDENTIAL_ARG_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "credentials", "auth_token",
})
_EXPORT_ACTIONS = frozenset({"db.dump", "file.export"})
_ARG_CLASSES = ("credential", "export", "network", "file_write",
                "benign")


class PackRefused(Exception):
    """Loud, machine-coded pack refusal."""

    def __init__(self, code, human):
        super().__init__("%s: %s" % (code, human))
        self.code = code
        self.human = human


def _refuse(code, human):
    raise PackRefused(code, human)


def _canon(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _digest_of(obj):
    return hashlib.sha256(_canon(obj)).hexdigest()


def _journal_to(journal, record):
    if journal is None:
        return record
    journal(record)
    return record


def _is_scalar(v):
    return v is None or isinstance(v, (str, int, float, bool))


# ------------------------------------------------------------------
# Schema validation (strict; loud).
# ------------------------------------------------------------------

def _need(cond, msg):
    if not cond:
        _refuse("behsig-pack-malformed", msg)


def _check_condition_shape(cond, where, macros_known, lists_known,
                           macro_field_sets=None):
    """Validate a condition tree shape. Raises PackRefused.

    Returns the set of enrichment fields the condition reads.
    ``macro_field_sets`` maps already-resolved macro names to their
    field sets (macro bodies are resolved before rules).
    """
    _need(isinstance(cond, dict), "%s: condition must be an object" % where)
    if "macro" in cond:
        _need(set(cond.keys()) == {"macro"},
              "%s: macro ref takes only 'macro'" % where)
        _need(isinstance(cond["macro"], str) and cond["macro"],
              "%s: macro name must be a non-empty string" % where)
        _need(cond["macro"] in macros_known,
              "%s: unknown macro %r" % (where, cond["macro"]))
        if macro_field_sets is None:
            return set()
        return set(macro_field_sets.get(cond["macro"], ()))
    op = cond.get("op")
    _need(op in _COMPARATORS + ("and", "or", "not", "in-list"),
          "%s: unknown comparator %r" % (where, op))
    if op in ("and", "or"):
        args = cond.get("args")
        _need(isinstance(args, list) and len(args) >= 1,
              "%s: '%s' needs a non-empty args list" % (where, op))
        fields = set()
        for i, sub in enumerate(args):
            fields |= _check_condition_shape(
                sub, "%s.%s[%d]" % (where, op, i), macros_known,
                lists_known, macro_field_sets)
        return fields
    if op == "not":
        _need("arg" in cond and isinstance(cond["arg"], dict),
              "%s: 'not' needs an 'arg' condition" % where)
        return _check_condition_shape(cond["arg"], where + ".not",
                                      macros_known, lists_known,
                                      macro_field_sets)
    # Leaf comparator.
    field = cond.get("field")
    _need(isinstance(field, str) and field,
          "%s: leaf comparator needs a string 'field'" % where)
    if op == "in-list":
        _need(cond.get("list") in lists_known,
              "%s: unknown list %r" % (where, cond.get("list")))
    elif op in ("in", "nin"):
        vals = cond.get("values")
        _need(isinstance(vals, list) and vals
              and all(_is_scalar(v) for v in vals),
              "%s: '%s' needs a non-empty scalar 'values' list"
              % (where, op))
    else:
        _need("value" in cond and _is_scalar(cond["value"]),
              "%s: '%s' needs a scalar 'value'" % (where, op))
    return {field}


def _check_exception_triple(triple, where):
    _need(isinstance(triple, dict),
          "%s: exception triple must be an object" % where)
    _need(set(triple.keys()) == {"field", "comparator", "value"},
          "%s: exception triple takes exactly "
          "field/comparator/value" % where)
    _need(isinstance(triple["field"], str) and triple["field"],
          "%s: exception field must be a non-empty string" % where)
    _need(triple["comparator"] in _COMPARATORS,
          "%s: unknown exception comparator %r"
          % (where, triple["comparator"]))
    _need(_is_scalar(triple["value"]),
          "%s: exception value must be scalar" % where)
    return triple["field"], triple["comparator"]


def _check_exception_shape(exc, where):
    """Validate one exception TUPLE.

    An exception is ``{"and": [triple, ...]}``: one or more
    (field, comparator, value) triples that must ALL hold for the
    tuple to except the event. The rule's exception list is OR'd
    across tuples. Returns (fields, shapes): the field set plus the
    set of (field, comparator) pairs the author declared -- tuning
    may only add tuples in author-declared shapes.
    """
    _need(isinstance(exc, dict), "%s: exception must be an object" % where)
    _need(set(exc.keys()) == {"and"},
          "%s: exception takes exactly 'and' (a tuple of "
          "field/comparator/value triples)" % where)
    triples = exc["and"]
    _need(isinstance(triples, list) and len(triples) >= 1,
          "%s: exception 'and' needs a non-empty triple list"
          % where)
    fields = set()
    shapes = set()
    for i, triple in enumerate(triples):
        field, comparator = _check_exception_triple(
            triple, "%s.and[%d]" % (where, i))
        fields.add(field)
        shapes.add((field, comparator))
    return fields, shapes


def _validate_pack(pack):
    """Validate pack schema. Returns (macros, lists, rules)."""
    _need(isinstance(pack, dict), "pack must be a JSON object")
    _need(pack.get("pack_format") == PACK_FORMAT,
          "pack_format must be %r" % PACK_FORMAT)
    _need(isinstance(pack.get("pack_id"), str) and pack["pack_id"],
          "pack_id must be a non-empty string")
    _need(isinstance(pack.get("pack_version"), str)
          and pack["pack_version"],
          "pack_version must be a non-empty string")
    _need(pack.get("engine_version") == ENGINE_VERSION,
          "pack engine_version %r is not supported by this engine "
          "(%r): packs are evaluated only against the engine "
          "semantics they were written for"
          % (pack.get("engine_version"), ENGINE_VERSION))

    macros = {}
    for i, m in enumerate(pack.get("macros", [])):
        where = "macros[%d]" % i
        _need(isinstance(m, dict), "%s: macro must be an object" % where)
        name = m.get("name")
        _need(isinstance(name, str) and name,
              "%s: macro name must be a non-empty string" % where)
        _need(name not in macros,
              "%s: duplicate macro name %r" % (where, name))
        _need(isinstance(m.get("def"), dict),
              "%s: macro needs a 'def' condition" % where)
        macros[name] = m["def"]
    # Macros may reference macros defined later; validate after all
    # names are known. Cycles (including self-reference) are refused:
    # they can never resolve.
    def _macro_refs(cond):
        refs = set()
        if not isinstance(cond, dict):
            return refs
        if set(cond.keys()) == {"macro"}:
            refs.add(cond["macro"])
            return refs
        op = cond.get("op")
        if op in ("and", "or"):
            for sub in cond.get("args", []):
                refs |= _macro_refs(sub)
        elif op == "not":
            refs |= _macro_refs(cond.get("arg", {}))
        return refs

    ref_graph = {name: _macro_refs(defi)
                 for name, defi in macros.items()}

    def _has_cycle(node, stack):
        if node in stack:
            return True
        stack = stack | {node}
        return any(_has_cycle(dep, stack)
                   for dep in ref_graph.get(node, ()))

    for name in macros:
        _need(not _has_cycle(name, frozenset()),
              "macros.%s: macro reference cycle refused" % name)

    # Resolve macro field sets before rules (cycles excluded above,
    # so this recursion terminates).
    macro_field_sets = {}

    def _fields_of_macro(mname):
        if mname in macro_field_sets:
            return macro_field_sets[mname]
        macro_field_sets[mname] = set()
        fields = _check_condition_shape(
            macros[mname], "macros.%s" % mname, set(macros), set(),
            macro_field_sets)
        macro_field_sets[mname] = fields
        return fields

    for mname in macros:
        _fields_of_macro(mname)

    lists = {}
    for i, li in enumerate(pack.get("lists", [])):
        where = "lists[%d]" % i
        _need(isinstance(li, dict), "%s: list must be an object" % where)
        name = li.get("name")
        _need(isinstance(name, str) and name,
              "%s: list name must be a non-empty string" % where)
        _need(name not in lists,
              "%s: duplicate list name %r" % (where, name))
        vals = li.get("values")
        _need(isinstance(vals, list)
              and all(_is_scalar(v) for v in vals),
              "%s: list values must be a scalar list" % where)
        lists[name] = list(vals)

    rules = pack.get("rules")
    _need(isinstance(rules, list) and rules,
          "rules must be a non-empty list")
    seen = set()
    out = []
    for i, r in enumerate(rules):
        where = "rules[%d]" % i
        _need(isinstance(r, dict), "%s: rule must be an object" % where)
        name = r.get("name")
        _need(isinstance(name, str) and name,
              "%s: rule name must be a non-empty string" % where)
        _need(name not in seen,
              "%s: duplicate rule name %r" % (where, name))
        seen.add(name)
        _need(isinstance(r.get("desc"), str),
              "%s: rule needs a string desc" % where)
        _need(isinstance(r.get("condition"), dict),
              "%s: rule needs a condition object" % where)
        fields = _check_condition_shape(
            r["condition"], "%s.condition" % name, set(macros),
            set(lists), macro_field_sets)
        _need(isinstance(r.get("output"), str) and r["output"],
              "%s: rule needs a non-empty output template" % where)
        _need(r.get("priority") in _PRIORITIES,
              "%s: priority must be one of %r"
              % (where, _PRIORITIES))
        _need(isinstance(r.get("enabled"), bool),
              "%s: enabled must be boolean" % where)
        _need(isinstance(r.get("source"), str),
              "%s: source must be a string" % where)
        _need(isinstance(r.get("tags"), list)
              and all(isinstance(t, str) for t in r["tags"]),
              "%s: tags must be a string list" % where)
        _need(r.get("maturity") in _MATURITY_ORDER,
              "%s: maturity must be one of %r"
              % (where, sorted(_MATURITY_ORDER)))
        exc_fields = set()
        exc_shapes = set()
        for j, exc in enumerate(r.get("exceptions", [])):
            fields_j, shapes_j = _check_exception_shape(
                exc, "%s.exceptions[%d]" % (name, j))
            exc_fields |= fields_j
            exc_shapes |= shapes_j
        cap = r.get("capture", {})
        _need(isinstance(cap, dict),
              "%s: capture must be an object" % where)
        _need(isinstance(cap.get("window_events", 0), int)
              and cap.get("window_events", 0) >= 0,
              "%s: capture.window_events must be a non-negative int"
              % where)
        params = r.get("params", {})
        _need(isinstance(params, dict)
              and all(_is_scalar(v) for v in params.values()),
              "%s: params must be a scalar-valued object" % where)
        out.append({
            "name": name,
            "desc": r["desc"],
            "condition": r["condition"],
            "fields": fields | exc_fields,
            "output": r["output"],
            "priority": r["priority"],
            "enabled": r["enabled"],
            "source": r["source"],
            "tags": list(r["tags"]),
            "maturity": r["maturity"],
            "exceptions": list(r.get("exceptions", [])),
            "exception_shapes": sorted(exc_shapes),
            "capture_window": cap.get("window_events", 0),
            "params": dict(params),
        })
    return macros, lists, out


# ------------------------------------------------------------------
# Pack loading: signature first, schema second, maturity last.
# ------------------------------------------------------------------

def _verify_signatures(doc, trust_keys):
    """Verify the signed envelope. Refuses behsig-pack-untrusted."""
    _need(isinstance(doc, dict), "pack envelope must be a JSON object")
    pack = doc.get("pack")
    _need(isinstance(pack, dict), "pack envelope needs a 'pack' object")
    sigs = doc.get("signatures")
    _need(isinstance(sigs, list),
          "pack envelope needs a 'signatures' list")
    if not trust_keys:
        _refuse("behsig-pack-untrusted",
                "no trust material configured: refusing pack "
                "fail-closed")
    canonical = _canon(pack)
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        keyid = entry.get("keyid")
        sig_hex = entry.get("sig")
        pub = trust_keys.get(keyid)
        if pub is None or not isinstance(sig_hex, str):
            continue
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            continue
        try:
            if ed25519.verify(pub, canonical, sig) is True:
                return pack
        except Exception:
            continue
    _refuse("behsig-pack-untrusted",
            "no valid signature from the configured trust material")


class CompiledRule(object):
    def __init__(self, spec):
        self.name = spec["name"]
        self.desc = spec["desc"]
        self.condition = spec["condition"]
        self.output = spec["output"]
        self.priority = spec["priority"]
        self.enabled = spec["enabled"]
        self.source = spec["source"]
        self.tags = tuple(spec["tags"])
        self.maturity = spec["maturity"]
        self.exceptions = list(spec["exceptions"])
        # Author-declared (field, comparator) shapes, as sorted
        # [field, comparator] pairs. Tuning may only add exception
        # tuples in these shapes; the deployment supplies values.
        self.exception_shapes = {
            (f, c) for f, c in spec.get("exception_shapes", [])}
        self.capture_window = spec["capture_window"]
        self.params = dict(spec["params"])


class LoadedPack(object):
    def __init__(self, pack_id, pack_version, rules, macros, lists,
                 disabled_rules, filtered_by_maturity, journal_records):
        self.pack_id = pack_id
        self.pack_version = pack_version
        self.rules = rules  # name -> CompiledRule
        self.macros = macros
        self.lists = lists
        self.disabled_rules = disabled_rules  # [(name, reason)]
        self.filtered_by_maturity = filtered_by_maturity
        self.journal_records = journal_records


def load_pack(pack_bytes, trust_keys, journal=None,
              min_maturity="sandbox"):
    """Load and verify a signed signature pack.

    Returns a ``LoadedPack``. Refuses loudly (``PackRefused``) on
    schema violations (``behsig-pack-malformed``) or trust failures
    (``behsig-pack-untrusted``). There is no unsigned path: trust
    material is required up front and packs are refused fail-closed
    without a valid signature. Rules referencing unknown enrichment
    fields are disabled with a loud ``behsig-rule-disabled`` journal
    record; the rest of the pack still loads.
    """
    _need(min_maturity in _MATURITY_ORDER,
          "min_maturity must be one of %r"
          % (sorted(_MATURITY_ORDER),))
    try:
        doc = json.loads(pack_bytes.decode("utf-8"))
    except Exception:
        _refuse("behsig-pack-malformed",
                "pack envelope is not valid UTF-8 JSON")
    records = []

    def _jr(rec):
        records.append(rec)
        if journal is not None:
            journal(rec)

    pack = _verify_signatures(doc, trust_keys or {})

    macros, lists, rule_specs = _validate_pack(pack)

    floor = _MATURITY_ORDER[min_maturity]
    rules = {}
    disabled = []
    filtered = []
    for spec in rule_specs:
        if not spec["enabled"]:
            disabled.append((spec["name"], "rule disabled in pack"))
            _jr({"code": "behsig-rule-disabled",
                 "rule": spec["name"],
                 "detail": "rule disabled in pack"})
            continue
        if _MATURITY_ORDER[spec["maturity"]] < floor:
            filtered.append(spec["name"])
            continue
        unknown = sorted(f for f in spec["fields"]
                         if f not in ENRICHED_FIELDS)
        if unknown:
            disabled.append(
                (spec["name"],
                 "unknown enrichment fields: %s" % ",".join(unknown)))
            _jr({"code": "behsig-rule-disabled",
                 "rule": spec["name"],
                 "detail": "unknown enrichment fields: %s; rule "
                           "disabled, pack continues"
                           % ",".join(unknown)})
            continue
        rules[spec["name"]] = CompiledRule(spec)
    return LoadedPack(pack_id=pack["pack_id"],
                      pack_version=pack["pack_version"],
                      rules=rules, macros=macros, lists=lists,
                      disabled_rules=disabled,
                      filtered_by_maturity=filtered,
                      journal_records=records)


# ------------------------------------------------------------------
# Enrichment: raw events -> closed agent-shape fields.
# Rules NEVER see raw text.
# ------------------------------------------------------------------

def _classify_args(tool_action, args):
    if not isinstance(args, dict):
        return "benign"
    keys = {str(k).lower() for k in args.keys()}
    if keys & _CREDENTIAL_ARG_KEYS:
        return "credential"
    for v in args.values():
        if isinstance(v, str):
            low = v.lower()
            if "password" in low or "secret" in low or "token" in low:
                return "credential"
    if tool_action in _EXPORT_ACTIONS:
        return "export"
    if tool_action.startswith("net.") or "egress" in tool_action:
        return "network"
    if "write" in tool_action:
        return "file_write"
    return "benign"


def enrich_event(raw):
    """Enrich one raw event into the closed agent-shape schema.

    Strict: malformed input raises ``ValueError`` loudly -- it is a
    caller bug, never silently normalized.
    """
    if not isinstance(raw, dict):
        raise ValueError("enrich_event: event must be a mapping")
    try:
        ts = float(raw["ts"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("enrich_event: event needs a numeric 'ts'")
    tool = raw.get("tool", "")
    if not isinstance(tool, str) or not tool:
        raise ValueError("enrich_event: event needs a string 'tool'")
    action = tool.strip().lower()
    target = raw.get("target", "")
    if not isinstance(target, str):
        raise ValueError("enrich_event: 'target' must be a string")
    args = raw.get("args", {})
    actor = str(raw.get("actor_id", ""))
    principal = str(raw.get("principal", actor))
    session = str(raw.get("session_id", ""))
    enriched = {
        "_enriched": True,
        "ts": ts,
        "actor_id": actor,
        "principal": principal,
        "session_id": session,
        "tool.name": action,
        "tool.action": action,
        "tool.target": target,
        "arg.class": _classify_args(action, args),
        "arg.digest": _digest_of(args if isinstance(args, dict)
                                 else {}),
        "raw.digest": _digest_of(raw),
    }
    return enriched


def _resolve_field(enriched, field):
    return enriched.get(field)


def _compare(comparator, actual, expected):
    if comparator == "eq":
        return actual == expected
    if comparator == "ne":
        return actual != expected
    if comparator in ("gt", "gte", "lt", "lte"):
        if not isinstance(actual, (int, float)) or not isinstance(
                expected, (int, float)):
            return False
        if comparator == "gt":
            return actual > expected
        if comparator == "gte":
            return actual >= expected
        if comparator == "lt":
            return actual < expected
        return actual <= expected
    if comparator == "in":
        return actual in expected
    if comparator == "nin":
        return actual not in expected
    if comparator == "contains":
        return (isinstance(actual, str)
                and isinstance(expected, str)
                and expected in actual)
    if comparator == "startswith":
        return (isinstance(actual, str)
                and isinstance(expected, str)
                and actual.startswith(expected))
    return False  # unreachable: schema-closed


def _eval_cond(cond, enriched, macros, lists, _depth=0):
    if _depth > 32:
        raise ValueError("condition nesting too deep")
    if set(cond.keys()) == {"macro"}:
        return _eval_cond(macros[cond["macro"]], enriched, macros,
                          lists, _depth + 1)
    op = cond["op"]
    if op == "and":
        return all(_eval_cond(c, enriched, macros, lists, _depth + 1)
                   for c in cond["args"])
    if op == "or":
        return any(_eval_cond(c, enriched, macros, lists, _depth + 1)
                   for c in cond["args"])
    if op == "not":
        return not _eval_cond(cond["arg"], enriched, macros, lists,
                              _depth + 1)
    actual = _resolve_field(enriched, cond["field"])
    if op == "in-list":
        return actual in lists[cond["list"]]
    if op in ("in", "nin"):
        return _compare(op, actual, cond["values"])
    return _compare(op, actual, cond["value"])


def _exception_hits(exc, enriched):
    # One exception TUPLE: every triple must hold (AND). The rule's
    # exception list is OR'd across tuples at the call site.
    for triple in exc["and"]:
        if not _compare(triple["comparator"],
                        _resolve_field(enriched, triple["field"]),
                        triple["value"]):
            return False
    return True


def _render_output(template, enriched):
    out = template
    for field in ENRICHED_FIELDS:
        token = "%" + field + "%"
        if token in out:
            out = out.replace(token, str(enriched.get(field, "")))
    return out


def _summarize(enriched):
    return {"digest": enriched["raw.digest"],
            "ts": enriched["ts"],
            "actor_id": enriched["actor_id"],
            "tool.action": enriched["tool.action"],
            "tool.target": enriched["tool.target"],
            "arg.class": enriched["arg.class"]}


class PackAlert(object):
    def __init__(self, rule_name, priority, maturity, output,
                 event_digest, capture, pack_id):
        self.rule_name = rule_name
        self.priority = priority
        self.maturity = maturity
        self.output = output
        self.event_digest = event_digest
        self.capture = capture  # evidence-on-fire window
        self.pack_id = pack_id


def _behsig_exception_context(ev):
    """Map an enriched event to the (principal, action, resource) context
    the canonical policy-exception engine evaluates. Advisory mapping:
    only the closed enriched fields are exposed, never raw text."""
    return {
        "principal": {"id": ev.get("actor_id", "")},
        "action": ev.get("tool.action", ""),
        "resource": {
            "target": ev.get("tool.target", ""),
            "class": ev.get("arg.class", ""),
        },
    }


def match_pack(pack, enriched_events, journal=None, policy_exceptions=None,
               eval_start=None):
    """Match enriched events against a loaded pack.

    ``enriched_events`` must be ``enrich_event`` outputs (marked
    ``_enriched``); raw events refuse loudly via ``ValueError`` --
    the matcher never sees raw text. Returns ``[PackAlert]`` in event
    order. Matching is advisory: it reports, never blocks.

    ``policy_exceptions`` (optional): loaded ``PolicyException``
    objects from ``gov.policy_exception`` (the canonical exception
    type). When given, a rule hit that a canonical exception covers is
    converted to a LOUD skip -- journaled with
    ``exception-rule-skipped`` and the exception identities -- instead
    of emitting an alert. This is the governed, expiring, attributed
    way to suppress behsig rules; ``policyName`` must equal the pack's
    ``pack_id``. ``eval_start`` (pinned time) is required when
    ``policy_exceptions`` is given: exception expiry never reads the
    wall clock.
    """
    alerts = []
    if policy_exceptions is not None and eval_start is None:
        raise ValueError(
            "match_pack: eval_start is required when policy_exceptions "
            "is given (exception expiry is pinned-time only)")
    events = list(enriched_events)
    for ev in events:
        if not (isinstance(ev, dict) and ev.get("_enriched") is True):
            raise ValueError(
                "match_pack: events must be enrich_event() outputs; "
                "raw events are never matched")
    for i, ev in enumerate(events):
        for rule in pack.rules.values():
            try:
                hit = _eval_cond(rule.condition, ev, pack.macros,
                                 pack.lists)
            except Exception:
                # A condition that errors on a well-formed enriched
                # event is a pack bug: fail closed on THIS rule for
                # THIS event (loud), never a silent pass of the rule.
                # The rule stays loaded; this is a transient skip,
                # not a disable (behsig-rule-disabled is the
                # load-time unknown-field disable).
                _journal_to(journal, {
                    "code": "behsig-rule-eval-failed",
                    "rule": rule.name,
                    "detail": "condition errored on an enriched "
                              "event; treated as no-match for this "
                              "event only"})
                continue
            if not hit:
                continue
            if any(_exception_hits(x, ev) for x in rule.exceptions):
                continue
            if policy_exceptions is not None:
                # Canonical governed exception: loud skip with the
                # exception identities attached, never a silent
                # suppression. Lazy import: behavioral_sig_packs must
                # stay importable without the exception module.
                from .policy_exception import apply as _pe_apply
                decision = _pe_apply(
                    pack.pack_id, rule.name,
                    _behsig_exception_context(ev), eval_start,
                    policy_exceptions)
                if decision.kind == "skip":
                    _journal_to(journal, {
                        "code": "exception-rule-skipped",
                        "rule": rule.name,
                        "policy": pack.pack_id,
                        "exception_ids": decision.exception_ids,
                        "event_digest": ev["raw.digest"]})
                    continue
            w = rule.capture_window
            capture = [_summarize(e)
                       for e in events[max(0, i - w):i + 1]]
            alerts.append(PackAlert(
                rule_name=rule.name, priority=rule.priority,
                maturity=rule.maturity,
                output=_render_output(rule.output, ev),
                event_digest=ev["raw.digest"], capture=capture,
                pack_id=pack.pack_id))
    return alerts


# ------------------------------------------------------------------
# Tuning: append/override discipline. Packs are never edited in place.
# ------------------------------------------------------------------

def _check_tuning_shape(tuning, pack):
    _need(isinstance(tuning, dict), "tuning must be a JSON object")
    _need(tuning.get("pack_id") == pack.pack_id,
          "tuning pack_id %r does not match pack %r"
          % (tuning.get("pack_id"), pack.pack_id))
    rt = tuning.get("rule_tuning", {})
    _need(isinstance(rt, dict), "tuning rule_tuning must be an object")
    for name, spec in rt.items():
        _need(name in pack.rules,
              "tuning targets unknown rule %r" % (name,))
        _need(isinstance(spec, dict),
              "tuning for %r must be an object" % (name,))
        allowed = {"exceptions_add", "params", "disable",
                   "justification"}
        _need(set(spec.keys()) <= allowed,
              "tuning for %r has unknown keys %r"
              % (name, sorted(set(spec.keys()) - allowed)))
        # Exception discipline: the rule AUTHOR defines which
        # (field, comparator) tuples are exceptable. The deployment
        # may only ADD tuples in those declared shapes, supplying
        # values for the slots -- it may not invent new shapes, and
        # every field is checked against the enrichment schema at
        # tuning time exactly as at load time. A tuned-in exception
        # on an unknown field would otherwise resolve to None and,
        # with comparator 'ne', permanently suppress the rule.
        declared = pack.rules[name].exception_shapes
        _need(isinstance(spec.get("exceptions_add", []), list),
              "tuning exceptions_add for %r must be a list" % (name,))
        for j, exc in enumerate(spec.get("exceptions_add", [])):
            fields_j, shapes_j = _check_exception_shape(
                exc, "tuning.%s.exceptions_add[%d]" % (name, j))
            unknown = sorted(f for f in fields_j
                             if f not in ENRICHED_FIELDS)
            _need(not unknown,
                  "tuning for %r adds an exception on unknown "
                  "enrichment fields %r: refused, never a silent "
                  "rule suppression" % (name, unknown))
            novel = sorted(shapes_j - declared)
            _need(not novel,
                  "tuning for %r adds an exception tuple shape %r "
                  "the rule author did not declare: the author owns "
                  "exceptable shapes, the deployment supplies values"
                  % (name, novel))
        params = spec.get("params", {})
        _need(isinstance(params, dict)
              and all(_is_scalar(v) for v in params.values()),
              "tuning params for %r must be scalar-valued" % (name,))
        _need(isinstance(spec.get("disable", False), bool),
              "tuning disable for %r must be boolean" % (name,))
        if "justification" in spec:
            _need(isinstance(spec["justification"], str)
                  and spec["justification"].strip(),
                  "tuning justification for %r must be a non-empty "
                  "string" % (name,))


def apply_tuning(pack, tuning, journal=None):
    """Apply a deployment tuning overlay to a loaded pack.

    Returns a NEW ``LoadedPack``; the input pack is unchanged (packs
    are never edited in place). Floors: a ``min_*`` param may only move
    UP, a ``max_*`` param only DOWN. Disabling a ``stable`` rule needs
    a written justification. Violations refuse loudly with
    ``behsig-tuning-rejected``; applications journal loudly as
    ``behsig-tuning-applied``.
    """
    if isinstance(tuning, (bytes, bytearray)):
        try:
            tuning = json.loads(bytes(tuning).decode("utf-8"))
        except Exception:
            _refuse("behsig-tuning-rejected",
                    "tuning document is not valid UTF-8 JSON")
    try:
        _check_tuning_shape(tuning, pack)
    except PackRefused as e:
        # Shape violations are tuning refusals, not pack refusals.
        _refuse("behsig-tuning-rejected",
                "tuning shape invalid: %s" % (e.human,))

    records = list(pack.journal_records)

    def _jr(rec):
        records.append(rec)
        if journal is not None:
            journal(rec)

    new_rules = {}
    for name, rule in pack.rules.items():
        spec = tuning.get("rule_tuning", {}).get(name)
        if spec is None:
            new_rules[name] = rule
            continue
        # Param floors: min_* only up, max_* only down.
        merged_params = dict(rule.params)
        for key, val in spec.get("params", {}).items():
            if key in rule.params:
                old = rule.params[key]
                if (key.startswith("min_")
                        and isinstance(val, (int, float))
                        and isinstance(old, (int, float))
                        and val < old):
                    _refuse(
                        "behsig-tuning-rejected",
                        "tuning for %r moves %s below the author "
                        "floor %r" % (name, key, old))
                if (key.startswith("max_")
                        and isinstance(val, (int, float))
                        and isinstance(old, (int, float))
                        and val > old):
                    _refuse(
                        "behsig-tuning-rejected",
                        "tuning for %r moves %s above the author "
                        "ceiling %r" % (name, key, old))
            merged_params[key] = val
        merged_exc = list(rule.exceptions) + list(
            spec.get("exceptions_add", []))
        if spec.get("disable", False):
            if rule.maturity == "stable" and not spec.get(
                    "justification"):
                _refuse(
                    "behsig-tuning-rejected",
                    "tuning disables stable rule %r without a written "
                    "justification" % (name,))
            _jr({"code": "behsig-tuning-applied",
                 "rule": name,
                 "detail": "disable applied%s" % (
                     " with justification: %s"
                     % spec["justification"]
                     if spec.get("justification") else "")})
            continue
        tuned = CompiledRule({
            "name": rule.name, "desc": rule.desc,
            "condition": rule.condition, "fields": ENRICHED_FIELDS,
            "output": rule.output, "priority": rule.priority,
            "enabled": rule.enabled, "source": rule.source,
            "tags": list(rule.tags), "maturity": rule.maturity,
            "exceptions": merged_exc,
            "exception_shapes": sorted(rule.exception_shapes),
            "capture_window": rule.capture_window,
            "params": merged_params,
        })
        new_rules[name] = tuned
        _jr({"code": "behsig-tuning-applied",
             "rule": name,
             "detail": "tuning applied: %d exceptions added, "
                       "%d params set"
                       % (len(spec.get("exceptions_add", [])),
                          len(spec.get("params", {})))})
    return LoadedPack(pack_id=pack.pack_id,
                      pack_version=pack.pack_version,
                      rules=new_rules, macros=pack.macros,
                      lists=pack.lists,
                      disabled_rules=list(pack.disabled_rules),
                      filtered_by_maturity=list(
                          pack.filtered_by_maturity),
                      journal_records=records)


# ------------------------------------------------------------------
# Stateful correlator: ABOVE the predicates, never inside them.
# ------------------------------------------------------------------

_CORRELATOR_KINDS = ("burst", "fire_storm", "slow_drip", "ratio")


def _check_corr_config(config):
    _need(isinstance(config, dict), "correlator config must be an object")
    for kind in _CORRELATOR_KINDS:
        spec = config.get(kind)
        if spec is None:
            continue
        _need(isinstance(spec, dict),
              "correlator %s spec must be an object" % kind)
        _need(isinstance(spec.get("window_s"), (int, float))
              and spec["window_s"] > 0,
              "correlator %s needs a positive window_s" % kind)
        if kind == "burst":
            _need(isinstance(spec.get("min_events"), int)
                  and spec["min_events"] >= 2,
                  "correlator burst needs min_events >= 2")
        elif kind == "fire_storm":
            _need(isinstance(spec.get("min_fires"), int)
                  and spec["min_fires"] >= 2,
                  "correlator fire_storm needs min_fires >= 2")
        elif kind == "slow_drip":
            _need(isinstance(spec.get("min_sessions"), int)
                  and spec["min_sessions"] >= 2,
                  "correlator slow_drip needs min_sessions >= 2")
            _need(spec.get("join_key") in ENRICHED_FIELDS,
                  "correlator slow_drip join_key must be a known "
                  "enrichment field")
        elif kind == "ratio":
            _need(isinstance(spec.get("min_events"), int)
                  and spec["min_events"] >= 2,
                  "correlator ratio needs min_events >= 2")
            _need(isinstance(spec.get("export_ratio"), (int, float))
                  and 0 < spec["export_ratio"] <= 1,
                  "correlator ratio needs 0 < export_ratio <= 1")


class CorrelatorAdvisory(object):
    def __init__(self, kind, actor_id, detail, event_digests,
                 window_s):
        self.kind = kind
        self.actor_id = actor_id
        self.detail = detail
        self.event_digests = event_digests
        self.window_s = window_s


class StatefulCorrelator(object):
    """Sliding-window correlator above the stateless rule predicates.

    Per-actor state only; windows are driven by event ``ts`` values
    (deterministic, no clock reads). Output is advisory-only: every
    firing journals ``behsig-correlator-advisory`` (digests, never raw
    arguments) and, when ``queue`` is supplied, emits a hold REQUEST
    for the deployment's human-approval queue. ``observe()`` never
    raises to block execution and the queue request is never a denial.
    """

    def __init__(self, config, journal=None, queue=None):
        _check_corr_config(config)
        self.config = dict(config)
        self._journal = journal
        self._queue = queue
        self.journal_records = []
        # actor_id -> {"events": deque[(ts, digest, arg_class)],
        #              "fires": deque[(ts, rule_name)],
        #              "drip": {join_value: {session_id: last_ts}},
        #              "cool": {kind: last_fire_ts}}
        self._actors = {}

    def _jr(self, rec):
        self.journal_records.append(rec)
        if self._journal is not None:
            self._journal(rec)

    def _state(self, actor_id):
        st = self._actors.get(actor_id)
        if st is None:
            st = {"events": deque(), "fires": deque(), "drip": {},
                  "cool": {}}
            self._actors[actor_id] = st
        return st

    def _max_windows(self):
        """Widest window per store, for bounded-memory pruning."""
        ev_w = 0.0
        fire_w = 0.0
        for kind, spec in self.config.items():
            w = spec["window_s"]
            if kind in ("burst", "ratio", "slow_drip"):
                ev_w = max(ev_w, w)
            if kind == "fire_storm":
                fire_w = max(fire_w, w)
        return ev_w, fire_w

    @staticmethod
    def _windowed(items, now, w):
        # Per-kind windowing over the shared store: one kind's prune
        # must never eat another kind's history.
        cutoff = now - w
        return [x for x in items if x[0] >= cutoff]

    def _cooled(self, st, kind, now, window_s):
        last = st["cool"].get(kind)
        return last is not None and (now - last) < window_s

    def _advise(self, kind, actor_id, window_s, detail, digests):
        advisory = CorrelatorAdvisory(
            kind=kind, actor_id=actor_id, detail=detail,
            event_digests=list(digests), window_s=window_s)
        self._jr({"code": "behsig-correlator-advisory",
                  "kind": kind,
                  "actor_id": actor_id,
                  "window_s": window_s,
                  "detail": detail,
                  "event_digests": list(digests)})
        if self._queue is not None:
            # A hold REQUEST for the deployment's human queue -- the
            # deployment decides; this is never a denial.
            self._queue({"type": "behsig_hold_request",
                         "code": "behsig-correlator-advisory",
                         "kind": kind,
                         "actor_id": actor_id,
                         "summary": detail,
                         "decision": "hold-request",
                         "event_digests": list(digests)})
        return advisory

    def observe(self, enriched_event, pack_alerts):
        """Consume one enriched event plus its pack alerts.

        Returns ``[CorrelatorAdvisory]`` (possibly empty). Never
        raises for advisory purposes and never blocks.
        """
        if not (isinstance(enriched_event, dict)
                and enriched_event.get("_enriched") is True):
            raise ValueError(
                "observe: event must be an enrich_event() output")
        actor = enriched_event.get("actor_id", "")
        now = enriched_event["ts"]
        st = self._state(actor)
        st["events"].append(
            (now, enriched_event["raw.digest"],
             enriched_event["arg.class"]))
        for alert in pack_alerts or []:
            st["fires"].append((now, alert.rule_name))

        # Bounded-memory prune at the widest configured windows.
        ev_w, fire_w = self._max_windows()
        while st["events"] and st["events"][0][0] < now - ev_w:
            st["events"].popleft()
        while st["fires"] and st["fires"][0][0] < now - fire_w:
            st["fires"].popleft()

        out = []
        cfg = self.config

        spec = cfg.get("burst")
        if spec is not None:
            w = spec["window_s"]
            evs = self._windowed(st["events"], now, w)
            if (len(evs) >= spec["min_events"]
                    and not self._cooled(st, "burst", now, w)):
                st["cool"]["burst"] = now
                out.append(self._advise(
                    "burst", actor, w,
                    "%d events in %ss for actor %s"
                    % (len(evs), w, actor),
                    [d for _, d, _ in evs]))

        spec = cfg.get("fire_storm")
        if spec is not None:
            w = spec["window_s"]
            evs = self._windowed(st["events"], now, w)
            fires = self._windowed(st["fires"], now, w)
            if (len(fires) >= spec["min_fires"]
                    and not self._cooled(st, "fire_storm", now, w)):
                st["cool"]["fire_storm"] = now
                out.append(self._advise(
                    "fire_storm", actor, w,
                    "%d rule fires in %ss for actor %s"
                    % (len(fires), w, actor),
                    [d for _, d, _ in evs]))

        spec = cfg.get("slow_drip")
        if spec is not None:
            w = spec["window_s"]
            join_key = spec["join_key"]
            join_val = enriched_event.get(join_key, "")
            bucket = st["drip"].setdefault(join_val, {})
            bucket[enriched_event.get("session_id", "")] = now
            # Expire stale session sightings.
            for jv in list(st["drip"]):
                for sess in list(st["drip"][jv]):
                    if now - st["drip"][jv][sess] > w:
                        del st["drip"][jv][sess]
                if not st["drip"][jv]:
                    del st["drip"][jv]
            sessions = set()
            for sess, seen in bucket.items():
                if now - seen <= w:
                    sessions.add(sess)
            if (len(sessions) >= spec["min_sessions"]
                    and not self._cooled(st, "slow_drip", now, w)):
                st["cool"]["slow_drip"] = now
                out.append(self._advise(
                    "slow_drip", actor, w,
                    "%d distinct sessions share %s=%r within %ss "
                    "for actor %s (shared-key join: exact key "
                    "match, explicitly approximate correlation -- "
                    "keys can collide or rotate)"
                    % (len(sessions), join_key, join_val, w, actor),
                    [d for _, d, _ in self._windowed(
                        st["events"], now, w)]))

        spec = cfg.get("ratio")
        if spec is not None:
            w = spec["window_s"]
            evs = self._windowed(st["events"], now, w)
            total = len(evs)
            exports = sum(1 for _, _, c in evs if c == "export")
            if (total >= spec["min_events"]
                    and total > 0
                    and exports / total >= spec["export_ratio"]
                    and not self._cooled(st, "ratio", now, w)):
                st["cool"]["ratio"] = now
                out.append(self._advise(
                    "ratio", actor, w,
                    "export-class share %d/%d >= %.2f in %ss for "
                    "actor %s"
                    % (exports, total, spec["export_ratio"], w,
                       actor),
                    [d for _, d, _ in evs]))
        return out
