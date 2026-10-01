"""Declarative detector schema: data-defined chained detectors over event streams.

Wave-261 feature lane 3 (aquasecurity/tracee ADAPT -- the *schema and
composition semantics* only: declarative detectors, CEL-shaped conditions,
versioned ``produced_event`` schemas, MITRE-tagged threat metadata,
auto-resolved subscription chains. No tracee code vendored, linked, or
translated; no eBPF -- our events are userspace agent-governance events).
Stdlib only.

A detector is DATA -- a plain dict (JSON-serializable), never code::

    {
      "name": "credential-swap-outside-allowlist",
      "version": "1.0.0",
      "description": "human-readable",
      "event_selector": {"type": "credential_swap"},
      "predicates": [
          {"field": "host", "op": "not_in",
           "value": ["vault.internal.example"]},
      ],
      "produces": {
          "event_name": "credential_swap_outside_allowlist",
          "event_schema_version": "1.0.0",
          "fields": {
              "host": {"from_field": "host"},
              "severity": {"literal": "high"},
          },
      },
      "threat": {"mitre": ["T1550"], "severity": "high",
                 "description": "..."},
      "subscribes": [],
    }

Predicate DSL (closed vocabulary -- NO eval, NO attribute access, NO
regex, NO arbitrary code):
  eq, ne, in, not_in, gt, ge, lt, le, startswith, endswith,
  exists, not_exists

``field`` paths are dotted lookups into the event dict (``a.b``); list
indices (``a.0``) are allowed. Segments must match ``[A-Za-z0-9_]+`` and
must not contain ``__`` -- dunder/proto traversal (``__class__``,
``__dict__``, ``__proto__``) is a LOUD registration refusal
(``detector-unknown-predicate``), never a silent skip. Comparison ops
take either a literal ``value`` or an ``other_field`` path (field-to-
field comparison); exactly one of the two must be present.

Semantics notes:
* All predicates on a detector are ANDed.
* A missing field never matches a value predicate -- ``eq``, ``ne``,
  ``in``, ``gt``, ``startswith`` etc. are all False when the field is
  absent. ``exists`` / ``not_exists`` are the explicit way to test
  presence. This is the conservative choice: absent data yields no
  detection, never a false positive.
* Numeric comparisons require real numbers on both sides (bools are
  excluded -- ``True`` is not ``1`` here); otherwise the predicate is
  False. ``startswith``/``endswith`` require strings on both sides.

:class:`DetectorEngine`:

* ``register(defn)`` / ``register_all(defs)`` -- validate the detector
  data. Malformed definitions, unknown predicate ops, duplicate names,
  dangling subscriptions, and subscription cycles are LOUD
  :class:`DetectorRegistrationError` refusals carrying machine codes
  (``detector-malformed``, ``detector-unknown-predicate``,
  ``detector-duplicate-name``, ``detector-cycle``). ``register_all`` is
  atomic: a bad batch registers nothing.
* ``process(event)`` -- match selectors, evaluate predicates, emit
  versioned produced events. Chained detectors (``subscribes``) consume
  engine-issued produced events within the same call; the subscription
  order is auto-resolved topologically at registration.
* ``process_stream(events)`` -- per-event isolation: a detector that
  errors on an event has the error counted and journaled, and processing
  continues for the remaining detectors and events. The stream is never
  silently dropped. (``BaseException`` still propagates -- only
  ``Exception`` is contained, per the wave-229 lesson.)
* ``stats()`` / ``journal_entries()`` -- counters and the error journal.

Trust boundary (fail-closed): subscription edges carry ONLY
engine-issued produced events, recognized by a per-engine secret stamp
that is stripped before events are returned to callers. A dict fed to
``process()`` that *claims* to be a produced event (``"produced": True``)
is treated as untrusted input: it may match raw selectors, but it NEVER
traverses a subscription edge. Forged or replayed produced events cannot
trigger chained detectors. Cross-engine provenance (persisted produced
events re-fed into a new engine) is a documented v1 residual -- it needs
digest-anchored provenance, not the in-memory stamp.

Alert discipline (wave-262 feature lane 2 -- falcosecurity/falco ADAPT, the
*alert half* only: fixed priority ladder, first-class exception blocks,
maturity tiers, override semantics; pattern only, no falco code):
`gov/detectors.py` is the detection half (match -> produced events, the
Tracee-shaped side); :class:`AlertSink` is the alert half (matched detector
+ exception evaluation -> structured alert record -> journal, the
Falco-shaped side). Three additive definition keys (all optional, so
wave-261 definitions load and behave identically):

* ``priority`` -- one of the fixed ladder ``PRIORITY_LADDER``
  (``emergency, alert, critical, error, warning, notice, informational,
  debug`` -- falco's order, most severe first). Unknown values are a LOUD
  ``detector-unknown-priority`` refusal. Every *alert* record carries a
  declared ladder value; a detector with no declared priority is NEVER
  inflated (no silent default to critical) -- its matches are journaled
  as observations with the reason recorded.
* ``exceptions`` -- a list of named allowlist blocks, each
  ``{name, description, fields, comps, values}`` where ``fields`` are
  dotted event paths, ``comps`` are per-field comparators from
  ``EXCEPTION_COMPS`` (``eq/ne/in/not_in/startswith/endswith``), and
  ``values`` are per-field non-empty scalar lists. Tuples inside one block
  are ANDed; blocks are ORed. A matching block suppresses the ALERT, never
  the produced event (detection flows on; the suppression is journaled as
  ``suppressed`` with the exception named -- never silently dropped).
  Malformed blocks are a LOUD ``detector-exception-malformed`` refusal:
  a broken allowlist must not silently re-arm the rule. Each block is
  independently overridable/disablable by deployment policy
  (:class:`AlertSink` ``policy``) without touching the rule -- overriding
  values replaces the block's ``values``; disabling a block
  (``enabled: false``) fails closed to alert, and the re-arming is
  journaled in the record's ``disabled_but_matched`` list (never silent).
* ``maturity`` -- ``stable`` (default), ``experimental``, or
  ``deprecated``. Unknown tiers are a LOUD ``detector-unknown-maturity``
  refusal; ``deprecated`` detectors refuse to load with the machine code
  ``detector-deprecated``. ``experimental`` detectors observe only: their
  matches journal as ``observation`` records and
  :meth:`AlertSink.may_gate_enforcement` returns False for them, so they
  can never gate an enforcement decision.

Machine codes (registry conventions -- `gov/decision_codes.py` TAXONOMY, domain
`detector`, severity medium, evidence `['detector-definition']`, reverify
`['recompute']`, sorted position): `detector-cycle`, `detector-deprecated`,
`detector-duplicate-name`, `detector-exception-malformed`,
`detector-malformed`, `detector-unknown-maturity`,
`detector-unknown-predicate`, `detector-unknown-priority`.
**Pin change: 1106 → 1110** (wave-262 feature lane 2).
"""

import copy
import hashlib
import json
import re
import secrets

# ---------------------------------------------------------------- codes

CODE_MALFORMED = "detector-malformed"
CODE_UNKNOWN_PREDICATE = "detector-unknown-predicate"
CODE_DUPLICATE_NAME = "detector-duplicate-name"
CODE_CYCLE = "detector-cycle"
# Wave-262 feature lane 2 (falco alert discipline, additive).
CODE_UNKNOWN_PRIORITY = "detector-unknown-priority"
CODE_EXCEPTION_MALFORMED = "detector-exception-malformed"
CODE_UNKNOWN_MATURITY = "detector-unknown-maturity"
CODE_DEPRECATED = "detector-deprecated"


# ------------------------------------------- alert-discipline vocabulary

# Falco's fixed priority ladder, most severe first. Every alert record
# carries a *declared* ladder value -- never a silent default.
PRIORITY_LADDER = ("emergency", "alert", "critical", "error", "warning",
                   "notice", "informational", "debug")
_PRIORITY_SET = frozenset(PRIORITY_LADDER)
# Lower rank = more severe (index into the ladder).
PRIORITY_RANK = {name: rank for rank, name in enumerate(PRIORITY_LADDER)}

# Maturity tiers. "experimental" observes only (cannot gate enforcement);
# "deprecated" refuses to load. Default (absent) is "stable" -- wave-261
# definitions keep their behavior.
MATURITIES = ("stable", "experimental", "deprecated")
_MATURITY_SET = frozenset(MATURITIES)

# Per-tuple comparators for exception blocks (closed vocabulary, same
# conservative semantics as the predicate DSL: missing fields and type
# mismatches never match).
EXCEPTION_COMPS = frozenset(
    ["eq", "ne", "in", "not_in", "startswith", "endswith"])


class DetectorRegistrationError(Exception):
    """Loud registration refusal carrying a machine code."""

    def __init__(self, code, detail):
        self.code = code
        super().__init__("%s: %s" % (code, detail))


# ------------------------------------------------------- shape patterns

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]{1,32})?$")
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_SEG_RE = re.compile(r"^[A-Za-z0-9_]+$")
_MAX_PATH_LEN = 128
_MAX_PATH_DEPTH = 8

_OPS_VALUE = frozenset(
    ["eq", "ne", "in", "not_in", "gt", "ge", "lt", "le",
     "startswith", "endswith"])
_OPS_FIELD_COMPARE = frozenset(["eq", "ne", "gt", "ge", "lt", "le"])
_OPS_PRESENCE = frozenset(["exists", "not_exists"])
_ALL_OPS = _OPS_VALUE | _OPS_PRESENCE

_SELECTOR_KEYS = frozenset(["type", "produced_by"])
_DEFINITION_KEYS = frozenset(
    ["name", "version", "description", "event_selector", "predicates",
     "produces", "threat", "subscribes",
     # Wave-262 (falco alert discipline, additive -- all optional):
     "priority", "exceptions", "maturity"])
_THREAT_KEYS = frozenset(["mitre", "severity", "description"])


def _refuse(code, detail):
    raise DetectorRegistrationError(code, detail)


def _check_path(path, what="field", code=CODE_UNKNOWN_PREDICATE):
    """Validate a dotted field path. Refuses loudly on any hostile shape.

    ``code`` selects the machine code of the refusal (the exception-block
    validator reuses path validation with the alert-discipline code).
    """
    if not isinstance(path, str):
        _refuse(code,
                "%s path must be a string, got %r" % (what, path))
    if not path or len(path) > _MAX_PATH_LEN:
        _refuse(code,
                "%s path has bad length: %r" % (what, path))
    segments = path.split(".")
    if len(segments) > _MAX_PATH_DEPTH:
        _refuse(code,
                "%s path too deep: %r" % (what, path))
    for seg in segments:
        if not seg or not _SEG_RE.match(seg) or "__" in seg:
            _refuse(code,
                    "%s path has illegal segment: %r" % (what, path))
    return path


_MISSING = object()


def _resolve_field(event, path):
    """Dotted lookup over dicts (and list indices). No attribute access."""
    current = event
    for seg in path.split("."):
        if isinstance(current, dict):
            if seg not in current:
                return _MISSING
            current = current[seg]
        elif isinstance(current, (list, tuple)) and seg.isdigit():
            idx = int(seg)
            if idx >= len(current):
                return _MISSING
            current = current[idx]
        else:
            return _MISSING
    return current


def _is_num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_scalar(value):
    return value is None or isinstance(value, (bool, int, float, str))


def _safe_eq(left, right):
    if _is_num(left) and _is_num(right):
        return left == right
    return type(left) is type(right) and left == right


def _eval_predicate(predicate, event):
    """Evaluate one validated predicate against one event."""
    op = predicate["op"]
    left = _resolve_field(event, predicate["field"])
    if op == "exists":
        return left is not _MISSING
    if op == "not_exists":
        return left is _MISSING
    if left is _MISSING:
        return False
    if "other_field" in predicate:
        right = _resolve_field(event, predicate["other_field"])
        if right is _MISSING:
            return False
    else:
        right = predicate["value"]
    if op == "eq":
        return _safe_eq(left, right)
    if op == "ne":
        return not _safe_eq(left, right)
    if op == "in":
        return any(_safe_eq(left, item) for item in right)
    if op == "not_in":
        return not any(_safe_eq(left, item) for item in right)
    if op in ("gt", "ge", "lt", "le"):
        if not (_is_num(left) and _is_num(right)):
            return False
        if op == "gt":
            return left > right
        if op == "ge":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right
    if op in ("startswith", "endswith"):
        if not (isinstance(left, str) and isinstance(right, str)):
            return False
        return (left.startswith(right) if op == "startswith"
                else left.endswith(right))
    raise AssertionError("unreachable: unknown op %r" % (op,))


def _validate_predicate(predicate):
    if not isinstance(predicate, dict):
        _refuse(CODE_UNKNOWN_PREDICATE,
                "predicate must be a dict, got %r" % (predicate,))
    unknown = set(predicate) - {"field", "op", "value", "other_field"}
    if unknown:
        _refuse(CODE_UNKNOWN_PREDICATE,
                "predicate has unknown keys: %r" % (sorted(unknown),))
    if "field" not in predicate or "op" not in predicate:
        _refuse(CODE_UNKNOWN_PREDICATE,
                "predicate needs 'field' and 'op': %r" % (predicate,))
    _check_path(predicate["field"])
    op = predicate["op"]
    if op not in _ALL_OPS:
        _refuse(CODE_UNKNOWN_PREDICATE, "unknown predicate op: %r" % (op,))
    has_value = "value" in predicate
    has_other = "other_field" in predicate
    if op in _OPS_PRESENCE:
        if has_value or has_other:
            _refuse(CODE_UNKNOWN_PREDICATE,
                    "op %r takes no value/other_field" % (op,))
        return
    if has_value == has_other:
        _refuse(CODE_UNKNOWN_PREDICATE,
                "op %r needs exactly one of value/other_field" % (op,))
    if has_other:
        if op not in _OPS_FIELD_COMPARE:
            _refuse(CODE_UNKNOWN_PREDICATE,
                    "op %r does not support other_field" % (op,))
        _check_path(predicate["other_field"], what="other_field")
        return
    value = predicate["value"]
    if op in ("in", "not_in"):
        if (not isinstance(value, list) or not value
                or not all(_is_scalar(item) for item in value)):
            _refuse(CODE_UNKNOWN_PREDICATE,
                    "op %r needs a non-empty list of scalars" % (op,))
        return
    if not _is_scalar(value):
        _refuse(CODE_UNKNOWN_PREDICATE,
                "op %r needs a scalar value, got %r" % (op, value))


def _validate_exception_block(block, seen_names):
    """Validate one named exception (allowlist) block.

    Shape: {name, description?, fields, comps, values} where fields/comps/
    values are parallel lists of equal length -- a (field, comp, values)
    tuple per position. Any structural problem is a LOUD
    ``detector-exception-malformed`` refusal: a broken allowlist must not
    silently re-arm the rule (fail closed at registration).
    """
    if not isinstance(block, dict):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception block must be a dict, got %r" % (block,))
    unknown = set(block) - {"name", "description", "fields", "comps",
                            "values"}
    if unknown:
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception block has unknown keys: %r" % (sorted(unknown),))
    name = block.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "bad exception name: %r" % (name,))
    if name in seen_names:
        _refuse(CODE_EXCEPTION_MALFORMED,
                "duplicate exception name: %r" % (name,))
    seen_names.add(name)
    description = block.get("description", "")
    if not isinstance(description, str):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception %r description must be a string" % (name,))
    fields = block.get("fields")
    if not isinstance(fields, list) or not fields:
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception %r fields must be a non-empty list" % (name,))
    for path in fields:
        _check_path(path, what="exception %r field" % (name,),
                    code=CODE_EXCEPTION_MALFORMED)
    comps = block.get("comps")
    if not isinstance(comps, list) or len(comps) != len(fields):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception %r comps must be a list aligned with fields "
                "(%d entries)" % (name, len(fields)))
    for comp in comps:
        if comp not in EXCEPTION_COMPS:
            _refuse(CODE_EXCEPTION_MALFORMED,
                    "exception %r unknown comp: %r" % (name, comp))
    values = block.get("values")
    if not isinstance(values, list) or len(values) != len(fields):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exception %r values must be a list aligned with fields "
                "(%d entries)" % (name, len(fields)))
    for vals in values:
        if (not isinstance(vals, list) or not vals
                or not all(_is_scalar(v) for v in vals)):
            _refuse(CODE_EXCEPTION_MALFORMED,
                    "exception %r values entries must be non-empty lists "
                    "of scalars" % (name,))


def _validate_alert_discipline(defn):
    """Validate the additive alert-discipline keys
    (priority/exceptions/maturity).

    All three are optional -- wave-261 definitions carry none of them and
    keep their behavior. Refusals are LOUD with alert-discipline machine
    codes; in particular a malformed exception block refuses the whole
    detector (a broken allowlist must not silently re-arm the rule) and a
    ``deprecated`` maturity refuses to load the detector at all.
    """
    priority = defn.get("priority")
    if priority is not None:
        if not isinstance(priority, str) or priority not in _PRIORITY_SET:
            _refuse(CODE_UNKNOWN_PRIORITY,
                    "unknown priority %r (fixed ladder: %s)"
                    % (priority, ", ".join(PRIORITY_LADDER)))
    maturity = defn.get("maturity", "stable")
    if not isinstance(maturity, str) or maturity not in _MATURITY_SET:
        _refuse(CODE_UNKNOWN_MATURITY,
                "unknown maturity %r (tiers: %s)"
                % (maturity, ", ".join(MATURITIES)))
    if maturity == "deprecated":
        _refuse(CODE_DEPRECATED,
                "detector %r is deprecated and refuses to load"
                % (defn.get("name"),))
    exceptions = defn.get("exceptions", [])
    if not isinstance(exceptions, list):
        _refuse(CODE_EXCEPTION_MALFORMED,
                "exceptions must be a list, got %r" % (exceptions,))
    seen_names = set()
    for block in exceptions:
        _validate_exception_block(block, seen_names)


def _validate_definition(defn):
    if not isinstance(defn, dict):
        _refuse(CODE_MALFORMED,
                "detector definition must be a dict, got %r" % (defn,))
    unknown = set(defn) - _DEFINITION_KEYS
    if unknown:
        _refuse(CODE_MALFORMED,
                "unknown definition keys: %r" % (sorted(unknown),))
    name = defn.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        _refuse(CODE_MALFORMED, "bad detector name: %r" % (name,))
    version = defn.get("version")
    if not isinstance(version, str) or not _SEMVER_RE.match(version):
        _refuse(CODE_MALFORMED, "bad detector version: %r" % (version,))
    description = defn.get("description", "")
    if not isinstance(description, str):
        _refuse(CODE_MALFORMED, "description must be a string")
    selector = defn.get("event_selector")
    if not isinstance(selector, dict) or not selector:
        _refuse(CODE_MALFORMED, "event_selector must be a non-empty dict")
    bad_keys = set(selector) - _SELECTOR_KEYS
    if bad_keys:
        _refuse(CODE_MALFORMED,
                "event_selector has unknown keys: %r" % (sorted(bad_keys),))
    for key, want in selector.items():
        if not isinstance(want, str) or not want:
            _refuse(CODE_MALFORMED,
                    "event_selector[%r] must be a non-empty string" % (key,))
    predicates = defn.get("predicates")
    if not isinstance(predicates, list) or not predicates:
        _refuse(CODE_MALFORMED, "predicates must be a non-empty list")
    for predicate in predicates:
        _validate_predicate(predicate)
    produces = defn.get("produces")
    if not isinstance(produces, dict):
        _refuse(CODE_MALFORMED, "produces must be a dict")
    if set(produces) != {"event_name", "event_schema_version", "fields"}:
        _refuse(CODE_MALFORMED,
                "produces needs exactly event_name, event_schema_version, "
                "fields")
    event_name = produces["event_name"]
    if not isinstance(event_name, str) or not _NAME_RE.match(event_name):
        _refuse(CODE_MALFORMED, "bad produced event_name: %r" % (event_name,))
    schema_version = produces["event_schema_version"]
    if not isinstance(schema_version, str) or not _SEMVER_RE.match(
            schema_version):
        _refuse(CODE_MALFORMED,
                "bad event_schema_version: %r" % (schema_version,))
    fields = produces["fields"]
    if not isinstance(fields, dict):
        _refuse(CODE_MALFORMED, "produces.fields must be a dict")
    for out_name, spec in fields.items():
        if (not isinstance(out_name, str) or not _SEG_RE.match(out_name)
                or "__" in out_name or "." in out_name):
            _refuse(CODE_MALFORMED,
                    "bad produced field name: %r" % (out_name,))
        if not isinstance(spec, dict) or set(spec) not in (
                {"from_field"}, {"literal"}):
            _refuse(CODE_MALFORMED,
                    "field %r needs exactly from_field or literal"
                    % (out_name,))
        if "from_field" in spec:
            _check_path(spec["from_field"], what="from_field")
        elif not _is_scalar(spec["literal"]):
            _refuse(CODE_MALFORMED,
                    "field %r literal must be a scalar" % (out_name,))
    threat = defn.get("threat")
    if threat is not None:
        if not isinstance(threat, dict):
            _refuse(CODE_MALFORMED, "threat must be a dict")
        bad_threat = set(threat) - _THREAT_KEYS
        if bad_threat:
            _refuse(CODE_MALFORMED,
                    "threat has unknown keys: %r" % (sorted(bad_threat),))
        for key in ("severity", "description"):
            if not isinstance(threat.get(key), str) or not threat.get(key):
                _refuse(CODE_MALFORMED,
                        "threat.%s must be a non-empty string" % (key,))
        mitre = threat.get("mitre", [])
        if (not isinstance(mitre, list)
                or any(not isinstance(t, str) or not _MITRE_RE.match(t)
                       for t in mitre)):
            _refuse(CODE_MALFORMED,
                    "threat.mitre must be a list of T####[.###] ids")
    subscribes = defn.get("subscribes", [])
    if (not isinstance(subscribes, list)
            or any(not isinstance(s, str) or not _NAME_RE.match(s)
                   for s in subscribes)):
        _refuse(CODE_MALFORMED, "subscribes must be a list of names")
    if "produced_by" in selector:
        if not subscribes:
            _refuse(CODE_MALFORMED,
                    "event_selector.produced_by needs non-empty subscribes")
        if selector["produced_by"] not in subscribes:
            _refuse(CODE_MALFORMED,
                    "event_selector.produced_by must name a subscribed "
                    "detector")
    # Wave-262 (falco alert discipline, additive): validate priority /
    # exceptions / maturity, then normalize the defaults into the stored
    # copy so downstream code sees a complete shape.
    _validate_alert_discipline(defn)
    normalized = copy.deepcopy(defn)
    normalized.setdefault("maturity", "stable")
    normalized.setdefault("exceptions", [])
    return normalized


def _topo_order(graph):
    """Kahn's algorithm over name -> set(dependencies). None on cycle."""
    deps = {name: set(parents) for name, parents in graph.items()}
    order = []
    while deps:
        ready = sorted(name for name, parents in deps.items() if not parents)
        if not ready:
            return None
        for name in ready:
            order.append(name)
            del deps[name]
        for parents in deps.values():
            parents.difference_update(ready)
    return order


def _exception_tuple_matches(comp, values, left):
    """One (field, comp, values) tuple of an exception block.

    Conservative like the predicate DSL: a missing field never matches,
    and type mismatches evaluate False rather than raising.
    """
    if left is _MISSING:
        return False
    if comp in ("eq", "in"):
        return any(_safe_eq(left, value) for value in values)
    if comp in ("ne", "not_in"):
        return not any(_safe_eq(left, value) for value in values)
    if comp in ("startswith", "endswith"):
        if not isinstance(left, str):
            return False
        candidates = [v for v in values if isinstance(v, str)]
        if not candidates:
            return False
        return any(left.startswith(v) if comp == "startswith"
                   else left.endswith(v) for v in candidates)
    return False  # unreachable: comps validated at registration


def _exception_block_matches(block, event):
    """An exception block matches iff EVERY (field, comp, values) tuple
    matches (tuples ANDed); blocks themselves are ORed by the caller."""
    for field, comp, values in zip(block["fields"], block["comps"],
                                   block["values"]):
        if not _exception_tuple_matches(comp, values,
                                        _resolve_field(event, field)):
            return False
    return True


def _selector_matches(selector, event):
    for key, want in selector.items():
        if key == "type":
            got = event.get("type", event.get("event_name", _MISSING))
        elif key == "produced_by":
            got = (event.get("detector", _MISSING)
                   if event.get("produced") else _MISSING)
        else:  # pragma: no cover -- selector keys validated at registration
            got = _MISSING
        if got is _MISSING or got != want:
            return False
    return True


_STAMP_KEY = "_engine_stamp"


def _event_digest(event):
    try:
        canonical = json.dumps(event, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True, default=str)
    except Exception:  # noqa: BLE001 -- digest must never fail
        canonical = repr(sorted((str(k), str(v))
                                for k, v in event.items()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DetectorEngine:
    """Runs declarative detectors over an event stream."""

    def __init__(self):
        self._detectors = {}
        self._order = []
        self._stamp = secrets.token_hex(16)
        self._events_seen = 0
        self._produced = 0
        self._errors = 0
        self._journal = []

    @property
    def detectors(self):
        return dict(self._detectors)

    def register(self, definition):
        """Register one detector definition (data dict)."""
        self.register_all([definition])

    def register_all(self, definitions):
        """Register a batch atomically: any refusal registers nothing."""
        if not isinstance(definitions, (list, tuple)) or not definitions:
            _refuse(CODE_MALFORMED,
                    "register_all needs a non-empty list of definitions")
        validated = [_validate_definition(d) for d in definitions]
        names = [v["name"] for v in validated]
        if len(set(names)) != len(names):
            _refuse(CODE_DUPLICATE_NAME,
                    "duplicate detector name inside the batch")
        for name in names:
            if name in self._detectors:
                _refuse(CODE_DUPLICATE_NAME,
                        "detector already registered: %r" % (name,))
        known = set(self._detectors) | set(names)
        for v in validated:
            for target in v["subscribes"]:
                if target not in known:
                    _refuse(CODE_MALFORMED,
                            "detector %r subscribes to unknown detector %r"
                            % (v["name"], target))
        graph = {name: set(self._detectors[name]["subscribes"])
                 if name in self._detectors else set()
                 for name in known}
        for v in validated:
            graph[v["name"]] = set(v["subscribes"])
        order = _topo_order(graph)
        if order is None:
            # The pre-existing graph was acyclic, so any cycle must
            # involve the new batch.
            _refuse(CODE_CYCLE,
                    "subscription cycle involving: %s"
                    % (", ".join(sorted(names)),))
        for v in validated:
            self._detectors[v["name"]] = v
        self._order = [n for n in order if n in self._detectors]

    def _produce(self, detector, source_event):
        fields = {}
        for out_name, spec in detector["produces"]["fields"].items():
            if "literal" in spec:
                fields[out_name] = copy.deepcopy(spec["literal"])
            else:
                value = _resolve_field(source_event, spec["from_field"])
                fields[out_name] = None if value is _MISSING else value
        source = {k: v for k, v in source_event.items() if k != _STAMP_KEY}
        threat = detector.get("threat")
        return {
            "produced": True,
            "event_name": detector["produces"]["event_name"],
            "event_schema_version":
                detector["produces"]["event_schema_version"],
            "detector": detector["name"],
            "detector_version": detector["version"],
            "produced_from": _event_digest(source),
            "fields": fields,
            "threat": copy.deepcopy(threat) if threat is not None else None,
        }

    def _run_detector(self, detector, event):
        """Run one detector on one event; errors are contained by caller."""
        if not _selector_matches(detector["event_selector"], event):
            return None
        if not all(_eval_predicate(p, event)
                   for p in detector["predicates"]):
            return None
        return self._produce(detector, event)

    def _note_error(self, detector_name, event, exc):
        self._errors += 1
        self._journal.append({
            "type": "detector_error",
            "detector": detector_name,
            "event_digest": _event_digest(event),
            "error_type": type(exc).__name__,
            "error": str(exc),
        })

    def process(self, event, on_match=None):
        """Run all detectors over one event; return produced events.

        Raises TypeError on a non-dict event (caller contract, loud).
        Per-detector errors are counted and journaled; they never stop
        the remaining detectors or drop the event.

        ``on_match`` (wave-262, additive -- defaults to None, wave-261
        callers unaffected) is an optional hook called once per detector
        match as ``on_match(detector, matched_event)``, where
        ``detector`` is the validated definition dict and
        ``matched_event`` is the event the detector matched with the
        engine-internal stamp stripped. The AlertSink uses it to turn
        matches into alert records. Hook exceptions propagate (loud) --
        they are never swallowed as detector errors.
        """
        if not isinstance(event, dict):
            raise TypeError("event must be a dict, got %r" % (type(event),))
        self._events_seen += 1
        produced_out = []
        # Level 0: raw input events -> detectors with no subscriptions.
        # Level k+1: engine-issued produced events from level k ->
        # detectors subscribed to their producer. The chain depth is
        # bounded by the detector count (defense in depth; cycles are
        # refused at registration).
        pending = [(None, dict(event))]
        depth = 0
        while pending and depth <= len(self._detectors):
            level = []
            for producer, current in pending:
                for name in self._order:
                    detector = self._detectors[name]
                    subscribed = detector["subscribes"]
                    if producer is None:
                        if subscribed:
                            continue
                    else:
                        if producer not in subscribed:
                            continue
                        if current.get(_STAMP_KEY) != self._stamp:
                            continue
                    try:
                        produced = self._run_detector(detector, current)
                    except Exception as exc:  # noqa: BLE001 -- isolated
                        self._note_error(name, current, exc)
                        continue
                    if produced is None:
                        continue
                    self._produced += 1
                    if on_match is not None:
                        matched = {k: v for k, v in current.items()
                                   if k != _STAMP_KEY}
                        on_match(detector, matched)
                    public = dict(produced)
                    produced_out.append(public)
                    internal = dict(produced)
                    internal[_STAMP_KEY] = self._stamp
                    level.append((name, internal))
            pending = level
            depth += 1
        return produced_out

    def process_stream(self, events):
        """Run detectors over an iterable of events; return produced events.

        One poisoned detector (or one detector error on one event) never
        drops the stream: the error is counted, journaled, and processing
        continues.
        """
        produced = []
        for event in events:
            produced.extend(self.process(event))
        return produced

    def stats(self):
        return {
            "events_seen": self._events_seen,
            "produced": self._produced,
            "detector_errors": self._errors,
            "detectors": len(self._detectors),
        }

    def journal_entries(self):
        return list(self._journal)


class AlertPolicyError(Exception):
    """Loud deployment-policy refusal.

    Raised when a sink policy targets an unknown detector or exception,
    has a bad shape, or carries override values that do not align with
    the exception block. A typo'd policy must never silently do nothing
    (that would be fail-open): it refuses at set time.
    """


class AlertSinkError(Exception):
    """Operational sink error (e.g. evaluating an unknown detector)."""


class AlertSink:
    """Falco-style alert discipline over a :class:`DetectorEngine`.

    The engine is the detection half (match -> produced events); the sink
    is the alert half: every detector match is evaluated against the
    detector's ``exceptions`` blocks (as modified by deployment policy)
    and turned into a structured alert record appended to the journal:

    * ``alert`` -- stable detector, no exception matched, declared
      priority carried verbatim. This is the only record type that may
      page anyone.
    * ``suppressed`` -- an enabled exception block matched. The ALERT is
      suppressed, never the produced event (detection flows on); the
      record names the suppressing exception as the reason. Suppressions
      are journaled, never silently dropped.
    * ``observation`` -- experimental maturity (observe-only), or a
      stable detector with no declared priority (never inflated to a
      ladder value). The reason is recorded.

    Deployment policy (``policy`` dict, validated LOUD at set time)::

        {"exceptions": {"<detector>": {"<exception>": {
            "enabled": False,            # disable: cannot suppress
            "values": [[...], ...],      # replace the block's values
        }}}}

    Each exception block is independently overridable/disablable without
    touching the rule. A *disabled* exception fails closed to alert: it
    cannot suppress, and if it would have matched, the re-arming is
    journaled in the record's ``exception_decision["disabled_but_matched"]``
    -- disabling an exception never silently re-arms the rule.

    ``journal_path`` (optional) appends every record as a JSONL line to a
    durable journal file, byte-equal to the in-memory journal.
    """

    _POLICY_TOP_KEYS = frozenset(["exceptions"])
    _POLICY_OVERRIDE_KEYS = frozenset(["enabled", "values"])

    def __init__(self, engine, policy=None, journal_path=None):
        if not isinstance(engine, DetectorEngine):
            raise TypeError("engine must be a DetectorEngine, got %r"
                            % (type(engine),))
        self._engine = engine
        self._journal = []
        self._seq = 0
        self._journal_path = journal_path
        self._policy = {}
        if policy is not None:
            self.set_policy(policy)

    # ------------------------------------------------------- policy

    def set_policy(self, policy):
        """Replace the deployment policy (validated LOUD, fail-closed)."""
        self._policy = self._validate_policy(policy)

    def policy(self):
        """The current deployment policy (a copy)."""
        return copy.deepcopy(self._policy)

    def _validate_policy(self, policy):
        if not isinstance(policy, dict):
            raise AlertPolicyError(
                "policy must be a dict, got %r" % (policy,))
        unknown = set(policy) - self._POLICY_TOP_KEYS
        if unknown:
            raise AlertPolicyError(
                "policy has unknown keys: %r" % (sorted(unknown),))
        detectors = self._engine.detectors
        validated = {}
        for det_name, overrides in policy.get("exceptions", {}).items():
            if det_name not in detectors:
                raise AlertPolicyError(
                    "policy targets unknown detector: %r" % (det_name,))
            if not isinstance(overrides, dict):
                raise AlertPolicyError(
                    "policy overrides for %r must be a dict" % (det_name,))
            blocks = {b["name"]: b
                      for b in detectors[det_name].get("exceptions", [])}
            det_validated = {}
            for exc_name, override in overrides.items():
                if exc_name not in blocks:
                    raise AlertPolicyError(
                        "policy targets unknown exception %r on "
                        "detector %r" % (exc_name, det_name))
                if not isinstance(override, dict):
                    raise AlertPolicyError(
                        "policy override for %r must be a dict"
                        % (exc_name,))
                bad = set(override) - self._POLICY_OVERRIDE_KEYS
                if bad:
                    raise AlertPolicyError(
                        "policy override for %r has unknown keys: %r"
                        % (exc_name, sorted(bad)))
                entry = {}
                if "enabled" in override:
                    if not isinstance(override["enabled"], bool):
                        raise AlertPolicyError(
                            "policy override %r 'enabled' must be a bool"
                            % (exc_name,))
                    entry["enabled"] = override["enabled"]
                if "values" in override:
                    entry["values"] = self._validate_policy_values(
                        exc_name, blocks[exc_name], override["values"])
                det_validated[exc_name] = entry
            validated[det_name] = det_validated
        return validated

    @staticmethod
    def _validate_policy_values(exc_name, block, values):
        want = len(block["fields"])
        if (not isinstance(values, list) or len(values) != want
                or any(not isinstance(v, list) or not v
                       or not all(_is_scalar(x) for x in v)
                       for v in values)):
            raise AlertPolicyError(
                "policy values for exception %r must be %d non-empty "
                "scalar lists (aligned with the block's fields)"
                % (exc_name, want))
        return copy.deepcopy(values)

    # ----------------------------------------------------- evaluation

    def _effective_block(self, det_name, block):
        """The block as modified by deployment policy (values override)."""
        override = self._policy.get(det_name, {}).get(block["name"], {})
        if "values" not in override:
            return block, override.get("enabled", True)
        effective = dict(block)
        effective["values"] = override["values"]
        return effective, override.get("enabled", True)

    def _evaluate_exceptions(self, definition, event):
        """Evaluate every exception block; return the exception decision.

        Blocks are ORed (any enabled matching block suppresses); tuples
        inside a block are ANDed. A block disabled by policy can never
        suppress -- but if it *would* have matched, it is listed in
        ``disabled_but_matched`` so the re-arming is never silent. An
        exception check that errors fails closed to alert (no suppression).
        """
        det_name = definition["name"]
        evaluated = []
        matched = []
        disabled_but_matched = []
        suppressing = None
        for block in definition.get("exceptions", []):
            exc_name = block["name"]
            evaluated.append(exc_name)
            effective, enabled = self._effective_block(det_name, block)
            try:
                does_match = _exception_block_matches(effective, event)
            except Exception:  # noqa: BLE001 -- fail closed to alert
                does_match = False
            if not does_match:
                continue
            matched.append(exc_name)
            if not enabled:
                disabled_but_matched.append(exc_name)
                continue
            if suppressing is None:
                suppressing = exc_name
        return {
            "evaluated": evaluated,
            "matched": matched,
            "disabled_but_matched": disabled_but_matched,
            "suppressing_exception": suppressing,
            "decision": ("suppressed" if suppressing is not None
                         else "no-suppression"),
        }

    def _record(self, definition, event):
        name = definition["name"]
        maturity = definition.get("maturity", "stable")
        priority = definition.get("priority")
        exc_decision = self._evaluate_exceptions(definition, event)
        if maturity == "experimental":
            record_type = "observation"
            reason = ("experimental maturity: observations only; this "
                      "detector cannot gate enforcement decisions")
        elif exc_decision["suppressing_exception"] is not None:
            record_type = "suppressed"
            reason = ("exception %r matched (allowlist); alert suppressed, "
                      "detection unaffected"
                      % (exc_decision["suppressing_exception"],))
        elif priority is None:
            record_type = "observation"
            reason = ("no priority declared on the fixed ladder; recorded "
                      "as an observation, never inflated to a ladder value")
        else:
            record_type = "alert"
            reason = None
        record = {
            "record_type": record_type,
            "seq": self._seq,
            "detector": name,
            "detector_version": definition["version"],
            "priority": priority,
            "maturity": maturity,
            "event_digest": _event_digest(event),
            "exception_decision": exc_decision,
            "reason": reason,
        }
        self._seq += 1
        self._journal.append(record)
        if self._journal_path is not None:
            with open(self._journal_path, "a",
                       encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True,
                                        separators=(",", ":"),
                                        ensure_ascii=True, default=str)
                             + "\n")
        return record

    def evaluate(self, detector, event):
        """Evaluate one matched detector -> journaled alert record.

        ``detector`` is a validated definition dict or a registered
        detector name; the definition is always re-resolved from the
        engine (a caller cannot smuggle a tampered definition). Returns
        the structured record (alert / suppressed / observation).
        """
        name = (detector.get("name") if isinstance(detector, dict)
                else detector)
        definitions = self._engine.detectors
        if name not in definitions:
            raise AlertSinkError("unknown detector: %r" % (name,))
        if not isinstance(event, dict):
            raise TypeError("event must be a dict, got %r" % (type(event),))
        return self._record(definitions[name], event)

    def process(self, event):
        """Run the engine over one event, journaling every match.

        Returns the engine's produced events. Exceptions suppress ALERTS,
        never produced events: detection flows on while the suppression
        is journaled. Every match is journaled exactly once (alert,
        suppressed, or observation -- never silently dropped).
        """
        matches = []

        def _hook(detector, matched_event):
            matches.append((detector["name"], matched_event))

        produced = self._engine.process(event, on_match=_hook)
        for det_name, matched_event in matches:
            self.evaluate(det_name, matched_event)
        return produced

    def process_stream(self, events):
        """Run the sink over an iterable of events; return produced events."""
        produced = []
        for event in events:
            produced.extend(self.process(event))
        return produced

    def may_gate_enforcement(self, detector_name):
        """Can this detector's matches gate an enforcement decision?

        Experimental detectors are observation-only (False). Unknown
        names fail closed (False). Stable detectors may gate (True).
        """
        definition = self._engine.detectors.get(detector_name)
        if definition is None:
            return False
        return definition.get("maturity", "stable") == "stable"

    def journal_entries(self):
        """The alert journal (in-memory copy; see journal_path for durable)."""
        return list(self._journal)


# ------------------------------------------------- sample detectors

SAMPLE_DETECTORS = [
    {
        "name": "credential-swap-outside-allowlist",
        "version": "1.0.0",
        "description": "Credential material is swapped for a host outside "
                       "the allowlist of credential-bearing hosts. The "
                       "sentinel-substitution lane (wave-178) swaps real "
                       "credentials only for authorized hosts; a swap "
                       "targeting any other host is exfiltration-shaped.",
        "event_selector": {"type": "credential_swap"},
        "predicates": [
            {"field": "host", "op": "exists"},
            {"field": "host", "op": "not_in",
             "value": ["vault.internal.example", "kms.internal.example"]},
        ],
        "produces": {
            "event_name": "credential_swap_outside_allowlist",
            "event_schema_version": "1.0.0",
            "fields": {
                "host": {"from_field": "host"},
                "agent_id": {"from_field": "agent_id"},
                "credential_id": {"from_field": "credential_id"},
                "severity": {"literal": "high"},
            },
        },
        "threat": {
            "mitre": ["T1550"],
            "severity": "high",
            "description": "Use Alternate Authentication Material: "
                           "credential swapped outside allowlisted hosts",
        },
        "subscribes": [],
    },
    {
        "name": "policy-version-rollback",
        "version": "1.0.0",
        "description": "An observed policy version is below the expected "
                       "minimum -- the shape of a rollback or a downgrade "
                       "attack against governance policy.",
        "event_selector": {"type": "policy_version_observed"},
        "predicates": [
            {"field": "observed_version", "op": "exists"},
            {"field": "expected_min_version", "op": "exists"},
            {"field": "observed_version", "op": "lt",
             "other_field": "expected_min_version"},
        ],
        "produces": {
            "event_name": "policy_rollback_detected",
            "event_schema_version": "1.0.0",
            "fields": {
                "policy_id": {"from_field": "policy_id"},
                "observed_version": {"from_field": "observed_version"},
                "expected_min_version":
                    {"from_field": "expected_min_version"},
            },
        },
        "threat": {
            "mitre": ["T1562"],
            "severity": "high",
            "description": "Impair Defenses: policy version moved below "
                           "the expected minimum",
        },
        "subscribes": [],
    },
    {
        "name": "quorum-ballot-open",
        "version": "1.0.0",
        "description": "Base context detector: an open quorum ballot. "
                       "Feeds quorum-ballot-stall via the subscription "
                       "chain.",
        "event_selector": {"type": "ballot"},
        "predicates": [
            {"field": "state", "op": "eq", "value": "open"},
        ],
        "produces": {
            "event_name": "ballot_open",
            "event_schema_version": "1.0.0",
            "fields": {
                "ballot_id": {"from_field": "ballot_id"},
                "votes_cast": {"from_field": "votes_cast"},
                "quorum": {"from_field": "quorum"},
                "elapsed_s": {"from_field": "elapsed_s"},
            },
        },
        "threat": {
            "severity": "low",
            "description": "context: an open quorum ballot "
                           "(feeds stall detection)",
        },
        "subscribes": [],
    },
    {
        "name": "quorum-ballot-stall",
        "version": "1.0.0",
        "description": "An open quorum ballot has not reached quorum past "
                       "the stall threshold -- governance is stuck and no "
                       "decision can be produced.",
        "event_selector": {"produced_by": "quorum-ballot-open"},
        "predicates": [
            {"field": "fields.votes_cast", "op": "exists"},
            {"field": "fields.quorum", "op": "exists"},
            {"field": "fields.votes_cast", "op": "lt",
             "other_field": "fields.quorum"},
            {"field": "fields.elapsed_s", "op": "gt", "value": 300},
        ],
        "produces": {
            "event_name": "quorum_stall_detected",
            "event_schema_version": "1.0.0",
            "fields": {
                "ballot_id": {"from_field": "fields.ballot_id"},
                "votes_cast": {"from_field": "fields.votes_cast"},
                "quorum": {"from_field": "fields.quorum"},
                "elapsed_s": {"from_field": "fields.elapsed_s"},
            },
        },
        "threat": {
            "severity": "medium",
            "description": "quorum not reached: open ballot stalled past "
                           "the stall threshold",
        },
        "subscribes": ["quorum-ballot-open"],
    },
]
