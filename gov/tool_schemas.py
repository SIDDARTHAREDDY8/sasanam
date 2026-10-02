"""Declarative typed schemas for tool arguments (wave-294 lane 4, ADAPT).

PATTERN LINEAGE: pydantic/pydantic-ai (MIT) -- declarative typed field
schemas validated at call time before the tool body runs. This is a
clean-room stdlib-only reimplementation of the *mechanism* (typed,
bounded, frozen schemas; fail-closed validation); no upstream code is
vendored.

Mechanisms adapted:
* Typed schemas -- every tool's arguments are declared with field types
  (string/integer/boolean/enum, bounded list/dict of typed members,
  optional-with-default) and validated at call time BEFORE the tool body
  runs. Type/range/shape mismatches refuse coded.
* Closed inventory -- the schema set closes the tool inventory: a call to
  an undeclared tool refuses coded ``toolcall-schema-unknown-tool``;
  undeclared args refuse coded ``toolcall-schema-invalid``.
* Compile-time freeze -- the schema set is validated and deep-frozen at
  compile (the F330/F340 pattern used by gov/tool_call_policy.py); a
  post-compile in-process mutation fails at the source instead of
  silently changing decisions under a still-valid digest.
* Credential-field gate -- any field NAME that looks like a credential
  refuses coded ``toolcall-schema-secret-field`` AT COMPILE TIME;
  secret-shaped string VALUES refuse coded ``toolcall-secret-in-args``
  at call time. Credentials travel in typed execution context, never in
  the call schema (generalizes the wave-27 sentinel work and wave-293's
  secret-in-args refusal).

Composition, not duplication:
* This module decides SHAPE (do these args match the declared types and
  bounds). ``gov/tool_call_policy.py`` decides AUTHORIZATION (may this
  caller invoke this tool with these args). Schema validation runs as a
  pre-filter inside ``CompiledToolPolicy.decide`` when a schema registry
  is bound (opt-in via ``bind_schema_registry``), right after the
  authn and declared-sequence layers: schema violations surface as coded
  ``toolcall-schema-*`` DENY decisions at the same decide seam, and the
  validated args (with defaults injected) flow into the policy rules.
  With no registry bound, ``decide`` behaves exactly as before.

Honest boundary (documented, not hidden): validation decides on the
DECLARED arg values handed to :meth:`validate_args`; it cannot see
whether the tool body honors the declared schema (actual-vs-claimed
enforcement is post-v1, Tetragon-class observation), same as the
policy layer. Pattern full-match semantics are documented in
:meth:`CompiledToolSchemaSet.validate_args`.

All refusals are LOUD: coded :class:`ToolSchemaError`, never silent.
"""

import hashlib
import json
import re
from types import MappingProxyType

# Shared backtracking-safety gate (F325 mechanism): schema ``pattern``
# fields are caller-triggerable at decide time, so they route the same
# static analysis that guards policy arg-matcher regexes (F339).
from gov.attack_manifest import RegexUnsafe as _RegexUnsafe
from gov.attack_manifest import check_regex_safety as _rx_safety_gate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_SET_FORMAT = "sasanam-tool-schema-set/v1"

#: Closed field-type vocabulary.
FIELD_TYPES = frozenset({"string", "integer", "boolean", "enum",
                         "list", "dict"})

#: Compile-time bounds (bounded documents only).
MAX_TOOLS = 256
MAX_FIELDS = 64
MAX_NAME_LEN = 128
MAX_NESTING_DEPTH = 4
MAX_ENUM_CHOICES = 256
MAX_PATTERN_LEN = 256
MAX_STRING_LEN_CAP = 65536
MAX_LIST_ITEMS_CAP = 10000
MAX_DICT_ITEMS_CAP = 10000

#: Decision-code vocabulary (registered in gov/decision_codes.py).
SCHEMA_COMPILE_INVALID = "toolcall-schema-compile-invalid"
SCHEMA_INVALID = "toolcall-schema-invalid"
SCHEMA_UNKNOWN_TOOL = "toolcall-schema-unknown-tool"
SCHEMA_SECRET_FIELD = "toolcall-schema-secret-field"

#: Reused for secret-shaped string VALUES at call time (registered for
#: the wave-293 tool-rules seam; same mechanism, same code).
SECRET_IN_ARGS = "toolcall-secret-in-args"

__all__ = [
    "SCHEMA_SET_FORMAT",
    "FIELD_TYPES",
    "ToolSchemaError",
    "CompiledToolSchemaSet",
    "compile_schema_set",
    "validate_args",
    "schema_set_digest",
]


class ToolSchemaError(ValueError):
    """LOUD coded refusal for the tool-schema seam."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical digest + deep freeze (the F330/F340 pattern)
# ---------------------------------------------------------------------------

def _json_default(obj):
    if isinstance(obj, MappingProxyType):
        return dict(obj)
    raise TypeError("object of type %s is not JSON serializable"
                    % type(obj).__name__)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=_json_default).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _freeze(obj):
    """Deep-freeze a validated schema-set document.

    dict -> MappingProxyType, list/tuple -> tuple, set -> frozenset.
    Post-compile in-process mutation then fails at the source instead of
    silently changing decisions under a still-valid digest. Digest-
    transparent: the frozen shape serializes back to the plain JSON form.
    """
    if isinstance(obj, dict):
        return MappingProxyType(
            {key: _freeze(value) for key, value in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(value) for value in obj)
    if isinstance(obj, (set, frozenset)):
        return frozenset(_freeze(value) for value in obj)
    return obj


def schema_set_digest(doc):
    """Content digest of a tool-schema-set document (the pin)."""
    return _digest(doc)


# ---------------------------------------------------------------------------
# Credential gates: name-shaped (compile time) and value-shaped (call time)
# ---------------------------------------------------------------------------

#: Bounded token list. A field name that normalizes (lowercase, strip
#: non-alphanumerics) to CONTAIN any of these refuses at compile time.
_CREDENTIAL_TOKENS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "apikey",
    "clientsecret", "accesstoken", "refreshtoken", "authtoken",
    "privatekey", "bearer", "credential", "credentials", "oauth",
    "sessiontoken", "clientid", "passphrase",
})


def _normalize_name(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _is_credential_name(name):
    norm = _normalize_name(name)
    return any(tok in norm for tok in _CREDENTIAL_TOKENS)


#: Bounded secret-value pattern set (same mechanism as
#: gov/tool_rules.py's gate: secrets travel via typed context, never
#: tool args; fail-closed on match).
_SECRET_VALUE_PATTERNS = (
    r"sk-[A-Za-z0-9]{16,}",
    r"gh[pousr]_[A-Za-z0-9]{16,}",
    r"xox[baprs]-[A-Za-z0-9-]{8,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
)
_SECRET_VALUE_RE = re.compile("|".join("(?:%s)" % p
                                       for p in _SECRET_VALUE_PATTERNS))


def _secret_value_found(value, depth, budget):
    """True iff a secret-shaped string occurs in value (bounded walk)."""
    if depth > MAX_NESTING_DEPTH or budget[0] <= 0:
        return False
    if isinstance(value, str):
        chunk = value[:budget[0]]
        budget[0] -= len(chunk)
        return _SECRET_VALUE_RE.search(chunk) is not None
    if isinstance(value, dict):
        return any(_secret_value_found(item, depth + 1, budget)
                   for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_secret_value_found(item, depth + 1, budget)
                   for item in value)
    return False


# ---------------------------------------------------------------------------
# Compile-time validation (fail-closed)
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]+")


def _refuse_compile(message, code=SCHEMA_COMPILE_INVALID):
    raise ToolSchemaError("tool-schema-set compile refused: %s" % (message,),
                         code=code)


def _check_name(value, what, credential_gate=False):
    if not isinstance(value, str) or not value \
            or len(value) > MAX_NAME_LEN \
            or _NAME_RE.fullmatch(value) is None:
        _refuse_compile("%s must be a non-empty string of [A-Za-z0-9_.:-] "
                        "(<= %d chars); got %r"
                        % (what, MAX_NAME_LEN, value))
    # The credential-field gate applies to FIELD names only: a schema-set
    # or tool may legitimately be named for a credential domain
    # ("secrets-tools"); a FIELD may never carry a credential.
    if credential_gate and _is_credential_name(value):
        _refuse_compile("%s %r names a credential-like field; credentials "
                        "travel in typed execution context, never in the "
                        "call schema" % (what, value),
                        code=SCHEMA_SECRET_FIELD)
    return value


def _check_bounds(value, what, lo, hi):
    if not isinstance(value, int) or isinstance(value, bool) \
            or value < lo or value > hi:
        _refuse_compile("%s must be an int in [%d, %d]; got %r"
                        % (what, lo, hi, value))
    return value


def _compile_string(spec, where, depth):
    out = {"type": "string"}
    min_len = spec.get("min_len", 0)
    max_len = spec.get("max_len")
    if max_len is None:
        _refuse_compile("%s: string needs an explicit max_len (bounded "
                        "strings only)" % (where,))
    _check_bounds(min_len, "%s min_len" % (where,), 0, MAX_STRING_LEN_CAP)
    _check_bounds(max_len, "%s max_len" % (where,), 0, MAX_STRING_LEN_CAP)
    if min_len > max_len:
        _refuse_compile("%s: min_len > max_len" % (where,))
    out["min_len"] = min_len
    out["max_len"] = max_len
    pattern = spec.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str) or not pattern \
                or len(pattern) > MAX_PATTERN_LEN:
            _refuse_compile("%s: pattern must be a non-empty string of "
                            "<= %d chars" % (where, MAX_PATTERN_LEN))
        try:
            re.compile(pattern)
        except re.error as e:
            _refuse_compile("%s: pattern does not compile: %s"
                            % (where, e))
        try:
            _rx_safety_gate(pattern, "%s pattern" % (where,))
        except _RegexUnsafe as e:
            _refuse_compile("%s: %s" % (where, e))
        out["pattern"] = pattern
    choices = spec.get("choices")
    if choices is not None:
        _check_choices(choices, where)
        out["choices"] = tuple(choices)
    return out


def _check_choices(choices, where):
    if not isinstance(choices, list) or not choices \
            or len(choices) > MAX_ENUM_CHOICES \
            or not all(isinstance(c, str) and c for c in choices) \
            or len(set(choices)) != len(choices):
        _refuse_compile("%s: choices must be a non-empty list of unique "
                        "non-empty strings (<= %d)" % (where, MAX_ENUM_CHOICES))


def _compile_integer(spec, where, depth):
    min_value = spec.get("min_value")
    max_value = spec.get("max_value")
    if min_value is None or max_value is None:
        _refuse_compile("%s: integer needs explicit min_value and "
                        "max_value (bounded integers only)" % (where,))
    for label, value in (("min_value", min_value),
                         ("max_value", max_value)):
        if not isinstance(value, int) or isinstance(value, bool):
            _refuse_compile("%s: %s must be an int; got %r"
                            % (where, label, value))
    if min_value > max_value:
        _refuse_compile("%s: min_value > max_value" % (where,))
    return {"type": "integer", "min_value": min_value,
            "max_value": max_value}


def _compile_field(spec, where, depth):
    """Compile one field spec (recursive, depth-bounded)."""
    if depth > MAX_NESTING_DEPTH:
        _refuse_compile("%s: schema nesting exceeds the %d-level bound"
                        % (where, MAX_NESTING_DEPTH))
    if not isinstance(spec, dict):
        _refuse_compile("%s must be a dict; got %r"
                        % (where, type(spec)))
    ftype = spec.get("type")
    if ftype not in FIELD_TYPES:
        _refuse_compile("%s has unknown type %r (closed: %s)"
                        % (where, ftype,
                           ", ".join(sorted(FIELD_TYPES))))
    if ftype == "string":
        allowed = {"type", "min_len", "max_len", "pattern", "choices",
                   "optional", "default"}
        out = _compile_string(spec, where, depth)
    elif ftype == "integer":
        allowed = {"type", "min_value", "max_value", "optional", "default"}
        out = _compile_integer(spec, where, depth)
    elif ftype == "boolean":
        allowed = {"type", "optional", "default"}
        out = {"type": "boolean"}
    elif ftype == "enum":
        allowed = {"type", "choices", "optional", "default"}
        _check_choices(spec.get("choices"), where)
        out = {"type": "enum", "choices": tuple(spec["choices"])}
    elif ftype == "list":
        allowed = {"type", "element", "min_items", "max_items",
                   "optional", "default"}
        element = spec.get("element")
        if element is None:
            _refuse_compile("%s: list needs an 'element' field spec"
                            % (where,))
        min_items = spec.get("min_items", 0)
        max_items = spec.get("max_items")
        if max_items is None:
            _refuse_compile("%s: list needs an explicit max_items "
                            "(bounded lists only)" % (where,))
        _check_bounds(min_items, "%s min_items" % (where,), 0,
                      MAX_LIST_ITEMS_CAP)
        _check_bounds(max_items, "%s max_items" % (where,), 0,
                      MAX_LIST_ITEMS_CAP)
        if min_items > max_items:
            _refuse_compile("%s: min_items > max_items" % (where,))
        out = {"type": "list",
               "element": _compile_field(element, "%s.element" % (where,),
                                         depth + 1),
               "min_items": min_items, "max_items": max_items}
    else:  # dict
        allowed = {"type", "value", "min_items", "max_items",
                   "optional", "default"}
        value = spec.get("value")
        if value is None:
            _refuse_compile("%s: dict needs a 'value' field spec"
                            % (where,))
        min_items = spec.get("min_items", 0)
        max_items = spec.get("max_items")
        if max_items is None:
            _refuse_compile("%s: dict needs an explicit max_items "
                            "(bounded dicts only)" % (where,))
        _check_bounds(min_items, "%s min_items" % (where,), 0,
                      MAX_DICT_ITEMS_CAP)
        _check_bounds(max_items, "%s max_items" % (where,), 0,
                      MAX_DICT_ITEMS_CAP)
        if min_items > max_items:
            _refuse_compile("%s: min_items > max_items" % (where,))
        out = {"type": "dict",
               "value": _compile_field(value, "%s.value" % (where,),
                                       depth + 1),
               "min_items": min_items, "max_items": max_items}
    for key in spec:
        if key not in allowed:
            _refuse_compile("%s has unknown key %r" % (where, key))
    optional = spec.get("optional", False)
    if not isinstance(optional, bool):
        _refuse_compile("%s: optional must be a bool" % (where,))
    out["optional"] = optional
    if "default" in spec:
        if not optional:
            _refuse_compile("%s: default requires optional=true"
                            % (where,))
        default = spec["default"]
        # A default that fails its own field's validation is a broken
        # declaration, not a caller error: translate to the compile-time
        # code (never let a caller-facing code escape at compile).
        try:
            _validate_value(out, default, where + ".default",
                            for_default=True)
        except ToolSchemaError as e:
            _refuse_compile("invalid default for %s: %s" % (where, e))
        out["default"] = default
    return out

# ---------------------------------------------------------------------------
# Call-time validation (fail-closed). Shared with compile-time default
# validation: a declared default must itself satisfy the field.
# ---------------------------------------------------------------------------

def _refuse_invalid(message, code=SCHEMA_INVALID):
    raise ToolSchemaError("tool-call schema refused: %s" % (message,),
                         code=code)


def _validate_value(field, value, where, for_default=False):
    """Validate one value against a COMPILED field spec.

    Returns a fresh (alias-free) validated value. Refuses coded on any
    type/range/shape mismatch. ``pattern`` uses FULLMATCH semantics
    (documented); enums match by equality against the declared choices.
    """
    ftype = field["type"]
    if value is None:
        _refuse_invalid("%s: null is not a valid %s (use optional "
                        "fields for absence)" % (where, ftype))
    if ftype == "string":
        if not isinstance(value, str):
            _refuse_invalid("%s: expected string; got %s"
                            % (where, type(value).__name__))
        if not (field["min_len"] <= len(value) <= field["max_len"]):
            _refuse_invalid(
                "%s: string length %d outside [%d, %d]"
                % (where, len(value), field["min_len"], field["max_len"]))
        pattern = field.get("pattern")
        if pattern is not None \
                and re.fullmatch(pattern, value) is None:
            _refuse_invalid("%s: string does not fully match the "
                            "declared pattern" % (where,))
        choices = field.get("choices")
        if choices is not None and value not in choices:
            _refuse_invalid("%s: string not in the declared choices"
                            % (where,))
        if not for_default and _secret_value_found(
                value, 0, [MAX_STRING_LEN_CAP]):
            raise ToolSchemaError(
                "tool-call refused: secret-shaped value in arg %r; "
                "secrets travel via typed context, never tool args"
                % (where,), code=SECRET_IN_ARGS)
        return value
    if ftype == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            _refuse_invalid("%s: expected integer; got %s"
                            % (where, type(value).__name__))
        if not (field["min_value"] <= value <= field["max_value"]):
            _refuse_invalid(
                "%s: integer %d outside [%d, %d]"
                % (where, value, field["min_value"], field["max_value"]))
        return value
    if ftype == "boolean":
        if type(value) is not bool:
            _refuse_invalid("%s: expected boolean; got %s"
                            % (where, type(value).__name__))
        return value
    if ftype == "enum":
        if not isinstance(value, str) or value not in field["choices"]:
            _refuse_invalid("%s: expected one of %s; got %r"
                            % (where, list(field["choices"]), value))
        return value
    if ftype == "list":
        if not isinstance(value, list):
            _refuse_invalid("%s: expected list; got %s"
                            % (where, type(value).__name__))
        if not (field["min_items"] <= len(value) <= field["max_items"]):
            _refuse_invalid(
                "%s: list length %d outside [%d, %d]"
                % (where, len(value), field["min_items"],
                   field["max_items"]))
        element = field["element"]
        return [_validate_value(element, item, "%s[%d]" % (where, i))
                for i, item in enumerate(value)]
    # dict
    if not isinstance(value, dict):
        _refuse_invalid("%s: expected dict; got %s"
                        % (where, type(value).__name__))
    if not (field["min_items"] <= len(value) <= field["max_items"]):
        _refuse_invalid(
            "%s: dict size %d outside [%d, %d]"
            % (where, len(value), field["min_items"], field["max_items"]))
    for key in value:
        if not isinstance(key, str):
            _refuse_invalid("%s: dict keys must be strings; got %s"
                            % (where, type(key).__name__))
    value_spec = field["value"]
    return {key: _validate_value(value_spec, item, "%s.%s" % (where, key))
            for key, item in value.items()}


def compile_schema_set(doc):
    """Validate a schema-set document fail-closed and compile it.

    Returns a frozen :class:`CompiledToolSchemaSet`. Any shape violation
    refuses LOUD with coded ``toolcall-schema-compile-invalid``; any
    credential-like field name refuses coded
    ``toolcall-schema-secret-field``.
    """
    if not isinstance(doc, dict):
        _refuse_compile("schema set must be a dict; got %r"
                        % (type(doc),))
    for key in doc:
        if key not in ("format", "name", "tools"):
            _refuse_compile("unknown top-level key %r" % (key,))
    if doc.get("format") != SCHEMA_SET_FORMAT:
        _refuse_compile("format must be %r; got %r"
                        % (SCHEMA_SET_FORMAT, doc.get("format")))
    _check_name(doc.get("name"), "name")
    tools = doc.get("tools")
    if not isinstance(tools, dict) or not tools \
            or len(tools) > MAX_TOOLS:
        _refuse_compile("tools must be a non-empty dict (<= %d tools)"
                        % (MAX_TOOLS,))
    compiled_tools = {}
    for tool_name, tool_spec in tools.items():
        _check_name(tool_name, "tool")
        if tool_name in compiled_tools:
            _refuse_compile("duplicate tool %r" % (tool_name,))
        where = "tools.%s" % (tool_name,)
        if not isinstance(tool_spec, dict):
            _refuse_compile("%s must be a dict" % (where,))
        for key in tool_spec:
            if key not in ("args",):
                _refuse_compile("%s has unknown key %r" % (where, key))
        args = tool_spec.get("args", {})
        if not isinstance(args, dict) or len(args) > MAX_FIELDS:
            _refuse_compile("%s: args must be a dict of <= %d fields"
                            % (where, MAX_FIELDS))
        compiled_args = {}
        for field_name, field_spec in args.items():
            _check_name(field_name, "%s field" % (where,),
                        credential_gate=True)
            if field_name in compiled_args:
                _refuse_compile("%s: duplicate field %r"
                                % (where, field_name))
            compiled_args[field_name] = _compile_field(
                field_spec, "%s.args.%s" % (where, field_name), 0)
        compiled_tools[tool_name] = {"args": compiled_args}
    frozen = _freeze({
        "name": doc["name"],
        "tools": compiled_tools,
    })
    return CompiledToolSchemaSet(frozen)


class CompiledToolSchemaSet:
    """One compiled tool-schema set: the enforceable shape checker.

    IMMUTABLE after compilation (the F330/F340 pattern): ``_doc`` is
    deep-frozen, so post-compile in-process mutation fails at the source.
    """

    def __init__(self, frozen_doc):
        # The document arrives frozen from compile_schema_set; _freeze is
        # idempotent over frozen structures, so direct construction with
        # an unfrozen dict is frozen here too. (No deepcopy: the frozen
        # MappingProxyType cannot be pickled/copied, and freezing already
        # severs every mutable alias.)
        self._doc = _freeze(frozen_doc)
        self.digest = _digest(self._doc)

    @property
    def name(self):
        return self._doc["name"]

    @property
    def tools(self):
        """The closed tool inventory: undeclared tools do not exist."""
        return tuple(sorted(self._doc["tools"]))

    def schema_for(self, tool):
        """Return the frozen arg-field mapping for a declared tool."""
        try:
            return self._doc["tools"][tool]["args"]
        except (KeyError, TypeError):
            raise ToolSchemaError(
                "undeclared tool %r; the bound schema set closes the "
                "tool inventory" % (tool,), code=SCHEMA_UNKNOWN_TOOL)

    def _refuse_shape(self, message, code=SCHEMA_INVALID):
        raise ToolSchemaError("tool-call schema refused: %s" % (message,),
                             code=code)

    def validate_args(self, tool, args=None):
        """Validate one tool call's args against the declared schema.

        Returns an alias-free dict of the validated args in declaration
        order, with optional defaults injected. Any violation --
        undeclared tool, ill-typed args, unknown arg, missing required
        field, type/range/shape mismatch, secret-shaped string value --
        raises coded :class:`ToolSchemaError` (``toolcall-schema-invalid``
        / ``toolcall-schema-unknown-tool`` / ``toolcall-secret-in-args``).
        """
        if not isinstance(tool, str) or not tool:
            self._refuse_shape("tool must be a non-empty string; got %r"
                               % (tool,))
        if args is None:
            args = {}
        if not isinstance(args, dict):
            self._refuse_shape("args must be a dict; got %r"
                               % (type(args),))
        for key in args:
            if not isinstance(key, str):
                self._refuse_shape("args keys must be strings; got %r"
                                   % (key,))
        fields = self.schema_for(tool)
        validated = {}
        for field_name, field in fields.items():
            if field_name in args:
                validated[field_name] = _validate_value(
                    field, args[field_name], "args.%s" % (field_name,))
            elif field["optional"]:
                if "default" in field:
                    validated[field_name] = _validate_value(
                        field, field["default"],
                        "args.%s (default)" % (field_name,),
                        for_default=True)
                # else: absent optional field stays absent
            else:
                self._refuse_shape("missing required arg %r for tool %r"
                                   % (field_name, tool))
        for key in args:
            if key not in fields:
                self._refuse_shape("undeclared arg %r for tool %r; the "
                                   "schema is closed" % (key, tool))
        return validated


def validate_args(schema_set, tool, args=None):
    """Validate args against a compiled schema set (module-level seam)."""
    if not isinstance(schema_set, CompiledToolSchemaSet):
        raise ToolSchemaError(
            "validate_args needs a CompiledToolSchemaSet; got %r"
            % (type(schema_set),), code=SCHEMA_COMPILE_INVALID)
    return schema_set.validate_args(tool, args)
