"""Typed actions: commitments that cover WHAT an action means.

A digest over ``{"action": "wire"}`` commits to nothing — the label
carries no semantics, so a verifier cannot tell what was actually
authorized. Typed actions close that gap: an :class:`ActionType`
defines the material fields an action of that type MUST carry, and
the type DEFINITION carries its own digest (computed over the
canonical type body). :func:`bind_action` seals material to a
registered type; the bound digest commits to ``{type_digest,
definition_sha256, type_id, version, material}`` — label, type
definition, AND validation semantics. ``definition_sha256`` is the
digest over the type's validation semantics: the required field
set, each field's declared type, and the depth/count/length
constraints. A re-registered definition with the same type_id and
version but different semantics refuses ``action-semantics-drift``;
legacy (pre-semantics) bindings verify under the original rule —
the pinning never widens old bindings. :func:`verify_typed_action`
re-derives everything from the verifier's registry — a substituted
type definition (same label, different required fields) refuses
``action-type-drift``; mutated material refuses
``action-binding-tampered``. :func:`bind_action_from_json` adds the
raw-JSON seam: duplicate object keys at any depth refuse
``action-duplicate-key``.

Capsule composition (:func:`bind_to_capsule` /
:func:`verify_capsule_typed_action`) seals a typed binding into a
NEW action capsule as digest-linked evidence. ``gov/action_capsule``
is untouched — composition happens through its public seal/verify
seams.

Re-derived prose. Stdlib only. No network. $0.
"""

import hashlib
import json

from .action_capsule import (canonical_json_bytes, seal_capsule,
                            verify_capsule)

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class TypedActionError(Exception):
    """Base class for all typed-action refusals. ``code`` is
    machine-readable; ``reason`` is the exact closed reason string
    (defaults to ``code``). Probes assert ``reason`` byte-for-byte
    where the spec demands it."""

    code = "typed-action-refused"

    def __init__(self, message="", reason=None):
        super().__init__(message)
        self.reason = self.code if reason is None else reason


class _Malformed(TypedActionError):
    code = "typed-action-malformed"


class _TypeUnknown(TypedActionError):
    code = "action-type-unknown"


class _MaterialMissing(TypedActionError):
    code = "action-material-missing"


class _TypeDrift(TypedActionError):
    code = "action-type-drift"


class _BindingTampered(TypedActionError):
    code = "action-binding-tampered"


class _NotBound(TypedActionError):
    code = "typed-action-not-bound"


class _SemanticsDrift(TypedActionError):
    code = "action-semantics-drift"


class _DepthExceeded(TypedActionError):
    code = "action-depth-exceeded"


class _ValueCountExceeded(TypedActionError):
    code = "action-value-count-exceeded"


class _DuplicateKey(TypedActionError):
    code = "action-duplicate-key"


class _TypeMismatch(TypedActionError):
    code = "action-material-type-mismatch"


class _ValueTooLong(TypedActionError):
    code = "action-value-too-long"


# ----------------------------------------------------------------------
# Constants.
# ----------------------------------------------------------------------

TYPED_ACTION_VERSION = 1

# Validation-semantics defaults. A definition built without explicit
# semantics kwargs gets these; the digest still covers them, so an
# explicit choice always differs from the default.
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_VALUES = 128
DEFAULT_MAX_VALUE_LEN = 4096

# Closed vocabulary for declared field types. "any" skips the check;
# every other label is matched with exact type() identity (bool is
# NOT int — a declared "int" field refuses True).
_FIELD_TYPE_LABELS = ("any", "str", "int", "float", "bool",
                      "bytes", "dict", "list", "none")

_TYPE_CHECKS = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "bytes": bytes,
    "dict": dict,
    "list": list,
}


def _type_matches(label, value):
    """Strict declared-type check for one material field."""
    if label == "any":
        return True
    if label == "none":
        return value is None
    return type(value) is _TYPE_CHECKS[label]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _type_digest(type_id, version, required_material) -> str:
    """Digest of the type DEFINITION, over the canonical body.

    The required-material list is sorted for the digest so field
    order is not load-bearing; the definition body keeps the given
    order for readability.
    """
    body = {
        "type_id": type_id,
        "version": version,
        "required_material": sorted(required_material),
    }
    return _digest(canonical_json_bytes(body))


def _definition_sha256(type_id, version, required_material,
                       field_types, max_depth, max_values,
                       max_value_len) -> str:
    """Digest over the type's validation SEMANTICS, not just its
    label.

    Covers the required field set, each field's declared type, and
    the depth/count/length constraints. Field order is not
    load-bearing (sorted for the digest). Two definitions with the
    same type_id and version but different semantics have different
    digests — a silent schema loosening between bind and verify is
    detectable, and the bound digest commits to it.
    """
    fields = sorted(required_material)
    body = {
        "type_id": type_id,
        "version": version,
        "required_material": fields,
        "field_types": {f: field_types[f] for f in fields},
        "max_depth": max_depth,
        "max_values": max_values,
        "max_value_len": max_value_len,
    }
    return _digest(canonical_json_bytes(body))


class ActionType:
    """A typed-action definition: id, version, required material,
    and validation semantics.

    Instances are created through :meth:`build`, which validates
    the definition and computes ``type_digest`` (over the field
    set) and ``definition_sha256`` (over the full validation
    semantics: field set, declared field types, and the
    depth/count/length constraints).
    """

    def __init__(self, type_id, version, required_material,
                 type_digest, field_types, max_depth, max_values,
                 max_value_len, definition_sha256):
        self.type_id = type_id
        self.version = version
        self.required_material = tuple(required_material)
        self.type_digest = type_digest
        self.field_types = dict(field_types)
        self.max_depth = max_depth
        self.max_values = max_values
        self.max_value_len = max_value_len
        self.definition_sha256 = definition_sha256

    @classmethod
    def build(cls, type_id, version, required_material, *,
              field_types=None, max_depth=DEFAULT_MAX_DEPTH,
              max_values=DEFAULT_MAX_VALUES,
              max_value_len=DEFAULT_MAX_VALUE_LEN):
        """Build and validate a type definition.

        ``type_id`` and ``version`` must be non-empty (version a
        positive int); ``required_material`` a non-empty list of
        non-empty, printable, unique field names. Optional
        semantics kwargs: ``field_types`` maps a subset of the
        required fields to closed type labels (unmentioned fields
        default to ``"any"``); ``max_depth``/``max_values``/
        ``max_value_len`` bound nesting depth, leaf-value count,
        and scalar length. Every choice — including the defaults —
        is covered by ``definition_sha256``.
        """
        if (not isinstance(type_id, str) or not type_id
                or not type_id.isprintable()):
            raise _Malformed("type_id must be a non-empty string")
        if (not isinstance(version, int) or isinstance(version, bool)
                or version < 1):
            raise _Malformed("version must be a positive integer")
        if (not isinstance(required_material, (list, tuple))
                or not required_material):
            raise _Malformed(
                "required_material must be a non-empty list")
        fields = list(required_material)
        if any(not isinstance(f, str) or not f or not f.isprintable()
               for f in fields):
            raise _Malformed(
                "required_material fields must be non-empty strings")
        if len(set(fields)) != len(fields):
            raise _Malformed("required_material fields must be unique")
        types = {}
        if field_types is not None:
            if not isinstance(field_types, dict):
                raise _Malformed("field_types must be a dict")
            for field, label in field_types.items():
                if field not in fields:
                    raise _Malformed(
                        "field_types names unknown field %r" % (field,))
                if label not in _FIELD_TYPE_LABELS:
                    raise _Malformed(
                        "unknown field type label %r" % (label,))
                types[field] = label
        for field in fields:
            types.setdefault(field, "any")
        for name, value in (("max_depth", max_depth),
                            ("max_values", max_values),
                            ("max_value_len", max_value_len)):
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 1):
                raise _Malformed(
                    "%s must be a positive integer" % name)
        return cls(type_id, version, fields,
                   _type_digest(type_id, version, fields),
                   types, max_depth, max_values, max_value_len,
                   _definition_sha256(type_id, version, fields, types,
                                      max_depth, max_values,
                                      max_value_len))

    def as_dict(self):
        return {
            "v": TYPED_ACTION_VERSION,
            "type_id": self.type_id,
            "version": self.version,
            "required_material": list(self.required_material),
            "type_digest": self.type_digest,
            "field_types": dict(self.field_types),
            "max_depth": self.max_depth,
            "max_values": self.max_values,
            "max_value_len": self.max_value_len,
            "definition_sha256": self.definition_sha256,
        }


class TypeRegistry:
    """Verifier-side registry of action-type definitions.

    The registry is the verifier's trusted store: verification
    re-derives digests from the definitions held here, so a type
    substitution anywhere upstream of the registry fails closed.
    """

    def __init__(self):
        self._types = {}

    @staticmethod
    def _key(type_id, version):
        return (type_id, version)

    def register(self, action_type):
        """Register an :class:`ActionType`. Overwrites an existing
        definition under the same (type_id, version) — the
        registry is the verifier's own store. Returns the
        registered definition as a dict."""
        if not isinstance(action_type, ActionType):
            raise _Malformed(
                "registry accepts only ActionType definitions")
        self._types[self._key(action_type.type_id,
                              action_type.version)] = action_type
        return action_type.as_dict()

    def lookup(self, type_id, version):
        """Return the registered :class:`ActionType`, or None."""
        return self._types.get(self._key(type_id, version))


def _require_known(type_id, version, registry):
    """Return the registered :class:`ActionType` for
    ``(type_id, version)``; refuse ``action-type-unknown`` when the
    verifier's registry holds no such definition."""
    definition = registry.lookup(type_id, version)
    if definition is None:
        raise _TypeUnknown(
            "no registered action type %r version %r"
            % (type_id, version))
    return definition


def _require_material(definition, material):
    """Fail closed when ``material`` is missing any required field
    of ``definition``; refuse ``action-material-missing``.

    The exception's ``reason`` is the exact closed string
    ``missing_material_field:<name>`` for the first missing field
    (alphabetical), so machine consumers can match it byte-for-byte.
    """
    missing = [f for f in definition.required_material
               if f not in material]
    if missing:
        first = sorted(missing)[0]
        raise _MaterialMissing(
            "material is missing required fields: %s"
            % ", ".join(sorted(missing)),
            reason="missing_material_field:%s" % first)


def _check_material_shape(material):
    """Gate the material's JSON-object shape before any digest or
    semantics work, so the refusal vocabulary stays inside
    typed_actions."""
    if not isinstance(material, dict):
        raise _Malformed("material must be a dict")
    for key in material:
        if (not isinstance(key, str) or not key
                or not key.isprintable()):
            raise _Malformed(
                "material keys must be non-empty strings")
    try:
        canonical_json_bytes(material)
    except Exception as exc:  # noqa: BLE001
        raise _Malformed(
            "material must be JSON-encodable: %s" % exc)


def _depth_of(value):
    """Nesting depth of one material value: scalars 0, each
    container level adds 1."""
    if isinstance(value, dict):
        return 1 + max((_depth_of(v) for v in value.values()),
                       default=0)
    if isinstance(value, (list, tuple)):
        return 1 + max((_depth_of(v) for v in value), default=0)
    return 0


def _leaf_count(value):
    """Number of scalar leaf values in one material value."""
    if isinstance(value, dict):
        return sum(_leaf_count(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return sum(_leaf_count(v) for v in value)
    return 1


def _check_scalar_lengths(value, max_len, path="$"):
    """Refuse ``action-value-too-long`` for any str/bytes leaf
    longer than ``max_len``."""
    if isinstance(value, dict):
        for key, sub in value.items():
            _check_scalar_lengths(sub, max_len, "%s.%s" % (path, key))
    elif isinstance(value, (list, tuple)):
        for idx, sub in enumerate(value):
            _check_scalar_lengths(sub, max_len, "%s[%d]" % (path, idx))
    elif isinstance(value, (str, bytes)):
        if len(value) > max_len:
            raise _ValueTooLong(
                "value at %s exceeds max_value_len %d" % (path, max_len))


def _enforce_semantics(definition, material):
    """Enforce the definition's validation semantics over
    ``material``.

    Declared field types (required fields only; extra fields are
    "any"), nesting depth, leaf-value count, and scalar length.
    Called at bind AND at verify — the verifier re-derives, never
    trusts the binder's word.
    """
    for field in definition.required_material:
        if field not in material:
            continue  # absence already refused by _require_material
        label = definition.field_types.get(field, "any")
        if not _type_matches(label, material[field]):
            raise _TypeMismatch(
                "field %r violates declared type %r" % (field, label))
    depth = max((_depth_of(v) for v in material.values()), default=0)
    if depth > definition.max_depth:
        raise _DepthExceeded(
            "material depth %d exceeds max_depth %d"
            % (depth, definition.max_depth))
    leaves = sum(_leaf_count(v) for v in material.values())
    if leaves > definition.max_values:
        raise _ValueCountExceeded(
            "material leaf count %d exceeds max_values %d"
            % (leaves, definition.max_values))
    _check_scalar_lengths(material, definition.max_value_len)


def _bound_digest(type_id, version, type_digest, material,
                  definition_sha256=None) -> str:
    """Digest of the binding: what the commitment covers.

    New bindings commit to ``definition_sha256`` as well — the
    chain covers label -> type definition -> validation semantics.
    ``definition_sha256=None`` reproduces the pre-semantics
    (wave-228) formula for the legacy verification path only.
    """
    body = {
        "type_id": type_id,
        "version": version,
        "type_digest": type_digest,
        "material": material,
    }
    if definition_sha256 is not None:
        body["definition_sha256"] = definition_sha256
    return _digest(canonical_json_bytes(body))


def verify_typed_action(bound_action, registry):
    """Verify a typed-action binding against the verifier's registry.

    Everything is recomputed, never asserted: the type digest is
    re-derived from the registered definition and compared to what
    the binding commits to (a substituted definition refuses
    ``action-type-drift``); the bound digest is recomputed over the
    presented material (tampering refuses
    ``action-binding-tampered``); required-material completeness is
    re-checked (``action-material-missing``). A binding with no type
    — e.g. a label-only ``{"action": "wire"}`` — refuses
    ``action-type-unknown``: it is not a typed action and cannot
    pass typed verification.

    Returns True on success.
    """
    if not isinstance(registry, TypeRegistry):
        raise _Malformed("verify_typed_action requires a TypeRegistry")
    if not isinstance(bound_action, dict):
        raise _Malformed("bound action must be a dict")
    type_id = bound_action.get("type_id")
    version = bound_action.get("version")
    if not isinstance(type_id, str) or not type_id \
            or not isinstance(version, int) or isinstance(version, bool):
        # A label-only action has no type; it cannot pass typed
        # verification. This is the "digest over a label commits to
        # nothing" gap made explicit: no type, no verification.
        raise _TypeUnknown(
            "bound action carries no registered type")
    definition = _require_known(type_id, version, registry)
    presented_digest = bound_action.get("type_digest")
    if not isinstance(presented_digest, str) or not presented_digest:
        raise _Malformed("bound action carries no type_digest")
    expected_digest = _type_digest(type_id, version,
                                   definition.required_material)
    if presented_digest != expected_digest:
        raise _TypeDrift(
            "presented type definition differs from what the "
            "binding commits to")
    # Semantics pinning. The registry's definition re-derives
    # definition_sha256; a binding that commits to different
    # validation semantics refuses action-semantics-drift. A binding
    # with no definition_sha256 field is a legacy (pre-semantics)
    # binding: it verifies under the original rule exactly as
    # wave-228 — the pinning never widens old bindings.
    presented_sem = bound_action.get("definition_sha256")
    expected_sem = _definition_sha256(
        type_id, version, definition.required_material,
        definition.field_types, definition.max_depth,
        definition.max_values, definition.max_value_len)
    legacy = presented_sem is None
    if not legacy and (not isinstance(presented_sem, str)
                       or presented_sem != expected_sem):
        raise _SemanticsDrift(
            "presented validation semantics differ from the "
            "registry definition")
    material = bound_action.get("material")
    if not isinstance(material, dict):
        raise _Malformed("bound action material must be a dict")
    presented_bound = bound_action.get("bound_digest")
    if not isinstance(presented_bound, str) or not presented_bound:
        # A structural defect is malformed input, not tampering:
        # tampering is a digest that fails to recompute, not a
        # missing one.
        raise _Malformed("bound action carries no bound_digest")
    expected_bound = _bound_digest(type_id, version, presented_digest,
                                   material,
                                   None if legacy else presented_sem)
    if presented_bound != expected_bound:
        raise _BindingTampered(
            "bound digest does not recompute over the material")
    _require_material(definition, material)
    if not legacy:
        _check_material_shape(material)
        _enforce_semantics(definition, material)
    return True


def _capsule_evidence_line(bound_digest) -> str:
    return "typed_action_binding:%s" % bound_digest


def bind_to_capsule(bound_action, capsule):
    """Seal a typed-action binding into a NEW action capsule.

    The binding is digest-linked into the capsule: the new
    attempt carries the full bound body under ``typed_action``
    and the new effect mirrors its ``bound_digest``. The new
    capsule is sealed through the public ``gov/action_capsule``
    seam — no changes to that module. ``capsule`` is replayed
    first (``verify_capsule``); a tampered incoming capsule
    refuses there.

    Returns the new sealed capsule.
    """
    if not isinstance(bound_action, dict):
        raise _Malformed("bound action must be a dict")
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    verify_capsule(capsule)  # replay; tampering refuses here
    bound_digest = bound_action.get("bound_digest")
    if not isinstance(bound_digest, str) or not bound_digest:
        raise _Malformed("bound action carries no bound_digest")
    type_id = bound_action.get("type_id")
    if not isinstance(type_id, str) or not type_id:
        raise _TypeUnknown("bound action carries no registered type")
    new_attempt = {
        "action": type_id,
        "typed_action": bound_action,
    }
    new_effect = {
        "status": "admitted",
        "evidence": _capsule_evidence_line(bound_digest),
        "typed_digest": bound_digest,
    }
    return seal_capsule({"attempt": new_attempt, "effect": new_effect})


def verify_capsule_typed_action(capsule, registry):
    """Verify a capsule's typed-action binding against the registry.

    Replays the capsule (``verify_capsule``), then re-runs
    :func:`verify_typed_action` over the embedded binding and
    checks the effect mirror. A capsule with no typed block
    refuses ``typed-action-not-bound``. Returns the verified
    bound body on success.
    """
    if not isinstance(registry, TypeRegistry):
        raise _Malformed(
            "verify_capsule_typed_action requires a TypeRegistry")
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    attempt = body.get("attempt")
    if not isinstance(attempt, dict):
        raise _Malformed("capsule attempt must be a dict")
    bound = attempt.get("typed_action")
    if not isinstance(bound, dict):
        raise _NotBound(
            "capsule carries no typed-action binding")
    verify_typed_action(bound, registry)  # recompute; drift refuses
    effect = body.get("effect")
    if not isinstance(effect, dict) \
            or effect.get("typed_digest") != bound.get("bound_digest"):
        raise _BindingTampered(
            "capsule effect does not mirror the typed binding")
    return bound


def bind_action(type_id, version, material, registry):
    """Bind material to a registered action type.

    ``material`` MUST contain every field the type definition
    requires (missing fields refuse ``action-material-missing``
    with the exact reason ``missing_material_field:<name>``) and
    satisfy the definition's validation semantics: declared field
    types (``action-material-type-mismatch``), nesting depth
    (``action-depth-exceeded``), leaf-value count
    (``action-value-count-exceeded``), and scalar length
    (``action-value-too-long``). Extra fields are permitted — and
    committed: the bound digest covers the full material, so
    silently dropping a field breaks the digest instead of the
    verification. Unknown types refuse ``action-type-unknown``.

    Returns the sealed binding::

        {v, type_id, version, type_digest, definition_sha256,
         material, bound_digest}

    The bound digest commits to ``definition_sha256``: label ->
    type definition -> validation semantics.
    """
    if not isinstance(registry, TypeRegistry):
        raise _Malformed("bind_action requires a TypeRegistry")
    definition = _require_known(type_id, version, registry)
    _check_material_shape(material)
    _require_material(definition, material)
    _enforce_semantics(definition, material)
    committed = dict(material)
    bound = {
        "v": TYPED_ACTION_VERSION,
        "type_id": definition.type_id,
        "version": definition.version,
        "type_digest": definition.type_digest,
        "definition_sha256": definition.definition_sha256,
        "material": committed,
    }
    bound["bound_digest"] = _bound_digest(
        definition.type_id, definition.version,
        definition.type_digest, committed,
        definition.definition_sha256)
    return bound


def bind_action_from_json(type_id, version, raw_json, registry):
    """Bind material supplied as raw JSON text to a registered
    action type.

    Duplicate object keys at ANY nesting level refuse
    ``action-duplicate-key`` — a shadowed key can never smuggle a
    value past the schema, because Python dicts silently keep the
    last occurrence. Unparseable input or a non-object top level
    refuses ``typed-action-malformed``. On success this is exactly
    :func:`bind_action` over the parsed material.
    """
    if isinstance(raw_json, bytes):
        try:
            text = raw_json.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _Malformed(
                "material JSON must be UTF-8: %s" % exc)
    elif isinstance(raw_json, str):
        text = raw_json
    else:
        raise _Malformed("material JSON must be str or bytes")

    def _no_dupes(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise _DuplicateKey(
                    "duplicate object key %r in material JSON" % (key,))
            seen[key] = value
        return seen

    try:
        material = json.loads(text, object_pairs_hook=_no_dupes)
    except _DuplicateKey:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _Malformed(
            "material JSON does not parse: %s" % exc)
    if not isinstance(material, dict):
        raise _Malformed("material JSON must decode to an object")
    return bind_action(type_id, version, material, registry)
