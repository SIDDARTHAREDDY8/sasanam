"""Typed actions: commitments that cover WHAT an action means.

A digest over ``{"action": "wire"}`` commits to nothing — the label
carries no semantics, so a verifier cannot tell what was actually
authorized. Typed actions close that gap: an :class:`ActionType`
defines the material fields an action of that type MUST carry, and
the type DEFINITION carries its own digest (computed over the
canonical type body). :func:`bind_action` seals material to a
registered type; the bound digest commits to ``{type_digest,
type_id, version, material}``. :func:`verify_typed_action`
re-derives everything from the verifier's registry — a substituted
type definition (same label, different required fields) refuses
``action-type-drift``; mutated material refuses
``action-binding-tampered``.

Capsule composition (:func:`bind_to_capsule` /
:func:`verify_capsule_typed_action`) seals a typed binding into a
NEW action capsule as digest-linked evidence. ``gov/action_capsule``
is untouched — composition happens through its public seal/verify
seams.

Re-derived prose. Stdlib only. No network. $0.
"""

import hashlib

from .action_capsule import (canonical_json_bytes, seal_capsule,
                            verify_capsule)

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class TypedActionError(Exception):
    """Base class for all typed-action refusals. ``code`` is
    machine-readable."""

    code = "typed-action-refused"


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


# ----------------------------------------------------------------------
# Constants.
# ----------------------------------------------------------------------

TYPED_ACTION_VERSION = 1


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


class ActionType:
    """A typed-action definition: id, version, required material.

    Instances are created through :meth:`build`, which validates
    the definition and computes ``type_digest``.
    """

    def __init__(self, type_id, version, required_material,
                 type_digest):
        self.type_id = type_id
        self.version = version
        self.required_material = tuple(required_material)
        self.type_digest = type_digest

    @classmethod
    def build(cls, type_id, version, required_material):
        """Build and validate a type definition.

        ``type_id`` and ``version`` must be non-empty (version a
        positive int); ``required_material`` a non-empty list of
        non-empty, printable, unique field names.
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
        return cls(type_id, version, fields,
                   _type_digest(type_id, version, fields))

    def as_dict(self):
        return {
            "v": TYPED_ACTION_VERSION,
            "type_id": self.type_id,
            "version": self.version,
            "required_material": list(self.required_material),
            "type_digest": self.type_digest,
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
    of ``definition``; refuse ``action-material-missing``."""
    missing = [f for f in definition.required_material
               if f not in material]
    if missing:
        raise _MaterialMissing(
            "material is missing required fields: %s"
            % ", ".join(sorted(missing)))


def _bound_digest(type_id, version, type_digest, material) -> str:
    """Digest of the binding: what the commitment covers."""
    body = {
        "type_id": type_id,
        "version": version,
        "type_digest": type_digest,
        "material": material,
    }
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
                                   material)
    if presented_bound != expected_bound:
        raise _BindingTampered(
            "bound digest does not recompute over the material")
    _require_material(definition, material)
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
    requires (missing fields refuse ``action-material-missing``).
    Extra fields are permitted — and committed: the bound digest
    covers the full material, so silently dropping a field breaks
    the digest instead of the verification. Unknown types refuse
    ``action-type-unknown``.

    Returns the sealed binding::

        {v, type_id, version, type_digest, material, bound_digest}
    """
    if not isinstance(registry, TypeRegistry):
        raise _Malformed("bind_action requires a TypeRegistry")
    definition = _require_known(type_id, version, registry)
    if not isinstance(material, dict):
        raise _Malformed("material must be a dict")
    _require_material(definition, material)
    committed = dict(material)
    bound = {
        "v": TYPED_ACTION_VERSION,
        "type_id": definition.type_id,
        "version": definition.version,
        "type_digest": definition.type_digest,
        "material": committed,
    }
    bound["bound_digest"] = _bound_digest(
        definition.type_id, definition.version,
        definition.type_digest, committed)
    return bound
