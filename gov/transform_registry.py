"""Transform registry: trusted transforms as (where, what) pairs.

Design lineage (attributed, not vendored):
- Sabelfeld & Sands, "Declassification: Dimensions and Principles" (JCS
  17(5), 2009): trusted transforms are *where*-points; the registry pins
  each transform's call-site identity (module + qualname + code digest)
  together with its declared output contract (the *what*). Anything outside
  the contract is an undeclared declassification and refuses coded.
- W3C Trusted Types: the registry is the named-policy list; registration
  is the privileged act; sinks accept only policy-created typed outputs.
- Spotlighting (Hines et al., 2024) as the negative rule: byte-marking /
  delimiter transforms are refused at registration.
- FIDES (arXiv:2505.23643): the output contract declares a capacity class
  (bool/enum/number/string/opaque-ref) that bounds the laundering budget.

Residual (stated): ``fn_identity`` pins (co_code, co_consts, co_names)
but not closure cells or defaults: two closures from one factory share
an identity. The damage is bounded by post-transform contract
re-verification (the output is still checked), but the identity check
cannot distinguish such closures.

Stdlib only. Deterministic: no time, no randomness.
"""

import hashlib
import marshal
import re

__all__ = [
    "TransformError",
    "TransformRegistration",
    "TransformRegistry",
    "fn_identity",
    "register_fn",
    "KINDS",
    "CAPACITIES",
    "REGISTRATION_CODES",
]

#: Refusal codes raised at registration time. Also registered in
#: gov/decision_codes.py (the transform-* family).
REGISTRATION_CODES = (
    "transform-registration-duplicate",
    "transform-registration-marking-refused",
    "transform-registration-denylist-refused",
    "transform-registration-model-lowering-refused",
)

#: Transform kinds. A "model" transform is mediated by an LLM (or any
#: non-deterministic interpreter) and can NEVER lower a label (CaMeL
#: discipline); only "deterministic" transforms are declassification
#: points.
KINDS = ("deterministic", "model")

#: FIDES capacity classes, ordered by information capacity.
#: opaque-ref carries no content at all (a reference, never bytes).
CAPACITIES = ("bool", "enum", "number", "string", "opaque-ref")


class TransformError(Exception):
    """Coded-by-construction refusal from the transform machinery.

    The message always starts with the machine-checkable code, e.g.
    ``"transform-registration-duplicate: ..."``.
    """


def _fail(code, detail):
    raise TransformError("%s: %s" % (code, detail))


def fn_identity(fn):
    """Return the (module, qualname, code_digest) identity of a function.

    The code digest is SHA-256 over the marshaled (co_code, co_consts,
    co_names) triple: it pins the *where* half of the (where, what) pair
    against silent implementation drift. Deterministic within a Python
    version; stdlib only.
    """
    try:
        code = fn.__code__
        blob = marshal.dumps((code.co_code, code.co_consts, code.co_names))
    except (AttributeError, ValueError, TypeError) as e:
        _fail("transform-identity-mismatch",
              "cannot take the identity of %r (%r)" % (fn, e))
    digest = hashlib.sha256(blob).hexdigest()
    return (getattr(fn, "__module__", "?"),
            getattr(fn, "__qualname__", "?"),
            digest)


class TransformRegistration(object):
    """A declared declassification point: a (where, what) pair.

    ``output_contract`` is a dict with:
      - ``capacity``: one of CAPACITIES (required)
      - ``max_bytes``: int, the longest output the contract covers (required)
      - ``shape``: allowlist regex (fullmatch) for string capacity
      - ``enum_values``: closed value list (required for enum capacity)
    A contract containing a ``deny`` key is a denylist and is refused at
    registration (the mXSS record: denylists lose).
    """

    __slots__ = ("name", "kind", "module", "qualname", "code_digest",
                 "marking", "input_contract", "output_contract",
                 "lowers_to", "description")

    def __init__(self, name, kind, module, qualname, code_digest,
                 marking=False, input_contract=None, output_contract=None,
                 lowers_to=None, description=""):
        self.name = name
        self.kind = kind
        self.module = module
        self.qualname = qualname
        self.code_digest = code_digest
        self.marking = bool(marking)
        self.input_contract = dict(input_contract or {})
        self.output_contract = dict(output_contract or {})
        self.lowers_to = lowers_to
        self.description = description

    def __repr__(self):
        return ("TransformRegistration(name=%r, kind=%r, lowers_to=%r)"
                % (self.name, self.kind, self.lowers_to))


def _validate_registration(name, kind, marking, output_contract, lowers_to):
    """Enforce the SPEC'd registration refusals. Called by both
    ``register_fn`` (convenience) and ``TransformRegistry.register``
    (so a hand-built registration cannot bypass them)."""
    if not isinstance(name, str) or not name:
        _fail("transform-registration-denylist-refused",
              "name must be a non-empty string")
    if kind not in KINDS:
        _fail("transform-registration-model-lowering-refused",
              "kind must be one of %r, got %r" % (KINDS, kind))
    if marking:
        _fail("transform-registration-marking-refused",
              "byte-marking/delimiter transforms are not label-lowering "
              "transforms (Spotlighting negative rule); %r refused at "
              "registration" % (name,))
    if kind == "model" and lowers_to is not None:
        _fail("transform-registration-model-lowering-refused",
              "model-mediated transforms are never label-lowering "
              "(CaMeL discipline); %r must not declare lowers_to"
              % (name,))
    _validate_contract(output_contract)
    if lowers_to is not None and \
            (not isinstance(lowers_to, int) or isinstance(lowers_to, bool)):
        _fail("transform-registration-denylist-refused",
              "lowers_to must be an int trust level or None")


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        _fail("transform-registration-denylist-refused",
              "%s must be a non-empty string" % what)


def _validate_contract(oc):
    """Refuse denylist-shaped or malformed output contracts."""
    if not isinstance(oc, dict):
        _fail("transform-registration-denylist-refused",
              "output_contract must be a dict")
    if "deny" in oc or "denylist" in oc or "blocklist" in oc:
        _fail("transform-registration-denylist-refused",
              "denylist-shaped output contracts are refused; declare an "
              "allowlist 'shape' instead (the mXSS record: denylists lose)")
    capacity = oc.get("capacity")
    if capacity not in CAPACITIES:
        _fail("transform-registration-denylist-refused",
              "output_contract['capacity'] must be one of %r" % (CAPACITIES,))
    max_bytes = oc.get("max_bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) \
            or max_bytes <= 0:
        _fail("transform-registration-denylist-refused",
              "output_contract['max_bytes'] must be a positive int")
    if capacity == "enum":
        values = oc.get("enum_values")
        if not isinstance(values, list) or not values or \
                not all(isinstance(v, str) for v in values):
            _fail("transform-registration-denylist-refused",
                  "enum capacity requires a non-empty 'enum_values' list "
                  "of strings")
    if capacity == "string" and "shape" in oc:
        if not isinstance(oc["shape"], str):
            _fail("transform-registration-denylist-refused",
                  "string 'shape' must be a regex string")
        try:
            re.compile(oc["shape"])  # fail fast, not at every certify
        except re.error as e:
            _fail("transform-registration-denylist-refused",
                  "string 'shape' is not a valid regex: %r" % (e,))


def register_fn(name, fn, *, kind, output_contract, lowers_to=None,
                marking=False, input_contract=None, description=""):
    """Build a TransformRegistration from a live function object.

    Refuses coded (never silently): marking transforms, denylist-shaped
    contracts, and model transforms that declare a label-lowering rule.
    The returned registration is NOT yet in any registry; the caller
    passes it to ``TransformRegistry.register``.
    """
    _validate_registration(name, kind, marking, output_contract, lowers_to)
    module, qualname, code_digest = fn_identity(fn)
    return TransformRegistration(
        name=name, kind=kind, module=module, qualname=qualname,
        code_digest=code_digest, marking=marking,
        input_contract=input_contract, output_contract=output_contract,
        lowers_to=lowers_to, description=description)


class TransformRegistry(object):
    """The named-policy list. Registration is the privileged act.

    The registry is append-only within an instance: names are unique and
    registrations are never silently replaced.
    """

    def __init__(self):
        self._by_name = {}

    def register(self, reg):
        """Add a registration. Duplicate names refuse coded, as do
        marking transforms, denylist-shaped contracts, and model
        transforms declaring a lowering rule -- the SPEC'd refusals are
        enforced here, not just in the ``register_fn`` convenience
        constructor, so a hand-built registration cannot bypass them."""
        if not isinstance(reg, TransformRegistration):
            _fail("transform-registration-denylist-refused",
                  "register() takes a TransformRegistration")
        _validate_registration(reg.name, reg.kind, reg.marking,
                               reg.output_contract, reg.lowers_to)
        if reg.name in self._by_name:
            _fail("transform-registration-duplicate",
                  "transform %r is already registered; registrations are "
                  "never silently replaced" % (reg.name,))
        self._by_name[reg.name] = reg
        return reg

    def get(self, name):
        """Return the registration for ``name``, or None."""
        return self._by_name.get(name)

    def names(self):
        """Sorted registered names (audit surface)."""
        return sorted(self._by_name)
