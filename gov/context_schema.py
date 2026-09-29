"""Typed context-attribute schema for authorization requests (wave-194 R1).

Steal from ``cedar-policy/cedar`` (Apache-2.0): a schema-typed request
layer where a mistyped attribute is unrepresentable -- it fails LOUD
at the contract boundary instead of being silently coerced at match
time. The wave-193 Cedar spike (D1) proved the gap: our engine coerced
context signals with ``bool()``/``int()`` in ``PolicyEngine._matches``,
so ``domain_allowlisted="false"`` (a truthy STRING) on an unallowlisted
domain silently skipped the ``deny-egress-unallowlisted`` forbid, and
``read_classified="false"`` made a ``read_classified: true`` rule fire.
Cedar on the same mistyped shape returns an explicit, machine-
distinguishable NoDecision -- never a silently evaluated verdict.

Design (deliberate, documented):

  * The schema declares the expected type of every KNOWN context
    signal. ``validate_context`` raises ``ContextTypeError`` (a
    ``TypeError``) on a mistyped known key -- at ``Request``
    construction, i.e. the contract boundary, before any evaluation.
  * ``None`` is the ABSENCE sentinel, not a mistype: a bool signal set
    to ``None`` behaves exactly as an omitted key (``False``), matching
    the engine's long-standing ``bool(context.get(key))`` convention
    that tests and producers encode. The refusal targets
    *coercion-shaped* values (truthy/falsy non-bools, numeric strings,
    ints for bools), not absence.
  * Unknown keys pass through (forward compatibility): the simulator
    and custom producers attach ad-hoc keys (``role``, ``agent``, ...);
    refusing them would break the engine's extensibility. A new engine
    signal must be declared here when it is introduced -- the
    ``test_schema_covers_match_keys`` pin enforces that every
    bool-compare key in ``_matches`` is declared.
  * The policy FILE side gets the same treatment at load time:
    ``validate_match_types`` refuses a rule whose match value is
    mistyped (``domain_allowlisted: "false"`` as a YAML string is the
    same bug on the authoring side). Loud ``ValueError``, F90
    convention.
  * ``checked_bool`` / ``checked_counter`` are the strict accessors
    ``_matches`` uses instead of bare ``bool()``/``int()`` -- defense
    in depth for direct ``_matches`` callers (tests do call it
    directly), with identical semantics on well-typed input
    (None -> False / 0 default).

``bool`` vs ``int``: ``type(value) is int`` (not ``isinstance``)
rejects ``bool`` for counters -- a ``True`` counter is a producer bug,
and ``int(True) == 1`` would silently accept it. For bool signals,
``isinstance(value, bool)`` is exact (no live ``bool`` subclasses).

This module is dependency-free: ``decision_contract`` and ``policy``
both import it; it imports neither (no import cycle).
"""

from typing import Any, Mapping

__all__ = [
    "BOOL_SIGNALS",
    "CONTEXT_SCHEMA",
    "THRESHOLD_KEYS",
    "ContextTypeError",
    "validate_context",
    "checked_bool",
    "checked_counter",
    "validate_match_types",
]


class ContextTypeError(TypeError):
    """A context attribute (or policy match value) has the wrong type.

    Machine-distinguishable: the message names the attribute, the
    expected type, and the actual type/value received. Subclasses
    TypeError so existing ``except TypeError`` guards around Request
    construction keep working.
    """


# Every context signal compared with bool() in PolicyEngine._matches.
# A new bool-compare key in _matches MUST be added here; the
# test_schema_covers_match_keys pin fails otherwise.
BOOL_SIGNALS = frozenset({
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
})

# Policy-side counter thresholds compared with int() in _matches.
THRESHOLD_KEYS = frozenset({
    "min_external_calls",
    "min_sends",
    "min_writes",
    "min_deletes",
})

# Declared type of every known context key. Kinds:
#   "bool_or_none"  - True/False, or None meaning "absent" (== False)
#   "int_or_none"   - exact int (bool rejected), or None
#   "str_or_none"   - str, or None
#   "list_or_none"  - list, or None
#   "dict_or_none"  - mapping, or None
#   "counters"      - mapping of str -> exact int, or None
CONTEXT_SCHEMA = {
    "counters": "counters",
    "api_calls": "int_or_none",
    "path_resolved": "str_or_none",
    "sandbox_root": "str_or_none",
    "artifact_refs": "list_or_none",
    "registry_hosts": "list_or_none",
    "authority_proof": "dict_or_none",
}
CONTEXT_SCHEMA.update({key: "bool_or_none" for key in BOOL_SIGNALS})


def _type_name(value):
    return type(value).__name__


def _refuse(key, expected, value):
    raise ContextTypeError(
        "typed-context: context[%r] must be %s, got %s (%r); "
        "mistyped context attributes are refused, never silently "
        "coerced" % (key, expected, _type_name(value), value))


def validate_context(context):
    """Fail loud on mistyped KNOWN context attributes.

    ``context`` must already be a Mapping (Request checks that first).
    Unknown keys pass through -- see the module docstring for why.
    Returns None; raises ContextTypeError on the first mistype.
    """
    for key, value in context.items():
        kind = CONTEXT_SCHEMA.get(key)
        if kind is None:
            continue  # unknown key: forward-compatible pass-through
        if kind == "bool_or_none":
            if value is not None and not isinstance(value, bool):
                _refuse(key, "bool or None", value)
        elif kind == "int_or_none":
            if value is not None and type(value) is not int:
                _refuse(key, "int or None", value)
        elif kind == "str_or_none":
            if value is not None and not isinstance(value, str):
                _refuse(key, "str or None", value)
        elif kind == "list_or_none":
            if value is not None and not isinstance(value, list):
                _refuse(key, "list or None", value)
        elif kind == "dict_or_none":
            if value is not None and not isinstance(value, Mapping):
                _refuse(key, "mapping or None", value)
        elif kind == "counters":
            if value is None:
                continue
            if not isinstance(value, Mapping):
                _refuse(key, "mapping of str->int or None", value)
            for ckey, cval in value.items():
                if type(cval) is not int:
                    raise ContextTypeError(
                        "typed-context: context[%r][%r] must be int, "
                        "got %s (%r); counters are never coerced"
                        % (key, ckey, _type_name(cval), cval))


def checked_bool(context, key):
    """Strict bool read for a declared bool signal.

    ``None`` (absent) -> ``False``, exactly the engine's historical
    ``bool(context.get(key))`` semantics. Any other non-bool raises
    ContextTypeError -- the silent-coercion case can no longer reach
    the comparison.
    """
    value = context.get(key)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    _refuse(key, "bool or None", value)


def checked_counter(counters, name):
    """Strict int read for a named attempt counter.

    Missing counters map -> 0 (the engine's ``.get(name, 0)`` default);
    a missing counter NAME -> 0. Non-int values (including bool and
    numeric strings like ``"5"``) raise ContextTypeError.
    """
    counters = counters or {}
    if not isinstance(counters, Mapping):
        raise ContextTypeError(
            "typed-context: context['counters'] must be a mapping or "
            "None, got %s (%r)" % (_type_name(counters), counters))
    value = counters.get(name, 0)
    if type(value) is not int:
        raise ContextTypeError(
            "typed-context: context['counters'][%r] must be int, got "
            "%s (%r); counters are never coerced"
            % (name, _type_name(value), value))
    return value


def validate_match_types(rule_id, match):
    """Fail loud at policy LOAD on mistyped match values (F90 style).

    The authoring-side twin of validate_context: a YAML
    ``domain_allowlisted: "false"`` (string) is the same silent-
    coercion bug as a mistyped context attribute. Raises ValueError.
    Only the schema-typed keys are checked; tool/role/agent and
    path_contains_any keep their existing validation.
    """
    for key in match:
        if key in BOOL_SIGNALS:
            value = match[key]
            if not isinstance(value, bool):
                raise ValueError(
                    "policy %s: match[%r] must be a bool, got %s (%r); "
                    "quoted YAML strings are never coerced"
                    % (rule_id, key, _type_name(value), value))
        elif key in THRESHOLD_KEYS:
            value = match[key]
            if type(value) is not int:
                raise ValueError(
                    "policy %s: match[%r] must be an int, got %s (%r)"
                    % (rule_id, key, _type_name(value), value))
        elif key == "path_contains_any":
            value = match[key]
            vals = value if isinstance(value, (list, tuple)) else [value]
            if not all(isinstance(v, str) for v in vals):
                raise ValueError(
                    "policy %s: match['path_contains_any'] must be a "
                    "string or list of strings, got %r"
                    % (rule_id, value))
