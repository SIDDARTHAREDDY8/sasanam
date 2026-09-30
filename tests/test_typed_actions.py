#!/usr/bin/env python3
"""Unit tests for gov/typed_actions.py: typed actions with required
material fields and digest over the type definition.

Independent spec-vector literals (no calls into the module under
test to derive expectations): refusal codes are asserted as literal
strings, digests as literals recomputed from stdlib hashlib over
fixed canonical bodies.
"""

import hashlib
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import action_capsule as cap  # noqa: E402
from gov import typed_actions as ta  # noqa: E402


def _code_of(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None)
    return None


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# Fixed fixtures (arbitrary non-secret vectors).
_TYPE_ID = "wire"
_VERSION = 1
_REQUIRED = ["amount", "recipient"]
_MATERIAL = {"amount": 100, "recipient": "alice"}
# Spec-vector literal: sha256 of the canonical type body.
_TYPE_BODY = {"type_id": _TYPE_ID, "version": _VERSION,
              "required_material": sorted(_REQUIRED)}
_TYPE_DIGEST_LITERAL = hashlib.sha256(_canon(_TYPE_BODY)).hexdigest()


def _registry(required=_REQUIRED):
    reg = ta.TypeRegistry()
    reg.register(ta.ActionType.build(_TYPE_ID, _VERSION, required))
    return reg


def _bound(reg=None, material=None):
    reg = reg or _registry()
    return ta.bind_action(_TYPE_ID, _VERSION,
                          dict(_MATERIAL) if material is None
                          else material, reg)


class ActionTypeTests(unittest.TestCase):
    def test_type_digest_matches_independent_literal(self):
        at = ta.ActionType.build(_TYPE_ID, _VERSION, _REQUIRED)
        self.assertEqual(at.type_digest, _TYPE_DIGEST_LITERAL)

    def test_empty_type_id_malformed(self):
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build("", 1, _REQUIRED)),
            "typed-action-malformed")

    def test_bad_version_malformed(self):
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build("wire", 0, _REQUIRED)),
            "typed-action-malformed")

    def test_empty_required_material_malformed(self):
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build("wire", 1, [])),
            "typed-action-malformed")

    def test_duplicate_fields_malformed(self):
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build(
                "wire", 1, ["amount", "amount"])),
            "typed-action-malformed")


class BindTests(unittest.TestCase):
    def test_bound_digest_matches_independent_literal(self):
        bound = _bound()
        # Wave-230: the bound digest also commits to
        # definition_sha256 (label -> type definition -> validation
        # semantics). The semantics body is recomputed from stdlib
        # primitives over fixed literals, not via the module under
        # test; defaults are the documented wave-230 constants.
        sem_body = {"type_id": _TYPE_ID, "version": _VERSION,
                    "required_material": sorted(_REQUIRED),
                    "field_types": {"amount": "any",
                                    "recipient": "any"},
                    "max_depth": 3, "max_values": 128,
                    "max_value_len": 4096}
        def_sha = hashlib.sha256(_canon(sem_body)).hexdigest()
        self.assertEqual(bound["definition_sha256"], def_sha)
        body = {"type_id": _TYPE_ID, "version": _VERSION,
                "type_digest": _TYPE_DIGEST_LITERAL,
                "definition_sha256": def_sha,
                "material": dict(_MATERIAL)}
        self.assertEqual(bound["bound_digest"],
                         hashlib.sha256(_canon(body)).hexdigest())

    def test_missing_required_refuses(self):
        reg = _registry()
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION, {"amount": 100}, reg)),
            "action-material-missing")

    def test_unknown_type_refuses(self):
        reg = _registry()
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                "revoke", 1, {"target": "x"}, reg)),
            "action-type-unknown")

    def test_unknown_version_refuses(self):
        reg = _registry()
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, 99, dict(_MATERIAL), reg)),
            "action-type-unknown")

    def test_non_dict_material_malformed(self):
        reg = _registry()
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION, ["amount"], reg)),
            "typed-action-malformed")


class VerifyTests(unittest.TestCase):
    def test_valid_binding_verifies(self):
        reg = _registry()
        self.assertTrue(ta.verify_typed_action(_bound(reg), reg))

    def test_substituted_definition_drift(self):
        binder = _registry(["amount", "recipient"])
        bound = _bound(binder)
        verifier = _registry(["amount"])  # permissive re-definition
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(bound, verifier)),
            "action-type-drift")

    def test_label_only_refuses_unknown(self):
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(
                {"action": "wire"}, _registry())),
            "action-type-unknown")

    def test_tampered_material_refuses(self):
        reg = _registry()
        bound = _bound(reg)
        tampered = dict(bound)
        tampered["material"] = dict(bound["material"])
        tampered["material"]["recipient"] = "mallory"
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(tampered, reg)),
            "action-binding-tampered")

    def test_missing_bound_digest_malformed(self):
        # A structural defect is malformed input, not tampering.
        reg = _registry()
        bound = _bound(reg)
        stripped = dict(bound)
        del stripped["bound_digest"]
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(stripped, reg)),
            "typed-action-malformed")

    def test_swapped_type_digest_refuses(self):
        reg = _registry()
        bound = _bound(reg)
        swapped = dict(bound)
        swapped["type_digest"] = "0" * 64
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(swapped, reg)),
            "action-type-drift")

    def test_unknown_type_in_bound_refuses(self):
        reg = _registry()
        bound = _bound(reg)
        renamed = dict(bound)
        renamed["type_id"] = "revoke"
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(renamed, reg)),
            "action-type-unknown")


class CapsuleCompositionTests(unittest.TestCase):
    def _plain_capsule(self):
        return cap.seal_capsule({
            "attempt": {"action": "wire", "initiator": "agent-1"},
            "effect": {"status": "admitted",
                       "evidence": "executor-receipt-001"},
        })

    def test_composed_capsule_verifies(self):
        reg = _registry()
        bound = _bound(reg)
        composed = ta.bind_to_capsule(bound, self._plain_capsule())
        cap.verify_capsule(composed)
        checked = ta.verify_capsule_typed_action(composed, reg)
        self.assertEqual(checked["bound_digest"],
                         bound["bound_digest"])

    def test_plain_capsule_not_bound(self):
        self.assertEqual(
            _code_of(lambda: ta.verify_capsule_typed_action(
                self._plain_capsule(), _registry())),
            "typed-action-not-bound")

    def test_composed_capsule_drift_refuses(self):
        binder = _registry(["amount", "recipient"])
        bound = ta.bind_action(_TYPE_ID, _VERSION, dict(_MATERIAL),
                               binder)
        composed = ta.bind_to_capsule(bound, self._plain_capsule())
        verifier = _registry(["amount"])
        self.assertEqual(
            _code_of(lambda: ta.verify_capsule_typed_action(
                composed, verifier)),
            "action-type-drift")


def _reason_of(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "reason", None)
    return None


def _sem_registry(**kw):
    reg = ta.TypeRegistry()
    reg.register(ta.ActionType.build(_TYPE_ID, _VERSION,
                                    list(_REQUIRED), **kw))
    return reg


class DefinitionSha256Tests(unittest.TestCase):
    def test_defsha_matches_independent_literal(self):
        t = ta.ActionType.build(_TYPE_ID, _VERSION, list(_REQUIRED))
        sem_body = {"type_id": _TYPE_ID, "version": _VERSION,
                    "required_material": sorted(_REQUIRED),
                    "field_types": {"amount": "any",
                                    "recipient": "any"},
                    "max_depth": 3, "max_values": 128,
                    "max_value_len": 4096}
        self.assertEqual(t.definition_sha256,
                         hashlib.sha256(_canon(sem_body)).hexdigest())

    def test_field_change_moves_digest(self):
        a = ta.ActionType.build("wire", 1, ["amount", "recipient"])
        b = ta.ActionType.build("wire", 1, ["amount"])
        self.assertNotEqual(a.definition_sha256, b.definition_sha256)

    def test_declared_type_change_moves_digest(self):
        a = ta.ActionType.build("wire", 1, ["amount"],
                                field_types={"amount": "int"})
        b = ta.ActionType.build("wire", 1, ["amount"],
                                field_types={"amount": "str"})
        self.assertNotEqual(a.definition_sha256, b.definition_sha256)

    def test_constraint_change_moves_digest(self):
        a = ta.ActionType.build("wire", 1, ["amount"], max_depth=3)
        b = ta.ActionType.build("wire", 1, ["amount"], max_depth=4)
        self.assertNotEqual(a.definition_sha256, b.definition_sha256)

    def test_order_independent(self):
        a = ta.ActionType.build(
            "wire", 1, ["amount", "recipient"],
            field_types={"amount": "int", "recipient": "str"})
        b = ta.ActionType.build(
            "wire", 1, ["recipient", "amount"],
            field_types={"recipient": "str", "amount": "int"})
        self.assertEqual(a.definition_sha256, b.definition_sha256)

    def test_as_dict_carries_semantics(self):
        d = ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "int"}, max_depth=2).as_dict()
        self.assertEqual(d["field_types"], {"amount": "int"})
        self.assertEqual(d["max_depth"], 2)
        self.assertEqual(len(d["definition_sha256"]), 64)

    def test_bad_semantics_kwargs_malformed(self):
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build(
                "wire", 1, ["amount"],
                field_types={"nope": "int"})),
            "typed-action-malformed")
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build(
                "wire", 1, ["amount"],
                field_types={"amount": "uuid"})),
            "typed-action-malformed")
        self.assertEqual(
            _code_of(lambda: ta.ActionType.build(
                "wire", 1, ["amount"], max_depth=0)),
            "typed-action-malformed")


class SemanticsEnforcementTests(unittest.TestCase):
    def test_exact_missing_field_reason(self):
        reg = _sem_registry()
        reason = _reason_of(
            lambda: ta.bind_action(_TYPE_ID, _VERSION,
                                   {"amount": 100}, reg))
        self.assertEqual(reason, "missing_material_field:recipient")
        self.assertEqual(
            _code_of(lambda: ta.bind_action(_TYPE_ID, _VERSION,
                                            {"amount": 100}, reg)),
            "action-material-missing")

    def test_declared_type_mismatch(self):
        reg = _sem_registry(field_types={"amount": "int",
                                         "recipient": "str"})
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION,
                {"amount": "100", "recipient": "alice"}, reg)),
            "action-material-type-mismatch")
        # bool is not int: exact-type identity, no subclass leniency.
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION,
                {"amount": True, "recipient": "alice"}, reg)),
            "action-material-type-mismatch")
        bound = ta.bind_action(
            _TYPE_ID, _VERSION,
            {"amount": 100, "recipient": "alice"}, reg)
        self.assertTrue(ta.verify_typed_action(bound, reg))

    def test_depth_exceeded(self):
        reg = _sem_registry(max_depth=1)
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION,
                {"amount": 100,
                 "recipient": {"nick": {"x": "deep"}}}, reg)),
            "action-depth-exceeded")
        shallow = ta.bind_action(
            _TYPE_ID, _VERSION,
            {"amount": 100, "recipient": {"nick": "a"}}, reg)
        self.assertTrue(ta.verify_typed_action(shallow, reg))

    def test_value_count_exceeded(self):
        reg = ta.TypeRegistry()
        reg.register(ta.ActionType.build("wire", 1, ["a", "b", "c"],
                                        max_values=2))
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                "wire", 1, {"a": 1, "b": 2, "c": 3}, reg)),
            "action-value-count-exceeded")

    def test_value_too_long(self):
        reg = _sem_registry(max_value_len=4)
        self.assertEqual(
            _code_of(lambda: ta.bind_action(
                _TYPE_ID, _VERSION,
                {"amount": 100, "recipient": "toolong"}, reg)),
            "action-value-too-long")

    def test_duplicate_key_json(self):
        reg = _sem_registry()
        self.assertEqual(
            _code_of(lambda: ta.bind_action_from_json(
                _TYPE_ID, _VERSION,
                b'{"amount": 100, "recipient": "a", "amount": 7}',
                reg)),
            "action-duplicate-key")
        self.assertEqual(
            _code_of(lambda: ta.bind_action_from_json(
                _TYPE_ID, _VERSION, b'[1, 2]', reg)),
            "typed-action-malformed")
        self.assertEqual(
            _code_of(lambda: ta.bind_action_from_json(
                _TYPE_ID, _VERSION, b'{"amount": ', reg)),
            "typed-action-malformed")
        bound = ta.bind_action_from_json(
            _TYPE_ID, _VERSION,
            '{"amount": 100, "recipient": "alice"}', reg)
        self.assertTrue(ta.verify_typed_action(bound, reg))

    def test_semantics_drift_between_bind_and_verify(self):
        binder = ta.TypeRegistry()
        binder.register(ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "int"}, max_depth=1))
        bound = ta.bind_action("wire", 1, {"amount": 100}, binder)
        verifier = ta.TypeRegistry()
        verifier.register(ta.ActionType.build(
            "wire", 1, ["amount"],
            field_types={"amount": "str"}, max_depth=9))
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(bound, verifier)),
            "action-semantics-drift")

    def test_swapped_defsha_in_binding_refuses(self):
        reg = _sem_registry()
        bound = ta.bind_action(_TYPE_ID, _VERSION, dict(_MATERIAL),
                               reg)
        swapped = dict(bound)
        swapped["definition_sha256"] = "0" * 64
        self.assertEqual(
            _code_of(lambda: ta.verify_typed_action(swapped, reg)),
            "action-semantics-drift")

    def test_legacy_binding_verifies_unwidened(self):
        # A pre-semantics binding (no definition_sha256 field,
        # wave-228 digest formula) verifies under the original rule.
        reg = _sem_registry()
        definition = reg.lookup(_TYPE_ID, _VERSION)
        material = dict(_MATERIAL)
        legacy_body = {"type_id": _TYPE_ID, "version": _VERSION,
                       "type_digest": definition.type_digest,
                       "material": material}
        legacy = dict(legacy_body)
        legacy["v"] = 1
        legacy["bound_digest"] = hashlib.sha256(
            _canon(legacy_body)).hexdigest()
        self.assertTrue(ta.verify_typed_action(legacy, reg))
        # ... but it does NOT gain semantics enforcement: a legacy
        # binding is verified exactly as wave-228 verified it.
        self.assertNotIn("definition_sha256", legacy)


if __name__ == "__main__":
    unittest.main()
