"""Unit tests for gov/rule_predicates.py (wave-295 lane 3).

Covers the two-phase CHECK/EVALUATE discipline: compile-time refusal of
undeclared fields, type confusion, over-bound ASTs; budget-guarded pure
evaluation; immutability; aggregate-only session fields; and the
tool_rules.py wiring for Conditional inline predicates.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import rule_predicates as rp
from gov import tool_rules as tr


def _ruleset(predicate, extra=None):
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "unit",
        "tools": ["read", "write"],
        "rules": [
            {"kind": "Conditional", "tool": "write", "predicate": predicate},
        ],
    }
    if extra:
        doc.update(extra)
    return tr.compile_rule_set(doc)


class TestCompilePhase(unittest.TestCase):
    def test_simple_predicate_compiles(self):
        p = rp.compile_predicate(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]})
        self.assertIsInstance(p, rp.CompiledPredicate)

    def test_undeclared_field_refuses_own_code(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate({"field": "nope"})
        self.assertEqual(ctx.exception.code,
                         "toolcall-predicate-undeclared-field")

    def test_undeclared_field_nested(self):
        spec = {"op": "or", "args": [{"field": "started"},
                                     {"field": "deep_secret"}]}
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate(spec)
        self.assertEqual(ctx.exception.code,
                         "toolcall-predicate-undeclared-field")

    def test_unknown_builtin(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate({"op": "xor", "args": [{"field": "started"},
                                                        {"field": "started"}]})
        self.assertEqual(ctx.exception.code, "toolcall-predicate-invalid")

    def test_type_confusion_gt(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate(
                {"op": "gt",
                 "args": [{"field": "last_tool"}, {"const": 1}]})
        self.assertEqual(ctx.exception.code, "toolcall-predicate-invalid")

    def test_bool_int_not_confused(self):
        with self.assertRaises(rp.PredicateError):
            rp.compile_predicate(
                {"op": "eq", "args": [{"const": True}, {"const": 1}]})

    def test_non_bool_result_pinned(self):
        with self.assertRaises(rp.PredicateError):
            rp.compile_predicate({"op": "len",
                                  "args": [{"field": "last_tool"}]})

    def test_over_node_budget(self):
        big = {"field": "started"}
        for _ in range(rp.MAX_AST_NODES + 5):
            big = {"op": "and", "args": [big, {"field": "started"}]}
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate(big)
        self.assertEqual(ctx.exception.code, "toolcall-predicate-budget")

    def test_env_narrowing_ok(self):
        env = rp.compile_predicate_env({"calls": "int"})
        p = rp.compile_predicate(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 0}]}, env)
        self.assertTrue(p.evaluate({"calls": 0}))

    def test_env_widening_refused(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate_env({"calls": "int", "evil": "str"})
        self.assertEqual(ctx.exception.code,
                         "toolcall-predicate-undeclared-field")

    def test_env_type_lie_refused(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.compile_predicate_env({"calls": "str"})
        self.assertEqual(ctx.exception.code, "toolcall-predicate-invalid")


class TestEvaluatePhase(unittest.TestCase):
    def _fields(self, n, last="read"):
        return {"calls": n, "last_tool": last,
                "distinct_tools": 1 if n else 0, "started": bool(n)}

    def test_true_and_false(self):
        p = rp.compile_predicate(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 2}]})
        self.assertFalse(p.evaluate(self._fields(1)))
        self.assertTrue(p.evaluate(self._fields(2)))

    def test_logic_builtins(self):
        p = rp.compile_predicate(
            {"op": "and", "args": [
                {"field": "started"},
                {"op": "not", "args": [
                    {"op": "eq", "args": [{"field": "last_tool"},
                                          {"const": "write"}]}]}]})
        self.assertTrue(p.evaluate(self._fields(1, "read")))
        self.assertFalse(p.evaluate(self._fields(1, "write")))
        self.assertFalse(p.evaluate(self._fields(0)))

    def test_in_contains_len(self):
        pin = rp.compile_predicate(
            {"op": "in", "args": [{"field": "last_tool"},
                                  {"const": ["read", "exec"]}]})
        self.assertTrue(pin.evaluate(self._fields(1, "read")))
        self.assertFalse(pin.evaluate(self._fields(1, "write")))
        pcon = rp.compile_predicate(
            {"op": "contains", "args": [{"field": "last_tool"},
                                        {"const": "ea"}]})
        self.assertTrue(pcon.evaluate(self._fields(1, "read")))
        plen = rp.compile_predicate(
            {"op": "eq", "args": [{"op": "len",
                                   "args": [{"field": "last_tool"}]},
                                  {"const": 4}]})
        self.assertTrue(plen.evaluate(self._fields(1, "read")))

    def test_runtime_type_mismatch_coded(self):
        p = rp.compile_predicate(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]})
        with self.assertRaises(rp.PredicateError) as ctx:
            p.evaluate({"calls": "1", "last_tool": "", "distinct_tools": 0,
                        "started": True})
        self.assertEqual(ctx.exception.code, "toolcall-predicate-invalid")

    def test_immutable(self):
        p = rp.compile_predicate({"field": "started"})
        env_copy = p.environment
        env_copy["calls"] = "str"  # mutating the returned COPY is harmless
        self.assertEqual(p.environment["calls"], "int")  # compiled unchanged
        with self.assertRaises(rp.PredicateError):
            p.anything = 1

    def test_spec_mutation_post_freeze(self):
        spec = {"op": "gte", "args": [{"field": "calls"}, {"const": 9}]}
        p = rp.compile_predicate(spec)
        spec["args"][1]["const"] = 0
        spec["args"][0] = {"field": "started"}
        self.assertFalse(p.evaluate(self._fields(1)))

    def test_session_fields_aggregate_only(self):
        fields = rp.session_fields([{"tool": "a"}, {"tool": "b"},
                                    {"tool": "a"}])
        self.assertEqual(fields, {"calls": 3, "last_tool": "a",
                                  "distinct_tools": 2, "started": True})
        self.assertEqual(rp.session_fields([])["last_tool"], "")

    def test_session_fields_malformed_coded(self):
        with self.assertRaises(rp.PredicateError) as ctx:
            rp.session_fields([{"tool": 5}])
        self.assertEqual(ctx.exception.code, "toolcall-predicate-invalid")


class TestToolRulesWiring(unittest.TestCase):
    def test_false_predicate_sequence_violated(self):
        rs = _ruleset({"op": "gte",
                       "args": [{"field": "calls"}, {"const": 1}]})
        with self.assertRaises(tr.ToolRuleError) as ctx:
            rs.check_call("write", {}, [])
        self.assertEqual(ctx.exception.code, "toolcall-sequence-violated")

    def test_true_predicate_allowed(self):
        rs = _ruleset({"op": "gte",
                       "args": [{"field": "calls"}, {"const": 1}]})
        rec = rs.check_call("write", {}, [{"tool": "read"}])
        self.assertTrue(rec["allowed"])

    def test_undeclared_field_own_code_at_ruleset_compile(self):
        with self.assertRaises(tr.ToolRuleError) as ctx:
            _ruleset({"field": "nope"})
        self.assertEqual(ctx.exception.code,
                         "toolcall-predicate-undeclared-field")

    def test_type_confusion_maps_to_compile_invalid(self):
        with self.assertRaises(tr.ToolRuleError) as ctx:
            _ruleset({"op": "gt",
                      "args": [{"field": "last_tool"}, {"const": 1}]})
        self.assertEqual(ctx.exception.code, "toolcall-rule-compile-invalid")

    def test_when_and_predicate_mutually_exclusive(self):
        doc = {
            "format": "sasanam-tool-rule-set/v1",
            "name": "unit",
            "tools": ["read", "write"],
            "predicates": {"p1": {"kind": "flag", "flag": "f"}},
            "rules": [{"kind": "Conditional", "tool": "write",
                       "when": "p1", "predicate": {"field": "started"}}],
        }
        with self.assertRaises(tr.ToolRuleError) as ctx:
            tr.compile_rule_set(doc)
        self.assertEqual(ctx.exception.code, "toolcall-rule-compile-invalid")

    def test_digest_covers_predicate(self):
        rs1 = _ruleset({"field": "started"})
        rs2 = _ruleset({"op": "not", "args": [{"field": "started"}]})
        self.assertNotEqual(rs1.digest, rs2.digest)

    def test_predicate_env_narrowing_in_ruleset(self):
        rs = _ruleset(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]},
            {"predicate_env": {"calls": "int", "started": "bool"}})
        self.assertTrue(rs.check_call("write", {},
                                      [{"tool": "read"}])["allowed"])
        with self.assertRaises(tr.ToolRuleError):
            _ruleset({"field": "last_tool"},
                     {"predicate_env": {"calls": "int"}})


if __name__ == "__main__":
    unittest.main()
