"""Unit tests for gov/tool_budget.py (wave-337, R12 per-tool budgets).

Deterministic, no framework deps, stdlib only. The adversarial
battery is evals/w337_ratelimit2_probes.py; these tests pin the wire
contract for the canonical suite.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import tool_budget as tb


class TestNormalizeSection(unittest.TestCase):
    def test_absent_is_empty(self):
        self.assertEqual(tb.normalize_section(None), {})

    def test_defaults_cost_per_call_to_one(self):
        out = tb.normalize_section({"http_post": {"budget": 30}})
        self.assertEqual(out, {"http_post": (30.0, 1.0)})

    def test_explicit_cost(self):
        out = tb.normalize_section(
            {"snow": {"budget": 1.0, "cost_per_call": 0.4}})
        self.assertEqual(out, {"snow": (1.0, 0.4)})

    def test_glob_keys_pass_through(self):
        out = tb.normalize_section({"db.*": {"budget": 4}})
        self.assertEqual(out, {"db.*": (4.0, 1.0)})

    def test_non_mapping_refused(self):
        with self.assertRaises(tb.ToolBudgetConfigError):
            tb.normalize_section([1, 2])

    def test_unknown_key_refused(self):
        with self.assertRaises(tb.ToolBudgetConfigError):
            tb.normalize_section({"x": {"budget": 5, "bogus": 1}})

    def test_missing_budget_refused(self):
        with self.assertRaises(tb.ToolBudgetConfigError):
            tb.normalize_section({"x": {"cost_per_call": 1}})

    def test_non_positive_budget_refused(self):
        for bad in (0, -3):
            with self.assertRaises(tb.ToolBudgetConfigError):
                tb.normalize_section({"x": {"budget": bad}})

    def test_non_finite_refused(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(tb.ToolBudgetConfigError):
                tb.normalize_section({"x": {"budget": bad}})
            with self.assertRaises(tb.ToolBudgetConfigError):
                tb.normalize_section(
                    {"x": {"budget": 5, "cost_per_call": bad}})

    def test_bool_is_not_a_number(self):
        with self.assertRaises(tb.ToolBudgetConfigError):
            tb.normalize_section({"x": {"budget": True}})


class TestToolBudgetWire(unittest.TestCase):
    def test_charge_accumulates_and_exhausts(self):
        wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0)})
        self.assertEqual(wire.charge("http_post"), 1.0)
        self.assertEqual(wire.charge("http_post"), 2.0)
        with self.assertRaises(tb.ToolBudgetExhausted) as ctx:
            wire.charge("http_post")
        self.assertEqual(ctx.exception.code, "tool-budget-exhausted")

    def test_refused_call_records_no_spend(self):
        wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0)})
        wire.charge("http_post")
        wire.charge("http_post")
        with self.assertRaises(tb.ToolBudgetExhausted):
            wire.charge("http_post")
        self.assertEqual(
            wire.budget_state("http_post")["http_post"]["spent"], 2.0)

    def test_unlisted_tool_uncharged(self):
        wire = tb.ToolBudgetWire({"http_post": (5.0, 1.0)})
        for _ in range(50):
            self.assertEqual(wire.charge("api_call"), 0.0)

    def test_family_bucket_shared(self):
        wire = tb.ToolBudgetWire({"db.*": (4.0, 2.0)})
        wire.charge("db.query")
        wire.charge("db.execute")
        with self.assertRaises(tb.ToolBudgetExhausted):
            wire.charge("db.drop_table")

    def test_reset_tool_zeroes_matching_buckets(self):
        wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0),
                                  "http_*": (100.0, 1.0)})
        wire.charge("http_post")
        wire.reset_tool("http_post")
        state = wire.budget_state("http_post")
        self.assertEqual(state["http_post"]["spent"], 0.0)
        self.assertEqual(state["http_*"]["spent"], 0.0)

    def test_budget_state_unmatched_raises(self):
        wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0)})
        with self.assertRaises(tb.ToolBudgetConfigError):
            wire.budget_state("api_call")

    def test_limit_for_unmatched(self):
        wire = tb.ToolBudgetWire({"http_post": (2.0, 1.0)})
        self.assertEqual(wire.limit_for("api_call"), (0.0, 0.0))

    def test_exceptions_are_code_first(self):
        # Unregistered codes never leave the constructors.
        with self.assertRaises(Exception):
            tb.ToolBudgetExhausted("no-such-code", "x")
        with self.assertRaises(Exception):
            tb.ToolBudgetUnavailable("no-such-code", "x")
        with self.assertRaises(Exception):
            tb.ToolBudgetConfigError("no-such-code", "x")


class TestYamlminiQuotedKeys(unittest.TestCase):
    """Wave-337: yamlmini accepts quoted mapping keys (needed for
    fnmatch family keys like "db.*" in policy files)."""

    def test_double_quoted_key(self):
        from gov.yamlmini import parse
        d = parse('tool_rate_limits:\n  "send_*":\n    max_calls: 2\n')
        self.assertEqual(d, {"tool_rate_limits":
                             {"send_*": {"max_calls": 2}}})

    def test_single_quoted_key(self):
        from gov.yamlmini import parse
        d = parse("a:\n  'x-y': 1\n")
        self.assertEqual(d, {"a": {"x-y": 1}})

    def test_bare_keys_unchanged(self):
        from gov.yamlmini import parse
        d = parse("a: 1\nb:\n  c: 2\n")
        self.assertEqual(d, {"a": 1, "b": {"c": 2}})

    def test_unbalanced_quote_still_refuses(self):
        from gov.yamlmini import parse
        with self.assertRaises(ValueError):
            parse('a:\n  "x: 1\n')

    def test_empty_quoted_key_refused_downstream(self):
        from gov.yamlmini import parse
        d = parse('tool_budgets:\n  "":\n    budget: 5\n')
        with self.assertRaises(tb.ToolBudgetConfigError):
            tb.normalize_section(d["tool_budgets"])


if __name__ == "__main__":
    unittest.main()
