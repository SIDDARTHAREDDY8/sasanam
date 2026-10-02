#!/usr/bin/env python3
"""Unit tests for gov/tool_guardrails.py (wave-279 lane 4).

Tool-guardrail outcome triad (STEAL of openai/openai-agents-python
tool_guardrails.py, MIT; mechanism only): allow() / reject_content() /
raise_exception() outcomes; ordered evaluation with first-decisive-wins;
a tripwire record emitted for every guardrail run; raise_exception and
guard crashes fail closed as ToolGuardrailTripwireTriggered with the
distinct coded verdict tool-guardrail-tripwire; reject_content denies
without killing the run and never trips the wire.

Stdlib + gov.tool_guardrails only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import tool_guardrails as tg  # noqa: E402


def _in(tool_name="read_file", arguments=None):
    return tg.ToolInputGuardrailData(
        tool_name=tool_name,
        tool_arguments=dict(arguments or {}))


def _out(tool_name="read_file", output="ok"):
    return tg.ToolOutputGuardrailData(tool_name=tool_name, output=output)


class OutcomeFactoryTest(unittest.TestCase):
    def test_allow_behavior(self):
        o = tg.allow()
        self.assertIsInstance(o, tg.ToolGuardrailFunctionOutput)
        self.assertEqual(o.behavior, "allow")
        self.assertIsNone(o.message)

    def test_reject_content_carries_message(self):
        o = tg.reject_content("nope: bad path")
        self.assertEqual(o.behavior, "reject_content")
        self.assertEqual(o.message, "nope: bad path")

    def test_reject_content_empty_message_is_programming_error(self):
        for bad in ("", "   ", None, 123):
            with self.assertRaises(ValueError):
                tg.reject_content(bad)

    def test_raise_exception_behavior(self):
        o = tg.raise_exception()
        self.assertEqual(o.behavior, "raise_exception")

    def test_tripwire_carries_distinct_code(self):
        self.assertEqual(tg.ToolGuardrailTripwireTriggered.code,
                         "tool-guardrail-tripwire")
        self.assertTrue(issubclass(tg.ToolGuardrailTripwireTriggered,
                                   tg.ToolGuardrailError))


class GuardDeclarationTest(unittest.TestCase):
    def test_input_guard_needs_name_and_callable(self):
        with self.assertRaises(ValueError):
            tg.ToolInputGuardrail(name="", run=lambda d: tg.allow())
        with self.assertRaises(ValueError):
            tg.ToolInputGuardrail(name="x", run="not-callable")
        g = tg.ToolInputGuardrail(name="x", run=lambda d: tg.allow())
        self.assertEqual(g.phase, "input")

    def test_output_guard_phase(self):
        g = tg.ToolOutputGuardrail(name="y", run=lambda d: tg.allow())
        self.assertEqual(g.phase, "output")

    def test_phase_mismatch_refused(self):
        g = tg.ToolOutputGuardrail(name="y", run=lambda d: tg.allow())
        with self.assertRaises(ValueError):
            tg.run_input_guardrails([g], _in())

    def test_bad_data_type_refused(self):
        g = tg.ToolInputGuardrail(name="x", run=lambda d: tg.allow())
        with self.assertRaises(ValueError):
            tg.run_input_guardrails([g], _out())


class RunnerTest(unittest.TestCase):
    def test_allow_all_returns_allow_verdict(self):
        records = []
        g = tg.ToolInputGuardrail(name="g", run=lambda d: tg.allow())
        v = tg.run_input_guardrails([g], _in(), emit=records.append)
        self.assertEqual(v.outcome, "allow")
        self.assertFalse(v.tripwire_triggered)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["outcome"], "allow")
        self.assertIs(records[0]["tripwire_triggered"], False)

    def test_reject_returns_verdict_wire_quiet(self):
        records = []
        g = tg.ToolInputGuardrail(
            name="g", run=lambda d: tg.reject_content("denied: reason"))
        v = tg.run_input_guardrails([g], _in(), emit=records.append)
        self.assertEqual(v.outcome, "reject_content")
        self.assertEqual(v.message, "denied: reason")
        self.assertFalse(v.tripwire_triggered)
        self.assertIn("denied: reason", records[0]["output_info"])

    def test_raise_halts_with_coded_verdict(self):
        records = []
        g = tg.ToolInputGuardrail(
            name="g", run=lambda d: tg.raise_exception("veto"))
        with self.assertRaises(tg.ToolGuardrailTripwireTriggered) as ctx:
            tg.run_input_guardrails([g], _in(), emit=records.append)
        self.assertEqual(ctx.exception.code, "tool-guardrail-tripwire")
        self.assertTrue(records[0]["tripwire_triggered"])

    def test_crashed_guard_fails_closed_not_pass_through(self):
        records = []

        def _boom(d):
            raise RuntimeError("kaput")

        g = tg.ToolInputGuardrail(name="g", run=_boom)
        with self.assertRaises(tg.ToolGuardrailTripwireTriggered) as ctx:
            tg.run_input_guardrails([g], _in(), emit=records.append)
        self.assertEqual(ctx.exception.code, "tool-guardrail-tripwire")
        self.assertIn("kaput", records[0]["output_info"])

    def test_first_decisive_wins_rest_not_run(self):
        seen = []
        records = []
        gs = [
            tg.ToolInputGuardrail(
                name="g1",
                run=lambda d: (seen.append("g1"), tg.allow())[1]),
            tg.ToolInputGuardrail(
                name="g2",
                run=lambda d: (seen.append("g2"),
                               tg.reject_content("stop"))[1]),
            tg.ToolInputGuardrail(
                name="g3",
                run=lambda d: (seen.append("g3"), tg.allow())[1]),
        ]
        v = tg.run_input_guardrails(gs, _in(), emit=records.append)
        self.assertEqual(seen, ["g1", "g2"])
        self.assertEqual(v.outcome, "reject_content")
        self.assertEqual(len(records), 2)

    def test_garbage_outcome_is_programming_error(self):
        g = tg.ToolInputGuardrail(name="g", run=lambda d: "fine")
        with self.assertRaises(ValueError):
            tg.run_input_guardrails([g], _in())

    def test_output_guard_replaces_output_with_message(self):
        records = []
        g = tg.ToolOutputGuardrail(
            name="g",
            run=lambda d: tg.reject_content("output redacted")
            if "SECRET" in str(d.output) else tg.allow())
        v = tg.run_output_guardrails(
            [g], _out(output="SECRET=hunter2"), emit=records.append)
        self.assertEqual(v.outcome, "reject_content")
        self.assertNotIn("hunter2", v.message)
        self.assertEqual(records[0]["phase"], "output")

    def test_tripwire_record_shape(self):
        records = []
        g = tg.ToolInputGuardrail(name="named", run=lambda d: tg.allow())
        tg.run_input_guardrails([g], _in(tool_name="write_file"),
                                emit=records.append)
        rec = records[0]
        self.assertEqual(rec["event"], "tool_guardrail_run")
        self.assertEqual(rec["guardrail_name"], "named")
        self.assertEqual(rec["tool_name"], "write_file")
        self.assertEqual(rec["phase"], "input")
        self.assertIn("outcome", rec)
        self.assertIn("tripwire_triggered", rec)
        self.assertIn("output_info", rec)

    def test_empty_guardrail_list_allows(self):
        v = tg.run_input_guardrails([], _in())
        self.assertEqual(v.outcome, "allow")

    def test_evidence_capped_not_silent(self):
        records = []
        g = tg.ToolInputGuardrail(
            name="g", run=lambda d: tg.allow(output_info="x" * 5000))
        tg.run_input_guardrails([g], _in(), emit=records.append)
        self.assertLessEqual(len(records[0]["output_info"]), 2200)
        self.assertTrue(records[0]["output_info"].endswith("[truncated]"))


if __name__ == "__main__":
    unittest.main()
