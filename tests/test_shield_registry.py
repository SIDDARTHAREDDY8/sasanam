"""Unit tests for gov/shield_registry.py (wave-280 lane 6)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import shield_registry as sr
from gov import tool_guardrails as tg
from gov.guardrail_evidence import (
    GuardrailEvidenceWriter,
    GuardrailFailureError,
    guardrail_run_records,
    verify_guardrail_records,
)
from gov.log import ActionLog


def _allow(data):
    return sr.ShieldVerdict("allow", "clean")


def _writer():
    d = tempfile.mkdtemp(prefix="g280u_",
                         dir=os.environ.get("TMPDIR"))
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    return log, GuardrailEvidenceWriter(log)


class RegistryTest(unittest.TestCase):
    def test_register_get_list(self):
        reg = sr.ShieldRegistry()
        sh = reg.register("s", params={"k": 1}, run=_allow)
        self.assertIs(reg.get("s"), sh)
        self.assertEqual(reg.list_shields(), ["s"])
        self.assertEqual(sh.params, {"k": 1})

    def test_duplicate_refused(self):
        reg = sr.ShieldRegistry()
        reg.register("s", run=_allow)
        with self.assertRaises(sr.ShieldError) as ctx:
            reg.register("s", run=_allow)
        self.assertEqual(ctx.exception.code, "shield-duplicate-id")

    def test_codes_are_machine_readable(self):
        with self.assertRaises(sr.ShieldViolation) as ctx:
            raise sr.ShieldViolation("s", "nope")
        self.assertEqual(ctx.exception.code, "shield-violation")
        self.assertEqual(ctx.exception.shield_id, "s")
        reg = sr.ShieldRegistry()
        with self.assertRaises(sr.ShieldResolutionError) as ctx:
            reg.get("ghost")
        self.assertEqual(ctx.exception.code, "shield-unknown-id")
        with self.assertRaises(sr.ShieldError) as ctx:
            sr.ShieldVerdict("maybe", "x")
        self.assertEqual(ctx.exception.code, "shield-bad-verdict")
        with self.assertRaises(sr.ShieldError) as ctx:
            sr.Shield("s", provider_kind="remote", run=_allow)
        self.assertEqual(ctx.exception.code, "shield-remote-no-endpoint")

    def test_unknown_get_refused(self):
        reg = sr.ShieldRegistry()
        with self.assertRaises(sr.ShieldResolutionError):
            reg.get("nope")

    def test_bad_params_refused(self):
        reg = sr.ShieldRegistry()
        with self.assertRaises(ValueError):
            reg.register("s", params={"f": object()}, run=_allow)

    def test_bad_verdict_refused(self):
        with self.assertRaises(ValueError):
            sr.ShieldVerdict("maybe", "x")

    def test_remote_needs_endpoint(self):
        reg = sr.ShieldRegistry()
        with self.assertRaises(ValueError):
            reg.register("r", provider_kind="remote", run=_allow)
        sh = reg.register("r2", provider_kind="remote",
                          endpoint="https://x.example/v1", run=_allow)
        self.assertEqual(sh.provider_kind, "remote")


class RunnerTest(unittest.TestCase):
    def test_allow_returns_ordered(self):
        reg = sr.ShieldRegistry()
        reg.register("a", run=_allow)
        reg.register("b", run=_allow)
        _, w = _writer()
        got = sr.run_input_shields(reg, ["b", "a"], {"t": 1}, writer=w)
        self.assertEqual(got, [("b", "allow"), ("a", "allow")])

    def test_violation_raises_with_detail(self):
        reg = sr.ShieldRegistry()
        reg.register("v", run=lambda d: sr.ShieldVerdict("violation", "nope"))
        _, w = _writer()
        with self.assertRaises(sr.ShieldViolation) as ctx:
            sr.run_input_shields(reg, ["v"], {"t": 1}, writer=w)
        self.assertIn("nope", str(ctx.exception))

    def test_first_violation_decisive(self):
        ran = []
        reg = sr.ShieldRegistry()
        reg.register("v", run=lambda d: ran.append("v") or
                     sr.ShieldVerdict("violation", "x"))
        reg.register("n", run=lambda d: ran.append("n") or
                     sr.ShieldVerdict("allow", ""))
        _, w = _writer()
        with self.assertRaises(sr.ShieldViolation):
            sr.run_input_shields(reg, ["v", "n"], {}, writer=w)
        self.assertEqual(ran, ["v"])

    def test_unknown_shield_fails_closed(self):
        reg = sr.ShieldRegistry()
        _, w = _writer()
        with self.assertRaises(sr.ShieldResolutionError):
            sr.run_output_shields(reg, ["ghost"], {"r": 1}, writer=w)

    def test_crash_fails_closed_technical_failure(self):
        def _boom(data):
            raise RuntimeError("x")

        reg = sr.ShieldRegistry()
        reg.register("c", run=_boom)
        log, w = _writer()
        with self.assertRaises(GuardrailFailureError):
            sr.run_input_shields(reg, ["c"], {}, writer=w)
        recs = guardrail_run_records(log)
        self.assertEqual(recs[-1]["outcome"], "technical_failure")
        self.assertEqual(recs[-1]["guardrail_id"], "shield:c")

    def test_verdicts_are_chained_loop_events(self):
        reg = sr.ShieldRegistry()
        reg.register("ok", run=_allow)
        reg.register("bad", run=lambda d: sr.ShieldVerdict("violation", "z"))
        log, w = _writer()
        sr.run_input_shields(reg, ["ok"], {"t": 1}, writer=w)
        with self.assertRaises(sr.ShieldViolation):
            sr.run_output_shields(reg, ["bad"], {"r": 1}, writer=w)
        recs = guardrail_run_records(log)
        self.assertTrue(verify_guardrail_records(recs))
        by_id = {r["guardrail_id"]: r for r in recs}
        self.assertEqual(by_id["shield:ok"]["outcome"], "allow")
        self.assertEqual(by_id["shield:ok"]["event_scope"], "input_shield")
        self.assertEqual(by_id["shield:ok"]["labels"],
                         {"provider_kind": "inline"})
        self.assertEqual(by_id["shield:bad"]["outcome"], "intentional_block")
        self.assertEqual(by_id["shield:bad"]["event_scope"], "output_shield")

    def test_remote_shield_label_marks_boundary(self):
        reg = sr.ShieldRegistry()
        reg.register("far", provider_kind="remote",
                     endpoint="https://x.example/v1", run=_allow)
        log, w = _writer()
        sr.run_input_shields(reg, ["far"], {"t": 1}, writer=w)
        recs = guardrail_run_records(log)
        self.assertTrue(verify_guardrail_records(recs))
        self.assertEqual(recs[0]["labels"],
                         {"provider_kind": "remote"})

    def test_non_verdict_return_fails_closed(self):
        reg = sr.ShieldRegistry()
        reg.register("j", run=lambda d: "allow")  # programming error
        _, w = _writer()
        with self.assertRaises(GuardrailFailureError):
            sr.run_input_shields(reg, ["j"], {}, writer=w)


class TriadCompositionTest(unittest.TestCase):
    def test_allow_and_violation(self):
        ok = sr.Shield("ok", provider_kind="inline", params={}, run=_allow)
        bad = sr.Shield("bad", provider_kind="inline", params={},
                        run=lambda d: sr.ShieldVerdict("violation", "policy no"))
        v_ok = tg.run_input_guardrails(
            [sr.as_tool_input_guardrail(ok)],
            tg.ToolInputGuardrailData("t", {"a": 1}))
        self.assertEqual(v_ok.outcome, "allow")
        v_bad = tg.run_input_guardrails(
            [sr.as_tool_input_guardrail(bad)],
            tg.ToolInputGuardrailData("t", {"a": 1}))
        self.assertEqual(v_bad.outcome, "reject_content")
        self.assertEqual(v_bad.message, "policy no")
        self.assertFalse(v_bad.tripwire_triggered)

    def test_crash_trips(self):
        def _boom(data):
            raise RuntimeError("x")

        boom = sr.Shield("boom", provider_kind="inline", params={}, run=_boom)
        with self.assertRaises(tg.ToolGuardrailTripwireTriggered):
            tg.run_input_guardrails(
                [sr.as_tool_input_guardrail(boom)],
                tg.ToolInputGuardrailData("t", {"a": 1}))

    def test_output_guardrail_replaces(self):
        bad = sr.Shield("bad", provider_kind="inline", params={},
                        run=lambda d: sr.ShieldVerdict("violation", "scrubbed"))
        v = tg.run_output_guardrails(
            [sr.as_tool_output_guardrail(bad)],
            tg.ToolOutputGuardrailData("t", "secret"))
        self.assertEqual(v.outcome, "reject_content")
        self.assertEqual(v.message, "scrubbed")


if __name__ == "__main__":
    unittest.main()
