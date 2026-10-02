"""Unit tests for gov/guard_plugins.py (wave-281 lane 9).

Portkey-AI/gateway interface STEAL: ordered guard hooks with
allow/deny/transform outcomes, structural error->deny, deterministic
default guards. Composes with gov.guardrail_evidence and
gov.tool_guardrails; no product-loop integration in this lane.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import guard_plugins as gp
from gov import guardrail_evidence as ge
from gov.log import ActionLog, read_entries
from gov.guardrail_evidence import GuardrailEvidenceWriter


def _fresh():
    d = tempfile.mkdtemp(prefix="gp_ut_")
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    return log, GuardrailEvidenceWriter(log)


class OutcomeTests(unittest.TestCase):
    def test_verdict_vocab(self):
        self.assertEqual(gp.VERDICTS, ("allow", "deny", "transform"))
        self.assertEqual(gp.HOOKS, ("before_tool_call", "after_tool_call",
                                    "start", "end"))

    def test_deny_requires_detail(self):
        with self.assertRaises(ValueError):
            gp.deny_outcome("")
        with self.assertRaises(ValueError):
            gp.deny_outcome("   ")

    def test_transform_requires_dict(self):
        with self.assertRaises(gp.GuardPluginError) as cm:
            gp.transform_outcome(["x"])
        self.assertEqual(cm.exception.code, "guardplugin-bad-transform")

    def test_bad_verdict_refused(self):
        with self.assertRaises(gp.GuardPluginError) as cm:
            gp.PluginOutcome("maybe")
        self.assertEqual(cm.exception.code, "guardplugin-bad-verdict")

    def test_plugin_deny_code(self):
        e = gp.PluginDeny("no")
        self.assertEqual(e.code, "guardplugin-denied")
        self.assertIsInstance(e, gp.GuardPluginError)


class RegistryTests(unittest.TestCase):
    def _reg(self):
        return gp.PluginRegistry()

    def test_register_and_get(self):
        reg = self._reg()
        p = reg.register("g", hooks=("before_tool_call",),
                         run=lambda ctx: gp.allow_outcome())
        self.assertIs(reg.get("g"), p)
        self.assertEqual(reg.list_plugins(), ["g"])
        self.assertEqual(reg.for_hook("before_tool_call"), ["g"])
        self.assertEqual(reg.for_hook("after_tool_call"), [])

    def test_duplicate_id(self):
        reg = self._reg()
        run = lambda ctx: gp.allow_outcome()
        reg.register("g", hooks=("before_tool_call",), run=run)
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.register("g", hooks=("before_tool_call",), run=run)
        self.assertEqual(cm.exception.code, "guardplugin-duplicate-id")

    def test_unknown_id(self):
        reg = self._reg()
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.get("ghost")
        self.assertEqual(cm.exception.code, "guardplugin-unknown-id")

    def test_bad_hook(self):
        reg = self._reg()
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.register("g", hooks=("nope",),
                         run=lambda ctx: gp.allow_outcome())
        self.assertEqual(cm.exception.code, "guardplugin-bad-hook")

    def test_bad_params(self):
        reg = self._reg()
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.register("g", hooks=("before_tool_call",),
                         params={"x": object()},
                         run=lambda ctx: gp.allow_outcome())
        self.assertEqual(cm.exception.code, "guardplugin-bad-params")

    def test_bad_id(self):
        reg = self._reg()
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.register("", hooks=("before_tool_call",),
                         run=lambda ctx: gp.allow_outcome())
        self.assertEqual(cm.exception.code, "guardplugin-bad-id")

    def test_bad_run_not_callable(self):
        reg = self._reg()
        with self.assertRaises(gp.GuardPluginError) as cm:
            reg.register("g", hooks=("before_tool_call",), run="nope")
        self.assertEqual(cm.exception.code, "guardplugin-bad-run")

    def test_technical_failure_carries_code(self):
        from gov import guardrail_evidence as ge
        log, writer = _fresh()
        reg = gp.PluginRegistry()

        def _boom(ctx):
            raise RuntimeError("x")

        reg.register("b", hooks=("before_tool_call",), run=_boom)
        chain = gp.GuardChain(reg, writer, log)
        with self.assertRaises(ge.GuardrailFailureError) as cm:
            chain.run_hook("before_tool_call", tool_name="t", payload={})
        # The bridge carries the machine-readable code AND is caught
        # as the established GuardrailFailureError.
        self.assertEqual(cm.exception.code, "guardplugin-error-refused")
        self.assertIsInstance(cm.exception, gp.PluginTechnicalFailure)


class ChainTests(unittest.TestCase):
    def test_allow_chain(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()
        reg.register("a", hooks=("before_tool_call",),
                     run=lambda ctx: gp.allow_outcome())
        chain = gp.GuardChain(reg, writer, log)
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"x": 1})
        self.assertTrue(v.allowed)
        self.assertEqual(v.payload, {"x": 1})
        self.assertIsNone(v.denied_by)
        self.assertEqual(v.transforms, [])

    def test_deny_chain(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()
        reg.register("d", hooks=("before_tool_call",),
                     run=lambda ctx: gp.deny_outcome("no"))
        chain = gp.GuardChain(reg, writer, log)
        v = chain.run_hook("before_tool_call", tool_name="t", payload={})
        self.assertFalse(v.allowed)
        self.assertEqual(v.denied_by, "d")
        recs = [e for e in read_entries(log.path)
                if e.get("record_type") == "guardrail-run"]
        self.assertEqual(recs[0]["outcome"], "intentional_block")
        self.assertEqual(recs[0]["decision_effect"], "deny")

    def test_transform_chain_records_diff(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()

        def _t(ctx):
            p = dict(ctx.payload)
            p["b"] = 2
            return gp.transform_outcome(p, "added b")

        reg.register("t", hooks=("before_tool_call",), run=_t)
        chain = gp.GuardChain(reg, writer, log)
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"a": 1})
        self.assertTrue(v.allowed)
        self.assertEqual(v.payload, {"a": 1, "b": 2})
        self.assertEqual(len(v.transforms), 1)
        t = v.transforms[0]
        self.assertEqual(t["changed_keys"], ["b"])
        self.assertNotEqual(t["old_digest"], t["new_digest"])
        tevents = [e for e in read_entries(log.path)
                   if e.get("record_type") == "guard-plugin-transform"]
        self.assertEqual(len(tevents), 1)
        self.assertEqual(tevents[0]["changed_keys"], ["b"])

    def test_error_is_loud_deny(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()

        def _boom(ctx):
            raise RuntimeError("x")

        reg.register("b", hooks=("before_tool_call",), run=_boom)
        chain = gp.GuardChain(reg, writer, log)
        with self.assertRaises(ge.GuardrailFailureError):
            chain.run_hook("before_tool_call", tool_name="t", payload={})
        recs = [e for e in read_entries(log.path)
                if e.get("record_type") == "guardrail-run"]
        self.assertEqual(recs[0]["outcome"], "technical_failure")

    def test_unknown_id_before_any_run(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()
        ran = []
        reg.register("a", hooks=("before_tool_call",),
                     run=lambda ctx: ran.append(1) or gp.allow_outcome())
        chain = gp.GuardChain(reg, writer, log)
        with self.assertRaises(gp.GuardPluginError) as cm:
            chain.run_hook("before_tool_call", tool_name="t", payload={},
                           plugin_ids=("ghost", "a"))
        self.assertEqual(cm.exception.code, "guardplugin-unknown-id")
        self.assertEqual(ran, [])

    def test_payload_not_mutated_by_plugin(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()

        def _evil(ctx):
            ctx.payload["x"] = 999  # must not escape
            return gp.allow_outcome()

        reg.register("e", hooks=("before_tool_call",), run=_evil)
        chain = gp.GuardChain(reg, writer, log)
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"x": 1})
        self.assertEqual(v.payload, {"x": 1})


class DefaultGuardTests(unittest.TestCase):
    def _chain(self, only, params_override=None):
        log, writer = _fresh()
        reg = gp.PluginRegistry()
        gp.register_defaults(reg, only=only, params_override=params_override)
        return gp.GuardChain(reg, writer, log), log

    def test_pii_redact_kinds(self):
        chain, log = self._chain(("pii-redact",))
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"m": "a@b.co and 1-2-3 x"})
        self.assertTrue(v.allowed)
        # email redacted; the "1-2-3" is not an SSN shape
        self.assertIn("[REDACTED:email]", v.payload["m"])
        blob = open(log.path).read()
        self.assertNotIn("a@b.co", blob)

    def test_injection_deny(self):
        chain, _ = self._chain(("injection-substrings",))
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"q": "please JAILBREAK now"})
        self.assertFalse(v.allowed)
        v2 = chain.run_hook("before_tool_call", tool_name="t",
                            payload={"q": "a normal question"})
        self.assertTrue(v2.allowed)

    def test_allowlist_misconfigured_fails_closed(self):
        log, writer = _fresh()
        reg = gp.PluginRegistry()
        # no params at all -> tools missing -> technical failure
        reg.register("al", hooks=("before_tool_call",),
                     params={}, run=gp.DEFAULT_GUARDS["tool-allowlist"][2])
        chain = gp.GuardChain(reg, writer, log)
        with self.assertRaises(ge.GuardrailFailureError):
            chain.run_hook("before_tool_call", tool_name="t", payload={})

    def test_byte_budget(self):
        chain, _ = self._chain(
            ("arg-byte-budget",),
            params_override={"arg-byte-budget": {"max_bytes": 10}})
        v = chain.run_hook("before_tool_call", tool_name="t",
                           payload={"x": "y"})
        self.assertTrue(v.allowed)
        v2 = chain.run_hook("before_tool_call", tool_name="t",
                            payload={"x": "y" * 50})
        self.assertFalse(v2.allowed)

    def test_json_schema(self):
        chain, _ = self._chain(
            ("json-schema-args",),
            params_override={"json-schema-args": {
                "schema": {"required": ["a"], "types": {"a": "int"},
                           "no_additional": True}}})
        self.assertFalse(chain.run_hook(
            "before_tool_call", tool_name="t", payload={}).allowed)
        self.assertFalse(chain.run_hook(
            "before_tool_call", tool_name="t",
            payload={"a": "not-int"}).allowed)
        self.assertFalse(chain.run_hook(
            "before_tool_call", tool_name="t",
            payload={"a": 1, "extra": 2}).allowed)
        self.assertTrue(chain.run_hook(
            "before_tool_call", tool_name="t", payload={"a": 1}).allowed)

    def test_register_defaults_ids(self):
        reg = gp.PluginRegistry()
        ids = gp.register_defaults(reg)
        self.assertEqual(sorted(ids), sorted(gp.DEFAULT_GUARDS))
        self.assertEqual(reg.list_plugins(), sorted(gp.DEFAULT_GUARDS))


class TriadAdapterTests(unittest.TestCase):
    def test_adapter_maps(self):
        from gov import tool_guardrails as tg
        reg = gp.PluginRegistry()
        reg.register("d", hooks=("before_tool_call",),
                     run=lambda ctx: gp.deny_outcome("nope"))
        g = gp.as_tool_input_guardrail(reg.get("d"))
        self.assertIsInstance(g, tg.ToolInputGuardrail)
        out = g.run(tg.ToolInputGuardrailData(tool_name="t",
                                              tool_arguments={}))
        self.assertEqual(out.behavior, "reject_content")


if __name__ == "__main__":
    unittest.main()
