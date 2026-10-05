"""Adapter tests: OpenAI Agents SDK native tool-input-guardrail shim.

No model API is ever called and the ``agents`` package is never imported
by the shim (it is an optional dependency): these tests drive the shim
against duck-typed stand-ins for the SDK's ``ToolInputGuardrailData`` /
``ToolContext`` shapes, verified against openai-agents 0.23.1 source
(``tool_guardrails.py``, ``tool_context.py``,
``run_internal/tool_execution.py``).

RED-FIRST baseline (passes on the unshimmed base tree): a function-tool-
shaped call with no shim executes with zero governance -- nothing is
mediated, denied, queued, or audited.

The shim (``gov.adapters.openai_agents``) maps ``GovernedBinding`` onto
the SDK's native ``tool_input_guardrails`` pipeline:
  executed -> allow
  denied   -> raise_exception tripwire (fail closed) [or reject_content]
  queued   -> raise_exception tripwire carrying the approval_id
             (human decides via the ApprovalQueue; the run is re-invoked)
             [or reject_content]
Malformed tool arguments fail closed via the tripwire. Hosted/built-in
tools, handoffs, and ``Agent.as_tool()`` nested runs never enter this
pipeline -- ``audit_agent_coverage`` refuses to certify an agent that
exposes any of them (honest boundary, tested below).
"""

import json
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import GovernedBinding, UnregisteredToolError


# ---------------------------------------------------------------------------
# Duck-typed stand-ins for the SDK shapes (verified against 0.23.1 source).
# ---------------------------------------------------------------------------

class _FakeToolContext:
    """Stands in for agents.tool_context.ToolContext.

    The SDK passes the RAW arguments string (tool_call.arguments) to
    input guardrails -- see ToolContext.from_agent_context and
    _execute_tool_input_guardrails in run_internal/tool_execution.py.
    """

    def __init__(self, tool_name, tool_arguments, tool_call_id="call_1"):
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments
        self.tool_call_id = tool_call_id


class _FakeGuardrailData:
    """Stands in for agents.tool_guardrails.ToolInputGuardrailData."""

    def __init__(self, context, agent=None):
        self.context = context
        self.agent = agent


class _FakeFunctionTool:
    """Duck-typed FunctionTool: the ONLY SDK tool kind that carries
    tool_input_guardrails (verified: no hosted/built-in tool class in
    agents/tool.py defines the attribute)."""

    def __init__(self, name, guardrails=(), is_agent_tool=False):
        self.name = name
        self.tool_input_guardrails = list(guardrails)
        if is_agent_tool:
            # The SDK's own marker, set by Agent.as_tool()
            # (agents/agent.py: run_agent_tool._is_agent_tool = True).
            self._is_agent_tool = True


class _FakeHostedTool:
    """Duck-typed hosted/built-in tool (WebSearchTool, ShellTool, ...):
    no tool_input_guardrails attribute -- outside the guardrail pipeline."""

    def __init__(self, name):
        self.name = name


class _FakeAgent:
    def __init__(self, name, tools, handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _guardrail_data(tool_name, arguments):
    return _FakeGuardrailData(
        _FakeToolContext(tool_name, json.dumps(arguments)))


# ---------------------------------------------------------------------------
# RED-FIRST baseline: the unshimmed base tree mediates nothing.
# ---------------------------------------------------------------------------

class TestUnshimmedBaseline(unittest.TestCase):
    def test_shim_module_now_exists(self):
        # RED-phase baseline (base tree) asserted ImportError here: no
        # shim existed, so SDK function-tool calls ran unmediated. The
        # shim now exists; the unmediated demonstration below is kept as
        # the documented hole the shim closes.
        import gov.adapters.openai_agents  # noqa: F401

    def test_unmediated_function_tool_call_executes_without_audit(self):
        # Simulates the SDK's default path: the function tool body runs
        # directly. No executor, no denial, no queue, no audit entry.
        ctx = make_run()
        side_effects = []

        def unshimmed_tool_body(path, content):
            side_effects.append((path, content))
            return "wrote %s" % path

        out = unshimmed_tool_body(path="/tmp/unshimmed-baseline.txt",
                                  content="no governance here")
        self.assertEqual(out, "wrote /tmp/unshimmed-baseline.txt")
        self.assertEqual(len(side_effects), 1)
        log_text = "".join(
            e.get("event", "") for e in ctx["read_log"]())
        self.assertNotIn("unshimmed", log_text)
        self.assertEqual(
            [r for r in ctx["approvals"].all()], [],
            "no approval record exists for the unmediated call")


# ---------------------------------------------------------------------------
# The shim (RED until gov.adapters.openai_agents exists).
# ---------------------------------------------------------------------------

def _import_shim():
    from gov.adapters import openai_agents as shim
    return shim


class TestMakeToolInputGuardrail(unittest.TestCase):
    def test_unregistered_tool_fails_closed_at_construction(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        with self.assertRaises(UnregisteredToolError):
            shim.make_tool_input_guardrail(binding, "drop_database")

    def test_executed_call_allows(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "write_file")
        out = guard(_guardrail_data("write_file",
                                    {"path": "notes.txt",
                                     "content": "hello"}))
        self.assertEqual(out.behavior["type"], "allow")
        self.assertTrue(
            (ctx["run_dir"] / "sandbox" / "notes.txt").is_file())

    def test_denied_call_trips_wire_fail_closed(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)  # coder may not send_email
        guard = shim.make_tool_input_guardrail(binding, "send_email")
        out = guard(_guardrail_data(
            "send_email",
            {"to": "x@synthetic.local", "subject": "s", "body": "b"}))
        # Fail closed: the SDK raises ToolGuardrailTripwireTriggered for
        # raise_exception, halting the run. Nothing was executed.
        self.assertEqual(out.behavior["type"], "raise_exception")
        info = out.output_info
        self.assertEqual(info["governance"], "sasanam")
        self.assertEqual(info["decision"], "denied")
        self.assertIn("policy_id", info)
        self.assertNotIn("x@synthetic.local", json.dumps(
            [e.get("event", "") for e in ctx["read_log"]()]))

    def test_denied_call_return_mode_rejects_content(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(
            binding, "send_email", on_denied="return")
        out = guard(_guardrail_data(
            "send_email",
            {"to": "x@synthetic.local", "subject": "s", "body": "b"}))
        self.assertEqual(out.behavior["type"], "reject_content")
        self.assertIn("message", out.behavior)
        self.assertTrue(out.behavior["message"])

    def test_queued_call_trips_wire_with_approval_id(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "write_file")
        out = guard(_guardrail_data(
            "write_file",
            {"path": "/tmp/adapter-should-not-write.txt", "content": "x"}))
        self.assertEqual(out.behavior["type"], "raise_exception")
        info = out.output_info
        self.assertEqual(info["decision"], "queued")
        approval_id = info.get("approval_id")
        self.assertIsNotNone(approval_id)
        # The approval is really in OUR queue (human decides there).
        rec = ctx["approvals"].get(approval_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "pending")
        self.assertFalse(os.path.exists("/tmp/adapter-should-not-write.txt"),
                         "queued call must not execute anywhere")

    def test_queued_call_return_mode_rejects_with_approval_notice(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(
            binding, "write_file", on_queued="return")
        out = guard(_guardrail_data(
            "write_file",
            {"path": "/tmp/adapter-should-not-write-2.txt",
             "content": "x"}))
        self.assertEqual(out.behavior["type"], "reject_content")
        self.assertIn("approval", out.behavior["message"].lower())

    def test_malformed_arguments_fail_closed(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "write_file")
        for bad_raw in ("{not json", "[1, 2]", '"just a string"', "42"):
            data = _FakeGuardrailData(
                _FakeToolContext("write_file", bad_raw))
            out = guard(data)
            self.assertEqual(
                out.behavior["type"], "raise_exception",
                "raw=%r must trip the wire, not execute" % (bad_raw,))
            self.assertEqual(out.output_info["governance"], "sasanam")
        self.assertFalse((ctx["run_dir"] / "sandbox" / "notes.txt").exists())

    def test_sdk_tool_name_mismatch_fails_closed(self):
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        # Guardrail built for the SDK tool "write_file" but attached to a
        # different FunctionTool: misconfiguration, fail closed.
        guard = shim.make_tool_input_guardrail(
            binding, "write_file", expect_sdk_tool_name="write_file")
        out = guard(_guardrail_data("read_file", {"path": "notes.txt"}))
        self.assertEqual(out.behavior["type"], "raise_exception")
        self.assertIn("misconfig", out.output_info["error"])

    def test_guardrail_accepts_bare_context_too(self):
        # Duck-typing: the guardrail reads .context when present, else
        # treats the argument itself as the tool context.
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "write_file")
        out = guard(_FakeToolContext(
            "write_file",
            json.dumps({"path": "bare.txt", "content": "x"})))
        self.assertEqual(out.behavior["type"], "allow")

    def test_output_shape_matches_sdk_contract(self):
        # The SDK's _execute_tool_input_guardrails reads
        # gr_out.behavior["type"] and gr_out.behavior["message"], and the
        # guardrail function may be sync (MaybeAwaitable).
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "write_file")
        self.assertTrue(callable(guard))
        out = guard(_guardrail_data("write_file",
                                    {"path": "shape.txt", "content": "x"}))
        self.assertIn(out.behavior["type"],
                      ("allow", "reject_content", "raise_exception"))
        self.assertIsNotNone(getattr(out, "output_info", None))


class TestAuditAgentCoverage(unittest.TestCase):
    def _clean_agent(self, shim, ctx):
        # F426 strict close-when: a correctly attached guardrail DECLARES
        # its SDK tool (expect_sdk_tool_name); the audit refuses any
        # FunctionTool whose guardrail declares none or a mismatched name.
        binding = _coder_binding(ctx)
        g1 = shim.make_tool_input_guardrail(binding, "write_file",
                                            expect_sdk_tool_name="write_file")
        g2 = shim.make_tool_input_guardrail(binding, "read_file",
                                            expect_sdk_tool_name="read_file")
        tools = [
            _FakeFunctionTool("write_file", guardrails=[g1]),
            _FakeFunctionTool("read_file", guardrails=[g2]),
        ]
        return _FakeAgent("coder-agent", tools), binding

    def test_clean_agent_passes_audit(self):
        shim = _import_shim()
        ctx = make_run()
        agent, _ = self._clean_agent(shim, ctx)
        report = shim.audit_agent_coverage(agent)
        self.assertEqual(report["handoffs"], [])
        self.assertEqual(sorted(report["tools"]), ["read_file", "write_file"])

    def test_handoff_is_flagged_outside_visibility(self):
        # The SDK's guardrail pipeline does not run for handoffs: the
        # audit must refuse to certify, not silently pass.
        shim = _import_shim()
        ctx = make_run()
        agent, _ = self._clean_agent(shim, ctx)
        agent.handoffs.append(object())  # a handoff target
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("handoff", str(cm.exception).lower())

    def test_hosted_tool_is_flagged_outside_visibility(self):
        # WebSearchTool / ShellTool / HostedMCPTool / ... have no
        # tool_input_guardrails in the SDK -- the shim cannot see them.
        shim = _import_shim()
        ctx = make_run()
        agent, _ = self._clean_agent(shim, ctx)
        agent.tools.append(_FakeHostedTool("web_search"))
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("web_search", str(cm.exception))

    def test_as_tool_nested_run_is_flagged_outside_visibility(self):
        # Agent.as_tool() wraps a nested agent run in a FunctionTool: the
        # guardrail sees only the outer input string, never the nested
        # tool calls. Flagged, not silently passed.
        shim = _import_shim()
        ctx = make_run()
        agent, binding = self._clean_agent(shim, ctx)
        nested_guard = shim.make_tool_input_guardrail(binding, "write_file")
        agent.tools.append(_FakeFunctionTool(
            "researcher", guardrails=[nested_guard], is_agent_tool=True))
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("researcher", str(cm.exception))
        self.assertIn("as_tool", str(cm.exception))

    def test_declared_nested_agent_tool_is_flagged(self):
        shim = _import_shim()
        ctx = make_run()
        agent, binding = self._clean_agent(shim, ctx)
        g = shim.make_tool_input_guardrail(binding, "write_file")
        agent.tools.append(_FakeFunctionTool("helper", guardrails=[g]))
        with self.assertRaises(shim.UncoveredSurfaceError):
            shim.audit_agent_coverage(agent, nested_agent_tools={"helper"})

    def test_none_agent_fails_closed(self):
        shim = _import_shim()
        with self.assertRaises(shim.UncoveredSurfaceError):
            shim.audit_agent_coverage(None)

    def test_function_tool_without_our_guardrail_is_flagged(self):
        shim = _import_shim()
        ctx = make_run()
        agent, binding = self._clean_agent(shim, ctx)
        agent.tools.append(_FakeFunctionTool("write_file"))  # no guardrail
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("write_file", str(cm.exception))

    # -- F426: guardrail<->tool correspondence --------------------------

    def test_issued_guardrail_exposes_correspondence_attributes(self):
        # The audit can only verify the correspondence because the
        # issued guardrail exposes framework_tool and
        # expect_sdk_tool_name as attributes (not mere closure vars).
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        g = shim.make_tool_input_guardrail(binding, "write_file",
                                           expect_sdk_tool_name="write_file")
        self.assertEqual(g.framework_tool, "write_file")
        self.assertEqual(g.expect_sdk_tool_name, "write_file")
        g2 = shim.make_tool_input_guardrail(binding, "read_file")
        self.assertEqual(g2.framework_tool, "read_file")
        self.assertIsNone(g2.expect_sdk_tool_name)

    def test_misattached_guardrail_without_declared_name_is_flagged(self):
        # F426 primary shape: read_file guardrail on the delete_file
        # tool, declaring no name -- the audit must refuse, not certify.
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        g = shim.make_tool_input_guardrail(binding, "read_file")
        agent = _FakeAgent("miswired",
                           [_FakeFunctionTool("delete_file",
                                              guardrails=[g])])
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("delete_file", str(cm.exception))
        self.assertIn("expect_sdk_tool_name", str(cm.exception))

    def test_misattached_guardrail_with_mismatched_name_is_flagged(self):
        # F426 variant: the declared name is consulted, not ignored -- a
        # guardrail declaring "read_file" on the delete_file tool is
        # refused.
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        g = shim.make_tool_input_guardrail(binding, "read_file",
                                           expect_sdk_tool_name="read_file")
        agent = _FakeAgent("miswired",
                           [_FakeFunctionTool("delete_file",
                                              guardrails=[g])])
        with self.assertRaises(shim.UncoveredSurfaceError) as cm:
            shim.audit_agent_coverage(agent)
        self.assertIn("read_file", str(cm.exception))
        self.assertIn("delete_file", str(cm.exception))

    def test_undeclared_name_refused_despite_name_coincidence(self):
        # A guardrail declaring no name is refused even when its
        # framework_tool name coincides with the SDK tool's name.
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        g = shim.make_tool_input_guardrail(binding, "write_file")
        agent = _FakeAgent("coincidence",
                           [_FakeFunctionTool("write_file",
                                              guardrails=[g])])
        with self.assertRaises(shim.UncoveredSurfaceError):
            shim.audit_agent_coverage(agent)

    def test_arg_shape_mismatch_refuses_coded_not_bare_keyerror(self):
        # F426 second shape: a bare KeyError from mediation must refuse
        # coded guardrail_argument_shape_mismatch via the tripwire,
        # never escape the guardrail uncoded.
        shim = _import_shim()
        ctx = make_run()
        binding = _coder_binding(ctx)
        g = shim.make_tool_input_guardrail(binding, "write_file")
        out = g(_guardrail_data("write_file",
                               {"to": "x@synthetic.local",
                                "subject": "s", "body": "b"}))
        self.assertEqual(out.behavior["type"], "raise_exception")
        self.assertEqual((out.output_info or {}).get("error"),
                         "guardrail_argument_shape_mismatch")


class TestHonestBoundary(unittest.TestCase):
    def test_residual_surfaces_are_documented(self):
        # The documented residual is a tested contract: hosted/built-in
        # tools, handoffs, and as_tool() must be NAMED as uncovered. If
        # the doc ever stops naming them, this test fails loudly.
        shim = _import_shim()
        doc = " ".join(shim.RESIDUAL_SURFACES).lower()
        for surface in ("hosted", "handoff", "as_tool"):
            self.assertIn(surface, doc,
                          "residual doc must name %r" % surface)

    def test_shim_works_without_sdk_installed(self):
        # The agents package is an optional dependency; the shim must
        # mediate (via its stand-in output shape) even when it is absent.
        shim = _import_shim()
        self.assertFalse(shim.sdk_available())
        ctx = make_run()
        binding = _coder_binding(ctx)
        guard = shim.make_tool_input_guardrail(binding, "send_email")
        out = guard(_guardrail_data(
            "send_email",
            {"to": "x@synthetic.local", "subject": "s", "body": "b"}))
        self.assertEqual(out.behavior["type"], "raise_exception")


if __name__ == "__main__":
    unittest.main()
