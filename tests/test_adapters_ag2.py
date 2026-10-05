"""Adapter tests: AG2 governance middleware shim.

Verifies the per-tool middleware (``governed_tool_middleware``) and the
agent-wide middleware (``GovernedAgentMiddleware``) mediate AG2 tool
executions: allowed calls reach the implementation exactly once, denied
/ queued / unregistered / malformed calls return a ``ToolErrorEvent``
and never invoke the implementation.

Uses the real AG2 event and middleware classes (verified against ag2
1.1.2); the agent loop itself is not driven (no model, no network --
the middleware seam is exercised directly with a recording
``call_next``).

Skipped unless the 'ag2' extra is installed (optional dependency, same
convention as the LangChain adapter tests).
"""

import asyncio
import json
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import (
    GovernedBinding,
    MalformedToolCallError,
)

try:
    from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent
    from ag2.middleware import BaseMiddleware, Middleware
    from gov.adapters.ag2_hooks import (
        GovernedAgentMiddleware,
        GovernedToolMiddleware,
        governed_tool_middleware,
    )
    AG2_AVAILABLE = True
except ImportError:
    AG2_AVAILABLE = False


if AG2_AVAILABLE:
    def _coder_binding(ctx):
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        return GovernedBinding(ctx["executor"], ident)


    def _call_event(name, arguments):
        return ToolCallEvent(name=name,
                             arguments=json.dumps(arguments))


    class _Recorder:
        """Stand-in for the downstream ToolExecution: records invocations
        and returns a successful ToolResultEvent."""
        def __init__(self):
            self.calls = []

        async def __call__(self, event, context):
            self.calls.append(event)
            return ToolResultEvent.from_call(
                event, result="implemented:%s" % event.name)


@unittest.skipUnless(AG2_AVAILABLE, "ag2 not installed")
class TestAG2ToolMiddleware(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_allowed_call_reaches_implementation_once(self):
        ctx = make_run()
        mw = governed_tool_middleware(_coder_binding(ctx))
        rec = _Recorder()
        event = _call_event("write_file",
                            {"path": "ag2-ok.txt", "content": "x"})
        out = self._run(mw(rec, event, None))
        self.assertIsInstance(out, ToolResultEvent)
        self.assertNotIsInstance(out, ToolErrorEvent)
        self.assertEqual(len(rec.calls), 1, "implementation must run once")
        self.assertTrue(
            (ctx["run_dir"] / "sandbox" / "ag2-ok.txt").is_file())
        self.assertEqual(ctx["executor"].counters.get("write_file"), 1)

    def test_denied_call_never_reaches_implementation(self):
        ctx = make_run()
        mw = governed_tool_middleware(_coder_binding(ctx))  # coder: no email
        rec = _Recorder()
        event = _call_event("send_email",
                            {"to": "x@synthetic.local", "subject": "s",
                             "body": "b"})
        out = self._run(mw(rec, event, None))
        self.assertIsInstance(out, ToolErrorEvent)
        self.assertEqual(rec.calls, [], "denied: implementation untouched")
        from gov.adapters.core import ToolDeniedError
        self.assertIsInstance(out.error, ToolDeniedError)
        # Denial is audited in the tamper-evident log.
        entries = [e for e in ctx["read_log"]()
                   if e.get("decision") == "denied"]
        self.assertTrue(entries)

    def test_queued_call_returns_error_event_with_approval_id(self):
        ctx = make_run()
        mw = governed_tool_middleware(_coder_binding(ctx))
        rec = _Recorder()
        event = _call_event("write_file",
                            {"path": "/tmp/ag2-should-not-write.txt",
                             "content": "x"})
        out = self._run(mw(rec, event, None))
        self.assertIsInstance(out, ToolErrorEvent)
        self.assertEqual(rec.calls, [], "queued: implementation untouched")
        from gov.adapters.core import ApprovalRequiredError
        self.assertIsInstance(out.error, ApprovalRequiredError)
        self.assertIsNotNone(out.error.approval_id)
        self.assertFalse(os.path.exists("/tmp/ag2-should-not-write.txt"))

    def test_unregistered_tool_never_reaches_implementation(self):
        ctx = make_run()
        mw = governed_tool_middleware(_coder_binding(ctx))
        rec = _Recorder()
        event = _call_event("not_a_tool", {"x": 1})
        out = self._run(mw(rec, event, None))
        self.assertIsInstance(out, ToolErrorEvent)
        self.assertEqual(rec.calls, [])
        from gov.adapters.core import UnregisteredToolError
        self.assertIsInstance(out.error, UnregisteredToolError)

    def test_malformed_arguments_never_reach_implementation(self):
        ctx = make_run()
        mw = governed_tool_middleware(_coder_binding(ctx))
        rec = _Recorder()
        for bad in ("not-json{", "[1, 2]"):
            event = ToolCallEvent(name="write_file", arguments=bad)
            out = self._run(mw(rec, event, None))
            self.assertIsInstance(out, ToolErrorEvent, bad)
            self.assertIsInstance(out.error, MalformedToolCallError, bad)
        self.assertEqual(rec.calls, [])

    def test_bad_binding_fails_closed_at_construction(self):
        with self.assertRaises(TypeError):
            GovernedToolMiddleware("not-a-binding")
        with self.assertRaises(TypeError):
            governed_tool_middleware(None)


@unittest.skipUnless(AG2_AVAILABLE, "ag2 not installed")
class TestAG2AgentMiddleware(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def _agent_mw(self, ctx):
        binding = _coder_binding(ctx)
        event = _call_event("write_file", {"path": "x", "content": "y"})
        return GovernedAgentMiddleware(event, None, binding=binding)

    def test_is_a_base_middleware(self):
        ctx = make_run()
        self.assertIsInstance(self._agent_mw(ctx), BaseMiddleware)

    def test_registers_through_ag2_factory(self):
        """The documented registration path -- Middleware(factory) --
        must accept the class with a binding option."""
        ctx = make_run()
        binding = _coder_binding(ctx)
        factory = Middleware(GovernedAgentMiddleware, binding=binding)
        event = _call_event("write_file", {"path": "x", "content": "y"})
        instance = factory(event, None)
        self.assertIsInstance(instance, GovernedAgentMiddleware)

    def test_agent_middleware_mediates_every_tool(self):
        ctx = make_run()
        mw = self._agent_mw(ctx)
        rec = _Recorder()
        good = _call_event("write_file", {"path": "ag2m-ok.txt",
                                          "content": "x"})
        out = self._run(mw.on_tool_execution(rec, good, None))
        self.assertNotIsInstance(out, ToolErrorEvent)
        self.assertEqual(len(rec.calls), 1)

        bad = _call_event("send_email", {"to": "x@synthetic.local",
                                         "subject": "s", "body": "b"})
        out = self._run(mw.on_tool_execution(rec, bad, None))
        self.assertIsInstance(out, ToolErrorEvent)
        self.assertEqual(len(rec.calls), 1, "denied call must not run")

    def test_agent_middleware_bad_binding_fails_closed(self):
        event = _call_event("write_file", {"path": "x", "content": "y"})
        with self.assertRaises(TypeError):
            GovernedAgentMiddleware(event, None, binding="nope")


if __name__ == "__main__":
    unittest.main()
