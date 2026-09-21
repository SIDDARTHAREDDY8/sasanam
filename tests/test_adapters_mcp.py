"""Adapter tests: MCP governed client wrapper.

Uses DeterministicFakeSession (no network). Verifies the session is
only touched after the executor allows the call, that denials/queued
approvals/unregistered names never reach the session, and that no
public path exposes the raw session.
"""

import asyncio
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.adapters.core import (
    ApprovalRequiredError,
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)
from gov.adapters.mcp_adapter import DeterministicFakeSession, GovernedMCPClient


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _run(coro):
    return asyncio.run(coro)


class TestGovernedMCPClient(unittest.TestCase):
    def test_allowed_call_reaches_session(self):
        ctx = make_run()
        session = DeterministicFakeSession(
            results={"write_file": {"ok": True, "server": "notes-svc"}})
        client = GovernedMCPClient(_coder_binding(ctx), session)
        result = _run(client.call_tool(
            "write_file", {"path": "mcp.txt", "content": "hi"}))
        self.assertEqual(result, {"ok": True, "server": "notes-svc"})
        self.assertEqual(session.calls,
                         [("write_file", {"path": "mcp.txt", "content": "hi"})])
        # The executor mediated it (audited), even though the server
        # produced the result.
        decisions = [e.get("decision") for e in ctx["read_log"]()]
        self.assertIn("execution_authorized", decisions)
        self.assertIn("allowed_executed", decisions)

    def test_denied_call_never_touches_session(self):
        ctx = make_run()
        session = DeterministicFakeSession()
        client = GovernedMCPClient(_coder_binding(ctx), session)  # coder
        with self.assertRaises(ToolDeniedError):
            _run(client.call_tool(
                "send_email",
                {"to": "x@synthetic.local", "subject": "s", "body": "b"}))
        self.assertEqual(session.calls, [],
                         "denied call must not reach the MCP server")

    def test_queued_call_never_touches_session(self):
        ctx = make_run()
        session = DeterministicFakeSession()
        client = GovernedMCPClient(_coder_binding(ctx), session)
        with self.assertRaises(ApprovalRequiredError):
            _run(client.call_tool(
                "write_file",
                {"path": "/tmp/mcp-should-not-write.txt", "content": "x"}))
        self.assertEqual(session.calls, [],
                         "queued call must not reach the MCP server")
        self.assertFalse(os.path.exists("/tmp/mcp-should-not-write.txt"))

    def test_unregistered_tool_fails_closed_before_session(self):
        ctx = make_run()
        session = DeterministicFakeSession()
        client = GovernedMCPClient(_coder_binding(ctx), session)
        with self.assertRaises(UnregisteredToolError):
            _run(client.call_tool("drop_database", {"name": "prod"}))
        self.assertEqual(session.calls, [])

    def test_no_public_session_accessor(self):
        ctx = make_run()
        client = GovernedMCPClient(_coder_binding(ctx),
                                   DeterministicFakeSession())
        self.assertFalse(hasattr(client, "session"),
                         "no public .session attribute may exist")
        self.assertNotIn("session", dir(client))
        self.assertNotIn("raw_session", dir(client))
        for attr in dir(client):
            self.assertFalse(
                attr.startswith("get_session") or attr == "unwrap",
                "no accessor may leak the session: %r" % attr)

    def test_alias_tool_map(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        binding = GovernedBinding(ctx["executor"], ident,
                                  tool_map={"store_note": "write_file"})
        session = DeterministicFakeSession()
        client = GovernedMCPClient(binding, session)
        result = _run(client.call_tool(
            "store_note", {"path": "a.txt", "content": "x"}))
        self.assertEqual(result["echo"], "store_note")
        # The server sees the framework-facing name it was asked for.
        self.assertEqual(session.calls[0][0], "store_note")
        self.assertIn("store_note", client.framework_tools)

    def test_arguments_must_be_dict(self):
        ctx = make_run()
        client = GovernedMCPClient(_coder_binding(ctx),
                                   DeterministicFakeSession())
        with self.assertRaises(TypeError):
            _run(client.call_tool("read_file", ["not", "a", "dict"]))

    def test_session_kwargs_forwarded_only_to_session(self):
        ctx = make_run()
        seen = {}

        class KwargSpySession(DeterministicFakeSession):
            async def call_tool(self, name, arguments=None, **kwargs):
                seen.update(kwargs)
                return await super().call_tool(name, arguments, **kwargs)

        client = GovernedMCPClient(_coder_binding(ctx), KwargSpySession())
        _run(client.call_tool("read_file", {"path": "x.txt"},
                              read_timeout_seconds=5))
        self.assertEqual(seen, {"read_timeout_seconds": 5})

    def test_list_tools_passthrough(self):
        ctx = make_run()
        session = DeterministicFakeSession(
            results={"read_file": {}, "write_file": {}})
        client = GovernedMCPClient(_coder_binding(ctx), session)
        tools = _run(client.list_tools())
        self.assertEqual(tools, [{"name": "read_file"}, {"name": "write_file"}])

    def test_constructor_validates(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        binding = GovernedBinding(ctx["executor"], ident)
        with self.assertRaises(TypeError):
            GovernedMCPClient("nope", DeterministicFakeSession())
        with self.assertRaises(TypeError):
            GovernedMCPClient(binding, None)
        with self.assertRaises(TypeError):
            GovernedMCPClient(binding, object())  # no call_tool

    def test_bypass_raw_session_is_unmediated_by_design(self):
        """Documents the deployment boundary: whoever holds the raw
        session can call it directly. The adapter removes every *public*
        path; never hand the raw session to agent code."""
        ctx = make_run()
        session = DeterministicFakeSession()
        GovernedMCPClient(_coder_binding(ctx), session)
        _run(session.call_tool(
            "send_email",
            {"to": "evil@example.com", "subject": "s", "body": "b"}))
        self.assertEqual(len(session.calls), 1)
        self.assertNotIn("send_email", ctx["executor"].counters,
                         "raw-session call bypassed the executor entirely")


if __name__ == "__main__":
    unittest.main()
