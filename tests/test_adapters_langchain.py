"""Adapter tests: LangChain governed tool shim.

Verifies every public LangChain execution path (invoke / run / ainvoke /
arun) is mediated, that denials/queued approvals surface without running
anything raw, that no raw callable is exposed, and documents the
framework-version funnel the mediation relies on.
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
    ApprovalRequiredError,
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)

try:
    from pydantic import BaseModel, ConfigDict, Field
    from gov.adapters.langchain_tools import (
        GovernedStructuredTool,
        make_governed_tool,
    )
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


if LANGCHAIN_AVAILABLE:
    class WriteArgs(BaseModel):
        # F62: governed tools require extra="allow" so undeclared kwargs
        # reach mediation instead of being silently dropped by
        # langchain-core before _run.
        model_config = ConfigDict(extra="allow")

        path: str = Field(description="Destination path")
        content: str = Field(description="Content to write")


    class EmailArgs(BaseModel):
        # F62: see WriteArgs.
        model_config = ConfigDict(extra="allow")

        to: str = Field(description="Recipient")
        subject: str = Field(description="Subject")
        body: str = Field(description="Body")


    def _coder_binding(ctx):
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        return GovernedBinding(ctx["executor"], ident)


    def _make_write_tool(binding, **kwargs):
        return make_governed_tool(
            binding,
            name="write_notes",
            description="Write a notes file.",
            args_schema=WriteArgs,
            framework_tool="write_file",
            **kwargs)


@unittest.skipUnless(LANGCHAIN_AVAILABLE, "langchain-core not installed")
class TestLangChainMediation(unittest.TestCase):
    def test_all_sync_paths_mediated(self):
        from langchain_core.tools import StructuredTool
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        self.assertIsInstance(tool, StructuredTool)
        self.assertIsInstance(tool, GovernedStructuredTool)

        for entry in ("invoke", "run"):
            path = "lc-%s.txt" % entry
            out = getattr(tool, entry)({"path": path, "content": "x"})
            payload = json.loads(out)
            self.assertEqual(payload["status"], "executed", entry)
            self.assertTrue(
                (ctx["run_dir"] / "sandbox" / path).is_file(), entry)
        # Both executions went through the binding (invoke + run).
        self.assertEqual(ctx["executor"].counters.get("write_file"), 2)

    def test_all_async_paths_mediated(self):
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))

        async def go():
            outs = []
            outs.append(await tool.ainvoke({"path": "a1.txt", "content": "x"}))
            outs.append(await tool.arun({"path": "a2.txt", "content": "x"}))
            return outs

        outs = asyncio.run(go())
        for out in outs:
            self.assertEqual(json.loads(out)["status"], "executed")
        self.assertTrue((ctx["run_dir"] / "sandbox" / "a1.txt").is_file())
        self.assertTrue((ctx["run_dir"] / "sandbox" / "a2.txt").is_file())

    def test_dunder_run_directly_is_still_mediated(self):
        """Even calling the overridden _run directly goes through the
        binding -- the mediation IS _run, not a wrapper around it."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        out = tool._run(config={}, path="d.txt", content="x")
        self.assertEqual(json.loads(out)["status"], "executed")

    def test_denied_raises_and_writes_nothing(self):
        ctx = make_run()
        tool = make_governed_tool(
            _coder_binding(ctx),  # coder may not send_email
            name="send_note",
            description="Send a note.",
            args_schema=EmailArgs,
            framework_tool="send_email")
        with self.assertRaises(ToolDeniedError):
            tool.invoke({"to": "x@synthetic.local", "subject": "s",
                         "body": "b"})
        # Denial is audited in the tamper-evident log.
        entries = [e for e in ctx["read_log"]()
                   if e.get("decision") == "denied"]
        self.assertTrue(entries)

    def test_queued_raises_approval_required(self):
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        with self.assertRaises(ApprovalRequiredError) as cm:
            tool.invoke({"path": "/tmp/lc-should-not-write.txt",
                         "content": "x"})
        self.assertIsNotNone(cm.exception.approval_id)
        self.assertFalse(os.path.exists("/tmp/lc-should-not-write.txt"))

    def test_no_raw_callable_exposed(self):
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        self.assertIsNone(tool.func,
                          "func must be None: no raw callable to steal")
        self.assertIsNone(tool.coroutine)
        # Invalid input is rejected by LangChain validation before
        # mediation is even reached.
        with self.assertRaises(Exception):
            tool.invoke({"path": "x.txt"})  # missing 'content'

    def test_unregistered_name_rejected_at_construction(self):
        ctx = make_run()
        with self.assertRaises(UnregisteredToolError):
            make_governed_tool(
                _coder_binding(ctx),
                name="drop_it",
                description="Nope.",
                args_schema=WriteArgs,
                framework_tool="drop_database")

    def test_tool_name_defaults_to_binding_name(self):
        ctx = make_run()
        tool = make_governed_tool(
            _coder_binding(ctx),
            name="write_file",  # native name; no framework_tool given
            description="Write.",
            args_schema=WriteArgs)
        out = tool.invoke({"path": "n.txt", "content": "x"})
        self.assertEqual(json.loads(out)["status"], "executed")

    def test_on_denied_return_mode(self):
        ctx = make_run()
        tool = make_governed_tool(
            _coder_binding(ctx),
            name="send_note",
            description="Send a note.",
            args_schema=EmailArgs,
            framework_tool="send_email",
            on_denied="return")
        out = tool.invoke({"to": "x@synthetic.local", "subject": "s",
                           "body": "b"})
        self.assertEqual(json.loads(out)["status"], "denied")

    def test_stream_path_mediated(self):
        """Runnable.stream() on a tool funnels through invoke -> _run;
        the streamed output must be the mediated result, exactly once."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        chunks = list(tool.stream({"path": "s.txt", "content": "x"}))
        self.assertTrue(chunks, "stream must yield at least one chunk")
        payload = json.loads(chunks[-1])
        self.assertEqual(payload["status"], "executed")
        self.assertEqual(ctx["executor"].counters.get("write_file"), 1,
                         "stream must mediate exactly one tool call")
        self.assertTrue((ctx["run_dir"] / "sandbox" / "s.txt").is_file())

    def test_retry_attempts_each_mediated(self):
        """with_retry() must not bypass mediation: every retry attempt is
        independently authorized, denied, and audited."""
        ctx = make_run()
        tool = make_governed_tool(
            _coder_binding(ctx),  # coder may not send_email
            name="send_note",
            description="Send a note.",
            args_schema=EmailArgs,
            framework_tool="send_email")
        retrying = tool.with_retry(stop_after_attempt=2, retry_if_exception_type=(ToolDeniedError,))
        with self.assertRaises(ToolDeniedError):
            retrying.invoke({"to": "x@synthetic.local", "subject": "s",
                             "body": "b"})
        self.assertEqual(ctx["executor"].counters.get("send_email"), 2,
                         "each retry attempt must be separately mediated")
        denials = [e for e in ctx["read_log"]()
                   if e.get("decision") == "denied"]
        self.assertEqual(len(denials), 2,
                         "each attempt must be separately audited")

    def test_funnel_assumption_pinned(self):
        """Pin the framework-version assumption mediation relies on:
        invoke() must funnel through run() into the overridden _run().
        If a future langchain-core changes this, this test fails loudly
        instead of silently unmediating."""
        import langchain_core
        from langchain_core.tools import BaseTool
        import inspect
        self.assertTrue(hasattr(BaseTool, "invoke"))
        self.assertTrue(hasattr(BaseTool, "run"))
        # _run must be the method our subclass overrides.
        self.assertEqual(GovernedStructuredTool._run.__qualname__,
                         "GovernedStructuredTool._run")
        src = inspect.getsource(BaseTool.run)
        self.assertIn("_run", src,
                      "BaseTool.run no longer delegates to _run?")
        print("\nlangchain-core version under test:",
              langchain_core.__version__)


if __name__ == "__main__":
    unittest.main()
