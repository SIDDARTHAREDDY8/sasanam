"""Adapter tests: CrewAI governed tool shim.

Verifies every public CrewAI execution path (run / arun) is mediated,
that denials/queued approvals surface without running anything raw,
that no raw callable is exposed, that the F62-class input hole
(undeclared kwargs silently dropped by BaseTool._validate_kwargs before
_run) is closed, and documents the framework-version funnel the
mediation relies on (crewai 1.15.23).

Skipped unless the 'crewai' extra is installed (optional dependency,
same convention as the LangChain adapter tests).
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
    from gov.adapters.crewai_tools import (
        GovernedCrewTool,
        make_governed_crewai_tool,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


if CREWAI_AVAILABLE:
    class WriteArgs(BaseModel):
        # F62 class: governed tools require extra="allow" so undeclared
        # kwargs reach mediation instead of being silently dropped by
        # BaseTool._validate_kwargs before _run.
        model_config = ConfigDict(extra="allow")

        path: str = Field(description="Destination path")
        content: str = Field(description="Content to write")


    class StrictArgs(BaseModel):
        # Deliberately strict: must be refused at construction.
        model_config = ConfigDict(extra="ignore")

        path: str = Field(description="Destination path")


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
        return make_governed_crewai_tool(
            binding,
            name="write_notes",
            description="Write a notes file.",
            args_schema=WriteArgs,
            framework_tool="write_file",
            **kwargs)


@unittest.skipUnless(CREWAI_AVAILABLE, "crewai not installed")
class TestCrewAIMediation(unittest.TestCase):
    def test_run_path_mediated(self):
        from crewai.tools import BaseTool
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        self.assertIsInstance(tool, BaseTool)
        self.assertIsInstance(tool, GovernedCrewTool)

        out = tool.run(path="crew-run.txt", content="x")
        payload = json.loads(out)
        self.assertEqual(payload["status"], "executed")
        self.assertTrue(
            (ctx["run_dir"] / "sandbox" / "crew-run.txt").is_file())
        self.assertEqual(ctx["executor"].counters.get("write_file"), 1)

    def test_arun_path_mediated(self):
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))

        async def go():
            return await tool.arun(path="crew-arun.txt", content="x")

        out = asyncio.run(go())
        self.assertEqual(json.loads(out)["status"], "executed")
        self.assertTrue(
            (ctx["run_dir"] / "sandbox" / "crew-arun.txt").is_file())

    def test_dunder_run_directly_is_still_mediated(self):
        """Even calling the overridden _run directly goes through the
        binding -- the mediation IS _run, not a wrapper around it."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        out = tool._run(path="d.txt", content="x")
        self.assertEqual(json.loads(out)["status"], "executed")

    def test_denied_raises_and_writes_nothing(self):
        ctx = make_run()
        tool = make_governed_crewai_tool(
            _coder_binding(ctx),  # coder may not send_email
            name="send_mail",
            description="Send an email.",
            args_schema=EmailArgs,
            framework_tool="send_email")
        with self.assertRaises(ToolDeniedError) as cm:
            tool.run(to="x@synthetic.local", subject="s", body="b")
        self.assertEqual(cm.exception.native_tool, "send_email")
        self.assertFalse(
            (ctx["run_dir"] / "sandbox" / "x").exists())

    def test_queued_raises_approval_required(self):
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        with self.assertRaises(ApprovalRequiredError) as cm:
            tool.run(path="/tmp/crewai-should-not-write.txt", content="x")
        self.assertIsNotNone(cm.exception.approval_id)
        self.assertFalse(os.path.exists("/tmp/crewai-should-not-write.txt"))

    def test_undeclared_kwarg_reaches_mediation_f62_class(self):
        """The F62-class hole: with extra='allow', a smuggled undeclared
        kwarg must reach mediation (and the audit record), not vanish in
        BaseTool._validate_kwargs."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        out = tool.run(path="f62.txt", content="x", bcc="evil@example.com")
        payload = json.loads(out)
        self.assertEqual(payload["status"], "executed")
        # The approval/audit record must show the smuggled kwarg. (The DLP
        # scan redacts the email VALUE as [REDACTED:pii-email]; the
        # property under test is that the kwarg was not silently dropped
        # before mediation.)
        found = any(
            "bcc" in (entry.get("args") or {})
            for entry in ctx["read_log"]()
            if entry.get("event") == "tool_call")
        self.assertTrue(found, "smuggled kwarg never reached the audit log")

    def test_strict_schema_refused_at_construction(self):
        """F62 class: a schema without extra='allow' fails closed at
        construction, not silently at first call."""
        ctx = make_run()
        with self.assertRaises(ValueError) as cm:
            make_governed_crewai_tool(
                _coder_binding(ctx),
                name="write_strict",
                description="Write, strictly.",
                args_schema=StrictArgs,
                framework_tool="write_file")
        self.assertIn("extra='allow'", str(cm.exception))

    def test_schema_reassignment_refused(self):
        """Post-construction reassignment to a strict schema is refused."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        with self.assertRaises(ValueError):
            tool.args_schema = StrictArgs

    def test_positional_args_refused(self):
        """run() skips schema validation when args are positional; the
        shim refuses to guess their meaning."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        with self.assertRaises(RuntimeError):
            tool.run("positional-input")

    def test_unregistered_name_refused_at_construction(self):
        ctx = make_run()
        with self.assertRaises(UnregisteredToolError):
            make_governed_crewai_tool(
                _coder_binding(ctx),
                name="nope",
                description="Not registered.",
                args_schema=WriteArgs,
                framework_tool="not_a_tool")

    def test_no_raw_callable_exposed(self):
        """BaseTool (unlike Tool) has no func field at all; the tool
        must not grow one."""
        ctx = make_run()
        tool = _make_write_tool(_coder_binding(ctx))
        self.assertFalse(hasattr(tool, "func"),
                         "governed tool must not expose a raw callable")
        # F31: the tool holds the facade, never the raw executor.
        self.assertFalse(hasattr(tool._facade, "executor"))
        self.assertFalse(hasattr(tool, "_binding"))

    def test_bad_modes_fail_closed(self):
        ctx = make_run()
        with self.assertRaises(ValueError):
            _make_write_tool(_coder_binding(ctx), on_denied="sometimes")
        with self.assertRaises(ValueError):
            _make_write_tool(_coder_binding(ctx), on_queued="sometimes")
        with self.assertRaises(TypeError):
            make_governed_crewai_tool(
                "not-a-binding", name="x", description="x",
                args_schema=WriteArgs, framework_tool="write_file")

    def test_funnel_assumption_pinned(self):
        """Pin the framework-version assumption mediation relies on:
        run() must delegate to the overridden _run(). If a future
        crewai changes this, this test fails loudly instead of silently
        unmediating."""
        import crewai
        from crewai.tools import BaseTool
        import inspect
        self.assertTrue(hasattr(BaseTool, "run"))
        self.assertEqual(GovernedCrewTool._run.__qualname__,
                         "GovernedCrewTool._run")
        src = inspect.getsource(BaseTool.run)
        self.assertIn("_run", src,
                      "BaseTool.run no longer delegates to _run?")
        print("\ncrewai version under test:", crewai.__version__)


if __name__ == "__main__":
    unittest.main()
