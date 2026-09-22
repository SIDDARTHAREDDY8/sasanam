"""R14 follow-up hardening tests (2026-09-21).

Item 1 -- F62 product-layer completion: gov/adapters/langchain_tools.py
fails closed at construction when the deployer-supplied args_schema does
not set extra="allow", so langchain-core can no longer silently drop
undeclared kwargs before mediation/DLP.

Item 2 -- gate TMPDIR hygiene: evals/run_evals.py cleans each cell's run
dirs in a finally block unless GOV_KEEP_CELL_DIRS=1.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from pydantic import BaseModel, ConfigDict
    from gov.adapters.core import GovernedBinding
    from gov.adapters.langchain_tools import (
        GovernedStructuredTool,
        make_governed_tool,
    )
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from tests.harness import make_run

REPO_ROOT = Path(__file__).resolve().parents[1]

# Synthetic AWS-docs access key (matches the dlp-aws-access-key pattern).
RAW_KEY = "AKIAIOSFODNN7EXAMPLE"


class _StrictArgs(BaseModel):
    """pydantic default: extra="ignore" -- the F62 hole."""

    to: str


class _AllowArgs(BaseModel):
    model_config = ConfigDict(extra="allow")

    to: str


def _support_binding(ctx):
    ident = ctx["mint_identity"]("sup-1", "support", "org")
    return GovernedBinding(ctx["executor"], ident)


@unittest.skipUnless(LANGCHAIN_AVAILABLE, "langchain-core not installed")
class TestF62ProductLayer(unittest.TestCase):
    """F62 follow-up: the PRODUCT adapter must not silently drop
    undeclared kwargs."""

    def test_strict_schema_rejected_at_construction(self):
        ctx = make_run()
        with self.assertRaises(Exception) as cm:
            make_governed_tool(_support_binding(ctx), name="send_email",
                               description="d", args_schema=_StrictArgs)
        msg = str(cm.exception).lower()
        self.assertIn("f62", msg)
        self.assertIn("extra", msg,
                      "error must name the cause (extra='allow')")

    def test_direct_construction_also_rejected(self):
        # The check lives on GovernedStructuredTool itself, so a
        # deployer bypassing make_governed_tool is still fail-closed.
        with self.assertRaises(Exception) as cm:
            GovernedStructuredTool(name="send_email", description="d",
                                   args_schema=_StrictArgs,
                                   func=None, coroutine=None)
        self.assertIn("extra", str(cm.exception).lower())

    def test_allow_schema_construction_succeeds(self):
        ctx = make_run()
        tool = make_governed_tool(_support_binding(ctx), name="send_email",
                                  description="d", args_schema=_AllowArgs)
        self.assertIsInstance(tool, GovernedStructuredTool)

    def test_reassignment_to_strict_schema_rejected(self):
        ctx = make_run()
        tool = make_governed_tool(_support_binding(ctx), name="send_email",
                                  description="d", args_schema=_AllowArgs)
        with self.assertRaises(Exception):
            tool.args_schema = _StrictArgs

    def test_bcc_kwarg_reaches_mediation_and_dlp(self):
        # The F62 payload: an AWS key smuggled in the undeclared kwarg
        # "bcc". It must be DENIED by dlp-credential-block -- never
        # silently clean -- and visible in the audit record.
        ctx = make_run()
        tool = make_governed_tool(
            _support_binding(ctx), name="send_email",
            description="d", args_schema=_AllowArgs,
            on_denied="return", on_queued="return")
        out = json.loads(tool.invoke({"to": "x@synthetic.local",
                                      "bcc": RAW_KEY}))
        self.assertEqual(out["status"], "denied")
        self.assertEqual(out["policy_id"], "dlp-credential-block")
        denied = [e for e in ctx["read_log"]()
                  if e.get("tool") == "send_email"
                  and e.get("decision") == "denied"]
        self.assertTrue(denied, "denial must be audit-logged")
        self.assertTrue(
            any("dlp-aws-access-key" in str(e.get("redactions_applied"))
                for e in denied),
            "the smuggled kwarg must be visible (redacted) in the "
            "approval/audit record, not dropped")


class TestCellDirHygiene(unittest.TestCase):
    """Item 2: per-cell run dirs are removed after the cell completes."""

    def _scratch(self, tmp, *names):
        paths = []
        for name in names:
            p = Path(tmp) / name
            p.mkdir()
            (p / "probe.txt").write_text("x")
            paths.append(str(p))
        return paths

    def test_cleanup_removes_only_harness_dirs(self):
        from evals.run_evals import _cleanup_cell_dirs
        with tempfile.TemporaryDirectory(prefix="hy-") as tmp:
            cell, run, other = self._scratch(
                tmp, "govcell-ledger-abc", "govred-abc", "do-not-touch")
            # F65 (R15): explicit tracking replaced the old prefix
            # allowlist — explicitly tracked dirs are removed regardless
            # of prefix (non-standard probe prefixes must be cleaned).
            _cleanup_cell_dirs(cell, run, other)
            self.assertFalse(Path(cell).exists())
            self.assertFalse(Path(run).exists())
            self.assertFalse(Path(other).exists(),
                             "tracked dirs are removed even with "
                             "non-harness prefixes")
        # Boundary protection (unchanged by F65): an explicitly passed
        # dir OUTSIDE the active temp root is never removed.
        with tempfile.TemporaryDirectory(prefix="hy-victim-") as tmp:
            victim = Path(tmp) / "victim"
            victim.mkdir()
            with mock.patch("tempfile.gettempdir",
                            return_value="/nonexistent-tmp-root-xyz"):
                _cleanup_cell_dirs(str(victim))
            self.assertTrue(victim.exists(),
                            "dirs outside the temp root must never be "
                            "removed")

    def test_cleanup_tolerates_missing_dirs(self):
        from evals.run_evals import _cleanup_cell_dirs
        _cleanup_cell_dirs("/nonexistent/govcell-ledger-x", None, "")
        # must not raise

    def test_keep_env_retains_dirs(self):
        from evals.run_evals import _cleanup_cell_dirs
        with tempfile.TemporaryDirectory(prefix="hy-") as tmp:
            (cell,) = self._scratch(tmp, "govcell-ledger-keep")
            with mock.patch.dict(os.environ, {"GOV_KEEP_CELL_DIRS": "1"}):
                _cleanup_cell_dirs(cell)
            self.assertTrue(Path(cell).exists(),
                            "GOV_KEEP_CELL_DIRS=1 must retain cell dirs")

    def test_run_cell_leaves_no_new_dirs(self):
        # End-to-end: two real gate cells in a FRESH constrained TMPDIR
        # (subprocess, so tempfile picks up the env) must leave zero new
        # govcell-ledger-*/govred-* dirs behind.
        script = (
            "import sys; sys.path.insert(0, '.');"
            "from evals.run_evals import run_cell;"
            "run_cell('sit1', 'langchain', 'standard', 'provisional');"
            "run_cell('sit1', 'langchain', 'standard', 'real');"
        )
        with tempfile.TemporaryDirectory(prefix="constr-tmp-") as tmp:
            env = dict(os.environ, TMPDIR=tmp)
            proc = subprocess.run(
                [sys.executable, "-c", script],
                cwd=str(REPO_ROOT), env=env,
                capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0,
                             "gate cells must still pass: %s"
                             % proc.stderr[-2000:])
            leftovers = sorted(p for p in os.listdir(tmp)
                               if p.startswith(("govcell-ledger-",
                                                 "govred-")))
            self.assertEqual(leftovers, [],
                             "cell run dirs leaked into TMPDIR")


if __name__ == "__main__":
    unittest.main()
