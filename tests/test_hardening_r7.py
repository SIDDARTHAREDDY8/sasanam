"""Hardening round-7 regression tests: wave-8 findings F27-F31.

Exact reproductions from evals/FINDINGS.md, grouped per finding.
No network, no clock dependence. Deterministic: key env is pinned in
setUp and restored afterwards.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

_KEY_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH")


def _pin_key_env():
    saved = {n: os.environ.get(n) for n in _KEY_NAMES}
    os.environ["GOV_LOG_KEY"] = "round-7-test-key-0123456789abcdef"
    os.environ.pop("GOV_LOG_KEY_EPOCH", None)

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


class _KeyPinnedCase(unittest.TestCase):
    def setUp(self):
        self._restore_env = _pin_key_env()

    def tearDown(self):
        self._restore_env()


# ---------------------------------------------------------------------------
# F27 — action-log checkpoint fail-closed (missing sidecar / truncation /
# sequence gaps)
# ---------------------------------------------------------------------------

class TestF27ActionLogFailClosed(_KeyPinnedCase):
    """Missing checkpoint sidecar for a non-empty log must fail closed."""

    def _log_with(self, n):
        from gov.log import ActionLog
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        log = ActionLog(path)
        for i in range(n):
            log.append({"event": "tool_call", "i": i})
        return d, path

    def test_missing_sidecar_after_truncation(self):
        # Exact F27 reproduction: 5 entries + checkpoint; delete the
        # sidecar; truncate to 2 entries -> verification must fail.
        from gov.log import _verify
        d, path = self._log_with(5)
        sidecar = d / "checkpoints.jsonl"
        self.assertTrue(sidecar.exists(), "setup: sidecar must exist")
        os.remove(sidecar)
        lines = Path(path).read_text().splitlines()
        Path(path).write_text("\n".join(lines[:2]) + "\n")
        verdict = _verify(path)
        self.assertFalse(verdict["ok"],
                         "deleted sidecar + truncation must fail closed")
        self.assertIn("MISSING", (verdict["error"] or ""))

    def test_missing_sidecar_typed_api_raises(self):
        from gov.log import require_verified, LogUnverifiableError
        d, path = self._log_with(5)
        os.remove(d / "checkpoints.jsonl")
        with self.assertRaises(LogUnverifiableError):
            require_verified(path)

    def test_sequence_gap_fails_closed(self):
        # Genesis-walk: drop seq 2 from a 1..3 chain -> gap, not OK.
        from gov.log import _verify
        d, path = self._log_with(3)
        lines = Path(path).read_text().splitlines()
        self.assertEqual(len(lines), 3)
        Path(path).write_text("\n".join([lines[0], lines[2]]) + "\n")
        verdict = _verify(path)
        self.assertFalse(verdict["ok"])
        self.assertIn("sequence gap", (verdict["error"] or ""))

    def test_empty_log_without_sidecar_stays_honest(self):
        # A genuinely empty, unused log is verifiable; nothing to check.
        from gov.log import _verify
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        Path(path).write_text("")
        verdict = _verify(path)
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["entries"], 0)


# ---------------------------------------------------------------------------
# F28 — corrupt checkpoint sidecar is a clean verdict, never an exception
# ---------------------------------------------------------------------------

class TestF28CorruptSidecar(_KeyPinnedCase):
    """Corrupt checkpoints.jsonl must not escape as JSONDecodeError."""

    def _log_with_corrupt_sidecar(self):
        from gov.log import ActionLog
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        ActionLog(path).append({"event": "tool_call"})
        (d / "checkpoints.jsonl").write_text("NOT JSON{{{\n\x00\n")
        return d, path

    def test_corrupt_sidecar_clean_failure(self):
        from gov.log import _verify
        d, path = self._log_with_corrupt_sidecar()
        verdict = _verify(path)  # must not raise
        self.assertFalse(verdict["ok"])
        self.assertIn("CORRUPT", (verdict["error"] or ""))

    def test_corrupt_sidecar_typed_api_raises(self):
        from gov.log import require_verified, LogUnverifiableError
        d, path = self._log_with_corrupt_sidecar()
        with self.assertRaises(LogUnverifiableError):
            require_verified(path)

    def test_empty_sidecar_fails_closed(self):
        from gov.log import ActionLog, _verify
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        ActionLog(path).append({"event": "tool_call"})
        (d / "checkpoints.jsonl").write_text("")
        verdict = _verify(path)
        self.assertFalse(verdict["ok"])
        self.assertIn("EMPTY", (verdict["error"] or ""))

    def test_clean_log_verifies(self):
        from gov.log import ActionLog, _verify, require_verified
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        for i in range(5):
            ActionLog(path).append({"event": "tool_call", "i": i})
        verdict = _verify(path)
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["checkpoints_checked"], 5)
        require_verified(path)  # must not raise


# ---------------------------------------------------------------------------
# F27/F28 — KeyRing.verify_log fails closed like gov.log._verify
# ---------------------------------------------------------------------------

class TestKeyRingVerifyLogFailClosed(_KeyPinnedCase):
    """The independent multi-epoch verification path mirrors the F27/F28
    fail-closed rules: missing/corrupt/empty sidecar on a non-empty log,
    and corrupt log JSON, all fail closed without raising."""

    def _log_with(self, n):
        from gov.log import ActionLog
        from gov.keys import KeyRing
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        log = ActionLog(path)
        for i in range(n):
            log.append({"event": "tool_call", "i": i})
        return d, path, KeyRing.from_env()

    def test_clean_log_verifies(self):
        d, path, ring = self._log_with(3)
        verdict = ring.verify_log(path)
        self.assertTrue(verdict["ok"], verdict["error"])
        self.assertGreater(verdict["checkpoints_checked"], 0)

    def test_missing_sidecar_after_truncation(self):
        d, path, ring = self._log_with(5)
        (d / "checkpoints.jsonl").unlink()
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        Path(path).write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        verdict = ring.verify_log(path)
        self.assertFalse(verdict["ok"])
        self.assertIn("MISSING", (verdict["error"] or ""))

    def test_corrupt_sidecar_no_crash(self):
        d, path, ring = self._log_with(2)
        (d / "checkpoints.jsonl").write_text("GARBAGE{{{\n\x00\n",
                                            encoding="utf-8")
        try:
            verdict = ring.verify_log(path)
        except Exception as exc:  # noqa: BLE001
            self.fail("verify_log raised on corrupt sidecar: %r" % exc)
        self.assertFalse(verdict["ok"])
        self.assertIn("CORRUPT", (verdict["error"] or ""))

    def test_empty_sidecar_fails_closed(self):
        d, path, ring = self._log_with(2)
        (d / "checkpoints.jsonl").write_text("", encoding="utf-8")
        verdict = ring.verify_log(path)
        self.assertFalse(verdict["ok"])
        self.assertIn("EMPTY", (verdict["error"] or ""))

    def test_corrupt_log_json_no_crash(self):
        d, path, ring = self._log_with(2)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("NOT JSON{{{\n")
        try:
            verdict = ring.verify_log(path)
        except Exception as exc:  # noqa: BLE001
            self.fail("verify_log raised on corrupt log JSON: %r" % exc)
        self.assertFalse(verdict["ok"])

    def test_empty_log_without_sidecar_stays_honest(self):
        from gov.keys import KeyRing
        d = Path(tempfile.mkdtemp())
        path = str(d / "actions.jsonl")
        Path(path).write_text("", encoding="utf-8")
        verdict = KeyRing.from_env().verify_log(path)
        self.assertTrue(verdict["ok"])


# ---------------------------------------------------------------------------
# F29 — report key-status disclosure (rendered text, not source)
# ---------------------------------------------------------------------------

class TestF29ReportKeyDisclosure(unittest.TestCase):
    """Non-production key epochs must be disclosed loudly in reports and
    integrity claims qualified; no unqualified "tamper-evident" claim.

    Wave-81: the published development key was removed from gov/ and the
    disclosure text changed from "PUBLIC/DEVELOPMENT" to the
    non-production epoch label contract below. The disclosure duty is
    unchanged — only the wording.
    """

    def _dev_entries(self):
        return [{"event": "tool_call", "key_epoch": "dev"} for _ in range(3)]

    def test_markdown_dev_key_disclosure(self):
        from demo.make_report import key_status, render_markdown
        key = key_status(self._dev_entries(), "dev")
        md = render_markdown("run-x", "2026-09-21", True, 3, [], [], key)
        self.assertIn("Non-production epoch label", md)
        self.assertIn("not a production custody claim", md)
        self.assertIn("not tamper-evidence against third parties", md)
        self.assertNotIn("tamper-evident log", md)

    def test_html_dev_key_disclosure(self):
        from demo.make_report import key_status, render_html
        key = key_status(self._dev_entries(), "dev")
        ht = render_html("run-x", "2026-09-21", True, 3, [], [], key)
        self.assertIn("Non-production epoch label", ht)
        self.assertIn("not a production custody claim", ht)
        self.assertIn("not tamper-evidence against third parties", ht)
        self.assertNotIn("tamper-evident log", ht)

    def test_production_epoch_qualified_language(self):
        from demo.make_report import key_status, render_markdown
        key = key_status([{"event": "tool_call", "key_epoch": "env"}], "env")
        self.assertEqual(key["status"], "nondev")
        md = render_markdown("run-x", "2026-09-21", True, 1, [], [], key)
        self.assertNotIn("tamper-evident log", md)
        self.assertIn("against parties that do NOT hold the key", md)


# ---------------------------------------------------------------------------
# F30 — policy-lint warnings for dangerous-but-valid settings
# ---------------------------------------------------------------------------

class TestF30LintWarnings(unittest.TestCase):
    """Empty exclusions, near-max auto-approve caps, and wildcard
    campaign entries must warn (not error)."""

    def _lint(self, text):
        from gov.policy_lint import lint_file
        d = Path(tempfile.mkdtemp())
        p = d / "policy.yaml"
        p.write_text(text)
        return {f["kind"]: f for f in lint_file(str(p))}

    _BASE = "policies: []\nroles:\n  researcher: [api_call]\n"

    def test_empty_batch_excluded_reasons_warns(self):
        kinds = self._lint(
            self._BASE + "approvals:\n  batch_excluded_queue_reasons: []\n")
        self.assertIn("empty_batch_excluded_reasons", kinds)
        self.assertEqual(kinds["empty_batch_excluded_reasons"]["severity"],
                         "warning")
        detail = kinds["empty_batch_excluded_reasons"]["detail"]
        self.assertIn("bulk-approve", detail)

    def test_broad_auto_approve_cap_warns(self):
        kinds = self._lint(
            self._BASE + "auto_approve:\n  enabled: true\n"
            "  max_risk_score: 100\n")
        self.assertIn("auto_approve_near_max_risk", kinds)
        self.assertEqual(kinds["auto_approve_near_max_risk"]["severity"],
                         "warning")
        self.assertIn("100", kinds["auto_approve_near_max_risk"]["detail"])

    def test_narrow_auto_approve_cap_silent(self):
        kinds = self._lint(
            self._BASE + "auto_approve:\n  enabled: true\n"
            "  max_risk_score: 25\n")
        self.assertNotIn("auto_approve_near_max_risk", kinds)

    def test_wildcard_campaign_entry_warns(self):
        kinds = self._lint(
            self._BASE + "campaign_allowlist:\n"
            "  - [\"evil-principal\", \"*\", [\"endpoint\"]]\n")
        self.assertIn("campaign_allowlist_wildcard", kinds)
        self.assertEqual(kinds["campaign_allowlist_wildcard"]["severity"],
                         "warning")
        self.assertIn("wildcard",
                      kinds["campaign_allowlist_wildcard"]["detail"].lower())

    def test_default_policy_unaffected(self):
        kinds = self._lint(
            Path("policies/default.yaml").read_text())
        new_kinds = {"empty_batch_excluded_reasons",
                     "auto_approve_near_max_risk", "campaign_allowlist_wildcard"}
        self.assertFalse(new_kinds & set(kinds),
                         "default policy picked up new warnings: %s"
                         % (new_kinds & set(kinds),))


# ---------------------------------------------------------------------------
# F31 — LangChain traversal blocked; verifier write-once
# ---------------------------------------------------------------------------

class TestF31IdentityVerifierHardening(unittest.TestCase):
    """The wave-8 traversal must fail; verifier replacement must raise;
    forged identities must stay rejected."""

    def _ctx(self):
        from harness import make_run
        return make_run()

    def _tool(self, ctx):
        try:
            from pydantic import BaseModel, ConfigDict
        except ImportError:
            self.skipTest("pydantic not installed")
        from gov.adapters.core import GovernedBinding
        from gov.adapters.langchain_tools import make_governed_tool

        class _Args(BaseModel):
            # F62: governed tools require extra="allow".
            model_config = ConfigDict(extra="allow")

            path: str = ""

        ident = ctx["mint_identity"]("r7-agent", "researcher", "org")
        binding = GovernedBinding(ctx["executor"], ident)
        return make_governed_tool(binding, name="read_file",
                                  description="read a file", args_schema=_Args)

    def test_exact_wave8_traversal_blocked(self):
        # F31 exact reproduction:
        #   tool._binding.executor.approvals.set_identity_verifier(...)
        # must no longer resolve to a mutable verifier.
        tool = self._tool(self._ctx())
        with self.assertRaises(AttributeError):
            tool._binding.executor.approvals.set_identity_verifier(
                lambda _: True)

    def test_tool_holds_restricted_facade(self):
        from gov.adapters.core import GovernedToolFacade
        tool = self._tool(self._ctx())
        self.assertIsInstance(tool._facade, GovernedToolFacade)
        self.assertFalse(hasattr(tool._facade, "executor"))
        self.assertFalse(hasattr(tool._facade, "identity"))

    def test_second_verifier_install_raises(self):
        from gov.approvals import IdentityVerifierAlreadySetError
        ctx = self._ctx()
        # ToolExecutor installed its verifier at construction.
        with self.assertRaises(IdentityVerifierAlreadySetError):
            ctx["approvals"].set_identity_verifier(lambda _: True)

    def test_original_verifier_still_authenticates(self):
        from gov.approvals import IdentityVerifierAlreadySetError
        from gov.identity import AgentIdentity, UnmintedIdentityError
        ctx = self._ctx()
        # The swap attempt must not have taken effect.
        with self.assertRaises(IdentityVerifierAlreadySetError):
            ctx["approvals"].set_identity_verifier(lambda _: True)
        forged = AgentIdentity(agent_id="mallory", role="researcher",
                               run_id=ctx["run_dir"].name,
                               principal="mallory")
        with self.assertRaises(UnmintedIdentityError):
            ctx["approvals"]._authenticate_caller(forged, "resolve_review")

    def test_first_install_on_fresh_queue_allowed(self):
        # A queue that never had a verifier (CLI path) can still take
        # exactly one; the second refuses.
        from gov.approvals import (ApprovalQueue,
                                   IdentityVerifierAlreadySetError)
        from gov.log import ActionLog
        run_dir = Path(tempfile.mkdtemp())
        log = ActionLog(str(run_dir / "actions.jsonl"))
        q = ApprovalQueue(run_dir, log)
        q.set_identity_verifier(lambda ident: True)
        with self.assertRaises(IdentityVerifierAlreadySetError):
            q.set_identity_verifier(lambda ident: True)

    def test_non_callable_verifier_refused(self):
        # A non-callable first installation is refused with TypeError and
        # does not seal the slot: a later callable install still works.
        from gov.approvals import (ApprovalQueue,
                                   IdentityVerifierAlreadySetError)
        from gov.log import ActionLog
        run_dir = Path(tempfile.mkdtemp())
        log = ActionLog(str(run_dir / "actions.jsonl"))
        q = ApprovalQueue(run_dir, log)
        with self.assertRaises(TypeError):
            q.set_identity_verifier("not-a-callable")
        q.set_identity_verifier(lambda ident: True)
        with self.assertRaises(IdentityVerifierAlreadySetError):
            q.set_identity_verifier(lambda ident: True)

    def test_second_executor_sharing_queue_keeps_original_verifier(self):
        # F31 write-once must not break the legitimate pattern of two
        # executors sharing one ApprovalQueue (sit32 policy-pinning):
        # the second executor constructs fine and the queue keeps the
        # FIRST executor's verifier (no silent swap).
        from gov.approvals import IdentityVerifierAlreadySetError
        from gov.executor import ToolExecutor
        ctx = self._ctx()
        ex1, q = ctx["executor"], ctx["approvals"]
        v1 = q._identity_verifier
        ex2 = ToolExecutor(ctx["run_dir"], ctx["policy"], ex1.log, q,
                           ledger_path=str(Path(tempfile.mkdtemp())
                                           / "ledger.jsonl"))
        self.assertIs(q._identity_verifier, v1)
        # Direct replacement is still refused.
        with self.assertRaises(IdentityVerifierAlreadySetError):
            q.set_identity_verifier(lambda ident: True)
        self.assertIs(q._identity_verifier, v1)
        self.assertIsNot(ex2, ex1)  # use ex2 so linters see it


if __name__ == "__main__":
    unittest.main()
