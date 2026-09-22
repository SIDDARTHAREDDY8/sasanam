"""D1-core Phase 2 tests: policy engine sections + lint L1-L10.

Covers: PolicyEngine.approvals_delegation / approvals_quorum
normalization (fail-closed at load, single source of truth in
gov/approvals.py), the policy linter's L1-L10 findings, the default
policy's delegation-disabled posture (both byte-identical copies),
and the CLI delegate path (which installs the delegation section from
--policy).
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tests  # noqa: F401  (sets GOV_DEV_KEYS for the harness)
from harness import make_run
from gov.policy import PolicyEngine
from gov.policy_lint import lint_file

_REPO = Path(_TESTS_DIR).parent


def _write_policy(approvals_block):
    """Write a minimal policy with the given approvals: block text."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("version: 1\n")
        f.write("approvals:\n")
        for line in approvals_block.splitlines():
            f.write("  %s\n" % line if line.strip() else "\n")
        f.write("policies: []\n")
    return path


def _kinds(path):
    return {(f["kind"], f["severity"]) for f in lint_file(path)}


class TestPolicyEngineD1Sections(unittest.TestCase):
    """PolicyEngine normalizes the D1 sections fail-closed at load."""

    def test_default_policy_posture(self):
        p = PolicyEngine(str(_REPO / "policies" / "default.yaml"))
        self.assertEqual(p.approvals_delegation,
                         {"enabled": False, "max_hops": 1})
        self.assertIsNone(p.approvals_quorum)

    def test_delegation_enabled_shape(self):
        path = _write_policy("delegation:\n    enabled: true\n"
                             "    max_hops: 3\n")
        try:
            p = PolicyEngine(path)
            self.assertEqual(p.approvals_delegation,
                             {"enabled": True, "max_hops": 3})
            self.assertIsNone(p.approvals_quorum)
        finally:
            os.unlink(path)

    def test_quorum_shape(self):
        path = _write_policy(
            "quorum:\n    min_approvals: 2\n"
            "    eligible_principals: [alice, bob, carol]\n")
        try:
            p = PolicyEngine(path)
            cfg = p.approvals_quorum
            self.assertEqual(cfg["min_approvals"], 2)
            self.assertEqual(cfg["eligible_principals"],
                             ("alice", "bob", "carol"))
            self.assertTrue(cfg["deny_veto"])
        finally:
            os.unlink(path)

    def test_invalid_sections_fail_the_load(self):
        bad_blocks = [
            # L1/L2/L3 — delegation
            "delegation: [enabled]\n",
            "delegation:\n    enabled: 'yes'\n",
            "delegation:\n    enabled: true\n    max_hops: 9\n",
            # L4/L5/L6/L7/L8/L9 — quorum
            "quorum: '2-of-3'\n",
            "quorum:\n    min_approvals: 0\n"
            "    eligible_principals: [alice]\n",
            "quorum:\n    min_approvals: 1\n"
            "    eligible_principals: []\n",
            "quorum:\n    min_approvals: 1\n"
            "    eligible_principals: [alice, alice]\n",
            "quorum:\n    min_approvals: 4\n"
            "    eligible_principals: [alice, bob, carol]\n",
            "quorum:\n    min_approvals: 1\n"
            "    eligible_principals: [alice]\n    deny_veto: false\n",
            "quorum:\n    min_approvals: 1\n"
            "    eligible_principals: [alice]\n    flags: 'x'\n",
        ]
        for block in bad_blocks:
            path = _write_policy(block)
            try:
                with self.assertRaises(ValueError, msg=block):
                    PolicyEngine(path)
            finally:
                os.unlink(path)


class TestLintD1(unittest.TestCase):
    """L1-L10: the linter mirrors the engine's fail-closed normalizers."""

    def _lint(self, approvals_block):
        path = _write_policy(approvals_block)
        try:
            return {(f["kind"], f["severity"]): f["detail"]
                    for f in lint_file(path)}
        finally:
            os.unlink(path)

    def test_l1_delegation_not_mapping(self):
        found = self._lint("delegation: [enabled]\n")
        self.assertIn(("delegation_invalid_shape", "error"), found)

    def test_l2_enabled_not_bool(self):
        found = self._lint("delegation:\n    enabled: 'yes'\n")
        self.assertIn(("delegation_enabled_not_bool", "error"), found)

    def test_l3_max_hops_out_of_range(self):
        found = self._lint("delegation:\n    enabled: true\n"
                           "    max_hops: 9\n")
        self.assertIn(("delegation_max_hops_out_of_range", "error"), found)

    def test_l4_quorum_not_mapping(self):
        found = self._lint("quorum: '2-of-3'\n")
        self.assertIn(("quorum_invalid_shape", "error"), found)

    def test_l5_bad_min_approvals(self):
        found = self._lint("quorum:\n    min_approvals: 0\n"
                           "    eligible_principals: [alice]\n")
        self.assertIn(("quorum_min_approvals_invalid", "error"), found)

    def test_l6_bad_eligible(self):
        found = self._lint("quorum:\n    min_approvals: 1\n"
                           "    eligible_principals: []\n")
        self.assertIn(("quorum_eligible_principals_invalid", "error"), found)
        found = self._lint("quorum:\n    min_approvals: 1\n"
                           "    eligible_principals: [alice, alice]\n")
        self.assertIn(("quorum_eligible_principals_invalid", "error"), found)

    def test_l7_unreachable_quorum(self):
        found = self._lint("quorum:\n    min_approvals: 4\n"
                           "    eligible_principals: [alice, bob, carol]\n")
        self.assertIn(("quorum_unreachable", "error"), found)

    def test_l8_deny_veto_false(self):
        found = self._lint("quorum:\n    min_approvals: 1\n"
                           "    eligible_principals: [alice]\n"
                           "    deny_veto: false\n")
        self.assertIn(("quorum_deny_veto_not_true", "error"), found)

    def test_l9_bad_flags(self):
        found = self._lint("quorum:\n    min_approvals: 1\n"
                           "    eligible_principals: [alice]\n"
                           "    flags: 'x'\n")
        self.assertIn(("quorum_flags_invalid", "error"), found)

    def test_l10_long_chain_is_warning(self):
        found = self._lint("delegation:\n    enabled: true\n"
                           "    max_hops: 3\n")
        self.assertIn(("delegation_long_chain", "warning"), found)
        # …but a single-hop config is silent.
        found = self._lint("delegation:\n    enabled: true\n"
                           "    max_hops: 1\n")
        self.assertNotIn(("delegation_long_chain", "warning"), found)

    def test_valid_sections_lint_clean(self):
        found = self._lint(
            "delegation:\n    enabled: true\n    max_hops: 1\n"
            "quorum:\n    min_approvals: 2\n"
            "    eligible_principals: [alice, bob, carol]\n")
        d1_kinds = {k for k, _s in found if "delegation" in k or "quorum" in k}
        self.assertEqual(d1_kinds, set())

    def test_default_policy_lints_clean_for_d1(self):
        d1 = [f for f in lint_file(str(_REPO / "policies" / "default.yaml"))
              if "delegation" in f["kind"] or "quorum" in f["kind"]
              or f["kind"] == "approvals_invalid_shape"]
        self.assertEqual(d1, [])

    def test_lint_and_engine_agree(self):
        # Every block the linter flags as a D1 error must also fail the
        # engine load (single source of truth — no drift).
        bad_blocks = [
            "delegation: [enabled]\n",
            "delegation:\n    enabled: 'yes'\n",
            "delegation:\n    enabled: true\n    max_hops: 0\n",
            "quorum:\n    min_approvals: 2\n"
            "    eligible_principals: [alice]\n    deny_veto: false\n",
        ]
        for block in bad_blocks:
            path = _write_policy(block)
            try:
                kinds = {k for k, s in _kinds(path) if s == "error"}
                self.assertTrue(
                    any("delegation" in k or "quorum" in k for k in kinds),
                    block)
                with self.assertRaises(ValueError, msg=block):
                    PolicyEngine(path)
            finally:
                os.unlink(path)


class TestDefaultPolicyCopies(unittest.TestCase):
    """The two default-policy copies stay byte-identical with
    delegation disabled and no quorum section."""

    def test_copies_byte_identical(self):
        a = (_REPO / "policies" / "default.yaml").read_bytes()
        b = (_REPO / "gov" / "data" / "default.yaml").read_bytes()
        self.assertEqual(a, b)

    def test_delegation_disabled_no_quorum(self):
        for name in ("policies/default.yaml", "gov/data/default.yaml"):
            p = PolicyEngine(str(_REPO / name))
            self.assertFalse(p.approvals_delegation["enabled"])
            self.assertIsNone(p.approvals_quorum)


class TestCLIDelegate(unittest.TestCase):
    """The CLI delegate path installs the delegation section from
    --policy (the same file the run enforces)."""

    def _run_cli(self, run, *argv):
        from gov.approvals import main as cli_main
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["--rundir", str(run["run_dir"])] + list(argv))
        return code, buf.getvalue()

    def _queue(self, run):
        ident = run["executor"].mint_identity("agent-1", "support",
                                              "agent-1")
        res = run["executor"].call(
            ident, "send_email", to="victim@synthetic.local",
            subject="hello", body="hello")
        assert res["status"] == "queued", res
        return res["approval_id"]

    def test_cli_delegate_round_trip(self):
        run = make_run()
        aid = self._queue(run)
        policy_path = _write_policy("delegation:\n    enabled: true\n"
                                    "    max_hops: 1\n")
        try:
            code, out = self._run_cli(run, "delegate", aid, "--to", "alice",
                                      "--reason", "on call",
                                      "--policy", policy_path)
        finally:
            os.unlink(policy_path)
        self.assertEqual(code, 0, out)
        self.assertIn("delegated approval", out)
        record = run["approvals"].get(aid)
        self.assertEqual(record["delegated_to"], "alice")

    def test_cli_delegate_refused_when_policy_disables(self):
        run = make_run()
        aid = self._queue(run)
        policy_path = _write_policy(
            "delegation:\n    enabled: false\n")
        try:
            code, out = self._run_cli(run, "delegate", aid, "--to", "alice",
                                      "--reason", "on call",
                                      "--policy", policy_path)
        finally:
            os.unlink(policy_path)
        self.assertEqual(code, 1)
        self.assertIsNone(run["approvals"].get(aid)["delegated_to"])


if __name__ == "__main__":
    unittest.main()
