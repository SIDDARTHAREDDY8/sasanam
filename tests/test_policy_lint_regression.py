"""Policy-lint regression tests for the S1-S5 policy sections.

Pins:

* ``policies/default.yaml`` (with the new ``approval-velocity-guard``
  rule) lints with 0 errors and 0 warnings.
* The linter is read-only/advisory w.r.t. enforcement (covered
  behaviorally in tests/test_ratings.py).

COVERAGE GAPS (linter lacks checks for the new sections — demonstrated
here as expectedFailure so they stay visible and flip to "unexpected
success" when the linter gains coverage):

* LINT-GAP-1: malformed ``budgets:`` sections (unknown key / negative
  value) pass the linter silently, even though the engine fails the
  policy load closed.
* LINT-GAP-2: malformed ``run_limits:`` sections pass silently.
* LINT-GAP-3: malformed ``velocity:`` sections pass silently.
* LINT-GAP-4: ``gov/tool_ratings.is_destructive`` is documented as
  driving "the policy-lint warning for destructive-rated tools
  allowed without an approval rule", but no such warning kind exists
  in ``gov/policy_lint.py``.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov import policy_lint  # noqa: E402

_DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

_BASE_POLICY = """\
version: 2
roles:
  sender: [send_email, api_call]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
%s
policies:
  - id: test-allow-api
    effect: allow
    match:
      tool: [api_call]
    reason: Test policy allows api_call.
  - id: test-deny-dangerous
    effect: deny
    match:
      tool: [send_email, http_post, delete_file]
    reason: Deny coverage so missing_deny_coverage stays silent.
"""


def _tmpdir(prefix):
    base = Path("/tmp/gov-run")
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


class TestPolicyLintRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir("govlint-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _lint_text(self, section_yaml):
        p = self.tmp / ("lint_%d.yaml" % id(self))
        p.write_text(_BASE_POLICY % section_yaml, encoding="utf-8")
        return policy_lint.lint_file(str(p))

    # -- the clean pin -----------------------------------------------------

    def test_default_policy_zero_errors_zero_warnings(self):
        """policies/default.yaml (with approval-velocity-guard) must
        lint with 0 errors and 0 warnings. Info-level findings are
        acceptable (they are style notes, not control gaps)."""
        findings = policy_lint.lint_file(str(_DEFAULT_POLICY))
        errors = [f for f in findings if f.get("severity") == "error"]
        warnings = [f for f in findings if f.get("severity") == "warning"]
        infos = [f for f in findings if f.get("severity") == "info"]
        self.assertEqual(errors, [],
                         "lint errors on default policy: %r" % (errors,))
        self.assertEqual(warnings, [],
                         "lint warnings on default policy: %r"
                         % (warnings,))
        # Record the info count so a future change is visible.
        self.assertLessEqual(len(infos), 5,
                             "info findings grew unexpectedly: %r"
                             % (infos,))

    def test_approval_velocity_guard_rule_lints_clean(self):
        """The new approval-velocity-guard rule draws no finding of
        its own (its match key is engine-known)."""
        findings = policy_lint.lint_file(str(_DEFAULT_POLICY))
        flagged = [f for f in findings
                   if f.get("rule_id") == "approval-velocity-guard"]
        self.assertEqual(flagged, [],
                         "approval-velocity-guard drew findings: %r"
                         % (flagged,))

    def test_linter_does_not_reject_valid_new_sections(self):
        """Well-formed budgets/run_limits/velocity sections are
        accepted silently by the linter (no false positives)."""
        findings = self._lint_text(
            "budgets:\n"
            "  max_tokens_per_run: 1000\n"
            "  max_spend_per_run: 0.5\n"
            "  max_actions_per_run: 50\n"
            "run_limits:\n"
            "  max_tool_calls_per_run: 200\n"
            "velocity:\n"
            "  window_secs: 3600\n"
            "  max_sends: 5\n")
        problems = [f for f in findings
                    if f.get("severity") in ("error", "warning")]
        self.assertEqual(problems, [],
                         "linter flagged valid new sections: %r"
                         % (problems,))

    # -- coverage gaps (linter is silent where it should flag) -------------

    @unittest.expectedFailure
    def test_linter_flags_malformed_budgets_section(self):
        """LINT-GAP-1: a budgets: section the ENGINE rejects (unknown
        key) should draw a linter error before the load fails."""
        findings = self._lint_text("budgets:\n  max_nope_per_run: 3\n")
        errors = [f for f in findings if f.get("severity") == "error"]
        self.assertTrue(
            any("budget" in f.get("kind", "") for f in errors),
            "linter silent on malformed budgets: section: %r"
            % (findings,))

    @unittest.expectedFailure
    def test_linter_flags_negative_budget_value(self):
        """LINT-GAP-1b: a negative budget value (engine: fail closed)
        should draw a linter error."""
        findings = self._lint_text(
            "budgets:\n  max_tokens_per_run: -5\n")
        errors = [f for f in findings if f.get("severity") == "error"]
        self.assertTrue(
            any("budget" in f.get("kind", "") for f in errors),
            "linter silent on negative budgets value: %r" % (findings,))

    @unittest.expectedFailure
    def test_linter_flags_malformed_run_limits_section(self):
        """LINT-GAP-2: a run_limits: section the ENGINE rejects
        (unknown key) should draw a linter error."""
        findings = self._lint_text(
            "run_limits:\n  max_nope_per_run: 3\n")
        errors = [f for f in findings if f.get("severity") == "error"]
        self.assertTrue(
            any("run_limit" in f.get("kind", "") for f in errors),
            "linter silent on malformed run_limits: section: %r"
            % (findings,))

    @unittest.expectedFailure
    def test_linter_flags_malformed_velocity_section(self):
        """LINT-GAP-3: a velocity: section the ENGINE rejects
        (negative threshold) should draw a linter error."""
        findings = self._lint_text("velocity:\n  max_sends: -1\n")
        errors = [f for f in findings if f.get("severity") == "error"]
        self.assertTrue(
            any("velocity" in f.get("kind", "") for f in errors),
            "linter silent on malformed velocity: section: %r"
            % (findings,))

    @unittest.expectedFailure
    def test_linter_destructive_warning_driven_by_ratings(self):
        """LINT-GAP-4: gov/tool_ratings.py documents that
        is_destructive "drives the policy-lint warning for
        destructive-rated tools allowed without an approval rule".
        delete_file is NOT destructive per is_destructive
        (compensatable reversibility, no financial impact), so a
        ratings-driven linter would not warn about it as a dangerous
        tool. Today the linter warns from a hardcoded DANGEROUS_TOOLS
        set instead — the ratings module is never consulted."""
        from gov.tool_ratings import (DEFAULT_TOOL_RATINGS,
                                      is_destructive)
        self.assertFalse(is_destructive(
            DEFAULT_TOOL_RATINGS["delete_file"]))
        p = self.tmp / "deletefile.yaml"
        p.write_text("""\
version: 2
roles:
  builder: [delete_file]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
policies:
  - id: test-allow-delete-no-approval
    effect: allow
    match:
      tool: [delete_file]
    reason: Non-destructive-rated tool allowed with no approval rule.
""", encoding="utf-8")
        findings = policy_lint.lint_file(str(p))
        dangerous = [f for f in findings
                     if "dangerous" in f.get("detail", "")]
        self.assertEqual(
            dangerous, [],
            "linter warns about delete_file as 'dangerous' even though "
            "it is not destructive-rated — warnings are driven by the "
            "hardcoded DANGEROUS_TOOLS set, not tool_ratings: %r"
            % (dangerous,))


if __name__ == "__main__":
    unittest.main()
