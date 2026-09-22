"""F90 regression: unknown policy fields fail LOUD at load (AGT scope-typo class).

Microsoft's AGT had a bug where a misspelled ``Policy.scope`` was silently
demoted to GLOBAL, flipping deny->allow under most_specific_wins. The
equivalent shapes in our engine were verified SILENT before the fix:

* a misspelled rule-level ``match:`` (``macht:``) on an allow rule loaded
  fine with ``match`` defaulting to {} -- the rule then matched EVERY
  action (deny->allow flip demonstrated in the F90 finding);
* a misspelled top-level section (``bugets:``) loaded with budgets
  silently unenforced;
* a misspelled ``approvals`` subkey (``batch_excluded_queue_reasonz``)
  normalized to () silently, making security-flagged items
  batch-approvable;
* a typo'd ``when`` operator (``gtte``) made the condition vacuously
  TRUE (allow rule fires unconditionally); a missing ``path`` made it
  always FALSE (deny rule never fires).

All of these now raise ValueError at PolicyEngine load. Each test below
FAILS on the pre-fix engine (silent load) and passes after.
"""

import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.policy import PolicyEngine  # noqa: E402


def _load(text):
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="f90-policy-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class TestF90UnknownFieldsRefusedLoud(unittest.TestCase):
    def _assert_loud(self, yaml_text, fragment):
        path = _load(yaml_text)
        try:
            with self.assertRaises(ValueError) as cm:
                PolicyEngine(path)
            self.assertIn(fragment, str(cm.exception),
                          "error should name the offending field")
        finally:
            os.unlink(path)

    def test_misspelled_match_key_on_allow_rule_is_loud(self):
        """The AGT shape: 'macht' for 'match' must not become match-all."""
        self._assert_loud(
            "policies:\n"
            "  - id: typo-allow\n"
            "    effect: allow\n"
            "    macht:\n"
            "      tool: [read_file]\n",
            "macht")

    def test_misspelled_match_key_on_deny_rule_is_loud(self):
        self._assert_loud(
            "policies:\n"
            "  - id: typo-deny\n"
            "    effect: deny\n"
            "    macht:\n"
            "      tool: [send_email]\n",
            "macht")

    def test_unknown_rule_field_is_loud(self):
        self._assert_loud(
            "policies:\n"
            "  - id: r\n"
            "    effect: allow\n"
            "    scope: per-agent\n"
            "    match:\n"
            "      tool: [read_file]\n",
            "scope")

    def test_misspelled_top_level_section_is_loud(self):
        self._assert_loud(
            "bugets:\n"
            "  max_actions_per_run: 1\n"
            "policies: []\n",
            "bugets")

    def test_misspelled_approvals_subkey_is_loud(self):
        self._assert_loud(
            "approvals:\n"
            "  batch_excluded_queue_reasonz: [security]\n"
            "policies: []\n",
            "batch_excluded_queue_reasonz")

    def test_typod_when_operator_is_loud(self):
        self._assert_loud(
            "policies:\n"
            "  - id: r\n"
            "    effect: allow\n"
            "    match:\n"
            "      tool: [read_file]\n"
            "      when:\n"
            "        - path: counters.api_call\n"
            "          gtte: 1\n",
            "gtte")

    def test_when_condition_without_operator_is_loud(self):
        """A path-only condition is vacuously true; refuse it."""
        self._assert_loud(
            "policies:\n"
            "  - id: r\n"
            "    effect: allow\n"
            "    match:\n"
            "      tool: [read_file]\n"
            "      when:\n"
            "        - path: counters.api_call\n",
            "no operator")

    def test_when_condition_without_path_is_loud(self):
        """A pathless condition is always false; a deny gated on it would
        never fire. Refuse it."""
        self._assert_loud(
            "policies:\n"
            "  - id: r\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: [send_email]\n"
            "      when:\n"
            "        - gte: 1\n",
            "path")

    def test_non_mapping_match_is_loud(self):
        self._assert_loud(
            "policies:\n"
            "  - id: r\n"
            "    effect: allow\n"
            "    match: read_file\n",
            "must be a mapping")

    def test_all_known_fields_still_load(self):
        """No false positives: every documented field is accepted."""
        path = _load(
            "version: 2\n"
            "roles:\n"
            "  support: [read_file]\n"
            "rate_limit: {}\n"
            "egress: {}\n"
            "approvals:\n"
            "  ttl_hours: 12\n"
            "  batch_excluded_queue_reasons: [security]\n"
            "auto_approve:\n"
            "  enabled: false\n"
            "campaign_allowlist: []\n"
            "delegation: null\n"
            "log_limits:\n"
            "  max_log_bytes: 1000000\n"
            "budgets:\n"
            "  max_actions_per_run: 5\n"
            "run_limits:\n"
            "  max_tool_calls_per_run: 50\n"
            "velocity:\n"
            "  max_sends: 10\n"
            "policies:\n"
            "  - id: ok\n"
            "    effect: allow\n"
            "    reason: fine\n"
            "    description: documented\n"
            "    flag: test\n"
            "    match:\n"
            "      tool: [read_file]\n"
            "      when:\n"
            "        - path: counters.api_call\n"
            "          gte: 2\n")
        try:
            eng = PolicyEngine(path)
            d = eng.evaluate(
                {"tool": "read_file", "role": "support", "agent_id": "a"},
                {"counters": {"api_call": 3}})
            self.assertEqual(d.effect, "allow")
            self.assertEqual(eng.budgets["max_actions_per_run"], 5)
            self.assertEqual(eng.batch_excluded_queue_reasons, ("security",))
        finally:
            os.unlink(path)

    def test_dsl_provenance_marker_still_loads(self):
        """gov/dsl.apply_dsl stamps dsl_rule/dsl_source_hash; the strict
        rule-field check must accept the engine's own markers."""
        path = _load(
            "policies:\n"
            "  - id: dsl-r\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: [send_email]\n"
            "    dsl_rule: true\n"
            "    dsl_source_hash: abc123\n")
        try:
            eng = PolicyEngine(path)
            self.assertEqual(len(eng.policies), 1)
        finally:
            os.unlink(path)

    def test_shipped_default_policy_still_loads(self):
        eng = PolicyEngine(
            os.path.join(os.path.dirname(_TESTS_DIR), "policies",
                         "default.yaml"))
        self.assertTrue(eng.policies)


if __name__ == "__main__":
    unittest.main()
