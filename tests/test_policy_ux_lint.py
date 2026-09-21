"""Tests for the extended policy linter (gov/policy_lint.py).

Note: the project's yamlmini parser does not support flow-style
``{...}`` mappings, so all test YAML uses block-style mappings, exactly
like policies/default.yaml does.
"""

import os
import tempfile
import textwrap
import unittest

from gov.policy_lint import lint_file


def _tmp_yaml(body):
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="lint-test-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(body))
    return path


def _lint(body):
    return lint_file(_tmp_yaml(body))


def _kinds(findings):
    return {f["kind"] for f in findings}


def _err_kinds(findings):
    return {f["kind"] for f in findings if f["severity"] == "error"}


class TestExtendedLint(unittest.TestCase):
    def test_unknown_role_is_error(self):
        f = _lint("""
        version: 1
        policies:
          - id: r1
            effect: allow
            match:
              tool: [read_file]
              role: [ghost-role]
            reason: test
        """)
        self.assertIn("unknown_role", _kinds(f))
        self.assertTrue(any("ghost-role" in x["detail"] for x in f
                            if x["kind"] == "unknown_role"))

    def test_unknown_tool_and_match_key_still_flagged(self):
        f = _lint("""
        version: 1
        policies:
          - id: r1
            effect: allow
            match:
              tool: [teleport]
              nonsense_key: true
            reason: test
        """)
        self.assertIn("unknown_tool", _kinds(f))
        self.assertIn("unknown_match_key", _kinds(f))

    def test_unreachable_allow_for_roleless_tool(self):
        f = _lint("""
        version: 1
        roles:
          coder: [read_file, write_file]
        policies:
          - id: dead-allow
            effect: allow
            match:
              tool: [http_post]
            reason: test
        """)
        self.assertIn("unreachable_rule", _err_kinds(f))

    def test_deny_for_roleless_tool_is_not_unreachable(self):
        f = _lint("""
        version: 1
        roles:
          coder: [read_file, write_file]
        policies:
          - id: belt-and-braces
            effect: deny
            match:
              tool: [http_post]
            flag: suspicious-http
            reason: test
        """)
        self.assertNotIn("unreachable_rule", _kinds(f))

    def test_empty_match_allow_is_error(self):
        f = _lint("""
        version: 1
        policies:
          - id: footgun
            effect: allow
            match: {}
            reason: test
        """)
        kinds = {x["kind"]: x["severity"] for x in f
                 if x["kind"] == "overly_broad_allow"}
        # yamlmini keeps "match: {}" as a literal string: malformed match.
        self.assertIn("invalid_match", _kinds(f))
        self.assertEqual(kinds.get("overly_broad_allow"), "error")

    def test_dangerous_tool_only_allow_is_warning(self):
        f = _lint("""
        version: 1
        roles:
          publisher: [send_email]
        policies:
          - id: broad-send
            effect: allow
            match:
              tool: [send_email]
            reason: test
        """)
        kinds = {x["kind"]: x["severity"] for x in f
                 if x["kind"] == "overly_broad_allow"}
        self.assertEqual(kinds.get("overly_broad_allow"), "warning")

    def test_missing_deny_coverage_for_dangerous_tool(self):
        f = _lint("""
        version: 1
        roles:
          publisher: [send_email]
        policies:
          - id: allow-send
            effect: allow
            match:
              tool: [send_email]
              role: [publisher]
            reason: test
        """)
        warns = [x for x in f if x["kind"] == "missing_deny_coverage"]
        tools = {x["detail"] for x in warns}
        self.assertTrue(any("send_email" in d for d in tools))
        self.assertTrue(any("http_post" in d for d in tools))
        self.assertTrue(any("delete_file" in d for d in tools))

    def test_explicit_deny_satisfies_coverage(self):
        f = _lint("""
        version: 1
        policies:
          - id: deny-ego
            effect: deny
            match:
              tool: [send_email, http_post]
              domain_allowlisted: false
            flag: x
            reason: t
          - id: deny-del
            effect: deny
            match:
              tool: [delete_file]
              path_outside_sandbox: true
            flag: x
            reason: t
        """)
        self.assertNotIn("missing_deny_coverage", _kinds(f))

    def test_mutually_covering_different_effects_is_contradiction(self):
        f = _lint("""
        version: 1
        policies:
          - id: a-allow
            effect: allow
            match:
              tool: [read_file]
              role: [coder]
            reason: t
          - id: b-deny
            effect: deny
            match:
              tool: [read_file]
              role: [coder]
            flag: x
            reason: t
        """)
        self.assertIn("contradictory_rule", _err_kinds(f))

    def test_forbid_priority_pairs_are_not_contradictions(self):
        # A narrower deny nested inside a broader allow is NORMAL forbid
        # priority layering (deny the bad subset, allow the rest).
        f = _lint("""
        version: 1
        policies:
          - id: deny-bad
            effect: deny
            match:
              tool: [read_file]
              path_outside_sandbox: true
            flag: x
            reason: t
          - id: allow-rest
            effect: allow
            match:
              tool: [read_file]
            reason: t
        """)
        self.assertNotIn("contradictory_rule", _kinds(f))
        self.assertNotIn("shadowed_rule", _kinds(f))

    def test_duplicate_rule_ids_are_errors(self):
        f = _lint("""
        version: 1
        policies:
          - id: same
            effect: allow
            match:
              tool: [read_file]
            reason: t
          - id: same
            effect: deny
            match:
              tool: [delete_file]
            flag: x
            reason: t
        """)
        self.assertIn("duplicate_rule_id", _err_kinds(f))

    def test_invalid_effect_flagged(self):
        f = _lint("""
        version: 1
        policies:
          - id: r1
            effect: sometimes
            match:
              tool: [read_file]
            reason: t
        """)
        self.assertIn("invalid_effect", _err_kinds(f))

    def test_shadowed_allow_by_narrower_earlier_deny(self):
        f = _lint("""
        version: 1
        policies:
          - id: blanket-allow
            effect: allow
            match:
              tool: [write_file]
            reason: t
          - id: deny-all-writes
            effect: deny
            match:
              tool: [write_file]
            flag: x
            reason: t
        """)
        self.assertIn("shadowed_rule", _err_kinds(f))
        self.assertTrue(any(x["rule_id"] == "blanket-allow" for x in f
                            if x["kind"] == "shadowed_rule"))

    def test_severities_are_valid(self):
        f = _lint("""
        version: 1
        policies:
          - id: r1
            effect: allow
            match:
              tool: [read_file]
            reason: t
        """)
        for x in f:
            self.assertIn(x["severity"], ("error", "warning", "info"))


if __name__ == "__main__":
    unittest.main()
