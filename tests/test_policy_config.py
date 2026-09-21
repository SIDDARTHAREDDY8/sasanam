"""Red-team tests: T7 (policy misconfiguration), R1 (fail-closed engine),
R9 (policy linting). Also T10 (config/tool-definition pinning, P1 control).

Every test here FAILS on the current code: each asserts a control that does
not exist, demonstrating the vulnerability as an assertion failure.
"""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)


def _tmp_policy(text):
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="redteam-policy-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class TestDefaultDeny(unittest.TestCase):
    """T7/R1: the default policy effect must be DENY. An unusual tool with
    no matching rule must not execute."""

    def test_unknown_tool_is_denied_by_default(self):
        run = make_run()  # default policy file
        ident = run["identities"]["support"]
        res = run["executor"].call(
            ident, "exec_shell", cmd="curl http://fresh-host.example/x")
        self.assertEqual(
            res["status"], "denied",
            "T7/R1: tool 'exec_shell' matched no rule and was EXECUTED "
            "(fail-open default). result=%r" % (res,),
        )


class TestForbidPriority(unittest.TestCase):
    """T7/R1: deny rules have forbid-priority independent of file order.
    A broad allow listed ABOVE a deny must not defeat the deny."""

    BROAD_ALLOW_FIRST = """\
version: 1
defaults:
  effect: allow
  reason: test default
policies:
  - id: broad-allow-write
    effect: allow
    match:
      tool: [write_file]
    reason: broad allow listed first
  - id: deny-write
    effect: deny
    match:
      tool: [write_file]
    reason: deny listed second
"""

    def test_deny_wins_regardless_of_order(self):
        path = _tmp_policy(self.BROAD_ALLOW_FIRST)
        try:
            run = make_run(policy_path=path)
            ident = run["identities"]["support"]
            res = run["executor"].call(
                ident, "write_file", path="x.txt", content="x")
            self.assertEqual(
                res["status"], "denied",
                "T7/R1: first-match allow defeated the later deny rule "
                "(no forbid priority). result=%r" % (res,),
            )
        finally:
            os.unlink(path)


class TestPolicyLint(unittest.TestCase):
    """T7/R9: python -m gov.policy_lint must exist and report unknown tools,
    unknown match keys, and shadowed/unreachable rules."""

    LINT_POLICY = """\
version: 1
defaults:
  effect: deny
  reason: test default
policies:
  - id: unknown-tool-rule
    effect: deny
    match:
      tool: [frobnicate]
    reason: references a tool that does not exist
  - id: unknown-match-key-rule
    effect: deny
    match:
      tool: [read_file]
      frobnicate_files: true
    reason: references a match key the engine does not support
  - id: broad-allow
    effect: allow
    match:
      tool: [write_file]
    reason: broad allow
  - id: narrow-shadowed
    effect: deny
    match:
      tool: [write_file]
    reason: unreachable, shadowed by broad-allow above
"""

    def test_lint_module_exists_and_flags_problems(self):
        try:
            lint = importlib.import_module("gov.policy_lint")
        except ImportError:
            self.fail("R9: gov.policy_lint module does not exist "
                      "(no policy linter)")
        path = _tmp_policy(self.LINT_POLICY)
        try:
            problems = lint.lint_file(path)
        finally:
            os.unlink(path)
        kinds = {p.get("kind") for p in problems}
        self.assertIn("unknown_tool", kinds,
                      "R9: linter missed the unknown tool name 'frobnicate'")
        self.assertIn("unknown_match_key", kinds,
                      "R9: linter missed the unknown match key 'frobnicate_files'")
        self.assertIn("shadowed_rule", kinds,
                      "R9: linter missed the rule shadowed by an earlier broader rule")


class TestPolicyFileIntegrity(unittest.TestCase):
    """T10 (P1: tool-definition/config pinning): the policy engine loads
    policy YAML with no integrity check, so a rewritten policy file is
    trusted silently."""

    def test_policy_file_pinned_on_load(self):
        from gov.policy import PolicyEngine
        path = _tmp_policy(
            "version: 1\ndefaults:\n  effect: deny\n  reason: locked\n"
            "policies: []\n")
        try:
            engine = PolicyEngine(path)
            # Attacker rewrites the policy file after it was loaded.
            with open(path, "w", encoding="utf-8") as f:
                f.write("version: 1\ndefaults:\n  effect: allow\n"
                        "  reason: pwned\npolicies: []\n")
            pinned = hasattr(engine, "policy_hash") or hasattr(engine, "source_digest")
            self.assertTrue(
                pinned,
                "T10: policy engine performs no integrity pinning of the "
                "policy file (rewrites are trusted silently)",
            )
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
