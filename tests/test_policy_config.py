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
            "version: 1\n"
            "policies: []\n")
        try:
            engine = PolicyEngine(path)
            # Attacker rewrites the policy file after it was loaded.
            with open(path, "w", encoding="utf-8") as f:
                f.write("version: 1\n"
                        "policies: []\n")
            pinned = hasattr(engine, "policy_hash") or hasattr(engine, "source_digest")
            self.assertTrue(
                pinned,
                "T10: policy engine performs no integrity pinning of the "
                "policy file (rewrites are trusted silently)",
            )
        finally:
            os.unlink(path)


class TestF146ResolvedPathMatching(unittest.TestCase):
    """F146 (PaperCut class): path_contains_any is evaluated against the
    symlink-resolved target as well as the declared path (fail-safe OR).
    Red: the break battery evals/f146excl_break.py p2/p4/p5
    (3 BREAK pre-fix, 0 BREAK post-fix)."""

    EXCL_POLICY = """\
version: 2
roles:
  coder: [read_file, write_file, delete_file]
policies:
  - id: deny-excluded-zone
    effect: deny
    match:
      tool: [write_file, read_file]
      path_contains_any: [excluded-zone]
    reason: standing operator exclusion
  - id: allow-files
    effect: allow
    match:
      tool: [write_file, read_file]
    reason: benign sandbox work
"""

    def _engine(self):
        from gov.policy import PolicyEngine
        return PolicyEngine(_tmp_policy(self.EXCL_POLICY))

    @staticmethod
    def _action(tool, path):
        return {"tool": tool, "args": {"path": path}, "role": "coder",
                "agent_id": "a1"}

    def test_declared_path_still_matches(self):
        eng = self._engine()
        d = eng.evaluate(self._action("write_file", "excluded-zone/x.txt"),
                         {})
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.policy_id, "deny-excluded-zone")

    def test_resolved_path_matches_when_declared_does_not(self):
        eng = self._engine()
        d = eng.evaluate(self._action("write_file", "innocent-link/x.txt"),
                         {"path_resolved": "excluded-zone/x.txt"})
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.policy_id, "deny-excluded-zone")

    def test_neither_matches_falls_through_to_allow(self):
        eng = self._engine()
        d = eng.evaluate(self._action("write_file", "notes.txt"),
                         {"path_resolved": "notes.txt"})
        self.assertEqual(d.effect, "allow")

    def test_missing_path_resolved_is_declared_only(self):
        # Policy evaluated outside ToolExecutor._context (no resolved
        # signal): behavior is exactly the pre-F146 declared-only match.
        eng = self._engine()
        d = eng.evaluate(self._action("write_file", "innocent-link/x.txt"),
                         {})
        self.assertEqual(d.effect, "allow")

    def test_allow_rule_also_sees_resolved_target(self):
        # Symmetric semantics: an allow rule keyed on a path substring
        # matches via the resolved target too.
        pol = ("version: 2\n"
               "roles:\n"
               "  coder: [read_file]\n"
               "policies:\n"
               "  - id: allow-docs\n"
               "    effect: allow\n"
               "    match:\n"
               "      tool: [read_file]\n"
               "      path_contains_any: [docs]\n"
               "    reason: docs are public\n")
        from gov.policy import PolicyEngine
        eng = PolicyEngine(_tmp_policy(pol))
        d = eng.evaluate(self._action("read_file", "d-link/m.txt"),
                         {"path_resolved": "docs/m.txt"})
        self.assertEqual(d.effect, "allow")

    def test_executor_denies_write_through_symlink_to_excluded_zone(self):
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        ident = run["executor"].mint_identity("f146-a", "coder", "f146-p")
        sb = Path(run["executor"].sandbox)
        (sb / "excluded-zone").mkdir(exist_ok=True)
        os.symlink(str(sb / "excluded-zone"), str(sb / "innocent-link"))
        r = run["executor"].call(ident, "write_file",
                                 path="innocent-link/p.txt", content="x")
        self.assertEqual(r["status"], "denied")

    def test_executor_denies_read_through_symlink_to_excluded_zone(self):
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        ident = run["executor"].mint_identity("f146-a", "coder", "f146-p")
        sb = Path(run["executor"].sandbox)
        (sb / "excluded-zone").mkdir(exist_ok=True)
        (sb / "excluded-zone" / "n.txt").write_text("s3cr3t",
                                                   encoding="utf-8")
        os.symlink(str(sb / "excluded-zone"), str(sb / "innocent-link"))
        r = run["executor"].call(ident, "read_file",
                                 path="innocent-link/n.txt")
        self.assertEqual(r["status"], "denied")

    def test_executor_allows_write_through_benign_symlink(self):
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        ident = run["executor"].mint_identity("f146-a", "coder", "f146-p")
        sb = Path(run["executor"].sandbox)
        (sb / "docs").mkdir(exist_ok=True)
        os.symlink(str(sb / "docs"), str(sb / "docs-link"))
        r = run["executor"].call(ident, "write_file",
                                 path="docs-link/m.txt", content="m")
        self.assertEqual(r["status"], "executed")

    def test_resolved_path_is_sandbox_relative(self):
        # The absolute sandbox prefix must not participate in substring
        # matching (false-positive factory); the resolved target stays
        # sandbox-relative when inside the sandbox.
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        sb = Path(run["executor"].sandbox)
        (sb / "docs").mkdir(exist_ok=True)
        os.symlink(str(sb / "docs"), str(sb / "docs-link"))
        resolved = run["executor"]._resolved_path_for_policy("docs-link/m.txt")
        self.assertEqual(resolved, "docs/m.txt")
        self.assertFalse(Path(resolved).is_absolute())

    def test_resolved_path_failure_falls_back_to_declared(self):
        # Resolution can never weaken matching: on failure the declared
        # path is returned, i.e. exactly today's behavior.
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        resolved = run["executor"]._resolved_path_for_policy(
            "nonexistent-dir/x.txt")
        self.assertEqual(resolved, "nonexistent-dir/x.txt")


class TestF147UseTimeRecheck(unittest.TestCase):
    """F147: symlink-swap TOCTOU between check-time policy evaluation
    and use-time _simulate for path_contains_any (direct-call() path).

    F146 evaluates path_contains_any against the check-time resolved
    target, but _simulate never re-checks: a symlink flipped between
    the verdict and the effect lets the use-time effect follow a
    target the policy never evaluated. The fix binds the check-time
    resolved target to the verdict and quarantines/denies at use time
    on mismatch (wave-35 idiom: fail closed on a mid-call change).

    Red: the break battery evals/f147toctou_break.py p1/p2
    (2 BREAK pre-fix, 0 BREAK post-fix). These tests model the exact
    TOCTOU window deterministically: the flip lands after check-time
    policy evaluation, before the use-time effect."""

    EXCL_POLICY = TestF146ResolvedPathMatching.EXCL_POLICY

    def _run_with_link(self):
        run = make_run(policy_path=_tmp_policy(self.EXCL_POLICY))
        ex = run["executor"]
        ident = ex.mint_identity("f147-a", "coder", "f147-p")
        sb = Path(ex.sandbox)
        (sb / "docs").mkdir(exist_ok=True)
        (sb / "excluded-zone").mkdir(exist_ok=True)
        link = sb / "hot-link"
        os.symlink(str(sb / "docs"), str(link))
        return run, ex, ident, sb, link

    def _call_with_midcall_flip(self, ex, ident, tool, target, **kwargs):
        """Run ex.call() with the symlink flipped to `target` after
        check-time policy evaluation but before the use-time effect."""
        sb = Path(ex.sandbox)
        link = sb / "hot-link"
        orig_simulate = ex._simulate

        def flipping_simulate(t, a, c):
            os.unlink(link)
            os.symlink(str(target), str(link))
            return orig_simulate(t, a, c)

        ex._simulate = flipping_simulate
        try:
            return ex.call(ident, tool, **kwargs)
        finally:
            ex._simulate = orig_simulate

    def test_write_quarantined_when_target_flips_to_excluded_mid_call(self):
        run, ex, ident, sb, link = self._run_with_link()
        r = self._call_with_midcall_flip(
            ex, ident, "write_file", sb / "excluded-zone",
            path="hot-link/p.txt", content="VICTIM")
        # Fail-closed: nothing lands in the excluded zone...
        self.assertFalse((sb / "excluded-zone" / "p.txt").exists())
        # ...and nothing lands via the stale benign target either --
        # the verdict authorized docs/p.txt, the effect would have hit
        # excluded-zone/p.txt, so no effect takes place.
        self.assertFalse((sb / "docs" / "p.txt").exists())

    def test_read_leaks_nothing_when_target_flips_to_excluded_mid_call(self):
        run, ex, ident, sb, link = self._run_with_link()
        (sb / "docs" / "notes.txt").write_text("benign docs",
                                               encoding="utf-8")
        (sb / "excluded-zone" / "notes.txt").write_text(
            "EXCLUDED-ZONE-MARKER", encoding="utf-8")
        r = self._call_with_midcall_flip(
            ex, ident, "read_file", sb / "excluded-zone",
            path="hot-link/notes.txt")
        content = (r.get("result") or {}).get("content", "")
        self.assertNotIn("EXCLUDED-ZONE-MARKER", content)

    def test_write_executes_cleanly_when_link_stable(self):
        # False-positive guard: a stable benign symlink is unaffected.
        run, ex, ident, sb, link = self._run_with_link()
        r = ex.call(ident, "write_file", path="hot-link/m.txt",
                    content="m")
        self.assertEqual(r["status"], "executed")
        self.assertTrue((sb / "docs" / "m.txt").exists())

    def test_read_executes_cleanly_when_link_stable(self):
        run, ex, ident, sb, link = self._run_with_link()
        (sb / "docs" / "n.txt").write_text("hello", encoding="utf-8")
        r = ex.call(ident, "read_file", path="hot-link/n.txt")
        self.assertEqual(r["status"], "executed")
        self.assertIn("hello", (r.get("result") or {}).get("content", ""))

    def test_write_quarantined_when_flip_stays_between_benign_targets(self):
        # A mid-call flip between two benign targets is still a target
        # change: the check-time verdict no longer describes the
        # use-time effect, so the effect is quarantined (fail closed).
        run, ex, ident, sb, link = self._run_with_link()
        (sb / "docs2").mkdir(exist_ok=True)
        r = self._call_with_midcall_flip(
            ex, ident, "write_file", sb / "docs2",
            path="hot-link/q.txt", content="q")
        self.assertFalse((sb / "docs2" / "q.txt").exists())
        self.assertFalse((sb / "docs" / "q.txt").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
