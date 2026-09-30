#!/usr/bin/env python3
"""Unit tests for gov/git_sanitize.py.

Independent spec-vector literals (not derived from the implementation):
each test states the fixture config, the expected verdict, and -- for
refusals -- the exact refusal code.
"""

import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import git_sanitize as gs  # noqa: E402


def _repo_with_config(config_text=None, raw_bytes=None):
    root = tempfile.mkdtemp(prefix="gitsan-unit-")
    gitdir = os.path.join(root, ".git")
    os.makedirs(gitdir, exist_ok=True)
    if raw_bytes is not None:
        with open(os.path.join(gitdir, "config"), "wb") as fh:
            fh.write(raw_bytes)
    elif config_text is not None:
        with open(os.path.join(gitdir, "config"), "w",
                  encoding="utf-8") as fh:
            fh.write(config_text)
    return root


class TestDenyConfigKeys(unittest.TestCase):

    def test_exact_fsmonitor_refused(self):
        repo = _repo_with_config("[core]\n\tfsmonitor = /tmp/x.sh\n")
        with self.assertRaises(gs.GitSpawnHostileConfigError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")
        self.assertIn("core.fsmonitor",
                      ctx.exception.offending_keys)

    def test_hooks_path_refused(self):
        repo = _repo_with_config("[core]\n\thooksPath = /tmp/hooks\n")
        with self.assertRaises(gs.GitSanitizeError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")

    def test_filter_smudge_refused(self):
        repo = _repo_with_config(
            '[filter "lfs"]\n\tsmudge = git-lfs smudge\n')
        with self.assertRaises(gs.GitSanitizeError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")
        self.assertTrue(any("filter" in k
                            for k in ctx.exception.offending_keys))

    def test_diff_external_refused(self):
        repo = _repo_with_config("[diff]\n\texternal = /tmp/d.sh\n")
        with self.assertRaises(gs.GitSanitizeError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")

    def test_case_insensitive_key(self):
        # Git keys are case-insensitive; the scan must be too.
        repo = _repo_with_config("[core]\n\tFSMONITOR = /tmp/x.sh\n")
        with self.assertRaises(gs.GitSanitizeError):
            gs.deny_config_keys(repo)

    def test_benign_alias_passes(self):
        repo = _repo_with_config("[alias]\n\tco = checkout\n")
        self.assertIsNone(gs.deny_config_keys(repo))

    def test_bang_alias_refused(self):
        repo = _repo_with_config("[alias]\n\tp = !git push --force\n")
        with self.assertRaises(gs.GitSanitizeError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")

    def test_clean_config_passes(self):
        repo = _repo_with_config(
            "[core]\n\trepositoryformatversion = 0\n"
            "[user]\n\tname = ci\n")
        self.assertIsNone(gs.deny_config_keys(repo))

    def test_no_config_passes(self):
        root = tempfile.mkdtemp(prefix="gitsan-nocfg-")
        self.assertIsNone(gs.deny_config_keys(root))

    def test_non_utf8_fails_closed(self):
        repo = _repo_with_config(raw_bytes=b"\xff\xfe\x00bad")
        with self.assertRaises(gs.GitSanitizeUnparseableError) as ctx:
            gs.deny_config_keys(repo)
        self.assertEqual(ctx.exception.code,
                         "gitspawn-config-unparseable")

    def test_key_outside_section_fails_closed(self):
        repo = _repo_with_config(raw_bytes=b"naked = 1\n")
        with self.assertRaises(gs.GitSanitizeUnparseableError):
            gs.deny_config_keys(repo)

    def test_worktree_gitdir_pointer(self):
        root = tempfile.mkdtemp(prefix="gitsan-worktree-")
        real_git = tempfile.mkdtemp(prefix="gitsan-realgit-")
        with open(os.path.join(real_git, "config"), "w") as fh:
            fh.write("[core]\n\tpager = /tmp/evil\n")
        with open(os.path.join(root, ".git"), "w") as fh:
            fh.write("gitdir: %s\n" % real_git)
        with self.assertRaises(gs.GitSanitizeError) as ctx:
            gs.deny_config_keys(root)
        self.assertEqual(ctx.exception.code, "gitspawn-hostile-config")

    def test_include_chain_cycle_terminates(self):
        root = tempfile.mkdtemp(prefix="gitsan-cycle-")
        gitdir = os.path.join(root, ".git")
        os.makedirs(gitdir, exist_ok=True)
        with open(os.path.join(gitdir, "config"), "w") as fh:
            fh.write("[include]\n\tpath = ../c1.inc\n")
        with open(os.path.join(root, "c1.inc"), "w") as fh:
            fh.write("[include]\n\tpath = c2.inc\n")
        with open(os.path.join(root, "c2.inc"), "w") as fh:
            fh.write("[include]\n\tpath = c1.inc\n[user]\n\tname = ok\n")
        # Terminates and passes: no exec keys anywhere in the chain.
        self.assertIsNone(gs.deny_config_keys(root))


class TestSanitizedGitEnv(unittest.TestCase):

    def test_protections_present(self):
        repo = _repo_with_config("[core]\n")
        env = gs.sanitized_git_env(repo)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_CONFIG_SYSTEM"], "/dev/null")
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "safe.directory")
        self.assertEqual(env["GIT_CONFIG_VALUE_0"],
                         os.path.abspath(repo))

    def test_deterministic(self):
        repo = _repo_with_config("[core]\n")
        self.assertEqual(gs.sanitized_git_env(repo),
                         gs.sanitized_git_env(repo))

    def test_does_not_mutate_process_env(self):
        before = dict(os.environ)
        gs.sanitized_git_env(_repo_with_config("[core]\n"))
        self.assertEqual(dict(os.environ), before)


class TestRunGitSanitized(unittest.TestCase):

    def test_deny_before_exec(self):
        repo = _repo_with_config(
            "[core]\n\tfsmonitor = /tmp/never.sh\n")
        calls = []
        with self.assertRaises(gs.GitSpawnHostileConfigError):
            gs.run_git_sanitized(["status"], repo,
                                 spawn=lambda a, env=None, cwd=None:
                                 calls.append(a))
        self.assertEqual(calls, [])

    def test_clean_repo_invokes_exec_with_hardened_env(self):
        repo = _repo_with_config("[user]\n\tname = ci\n")
        seen = {}

        def _fake(argv, env=None, cwd=None):
            seen["argv"] = argv
            seen["env"] = env
            seen["cwd"] = cwd
            return 42

        rc = gs.run_git_sanitized(["rev-parse", "--git-dir"], repo,
                                  spawn=_fake)
        self.assertEqual(rc, 42)
        self.assertEqual(seen["argv"], ["git", "rev-parse", "--git-dir"])
        self.assertEqual(seen["cwd"], os.path.abspath(repo))
        self.assertEqual(seen["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_in_repo_spawn_refused(self):
        repo = _repo_with_config("[user]\n\tname = ci\n")
        with self.assertRaises(gs.GitSpawnInRepoRefusedError) as ctx:
            gs.run_git_sanitized(["status"], repo)
        self.assertEqual(ctx.exception.code,
                         "gitspawn-in-repo-git-refused")

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(gs.GitSpawnHostileConfigError,
                                   gs.GitSanitizeError))
        self.assertTrue(issubclass(gs.GitSanitizeUnparseableError,
                                   gs.GitSanitizeError))
        self.assertTrue(issubclass(gs.GitSpawnInRepoRefusedError,
                                   gs.GitSanitizeError))


if __name__ == "__main__":
    unittest.main()
