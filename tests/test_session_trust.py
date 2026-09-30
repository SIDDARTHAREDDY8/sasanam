"""Unit tests for gov.session_trust (wave-244 lane A).

Pins the trust-ordering contract beyond the red-first battery: state
defaults, registry behavior, escape resolution, audit redaction, and the
registered refusal vocabulary. No subprocesses; the git binary is never
executed.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import session_trust as st  # noqa: E402


def _repo(parent, name, config=None):
    root = os.path.join(parent, name)
    git = os.path.join(root, ".git")
    os.makedirs(git, exist_ok=True)
    with open(os.path.join(git, "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    if config is not None:
        with open(os.path.join(git, "config"), "w") as f:
            f.write(config)
    return root


class TestStates(unittest.TestCase):
    def test_default_is_untrusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            self.assertEqual(reg.state_of(root), st.UNTRUSTED)

    def test_record_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            reg.record_trust(root, st.ALLOWED, decided_by="op")
            self.assertEqual(reg.state_of(root), st.ALLOWED)
            reg.record_trust(root, st.DENIED, decided_by="op")
            self.assertEqual(reg.state_of(root), st.DENIED)

    def test_records_keyed_by_canonical_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            reg.record_trust(root + "/.", st.ALLOWED, decided_by="op")
            self.assertEqual(reg.state_of(root), st.ALLOWED)


class TestMalformed(unittest.TestCase):
    def test_unknown_state_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            with self.assertRaises(st.SessionTrustError) as ctx:
                reg.record_trust(root, "super-trusted", decided_by="op")
            self.assertEqual(ctx.exception.code,
                             "session-trust-malformed")
            self.assertEqual(reg.state_of(root), st.UNTRUSTED)

    def test_empty_decided_by_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            with self.assertRaises(st.SessionTrustError) as ctx:
                reg.record_trust(root, st.ALLOWED, decided_by="  ")
            self.assertEqual(ctx.exception.code,
                             "session-trust-malformed")

    def test_unregistered_code_cannot_raise(self):
        with self.assertRaises(st.SessionTrustError) as ctx:
            st.raise_refusal("not-a-real-code")
        self.assertEqual(ctx.exception.code, "session-trust-malformed")
        self.assertIn("not-a-real-code", ctx.exception.detail)

    def test_vocabulary_is_registered(self):
        vocab = st.registered_refusals()
        self.assertIn("repo-hook-pretrust-refused", vocab)
        self.assertIn("repo-hook-trust-denied", vocab)
        self.assertIn("repo-hook-escape-refused", vocab)
        self.assertIn("session-trust-malformed", vocab)


class TestCheckedSpawn(unittest.TestCase):
    def test_untrusted_refuses_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a", config="[core]\n\tfsmonitor = /x\n")
            reg = st.TrustRegistry()
            calls = []
            with self.assertRaises(st.SessionTrustError) as ctx:
                st.checked_spawn(["status"], root, reg,
                                 spawn=lambda a, env=None, cwd=None:
                                 calls.append(a))
            self.assertEqual(ctx.exception.code,
                             "repo-hook-pretrust-refused")
            self.assertEqual(calls, [])

    def test_denied_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            reg.record_trust(root, st.DENIED, decided_by="op")
            with self.assertRaises(st.SessionTrustError) as ctx:
                st.checked_spawn(["status"], root, reg, spawn=lambda *a,
                                 **k: None)
            self.assertEqual(ctx.exception.code, "repo-hook-trust-denied")

    def test_no_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            with self.assertRaises(st.SessionTrustError) as ctx:
                st.checked_spawn(["status"], root, None,
                                 spawn=lambda *a, **k: None)
            self.assertEqual(ctx.exception.code,
                             "session-trust-malformed")

    def test_error_carries_no_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a", config="[core]\n\tfsmonitor = /x\n")
            reg = st.TrustRegistry()
            try:
                st.checked_spawn(["status"], root, reg,
                                 spawn=lambda *a, **k: None)
                self.fail("no refusal")
            except st.SessionTrustError as e:
                self.assertNotIn("/x", str(e))
                self.assertNotIn(root, str(e))


class TestEscape(unittest.TestCase):
    def test_git_symlink_outside_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = os.path.join(tmp, "outside")
            os.makedirs(outside)
            root = _repo(tmp, "a")
            shutil.rmtree(os.path.join(root, ".git"))
            os.symlink(outside, os.path.join(root, ".git"))
            with self.assertRaises(st.SessionTrustError) as ctx:
                st.resolve_repo_root(root)
            self.assertEqual(ctx.exception.code,
                             "repo-hook-escape-refused")

    def test_config_symlink_outside_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = os.path.join(tmp, "secret-config")
            with open(secret, "w") as f:
                f.write("[core]\n")
            root = _repo(tmp, "a")
            os.remove(os.path.join(root, ".git", "HEAD"))
            os.symlink(secret, os.path.join(root, ".git", "config"))
            with self.assertRaises(st.SessionTrustError) as ctx:
                st.resolve_repo_root(root)
            self.assertEqual(ctx.exception.code,
                             "repo-hook-escape-refused")

    def test_git_symlink_inside_root_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            target = os.path.join(root, "real-git")
            os.makedirs(target)
            shutil.rmtree(os.path.join(root, ".git"))
            os.symlink(target, os.path.join(root, ".git"))
            self.assertEqual(st.resolve_repo_root(root),
                             os.path.realpath(root))


class TestAudit(unittest.TestCase):
    def test_refusal_record_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a", config="[core]\n\tfsmonitor = /S3CR3T\n")
            reg = st.TrustRegistry()
            records = []
            try:
                st.checked_spawn(["status"], root, reg,
                                 spawn=lambda *a, **k: None,
                                 audit=records.append)
                self.fail("no refusal")
            except st.SessionTrustError:
                pass
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["event"], "trust-refusal")
            self.assertEqual(rec["code"], "repo-hook-pretrust-refused")
            self.assertNotIn("/S3CR3T", repr(rec))
            self.assertNotIn("fsmonitor", repr(rec))
            self.assertNotIn(root, repr(rec))

    def test_audit_none_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(tmp, "a")
            reg = st.TrustRegistry()
            with self.assertRaises(st.SessionTrustError):
                st.checked_spawn(["status"], root, reg,
                                 spawn=lambda *a, **k: None, audit=None)


if __name__ == "__main__":
    unittest.main()
