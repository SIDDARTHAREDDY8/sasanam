"""F75 supply-chain controls: lockfile, allowlist, artifact verification.

Covers ``gov/supplychain.py`` — the closure of finding F75 (unpinned
dependency graph: the governed surface started *after* dependency
resolution, so a dependency-confusion or typosquat package in the
install path ran with operator privileges, outside every control):

  * the repo ``requirements.lock`` parses, pins exact versions, and
    carries sha256 hashes for every entry;
  * malformed lockfiles fail closed (no silent half-read);
  * the environment audit rejects unlisted packages (typosquat /
    dependency-confusion shape) and version drift (tampered installs)
    before any test runs;
  * artifact verification accepts the pinned bytes and rejects
    tampered bytes;
  * the mini PEP 508 marker evaluator agrees with ``packaging`` on
    every real marker in the installed metadata (stdlib-only regen).

Hermetic: synthetic lockfiles/distributions live in temp dirs and are
passed explicitly; the real-environment tests are read-only.
"""

import hashlib
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import supplychain as sc  # noqa: E402

_FAKE_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _write_lock(tmp, body):
    path = os.path.join(tmp, "requirements.lock")
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path


_GOOD_LOCK = """\
# test lock
alpha-pkg==1.2.3 \\
    --hash=sha256:%s \\
    --hash=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
beta_pkg==0.1 \\
    --hash=sha256:%s
""" % (_FAKE_DIGEST, _FAKE_DIGEST)


class TestLockfileParsing(unittest.TestCase):
    def test_repo_lockfile_parses_with_exact_pins_and_hashes(self):
        lock = sc.load_lockfile()
        self.assertGreaterEqual(len(lock), 30)
        for key, entry in lock.items():
            self.assertRegex(entry["version"], r"^[A-Za-z0-9_.\-+!]+$")
            self.assertGreaterEqual(len(entry["hashes"]), 1)
            for h in entry["hashes"]:
                algo, digest = h.split(":")
                self.assertEqual(algo, "sha256")
                self.assertEqual(len(digest), 64)
        # spot-check the pins the suite actually depends on
        self.assertEqual(lock["pyyaml"]["version"], "6.0.3")
        self.assertEqual(lock["pydantic"]["version"], "2.13.5")
        self.assertIn("langchain-core", lock)

    def test_good_lock_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = sc.load_lockfile(_write_lock(tmp, _GOOD_LOCK))
        self.assertEqual(lock["alpha-pkg"]["version"], "1.2.3")
        self.assertEqual(len(lock["alpha-pkg"]["hashes"]), 2)
        self.assertEqual(lock["beta-pkg"]["version"], "0.1")

    def test_malformed_locks_fail_closed(self):
        bad = [
            # entry with no hashes
            "alpha==1.0 \\\n",
            # hash before any package line
            "--hash=sha256:%s\n" % _FAKE_DIGEST,
            # non-exact pin
            "alpha>=1.0 \\\n    --hash=sha256:%s\n" % _FAKE_DIGEST,
            # short digest
            "alpha==1.0 \\\n    --hash=sha256:abcd\n",
            # non-sha256 algorithm
            "alpha==1.0 \\\n    --hash=sha512:%s\n" % ("ab" * 64),
            # duplicate entry
            "alpha==1.0 \\\n    --hash=sha256:%s\nalpha==1.0 \\\n    --hash=sha256:%s\n"
            % (_FAKE_DIGEST, _FAKE_DIGEST),
            # garbage line
            "this is not a lockfile\n",
            # empty file
            "",
        ]
        for body in bad:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(sc.SupplyChainError, msg=body[:40]):
                    sc.load_lockfile(_write_lock(tmp, body))

    def test_missing_lockfile_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(sc.SupplyChainError):
                sc.load_lockfile(os.path.join(tmp, "nope.lock"))


class TestEnvironmentAudit(unittest.TestCase):
    def _lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            return sc.load_lockfile(_write_lock(tmp, _GOOD_LOCK))

    def test_clean_synthetic_env_passes(self):
        lock = self._lock()
        dists = [("alpha-pkg", "1.2.3"), ("beta_pkg", "0.1"),
                 ("agent-governance", "0.2.0")]
        rep = sc.audit_environment(lock, _dists=dists)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["checked"], 3)

    def test_tampered_version_fails_closed(self):
        # attacker swaps in alpha-pkg 9.9.9 (or a silent upgrade drifts it)
        lock = self._lock()
        with self.assertRaises(sc.SupplyChainError) as c:
            sc.audit_environment(lock, _dists=[("alpha-pkg", "9.9.9")])
        self.assertIn("version drift", str(c.exception))
        self.assertIn("1.2.3", str(c.exception))

    def test_unlisted_package_fails_closed(self):
        # dependency-confusion / typosquat shape: name not in allowlist
        lock = self._lock()
        with self.assertRaises(sc.SupplyChainError) as c:
            sc.audit_environment(
                lock, _dists=[("alpha-pkg", "1.2.3"),
                              ("alpha-pkg-internal", "1.2.3")])
        self.assertIn("unlisted package", str(c.exception))
        self.assertIn("alpha-pkg-internal", str(c.exception))

    def test_multiple_violations_all_reported(self):
        lock = self._lock()
        with self.assertRaises(sc.SupplyChainError) as c:
            sc.audit_environment(
                lock, _dists=[("alpha-pkg", "9.9.9"), ("evil", "1.0")])
        self.assertIn("2 violation", str(c.exception))

    def test_local_project_name_allowlisted(self):
        lock = self._lock()
        rep = sc.audit_environment(
            lock, _dists=[("agent-governance", "99.99")])
        self.assertTrue(rep["ok"])  # version not pinned: it is the source tree

    def test_canonicalization(self):
        self.assertEqual(sc._canonical("Alpha_Pkg"), "alpha-pkg")
        self.assertEqual(sc._canonical("beta.pkg"), "beta-pkg")

    def test_real_environment_passes(self):
        # read-only: the venv this suite runs in must satisfy the lockfile
        rep = sc.audit_environment()
        self.assertTrue(rep["ok"])
        self.assertGreater(rep["checked"], 30)


class TestInstallGate(unittest.TestCase):
    def test_allowlisted_install_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = sc.load_lockfile(_write_lock(tmp, _GOOD_LOCK))
        entry = sc.check_install_allowed("alpha-pkg", lock)
        self.assertEqual(entry["version"], "1.2.3")

    def test_unlisted_install_refused_before_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = sc.load_lockfile(_write_lock(tmp, _GOOD_LOCK))
        with self.assertRaises(sc.SupplyChainError):
            sc.check_install_allowed("alpha-pkg-internal", lock)


class TestArtifactVerification(unittest.TestCase):
    def test_pinned_bytes_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "artifact.whl")
            data = b"fake wheel bytes"
            with open(p, "wb") as f:
                f.write(data)
            digest = hashlib.sha256(data).hexdigest()
            got = sc.verify_artifact(p, frozenset({"sha256:" + digest}))
            self.assertEqual(got, digest)

    def test_tampered_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "artifact.whl")
            with open(p, "wb") as f:
                f.write(b"tampered bytes")
            with self.assertRaises(sc.SupplyChainError) as c:
                sc.verify_artifact(p, frozenset({"sha256:" + _FAKE_DIGEST}))
            self.assertIn("hash mismatch", str(c.exception))

    def test_repo_lock_pins_verify_a_known_artifact(self):
        # end-to-end: a hash pinned in the real lockfile verifies bytes
        # whose digest we compute independently (self-consistency of the
        # pin format pip will enforce with --require-hashes).
        lock = sc.load_lockfile()
        entry = lock["pyyaml"]
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "x")
            with open(p, "wb") as f:
                f.write(b"")
            # empty file must NOT verify against the real pins
            with self.assertRaises(sc.SupplyChainError):
                sc.verify_artifact(p, entry["hashes"])


class TestMarkerEvaluator(unittest.TestCase):
    def test_agrees_with_packaging_on_real_markers(self):
        try:
            from importlib.metadata import distributions as _dists
            from packaging.requirements import Requirement
        except ImportError:
            self.skipTest("packaging not installed")
        markers = {str(Requirement(r).marker)
                   for d in _dists() for r in (d.requires or [])
                   if Requirement(r).marker is not None}
        self.assertGreater(len(markers), 10)
        for m in sorted(markers):
            expected = Requirement("x;" + m).marker.evaluate()
            self.assertEqual(sc._marker_eval(m), expected, "marker: %r" % m)

    def test_extra_gated_markers_excluded(self):
        self.assertFalse(sc._marker_eval('extra == "test"'))
        self.assertTrue(sc._marker_eval('python_version >= "3.8"'))
        self.assertTrue(sc._marker_eval('sys_platform != "win32"'))


class TestClosure(unittest.TestCase):
    def test_closure_matches_installed_minus_local_project(self):
        try:
            from importlib.metadata import distributions as _dists
            from packaging.utils import canonicalize_name
        except ImportError:
            self.skipTest("packaging not installed")
        closure, _ = sc._closure(["pydantic", "langchain-core", "PyYAML",
                                  "pip", "setuptools"])
        real = {canonicalize_name(d.metadata["Name"]) for d in _dists()
                if d.metadata.get("Name")}
        real.discard("agent-governance")
        self.assertEqual(closure, real)


if __name__ == "__main__":
    unittest.main()
