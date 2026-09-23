"""Tests for the G1 prototype (stream 2, custody-harden).

Verifies the uniform fail-closed permission posture:
refuse group/world-readable key files, refuse symlinks and non-regular
files, refuse-then-never-read (fail-closed ordering), and parity with
the existing gov/ behavior on the happy path.

Synthetic/local only: temp dirs, random keys, no network.
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

# Import the prototype under test. The stream dir is not a package; load
# by path so the test runs from the repo root like the rest of the
# suite (PYTHONPATH=<repo>).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from strict_keyfiles import (  # noqa: E402
    load_anchor_seed_strict,
    load_or_create_lineage_key_strict,
    require_private_key_file,
)


def _write(path, data, mode):
    p = Path(path)
    p.write_bytes(data)
    os.chmod(p, mode)
    return p


class RequirePrivateKeyFileTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_ok_0600(self):
        p = _write(self.dir / "k", b"x" * 32, 0o600)
        self.assertEqual(require_private_key_file(p), p)

    def test_ok_0400(self):
        p = _write(self.dir / "k", b"x" * 32, 0o400)
        require_private_key_file(p)  # read-only owner is fine

    def test_refuse_0644(self):
        p = _write(self.dir / "k", b"x" * 32, 0o644)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_refuse_0660(self):
        p = _write(self.dir / "k", b"x" * 32, 0o660)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_refuse_0602_world_writable(self):
        p = _write(self.dir / "k", b"x" * 32, 0o602)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_missing_raises_not_silent(self):
        with self.assertRaises(FileNotFoundError):
            require_private_key_file(self.dir / "nope")

    def test_refuse_symlink(self):
        target = _write(self.dir / "real", b"x" * 32, 0o600)
        link = self.dir / "link"
        os.symlink(target, link)
        with self.assertRaises(PermissionError):
            require_private_key_file(link)

    def test_refuse_directory(self):
        with self.assertRaises(PermissionError):
            require_private_key_file(self.dir)

    def test_refuse_fifo(self):
        fifo = self.dir / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(PermissionError):
            require_private_key_file(fifo)


class LoadAnchorSeedStrictTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = Path(self._td.name)
        self.seed = os.urandom(32)
        self.good = _write(self.dir / "anchor.key",
                           self.seed.hex().encode("ascii"), 0o600)

    def tearDown(self):
        self._td.cleanup()

    def test_happy_path_shape(self):
        got = load_anchor_seed_strict(self.good)
        self.assertEqual(got["seed"], self.seed)
        self.assertFalse(got["dev"])
        self.assertEqual(len(got["pubkey_hex"]), 64)
        self.assertTrue(got["key_id"])

    def test_refuse_0644_where_gov_warns(self):
        # G1: gov/anchorer.resolve_anchor_key warns and loads a 0644
        # anchor key file; the strict loader refuses.
        bad = _write(self.dir / "anchor0644.key",
                     self.seed.hex().encode("ascii"), 0o644)
        with self.assertRaises(PermissionError):
            load_anchor_seed_strict(bad)

    def test_refuse_not_hex(self):
        p = _write(self.dir / "bad.key", b"not-hex", 0o600)
        with self.assertRaises(ValueError):
            load_anchor_seed_strict(p)

    def test_refuse_wrong_length(self):
        p = _write(self.dir / "short.key",
                   os.urandom(16).hex().encode("ascii"), 0o600)
        with self.assertRaises(ValueError):
            load_anchor_seed_strict(p)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_anchor_seed_strict(self.dir / "missing.key")

    def test_pubkey_matches_gov_derivation(self):
        # The strict loader must agree byte-for-byte with gov's own
        # derivation (drop-in compatibility for the file branch).
        from gov.anchorer import resolve_anchor_key
        os.environ["GOV_ANCHOR_KEY"] = self.seed.hex()
        try:
            expected = resolve_anchor_key()
        finally:
            del os.environ["GOV_ANCHOR_KEY"]
        got = load_anchor_seed_strict(self.good)
        self.assertEqual(got["key_id"], expected["key_id"])
        self.assertEqual(got["pubkey_hex"], expected["pubkey_hex"])


class LoadOrCreateLineageKeyStrictTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_create_is_0600_and_32_bytes(self):
        key = load_or_create_lineage_key_strict(self.dir)
        self.assertEqual(len(key), 32)
        st = (self.dir / "run.key").stat()
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)

    def test_existing_0600_is_reused(self):
        first = load_or_create_lineage_key_strict(self.dir)
        second = load_or_create_lineage_key_strict(self.dir)
        self.assertEqual(first, second)

    def test_existing_0644_refused_not_silently_loaded(self):
        # G1: gov/lineage loads a 0644 run key silently; strict refuses.
        p = self.dir / "run.key"
        p.write_bytes(os.urandom(32))
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            load_or_create_lineage_key_strict(self.dir)

    def test_degenerate_file_rotated(self):
        p = self.dir / "run.key"
        p.write_bytes(b"short")
        os.chmod(p, 0o600)
        key = load_or_create_lineage_key_strict(self.dir)
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, b"short")

    def test_symlink_refused(self):
        target = self.dir / "real.key"
        target.write_bytes(os.urandom(32))
        os.chmod(target, 0o600)
        os.symlink(target, self.dir / "run.key")
        with self.assertRaises(PermissionError):
            load_or_create_lineage_key_strict(self.dir)

    def test_keys_are_fresh_random_per_dir(self):
        other = Path(tempfile.mkdtemp())
        try:
            k1 = load_or_create_lineage_key_strict(self.dir)
            k2 = load_or_create_lineage_key_strict(other)
            self.assertNotEqual(k1, k2)
        finally:
            import shutil
            shutil.rmtree(other, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
