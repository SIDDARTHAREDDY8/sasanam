"""Tests for gov/keyfiles.py and its two integration points (wave-91, G1).

Custody-harden audit (stream 2) found the permission posture on key
files was inconsistent: four loaders refused group/world-readable
files, but ``resolve_anchor_key`` warned-and-loaded a 0644 anchor key
file, and ``LineageTracker._load_or_create_key`` checked nothing.
The fix: a uniform fail-closed gate (``require_private_key_file``)
applied BEFORE any key bytes are read.

Break-first evidence for the two integration points: pre-fix, a 0644
``GOV_ANCHOR_KEY_FILE`` produced a stderr warning and loaded; a 0644
lineage ``.key`` loaded silently. These tests pin the post-fix
refusal.

Deterministic: stdlib unittest only. Distinct TMPDIR per run via the
canonical runner.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from gov.keyfiles import require_private_key_file

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_key(path, mode=0o600, nbytes=32):
    p = Path(path)
    p.write_bytes(os.urandom(nbytes))
    os.chmod(p, mode)
    return p


class GateTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="govkeyfiles-")
        self.addCleanup(self._td.cleanup)
        self.d = Path(self._td.name)

    def test_private_file_passes(self):
        p = _write_key(self.d / "k", mode=0o600)
        self.assertEqual(require_private_key_file(p), p)

    def test_group_readable_refused(self):
        p = _write_key(self.d / "k", mode=0o640)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_world_readable_refused(self):
        p = _write_key(self.d / "k", mode=0o644)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_world_writable_refused(self):
        p = _write_key(self.d / "k", mode=0o602)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)

    def test_missing_raises_not_found(self):
        with self.assertRaises(FileNotFoundError):
            require_private_key_file(self.d / "nope")

    def test_symlink_refused_even_to_private_target(self):
        target = _write_key(self.d / "target", mode=0o600)
        link = self.d / "link"
        os.symlink(target, link)
        with self.assertRaises(PermissionError):
            require_private_key_file(link)

    def test_directory_refused(self):
        with self.assertRaises(PermissionError):
            require_private_key_file(self.d)

    def test_refusal_happens_before_read(self):
        # The gate must not need to read the file to refuse it: a
        # 0644 file with garbage bytes is refused for permissions,
        # not for content.
        p = self.d / "k"
        p.write_bytes(b"not-a-key")
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            require_private_key_file(p)


class AnchorerIntegrationTest(unittest.TestCase):
    """GOV_ANCHOR_KEY_FILE: 0644 is refused (was: warn-and-load)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="govanchor-")
        self.addCleanup(self._td.cleanup)
        self.d = Path(self._td.name)
        self._old = os.environ.get("GOV_ANCHOR_KEY_FILE")
        os.environ.pop("GOV_ANCHOR_KEY_FILE", None)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._old is None:
            os.environ.pop("GOV_ANCHOR_KEY_FILE", None)
        else:
            os.environ["GOV_ANCHOR_KEY_FILE"] = self._old

    def _seed_file(self, mode):
        from gov.anchor_backend import anchor_pubkey
        seed = os.urandom(32)
        p = self.d / "anchor.key"
        p.write_text(seed.hex(), encoding="utf-8")
        os.chmod(p, mode)
        return p, anchor_pubkey(seed).hex()

    def test_private_anchor_file_loads(self):
        from gov.anchorer import resolve_anchor_key
        p, pub = self._seed_file(0o600)
        os.environ["GOV_ANCHOR_KEY_FILE"] = str(p)
        got = resolve_anchor_key()
        self.assertEqual(got["pubkey_hex"], pub)
        self.assertFalse(got["dev"])

    def test_group_world_readable_anchor_file_refused(self):
        from gov.anchorer import NoAnchorKeyError, resolve_anchor_key
        p, _ = self._seed_file(0o644)
        os.environ["GOV_ANCHOR_KEY_FILE"] = str(p)
        with self.assertRaises(NoAnchorKeyError) as ctx:
            resolve_anchor_key()
        self.assertIn("chmod 600", str(ctx.exception))

    def test_missing_anchor_file_refused_loudly(self):
        from gov.anchorer import NoAnchorKeyError, resolve_anchor_key
        os.environ["GOV_ANCHOR_KEY_FILE"] = str(self.d / "missing.key")
        with self.assertRaises(NoAnchorKeyError):
            resolve_anchor_key()


class LineageIntegrationTest(unittest.TestCase):
    """Lineage run key: a 0644 .key is refused (was: silently loaded)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="govlineage-")
        self.addCleanup(self._td.cleanup)
        self.d = Path(self._td.name)

    def _tracker_dir(self):
        from gov.lineage import _KEY_NAME
        run_dir = self.d / "run"
        ldir = run_dir / "lineage"
        ldir.mkdir(parents=True)
        return run_dir, ldir / _KEY_NAME

    def test_private_key_file_loads(self):
        from gov.lineage import LineageTracker
        run_dir, key_path = self._tracker_dir()
        key_path.write_bytes(os.urandom(32))
        os.chmod(key_path, 0o600)

        class _StubLog(object):
            def append(self, entry):
                return {"seq": 0}

        t = LineageTracker(run_dir, _StubLog())
        self.assertEqual(t._key, key_path.read_bytes())

    def test_world_readable_key_file_refused(self):
        from gov.lineage import LineageTracker
        run_dir, key_path = self._tracker_dir()
        key_path.write_bytes(os.urandom(32))
        os.chmod(key_path, 0o644)

        class _StubLog(object):
            def append(self, entry):
                return {"seq": 0}

        with self.assertRaises(PermissionError):
            LineageTracker(run_dir, _StubLog())

    def test_symlinked_key_file_refused(self):
        from gov.lineage import LineageTracker
        run_dir, key_path = self._tracker_dir()
        target = self.d / "real.key"
        target.write_bytes(os.urandom(32))
        os.chmod(target, 0o600)
        os.symlink(target, key_path)

        class _StubLog(object):
            def append(self, entry):
                return {"seq": 0}

        with self.assertRaises(PermissionError):
            LineageTracker(run_dir, _StubLog())

    def test_fresh_tracker_still_creates_0600(self):
        from gov.lineage import LineageTracker
        run_dir, key_path = self._tracker_dir()

        class _StubLog(object):
            def append(self, entry):
                return {"seq": 0}

        LineageTracker(run_dir, _StubLog())
        self.assertTrue(key_path.is_file())
        self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
