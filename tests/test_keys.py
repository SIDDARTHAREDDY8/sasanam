"""Tests for gov/keys.py: rotation epochs, backends, dev-key gating,
rotation ceremony, and cross-epoch log verification.

Deterministic: keys are random but every assertion is over structure,
round-trips, and verification verdicts — never over key values.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tempfile

from gov import keys
from gov.keys import KeyRing, NoKeyConfiguredError
from gov.log import ActionLog


def _clean_env():
    """Snapshot and scrub key-related env vars; returns a restore closure."""
    names = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
             "GOV_DEV_KEYS")
    saved = {n: os.environ.get(n) for n in names}
    for n in names:
        os.environ.pop(n, None)
    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v
    return restore


class KeyRingTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="govkeys-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_generate_has_epoch_keyid_and_32b_key(self):
        ring = KeyRing.generate("epoch-1")
        mat = ring.active()
        self.assertEqual(mat.epoch, "epoch-1")
        self.assertEqual(mat.status, "active")
        self.assertEqual(len(mat.key), 64)  # 32 random bytes, hex-encoded
        self.assertEqual(len(mat.key_id), 16)
        int(mat.key_id, 16)  # valid hex
        self.assertEqual(ring.epochs(), ["epoch-1"])

    def test_epoch_labels_validated(self):
        with self.assertRaises(ValueError):
            KeyRing.generate("../evil")
        with self.assertRaises(ValueError):
            KeyRing.generate("")

    def test_file_backend_roundtrip_and_perms(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        mode = p.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        loaded = KeyRing.load(p)
        self.assertEqual(loaded.active().key, ring.active().key)
        self.assertEqual(loaded.active().key_id, ring.active().key_id)
        self.assertEqual(loaded.epochs(), ["epoch-1"])

    def test_file_backend_refuses_world_readable(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            KeyRing.load(p)

    def test_file_backend_rejects_bad_format(self):
        p = self.tmp / "keyring.json"
        p.write_text(json.dumps({"format_version": 999, "keys": {},
                                 "active_epoch": "x"}))
        os.chmod(p, 0o600)
        with self.assertRaises(ValueError):
            KeyRing.load(p)

    def test_env_backend_roundtrip_with_archive(self):
        ring = KeyRing.generate("epoch-1")
        ring.rotate("epoch-2")
        ring.activate()
        # Env now carries current + archive; a fresh process-equivalent ring
        # rebuilt purely from env must hold both epochs.
        rebuilt = KeyRing.from_env()
        self.assertEqual(rebuilt.active().epoch, "epoch-2")
        self.assertEqual(rebuilt.active().key, ring.active().key)
        self.assertEqual(rebuilt.get("epoch-1").key, ring.get("epoch-1").key)
        self.assertEqual(rebuilt.get("epoch-1").status, "retired")

    def test_env_backend_missing_key_raises(self):
        with self.assertRaises(NoKeyConfiguredError):
            KeyRing.from_env()

    def test_env_backend_bad_archive_raises(self):
        os.environ["GOV_LOG_KEY"] = "somekey"
        os.environ["GOV_LOG_KEY_ARCHIVE"] = "not-json{"
        with self.assertRaises(NoKeyConfiguredError):
            KeyRing.from_env()

    def test_rotate_retains_old_key_and_labels(self):
        ring = KeyRing.generate("epoch-1")
        old_key = ring.active().key
        new_epoch = ring.rotate()
        self.assertEqual(new_epoch, "epoch-2")
        self.assertEqual(ring.active().epoch, "epoch-2")
        self.assertNotEqual(ring.active().key, old_key)
        self.assertEqual(ring.get("epoch-1").key, old_key)
        self.assertEqual(ring.get("epoch-1").status, "retired")
        # Unknown epoch lookup fails closed.
        with self.assertRaises(KeyError):
            ring.get("epoch-999")

    def test_rotate_rejects_duplicate_epoch(self):
        ring = KeyRing.generate("epoch-1")
        with self.assertRaises(ValueError):
            ring.rotate("epoch-1")

    def test_describe_never_leaks_key_material(self):
        ring = KeyRing.generate("epoch-1")
        blob = json.dumps(ring.describe())
        self.assertNotIn(ring.active().key.decode(), blob)
        self.assertIn(ring.active().key_id, blob)


class DevKeyGatingTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())

    def test_no_key_no_optin_fails_closed(self):
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key()
        with self.assertRaises(NoKeyConfiguredError):
            KeyRing.dev()

    def test_dev_opt_in_warns_loudly(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        buf = io.StringIO()
        with redirect_stderr(buf):
            ring = keys.require_key()
        out = buf.getvalue()
        self.assertIn("WARNING", out)
        self.assertIn("PUBLIC development key", out)
        self.assertEqual(ring.active().epoch, "dev")

    def test_configured_key_beats_dev_opt_in(self):
        os.environ["GOV_LOG_KEY"] = "prod-key-here"
        os.environ["GOV_DEV_KEYS"] = "1"
        ring = keys.require_key()
        self.assertEqual(ring.active().epoch, "env")
        self.assertNotEqual(ring.active().epoch, "dev")

    def test_require_production_key_unset_fails_closed(self):
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_production_key()
        # The GOV_DEV_KEYS opt-in is irrelevant on this path: dev keys
        # are structurally unreachable here.
        os.environ["GOV_DEV_KEYS"] = "1"
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_production_key()

    def test_require_production_key_rejects_configured_dev_material(self):
        os.environ["GOV_LOG_KEY"] = keys._DEV_KEY_CANONICAL.decode("utf-8")
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_production_key()

    def test_require_production_key_rejects_dev_epoch(self):
        os.environ["GOV_LOG_KEY"] = "something-not-dev-bytes"
        os.environ["GOV_LOG_KEY_EPOCH"] = "dev"
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_production_key()

    def test_require_production_key_accepts_configured_key(self):
        os.environ["GOV_LOG_KEY"] = "prod-key-here"
        os.environ["GOV_DEV_KEYS"] = "1"
        ring = keys.require_production_key()
        self.assertEqual(ring.active().epoch, "env")
        self.assertEqual(ring.active().key, b"prod-key-here")


class RotationCeremonyTest(unittest.TestCase):
    """rotate -> old logs still verify with old epoch keys; tampered log
    blocks rotation."""

    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="govkeys-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _write_entries(self, log_path, n):
        log = ActionLog(log_path)
        for i in range(n):
            log.append({"event": "tool_call", "i": i})
        return log

    def test_rotate_then_old_and_new_logs_verify(self):
        ring = KeyRing.generate("epoch-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate()

        log_path = self.tmp / "actions.jsonl"
        self._write_entries(log_path, 3)
        entries = [json.loads(l) for l in
                   log_path.read_text().splitlines() if l.strip()]
        self.assertTrue(all(e["key_epoch"] == "epoch-1" for e in entries))

        # The ceremony: verify old log, rotate, persist, activate.
        ring2, new_epoch = keys.rotate_keyring(
            kr_path, new_epoch="epoch-2", log_path=log_path)
        self.assertEqual(new_epoch, "epoch-2")
        ring2.activate()
        self._write_entries(log_path, 2)

        entries = [json.loads(l) for l in
                   log_path.read_text().splitlines() if l.strip()]
        epochs = [e["key_epoch"] for e in entries]
        self.assertEqual(epochs, ["epoch-1"] * 3 + ["epoch-2"] * 2)

        # Cross-epoch verification with the full ring: OK.
        verdict = ring2.verify_log(log_path)
        self.assertTrue(verdict["ok"], verdict["error"])
        self.assertEqual(verdict["entries"], 5)
        self.assertEqual(verdict["epochs_seen"], ["epoch-1", "epoch-2"])
        self.assertGreater(verdict["checkpoints_checked"], 0)

        # A ring that LOST the old key cannot verify history: fail closed.
        partial = KeyRing.generate("epoch-2")
        v2 = partial.verify_log(log_path)
        self.assertFalse(v2["ok"])
        self.assertIn("unknown key epoch", v2["error"])

    def test_rotation_refused_on_tampered_log(self):
        ring = KeyRing.generate("epoch-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate()
        log_path = self.tmp / "actions.jsonl"
        self._write_entries(log_path, 2)
        # Attacker flips a byte in the log body.
        lines = log_path.read_text().splitlines()
        lines[0] = lines[0].replace('"i": 0', '"i": 999')
        log_path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(RuntimeError) as cm:
            keys.rotate_keyring(kr_path, log_path=log_path)
        self.assertIn("refusing to rotate", str(cm.exception))
        # Ring on disk still has the old active epoch (no rotation happened).
        self.assertEqual(KeyRing.load(kr_path).active().epoch, "epoch-1")

    def test_tampered_entry_detected_per_epoch(self):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        log_path = self.tmp / "actions.jsonl"
        self._write_entries(log_path, 2)
        lines = log_path.read_text().splitlines()
        lines[1] = lines[1].replace('"i": 1', '"i": 31337')
        log_path.write_text("\n".join(lines) + "\n")
        verdict = ring.verify_log(log_path)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["broken_seq"], 2)
        self.assertIn("MAC mismatch", verdict["error"])

    def test_tail_truncation_detected_after_rotation(self):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        log_path = self.tmp / "actions.jsonl"
        self._write_entries(log_path, 3)
        ring.rotate("epoch-2")
        ring.activate()
        self._write_entries(log_path, 2)
        # Attacker truncates the newest (epoch-2) entries.
        lines = log_path.read_text().splitlines()[:3]
        log_path.write_text("\n".join(lines) + "\n")
        verdict = ring.verify_log(log_path)
        self.assertFalse(verdict["ok"])
        self.assertIn("tail truncation", verdict["error"])


    def test_rotation_leaves_backup_with_old_ring(self):
        ring = KeyRing.generate("epoch-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring2, new_epoch = keys.rotate_keyring(kr_path, new_epoch="epoch-2")
        self.assertEqual(new_epoch, "epoch-2")
        bak = Path(str(kr_path) + ".bak")
        self.assertTrue(bak.exists(), "rotation must leave a backup")
        old_ring = KeyRing.load(bak)
        self.assertEqual(old_ring._active_epoch, "epoch-1")
        # The backup still holds the old key: history remains verifiable.
        self.assertEqual(old_ring.get("epoch-1").key,
                         ring.get("epoch-1").key)

    def test_record_rotation_logs_identifiers_not_material(self):
        ring = KeyRing.generate("epoch-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate()
        log_path = self.tmp / "actions.jsonl"
        log = ActionLog(log_path)
        log.append({"event": "tool_call", "i": 0})
        ring2, new_epoch = keys.rotate_keyring(kr_path, new_epoch="epoch-2")
        ring2.activate()
        rec = keys.record_rotation(log, ring2, new_epoch, actor="test-op")
        self.assertEqual(rec["event"], "key_rotation")
        entries = [json.loads(l) for l in
                   log_path.read_text().splitlines() if l.strip()]
        rot = entries[-1]
        self.assertEqual(rot["event"], "key_rotation")
        self.assertEqual(rot["new_epoch"], "epoch-2")
        self.assertEqual(rot["new_key_id"], ring2.get("epoch-2").key_id)
        self.assertEqual(rot["actor"], "test-op")
        # No key material anywhere in the log: identifiers only.
        blob = log_path.read_text()
        self.assertNotIn(ring2.get("epoch-2").key.decode("ascii"), blob)
        self.assertNotIn(ring.get("epoch-1").key.decode("ascii"), blob)
        # The rotation record itself verifies under the new epoch.
        verdict = ring2.verify_log(log_path)
        self.assertTrue(verdict["ok"], verdict["error"])


class AtomicPersistenceTest(unittest.TestCase):
    """save() must be atomic: same-dir temp + fsync + os.replace.

    A crash mid-write must leave the old keyring or the new keyring —
    never a truncated file. Adversarial angles: missing directory,
    symlink at the target, write failure cleanup, concurrent saves.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="govkeys-atomic-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _no_tmps(self):
        return [p for p in self.tmp.iterdir() if ".tmp-" in p.name]

    def test_save_roundtrip_mode_and_no_temp_left(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        self.assertEqual(self._no_tmps(), [])
        self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
        loaded = KeyRing.load(p)
        self.assertEqual(loaded.active().epoch, "epoch-1")
        self.assertEqual(loaded.active().key_id,
                         ring.active().key_id)

    def test_save_refuses_missing_directory(self):
        ring = KeyRing.generate("epoch-1")
        with self.assertRaises(FileNotFoundError):
            ring.save(self.tmp / "no-such-dir" / "keyring.json")

    def test_save_replaces_symlink_without_following(self):
        # Attacker plants a symlink at the target pointing at a victim
        # file: os.replace() must swap the LINK, not write through it.
        victim = self.tmp / "victim.txt"
        victim.write_text("untouched")
        link = self.tmp / "keyring.json"
        link.symlink_to(victim)
        ring = KeyRing.generate("epoch-1")
        ring.save(link)
        self.assertEqual(victim.read_text(), "untouched")
        self.assertFalse(link.is_symlink())
        self.assertEqual(KeyRing.load(link).active().epoch, "epoch-1")

    def test_save_cleans_temp_on_write_failure(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        before = p.read_bytes()
        real_fsync = os.fsync
        def _boom(*a, **k):
            raise OSError(5, "forced fsync failure")
        os.fsync = _boom
        try:
            with self.assertRaises(OSError):
                KeyRing.generate("epoch-2").save(p)
        finally:
            os.fsync = real_fsync
        # Original intact, no temp debris left behind.
        self.assertEqual(p.read_bytes(), before)
        self.assertEqual(self._no_tmps(), [])
        self.assertEqual(KeyRing.load(p).active().epoch, "epoch-1")

    def test_concurrent_saves_never_corrupt(self):
        import threading
        p = self.tmp / "keyring.json"
        KeyRing.generate("epoch-1").save(p)
        errors = []
        def _saver(i):
            try:
                for _ in range(10):
                    KeyRing.generate("epoch-%d" % (100 + i)).save(p)
            except Exception as e:  # noqa: BLE001 - collected, asserted
                errors.append(e)
        threads = [threading.Thread(target=_saver, args=(i,))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        # Whatever won, the file is complete valid JSON that loads.
        loaded = KeyRing.load(p)
        self.assertTrue(loaded.active().epoch.startswith("epoch-"))
        self.assertEqual(self._no_tmps(), [])

    def test_rotation_backup_is_atomic_too(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        ring2, _ = keys.rotate_keyring(p, new_epoch="epoch-2")
        bak = Path(str(p) + ".bak")
        self.assertEqual(oct(bak.stat().st_mode & 0o777), "0o600")
        old = KeyRing.load(bak)
        self.assertEqual(old.active().epoch, "epoch-1")
        self.assertEqual(ring2.active().epoch, "epoch-2")
        self.assertEqual(self._no_tmps(), [])


class ConcurrentRotationTest(unittest.TestCase):
    """Concurrent rotate_keyring calls must serialize: no torn file, no
    silently dropped epochs."""

    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="govkeys-concrot-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_concurrent_rotations_all_epochs_survive(self):
        from concurrent.futures import ThreadPoolExecutor
        p = self.tmp / "keyring.json"
        KeyRing.generate("epoch-0").save(p)
        epochs = ["epoch-%d" % i for i in range(1, 9)]

        def one(ep):
            return keys.rotate_keyring(p, new_epoch=ep)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, epochs))

        # Every ceremony returned its own epoch...
        self.assertEqual(sorted(r[1] for r in results), sorted(epochs))
        # ...and the final keyring contains ALL of them: no lost updates,
        # exactly one active key, file still valid.
        final = KeyRing.load(p)
        self.assertEqual(set(final._keys), set(["epoch-0"] + epochs))
        actives = [m for m in final._keys.values()
                   if m.status == "active"]
        self.assertEqual(len(actives), 1)
        # Backup chain intact too.
        self.assertTrue(Path(str(p) + ".bak").exists())


if __name__ == "__main__":
    unittest.main()
