"""Wave-69 tests: prod KMS key management — kill the dev-key fallback.

Covers the new ``gov/keyprovider.py`` chokepoint (KeyProvider ABC +
Dev/Env/File/EnvelopeKms providers), the wave-61-style deployment_mode
rule (explicit declaration, default least-privilege, production+dev
contradiction refuses loud), the ``keys.require_key()`` double-opt-in
tightening, and the break-first properties: fallback resurrection,
key confusion (era mismatch), mixed-key chains (rotation + splice),
lost-key behavior, and era-marking honesty in the evidence export.

Deterministic, $0, synthetic/local only. Env hygiene: every test saves
and restores all touched env vars plus the ``gov.log._dev_enabled``
module flag.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import keyprovider as kp
from gov import keys
from gov import log as log_mod
from gov.keys import KeyRing, NoKeyConfiguredError
from gov.log import ActionLog, _DEV_KEY

_ENV_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
              "GOV_DEV_KEYS", "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


def _clean_env():
    saved = {n: os.environ.get(n) for n in _ENV_NAMES}
    had = {n: n in os.environ for n in _ENV_NAMES}
    prev_enabled = log_mod._dev_enabled
    prev_warned = log_mod._dev_warned
    for n in _ENV_NAMES:
        os.environ.pop(n, None)

    def restore():
        for n in _ENV_NAMES:
            if had[n]:
                os.environ[n] = saved[n]
            else:
                os.environ.pop(n, None)
        log_mod._dev_enabled = prev_enabled
        log_mod._dev_warned = prev_warned

    return restore


class DeploymentModeTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())

    def test_default_is_production(self):
        # Least-privilege default: ambiguity defaults to production.
        self.assertEqual(kp.resolve_deployment_mode(), "production")
        self.assertEqual(kp.resolve_deployment_mode(""), "production")

    def test_env_declaration(self):
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        self.assertEqual(kp.resolve_deployment_mode(), "staging")
        os.environ["GOV_DEPLOYMENT_MODE"] = "dev"
        self.assertEqual(kp.resolve_deployment_mode(), "dev")
        os.environ["GOV_DEPLOYMENT_MODE"] = "test"
        self.assertEqual(kp.resolve_deployment_mode(), "test")

    def test_kwarg_wins_over_env(self):
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        self.assertEqual(kp.resolve_deployment_mode("production"),
                         "production")

    def test_unknown_mode_fails_fast(self):
        with self.assertRaises(ValueError):
            kp.resolve_deployment_mode("prod")
        os.environ["GOV_DEPLOYMENT_MODE"] = "live"
        with self.assertRaises(ValueError):
            kp.resolve_deployment_mode()


class DevKeyProviderTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        log_mod._dev_warned = False  # full-suite order independence

    def _opt_in(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()

    def test_staging_double_opt_in_resolves_dev_loud(self):
        self._opt_in()
        buf = io.StringIO()
        with redirect_stderr(buf):
            key, epoch = kp.DevKeyProvider(
                deployment_mode="staging").resolve()
        self.assertEqual(key, _DEV_KEY)
        self.assertEqual(epoch, "dev")
        self.assertIn("PUBLIC development key", buf.getvalue())

    def test_production_refuses_even_with_double_opt_in(self):
        # The wave-69 contradiction: explicit dev opt-in in production.
        self._opt_in()
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            kp.DevKeyProvider(deployment_mode="production").resolve()
        self.assertIn("production", str(ctx.exception))

    def test_env_alone_never_sufficient(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod._dev_enabled = False
        with self.assertRaises(NoKeyConfiguredError):
            kp.DevKeyProvider(deployment_mode="staging").resolve()

    def test_in_code_alone_never_sufficient(self):
        log_mod.enable_dev_keys()
        with self.assertRaises(NoKeyConfiguredError):
            kp.DevKeyProvider(deployment_mode="staging").resolve()

    def test_describe_marks_dev(self):
        d = kp.DevKeyProvider().describe()
        self.assertEqual(d["provider"], "dev")
        self.assertIn("zero integrity", d["warning"])


class EnvKeyProviderTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())

    def test_configured_key_resolves(self):
        os.environ["GOV_LOG_KEY"] = "operator-secret"
        key, epoch = kp.EnvKeyProvider().resolve()
        self.assertEqual(key, b"operator-secret")
        self.assertEqual(epoch, "env")

    def test_custom_epoch(self):
        os.environ["GOV_LOG_KEY"] = "operator-secret"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-7"
        key, epoch = kp.EnvKeyProvider().resolve()
        self.assertEqual(epoch, "epoch-7")

    def test_dev_bytes_rejected(self):
        os.environ["GOV_LOG_KEY"] = _DEV_KEY.decode("utf-8")
        with self.assertRaises(NoKeyConfiguredError):
            kp.EnvKeyProvider().resolve()

    def test_dev_epoch_rejected(self):
        os.environ["GOV_LOG_KEY"] = "real-key-material"
        os.environ["GOV_LOG_KEY_EPOCH"] = "dev"
        with self.assertRaises(NoKeyConfiguredError):
            kp.EnvKeyProvider().resolve()

    def test_unset_raises(self):
        with self.assertRaises(NoKeyConfiguredError):
            kp.EnvKeyProvider().resolve()


class FileKeyProviderTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69key-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _save_ring(self, ring, name="keyring.json"):
        p = self.tmp / name
        ring.save(str(p))
        return str(p)

    def test_file_provider_resolves(self):
        ring = KeyRing.generate("epoch-1")
        path = self._save_ring(ring)
        key, epoch = kp.FileKeyProvider(path).resolve()
        self.assertEqual(key, ring.active().key)
        self.assertEqual(epoch, "epoch-1")

    def test_group_readable_refused(self):
        ring = KeyRing.generate("epoch-1")
        path = self._save_ring(ring)
        os.chmod(path, 0o640)
        with self.assertRaises(PermissionError):
            kp.FileKeyProvider(path).resolve()

    def test_dev_seeded_keyring_refused(self):
        ring = KeyRing.generate("epoch-1")
        # Attacker/operator seeds the keyring file with the public dev key.
        dev_mat = keys.KeyMaterial("epoch-1", _DEV_KEY, status="active")
        ring._keys["epoch-1"] = dev_mat
        path = self._save_ring(ring)
        with self.assertRaises(NoKeyConfiguredError):
            kp.FileKeyProvider(path).resolve()

    def test_missing_file_fails_closed(self):
        with self.assertRaises((FileNotFoundError, OSError)):
            kp.FileKeyProvider(str(self.tmp / "nope.json")).resolve()

    def test_corrupt_file_fails_closed(self):
        p = self.tmp / "corrupt.json"
        p.write_text("{not json", encoding="utf-8")
        os.chmod(str(p), 0o600)
        with self.assertRaises(ValueError):
            kp.FileKeyProvider(str(p)).resolve()


class ResolveActiveKeyTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        log_mod._dev_warned = False  # full-suite order independence
        self.tmp = Path(tempfile.mkdtemp(prefix="w69key-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _opt_in(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()

    def test_env_provider_wins_over_file(self):
        ring = KeyRing.generate("epoch-9")
        p = self.tmp / "k.json"
        ring.save(str(p))
        os.environ["GOV_KEYRING_FILE"] = str(p)
        os.environ["GOV_LOG_KEY"] = "env-key-wins"
        key, epoch = kp.resolve_active_key(deployment_mode="production")
        self.assertEqual(key, b"env-key-wins")

    def test_keyring_file_path(self):
        ring = KeyRing.generate("epoch-3")
        p = self.tmp / "k.json"
        ring.save(str(p))
        os.environ["GOV_KEYRING_FILE"] = str(p)
        key, epoch = kp.resolve_active_key(deployment_mode="production")
        self.assertEqual(key, ring.active().key)
        self.assertEqual(epoch, "epoch-3")

    def test_production_contradiction_refuses_loud(self):
        self._opt_in()
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            kp.resolve_active_key(deployment_mode="production")
        msg = str(ctx.exception)
        self.assertIn("production", msg)
        self.assertIn("contradicts", msg)

    def test_production_default_contradiction(self):
        # Unset mode defaults to production: the contradiction fires.
        self._opt_in()
        with self.assertRaises(NoKeyConfiguredError):
            kp.resolve_active_key()

    def test_production_no_key_f73(self):
        log_mod._dev_enabled = False
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            kp.resolve_active_key(deployment_mode="production")
        self.assertIn("F73", str(ctx.exception))

    def test_staging_dev_path_loud(self):
        self._opt_in()
        buf = io.StringIO()
        with redirect_stderr(buf):
            key, epoch = kp.resolve_active_key(deployment_mode="staging")
        self.assertEqual((key, epoch), (_DEV_KEY, "dev"))
        self.assertIn("PUBLIC development key", buf.getvalue())

    def test_nonproduction_no_optin_fails_closed(self):
        log_mod._dev_enabled = False
        with self.assertRaises(NoKeyConfiguredError):
            kp.resolve_active_key(deployment_mode="staging")

    def test_log_active_key_delegates(self):
        # gov/log.py::_active_key goes through the chokepoint: staging +
        # double opt-in resolves the dev key exactly as before.
        self._opt_in()
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        buf = io.StringIO()
        with redirect_stderr(buf):
            key, epoch = log_mod._active_key()
        self.assertEqual((key, epoch), (_DEV_KEY, "dev"))

    def test_log_active_key_contradiction(self):
        self._opt_in()
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        with self.assertRaises(NoKeyConfiguredError):
            log_mod._active_key()


class RequireKeyTighteningTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        log_mod._dev_warned = False  # full-suite order independence

    def test_env_only_no_longer_falls_back(self):
        # Wave-69: require_key() needs the in-code opt-in too now.
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod._dev_enabled = False
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key()

    def test_double_opt_in_still_falls_back_loud(self):
        # Non-production (staging) declared: the legacy dev path still
        # works loudly. (Default mode is production, where this same
        # double opt-in now refuses as a contradiction — see above.)
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        buf = io.StringIO()
        with redirect_stderr(buf):
            ring = keys.require_key()
        self.assertEqual(ring.active().epoch, "dev")
        self.assertIn("PUBLIC development key", buf.getvalue())

    def test_production_contradiction_in_require_key(self):
        # Wave-69 same-wave gap: require_key() must refuse the
        # production + double-opt-in contradiction, not hand back the dev
        # ring behind the mode guard.
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        with self.assertRaisesRegex(NoKeyConfiguredError, "contradict"):
            keys.require_key()

    def test_default_mode_contradiction_in_require_key(self):
        # Unset mode defaults to production, so the same refusal applies.
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        with self.assertRaisesRegex(NoKeyConfiguredError, "contradict"):
            keys.require_key()

    def test_configured_key_beats_everything(self):
        os.environ["GOV_LOG_KEY"] = "prod-key-here"
        ring = keys.require_key()
        self.assertEqual(ring.active().epoch, "env")


class KeyConfusionTest(unittest.TestCase):
    """Dev-signed records must never verify under a prod key and vice
    versa — era mismatch fails closed with a clear signal."""

    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69conf-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _opt_in(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()

    def _write_entries(self, n):
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        for i in range(n):
            log.append({"event": "probe", "i": i})
        return str(self.tmp / "actions.jsonl")

    def test_dev_log_rejected_by_prod_verifier(self):
        self._opt_in()
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        path = self._write_entries(3)
        # Now verify as production with a real key: era/label mismatch.
        os.environ["GOV_LOG_KEY"] = "production-key-material"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        v = log_mod._verify(path)
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])

    def test_prod_log_rejected_by_dev_verifier(self):
        os.environ["GOV_LOG_KEY"] = "production-key-material"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-1"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        path = self._write_entries(3)
        # Now verify under dev keys: the prod labels mismatch the dev epoch.
        os.environ.pop("GOV_LOG_KEY", None)
        os.environ.pop("GOV_LOG_KEY_EPOCH", None)
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        self._opt_in()
        v = log_mod._verify(path)
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])

    def test_forged_prod_labels_under_dev_key_fail(self):
        # F32 shape through the chokepoint: entries HMAC'd under the dev
        # key but labeled "production" do not verify under either key.
        self._opt_in()
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        path = self._write_entries(2)
        entries = [json.loads(l) for l in
                   Path(path).read_text(encoding="utf-8").splitlines()
                   if l.strip()]
        for e in entries:
            e["key_epoch"] = "production"
            # Re-MAC under the dev key with the forged label (attacker
            # with the public dev key can do this).
            e["hash"] = log_mod._compute_mac(
                _DEV_KEY, "production", e["prev_hash"],
                log_mod._canonical(e))
        forged = self.tmp / "forged.jsonl"
        forged.write_text("\n".join(
            json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
            encoding="utf-8")
        # Under dev keys: label != configured epoch -> fail.
        v = log_mod._verify(str(forged))
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])
        # Under a prod key: MACs don't match either.
        os.environ["GOV_LOG_KEY"] = "production-key-material"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        v = log_mod._verify(str(forged))
        self.assertFalse(v["ok"])


class RotationAndSpliceTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69rot-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_rotation_mid_chain_verifies_per_epoch(self):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log_path = str(self.tmp / "actions.jsonl")
        log = ActionLog(log_path)
        log.append({"event": "before-rotation", "i": 1})
        log.append({"event": "before-rotation", "i": 2})
        ring.rotate("epoch-2")
        ring.activate()
        log.append({"event": "after-rotation", "i": 3})
        log.append({"event": "after-rotation", "i": 4})
        # Single-key verifier fails closed on mixed epochs BY DESIGN (F32).
        v = log_mod._verify(log_path)
        self.assertFalse(v["ok"])
        # The ring verifier selects the key per epoch.
        verdict = ring.verify_log(log_path)
        self.assertTrue(verdict["ok"], verdict.get("error"))
        self.assertEqual(verdict["epochs_seen"], ["epoch-1", "epoch-2"])

    def test_spliced_segment_fails_verification(self):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log_path = str(self.tmp / "actions.jsonl")
        log = ActionLog(log_path)
        for i in range(4):
            log.append({"event": "e", "i": i})
        ring.rotate("epoch-2")
        ring.activate()
        for i in range(4, 6):
            log.append({"event": "e", "i": i})
        lines = [l for l in Path(log_path).read_text(
            encoding="utf-8").splitlines() if l.strip()]
        # Splice: transplant the seq-1 (epoch-1) line into position 3,
        # keeping the file's line count (a crude cut-and-paste forgery).
        victim = json.loads(lines[2])
        donor = json.loads(lines[0])
        donor["seq"] = victim["seq"]
        lines[2] = json.dumps(donor, ensure_ascii=True)
        Path(log_path).write_text("\n".join(lines) + "\n",
                                  encoding="utf-8")
        verdict = ring.verify_log(log_path)
        self.assertFalse(verdict["ok"])

    def test_swapped_entries_fail_verification(self):
        ring = KeyRing.generate("epoch-1")
        ring.activate()
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log_path = str(self.tmp / "actions.jsonl")
        log = ActionLog(log_path)
        for i in range(3):
            log.append({"event": "e", "i": i})
        lines = [l for l in Path(log_path).read_text(
            encoding="utf-8").splitlines() if l.strip()]
        lines[1], lines[2] = lines[2], lines[1]
        Path(log_path).write_text("\n".join(lines) + "\n",
                                  encoding="utf-8")
        verdict = ring.verify_log(log_path)
        self.assertFalse(verdict["ok"])


class LostKeyTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69lost-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_keyring_file_deleted_fails_closed(self):
        ring = KeyRing.generate("epoch-1")
        p = self.tmp / "k.json"
        ring.save(str(p))
        os.environ["GOV_KEYRING_FILE"] = str(p)
        key, _ = kp.resolve_active_key(deployment_mode="production")
        self.assertEqual(key, ring.active().key)
        p.unlink()
        with self.assertRaises((FileNotFoundError, OSError)):
            kp.resolve_active_key(deployment_mode="production")

    def test_env_key_unset_mid_run_fails_closed(self):
        os.environ["GOV_LOG_KEY"] = "mid-run-key"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "before"})
        # The key vanishes mid-run: the next append fails closed — no
        # silent unsigned continuation.
        del os.environ["GOV_LOG_KEY"]
        os.environ.pop("GOV_DEV_KEYS", None)
        log_mod._dev_enabled = False
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"event": "after"})

    def test_env_key_unset_mid_run_with_dev_optin_contradicts(self):
        # Even WITH the dev opt-in present, losing the configured key in
        # production does not silently downgrade to dev: contradiction.
        os.environ["GOV_LOG_KEY"] = "mid-run-key"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "before"})
        del os.environ["GOV_LOG_KEY"]
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            log.append({"event": "after"})
        self.assertIn("contradicts", str(ctx.exception))


class EraMarkingHonestyTest(unittest.TestCase):
    """A dev-key record must never render as prod-grade in the evidence
    export (demo/make_report.py key_status)."""

    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69era-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _load_make_report(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "w69_make_report",
            str(Path(_TESTS_DIR).parent / "demo" / "make_report.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_dev_era_renders_dev_banner(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "probe"})
        entries = [json.loads(l) for l in
                   (self.tmp / "actions.jsonl").read_text(
                       encoding="utf-8").splitlines() if l.strip()]
        verdict = log_mod._verify(str(self.tmp / "actions.jsonl"))
        self.assertTrue(verdict["ok"])
        mr = self._load_make_report()
        ks = mr.key_status(entries, verdict["key_epoch"])
        self.assertEqual(ks["status"], "dev")
        self.assertIn("PUBLIC/DEVELOPMENT", ks["banner_line"])
        self.assertIn("NOT tamper-evident", ks["integrity_note"])

    def test_forged_prod_labels_render_failed_never_prod(self):
        os.environ["GOV_DEV_KEYS"] = "1"
        log_mod.enable_dev_keys()
        os.environ["GOV_DEPLOYMENT_MODE"] = "staging"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "probe"})
        entries = [json.loads(l) for l in
                   (self.tmp / "actions.jsonl").read_text(
                       encoding="utf-8").splitlines() if l.strip()]
        for e in entries:
            e["key_epoch"] = "production"
            e["hash"] = log_mod._compute_mac(
                _DEV_KEY, "production", e["prev_hash"],
                log_mod._canonical(e))
        forged = self.tmp / "forged.jsonl"
        forged.write_text("\n".join(
            json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
            encoding="utf-8")
        verdict = log_mod._verify(str(forged))
        self.assertFalse(verdict["ok"])
        mr = self._load_make_report()
        # The report binds to the VERIFIED epoch (the configured dev
        # epoch here), never to the forged labels.
        ks = mr.key_status(entries, verdict["key_epoch"])
        self.assertEqual(ks["status"], "dev")
        self.assertTrue(ks["label_mismatch"])
        self.assertNotIn("Operator-configured key", ks["banner_line"])


class EnvelopeProviderTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69env-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_envelope_provider_resolves(self):
        from gov import kms as kms_mod
        os.environ["GOV_DEV_KEYS"] = "1"  # test-only provider wiring
        provider = kms_mod.FakeKmsProvider(["test-master-key"])
        ring = kms_mod.EnvelopeKeyRing.generate(
            provider, "test-master-key", epoch="epoch-1")
        p = self.tmp / "envelope.json"
        ring.save(str(p))
        key, epoch = kp.EnvelopeKmsProvider(str(p), provider).resolve()
        self.assertEqual(epoch, "epoch-1")
        self.assertEqual(len(key), 64)
        # The resolved key matches what activation would publish.
        mat = ring.materialize(provider).active()
        self.assertEqual(key, mat.key)

    def test_envelope_outage_fails_closed(self):
        from gov import kms as kms_mod
        provider = kms_mod.FakeKmsProvider(["test-master-key"])
        ring = kms_mod.EnvelopeKeyRing.generate(
            provider, "test-master-key", epoch="epoch-1")
        p = self.tmp / "envelope.json"
        ring.save(str(p))
        provider.outage = True
        with self.assertRaises(kms_mod.KmsError):
            kp.EnvelopeKmsProvider(str(p), provider).resolve()

    def test_envelope_group_readable_refused(self):
        from gov import kms as kms_mod
        provider = kms_mod.FakeKmsProvider(["test-master-key"])
        ring = kms_mod.EnvelopeKeyRing.generate(
            provider, "test-master-key", epoch="epoch-1")
        p = self.tmp / "envelope.json"
        ring.save(str(p))
        os.chmod(str(p), 0o640)
        with self.assertRaises(PermissionError):
            kp.EnvelopeKmsProvider(str(p), provider).resolve()


if __name__ == "__main__":
    unittest.main()
