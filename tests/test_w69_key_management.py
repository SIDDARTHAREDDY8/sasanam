"""Wave-81 tests: explicit key provisioning -- the dev-key fallback is dead.

Covers the ``gov/keyprovider.py`` chokepoint (KeyProvider ABC +
Env/File/EnvelopeKms providers -- the Dev provider is deleted),
the wave-61-style deployment_mode rule (explicit declaration, default
least-privilege, unknown modes fail fast), ``keys.require_key()``
failing closed with no key in EVERY mode, and the break-first
properties: old dev names absent, key confusion (era mismatch),
mixed-key chains (rotation + splice), lost-key behavior, and
era-marking honesty in the evidence export.

Wave-69 originally built this file around the dev-key double opt-in;
wave-81 deleted the dev key, every opt-in, and every fallback from
``gov/``, so every dev-path test is replaced by a refusal/absence test.

Deterministic, $0, synthetic/local only. Env hygiene: every test saves
and restores all touched env vars.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import keyprovider as kp
from gov import keys
from gov import log as log_mod
from gov.keys import KeyRing, NoKeyConfiguredError
from gov.log import ActionLog

_ENV_NAMES = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
              "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


def _clean_env():
    saved = {n: os.environ.get(n) for n in _ENV_NAMES}
    had = {n: n in os.environ for n in _ENV_NAMES}
    for n in _ENV_NAMES:
        os.environ.pop(n, None)

    def restore():
        for n in _ENV_NAMES:
            if had[n]:
                os.environ[n] = saved[n]
            else:
                os.environ.pop(n, None)

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


class ProviderAbsenceTest(unittest.TestCase):
    """Wave-81 break-first: the dev provider and the production/dev
    contradiction are deleted from gov/keyprovider.py -- every mode
    requires explicit provisioning."""

    def setUp(self):
        self.addCleanup(_clean_env())

    def test_dev_provider_absent(self):
        self.assertFalse(hasattr(kp, "DevKeyProvider"))
        with self.assertRaises(AttributeError):
            kp.DevKeyProvider  # noqa: B018

    def test_contradiction_helper_absent(self):
        # production_contradiction() existed to refuse the
        # production+dev-opt-in combination; with the dev key deleted the
        # contradiction is unstatable.
        self.assertFalse(hasattr(kp, "production_contradiction"))

    def test_old_dev_names_absent_from_log(self):
        for name in ("enable_dev_keys", "dev_keys_enabled"):
            self.assertFalse(hasattr(log_mod, name), name)

    def test_explicit_providers_still_present(self):
        for name in ("KeyProvider", "EnvKeyProvider", "FileKeyProvider",
                     "EnvelopeKmsProvider", "resolve_active_key",
                     "resolve_deployment_mode"):
            self.assertTrue(hasattr(kp, name), name)

    def test_no_key_refuses_in_every_mode(self):
        for mode in ("production", "staging", "dev", "test"):
            with self.assertRaises(NoKeyConfiguredError, msg=mode):
                kp.resolve_active_key(deployment_mode=mode)


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
        self.tmp = Path(tempfile.mkdtemp(prefix="w69key-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

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

    def test_no_key_refuses_in_every_mode(self):
        # Wave-81: no fallback exists, so the chokepoint refuses loudly
        # in production, staging, dev, and test alike.
        for mode in ("production", "staging", "dev", "test"):
            with self.assertRaises(NoKeyConfiguredError, msg=mode):
                kp.resolve_active_key(deployment_mode=mode)

    def test_no_key_refusal_names_the_fix(self):
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            kp.resolve_active_key(deployment_mode="production")
        self.assertIn("GOV_LOG_KEY", str(ctx.exception))

    def test_unknown_mode_fails_fast(self):
        os.environ["GOV_LOG_KEY"] = "some-key"
        with self.assertRaises(ValueError):
            kp.resolve_active_key(deployment_mode="prod")

    def test_log_active_key_delegates(self):
        # gov/log.py::_active_key goes through the chokepoint: an
        # explicitly configured key resolves identically.
        os.environ["GOV_LOG_KEY"] = "delegated-key"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-5"
        key, epoch = log_mod._active_key()
        self.assertEqual(key, b"delegated-key")
        self.assertEqual(epoch, "epoch-5")

    def test_log_active_key_no_key_refuses(self):
        with self.assertRaises(NoKeyConfiguredError):
            log_mod._active_key()


class RequireKeyTighteningTest(unittest.TestCase):
    """Wave-81: require_key() fails closed with no key in every mode --
    there is no fallback left to tighten."""

    def setUp(self):
        self.addCleanup(_clean_env())

    def test_no_key_refuses(self):
        with self.assertRaises(NoKeyConfiguredError):
            keys.require_key()

    def test_no_key_refuses_in_every_mode(self):
        for mode in ("production", "staging", "dev", "test"):
            os.environ["GOV_DEPLOYMENT_MODE"] = mode
            with self.assertRaises(NoKeyConfiguredError, msg=mode):
                keys.require_key()

    def test_configured_key_beats_everything(self):
        os.environ["GOV_LOG_KEY"] = "prod-key-here"
        ring = keys.require_key()
        self.assertEqual(ring.active().epoch, "env")


class CrossKeyConfusionTest(unittest.TestCase):
    """Wave-81: with no dev key, era confusion is between explicitly
    configured keys -- records MAC'd under one key never verify under
    another, and forged epoch labels fail closed under both."""

    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69conf-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def _configure(self, key, epoch):
        os.environ["GOV_LOG_KEY"] = key
        os.environ["GOV_LOG_KEY_EPOCH"] = epoch

    def _write_entries(self, n):
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        for i in range(n):
            log.append({"event": "probe", "i": i})
        return str(self.tmp / "actions.jsonl")

    def test_other_key_rejects_log(self):
        self._configure("key-one-material", "epoch-1")
        path = self._write_entries(3)
        # Verify under a different explicit key/epoch: label mismatch.
        self._configure("key-two-material", "epoch-2")
        v = log_mod._verify(path)
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])

    def test_same_key_wrong_epoch_label_rejected(self):
        # Same key material, wrong epoch label configured: the F32 bind
        # still fails closed (label forgery or misconfigured epoch).
        self._configure("key-one-material", "epoch-1")
        path = self._write_entries(3)
        self._configure("key-one-material", "epoch-9")
        v = log_mod._verify(path)
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])

    def test_forged_labels_fail_under_both_keys(self):
        # F32 shape through the chokepoint: entries HMAC'd under key-one
        # but labeled "epoch-2" do not verify under either key.
        self._configure("key-one-material", "epoch-1")
        path = self._write_entries(2)
        entries = [json.loads(l) for l in
                   Path(path).read_text(encoding="utf-8").splitlines()
                   if l.strip()]
        key_one = b"key-one-material"
        for e in entries:
            e["key_epoch"] = "epoch-2"
            # Re-MAC under key-one with the forged label (an attacker
            # holding key-one can do this).
            e["hash"] = log_mod._compute_mac(
                key_one, "epoch-2", e["prev_hash"],
                log_mod._canonical(e))
        forged = self.tmp / "forged.jsonl"
        forged.write_text("\n".join(
            json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
            encoding="utf-8")
        # Under key-one/epoch-1: label != configured epoch -> fail.
        v = log_mod._verify(str(forged))
        self.assertFalse(v["ok"])
        self.assertIn("key_epoch", v["error"])
        # Under key-two/epoch-2: labels match the configured epoch but
        # the MACs were made under key-one -> fail.
        self._configure("key-two-material", "epoch-2")
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
        with self.assertRaises(NoKeyConfiguredError):
            log.append({"event": "after"})

    def test_mid_run_key_loss_message_names_the_fix(self):
        # Wave-81: the refusal is loud about what to configure; there is
        # no fallback it could silently downgrade to.
        os.environ["GOV_LOG_KEY"] = "mid-run-key"
        os.environ["GOV_DEPLOYMENT_MODE"] = "production"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "before"})
        del os.environ["GOV_LOG_KEY"]
        with self.assertRaises(NoKeyConfiguredError) as ctx:
            log.append({"event": "after"})
        self.assertIn("GOV_LOG_KEY", str(ctx.exception))


class EraMarkingHonestyTest(unittest.TestCase):
    """Wave-81: there is no dev key anymore, so era-marking honesty is
    about LABELS -- a non-production epoch label must never render as a
    production custody claim, and forged labels must render as forgery
    evidence."""

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

    def _entries(self):
        return [json.loads(l) for l in
                (self.tmp / "actions.jsonl").read_text(
                    encoding="utf-8").splitlines() if l.strip()]

    def test_nonprod_epoch_label_renders_cautious_banner(self):
        # An operator-chosen non-production epoch label ("dev") verifies
        # clean under the explicitly configured key, but the report must
        # not render it as a production custody claim.
        os.environ["GOV_LOG_KEY"] = "operator-key"
        os.environ["GOV_LOG_KEY_EPOCH"] = "dev"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "probe"})
        entries = self._entries()
        verdict = log_mod._verify(str(self.tmp / "actions.jsonl"))
        self.assertTrue(verdict["ok"])
        mr = self._load_make_report()
        ks = mr.key_status(entries, verdict["key_epoch"])
        self.assertEqual(ks["status"], "dev")
        self.assertIn("Non-production epoch label", ks["banner_line"])
        self.assertNotIn("published in the source tree",
                         ks["integrity_note"])
        self.assertNotIn("PUBLIC/DEVELOPMENT", ks["banner_line"])

    def test_forged_labels_render_mismatch_never_clean(self):
        # Forged epoch labels fail verification; the report binds to the
        # VERIFIED (configured) epoch and flags the labels as forgery
        # evidence -- never a clean production banner.
        os.environ["GOV_LOG_KEY"] = "operator-key"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-1"
        log = ActionLog(str(self.tmp / "actions.jsonl"))
        log.append({"event": "probe"})
        entries = self._entries()
        key = b"operator-key"
        for e in entries:
            e["key_epoch"] = "production"
            e["hash"] = log_mod._compute_mac(
                key, "production", e["prev_hash"],
                log_mod._canonical(e))
        forged = self.tmp / "forged.jsonl"
        forged.write_text("\n".join(
            json.dumps(e, ensure_ascii=True) for e in entries) + "\n",
            encoding="utf-8")
        verdict = log_mod._verify(str(forged))
        self.assertFalse(verdict["ok"])
        mr = self._load_make_report()
        # The report binds to the VERIFIED epoch (the configured
        # "epoch-1" here), never to the forged labels.
        ks = mr.key_status(entries, verdict["key_epoch"])
        self.assertEqual(ks["verified_epoch"], "epoch-1")
        self.assertTrue(ks["label_mismatch"])
        self.assertIn("LABEL MISMATCH", ks["banner_line"])
        self.assertNotIn("Operator-configured key (verified epoch `production`",
                         ks["banner_line"])


class EnvelopeProviderTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())
        self.tmp = Path(tempfile.mkdtemp(prefix="w69env-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))

    def test_envelope_provider_resolves(self):
        from gov import kms as kms_mod
        # FakeKmsProvider is constructed directly in code (test-only).
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
