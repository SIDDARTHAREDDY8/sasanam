"""Tests for gov/kms.py: KMS envelope encryption for log data keys.

Promoted from workstreams/kms/prototype/test_kms_prototype.py (40 tests,
green) after QA green + Architect review of workstreams/kms/DESIGN.md.

Covers: FakeKmsProvider protocol behavior (determinism, key-id binding,
tamper-evidence, outage/disabled fail-closed), EnvelopeKeyRing
(generate/rotate/rewrap/materialize/activate/verify, wrapped-only
persistence, lazy retired-epoch unwrap), production key resolution
(no dev-key fallback: wave-81 deleted it), the provider factory, and the RED-TEAM
regression tests:

* Attack 1 (workstreams/kms/redteam/attack_env_dev_fallback.py):
  env-scrub must fail closed on the production path (F73).
* Attack 2 (workstreams/kms/redteam/attack_kms_impersonator.py):
  KMS key-id swap must be rejected at unwrap.

Deterministic: stdlib unittest only, no network, FakeKmsProvider only.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from gov import kms
from gov.kms import KmsError, FakeKmsProvider, EnvelopeKeyRing
from gov.keys import (KeyRing, NoKeyConfiguredError, require_production_key)
from gov.log import ActionLog
import gov.log as gov_log


def _clean_env():
    """Scrub key env vars; returns a restore closure.

    The harness (tests/__init__) provisions an explicit key
    process-wide; these tests need a pristine resolver per case, so the
    env is snapshotted and restored to stay order-independent within the
    suite. (Wave-81: there are no process-level dev flags anymore.)
    """
    names = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")
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


class _TmpMixin(unittest.TestCase):
    def setUp(self):
        self.addCleanup(_clean_env())  # scrubs now; restores on teardown
        self.tmp = Path(tempfile.mkdtemp(prefix="kms-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.provider = FakeKmsProvider(["prod-key-1", "prod-key-2"])


# ---------------------------------------------------------------------------
# FakeKmsProvider protocol behavior
# ---------------------------------------------------------------------------

class FakeKmsProviderTest(_TmpMixin):
    def test_wrap_unwrap_roundtrip(self):
        pt = b"\xab" * 32
        blob = self.provider.wrap_data_key("prod-key-1", pt)
        self.assertEqual(self.provider.unwrap_data_key("prod-key-1", blob),
                         pt)

    def test_wrap_deterministic_for_same_inputs(self):
        a = FakeKmsProvider(["k1"])
        b = FakeKmsProvider(["k1"])
        pt = b"\x11" * 32
        self.assertEqual(a.wrap_data_key("k1", pt), b.wrap_data_key("k1", pt))

    def test_unknown_key_id_rejected(self):
        with self.assertRaises(KmsError):
            self.provider.wrap_data_key("nope", b"x" * 32)
        with self.assertRaises(KmsError):
            self.provider.unwrap_data_key("nope", b"junk")
        with self.assertRaises(KmsError):
            self.provider.describe_key("nope")

    def test_disabled_key_rejected_but_describable(self):
        self.provider.disable_key("prod-key-1")
        desc = self.provider.describe_key("prod-key-1")
        self.assertFalse(desc.enabled)
        with self.assertRaises(KmsError):
            self.provider.wrap_data_key("prod-key-1", b"x" * 32)
        blob = FakeKmsProvider(["prod-key-1"]).wrap_data_key(
            "prod-key-1", b"x" * 32)
        with self.assertRaises(KmsError):
            self.provider.unwrap_data_key("prod-key-1", blob)

    def test_outage_fails_closed(self):
        self.provider.outage = True
        blob = FakeKmsProvider(["prod-key-1"]).wrap_data_key(
            "prod-key-1", b"x" * 32)
        for op in (lambda: self.provider.wrap_data_key("prod-key-1", b"x" * 32),
                   lambda: self.provider.unwrap_data_key("prod-key-1", blob),
                   lambda: self.provider.describe_key("prod-key-1")):
            with self.assertRaises(KmsError):
                op()

    def test_tampered_blob_rejected(self):
        blob = bytearray(self.provider.wrap_data_key("prod-key-1", b"\x01" * 32))
        blob[20] ^= 0xFF  # flip a ciphertext byte -> tag mismatch
        with self.assertRaises(KmsError):
            self.provider.unwrap_data_key("prod-key-1", bytes(blob))

    def test_malformed_blobs_rejected(self):
        for bad in (b"", b"short", b"FAKEKMS1" + b"\x00" * 40,
                    self.provider.wrap_data_key("prod-key-1", b"y" * 32)[:-5]):
            with self.assertRaises(KmsError):
                self.provider.unwrap_data_key("prod-key-1", bad)

    def test_kms_impersonator_keyid_swap_rejected(self):
        """RED-TEAM Attack 2 regression: a blob wrapped under the
        attacker's key id must NOT unwrap under the production key id."""
        evil_blob = self.provider.wrap_data_key("prod-key-2", b"E" * 32)
        with self.assertRaises(KmsError):
            self.provider.unwrap_data_key("prod-key-1", evil_blob)

    def test_bad_key_id_and_empty_plaintext_rejected(self):
        with self.assertRaises(KmsError):
            self.provider.wrap_data_key("../evil", b"x" * 32)
        with self.assertRaises(KmsError):
            self.provider.wrap_data_key("prod-key-1", b"")

    def test_calls_audited(self):
        pt = b"\x02" * 32
        blob = self.provider.wrap_data_key("prod-key-1", pt)
        self.provider.unwrap_data_key("prod-key-1", blob)
        self.provider.describe_key("prod-key-1")
        ops = [c[0] for c in self.provider.calls]
        self.assertEqual(ops, ["wrap", "unwrap", "describe"])
        self.assertTrue(all(c[1] == "prod-key-1" for c in self.provider.calls))

    def test_constructor_validates(self):
        with self.assertRaises(ValueError):
            FakeKmsProvider([])
        with self.assertRaises(ValueError):
            FakeKmsProvider(["k1", "k1"])
        with self.assertRaises(KmsError):
            FakeKmsProvider(["../evil"])


# ---------------------------------------------------------------------------
# EnvelopeKeyRing
# ---------------------------------------------------------------------------

class EnvelopeKeyRingTest(_TmpMixin):
    def test_generate_and_materialize_roundtrip(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        self.assertEqual(ring.epochs(), ["epoch-1"])
        self.assertEqual(ring.active().kms_key_id, "prod-key-1")
        mat = ring.materialize(self.provider)
        self.assertEqual(mat.epochs(), ["epoch-1"])
        self.assertEqual(len(mat.active().key), 64)  # canonical hex form
        self.assertEqual(mat.active().key_id, ring.active().key_id)
        self.assertEqual(mat.active().status, "active")

    def test_materialize_unwraps_active_eagerly_retired_lazily(self):
        """Architect ruling: materialize() keeps the ACTIVE epoch in
        memory and unwraps each RETIRED epoch on first use, so the
        plaintext window during cross-epoch verification is minimal."""
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        ring.rotate(self.provider, new_epoch="epoch-2")
        self.provider.calls.clear()
        mat = ring.materialize(self.provider)
        unwraps = [c for c in self.provider.calls if c[0] == "unwrap"]
        self.assertEqual(len(unwraps), 1,
                         "only the active epoch unwraps eagerly")
        self.assertEqual(unwraps[0][1], "prod-key-1")
        # Retired epoch untouched until first get().
        mat.get("epoch-1")
        unwraps = [c for c in self.provider.calls if c[0] == "unwrap"]
        self.assertEqual(len(unwraps), 2)
        # Second get() hits the cache: no further KMS call.
        mat.get("epoch-1")
        unwraps = [c for c in self.provider.calls if c[0] == "unwrap"]
        self.assertEqual(len(unwraps), 2)

    def test_materialize_unknown_epoch_raises_keyerror(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        mat = ring.materialize(self.provider)
        with self.assertRaises(KeyError):
            mat.get("epoch-9")

    def test_materialized_ring_refuses_persistence(self):
        """A materialized (plaintext) ring must never be persisted."""
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        mat = ring.materialize(self.provider)
        with self.assertRaises(RuntimeError):
            mat.save(self.tmp / "nope.json")
        with self.assertRaises(RuntimeError):
            mat.to_dict()

    def test_activate_publishes_all_epochs_to_env(self):
        """activate() is the deliberate full-materialization path: the
        archive env var carries every retired epoch (same contract as
        KeyRing.activate)."""
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        ring.rotate(self.provider, new_epoch="epoch-2")
        published = ring.activate(self.provider)
        self.assertEqual(os.environ["GOV_LOG_KEY_EPOCH"], "epoch-2")
        self.assertEqual(published["GOV_LOG_KEY_EPOCH"], "epoch-2")
        archive = json.loads(os.environ["GOV_LOG_KEY_ARCHIVE"])
        self.assertEqual(sorted(archive), ["epoch-1"])

    def test_save_load_wrapped_only_and_perms(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        raw = p.read_bytes()
        # No plaintext anywhere in the persisted file: only wrapped blobs.
        mat = ring.materialize(self.provider)
        self.assertNotIn(mat.active().key, raw)
        self.assertIn(b"wrapped_b64", raw)
        loaded = EnvelopeKeyRing.load(p)
        self.assertEqual(loaded.active().key_id, ring.active().key_id)
        self.assertEqual(loaded.active().kms_key_id, "prod-key-1")

    def test_load_refuses_world_readable(self):
        p = self.tmp / "keyring.json"
        EnvelopeKeyRing.generate(self.provider, "prod-key-1").save(p)
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            EnvelopeKeyRing.load(p)

    def test_v1_plaintext_file_rejected_explicitly(self):
        p = self.tmp / "keyring-v1.json"
        KeyRing.generate("epoch-1").save(p)
        with self.assertRaises(ValueError) as cm:
            EnvelopeKeyRing.load(p)
        self.assertIn("v2", str(cm.exception))

    def test_v1_loader_rejects_v2_file(self):
        p = self.tmp / "keyring.json"
        EnvelopeKeyRing.generate(self.provider, "prod-key-1").save(p)
        with self.assertRaises(ValueError):
            KeyRing.load(p)

    def test_rotate_new_epoch_wrapped_old_retained(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        old_key = ring.materialize(self.provider).active().key
        ep = ring.rotate(self.provider, new_epoch="epoch-2")
        self.assertEqual(ep, "epoch-2")
        self.assertEqual(ring.get("epoch-1").status, "retired")
        mat = ring.materialize(self.provider)
        self.assertNotEqual(mat.active().key, old_key)
        self.assertEqual(mat.get("epoch-1").key, old_key)

    def test_rotate_wrap_failure_leaves_ring_unmutated(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        p = self.tmp / "keyring.json"
        ring.save(p)
        self.provider.outage = True
        with self.assertRaises(KmsError):
            ring.rotate(self.provider, new_epoch="epoch-2")
        self.assertEqual(ring.epochs(), ["epoch-1"])
        self.assertEqual(ring.active().status, "active")
        # Nothing persisted either.
        self.assertEqual(EnvelopeKeyRing.load(p).epochs(), ["epoch-1"])

    def test_rotate_rejects_duplicate_epoch(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        with self.assertRaises(ValueError):
            ring.rotate(self.provider, new_epoch="epoch-1")

    def test_rewrap_changes_kms_key_id_not_epochs(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        ring.rotate(self.provider, new_epoch="epoch-2")
        before = {ep: ring.materialize(self.provider).get(ep).key
                  for ep in ring.epochs()}
        ring.rewrap(self.provider, "prod-key-2")
        self.assertEqual(ring.epochs(), ["epoch-1", "epoch-2"])
        self.assertTrue(all(w.kms_key_id == "prod-key-2"
                            for w in ring._wrapped.values()))
        after = {ep: ring.materialize(self.provider).get(ep).key
                 for ep in ring.epochs()}
        self.assertEqual(before, after)  # same data keys, new KMS key

    def test_materialize_outage_fails_closed(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        self.provider.outage = True
        with self.assertRaises(KmsError):
            ring.materialize(self.provider)

    def test_envelope_end_to_end_log_verifies_across_rotation(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate(self.provider)
        log_path = self.tmp / "actions.jsonl"
        ActionLog(log_path).append({"event": "tool_call", "i": 0})
        ring2, new_epoch = kms.rotate_envelope_keyring(
            kr_path, self.provider, new_epoch="epoch-2", log_path=log_path)
        self.assertEqual(new_epoch, "epoch-2")
        ring2.activate(self.provider)
        ActionLog(log_path).append({"event": "tool_call", "i": 1})
        verdict = ring2.verify_log(log_path, self.provider)
        self.assertTrue(verdict["ok"], verdict["error"])
        self.assertEqual(verdict["epochs_seen"], ["epoch-1", "epoch-2"])
        # Backup left behind, wrapped-only.
        bak = Path(str(kr_path) + ".bak")
        self.assertTrue(bak.exists())
        self.assertEqual(EnvelopeKeyRing.load(bak).active().epoch, "epoch-1")

    def test_verify_log_unwraps_retired_only_when_reached(self):
        """Cross-epoch verify_log rides the lazy ring: the retired epoch
        unwraps when the replay reaches it, not before."""
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        ring.activate(self.provider)
        log_path = self.tmp / "actions.jsonl"
        ActionLog(log_path).append({"event": "a"})
        ring.rotate(self.provider, new_epoch="epoch-2")
        ring.activate(self.provider)
        ActionLog(log_path).append({"event": "b"})
        self.provider.calls.clear()
        verdict = ring.verify_log(log_path, self.provider)
        self.assertTrue(verdict["ok"], verdict["error"])
        unwraps = [c for c in self.provider.calls if c[0] == "unwrap"]
        self.assertEqual(len(unwraps), 2)  # active + retired, on demand

    def test_ceremony_refuses_on_tampered_log(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate(self.provider)
        log_path = self.tmp / "actions.jsonl"
        ActionLog(log_path).append({"event": "tool_call", "i": 0})
        lines = log_path.read_text().splitlines()
        lines[0] = lines[0].replace('"i": 0', '"i": 999')
        log_path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(RuntimeError) as cm:
            kms.rotate_envelope_keyring(kr_path, self.provider,
                                        log_path=log_path)
        self.assertIn("refusing to rotate", str(cm.exception))
        self.assertEqual(
            EnvelopeKeyRing.load(kr_path).active().epoch, "epoch-1")

    def test_ceremony_refuses_when_kms_down(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        kr_path = self.tmp / "keyring.json"
        ring.save(kr_path)
        ring.activate(self.provider)
        log_path = self.tmp / "actions.jsonl"
        ActionLog(log_path).append({"event": "tool_call", "i": 0})
        self.provider.outage = True  # cannot verify old log -> refuse
        with self.assertRaises(KmsError):
            kms.rotate_envelope_keyring(kr_path, self.provider,
                                        log_path=log_path)
        self.assertEqual(
            EnvelopeKeyRing.load(kr_path).epochs(), ["epoch-1"])

    def test_describe_never_leaks_key_material(self):
        ring = EnvelopeKeyRing.generate(self.provider, "prod-key-1")
        mat = ring.materialize(self.provider)
        blob = json.dumps(ring.describe())
        self.assertNotIn(mat.active().key.decode(), blob)
        self.assertIn(ring.active().key_id, blob)
        self.assertIn("prod-key-1", blob)


# ---------------------------------------------------------------------------
# Production key resolution — dev keys structurally unreachable (Attack 1)
# ---------------------------------------------------------------------------

class StrictResolverTest(_TmpMixin):
    """Wave-81: the dev key is deleted from gov/ -- there is no fallback
    in any mode. The key resolver in gov/log.py fails closed when no key
    is provisioned, and the old double-opt-in names are absent. (F73's
    forged-history finding is closed by deletion: there is no public dev
    key left to forge with.)"""

    def test_env_scrub_fails_closed(self):
        with self.assertRaises(NoKeyConfiguredError):
            gov_log._active_key()

    def test_old_dev_names_absent_from_log_module(self):
        for name in ("enable_dev_keys", "dev_keys_enabled"):
            self.assertFalse(hasattr(gov_log, name), name)

    def test_configured_key_works(self):
        os.environ["GOV_LOG_KEY"] = "prod-key-material"
        os.environ["GOV_LOG_KEY_EPOCH"] = "epoch-7"
        key, epoch = gov_log._active_key()
        self.assertEqual(key, b"prod-key-material")
        self.assertEqual(epoch, "epoch-7")

    def test_action_log_fails_closed_on_env_scrub(self):
        """The full production path: ActionLog.append with no key
        provisioned raises -- there is no silent fallback."""
        with self.assertRaises(NoKeyConfiguredError):
            ActionLog(self.tmp / "actions.jsonl").append({"event": "x"})


class RequireProductionKeyTest(_TmpMixin):
    def test_configured_key_ok(self):
        os.environ["GOV_LOG_KEY"] = "s3cr3t-prod-key"
        ring = require_production_key()
        self.assertEqual(ring.active().epoch, "env")

    def test_unset_raises(self):
        # Wave-81: no fallback exists, so unset always refuses.
        with self.assertRaises(NoKeyConfiguredError):
            require_production_key()


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

class ProviderFactoryTest(_TmpMixin):
    def test_factory_refuses_fake_unconditionally(self):
        # Wave-81: the dev opt-in variable is deleted from gov/; the
        # operator config surface never builds the fake KMS.
        with self.assertRaises(KmsError) as cm:
            kms.kms_provider_from_config(
                {"provider": "fake", "key_ids": ["k1"]})
        self.assertIn("test-only", str(cm.exception))

    def test_fake_constructed_directly_in_code(self):
        # Tests construct FakeKmsProvider directly (explicit, in-code).
        p = FakeKmsProvider(["k1"])
        blob = p.wrap_data_key("k1", b"\x00" * 32)
        self.assertEqual(p.unwrap_data_key("k1", blob), b"\x00" * 32)

    def test_factory_real_providers_not_built(self):
        for name in ("aws", "gcp", "azure"):
            with self.assertRaises(KmsError) as cm:
                kms.kms_provider_from_config(
                    {"provider": name, "key_id": "x"})
            self.assertIn("not built", str(cm.exception))

    def test_factory_rejects_unknown_and_malformed(self):
        with self.assertRaises(KmsError):
            kms.kms_provider_from_config({"provider": "oracle"})
        with self.assertRaises(KmsError):
            kms.kms_provider_from_config("not-a-mapping")


if __name__ == "__main__":
    unittest.main()
