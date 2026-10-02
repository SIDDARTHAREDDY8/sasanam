"""Unit tests for gov/kms_keyset.py (wave-284 lane 8, tink ADAPT)."""

import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import kms_keyset as kk
from gov.kms import FakeKmsProvider, KmsError


def _ks(*kids):
    kids = kids or ("k1", "k2")
    provider = FakeKmsProvider(list(kids))
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id=kids[0], provider_name="fake")
    for kid in kids[1:]:
        ks.add_key(kid, provider_name="fake")
    return ks, provider


class TestKeysetSchema(unittest.TestCase):
    def test_new_requires_declared_template(self):
        with self.assertRaises(kk.KeysetError) as c:
            kk.KmsKeyset.new(template_name="NOPE/v9", primary_key_id="k1",
                             provider_name="fake")
        self.assertEqual(c.exception.code, "keyset-bad-template")

    def test_template_name_must_carry_version(self):
        with self.assertRaises(kk.KeysetError) as c:
            kk.KeyTemplate("noversion", primitive="p", params={})
        self.assertEqual(c.exception.code, "keyset-bad-template")

    def test_digest_stable_and_pinned(self):
        ks, _ = _ks()
        d1 = ks.to_dict()["keyset_digest"]
        ks2 = kk.KmsKeyset.from_dict(ks.to_dict())
        self.assertEqual(ks2.to_dict()["keyset_digest"], d1)

    def test_tampered_digest_refused(self):
        ks, _ = _ks()
        doc = ks.to_dict()
        doc["primary_key_id"] = "k2"
        with self.assertRaises(kk.KeysetError) as c:
            kk.KmsKeyset.from_dict(doc)
        self.assertEqual(c.exception.code, "keyset-verify-failed")

    def test_duplicate_key_id_refused(self):
        ks, _ = _ks()
        doc = ks.to_dict()
        doc["keys"].append(dict(doc["keys"][0]))
        doc = kk.KmsKeyset._repin(doc)
        with self.assertRaises(kk.KeysetError) as c:
            kk.KmsKeyset.from_dict(doc)
        self.assertEqual(c.exception.code, "keyset-duplicate-key")

    def test_add_duplicate_key_refused(self):
        ks, _ = _ks()
        with self.assertRaises(kk.KeysetError) as c:
            ks.add_key("k1", provider_name="fake")
        self.assertEqual(c.exception.code, "keyset-duplicate-key")

    def test_unknown_key_status(self):
        self.assertEqual(kk.KmsKeyset.new(
            template_name="KMS-ENVELOPE/v1", primary_key_id="k1",
            provider_name="fake").key_status("k1"), "enabled")
        ks, _ = _ks()
        with self.assertRaises(kk.KeysetError) as c:
            ks.key_status("nope")
        self.assertEqual(c.exception.code, "keyset-unknown-key")

    def test_describe_is_material_free(self):
        ks, _ = _ks()
        desc = ks.describe()
        blob = json.dumps(desc).encode()
        # No key material: the fake provider's wrap secret never appears,
        # and no 32-byte blobs are present.
        self.assertNotIn(b"fake-kms-test-wrap-secret", blob)
        self.assertIn("keyset_digest", desc)
        self.assertEqual(desc["primary_key_id"], "k1")


class TestLifecycle(unittest.TestCase):
    def test_wrap_unwrap_round_trip(self):
        ks, provider = _ks()
        blob = ks.wrap_data_key(provider, b"d" * 32)
        self.assertEqual(ks.unwrap_data_key(provider, "k1", blob), b"d" * 32)

    def test_verify_key_refuses_destroyed(self):
        # DESTROYED refuses ALL operations, verify included.
        ks, provider = _ks()
        ks.destroy_key("k2", reason="test")
        with self.assertRaises(kk.KeysetError) as c:
            ks.verify_key(provider, "k2")
        self.assertEqual(c.exception.code, "keyset-key-destroyed")

    def test_verify_key_refuses_tampered_chain(self):
        # verify_key mutates (audit event + repin), so it must refuse a
        # broken audit chain like every other mutating op.
        ks, provider = _ks()
        ks._doc["audit_chain"][0]["reason"] = "forged"
        doc = kk.KmsKeyset._repin(ks.to_dict())
        ks2 = kk.KmsKeyset.from_dict(doc)
        with self.assertRaises(kk.KeysetError) as c:
            ks2.verify_key(provider, "k1")
        self.assertEqual(c.exception.code, "keyset-verify-failed")

    def test_destroy_primary_needs_distinct_successor(self):
        # The atomic-successor rule is void if the successor is the key
        # being destroyed: a destroyed primary with no enabled successor.
        ks, _ = _ks()
        with self.assertRaises(kk.KeysetError) as c:
            ks.destroy_key("k1", reason="test", new_primary="k1")
        self.assertEqual(c.exception.code, "keyset-primary-not-enabled")
        self.assertEqual(ks.key_status("k1"), "enabled")

    def test_destroyed_key_terminal(self):
        ks, provider = _ks()
        ks.destroy_key("k2", reason="test")
        self.assertEqual(ks.key_status("k2"), "destroyed")
        with self.assertRaises(kk.KeysetError) as c:
            ks.unwrap_data_key(provider, "k2", b"blob")
        self.assertEqual(c.exception.code, "keyset-key-destroyed")
        with self.assertRaises(kk.KeysetError):
            ks.enable_key("k2", reason="nope")

    def test_destroy_primary_needs_successor(self):
        ks, provider = _ks()
        with self.assertRaises(kk.KeysetError) as c:
            ks.destroy_key("k1", reason="x")
        self.assertEqual(c.exception.code, "keyset-primary-not-enabled")
        ks.destroy_key("k1", reason="x", new_primary="k2")
        self.assertEqual(ks.primary_key_id(), "k2")
        self.assertEqual(ks.key_status("k1"), "destroyed")

    def test_disable_primary_stops_minting(self):
        ks, provider = _ks()
        ks.disable_key("k1", reason="incident")
        with self.assertRaises(kk.KeysetError) as c:
            ks.wrap_data_key(provider, b"e" * 32)
        self.assertEqual(c.exception.code, "keyset-key-disabled")

    def test_disabled_unwrap_permitted_at_keyset_layer(self):
        ks, provider = _ks()
        blob = ks.wrap_data_key(provider, b"f" * 32)
        ks.disable_key("k2", reason="winding down")
        # Keyset layer permits; the fake (AWS-like) refuses with KmsError.
        with self.assertRaises(KmsError):
            ks.unwrap_data_key(provider, "k2", blob)

    def test_corroboration_refuses_on_disagreement(self):
        ks, provider = _ks()
        provider.destroy_key("k1")  # provider-side destroy, keyset unaware
        # The fake refuses describe on destroyed keys, so its own
        # fail-closed stands: the wrap is refused either way.
        with self.assertRaises((kk.KeysetError, KmsError)):
            ks.wrap_data_key(provider, b"g" * 32)

    def test_corroboration_disabled_disagreement(self):
        ks, provider = _ks()
        provider.disable_key("k1")  # provider-side disable, keyset unaware
        # describe succeeds with status=disabled -> keyset detects the
        # disagreement LOUD before the provider is asked to mint.
        with self.assertRaises(kk.KeysetError) as c:
            ks.wrap_data_key(provider, b"g" * 32)
        self.assertEqual(c.exception.code, "keyset-key-disabled")


class TestCeremony(unittest.TestCase):
    def _rot(self):
        ks, _ = _ks("k1", "k2")
        provider = FakeKmsProvider(["k1", "k2", "k3"])
        return ks, provider

    def test_full_ceremony(self):
        ks, provider = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        self.assertEqual(ks.ceremony_state()["phase"], "rolling-out")
        ks.roll_out(provider)
        self.assertEqual(ks.ceremony_state()["phase"], "verified")
        ks.promote(reason="scheduled")
        self.assertEqual(ks.primary_key_id(), "k3")
        self.assertEqual(ks.key_status("k1"), "disabled")
        self.assertEqual(ks.ceremony_state()["phase"], "complete")

    def test_promote_before_verify_refused(self):
        ks, _ = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        with self.assertRaises(kk.KeysetError) as c:
            ks.promote(reason="x")
        self.assertEqual(c.exception.code, "keyset-ceremony-incomplete")

    def test_double_begin_refused(self):
        ks, _ = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        with self.assertRaises(kk.KeysetError) as c:
            ks.begin_rotation("k2", provider_name="fake")
        self.assertEqual(c.exception.code, "keyset-ceremony-incomplete")

    def test_roll_out_failure_is_loud_and_visible(self):
        ks, provider = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        provider.outage = True
        with self.assertRaises(kk.KeysetError) as c:
            ks.roll_out(provider, attempts=2)
        self.assertEqual(c.exception.code, "keyset-verify-failed")
        self.assertEqual(ks.ceremony_state()["phase"], "roll-out-failed")

    def test_roll_out_destroyed_candidate_reports_destroyed(self):
        ks, provider = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        ks.destroy_key("k3", reason="test")
        with self.assertRaises(kk.KeysetError) as c:
            ks.roll_out(provider)
        self.assertEqual(c.exception.code, "keyset-key-destroyed")

    def test_begin_rotation_refuses_empty_provider_name(self):
        ks, _ = _ks("k1", "k2")
        with self.assertRaises(kk.KeysetError):
            ks.begin_rotation("k3", provider_name="")

    def test_parse_refuses_ceremony_without_successor(self):
        # A phase that claims progress must name its successor; the
        # refusal is coded, never a raw KeyError downstream.
        ks, _ = _ks("k1", "k2")
        doc = ks.to_dict()
        doc["ceremony"] = {"phase": "rolling-out", "new_key_id": None,
                           "attempts": 0}
        with self.assertRaises(kk.KeysetError) as c:
            kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc))
        self.assertEqual(c.exception.code, "keyset-ceremony-incomplete")

    def test_promote_does_not_resurrect_destroyed_old_primary(self):
        # Post-incident state: the primary was destroyed before the
        # ceremony. Promoting the successor must not resurrect it.
        ks, _ = _ks("k1", "k2")
        provider = FakeKmsProvider(["k1", "k2", "k3"])
        doc = ks.to_dict()
        for k in doc["keys"]:
            if k["key_id"] == "k1":
                k["status"] = "destroyed"
        ks2 = kk.KmsKeyset.from_dict(kk.KmsKeyset._repin(doc))
        ks2.begin_rotation("k3", provider_name="fake")
        ks2.roll_out(provider)
        ks2.promote(reason="test")
        self.assertEqual(ks2.primary_key_id(), "k3")
        self.assertEqual(ks2.key_status("k1"), "destroyed")

    def test_abandon_never_resurrects_destroyed(self):
        ks, provider = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        ks.destroy_key("k3", reason="test")
        ks.abandon_ceremony(reason="test")
        self.assertEqual(ks._entry("k3")["status"], "destroyed")
        ks, _ = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        ks.abandon_ceremony(reason="cancelled")
        self.assertEqual(ks.ceremony_state()["phase"], "none")
        self.assertEqual(ks.key_status("k3"), "disabled")
        self.assertEqual(ks.primary_key_id(), "k1")

    def test_ceremony_survives_serialization(self):
        ks, _ = self._rot()
        ks.begin_rotation("k3", provider_name="fake")
        ks2 = kk.KmsKeyset.from_dict(ks.to_dict())
        self.assertEqual(ks2.ceremony_state()["phase"], "rolling-out")
        self.assertEqual(ks2.ceremony_state()["new_key_id"], "k3")


class TestAuditChain(unittest.TestCase):
    def test_chain_verifies_and_tamper_fails(self):
        ks, _ = _ks()
        ks.disable_key("k2", reason="x")
        self.assertTrue(ks.verify_chain())
        doc = ks.to_dict()
        doc["audit_chain"][0]["reason"] = "forged"
        doc = kk.KmsKeyset._repin(doc)
        self.assertFalse(kk.KmsKeyset.from_dict(doc).verify_chain())

    def test_mutation_refuses_on_broken_chain(self):
        ks, _ = _ks()
        ks._doc["audit_chain"][0]["reason"] = "forged"
        with self.assertRaises(kk.KeysetError) as c:
            ks.disable_key("k2", reason="x")
        self.assertEqual(c.exception.code, "keyset-verify-failed")


class TestTemplates(unittest.TestCase):
    def test_retemplate_governed(self):
        # Retemplate to an unknown name refuses, and a no-op retemplate
        # refuses.
        ks, _ = _ks()
        with self.assertRaises(kk.KeysetError) as c:
            ks.retemplate("NOPE/v9", reason="x")
        self.assertEqual(c.exception.code, "keyset-bad-template")
        with self.assertRaises(kk.KeysetError):
            ks.retemplate("KMS-ENVELOPE/v1", reason="x")

    def test_retemplate_positive_path(self):
        # The upgrade mechanism is explicit: a declared second template
        # rebinds the primitive under audit.
        ks, _ = _ks()
        before = len(ks.audit_events())
        ks.retemplate("KMS-ENVELOPE-HKDF/v1", reason="upgrade")
        self.assertEqual(ks.template().primitive, "provider-wrap-hkdf")
        self.assertEqual(len(ks.audit_events()), before + 1)
        self.assertTrue(ks.verify_chain())

    def test_template_describe(self):
        ks, _ = _ks()
        t = ks.template()
        self.assertEqual(t.name, "KMS-ENVELOPE/v1")
        self.assertTrue(t.primitive)


class TestProviderContracts(unittest.TestCase):
    def test_full_conformance_fake(self):
        result = kk.verify_provider_contracts(
            FakeKmsProvider(["k1", "k2"]), ["k1", "k2"])
        self.assertTrue(result["ok"], result["checks"])

    def test_rejects_non_provider(self):
        result = kk.verify_provider_contracts(object(), ["k1"])
        self.assertFalse(result["ok"])

    def test_vault_surface(self):
        from gov import kms_vault
        surface = kk.provider_contract_surface(
            kms_vault.VaultKmsProvider)
        self.assertTrue(surface["ok"], surface["checks"])
        self.assertEqual(surface["lifecycle"],
                         "provider-reports-enabled-only")

    def test_vault_surface_rejects_non_provider(self):
        surface = kk.provider_contract_surface(int)
        self.assertFalse(surface["ok"])


if __name__ == "__main__":
    unittest.main()
