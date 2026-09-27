"""Row-12 unit tests: the deployment-pinned artifact manifest.

Break-first discipline: every behavior here was demonstrated red
by evals/deployment_manifest_probes.py before the seam existed.

Deterministic, $0, stdlib only, unittest only.
"""

import hashlib
import os
import unittest

from gov import artifact_inventory_manifest as man
from gov import artifact_sweep as sweep
from gov import keyprovider

TEST_KEY = b"row12-unit-test-key-32-bytes-long!"


def _pin(entries, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return man.pin_manifest(entries, **kw)


class TestPinCeremony(unittest.TestCase):
    def test_pin_verify_round_trip(self):
        pinned = _pin({"weights/model.bin": "ab" * 32})
        ok, reason = man.verify_manifest_pin(pinned, hmac_key=TEST_KEY)
        self.assertTrue(ok, reason)

    def test_pin_normalizes_paths_and_case(self):
        pinned = _pin({"./weights/model.bin": "AB" * 32})
        self.assertEqual(list(pinned["manifest"]),
                         ["weights/model.bin"])
        self.assertEqual(pinned["manifest"]["weights/model.bin"],
                         "ab" * 32)

    def test_pin_envelope_shape(self):
        pinned = _pin({"a.bin": "cd" * 32})
        self.assertEqual(pinned["pinned_manifest"],
                         man.MANIFEST_PINNED_VERSION)
        self.assertTrue(pinned["pinned_at"])
        self.assertEqual(pinned["key_epoch"], "explicit-override")
        self.assertTrue(pinned["pin"])

    def test_malformed_digest_rejected_fail_closed(self):
        for bad in ("zz" * 32, "ab" * 31, "ab" * 33, 12345, ""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                _pin({"a.bin": bad})

    def test_empty_manifest_rejected(self):
        with self.assertRaises(ValueError):
            _pin({})

    def test_no_key_configured_raises_fail_closed(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GOV_LOG_KEY", "GOV_KEYRING_FILE")}
        old = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(
                    keyprovider.NoKeyConfiguredError):
                man.pin_manifest({"a.bin": "ab" * 32})
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_ceremony_audit_event(self):
        events = []
        pinned = _pin({"a.bin": "ab" * 32},
                      audit=events.append, run_id="u1")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], man.MANIFEST_PINNED_EVENT)
        self.assertEqual(ev["run_id"], "u1")
        self.assertEqual(ev["entry_count"], 1)
        self.assertEqual(ev["manifest_digest"],
                         man.manifest_digest(pinned))
        # no secrets or digests in the event
        blob = repr(ev)
        self.assertNotIn("ab" * 32, blob)
        self.assertNotIn(TEST_KEY.decode("latin1"), blob)


class TestVerifyFailClosed(unittest.TestCase):
    def test_tampered_pin_rejected(self):
        pinned = _pin({"a.bin": "ab" * 32})
        pinned["pin"] = "00" * 32
        ok, reason = man.verify_manifest_pin(pinned,
                                             hmac_key=TEST_KEY)
        self.assertFalse(ok)
        self.assertIn("pin_mismatch", reason)

    def test_swapped_digest_rejected(self):
        pinned = _pin({"a.bin": "ab" * 32})
        pinned["manifest"]["a.bin"] = "cd" * 32
        ok, reason = man.verify_manifest_pin(pinned,
                                             hmac_key=TEST_KEY)
        self.assertFalse(ok)
        self.assertIn("pin_mismatch", reason)

    def test_pin_stripped_envelope_rejected(self):
        # the F182 shape: any dict claims the pinned form
        ok, reason = man.verify_manifest_pin(
            {"manifest": {"a.bin": "ab" * 32}}, hmac_key=TEST_KEY)
        self.assertFalse(ok)
        self.assertIn("malformed_manifest_envelope", reason)

    def test_non_dict_rejected(self):
        for bad in (None, [], "pinned", 42):
            ok, _ = man.verify_manifest_pin(bad, hmac_key=TEST_KEY)
            self.assertFalse(ok, repr(bad))

    def test_wrong_key_rejected(self):
        pinned = _pin({"a.bin": "ab" * 32})
        ok, reason = man.verify_manifest_pin(
            pinned, hmac_key=b"a-different-32-byte-test-key!!")
        self.assertFalse(ok)
        self.assertIn("pin_mismatch", reason)

    def test_epoch_rotation_rejected(self):
        # key from the chokepoint: pin under epoch A, verify after
        # the epoch rotates -> stale, fail-closed
        saved = os.environ.get("GOV_LOG_KEY_EPOCH")
        try:
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit-epoch-a"
            pinned = man.pin_manifest({"a.bin": "ab" * 32})
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit-epoch-b"
            ok, reason = man.verify_manifest_pin(pinned)
            self.assertFalse(ok)
            self.assertIn("stale_pin_epoch", reason)
        finally:
            if saved is None:
                os.environ.pop("GOV_LOG_KEY_EPOCH", None)
            else:
                os.environ["GOV_LOG_KEY_EPOCH"] = saved

    def test_ttl_expiry_rejected(self):
        pinned = _pin({"a.bin": "ab" * 32})
        pinned["pinned_at"] = "2000-01-01T00:00:00+00:00"
        # re-pin the body so the MAC matches the stale timestamp
        body = man._manifest_body(
            man.MANIFEST_PINNED_VERSION, pinned["manifest"],
            pinned["pinned_at"], pinned["key_epoch"])
        pinned["pin"] = sweep._inventory_pin_mac(TEST_KEY, body)
        ok, reason = man.verify_manifest_pin(
            pinned, hmac_key=TEST_KEY, ttl_seconds=60)
        self.assertFalse(ok)
        self.assertIn("stale_pin_epoch", reason)

    def test_ttl_not_expired_accepted(self):
        pinned = _pin({"a.bin": "ab" * 32})
        ok, reason = man.verify_manifest_pin(
            pinned, hmac_key=TEST_KEY, ttl_seconds=3600)
        self.assertTrue(ok, reason)

    def test_cross_domain_pins_do_not_verify(self):
        # a manifest pin must never verify as an inventory pin and
        # vice versa (nested domain separation)
        pinned = _pin({"a.bin": "ab" * 32})
        inv = sweep.pin_inventory(["a.bin"], hmac_key=TEST_KEY)
        ok, _ = man.verify_manifest_pin(inv, hmac_key=TEST_KEY)
        self.assertFalse(ok)
        ok, _ = sweep.verify_inventory_pin(pinned, hmac_key=TEST_KEY)
        self.assertFalse(ok)
        # and the MACs genuinely differ over the same logical input
        self.assertNotEqual(pinned["pin"], inv["pin"])

    def test_no_new_hmac_site(self):
        # row-12 reuses the allowlisted wave-141 pin MAC: this
        # module must introduce NO new hmac.new/HMAC/digest call
        # site, so the w70 chokepoint audit stays green.
        import ast
        from pathlib import Path
        tree = ast.parse(Path(
            man.__file__).read_text(encoding="utf-8"))
        hits = [n for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("new", "HMAC", "digest")]
        self.assertEqual(hits, [])


class TestCheckManifest(unittest.TestCase):
    def test_match_is_clean(self):
        pinned = _pin({"a.bin": "ab" * 32})
        v = man.check_manifest("a.bin", "ab" * 32, pinned,
                               hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_clean")
        self.assertIsNone(v["flag"])

    def test_mismatch_flags(self):
        pinned = _pin({"a.bin": "ab" * 32})
        v = man.check_manifest("a.bin", "cd" * 32, pinned,
                               hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_mismatch")
        self.assertEqual(v["flag"], man.MANIFEST_MISMATCH_FLAG)
        self.assertIn("deployment pin", v["detail"])

    def test_forged_manifest_fails_closed(self):
        pinned = _pin({"a.bin": "ab" * 32})
        pinned["manifest"]["a.bin"] = "cd" * 32  # forger rewrites
        v = man.check_manifest("a.bin", "cd" * 32, pinned,
                               hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_unverifiable")
        self.assertEqual(v["flag"], man.MANIFEST_UNVERIFIABLE_FLAG)

    def test_pin_stripped_fails_closed(self):
        v = man.check_manifest(
            "a.bin", "ab" * 32, {"manifest": {"a.bin": "ab" * 32}},
            hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_unverifiable")

    def test_unlisted_path_is_silent(self):
        pinned = _pin({"a.bin": "ab" * 32})
        v = man.check_manifest("b.bin", "cd" * 32, pinned,
                               hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_absent")
        self.assertIsNone(v["flag"])

    def test_unreadable_is_fail_open(self):
        pinned = _pin({"a.bin": "ab" * 32})
        v = man.check_manifest("a.bin", None, pinned,
                               hmac_key=TEST_KEY)
        self.assertEqual(v["status"], "manifest_unreadable")
        self.assertIsNone(v["flag"])

    def test_check_never_raises(self):
        for bad in (None, {}, [], "x"):
            v = man.check_manifest("a.bin", "ab" * 32, bad,
                                   hmac_key=TEST_KEY)
            self.assertEqual(v["status"], "manifest_unverifiable")

    def test_detail_leaks_nothing_secret(self):
        pinned = _pin({"a.bin": "ab" * 32})
        v = man.check_manifest("a.bin", "cd" * 32, pinned,
                               hmac_key=TEST_KEY)
        blob = repr(v)
        self.assertNotIn("ab" * 32, blob)
        self.assertNotIn("cd" * 32, blob)


class TestManifestDigest(unittest.TestCase):
    def test_digest_deterministic(self):
        pinned = _pin({"b.bin": "cd" * 32, "a.bin": "ab" * 32})
        self.assertEqual(man.manifest_digest(pinned),
                         man.manifest_digest(pinned))

    def test_digest_is_sha256_hex(self):
        pinned = _pin({"a.bin": "ab" * 32})
        d = man.manifest_digest(pinned)
        self.assertEqual(len(d), 64)
        int(d, 16)

    def test_digest_changes_with_entries(self):
        p1 = _pin({"a.bin": "ab" * 32})
        p2 = _pin({"a.bin": "cd" * 32})
        self.assertNotEqual(man.manifest_digest(p1),
                            man.manifest_digest(p2))

    def test_digest_malformed_raises(self):
        with self.assertRaises(ValueError):
            man.manifest_digest({"manifest": {}})


class TestInventoryAttach(unittest.TestCase):
    def test_attach_valid(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        self.assertFalse(inv.has_deployment_manifest)
        pinned = _pin({"a.bin": "ab" * 32})
        inv.attach_deployment_manifest(pinned, hmac_key=TEST_KEY)
        self.assertTrue(inv.has_deployment_manifest)

    def test_attach_forged_raises_loud(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        pinned = _pin({"a.bin": "ab" * 32})
        pinned["manifest"]["a.bin"] = "cd" * 32
        with self.assertRaises(ValueError):
            inv.attach_deployment_manifest(pinned, hmac_key=TEST_KEY)
        self.assertFalse(inv.has_deployment_manifest)

    def test_attach_malformed_raises_loud(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        with self.assertRaises(ValueError):
            inv.attach_deployment_manifest({"manifest": {}},
                                           hmac_key=TEST_KEY)

    def test_attach_wrong_key_raises_loud(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        pinned = _pin({"a.bin": "ab" * 32})
        with self.assertRaises(ValueError):
            inv.attach_deployment_manifest(
                pinned, hmac_key=b"a-different-32-byte-test-key!!")

    def test_constructor_verifies_fail_loud(self):
        from gov.artifacts import ArtifactInventory
        pinned = _pin({"a.bin": "ab" * 32})  # pinned under TEST_KEY
        with self.assertRaises(ValueError):
            ArtifactInventory(pinned)  # ambient key cannot verify it

    def test_constructor_accepts_manifest_ambient_key(self):
        from gov.artifacts import ArtifactInventory
        # pinned under the ambient test key (tests/__init__.py
        # provisions GOV_LOG_KEY), verified via the chokepoint.
        pinned = man.pin_manifest({"a.bin": "ab" * 32})
        inv = ArtifactInventory(pinned)
        self.assertTrue(inv.has_deployment_manifest)

    def test_detach(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        inv.attach_deployment_manifest(_pin({"a.bin": "ab" * 32}),
                                       hmac_key=TEST_KEY)
        inv.detach_deployment_manifest()
        self.assertFalse(inv.has_deployment_manifest)
        v = inv.check_egress("a.bin", sha256_now="ab" * 32)
        self.assertNotIn("manifest_status", v)


class TestInventoryCheckEgressWithManifest(unittest.TestCase):
    def _inv(self, entries):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        inv.attach_deployment_manifest(_pin(entries),
                                       hmac_key=TEST_KEY)
        return inv

    def _reg(self, inv, path, sha, classification=None):
        return inv.register(path, sha256=sha, size=10,
                            agent_id="a", run_id="r",
                            classification=classification)

    def test_no_manifest_verdict_unchanged(self):
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        self._reg(inv, "a.bin", "ab" * 32)
        v = inv.check_egress("a.bin", sha256_now="ab" * 32)
        self.assertEqual(v["status"], "clean")
        self.assertNotIn("manifest_status", v)

    def test_listed_match_registered_clean(self):
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "a.bin", "ab" * 32)
        v = inv.check_egress("a.bin", sha256_now="ab" * 32)
        self.assertEqual(v["status"], "clean")
        self.assertIsNone(v["manifest_status"])
        self.assertIsNone(v["manifest_detail"])

    def test_laundering_upgraded_to_tampered(self):
        # the m1 shape: governed write REGISTERS hostile bytes, so
        # the run check reads clean -- the manifest is the only
        # record that knows the truth.
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "a.bin", "cd" * 32)  # hostile bytes registered
        v = inv.check_egress("a.bin", sha256_now="cd" * 32)
        self.assertEqual(v["status"], "tampered")
        self.assertEqual(v["flag"], "artifact_tampered")
        self.assertEqual(v["manifest_status"], "manifest_mismatch")
        self.assertIn("deployment", v["manifest_detail"].lower())

    def test_cross_run_unknown_upgraded_to_tampered(self):
        # the m2 shape: never registered this run, bytes differ
        # from the deployment pin.
        inv = self._inv({"a.bin": "ab" * 32})
        v = inv.check_egress("a.bin", sha256_now="cd" * 32)
        self.assertEqual(v["status"], "tampered")
        self.assertEqual(v["flag"], "artifact_tampered")
        self.assertEqual(v["manifest_status"], "manifest_mismatch")

    def test_restricted_never_weakened(self):
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "a.bin", "cd" * 32, classification="restricted")
        v = inv.check_egress("a.bin", sha256_now="cd" * 32)
        self.assertEqual(v["status"], "restricted")
        # the manifest signal still rides for reviewers
        self.assertEqual(v["manifest_status"], "manifest_mismatch")

    def test_unlisted_path_silent(self):
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "b.bin", "ef" * 32)
        v = inv.check_egress("b.bin", sha256_now="ef" * 32)
        self.assertEqual(v["status"], "clean")
        self.assertIsNone(v["manifest_status"])

    def test_unreadable_fail_open(self):
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "a.bin", "ab" * 32)
        v = inv.check_egress("a.bin", sha256_now=None)
        self.assertEqual(v["status"], "clean")
        self.assertIsNone(v["manifest_status"])

    def test_mutated_envelope_fails_closed_at_consult(self):
        # the pin is re-verified on every egress: a mid-run
        # envelope mutation cannot silently widen the gate.
        pinned = _pin({"a.bin": "ab" * 32})
        from gov.artifacts import ArtifactInventory
        inv = ArtifactInventory()
        inv.attach_deployment_manifest(pinned, hmac_key=TEST_KEY)
        self._reg(inv, "a.bin", "ab" * 32)
        pinned["manifest"]["a.bin"] = "cd" * 32  # mutate post-attach
        v = inv.check_egress("a.bin", sha256_now="ab" * 32)
        self.assertEqual(v["status"], "tampered")
        self.assertEqual(v["manifest_status"],
                         "manifest_unverifiable")

    def test_key_rotation_fails_closed_at_consult(self):
        saved = os.environ.get("GOV_LOG_KEY_EPOCH")
        try:
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit-epoch-a"
            from gov.artifacts import ArtifactInventory
            inv = ArtifactInventory()
            inv.attach_deployment_manifest(
                man.pin_manifest({"a.bin": "ab" * 32}))
            os.environ["GOV_LOG_KEY_EPOCH"] = "unit-epoch-b"
            v = inv.check_egress("a.bin", sha256_now="ab" * 32)
            self.assertEqual(v["status"], "tampered")
            self.assertEqual(v["manifest_status"],
                             "manifest_unverifiable")
        finally:
            if saved is None:
                os.environ.pop("GOV_LOG_KEY_EPOCH", None)
            else:
                os.environ["GOV_LOG_KEY_EPOCH"] = saved

    def test_manifest_detail_leaks_nothing_secret(self):
        inv = self._inv({"a.bin": "ab" * 32})
        self._reg(inv, "a.bin", "cd" * 32)
        v = inv.check_egress("a.bin", sha256_now="cd" * 32)
        blob = repr(v)
        self.assertNotIn("ab" * 32, blob)
        self.assertNotIn("cd" * 32, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
