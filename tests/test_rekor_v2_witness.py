"""Unit tests for gov.rekor_v2_witness (wave-277 lane, rekor).

Complements evals/w277_rekor_probes.py (the red-first battery): the
probes attack the public seams break-first; these tests pin edge-case
behavior and the error taxonomy at the same seams.
"""

import base64
import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import rekor_v2_witness as w
from gov.digest_ref import DigestRef


def _doc(**kw):
    doc = {
        "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
        "rekor": [
            {"url": "https://log2026-2.rekor.example.invalid",
             "majorApiVersion": 2, "logId": "ab" * 32,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ],
        "tsa": [
            {"url": "https://tsa.example.invalid", "majorApiVersion": 1,
             "validFor": {"start": "2021-01-01T00:00:00Z"}},
        ],
    }
    doc.update(kw)
    return doc


def _material(seed_byte=41):
    from gov import anchor_backend as _ab
    from gov import ed25519 as _ed
    seed = bytes([seed_byte]) * 32
    digest = hashlib.sha256(b"bundle-%d" % seed_byte).hexdigest()
    sig = _ed.sign_ph(seed, bytes.fromhex(digest))
    pem = _ab.anchor_spki_pem(_ed.publickey(seed))
    return (digest, base64.b64encode(sig).decode("ascii"), pem)


class TestFlag(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop("GOV_REKOR_V2_WITNESS", None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("GOV_REKOR_V2_WITNESS", None)
        else:
            os.environ["GOV_REKOR_V2_WITNESS"] = self._saved

    def test_default_off(self):
        self.assertFalse(w.witness_enabled())

    def test_env_spellings(self):
        for yes in ("1", "true", "TRUE", "yes", "Yes", "YES"):
            os.environ["GOV_REKOR_V2_WITNESS"] = yes
            self.assertTrue(w.witness_enabled(), yes)
        for no in ("0", "false", "no", "", "maybe"):
            os.environ["GOV_REKOR_V2_WITNESS"] = no
            self.assertFalse(w.witness_enabled(), no)

    def test_explicit_wins(self):
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        self.assertFalse(w.witness_enabled(explicit=False))
        self.assertFalse(w.witness_enabled(explicit=0))
        os.environ["GOV_REKOR_V2_WITNESS"] = "0"
        self.assertTrue(w.witness_enabled(explicit=True))


class TestDiscovery(unittest.TestCase):
    def test_v1_and_expired_skipped(self):
        doc = _doc(rekor=[
            {"url": "https://v1.example.invalid", "majorApiVersion": 1,
             "validFor": {"start": "2021-01-01T00:00:00Z"}},
            {"url": "https://old-v2.example.invalid", "majorApiVersion": 2,
             "logId": "00" * 32,
             "validFor": {"start": "2025-01-01T00:00:00Z",
                          "end": "2025-06-01T00:00:00Z"}},
            {"url": "https://new-v2.example.invalid", "majorApiVersion": 2,
             "logId": "ff" * 32,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ])
        from datetime import datetime, timezone
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        shard = w.discover_v2_shard(doc, now=now)
        self.assertEqual(shard["log_url"], "https://new-v2.example.invalid")
        self.assertEqual(shard["log_id"], "ff" * 32)

    def test_legacy_spellings(self):
        # v0.1 field names: baseUrl + apiVersion.
        doc = _doc(rekor=[
            {"baseUrl": "https://legacy.example.invalid/", "apiVersion": 2,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ])
        shard = w.discover_v2_shard(doc)
        self.assertEqual(shard["log_url"], "https://legacy.example.invalid")

    def test_window_boundaries(self):
        from datetime import datetime, timezone
        doc = _doc(rekor=[
            {"url": "https://w.example.invalid", "majorApiVersion": 2,
             "validFor": {"start": "2026-01-01T00:00:00Z",
                          "end": "2026-07-01T00:00:00Z"}},
        ])
        # Start inclusive, end exclusive.
        ok = w.discover_v2_shard(
            doc, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(ok["log_url"], "https://w.example.invalid")
        with self.assertRaises(w.ShardDiscoveryError):
            w.discover_v2_shard(
                doc, now=datetime(2026, 7, 1, tzinfo=timezone.utc))

    def test_no_v2_fail_closed(self):
        with self.assertRaises(w.ShardDiscoveryError):
            w.discover_v2_shard(_doc(rekor=[]))

    def test_no_tsa_fail_closed(self):
        with self.assertRaises(w.ShardDiscoveryError):
            w.discover_v2_shard(_doc(tsa=[]))

    def test_malformed_inputs(self):
        for bad in (None, 42, "", "not json", '{"rekor": 42}'):
            with self.assertRaises(w.ShardDiscoveryError):
                w.discover_v2_shard(bad)

    def test_json_string_accepted(self):
        shard = w.discover_v2_shard(json.dumps(_doc()))
        self.assertEqual(shard["log_url"],
                         "https://log2026-2.rekor.example.invalid")

    def test_log_id_derivations(self):
        # Explicit logId wins.
        shard = w.discover_v2_shard(_doc())
        self.assertEqual(shard["log_id"], "ab" * 32)
        # Else sha256(url) fallback is deterministic.
        doc = _doc(rekor=[
            {"url": "https://noid.example.invalid", "majorApiVersion": 2,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ])
        shard = w.discover_v2_shard(doc)
        want = hashlib.sha256(
            b"https://noid.example.invalid").hexdigest()
        self.assertEqual(shard["log_id"], want)


class TestAttach(unittest.TestCase):
    def test_record_shape(self):
        digest, sig, pem = _material()
        wit = w.RekorV2Witness(enabled=True, signing_config=_doc(),
                               clock=lambda: "2026-10-01T00:00:00Z")
        rec = wit.attach(digest, signature_b64=sig, pubkey_pem=pem)
        self.assertEqual(rec["witness"], "rekor-v2")
        self.assertEqual(rec["status"], "attached")
        self.assertEqual(rec["evidentiary_grade"], "digest-existence-only")
        self.assertIs(rec["authority_proof"], False)
        self.assertEqual(rec["log_generation"]["log_id"], "ab" * 32)
        self.assertEqual(rec["recorded_at"], "2026-10-01T00:00:00Z")
        self.assertEqual(rec["receipt"]["verification.source"],
                         "rekor-v2-hermetic")

    def test_digest_ref_accepted(self):
        digest, sig, pem = _material()
        wit = w.RekorV2Witness(enabled=True, signing_config=_doc())
        rec = wit.attach(DigestRef("sha256", digest), signature_b64=sig,
                         pubkey_pem=pem)
        self.assertEqual(rec["status"], "attached")

    def test_malformed_digest_is_failed_not_raised(self):
        _, sig, pem = _material()
        wit = w.RekorV2Witness(enabled=True, signing_config=_doc())
        rec = wit.attach("not-a-digest", signature_b64=sig,
                         pubkey_pem=pem)
        self.assertEqual(rec["status"], "failed")
        self.assertTrue(rec["reason"])

    def test_no_signing_config_is_failed(self):
        digest, sig, pem = _material()
        saved = os.environ.pop("GOV_REKOR_V2_SIGNING_CONFIG", None)
        try:
            wit = w.RekorV2Witness(enabled=True, signing_config=None)
            rec = wit.attach(digest, signature_b64=sig, pubkey_pem=pem)
        finally:
            if saved is not None:
                os.environ["GOV_REKOR_V2_SIGNING_CONFIG"] = saved
        self.assertEqual(rec["status"], "failed")
        self.assertIn("signing", rec["reason"].lower())

    def test_env_config_path(self):
        import tempfile
        digest, sig, pem = _material()
        path = os.path.join(tempfile.mkdtemp(dir=tempfile.gettempdir()),
                            "sc.json")  # wave-279 merge: was hardcoded to the wave-277 gate TMPDIR /var/tmp/g277-rekor (deleted); use the process TMPDIR
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(_doc(), fh)
        saved = os.environ.get("GOV_REKOR_V2_SIGNING_CONFIG")
        os.environ["GOV_REKOR_V2_SIGNING_CONFIG"] = path
        try:
            wit = w.RekorV2Witness(enabled=True)
            rec = wit.attach(digest, signature_b64=sig, pubkey_pem=pem)
        finally:
            if saved is None:
                os.environ.pop("GOV_REKOR_V2_SIGNING_CONFIG", None)
            else:
                os.environ["GOV_REKOR_V2_SIGNING_CONFIG"] = saved
        self.assertEqual(rec["status"], "attached")

    def test_disabled_property(self):
        wit = w.RekorV2Witness(enabled=False, signing_config=_doc())
        self.assertFalse(wit.enabled)


class TestRecordInMetadata(unittest.TestCase):
    def test_appends_and_returns(self):
        meta = {}
        rec = {"witness": "rekor-v2", "status": "failed", "reason": "x"}
        out = w.record_in_metadata(meta, rec)
        self.assertIs(out, meta)
        self.assertEqual(meta["witnesses"], [rec])
        # The stored record is a copy: later mutation is not aliased.
        rec["status"] = "attached"
        self.assertEqual(meta["witnesses"][0]["status"], "failed")

    def test_existing_list_extended(self):
        meta = {"witnesses": [{"witness": "local-anchor"}]}
        w.record_in_metadata(meta, {"witness": "rekor-v2"})
        self.assertEqual(len(meta["witnesses"]), 2)

    def test_shape_fail_closed(self):
        with self.assertRaises(TypeError):
            w.record_in_metadata([], {})
        with self.assertRaises(TypeError):
            w.record_in_metadata({}, [])
        with self.assertRaises(TypeError):
            w.record_in_metadata({"witnesses": {}}, {})


if __name__ == "__main__":
    unittest.main()
