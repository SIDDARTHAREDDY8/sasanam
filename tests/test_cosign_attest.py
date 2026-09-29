"""Unit tests for gov.cosign_attest (keyset-attested cosign signing).

Red-first companion to evals/cosign_attest_probes.py. All cosign CLI
interaction goes through tests/fake_cosign.py (zero network); no real
cosign binary is required. Key material is synthetic and deterministic
(SHA256 of probe tags); the only fixed key is a synthetic ECDSA-P256
*public* key whose private half was shredded at generation time.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from gov import cosign_attest as ca
from gov.keyset import (
    Keyset,
    KeysetError,
    new_keyset,
    rotate_keyset,
    revoke_version,
)

FAKE_COSIGN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fake_cosign.py")

# Fixed synthetic ECDSA-P256 public key (public material only).
TEST_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKufs+gu8Zcvi606EJlmckiTHVSF
iVzmhr2b6DwQyHF6I6cZ98Kui07xlRUp2PpWK+qkuO5VWZc+4QH2J269FQ==
-----END PUBLIC KEY-----
"""

# A different synthetic P-256 public key (the "attacker's"): valid P-256
# SPKI, different point (bytes flipped inside the uncompressed point of
# TEST_PEM), hence a different fingerprint. Public material only.
ATTACKER_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKuf6egu8Zcvi606EJlmckiTR1SF
iVzmhr2b6DwQyHF6I6cZ98Kui07xlU8p2PpWK+qkuO5VWZc+4QH2J269FQ==
-----END PUBLIC KEY-----
"""

# Ed25519 SPKI (wrong algorithm for the cosign seam -- must be refused).
ED25519_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGy8H0kF1FQJ7r7J6r7J6r7J6r7J6r7J6r7J6r7J6r7I=
-----END PUBLIC KEY-----
"""


def _seed(tag):
    return hashlib.sha256(("test-cosign-attest:" + tag).encode()).digest()


def _keyset(tag, purpose="cosign-key-attestation"):
    ks, _ = new_keyset(_seed(tag), purpose=purpose)
    return ks


def _attest(ks, tag, version=None):
    return ca.attest_cosign_key(ks, TEST_PEM, _seed(tag), version=version,
                                at=1700000000)


class TestPemHandling(unittest.TestCase):
    def test_fingerprint_derives_from_pem(self):
        fp = ca.cosign_key_fingerprint(TEST_PEM)
        self.assertEqual(
            fp,
            "sha256:f71df3a02336cd3a9d5fc065135bec358e6f0ef860748e3769e50deaa771149d")

    def test_non_p256_refused(self):
        with self.assertRaises(ca.CosignAttestationError):
            ca.cosign_key_fingerprint(ED25519_PEM)

    def test_malformed_pem_refused(self):
        for bad in ("not a pem",
                    "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----",
                    TEST_PEM.replace("BEGIN PUBLIC KEY",
                                     "BEGIN RSA PUBLIC KEY"),
                    12345):
            with self.assertRaises(ca.CosignAttestationError,
                                   msg="pem %r accepted" % (bad,)):
                ca.cosign_key_fingerprint(bad)

    def test_multi_block_refused(self):
        with self.assertRaises(ca.CosignAttestationError):
            ca.pem_to_der(TEST_PEM + TEST_PEM)


class TestMint(unittest.TestCase):
    def test_attestation_shape(self):
        ks = _keyset("mint-shape")
        att = _attest(ks, "mint-shape")
        self.assertEqual(att["format"], ca.ATTESTATION_FORMAT)
        self.assertEqual(att["cosign_public_key_pem"], TEST_PEM)
        self.assertEqual(att["cosign_key_fingerprint"],
                         ca.cosign_key_fingerprint(TEST_PEM))
        by = att["attested_by"]
        self.assertEqual(by["purpose"], "cosign-key-attestation")
        self.assertEqual(by["keyset_key_id"], ks.version(1).key_id)
        self.assertEqual(by["keyset_version"], 1)
        self.assertEqual(len(by["keyset_hash"]), 64)
        self.assertEqual(att["at"], 1700000000)
        env = att["envelope"]
        self.assertEqual(env["sig_key_id"], ks.version(1).key_id)
        self.assertEqual(env["sig_key_version"], 1)
        self.assertEqual(len(bytes.fromhex(env["sig"])), 64)

    def test_wrong_purpose_keyset_refused(self):
        ks = _keyset("mint-purpose", purpose="audit-entry-signing")
        with self.assertRaises(ca.CosignAttestationError) as cm:
            ca.attest_cosign_key(ks, TEST_PEM, _seed("mint-purpose"),
                                 at=1700000000)
        self.assertIn("purpose", str(cm.exception))

    def test_non_p256_pem_refused_at_mint(self):
        ks = _keyset("mint-p256")
        with self.assertRaises(ca.CosignAttestationError):
            ca.attest_cosign_key(ks, ED25519_PEM, _seed("mint-p256"),
                                 at=1700000000)

    def test_seed_mismatch_refused(self):
        ks = _keyset("mint-seed")
        with self.assertRaises(ca.CosignAttestationError):
            ca.attest_cosign_key(ks, TEST_PEM, _seed("mint-seed-WRONG"),
                                 at=1700000000)

    def test_revoked_seed_refused(self):
        ks1 = _keyset("mint-rev")
        ks2, _ = rotate_keyset(ks1, _seed("mint-rev2"), _seed("mint-rev"))
        ks3 = revoke_version(ks2, 1, "test compromise", _seed("mint-rev2"))
        with self.assertRaises(ca.CosignAttestationError) as cm:
            ca.attest_cosign_key(ks3, TEST_PEM, _seed("mint-rev"),
                                 version=1, at=1700000000)
        self.assertIn("revoked", str(cm.exception))

    def test_verify_only_seed_refused(self):
        ks1 = _keyset("mint-vo")
        ks2, _ = rotate_keyset(ks1, _seed("mint-vo2"), _seed("mint-vo"))
        with self.assertRaises(ca.CosignAttestationError) as cm:
            ca.attest_cosign_key(ks2, TEST_PEM, _seed("mint-vo"),
                                 version=1, at=1700000000)
        self.assertIn("verify-only", str(cm.exception))

    def test_keyset_hash_pins_live_document(self):
        ks = _keyset("mint-hash")
        att = _attest(ks, "mint-hash")
        self.assertEqual(att["attested_by"]["keyset_hash"],
                         ks.keyset_hash())

    def test_keyset_hash_survives_rotation_via_lineage(self):
        ks1 = _keyset("mint-hist")
        h1 = ks1.keyset_hash()
        ks2, _ = rotate_keyset(ks1, _seed("mint-hist2"), _seed("mint-hist"))
        # The full document hash changed...
        self.assertNotEqual(ks1.keyset_hash(), ks2.keyset_hash())
        # ...but the historical pin for v1 is the pre-rotation hash,
        # recovered from the lineage's prev_keyset_hash.
        self.assertEqual(ca.keyset_hash_at_version(ks2, 1), h1)
        self.assertEqual(
            ks2.to_dict()["rotation_lineage"][0]["prev_keyset_hash"], h1)
        att = _attest(ks1, "mint-hist")
        ok, info = ca.verify_attestation(att, ks2.to_dict())
        self.assertTrue(ok, info)

    def test_keyset_hash_unknown_version(self):
        ks = _keyset("mint-unk")
        with self.assertRaises(KeysetError):
            ca.keyset_hash_at_version(ks, 99)


class TestVerify(unittest.TestCase):
    def test_happy_path(self):
        ks = _keyset("verify-happy")
        att = _attest(ks, "verify-happy")
        ok, info = ca.verify_attestation(att, ks.to_dict())
        self.assertTrue(ok, info)
        self.assertEqual(info["keyset_version"], 1)
        self.assertEqual(info["status"], "active")

    def test_format_exact_match(self):
        ks = _keyset("verify-fmt")
        att = _attest(ks, "verify-fmt")
        for bad_fmt in ("sasanam-cosign-key-attestation/v1.1",
                        "sasanam-cosign-key-attestation/v2",
                        "SASANAM-COSIGN-KEY-ATTESTATION/V1"):
            evil = copy.deepcopy(att)
            evil["format"] = bad_fmt
            ok, info = ca.verify_attestation(evil, ks.to_dict())
            self.assertFalse(ok, "format %r accepted" % bad_fmt)
            self.assertIn("format", info)

    def test_unknown_fields_refused(self):
        ks = _keyset("verify-unknown")
        att = _attest(ks, "verify-unknown")
        evil = copy.deepcopy(att)
        evil["extra"] = "nope"
        ok, _ = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)

    def test_missing_envelope_refused(self):
        ks = _keyset("verify-noenv")
        att = _attest(ks, "verify-noenv")
        evil = copy.deepcopy(att)
        del evil["envelope"]
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("envelope", info)

    def test_envelope_attested_by_mismatch_refused(self):
        ks = _keyset("verify-mismatch")
        att = _attest(ks, "verify-mismatch")
        evil = copy.deepcopy(att)
        evil["envelope"]["sig_key_version"] = 999
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("mismatch", info)

    def test_tampered_signature_refused(self):
        ks = _keyset("verify-tamper")
        att = _attest(ks, "verify-tamper")
        evil = copy.deepcopy(att)
        sig = bytearray(bytes.fromhex(evil["envelope"]["sig"]))
        sig[0] ^= 0x01
        evil["envelope"]["sig"] = bytes(sig).hex()
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", info)

    def test_wrong_domain_refused(self):
        # A statement signed under a different domain must not verify
        # under the v1 domain, even with a valid keyset key.
        from gov import ed25519 as _ed
        ks = _keyset("verify-domain")
        att = _attest(ks, "verify-domain")
        stmt = {k: v for k, v in att.items() if k != "envelope"}
        body = json.dumps(stmt, sort_keys=True,
                          separators=(",", ":"),
                          ensure_ascii=True).encode()
        evil_sig = _ed.sign(_seed("verify-domain"),
                            b"sasanam-cosign-key-attestation/v2\x00" + body)
        evil = copy.deepcopy(att)
        evil["envelope"]["sig"] = evil_sig.hex()
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("signature", info)

    def test_attacker_pem_stale_fingerprint(self):
        ks = _keyset("verify-r5a")
        att = _attest(ks, "verify-r5a")
        evil = copy.deepcopy(att)
        evil["cosign_public_key_pem"] = ATTACKER_PEM
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok, "attacker PEM + stale fingerprint verified")
        self.assertIn("signature", info)

    def test_attacker_pem_fresh_fingerprint(self):
        ks = _keyset("verify-r5b")
        att = _attest(ks, "verify-r5b")
        evil = copy.deepcopy(att)
        evil["cosign_public_key_pem"] = ATTACKER_PEM
        evil["cosign_key_fingerprint"] = ca.cosign_key_fingerprint(
            ATTACKER_PEM)
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok, "attacker PEM + fresh fingerprint verified")
        self.assertIn("signature", info)

    def test_keyset_hash_pin(self):
        ks = _keyset("verify-hash")
        att = _attest(ks, "verify-hash")
        evil = copy.deepcopy(att)
        # Re-sign with the tampered hash so the failure is pinned to
        # the hash check, not the signature.
        from gov import ed25519 as _ed
        evil["attested_by"]["keyset_hash"] = "00" * 32
        stmt = {k: v for k, v in evil.items() if k != "envelope"}
        body = json.dumps(stmt, sort_keys=True,
                          separators=(",", ":"),
                          ensure_ascii=True).encode()
        evil["envelope"]["sig"] = _ed.sign(
            _seed("verify-hash"), ca.ATTESTATION_DOMAIN + body).hex()
        ok, info = ca.verify_attestation(evil, ks.to_dict())
        self.assertFalse(ok)
        self.assertIn("keyset_hash", info)

    def test_verify_only_verifies(self):
        ks1 = _keyset("verify-rot")
        att = _attest(ks1, "verify-rot")
        ks2, _ = rotate_keyset(ks1, _seed("verify-rot2"), _seed("verify-rot"))
        ok, info = ca.verify_attestation(att, ks2.to_dict())
        self.assertTrue(ok, info)
        self.assertEqual(info["status"], "verify-only")

    def test_revoked_refuses_authorization(self):
        ks1 = _keyset("verify-rev")
        att = _attest(ks1, "verify-rev")
        ks2, _ = rotate_keyset(ks1, _seed("verify-rev2"), _seed("verify-rev"))
        ks3 = revoke_version(ks2, 1, "test compromise", _seed("verify-rev2"))
        ok, info = ca.verify_attestation(att, ks3.to_dict())
        self.assertFalse(ok)
        self.assertIn("revoked", info)

    def test_revoked_verifies_forensics(self):
        ks1 = _keyset("verify-for")
        att = _attest(ks1, "verify-for")
        ks2, _ = rotate_keyset(ks1, _seed("verify-for2"), _seed("verify-for"))
        ks3 = revoke_version(ks2, 1, "test compromise", _seed("verify-for2"))
        ok, info = ca.verify_attestation(att, ks3.to_dict(),
                                         forensics=True)
        self.assertTrue(ok, info)
        self.assertEqual(info["status"], "revoked")

    def test_broken_lineage_refused(self):
        ks1 = _keyset("verify-lin")
        att = _attest(ks1, "verify-lin")
        ks2, _ = rotate_keyset(ks1, _seed("verify-lin2"), _seed("verify-lin"))
        doc = ks2.to_dict()
        doc["rotation_lineage"][0]["sig"] = "00" * 64
        ok, info = ca.verify_attestation(att, doc)
        self.assertFalse(ok)
        self.assertIn("lineage", info)


class TestCliSurface(unittest.TestCase):
    def _keyfile(self, td):
        p = os.path.join(td, "cosign.key")
        with open(p, "wb") as f:
            f.write(b"test-cli-key")
        return p

    def test_sign_returns_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            bundle = ca.sign_bundle_blob(b"cli-tar-bytes" * 32,
                                         self._keyfile(td),
                                         cosign_bin=FAKE_COSIGN)
            doc = json.loads(bundle.decode())
            self.assertTrue(doc.get("fakeCosignBundle"))

    def test_sign_offline_flag_in_argv(self):
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "argv.log")
            old = os.environ.get("FAKE_COSIGN_ARGV_LOG")
            os.environ["FAKE_COSIGN_ARGV_LOG"] = log
            try:
                ca.sign_bundle_blob(b"cli-flag-tar" * 32,
                                    self._keyfile(td),
                                    cosign_bin=FAKE_COSIGN)
            finally:
                if old is None:
                    os.environ.pop("FAKE_COSIGN_ARGV_LOG", None)
                else:
                    os.environ["FAKE_COSIGN_ARGV_LOG"] = old
            sign_argv = None
            with open(log, encoding="utf-8") as f:
                for line in f:
                    argv = json.loads(line)
                    if len(argv) > 1 and argv[1] == "sign-blob":
                        sign_argv = argv
            self.assertIsNotNone(sign_argv)
            self.assertIn("--use-signing-config=false", sign_argv)

    def test_sign_empty_tar_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ca.CosignAttestationError):
                ca.sign_bundle_blob(b"", self._keyfile(td),
                                    cosign_bin=FAKE_COSIGN)

    def test_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            tar = b"cli-roundtrip-tar" * 32
            bundle = ca.sign_bundle_blob(tar, self._keyfile(td),
                                         cosign_bin=FAKE_COSIGN)
            ok, reason = ca.verify_bundle_blob(tar, bundle, TEST_PEM,
                                               cosign_bin=FAKE_COSIGN)
            self.assertTrue(ok, reason)

    def test_verify_tampered_refused(self):
        with tempfile.TemporaryDirectory() as td:
            tar = bytearray(b"cli-tamper-tar" * 32)
            bundle = ca.sign_bundle_blob(bytes(tar), self._keyfile(td),
                                         cosign_bin=FAKE_COSIGN)
            tar[5] ^= 0x01
            ok, reason = ca.verify_bundle_blob(bytes(tar), bundle,
                                               TEST_PEM,
                                               cosign_bin=FAKE_COSIGN)
            self.assertFalse(ok)
            self.assertIn("refused", reason)

    def test_verify_bad_pem_never_shells(self):
        ok, reason = ca.verify_bundle_blob(b"tar", b"{}", ED25519_PEM,
                                           cosign_bin=FAKE_COSIGN)
        self.assertFalse(ok)
        self.assertIn("P-256", reason)

    def test_cli_timeout_fails_closed(self):
        # A cosign binary that hangs (e.g. blocked on a Rekor upload
        # where the transparency log is unreachable -- verified
        # 2026-09-29 against cosign v3.1.3) must fail LOUD and closed,
        # never hang the caller.
        with tempfile.TemporaryDirectory() as td:
            hang = os.path.join(td, "hang.sh")
            with open(hang, "w") as f:
                f.write("#!/bin/sh\nsleep 30\n")
            os.chmod(hang, 0o755)
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.sign_bundle_blob(b"timeout-tar" * 32,
                                    self._keyfile(td),
                                    cosign_bin=hang, timeout=2)
            self.assertIn("timed out", str(cm.exception))


class TestPipeline(unittest.TestCase):
    def _setup(self, td, tag="pipe"):
        ks = _keyset(tag)
        att = ca.attest_cosign_key(ks, TEST_PEM, _seed(tag), at=1700000000)
        tar = b"pipeline-tar-%s" % tag.encode() * 32
        bundle = ca.sign_bundle_blob(tar, self._keyfile(td),
                                     cosign_bin=FAKE_COSIGN)
        return ks, att, tar, bundle

    def _keyfile(self, td):
        p = os.path.join(td, "cosign.key")
        with open(p, "wb") as f:
            f.write(b"test-pipe-key")
        return p

    def test_authorize_verified(self):
        with tempfile.TemporaryDirectory() as td:
            ks, att, tar, bundle = self._setup(td)
            verdict = ca.authorize_bundle_signature(
                tar, bundle, att, ks.to_dict(), ks.version(1).key_id,
                cosign_bin=FAKE_COSIGN)
            self.assertEqual(verdict["verdict"], "VERIFIED")
            self.assertFalse(verdict["forensics"])

    def test_no_pin_refuses_to_start(self):
        with tempfile.TemporaryDirectory() as td:
            ks, att, tar, bundle = self._setup(td)
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.authorize_bundle_signature(
                    tar, bundle, att, ks.to_dict(), "",
                    cosign_bin=FAKE_COSIGN)
            self.assertIn("AUDIT FAILED", str(cm.exception))
            self.assertIn("pin", str(cm.exception))

    def test_foreign_genesis_refused_at_pin(self):
        with tempfile.TemporaryDirectory() as td:
            ks, att, tar, bundle = self._setup(td, "pipe-a")
            other = _keyset("pipe-b")
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.authorize_bundle_signature(
                    tar, bundle, att, other.to_dict(),
                    ks.version(1).key_id, cosign_bin=FAKE_COSIGN)
            self.assertIn("genesis", str(cm.exception).lower())

    def test_tampered_tar_audit_failed(self):
        with tempfile.TemporaryDirectory() as td:
            ks, att, tar, bundle = self._setup(td)
            bad = bytearray(tar)
            bad[3] ^= 0x01
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.authorize_bundle_signature(
                    bytes(bad), bundle, att, ks.to_dict(),
                    ks.version(1).key_id, cosign_bin=FAKE_COSIGN)
            self.assertIn("AUDIT FAILED", str(cm.exception))
            self.assertIn("refused", str(cm.exception))

    def test_revoked_authorize_refuses_forensics_attributes(self):
        with tempfile.TemporaryDirectory() as td:
            ks1 = _keyset("pipe-rev")
            att = ca.attest_cosign_key(ks1, TEST_PEM, _seed("pipe-rev"),
                                       at=1700000000)
            ks2, _ = rotate_keyset(ks1, _seed("pipe-rev2"),
                                   _seed("pipe-rev"))
            ks3 = revoke_version(ks2, 1, "test compromise",
                                 _seed("pipe-rev2"))
            tar = b"pipe-rev-tar" * 32
            bundle = ca.sign_bundle_blob(tar, self._keyfile(td),
                                         cosign_bin=FAKE_COSIGN)
            pin = ks3.version(1).key_id
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.authorize_bundle_signature(
                    tar, bundle, att, ks3.to_dict(), pin,
                    cosign_bin=FAKE_COSIGN)
            self.assertIn("revoked", str(cm.exception))
            verdict = ca.attribute_bundle_signature(
                tar, bundle, att, ks3.to_dict(), pin,
                cosign_bin=FAKE_COSIGN)
            self.assertEqual(verdict["verdict"], "VERIFIED")
            self.assertTrue(verdict["forensics"])

    def test_paths_are_distinct_callables(self):
        self.assertIsNot(ca.authorize_bundle_signature,
                         ca.attribute_bundle_signature)
        self.assertNotEqual(ca.authorize_bundle_signature.__name__,
                            ca.attribute_bundle_signature.__name__)

    def test_pem_comes_from_attestation(self):
        # The pipeline writes the attestation's own PEM to the CLI --
        # proved by a forged-pem attestation failing before cosign runs.
        with tempfile.TemporaryDirectory() as td:
            ks, att, tar, bundle = self._setup(td)
            evil = copy.deepcopy(att)
            evil["cosign_public_key_pem"] = ATTACKER_PEM
            with self.assertRaises(ca.CosignAttestationError) as cm:
                ca.authorize_bundle_signature(
                    tar, bundle, evil, ks.to_dict(),
                    ks.version(1).key_id, cosign_bin=FAKE_COSIGN)
            self.assertIn("attestation", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
