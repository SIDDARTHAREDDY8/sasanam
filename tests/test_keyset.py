"""Wave-183: regression tests for versioned signing keysets.

Covers the public seams of ``gov/keyset.py`` and its integration with
the audit/evidence signing path (``gov/log.py``, ``gov/evidence_bundle.py``,
``gov/evidence_verify.py`` V9d):

  * genesis / rotation / revocation rituals (Tink KeysetHandle pattern,
    stdlib-only; no Tink code vendored)
  * fail-closed parsing of keyset documents
  * the trust-directory lookup (Keyset.find_verifying_key)
  * KeysetSigner as a gov.signing.Signer
  * config resolution (GOV_AUDIT_KEYSET_FILE) and open_audit_log wiring
  * version binding in entry envelopes (tamper/strip fail closed)
  * legacy (unversioned) entries keep verifying; HMAC/Merkle unchanged
  * signed-body byte-equivalence across the three implementations
    (gov/log.py, gov/evidence_verify.py, tools/offline-verify)
  * evidence-bundle seal(entry_keyset=...) + V9d revocation enforcement

Deterministic: all Ed25519 seeds derive from SHA256(test tags); the
HMAC chain key comes from tests/keyfixture.py (explicit production
env-backend path). ``GOV_DEPLOYMENT_MODE=staging`` at module level per
the wave-95 convention.
"""

import hashlib
import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               ".."))

from gov import ed25519 as _ed
from gov import keyset as ks
from gov import log as _log
from gov import evidence_verify as _ev
from gov.signing import Signer, Ed25519Signer, ed25519_key_id

from tests.keyfixture import provision_test_key, scrub_key_env


def _seed(tag):
    return hashlib.sha256(("wave183-test-keyset:" + tag).encode()).digest()


_AUDIT_VARS = ("GOV_AUDIT_SIGNING_KEY", "GOV_AUDIT_SIGNING_KEY_FILE",
               "GOV_AUDIT_KEYSET_FILE")


class _KeysetTestBase(unittest.TestCase):
    def setUp(self):
        self._saved = {n: os.environ.get(n) for n in _AUDIT_VARS}
        for n in _AUDIT_VARS:
            os.environ.pop(n, None)
        self._restore_key = scrub_key_env()
        provision_test_key()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()
        self._restore_key()
        for n, v in self._saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    def _log(self, signer, name="a.jsonl"):
        return _log.ActionLog(os.path.join(self.tmp.name, name),
                              signer=signer)


# ---------------------------------------------------------------------------
# Genesis
# ---------------------------------------------------------------------------

class TestKeysetGenesis(_KeysetTestBase):
    def test_genesis_shape(self):
        keyset, signer = ks.new_keyset(_seed("genesis"))
        self.assertEqual(keyset.primary_version, 1)
        self.assertEqual([v.version for v in keyset.versions], [1])
        self.assertEqual(keyset.versions[0].status, ks.STATUS_ACTIVE)
        self.assertEqual(signer.key_version, 1)
        self.assertEqual(signer.key_id, keyset.versions[0].key_id)
        self.assertEqual(signer.public_key, keyset.versions[0].public_key)
        ok, err = keyset.verify()
        self.assertTrue(ok, err)

    def test_genesis_doc_round_trip(self):
        keyset, _ = ks.new_keyset(_seed("genesis-rt"))
        doc = keyset.to_dict()
        self.assertEqual(doc["format"], ks.KEYSET_FORMAT)
        rt = ks.Keyset.from_dict(json.loads(json.dumps(doc)))
        self.assertEqual(rt.keyset_hash(), keyset.keyset_hash())

    def test_genesis_bad_seed(self):
        with self.assertRaises(ks.KeysetError):
            ks.new_keyset(b"too short")
        with self.assertRaises(ks.KeysetError):
            ks.new_keyset("not-bytes")

    def test_genesis_bad_purpose(self):
        with self.assertRaises(ks.KeysetError):
            ks.new_keyset(_seed("genesis-p"), purpose="")


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

class TestKeysetRotation(_KeysetTestBase):
    def test_rotation_ritual(self):
        k1, s1 = ks.new_keyset(_seed("rot-v1"))
        k2, s2 = ks.rotate_keyset(k1, _seed("rot-v2"), _seed("rot-v1"))
        self.assertEqual(k2.primary_version, 2)
        self.assertEqual(k2.version(1).status, ks.STATUS_VERIFY_ONLY)
        self.assertEqual(k2.version(2).status, ks.STATUS_ACTIVE)
        self.assertEqual(s2.key_version, 2)
        ok, err = k2.verify()
        self.assertTrue(ok, err)
        # Lineage record: authorized by the previous primary.
        rec = k2.to_dict()["rotation_lineage"][0]
        self.assertEqual((rec["from_version"], rec["to_version"]), (1, 2))
        self.assertEqual(rec["from_key_id"], k1.version(1).key_id)
        self.assertEqual(rec["to_key_id"], k2.version(2).key_id)
        body = ks.ROTATION_DOMAIN + ks.rotation_statement(
            1, 2, rec["from_key_id"], rec["to_key_id"],
            rec["to_public_key_hex"], rec["prev_keyset_hash"], at=rec["at"])
        self.assertTrue(_ed.verify(k1.version(1).public_key, body,
                                   bytes.fromhex(rec["sig"])))
        # The old keyset is untouched (rotation returns a new object).
        self.assertEqual(k1.primary_version, 1)

    def test_rotation_chains(self):
        k1, _ = ks.new_keyset(_seed("chain-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("chain-v2"), _seed("chain-v1"))
        k3, _ = ks.rotate_keyset(k2, _seed("chain-v3"), _seed("chain-v2"))
        ok, err = k3.verify()
        self.assertTrue(ok, err)
        self.assertEqual(k3.primary_version, 3)
        self.assertEqual(len(k3.to_dict()["rotation_lineage"]), 2)

    def test_rotation_wrong_old_seed(self):
        k1, _ = ks.new_keyset(_seed("rotw-v1"))
        with self.assertRaises(ks.KeysetError):
            ks.rotate_keyset(k1, _seed("rotw-v2"), _seed("rotw-evil"))

    def test_rotation_key_reuse_forbidden(self):
        k1, _ = ks.new_keyset(_seed("reuse-v1"))
        with self.assertRaises(ks.KeysetError):
            # Same seed as v1: key reuse across versions is forbidden.
            ks.rotate_keyset(k1, _seed("reuse-v1"), _seed("reuse-v1"))

    def test_rotation_from_invalid_keyset(self):
        k1, _ = ks.new_keyset(_seed("roti-v1"))
        doc = k1.to_dict()
        doc["rotation_lineage"].append({"bogus": True})
        # from_dict is structural-only; verify() catches the lineage gap.
        bad = ks.Keyset.from_dict(doc)
        ok, _ = bad.verify()
        self.assertFalse(ok)
        with self.assertRaises(ks.KeysetError):
            ks.rotate_keyset(bad, _seed("roti-v2"), _seed("roti-v1"))

    def test_rotation_bad_new_seed(self):
        k1, _ = ks.new_keyset(_seed("rotn-v1"))
        with self.assertRaises(ks.KeysetError):
            ks.rotate_keyset(k1, b"short", _seed("rotn-v1"))


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestKeysetRevocation(_KeysetTestBase):
    def _three(self):
        k1, _ = ks.new_keyset(_seed("rev-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("rev-v2"), _seed("rev-v1"))
        k3, s3 = ks.rotate_keyset(k2, _seed("rev-v3"), _seed("rev-v2"))
        return k3, s3

    def test_revoke_compromised(self):
        k3, _ = self._three()
        k4 = ks.revoke_version(k3, 2, "suspected compromise",
                               _seed("rev-v3"))
        self.assertEqual(k4.version(2).status, ks.STATUS_REVOKED)
        self.assertEqual(k4.primary_version, 3)
        ok, err = k4.verify()
        self.assertTrue(ok, err)
        rec = k4.to_dict()["revocations"][0]
        self.assertEqual(rec["revoked_by_version"], 3)
        body = ks.REVOKE_DOMAIN + ks.revocation_statement(
            2, rec["key_id"], rec["reason"], 3,
            rec["revoked_by_key_id"], rec["keyset_hash"], at=rec["at"])
        self.assertTrue(_ed.verify(k4.version(3).public_key, body,
                                   bytes.fromhex(rec["sig"])))

    def test_revoke_primary_refused(self):
        k3, _ = self._three()
        with self.assertRaises(ks.KeysetError):
            ks.revoke_version(k3, 3, "oops", _seed("rev-v3"))

    def test_revoke_unknown_version(self):
        k3, _ = self._three()
        with self.assertRaises(ks.KeysetError):
            ks.revoke_version(k3, 99, "nope", _seed("rev-v3"))

    def test_revoke_twice_refused(self):
        k3, _ = self._three()
        k4 = ks.revoke_version(k3, 1, "compromised", _seed("rev-v3"))
        with self.assertRaises(ks.KeysetError):
            ks.revoke_version(k4, 1, "again", _seed("rev-v3"))

    def test_revoke_empty_reason_refused(self):
        k3, _ = self._three()
        with self.assertRaises(ks.KeysetError):
            ks.revoke_version(k3, 1, "   ", _seed("rev-v3"))

    def test_revoke_wrong_primary_seed(self):
        k3, _ = self._three()
        with self.assertRaises(ks.KeysetError):
            ks.revoke_version(k3, 1, "compromised", _seed("rev-evil"))

    def test_revoked_version_has_no_lineage_gap(self):
        # Revoking v1 after two rotations: lineage still verifies.
        k3, _ = self._three()
        k4 = ks.revoke_version(k3, 1, "compromised", _seed("rev-v3"))
        ok, err = k4.verify()
        self.assertTrue(ok, err)


# ---------------------------------------------------------------------------
# Parsing (fail-closed)
# ---------------------------------------------------------------------------

class TestKeysetParsing(_KeysetTestBase):
    def _doc(self):
        k1, _ = ks.new_keyset(_seed("parse-v1"))
        return k1.to_dict()

    def test_rejects(self):
        cases = []
        d = self._doc()
        d["format"] = "something-else"
        cases.append(d)
        d = self._doc()
        d["versions"] = []
        cases.append(d)
        d = self._doc()
        d["versions"][0]["status"] = "active"
        d["versions"].append(dict(d["versions"][0], version=2,
                                 status="active"))
        d["primary_version"] = 2  # two actives
        cases.append(d)
        d = self._doc()
        d["versions"][0]["key_id"] = "00" * 8  # key_id/pubkey mismatch
        cases.append(d)
        d = self._doc()
        d["mystery"] = 1  # unknown top-level field
        cases.append(d)
        d = self._doc()
        d["versions"][0]["label"] = "v1"  # unknown version field
        cases.append(d)
        d = self._doc()
        d["versions"].append(dict(d["versions"][0], version=3))  # non-dense
        cases.append(d)
        d = self._doc()
        d["primary_version"] = 99
        cases.append(d)
        for i, bad in enumerate(cases):
            with self.assertRaises(ks.KeysetError, msg="case %d" % i):
                ks.Keyset.from_dict(bad)

    def test_not_a_mapping(self):
        with self.assertRaises(ks.KeysetError):
            ks.Keyset.from_dict([1, 2, 3])

    def test_forged_lineage_rejected(self):
        k1, _ = ks.new_keyset(_seed("fl-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("fl-v2"), _seed("fl-v1"))
        doc = k2.to_dict()
        evil_pub = _ed.publickey(_seed("fl-evil"))
        rec = dict(doc["rotation_lineage"][0])
        rec["to_public_key_hex"] = evil_pub.hex()
        rec["to_key_id"] = ed25519_key_id(evil_pub)
        stmt = ks.rotation_statement(
            1, 2, k1.version(1).key_id, rec["to_key_id"],
            rec["to_public_key_hex"], k1.keyset_hash(), at=rec["at"])
        rec["sig"] = _ed.sign(_seed("fl-evil"),
                              ks.ROTATION_DOMAIN + stmt).hex()
        doc["rotation_lineage"] = [rec]
        doc["versions"][1]["public_key_hex"] = evil_pub.hex()
        doc["versions"][1]["key_id"] = rec["to_key_id"]
        evil = ks.Keyset.from_dict(doc)
        ok, err = evil.verify()
        self.assertFalse(ok, "forged lineage verified: %s" % err)

    def test_missing_lineage_rejected(self):
        k1, _ = ks.new_keyset(_seed("ml-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("ml-v2"), _seed("ml-v1"))
        doc = k2.to_dict()
        doc["rotation_lineage"] = []
        bad = ks.Keyset.from_dict(doc)
        ok, _ = bad.verify()
        self.assertFalse(ok)

    def test_revocation_record_without_revoked_status(self):
        k1, _ = ks.new_keyset(_seed("rr-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("rr-v2"), _seed("rr-v1"))
        k3 = ks.revoke_version(k2, 1, "compromised", _seed("rr-v2"))
        doc = k3.to_dict()
        doc["versions"][0]["status"] = ks.STATUS_VERIFY_ONLY  # lie
        bad = ks.Keyset.from_dict(doc)
        ok, _ = bad.verify()
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Trust-directory lookup
# ---------------------------------------------------------------------------

class TestFindVerifyingKey(_KeysetTestBase):
    def _ks3_revoked_v2(self):
        k1, _ = ks.new_keyset(_seed("fvk-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("fvk-v2"), _seed("fvk-v1"))
        k3, _ = ks.rotate_keyset(k2, _seed("fvk-v3"), _seed("fvk-v2"))
        return ks.revoke_version(k3, 2, "compromised", _seed("fvk-v3"))

    def _entry(self, keyset, version):
        kv = keyset.version(version)
        e = {"sig_key_id": kv.key_id, "ed_sig": "00" * 64}
        if version is not None:
            e["sig_key_version"] = version
        return e

    def test_versioned_ok(self):
        k4 = self._ks3_revoked_v2()
        kv, reason = k4.find_verifying_key(self._entry(k4, 3))
        self.assertIsNotNone(kv)
        self.assertEqual(kv.version, 3)

    def test_verify_only_ok(self):
        k4 = self._ks3_revoked_v2()
        kv, _ = k4.find_verifying_key(self._entry(k4, 1))
        self.assertIsNotNone(kv)
        self.assertEqual(kv.version, 1)

    def test_revoked_refused(self):
        k4 = self._ks3_revoked_v2()
        kv, reason = k4.find_verifying_key(self._entry(k4, 2))
        self.assertIsNone(kv)
        self.assertIn("revoked", reason)

    def test_legacy_path(self):
        k4 = self._ks3_revoked_v2()
        # Legacy lookup is by key id: v1's key id with no version.
        e = {"sig_key_id": k4.version(1).key_id, "ed_sig": "00" * 64}
        kv, reason = k4.find_verifying_key(e)
        self.assertIsNotNone(kv)
        self.assertEqual(kv.version, 1)
        self.assertIn("legacy", reason)

    def test_legacy_revoked_refused(self):
        k4 = self._ks3_revoked_v2()
        e = {"sig_key_id": k4.version(2).key_id, "ed_sig": "00" * 64}
        kv, reason = k4.find_verifying_key(e)
        self.assertIsNone(kv)
        self.assertIn("revoked", reason)

    def test_legacy_unknown_key(self):
        k4 = self._ks3_revoked_v2()
        e = {"sig_key_id": "ff" * 8, "ed_sig": "00" * 64}
        kv, _ = k4.find_verifying_key(e)
        self.assertIsNone(kv)

    def test_confusion(self):
        k4 = self._ks3_revoked_v2()
        e = self._entry(k4, 3)
        e["sig_key_id"] = k4.version(1).key_id  # version 3, v1's key id
        kv, reason = k4.find_verifying_key(e)
        self.assertIsNone(kv)
        self.assertIn("mismatch", reason)

    def test_unknown_version(self):
        k4 = self._ks3_revoked_v2()
        e = self._entry(k4, 3)
        e["sig_key_version"] = 99
        kv, _ = k4.find_verifying_key(e)
        self.assertIsNone(kv)

    def test_non_integer_version(self):
        k4 = self._ks3_revoked_v2()
        for bad in ("3", 3.0, True, -1, 0):
            e = self._entry(k4, 3)
            e["sig_key_version"] = bad
            kv, _ = k4.find_verifying_key(e)
            self.assertIsNone(kv, "version %r" % (bad,))

    def test_malformed_envelopes(self):
        k4 = self._ks3_revoked_v2()
        for bad in (None, [], "x", {}, {"sig_key_id": ""},
                    {"sig_key_version": 3}):
            kv, _ = k4.find_verifying_key(bad)
            self.assertIsNone(kv, "entry %r" % (bad,))


# ---------------------------------------------------------------------------
# KeysetSigner as a gov.signing.Signer
# ---------------------------------------------------------------------------

class TestKeysetSigner(_KeysetTestBase):
    def test_satisfies_signer_abc(self):
        _, signer = ks.new_keyset(_seed("abc-v1"))
        self.assertIsInstance(signer, Signer)
        sig = signer.sign(b"hello")
        self.assertEqual(len(sig), 64)
        self.assertTrue(_ed.verify(signer.public_key, b"hello", sig))

    def test_bad_version(self):
        with self.assertRaises(ks.KeysetError):
            ks.KeysetSigner(_seed("abcv-v1"), 0)
        with self.assertRaises(ks.KeysetError):
            ks.KeysetSigner(_seed("abcv-v1"), "1")

    def test_signer_for_version_gates(self):
        k1, _ = ks.new_keyset(_seed("gate-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("gate-v2"), _seed("gate-v1"))
        # Verify-only version: no signing handle.
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_for_version(k2, 1, _seed("gate-v1"))
        # Wrong seed for the active version: no signing handle.
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_for_version(k2, 2, _seed("gate-evil"))
        # Unknown version.
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_for_version(k2, 9, _seed("gate-v2"))
        # Happy path.
        s2 = ks.keyset_signer_for_version(k2, 2, _seed("gate-v2"))
        self.assertEqual(s2.key_version, 2)


# ---------------------------------------------------------------------------
# Config resolution + open_audit_log wiring
# ---------------------------------------------------------------------------

class TestKeysetConfig(_KeysetTestBase):
    def _write_keyset(self, keyset, name="keyset.json"):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(keyset.to_dict(), f)
        return path

    def test_unset_falls_back(self):
        self.assertEqual(ks.keyset_signer_from_config(), (None, None))

    def test_round_trip(self):
        k1, _ = ks.new_keyset(_seed("cfg-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("cfg-v2"), _seed("cfg-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k2)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfg-v2").hex()
        got_ks, signer = ks.keyset_signer_from_config()
        self.assertEqual(got_ks.keyset_hash(), k2.keyset_hash())
        self.assertEqual(signer.key_version, 2)

    def test_seed_mismatch_loud(self):
        k1, _ = ks.new_keyset(_seed("cfgm-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("cfgm-v2"), _seed("cfgm-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k2)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgm-v1").hex()  # stale
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_from_config()

    def test_missing_seed_loud(self):
        k1, _ = ks.new_keyset(_seed("cfgn-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k1)
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_from_config()

    def test_bad_keyset_file_loud(self):
        path = os.path.join(self.tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        os.environ["GOV_AUDIT_KEYSET_FILE"] = path
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgb-v1").hex()
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_from_config()

    def test_missing_keyset_file_loud(self):
        os.environ["GOV_AUDIT_KEYSET_FILE"] = os.path.join(
            self.tmp.name, "nope.json")
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgq-v1").hex()
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_from_config()

    def test_wrong_purpose_loud(self):
        keyset, _ = ks.new_keyset(_seed("cfgp-v1"),
                                  purpose="receipt-signing")
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(keyset)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgp-v1").hex()
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_from_config()

    def test_open_audit_log_uses_keyset(self):
        k1, _ = ks.new_keyset(_seed("cfgo-v1"))
        k2, _ = ks.rotate_keyset(k1, _seed("cfgo-v2"), _seed("cfgo-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k2)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgo-v2").hex()
        alog = _log.open_audit_log(os.path.join(self.tmp.name, "k.jsonl"))
        e = alog.append({"event": "x"})
        self.assertEqual(e.get("sig_key_version"), 2)
        ok, _ = _log.verify_entry_against_keyset(e, k2)
        self.assertTrue(ok)

    def test_open_audit_log_mismatch_loud(self):
        k1, _ = ks.new_keyset(_seed("cfgo2-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k1)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgo2-evil").hex()
        with self.assertRaises(ks.KeysetError):
            _log.open_audit_log(os.path.join(self.tmp.name, "k.jsonl"))

    def test_open_audit_log_legacy_unchanged(self):
        # No keyset configured: the legacy single-seed path is untouched.
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfgl-v1").hex()
        alog = _log.open_audit_log(os.path.join(self.tmp.name, "l.jsonl"))
        e = alog.append({"event": "x"})
        self.assertNotIn("sig_key_version", e)
        self.assertIsInstance(e.get("sig_key_id"), str)

    def test_open_audit_log_explicit_signer_wins(self):
        k1, _ = ks.new_keyset(_seed("cfge-v1"))
        os.environ["GOV_AUDIT_KEYSET_FILE"] = self._write_keyset(k1)
        os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("cfge-v1").hex()
        alog = _log.open_audit_log(os.path.join(self.tmp.name, "e.jsonl"),
                                   signer=None)
        e = alog.append({"event": "x"})
        self.assertNotIn("ed_sig", e)  # explicit None respected


# ---------------------------------------------------------------------------
# Entry verification (version binding at the signing seam)
# ---------------------------------------------------------------------------

class TestEntryVerification(_KeysetTestBase):
    def _keyset2(self):
        k1, s1 = ks.new_keyset(_seed("ev-v1"))
        k2, s2 = ks.rotate_keyset(k1, _seed("ev-v2"), _seed("ev-v1"))
        return k1, s1, k2, s2

    def test_versioned_verifies(self):
        k1, s1, k2, s2 = self._keyset2()
        e = self._log(s2, "v2.jsonl").append({"event": "a"})
        self.assertEqual(e["sig_key_version"], 2)
        ok, _ = _log.verify_entry_against_keyset(e, k2)
        self.assertTrue(ok)
        ok, _ = _log.verify_entry_against_keyset(e, k1)
        self.assertFalse(ok)  # k1 predates v2: unknown version

    def test_old_version_verifies_after_rotation(self):
        k1, s1, k2, s2 = self._keyset2()
        e = self._log(s1, "v1.jsonl").append({"event": "a"})
        ok, reason = _log.verify_entry_against_keyset(e, k2)
        self.assertTrue(ok, reason)

    def test_tampered_version_fails(self):
        _, _, k2, s2 = self._keyset2()
        e = self._log(s2).append({"event": "a"})
        for attacked in (dict(e, sig_key_version=1),
                         {k: v for k, v in e.items()
                          if k != "sig_key_version"}):
            ok, _ = _log.verify_entry_against_keyset(attacked, k2)
            self.assertFalse(ok)

    def test_revoked_fails(self):
        k1, s1, k2, s2 = self._keyset2()
        k3, s3 = ks.rotate_keyset(k2, _seed("ev-v3"), _seed("ev-v2"))
        e = self._log(s2, "v2b.jsonl").append({"event": "a"})
        k4 = ks.revoke_version(k3, 2, "compromised", _seed("ev-v3"))
        ok, reason = _log.verify_entry_against_keyset(e, k4)
        self.assertFalse(ok)
        self.assertIn("revoked", reason)

    def test_revoked_forensics_path(self):
        # The forensics method attributes the historical signature
        # (crypto still verifies); the standard path keeps refusing.
        k1, s1, k2, s2 = self._keyset2()
        k3, _ = ks.rotate_keyset(k2, _seed("evf-v3"), _seed("ev-v2"))
        e = self._log(s2, "v2c.jsonl").append({"event": "a"})
        k4 = ks.revoke_version(k3, 2, "compromised", _seed("evf-v3"))
        kv, reason = k4.find_verifying_key_for_forensics(e)
        self.assertIsNotNone(kv, reason)
        self.assertEqual(kv.version, 2)
        sig = bytes.fromhex(e["ed_sig"])
        self.assertTrue(_ed.verify(kv.public_key,
                                   _log._entry_sig_body(e), sig))
        ok, _ = _log.verify_entry_against_keyset(e, k4)
        self.assertFalse(ok)  # standard path still refuses

    def test_legacy_entry_verifies(self):
        k1, s1, k2, _ = self._keyset2()
        legacy = Ed25519Signer(_seed("ev-v1"))
        e = self._log(legacy, "leg.jsonl").append({"event": "a"})
        self.assertNotIn("sig_key_version", e)
        ok, reason = _log.verify_entry_against_keyset(e, k2)
        self.assertTrue(ok, reason)

    def test_malformed_sig_fails_closed(self):
        _, _, k2, s2 = self._keyset2()
        e = self._log(s2).append({"event": "a"})
        for bad_sig in ("zz", "00" * 63, None, 123):
            bad = dict(e, ed_sig=bad_sig)
            ok, _ = _log.verify_entry_against_keyset(bad, k2)
            self.assertFalse(ok, "sig %r" % (bad_sig,))

    def test_hmac_chain_untouched(self):
        # The sig envelope (ed_sig/sig_key_id/sig_key_version) is
        # excluded from the HMAC canonical form and the Merkle leaf:
        # adding or removing it never changes chain hashes or tree
        # roots. (A live A/B across two logs would be flaky by design:
        # entries carry wall-clock timestamps, so this pins the
        # property directly on the canonical forms instead.)
        _, s1 = ks.new_keyset(_seed("evc-v1"))
        e = self._log(s1, "b.jsonl").append({"event": "x"})
        self.assertIn("sig_key_version", e)
        stripped = {k: v for k, v in e.items()
                    if k not in ("ed_sig", "sig_key_id",
                                 "sig_key_version")}
        self.assertEqual(_log._canonical(e), _log._canonical(stripped))
        self.assertEqual(_log._leaf_input(e), _log._leaf_input(stripped))
        # And the legacy signer never writes the envelope at all.
        legacy = self._log(Ed25519Signer(_seed("evc-v1")),
                           "a.jsonl").append({"event": "x"})
        self.assertNotIn("sig_key_version", legacy)

    def test_junk_key_version_not_written(self):
        # A signer exposing a non-integer key_version must not produce
        # an inconsistent envelope (version present but v1 body).
        class JunkSigner(Ed25519Signer):
            key_version = "2"

        e = self._log(JunkSigner(_seed("evj-v1")), "j.jsonl").append(
            {"event": "x"})
        self.assertNotIn("sig_key_version", e)
        self.assertEqual(
            _log._entry_sig_body(e),
            _log._ENTRY_SIG_DOMAIN + _log._canonical(e).encode("utf-8")
            + b"\x00" + str(e["hash"]).encode("utf-8"))


# ---------------------------------------------------------------------------
# Signed-body equivalence across the three implementations
# ---------------------------------------------------------------------------

class TestBodyEquivalence(_KeysetTestBase):
    def _entries(self):
        k1, s1 = ks.new_keyset(_seed("be-v1"))
        legacy = self._log(Ed25519Signer(_seed("be-v1")),
                           "leg.jsonl").append({"event": "x"})
        versioned = self._log(s1, "ver.jsonl").append({"event": "x"})
        return legacy, versioned

    def test_log_vs_evidence_verify(self):
        legacy, versioned = self._entries()
        for e in (legacy, versioned):
            self.assertEqual(_log._entry_sig_body(e),
                             _ev._entry_sig_body(e))

    def test_offline_verify_matches(self):
        # tools/offline-verify keeps its own sig_body (nested function);
        # pin the byte recipe here so drift breaks loudly.
        import re
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "tools", "offline-verify")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        self.assertIn('_ENTRY_SIG_DOMAIN_V2 = b"gov-entry-sig/v2\\x00"',
                      src)
        self.assertIn('"sig_key_version"', src)
        legacy, versioned = self._entries()
        # Recompute the offline recipe inline (it mirrors gov/log.py).
        for e, want_v2 in ((legacy, False), (versioned, True)):
            content = {k: v for k, v in e.items()
                       if k != "hash" and k != "ed_sig"
                       and k != "sig_key_id" and k != "sig_key_version"}
            body = (b"gov-entry-sig/v2\x00" if want_v2
                    else b"gov-entry-sig/v1\x00")
            body += json.dumps(content, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True,
                               default=str).encode("utf-8") + b"\x00"
            if want_v2:
                body += str(e["sig_key_version"]).encode() + b"\x00"
            body += str(e["hash"]).encode("utf-8")
            self.assertEqual(_log._entry_sig_body(e), body)

    def test_tools_evidence_verify_in_sync(self):
        import filecmp
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertTrue(
            filecmp.cmp(os.path.join(repo, "gov", "evidence_verify.py"),
                        os.path.join(repo, "tools", "evidence-verify"),
                        shallow=False),
            "tools/evidence-verify drifted from gov/evidence_verify.py")


# ---------------------------------------------------------------------------
# Evidence bundle: seal(entry_keyset=...) + V9d revocation enforcement
# ---------------------------------------------------------------------------

class TestEvidenceBundleKeyset(_KeysetTestBase):
    def _seal_with_keyset(self, keyset, signer):
        from gov.evidence_bundle import EvidenceBundle
        log_path = os.path.join(self.tmp.name, "audit.log")
        alog = _log.ActionLog(log_path, signer=signer)
        for i in range(3):
            alog.append({"event": "e%d" % i})
        eb = EvidenceBundle(log_path, exported_at="2026-09-28T00:00:00+00:00",
                            operator_id="keyset-test")
        payload = eb.build()
        op = _signer_op()
        manifest = eb.seal(payload, signer=op, entry_keyset=keyset)
        return manifest

    def test_seal_embeds_keyset(self):
        k1, s1 = ks.new_keyset(_seed("eb-v1"))
        manifest = self._seal_with_keyset(k1, s1)
        block = manifest["audit_entry_signing"]
        self.assertIn("keyset", block)
        self.assertEqual(block["keyset"]["format"], ks.KEYSET_FORMAT)
        self.assertEqual(len(block["key_ids"]), 1)

    def test_seal_without_keyset_unchanged(self):
        k1, s1 = ks.new_keyset(_seed("eb2-v1"))
        from gov.evidence_bundle import EvidenceBundle
        log_path = os.path.join(self.tmp.name, "audit2.log")
        alog = _log.ActionLog(log_path, signer=s1)
        alog.append({"event": "x"})
        eb = EvidenceBundle(log_path, exported_at="2026-09-28T00:00:00+00:00",
                            operator_id="keyset-test")
        payload = eb.build()
        manifest = eb.seal(payload, signer=_signer_op())
        self.assertNotIn("keyset", manifest["audit_entry_signing"])

    def test_seal_rejects_bad_keyset(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        k1, s1 = ks.new_keyset(_seed("eb3-v1"))
        log_path = os.path.join(self.tmp.name, "audit3.log")
        _log.ActionLog(log_path, signer=s1).append({"event": "x"})
        eb = EvidenceBundle(log_path, exported_at="2026-09-28T00:00:00+00:00",
                            operator_id="keyset-test")
        payload = eb.build()
        with self.assertRaises(EvidenceBundleError):
            eb.seal(payload, signer=_signer_op(),
                    entry_keyset={"format": "nope"})
        with self.assertRaises(EvidenceBundleError):
            eb.seal(payload, signer=_signer_op(), entry_keyset=42)

    def _v9d_ctx(self, entry, keyset_doc, kid, pub):
        class Ctx:
            pass
        ctx = Ctx()
        ctx.manifest = {"audit_entry_signing": {
            "key_ids": [kid], "signed_entries": 1, "total_entries": 1,
            "keyset": keyset_doc}}
        ctx.slice_entries = [entry]
        ctx.cp_envelope = [{"key_id": kid,
                            "public_key_hex": pub.hex()}]
        return ctx

    def test_v9d_passes_with_keyset(self):
        k1, s1 = ks.new_keyset(_seed("v9d-v1"))
        e = self._log(s1, "v9d.jsonl").append({"event": "x"})
        kid = k1.version(1).key_id
        ctx = self._v9d_ctx(e, k1.to_dict(), kid,
                            k1.version(1).public_key)
        check = _ev.v9d_entry_signatures(ctx)
        self.assertEqual(check.status, "pass", check.detail)
        self.assertIn("revocation", check.detail)

    def test_v9d_rejects_revoked(self):
        k1, s1 = ks.new_keyset(_seed("v9dr-v1"))
        k2, s2 = ks.rotate_keyset(k1, _seed("v9dr-v2"), _seed("v9dr-v1"))
        k3, _ = ks.rotate_keyset(k2, _seed("v9dr-v3"), _seed("v9dr-v2"))
        e = self._log(s2, "v9dr.jsonl").append({"event": "x"})
        k4 = ks.revoke_version(k3, 2, "compromised", _seed("v9dr-v3"))
        kid = k4.version(2).key_id
        ctx = self._v9d_ctx(e, k4.to_dict(), kid,
                            k4.version(2).public_key)
        check = _ev.v9d_entry_signatures(ctx)
        self.assertEqual(check.status, "fail", check.detail)
        self.assertIn("REVOKED", check.detail)

    def test_v9d_malformed_keyset_fails_closed(self):
        k1, s1 = ks.new_keyset(_seed("v9dm-v1"))
        e = self._log(s1, "v9dm.jsonl").append({"event": "x"})
        kid = k1.version(1).key_id
        ctx = self._v9d_ctx(e, {"format": "nope"}, kid,
                            k1.version(1).public_key)
        check = _ev.v9d_entry_signatures(ctx)
        self.assertEqual(check.status, "fail", check.detail)

    def test_v9d_unknown_version_fails_closed(self):
        k1, s1 = ks.new_keyset(_seed("v9du-v1"))
        e = self._log(s1, "v9du.jsonl").append({"event": "x"})
        # Attacker rewrites the bound version to one the keyset never
        # issued. The v2 body changes with it, so crypto fails closed
        # (and the keyset lookup would too).
        e = dict(e, sig_key_version=99)
        kid = k1.version(1).key_id
        ctx = self._v9d_ctx(e, k1.to_dict(), kid,
                            k1.version(1).public_key)
        check = _ev.v9d_entry_signatures(ctx)
        self.assertEqual(check.status, "fail")


def _signer_op():
    """Operator signer for evidence_bundle.seal in these tests."""
    return Ed25519Signer(_seed("test-operator"))


if __name__ == "__main__":
    unittest.main()
