"""Unit tests for gov/trust_root_refresh (wave-318 lane 3).

TDD red: this file is written BEFORE the module exists. Every test must
FAIL (ImportError) until gov/trust_root_refresh.py lands, then go green
one by one.

Seams: the pure chain module only (no verifier/VSA wiring here -- that is
the battery's job). Fixtures use synthetic test-local keypairs; the
module never sees production keys.
"""

import base64
import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from gov import ed25519

NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
SEED_OLD = "31" * 32  # genesis root key (test-local, not a secret)
SEED_NEW = "32" * 32  # rotation target root key
SEED_EVE = "33" * 32  # attacker key: never a root key


def _signer(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    keyid = hashlib.sha256(pub).hexdigest()[:16]

    class _S(object):
        def keyid(self):
            return keyid

        def pubkey_hex(self):
            return pub.hex()

        def sign(self, msg):
            return ed25519.sign(seed, msg)

    return _S()


def _root_doc(signer):
    return {
        "version": 1,
        "policy_keys": [
            {"keyid": signer.keyid(), "pubkey_hex": signer.pubkey_hex()},
        ],
    }


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestGenesis(unittest.TestCase):
    def test_genesis_pins_content_hash(self):
        import gov.trust_root_refresh as trr
        doc = _root_doc(_signer(SEED_OLD))
        e = trr.genesis_entry(doc, source_commit="sasanam@abc123",
                              review_date=_iso(NOW))
        self.assertEqual(e["chain_version"], 1)
        want = hashlib.sha256(trr.canonical(doc)).hexdigest()
        self.assertEqual(e["content_hash"], want)
        self.assertEqual(e["root_doc"], doc)

    def test_genesis_rejects_malformed_root_doc(self):
        import gov.trust_root_refresh as trr
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.genesis_entry({"version": 1, "policy_keys": []},
                              source_commit="sasanam@abc123",
                              review_date=_iso(NOW))
        self.assertEqual(cm.exception.code, "trust-root-chain-malformed")

    def test_genesis_rejects_bad_pubkey(self):
        import gov.trust_root_refresh as trr
        doc = {"version": 1,
               "policy_keys": [{"keyid": "k", "pubkey_hex": "zz"}]}
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.genesis_entry(doc, source_commit="sasanam@abc123",
                              review_date=_iso(NOW))
        self.assertEqual(cm.exception.code, "trust-root-chain-malformed")

    def test_genesis_requires_pin_fields(self):
        import gov.trust_root_refresh as trr
        doc = _root_doc(_signer(SEED_OLD))
        with self.assertRaises(trr.TrustRootError):
            trr.genesis_entry(doc, source_commit="",
                              review_date=_iso(NOW))
        with self.assertRaises(trr.TrustRootError):
            trr.genesis_entry(doc, source_commit="sasanam@abc123",
                              review_date="not-a-time")


class TestRotationCeremony(unittest.TestCase):
    def _v1(self):
        import gov.trust_root_refresh as trr
        return trr.genesis_entry(
            _root_doc(_signer(SEED_OLD)),
            source_commit="sasanam@aaa",
            review_date=_iso(NOW - timedelta(days=30)))

    def _v2_doc(self):
        return _root_doc(_signer(SEED_NEW))

    def test_rotation_happy_path(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        chain = trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[1]["chain_version"], 2)
        self.assertIsNotNone(chain[1]["rotation_record"])
        tip = trr.verify_chain(
            chain, freshness=trr.build_freshness_statement(
                chain[1], issued_at=NOW, signers=[_signer(SEED_NEW)]),
            bundle_timestamp=NOW, now=NOW)
        self.assertEqual(tip["chain_version"], 2)

    def test_rotation_rejects_version_skip(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        rec["record"]["to_version"] = 3
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_rotation_rejects_unknown_signer(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_EVE)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_rotation_rejects_hash_mismatch(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        other = _root_doc(_signer(SEED_EVE))
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, other, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_rotation_rejects_tampered_signature(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        sig = rec["signatures"][0]["sig"]
        raw = bytearray(base64.b64decode(sig))
        raw[0] ^= 0xFF
        rec["signatures"][0]["sig"] = base64.b64encode(bytes(raw)) \
            .decode("ascii")
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_rotation_rejects_future_review_date(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW + timedelta(hours=2)),
            signers=[_signer(SEED_OLD)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_rotation_by_expired_root_rejected(self):
        # CVE-2026-24122 chain-wide: the rotation ceremony's review date
        # must fall inside the SIGNING root's validity window.
        import gov.trust_root_refresh as trr
        v1 = trr.genesis_entry(
            _root_doc(_signer(SEED_OLD)),
            source_commit="sasanam@aaa",
            review_date=_iso(NOW - timedelta(days=60)))
        v1["valid_until"] = _iso(NOW - timedelta(days=1))
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")

    def test_adopt_does_not_mutate_input_chain(self):
        import gov.trust_root_refresh as trr
        v1 = self._v1()
        rec = trr.build_rotation_record(
            v1, self._v2_doc(), source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[_signer(SEED_OLD)])
        before = [dict(e) for e in [v1]]
        chain = trr.adopt_rotation([v1], rec, self._v2_doc(), now=NOW)
        self.assertEqual(len([v1]), 1)
        self.assertEqual([dict(e) for e in [v1]], before)
        self.assertEqual(len(chain), 2)


class TestSilentSwap(unittest.TestCase):
    def test_silent_swap_rejected(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        v1 = trr.genesis_entry(_root_doc(old), source_commit="sasanam@aaa",
                               review_date=_iso(NOW - timedelta(days=30)))
        v2 = trr.make_entry(_root_doc(_signer(SEED_NEW)), chain_version=2,
                            source_commit="sasanam@bbb",
                            review_date=_iso(NOW))
        fresh = trr.build_freshness_statement(v2, issued_at=NOW,
                                              signers=[_signer(SEED_NEW)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain([v1, v2], freshness=fresh,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-silent-swap")

    def test_swapped_record_for_other_doc_rejected(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        v1 = trr.genesis_entry(_root_doc(old), source_commit="sasanam@aaa",
                               review_date=_iso(NOW - timedelta(days=30)))
        new_doc = _root_doc(_signer(SEED_NEW))
        rec = trr.build_rotation_record(
            v1, new_doc, source_commit="sasanam@bbb",
            review_date=_iso(NOW), signers=[old])
        # Attacker keeps the valid record but swaps the entry's doc.
        v2 = trr.make_entry(_root_doc(_signer(SEED_EVE)), chain_version=2,
                            source_commit="sasanam@bbb",
                            review_date=_iso(NOW))
        v2["rotation_record"] = rec
        fresh = trr.build_freshness_statement(v2, issued_at=NOW,
                                              signers=[_signer(SEED_EVE)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain([v1, v2], freshness=fresh,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-rotation-invalid")


class TestFreshness(unittest.TestCase):
    def _chain1(self):
        import gov.trust_root_refresh as trr
        return [trr.genesis_entry(_root_doc(_signer(SEED_OLD)),
                                 source_commit="sasanam@aaa",
                                 review_date=_iso(NOW - timedelta(days=1)))]

    def test_missing_freshness_fails_closed(self):
        import gov.trust_root_refresh as trr
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(self._chain1(), freshness=None,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-stale-freshness")

    def test_stale_freshness_fails_closed(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        fresh = trr.build_freshness_statement(
            self._chain1()[0], issued_at=NOW - timedelta(hours=25),
            signers=[old])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(self._chain1(), freshness=fresh,
                             bundle_timestamp=NOW, now=NOW,
                             max_age_seconds=86400)
        self.assertEqual(cm.exception.code, "trust-root-stale-freshness")

    def test_future_freshness_fails_closed(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        fresh = trr.build_freshness_statement(
            self._chain1()[0], issued_at=NOW + timedelta(hours=1),
            signers=[old])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(self._chain1(), freshness=fresh,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-stale-freshness")

    def test_freshness_for_wrong_version_fails_closed(self):
        import gov.trust_root_refresh as trr
        old, new = _signer(SEED_OLD), _signer(SEED_NEW)
        v1 = trr.genesis_entry(_root_doc(old), source_commit="sasanam@aaa",
                               review_date=_iso(NOW - timedelta(days=2)))
        rec = trr.build_rotation_record(
            v1, _root_doc(new), source_commit="sasanam@bbb",
            review_date=_iso(NOW - timedelta(days=1)), signers=[old])
        chain = trr.adopt_rotation([v1], rec, _root_doc(new),
                                   now=NOW - timedelta(days=1))
        stale_version = trr.build_freshness_statement(
            v1, issued_at=NOW, signers=[old])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(chain, freshness=stale_version,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-stale-freshness")

    def test_freshness_bad_signature_fails_closed(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        fresh = trr.build_freshness_statement(self._chain1()[0],
                                              issued_at=NOW, signers=[old])
        fresh["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64) \
            .decode("ascii")
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(self._chain1(), freshness=fresh,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-stale-freshness")


class TestExpiryAtTimestampTime(unittest.TestCase):
    def _expiring_v1(self, valid_until):
        import gov.trust_root_refresh as trr
        return [trr.genesis_entry(
            _root_doc(_signer(SEED_OLD)), source_commit="sasanam@aaa",
            review_date=_iso(NOW - timedelta(days=60)),
            valid_from=_iso(NOW - timedelta(days=60)),
            valid_until=_iso(valid_until))]

    def _fresh(self, chain):
        import gov.trust_root_refresh as trr
        return trr.build_freshness_statement(chain[-1], issued_at=NOW,
                                             signers=[_signer(SEED_OLD)])

    def test_expired_at_bundle_time_refused(self):
        import gov.trust_root_refresh as trr
        chain = self._expiring_v1(NOW - timedelta(days=1))
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(chain, freshness=self._fresh(chain),
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-expired")

    def test_not_yet_valid_at_bundle_time_refused(self):
        import gov.trust_root_refresh as trr
        chain = self._expiring_v1(NOW + timedelta(days=30))
        chain[0]["valid_from"] = _iso(NOW + timedelta(days=1))
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(chain, freshness=self._fresh(chain),
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-expired")

    def test_bundle_timestamped_before_expiry_still_verifies(self):
        # CVE-2026-24122 core: expiry is evaluated at the TIMESTAMP's
        # time, not at verification time. The root expired an hour ago,
        # but the bundle was timestamped yesterday: HELD.
        import gov.trust_root_refresh as trr
        chain = self._expiring_v1(NOW - timedelta(hours=1))
        tip = trr.verify_chain(
            chain, freshness=self._fresh(chain),
            bundle_timestamp=NOW - timedelta(days=1), now=NOW)
        self.assertEqual(tip["chain_version"], 1)

    def test_expiry_checked_at_timestamp_not_at_now(self):
        # The distinguishing case: bundle timestamped AFTER expiry must
        # refuse even though "now" is also after expiry -- i.e. the check
        # must not degenerate to checking at now with a grace loophole.
        import gov.trust_root_refresh as trr
        chain = self._expiring_v1(NOW - timedelta(days=1))
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain(chain, freshness=self._fresh(chain),
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-expired")
        # ...while a bundle from inside the window verifies at the same now.
        tip = trr.verify_chain(
            chain, freshness=self._fresh(chain),
            bundle_timestamp=NOW - timedelta(days=2), now=NOW)
        self.assertEqual(tip["chain_version"], 1)


class TestChainMalformed(unittest.TestCase):
    def test_empty_chain(self):
        import gov.trust_root_refresh as trr
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain([], freshness=None, bundle_timestamp=NOW,
                             now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-chain-malformed")

    def test_non_consecutive_versions(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        v1 = trr.genesis_entry(_root_doc(old), source_commit="sasanam@aaa",
                               review_date=_iso(NOW - timedelta(days=1)))
        v3 = trr.make_entry(_root_doc(_signer(SEED_NEW)), chain_version=3,
                            source_commit="sasanam@bbb",
                            review_date=_iso(NOW))
        v3["rotation_record"] = {"record": {}, "signatures": []}
        fresh = trr.build_freshness_statement(v3, issued_at=NOW,
                                              signers=[_signer(SEED_NEW)])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain([v1, v3], freshness=fresh,
                             bundle_timestamp=NOW, now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-chain-malformed")

    def test_tampered_entry_doc_detected(self):
        import gov.trust_root_refresh as trr
        old = _signer(SEED_OLD)
        v1 = trr.genesis_entry(_root_doc(old), source_commit="sasanam@aaa",
                               review_date=_iso(NOW - timedelta(days=1)))
        v1["root_doc"]["policy_keys"][0]["pubkey_hex"] = \
            _signer(SEED_EVE).pubkey_hex()
        fresh = trr.build_freshness_statement(v1, issued_at=NOW,
                                              signers=[old])
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.verify_chain([v1], freshness=fresh, bundle_timestamp=NOW,
                             now=NOW)
        self.assertEqual(cm.exception.code, "trust-root-chain-malformed")


class TestVerifyContractPin(unittest.TestCase):
    def test_ed25519_contract_pinned(self):
        # Wave-243 lesson: never assume a verify() raises -- check the
        # return. Pin the contract the ceremony/freshness checks rely on:
        # good signature verifies ``is True``, forged verifies ``is False``.
        import gov.trust_root_refresh as trr
        s = _signer(SEED_OLD)
        body = trr.PAE_DOMAIN_ROTATION + b"contract-pin"
        good = s.sign(body)
        bad = bytearray(good)
        bad[0] ^= 0xFF
        mod = trr._ed()
        self.assertIs(
            mod.verify(bytes.fromhex(s.pubkey_hex()), body, good), True)
        self.assertIs(
            mod.verify(bytes.fromhex(s.pubkey_hex()), body, bytes(bad)),
            False)


class TestReceiptBinding(unittest.TestCase):
    def _receipt(self, digest, sig_hex, pub_hex, witness):
        import gov.trust_root_refresh as trr
        body = trr.canonical({"artifact_digest": digest,
                              "signature": sig_hex,
                              "signer_pubkey": pub_hex})
        return {
            "artifact_digest": digest,
            "signature": sig_hex,
            "signer_pubkey": pub_hex,
            "witness_sig": base64.b64encode(
                witness.sign(trr.PAE_DOMAIN_RECEIPT + body)).decode("ascii"),
        }

    def test_receipt_binding_happy_path(self):
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        digest = hashlib.sha256(b"artifact").hexdigest()
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(digest, sig_hex, pub_hex, wit)
        trr.bind_receipt(artifact_digest=digest, signature_hex=sig_hex,
                         signer_pubkey_hex=pub_hex, receipt=rec,
                         witness_pubkey_hex=wit.pubkey_hex())

    def test_receipt_wrong_digest_unbound(self):
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        digest = hashlib.sha256(b"artifact").hexdigest()
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(digest, sig_hex, pub_hex, wit)
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest=hashlib.sha256(b"other")
                             .hexdigest(),
                             signature_hex=sig_hex,
                             signer_pubkey_hex=pub_hex, receipt=rec,
                             witness_pubkey_hex=wit.pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

    def test_receipt_wrong_signature_field_unbound(self):
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        digest = hashlib.sha256(b"artifact").hexdigest()
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(digest, sig_hex, pub_hex, wit)
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest=digest,
                             signature_hex=_signer(SEED_EVE).sign(b"x")
                             .hex(),
                             signer_pubkey_hex=pub_hex, receipt=rec,
                             witness_pubkey_hex=wit.pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

    def test_receipt_forged_witness_sig_unbound(self):
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        digest = hashlib.sha256(b"artifact").hexdigest()
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(digest, sig_hex, pub_hex, wit)
        rec["witness_sig"] = base64.b64encode(b"\x01" * 64).decode("ascii")
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest=digest, signature_hex=sig_hex,
                             signer_pubkey_hex=pub_hex, receipt=rec,
                             witness_pubkey_hex=wit.pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

    def test_receipt_transplant_unbound(self):
        # CVE-2026-22703: a valid receipt for artifact A must not verify
        # for artifact B even though the receipt itself is well-formed.
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(hashlib.sha256(b"A").hexdigest(), sig_hex,
                            pub_hex, wit)
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest=hashlib.sha256(b"B")
                             .hexdigest(),
                             signature_hex=sig_hex,
                             signer_pubkey_hex=pub_hex, receipt=rec,
                             witness_pubkey_hex=wit.pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

    def test_receipt_non_dict_unbound(self):
        import gov.trust_root_refresh as trr
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest="ab" * 32,
                             signature_hex="cd" * 64,
                             signer_pubkey_hex=_signer(SEED_NEW)
                             .pubkey_hex(),
                             receipt=["not", "a", "dict"],
                             witness_pubkey_hex=_signer(SEED_OLD)
                             .pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

    def test_receipt_non_base64_witness_sig_unbound(self):
        import gov.trust_root_refresh as trr
        wit = _signer(SEED_OLD)
        digest = hashlib.sha256(b"artifact").hexdigest()
        sig_hex = _signer(SEED_NEW).sign(b"data").hex()
        pub_hex = _signer(SEED_NEW).pubkey_hex()
        rec = self._receipt(digest, sig_hex, pub_hex, wit)
        rec["witness_sig"] = "!!! not base64 !!!"
        with self.assertRaises(trr.TrustRootError) as cm:
            trr.bind_receipt(artifact_digest=digest, signature_hex=sig_hex,
                             signer_pubkey_hex=pub_hex, receipt=rec,
                             witness_pubkey_hex=wit.pubkey_hex())
        self.assertEqual(cm.exception.code, "trust-root-receipt-unbound")

if __name__ == "__main__":
    unittest.main()
