"""Unit tests for gov/attested_identity.py (wave-204).

Public seams only. The 29-probe break battery
(evals/attested_identity_probes.py) covers the attack matrix end to
end; these tests pin the parser strictness, constructor validation,
ceremony bookkeeping, and the additive BOM/PolicyReport wiring
(byte-identical when the tier is omitted).
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import attested_identity as ai  # noqa: E402
from gov import decision_bom as bom  # noqa: E402
from gov import ed25519 as _ed25519  # noqa: E402
from gov import mode_ledger as ml  # noqa: E402
from gov import policy_report as pr  # noqa: E402
from gov import tee_attest as ta  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


# Fixed 1024-bit RSA test key, generated once with openssl and embedded
# so the unit tests are hermetic: no CLI, no keygen, deterministic.
# Public exponent 65537. The battery (evals/) keeps its own openssl
# multi-key fixtures for the full attack matrix; here one key plays both
# the EK and AIK roles (the unit tests never need cross-key confusion).
_TEST_N_HEX = (
    "00b3a35d6759ba875e28cdabd941c804c3a1d99ab9461c19e2ebca92cc8d"
    "3cdf9860c94c6bd1fffbbb67603119756a9a697552537f9f9eaabc1de199"
    "e1ae9b1f01a48bfb080e67ada449dee737d0339f0aa5d5a6d66e658c317"
    "adaf3839b959f41aa005215604fb43710a399560374cd1dbde1f3dc7672"
    "a39977c5e528d95c5e9d")
_TEST_D_HEX = (
    "0090f088d670b16db36d5cb501707000581068d0cc186368078d943ee9c8"
    "338b7d18ea923c948de4008b2233bb84df64831e643476cec568a0abc371"
    "33847c288100c55511d6ec6cc1261029a4f6a90e4d723be65427af430e50"
    "520668e23187e05b581064233c8e71e25c715761ad5447885906487dffab"
    "bff63b8fc9a2529181")
_TEST_SPKI_DER_HEX = (
    "30819f300d06092a864886f70d010101050003818d0030818902818100b3"
    "a35d6759ba875e28cdabd941c804c3a1d99ab9461c19e2ebca92cc8d3cdf"
    "9860c94c6bd1fffbbb67603119756a9a697552537f9f9eaabc1de199e1ae"
    "9b1f01a48bfb080e67ada449dee737d0339f0aa5d5a6d66e658c317adaf3"
    "839b959f41aa005215604fb43710a399560374cd1dbde1f3dc7672a39977"
    "c5e528d95c5e9d0203010001")
_TEST_E = 65537
_TEST_DIGESTINFO_SHA256 = bytes.fromhex(
    "3031300d060960864801650304020105000420")


class _TestKey(object):
    """Fixture signer: pure-python RSASSA-PKCS1-v1_5/SHA-256.

    Test-only. Every signature it produces is checked by the product's
    stdlib verifier, so a padding bug here fails the positive tests
    loudly instead of silently weakening them.
    """

    def __init__(self):
        self.n = int(_TEST_N_HEX, 16)
        self.d = int(_TEST_D_HEX, 16)
        self.e = _TEST_E
        self.der = bytes.fromhex(_TEST_SPKI_DER_HEX)

    def sign(self, message):
        digest = hashlib.sha256(bytes(message)).digest()
        t = _TEST_DIGESTINFO_SHA256 + digest
        k = (self.n.bit_length() + 7) // 8
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return pow(int.from_bytes(em, "big"), self.d,
                   self.n).to_bytes(k, "big")


_KEYS = None


def _keys():
    """Process-cached fixture key (one key, two roles: ek and aik)."""
    global _KEYS
    if _KEYS is None:
        k = _TestKey()
        entry = {"der": k.der, "sign": k.sign}
        _KEYS = {"ek": entry, "aik": entry}
    return _KEYS


def _attester(**kw):
    keys = _keys()
    params = dict(
        quote_verifier=ai.QuoteVerifier(
            trusted_ek_pubkeys_der=[keys["ek"]["der"]],
            expected_pcr_digest=b"pcr-policy",
            expected_pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")]),
        credential_ttl_s=600)
    params.update(kw)
    return ai.Attester(Ed25519Signer(os.urandom(32)), **params)


class RsaParserTest(unittest.TestCase):
    def test_good_key_parses(self):
        n, e = ai.parse_spki_rsa_pubkey(_keys()["aik"]["der"])
        self.assertEqual(e, 65537)
        self.assertGreaterEqual(n.bit_length(), 1024)

    def test_rejects_non_der(self):
        with self.assertRaises(ai.RsaError):
            ai.parse_spki_rsa_pubkey(b"not-der")

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(ai.RsaError):
            ai.parse_spki_rsa_pubkey(_keys()["aik"]["der"] + b"\x00")

    def test_rejects_wrong_oid(self):
        # Corrupt the rsaEncryption OID byte inside the AlgorithmId.
        bad = bytearray(_keys()["aik"]["der"])
        idx = bytes(bad).find(bytes([0x06, 0x09, 0x2A, 0x86, 0x48]))
        self.assertNotEqual(idx, -1)
        bad[idx + 3] ^= 0xFF
        with self.assertRaises(ai.RsaError):
            ai.parse_spki_rsa_pubkey(bytes(bad))

    def test_verify_round_trip(self):
        keys = _keys()
        n, e = ai.parse_spki_rsa_pubkey(keys["aik"]["der"])
        msg = b"hello"
        sig = keys["aik"]["sign"](msg)
        self.assertTrue(ai.verify_rsassa_pkcs1_v1_5_sha256(msg, sig, n, e))
        self.assertFalse(ai.verify_rsassa_pkcs1_v1_5_sha256(b"bye", sig,
                                                            n, e))
        self.assertFalse(ai.verify_rsassa_pkcs1_v1_5_sha256(
            msg, sig[:-2], n, e))

    def test_rejects_even_exponent_key(self):
        # Hand-built SPKI with e=2 must fail closed (not silently
        # accepted with a weak exponent).
        def _tlv(tag, value):
            n = len(value)
            if n < 128:
                head = bytes([n])
            else:
                lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
                head = bytes([0x80 | len(lb)]) + lb
            return bytes([tag]) + head + value

        def _int(x):
            raw = x.to_bytes((x.bit_length() + 7) // 8, "big")
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return _tlv(0x02, raw)

        n, _e = ai.parse_spki_rsa_pubkey(_keys()["aik"]["der"])
        inner = _tlv(0x30, _int(n) + _int(2))
        bitstr = _tlv(0x03, b"\x00" + inner)
        algid = bytes([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                       0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00])
        spki = _tlv(0x30, algid + bitstr)
        with self.assertRaises(ai.RsaError):
            ai.parse_spki_rsa_pubkey(spki)


class TpmMarshalTest(unittest.TestCase):
    def _marshal(self):
        return ai.marshal_tpms_attest_quote(
            qualified_signer=b"qs", extra_data=b"n", clock=0,
            reset_count=0, restart_count=0, safe=True,
            firmware_version=0,
            pcr_selections=[(ai.TPM_ALG_SHA256, b"\x01")],
            pcr_digest=b"d")

    def _offsets(self):
        # magic(4) type(2) qsTPM2B(2+2) extraTPM2B(2+1) clock(8)
        # reset(4) restart(4) safe(1) fw(8) count(4)
        safe_at = 4 + 2 + 4 + 3 + 8 + 4 + 4
        return safe_at, safe_at + 1 + 8

    def test_rejects_oversize_selection_count(self):
        good = self._marshal()
        safe_at, count_at = self._offsets()
        bad = good[:count_at] + b"\x00\x00\x00\x09" + good[count_at + 4:]
        with self.assertRaises(ai.QuoteError):
            ai.parse_tpms_attest_quote(bad)

    def test_rejects_bad_safe_byte(self):
        good = self._marshal()
        safe_at, _count_at = self._offsets()
        bad = good[:safe_at] + b"\x02" + good[safe_at + 1:]
        with self.assertRaises(ai.QuoteError):
            ai.parse_tpms_attest_quote(bad)

    def test_rejects_empty_buffer(self):
        with self.assertRaises(ai.QuoteError):
            ai.parse_tpms_attest_quote(b"")

    def test_marshal_validates_inputs(self):
        with self.assertRaises(ai.QuoteError):
            ai.marshal_tpms_attest_quote(
                qualified_signer="not-bytes", extra_data=b"n", clock=0,
                reset_count=0, restart_count=0, safe=True,
                firmware_version=0, pcr_selections=[],
                pcr_digest=b"d")


class QuoteVerifierConfigTest(unittest.TestCase):
    def test_requires_a_trust_anchor(self):
        with self.assertRaises(ai.QuoteError):
            ai.QuoteVerifier(expected_pcr_digest=b"x",
                             expected_pcr_selections=[(1, b"y")])

    def test_rejects_unparseable_ek(self):
        with self.assertRaises(ai.RsaError):
            ai.QuoteVerifier(trusted_ek_pubkeys_der=[b"junk"],
                             expected_pcr_digest=b"x",
                             expected_pcr_selections=[(1, b"y")])

    def test_pinned_aik_path_needs_no_ek(self):
        keys = _keys()
        v = ai.QuoteVerifier(
            pinned_aik_pubkeys_der=[keys["aik"]["der"]],
            expected_pcr_digest=b"pcr-policy",
            expected_pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")])
        q = ai.make_quote(nonce=b"n" * 16, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        claims = v.verify(q, aik_pubkey_der=keys["aik"]["der"],
                          endorsement=None, expected_nonce=b"n" * 16)
        self.assertEqual(claims["kind"], "tpm_quote")

    def test_wrong_nonce_type_refused(self):
        keys = _keys()
        v = ai.QuoteVerifier(
            pinned_aik_pubkeys_der=[keys["aik"]["der"]],
            expected_pcr_digest=b"pcr-policy",
            expected_pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")])
        q = ai.make_quote(nonce=b"n" * 16, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        with self.assertRaises(ai.QuoteError):
            v.verify(q, aik_pubkey_der=keys["aik"]["der"],
                     expected_nonce="")


class CeremonyTest(unittest.TestCase):
    def test_challenge_single_use(self):
        a = _attester()
        cid, _nonce = a.issue_challenge("s")
        a._consume_challenge(cid)
        with self.assertRaises(ai.IdentityError):
            a._consume_challenge(cid)

    def test_unknown_challenge_refused(self):
        a = _attester()
        with self.assertRaises(ai.IdentityError):
            a._consume_challenge("chal-nope")

    def test_bad_issuer_signer_refused(self):
        class Bad(object):
            pass
        with self.assertRaises(ai.IdentityError):
            ai.Attester(Bad())

    def test_evidence_replay_refused_across_methods(self):
        keys = _keys()
        a = _attester(aws_verifier=ai.AwsStyleVerifier(
            signer_pubkey_der=keys["aik"]["der"],
            allowed_account_ids={"1"}, allowed_regions={"r"}))
        bundle = ai.make_aws_style_doc(
            instance_id="i-1", account_id="1", region="r",
            signer=keys["aik"]["sign"])
        cid1, _ = a.issue_challenge("s")
        a.bootstrap_with_aws_iid(challenge_id=cid1, bundle=bundle)
        # Same evidence digest presented again (fresh challenge) still
        # refuses at the consumed-evidence log.
        cid2, _ = a.issue_challenge("s")
        with self.assertRaises(ai.IdentityError):
            a.bootstrap_with_aws_iid(challenge_id=cid2, bundle=bundle)

    def test_authorize_rejects_non_identity(self):
        a = _attester()
        with self.assertRaises(ai.IdentityError):
            a.authorize({"tier": 1}, "emit_telemetry")

    def test_action_policy_boundary_every_action(self):
        a = _attester()
        t2 = a.register_kernel_fact_identity(cgroup="/c", uid=1,
                                              hostname="h")
        for action, min_tier in ai.ACTION_POLICY.items():
            if min_tier == ai.TIER_KERNEL_FACT:
                self.assertTrue(a.authorize(t2, action))
            else:
                with self.assertRaises(ai.IdentityError):
                    a.authorize(t2, action)

    def test_tier1_claims_carry_ceremony_kind(self):
        # Regression: verifier claim dicts carry their own "kind"
        # ("tpm_quote"); the minted credential must carry the ceremony
        # kind ("tpm_attested"), matching the audit log.
        keys = _keys()
        a = _attester()
        cid, nonce = a.issue_challenge("s")
        q = ai.make_quote(nonce=nonce, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        end = ai.endorse_aik(keys["aik"]["der"], keys["ek"]["sign"])
        ident = a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=keys["aik"]["der"], endorsement=end)
        self.assertEqual(ident.claims["kind"], "tpm_attested")
        self.assertEqual(a.audit[0]["kind"], "tpm_attested")
        self.assertTrue(ai._is_hex64(ident.claims["evidence_digest"]))

    def test_audit_log_records_ceremony(self):
        keys = _keys()
        a = _attester()
        cid, nonce = a.issue_challenge("agent-1")
        q = ai.make_quote(nonce=nonce, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        end = ai.endorse_aik(keys["aik"]["der"], keys["ek"]["sign"])
        ident = a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=keys["aik"]["der"], endorsement=end)
        a.authorize(ident, "sign_evidence")
        events = [e["event"] for e in a.audit]
        self.assertEqual(events, ["tier1_issued", "authorized"])

    def test_tier2_credential_verifies_but_stays_tier2(self):
        a = _attester()
        t2 = a.register_kernel_fact_identity(cgroup="/c", uid=1,
                                              hostname="h")
        self.assertTrue(a.verify_credential(t2))
        self.assertEqual(t2.tier_label, "tier-2-kernel-fact")

    def test_verify_credential_never_raises(self):
        a = _attester()
        self.assertFalse(a.verify_credential(None))
        self.assertFalse(a.verify_credential("not-an-identity"))


def _tee_snp_setup():
    """Fresh SNP fixture + verifier pinned to its ARK + bundle builder."""
    fx = ta.make_snp_fixture(policy=0x30000, measurement=b"m" * 48,
                             tcb=b"\x01\x02\x03\x04\x05\x06\x07\x08",
                             chip_id=b"c" * 64, salt=os.urandom(32))

    def bundle_for(salt):
        fx2 = ta.make_snp_fixture(
            policy=fx["policy"], measurement=fx["measurement"],
            tcb=fx["tcb"], chip_id=b"d" * 64, salt=salt,
            ark_priv=fx["ark_priv"], ark_point=fx["ark_pubkey"])
        return {"report": fx2["report"],
                "ask_cert": fx2["ask_cert"],
                "vcek_cert": fx2["vcek_cert"],
                "expected_policy": fx2["policy"],
                "expected_measurement": fx2["measurement"],
                "tcb_allowlist": [fx2["tcb"]],
                "tee_pubkey": fx2["tee_pubkey"],
                "salt": fx2["salt"]}

    verifier = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"], enabled=True)
    return fx, verifier, bundle_for


class TeeBootstrapTest(unittest.TestCase):
    def test_tee_bootstrap_mints_tier1_with_ceremony_kind(self):
        _fx, verifier, bundle_for = _tee_snp_setup()
        a = ai.Attester(Ed25519Signer(os.urandom(32)),
                        tee_verifier=verifier)
        cid, nonce = a.issue_challenge("agent-tee")
        ident = a.bootstrap_with_tee_report(
            challenge_id=cid, bundle=bundle_for(nonce))
        self.assertEqual(ident.tier, ai.TIER_ATTESTED)
        self.assertEqual(ident.claims["kind"], "tee_attested")
        self.assertEqual(ident.claims["platform"], "sev-snp")
        self.assertTrue(a.verify_credential(ident))
        self.assertEqual(a.audit[0]["kind"], "tee_attested")

    def test_tee_verifier_defaults_to_none(self):
        a = _attester()
        self.assertIsNone(a.tee_verifier)

    def test_tee_bootstrap_without_verifier_refuses(self):
        a = _attester()  # no tee_verifier configured
        cid, _nonce = a.issue_challenge("agent-tee")
        with self.assertRaises(ai.IdentityError):
            a.bootstrap_with_tee_report(challenge_id=cid, bundle={})

    def test_tee_bootstrap_wrong_salt_refuses(self):
        _fx, verifier, bundle_for = _tee_snp_setup()
        a = ai.Attester(Ed25519Signer(os.urandom(32)),
                        tee_verifier=verifier)
        cid, _nonce = a.issue_challenge("agent-tee")
        with self.assertRaises(ai.IdentityError):
            a.bootstrap_with_tee_report(
                challenge_id=cid, bundle=bundle_for(os.urandom(32)))

    def test_tee_bootstrap_stale_report_refuses(self):
        _fx, verifier, bundle_for = _tee_snp_setup()
        a = ai.Attester(Ed25519Signer(os.urandom(32)),
                        tee_verifier=verifier)
        cid1, nonce1 = a.issue_challenge("agent-tee-1")
        stale = bundle_for(nonce1)
        cid2, nonce2 = a.issue_challenge("agent-tee-2")
        a.bootstrap_with_tee_report(
            challenge_id=cid2, bundle=bundle_for(nonce2))
        # The report built for the first challenge cannot bootstrap
        # against a fresh challenge: the REPORT_DATA salt no longer
        # matches the single-use nonce.
        cid3, _nonce3 = a.issue_challenge("agent-tee-3")
        with self.assertRaises(ai.IdentityError):
            a.bootstrap_with_tee_report(
                challenge_id=cid3, bundle=stale)

    def test_tee_evidence_cannot_mint_twice(self):
        _fx, verifier, bundle_for = _tee_snp_setup()
        a = ai.Attester(Ed25519Signer(os.urandom(32)),
                        tee_verifier=verifier)
        cid, nonce = a.issue_challenge("agent-tee")
        bundle = bundle_for(nonce)
        a.bootstrap_with_tee_report(challenge_id=cid, bundle=bundle)
        digests = [e["evidence_digest"] for e in a.audit
                   if e["event"] == "tier1_issued"]
        self.assertEqual(len(digests), 1)

    def test_existing_paths_unchanged_by_tee_verifier(self):
        # Passing a tee_verifier must not disturb the TPM bootstrap.
        _fx, verifier, _bundle_for = _tee_snp_setup()
        keys = _keys()
        a = _attester(tee_verifier=verifier)
        cid, nonce = a.issue_challenge("s")
        q = ai.make_quote(nonce=nonce, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        end = ai.endorse_aik(keys["aik"]["der"], keys["ek"]["sign"])
        ident = a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=keys["aik"]["der"], endorsement=end)
        self.assertEqual(ident.claims["kind"], "tpm_attested")


class CredentialEncodingTest(unittest.TestCase):
    def test_signing_bytes_domain_separated(self):
        body = ai.credential_body(1, {"k": "v"}, 123)
        sig_bytes = ai.credential_signing_bytes(body)
        self.assertTrue(sig_bytes.startswith(ai.CRED_DOMAIN))
        self.assertEqual(
            ai.credential_digest_of(body),
            hashlib.sha256(ai.canonical_json(body)).hexdigest())

    def test_bool_tier_refused(self):
        # True == 1 in Python: tier=True must not silently mint tier-1.
        with self.assertRaises(ai.IdentityError):
            ai.credential_body(True, {}, 123)
        with self.assertRaises(ai.IdentityError):
            ai.Identity(tier=True, claims={}, credential_sig=b"\x00",
                        expires_at=1)
        with self.assertRaises(ai.IdentityError):
            ai.Identity(tier=False, claims={}, credential_sig=b"\x00",
                        expires_at=1)

    def test_spec_alias_names_tier2(self):
        self.assertEqual(ai.TIER_KERNEL_CLAIM, ai.TIER_KERNEL_FACT)
        self.assertEqual(ai.TIER_KERNEL_CLAIM, 2)

    def test_wrong_domain_refused(self):
        with self.assertRaises(ai.IdentityError):
            ai.credential_signing_bytes({"domain": "other", "tier": 1})

    def test_canonical_json_rejects_non_dict(self):
        with self.assertRaises(ai.IdentityError):
            ai.canonical_json(["x"])


class BomSectionTest(unittest.TestCase):
    def test_tier2_refused_loudly(self):
        a = _attester()
        t2 = a.register_kernel_fact_identity(cgroup="/c", uid=1,
                                              hostname="h")
        with self.assertRaises(ai.IdentityError):
            ai.bom_identity_section(t2)

    def test_non_identity_refused(self):
        with self.assertRaises(ai.IdentityError):
            ai.bom_identity_section({"tier": 1})


class BomWiringTest(unittest.TestCase):
    def _bom_kwargs(self):
        return dict(policy_id="p", policy_version="v1",
                    policy_digest="0" * 64,
                    evidence_head_digest="1" * 64,
                    principal={"agent_id": "a1"})

    def test_absence_is_byte_identical(self):
        before = bom.build_bom(**self._bom_kwargs())
        after = bom.build_bom(**self._bom_kwargs(), attested_identity=None)
        self.assertEqual(
            bom.bom_digest(before), bom.bom_digest(after))
        self.assertNotIn("attested_identity", after["inputs"])

    def test_partial_section_refused(self):
        with self.assertRaises(bom.BomError):
            bom.build_bom(attested_identity={"tier": 1},
                          **self._bom_kwargs())

    def test_shape_rejects_unknown_keys(self):
        b = bom.build_bom(**self._bom_kwargs())
        b["inputs"]["attested_identity"] = {
            "tier": 1, "credential_digest": "a" * 64,
            "evidence_digest": "b" * 64, "extra": 1}
        ok, _reason = bom.check_bom_shape(b)
        self.assertFalse(ok)

    def test_bool_tier_refused_in_bom(self):
        # True == 1 in Python: tier=True must not slip into the section
        # at build time or pass the shape check on a received BOM.
        section = {"tier": True, "credential_digest": "a" * 64,
                   "evidence_digest": "b" * 64}
        with self.assertRaises(bom.BomError):
            bom.build_bom(attested_identity=section,
                          **self._bom_kwargs())
        b = bom.build_bom(**self._bom_kwargs())
        b["inputs"]["attested_identity"] = dict(section)
        ok, _reason = bom.check_bom_shape(b)
        self.assertFalse(ok)

    def test_verify_bom_rejects_non_dict_body(self):
        keys = _keys()
        a = _attester()
        cid, nonce = a.issue_challenge("s")
        q = ai.make_quote(nonce=nonce, pcr_digest=b"pcr-policy",
                          pcr_selections=[(ai.TPM_ALG_SHA256, b"\xff")],
                          signer=keys["aik"]["sign"])
        end = ai.endorse_aik(keys["aik"]["der"], keys["ek"]["sign"])
        ident = a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=keys["aik"]["der"], endorsement=end)
        bundle_bytes = b"policy-bundle-fixture"
        b = bom.build_bom(
            attested_identity=ai.bom_identity_section(ident),
            policy_id="p", policy_version="v1",
            policy_digest=hashlib.sha256(bundle_bytes).hexdigest(),
            evidence_head_digest="1" * 64,
            principal={"agent_id": "a1"})
        ok, reason = bom.verify_bom(
            b, policy_bundle_bytes=bundle_bytes,
            identity_credential_body=["nope"])
        self.assertFalse(ok)
        self.assertIn("identity_credential_body", reason)


class PolicyReportWiringTest(unittest.TestCase):
    def _ledger(self):
        ledger = ml.ModeLedger(clock=lambda: 1700000000.0)
        ledger.register_rule("r1", mode="warn")
        ledger.observe("r1", mode="warn", matched=True,
                       nominal_effect="queue", request_digest="d" * 64)
        return ledger

    def test_omitted_tier_is_byte_identical(self):
        rep1 = pr.build_report(self._ledger(), policy_name="p")
        rep2 = pr.build_report(self._ledger(), policy_name="p",
                               identity_tier=None)
        self.assertEqual(pr._canonical(rep1), pr._canonical(rep2))

    def test_invalid_tier_refused(self):
        with self.assertRaises(pr.PolicyReportError):
            pr.build_report(self._ledger(), policy_name="p",
                            identity_tier=0)

    def test_bool_tier_refused(self):
        # True == 1 in Python: identity_tier=True must not silently
        # label a report "tier-1-attested".
        ledger = self._ledger()
        rec = next(r for r in ledger._chain if r["rule_id"] == "r1")
        with self.assertRaises(pr.PolicyReportError):
            pr.build_report(ledger, policy_name="p", identity_tier=True)
        with self.assertRaises(pr.PolicyReportError):
            pr.project_result(rec, policy_name="p", identity_tier=True)

    def test_project_result_invalid_tier_refused(self):
        ledger = self._ledger()
        rec = next(r for r in ledger._chain if r["rule_id"] == "r1")
        with self.assertRaises(pr.PolicyReportError):
            pr.project_result(rec, policy_name="p", identity_tier=9)


if __name__ == "__main__":
    unittest.main()
