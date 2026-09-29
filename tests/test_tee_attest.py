"""Unit tests for gov/tee_attest.py (wave-208, lane D).

Public seams only. The 19-probe break battery
(evals/tee_attest_probes.py) covers the attack matrix end to end; these
tests pin the flag gate, the strict parsers, the three-hop TDX binding,
the REPORT_DATA construction, and the AuthorityProof/BOM composition
helpers.
"""

import base64
import hashlib
import os
import struct
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import authority_proof as ap  # noqa: E402
from gov import tee_attest as ta  # noqa: E402


def _snp_fixture(**over):
    kw = dict(policy=0x30000, measurement=b"m" * 48,
              tcb=b"\x01\x02\x03\x04\x05\x06\x07\x08",
              chip_id=b"c" * 64, salt=os.urandom(32))
    kw.update(over)
    return ta.make_snp_fixture(**kw)


def _snp_bundle(fx):
    return {"report": fx["report"],
            "ask_cert": fx["ask_cert"],
            "vcek_cert": fx["vcek_cert"],
            "expected_policy": fx["policy"],
            "expected_measurement": fx["measurement"],
            "tcb_allowlist": [fx["tcb"]],
            "tee_pubkey": fx["tee_pubkey"],
            "salt": fx["salt"]}


def _tdx_fixture(**over):
    now = 1800000000
    kw = dict(mrtd=b"t" * 48,
              rtmrs={0: b"r" * 48, 1: b"s" * 48},
              tcb_info={"valid_from": now - 10000,
                        "valid_until": now + 10000},
              salt=os.urandom(32), now=now)
    kw.update(over)
    return ta.make_tdx_fixture(**kw)


def _tdx_bundle(fx):
    return {"quote": fx["quote"],
            "pck_cert": fx["pck_cert"],
            "tcb_info": dict(fx["tcb_info"]),
            "expected_mrtd": fx["mrtd"],
            "expected_rtmrs": dict(fx["rtmrs"]),
            "tee_pubkey": fx["tee_pubkey"],
            "salt": fx["salt"],
            "now": fx["now"]}


class FlagGateTests(unittest.TestCase):
    def test_default_is_off(self):
        old = os.environ.pop(ta.TEE_ATTEST_FLAG, None)
        try:
            self.assertFalse(ta.is_enabled())
            with self.assertRaises(ta.FlagDisabledError):
                ta.SevSnpVerifier(ark_pubkey=_snp_fixture()["ark_pubkey"]
                                  ).verify({})
            with self.assertRaises(ta.FlagDisabledError):
                ta.TdxQuoteVerifier(
                    intel_root_pubkey=_tdx_fixture()["intel_root_pubkey"]
                ).verify({})
        finally:
            if old is not None:
                os.environ[ta.TEE_ATTEST_FLAG] = old

    def test_explicit_enable_variants(self):
        self.assertTrue(ta.is_enabled(True))
        self.assertTrue(ta.is_enabled("1"))
        self.assertTrue(ta.is_enabled("true"))
        self.assertTrue(ta.is_enabled("YeS"))
        self.assertFalse(ta.is_enabled(False))
        self.assertFalse(ta.is_enabled("0"))
        self.assertFalse(ta.is_enabled(""))
    def test_none_reads_environment(self):
        old = os.environ.get(ta.TEE_ATTEST_FLAG)
        try:
            os.environ[ta.TEE_ATTEST_FLAG] = "1"
            self.assertTrue(ta.is_enabled(None))
            os.environ.pop(ta.TEE_ATTEST_FLAG, None)
            self.assertFalse(ta.is_enabled(None))
        finally:
            if old is None:
                os.environ.pop(ta.TEE_ATTEST_FLAG, None)
            else:
                os.environ[ta.TEE_ATTEST_FLAG] = old

    def test_env_enable(self):
        old = os.environ.get(ta.TEE_ATTEST_FLAG)
        os.environ[ta.TEE_ATTEST_FLAG] = "1"
        try:
            self.assertTrue(ta.is_enabled())
            self.assertTrue(ta.SevSnpVerifier(
                ark_pubkey=_snp_fixture()["ark_pubkey"]).enabled)
        finally:
            if old is None:
                os.environ.pop(ta.TEE_ATTEST_FLAG, None)
            else:
                os.environ[ta.TEE_ATTEST_FLAG] = old


class EcPrimitiveTests(unittest.TestCase):
    def test_keypair_roundtrip_both_curves(self):
        for name in ("P-256", "P-384"):
            priv, pub = ta.gen_keypair(name)
            curve = ta._curve(name)
            point = ta._point_from_bytes(curve, pub)
            self.assertEqual(ta._point_to_bytes(curve, point), pub)

    def test_sign_verify_roundtrip_and_tamper(self):
        for name in ("P-256", "P-384"):
            curve = ta._curve(name)
            priv, pub = ta.gen_keypair(name)
            point = ta._point_from_bytes(curve, pub)
            digest = hashlib.new(curve.hash_name, b"hello").digest()
            r, s = ta.ecdsa_sign(curve, priv, digest)
            self.assertTrue(ta.ecdsa_verify(curve, point, digest, r, s))
            bad = hashlib.new(curve.hash_name, b"hellp").digest()
            self.assertFalse(ta.ecdsa_verify(curve, point, bad, r, s))
            self.assertFalse(
                ta.ecdsa_verify(curve, point, digest, r, (s + 1) % curve.n))
            self.assertFalse(ta.ecdsa_verify(curve, point, digest, 0, s))

    def test_malformed_point_refused(self):
        with self.assertRaises(ta.ReportFormatError):
            ta._point_from_bytes(ta.P256, b"\x04" + b"\x00" * 64)
        with self.assertRaises(ta.ReportFormatError):
            ta._point_from_bytes(ta.P256, b"short")


class ReportDataTests(unittest.TestCase):
    def test_construction_is_byte_exact(self):
        _, pub = ta.gen_keypair("P-384")
        salt = b"s" * 32
        rd = ta.report_data_for("P-384", pub, salt)
        self.assertEqual(len(rd), 64)
        self.assertEqual(rd[:32], ta.jwk_thumbprint("P-384", pub))
        self.assertEqual(rd[32:], salt)

    def test_thumbprint_deterministic_and_key_bound(self):
        _, pub = ta.gen_keypair("P-256")
        self.assertEqual(ta.jwk_thumbprint("P-256", pub),
                         ta.jwk_thumbprint("P-256", pub))
        _, other = ta.gen_keypair("P-256")
        self.assertNotEqual(ta.jwk_thumbprint("P-256", pub),
                            ta.jwk_thumbprint("P-256", other))

    def test_salt_length_enforced(self):
        _, pub = ta.gen_keypair("P-256")
        with self.assertRaises(ta.BindingError):
            ta.report_data_for("P-256", pub, b"short")


class SnpLayoutTests(unittest.TestCase):
    # The synthetic report follows the AMD SEV-SNP Firmware ABI Table 20
    # field offsets. Pin them: a drift here silently attests the wrong
    # bytes (this test caught REPORT_DATA/MEASUREMENT/REPORTED_TCB/
    # CHIP_ID being placed at doubled offsets during review).
    def test_table20_offsets(self):
        self.assertEqual(ta.SNP_REPORT_SIZE, 0x4A0)
        self.assertEqual(ta.SNP_SIGNED_SIZE, 0x2A0)
        self.assertEqual(ta.SNP_SIG_OFFSET, 0x2A0)
        self.assertEqual(ta.SNP_REPORT_DATA, 0x50)
        self.assertEqual(ta.SNP_MEASUREMENT, 0x90)
        self.assertEqual(ta.SNP_REPORTED_TCB, 0x180)
        self.assertEqual(ta.SNP_CHIP_ID, 0x1A0)

    def test_fixture_places_fields_at_table20_offsets(self):
        fx = _snp_fixture()
        report = fx["report"]
        self.assertEqual(report[0x50:0x50 + 64],
                         ta.report_data_for("P-384", fx["tee_pubkey"],
                                            fx["salt"]))
        self.assertEqual(report[0x90:0x90 + 48], fx["measurement"])
        self.assertEqual(report[0x180:0x180 + 8], fx["tcb"])
        self.assertEqual(report[0x1A0:0x1A0 + 64], fx["chip_id"])
        self.assertEqual(struct.unpack_from("<Q", report, 0x08)[0],
                         fx["policy"])
        self.assertEqual(struct.unpack_from("<I", report, 0x34)[0],
                         ta.SNP_SIG_ALGO_ECDSA_P384_SHA384)


class SnpVerifierTests(unittest.TestCase):
    def _verifier(self, fx):
        return ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"], enabled=True)

    def test_conforming_verifies(self):
        fx = _snp_fixture()
        claims = self._verifier(fx).verify(_snp_bundle(fx))
        self.assertEqual(claims["kind"], "sev_snp_attested")
        self.assertEqual(claims["platform"], "sev-snp")
        self.assertEqual(claims["measurement"], fx["measurement"].hex())
        self.assertEqual(len(claims["evidence_digest"]), 64)

    def test_wrong_report_size_refused(self):
        fx = _snp_fixture()
        bundle = _snp_bundle(fx)
        bundle["report"] = bundle["report"][:-1]
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_wrong_version_refused(self):
        fx = _snp_fixture()
        bad = bytearray(fx["report"])
        struct.pack_into("<I", bad, 0, 99)
        bundle = _snp_bundle(fx)
        bundle["report"] = bytes(bad)
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_bigendian_rs_refused(self):
        # The signature blob stores R/S little-endian; a big-endian
        # reader must fail, while the little-endian original verifies.
        fx = _snp_fixture()
        self._verifier(fx).verify(_snp_bundle(fx))  # control passes
        blob = bytearray(
            fx["report"][ta.SNP_SIG_OFFSET:
                         ta.SNP_SIG_OFFSET + ta.SNP_SIG_BLOB])
        r = int.from_bytes(bytes(blob[0:72]), "little")
        s = int.from_bytes(bytes(blob[72:144]), "little")
        blob[0:72] = r.to_bytes(72, "big")
        blob[72:144] = s.to_bytes(72, "big")
        bad = (fx["report"][:ta.SNP_SIG_OFFSET] + bytes(blob)
               + fx["report"][ta.SNP_SIG_OFFSET + ta.SNP_SIG_BLOB:])
        bundle = _snp_bundle(fx)
        bundle["report"] = bad
        with self.assertRaises(ta.TeeAttestError):
            self._verifier(fx).verify(bundle)

    def test_signature_is_load_bearing(self):
        # Flip a measurement byte and update the *expectation* to match:
        # policy now agrees, so only the report signature can refuse.
        fx = _snp_fixture()
        bad = bytearray(fx["report"])
        bad[ta.SNP_MEASUREMENT] ^= 0x01
        bundle = _snp_bundle(fx)
        bundle["report"] = bytes(bad)
        bundle["expected_measurement"] = bytes(
            bad[ta.SNP_MEASUREMENT:ta.SNP_MEASUREMENT + 48])
        with self.assertRaises(ta.ChainError):
            self._verifier(fx).verify(bundle)

    def test_nonzero_signature_trailer_refused(self):
        fx = _snp_fixture()
        bad = bytearray(fx["report"])
        bad[ta.SNP_SIG_OFFSET + 200] = 0x01
        bundle = _snp_bundle(fx)
        bundle["report"] = bytes(bad)
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_wrong_ark_refused(self):
        fx = _snp_fixture()
        rogue = _snp_fixture()
        verifier = ta.SevSnpVerifier(ark_pubkey=rogue["ark_pubkey"],
                                     enabled=True)
        with self.assertRaises(ta.ChainError):
            verifier.verify(_snp_bundle(fx))

    def test_vcek_tcb_mismatch_refused(self):
        fx = _snp_fixture()
        bad = bytearray(fx["report"])
        bad[ta.SNP_REPORTED_TCB] ^= 0xFF
        bundle = _snp_bundle(fx)
        bundle["report"] = bytes(bad)
        with self.assertRaises(ta.ChainError):
            self._verifier(fx).verify(bundle)

    def test_measurement_policy_allowlist_refused(self):
        fx = _snp_fixture()
        bundle = _snp_bundle(fx)
        bundle["expected_measurement"] = b"X" * 48
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)
        bundle = _snp_bundle(fx)
        bundle["expected_policy"] = fx["policy"] ^ 0xFFFF
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)
        bundle = _snp_bundle(fx)
        bundle["tcb_allowlist"] = [b"\x00" * 8]
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)
        bundle = _snp_bundle(fx)
        bundle["tcb_allowlist"] = []
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)

    def test_report_data_salt_mismatch_refused(self):
        fx = _snp_fixture()
        bundle = _snp_bundle(fx)
        bundle["salt"] = b"Z" * 32
        with self.assertRaises(ta.BindingError):
            self._verifier(fx).verify(bundle)

    def test_malformed_cert_pubkey_encoding_refused(self):
        # A cert with a *valid* issuer signature but garbage base64url in
        # the pubkey field must refuse as ChainError, never leak a raw
        # ValueError from the decoder.
        fx = _snp_fixture()
        body = {"subject": "ask", "pubkey": "!!!not-base64!!!",
                "tcb": fx["tcb"].hex(), "chip_id": fx["chip_id"].hex()}
        digest = ta._sha384(ta._canonical_json(body))
        r, s = ta.ecdsa_sign(ta.P384, fx["ark_priv"], digest)
        cert = dict(body, sig_r=format(r, "x"), sig_s=format(s, "x"))
        bundle = _snp_bundle(fx)
        bundle["ask_cert"] = cert
        with self.assertRaises(ta.ChainError):
            self._verifier(fx).verify(bundle)

    def test_non_bytes_report_refused(self):
        fx = _snp_fixture()
        bundle = _snp_bundle(fx)
        bundle["report"] = "not-bytes"
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_fixture_input_validation(self):
        with self.assertRaises(ta.TeeAttestError):
            _snp_fixture(measurement=b"short")
        with self.assertRaises(ta.TeeAttestError):
            _snp_fixture(salt=b"short")
        with self.assertRaises(ta.TeeAttestError):
            _snp_fixture(policy=-1)


class TdxLayoutTests(unittest.TestCase):
    # Pin the synthetic quote body to the real Intel TDX body offsets:
    # MRTD at 136, RTMR0 at 328, REPORTDATA at 520..584 (the last field).
    # A drift here silently measures the wrong bytes.
    def test_body_offsets(self):
        self.assertEqual(ta.TDX_HEADER_SIZE, 48)
        self.assertEqual(ta.TDX_BODY_SIZE, 584)
        self.assertEqual(ta.TDX_MRTD, 136)
        self.assertEqual(ta.TDX_RTMR0, 328)
        self.assertEqual(ta.TDX_REPORTDATA, 520)

    def test_fixture_places_fields_at_body_offsets(self):
        fx = _tdx_fixture()
        body = fx["quote"][ta.TDX_BODY_OFFSET:
                           ta.TDX_BODY_OFFSET + ta.TDX_BODY_SIZE]
        self.assertEqual(body[136:136 + 48], fx["mrtd"])
        for i in range(4):
            self.assertEqual(body[328 + i * 48:328 + (i + 1) * 48],
                             fx["rtmrs"].get(i, b"\x00" * 48))
        self.assertEqual(body[520:520 + 64],
                         ta.report_data_for("P-256", fx["tee_pubkey"],
                                            fx["salt"]))


class TdxVerifierTests(unittest.TestCase):
    def _verifier(self, fx):
        return ta.TdxQuoteVerifier(intel_root_pubkey=fx["intel_root_pubkey"],
                                    enabled=True)

    def test_conforming_verifies(self):
        fx = _tdx_fixture()
        claims = self._verifier(fx).verify(_tdx_bundle(fx))
        self.assertEqual(claims["kind"], "tdx_attested")
        self.assertEqual(claims["platform"], "tdx")
        self.assertEqual(claims["measurement"], fx["mrtd"].hex())
        self.assertEqual(len(claims["evidence_digest"]), 64)

    def test_local_tdreport_refused_first(self):
        fx = _tdx_fixture()
        local = ta.make_synthetic_local_tdreport(
            mrtd=fx["mrtd"], tee_pubkey=fx["tee_pubkey"], salt=fx["salt"])
        self.assertEqual(len(local), ta.TDX_LOCAL_SIZE)
        bundle = _tdx_bundle(fx)
        bundle["quote"] = local
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_severed_qe_binding_refused(self):
        # Mutate the QE report_data (breaking hop b) but re-sign the QE
        # report with the legitimate PCK key: hop (a) still holds, so the
        # refusal must come from the binding check itself.
        fx = _tdx_fixture()
        fx["qe_report"] = {"report_data": "00" * 32}
        bundle = _tdx_bundle(fx)
        bundle["quote"] = ta._rebind_tdx_quote(fx)
        with self.assertRaises(ta.BindingError):
            self._verifier(fx).verify(bundle)

    def test_wrong_attestation_key_refused(self):
        # Hop (b) binds the original attestation key; signing the body
        # with a fresh key breaks hop (c).
        fx = _tdx_fixture()
        fx["att_priv"], att_pub = ta.gen_keypair("P-256")
        fx["att_point"] = ta._point_from_bytes(ta.P256, att_pub)
        bundle = _tdx_bundle(fx)
        bundle["quote"] = ta._rebind_tdx_quote(fx)
        with self.assertRaises(ta.BindingError):
            self._verifier(fx).verify(bundle)

    def test_unpinned_pck_refused(self):
        fx = _tdx_fixture()
        rogue_priv, _ = ta.gen_keypair("P-256")
        fx["pck_cert"] = ta.make_pck_cert(
            fx["pck_priv"], fx["pck_pubkey"],
            tcb_hex="tcb-fixture", issuer_priv=rogue_priv)
        bundle = _tdx_bundle(fx)
        bundle["quote"] = ta._rebind_tdx_quote(fx)
        with self.assertRaises(ta.ChainError):
            self._verifier(fx).verify(bundle)

    def test_expired_collateral_refused(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        bundle["tcb_info"] = {"valid_from": fx["now"] - 20000,
                              "valid_until": fx["now"] - 1}
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)

    def test_missing_collateral_refused(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        del bundle["pck_cert"]
        with self.assertRaises(ta.TeeAttestError):
            self._verifier(fx).verify(bundle)
        bundle = _tdx_bundle(fx)
        del bundle["tcb_info"]
        with self.assertRaises(ta.TeeAttestError):
            self._verifier(fx).verify(bundle)

    def test_mrtd_mismatch_refused(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        bundle["expected_mrtd"] = b"Q" * 48
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)

    def test_reportdata_salt_mismatch_refused(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        bundle["salt"] = b"Z" * 32
        with self.assertRaises(ta.BindingError):
            self._verifier(fx).verify(bundle)

    def test_truncated_quote_refused(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        bundle["quote"] = fx["quote"][:100]
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)

    def test_expected_rtmrs_validated(self):
        fx = _tdx_fixture()
        bundle = _tdx_bundle(fx)
        bundle["expected_rtmrs"] = {"0": b"r" * 48}
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)
        bundle = _tdx_bundle(fx)
        bundle["expected_rtmrs"] = {9: b"r" * 48}
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)
        bundle = _tdx_bundle(fx)
        bundle["expected_rtmrs"] = {0: b"short"}
        with self.assertRaises(ta.PolicyError):
            self._verifier(fx).verify(bundle)

    def test_unknown_kind_refused(self):
        fx = _tdx_fixture()
        bad = bytearray(fx["quote"])
        bad[0] = 0x7F
        bundle = _tdx_bundle(fx)
        bundle["quote"] = bytes(bad)
        with self.assertRaises(ta.ReportFormatError):
            self._verifier(fx).verify(bundle)


class CompositionTests(unittest.TestCase):
    def _within(self):
        return ap.AuthorityProof(
            verdict=ap.WITHIN, covered_domains=("fs",),
            uncovered_domains=(), counterexample=None, boundary_id="b1",
            boundary_version="1", resolution_source="path_resolved",
            detail="fs ok")

    def test_attach_records_platform_and_measurement(self):
        fx = _snp_fixture()
        claims = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"],
                                   enabled=True).verify(_snp_bundle(fx))
        out = ta.attach_tee_proof(self._within(), claims)
        self.assertIn("platform:sev-snp", out.detail)
        self.assertIn("measurement:%s" % fx["measurement"].hex(),
                      out.detail)
        self.assertEqual(out.verdict, ap.WITHIN)

    def test_attach_refuses_non_within(self):
        fx = _snp_fixture()
        claims = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"],
                                   enabled=True).verify(_snp_bundle(fx))
        for verdict in (ap.EXCEEDS, ap.UNSUPPORTED, ap.INCONCLUSIVE):
            proof = ap.AuthorityProof(
                verdict=verdict, covered_domains=(), uncovered_domains=(),
                counterexample=None, boundary_id="b1",
                boundary_version="1", resolution_source="path_resolved",
                detail="denied")
            with self.assertRaises(ta.BindingError):
                ta.attach_tee_proof(proof, claims)

    def test_attach_requires_claims(self):
        with self.assertRaises(ta.BindingError):
            ta.attach_tee_proof(self._within(), {"platform": "tdx"})

    def test_bom_section_shape(self):
        fx = _tdx_fixture()
        claims = ta.TdxQuoteVerifier(
            intel_root_pubkey=fx["intel_root_pubkey"],
            enabled=True).verify(_tdx_bundle(fx))
        section = ta.tee_bom_section(claims)
        self.assertEqual(section["platform"], "tdx")
        self.assertEqual(section["measurement"], fx["mrtd"].hex())
        self.assertEqual(section["evidence_digest"],
                         claims["evidence_digest"])
        self.assertEqual(section["report_data"], claims["report_data"])

    def test_bom_section_requires_fields(self):
        with self.assertRaises(ta.TeeAttestError):
            ta.tee_bom_section({"platform": "tdx"})
        with self.assertRaises(ta.TeeAttestError):
            ta.tee_bom_section("not-a-dict")


if __name__ == "__main__":
    unittest.main()
