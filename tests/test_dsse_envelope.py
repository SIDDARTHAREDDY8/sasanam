"""Unit tests for gov.dsse_envelope (wave-204 lane B).

Complements evals/dsse_envelope_probes.py (the red-first battery): the
probes attack the public seams break-first; these tests pin edge-case
behavior and error taxonomy at the same seams.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import dsse_envelope as dsse
from gov.signing import Ed25519Signer, Ed25519Verifier

P1 = "ab" * 32
P2 = "cd" * 32
COMMENTS = ["release-approval v5", "auditor: acme-audit"]
STYPE = dsse.STATEMENT_PAYLOAD_TYPE


def keys():
    s1 = Ed25519Signer(bytes([11]) * 32)
    s2 = Ed25519Signer(bytes([22]) * 32)
    return (s1, Ed25519Verifier(s1.public_key, s1.key_id),
            s2, Ed25519Verifier(s2.public_key, s2.key_id))


class TestPAE(unittest.TestCase):
    def test_known_vector(self):
        # Independent source of truth: the DSSE spec formula.
        self.assertEqual(dsse.pae("application/json", b"hello"),
                         b"DSSEv1 16 application/json 5 hello")

    def test_empty_payload(self):
        self.assertEqual(dsse.pae("t", b""), b"DSSEv1 1 t 0 ")

    def test_type_with_space(self):
        # Length-prefixing keeps "a b" unambiguous.
        got = dsse.pae("a b", b"xy")
        self.assertEqual(got, b"DSSEv1 3 a b 2 xy")

    def test_rejects_empty_type(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.pae("", b"x")

    def test_rejects_non_bytes_payload(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.pae("t", "x")


class TestStrictParse(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, _, _ = keys()
        self.env = dsse.seal(b"data", "t", [self.s1])

    def test_round_trip(self):
        got = dsse.open_envelope(self.env, b"data", "t", [self.v1])
        self.assertEqual(got["key_ids"], [self.s1.key_id])
        self.assertEqual(got["payload_type"], "t")

    def test_missing_payload(self):
        env = copy.deepcopy(self.env)
        del env["payload"]
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_sig_uppercase_hex_refused(self):
        env = copy.deepcopy(self.env)
        env["signatures"][0]["sig"] = env["signatures"][0]["sig"].upper()
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_sig_wrong_length_refused(self):
        env = copy.deepcopy(self.env)
        env["signatures"][0]["sig"] = "ab" * 16
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_signature_entry_unknown_field_refused(self):
        env = copy.deepcopy(self.env)
        env["signatures"][0]["alg"] = "ed25519"
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_empty_signatures_refused(self):
        env = copy.deepcopy(self.env)
        env["signatures"] = []
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_seal_requires_signer(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.seal(b"data", "t", [])

    def test_open_requires_verifier(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(self.env, b"data", "t", [])

    def test_threshold_zero_refused(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(self.env, b"data", "t", [self.v1], threshold=0)

    def test_unknown_keyid_contributes_nothing(self):
        env = copy.deepcopy(self.env)
        env["signatures"][0]["keyid"] = "no-such-key"
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1])

    def test_duplicate_keyid_counts_once(self):
        # Two signature entries from the same key = one distinct key.
        env = dsse.seal(b"data", "t", [self.s1, self.s1])
        self.assertEqual(len(env["signatures"]), 2)
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(env, b"data", "t", [self.v1], threshold=2)

    def test_keyid_less_signature(self):
        env = copy.deepcopy(self.env)
        del env["signatures"][0]["keyid"]
        got = dsse.open_envelope(env, b"data", "t", [self.v1])
        self.assertEqual(got["key_ids"], [self.s1.key_id])

    def test_allowlist(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_envelope(self.env, b"data", "t", [self.v1],
                               allowed_payload_types=frozenset({"other"}))
        got = dsse.open_envelope(self.env, b"data", "t", [self.v1],
                                 allowed_payload_types=frozenset({"t"}))
        self.assertEqual(got["payload_type"], "t")


class TestStatement(unittest.TestCase):
    def setUp(self):
        self.s1, self.v1, self.s2, self.v2 = keys()

    def test_round_trip_with_provenance(self):
        env = dsse.seal_statement(P1, P2, COMMENTS, [self.s1])
        got = dsse.open_statement(env, P1, P2, COMMENTS, [self.v1])
        self.assertEqual(got["provenance_digest"], P2)
        self.assertEqual(got["trusted_comments"], COMMENTS)

    def test_round_trip_provenance_free(self):
        env = dsse.seal_statement(P1, None, COMMENTS, [self.s1])
        got = dsse.open_statement(env, P1, None, COMMENTS, [self.v1])
        self.assertIsNone(got["provenance_digest"])

    def test_non_canonical_statement_refused(self):
        # Same fields, different key order / spacing: signature was over
        # canonical bytes, so this must fail on the signature path.
        env = dsse.seal_statement(P1, P2, COMMENTS, [self.s1])
        env2 = copy.deepcopy(env)
        stmt = {"trusted_comments": COMMENTS, "provenance_digest": P2,
                "payload_sha256": P1}
        env2["payload"] = base64.b64encode(
            json.dumps(stmt, indent=2).encode("utf-8")).decode("ascii")
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_statement(env2, P1, P2, COMMENTS, [self.v1])

    def test_statement_unknown_field_refused(self):
        # A statement with an extra field cannot be produced by
        # seal_statement; if it somehow arrives signed (e.g. a different
        # producer), the strict shape check refuses it.
        env = dsse.seal_statement(P1, P2, COMMENTS, [self.s1, self.s2])
        raw = base64.b64decode(env["payload"])
        stmt = json.loads(raw.decode("utf-8"))
        stmt["extra"] = 1
        # Re-sign with both keys so the signature is valid for the new
        # bytes: the refusal must come from the shape check, proving the
        # shape check is load-bearing and not dead code.
        env2 = dsse.seal(json.dumps(stmt, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8"),
                         STYPE, [self.s1, self.s2])
        with self.assertRaises(dsse.EnvelopeError):
            dsse.open_statement(env2, P1, P2, COMMENTS,
                                [self.v1, self.v2], threshold=2)

    def test_empty_comments_refused_at_seal(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.seal_statement(P1, P2, [], [self.s1])

    def test_bad_digest_refused_at_seal(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.seal_statement("not-hex", P2, COMMENTS, [self.s1])


class TestDispatch(unittest.TestCase):
    def test_detect_dsse(self):
        s1, _, _, _ = keys()
        env = dsse.seal(b"x", "t", [s1])
        self.assertEqual(dsse.detect_envelope(env), "dsse")

    def test_detect_v2(self):
        from gov import signature_envelope_v2 as env2
        s1, _, _, _ = keys()
        env = env2.seal(P1, s1, COMMENTS, provenance_digest=P2)
        self.assertEqual(dsse.detect_envelope(env), "v2")

    def test_detect_unknown(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.detect_envelope({"foo": 1})

    def test_open_any_dsse(self):
        s1, v1, _, _ = keys()
        env = dsse.seal_statement(P1, P2, COMMENTS, [s1])
        got = dsse.open_any(env, P1, P2, COMMENTS, [v1])
        self.assertEqual(got["format"], "dsse")

    def test_open_any_v2(self):
        from gov import signature_envelope_v2 as env2
        s1, v1, _, _ = keys()
        env = env2.seal(P1, s1, COMMENTS, provenance_digest=P2)
        got = dsse.open_any(env, P1, P2, COMMENTS, [v1])
        self.assertEqual(got["format"], "v2")
        self.assertEqual(got["trusted_comments"], COMMENTS)


# ---------------------------------------------------------------------------
# Wave-232 lane C: vendored payload-type namespace, strict PAE decode,
# plain-callback envelope wrapper.
# ---------------------------------------------------------------------------


_W232_PT = "application/vnd.sasanam.denial-receipt+json"
_W232_PAYLOAD = b'{"verdict":"DENY"}'

# Hand-computed from the PAE shape: "DSSEv1" + " " + "43" + " " + type
# (43 bytes) + " " + "18" + " " + payload (18 bytes). Independent
# literal, not recomputed by the code under test.
_W232_PAE = (
    b"DSSEv1 43 application/vnd.sasanam.denial-receipt+json "
    b"18 " + _W232_PAYLOAD
)


def _w232_signer(secret):
    def _sign(msg):
        return hmac.new(secret, msg, hashlib.sha256).digest()
    return _sign


def _w232_verifier(secret):
    def _verify(msg, sig):
        return hmac.compare_digest(
            hmac.new(secret, msg, hashlib.sha256).digest(), sig)
    return _verify


class TestVendoredNamespace(unittest.TestCase):
    def test_vendored_type_accepted(self):
        self.assertEqual(
            dsse.check_payload_type_namespace(_W232_PT), _W232_PT)

    def test_generic_type_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.check_payload_type_namespace("application/json")
        self.assertIn("dsse-payload-type-refused", ctx.exception.reason)

    def test_empty_type_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.check_payload_type_namespace("")
        self.assertIn("dsse-payload-type-refused", ctx.exception.reason)

    def test_non_string_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.check_payload_type_namespace(None)
        self.assertIn("dsse-payload-type-refused", ctx.exception.reason)


class TestPaeDecode(unittest.TestCase):
    def test_round_trip_literal(self):
        self.assertEqual(dsse.pae(_W232_PT, _W232_PAYLOAD), _W232_PAE)
        got_type, got_body = dsse.pae_decode(_W232_PAE)
        self.assertEqual(got_type, _W232_PT)
        self.assertEqual(got_body, _W232_PAYLOAD)

    def test_leading_zero_refused(self):
        amb = _W232_PAE.replace(b"DSSEv1 43 ", b"DSSEv1 043 ", 1)
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.pae_decode(amb)
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_trailing_bytes_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.pae_decode(_W232_PAE + b"\x00")
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_wrong_domain_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.pae_decode(b"X" + _W232_PAE[1:])
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_truncated_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.pae_decode(_W232_PAE[:-5])
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_non_decimal_length_refused(self):
        bad = _W232_PAE.replace(b"DSSEv1 43 ", b"DSSEv1 4x ", 1)
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.pae_decode(bad)
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)


class TestCallbackEnvelope(unittest.TestCase):
    def setUp(self):
        self.secret = hashlib.sha256(b"unit-dsse-key").digest()

    def test_round_trip(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret), key_id="k1")
        out = dsse.verify_envelope(env, verify=_w232_verifier(self.secret),
                                   expect_payload_type=_W232_PT)
        self.assertTrue(out["ok"])
        self.assertEqual(out["payload"], _W232_PAYLOAD)
        self.assertEqual(out["key_id"], "k1")

    def test_wrong_expected_type_refused(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret))
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(
                env, verify=_w232_verifier(self.secret),
                expect_payload_type=
                "application/vnd.sasanam.decision-packet+json")
        self.assertIn("dsse-payload-type-refused", ctx.exception.reason)

    def test_tampered_payload_refused(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret))
        bad = dict(env)
        raw = bytearray(base64.b64decode(bad["payload"]))
        raw[0] ^= 0x01
        bad["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(bad, verify=_w232_verifier(self.secret),
                                 expect_payload_type=_W232_PT)
        self.assertTrue(
            "dsse-signature-invalid" in ctx.exception.reason
            or "dsse-envelope-malformed" in ctx.exception.reason)

    def test_wrong_key_refused(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret))
        other = hashlib.sha256(b"other-key").digest()
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(env, verify=_w232_verifier(other),
                                 expect_payload_type=_W232_PT)
        self.assertIn("dsse-signature-invalid", ctx.exception.reason)

    def test_unknown_field_refused(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret))
        bad = dict(env)
        bad["extra"] = "nope"
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(bad, verify=_w232_verifier(self.secret))
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_digest_binding_mismatch_refused(self):
        env = dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT,
                            sign=_w232_signer(self.secret))
        bad = dict(env)
        bad["signing_input_digest"] = "0" * 64
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(bad, verify=_w232_verifier(self.secret))
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_signer_failure_is_malformed(self):
        def _boom(_msg):
            raise RuntimeError("nope")

        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.envelope(_W232_PAYLOAD, payload_type=_W232_PT, sign=_boom)
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)


class TestOneSignatureDiscipline(unittest.TestCase):
    """Wave-233: exactly-one-signature rule, expected_type binding, and
    cross-module transplant naming at the verify_envelope seam."""

    def setUp(self):
        self.secret = hashlib.sha256(b"unit-one-sig").digest()
        self.sign = _w232_signer(self.secret)
        self.verify = _w232_verifier(self.secret)
        self.pt = _W232_PT
        self.pt_other = "application/vnd.sasanam.decision-packet+json"
        self.pt_free = "application/vnd.sasanam.unclaimed+json"

    def _env(self, payload_type=None):
        return dsse.envelope(_W232_PAYLOAD,
                             payload_type=payload_type or self.pt,
                             sign=self.sign)

    def _two_sig_env(self, bad_second=False):
        env = dict(self._env())
        second = ("00" * 32 if bad_second else hmac.new(
            self.secret, dsse.pae(self.pt, _W232_PAYLOAD),
            hashlib.sha256).digest().hex())
        env["signatures"] = list(env["signatures"]) + [
            {"keyid": "k2", "sig": second}]
        return env

    def test_zero_signatures_refused(self):
        env = dict(self._env())
        env["signatures"] = []
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(env, verify=self.verify,
                                 expect_payload_type=self.pt)
        self.assertIn("dsse-envelope-no-signature", ctx.exception.reason)

    def test_two_signatures_default_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._two_sig_env(), verify=self.verify,
                                 expect_payload_type=self.pt)
        self.assertIn("dsse-envelope-multi-signature", ctx.exception.reason)

    def test_opt_in_two_valid_signatures_verifies(self):
        out = dsse.verify_envelope(self._two_sig_env(), verify=self.verify,
                                   expect_payload_type=self.pt,
                                   expected_signatures=2)
        self.assertTrue(out["ok"])
        self.assertEqual(out["payload"], _W232_PAYLOAD)

    def test_opt_in_no_partial_acceptance(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._two_sig_env(bad_second=True),
                                 verify=self.verify,
                                 expect_payload_type=self.pt,
                                 expected_signatures=2)
        self.assertIn("dsse-signature-invalid", ctx.exception.reason)

    def test_opt_in_count_mismatch_refused(self):
        # expected_signatures=2 but the envelope carries 1.
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._env(), verify=self.verify,
                                 expect_payload_type=self.pt,
                                 expected_signatures=2)
        self.assertIn("dsse-envelope-multi-signature", ctx.exception.reason)
        # expected_signatures=1 but the envelope carries 2.
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._two_sig_env(), verify=self.verify,
                                 expect_payload_type=self.pt,
                                 expected_signatures=1)
        self.assertIn("dsse-envelope-multi-signature", ctx.exception.reason)

    def test_expected_signatures_must_be_positive_int(self):
        # None is the valid no-opt-in sentinel (default exactly-one).
        for bad in (0, -1, "2", 2.0, True):
            with self.assertRaises(dsse.EnvelopeError) as ctx:
                dsse.verify_envelope(self._env(), verify=self.verify,
                                     expect_payload_type=self.pt,
                                     expected_signatures=bad)
            self.assertIn("dsse-envelope-malformed", ctx.exception.reason)

    def test_expected_type_match_verifies(self):
        out = dsse.verify_envelope(self._env(), verify=self.verify,
                                   expected_type=self.pt)
        self.assertTrue(out["ok"])

    def test_expected_type_mismatch_refused(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._env(), verify=self.verify,
                                 expected_type=self.pt_free)
        self.assertIn("dsse-payloadtype-mismatch", ctx.exception.reason)

    def test_legacy_expect_payload_type_unchanged(self):
        # The wave-232 path keeps its refusal code and behavior.
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._env(), verify=self.verify,
                                 expect_payload_type=self.pt_free)
        self.assertIn("dsse-payload-type-refused", ctx.exception.reason)

    def test_transplant_refused(self):
        # Throwaway vendored types, never the real module constants:
        # these tests must not overwrite (or delete) legitimate domain
        # registrations when run in the full suite alongside
        # test_decision_packet / test_deny_receipts.
        type_a = "application/vnd.sasanam.test-domain-a+json"
        type_b = "application/vnd.sasanam.test-domain-b+json"
        dsse.register_envelope_domain("domain-a", type_a)
        dsse.register_envelope_domain("domain-b", type_b)
        try:
            env = dsse.envelope(_W232_PAYLOAD, payload_type=type_b,
                                sign=self.sign)
            with self.assertRaises(dsse.EnvelopeError) as ctx:
                dsse.verify_envelope(env, verify=self.verify,
                                     expected_domain="domain-a")
            self.assertIn("dsse-envelope-transplant", ctx.exception.reason)
        finally:
            dsse._ENVELOPE_DOMAIN_TYPES.pop(type_a, None)
            dsse._ENVELOPE_DOMAIN_TYPES.pop(type_b, None)
            dsse._ENVELOPE_DOMAINS.pop("domain-a", None)
            dsse._ENVELOPE_DOMAINS.pop("domain-b", None)

    def test_unregistered_type_is_not_transplant(self):
        type_a = "application/vnd.sasanam.test-domain-a+json"
        type_free = "application/vnd.sasanam.test-unclaimed+json"
        dsse.register_envelope_domain("domain-a", type_a)
        try:
            # type_free is vendored but registered to no domain:
            # not a transplant -- falls through to the type binding.
            env = dsse.envelope(_W232_PAYLOAD, payload_type=type_free,
                                sign=self.sign)
            with self.assertRaises(dsse.EnvelopeError) as ctx:
                dsse.verify_envelope(
                    env, verify=self.verify,
                    expected_domain="domain-a",
                    expected_type=type_a)
            self.assertIn("dsse-payloadtype-mismatch", ctx.exception.reason)
        finally:
            dsse._ENVELOPE_DOMAIN_TYPES.pop(type_a, None)
            dsse._ENVELOPE_DOMAINS.pop("domain-a", None)

    def test_register_domain_idempotent_and_lookup(self):
        type_a = "application/vnd.sasanam.test-domain-a+json"
        dsse.register_envelope_domain("domain-a", type_a)
        try:
            dsse.register_envelope_domain("domain-a", type_a)
            self.assertEqual(dsse.envelope_domain_of(type_a), "domain-a")
            self.assertIsNone(dsse.envelope_domain_of(self.pt_free))
        finally:
            dsse._ENVELOPE_DOMAIN_TYPES.pop(type_a, None)
            dsse._ENVELOPE_DOMAINS.pop("domain-a", None)

    def test_register_domain_rejects_bad_inputs(self):
        with self.assertRaises(dsse.EnvelopeError):
            dsse.register_envelope_domain("", self.pt)
        with self.assertRaises(dsse.EnvelopeError):
            dsse.register_envelope_domain("d", "application/json")

    def test_expected_domain_must_be_non_empty_str(self):
        with self.assertRaises(dsse.EnvelopeError) as ctx:
            dsse.verify_envelope(self._env(), verify=self.verify,
                                 expected_domain="")
        self.assertIn("dsse-envelope-malformed", ctx.exception.reason)


if __name__ == "__main__":
    unittest.main()
