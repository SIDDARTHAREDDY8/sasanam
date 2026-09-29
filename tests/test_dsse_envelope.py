"""Unit tests for gov.dsse_envelope (wave-204 lane B).

Complements evals/dsse_envelope_probes.py (the red-first battery): the
probes attack the public seams break-first; these tests pin edge-case
behavior and error taxonomy at the same seams.
"""

import base64
import copy
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


if __name__ == "__main__":
    unittest.main()
