"""Unit tests for gov.evidence_intoto (wave-310 lane E).

in-toto Statement v1 re-enveloping for the offline evidence bundle
(prospectus build-order step 2, ``research/prospecting/w308_evidence_envelopes.md``):
the bundle becomes the ``subject`` (digest-matched, capture-time) of an
in-toto Statement under our predicateType namespace, sealed with the
wave-309 DSSE module (payloadType ``application/vnd.in-toto+json``).

These tests pin the statement seam:

- the 4-field statement shape (``_type``/``subject``/``predicateType``/
  ``predicate``) per the in-toto Statement v1 spec;
- the subject digest is the sha256 of the EXACT bundle bytes supplied
  (capture-time, never recomputed at export);
- ``predicateType`` is our namespace URI; the predicate passes through
  by reference (no redesign of the bundle);
- the sealed payload is the canonical serialization of the statement;
- the signature is over the spec PAE (independent hand-built check,
  not tautological);
- the verifier's discipline: authentication precedes binding (the
  subject digest must match the caller's expected bundle bytes),
  tampered predicates break the signature, threshold behavior is
  inherited from the DSSE layer;
- the third-party acceptance test: verify with stdlib json + the
  spec's PAE formula + raw ed25519 only — no Sasanam envelope code —
  proving "sell evidence, not the engine".
"""

import base64
import copy
import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import dsse_envelope as _dsse
from gov import ed25519 as _ed25519
from gov import evidence_dsse
from gov import evidence_intoto
from gov.signing import Ed25519Signer, Ed25519Verifier

INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"
PT = evidence_dsse.EVIDENCE_DSSE_PAYLOAD_TYPE

BUNDLE = b'{"bundle":"synthetic-test-bytes-001"}'
OTHER = b'{"bundle":"different-bytes-002"}'
CLAIMS = {"window": "2026-10-03", "tip": "ab" * 16, "decisions": 3}


def _signers(n, base=21):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _seal(stmt, signers):
    return evidence_intoto.seal_statement(stmt, signers)


class TestStatementShape(unittest.TestCase):
    def test_four_fields_exactly(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(set(stmt),
                         {"_type", "subject", "predicateType", "predicate"})

    def test_type_is_intoto_v1(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(stmt["_type"], INTOTO_TYPE)

    def test_subject_is_single_digest_entry(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(stmt["subject"], [{
            "name": "evidence-bundle",
            "digest": {"sha256": hashlib.sha256(BUNDLE).hexdigest()},
        }])

    def test_digest_is_of_the_input_bytes(self):
        # Capture-time: the digest commits to the exact bytes supplied,
        # not to anything recomputed at export.
        stmt = evidence_intoto.build_statement(OTHER, CLAIMS)
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"],
                         hashlib.sha256(OTHER).hexdigest())
        self.assertNotEqual(
            stmt["subject"][0]["digest"]["sha256"],
            hashlib.sha256(BUNDLE).hexdigest())

    def test_predicate_type_is_our_namespace(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(stmt["predicateType"], PREDICATE_TYPE)

    def test_predicate_passed_through(self):
        # The bundle's claims object passes through untouched: this lane
        # does not redesign the bundle, it re-envelopes it.
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(stmt["predicate"], CLAIMS)
        self.assertIs(stmt["predicate"], CLAIMS)

    def test_bundle_bytes_must_be_nonempty_bytes(self):
        for bad in (b"", "", None, 123, ["x"]):
            with self.assertRaises(_dsse.EnvelopeError):
                evidence_intoto.build_statement(bad, CLAIMS)

    def test_predicate_claims_must_be_dict(self):
        for bad in (None, [], "claims", 42):
            with self.assertRaises(_dsse.EnvelopeError):
                evidence_intoto.build_statement(BUNDLE, bad)


class TestStatementBytes(unittest.TestCase):
    def test_canonical_serialization(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        raw = evidence_intoto.statement_bytes(stmt)
        expect = json.dumps(stmt, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("utf-8")
        self.assertEqual(raw, expect)

    def test_deterministic(self):
        a = evidence_intoto.statement_bytes(
            evidence_intoto.build_statement(BUNDLE, CLAIMS))
        b = evidence_intoto.statement_bytes(
            evidence_intoto.build_statement(BUNDLE, CLAIMS))
        self.assertEqual(a, b)

    def test_rejects_non_dict(self):
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.statement_bytes("not-a-dict")


class TestSeal(unittest.TestCase):
    def test_envelope_shape_and_type(self):
        env = _seal(evidence_intoto.build_statement(BUNDLE, CLAIMS),
                    _signers(1))
        self.assertEqual(set(env), {"payload", "payloadType", "signatures"})
        self.assertEqual(env["payloadType"], PT)
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")

    def test_payload_is_statement_bytes(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = _seal(stmt, _signers(1))
        self.assertEqual(base64.b64decode(env["payload"]),
                         evidence_intoto.statement_bytes(stmt))

    def test_signature_is_over_spec_pae(self):
        # Independent check: hand-build the PAE from the spec formula
        # (not via dsse_envelope.pae) and verify with the raw primitive,
        # so the test can disagree with the implementation.
        s = _signers(1)[0]
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = _seal(stmt, [s])
        body = base64.b64decode(env["payload"])
        ptype = env["payloadType"].encode("utf-8")
        pae = (b"DSSEv1 " + str(len(ptype)).encode("ascii") + b" " + ptype
               + b" " + str(len(body)).encode("ascii") + b" " + body)
        sig = bytes.fromhex(env["signatures"][0]["sig"])
        self.assertIs(_ed25519.verify(s.public_key, pae, sig), True)

    def test_threshold_signers(self):
        signers = _signers(3)
        env = _seal(evidence_intoto.build_statement(BUNDLE, CLAIMS), signers)
        self.assertEqual(len(env["signatures"]), 3)

    def test_seal_rejects_malformed_statement(self):
        # Fail fast at seal time: a statement that is not our shape is
        # never signed.
        bad = {"_type": INTOTO_TYPE}  # missing subject/predicateType/predicate
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.seal_statement(bad, _signers(1))


class TestOpen(unittest.TestCase):
    def _sealed(self, bundle=BUNDLE, claims=CLAIMS, n=1):
        signers = _signers(n)
        stmt = evidence_intoto.build_statement(bundle, claims)
        return _seal(stmt, signers), signers, stmt

    def test_roundtrip_returns_statement(self):
        env, signers, stmt = self._sealed()
        got = evidence_intoto.open_statement(env, BUNDLE,
                                             _verifiers(signers))
        self.assertEqual(got, stmt)

    def test_accepts_envelope_bytes(self):
        # The wire journey is bytes: envelope_bytes_or_dict.
        env, signers, stmt = self._sealed()
        wire = json.dumps(env).encode("utf-8")
        got = evidence_intoto.open_statement(wire, BUNDLE,
                                             _verifiers(signers))
        self.assertEqual(got, stmt)

    def test_subject_digest_mismatch_refuses(self):
        # Authentication precedes binding: a valid signature over a
        # statement about bundle A does not verify as bundle B.
        env, signers, _ = self._sealed()
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, OTHER, _verifiers(signers))

    def test_returns_envelope_statement_not_caller_claims(self):
        claims_a = {"window": "2026-10-03", "marker": "A"}
        env, signers, stmt = self._sealed(claims=claims_a)
        got = evidence_intoto.open_statement(env, BUNDLE,
                                             _verifiers(signers))
        self.assertEqual(got["predicate"], claims_a)

    def test_tampered_predicate_breaks_signature(self):
        env, signers, _ = self._sealed()
        body = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
        body["predicate"]["window"] = "1999-01-01"
        tampered = copy.deepcopy(env)
        tampered["payload"] = base64.b64encode(
            json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")).decode("ascii")
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(tampered, BUNDLE,
                                           _verifiers(signers))

    def test_wrong_predicate_type_refuses(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        stmt["predicateType"] = "https://example.com/other/v9"
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(
            evidence_intoto.statement_bytes(stmt), signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE,
                                           _verifiers(signers))

    def test_wrong_statement_type_refuses(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        stmt["_type"] = "https://in-toto.io/Statement/v0.1"
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(
            evidence_intoto.statement_bytes(stmt), signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE,
                                           _verifiers(signers))

    def test_wrong_payload_type_refuses(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        signers = _signers(1)
        env = _dsse.seal(evidence_intoto.statement_bytes(stmt),
                         "application/json", signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE,
                                           _verifiers(signers))

    def test_threshold_2_of_3(self):
        env, signers, stmt = self._sealed(n=3)
        got = evidence_intoto.open_statement(env, BUNDLE,
                                             _verifiers(signers),
                                             threshold=2)
        self.assertEqual(got, stmt)

    def test_threshold_not_met_refuses(self):
        env, signers, _ = self._sealed(n=1)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE,
                                           _verifiers(signers),
                                           threshold=2)

    def test_keyid_is_hint(self):
        # Unknown keyid falls back to try-all (inherited DSSE behavior);
        # authentication is not weakened.
        env, signers, stmt = self._sealed()
        stripped = copy.deepcopy(env)
        for entry in stripped["signatures"]:
            entry.pop("keyid", None)
        got = evidence_intoto.open_statement(stripped, BUNDLE,
                                             _verifiers(signers))
        self.assertEqual(got, stmt)

    def test_empty_subject_refuses(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        stmt["subject"] = []
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(
            evidence_intoto.statement_bytes(stmt), signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE,
                                           _verifiers(signers))

    def test_malformed_envelope_refuses(self):
        signers = _signers(1)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement({}, BUNDLE, _verifiers(signers))

    def test_no_verifiers_refuses(self):
        env, _, _ = self._sealed()
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_intoto.open_statement(env, BUNDLE, [])


class TestThirdPartyConsumer(unittest.TestCase):
    """The acceptance test for "sell evidence, not the engine".

    Verify a sealed statement the way a third party would: stdlib JSON +
    the DSSE spec's PAE formula + the raw Ed25519 primitive. No
    ``gov.dsse_envelope``, no ``gov.evidence_dsse``, no
    ``gov.evidence_intoto`` anywhere in the verify path — only the
    signer's public key bytes (which any consumer holds) and the spec.
    """

    def test_verify_with_stdlib_only(self):
        s = _signers(1)[0]
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, [s])

        # The wire journey: the envelope travels as JSON bytes.
        wire = json.dumps(env).encode("utf-8")
        parsed = json.loads(wire.decode("utf-8"))

        # 1. Envelope shape per the DSSE spec.
        self.assertEqual(set(parsed), {"payload", "payloadType",
                                       "signatures"})
        self.assertEqual(parsed["payloadType"],
                         "application/vnd.in-toto+json")

        # 2. Payload bytes (DSSE verifiers MUST accept both base64
        # variants; our seal emits standard).
        body = base64.b64decode(parsed["payload"])

        # 3. PAE hand-built from the spec formula:
        #    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP
        #                      LEN(body) SP body
        ptype = parsed["payloadType"].encode("utf-8")
        pae = (b"DSSEv1 " + str(len(ptype)).encode("ascii") + b" "
               + ptype + b" " + str(len(body)).encode("ascii")
               + b" " + body)

        # 4. Signatures verify with the raw primitive against the
        # signer's public key — threshold 1 here.
        verified = 0
        for entry in parsed["signatures"]:
            sig = bytes.fromhex(entry["sig"])
            if _ed25519.verify(s.public_key, pae, sig) is True:
                verified += 1
        self.assertGreaterEqual(verified, 1)

        # 5. The statement itself is plain in-toto JSON: subject
        # digest-matched against the bundle bytes we hold.
        statement = json.loads(body.decode("utf-8"))
        self.assertEqual(statement["_type"], INTOTO_TYPE)
        self.assertEqual(statement["predicateType"], PREDICATE_TYPE)
        self.assertEqual(
            statement["subject"][0]["digest"]["sha256"],
            hashlib.sha256(BUNDLE).hexdigest())
        self.assertEqual(statement["predicate"], CLAIMS)


if __name__ == "__main__":
    unittest.main()
