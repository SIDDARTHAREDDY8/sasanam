"""Unit tests: human-corroboration receipts (wave-267).

White-box pins for the JCS canonicalizer, the did:key issuer
binding, the cosign-style verify split, and the DataIntegrityProof
layer. The adversarial behavior is covered break-first by
``evals/w267_corrob_probes.py``; these tests pin contracts the
battery exercises end to end.
"""

import base64
import json
import unittest

from gov.agent_identity import did_key_from_pubkey
from gov import corroboration_receipt as cr
from gov import decision_codes
from gov.signing import Ed25519Signer, Ed25519Verifier


def _signer(seed_byte):
    return Ed25519Signer(bytes([seed_byte]) * 32)


def _did(signer):
    return did_key_from_pubkey(bytes(signer.public_key))


_STATEMENT_KW = {
    "decision_digest": "a" * 64,
    "evidence_digests": ["b" * 64],
    "scope": {"action": "tool.execute",
              "resource": "hr:termination-case-42"},
    "verdict": "corroborated",
    "issued_at": "2026-10-01T13:00:00Z",
    "approval_channel": "approval-queue",
    "statement_entry_digest": "c" * 64,
}


class JcsTests(unittest.TestCase):
    def test_key_ordering_ascii(self):
        self.assertEqual(cr._jcs({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_key_ordering_utf16_code_units(self):
        # U+00E9 (1 UTF-16 unit) sorts before U+1D11E (surrogate pair:
        # first unit U+D834); code-point order agrees here, but the
        # implementation compares UTF-16 units per RFC 8785 3.2.1.
        doc = {"\U0001d11e": 1, "é": 2}
        out = cr._jcs(doc)
        self.assertTrue(out.index('"é"') < out.index('"\U0001d11e"'))

    def test_string_escaping(self):
        self.assertEqual(cr._jcs({"s": 'a"b\\c\x01d'}),
                         '{"s":"a\\"b\\\\c\\u0001d"}')

    def test_unicode_not_ascii_escaped(self):
        self.assertEqual(cr._jcs({"s": "é"}), '{"s":"é"}')

    def test_numbers(self):
        self.assertEqual(cr._jcs(0.1), "0.1")
        self.assertEqual(cr._jcs(1e-5), "0.00001")  # not "1e-05"
        self.assertEqual(cr._jcs(2.0), "2")  # integer-valued -> integer
        self.assertEqual(cr._jcs(-0.0), "0")  # -0 -> "0"
        self.assertEqual(cr._jcs(1e21),
                         "1000000000000000000000")  # integer-valued
        self.assertEqual(cr._jcs(123.456), "123.456")

    def test_nan_inf_refused(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(cr.CorroborationReceiptError) as ctx:
                cr._jcs(bad)
            self.assertEqual(ctx.exception.code,
                             "corrob-receipt-malformed")

    def test_lone_surrogate_refused(self):
        with self.assertRaises(cr.CorroborationReceiptError):
            cr._jcs({"s": "\ud800"})

    def test_nested_deterministic(self):
        doc = {"z": [3, 2, {"b": 1, "a": None}], "a": True}
        once = cr._jcs_bytes(doc)
        twice = cr._jcs_bytes(json.loads(json.dumps(doc)))
        self.assertEqual(once, twice)
        self.assertEqual(once,
                         b'{"a":true,"z":[3,2,{"a":null,"b":1}]}')


class StatementTests(unittest.TestCase):
    def test_happy_shape(self):
        signer = _signer(1)
        stmt = cr.build_statement(_did(signer), **_STATEMENT_KW)
        self.assertEqual(stmt["_type"],
                         "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"],
                         cr.HUMAN_CORROBORATION_PREDICATE)
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertEqual(stmt["predicate"]["reviewer"], _did(signer))
        self.assertEqual(stmt["predicate"]["evidenceDigests"], ["b" * 64])

    def test_honest_absence_empty_evidence(self):
        signer = _signer(2)
        kw = dict(_STATEMENT_KW, evidence_digests=[])
        stmt = cr.build_statement(_did(signer), **kw)
        self.assertEqual(stmt["predicate"]["evidenceDigests"], [])

    def test_bad_verdict_refused(self):
        signer = _signer(3)
        kw = dict(_STATEMENT_KW, verdict="rubber-stamped")
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.build_statement(_did(signer), **kw)
        self.assertEqual(ctx.exception.code, "corrob-receipt-malformed")

    def test_statement_digest_stable(self):
        signer = _signer(4)
        stmt = cr.build_statement(_did(signer), **_STATEMENT_KW)
        self.assertEqual(cr.statement_digest(stmt),
                         cr.statement_digest(
                             json.loads(json.dumps(stmt))))


class IssuerBindingTests(unittest.TestCase):
    def test_construction_binds_key_to_did(self):
        signer = _signer(5)
        issuer = cr.CorroborationIssuer(signer, _did(signer))
        self.assertEqual(issuer.reviewer_did, _did(signer))

    def test_construction_refuses_unbound_key(self):
        signer = _signer(6)
        other = _signer(7)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.CorroborationIssuer(signer, _did(other))
        self.assertEqual(ctx.exception.code,
                         "corrob-receipt-unbound-issuer")

    def test_issue_refuses_unapproved(self):
        signer = _signer(8)
        issuer = cr.CorroborationIssuer(signer, _did(signer))
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            issuer.issue("a" * 64, [], {"action": "x"}, "corroborated",
                         "approval-queue", "c" * 64, approved=False)
        self.assertEqual(ctx.exception.code, "corrob-receipt-not-approved")

    def test_issue_requires_credential_status(self):
        signer = _signer(9)
        issuer = cr.CorroborationIssuer(signer, _did(signer))
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            issuer.issue("a" * 64, [], {"action": "x"}, "corroborated",
                         "approval-queue", "c" * 64, approved=True)
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")

    def test_config_requires_credential_status(self):
        signer = _signer(10)
        issuer = cr.CorroborationIssuer(signer, _did(signer))
        with self.assertRaises(TypeError):
            cr.CorroborationConfig(issuer, _did(signer))
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.CorroborationConfig(issuer, _did(signer),
                                   credential_status={"id": "x"})
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")


class EnvelopeTests(unittest.TestCase):
    def _signed(self, seed=11):
        signer = _signer(seed)
        stmt = cr.build_statement(_did(signer), **_STATEMENT_KW)
        env = cr.sign_envelope(cr.dsse_envelope(stmt), signer,
                               signer.key_id)
        return signer, stmt, env

    def test_verify_returns_true_and_statement(self):
        signer, stmt, env = self._signed()
        ok, parsed = cr.verify_envelope(
            env, Ed25519Verifier(bytes(signer.public_key)))
        self.assertIs(ok, True)
        self.assertEqual(parsed, stmt)

    def test_tampered_payload_refused(self):
        signer, stmt, env = self._signed()
        raw = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
        raw["predicate"]["verdict"] = "corroborated-with-notes"
        env["payload"] = base64.b64encode(
            json.dumps(raw, sort_keys=True).encode("utf-8")).decode("ascii")
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_envelope(env,
                               Ed25519Verifier(bytes(signer.public_key)))
        self.assertEqual(ctx.exception.code,
                         "corrob-receipt-signature-invalid")

    def test_unbound_issuer_refused_before_signature_math(self):
        signer, stmt, env = self._signed()
        other = _signer(12)
        stmt2 = json.loads(json.dumps(stmt))
        stmt2["predicate"]["reviewer"] = _did(other)
        env2 = cr.sign_envelope(cr.dsse_envelope(stmt2), signer,
                                signer.key_id)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_envelope(env2,
                               Ed25519Verifier(bytes(signer.public_key)))
        self.assertEqual(ctx.exception.code,
                         "corrob-receipt-unbound-issuer")

    def test_binding_step_split(self):
        signer, stmt, env = self._signed()
        ok, parsed = cr.verify_envelope(
            env, Ed25519Verifier(bytes(signer.public_key)))
        self.assertIs(ok, True)
        # Step 2 is independent: the right digest binds, a wrong one
        # refuses even though the signature verified.
        self.assertIs(cr.verify_statement_binding(parsed, "a" * 64), True)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_statement_binding(parsed, "e" * 64)
        self.assertEqual(ctx.exception.code,
                         "corrob-receipt-subject-mismatch")


class VcTests(unittest.TestCase):
    def _vc(self, seed=21):
        signer = _signer(seed)
        return signer, cr.build_vc(
            _did(signer), "f" * 64, {"action": "tool.execute"},
            "corroborated", "2026-10-01T13:00:00Z", "urn:uuid:vc-1")

    def test_round_trip(self):
        signer, vc = self._vc()
        signed = cr.sign_vc(vc, signer)
        proof = signed["proof"]
        self.assertEqual(proof["type"], "DataIntegrityProof")
        self.assertEqual(proof["cryptosuite"], "eddsa-jcs-2022")
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
        self.assertTrue(proof["proofValue"].startswith("z"))
        self.assertIs(cr.verify_vc(
            signed, Ed25519Verifier(bytes(signer.public_key))), True)

    def test_wrong_key_proof_refused(self):
        signer, vc = self._vc()
        attacker = _signer(22)
        signed = cr.sign_vc(vc, attacker)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_vc(signed,
                         Ed25519Verifier(bytes(signer.public_key)))
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")

    def test_verifier_must_be_issuer(self):
        signer, vc = self._vc()
        signed = cr.sign_vc(vc, signer)
        other = _signer(23)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_vc(signed,
                         Ed25519Verifier(bytes(other.public_key)))
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")

    def test_missing_statement_digest_refused(self):
        signer, vc = self._vc()
        del vc["credentialSubject"]["statementDigest"]
        signed = cr.sign_vc(vc, signer)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_vc(signed,
                         Ed25519Verifier(bytes(signer.public_key)))
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")

    def test_credential_status_attached_when_supplied(self):
        signer, vc = self._vc()
        status = {
            "id": "https://example.invalid/status/7#42",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "42",
            "statusListCredential": "https://example.invalid/status/7",
        }
        vc2 = cr.build_vc(_did(signer), "f" * 64,
                          {"action": "tool.execute"}, "corroborated",
                          "2026-10-01T13:00:00Z", "urn:uuid:vc-2", status)
        self.assertEqual(vc2["credentialStatus"]["statusListIndex"], "42")
        signed = cr.sign_vc(vc2, signer)
        self.assertIs(cr.verify_vc(
            signed, Ed25519Verifier(bytes(signer.public_key))), True)

    def test_honest_limits_in_artifacts(self):
        signer = _signer(24)
        stmt = cr.build_statement(_did(signer), **_STATEMENT_KW)
        self.assertIn("does not prove independent investigation",
                      stmt["predicate"]["honestLimits"])
        _, vc = self._vc(seed=25)
        self.assertIn("does not prove independent investigation",
                      vc["credentialSubject"]["honestLimits"])

    def test_decision_reason_threaded(self):
        signer = _signer(26)
        kw = dict(_STATEMENT_KW, decision_reason="spot-checked the diff")
        stmt = cr.build_statement(_did(signer), **kw)
        self.assertEqual(stmt["predicate"]["decisionReason"],
                         "spot-checked the diff")
        stmt2 = cr.build_statement(_did(signer), **_STATEMENT_KW)
        self.assertEqual(stmt2["predicate"]["decisionReason"], "")


class DualReceiptTests(unittest.TestCase):
    _STATUS = {
        "id": "https://example.invalid/status/7#42",
        "type": "StatusList2021Entry",
        "statusPurpose": "revocation",
        "statusListIndex": "42",
        "statusListCredential": "https://example.invalid/status/7",
    }

    def _receipt(self, seed=31):
        signer = _signer(seed)
        issuer = cr.CorroborationIssuer(signer, _did(signer))
        receipt = issuer.issue(
            "a" * 64, ["b" * 64],
            {"action": "tool.execute",
             "resource": "hr:termination-case-42"},
            "corroborated", "approval-queue", "c" * 64,
            approved=True, credential_status=dict(self._STATUS))
        return signer, receipt

    def test_dual_ceremony_happy_path(self):
        signer, receipt = self._receipt()
        ok, statement = cr.verify_dual_receipt(
            receipt["envelope"], receipt["vc"],
            Ed25519Verifier(bytes(signer.public_key)), "a" * 64)
        self.assertIs(ok, True)
        self.assertEqual(statement, receipt["statement"])

    def test_repointed_vc_refused(self):
        signer, receipt = self._receipt()
        other = _signer(32)
        other_stmt = cr.build_statement(
            _did(other), "d" * 64, [],
            {"action": "tool.execute", "resource": "hr:other"},
            "corroborated", "2026-10-01T13:00:00Z", "approval-queue",
            "c" * 64)
        bad_vc = json.loads(json.dumps(receipt["vc"]))
        bad_vc["credentialSubject"]["statementDigest"] = cr.statement_digest(
            other_stmt)
        del bad_vc["proof"]  # re-pointing means re-proving
        bad_vc = cr.sign_vc(bad_vc, signer)
        # The re-pointed VC's own proof verifies (well-formed signed
        # claim); the ceremony's cross-check refuses it.
        self.assertIs(cr.verify_vc(
            bad_vc, Ed25519Verifier(bytes(signer.public_key))), True)
        with self.assertRaises(cr.CorroborationReceiptError) as ctx:
            cr.verify_dual_receipt(
                receipt["envelope"], bad_vc,
                Ed25519Verifier(bytes(signer.public_key)), "a" * 64)
        self.assertEqual(ctx.exception.code, "corrob-vc-proof-invalid")


class TaxonomyTests(unittest.TestCase):
    EXPECTED = (
        "corrob-receipt-failed",
        "corrob-receipt-malformed",
        "corrob-receipt-not-approved",
        "corrob-receipt-predicate-mismatch",
        "corrob-receipt-self-corroboration",
        "corrob-receipt-signature-invalid",
        "corrob-receipt-subject-mismatch",
        "corrob-receipt-unbound-issuer",
        "corrob-vc-proof-invalid",
    )

    def test_codes_present(self):
        missing = [c for c in self.EXPECTED
                   if c not in decision_codes.TAXONOMY]
        self.assertEqual(missing, [])

    def test_domains_and_severity(self):
        for code in self.EXPECTED:
            entry = decision_codes.TAXONOMY[code]
            self.assertEqual(entry["domain"], "corroboration")
            self.assertIn(entry["severity"], ("high", "medium"))


if __name__ == "__main__":
    unittest.main()
