"""Unit tests for gov/ceremony_binding.py (wave-289 lane 5).

Challenge-bound evidence: the verifier's challenge (nonce >= 64 bits +
purpose) is bound into the operator-signed envelope, and the anchor
chain witnesses the (content digest, nonce, purpose) tuple.
"""

import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ceremony_binding as cb
from gov import ed25519
from gov.evidence_anchor import TransparencyLog


def _op():
    seed = secrets.token_bytes(32)
    return seed, ed25519.publickey(seed).hex()


_UNSET = object()


def _issue(seed, nonce=_UNSET, purpose="unit-test", digest=_UNSET):
    return cb.issue_binding(
        operator_seed=seed, operator_keyid="op-unit",
        challenge_nonce=secrets.token_bytes(16) if nonce is _UNSET else nonce,
        challenge_purpose=purpose,
        content_digest=("ab" * 32) if digest is _UNSET else digest)


class TestIssueBinding(unittest.TestCase):
    def test_round_trip(self):
        seed, pub = _op()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        payload = cb.verify_binding(rec, pub, expected_nonce=nonce,
                                    expected_purpose="unit-test")
        self.assertEqual(payload["challenge_nonce"], nonce.hex())

    def test_issue_refuses_missing_nonce(self):
        seed, _ = _op()
        for bad in (b"", b"\x01" * 7, "not-bytes", None):
            with self.assertRaises(cb.CeremonyError) as cm:
                _issue(seed, nonce=bad)
            self.assertEqual(cm.exception.code, "challenge-nonce-invalid")

    def test_issue_refuses_bad_purpose(self):
        seed, _ = _op()
        for bad in ("", None, 42):
            with self.assertRaises(cb.CeremonyError) as cm:
                _issue(seed, purpose=bad)
            self.assertEqual(cm.exception.code, "challenge-invalid-shape")

    def test_issue_refuses_bad_digest(self):
        seed, _ = _op()
        for bad in ("nothex", "ab" * 31, None):
            with self.assertRaises(cb.CeremonyError) as cm:
                _issue(seed, digest=bad)
            self.assertEqual(cm.exception.code, "challenge-invalid-shape")

    def test_purpose_over_256_chars_refused(self):
        seed, _ = _op()
        with self.assertRaises(cb.CeremonyError) as cm:
            _issue(seed, purpose="x" * 257)
        self.assertEqual(cm.exception.code, "challenge-invalid-shape")

    def test_issue_refuses_bad_seed(self):
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.issue_binding(operator_seed=b"short", operator_keyid="op-1",
                             challenge_nonce=secrets.token_bytes(16),
                             challenge_purpose="unit-test",
                             content_digest="ab" * 32)
        self.assertEqual(cm.exception.code, "challenge-invalid-shape")

    def test_longer_nonce_accepted(self):
        seed, pub = _op()
        nonce = secrets.token_bytes(32)  # 256 bits: more is fine
        rec = _issue(seed, nonce=nonce)
        payload = cb.verify_binding(rec, pub, expected_nonce=nonce)
        self.assertEqual(payload["challenge_nonce"], nonce.hex())

    def test_signature_covers_all_fields(self):
        seed, pub = _op()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        import json
        for field, new in (("challenge_nonce", secrets.token_bytes(16).hex()),
                           ("challenge_purpose", "other"),
                           ("content_digest", "cd" * 32)):
            tampered = json.loads(json.dumps(rec))
            tampered["payload"][field] = new
            with self.assertRaises(cb.CeremonyError):
                cb.verify_binding(tampered, pub)
        # Untouched record still verifies.
        cb.verify_binding(rec, pub)


class TestVerifyBinding(unittest.TestCase):
    def test_verify_without_expectations(self):
        seed, pub = _op()
        rec = _issue(seed)
        cb.verify_binding(rec, pub)

    def test_nonce_mismatch_is_coded(self):
        seed, pub = _op()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(rec, pub, expected_nonce=secrets.token_bytes(16))
        self.assertEqual(cm.exception.code, "challenge-nonce-mismatch")

    def test_purpose_mismatch_is_coded(self):
        seed, pub = _op()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(rec, pub, expected_nonce=nonce,
                              expected_purpose="other")
        self.assertEqual(cm.exception.code, "challenge-purpose-mismatch")

    def test_wrong_key_refuses_coded(self):
        seed, _ = _op()
        other_pub = ed25519.publickey(secrets.token_bytes(32)).hex()
        rec = _issue(seed)
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(rec, other_pub)
        self.assertEqual(cm.exception.code, "challenge-signature-invalid")

    def test_verify_bool_contract(self):
        # wave-243: verify() returns bool; the refusal must come from the
        # module's is-not-True check, never truthiness.
        seed, pub = _op()
        rec = _issue(seed)
        ok = ed25519.verify(bytes.fromhex(pub),
                            cb._sig_structure(rec["protected"],
                                              rec["payload"]),
                            bytes.fromhex(rec["signature"]))
        self.assertIs(ok, True)

    def test_tampered_signature_refuses(self):
        seed, pub = _op()
        rec = _issue(seed)
        import json
        tampered = json.loads(json.dumps(rec))
        sig = bytearray(bytes.fromhex(tampered["signature"]))
        sig[0] ^= 0xFF
        tampered["signature"] = bytes(sig).hex()
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(tampered, pub)
        self.assertEqual(cm.exception.code, "challenge-signature-invalid")
    def test_nonhex_signature_refused_coded(self):
        # F355: a non-hex signature string must refuse LOUD with a
        # coded refusal, never a raw ValueError from bytes.fromhex.
        seed, pub = _op()
        rec = _issue(seed)
        rec["signature"] = "not-hex!!"
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(rec, pub)
        self.assertEqual(cm.exception.code, "challenge-signature-invalid")

    def test_short_hex_signature_refused_coded(self):
        # Edge: well-formed hex of the wrong length is a forged
        # signature, not a crash.
        seed, pub = _op()
        rec = _issue(seed)
        rec["signature"] = "ab"
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_binding(rec, pub)
        self.assertEqual(cm.exception.code, "challenge-signature-invalid")


class TestAnchorComposition(unittest.TestCase):
    def _log(self):
        log_seed = secrets.token_bytes(32)
        log_pub = ed25519.publickey(log_seed).hex()
        log = TransparencyLog(tempfile.mkdtemp(prefix="challenge-unit-"),
                              "unit-origin", "log-key", signer_seed=log_seed)
        return log, log_pub

    def test_keyless_payload_leaf_refuses_coded(self):
        # F353: a shape-valid-but-keyless payload must refuse LOUD
        # with a coded refusal, never a raw KeyError.
        rec = {"ceremony_format": cb.CEREMONY_FORMAT,
               "protected": {}, "payload": {}, "signature": "00"}
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.ceremony_leaf(rec)
        self.assertEqual(cm.exception.code, "challenge-invalid-shape")

    def test_anchor_leaf_binds_nonce_and_purpose(self):
        seed, _ = _op()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        leaf = cb.ceremony_leaf(rec)
        self.assertEqual(len(leaf), 64)
        self.assertNotEqual(leaf, "ab" * 32)
        # Same content, different ceremony -> different leaf.
        rec2 = _issue(seed, digest="ab" * 32)
        self.assertNotEqual(cb.ceremony_leaf(rec), cb.ceremony_leaf(rec2))

    def test_anchored_round_trip(self):
        seed, pub = _op()
        log, log_pub = self._log()
        nonce = secrets.token_bytes(16)
        rec = _issue(seed, nonce=nonce)
        receipt, leaf = cb.anchor_binding(log, rec)
        self.assertEqual(receipt["bundle_digest"], leaf)
        payload = cb.verify_anchored_binding(
            rec, receipt, log_pub, pub, expected_nonce=nonce,
            expected_purpose="unit-test")
        self.assertEqual(payload["challenge_purpose"], "unit-test")

    def test_anchor_substitution_refused(self):
        seed, pub = _op()
        log, log_pub = self._log()
        nonce_a = secrets.token_bytes(16)
        rec_a = _issue(seed, nonce=nonce_a)
        rec_b = _issue(seed)
        receipt_b, _ = cb.anchor_binding(log, rec_b)
        with self.assertRaises(cb.CeremonyError) as cm:
            cb.verify_anchored_binding(rec_a, receipt_b, log_pub, pub,
                                       expected_nonce=nonce_a,
                                       expected_purpose="unit-test")
        self.assertEqual(cm.exception.code, "challenge-anchor-mismatch")


class TestErrorConvention(unittest.TestCase):
    def test_all_codes_registered(self):
        from gov import decision_codes
        tax = decision_codes.TAXONOMY
        for code in ("challenge-invalid-shape", "challenge-signature-invalid",
                     "challenge-nonce-invalid", "challenge-nonce-mismatch",
                     "challenge-purpose-mismatch",
                     "challenge-anchor-mismatch"):
            self.assertIn(code, tax)

    def test_emit_sink(self):
        events = []
        cb.set_emit(events.append)
        try:
            seed, _ = _op()
            _issue(seed)
        finally:
            cb.set_emit(None)
        self.assertTrue(any(e.get("event") == "binding-issued"
                            for e in events))

    def test_taxonomy_pin(self):
        import re
        src = open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "gov", "decision_codes.py"), encoding="utf-8").read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertEqual(len(lits), 1934)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(len(set(lits)), 1934)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(lits, sorted(lits))


if __name__ == "__main__":
    unittest.main()
