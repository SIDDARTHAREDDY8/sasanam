"""Unit tests for gov.scitt_receipt (wave-208 lane B).

Complements evals/scitt_receipt_probes.py (the red-first battery):
the probes attack the public seams break-first; these tests pin
edge-case behavior and error taxonomy at the same seams.
"""

import base64
import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import scitt_receipt as sr
from gov import dsse_envelope as _de
from gov.signing import Ed25519Signer, Ed25519Verifier

_SEED_ISSUER = bytes.fromhex("61" * 32)
_SEED_TS = bytes.fromhex("62" * 32)
_SEED_OTHER = bytes.fromhex("63" * 32)
_CFG = {"log_url": "hermetic://scitt-test",
        "log_id": "scitt-test-log",
        "tsa_url": "hermetic://tsa-test"}


def _policy(**kw):
    base = dict(name="test-admission", version="v1",
                allowed_issuers=("issuer-a",),
                allowed_content_types=("application/octet-stream",),
                max_statement_bytes=65536)
    base.update(kw)
    return sr.RegistrationPolicy(**base)


def _ts(policy=None, issuer_threshold=1):
    issuer_signer = Ed25519Signer(_SEED_ISSUER)
    ts_signer = Ed25519Signer(_SEED_TS)
    ts = sr.TransparencyService(
        identity="ts-test-1", ts_signer=ts_signer,
        registration_policy=policy or _policy(),
        signing_config=dict(_CFG),
        issuer_verifiers=[Ed25519Verifier(issuer_signer.public_key)],
        issuer_threshold=issuer_threshold)
    return ts, issuer_signer, ts_signer


def _vargs(ts, issuer_signer, ts_signer, policy):
    return dict(
        issuer_verifiers=[Ed25519Verifier(issuer_signer.public_key)],
        ts_verifiers=[Ed25519Verifier(ts_signer.public_key)],
        ts_identity=ts.identity,
        pinned_policy_digest=policy.digest)


class TestIssueStatement(unittest.TestCase):
    def test_statement_binds_content_digest(self):
        s = Ed25519Signer(_SEED_ISSUER)
        env = sr.issue_statement(s, issuer="issuer-a", subject="agent/1",
                                 content=b"hello")
        self.assertEqual(env["payloadType"], sr.STATEMENT_PAYLOAD_TYPE)
        body = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(body["content_sha256"],
                         hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(body["issuer"], "issuer-a")
        self.assertEqual(body["subject"], "agent/1")

    def test_content_never_in_statement(self):
        s = Ed25519Signer(_SEED_ISSUER)
        env = sr.issue_statement(s, issuer="issuer-a", subject="agent/1",
                                 content=b"super-secret-bytes")
        self.assertNotIn(b"super-secret-bytes",
                         base64.b64decode(env["payload"]))

    def test_claims_passthrough(self):
        s = Ed25519Signer(_SEED_ISSUER)
        env = sr.issue_statement(s, issuer="issuer-a", subject="agent/1",
                                 content=b"x", claims={"k": "v"})
        body = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(body["claims"], {"k": "v"})

    def test_validation(self):
        s = Ed25519Signer(_SEED_ISSUER)
        with self.assertRaises(sr.ReceiptError):
            sr.issue_statement(s, issuer="", subject="a", content=b"x")
        with self.assertRaises(sr.ReceiptError):
            sr.issue_statement(s, issuer="a", subject="a", content="x")
        with self.assertRaises(sr.ReceiptError):
            sr.issue_statement("not-a-signer", issuer="a", subject="a",
                               content=b"x")
        with self.assertRaises(sr.ReceiptError):
            sr.issue_statement(s, issuer="a", subject="a", content=b"x",
                               claims=["not-a-mapping"])


class TestRegistrationPolicy(unittest.TestCase):
    def test_digest_deterministic(self):
        self.assertEqual(_policy().digest, _policy().digest)

    def test_digest_changes_with_rules(self):
        self.assertNotEqual(_policy().digest,
                            _policy(max_statement_bytes=1).digest)

    def test_config_validation(self):
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="", version="v1",
                                  allowed_issuers=("a",))
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="n", version="v1",
                                  allowed_issuers=())
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="n", version="v1",
                                  allowed_issuers=("a",),
                                  max_statement_bytes=0)

    def test_check_refusal_codes(self):
        p = _policy(denied_subjects=("nope",))
        body = {"issuer": "issuer-a", "subject": "ok",
                "content_type": "application/octet-stream"}
        p.check(body, b"x" * 10)  # conforming passes
        with self.assertRaises(sr.RegistrationRefused) as c:
            p.check(dict(body, issuer="issuer-b"), b"x")
        self.assertEqual(c.exception.code, "issuer-not-allowlisted")
        with self.assertRaises(sr.RegistrationRefused) as c:
            p.check(dict(body, subject="nope"), b"x")
        self.assertEqual(c.exception.code, "subject-denied")
        with self.assertRaises(sr.RegistrationRefused) as c:
            p.check(dict(body, content_type="text/evil"), b"x")
        self.assertEqual(c.exception.code, "content-type-not-allowlisted")
        with self.assertRaises(sr.RegistrationRefused) as c:
            p.check(body, b"x" * 70000)
        self.assertEqual(c.exception.code, "statement-too-large")


class TestTransparencyServiceConfig(unittest.TestCase):
    def test_bad_identity(self):
        _, _, ts_signer = _ts()
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(identity="", ts_signer=ts_signer,
                                   registration_policy=_policy(),
                                   signing_config=dict(_CFG),
                                   issuer_verifiers=[Ed25519Verifier(
                                       ts_signer.public_key)])

    def test_bad_signer(self):
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(identity="t", ts_signer="nope",
                                   registration_policy=_policy(),
                                   signing_config=dict(_CFG),
                                   issuer_verifiers=[Ed25519Verifier(
                                       Ed25519Signer(_SEED_TS).public_key)])

    def test_bad_policy(self):
        _, _, ts_signer = _ts()
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(identity="t", ts_signer=ts_signer,
                                   registration_policy="nope",
                                   signing_config=dict(_CFG),
                                   issuer_verifiers=[Ed25519Verifier(
                                       ts_signer.public_key)])

    def test_no_issuer_verifiers(self):
        _, _, ts_signer = _ts()
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(identity="t", ts_signer=ts_signer,
                                   registration_policy=_policy(),
                                   signing_config=dict(_CFG),
                                   issuer_verifiers=[])


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.policy = _policy()
        self.ts, self.issuer_signer, self.ts_signer = _ts(self.policy)
        self.args = _vargs(self.ts, self.issuer_signer, self.ts_signer,
                           self.policy)

    def _stmt(self, **kw):
        d = dict(issuer="issuer-a", subject="agent/1", content=b"data")
        d.update(kw)
        return sr.issue_statement(self.issuer_signer, **d)

    def test_receipt_carries_policy_and_grade(self):
        t = self.ts.register(self._stmt())
        body = json.loads(base64.b64decode(t["receipt"]["payload"]))
        self.assertEqual(body["registration_policy"]["digest"],
                         self.policy.digest)
        self.assertEqual(body["evidentiary_grade"],
                         "registration-proven-not-content")
        self.assertFalse(body["authority_proof"])
        self.assertIn("correct, safe, or wise", body["narrow_claim"])

    def test_bad_issuer_signature_refused(self):
        other = Ed25519Signer(_SEED_OTHER)
        stmt = sr.issue_statement(other, issuer="issuer-a",
                                  subject="agent/1", content=b"data")
        with self.assertRaises(sr.RegistrationRefused) as c:
            self.ts.register(stmt)
        self.assertEqual(c.exception.code, "bad-statement-signature")

    def test_malformed_envelope_refused(self):
        with self.assertRaises(sr.RegistrationRefused) as c:
            self.ts.register({"payload": "e30=", "payloadType": "x",
                              "signatures": []})
        self.assertIn(c.exception.code,
                      ("malformed-statement", "bad-statement-signature"))

    def test_reregister_idempotent(self):
        # Same bytes re-registered: the ORIGINAL transparent statement
        # is returned -- no duplicate leaf, no second receipt, and the
        # non-shredding index is not polluted with a duplicate.
        stmt = self._stmt()
        t1 = self.ts.register(stmt)
        t2 = self.ts.register(stmt)
        self.assertEqual(t1, t2)
        self.assertEqual(len(self.ts.statements_for("agent/1")), 1)

    def test_receipt_for_unknown_statement(self):
        stmt = self._stmt(subject="never-registered")
        with self.assertRaises(sr.ReceiptError):
            self.ts.receipt_for(stmt)


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.policy = _policy()
        self.ts, self.issuer_signer, self.ts_signer = _ts(self.policy)
        self.args = _vargs(self.ts, self.issuer_signer, self.ts_signer,
                           self.policy)
        stmt = sr.issue_statement(self.issuer_signer, issuer="issuer-a",
                                  subject="agent/1", content=b"data")
        self.transparent = self.ts.register(stmt)

    def test_wrong_ts_identity(self):
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(self.transparent,
                                            **dict(self.args,
                                                   ts_identity="other-ts"))

    def test_wrong_pinned_policy(self):
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(
                self.transparent,
                **dict(self.args, pinned_policy_digest="0" * 64))

    def test_wrong_issuer_verifier(self):
        other = Ed25519Verifier(Ed25519Signer(_SEED_OTHER).public_key)
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(
                self.transparent,
                **dict(self.args, issuer_verifiers=[other]))

    def test_extra_field_refused(self):
        bad = dict(self.transparent, extra=1)
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(bad, **self.args)

    def test_missing_field_refused(self):
        bad = {k: v for k, v in self.transparent.items()
               if k != "receipt"}
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(bad, **self.args)

    def test_tampered_inclusion_root_fails(self):
        import copy
        bad = copy.deepcopy(self.transparent)
        body = json.loads(base64.b64decode(bad["receipt"]["payload"]))
        body["anchor_receipt"]["inclusion"]["root_hash"] = "ff" * 32
        # re-seal with the TS key so the signature still verifies --
        # the inclusion check itself must catch the lie
        resealed = _de.seal(
            json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8"),
            sr.RECEIPT_PAYLOAD_TYPE, [self.ts_signer])
        bad["receipt"] = resealed
        with self.assertRaises(sr.VerificationFailed):
            sr.verify_transparent_statement(bad, **self.args)

    def test_issuer_threshold(self):
        # An impossible threshold (2-of-1) is a configuration error:
        # it must fail loudly at construction, not per-registration.
        with self.assertRaises(sr.RegistrationError):
            _ts(self.policy, issuer_threshold=2)


class TestAuditSubject(unittest.TestCase):
    def test_no_equivocation_single_statement(self):
        policy = _policy()
        ts, s1, ts_s = _ts(policy)
        stmt = sr.issue_statement(s1, issuer="issuer-a", subject="solo",
                                  content=b"one")
        ts.register(stmt)
        audit = sr.audit_subject(ts, "solo",
                                 **_vargs(ts, s1, ts_s, policy))
        self.assertEqual(audit["statement_count"], 1)
        self.assertFalse(audit["equivocation_detected"])
        self.assertEqual(audit["verification_failures"], [])

    def test_empty_subject(self):
        policy = _policy()
        ts, s1, ts_s = _ts(policy)
        audit = sr.audit_subject(ts, "nobody",
                                 **_vargs(ts, s1, ts_s, policy))
        self.assertEqual(audit["statement_count"], 0)
        self.assertFalse(audit["equivocation_detected"])

    def test_non_ts_refused(self):
        policy = _policy()
        ts, s1, ts_s = _ts(policy)
        with self.assertRaises(sr.ReceiptError):
            sr.audit_subject("not-a-ts", "x",
                             **_vargs(ts, s1, ts_s, policy))


class TestReviewFindings(unittest.TestCase):
    """Regression tests for the two-axis review findings (wave-208)."""

    def test_policy_as_dict_deep_copy(self):
        # Finding 1: mutating the as_dict() result must not change the
        # live policy (receipts pin the digest -- the policy is the
        # evidence).
        policy = _policy()
        policy.as_dict()["allowed_issuers"].append("mallory")
        self.assertNotIn("mallory", policy.as_dict()["allowed_issuers"])
        self.assertEqual(policy.digest, _policy().digest)

    def test_impossible_threshold_is_config_error(self):
        # Finding 2: threshold > verifier count must fail at
        # construction (RegistrationError), not per-registration as a
        # misleading bad-signature refusal.
        with self.assertRaises(sr.RegistrationError):
            _ts(_policy(), issuer_threshold=2)

    def test_bare_string_allowlist_refused(self):
        # Finding 3: tuple("alice") would silently become
        # per-character -- refuse loudly instead.
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="n", version="v1",
                                  allowed_issuers="alice")
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="n", version="v1",
                                  allowed_issuers=("a",),
                                  denied_subjects="nope")

    def test_bool_max_statement_bytes_refused(self):
        with self.assertRaises(sr.RegistrationError):
            sr.RegistrationPolicy(name="n", version="v1",
                                  allowed_issuers=("a",),
                                  max_statement_bytes=True)

    def test_caller_mutation_after_register_is_fail_closed(self):
        # Nit 4: the index holds a deep copy; mutating the caller's
        # envelope after register cannot corrupt the record.
        policy = _policy()
        ts, s1, ts_s = _ts(policy)
        stmt = sr.issue_statement(s1, issuer="issuer-a", subject="m",
                                  content=b"data")
        ts.register(stmt)
        stmt["payload"] = base64.b64encode(b"forged").decode("ascii")
        stored = ts.statements_for("m")[0]
        self.assertNotEqual(stored["payload"], stmt["payload"])
        # And the read path also returns copies.
        stored["payload"] = "mutated-again"
        self.assertNotEqual(ts.statements_for("m")[0]["payload"],
                            "mutated-again")

    def test_injectable_clock(self):
        # Nit 5: receipt issued_at follows the injected clock.
        policy = _policy()
        ts, s1, ts_s = _ts(policy)
        ts2 = sr.TransparencyService(
            identity="ts-clock", ts_signer=ts_s,
            registration_policy=policy, signing_config=dict(_CFG),
            issuer_verifiers=[Ed25519Verifier(s1.public_key)],
            clock=lambda: "2030-01-01T00:00:00Z")
        stmt = sr.issue_statement(s1, issuer="issuer-a", subject="c",
                                  content=b"x")
        t = ts2.register(stmt)
        body = json.loads(base64.b64decode(t["receipt"]["payload"]))
        self.assertEqual(body["issued_at"], "2030-01-01T00:00:00Z")
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(
                identity="t", ts_signer=ts_s,
                registration_policy=policy, signing_config=dict(_CFG),
                issuer_verifiers=[Ed25519Verifier(s1.public_key)],
                clock="not-callable")

    def test_bad_signing_config_is_registration_error(self):
        # Nit 6: bad signing_config surfaces as RegistrationError per
        # the TS taxonomy, not a raw V2ConfigError.
        _, s1, ts_s = _ts()
        with self.assertRaises(sr.RegistrationError):
            sr.TransparencyService(
                identity="t", ts_signer=ts_s,
                registration_policy=_policy(), signing_config={},
                issuer_verifiers=[Ed25519Verifier(s1.public_key)])


if __name__ == "__main__":
    unittest.main()
