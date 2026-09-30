"""Unit tests for gov/authorization_receipts.py (wave-217 lane C).

The EMILIA ADAPT three-digests-three-jobs discipline: subject
(WHAT), authorization-payload (WHO/WHY), and statement-entry
(envelope locator) digests are typed by role, never conflated;
standing grants are referenced by hash, never inlined.
"""

import copy
import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import authorization_receipts as ar  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402


def _seed(i):
    return bytes([i]) * 32


def _harness():
    signer = Ed25519Signer(_seed(21))
    verifier = Ed25519Verifier(signer.public_key, key_id=signer.key_id)
    grants = ar.GrantRegistry()
    issuer = ar.ReceiptIssuer(signer, "issuer-test", grants)
    return signer, verifier, grants, issuer


def _digests():
    return (ar.SubjectDigest.from_bytes(b"subject-bytes"),
            ar.AuthorizationPayloadDigest.from_bytes(b"payload-bytes"),
            ar.StatementEntryDigest.from_bytes(b"entry-bytes"))


class TestTypedDigests(unittest.TestCase):
    def test_roles_bound_to_types(self):
        s, p, e = _digests()
        self.assertEqual(s.role, "subject")
        self.assertEqual(p.role, "authorization-payload")
        self.assertEqual(e.role, "statement-entry")

    def test_same_bytes_different_roles_not_equal(self):
        s = ar.SubjectDigest.from_bytes(b"x")
        p = ar.AuthorizationPayloadDigest.from_bytes(b"x")
        self.assertNotEqual(s, p)
        # Same sha256 value, different roles -- not interchangeable.
        self.assertEqual(s.hex, p.hex)
        with self.assertRaises(ar.AuthorizationReceiptError):
            ar.ReceiptIssuer(Ed25519Signer(_seed(99)), "x",
                             ar.GrantRegistry()).issue(
                                 s, s,
                                 ar.StatementEntryDigest.from_bytes(b"x"),
                                 now=1)

    def test_bad_hex_refused(self):
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.SubjectDigest("ZZZ-not-hex")
        self.assertEqual(ctx.exception.code, "digest-malformed")

    def test_non_bytes_refused(self):
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.SubjectDigest.from_bytes("not-bytes")
        self.assertEqual(ctx.exception.code, "digest-bad-input")


class TestGrantRegistry(unittest.TestCase):
    def test_register_resolve(self):
        grants = ar.GrantRegistry()
        gh = grants.register({"grant_id": "g1"})
        self.assertEqual(grants.resolve_active(gh), {"grant_id": "g1"})

    def test_unknown_grant_refused(self):
        grants = ar.GrantRegistry()
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            grants.resolve_active("ab" * 32)
        self.assertEqual(ctx.exception.code, "unknown-grant")

    def test_revoke_unknown_refused(self):
        grants = ar.GrantRegistry()
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            grants.revoke("ab" * 32)
        self.assertEqual(ctx.exception.code, "unknown-grant")

    def test_revoked_grant_refused(self):
        grants = ar.GrantRegistry()
        gh = grants.register({"grant_id": "g2"})
        grants.revoke(gh)
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            grants.resolve_active(gh)
        self.assertEqual(ctx.exception.code, "grant-revoked")

    def test_registry_returns_copies(self):
        grants = ar.GrantRegistry()
        gh = grants.register({"grant_id": "g3"})
        rec = grants.resolve_active(gh)
        rec["grant_id"] = "mutated"
        self.assertEqual(grants.resolve_active(gh)["grant_id"], "g3")


class TestIssuerVerifier(unittest.TestCase):
    def test_round_trip(self):
        signer, verifier, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000)
        body = ar.verify_receipt(env, verifier, grants,
                                 now=1700000000)
        self.assertEqual(body["issuer_kid"], signer.key_id)
        self.assertEqual(body["issuer"], "issuer-test")
        self.assertEqual(body["grant_refs"], [])

    def test_issuer_id_must_be_nonempty(self):
        signer, _v, grants, _i = _harness()
        with self.assertRaises(ar.AuthorizationReceiptError):
            ar.ReceiptIssuer(signer, "", grants)

    def test_ttl_must_be_positive(self):
        _s, _v, grants, issuer = _harness()
        s, p, e = _digests()
        with self.assertRaises(ar.AuthorizationReceiptError):
            issuer.issue(s, p, e, now=1700000000, ttl_seconds=0)

    def test_conflation_role_mismatch(self):
        _s, _v, grants, issuer = _harness()
        s, p, e = _digests()
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            issuer.issue(p, p, e, now=1700000000)
        self.assertEqual(ctx.exception.code, "digest-role-mismatch")

    def test_conflation_reversed(self):
        _s, _v, grants, issuer = _harness()
        s, p, e = _digests()
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            issuer.issue(e, s, p, now=1700000000)
        self.assertEqual(ctx.exception.code, "digest-role-mismatch")

    def test_body_mutation_breaks_signature(self):
        _s, verifier, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000)
        bad = copy.deepcopy(env)
        bad["receipt"]["issued_at"] = 1700000001
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.verify_receipt(bad, verifier, grants, now=1700000000)
        self.assertEqual(ctx.exception.code, "signature-invalid")

    def test_key_id_mismatch_refused(self):
        _s, _v, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000)
        other = Ed25519Signer(_seed(22))
        other_ver = Ed25519Verifier(other.public_key,
                                    key_id=other.key_id)
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.verify_receipt(env, other_ver, grants, now=1700000000)
        self.assertEqual(ctx.exception.code, "key-swap-refused")

    def test_expired_refused(self):
        _s, verifier, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000, ttl_seconds=10)
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.verify_receipt(env, verifier, grants,
                              now=1700000010)
        self.assertEqual(ctx.exception.code, "receipt-expired")

    def test_format_tag_exact(self):
        _s, verifier, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000)
        env["receipt"]["format"] = "sasanam-authorization-receipt/v2"
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.verify_receipt(env, verifier, grants, now=1700000000)
        self.assertEqual(ctx.exception.code, "receipt-format-mismatch")

    def test_malformed_signature_hex_refused(self):
        _s, verifier, grants, issuer = _harness()
        s, p, e = _digests()
        env = issuer.issue(s, p, e, now=1700000000)
        env["signature"] = "not-hex"
        with self.assertRaises(ar.AuthorizationReceiptError):
            ar.verify_receipt(env, verifier, grants, now=1700000000)

    def test_verify_unknown_grant_refused(self):
        signer, verifier, grants, issuer = _harness()
        gh = grants.register({"grant_id": "g-verify"})
        s, p, e = _digests()
        env = issuer.issue(s, p, e, grant_hashes=[gh], now=1700000000)
        # A deployment whose registry never saw the grant: the ref is
        # unresolvable here even though it was valid at issuance.
        with self.assertRaises(ar.AuthorizationReceiptError) as ctx:
            ar.verify_receipt(env, verifier, ar.GrantRegistry(),
                              now=1700000000)
        self.assertEqual(ctx.exception.code, "unknown-grant")


class TestApprovalWiring(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="gov-receipt-unit-")
        os.environ.setdefault("GOV_LOG_KEY", os.urandom(32).hex())
        os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w217-receipt-unit")
        self.log = ActionLog(os.path.join(self.run_dir,
                                          "actions.jsonl"))

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _queue_one(self, queue):
        ident = AgentIdentity("agent-1", "researcher",
                              os.path.basename(self.run_dir), "user-1")
        queue.set_identity_verifier(lambda _ident: True)
        action = {"tool": "write_file",
                  "args": {"path": "/tmp/z.txt"},
                  "agent_justification": "unit",
                  "redactions": []}
        return queue.queue(
            action,
            PolicyDecision("require_approval", "unit",
                           policy_id="unit", flag="b"),
            "agent_direct", "preview", caller_identity=ident)

    def test_legacy_queue_no_config_no_receipt(self):
        q = ApprovalQueue(self.run_dir, self.log)
        aid = self._queue_one(q)
        target, entry = q.decide(aid, True, "ok",
                                 decided_by="op-rios")
        self.assertEqual(target["status"], "approved")
        self.assertFalse(hasattr(q, "emitted_receipts"))

    def test_subclass_inert_without_config(self):
        # Spec note: ReceiptEmittingApprovalQueue with the DEFAULT
        # receipt_config=None must be byte-identical legacy -- the
        # subclass adds nothing unless opted in.
        q = ar.ReceiptEmittingApprovalQueue(self.run_dir, self.log)
        aid = self._queue_one(q)
        target, entry = q.decide(aid, True, "ok",
                                 decided_by="op-rios")
        self.assertEqual(target["status"], "approved")
        self.assertEqual(q.emitted_receipts, [])
        entries = list(read_entries(
            os.path.join(self.run_dir, "actions.jsonl")))
        events = [e.get("event") for e in entries
                  if isinstance(e, dict)]
        self.assertNotIn("authorization_receipt_emitted", events)
        self.assertNotIn("authorization_receipt_failed", events)

    def test_receipt_queue_emits_on_approve(self):
        signer = Ed25519Signer(_seed(31))
        verifier = Ed25519Verifier(signer.public_key,
                                   key_id=signer.key_id)
        grants = ar.GrantRegistry()
        issuer = ar.ReceiptIssuer(signer, "issuer-unit", grants)
        cfg = ar.ReceiptConfig(issuer)
        q = ar.ReceiptEmittingApprovalQueue(self.run_dir, self.log,
                                            receipt_config=cfg)
        aid = self._queue_one(q)
        target, entry = q.decide(aid, True, "ok",
                                 decided_by="op-rios")
        self.assertEqual(len(q.emitted_receipts), 1)
        body = ar.verify_receipt(q.emitted_receipts[0], verifier,
                                 grants)
        self.assertEqual(body["subject_digest"],
                         ar.SubjectDigest.from_bytes(
                             ar._subject_bytes(target)).hex)

    def test_rejection_emits_nothing(self):
        signer = Ed25519Signer(_seed(32))
        grants = ar.GrantRegistry()
        issuer = ar.ReceiptIssuer(signer, "issuer-unit", grants)
        cfg = ar.ReceiptConfig(issuer)
        q = ar.ReceiptEmittingApprovalQueue(self.run_dir, self.log,
                                            receipt_config=cfg)
        aid = self._queue_one(q)
        q.decide(aid, False, "no", decided_by="op-rios")
        self.assertEqual(q.emitted_receipts, [])

    def test_bad_receipt_config_refused(self):
        with self.assertRaises(ar.AuthorizationReceiptError):
            ar.ReceiptEmittingApprovalQueue(self.run_dir, self.log,
                                            receipt_config="nope")


if __name__ == "__main__":
    unittest.main()
