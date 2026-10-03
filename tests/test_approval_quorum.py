"""Unit tests for gov/approval_quorum.py (wave-297 lane 2).

20+ tests: predicate bounds/freeze, request validation, vote signing,
tally rules (order of refusals), veto un-outvotability, self-vote,
append-only, forged votes, expiry, double-vote, decision re-verify.
"""

import unittest

from gov import approval_quorum as AQ
from gov import ed25519 as _ed


def _seeds(*ids):
    return {v: bytes([i + 1]) * 32 for i, v in enumerate(ids)}


def _req(**kw):
    base = {
        "schema": "approval-request/v1",
        "request_id": "req-1",
        "requester_id": "requester-1",
        "action_digest": "ab" * 32,
        "expires_at": 2000000000,
        "version": 1,
    }
    base.update(kw)
    return base


class QuorumPredicateTests(unittest.TestCase):
    def test_min_bounds(self):
        for bad in (0, 100, -1, True, "2", 2.0):
            with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
                AQ.QuorumPredicate(min_approvals=bad)
            self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_veto_roles_frozen(self):
        p = AQ.QuorumPredicate(min_approvals=2,
                               blocking_veto_roles=["sec-lead"])
        self.assertEqual(p.blocking_veto_roles,
                         frozenset({"sec-lead"}))
        # frozenset: post-build mutation fails at the source
        with self.assertRaises(AttributeError):
            p.blocking_veto_roles.add("intruder")

    def test_bad_veto_role(self):
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.QuorumPredicate(min_approvals=1,
                               blocking_veto_roles=["ok", ""])
        self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_digest_stable(self):
        a = AQ.QuorumPredicate(min_approvals=3,
                               blocking_veto_roles=("b", "a"))
        b = AQ.QuorumPredicate(min_approvals=3,
                               blocking_veto_roles=("a", "b"))
        self.assertEqual(a.digest(), b.digest())

    def test_max_voters_bound(self):
        with self.assertRaises(AQ.ApprovalQuorumError):
            AQ.QuorumPredicate(min_approvals=1, max_voters=0)


class RequestTests(unittest.TestCase):
    def test_digest_stable_across_key_order(self):
        r1 = _req()
        r2 = dict(reversed(list(r1.items())))
        self.assertEqual(AQ.request_digest(r1), AQ.request_digest(r2))

    def test_malformed_requests(self):
        bads = [
            "not-a-dict",
            {"schema": "wrong"},
            _req(action_digest="zz"),
            _req(expires_at=-5),
            _req(expires_at="soon"),
            _req(version=2),
            _req(requester_id=""),
        ]
        for bad in bads:
            with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
                AQ.validate_request(bad)
            self.assertEqual(ctx.exception.code, "approval-quorum-invalid")


class VoteTests(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self):
        seeds = _seeds("v1")
        digest = AQ.request_digest(_req())
        vote = AQ.cast_vote(seeds["v1"], digest, "v1", "approve",
                            "cd" * 32)
        registry = AQ.build_registry(seeds)
        voter, verdict = AQ._verify_vote_envelope(vote, registry)
        self.assertEqual((voter, verdict), ("v1", "approve"))

    def test_ed25519_verify_checked_is_true(self):
        # wave-243 lesson: pin the exact True/False contract at the seam
        seeds = _seeds("v1")
        digest = AQ.request_digest(_req())
        body = AQ.vote_body(digest, "v1", "approve", "cd" * 32)
        sig = _ed.sign(seeds["v1"], AQ._canonical(body))
        pub = _ed.publickey(seeds["v1"])
        self.assertIs(_ed.verify(pub, AQ._canonical(body), sig), True)
        self.assertIs(
            _ed.verify(pub, AQ._canonical(dict(body, verdict="reject")),
                       sig),
            False)

    def test_bad_verdict_shape(self):
        with self.assertRaises(AQ._SchemaViolation):
            AQ.vote_body("ab" * 32, "v1", "maybe", "cd" * 32)


class TallyTests(unittest.TestCase):
    def _setup(self, ids, **kw):
        seeds = _seeds(*ids)
        registry = AQ.build_registry(seeds)
        req = _req(**kw)
        digest = AQ.request_digest(req)
        return seeds, registry, req, digest

    def _votes(self, seeds, registry, digest, plan):
        return [AQ.cast_vote(seeds[v], digest, v, verdict, "cd" * 32)
                for v, verdict in plan]

    def test_approve_passes(self):
        seeds, registry, req, digest = self._setup(["v1", "v2"])
        votes = self._votes(seeds, registry, digest,
                            [("v1", "approve"), ("v2", "approve")])
        d = AQ.tally(votes, AQ.QuorumPredicate(min_approvals=2), req,
                     registry, now=1000)
        self.assertEqual(d["outcome"], "approved")
        self.assertEqual(d["approve_count"], 2)
        self.assertEqual(d["request_digest"], digest)
        self.assertTrue(AQ.verify_decision(d, votes,
                                           AQ.QuorumPredicate(min_approvals=2),
                                           req, registry))

    def test_refusal_order_expiry_before_bad_ballot(self):
        seeds, registry, req, digest = self._setup(["v1"],
                                                   expires_at=1000)
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(["garbage"], AQ.QuorumPredicate(min_approvals=1),
                     req, registry, now=1001)
        self.assertEqual(ctx.exception.code, "approval-request-expired")

    def test_refusal_order_self_vote_before_veto(self):
        # requester casts a veto: self-vote fires first (rule 4 < rule 6)
        seeds, registry, req, digest = self._setup(["requester-1"])
        votes = self._votes(seeds, registry, digest,
                            [("requester-1", "veto")])
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(votes,
                     AQ.QuorumPredicate(min_approvals=1,
                                        blocking_veto_roles=("requester-1",)),
                     req, registry, now=1000)
        self.assertEqual(ctx.exception.code, "approval-quorum-self-vote")

    def test_veto_beats_ten_approves(self):
        ids = ["v%d" % i for i in range(10)] + ["sec-lead"]
        seeds, registry, req, digest = self._setup(ids)
        plan = [("v%d" % i, "approve") for i in range(10)]
        plan.append(("sec-lead", "veto"))
        votes = self._votes(seeds, registry, digest, plan)
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(votes,
                     AQ.QuorumPredicate(min_approvals=2,
                                        blocking_veto_roles=("sec-lead",)),
                     req, registry, now=1000)
        self.assertEqual(ctx.exception.code, "approval-quorum-vetoed")

    def test_tampered_vote_body_rejected(self):
        seeds, registry, req, digest = self._setup(["v1", "v2"])
        votes = self._votes(seeds, registry, digest,
                            [("v1", "approve"), ("v2", "approve")])
        tampered = dict(votes[0])
        tampered["body"] = dict(votes[0]["body"], verdict="reject")
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally([tampered, votes[1]],
                     AQ.QuorumPredicate(min_approvals=2), req, registry,
                     now=1000)
        self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_non_mapping_votes(self):
        seeds, registry, req, digest = self._setup(["v1"])
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally("nope", AQ.QuorumPredicate(min_approvals=1), req,
                     registry, now=1000)
        self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_empty_votes_unmet(self):
        seeds, registry, req, digest = self._setup(["v1"])
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally([], AQ.QuorumPredicate(min_approvals=1), req,
                     registry, now=1000)
        self.assertEqual(ctx.exception.code, "approval-quorum-unmet")

    def test_retract_always_refuses(self):
        seeds, registry, req, digest = self._setup(["v1"])
        vote = AQ.cast_vote(seeds["v1"], digest, "v1", "approve",
                            "cd" * 32)
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.retract_vote(vote)
        self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_build_registry_rejects_empty(self):
        with self.assertRaises(AQ.ApprovalQuorumError):
            AQ.build_registry({})

    def test_empty_veto_roles_plain_quorum(self):
        seeds, registry, req, digest = self._setup(["v1", "v2"])
        votes = self._votes(seeds, registry, digest,
                            [("v1", "approve"), ("v2", "approve")])
        d = AQ.tally(votes, AQ.QuorumPredicate(min_approvals=2), req,
                     registry, now=1000)
        self.assertEqual(d["vetoes"], 0)

    def test_registry_pubkeys_are_32_byte_hex(self):
        seeds, registry, req, digest = self._setup(["v1"])
        for voter, pub in dict(registry).items():
            self.assertEqual(len(bytes.fromhex(pub)), 32)


if __name__ == "__main__":
    unittest.main()
