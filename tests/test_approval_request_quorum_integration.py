"""Integration test: gov.approval_request (wave-297 lane 1) composes with
gov.approval_quorum (wave-297 lane 2) end to end.

Proves the merge seam: a request issued by ``gov.approval_request``
projects into the quorum's digest shape (``quorum_digest_input`` ->
``request_digest_from_request``), and votes bound to that digest tally
to an approval. Also pins the refusal surface at the seam: a
tampered request body changes the digest (votes no longer match);
a requester's own vote refuses ``approval-quorum-self-vote``.
"""

import os
import hashlib
import time
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import approval_request as AR
from gov import approval_quorum as AQ
from gov import ed25519 as _ed

_SEED = bytes([7]) * 32
_PUB = _ed.publickey(_SEED).hex()


def _issue(**kw):
    base = {
        "action_digest": "ab" * 32,
        "requester_agent_id": "agent-a",
        "requester_principal": "principal-a",
        "requester_pubkey_hex": _PUB,
        "context_digests": {"inputs": "cd" * 32, "policy": "ef" * 32},
        "approver_schema": [],
        "ttl_seconds": 3600,
        # Live at wall clock (verify_decision re-tallies at wall clock).
        "issued_at": int(time.time()),
        "requester_seed": _SEED,
    }
    base.update(kw)
    return AR.issue(**base)


# _NOW is used only for expiry-boundary assertions relative to issue time.
_NOW = int(time.time())


def _voter_seeds(*ids):
    return {v: bytes([i + 1]) * 32 for i, v in enumerate(ids)}


class SeamProjectionTests(unittest.TestCase):
    def test_projection_matches_digest_shape(self):
        env = _issue()
        proj = AR.quorum_digest_input(env)
        self.assertEqual(proj["schema"], "approval-request/v1")
        self.assertEqual(proj["requester_id"], "agent-a")
        self.assertEqual(proj["action_digest"], "ab" * 32)
        self.assertEqual(proj["expires_at"],
                         env["request"]["issued_at"]
                         + env["request"]["ttl_seconds"])
        self.assertEqual(proj["version"], 1)
        self.assertTrue(isinstance(proj["request_id"], str)
                        and len(proj["request_id"]) == 64)
        # request_id is the canonical body digest (content-unique).
        body = env["request"]
        self.assertEqual(
            proj["request_id"],
            hashlib.sha256(AR._canonical(body)).hexdigest())

    def test_adapter_equals_direct_digest(self):
        env = _issue()
        self.assertEqual(AQ.request_digest_from_request(env),
                         AQ.request_digest(AR.quorum_digest_input(env)))

    def test_body_input_also_accepted(self):
        env = _issue()
        self.assertEqual(AQ.request_digest_from_request(env["request"]),
                         AQ.request_digest_from_request(env))

    def test_replanned_request_is_a_new_digest(self):
        a = _issue()
        b = _issue(action_digest="ff" * 32)
        self.assertNotEqual(AQ.request_digest_from_request(a),
                            AQ.request_digest_from_request(b))

    def test_malformed_envelope_refuses_invalid(self):
        with self.assertRaises(AR.ApprovalRequestError) as ctx:
            AR.quorum_digest_input({"request": {"schema": "nope"}})
        self.assertEqual(ctx.exception.code, "approval-request-invalid")


class EndToEndTallyTests(unittest.TestCase):
    def _setup(self):
        env = _issue()
        digest = AQ.request_digest_from_request(env)
        seeds = _voter_seeds("v1", "v2")
        registry = AQ.build_registry(seeds)
        return env, digest, seeds, registry

    def test_two_approvals_tally_to_approved(self):
        _env, digest, seeds, registry = self._setup()
        votes = [AQ.cast_vote(seeds[v], digest, v, "approve", "cd" * 32)
                 for v in ("v1", "v2")]
        proj = AR.quorum_digest_input(_env)
        d = AQ.tally(votes, AQ.QuorumPredicate(min_approvals=2), proj,
                     registry, now=_NOW)
        self.assertEqual(d["outcome"], "approved")
        self.assertEqual(d["request_digest"], digest)
        self.assertTrue(AQ.verify_decision(
            d, votes, AQ.QuorumPredicate(min_approvals=2), proj, registry))

    def test_votes_on_tampered_request_do_not_match(self):
        env, digest, seeds, registry = self._setup()
        tampered = {"request": dict(env["request"],
                                   action_digest="ff" * 32),
                    "signature": env["signature"]}
        # The tampered body projects to a DIFFERENT digest, so votes
        # cast for the honest digest cannot be rebound onto it.
        other = AQ.request_digest_from_request(tampered)
        self.assertNotEqual(other, digest)
        votes = [AQ.cast_vote(seeds["v1"], digest, "v1", "approve",
                              "cd" * 32)]
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(votes, AQ.QuorumPredicate(min_approvals=1),
                     AR.quorum_digest_input(tampered), registry, now=_NOW)
        # Vote envelope binds the honest digest; ballot is malformed
        # against the tampered request.
        self.assertEqual(ctx.exception.code, "approval-quorum-invalid")

    def test_requester_self_vote_refuses(self):
        env, digest, seeds, registry = self._setup()
        seeds2 = dict(seeds)
        seeds2["agent-a"] = _SEED
        registry2 = AQ.build_registry(seeds2)
        votes = [AQ.cast_vote(_SEED, digest, "agent-a", "approve",
                              "cd" * 32)]
        proj = AR.quorum_digest_input(env)
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(votes, AQ.QuorumPredicate(min_approvals=1), proj,
                     registry2, now=_NOW)
        self.assertEqual(ctx.exception.code, "approval-quorum-self-vote")

    def test_expired_request_cannot_complete_quorum(self):
        env, digest, seeds, registry = self._setup()
        votes = [AQ.cast_vote(seeds["v1"], digest, "v1", "approve",
                              "cd" * 32)]
        proj = AR.quorum_digest_input(env)
        with self.assertRaises(AQ.ApprovalQuorumError) as ctx:
            AQ.tally(votes, AQ.QuorumPredicate(min_approvals=1), proj,
                     registry, now=proj["expires_at"] + 3600)
        self.assertEqual(ctx.exception.code, "approval-request-expired")


if __name__ == "__main__":
    unittest.main()
