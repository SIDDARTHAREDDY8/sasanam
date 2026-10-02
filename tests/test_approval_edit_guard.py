#!/usr/bin/env python3
"""Unit tests for gov/approval_edit_guard.py (wave-237).

Tests verify behavior at the public seams (propose / check_approval /
repropose); expected digests are worked literals where they pin the
domain separation, never recomputed the way the code does.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import approval_edit_guard as aeg  # noqa: E402
from gov import decision_codes  # noqa: E402


def _expect_code(fn, code):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None) or type(exc).__name__
        assert got == code, "wrong code %r (want %r)" % (got, code)
        return
    raise AssertionError("no refusal raised (want %r)" % (code,))


class ProposeTests(unittest.TestCase):
    def test_propose_binds_canonical_action_bytes(self):
        proposal = aeg.propose(b'{"b":2,"a":1}', proposal_id="p1")
        self.assertEqual(proposal["proposal_id"], "p1")
        self.assertEqual(proposal["version"], 1)
        # Worked literal: sha256(domain || JCS('{"a":1,"b":2}')).
        expected = hashlib.sha256(
            b"sasanam-approval-edit-guard-v1:"
            + b'{"a":1,"b":2}').hexdigest()
        self.assertEqual(proposal["action_digest"], expected)

    def test_propose_default_id_is_deterministic_and_fresh(self):
        a = aeg.propose(b'{"a":1}')
        b = aeg.propose(b'{"a":1}')
        c = aeg.propose(b'{"a":2}')
        self.assertEqual(a["proposal_id"], b["proposal_id"])
        self.assertNotEqual(a["proposal_id"], c["proposal_id"])

    def test_propose_domain_separates_from_permit_closure(self):
        # The same bytes must NOT collide with the permit_closure
        # request digest (plain sha256 of canonical bytes there).
        raw = b'{"action":"deploy","params":{"tag":"v1.2.3"},"target":"prod"}'
        ours = aeg.propose(raw)["action_digest"]
        plain = hashlib.sha256(
            json.dumps(json.loads(raw), sort_keys=True,
                       separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")).hexdigest()
        self.assertNotEqual(ours, plain)

    def test_propose_rejects_bad_shapes(self):
        _expect_code(lambda: aeg.propose(b""), "approval-malformed")
        _expect_code(lambda: aeg.propose("not-bytes"), "approval-malformed")
        _expect_code(lambda: aeg.propose(b'{"a":1}', proposal_id=""),
                     "approval-malformed")

    def test_opaque_bytes_bind_byte_exact(self):
        a = aeg.propose(b"\x00\x01opaque", proposal_id="op")
        b = aeg.propose(b"\x01\x00opaque", proposal_id="op")
        self.assertNotEqual(a["action_digest"], b["action_digest"])


class CheckApprovalTests(unittest.TestCase):
    def test_byte_identical_approval_passes(self):
        action = b'{"action":"deploy","target":"prod"}'
        proposal = aeg.propose(action, proposal_id="p1")
        self.assertTrue(
            aeg.check_approval(proposal,
                               {"proposal_id": "p1",
                                "action_bytes": action}))

    def test_semantically_identical_wire_shape_passes(self):
        proposal = aeg.propose(b'{"a":1,"b":2}', proposal_id="p1")
        self.assertTrue(
            aeg.check_approval(proposal,
                               {"proposal_id": "p1",
                                "action_bytes": b'{ "b" : 2 , "a" : 1 }'}))

    def test_edited_action_refused(self):
        proposal = aeg.propose(b'{"a":1}', proposal_id="p1")
        _expect_code(
            lambda: aeg.check_approval(
                proposal,
                {"proposal_id": "p1", "action_bytes": b'{"a":2}'}),
            "approval-edited")

    def test_attacker_rewritten_id_refused_as_edited(self):
        # Approval genuinely bound to Y, id rewritten to X: ids match,
        # digests differ -> approval-edited (the binding was tampered).
        prop_x = aeg.propose(b'{"a":1}', proposal_id="X")
        _expect_code(
            lambda: aeg.check_approval(
                prop_x,
                {"proposal_id": "X", "action_bytes": b'{"a":2}'}),
            "approval-edited")

    def test_rebinding_across_contexts_refused(self):
        # Approval genuinely bound to Y presented in X's context:
        # different id -> approval-rebinding, even with clean bytes.
        prop_x = aeg.propose(b'{"a":1}', proposal_id="X")
        prop_y = aeg.propose(b'{"a":2}', proposal_id="Y")
        self.assertTrue(
            aeg.check_approval(prop_y,
                               {"proposal_id": "Y",
                                "action_bytes": b'{"a":2}'}))
        _expect_code(
            lambda: aeg.check_approval(
                prop_x,
                {"proposal_id": "Y", "action_bytes": b'{"a":2}'}),
            "approval-rebinding")

    def test_identical_bytes_different_id_still_rebinding(self):
        # Even when the action bytes are identical, presenting Y's
        # approval in X's context refuses: contexts are not conflated.
        prop_x = aeg.propose(b'{"a":1}', proposal_id="X")
        _expect_code(
            lambda: aeg.check_approval(
                prop_x,
                {"proposal_id": "Y", "action_bytes": b'{"a":1}'}),
            "approval-rebinding")

    def test_malformed_shapes(self):
        proposal = aeg.propose(b'{"a":1}', proposal_id="p1")
        _expect_code(lambda: aeg.check_approval("nope", {}),
                     "approval-malformed")
        _expect_code(lambda: aeg.check_approval(proposal, "nope"),
                     "approval-malformed")
        _expect_code(
            lambda: aeg.check_approval(proposal, {"proposal_id": "p1"}),
            "approval-malformed")
        _expect_code(
            lambda: aeg.check_approval(
                {"proposal_id": "p1", "action_digest": "zz"},
                {"proposal_id": "p1", "action_bytes": b'{"a":1}'}),
            "approval-malformed")


class ReproposeTests(unittest.TestCase):
    def test_repropose_is_fresh_and_unlinked(self):
        old = aeg.propose(b'{"a":1}', proposal_id="p1")
        fresh = aeg.repropose(b'{"a":2}')
        self.assertNotEqual(fresh["proposal_id"], old["proposal_id"])
        self.assertNotEqual(fresh["action_digest"], old["action_digest"])
        self.assertEqual(set(fresh),
                         {"version", "proposal_id", "action_digest",
                          "issued_at"})
        # The old (proposal, approval) pair still fails against the
        # fresh proposal: no silent link.
        _expect_code(
            lambda: aeg.check_approval(
                fresh, {"proposal_id": "p1", "action_bytes": b'{"a":1}'}),
            "approval-rebinding")
        # And a clean approval against the fresh proposal consumes.
        self.assertTrue(
            aeg.check_approval(
                fresh,
                {"proposal_id": fresh["proposal_id"],
                 "action_bytes": b'{"a":2}'}))


class CanonicalEquivalenceTests(unittest.TestCase):
    def test_matches_permit_closure_canonicalization(self):
        # Guard against drift from the existing request-canonicalization
        # (gov/permit_closure.py): the same fixtures must canonicalize
        # identically here. The guard is self-contained (no private
        # coupling) but mechanically pinned to the original.
        from gov import permit_closure as pc
        fixtures = [
            b'{"action":"deploy","params":{"tag":"v1.2.3"},"target":"prod"}',
            b'{ "target" : "prod" , "action" : "deploy" }',
            b'[1, 2, {"z": null, "y": true}]',
            b"\x00\x01opaque-payload",
            b"plain text, not json {",
        ]
        for raw in fixtures:
            self.assertEqual(aeg._canonical_action_bytes(raw),
                             pc._canonical_request_bytes(raw),
                             "drift on %r" % (raw,))


class TaxonomyTests(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in ("approval-edited", "approval-rebinding",
                     "approval-malformed"):
            record = decision_codes.code_for(code)
            self.assertEqual(record["code"], code)
            self.assertEqual(record["domain"], "approval")

    def test_pin(self):
        # Wave-237 merge: re-pointed 650 -> 667 (lane-local 647 + 3;
        # the merge composes 20 new codes: 647 -> 667).
        # Wave-238 merge: re-pointed 667 -> 695 (28 new codes across
        # four lanes), composed from the four lane commits by direct
        # byte-verification.
        # Wave-239 merge: re-pointed 695 -> 718 (23 new codes across
        # four lanes: 8 AAuth R3 + 6 claim-at-dispatch + 3
        # refusal-oracle guard + 6 AER-1 provenance non-upgrade),
        # composed from the four lane commits by direct
        # byte-verification.
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1742)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main(verbosity=1)
