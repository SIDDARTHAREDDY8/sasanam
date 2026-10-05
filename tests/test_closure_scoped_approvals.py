#!/usr/bin/env python3
"""Unit tests for gov.closure_scoped_approvals (wave-237 lane D).

Tests live at the public seams: issue_scoped_approval,
verify_scoped_approval, settle_attempt, exercise_capability,
recheck_and_write. Assertions use literal expected values (worked
examples), never recompute the module's own digest to "prove" the
digest.
"""

import copy
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import closure_scoped_approvals as csa  # noqa: E402


def _issue(**over):
    kw = dict(run_id="run-001", sandbox_id="sbx-a",
              requester_id="agent-7", route="deploy/prod",
              approval_identity="approver-3",
              capabilities=["deploy:prod", "logs:read"],
              request_digest="ab" * 32, state_digest="cd" * 32)
    kw.update(over)
    return csa.issue_scoped_approval(**kw)


class IssueTest(unittest.TestCase):
    def test_packet_shape_and_seal(self):
        packet = _issue()
        self.assertEqual(packet["version"], 1)
        self.assertEqual(len(packet["approval_digest"]), 64)
        # Deterministic: same inputs seal identically, derive the same id.
        again = _issue()
        self.assertEqual(again["approval_digest"], packet["approval_digest"])
        self.assertEqual(again["approval_id"], packet["approval_id"])
        self.assertFalse(packet["settled"])
        self.assertEqual(packet["consumption"], [])

    def test_explicit_approval_id_kept(self):
        packet = _issue(approval_id="my-approval")
        self.assertEqual(packet["approval_id"], "my-approval")
        self.assertTrue(csa.verify_scoped_approval(packet))

    def test_malformed_inputs_refused(self):
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            _issue(run_id="")
        self.assertEqual(cm.exception.code, "scoped-approval-malformed")
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            _issue(capabilities=[])
        self.assertEqual(cm.exception.code, "scoped-approval-malformed")
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            _issue(request_digest="not-hex")
        self.assertEqual(cm.exception.code, "scoped-approval-malformed")
        # Duplicate capabilities are a shape violation, not silent dedup.
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            _issue(capabilities=["a", "a"])
        self.assertEqual(cm.exception.code, "scoped-approval-malformed")


class VerifyTest(unittest.TestCase):
    def test_happy(self):
        self.assertTrue(csa.verify_scoped_approval(_issue()))
        self.assertTrue(csa.verify_scoped_approval(
            _issue(), run_id="run-001", sandbox_id="sbx-a",
            route="deploy/prod"))

    def test_named_context_mismatches(self):
        packet = _issue()
        for kwargs, code in (
                ({"run_id": "run-x"}, "approval-run-mismatch"),
                ({"sandbox_id": "sbx-x"}, "approval-sandbox-mismatch"),
                ({"route": "deploy/x"}, "approval-route-mismatch")):
            with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
                csa.verify_scoped_approval(packet, **kwargs)
            self.assertEqual(cm.exception.code, code)
        # No context arguments: no check, no refusal.
        self.assertTrue(csa.verify_scoped_approval(packet))

    def test_tampered_packet_refused(self):
        packet = _issue()
        edited = dict(packet)
        edited["route"] = "deploy/evil"
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.verify_scoped_approval(edited)
        self.assertEqual(cm.exception.code, "scoped-approval-tampered")

    def test_malformed_packet_refused(self):
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.verify_scoped_approval({"version": 1})
        self.assertEqual(cm.exception.code, "scoped-approval-malformed")


class SettleTest(unittest.TestCase):
    def test_settle_and_idempotence(self):
        packet = _issue()
        r1 = csa.settle_attempt(packet)
        self.assertTrue(r1["settled"])
        self.assertEqual(r1["approval_digest"], packet["approval_digest"])
        r2 = csa.settle_attempt(packet)
        # Idempotent: the same receipt, never a second execution.
        self.assertEqual(r1, r2)

    def test_settle_tampered_refused(self):
        packet = _issue()
        edited = dict(packet)
        edited["capabilities"] = ["*"]
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.settle_attempt(edited)
        self.assertEqual(cm.exception.code, "scoped-approval-tampered")


class CapabilityTest(unittest.TestCase):
    def test_exercise_once_then_dead(self):
        packet = _issue()
        record = csa.exercise_capability(packet, "deploy:prod")
        self.assertEqual(record["capability"], "deploy:prod")
        self.assertEqual(len(packet["consumption"]), 1)
        csa.settle_attempt(packet)
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.exercise_capability(packet, "logs:read")
        self.assertEqual(cm.exception.code, "approval-capability-dead")

    def test_unknown_capability_refused(self):
        packet = _issue()
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.exercise_capability(packet, "secrets:read")
        self.assertEqual(cm.exception.code,
                         "scoped-approval-capability-unknown")

    def test_exercise_in_wrong_context_refused(self):
        packet = _issue()
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.exercise_capability(packet, "deploy:prod", run_id="run-x")
        self.assertEqual(cm.exception.code, "approval-run-mismatch")


class RecheckWriteTest(unittest.TestCase):
    def test_stale_state_refused_and_not_settled(self):
        packet = _issue()
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.recheck_and_write(packet, "ef" * 32)
        self.assertEqual(cm.exception.code, "approval-state-stale")
        self.assertFalse(packet["settled"])  # refusal is not the write

    def test_fresh_state_writes_and_settles(self):
        packet = _issue()
        receipt = csa.recheck_and_write(packet, "cd" * 32)
        self.assertTrue(receipt["settled"])
        self.assertEqual(receipt["approval_digest"],
                         packet["approval_digest"])
        # A second write under the same approval is dead.
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.recheck_and_write(packet, "cd" * 32)
        self.assertEqual(cm.exception.code, "approval-capability-dead")

    def test_apply_called_between_recheck_and_settlement(self):
        packet = _issue()
        calls = []

        def apply(p):
            calls.append(p["approval_digest"])

        receipt = csa.recheck_and_write(packet, "cd" * 32, apply=apply)
        self.assertEqual(calls, [packet["approval_digest"]])
        self.assertTrue(receipt["settled"])

    def test_apply_failure_does_not_settle(self):
        packet = _issue()

        def boom(p):
            raise RuntimeError("deployment write failed")

        with self.assertRaises(RuntimeError):
            csa.recheck_and_write(packet, "cd" * 32, apply=boom)
        self.assertFalse(packet["settled"])

    def test_write_in_wrong_context_refused(self):
        packet = _issue()
        with self.assertRaises(csa.ClosureScopedApprovalError) as cm:
            csa.recheck_and_write(packet, "cd" * 32,
                                  sandbox_id="sbx-other")
        self.assertEqual(cm.exception.code, "approval-sandbox-mismatch")


class TaxonomyPinTest(unittest.TestCase):
    def test_new_codes_registered(self):
        from gov import decision_codes as dc
        for code in ("approval-run-mismatch", "approval-sandbox-mismatch",
                     "approval-route-mismatch", "approval-capability-dead",
                     "approval-state-stale", "scoped-approval-malformed",
                     "scoped-approval-tampered",
                     "scoped-approval-capability-unknown"):
            self.assertIn(code, dc.TAXONOMY)
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
        self.assertEqual(len(dc.TAXONOMY), 2130) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
