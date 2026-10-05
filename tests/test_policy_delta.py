"""Unit tests for gov/policy_delta.py (wave-267).

Pin: 1222 (wave-266 merge) + 6 policy-delta-* = 1228. This file is
the lane's own pin holder; the global test_decision_codes.py pin is
left for the merge coordinator's repoint pass (standard lane
convention).
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import policy_delta as pd
from gov.agent_callbacks import Continue, HumanApprovalGate

TAXONOMY_PIN = 2070 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).




def _egress(rid, subject, hosts, ports=(443,), methods=("GET",),
            paths=("/",), credential=None, effect="allow"):
    return {"id": rid, "subject": subject, "effect": effect,
            "action": "egress", "hosts": list(hosts),
            "ports": list(ports), "methods": list(methods),
            "paths": list(paths), "credential": credential}


def _pol(*rules):
    return {"version": 1, "rules": list(rules)}


CURRENT = _pol(_egress("llm", "agent-worker", ["api.example.com"],
                       paths=["/v1/*"]))
WIDE_BOUNDARY = _pol(_egress("b", "agent-worker", ["*.example.com"],
                             methods=["GET", "POST"], paths=["*"]))


class TestCodes(unittest.TestCase):
    def test_codes_tuple_sorted(self):
        self.assertEqual(list(pd.CODES), sorted(pd.CODES))
        self.assertEqual(len(pd.CODES), 6)

    def test_codes_in_taxonomy(self):
        for code in pd.CODES:
            self.assertIn(code, dc.TAXONOMY)

    def test_malformed_reuses_existing_code(self):
        # policy-delta-malformed is owned by gov/policy_delta_gate.py;
        # this seam reuses it instead of minting a duplicate.
        self.assertIn(pd.MALFORMED, dc.TAXONOMY)

    def test_taxonomy_pin(self):
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)

    def test_policy_version(self):
        self.assertEqual(pd.POLICY_VERSION, 1)


class TestCounterexamples(unittest.TestCase):
    def test_widen_emits_concrete_artifact(self):
        cand = _pol(_egress("llm", "agent-worker", ["api.example.com"],
                            paths=["/v1/*"]),
                    _egress("new", "agent-worker", ["new.example.com"],
                            methods=["POST"], paths=["/admin"]))
        r = pd.counterexamples(cand, CURRENT, WIDE_BOUNDARY)
        self.assertEqual(r["verdict"], "within_boundary")
        self.assertEqual(r["delta_class"], "expanding")
        self.assertEqual(len(r["counterexamples"]), 1)
        cx = r["counterexamples"][0]
        self.assertEqual(cx["code"], "policy-delta-counterexample-raised")
        self.assertEqual(cx["subject"], "agent-worker")
        self.assertEqual(cx["action"], "egress")
        self.assertEqual(cx["resource"]["host"], "new.example.com")
        self.assertEqual(cx["resource"]["method"], "POST")
        self.assertEqual(cx["resource"]["path"], "/admin")
        self.assertTrue(cx["within_boundary"])
        self.assertEqual(len(cx["evidence_digest"]), 64)

    def test_restrictive_emits_none(self):
        r = pd.counterexamples(_pol(), CURRENT, WIDE_BOUNDARY)
        self.assertEqual(r["counterexamples"], [])
        self.assertEqual(r["delta_class"], "restrictive")

    def test_forbid_veto(self):
        cand = _pol(_egress("llm", "agent-worker", ["api.example.com"],
                            paths=["/v1/*"]),
                    _egress("deny", "agent-worker", ["*"], effect="deny"))
        r = pd.counterexamples(cand, CURRENT, WIDE_BOUNDARY)
        self.assertEqual(r["verdict"], "uncheckable")
        self.assertIn("policy-delta-forbid-residual",
                      r["failed_checks"])

    def test_unknown_delta_uncheckable(self):
        cand = _pol(_egress("llm", "agent-worker", ["api.example.com"],
                            paths=["/v1/*"]),
                    _egress("weird", "agent-worker", ["not a host!!"]))
        r = pd.counterexamples(cand, CURRENT, WIDE_BOUNDARY)
        self.assertEqual(r["verdict"], "uncheckable")
        self.assertIn("policy-delta-unknown", r["failed_checks"])
        self.assertEqual(r["counterexamples"], [])

    def test_malformed_loud(self):
        with self.assertRaises(pd.PolicyDeltaError) as ctx:
            pd.counterexamples("nope", CURRENT, WIDE_BOUNDARY)
        self.assertEqual(ctx.exception.code, "policy-delta-malformed")

    def test_malformed_credentialed_hosts(self):
        with self.assertRaises(pd.PolicyDeltaError) as ctx:
            pd.counterexamples(CURRENT, CURRENT, WIDE_BOUNDARY,
                               credentialed_hosts="bare-string")
        self.assertEqual(ctx.exception.code, "policy-delta-malformed")


class TestEngine(unittest.TestCase):
    def test_allow(self):
        d = pd.evaluate(
            CURRENT,
            {"subject": "agent-worker", "action": "egress",
             "host": "api.example.com", "port": 443,
             "method": "GET", "path": "/v1/x", "credential": None})
        self.assertEqual(d["decision"], "Allow")
        self.assertEqual(d["matched_rule"], "llm")

    def test_default_deny(self):
        d = pd.evaluate(
            CURRENT,
            {"subject": "agent-worker", "action": "egress",
             "host": "nope.example.com", "port": 443,
             "method": "GET", "path": "/v1/x", "credential": None})
        self.assertEqual(d["decision"], "Deny")
        self.assertEqual(d["reason"], "policy-delta-default-deny")

    def test_forbid_overrides(self):
        pol = _pol(_egress("a", "agent-worker", ["api.example.com"],
                           paths=["/v1/*"]),
                   _egress("d", "agent-worker", ["api.example.com"],
                           paths=["/v1/*"], effect="deny"))
        d = pd.evaluate(
            pol,
            {"subject": "agent-worker", "action": "egress",
             "host": "api.example.com", "port": 443,
             "method": "GET", "path": "/v1/x", "credential": None})
        self.assertEqual(d["decision"], "Deny")
        self.assertEqual(d["reason"], "policy-delta-forbid")

    def test_residual_forbid_unknown(self):
        pol = _pol(_egress("a", "agent-worker", ["api.example.com"],
                           paths=["/v1/*"]),
                   _egress("d", "agent-worker", ["not a host!!"],
                           effect="deny"))
        d = pd.evaluate(
            pol,
            {"subject": "agent-worker", "action": "egress",
             "host": "api.example.com", "port": 443,
             "method": "GET", "path": "/v1/x", "credential": None})
        self.assertEqual(d["decision"], "Unknown")
        self.assertEqual(d["reason"], "policy-delta-forbid-residual")

    def test_empty_policy_denies(self):
        d = pd.evaluate(_pol(), {"subject": "s", "action": "egress",
                                 "host": "h", "port": 443,
                                 "method": "GET", "path": "/",
                                 "credential": None})
        self.assertEqual(d["decision"], "Deny")

    def test_malformed_policy_loud(self):
        with self.assertRaises(pd.PolicyDeltaError) as ctx:
            pd.evaluate({"version": 1}, {"subject": "s"})
        self.assertEqual(ctx.exception.code, "policy-delta-malformed")


class TestReviewWiring(unittest.TestCase):
    def test_digest_only_journal(self):
        cand = _pol(_egress("llm", "agent-worker", ["api.example.com"],
                            paths=["/v1/*"]),
                    _egress("evil", "agent-worker", ["evil.example.com"]))
        r = pd.counterexamples(cand, CURRENT, WIDE_BOUNDARY)
        journal = []
        gate = HumanApprovalGate(journal)
        approval_id, artifacts = pd.request_review(gate, r, "pol-1")
        self.assertTrue(approval_id)
        self.assertEqual(artifacts, r["counterexamples"])
        # Public-seam proof the approval was registered: resolve it.
        verdict = gate.resolve(approval_id, True, decider="reviewer")
        self.assertIsInstance(verdict, Continue)
        blob = str(journal)
        self.assertNotIn("evil.example.com", blob)
        reqs = [e for e in journal
                if e.get("kind") == "approval-request"]
        self.assertEqual(reqs[0]["tool"], "policy-delta-review")

    def test_bad_gate_loud(self):
        r = pd.counterexamples(CURRENT, CURRENT, WIDE_BOUNDARY)
        with self.assertRaises(pd.PolicyDeltaError):
            pd.request_review(None, r, "pol-1")


if __name__ == "__main__":
    unittest.main()
