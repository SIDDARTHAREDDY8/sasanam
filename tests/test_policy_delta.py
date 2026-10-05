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

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).



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
