"""Unit tests for gov/policy_change_containment.py (wave-266).

Pin: 1205 (wave-265 merge) + 7 policy-* = 1212. This file is the
lane's own pin holder; the global test_decision_codes.py pin is
left for the merge coordinator's repoint pass (standard lane
convention).
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import policy_change_containment as pcc

TAXONOMY_PIN = 2144  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144



def _egress(rid, subject, hosts, ports=(443,), methods=("GET",),
            paths=("/",), credential=None):
    rule = {"id": rid, "subject": subject, "effect": "allow",
            "action": "egress", "hosts": list(hosts),
            "ports": list(ports), "methods": list(methods),
            "paths": list(paths), "credential": credential}
    return rule


def _pol(*rules):
    return {"version": 1, "rules": list(rules)}


class TestCodes(unittest.TestCase):
    def test_codes_tuple(self):
        self.assertEqual(list(pcc.CODES), sorted(pcc.CODES))
        self.assertEqual(len(pcc.CODES), 7)

    def test_taxonomy_pin(self):
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)

    def test_entries_present(self):
        for code in pcc.CODES:
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "policy")
            self.assertEqual(dc.TAXONOMY[code]["code"], code)


class TestContainment(unittest.TestCase):
    def setUp(self):
        self.boundary = _pol(
            _egress("b", "*", ["api.example.com"], ports=(443,),
                    methods=("GET", "POST"), paths=("/v1/*",)))
        self.current = _pol(
            _egress("c", "agent-worker", ["api.example.com"],
                    ports=(443,), methods=("GET",),
                    paths=("/v1/chat",)))

    def test_equivalent_passes(self):
        rep = pcc.gate_policy_change(self.current, self.current,
                                     self.boundary)
        self.assertEqual(rep["verdict"], "within_boundary")
        self.assertEqual(rep["delta_class"], "equivalent")
        self.assertEqual(rep["failed_checks"], [])

    def test_restrictive_passes(self):
        cand = _pol()
        rep = pcc.gate_policy_change(cand, self.current,
                                     self.boundary)
        self.assertEqual(rep["verdict"], "within_boundary")
        self.assertEqual(rep["delta_class"], "restrictive")

    def test_boundary_exceeded(self):
        cand = _pol(
            _egress("x", "agent-worker", ["evil.example.com"]),
            *self.current["rules"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(cand, self.current,
                                   self.boundary)
        self.assertEqual(cm.exception.code,
                         "policy-boundary-exceeded")

    def test_capability_expansion(self):
        boundary = _pol(
            _egress("b2", "*", ["api.example.com"], ports=(443,),
                    methods=("GET", "POST", "DELETE"),
                    paths=("/v1/*",)))
        cand = _pol(
            _egress("x", "agent-worker", ["api.example.com"],
                    ports=(443,), methods=("DELETE",),
                    paths=("/v1/users",)),
            *self.current["rules"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(cand, self.current,
                                   boundary)
        self.assertEqual(cm.exception.code,
                         "policy-change-capability-expansion")

    def test_new_host_in_boundary_passes(self):
        # A brand-new host:port inside the declared boundary is a
        # boundary question, not a capability-expansion finding.
        boundary = _pol(
            _egress("b", "*", ["*.example.com"], ports=(443,),
                    methods=("GET",), paths=("/v1/*",)))
        cand = _pol(
            _egress("x", "agent-worker", ["new.example.com"],
                    ports=(443,), methods=("GET",),
                    paths=("/v1/chat",)),
            *self.current["rules"])
        rep = pcc.gate_policy_change(cand, self.current, boundary)
        self.assertEqual(rep["verdict"], "within_boundary")

    def test_link_local_refused(self):
        boundary = _pol(
            _egress("b-meta", "*", ["169.254.169.254"]),
            *self.boundary["rules"])
        cand = _pol(
            _egress("x", "agent-worker", ["169.254.169.254"]),
            *self.current["rules"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(cand, self.current, boundary)
        self.assertEqual(cm.exception.code,
                         "policy-change-link-local-reach")

    def test_l7_bypass_refused(self):
        boundary = _pol(
            _egress("b", "agent-worker", ["vault.internal"],
                    ports=(8200,), methods=("GET", "POST"),
                    paths=("/v1/*",)))
        current = _pol(
            _egress("c", "agent-worker", ["vault.internal"],
                    ports=(8200,), methods=("GET",),
                    paths=("/v1/secrets",)))
        cand = _pol(
            _egress("x", "agent-worker", ["vault.internal"],
                    ports=(8200,), methods=("POST",),
                    paths=("/v1/admin",)),
            *current["rules"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(
                cand, current, boundary,
                credentialed_hosts=("vault.internal",))
        self.assertEqual(cm.exception.code,
                         "policy-change-l7-bypass-credentialed")

    def test_credential_reach_refused(self):
        boundary = _pol(
            {"id": "b", "subject": "*", "effect": "allow",
             "action": "credential-use", "credential": "prod-db"})
        current = _pol(
            {"id": "c", "subject": "agent-worker",
             "effect": "allow", "action": "credential-use",
             "credential": "prod-db"})
        cand = _pol(
            {"id": "x", "subject": "new-bot", "effect": "allow",
             "action": "credential-use", "credential": "prod-db"},
            *current["rules"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(cand, current, boundary)
        self.assertEqual(cm.exception.code,
                         "policy-change-credential-reach-expansion")

    def test_uncheckable_deny_rule(self):
        cand = _pol(
            {"id": "x", "subject": "agent-worker",
             "effect": "deny", "action": "egress",
             "hosts": ["evil.example.com"]},
            *self.current["rules"])
        rep = pcc.check_policy_change(cand, self.current,
                                      self.boundary)
        self.assertEqual(rep["verdict"], "uncheckable")
        self.assertEqual(rep["failed_checks"],
                         ["policy-change-uncheckable"])
        with self.assertRaises(pcc.PolicyChangeError) as cm:
            pcc.gate_policy_change(cand, self.current,
                                   self.boundary)
        self.assertEqual(cm.exception.code,
                         "policy-change-uncheckable")

    def test_empty_boundary_uncheckable(self):
        rep = pcc.check_policy_change(self.current, self.current,
                                      _pol())
        self.assertEqual(rep["verdict"], "uncheckable")

    def test_malformed_loud(self):
        for bad in ("nope", {"version": 2, "rules": []},
                    {"version": 1, "rules": [{"id": ""}]}):
            with self.assertRaises(pcc.PolicyChangeError) as cm:
                pcc.check_policy_change(bad, self.current,
                                        self.boundary)
            self.assertEqual(cm.exception.code,
                             "policy-change-malformed")

    def test_coverage_honest(self):
        rep = pcc.check_policy_change(self.current, self.current,
                                      self.boundary)
        self.assertTrue(rep["checked"])
        self.assertTrue(rep["out_of_scope"])
        self.assertTrue(any("deny" in s
                            for s in rep["out_of_scope"]))
        self.assertEqual(len(rep["evidence_digest"]), 64)

    def test_to_evidence(self):
        rep = pcc.check_policy_change(self.current, self.current,
                                      self.boundary)
        ev = pcc.to_evidence(rep)
        self.assertEqual(ev["kind"], "policy-change-decision")
        self.assertEqual(ev["verdict"], "within_boundary")
        self.assertEqual(len(ev["record_digest"]), 64)

    def test_wildcard_host_expansion_is_link_local_screened(self):
        # Over-approximation, documented: "*" could cover the
        # metadata IP, so the risk check fires.
        boundary = _pol(
            _egress("b", "*", ["*"], ports=(443,),
                    methods=("GET",), paths=("/",)))
        cand = _pol(
            _egress("x", "agent-worker", ["*"], ports=(443,),
                    methods=("GET",), paths=("/",)),
            *self.current["rules"])
        rep = pcc.check_policy_change(cand, self.current,
                                      boundary)
        self.assertIn("policy-change-link-local-reach",
                      rep["failed_checks"])


if __name__ == "__main__":
    unittest.main()
