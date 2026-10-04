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

TAXONOMY_PIN = 2020 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*)




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
