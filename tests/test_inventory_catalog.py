"""Unit tests for gov/inventory_catalog.py (wave-255 lane 4).

Backstage (Apache-2.0) pattern adaptation: declarative agent/tool/skill
inventory catalog, fail-closed load, posture-card scorecard attachment,
and deployment-owned grant-graph composition.
"""

import unittest

from gov import decision_codes
from gov import inventory_catalog as ic

# Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive


def _entry(name, kind="agent", rels=()):
    e = {"kind": kind, "name": name, "owner": "team-a"}
    if rels:
        e["relationships"] = list(rels)
    return e


def _three():
    return ic.load_catalog([
        _entry("agent-1", rels=[
            {"to": "tool-x", "type": "uses"},
            {"to": "skill-y", "type": "grant"},
        ]),
        _entry("tool-x", kind="tool"),
        _entry("skill-y", kind="skill"),
    ])


def _cards():
    return [
        {"track": "policy", "check": "c1", "score": 0.8,
         "reason": "r", "remediation": "m"},
        {"track": "identity", "check": "c2", "score": 0.5,
         "reason": "r", "remediation": "m"},
    ]


class LoadTest(unittest.TestCase):
    def test_load_ok(self):
        cat = _three()
        self.assertEqual(cat.names(), ["agent-1", "skill-y", "tool-x"])

    def test_empty_catalog_ok(self):
        self.assertEqual(ic.load_catalog([]).names(), [])

    def test_non_list_catalog_refused(self):
        with self.assertRaises(ic.CatalogRefused) as ctx:
            ic.load_catalog({"agent-1": {}})
        self.assertEqual(ctx.exception.code,
                         "inventory-catalog-entry-malformed")

    def test_non_dict_entry_refused(self):
        with self.assertRaises(ic.CatalogRefused) as ctx:
            ic.load_catalog(["agent-1"])
        self.assertEqual(ctx.exception.code,
                         "inventory-catalog-entry-malformed")


class TaxonomyPinTest(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog),
        # additive
        self.assertEqual(len(decision_codes.TAXONOMY), 1900)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        self.assertEqual(len(set(decision_codes.TAXONOMY)), 1900)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*)
        for code in ("inventory-catalog-card-malformed",
                     "inventory-catalog-dangling-reference",
                     "inventory-catalog-duplicate-entry",
                     "inventory-catalog-entry-malformed",
                     "inventory-catalog-grant-unresolved",
                     "inventory-catalog-seam-unavailable",
                     "inventory-catalog-unknown-entry"):
            decision_codes.code_for(code)


class ScorecardTest(unittest.TestCase):
    def test_attach_returns_new_catalog(self):
        cat = _three()
        cat2 = ic.attach_scorecard(cat, "agent-1", _cards())
        self.assertIsNot(cat, cat2)
        rep = ic.report(cat2, "agent-1")
        self.assertEqual(rep["entry"]["name"], "agent-1")
        self.assertIn("policy", rep["scorecard"])
        self.assertIn("identity", rep["scorecard"])

    def test_report_without_scorecard_none(self):
        rep = ic.report(_three(), "tool-x")
        self.assertIsNone(rep["scorecard"])


class GrantEdgeTest(unittest.TestCase):
    def test_confirmed_grant_resolves(self):
        def provider(agent, tool):
            return (agent, tool) == ("agent-1", "skill-y")

        self.assertEqual(
            ic.grant_edges(_three(), grants_provider=provider),
            [("agent-1", "skill-y")])

    def test_mapping_provider_resolves(self):
        self.assertEqual(
            ic.grant_edges(_three(),
                           grants_provider={("agent-1", "skill-y"): True}),
            [("agent-1", "skill-y")])

    def test_provider_exception_refuses(self):
        def provider(agent, tool):
            raise RuntimeError("downstream down")

        with self.assertRaises(ic.CatalogRefused) as ctx:
            ic.grant_edges(_three(), grants_provider=provider)
        self.assertEqual(ctx.exception.code,
                         "inventory-catalog-grant-unresolved")


class RegisteredPredicateTest(unittest.TestCase):
    def test_declared_true_undeclared_false(self):
        cat = _three()
        self.assertTrue(ic.is_registered_name(cat, "agent-1"))
        self.assertFalse(ic.is_registered_name(cat, "ghost"))

    def test_non_catalog_refuses(self):
        with self.assertRaises(ic.CatalogRefused) as ctx:
            ic.is_registered_name({}, "agent-1")
        self.assertEqual(ctx.exception.code,
                         "inventory-catalog-entry-malformed")


if __name__ == "__main__":
    unittest.main()
