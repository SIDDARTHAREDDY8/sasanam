"""Tests for the NIST control-claim table (gov/control_claims.py) and its
additive OSCAL extension (gov/evidence/oscal_control_claims.py).

Every check in the claim table runs real operations against the real
modules -- these tests assert the table is well-formed, the checks
evaluate and hold, and the fail-closed detector is honest (a bogus or
exploding check is UNCHECKABLE, never a pass). The OSCAL extension is
tested for determinism, digest sensitivity, and the loud not-claimed
rows.

Hermetic: each check uses a fresh temp dir; the SI-4 check provisions
a fresh random log key through the explicit operator seam and restores
the env. Stdlib only (unittest), offline, $0, deterministic.
"""

import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import control_claims as cc
from gov.evidence import oscal_control_claims as osc


class ClaimTableShapeTest(unittest.TestCase):
    def test_every_claim_has_all_fields(self):
        self.assertTrue(cc.CONTROL_CLAIMS)
        seen = set()
        for claim in cc.CONTROL_CLAIMS:
            self.assertEqual(set(claim.keys()), set(cc.CLAIM_FIELDS))
            for field in cc.CLAIM_FIELDS:
                self.assertTrue(claim[field],
                                "%s.%s is empty" % (claim["control_id"],
                                                    field))
            seen.add(claim["control_id"])
        self.assertEqual(len(seen), len(cc.CONTROL_CLAIMS),
                         "duplicate control_id in the claim table")

    def test_every_check_is_registered_and_callable(self):
        for claim in cc.CONTROL_CLAIMS:
            name = claim["check"]
            self.assertIn(name, cc.CHECKS, "%s names unknown check %r"
                          % (claim["control_id"], name))
            self.assertTrue(callable(cc.CHECKS[name]))

    def test_not_claimed_is_loud(self):
        self.assertTrue(cc.NOT_CLAIMED)
        for entry in cc.NOT_CLAIMED:
            for key in ("control_id", "title", "why_not"):
                self.assertTrue(entry.get(key), "not-claimed entry missing %r"
                                % (key,))
        claimed_ids = {c["control_id"] for c in cc.CONTROL_CLAIMS}
        for entry in cc.NOT_CLAIMED:
            self.assertNotIn(entry["control_id"], claimed_ids,
                             "control both claimed and not-claimed")

    def test_get_claim(self):
        self.assertEqual(cc.get_claim("SI-7")["control_id"], "SI-7")
        with self.assertRaises(KeyError):
            cc.get_claim("XX-99")


class ClaimChecksHoldTest(unittest.TestCase):
    def test_every_claim_holds(self):
        failures = []
        for result in cc.check_all():
            if not (result.held and result.checkable):
                failures.append("%s: %s" % (result.control_id,
                                            result.detail))
        self.assertEqual([], failures,
                         "claims not held: %s" % failures)

    def test_check_claim_matches_evaluate(self):
        r = cc.check_claim("SI-7")
        self.assertTrue(r.held and r.checkable)
        self.assertEqual(r.control_id, "SI-7")


class FailClosedDetectorTest(unittest.TestCase):
    def test_unknown_check_name_is_uncheckable_never_a_pass(self):
        bogus = dict(cc.CONTROL_CLAIMS[0])
        bogus["check"] = "check_does_not_exist"
        r = cc.evaluate_claim(bogus)
        self.assertFalse(r.held)
        self.assertFalse(r.checkable)
        self.assertIn("UNCHECKABLE", r.detail)

    def test_exploding_check_is_uncheckable_never_a_pass(self):
        def _boom():
            raise RuntimeError("mechanism imploded")
        cc.CHECKS["check_boom_probe"] = _boom
        try:
            bogus = dict(cc.CONTROL_CLAIMS[0])
            bogus["check"] = "check_boom_probe"
            r = cc.evaluate_claim(bogus)
            self.assertFalse(r.held)
            self.assertFalse(r.checkable)
            self.assertIn("UNCHECKABLE", r.detail)
        finally:
            del cc.CHECKS["check_boom_probe"]

    def test_non_bool_held_is_uncheckable(self):
        cc.CHECKS["check_weird_probe"] = lambda: ("yes", "detail")
        try:
            bogus = dict(cc.CONTROL_CLAIMS[0])
            bogus["check"] = "check_weird_probe"
            r = cc.evaluate_claim(bogus)
            self.assertFalse(r.held)
            self.assertFalse(r.checkable)
        finally:
            del cc.CHECKS["check_weird_probe"]

    def test_evaluate_claim_never_raises(self):
        r = cc.evaluate_claim({})
        self.assertFalse(r.held)
        self.assertFalse(r.checkable)


class OscalExtensionTest(unittest.TestCase):
    TS = "2026-09-29T00:00:00+00:00"

    def test_deterministic(self):
        a = osc.component_definition_json(self.TS)
        b = osc.component_definition_json(self.TS)
        self.assertEqual(a, b)
        # The last-modified line is the only time-varying part.
        pkg = json.loads(a)
        self.assertEqual(
            pkg["component-definition"]["metadata"]["last-modified"],
            self.TS)

    def test_digest_is_a_real_function_of_content(self):
        d1 = osc.control_claims_content_digest()
        self.assertEqual(len(d1), 64)
        # Sensitivity: a mutated table must digest differently.
        mutated = [dict(c) for c in cc.CONTROL_CLAIMS]
        mutated[0] = dict(mutated[0])
        mutated[0]["scope"] = "mutated scope"
        d2_bytes = osc._canonical_claims_bytes(mutated, cc.NOT_CLAIMED)
        import hashlib
        d2 = hashlib.sha256(d2_bytes).hexdigest()
        self.assertNotEqual(d1, d2)
        # And the metadata prop carries the same digest.
        pkg = osc.generate_control_claims_component_definition(self.TS)
        props = {p["name"]: p["value"] for p in
                 pkg["component-definition"]["metadata"]["props"]}
        self.assertEqual(props["x-control-claims-sha256"], d1)

    def test_claimed_and_not_claimed_rows(self):
        pkg = osc.generate_control_claims_component_definition(self.TS)
        comp = pkg["component-definition"]["components"][0]
        impls = comp["control-implementations"]
        self.assertEqual(len(impls), 1)
        self.assertEqual(impls[0]["source"], cc.FRAMEWORK_ID)
        reqs = impls[0]["implemented-requirements"]
        by_status = {}
        for r in reqs:
            props = {p["name"]: p["value"] for p in r["props"]}
            by_status.setdefault(props["x-claim-status"],
                                 []).append((r["control-id"], props))
        self.assertEqual(len(by_status["claimed"]), len(cc.CONTROL_CLAIMS))
        self.assertEqual(len(by_status["not-claimed"]), len(cc.NOT_CLAIMED))
        claimed_ids = {c for (c, _) in by_status["claimed"]}
        self.assertEqual(claimed_ids,
                         {c["control_id"] for c in cc.CONTROL_CLAIMS})
        not_claimed_ids = {c for (c, _) in by_status["not-claimed"]}
        self.assertEqual(not_claimed_ids,
                         {e["control_id"] for e in cc.NOT_CLAIMED})

    def test_every_claimed_row_names_check_and_evidence_field(self):
        pkg = osc.generate_control_claims_component_definition(self.TS)
        reqs = pkg["component-definition"]["components"][0][
            "control-implementations"][0]["implemented-requirements"]
        for r in reqs:
            props = {p["name"]: p["value"] for p in r["props"]}
            if props["x-claim-status"] != "claimed":
                continue
            self.assertTrue(props["x-claim-check"])
            self.assertTrue(props["x-evidence-field"])
            self.assertIn(props["x-claim-check"], cc.CHECKS)
            self.assertTrue(props["x-scope"])
            self.assertTrue(props["x-not-claimed"])

    def test_existing_exporter_untouched(self):
        # The additive module must not change the wave-174 exporter.
        from gov.evidence import oscal_export
        a = oscal_export.component_definition_json(self.TS)
        self.assertIn("x-crosswalk-sha256", a)
        self.assertNotIn("control-claims", a.lower())


if __name__ == "__main__":
    unittest.main()
