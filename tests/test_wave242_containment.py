"""Unit tests for wave-242 lane B: stale-authority probe class (W242-2)
and delegation containment + policy currentness (W242-5).

Stdlib unittest only. Deterministic.
"""

import sys
import os
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import stale_authority as sa
from gov import delegation_containment as dcnt
from gov import decision_codes


def _utc(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


class StaleAuthorityTest(unittest.TestCase):
    def test_post_lapse_refuses_with_cause(self):
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                               _utc(2026, 10, 14))
        self.assertEqual(ctx.exception.code, "stale-authority")
        self.assertIn("2026-10-13", ctx.exception.detail)
        self.assertIn("cause", ctx.exception.detail.lower())

    def test_lapse_instant_boundary_refuses(self):
        # minted exactly at the lapse instant is post-lapse.
        with self.assertRaises(sa.StaleAuthorityError):
            sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                               sa.EMIRDAG_LAPSE_UTC)

    def test_pre_expiry_accepts_with_downgraded_annotation(self):
        verdict = sa.check_authority(
            "draft-emirdag-scitt-ai-agent-execution-00", _utc(2026, 10, 1))
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["provenance"], "downgraded")
        self.assertEqual(verdict["annotation"],
                         "authority-expired-2026-10-13")

    def test_live_draft_has_no_flag(self):
        verdict = sa.check_authority("draft-saha-bound-permit-00",
                                     _utc(2026, 10, 14))
        self.assertEqual(verdict, {"status": "accepted"})

    def test_prestaged_omp_lapse_refuses(self):
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            sa.check_authority("draft-veridom-omp-02", _utc(2026, 11, 20))
        self.assertEqual(ctx.exception.code, "stale-authority")
        self.assertIn("2026-11-14", ctx.exception.detail)

    def test_prestaged_omp_pre_lapse_accepts(self):
        verdict = sa.check_authority("draft-veridom-omp-02",
                                     _utc(2026, 10, 1))
        self.assertEqual(verdict["status"], "accepted")
        self.assertEqual(verdict["annotation"],
                         "authority-expired-2026-11-14")

    def test_prestaged_sharif_attp_refuses(self):
        with self.assertRaises(sa.StaleAuthorityError):
            sa.check_authority("draft-sharif-attp-01", _utc(2026, 12, 20))

    def test_naive_datetime_treated_as_utc(self):
        with self.assertRaises(sa.StaleAuthorityError):
            sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                               datetime(2026, 10, 14))

    def test_malformed_minted_at_refuses(self):
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            sa.check_authority("draft-emirdag-scitt-ai-agent-execution-00",
                               "yesterday")
        self.assertEqual(ctx.exception.code, "stale-authority-malformed")

    def test_empty_authority_refuses_malformed(self):
        with self.assertRaises(sa.StaleAuthorityError) as ctx:
            sa.check_authority("", _utc(2026, 10, 1))
        self.assertEqual(ctx.exception.code, "stale-authority-malformed")

    def test_lapse_registry_has_three_entries(self):
        self.assertEqual(len(sa.LAPSED_AUTHORITIES), 3)


class DelegationContainmentTest(unittest.TestCase):
    def test_parent_permit_refused_at_admission(self):
        with self.assertRaises(dcnt.ContainmentError) as ctx:
            dcnt.declare_permit("p1", bounds={"spend": 100},
                                parent_permit="p0")
        self.assertEqual(ctx.exception.code, "permit-parent-named")
        self.assertEqual(ctx.exception.step, "admission")
        self.assertIn("p0", ctx.exception.detail)

    def test_parentless_permit_admitted(self):
        permit = dcnt.declare_permit("p1", bounds={"spend": 100})
        self.assertTrue(permit["admitted"])
        self.assertIsNone(permit["parent_permit"])

    def test_empty_permit_id_refuses(self):
        with self.assertRaises(dcnt.ContainmentError) as ctx:
            dcnt.declare_permit("", bounds={"spend": 100})
        self.assertEqual(ctx.exception.code, "permit-containment-malformed")

    def test_currentness_unwired_is_could_not_check(self):
        verdict = dcnt.check_currentness()
        self.assertEqual(verdict["status"], "could-not-check")
        self.assertEqual(verdict["dependency"],
                         "policy-currentness-authority")
        self.assertEqual(verdict["code"],
                         "permit-currentness-could-not-check")

    def test_currentness_wired_is_still_could_not_check(self):
        verdict = dcnt.check_currentness(policy_authority={"name": "ops"})
        self.assertEqual(verdict["status"], "could-not-check")
        self.assertNotIn("verified", verdict["status"])

    def test_containment_violation_refuses_naming_key(self):
        with self.assertRaises(dcnt.ContainmentError) as ctx:
            dcnt.verify_containment(parent_bounds={"spend": 100},
                                    child_bounds={"spend": 101})
        self.assertEqual(ctx.exception.code,
                         "delegation-containment-violated")
        self.assertIn("spend", ctx.exception.detail)

    def test_containment_unknown_key_is_violation_under_strict(self):
        with self.assertRaises(dcnt.ContainmentError) as ctx:
            dcnt.verify_containment(parent_bounds={"spend": 100},
                                    child_bounds={"spend": 50,
                                                  "blast": 1})
        self.assertEqual(ctx.exception.code,
                         "delegation-containment-violated")
        self.assertIn("blast", ctx.exception.detail)

    def test_containment_within_parent_ok(self):
        verdict = dcnt.verify_containment(
            parent_bounds={"spend": 100, "depth": 3},
            child_bounds={"spend": 100, "depth": 3})
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["violated"], [])

    def test_malformed_bounds_refuse(self):
        with self.assertRaises(dcnt.ContainmentError) as ctx:
            dcnt.verify_containment(parent_bounds={"spend": "lots"},
                                    child_bounds={"spend": 1})
        self.assertEqual(ctx.exception.code, "permit-containment-malformed")


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in ("stale-authority", "stale-authority-malformed",
                     "permit-parent-named",
                     "permit-currentness-could-not-check",
                     "delegation-containment-violated",
                     "permit-containment-malformed"):
            rec = decision_codes.code_for(code)
            self.assertEqual(rec["code"], code)

    def test_pin(self):
        # Wave-242 merge: re-pointed to composed pin 788 (22 new codes:
        # 5 aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 2109) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
