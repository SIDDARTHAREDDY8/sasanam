"""Unit tests for gov/provenance_nonupgrade.py (W239-7, AER-1).

Behavior-level tests at the public seams. Every refusal path asserts
its named decision code; positive paths assert the class is preserved,
never upgraded.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import provenance_nonupgrade as pn  # noqa: E402


class EmissionTests(unittest.TestCase):
    def test_missing_class_refuses(self):
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.emit_receipt(None, {"a": 1})
        self.assertEqual(cm.exception.code, "provenance-class-missing")

    def test_empty_class_refuses(self):
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.emit_receipt("", {"a": 1})
        self.assertEqual(cm.exception.code, "provenance-class-missing")

    def test_unknown_class_refuses_case_exact(self):
        for bad in ("OBSERVED", "executed", "Logged ", "EXECUTED "):
            with self.assertRaises(pn.ProvenanceError) as cm:
                pn.emit_receipt(bad, {"a": 1})
            self.assertEqual(cm.exception.code, "provenance-class-unknown")

    def test_emit_logged_roundtrip(self):
        r = pn.emit_receipt("LOGGED", {"action": "transfer"})
        self.assertEqual(r["provenance"], "LOGGED")
        self.assertIn("receipt_digest", r)
        # Deterministic: same bytes -> same digest.
        r2 = pn.emit_receipt("LOGGED", {"action": "transfer"})
        self.assertEqual(r["receipt_digest"], r2["receipt_digest"])


class VerificationTests(unittest.TestCase):
    def test_verified_report_keeps_class(self):
        r = pn.emit_receipt("LOGGED", {"x": 1})
        v = pn.verify_receipt(r)
        self.assertEqual(v["provenance"], "LOGGED")
        self.assertEqual(v["verdict"], "verified-report")

    def test_verified_observation_keeps_class(self):
        r = pn.emit_receipt("EXECUTED", {"x": 1})
        v = pn.verify_receipt(r)
        self.assertEqual(v["provenance"], "EXECUTED")
        self.assertEqual(v["verdict"], "verified-observation")

    def test_tamper_refuses(self):
        r = pn.emit_receipt("EXECUTED", {"x": 1})
        bad = dict(r)
        bad["fields"] = {"x": 999}
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.verify_receipt(bad)
        self.assertEqual(cm.exception.code, "provenance-digest-mismatch")

    def test_malformed_refuses_closed(self):
        with self.assertRaises(pn.ProvenanceError):
            pn.verify_receipt({"not": "a receipt"})


class PresentationTests(unittest.TestCase):
    def test_render_labels_every_field(self):
        r = pn.emit_receipt("LOGGED", {"a": 1, "b": 2})
        rendered = pn.render(r)
        for field, value in r["fields"].items():
            self.assertEqual(rendered[field]["provenance"], "LOGGED")
            self.assertEqual(rendered[field]["value"], value)

    def test_present_logged_as_executed_refuses(self):
        r = pn.emit_receipt("LOGGED", {"a": 1})
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.present_with_authority(r, "EXECUTED")
        self.assertEqual(cm.exception.code, "provenance-upgraded")

    def test_present_executed_as_executed_ok(self):
        r = pn.emit_receipt("EXECUTED", {"a": 1})
        out = pn.present_with_authority(r, "EXECUTED")
        self.assertEqual(out["presented"], "EXECUTED")

    def test_present_executed_as_logged_ok_downward(self):
        # Downward presentation (observation read as mere report) is
        # conformant: the rule only forbids upgrades.
        r = pn.emit_receipt("EXECUTED", {"a": 1})
        out = pn.present_with_authority(r, "LOGGED")
        self.assertEqual(out["presented"], "LOGGED")

    def test_unknown_authority_refuses(self):
        r = pn.emit_receipt("LOGGED", {"a": 1})
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.present_with_authority(r, "OBSERVED")
        self.assertEqual(cm.exception.code, "provenance-class-unknown")


class ChainTests(unittest.TestCase):
    def test_chained_logged_stays_report(self):
        a = pn.emit_receipt("LOGGED", {"step": "plan"})
        b = pn.emit_receipt("LOGGED", {"step": "apply"})
        verdicts = pn.verify_chain(pn.chain_receipts([a, b]))
        self.assertEqual([v["verdict"] for v in verdicts],
                         ["chained-report", "chained-report"])
        self.assertEqual([v["provenance"] for v in verdicts],
                         ["LOGGED", "LOGGED"])

    def test_chained_executed_stays_observation(self):
        a = pn.emit_receipt("EXECUTED", {"step": "run"})
        verdicts = pn.verify_chain(pn.chain_receipts([a]))
        self.assertEqual(verdicts[0]["verdict"], "chained-observation")

    def test_chain_tamper_refuses(self):
        a = pn.emit_receipt("LOGGED", {"step": "plan"})
        entries = pn.chain_receipts([a])
        entries[0]["receipt_digest"] = "0" * 64
        with self.assertRaises(pn.ProvenanceError):
            pn.verify_chain(entries)


class MerkleTests(unittest.TestCase):
    def _steps(self, cls="EXECUTED", n=3):
        return [pn.emit_receipt(cls, {"n": i}) for i in range(n)]

    def test_commit_and_verify(self):
        steps = self._steps()
        commitment = pn.commit_workflow(steps)
        verdicts = pn.verify_steps(steps, commitment)
        self.assertEqual(len(verdicts), 3)
        self.assertTrue(all(v["verdict"] == "step-verified"
                            for v in verdicts))

    def test_deletion_names_index(self):
        steps = self._steps()
        commitment = pn.commit_workflow(steps)
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.verify_steps([steps[0], steps[2]], commitment)
        self.assertEqual(cm.exception.code, "provenance-step-break")
        self.assertIn("index 1", str(cm.exception))

    def test_reorder_names_index(self):
        steps = self._steps(n=2)
        commitment = pn.commit_workflow(steps)
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.verify_steps([steps[1], steps[0]], commitment)
        self.assertEqual(cm.exception.code, "provenance-step-break")
        self.assertIn("index 0", str(cm.exception))

    def test_bare_root_still_detects(self):
        steps = self._steps()
        root = pn.merkle_root([s["receipt_digest"] for s in steps])
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.verify_steps([steps[2], steps[0], steps[1]], root)
        self.assertEqual(cm.exception.code, "provenance-step-break")
        # Clean presented sequence against bare root verifies.
        out = pn.verify_steps(steps, root)
        self.assertEqual(len(out), 3)

    def test_empty_workflow_refuses(self):
        with self.assertRaises(pn.ProvenanceError) as cm:
            pn.merkle_root([])
        self.assertEqual(cm.exception.code, "provenance-step-break")


class TaxonomyTests(unittest.TestCase):
    def test_codes_mapped(self):
        from gov import decision_codes as dc
        for code in ("provenance-class-missing",
                     "provenance-class-unknown",
                     "provenance-upgraded",
                     "provenance-chain-class-mismatch",
                     "provenance-digest-mismatch",
                     "provenance-step-break"):
            self.assertIsNotNone(dc.code_for(code), code)
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
        self.assertEqual(len(dc.TAXONOMY), 1769)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
