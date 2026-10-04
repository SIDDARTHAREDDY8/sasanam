"""Unit tests for gov/breach_boundary.py (W246-8) + taxonomy pin."""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import breach_boundary as bb
from gov import decision_codes


def _vouch(*identities):
    return {i: bb.VOUCHED for i in identities}


def _boundary():
    b = bb.BreachBoundary()
    b.declare_component("mem", bb.TRUST_ASSUMED_BREACHABLE)
    return b


def _verified(b, component="mem"):
    q = b.ingest(component, {"payload": "x"})
    return b.verify(q, {"verifier_id": "v1", "evidence": "ok"},
                    _vouch("v1"))


class DeclareTest(unittest.TestCase):
    def test_declare_happy_path(self):
        b = bb.BreachBoundary()
        d = b.declare_component("mem", bb.TRUST_ASSUMED_BREACHABLE,
                                budget=3, window=100)
        self.assertEqual(d["trust_class"], "assumed-breachable")
        self.assertEqual(d["budget"], 3)

    def test_unknown_trust_class_malformed(self):
        b = bb.BreachBoundary()
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.declare_component("x", "maybe-trusted")
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-record-malformed")

    def test_budget_without_window_malformed(self):
        b = bb.BreachBoundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.declare_component("x", bb.TRUST_GOVERNED, budget=5)

    def test_bool_budget_malformed(self):
        b = bb.BreachBoundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.declare_component("x", bb.TRUST_GOVERNED, budget=True,
                                window=10)

    def test_redeclare_refused(self):
        b = bb.BreachBoundary()
        b.declare_component("x", bb.TRUST_GOVERNED)
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.declare_component("x", bb.TRUST_GOVERNED)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-record-malformed")

    def test_empty_name_malformed(self):
        b = bb.BreachBoundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.declare_component("", bb.TRUST_GOVERNED)


class IngestTest(unittest.TestCase):
    def test_governed_passthrough(self):
        b = bb.BreachBoundary()
        b.declare_component("g", bb.TRUST_GOVERNED)
        v = b.ingest("g", {"a": 1})
        self.assertEqual(v["decision"], "passthrough")

    def test_assumed_breachable_quarantined(self):
        b = _boundary()
        q1 = b.ingest("mem", {"a": 1})
        q2 = b.ingest("mem", {"a": 2})
        self.assertEqual(q1["decision"], "quarantined")
        self.assertEqual(q1["code"], "breach-boundary-quarantined")
        self.assertEqual(q1["seq"], 1)
        self.assertEqual(q2["seq"], 2)
        self.assertFalse(q1["verified"])

    def test_external_untrusted_refused(self):
        b = bb.BreachBoundary()
        b.declare_component("e", bb.TRUST_EXTERNAL_UNTRUSTED)
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.ingest("e", {"a": 1})
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-external-untrusted")

    def test_unknown_component(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.ingest("ghost", {"a": 1})
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-unknown-component")

    def test_none_output_malformed(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.ingest("mem", None)


class VerifyUseTest(unittest.TestCase):
    def test_unverified_use_refused(self):
        b = _boundary()
        q = b.ingest("mem", {"a": 1})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(q)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-unverified-use-refused")

    def test_unvouched_verifier_refused(self):
        b = _boundary()
        q = b.ingest("mem", {"a": 1})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.verify(q, {"verifier_id": "agent-self", "evidence": "ok"},
                     _vouch("someone-else"))
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-verifier-unvouched")

    def test_verify_returns_new_record(self):
        b = _boundary()
        q = b.ingest("mem", {"a": 1})
        v = b.verify(q, {"verifier_id": "v1", "evidence": "ok"},
                     _vouch("v1"))
        self.assertFalse(q["verified"])
        self.assertTrue(v["verified"])
        self.assertEqual(v["verification"]["verifier_id"], "v1")

    def test_verified_use_allowed_but_marked(self):
        b = _boundary()
        v = _verified(b)
        verdict = b.use(v)
        self.assertEqual(verdict["decision"], "allow")
        self.assertEqual(verdict["code"], "breach-boundary-quarantined")
        self.assertIn("never silent", verdict["note"])
        self.assertEqual(verdict["output"], {"payload": "x"})

    def test_use_non_quarantine_dict_malformed(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use({"decision": "quarantined"})
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-record-malformed")

    def test_missing_verifier_id_malformed(self):
        b = _boundary()
        q = b.ingest("mem", {"a": 1})
        with self.assertRaises(bb.BreachBoundaryError):
            b.verify(q, {"evidence": "ok"}, _vouch("v1"))


class BudgetTest(unittest.TestCase):
    def test_spend_accounting_and_window_rollover(self):
        b = bb.BreachBoundary()
        b.declare_component("d", bb.TRUST_ASSUMED_BREACHABLE,
                            budget=2, window=100)
        self.assertEqual(b.spend("d", 0)["remaining"], 1)
        self.assertEqual(b.spend("d", 99)["remaining"], 0)
        # new window: budget resets
        self.assertEqual(b.spend("d", 100)["remaining"], 1)

    def test_overspend_trips_circuit(self):
        b = bb.BreachBoundary()
        b.declare_component("d", bb.TRUST_ASSUMED_BREACHABLE,
                            budget=1, window=100)
        b.spend("d", 0)
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.spend("d", 1)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-budget-exceeded")
        with self.assertRaises(bb.BreachBoundaryError) as ctx2:
            b.ingest("d", {"a": 1})
        self.assertEqual(ctx2.exception.code,
                         "breach-boundary-circuit-tripped")

    def test_no_budget_spend_recorded_only(self):
        b = _boundary()
        v = b.spend("mem", 5)
        self.assertEqual(v["decision"], "spend-recorded")
        self.assertIn("no budget", v["note"])

    def test_bad_tick_malformed(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.spend("mem", -1)
        with self.assertRaises(bb.BreachBoundaryError):
            b.spend("mem", True)


class CircuitTest(unittest.TestCase):
    def test_signal_trips_and_use_refused(self):
        b = _boundary()
        v = _verified(b)
        b.signal_breach("mem", {"signal": "s", "detail": "d"})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-circuit-tripped")

    def test_malformed_signal(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.signal_breach("mem", ["not", "a", "dict"])

    def test_self_reset_refused(self):
        b = _boundary()
        b.signal_breach("mem", {"signal": "s", "detail": "d"})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.reset("mem", {"reset_id": "mem"}, _vouch("other"))
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-reset-unvouched")

    def test_vouched_reset(self):
        b = _boundary()
        b.signal_breach("mem", {"signal": "s", "detail": "d"})
        r = b.reset("mem", {"reset_id": "r1"}, _vouch("r1"))
        self.assertTrue(r["was_tripped"])
        q = b.ingest("mem", {"a": 1})
        self.assertEqual(q["decision"], "quarantined")

    def test_reset_when_not_tripped_ok(self):
        b = _boundary()
        r = b.reset("mem", {"reset_id": "r1"}, _vouch("r1"))
        self.assertFalse(r["was_tripped"])


class CompromiseTest(unittest.TestCase):
    def test_mark_compromised_refuses_use(self):
        b = _boundary()
        v = _verified(b)
        b.mark_compromised("mem", {"reason": "CVE-2026-85706"})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.use(v)
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-compromised-source")

    def test_self_rotation_refused(self):
        b = _boundary()
        b.mark_compromised("mem", {"reason": "x"})
        with self.assertRaises(bb.BreachBoundaryError) as ctx:
            b.rotate("mem", {"rotation_id": "mem"}, _vouch("other"))
        self.assertEqual(ctx.exception.code,
                         "breach-boundary-rotation-unvouched")

    def test_vouched_rotation_restores(self):
        b = _boundary()
        v = _verified(b)
        b.mark_compromised("mem", {"reason": "x"})
        r = b.rotate("mem", {"rotation_id": "rot-1"}, _vouch("rot-1"))
        self.assertTrue(r["was_compromised"])
        self.assertEqual(b.use(v)["decision"], "allow")

    def test_compromise_is_per_component(self):
        b = bb.BreachBoundary()
        b.declare_component("a", bb.TRUST_ASSUMED_BREACHABLE)
        b.declare_component("c", bb.TRUST_ASSUMED_BREACHABLE)
        b.mark_compromised("a", {"reason": "x"})
        v = _verified(b, component="c")
        self.assertEqual(b.use(v)["decision"], "allow")
        b.rotate("a", {"rotation_id": "r"}, _vouch("r"))
        # rotating "a" never touched "c", and "c" was never compromised
        self.assertEqual(b.use(v)["decision"], "allow")

    def test_missing_reason_malformed(self):
        b = _boundary()
        with self.assertRaises(bb.BreachBoundaryError):
            b.mark_compromised("mem", {"noreason": 1})


class TaxonomyTest(unittest.TestCase):
    CODES = [
        "breach-boundary-record-malformed",
        "breach-boundary-unknown-component",
        "breach-boundary-unverified-use-refused",
        "breach-boundary-circuit-tripped",
        "breach-boundary-budget-exceeded",
        "breach-boundary-reset-unvouched",
        "breach-boundary-compromised-source",
        "breach-boundary-rotation-unvouched",
        "breach-boundary-external-untrusted",
        "breach-boundary-verifier-unvouched",
        "breach-boundary-quarantined",
        "breach-boundary-seal-invalid",
    ]

    def test_all_codes_mapped(self):
        for code in self.CODES:
            self.assertIn(code, decision_codes.TAXONOMY, code)
            entry = decision_codes.TAXONOMY[code]
            self.assertEqual(entry["code"], code)
            self.assertEqual(entry["domain"], "breach-boundary")

    def test_code_for_resolves(self):
        for code in self.CODES:
            self.assertEqual(decision_codes.code_for(code)["code"], code)

    def test_module_constants_match_taxonomy(self):
        consts = [getattr(bb, n) for n in dir(bb)
                  if n.startswith("BREACH_BOUNDARY_")]
        self.assertEqual(sorted(consts), sorted(self.CODES))

    def test_taxonomy_pin(self):
        # Wave-246 lane 8 (W246-8): 895 + 11 additive breach-boundary
        # codes, zero collisions, add-only.
        # Wave-246 merge: re-pointed lane-local pin to the composed 936 (was lane-local 906); additive only.
        # Wave-247 merge: re-pointed to the composed 938 (+2
        # uri-normalize codes); additive only.
        # Wave-248 lane 1 (F210 closure): 938 + 1 additive
        # breach-boundary-seal-invalid code; additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1946)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
