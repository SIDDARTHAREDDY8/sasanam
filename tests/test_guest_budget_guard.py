"""Unit tests for gov.guest_budget_guard (wave-244 lane C, W244-3).

Pin the enforcement contract:
- envelope declared by the host; agent-supplied slack refused;
- amplification in any dimension terminates the guest (no re-budget);
- termination is sticky; exact-envelope use passes;
- per-guest scopes are isolated (no pooling);
- new refusal codes map in the taxonomy; pin 828 -> 832.
"""

import unittest

from gov import decision_codes as dc
from gov import guest_budget_guard as gb


class TestEnvelopeDeclaration(unittest.TestCase):
    def setUp(self):
        self.g = gb.BudgetLedger(now=lambda: 1000.0)

    def _declare(self, scope="g1", **kw):
        args = {"guest_scope": scope, "fuel_units": 100,
                "memory_bytes": 1 << 20, "wall_clock_seconds": 10}
        args.update(kw)
        return self.g.declare_envelope(**args)

    def test_declare_ok(self):
        st = self._declare()
        self.assertEqual(st["fuel_units"], 100.0)
        self.assertFalse(st["terminated"])

    def test_slack_kwarg_refused_malformed(self):
        # The accounting slack is a declared module constant; an
        # agent-supplied slack must be refused, never read.
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self._declare(slack={"fuel_units": 10 ** 9})
        self.assertEqual(ctx.exception.code,
                         "guest-budget-envelope-malformed")

    def test_bool_fuel_rejected(self):
        # The True == 1 trap: bool is not a number.
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self._declare(fuel_units=True)
        self.assertEqual(ctx.exception.code,
                         "guest-budget-envelope-malformed")

    def test_redeclaration_refused(self):
        self._declare()
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self._declare()
        self.assertEqual(ctx.exception.code,
                         "guest-budget-envelope-malformed")

    def test_undeclared_scope_refused(self):
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.report_consumption(guest_scope="nope", fuel_units=1,
                                      memory_bytes=1, elapsed_seconds=0.1)
        self.assertEqual(ctx.exception.code,
                         "guest-budget-scope-undeclared")


class TestNonAmplification(unittest.TestCase):
    def setUp(self):
        self.g = gb.BudgetLedger(now=lambda: 1000.0)
        self.g.declare_envelope(guest_scope="g1", fuel_units=100,
                                memory_bytes=1 << 20,
                                wall_clock_seconds=10)

    def test_fuel_amplification_terminates(self):
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.report_consumption(
                guest_scope="g1", fuel_units=150,
                memory_bytes=1 << 19, elapsed_seconds=1.0)
        self.assertEqual(ctx.exception.code, "guest-budget-amplified")
        self.assertTrue(self.g.state("g1")["terminated"])

    def test_termination_is_sticky(self):
        with self.assertRaises(gb.BudgetGuardError):
            self.g.report_consumption(
                guest_scope="g1", fuel_units=150,
                memory_bytes=1 << 19, elapsed_seconds=1.0)
        # Even a trivial later report and any effect commit refuse.
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.report_consumption(guest_scope="g1", fuel_units=0,
                                      memory_bytes=0, elapsed_seconds=0.1)
        self.assertEqual(ctx.exception.code, "guest-budget-amplified")
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.commit_effect(guest_scope="g1", effect={"op": "x"})
        self.assertEqual(ctx.exception.code, "guest-budget-amplified")

    def test_exact_envelope_passes(self):
        st = self.g.report_consumption(
            guest_scope="g1", fuel_units=100, memory_bytes=1 << 20,
            elapsed_seconds=10.0)
        self.assertFalse(st["terminated"])
        out = self.g.commit_effect(guest_scope="g1", effect={"op": "r"})
        self.assertTrue(out["committed"])

    def test_in_slack_passes(self):
        slack = gb.ACCOUNTING_SLACK
        st = self.g.report_consumption(
            guest_scope="g1", fuel_units=100 + slack["fuel_units"],
            memory_bytes=0, elapsed_seconds=1.0)
        self.assertFalse(st["terminated"])

    def test_deadline_fires(self):
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.check_deadline(guest_scope="g1", elapsed_seconds=30.0)
        self.assertEqual(ctx.exception.code,
                         "guest-budget-deadline-fired")
        self.assertTrue(self.g.state("g1")["terminated"])
        # In-flight effects are never committed after the deadline.
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.commit_effect(guest_scope="g1", effect={"op": "w"})
        self.assertEqual(ctx.exception.code, "guest-budget-amplified")

    def test_allocation_point_refusal(self):
        self.g.allocate(guest_scope="g1", memory_bytes=1 << 20)
        with self.assertRaises(gb.BudgetGuardError) as ctx:
            self.g.allocate(
                guest_scope="g1",
                memory_bytes=(1 << 20)
                + gb.ACCOUNTING_SLACK["memory_bytes"] + 1)
        self.assertEqual(ctx.exception.code, "guest-budget-amplified")
        self.assertTrue(self.g.state("g1")["terminated"])

    def test_zero_spend_report_ok(self):
        st = self.g.report_consumption(guest_scope="g1", fuel_units=0,
                                       memory_bytes=0, elapsed_seconds=0.1)
        self.assertFalse(st["terminated"])


class TestIsolation(unittest.TestCase):
    def test_no_pooling(self):
        g = gb.BudgetLedger(now=lambda: 1000.0)
        g.declare_envelope(guest_scope="a", fuel_units=50,
                           memory_bytes=1 << 20, wall_clock_seconds=60)
        g.declare_envelope(guest_scope="b", fuel_units=50,
                           memory_bytes=1 << 20, wall_clock_seconds=60)
        g.report_consumption(guest_scope="b", fuel_units=40,
                             memory_bytes=1, elapsed_seconds=1.0)
        with self.assertRaises(gb.BudgetGuardError):
            g.report_consumption(guest_scope="a", fuel_units=500,
                                 memory_bytes=1, elapsed_seconds=1.0)
        self.assertTrue(g.state("a")["terminated"])
        self.assertFalse(g.state("b")["terminated"])
        # B's aggregate carries only B's charges.
        self.assertEqual(
            g.state("b")["aggregate"]["aggregate_total"], 40.0)
        self.assertEqual(
            g.state("a")["aggregate"]["aggregate_total"], 0.0)

    def test_delta_charging_no_double_count(self):
        g = gb.BudgetLedger(now=lambda: 1000.0)
        g.declare_envelope(guest_scope="c", fuel_units=100,
                           memory_bytes=1 << 20, wall_clock_seconds=60)
        g.report_consumption(guest_scope="c", fuel_units=30,
                             memory_bytes=1, elapsed_seconds=1.0)
        g.report_consumption(guest_scope="c", fuel_units=60,
                             memory_bytes=1, elapsed_seconds=2.0)
        self.assertEqual(
            g.state("c")["aggregate"]["aggregate_total"], 60.0)


class TestTaxonomyPin(unittest.TestCase):
    def test_new_codes_mapped(self):
        # Wave-244 lane C (W244-3): 4 additive guest-budget codes.
        for code in ("guest-budget-amplified",
                     "guest-budget-envelope-malformed",
                     "guest-budget-deadline-fired",
                     "guest-budget-scope-undeclared"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.code_for(code)["code"], code)
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2035)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
