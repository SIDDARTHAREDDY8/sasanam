"""Unit tests for gov.agent_callbacks (wave-265 feature lane)."""

import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import agent_callbacks as ac
from gov import decision_codes


class TaxonomyPinTests(unittest.TestCase):
    def test_pin(self):
        # Wave-265 lane (callback seams): pin -> 1186 (1177 + 9
        # callback-*).
        self.assertEqual(len(decision_codes.TAXONOMY), 1869)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        for code in ac.CODES:
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_code_literals_unique(self):
        import re
        src = open("gov/decision_codes.py").read()
        lits = [a or b for a, b in
                re.findall(r'"code": \'([^\']+)\'|"code": "([^"]+)"',
                           src)]
        self.assertEqual(len(lits), 1869)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*)
        self.assertEqual(len(set(lits)), len(lits))


def _tool(tool_name, args):
    return {"ok": True, "tool": tool_name}


class VerdictTests(unittest.TestCase):
    def test_block_refuses_with_code(self):
        ex = ac.CallbackExecutor()
        with self.assertRaises(ac.CallbackError) as ctx:
            ex.execute(_tool, "t", {"a": 1},
                       before=(lambda t, a: ac.Block(),))
        self.assertEqual(ctx.exception.code, "callback-blocked")

    def test_rewrite_uses_new_args(self):
        ex = ac.CallbackExecutor()
        seen = []

        def spy(t, a):
            seen.append(dict(a))
            return _tool(t, a)

        ex.execute(spy, "t", {"a": 1},
                   before=(lambda t, a: ac.Rewrite({"a": 2}),))
        self.assertEqual(seen, [{"a": 2}])

    def test_rewrite_non_dict_refuses(self):
        ex = ac.CallbackExecutor()
        with self.assertRaises(ac.CallbackError) as ctx:
            ex.execute(_tool, "t", {"a": 1},
                       before=(lambda t, a: ac.Rewrite(["nope"]),))
        self.assertEqual(ctx.exception.code, "callback-malformed-verdict")

    def test_escalate_returns_paused_call(self):
        ex = ac.CallbackExecutor()
        ran = []

        def spy(t, a):
            ran.append(t)
            return _tool(t, a)

        out = ex.execute(spy, "t", {"a": 1},
                         before=(lambda t, a: ac.Escalate("x"),))
        self.assertIsInstance(out, ac.EscalatedCall)
        self.assertEqual(ran, [])
        self.assertEqual(out.tool_name, "t")

    def test_after_replaces_result(self):
        ex = ac.CallbackExecutor()
        out = ex.execute(_tool, "t", {"a": 1},
                         after=(lambda t, a, r: {"replaced": True},))
        self.assertEqual(out, {"replaced": True})

    def test_after_block_is_malformed(self):
        ex = ac.CallbackExecutor()
        with self.assertRaises(ac.CallbackError) as ctx:
            ex.execute(_tool, "t", {"a": 1},
                       after=(lambda t, a, r: ac.Block(),))
        self.assertEqual(ctx.exception.code, "callback-malformed-verdict")

    def test_on_error_suppresses(self):
        def failer(t, a):
            raise IOError("nope")

        ex = ac.CallbackExecutor()
        out = ex.execute(failer, "t", {"a": 1},
                         on_error=(lambda t, a, e: {"suppressed": True},))
        self.assertEqual(out, {"suppressed": True})

    def test_on_error_reraise_without_suppressor(self):
        def failer(t, a):
            raise IOError("nope")

        ex = ac.CallbackExecutor()
        with self.assertRaises(IOError):
            ex.execute(failer, "t", {"a": 1})

    def test_noncallable_registration_refuses(self):
        ex = ac.CallbackExecutor()
        with self.assertRaises(ac.CallbackError) as ctx:
            ex.add_before("not-a-callable")
        self.assertEqual(ctx.exception.code, "callback-malformed-verdict")


class FloorTests(unittest.TestCase):
    def test_enforcement_denial_skips_callbacks(self):
        consulted = []

        def deny(t, a):
            return (False, "scope-listing-denied")

        ex = ac.CallbackExecutor()

        def witness(t, a):
            consulted.append(t)
            return ac.Continue()

        with self.assertRaises(ac.CallbackError) as ctx:
            ex.execute(_tool, "t", {"a": 1}, enforcement=deny,
                       before=(witness,))
        self.assertEqual(ctx.exception.code, "scope-listing-denied")
        self.assertEqual(consulted, [])

    def test_enforcement_allows(self):
        ex = ac.CallbackExecutor()
        out = ex.execute(_tool, "t", {"a": 1},
                         enforcement=lambda t, a: (True, None))
        self.assertEqual(out, {"ok": True, "tool": "t"})

    def test_enforcement_bad_shape_faults(self):
        ex = ac.CallbackExecutor()
        with self.assertRaises(ac.CallbackError) as ctx:
            ex.execute(_tool, "t", {"a": 1},
                       enforcement=lambda t, a: "yes")
        self.assertEqual(ctx.exception.code, "callback-faulted")


class GateTests(unittest.TestCase):
    def test_request_resolve_approve(self):
        journal = []
        gate = ac.HumanApprovalGate(journal)
        aid = gate.request("payments.refund", {"amount": 500})
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["code"], "callback-approval-requested")
        self.assertNotIn("amount", json.dumps(journal[0]))
        verdict = gate.resolve(aid, True, decider="human-1")
        self.assertIsInstance(verdict, ac.Continue)
        self.assertEqual(journal[1]["state"], "approved")

    def test_resolve_unknown_refuses(self):
        gate = ac.HumanApprovalGate([])
        with self.assertRaises(ac.CallbackError) as ctx:
            gate.resolve("nope", True)
        self.assertEqual(ctx.exception.code, "callback-unknown-approval")

    def test_gate_requires_journal(self):
        with self.assertRaises(ac.CallbackError) as ctx:
            ac.HumanApprovalGate(None)
        self.assertEqual(ctx.exception.code, "callback-malformed-verdict")


if __name__ == "__main__":
    unittest.main()
