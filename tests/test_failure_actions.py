#!/usr/bin/env python3
"""Unit tests for gov/failure_actions.py + the evidence_quality wiring
(wave-261 lane 2: failure-action correction pipeline).

Stdlib + gov only. Deterministic.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc  # noqa: E402
from gov import evidence_quality as eq  # noqa: E402
from gov import failure_actions as fa  # noqa: E402


def _fr(code="evidence-quality-malformed", action="exception",
        detail="unit failure", diagnostics=None):
    return fa.FailResult(code=code, action=action, detail=detail,
                         diagnostics=diagnostics)


class VocabularyTest(unittest.TestCase):
    def test_eight_members(self):
        self.assertEqual(
            sorted([fa.OnFailAction.REASK, fa.OnFailAction.FIX,
                    fa.OnFailAction.FIX_REASK, fa.OnFailAction.FILTER,
                    fa.OnFailAction.REFRAIN, fa.OnFailAction.NOOP,
                    fa.OnFailAction.EXCEPTION, fa.OnFailAction.CUSTOM]),
            ["custom", "exception", "filter", "fix", "fix_reask",
             "noop", "reask", "refrain"])

    def test_is_known_action(self):
        for name in ("reask", "fix", "fix_reask", "filter", "refrain",
                     "noop", "exception", "custom"):
            self.assertTrue(fa.is_known_action(name), name)
        for bad in ("", "FILTER", "teleport", None, 42, b"filter"):
            self.assertFalse(fa.is_known_action(bad), repr(bad))

    def test_default_is_exception(self):
        self.assertEqual(fa.DEFAULT_ACTION, "exception")


class FailResultTest(unittest.TestCase):
    def test_shape_validation(self):
        with self.assertRaises(TypeError):
            fa.FailResult("", "exception")
        with self.assertRaises(TypeError):
            fa.FailResult("code", "")
        with self.assertRaises(TypeError):
            fa.FailResult("code", "exception", detail=42)
        with self.assertRaises(TypeError):
            fa.FailResult("code", "exception", diagnostics=[1])

    def test_diagnostics_copied(self):
        diag = {"field_path": "[1]"}
        fr = fa.FailResult("c", "filter", diagnostics=diag)
        diag["field_path"] = "[9]"
        self.assertEqual(fr.diagnostics, {"field_path": "[1]"})

    def test_unknown_action_name_allowed_at_construction(self):
        # Membership is enforced by apply_action (fail-closed there),
        # not at construction: the FailResult is inert data.
        fr = fa.FailResult("c", "teleport")
        self.assertEqual(fr.action, "teleport")


class ApplyActionContractTest(unittest.TestCase):
    def test_rejects_non_failresult(self):
        with self.assertRaises(TypeError):
            fa.apply_action("not-a-failresult")
        with self.assertRaises(TypeError):
            fa.apply_action(None)

    def test_rejects_non_dict_context(self):
        with self.assertRaises(TypeError):
            fa.apply_action(_fr(), context=[1])

    def test_unknown_action_raises_with_original_code(self):
        fr = _fr(code="evidence-quality-evidence-malformed",
                 action="teleport")
        with self.assertRaises(fa.FailureActionError) as ctx:
            fa.apply_action(fr, {})
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-evidence-malformed")
        self.assertIs(ctx.exception.fail_result, fr)

    def test_exception_action_raises_machine_coded(self):
        fr = _fr(code="evidence-quality-empty-evidence",
                 action="exception", detail="vacuous")
        with self.assertRaises(fa.FailureActionError) as ctx:
            fa.apply_action(fr, {})
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-empty-evidence")
        self.assertIn("evidence-quality-empty-evidence",
                      str(ctx.exception))
        self.assertIs(ctx.exception.fail_result, fr)


class NoopRefrainTest(unittest.TestCase):
    def test_noop_continues_and_records(self):
        journal = []
        out = fa.apply_action(_fr(action="noop"), {"journal": journal})
        self.assertEqual(out["disposition"], "continued")
        self.assertEqual(out["action"], "noop")
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["action"], "noop")
        self.assertEqual(journal[0]["disposition"], "continued")
        self.assertIn("recorded_at", journal[0])

    def test_noop_without_journal_still_continues(self):
        out = fa.apply_action(_fr(action="noop"), {})
        self.assertEqual(out["disposition"], "continued")
        self.assertFalse(out["payload"]["recorded"])

    def test_refrain_stops_step(self):
        journal = []
        out = fa.apply_action(
            _fr(code="evidence-quality-gate-failed", action="refrain"),
            {"journal": journal})
        self.assertEqual(out["disposition"], "refrained")
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["disposition"], "refrained")

    def test_journal_not_a_list_is_ignored(self):
        out = fa.apply_action(_fr(action="noop"),
                              {"journal": "not-a-list"})
        self.assertEqual(out["disposition"], "continued")


class AgenticActionTest(unittest.TestCase):
    def test_requests_are_structured_and_recorded(self):
        for action in ("reask", "fix", "fix_reask"):
            journal = []
            data = {"evidence": [{"seq": 1}]}
            snapshot = copy.deepcopy(data)
            fr = _fr(action=action, detail="needs work",
                     diagnostics={"field_path": "[0]"})
            out = fa.apply_action(
                fr, {"value": data, "journal": journal,
                     "constraints": {"max_attempts": 2}})
            self.assertEqual(out["disposition"], "requested")
            req = out["payload"]
            self.assertEqual(req["type"], "action-request")
            self.assertEqual(req["action"], action)
            self.assertEqual(req["code"], "evidence-quality-malformed")
            self.assertEqual(req["diagnostics"],
                             {"field_path": "[0]"})
            self.assertEqual(req["constraints"], {"max_attempts": 2})
            # never auto-repairs caller data
            self.assertEqual(data, snapshot)
            self.assertEqual(len(journal), 1)
            self.assertEqual(journal[0]["disposition"], "requested")


class FilterActionTest(unittest.TestCase):
    def test_exact_redaction(self):
        value = [{"seq": 1}, {"seq": "bad"}, {"seq": 3}]
        snapshot = copy.deepcopy(value)
        out = fa.apply_action(
            _fr(code="evidence-quality-evidence-malformed",
                action="filter", diagnostics={"field_path": "[1]"}),
            {"value": value})
        self.assertEqual(out["disposition"], "continued")
        self.assertEqual(out["payload"]["value"],
                         [{"seq": 1}, {"seq": 3}])
        self.assertEqual(out["payload"]["redacted_path"], "[1]")
        self.assertEqual(value, snapshot)  # caller unmutated

    def test_nested_path(self):
        value = {"items": [{"ok": 1}, {"bad": True}], "n": 2}
        out = fa.apply_action(
            _fr(action="filter",
                diagnostics={"field_path": "items[1].bad"}),
            {"value": value})
        self.assertEqual(out["payload"]["value"],
                         {"items": [{"ok": 1}, {}], "n": 2})

    def test_missing_field_path_fails_closed(self):
        with self.assertRaises(fa.FailureActionError):
            fa.apply_action(_fr(action="filter", diagnostics={}),
                            {"value": [1]})

    def test_missing_value_fails_closed(self):
        with self.assertRaises(fa.FailureActionError):
            fa.apply_action(
                _fr(action="filter",
                    diagnostics={"field_path": "[0]"}), {})

    def test_malformed_path_fails_closed(self):
        for bad in ("evidence[", "[x]", "a..b", "", "[1", ".."):
            with self.assertRaises(fa.FailureActionError,
                                   msg=bad):
                fa.apply_action(
                    _fr(action="filter",
                        diagnostics={"field_path": bad}),
                    {"value": [{"a": 1}]})

    def test_unresolvable_path_fails_closed(self):
        with self.assertRaises(fa.FailureActionError):
            fa.apply_action(
                _fr(action="filter",
                    diagnostics={"field_path": "[7]"}),
                {"value": [{"a": 1}]})
        with self.assertRaises(fa.FailureActionError):
            fa.apply_action(
                _fr(action="filter",
                    diagnostics={"field_path": "missing[0]"}),
                {"value": [{"a": 1}]})

    def test_tuple_path_fails_closed(self):
        with self.assertRaises(fa.FailureActionError):
            fa.apply_action(
                _fr(action="filter",
                    diagnostics={"field_path": "[0]"}),
                {"value": ({"a": 1},)})

    def test_aliased_bypass_refuses(self):
        bad = {"marker": "OFFENDING"}
        value = [{"seq": 1}, bad, {"alias": bad}]
        with self.assertRaises(fa.FailureActionError) as ctx:
            fa.apply_action(
                _fr(code="evidence-quality-evidence-malformed",
                    action="filter",
                    diagnostics={"field_path": "[1]"}),
                {"value": value})
        self.assertIn("bypass", str(ctx.exception))

    def test_cyclic_value_does_not_hang(self):
        value = [{"seq": 1}]
        value.append(value)  # cycle: the sweep must be id()-safe
        out = fa.apply_action(
            _fr(action="filter",
                diagnostics={"field_path": "[0]"}),
            {"value": value})
        self.assertEqual(out["disposition"], "continued")
        self.assertEqual(len(out["payload"]["value"]), 1)


class CustomActionTest(unittest.TestCase):
    def test_handler_result_passed_through(self):
        journal = []
        out = fa.apply_action(
            _fr(action="custom"),
            {"handler": lambda fr, ctx: {"escalated": True},
             "journal": journal})
        self.assertEqual(out["disposition"], "custom")
        self.assertEqual(out["payload"], {"escalated": True})
        self.assertEqual(journal[0]["action"], "custom")

    def test_missing_handler_fails_closed(self):
        with self.assertRaises(fa.FailureActionError) as ctx:
            fa.apply_action(_fr(action="custom"), {})
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-malformed")

    def test_raising_handler_fails_closed(self):
        def _raiser(fr, ctx):
            raise RuntimeError("boom")

        with self.assertRaises(fa.FailureActionError) as ctx:
            fa.apply_action(_fr(action="custom"),
                            {"handler": _raiser})
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-malformed")
        self.assertIn("RuntimeError", str(ctx.exception))

    def test_base_exception_propagates_raw(self):
        def _kbd(fr, ctx):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            fa.apply_action(_fr(action="custom"), {"handler": _kbd})


class EvidenceQualitySeamTest(unittest.TestCase):
    _EXP = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]

    def test_malformed_item_carries_filter(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.evaluate(self._EXP, [{"seq": 1}, "nope"])
        exc = ctx.exception
        self.assertEqual(exc.code,
                         "evidence-quality-evidence-malformed")
        self.assertIsNotNone(exc.fail_result)
        self.assertEqual(exc.fail_result.action, "filter")
        self.assertEqual(exc.fail_result.diagnostics["field_path"],
                         "[1]")

    def test_whole_shape_violation_prescribes_exception(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.evaluate(self._EXP, "not-a-list")
        self.assertEqual(ctx.exception.fail_result.action,
                         "exception")

    def test_empty_evidence_prescribes_exception(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.evaluate(self._EXP, [])
        exc = ctx.exception
        self.assertEqual(exc.code, "evidence-quality-empty-evidence")
        self.assertEqual(exc.fail_result.action, "exception")

    def test_gate_failed_prescribes_refrain(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.emit_with_quality_gate(
                "s", "json", self._EXP, [{"seq": 2}, {"seq": 1}])
        exc = ctx.exception
        self.assertEqual(exc.code, "evidence-quality-gate-failed")
        self.assertEqual(exc.fail_result.action, "refrain")
        self.assertIn("expect_evidence_monotonic",
                      exc.fail_result.diagnostics["failed_expectations"])

    def test_evaluate_with_action_opt_in(self):
        report, fr = eq.evaluate_with_action(self._EXP, [])
        self.assertIsNone(report)
        self.assertEqual(fr.code, "evidence-quality-empty-evidence")
        self.assertEqual(fr.action, "exception")
        good = [{"seq": 1}, {"seq": 2}]
        report2, fr2 = eq.evaluate_with_action(self._EXP, good)
        self.assertIsNone(fr2)
        self.assertTrue(report2["success"])

    def test_default_evaluate_still_raises(self):
        with self.assertRaises(eq.EvidenceQualityError):
            eq.evaluate(self._EXP, [])

    def test_end_to_end_filter(self):
        evidence = [{"seq": 1}, "nope", {"seq": 3}]
        try:
            eq.evaluate(self._EXP, evidence)
            self.fail("should have refused")
        except eq.EvidenceQualityError as exc:
            fr = exc.fail_result
        out = fa.apply_action(fr, {"value": evidence})
        self.assertEqual(out["payload"]["value"],
                         [{"seq": 1}, {"seq": 3}])

    def test_taxonomy_pin_unchanged(self):
        # Wave-261 lane 2 adds no decision codes: failures re-raise
        # the FailResult's own machine code.
        self.assertEqual(len(dc.TAXONOMY), 2124) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)


if __name__ == "__main__":
    unittest.main()
