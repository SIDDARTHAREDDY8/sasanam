"""Unit tests for the F384 operator recovery path in gov/workflow_saga.py.

Red-first: these tests were written against the close-when criteria
(resolve_escalation / retry_compensation that re-drive the failed
compensation after the underlying cause is fixed, coded refusals on
bad operator authority, journaled recovery, safe double-recovery).
"""

import json
import os
import unittest

from gov import workflow_saga as saga


def _escalated(tag, maxc=1, op_ref="op", op_ok=True):
    saga.clear_ops()
    saga.register_op("t-a-%s" % tag, lambda p: ({"ok": 1}, []))

    def _bad(p):
        raise RuntimeError("downstream still down")

    saga.register_op("t-c-%s" % tag, _bad)
    saga.register_op("t-f-%s" % tag, lambda p: 1 / 0)
    mgr = saga.SagaManager(
        authority_verifiers={"op": lambda: op_ok} if op_ref else {},
        max_compensation_attempts=maxc,
        operator_authority_ref=op_ref)
    d = mgr.define([
        saga.SagaStepDef("s1", "t-a-%s" % tag, {}, "t-c-%s" % tag, {}),
        saga.SagaStepDef("s2", "t-f-%s" % tag, {}, "t-c-%s" % tag, {}),
    ])
    inst = mgr.start(d, saga_id="t-%s" % tag)
    try:
        mgr.run(inst)
    except saga.SagaError:
        pass
    assert inst.status == "escalated"
    return mgr, inst


def _assert_code(test, fn, code):
    with test.assertRaises(saga.SagaError) as ctx:
        fn()
    test.assertEqual(ctx.exception.code, code)


class RecoveryApiTests(unittest.TestCase):
    def test_api_methods_exist(self):
        for meth in ("describe_escalation", "resolve_escalation",
                     "retry_compensation"):
            self.assertTrue(callable(getattr(saga.SagaManager, meth, None)),
                            "SagaManager.%s missing" % meth)

    def test_new_codes_registered(self):
        from gov import decision_codes
        self.assertIn("workflow-saga-operator-unauthorized",
                      decision_codes.TAXONOMY)
        self.assertIn("workflow-saga-resolution-invalid",
                      decision_codes.TAXONOMY)


class DescribeTests(unittest.TestCase):
    def test_describe_escalation_summary(self):
        mgr, inst = _escalated("d1")
        desc = mgr.describe_escalation(inst)
        self.assertEqual(desc["status"], "escalated")
        self.assertEqual(desc["escalation_code"],
                         "workflow-saga-compensation-failed")
        self.assertEqual([s["step_id"] for s in desc["outstanding_steps"]],
                         ["s1"])
        json.dumps(desc)  # operator-tool consumable

    def test_describe_non_escalated_refuses(self):
        mgr, inst = _escalated("d2")
        saga.register_op("t-c-d2", lambda p: None)
        mgr.retry_compensation(inst)
        _assert_code(self, lambda: mgr.describe_escalation(inst),
                     "workflow-saga-resolution-invalid")


class RetryTests(unittest.TestCase):
    def test_retry_recovers_and_journals(self):
        mgr, inst = _escalated("r1")
        saga.register_op("t-c-r1", lambda p: None)
        mgr.retry_compensation(inst)
        self.assertEqual(inst.status, "compensated")
        types = [e["type"] for e in inst.history]
        self.assertIn("escalation_recovery_started", types)
        self.assertIn("escalation_resolved", types)

    def test_retry_resets_attempt_window(self):
        mgr, inst = _escalated("r2", maxc=1)
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(st["comp_attempts"], 1)
        saga.register_op("t-c-r2", lambda p: None)
        mgr.retry_compensation(inst)
        # Fresh window: attempts were reset before the successful retry.
        self.assertEqual(inst.status, "compensated")

    def test_retry_forged_operator_refuses(self):
        mgr, inst = _escalated("r3", op_ok=False)
        _assert_code(self, lambda: mgr.retry_compensation(inst),
                     "workflow-saga-operator-unauthorized")
        self.assertEqual(inst.status, "escalated")

    def test_retry_missing_operator_ref_refuses(self):
        mgr, inst = _escalated("r4", op_ref=None)
        _assert_code(self, lambda: mgr.retry_compensation(inst),
                     "workflow-saga-operator-unauthorized")

    def test_retry_still_broken_reescalates(self):
        mgr, inst = _escalated("r5")
        _assert_code(self, lambda: mgr.retry_compensation(inst),
                     "workflow-saga-compensation-failed")
        self.assertEqual(inst.status, "escalated")

    def test_double_recovery_refuses(self):
        mgr, inst = _escalated("r6")
        saga.register_op("t-c-r6", lambda p: None)
        mgr.retry_compensation(inst)
        _assert_code(self, lambda: mgr.retry_compensation(inst),
                     "workflow-saga-resolution-invalid")
        self.assertEqual(inst.status, "compensated")

    def test_recovered_saga_run_resume_noop(self):
        mgr, inst = _escalated("r7")
        saga.register_op("t-c-r7", lambda p: None)
        mgr.retry_compensation(inst)
        mgr.run(inst)
        mgr.resume(inst)
        self.assertEqual(inst.status, "compensated")


class AbortTests(unittest.TestCase):
    def test_abort_keeps_attempt_budget(self):
        mgr, inst = _escalated("a1", maxc=2)
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        before = st["comp_attempts"]
        saga.register_op("t-c-a1", lambda p: None)
        mgr.resolve_escalation(inst, {"action": "abort_and_compensate_all"})
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(st["comp_attempts"], before)

    def test_unknown_action_refuses(self):
        mgr, inst = _escalated("a2")
        _assert_code(
            self,
            lambda: mgr.resolve_escalation(inst, {"action": "self_destruct"}),
            "workflow-saga-resolution-invalid")


class ManualRemediationTests(unittest.TestCase):
    def test_manual_remediation(self):
        mgr, inst = _escalated("m1")
        mgr.resolve_escalation(inst, {
            "action": "accept_manual_remediation", "step_ids": ["s1"]})
        st = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(st["state"], "compensated")
        self.assertTrue(st.get("manual_remediation"))
        # Round-trips dump/load.
        inst2 = mgr.load(json.loads(json.dumps(mgr.dump(inst))))
        st2 = [s for s in inst2.steps if s["step_id"] == "s1"][0]
        self.assertTrue(st2.get("manual_remediation"))

    def test_incomplete_attestation_refuses(self):
        mgr, inst = _escalated("m2")
        _assert_code(
            self,
            lambda: mgr.resolve_escalation(inst, {
                "action": "accept_manual_remediation", "step_ids": []}),
            "workflow-saga-resolution-invalid")
        self.assertEqual(inst.status, "escalated")

    def test_resolve_non_escalated_refuses(self):
        mgr, inst = _escalated("m3")
        saga.register_op("t-c-m3", lambda p: None)
        mgr.retry_compensation(inst)
        _assert_code(
            self,
            lambda: mgr.resolve_escalation(
                inst, {"action": "retry_compensation"}),
            "workflow-saga-resolution-invalid")


if __name__ == "__main__":
    unittest.main()
