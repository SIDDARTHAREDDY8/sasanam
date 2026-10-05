"""Unit tests for gov/workflow_saga.py (wave-301 lane 4).

Saga orchestration: forward steps with declared compensations,
reverse-order rollback, transactional outbox, authority re-verification
at compensation time. Every coded refusal is asserted by code.
"""

import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import unittest

from gov import decision_codes
from gov import workflow_saga as ws

PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


class CrashSim(BaseException):
    pass


class WorkflowSagaTests(unittest.TestCase):
    def setUp(self):
        self.log = []
        # Fresh registry per test: the module registry is process-global.
        ws.clear_ops()
        ws.register_op("ok", self._ok)
        ws.register_op("fail", self._fail_op)
        ws.register_op("comp", self._comp)
        self.mgr = ws.SagaManager()

    def _ok(self, params):
        self.log.append("a:" + params["sid"])
        return ({"ok": True}, [{"body": "m:" + params["sid"]}])

    def _fail_op(self, params):
        self.log.append("a:" + params["sid"])
        raise RuntimeError("boom")

    def _comp(self, params):
        self.log.append("c:" + params["sid"])
        return {"compensated": True}

    def _step(self, sid, action="ok", comp="comp", **kw):
        d = {"step_id": sid, "action_op": action,
             "action_params": {"sid": sid},
             "compensation_op": comp,
             "compensation_params": {"sid": sid}}
        d.update(kw)
        return d

    def _code(self, fn, *a, **kw):
        try:
            fn(*a, **kw)
        except ws.SagaError as e:
            return e.code
        self.fail("expected SagaError, none raised")

    # -- definition ----------------------------------------------------
    def test_define_valid(self):
        d = self.mgr.define([self._step("s1"), self._step("s2")])
        self.assertEqual(len(d.steps), 2)
        self.assertEqual(len(d.digest), 64)

    def test_define_rejects_missing_compensation(self):
        bad = dict(self._step("s1"))
        bad["compensation_op"] = ""
        self.assertEqual(self._code(self.mgr.define, [bad]),
                         "workflow-saga-definition-invalid")

    def test_define_rejects_empty_and_duplicates(self):
        self.assertEqual(self._code(self.mgr.define, []),
                         "workflow-saga-definition-invalid")
        self.assertEqual(self._code(self.mgr.define,
                                   [self._step("s1"), self._step("s1")]),
                         "workflow-saga-definition-invalid")

    def test_define_rejects_unserializable_params(self):
        bad = self._step("s1")
        bad["action_params"] = {"x": object()}
        self.assertEqual(self._code(self.mgr.define, [bad]),
                         "workflow-saga-definition-invalid")

    # -- forward -------------------------------------------------------
    def test_happy_path(self):
        inst = self.mgr.start(self.mgr.define([self._step("s1"),
                                               self._step("s2")]))
        self.mgr.run(inst)
        self.assertEqual(inst.status, "succeeded")
        self.assertEqual([s["state"] for s in inst.steps],
                         ["succeeded", "succeeded"])
        n = self.mgr.drain_outbox(inst, lambda i: None)
        self.assertEqual(n, 2)

    def test_unknown_action_op_fails_step_and_compensates(self):
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1"), self._step("s2", action="nope")]))
        self.mgr.run(inst)
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(self.log, ["a:s1", "c:s1"])

    def test_run_is_idempotent_on_terminal_success(self):
        inst = self.mgr.start(self.mgr.define([self._step("s1")]))
        self.mgr.run(inst)
        self.mgr.run(inst)
        self.assertEqual(self.log.count("a:s1"), 1)

    # -- compensation --------------------------------------------------
    def test_compensation_reverse_order(self):
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1"), self._step("s2"),
             self._step("s3", action="fail")]))
        self.mgr.run(inst)
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(self.log[-2:], ["c:s2", "c:s1"])

    def test_compensation_failure_escalates_coded(self):
        ws.register_op("comp_boom", lambda p: (_ for _ in ()).throw(
            RuntimeError("nope")))
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1", comp="comp_boom"),
             self._step("s2", action="fail")]))
        code = self._code(self.mgr.run, inst)
        self.assertEqual(code, "workflow-saga-compensation-failed")
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(inst.escalation_code,
                         "workflow-saga-compensation-failed")

    def test_unregistered_compensation_op_escalates_immediately(self):
        # Declared but unresolvable in this process: no doomed retries,
        # immediate escalation under the compensation-failed code.
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1", comp="ghost_comp"),
             self._step("s2", action="fail")]))
        code = self._code(self.mgr.run, inst)
        self.assertEqual(code, "workflow-saga-compensation-failed")
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(self.log, ["a:s1", "a:s2"])  # no comp attempts
        types = [e["type"] for e in inst.history]
        self.assertIn("compensation_failed", types)

    def test_escalated_refuses_run_and_resume(self):
        ws.register_op("comp_boom", lambda p: (_ for _ in ()).throw(
            RuntimeError("nope")))
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1", comp="comp_boom"),
             self._step("s2", action="fail")]))
        try:
            self.mgr.run(inst)
        except ws.SagaError:
            pass
        self.assertEqual(self._code(self.mgr.run, inst),
                         "workflow-saga-compensation-failed")
        self.assertEqual(self._code(self.mgr.resume, inst),
                         "workflow-saga-compensation-failed")

    # -- authority -----------------------------------------------------
    def test_compensation_reverifies_authority(self):
        # Verifier passes the forward check, then is revoked before the
        # compensation runs: the compensation must refuse loudly.
        calls = {"n": 0}

        def verifier():
            calls["n"] += 1
            return calls["n"] == 1

        mgr = ws.SagaManager(authority_verifiers={"a1": verifier})
        inst = mgr.start(mgr.define(
            [self._step("s1", authority_ref="a1"),
             self._step("s2", action="fail")]))
        code = self._code(mgr.run, inst)
        self.assertEqual(code, "workflow-saga-compensation-unauthorized")
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(calls["n"], 2)  # forward ok, compensation refused

    def test_unknown_authority_ref_fails_step_loudly(self):
        # Unknown authority on the forward path: the step fails recorded
        # ('authority-revoked-forward'); with nothing completed, the saga
        # compensates vacuously.
        mgr = ws.SagaManager(authority_verifiers={})
        inst = mgr.start(mgr.define(
            [self._step("s1", authority_ref="ghost"),
             self._step("s2", action="fail")]))
        mgr.run(inst)
        s1 = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(s1["state"], "failed")
        self.assertEqual(s1["error"], "authority-revoked-forward")
        self.assertEqual(inst.status, "compensated")

    def test_healthy_authority_compensates_cleanly(self):
        mgr = ws.SagaManager(authority_verifiers={"a1": lambda: True})
        inst = mgr.start(mgr.define(
            [self._step("s1", authority_ref="a1"),
             self._step("s2", action="fail")]))
        mgr.run(inst)
        self.assertEqual(inst.status, "compensated")

    # -- crash / resume ------------------------------------------------
    def test_crash_resume_marks_interrupted_and_compensates(self):
        ws.register_op("crash", lambda p: (_ for _ in ()).throw(CrashSim()))
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1"), self._step("s2", action="crash")]))
        with self.assertRaises(CrashSim):
            self.mgr.run(inst)
        snap = json.loads(json.dumps(self.mgr.dump(inst)))
        inst2 = ws.SagaManager().load(snap)
        self.mgr.resume(inst2)
        self.assertEqual(inst2.status, "compensated")
        self.assertEqual(self.log.count("a:s1"), 1)  # not re-executed
        types = [e["type"] for e in inst2.history]
        self.assertIn("step_interrupted", types)

    def test_dump_load_roundtrip(self):
        inst = self.mgr.start(self.mgr.define([self._step("s1")]))
        self.mgr.run(inst)
        d = json.loads(json.dumps(self.mgr.dump(inst)))
        inst2 = self.mgr.load(d)
        self.assertEqual(inst2.saga_id, inst.saga_id)
        self.assertEqual(inst2.status, "succeeded")
        self.assertEqual(len(inst2.history), len(inst.history))

    def test_load_rejects_malformed(self):
        with self.assertRaises(ValueError):
            self.mgr.load({"nope": True})

    # -- outbox --------------------------------------------------------
    def test_outbox_exactly_once_records(self):
        inst = self.mgr.start(self.mgr.define([self._step("s1")]))
        self.mgr.run(inst)
        got = []
        self.assertEqual(self.mgr.drain_outbox(inst, got.append), 1)
        self.assertEqual(self.mgr.drain_outbox(inst, got.append), 0)
        self.assertEqual(len(got), 1)

    def test_outbox_uncommitted_step_never_dispatches(self):
        ws.register_op("crash", lambda p: (_ for _ in ()).throw(CrashSim()))
        inst = self.mgr.start(self.mgr.define(
            [self._step("s1", action="crash")]))
        with self.assertRaises(CrashSim):
            self.mgr.run(inst)
        got = []
        # The crashed step never committed: nothing to dispatch.
        self.assertEqual(self.mgr.drain_outbox(inst, got.append), 0)

    # -- taxonomy ------------------------------------------------------
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), PIN)

    def test_new_codes_registered(self):
        for code in ("workflow-saga-definition-invalid",
                     "workflow-saga-compensation-failed",
                     "workflow-saga-compensation-unauthorized"):
            entry = decision_codes.TAXONOMY[code]
            self.assertEqual(entry["code"], code)
            self.assertEqual(entry["domain"], "workflow_saga")
            self.assertEqual(entry["severity"], "high")


if __name__ == "__main__":
    unittest.main(verbosity=1)
