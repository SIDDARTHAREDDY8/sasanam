"""Unit tests for F392: _resolve_replay idempotency-binding check.

F392 (MEDIUM, wave-307 lane A): the F390 fix bound _resolve_replay's
expected_step_name to the replaying unit, but step names are unique per
(plan, unit) -- not per run. execute() takes a caller-provided run_id
and never binds a run to a single plan, so a second plan executed under
the same run can record the SAME step name for a different unit's work.
A poisoned (digest, ref) pair naming the attacker's same-named step then
passes every F388/F390 check (run, caller, completion, digest, name) and
returns the wrong unit's outputs without executing it.

The fix binds the workflow step to the exact idempotency record that
created it: the step records the (namespace, op_class, key) triple as
its idempotency_key (via _step_binding), and _resolve_replay refuses
coded workflow-composed-replay-foreign when the resolved step's binding
does not match the replaying record's key. No new decision codes
(pin 1827+0).
"""
import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import workflow as wf
from gov import workflow_saga as saga
from gov import workflow_idempotency as idem
from gov import workflow_composed as wc
from gov import delegation as dg
from gov import ed25519
from gov import delegation_revocation as rv

AT = 1_700_000_000
FOREIGN_CODE = "workflow-composed-replay-foreign"


def _seed(tag):
    return hashlib.sha256(("ut-f392-" + tag).encode()).digest()


def _scaffold():
    sa, sb = _seed("a"), _seed("b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    return comp, ws, im, auth


def _fn_op_digest(plan, unit_name, inputs):
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


class F392StepBindingTest(unittest.TestCase):
    def test_same_name_different_plan_refused_coded(self):
        # A1 (the F392 attack): two plans under one run, both with a
        # unit named "u2". The attacker's plan records fn:u2 at seq 1;
        # the victim's key is then planted with (digest, "wfstep:R:1").
        # Every F388/F390 check passes (run, caller, completion, digest,
        # name) -- only the binding check refuses, coded.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        evil = wc.ComposedPlan([
            {"kind": "fn", "name": "u2",
             "fn": lambda i: {"evil": 1},
             "inputs": {}, "idem_key": "ke"}])
        comp.execute(evil, run_id="R", authority=auth, at=AT)
        victim = wc.ComposedPlan([
            {"kind": "fn", "name": "u2",
             "fn": lambda i: {"real": 2},
             "inputs": {}, "idem_key": "k2"}])
        plant = im.begin("composed", "composed-unit", "k2",
                         _fn_op_digest(victim, "u2", {}),
                         caller="agent-b",
                         authority_verifier=lambda **k: True, at=AT)
        self.assertEqual(plant.status, "new")
        plant.complete(wc._digest({"evil": 1}), "wfstep:R:1", at=AT)
        with self.assertRaises(wc.ComposedError) as cm:
            comp.execute(victim, run_id="R", authority=auth, at=AT)
        self.assertEqual(cm.exception.code, FOREIGN_CODE)
        self.assertIn("binding", str(cm.exception))

    def test_step_records_binding(self):
        # The recorded step carries the idempotency binding of the
        # record that created it.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": lambda i: {"real": 1},
             "inputs": {}, "idem_key": "k1"}])
        comp.execute(plan, run_id="R", authority=auth, at=AT)
        step = ws._steps[("R", 1)]
        self.assertEqual(step["name"], "fn:u")
        self.assertEqual(
            step["idempotency_key"],
            comp._step_binding(wc._OP_UNIT, "k1"))

    def test_same_plan_replay_still_resolves(self):
        # C1: no-regression -- the same plan re-executed under the same
        # run replays the unit's OWN outputs without re-running.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        calls = []
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": lambda i: calls.append(1) or {"real": 1},
             "inputs": {}, "idem_key": "ak"}])
        r1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        self.assertEqual(len(calls), 1)
        self.assertEqual(r2["units"]["u"]["outputs"], {"real": 1})
        self.assertTrue(r2["units"]["u"].get("replayed"))

    def test_crash_before_complete_replays_without_rerun(self):
        # C2: a step recorded (with binding) but whose idem record is
        # still in-flight (crash before _complete_unit) replays via the
        # binding -- no duplicate execution.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        calls = []
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": lambda i: calls.append(1) or {"real": 1},
             "inputs": {}, "idem_key": "ak"}])
        comp.execute(plan, run_id="R", authority=auth, at=AT)
        # Simulate a crash: the idem record is completed, so instead
        # reset it to in-flight by re-beginning with the same digest --
        # begin() returns "retry" for an in-flight record with a
        # matching digest.
        im2 = idem.IdempotencyStore()
        comp2 = wc.WorkflowComposer(ws, saga.SagaManager(), im2)
        out = im2.begin("composed", "composed-unit", "ak",
                        _fn_op_digest(plan, "u", {}),
                        caller="agent-b",
                        authority_verifier=lambda **k: True, at=AT)
        self.assertEqual(out.status, "new")
        seq = comp2._next_seq()
        outputs, replayed = comp2._wstore.run_step(
            "R", seq, "fn:u", plan.units[0]["fn"], {},
            idempotency_key=comp2._step_binding(wc._OP_UNIT, "ak"),
            authority=auth, at=AT)
        self.assertTrue(replayed)
        self.assertEqual(outputs, {"real": 1})
        self.assertEqual(len(calls), 1)

    def test_binding_uses_nul_separators(self):
        # The binding format must not be ambiguous when a key contains
        # ":" -- the NUL separators keep the triple's fields distinct.
        comp, ws, im, auth = _scaffold()
        b1 = comp._step_binding("op", "a:b")
        b2 = comp._step_binding("op:a", "b")
        self.assertNotEqual(b1, b2)
        self.assertEqual(b1, "composed\x00op\x00a:b")
        self.assertEqual(b2, "composed\x00op:a\x00b")


if __name__ == "__main__":
    unittest.main()
