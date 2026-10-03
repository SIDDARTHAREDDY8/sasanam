"""Unit tests for F393: composed idempotency identity binds the unit's
code, and the run binds to the first plan digest.

F393 (MEDIUM, wave-308 lane D): ComposedPlan.digest covered kind/name/
idem_key/inputs_digest but NOT the fn callable, so a descriptor-
identical evil plan (same kind, name, idem_key, inputs; different fn)
yielded a bit-identical op_digest. The victim's _begin_unit returned
REPLAY on the attacker's record and _resolve_replay passed every check
(run, record-caller, digest, F390 step name, F392 idempotency binding)
-- the victim's fn never executed and the attacker's outputs returned
as native. Verified on the fn path and the saga action path.

The fix (wave-309 lane A) has two parts, matching the close-when's
first direction (extended):
1. Code identity in the digest: ComposedPlan.digest now includes a
   per-unit code_digest -- a fingerprint of the fn's code object
   (bytecode, constants incl. nested code objects, names, argcounts,
   flags; line numbers and filenames excluded) plus JSON-native
   closed-over values bound by value. Callables without __code__
   (builtins, functools.partial) refuse
   workflow-composed-definition-invalid at plan construction.
2. Run->plan-digest binding: WorkflowStore.bind_plan_digest records
   the first plan digest executed under a run (journal-appended as a
   "run_plan" record, so it survives crash-recovery). A different plan
   digest under the same run refuses coded
   workflow-composed-plan-mismatch. A refused execute never clobbers
   the binding; same-plan re-execution still replays.

New decision code: workflow-composed-plan-mismatch (pin 1828 -> 1829).
"""
import functools
import hashlib
import os
import sys
import tempfile
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
PLAN_MISMATCH = "workflow-composed-plan-mismatch"


def _seed(tag):
    return hashlib.sha256(("ut-f393-" + tag).encode()).digest()


def _scaffold(journal_path=None):
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
    ws = wf.WorkflowStore(path=journal_path)
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return comp, ws, sm, im, auth


class F393CodeDigestTest(unittest.TestCase):
    def test_descriptor_identical_plans_differ_by_code(self):
        _scaffold()
        evil = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": lambda i: {"evil": 1},
             "inputs": {}, "idem_key": "k"}])
        victim = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": lambda i: {"real": 1},
             "inputs": {}, "idem_key": "k"}])
        self.assertNotEqual(evil.digest, victim.digest)

    def test_identical_source_rebuilds_same_digest(self):
        _scaffold()
        src = "lambda i: {'v': 1}"
        pa = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": eval(src),
             "inputs": {}, "idem_key": "k"}])
        pb = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": eval(src),
             "inputs": {}, "idem_key": "k"}])
        self.assertEqual(pa.digest, pb.digest)

    def test_closure_value_bound_by_value(self):
        _scaffold()

        def make(threshold):
            def fn(i):
                return {"over": i.get("x", 0) > threshold}
            return fn

        pa = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": make(5),
             "inputs": {}, "idem_key": "k"}])
        pb = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": make(10),
             "inputs": {}, "idem_key": "k"}])
        self.assertNotEqual(pa.digest, pb.digest)

    def test_uninspectable_fn_refused_at_construction(self):
        _scaffold()
        for bad_fn in (len, functools.partial(lambda i, x: x, x=1)):
            with self.assertRaises(Exception) as ctx:
                wc.ComposedPlan([
                    {"kind": "fn", "name": "u", "fn": bad_fn,
                     "inputs": {}, "idem_key": "k"}])
            self.assertEqual(
                getattr(ctx.exception, "code", None),
                "workflow-composed-definition-invalid")


class F393RunPlanBindingTest(unittest.TestCase):
    def test_different_plan_under_same_run_refused_coded(self):
        comp, ws, sm, im, auth = _scaffold()
        plan_a = wc.ComposedPlan([
            {"kind": "fn", "name": "ua", "fn": lambda i: {"a": 1},
             "inputs": {}, "idem_key": "ka"}])
        comp.execute(plan_a, run_id="R", authority=auth, at=AT)
        executed = []
        plan_b = wc.ComposedPlan([
            {"kind": "fn", "name": "ub",
             "fn": lambda i: executed.append(1) or {"b": 2},
             "inputs": {}, "idem_key": "kb"}])
        with self.assertRaises(Exception) as ctx:
            comp.execute(plan_b, run_id="R", authority=auth, at=AT)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         PLAN_MISMATCH)
        self.assertEqual(executed, [])

    def test_same_plan_replays_without_refusal(self):
        comp, ws, sm, im, auth = _scaffold()
        calls = []

        def fn(i):
            calls.append(1)
            return {"v": 1}

        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": fn,
             "inputs": {}, "idem_key": "k"}])
        r1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        self.assertEqual(len(calls), 1)
        self.assertEqual(r2["units"]["u"]["outputs"],
                         r1["units"]["u"]["outputs"])

    def test_refused_execute_does_not_clobber_binding(self):
        comp, ws, sm, im, auth = _scaffold()
        calls = []

        def fn(i):
            calls.append(1)
            return {"v": 1}

        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": fn,
             "inputs": {}, "idem_key": "k"}])
        comp.execute(plan, run_id="R", authority=auth, at=AT)
        evil = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": lambda i: {"evil": 1},
             "inputs": {}, "idem_key": "k"}])
        with self.assertRaises(Exception) as ctx:
            comp.execute(evil, run_id="R", authority=auth, at=AT)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         PLAN_MISMATCH)
        r2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        self.assertEqual(len(calls), 1)
        self.assertEqual(r2["units"]["u"]["outputs"], {"v": 1})

    def test_binding_survives_journal_reload(self):
        journal = tempfile.NamedTemporaryFile(
            prefix="ut-f393-", suffix=".jsonl", delete=False).name
        comp, ws, sm, im, auth = _scaffold(journal_path=journal)
        ws2 = wf.WorkflowStore(path=journal)
        ws2.start_run("probe", run_id="R", authority=auth, at=AT)
        comp2 = wc.WorkflowComposer(ws2, saga.SagaManager(), im)
        plan_a = wc.ComposedPlan([
            {"kind": "fn", "name": "ua", "fn": lambda i: {"a": 1},
             "inputs": {}, "idem_key": "ka"}])
        comp2.execute(plan_a, run_id="R", authority=auth, at=AT)
        # Reload from the journal: the binding must survive.
        ws3 = wf.WorkflowStore(path=journal)
        self.assertEqual(
            ws3.bind_plan_digest("R", plan_a.digest, authority=auth,
                                 at=AT),
            plan_a.digest)
        plan_b = wc.ComposedPlan([
            {"kind": "fn", "name": "ub", "fn": lambda i: {"b": 2},
             "inputs": {}, "idem_key": "kb"}])
        comp3 = wc.WorkflowComposer(ws3, saga.SagaManager(),
                                    idem.IdempotencyStore(
                                        backing=im._backing))
        with self.assertRaises(Exception) as ctx:
            comp3.execute(plan_b, run_id="R", authority=auth, at=AT)
        self.assertEqual(getattr(ctx.exception, "code", None),
                         PLAN_MISMATCH)

    def test_first_execute_binds_fresh_run(self):
        comp, ws, sm, im, auth = _scaffold()
        ws.start_run("probe", run_id="R2", authority=auth, at=AT)
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": lambda i: {"v": 1},
             "inputs": {}, "idem_key": "k"}])
        comp.execute(plan, run_id="R2", authority=auth, at=AT)
        self.assertEqual(
            ws.bind_plan_digest("R2", plan.digest, authority=auth,
                                at=AT),
            plan.digest)


if __name__ == "__main__":
    unittest.main()
