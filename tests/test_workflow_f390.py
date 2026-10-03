"""Unit tests for F390: _resolve_replay step-name binding.

F390 (MEDIUM, wave-306 lane B): the F388-hardened _resolve_replay bound
the idempotency pair to run + caller + completion + digest, but not the
ref's step to the replaying unit. A plant under the victim's key naming
a different completed step of the same run returned the wrong unit's
outputs. The fix passes the expected step name into _resolve_replay and
refuses coded workflow-composed-replay-foreign on mismatch.
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
    return hashlib.sha256(("ut-f390-" + tag).encode()).digest()


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


class F390StepNameBindingTest(unittest.TestCase):
    def test_wrong_step_ref_refused_coded(self):
        # A plant under u2's key naming u1's completed step (same run,
        # same caller, valid digest) must refuse coded.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        plan1 = wc.ComposedPlan([
            {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
             "inputs": {}, "idem_key": "k1"}])
        comp.execute(plan1, run_id="R", authority=auth, at=AT)
        plan2 = wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
             "inputs": {}, "idem_key": "k2"}])
        plant = im.begin("composed", "composed-unit", "k2",
                         _fn_op_digest(plan2, "u2", {}),
                         caller="agent-b",
                         authority_verifier=lambda **k: True, at=AT)
        self.assertEqual(plant.status, "new")
        plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
        with self.assertRaises(Exception) as cm:
            comp.execute(plan2, run_id="R", authority=auth, at=AT)
        self.assertEqual(getattr(cm.exception, "code", None), FOREIGN_CODE)

    def test_legitimate_replay_still_works(self):
        # The same plan re-executed under the same run must replay the
        # unit's OWN outputs without re-running.
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

    def test_expected_step_name_propagated(self):
        # Direct unit check: _resolve_replay with a mismatched expected
        # name refuses even when all F388 checks pass.
        comp, ws, im, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
             "inputs": {}, "idem_key": "k1"}])
        comp.execute(plan, run_id="R", authority=auth, at=AT)
        # Simulate an in-progress composed execution.
        comp._exec_ctx = {"run_id": "R", "actor": "agent-b",
                          "plan_digest": plan.digest, "at": AT}
        try:
            plant = im.begin("composed", "composed-unit", "k9",
                             _fn_op_digest(plan, "u1", {}),
                             caller="agent-b",
                             authority_verifier=lambda **k: True, at=AT)
            plant.complete(wc._digest({"one": 1}), "wfstep:R:1", at=AT)
            replay = im.begin("composed", "composed-unit", "k9",
                              _fn_op_digest(plan, "u1", {}),
                              caller="agent-b",
                              authority_verifier=lambda **k: True, at=AT)
            self.assertEqual(replay.status, "replay")
            with self.assertRaises(Exception) as cm:
                comp._resolve_replay(replay, "composed-unit",
                                     "unreachable-key", "fn:some-other-unit")
            self.assertEqual(getattr(cm.exception, "code", None),
                             FOREIGN_CODE)
            # F392: the correct name alone is NOT enough. The step was
            # recorded by the composer's execution under idem key "k1";
            # this plant is under "k9", so the binding check refuses
            # even with the right name.
            with self.assertRaises(Exception) as cm2:
                comp._resolve_replay(replay, "composed-unit",
                                     "k9", "fn:u1")
            self.assertEqual(getattr(cm2.exception, "code", None),
                             FOREIGN_CODE)
            self.assertIn("binding", str(cm2.exception))
        finally:
            comp._exec_ctx = None


if __name__ == "__main__":
    unittest.main()
