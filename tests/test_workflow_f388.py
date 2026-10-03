"""F388: composed _resolve_replay must never trust a foreign (digest, ref).

Red-first: p-style attack tests reproduce the amplification (poisoned pair
planted by an attacker who began+completed as one caller) and fail on the
pre-fix tree; the rest pin the fix contract and the no-regression control.

Public-seam coverage mirrors evals/w303_f387_probes.py; the direct-seam
tests pin the internal resolver's fail-closed contract.
"""
import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import decision_codes as dc
from gov import workflow_composed as wc
from gov import workflow as wf
from gov import workflow_saga as saga
from gov import workflow_idempotency as idem
from gov import delegation as dg
from gov import ed25519
from gov import delegation_revocation as rv

AT = 1_700_000_000
FOREIGN_CODE = "workflow-composed-replay-foreign"
PERMISSIVE = lambda **kw: True  # noqa: E731


def _seed(tag):
    return hashlib.sha256(("w304f388-" + tag).encode()).digest()


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
    return wc, ws, sm, im, comp, auth


def _fn_op_digest(plan, unit_name, inputs):
    # White-box: the exact op_digest construction in
    # WorkflowComposer._execute_fn_unit.
    return wc._digest({"plan": plan.digest, "op": "unit",
                       "unit": unit_name,
                       "inputs": wc._digest(inputs)})


def _plant(im, key, op_digest, result_digest, result_ref, caller="mallory"):
    plant = im.begin("composed", "composed-unit", key, op_digest,
                     caller=caller, authority_verifier=PERMISSIVE, at=AT)
    assert plant.status == "new", plant.status
    plant.complete(result_digest, result_ref, at=AT)


class F388ComposedReplayForeign(unittest.TestCase):
    def test_foreign_run_replay_refused_coded(self):
        """A1: foreign run's outputs must never return without executing."""
        _, ws, _, im, comp, auth = _scaffold()
        ws.start_run("probe", run_id="victim", authority=auth, at=AT)
        ws.run_step("victim", 1, "vstep", lambda i: {"stolen": 1}, {},
                    authority=auth, at=AT)
        victim_digest = wc._digest({"stolen": 1})
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": lambda i: {"real": 1},
             "inputs": {}, "idem_key": "ak"}])
        forged = _fn_op_digest(plan, "u", {})
        _plant(im, "ak", forged, victim_digest, "wfstep:victim:1")
        executed = []
        plan2 = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": lambda i: executed.append(1) or {"real": 1},
             "inputs": {}, "idem_key": "ak"}])
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        with self.assertRaises(wc.ComposedError) as ctx:
            comp.execute(plan2, run_id="R", authority=auth, at=AT)
        self.assertEqual(ctx.exception.code, FOREIGN_CODE)
        self.assertIn("victim", str(ctx.exception))
        self.assertEqual(executed, [])

    def test_same_run_ref_repoint_refused_coded(self):
        """A2: run binds but the record caller does not -> coded refusal."""
        _, ws, _, im, comp, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        plan1 = wc.ComposedPlan([
            {"kind": "fn", "name": "u1", "fn": lambda i: {"one": 1},
             "inputs": {}, "idem_key": "k1"}])
        comp.execute(plan1, run_id="R", authority=auth, at=AT)
        step_digest = wc._digest({"one": 1})
        plan2 = wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": lambda i: {"two": 2},
             "inputs": {}, "idem_key": "k2"}])
        forged = _fn_op_digest(plan2, "u2", {})
        _plant(im, "k2", forged, step_digest, "wfstep:R:1")
        with self.assertRaises(wc.ComposedError) as ctx:
            comp.execute(plan2, run_id="R", authority=auth, at=AT)
        self.assertEqual(ctx.exception.code, FOREIGN_CODE)

    def test_record_caller_mismatch_direct(self):
        """Direct seam: run matches ctx but record caller differs."""
        _, _, _, im, comp, _ = _scaffold()
        comp._exec_ctx = {"run_id": "run-x", "actor": "alice"}
        try:
            d = wc._digest({"op": "direct-caller"})
            out = im.begin("composed", "composed-unit", "k", d,
                           caller="mallory", authority_verifier=PERMISSIVE,
                           at=AT)
            out.complete(wc._digest({"out": 1}), "wfstep:run-x:1", at=AT)
            # complete() persists to the store; the replay outcome comes
            # from a second begin (status "replay").
            replay = im.begin("composed", "composed-unit", "k", d,
                              caller="mallory",
                              authority_verifier=PERMISSIVE, at=AT)
            assert replay.status == "replay", replay.status
            with self.assertRaises(wc.ComposedError) as ctx:
                # F390: expected_step_name required; F392: key required.
                # The caller check fires before either is used.
                comp._resolve_replay(replay, "composed-unit",
                                     "unreachable-key", "fn:direct-caller")
            self.assertEqual(ctx.exception.code, FOREIGN_CODE)
            self.assertIn("mallory", str(ctx.exception))
        finally:
            comp._exec_ctx = None

    def test_detached_resolution_refused_coded(self):
        """Direct seam: no composed execution in progress -> fail closed."""
        _, _, _, im, comp, _ = _scaffold()
        self.assertIsNone(comp._exec_ctx)
        d = wc._digest({"op": "direct-detached"})
        out = im.begin("composed", "composed-unit", "k", d,
                       caller="mallory", authority_verifier=PERMISSIVE,
                       at=AT)
        out.complete(wc._digest({"out": 1}), "wfstep:run-q:1", at=AT)
        replay = im.begin("composed", "composed-unit", "k", d,
                          caller="mallory", authority_verifier=PERMISSIVE,
                          at=AT)
        assert replay.status == "replay", replay.status
        with self.assertRaises(wc.ComposedError) as ctx:
            # F390: expected_step_name required; F392: key required.
            # The detached check fires before either is used.
            comp._resolve_replay(replay, "composed-unit",
                                     "unreachable-key", "fn:detached")
        self.assertEqual(ctx.exception.code, FOREIGN_CODE)

    def test_legit_replay_still_resolves(self):
        """C1: no-regression -- same-run native replay executes once."""
        _, ws, _, _, comp, auth = _scaffold()
        ws.start_run("probe", run_id="R", authority=auth, at=AT)
        calls = []
        plan = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": lambda i: calls.append(1) or {"v": 7},
             "inputs": {}, "idem_key": "k"}])
        res1 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        res2 = comp.execute(plan, run_id="R", authority=auth, at=AT)
        self.assertEqual(len(calls), 1)
        self.assertEqual(res2["units"]["u"]["outputs"], {"v": 7})
        self.assertEqual(res1["units"]["u"]["outputs"],
                         res2["units"]["u"]["outputs"])

    def test_record_caller_property(self):
        """BeginOutcome exposes the begin-time record caller (F387)."""
        _, _, _, im, _, _ = _scaffold()
        d = wc._digest({"op": "record-caller"})
        out = im.begin("composed", "composed-unit", "k", d,
                       caller="mallory", authority_verifier=PERMISSIVE,
                       at=AT)
        self.assertEqual(out.record_caller, "mallory")

    def test_replay_foreign_code_registered(self):
        """New code registered once, sorted, severity critical."""
        codes = [e["code"] for e in dc.TAXONOMY.values()]
        self.assertEqual(codes.count(FOREIGN_CODE), 1)
        self.assertEqual(dc.TAXONOMY[FOREIGN_CODE]["severity"], "critical")
        i = codes.index(FOREIGN_CODE)
        self.assertLess(codes[i - 1], FOREIGN_CODE)
        self.assertGreater(codes[i + 1], FOREIGN_CODE)


if __name__ == "__main__":
    unittest.main()
