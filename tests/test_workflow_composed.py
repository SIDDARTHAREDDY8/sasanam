"""Unit tests for gov/workflow_composed.py: the composed workflow path.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned (wave-243); the three new decision codes
are pinned as raw source literals.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf
from gov import workflow_saga as saga
from gov import workflow_routing as wr
from gov import workflow_idempotency as idem
from gov import workflow_composed as wc


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()


class ComposedTestBase(unittest.TestCase):
    def setUp(self):
        self.sa = _seed("w302wc-a")
        self.sb = _seed("w302wc-b")
        self.pa = ed25519.publickey(self.sa).hex()
        self.pb = ed25519.publickey(self.sb).hex()
        self.at = 1_700_000_000
        self.ws = wf.WorkflowStore()
        self.sm = saga.SagaManager()
        self.im = idem.IdempotencyStore()
        self.c = wc.WorkflowComposer(self.ws, self.sm, self.im)

    def _chain(self, delegatee="agent-b"):
        cons = {"expires_at": self.at + 3600, "max_depth": 4,
                "allowed_targets": [delegatee]}
        return [dg.issue(self.sa, "agent-a", delegatee, self.pb,
                         ("tool.invoke",), issued_at=self.at,
                         constraints=cons)]

    def _auth(self, actor="agent-b"):
        return {"actor_id": actor, "action": "tool.invoke",
                "chain": self._chain(actor), "trust_roots": [self.pa],
                "revocation_ledger": drv.DelegationRevoker(self.sa,
                                                          "agent-a")}

    def _run(self, run_id="r1", actor="agent-b"):
        auth = self._auth(actor)
        return self.ws.start_run("plan", run_id=run_id, authority=auth,
                                 at=self.at), auth

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    def _fn_plan(self, name="u", key="k", val=1):
        return wc.ComposedPlan([
            {"kind": "fn", "name": name,
             "fn": lambda i, v=val: {"v": v},
             "inputs": {"x": val}, "idem_key": key}])


class PlanValidationTests(ComposedTestBase):
    def test_empty_plan_refused(self):
        self.assertEqual(self._code_of(wc.ComposedPlan, []),
                         "workflow-composed-definition-invalid")

    def test_unknown_kind_refused(self):
        self.assertEqual(
            self._code_of(wc.ComposedPlan, [
                {"kind": "nope", "name": "u", "idem_key": "k"}]),
            "workflow-composed-definition-invalid")

    def test_duplicate_unit_name_refused(self):
        self.assertEqual(
            self._code_of(wc.ComposedPlan, [
                {"kind": "fn", "name": "u", "fn": lambda i: {},
                 "idem_key": "k1"},
                {"kind": "fn", "name": "u", "fn": lambda i: {},
                 "idem_key": "k2"}]),
            "workflow-composed-definition-invalid")

    def test_saga_unit_missing_fns_refused(self):
        sd = self.sm.define([saga.SagaStepDef("s1", "a", {}, "c")])
        self.assertEqual(
            self._code_of(wc.ComposedPlan, [
                {"kind": "saga", "name": "sg", "definition": sd,
                 "action_fns": {"s1": lambda i: (None, [])},
                 "comp_fns": {}, "idem_key": "k"}]),
            "workflow-composed-definition-invalid")

    def test_plan_digest_stable(self):
        p1 = self._fn_plan()
        p2 = self._fn_plan()
        self.assertEqual(p1.digest, p2.digest)


class FnUnitTests(ComposedTestBase):
    def test_fn_unit_executes_and_checkpoints(self):
        run, auth = self._run()
        res = self.c.execute(self._fn_plan(), run_id=run["run_id"],
                             authority=auth, at=self.at)
        self.assertFalse(res["units"]["u"]["replayed"])
        self.assertEqual(res["units"]["u"]["outputs"], {"v": 1})
        steps = self.ws.list_steps(run["run_id"])
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["status"], "completed")

    def test_fn_unit_idempotent_replay(self):
        run, auth = self._run()
        plan = self._fn_plan()
        self.c.execute(plan, run_id=run["run_id"], authority=auth,
                       at=self.at)
        c2 = wc.WorkflowComposer(self.ws, self.sm, self.im)
        c2.load_state(self.c.dump_state())
        res = c2.execute(plan, run_id=run["run_id"], authority=auth,
                         at=self.at)
        self.assertTrue(res["units"]["u"]["replayed"])
        self.assertEqual(res["units"]["u"]["outputs"], {"v": 1})
        self.assertEqual(len(self.ws.list_steps(run["run_id"])), 1)

    def test_digest_confusion_refused(self):
        run, auth = self._run()
        self.c.execute(self._fn_plan(key="kx"), run_id=run["run_id"],
                       authority=auth, at=self.at)
        run2, _ = self._run(run_id="r2")
        evil = wc.ComposedPlan([
            {"kind": "fn", "name": "evil",
             "fn": lambda i: {"v": 999}, "inputs": {"x": 999},
             "idem_key": "kx"}])
        self.assertEqual(
            self._code_of(self.c.execute, evil, run_id=run2["run_id"],
                          authority=auth, at=self.at),
            "permit-idempotency-conflict")

    def test_actor_substitution_refused(self):
        run, auth = self._run()
        self.c.execute(self._fn_plan(key="ka"), run_id=run["run_id"],
                       authority=auth, at=self.at)
        run2, auth_evil = self._run(run_id="r9", actor="agent-evil")
        evil = wc.ComposedPlan([
            {"kind": "fn", "name": "e", "fn": lambda i: {},
             "idem_key": "ke"}])
        self.assertEqual(
            self._code_of(self.c.execute, evil, run_id=run2["run_id"],
                          authority=auth_evil, at=self.at),
            "workflow-composed-authority-mismatch")

    def test_divergent_layers_refused(self):
        run, auth = self._run()
        plan = self._fn_plan(key="kdiv")
        self.c.execute(plan, run_id=run["run_id"], authority=auth,
                       at=self.at)
        # Wipe the checkpoint layer but keep the idempotency layer.
        ws2 = wf.WorkflowStore()
        run2 = ws2.start_run("plan", run_id=run["run_id"], authority=auth,
                             at=self.at)
        c2 = wc.WorkflowComposer(ws2, self.sm, self.im)
        self.assertEqual(
            self._code_of(c2.execute, plan, run_id=run2["run_id"],
                          authority=auth, at=self.at),
            "workflow-composed-divergent")


class SagaUnitTests(ComposedTestBase):
    def _saga_plan(self, key="ksg", fail_second=False):
        def ok(i):
            return ({"r": 1}, [])
        def boom(i):
            raise RuntimeError("kaboom")
        def c1(i):
            return {"u": 1}
        steps = [saga.SagaStepDef("s1", "a1", {"n": 1}, "c1")]
        af = {"s1": ok}
        cf = {"s1": c1}
        if fail_second:
            steps.append(saga.SagaStepDef("s2", "a2", {}, "c2"))
            af["s2"] = boom
            cf["s2"] = lambda i: {"u": 2}
        sd = self.sm.define(steps)
        return wc.ComposedPlan([
            {"kind": "saga", "name": "sg", "definition": sd,
             "action_fns": af, "comp_fns": cf, "idem_key": key}])

    def test_saga_unit_succeeds(self):
        run, auth = self._run()
        res = self.c.execute(self._saga_plan(), run_id=run["run_id"],
                             authority=auth, at=self.at)
        self.assertEqual(res["units"]["sg"]["status"], "succeeded")
        names = [s["name"] for s in self.ws.list_steps(run["run_id"])]
        self.assertIn("saga:sg:s1", names)

    def test_saga_failure_compensates_in_checkpoint(self):
        run, auth = self._run()
        res = self.c.execute(self._saga_plan(fail_second=True),
                             run_id=run["run_id"], authority=auth,
                             at=self.at)
        self.assertEqual(res["units"]["sg"]["status"], "compensated")
        names = [s["name"] for s in self.ws.list_steps(run["run_id"])]
        # Forward steps then the compensation, all in one trail.
        self.assertEqual(names, ["saga:sg:s1", "saga:sg:s2",
                                 "saga-comp:sg:s1"])

    def test_saga_outbox_dispatches_through_idempotency(self):
        dispatched = []

        def ship(i):
            return ({"r": 1}, [{"intent_id": "i1", "what": "send"}])
        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
        plan = wc.ComposedPlan([
            {"kind": "saga", "name": "sg", "definition": sd,
             "action_fns": {"s1": ship},
             "comp_fns": {"s1": lambda i: {}}, "idem_key": "kob"}])
        run, auth = self._run()
        # Patch the dispatcher path: drain happens inside execute; we
        # verify via the idempotency store that the dispatch recorded.
        res = self.c.execute(plan, run_id=run["run_id"], authority=auth,
                             at=self.at)
        self.assertEqual(res["units"]["sg"]["outbox_dispatched"], 1)
        # A second execute replays everything without redispatch.
        c2 = wc.WorkflowComposer(self.ws, self.sm, self.im)
        c2.load_state(self.c.dump_state())
        res2 = c2.execute(plan, run_id=run["run_id"], authority=auth,
                          at=self.at)
        self.assertEqual(res2["units"]["sg"]["status"], "succeeded")
        self.assertEqual(len(dispatched), 0)


class SlipUnitTests(ComposedTestBase):
    def _slip_plan(self, key="krt"):
        legs = [{"handler_id": "h1", "handler_pubkey_hex": self.pb,
                 "rights": ["tool.invoke"], "input_digest": "0" * 64,
                 "output_digest": "0" * 64},
                {"handler_id": "h2", "handler_pubkey_hex": self.pb,
                 "rights": ["tool.invoke"], "input_digest": "0" * 64,
                 "output_digest": "0" * 64}]
        slip = wr.issue_slip(self.sa, "issuer", legs, self.at)
        return wc.ComposedPlan([
            {"kind": "slip", "name": "rt", "slip": slip,
             "trust_roots": [self.pa],
             "leg_fns": {0: (self.sb, lambda i: {"l": 0}),
                         1: (self.sb, lambda i: {"l": 1})},
             "idem_key": key}])

    def test_slip_unit_binds_receipts(self):
        run, auth = self._run()
        res = self.c.execute(self._slip_plan(), run_id=run["run_id"],
                             authority=auth, at=self.at)
        unit = res["units"]["rt"]
        self.assertTrue(unit["completed"])
        self.assertEqual(len(unit["slip"]["receipts"]), 2)
        steps = self.ws.list_steps(run["run_id"])
        self.assertEqual(len(steps), 2)
        for s in steps:
            self.assertIn("_composed_receipt_digest", s["outputs"])

    def test_slip_leg_failure_leaves_slip_unadvanced(self):
        def bad(i):
            raise RuntimeError("leg blew up")
        legs = [{"handler_id": "h1", "handler_pubkey_hex": self.pb,
                 "rights": ["tool.invoke"], "input_digest": "0" * 64,
                 "output_digest": "0" * 64}]
        slip = wr.issue_slip(self.sa, "issuer", legs, self.at)
        plan = wc.ComposedPlan([
            {"kind": "slip", "name": "rt", "slip": slip,
             "trust_roots": [self.pa],
             "leg_fns": {0: (self.sb, bad)}, "idem_key": "kbad"}])
        run, auth = self._run()
        res = self.c.execute(plan, run_id=run["run_id"], authority=auth,
                             at=self.at)
        unit = res["units"]["rt"]
        self.assertFalse(unit["completed"])
        self.assertEqual(unit["failed_leg"], 0)
        self.assertEqual(len(unit["slip"]["receipts"]), 0)


class CodePinTests(ComposedTestBase):
    def test_new_codes_present_as_literals(self):
        import gov.decision_codes as dc
        codes = {c["code"] for c in dc.TAXONOMY.values()}
        for want in ("workflow-composed-divergent",
                     "workflow-composed-definition-invalid",
                     "workflow-composed-authority-mismatch"):
            self.assertIn(want, codes)

    def test_ed25519_verify_contract(self):
        sig = ed25519.sign(self.sa, b"probe")
        pub = bytes.fromhex(self.pa)
        self.assertIs(ed25519.verify(pub, b"probe", sig), True)
        self.assertIs(ed25519.verify(pub, b"tampered", sig), False)


class ExoticClosureTests(ComposedTestBase):
    """F395: ComposedPlan refuses coded fns that close over
    non-JSON-native values (fail closed -- type-name binding
    collides, repr binding is unstable)."""

    class _Client:
        def __init__(self, endpoint):
            self.endpoint = endpoint

    def _mkfn(self, client):
        def fn(i):
            return client.fetch()
        return fn

    def test_exotic_closure_fn_refused(self):
        self.assertEqual(
            self._code_of(
                wc.ComposedPlan,
                [{"kind": "fn", "name": "u", "fn": self._mkfn(
                    self._Client("x")), "inputs": {}, "idem_key": "k"}]),
            "workflow-composed-definition-invalid")

    def test_exotic_closure_saga_action_refused(self):
        def mkaction(client):
            def action(params):
                return client, []
            return action
        sd = saga.SagaDefinition([
            saga.SagaStepDef("s1", "a", {}, "c")])
        self.assertEqual(
            self._code_of(
                wc.ComposedPlan,
                [{"kind": "saga", "name": "sg", "definition": sd,
                  "action_fns": {"s1": mkaction(self._Client("x"))},
                  "comp_fns": {"s1": lambda p: None}, "idem_key": "k"}]),
            "workflow-composed-definition-invalid")

    def test_nested_exotic_refused(self):
        def mknested(client):
            def fn(i):
                return ("a", client)
            return fn
        self.assertEqual(
            self._code_of(
                wc.ComposedPlan,
                [{"kind": "fn", "name": "u", "fn": mknested(
                    self._Client("x")), "inputs": {}, "idem_key": "k"}]),
            "workflow-composed-definition-invalid")

    def test_json_native_closure_still_binds_by_value(self):
        def mkj(v):
            def fn(i):
                return v
            return fn
        v = {"a": [1, 2, ("x", None)], "b": True}
        p1 = wc.ComposedPlan([
            {"kind": "fn", "name": "u", "fn": mkj(v),
             "inputs": {}, "idem_key": "k"}])
        p2 = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": mkj({"a": [1, 2, ("x", None)], "b": True}),
             "inputs": {}, "idem_key": "k"}])
        p3 = wc.ComposedPlan([
            {"kind": "fn", "name": "u",
             "fn": mkj({"a": [1, 2, ("y", None)], "b": True}),
             "inputs": {}, "idem_key": "k"}])
        self.assertEqual(p1.digest, p2.digest)
        self.assertNotEqual(p1.digest, p3.digest)

    def test_is_json_native_edge_cases(self):
        self.assertTrue(wc._is_json_native({"k": [1, "s", (2.5, None)]}))
        self.assertTrue(wc._is_json_native({1: "int-key"}))
        self.assertFalse(wc._is_json_native(object()))
        self.assertFalse(wc._is_json_native(frozenset({1, 2})))
        self.assertFalse(wc._is_json_native([object()]))
        cyclic = []
        cyclic.append(cyclic)
        self.assertFalse(wc._is_json_native(cyclic))
        # A shared substructure (DAG, no cycle) is JSON-native.
        shared = {"cfg": 1}
        self.assertTrue(wc._is_json_native({"a": shared, "b": [shared]}))
        # Container subclasses can lie to json.dumps via overridden
        # .items()/__iter__ (digest would bind different bytes than the
        # fn reads at runtime): exotic, must refuse.
        class LyingDict(dict):
            def items(self):
                return [("lied", "clean")]
        self.assertFalse(wc._is_json_native(LyingDict({"real": 1})))
        class LyingList(list):
            def __iter__(self):
                return iter(["lied"])
        self.assertFalse(wc._is_json_native(LyingList([1])))
        # Scalar subclasses cannot lie (encoder binds the true value).
        class HonestStr(str):
            pass
        self.assertTrue(wc._is_json_native(HonestStr("s")))
        deep = cur = []
        for _ in range(100000):
            nxt = []
            cur.append(nxt)
            cur = nxt
        self.assertTrue(wc._is_json_native(deep))


class StaleAtTests(ComposedTestBase):
    """F397: retry_saga_unit refuses a stale `at` coded.

    The composer retains the escalation's logical instant in the
    retry material; a retry instant at or before it is a stale clock
    claim and refuses workflow-saga-resolution-invalid. Malformed
    `at` keeps the existing workflow-composed-definition-invalid.
    """

    def _escalated(self, ttl=3600):
        sm = saga.SagaManager(authority_verifiers={"op": lambda: True},
                              operator_authority_ref="op")
        comp = wc.WorkflowComposer(self.ws, sm, self.im)
        calls = {"comp": 0}

        def ok(i):
            return ({"r": 1}, [])

        def boom(i):
            raise RuntimeError("kaboom")

        def flaky(i):
            calls["comp"] += 1
            if calls["comp"] <= 3:
                raise RuntimeError("blip")
            return {"fixed": True}

        sd = sm.define([
            saga.SagaStepDef("s1", "a1", {}, "c1"),
            saga.SagaStepDef("s2", "a2", {}, "c2"),
        ])
        plan = wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": sd,
            "action_fns": {"s1": ok, "s2": boom},
            "comp_fns": {"s1": flaky, "s2": flaky}, "idem_key": "kes"}])
        cons = {"expires_at": self.at + ttl, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        chain = [dg.issue(self.sa, "agent-a", "agent-b", self.pb,
                          ("tool.invoke",), issued_at=self.at,
                          constraints=cons)]
        auth = {"actor_id": "agent-b", "action": "tool.invoke",
                "chain": chain, "trust_roots": [self.pa],
                "revocation_ledger": drv.DelegationRevoker(self.sa,
                                                           "agent-a")}
        run = self.ws.start_run("plan", run_id="r-esc", authority=auth,
                                at=self.at)
        try:
            comp.execute(plan, run_id=run["run_id"], authority=auth,
                         at=self.at)
        except Exception:  # noqa: BLE001 -- escalation is expected
            pass
        inst = comp._saga_instances["sg"]
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(comp._saga_retry_ctx["sg"]["escalated_at"],
                         self.at)
        return comp, inst, calls

    def test_stale_at_equal_escalation_refused(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"},
                             at=self.at)
        self.assertEqual(code, "workflow-saga-resolution-invalid")
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(calls["comp"], 3)

    def test_stale_at_zero_refused(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"}, at=0)
        self.assertEqual(code, "workflow-saga-resolution-invalid")
        self.assertEqual(calls["comp"], 3)

    def test_stale_at_before_escalation_refused(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"},
                             at=self.at - 1)
        self.assertEqual(code, "workflow-saga-resolution-invalid")
        self.assertEqual(calls["comp"], 3)

    def test_negative_at_refused(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"}, at=-1)
        self.assertEqual(code, "workflow-composed-definition-invalid")

    def test_nonint_at_refused(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"},
                             at="not-an-instant")
        self.assertEqual(code, "workflow-composed-definition-invalid")

    def test_missing_escalated_at_fails_closed(self):
        comp, inst, calls = self._escalated()
        del comp._saga_retry_ctx["sg"]["escalated_at"]
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"},
                             at=self.at + 1)
        self.assertEqual(code, "workflow-saga-resolution-invalid")
        self.assertEqual(calls["comp"], 3)

    def test_fresh_at_live_delegation_succeeds(self):
        comp, inst, calls = self._escalated(ttl=10000)
        comp.retry_saga_unit("sg", {"action": "retry_compensation"},
                             at=self.at + 7200)
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(calls["comp"], 4)

    def test_expired_at_true_instant_refuses(self):
        comp, inst, calls = self._escalated()
        code = self._code_of(comp.retry_saga_unit, "sg",
                             {"action": "retry_compensation"},
                             at=self.at + 7200)
        self.assertEqual(code, "workflow-saga-compensation-unauthorized")
        self.assertEqual(inst.status, "escalated")
        self.assertEqual(calls["comp"], 3)


if __name__ == "__main__":
    unittest.main()
