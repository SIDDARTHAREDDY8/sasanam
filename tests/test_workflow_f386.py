"""Unit tests for the F386 closure in gov/workflow_composed.py.

F386 (LOW, OPEN): ``_install_saga_verifier`` stored plan-scoped verifier
closures in the shared process-global ``SagaManager._verifiers`` (and
plan-scoped op names in the process-global op registry), bound them to
per-composer-instance mutable ``_exec_ctx``, and never removed entries.
A second composer sharing the manager overwrote the first composer's
verifier; reentrant same-plan execution during compensation then
escalated the first composer coded
``workflow-saga-compensation-unauthorized``.

The fix (close-when): a per-composer-instance nonce scopes every ref the
composer installs on shared registries (verifier entries AND the global
op registry names), and the verifier entry is removed deterministically
when the unit completes (success, failure, or compensation end).

Red-first: test_reentrant_same_plan_no_collision is the w303 red-team
probe shape; it BREAKs (escalation coded
workflow-saga-compensation-unauthorized) on the pristine base.
"""

import hashlib
import os
import unittest

from gov import ed25519
from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import workflow as wf
from gov import workflow_idempotency as idem
from gov import workflow_saga as saga
import gov.workflow_composed as wc

AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256((b"w304f386-" + tag)).digest()


def _fixture():
    sa, sb = _seed(b"a"), _seed(b"b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    return sa, sb, pa, pb, root


class F386ClosureTests(unittest.TestCase):
    def setUp(self):
        saga.clear_ops()
        self.sa, self.sb, self.pa, self.pb, self.root = _fixture()
        self.chain = [self.root]
        self.ledger = drv.DelegationRevoker(self.sa, "agent-a")
        self.auth = {"actor_id": "agent-b", "action": "tool.invoke",
                     "chain": self.chain, "trust_roots": [self.pa],
                     "revocation_ledger": self.ledger}
        self.store = wf.WorkflowStore()
        self.sm = saga.SagaManager()

    def _composer(self):
        return wc.WorkflowComposer(self.store, self.sm,
                                   idem.IdempotencyStore())

    def _plan(self, sd, action_fns, comp_fns, key="ck"):
        return wc.ComposedPlan([
            {"kind": "saga", "name": "sg", "definition": sd,
             "action_fns": action_fns, "comp_fns": comp_fns,
             "idem_key": key}])

    def _boom_plan(self, action_fns=None, comp_fns=None, key="ck"):
        def ok(i):
            return ({"r": 1}, [])

        def boom(i):
            raise RuntimeError("kaboom")

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([
            saga.SagaStepDef("s1", "a1", {}, "c1"),
            saga.SagaStepDef("s2", "a2", {}, "c2"),
            saga.SagaStepDef("s3", "a3", {}, "c3")])
        return self._plan(
            sd,
            action_fns or {"s1": ok, "s2": ok, "s3": boom},
            comp_fns or {"s1": comp, "s2": comp, "s3": comp},
            key=key)

    # -- per-composer-instance nonce -----------------------------------

    def test_nonce_unique_per_composer_instance(self):
        c1, c2 = self._composer(), self._composer()
        self.assertTrue(c1._verifier_nonce)
        self.assertTrue(c2._verifier_nonce)
        self.assertEqual(len(c1._verifier_nonce), 16)
        self.assertNotEqual(c1._verifier_nonce, c2._verifier_nonce)

    def test_verifier_ref_carries_composer_nonce(self):
        c1 = self._composer()
        self.store.start_run("probe", run_id="n1", authority=self.auth,
                             at=AT)
        seen = {}

        def spy(i):
            seen["refs"] = [k for k in self.sm._verifiers
                            if c1._verifier_nonce in k]
            return ({"r": 1}, [])

        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
        plan = self._plan(
            sd, {"s1": spy},
            {"s1": lambda i: {"u": 1}}, key="nk")
        res = c1.execute(plan, run_id="n1", authority=self.auth, at=AT)
        self.assertEqual(res["units"]["sg"]["status"], "succeeded")
        # One verifier entry per executed unit, scoped to this composer.
        self.assertEqual(len(seen["refs"]), 1)
        self.assertIn(c1._verifier_nonce, seen["refs"][0])
        self.assertTrue(seen["refs"][0].startswith("composed-auth:"))

    # -- deterministic entry removal -----------------------------------

    def test_verifier_entry_removed_after_successful_unit(self):
        c1 = self._composer()
        self.store.start_run("probe", run_id="r1", authority=self.auth,
                             at=AT)
        plan = self._boom_plan(key="k1")
        res = c1.execute(plan, run_id="r1", authority=self.auth, at=AT)
        self.assertEqual(res["units"]["sg"]["status"], "compensated")
        leftovers = [k for k in self.sm._verifiers
                     if c1._verifier_nonce in k]
        self.assertEqual(leftovers, [],
                         "verifier entry leaked: %r" % (leftovers,))

    def test_verifier_entry_removed_after_failed_unit(self):
        c1 = self._composer()
        self.store.start_run("probe", run_id="r2", authority=self.auth,
                             at=AT)

        def bad_comp(i):
            raise RuntimeError("compensation still broken")

        plan = self._boom_plan(comp_fns={"s1": bad_comp, "s2": bad_comp,
                                         "s3": bad_comp}, key="k2")
        with self.assertRaises(wc.ComposedError) as ctx:
            c1.execute(plan, run_id="r2", authority=self.auth, at=AT)
        self.assertIsNotNone(ctx.exception.code)
        leftovers = [k for k in self.sm._verifiers
                     if c1._verifier_nonce in k]
        self.assertEqual(leftovers, [],
                         "verifier entry leaked on failure: %r"
                         % (leftovers,))

    # -- the collision itself ------------------------------------------

    def test_reentrant_same_plan_no_collision(self):
        # The w303 red-team F386 probe shape: two composers share one
        # SagaManager; c2 reentrantly executes the SAME plan from inside
        # c1's compensation. Pre-fix this escalated c1 coded
        # workflow-saga-compensation-unauthorized.
        c1 = self._composer()
        c2 = self._composer()
        self.store.start_run("probe", run_id="col-r1", authority=self.auth,
                             at=AT)
        self.store.start_run("probe", run_id="col-r2", authority=self.auth,
                             at=AT)
        entered = {"n": 0}

        def ok(i):
            return ({"r": 1}, [])

        def boom(i):
            raise RuntimeError("kaboom")

        def comp_s1(i):
            return {"u": 1}

        def comp_s2(i):
            if entered["n"] == 0:
                entered["n"] += 1
                c2.execute(plan, run_id="col-r2", authority=self.auth,
                           at=AT)
            return {"u": 2}

        sd = self.sm.define([
            saga.SagaStepDef("s1", "a1", {}, "c1"),
            saga.SagaStepDef("s2", "a2", {}, "c2"),
            saga.SagaStepDef("s3", "a3", {}, "c3")])
        plan = wc.ComposedPlan([
            {"kind": "saga", "name": "sg", "definition": sd,
             "action_fns": {"s1": ok, "s2": ok, "s3": boom},
             "comp_fns": {"s1": comp_s1, "s2": comp_s2, "s3": comp_s1},
             "idem_key": "ck"}])
        res = c1.execute(plan, run_id="col-r1", authority=self.auth,
                         at=AT)
        self.assertEqual(res["units"]["sg"]["status"], "compensated")
        # Nothing lingered on the shared manager from either composer.
        leftovers = [k for k in self.sm._verifiers
                     if "composed-auth:" in k]
        self.assertEqual(leftovers, [],
                         "shared-manager verifier entries linger: %r"
                         % (leftovers,))

    def test_op_names_scoped_to_composer(self):
        # The process-global op registry is keyed by unit tag; the tag
        # now carries the composer nonce, so the second composer's
        # registration cannot shadow the first's wrapper ops.
        c1, c2 = self._composer(), self._composer()
        self.store.start_run("probe", run_id="o1", authority=self.auth,
                             at=AT)
        self.store.start_run("probe", run_id="o2", authority=self.auth,
                             at=AT)

        def ok(i):
            return ({"r": 1}, [])

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
        p1 = self._plan(sd, {"s1": ok}, {"s1": comp}, key="ok1")
        p2 = self._plan(sd, {"s1": ok}, {"s1": comp}, key="ok2")
        c1.execute(p1, run_id="o1", authority=self.auth, at=AT)
        c2.execute(p2, run_id="o2", authority=self.auth, at=AT)
        tag1, tag2 = p1.digest[:12], p2.digest[:12]
        scoped1 = "composed:%s:%s:sg:comp:s1" % (c1._verifier_nonce, tag1)
        scoped2 = "composed:%s:%s:sg:comp:s1" % (c2._verifier_nonce, tag2)
        unscoped = "composed:%s:sg:comp:s1" % tag1
        self.assertIsNotNone(saga.get_op(scoped1))
        self.assertIsNotNone(saga.get_op(scoped2))
        self.assertIs(saga.get_op(scoped1) is saga.get_op(scoped2), False)
        self.assertIsNone(saga.get_op(unscoped),
                          "unscoped plan-wide op name still registered")

    # -- the compensation authority model is intact ---------------------

    def test_compensation_still_reproves_authority(self):
        # F379/F384 semantics: compensation re-proves the step authority
        # NOW. Revoking the root delegation mid-flight (inside the
        # failing action) must still refuse compensation coded
        # workflow-saga-compensation-unauthorized.
        c1 = self._composer()
        self.store.start_run("probe", run_id="v1", authority=self.auth,
                             at=AT)

        def ok(i):
            return ({"r": 1}, [])

        def boom_and_revoke(i):
            self.ledger.revoke(self.root["receipt_id"], AT + 1)
            raise RuntimeError("kaboom")

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([
            saga.SagaStepDef("s1", "a1", {}, "c1"),
            saga.SagaStepDef("s2", "a2", {}, "c2")])
        plan = self._plan(
            sd, {"s1": ok, "s2": boom_and_revoke},
            {"s1": comp, "s2": comp}, key="vk")
        with self.assertRaises(wc.ComposedError) as ctx:
            c1.execute(plan, run_id="v1", authority=self.auth, at=AT)
        self.assertEqual(ctx.exception.code,
                         "workflow-saga-compensation-unauthorized")

    def test_no_new_decision_codes(self):
        # F386 adds no decision codes: the raw literal inventory is
        # unchanged at 1827/1827/0.
        import re
        with open(os.path.join(os.path.dirname(__file__), "..", "gov",
                               "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertEqual(len(lits), 1827)
        self.assertEqual(len(set(lits)), 1827)
        self.assertEqual(lits, sorted(lits))


if __name__ == "__main__":
    unittest.main()
