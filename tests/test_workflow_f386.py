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


# Wave-311 merge: the F395 closure contract requires plan fns to close
# over JSON-native values only (ComposedPlan refuses coded
# workflow-composed-definition-invalid for exotic closures). Test
# instrumentation that needs live objects (ledger, composer, saga
# manager) during execution uses this module-level registry keyed by a
# JSON-native string: the fn closes over nothing and looks the objects
# up by key. This is F395-safe: the registry is process-global, so two
# plans with identical code resolve identical objects — no confusion.
_F386_PROBE_STATE = {}


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
        # F395 contract: spy must not close over self/c1 (exotic). The
        # live registry and the nonce travel via the module registry.
        _F386_PROBE_STATE["n1"] = {"sm": self.sm,
                                   "nonce": c1._verifier_nonce,
                                   "seen": seen}

        def spy(i):
            st = _F386_PROBE_STATE["n1"]
            st["seen"]["refs"] = [k for k in st["sm"]._verifiers
                                  if st["nonce"] in k]
            return ({"r": 1}, [])

        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
        plan = self._plan(
            sd, {"s1": spy},
            {"s1": lambda i: {"u": 1}}, key="nk")
        try:
            res = c1.execute(plan, run_id="n1", authority=self.auth, at=AT)
        finally:
            _F386_PROBE_STATE.pop("n1", None)
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
            # F395 contract: must not close over c2/plan/self.auth
            # (exotic). The reentrant targets travel via the module
            # registry, populated after plan construction.
            st = _F386_PROBE_STATE["col"]
            if st["entered"]["n"] == 0:
                st["entered"]["n"] += 1
                st["c2"].execute(st["plan"], run_id="col-r2",
                                 authority=st["auth"], at=AT)
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
        _F386_PROBE_STATE["col"] = {"c2": c2, "plan": plan,
                                    "auth": self.auth,
                                    "entered": entered}
        try:
            res = c1.execute(plan, run_id="col-r1", authority=self.auth,
                             at=AT)
        finally:
            _F386_PROBE_STATE.pop("col", None)
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
        # registration cannot shadow the first's wrapper ops. Scoping
        # is observed DURING execution (wave-305 removes the entries on
        # completion, so post-completion lookup finds nothing).
        c1, c2 = self._composer(), self._composer()
        self.store.start_run("probe", run_id="o1", authority=self.auth,
                             at=AT)
        self.store.start_run("probe", run_id="o2", authority=self.auth,
                             at=AT)
        seen = {}

        def ok(i):
            seen.setdefault("names", []).extend(
                k for k in saga.registered_ops()
                if k.startswith("composed:"))
            return ({"r": 1}, [])

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1")])
        p1 = self._plan(sd, {"s1": ok}, {"s1": comp}, key="ok1")
        p2 = self._plan(sd, {"s1": ok}, {"s1": comp}, key="ok2")
        c1.execute(p1, run_id="o1", authority=self.auth, at=AT)
        c2.execute(p2, run_id="o2", authority=self.auth, at=AT)
        tag1, tag2 = p1.digest[:12], p2.digest[:12]
        during = seen.get("names", [])
        self.assertTrue(any(c1._verifier_nonce in k and tag1 in k
                            for k in during),
                        "c1's scoped op never visible during execution")
        self.assertTrue(any(c2._verifier_nonce in k and tag2 in k
                            for k in during),
                        "c2's scoped op never visible during execution")
        unscoped = "composed:%s:sg:comp:s1" % tag1
        self.assertFalse(any(k == unscoped for k in during),
                         "unscoped plan-wide op name registered")

    # -- wave-305: deterministic op-registry cleanup ---------------------

    def _scoped_ops(self, composer):
        return [k for k in saga.registered_ops()
                if composer._verifier_nonce in k]

    def test_op_entries_removed_after_successful_unit(self):
        c1 = self._composer()
        self.store.start_run("probe", run_id="w1", authority=self.auth,
                             at=AT)
        plan = self._boom_plan(key="w1")
        res = c1.execute(plan, run_id="w1", authority=self.auth, at=AT)
        self.assertEqual(res["units"]["sg"]["status"], "compensated")
        leftovers = self._scoped_ops(c1)
        self.assertEqual(leftovers, [],
                         "scoped op entries leaked: %r" % (leftovers,))

    def test_op_entries_removed_after_failed_unit(self):
        c1 = self._composer()
        self.store.start_run("probe", run_id="w2", authority=self.auth,
                             at=AT)

        def bad_comp(i):
            raise RuntimeError("compensation still broken")

        plan = self._boom_plan(comp_fns={"s1": bad_comp, "s2": bad_comp,
                                         "s3": bad_comp}, key="w2")
        with self.assertRaises(wc.ComposedError):
            c1.execute(plan, run_id="w2", authority=self.auth, at=AT)
        leftovers = self._scoped_ops(c1)
        self.assertEqual(leftovers, [],
                         "scoped op entries leaked on failure: %r"
                         % (leftovers,))

    def test_op_registry_stable_across_executions(self):
        # Wave-305: ten 2-step saga executions must leave the
        # process-global registry exactly as found (pre-fix: +4 per
        # execution, 40 after 10).
        def ok(i):
            return ({"r": 1}, [])

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([saga.SagaStepDef("s1", "a1", {}, "c1"),
                             saga.SagaStepDef("s2", "a2", {}, "c2")])
        before = len(saga.registered_ops())
        for i in range(10):
            c = self._composer()
            run_id = "st%d" % i
            self.store.start_run("probe", run_id=run_id,
                                 authority=self.auth, at=AT)
            plan = self._plan(sd, {"s1": ok, "s2": ok},
                              {"s1": comp, "s2": comp}, key="stk%d" % i)
            res = c.execute(plan, run_id=run_id, authority=self.auth,
                            at=AT)
            self.assertEqual(res["units"]["sg"]["status"], "succeeded")
        self.assertEqual(len(saga.registered_ops()), before,
                         "op registry grew across executions")

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

        # F395 contract: boom_and_revoke must not close over
        # self.ledger/self.root (exotic). The revocation target travels
        # via the module registry.
        _F386_PROBE_STATE["v1"] = {"ledger": self.ledger,
                                   "receipt_id": self.root["receipt_id"]}

        def boom_and_revoke(i):
            st = _F386_PROBE_STATE["v1"]
            st["ledger"].revoke(st["receipt_id"], AT + 1)
            raise RuntimeError("kaboom")

        def comp(i):
            return {"u": 1}

        sd = self.sm.define([
            saga.SagaStepDef("s1", "a1", {}, "c1"),
            saga.SagaStepDef("s2", "a2", {}, "c2")])
        plan = self._plan(
            sd, {"s1": ok, "s2": boom_and_revoke},
            {"s1": comp, "s2": comp}, key="vk")
        try:
            with self.assertRaises(wc.ComposedError) as ctx:
                c1.execute(plan, run_id="v1", authority=self.auth, at=AT)
        finally:
            _F386_PROBE_STATE.pop("v1", None)
        self.assertEqual(ctx.exception.code,
                         "workflow-saga-compensation-unauthorized")

    def test_no_new_decision_codes(self):
        # F386 adds no decision codes: the raw literal inventory is
        # unchanged at 1829/1829/0.
        import re
        with open(os.path.join(os.path.dirname(__file__), "..", "gov",
                               "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertEqual(len(lits), 1976)  #Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(len(set(lits)), 1976)  #Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        self.assertEqual(lits, sorted(lits))


if __name__ == "__main__":
    unittest.main()
