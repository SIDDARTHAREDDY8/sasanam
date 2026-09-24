#!/usr/bin/env python3
"""Unit tests for the anti-sandbagging eval-integrity harness (GAP-4)."""

import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test-eval-harness")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov import eval_harness as eh  # noqa: E402
from gov.detection import BehavioralMonitor, identity_key_of  # noqa: E402

MODEL_A = {"model_id": "gov-reasoner", "model_version": "2026.09.1"}
MODEL_B = {"model_id": "gov-reasoner", "model_version": "2026.09.1-crippled"}
SESSION_OPEN = "2026-09-24T00:00:00Z"


def _pool():
    pool = [{"task_id": "scored-%02d" % i, "kind": "scored",
             "family": "reasoning", "difficulty": 0.2}
            for i in range(10)]
    pool += [{"task_id": "canary-%02d" % i, "kind": "canary",
              "family": "reasoning", "difficulty": 0.3}
             for i in range(4)]
    return pool


def _ctx():
    tmp = tempfile.mkdtemp(prefix="govevalharness-ut-")
    ctx = make_run(ledger_path=os.path.join(tmp, "egress.jsonl"))
    ident = ctx["executor"].mint_identity("harness-tester", "eval-runner",
                                          "eval-principal")
    return ctx, ident, BehavioralMonitor()


def _commit(ctx, session_id, **kw):
    args = dict(model_identity=dict(MODEL_A), n_scored=4, n_canary=3,
                seed="unit-seed", log=ctx["log"], session_id=session_id,
                session_open=SESSION_OPEN)
    args.update(kw)
    return eh.commit_battery(_pool(), **args)


def _record_all(ctx, manifest, session_id, outcomes):
    for o in outcomes:
        eh.record_task_outcome(ctx["log"], session_id=session_id,
                               battery_id=manifest["battery_id"],
                               task_id=o["task_id"], success=o["success"],
                               session_open=SESSION_OPEN)


def _accept(ctx, ident, monitor, manifest, outcomes, session_id, **kw):
    args = dict(manifest=manifest,
                attested_model_identity=dict(MODEL_A),
                log=ctx["log"], session_id=session_id,
                session_open=SESSION_OPEN, monitor=monitor,
                identity=ident, identity_key=identity_key_of(ident))
    args.update(kw)
    return eh.accept_eval_results(outcomes, **args)


def _trip_signals(ctx):
    return [((e.get("prov") or {}).get("detector_trip") or {}).get("signal")
            for e in ctx["read_log"]()
            if isinstance(e, dict)
            and (e.get("prov") or {}).get("detector_trip")]


class CommitTests(unittest.TestCase):
    def test_commit_build_roundtrip_and_replay(self):
        ctx, _, _ = _ctx()
        m1 = _commit(ctx, "s-replay")
        tasks = eh.build_battery(m1, _pool())
        self.assertEqual([t["task_id"] for t in tasks],
                         [t["task_id"] for t in m1["tasks"]])
        # Same seed replays the identical battery (auditable draw).
        ctx2, _, _ = _ctx()
        m2 = _commit(ctx2, "s-replay")
        self.assertEqual(m1["battery_id"], m2["battery_id"])
        self.assertEqual(m1["manifest_digest"], m2["manifest_digest"])
        # Canary positions are shuffled, not all trailing.
        kinds = [t["kind"] for t in m1["tasks"]]
        self.assertIn("canary", kinds[:3] + kinds[-3:])

    def test_canary_free_commit_refused(self):
        ctx, _, _ = _ctx()
        with self.assertRaises(ValueError):
            _commit(ctx, "s-nocanary", n_canary=0)

    def test_manifest_tamper_refused(self):
        ctx, _, _ = _ctx()
        m = _commit(ctx, "s-tamper")
        m["tasks"][0]["task_id"] = "scored-00-evil"
        with self.assertRaises(ValueError):
            eh.build_battery(m, _pool())

    def test_pool_kind_swap_detected(self):
        ctx, _, _ = _ctx()
        m = _commit(ctx, "s-kindswap")
        pool = [dict(t) for t in _pool()]
        for t in pool:
            if t["task_id"] == m["tasks"][0]["task_id"]:
                t["kind"] = "canary" if t["kind"] == "scored" else "scored"
        with self.assertRaises(ValueError):
            eh.build_battery(m, pool)

    def test_zero_canary_manifest_refused_at_recompute(self):
        # Hand-built manifest with a VALID digest but zero canaries: the
        # harness must refuse it the same way commit_battery does
        # (fail-closed: ValueError, never a ZeroDivisionError at
        # acceptance).
        tuples = [("scored-00", "scored", "reasoning", 0.2, None)]
        inner = eh._manifest_inner_digest(
            seed="s", model_identity=dict(MODEL_A), task_tuples=tuples)
        battery_id = "eb-" + inner[:12]
        manifest = {
            "battery_id": battery_id, "seed": "s",
            "model_identity": dict(MODEL_A),
            "tasks": [{"task_id": t[0], "kind": t[1], "family": t[2],
                       "difficulty": t[3], "content_sha256": t[4]}
                      for t in tuples],
            "manifest_digest": eh._manifest_digest(
                battery_id=battery_id, inner_digest=inner),
        }
        with self.assertRaises(ValueError):
            eh.build_battery(manifest, _pool())

    def test_commit_chains_record(self):
        ctx, _, _ = _ctx()
        m = _commit(ctx, "s-chained")
        recs = [e for e in ctx["read_log"]()
                if isinstance(e, dict)
                and e.get("signal") == "eval_battery_committed"
                and e.get("session_id") == "s-chained"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["manifest_digest"],
                         m["manifest_digest"])
        self.assertEqual(recs[0]["n_canary"], 3)
        # The chained record reconstructs the battery on its own.
        self.assertEqual([t["task_id"] for t in recs[0]["tasks"]],
                         [t["task_id"] for t in m["tasks"]])
        self.assertTrue(all(t["kind"] in ("scored", "canary")
                            for t in recs[0]["tasks"]))


class AcceptTests(unittest.TestCase):
    def _honest(self, ctx, ident, monitor, session_id):
        m = _commit(ctx, session_id)
        ids = [t["task_id"] for t in m["tasks"]]
        canaries = [t["task_id"] for t in m["tasks"]
                    if t["kind"] == "canary"]
        outcomes = [{"task_id": t, "success": True} for t in ids]
        _record_all(ctx, m, session_id, outcomes)
        return m, outcomes, canaries

    def test_honest_run_accepted(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-honest")
        res = _accept(ctx, ident, monitor, m, outcomes, "s-honest",
                      deployment_model_identity=dict(MODEL_A))
        self.assertTrue(res["accepted"])
        self.assertEqual(res["violations"], [])
        self.assertEqual(res["canary"]["verdict"], "nominal")
        checks = [e for e in ctx["read_log"]()
                  if isinstance(e, dict)
                  and e.get("signal") == "eval_results_checked"
                  and e.get("session_id") == "s-honest"]
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["accepted"])
        self.assertEqual(checks[0]["manifest_digest"],
                         m["manifest_digest"])
        # The acceptance record binds the per-task outcomes themselves.
        self.assertEqual(
            {o["task_id"]: o["success"] for o in checks[0]["outcomes"]},
            {o["task_id"]: o["success"] for o in outcomes})

    def test_outcome_tamper_refused_with_violation(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-tamper2")
        tampered = [dict(o) for o in outcomes]
        tampered[0]["success"] = not tampered[0]["success"]
        res = _accept(ctx, ident, monitor, m, tampered, "s-tamper2")
        self.assertFalse(res["accepted"])
        self.assertIn("task", res["reason"].lower())
        self.assertIn("eval_outcome_tamper", _trip_signals(ctx))

    def test_task_swap_refused_with_violation(self):
        ctx, ident, monitor = _ctx()
        m = _commit(ctx, "s-swap")
        ids = [t["task_id"] for t in m["tasks"]]
        swapped = ids[1:] + ["gift-01"]
        outcomes = [{"task_id": t, "success": True} for t in swapped]
        _record_all(ctx, m, "s-swap", outcomes)
        res = _accept(ctx, ident, monitor, m, outcomes, "s-swap")
        self.assertFalse(res["accepted"])
        self.assertIn("task", res["reason"].lower())
        self.assertIn("eval_taskset_mismatch", _trip_signals(ctx))

    def test_model_substitution_refused_with_violation(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-subst")
        res = _accept(ctx, ident, monitor, m, outcomes, "s-subst",
                      attested_model_identity=dict(MODEL_B))
        self.assertFalse(res["accepted"])
        self.assertIn("model_identity_mismatch", _trip_signals(ctx))

    def test_deployment_inequivalence_refused(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-depineq")
        res = _accept(ctx, ident, monitor, m, outcomes, "s-depineq",
                      deployment_model_identity=dict(MODEL_B))
        self.assertFalse(res["accepted"])
        self.assertIn("deployment_inequivalence", _trip_signals(ctx))

    def test_duplicate_acceptance_refused(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-dupe")
        first = _accept(ctx, ident, monitor, m, outcomes, "s-dupe")
        self.assertTrue(first["accepted"])
        second = _accept(ctx, ident, monitor, m, outcomes, "s-dupe")
        self.assertFalse(second["accepted"])
        self.assertIn("duplicate", second["reason"].lower())

    def test_violation_result_carries_signal(self):
        ctx, ident, monitor = _ctx()
        m, outcomes, _ = self._honest(ctx, ident, monitor, "s-sigcarry")
        res = _accept(ctx, ident, monitor, m, outcomes, "s-sigcarry",
                      attested_model_identity=dict(MODEL_B))
        self.assertFalse(res["accepted"])
        self.assertEqual([v.get("signal") for v in res["violations"]],
                         ["model_identity_mismatch"])

    def test_canary_underperformance_refused(self):
        ctx, ident, monitor = _ctx()
        m = _commit(ctx, "s-canaryfail", n_scored=2, n_canary=4)
        ids = [t["task_id"] for t in m["tasks"]]
        canaries = {t["task_id"] for t in m["tasks"]
                    if t["kind"] == "canary"}
        # Canaries fail far below demonstrated (1 - 0.3 = 0.7); scored pass.
        outcomes = [{"task_id": t, "success": t not in canaries}
                    for t in ids]
        _record_all(ctx, m, "s-canaryfail", outcomes)
        res = _accept(ctx, ident, monitor, m, outcomes, "s-canaryfail")
        self.assertFalse(res["accepted"])
        self.assertEqual(res["canary"]["verdict"], "underperforming")
        self.assertIn("canary_underperformance", _trip_signals(ctx))


class ConsistencyMonitorTests(unittest.TestCase):
    def test_flags_longitudinal_drift(self):
        mon = eh.CapabilityConsistencyMonitor()
        mon.record_deployment_baseline("k1", "reasoning", [1.0] * 19 + [0.0])
        res = mon.check_eval("k1", "reasoning", [1.0] * 6 + [0.0] * 4)
        self.assertEqual(res["verdict"], "underperforming")

    def test_nominal_when_consistent(self):
        mon = eh.CapabilityConsistencyMonitor()
        mon.record_deployment_baseline("k1", "reasoning", [1.0] * 19 + [0.0])
        res = mon.check_eval("k1", "reasoning", [1.0] * 9 + [0.0])
        self.assertEqual(res["verdict"], "nominal")

    def test_insufficient_data_without_baseline(self):
        mon = eh.CapabilityConsistencyMonitor()
        res = mon.check_eval("k9", "reasoning", [1.0] * 6 + [0.0] * 4)
        self.assertEqual(res["verdict"], "insufficient_data")

    def test_eval_outcomes_never_train_baseline(self):
        mon = eh.CapabilityConsistencyMonitor()
        mon.record_deployment_baseline("k1", "reasoning", [1.0] * 19 + [0.0])
        before = mon.baseline("k1", "reasoning")
        mon.check_eval("k1", "reasoning", [0.0] * 10)
        self.assertEqual(mon.baseline("k1", "reasoning"), before)

    def test_drift_refuses_acceptance(self):
        ctx, ident, monitor = _ctx()
        mon = eh.CapabilityConsistencyMonitor()
        mon.record_deployment_baseline(identity_key_of(ident), "reasoning",
                                       [1.0] * 19 + [0.0])
        m = _commit(ctx, "s-drift", n_scored=10, n_canary=2)
        scored = [t["task_id"] for t in m["tasks"]
                  if t["kind"] == "scored"]
        canaries = [t["task_id"] for t in m["tasks"]
                    if t["kind"] == "canary"]
        ok = set(scored[:6]) | set(canaries)
        outcomes = [{"task_id": t["task_id"], "success": t["task_id"] in ok}
                    for t in m["tasks"]]
        _record_all(ctx, m, "s-drift", outcomes)
        res = _accept(ctx, ident, monitor, m, outcomes, "s-drift",
                      consistency_monitor=mon,
                      consistency_family="reasoning")
        self.assertFalse(res["accepted"])
        self.assertEqual(res["consistency"]["verdict"], "underperforming")
        self.assertIn("eval_capability_drift", _trip_signals(ctx))


class EquivalenceTests(unittest.TestCase):
    def test_equivalent(self):
        ctx, _, _ = _ctx()
        m = _commit(ctx, "s-equiv")
        res = eh.verify_deployment_equivalence(m, dict(MODEL_A))
        self.assertTrue(res["equivalent"])

    def test_inequivalent(self):
        ctx, _, _ = _ctx()
        m = _commit(ctx, "s-inequiv")
        res = eh.verify_deployment_equivalence(m, dict(MODEL_B))
        self.assertFalse(res["equivalent"])
        self.assertIn("mismatch", res["reason"].lower())


class LintTests(unittest.TestCase):
    def test_lists_sessions_without_committed_battery(self):
        ctx, _, _ = _ctx()
        _commit(ctx, "s-committed")
        entries = list(ctx["read_log"]())
        missing = eh.eval_sessions_missing_battery_commit(
            entries, session_ids=["s-committed", "s-skipped"])
        self.assertEqual(missing, ["s-skipped"])


if __name__ == "__main__":
    unittest.main()
