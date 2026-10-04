"""Wave-301 saga battery: red-first break-first probes.

Target: gov/workflow_saga.py (new in this lane) -- saga orchestration
with reverse-order compensation and a transactional outbox, stolen from
eventuate-tram/eventuate-tram-sagas (STEAL, Apache-2.0) and rebuilt on
Sasanam's own discipline. Standing design rule: "A workflow outlives its
runner -- every step is checkpointed, and every resume re-proves its
authority."

Base: wave-300 merge 94bc43deb58ba78163f3ee61a59c2240cdd008f3.
Pin 1802 -> 1812 (lane-local 1805 at lane time; 3 new codes:
workflow-saga-definition-invalid, workflow-saga-compensation-failed,
workflow-saga-compensation-unauthorized).

Red-first: on the pristine base the module is absent, so every feature
probe BREAKs; on the fixed tree every attack probe must be HELD
(refused/recorded coded). No probe may ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Module-level deployment mode; also verified under a
clean environment. Depth-1 green checks honor GOV_SKIP_GREEN.

Run:
  mkdir -p /var/tmp/g301-saga && TMPDIR=/var/tmp/g301-saga \
    ~/workspace/.gov-venv/bin/python evals/w301_saga_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g301-sagab \
    ~/workspace/.gov-venv/bin/python evals/w301_saga_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PIN = 2012 # Wave-300 merge pin 1802; wave-301 lane 4: pin 1802 -> 1805 (+3 workflow-saga-*); wave-301 merge: 1812 (+10 workflow-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)


SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from gov import decision_codes
    from gov import workflow_saga as ws
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


class CrashSim(BaseException):
    """Simulated crash: NOT an Exception, so the manager must not catch it."""


def _need_module(tc):
    if not HAVE_MODULE:
        tc.fail("BREAK: gov/workflow_saga.py absent on this tree")


class SagaProbes(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        _need_module(self)
        self.log = []
        self.mgr = ws.SagaManager()
        ws.register_op("t_ok", self._op_ok)
        ws.register_op("t_fail", self._op_fail)
        ws.register_op("t_crash", self._op_crash)
        ws.register_op("t_comp", self._op_comp)
        ws.register_op("t_comp_fail", self._op_comp_fail)

    # -- test ops ------------------------------------------------------
    def _op_ok(self, params):
        self.log.append("a:" + params["sid"])
        return ({"ok": True}, [{"body": "msg-for-" + params["sid"]}])

    def _op_fail(self, params):
        self.log.append("a:" + params["sid"])
        raise RuntimeError("boom-" + params["sid"])

    def _op_crash(self, params):
        self.log.append("a:" + params["sid"])
        raise CrashSim("simulated crash in " + params["sid"])

    def _op_comp(self, params):
        self.log.append("c:" + params["sid"])
        return {"compensated": True}

    def _op_comp_fail(self, params):
        self.log.append("c:" + params["sid"])
        raise RuntimeError("compensation-boom-" + params["sid"])

    def _step(self, sid, action="t_ok", comp="t_comp", authority_ref=None):
        d = {"step_id": sid, "action_op": action,
             "action_params": {"sid": sid},
             "compensation_op": comp,
             "compensation_params": {"sid": sid}}
        if authority_ref is not None:
            d["authority_ref"] = authority_ref
        return d

    def _assert_code(self, code, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except ws.SagaError as e:
            self.assertEqual(e.code, code,
                             "expected code %r, got %r (%s)" % (code, e.code, e))
            return e
        self.fail("BREAK: expected SagaError code %r, no error raised" % code)

    # -- probes ---------------------------------------------------------
    def test_crash_mid_saga_resume(self):
        """Crash mid-step-2: step 1 is NOT re-executed; step 2 is marked
        interrupted and compensated; forward history is preserved."""
        defn = self.mgr.define([self._step("s1"), self._step("s2", action="t_crash"),
                                self._step("s3")])
        inst = self.mgr.start(defn)
        with self.assertRaises(CrashSim):
            self.mgr.run(inst)
        # "Crash": drop the manager, reload the persisted instance.
        snap = json.loads(json.dumps(self.mgr.dump(inst)))
        mgr2 = ws.SagaManager()
        inst2 = mgr2.load(snap)
        mgr2.resume(inst2)
        self.assertEqual(inst2.status, "compensated", inst2.status)
        # Step 1's action ran exactly once -- resume did not re-execute it.
        self.assertEqual(self.log.count("a:s1"), 1, self.log)
        # Step 2 was interrupted (never committed) and step 1 compensated.
        self.assertEqual(self.log, ["a:s1", "a:s2", "c:s1"], self.log)
        types = [e["type"] for e in inst2.history]
        self.assertIn("step_interrupted", types)
        self.assertIn("saga_compensated", types)
        # Forward history was reconstructed, never edited.
        self.assertIn("step_succeeded", types)
        seqs = [e["seq"] for e in inst2.history]
        self.assertEqual(seqs, sorted(seqs))

    def test_failing_compensation_escalation(self):
        """A compensation that keeps failing is retried, then escalates
        loudly -- never silently skipped."""
        defn = self.mgr.define([self._step("s1", comp="t_comp_fail"),
                                self._step("s2", action="t_fail")])
        inst = self.mgr.start(defn)
        err = self._assert_code("workflow-saga-compensation-failed",
                               self.mgr.run, inst)
        self.assertIn("s1", str(err))
        self.assertEqual(inst.status, "escalated")
        # Retried exactly max_compensation_attempts times, then escalated.
        self.assertEqual(self.log.count("c:s1"), 3, self.log)
        types = [e["type"] for e in inst.history]
        self.assertIn("compensation_failed", types)
        self.assertNotIn("saga_compensated", types)
        # The failed step's record is intact and marked.
        s1 = [s for s in inst.steps if s["step_id"] == "s1"][0]
        self.assertEqual(s1["state"], "compensation_failed")

    def test_outbox_double_dispatch_under_crash_replay(self):
        """Committed outbox intents survive a crash before drain and are
        delivered exactly once per intent record across resume+replay."""
        defn = self.mgr.define([self._step("s1"), self._step("s2")])
        inst = self.mgr.start(defn)
        self.mgr.run(inst)
        self.assertEqual(inst.status, "succeeded")
        # Crash before drain: drop the manager, reload.
        snap = json.loads(json.dumps(self.mgr.dump(inst)))
        mgr2 = ws.SagaManager()
        inst2 = mgr2.load(snap)
        received = []
        n = mgr2.drain_outbox(inst2, received.append)
        self.assertEqual(n, 2)
        self.assertEqual(len(received), 2)
        bodies = sorted(r["payload"]["body"] for r in received)
        self.assertEqual(bodies, ["msg-for-s1", "msg-for-s2"])
        # Replay the drain: nothing new is delivered (exactly-once records).
        n2 = mgr2.drain_outbox(inst2, received.append)
        self.assertEqual(n2, 0)
        self.assertEqual(len(received), 2)
        # No duplicate intent records exist.
        ids = [i["intent_id"] for i in inst2.outbox]
        self.assertEqual(len(ids), len(set(ids)))

    def test_compensation_order(self):
        """Compensations run in exact reverse completion order."""
        defn = self.mgr.define([self._step("s1"), self._step("s2"),
                                self._step("s3", action="t_fail"),
                                self._step("s4")])
        inst = self.mgr.start(defn)
        self.mgr.run(inst)
        self.assertEqual(inst.status, "compensated")
        self.assertEqual(self.log,
                         ["a:s1", "a:s2", "a:s3", "c:s2", "c:s1"], self.log)
        # History order: forward events, then compensations reversed.
        types = [(e["type"], e["step_id"]) for e in inst.history]
        comp_started = [sid for (t, sid) in types if t == "compensation_started"
                        and sid is not None]
        self.assertEqual(comp_started, ["s2", "s1"], types)

    def test_revoked_authority_compensation_refuses(self):
        """A compensation whose authority was revoked refuses loudly and
        escalates -- the step stays recorded as uncompensated."""
        calls = {"n": 0}

        def verifier():
            # Pass the forward check, revoke before the compensation check.
            calls["n"] += 1
            return calls["n"] == 1

        mgr = ws.SagaManager(authority_verifiers={"authA": verifier})
        defn = mgr.define([self._step("s1", authority_ref="authA"),
                           self._step("s2", action="t_fail")])
        inst = mgr.start(defn)
        err = self._assert_code("workflow-saga-compensation-unauthorized",
                               mgr.run, inst)
        self.assertIn("s1", str(err))
        self.assertEqual(inst.status, "escalated")
        s1 = [s for s in inst.steps if s["step_id"] == "s1"][0]
        # Recorded as still-succeeded (uncompensated), never silently skipped.
        self.assertEqual(s1["state"], "succeeded")
        types = [e["type"] for e in inst.history]
        self.assertIn("compensation_refused", types)

    def test_definition_requires_compensation(self):
        """The DSL refuses a step without a declared compensation: it is
        declared up front, never invented at failure time."""
        bad = {"step_id": "s1", "action_op": "t_ok",
               "action_params": {}, "compensation_op": ""}
        self._assert_code("workflow-saga-definition-invalid",
                         self.mgr.define, [bad])
        self._assert_code("workflow-saga-definition-invalid",
                         self.mgr.define, [])
        dup = [self._step("s1"), self._step("s1")]
        self._assert_code("workflow-saga-definition-invalid",
                         self.mgr.define, dup)

    def test_resume_twice_stable(self):
        """Resuming a compensated saga is stable: no duplicate compensations."""
        defn = self.mgr.define([self._step("s1"),
                                self._step("s2", action="t_fail")])
        inst = self.mgr.start(defn)
        self.mgr.run(inst)
        self.assertEqual(inst.status, "compensated")
        n_comp = self.log.count("c:s1")
        self.mgr.resume(inst)
        self.mgr.resume(inst)
        self.assertEqual(self.log.count("c:s1"), n_comp, self.log)
        self.assertEqual(inst.status, "compensated")

    def test_pin_taxonomy(self):
        self.assertEqual(len(decision_codes.TAXONOMY), PIN,
                         "taxonomy pin drift: expected %d, got %d"
                         % (PIN, len(decision_codes.TAXONOMY)))


class GreenChecks(unittest.TestCase):
    def _run(self, name, path, tolerate=()):
        if SKIP_GREEN:
            return
        if not os.path.exists(path):
            self.fail("green check %s: target missing: %s" % (name, path))
        tmp = tempfile.mkdtemp(prefix="g301-green-")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600, env=env, cwd=REPO)
            out = proc.stdout + proc.stderr
        except Exception as e:  # noqa: BLE001
            self.fail("green check %s crashed: %r" % (name, e))
        import re
        bad = []
        for ln in out.splitlines():
            s = ln.strip()
            m = re.match(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", s)
            if m and (int(m.group(1)) or int(m.group(3))):
                if not any(t in s for t in tolerate):
                    bad.append(s)
                continue
            if s.startswith("FAIL:") or s.startswith("ERROR:"):
                if not any(t in s for t in tolerate):
                    bad.append(s)
        self.assertEqual(bad, [], "green check %s had failures: %s"
                         % (name, bad[:5]))

    def test_green_workflow_saga_unit(self):
        self._run("test_workflow_saga",
                  os.path.join(REPO, "tests", "test_workflow_saga.py"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
