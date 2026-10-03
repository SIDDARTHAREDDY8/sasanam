"""Unit tests for gov/workflow.py: durable workflow step records.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned (wave-243); the three new decision codes
are pinned as raw source literals.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_revocation as drv
from gov import ed25519
from gov import workflow as wf


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()


class WorkflowTestBase(unittest.TestCase):
    def setUp(self):
        self.seed_a = _seed("w301wf-a")
        self.seed_b = _seed("w301wf-b")
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.at = 1_700_000_000
        self.store = wf.WorkflowStore()

    def _root(self, delegatee="agent-b", rights=("tool.invoke",)):
        cons = {"expires_at": self.at + 3600, "max_depth": 4,
                "allowed_targets": [delegatee]}
        return dg.issue(self.seed_a, "agent-a", delegatee, self.pub_b,
                        rights, issued_at=self.at, constraints=cons)

    def _ledger(self):
        return drv.DelegationRevoker(self.seed_a, "agent-a")

    def _auth(self, chain, actor="agent-b", ledger=None, action="tool.invoke"):
        return {"actor_id": actor, "action": action, "chain": chain,
                "trust_roots": [self.pub_a],
                "revocation_ledger": (ledger if ledger is not None
                                      else self._ledger())}

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")


class StartRunTests(WorkflowTestBase):
    def test_start_run_records_run(self):
        auth = self._auth([self._root()])
        run = self.store.start_run("etl", run_id="r1", authority=auth,
                                   at=self.at)
        self.assertEqual(run["run_id"], "r1")
        self.assertEqual(run["workflow_name"], "etl")
        self.assertEqual(run["status"], "running")
        self.assertEqual(self.store.run_status("r1"), "running")

    def test_start_run_idempotent_on_idempotency_key(self):
        auth = self._auth([self._root()])
        r1 = self.store.start_run("etl", run_id="r1", idempotency_key="evt-9",
                                  authority=auth, at=self.at)
        r2 = self.store.start_run("etl", run_id="r2", idempotency_key="evt-9",
                                  authority=auth, at=self.at)
        self.assertEqual(r1["run_id"], r2["run_id"])
        self.assertEqual(len(self.store.list_runs()), 1)

    def test_start_run_refuses_without_authority(self):
        self.assertEqual(
            self._code_of(self.store.start_run, "etl", run_id="r1",
                          authority=None, at=self.at),
            "workflow-step-unauthorized")

    def test_start_run_refuses_actor_mismatch_on_resume(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        evil = self._auth([self._root(delegatee="agent-evil")],
                          actor="agent-evil")
        self.assertEqual(
            self._code_of(self.store.start_run, "etl", run_id="r1",
                          authority=evil, at=self.at),
            "workflow-step-unauthorized")


class RunStepTests(WorkflowTestBase):
    def test_step_executes_and_checkpoints(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        calls = []
        out, replayed = self.store.run_step(
            "r1", 0, "extract", lambda i: calls.append(i) or {"rows": 3},
            inputs={"src": "db"}, authority=auth, at=self.at)
        self.assertEqual(out, {"rows": 3})
        self.assertFalse(replayed)
        self.assertEqual(len(calls), 1)
        steps = self.store.list_steps("r1")
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["status"], "completed")
        self.assertEqual(len(steps[0]["inputs_digest"]), 64)
        self.assertEqual(len(steps[0]["outputs_digest"]), 64)

    def test_step_replays_recorded_result(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        calls = []
        self.store.run_step("r1", 0, "extract",
                            lambda i: calls.append(1) or {"rows": 3},
                            inputs={"src": "db"}, authority=auth, at=self.at)
        out, replayed = self.store.run_step(
            "r1", 0, "extract",
            lambda i: calls.append(1) or {"rows": 999},
            inputs={"src": "db"}, authority=auth, at=self.at)
        self.assertEqual(out, {"rows": 3})
        self.assertTrue(replayed)
        self.assertEqual(len(calls), 1)  # fn NOT re-executed

    def test_step_idempotency_key_replays_across_seq(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        calls = []
        self.store.run_step("r1", 0, "extract",
                            lambda i: calls.append(1) or {"rows": 3},
                            inputs={"src": "db"}, idempotency_key="step-k",
                            authority=auth, at=self.at)
        out, replayed = self.store.run_step(
            "r1", 7, "extract-again",
            lambda i: calls.append(1) or {"rows": 999},
            inputs={"src": "db"}, idempotency_key="step-k",
            authority=auth, at=self.at)
        self.assertEqual(out, {"rows": 3})
        self.assertTrue(replayed)
        self.assertEqual(len(calls), 1)

    def test_step_definition_drift_refused(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.store.run_step("r1", 0, "extract", lambda i: {"rows": 3},
                            inputs={"src": "db"}, authority=auth, at=self.at)
        self.assertEqual(
            self._code_of(self.store.run_step, "r1", 0, "extract",
                          lambda i: {"rows": 3}, inputs={"src": "other"},
                          authority=auth, at=self.at),
            "workflow-step-unauthorized")

    def test_failed_step_reruns_on_resume(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        attempts = []

        def flaky(i):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("boom")
            return {"ok": True}

        with self.assertRaises(RuntimeError):
            self.store.run_step("r1", 0, "extract", flaky,
                                inputs={}, authority=auth, at=self.at)
        out, replayed = self.store.run_step("r1", 0, "extract", flaky,
                                            inputs={}, authority=auth,
                                            at=self.at)
        self.assertEqual(out, {"ok": True})
        self.assertFalse(replayed)
        self.assertEqual(len(attempts), 2)

    def test_replay_convenience_resumes_run(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        calls = []
        steps = [
            {"seq": 0, "name": "a",
             "fn": lambda i: calls.append("a") or 1, "inputs": {}},
            {"seq": 1, "name": "b",
             "fn": lambda i: calls.append("b") or 2, "inputs": {}},
        ]
        first = self.store.replay("r1", steps, authority=auth, at=self.at)
        self.assertEqual([s for _, _, s, _, _ in first],
                         ["completed", "completed"])
        # Second replay: both replay, fns not called again.
        second = self.store.replay("r1", steps, authority=auth, at=self.at)
        self.assertTrue(all(r for _, _, _, r, _ in second))
        self.assertEqual(calls, ["a", "b"])

    def test_list_runs_and_status(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.store.start_run("etl", run_id="r2", authority=auth, at=self.at)
        self.store.complete_run("r1", authority=auth, at=self.at)
        self.assertEqual(self.store.run_status("r1"), "completed")
        self.assertEqual(self.store.run_status("r2"), "running")
        self.assertEqual(len(self.store.list_runs()), 2)
        self.assertEqual(len(self.store.list_runs(status="completed")), 1)

    def test_step_outputs_must_be_checkpointable(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.assertEqual(
            self._code_of(self.store.run_step, "r1", 0, "extract",
                          lambda i: object(), inputs={},
                          authority=auth, at=self.at),
            "workflow-checkpoint-tampered")


if __name__ == "__main__":
    unittest.main()


class CrashResumeTests(WorkflowTestBase):
    def _file_store(self, tmp):
        path = os.path.join(tmp, "wf.jsonl")
        return wf.WorkflowStore(path=path), path

    def test_crash_mid_run_resumes_from_checkpoint(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        store, path = self._file_store(tmp)
        auth = self._auth([self._root()])
        store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        calls = []
        for seq in range(3):
            store.run_step("r1", seq, "s%d" % seq,
                           lambda i, s=seq: calls.append(s) or s,
                           inputs={"n": seq}, authority=auth, at=self.at)
        # Simulate process death: drop the store, reload from the file.
        del store
        store2 = wf.WorkflowStore(path=path)
        self.assertEqual(len(store2.list_steps("r1")), 3)
        # Resume: steps 0-2 replay (fns NOT called), step 3 executes.
        out = store2.replay("r1", [
            {"seq": s, "name": "s%d" % s,
             "fn": lambda i, s=s: calls.append("r%d" % s) or s,
             "inputs": {"n": s}} for s in range(4)
        ], authority=auth, at=self.at)
        self.assertEqual([r for _, _, _, r, _ in out],
                         [True, True, True, False])
        self.assertEqual([o for _, _, _, _, o in out], [0, 1, 2, 3])
        self.assertEqual(calls, [0, 1, 2, "r3"])  # no re-execution of 0-2

    def test_revoked_authority_resume_refused(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        store, path = self._file_store(tmp)
        ledger = self._ledger()
        chain = [self._root()]
        auth = self._auth(chain, ledger=ledger)
        store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        store.run_step("r1", 0, "extract", lambda i: {"rows": 1},
                       inputs={}, authority=auth, at=self.at)
        # The delegator revokes the leaf receipt after the crash.
        ledger.revoke(chain[-1]["receipt_id"], self.at + 10)
        del store
        store2 = wf.WorkflowStore(path=path)
        self.assertEqual(
            self._code_of(store2.run_step, "r1", 1, "load",
                          lambda i: {"ok": True}, inputs={},
                          authority=auth, at=self.at + 20),
            "workflow-authority-revoked")

    def test_revoked_chain_refuses_even_without_new_reproof(self):
        ledger = self._ledger()
        chain = [self._root()]
        auth = self._auth(chain, ledger=ledger)
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        ledger.revoke(chain[-1]["receipt_id"], self.at + 5)
        self.assertEqual(
            self._code_of(self.store.run_step, "r1", 0, "extract",
                          lambda i: {"ok": True}, inputs={},
                          authority=auth, at=self.at + 10),
            "workflow-authority-revoked")

    def test_forged_checkpoint_refused_on_load(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        store, path = self._file_store(tmp)
        auth = self._auth([self._root()])
        store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        store.run_step("r1", 0, "extract", lambda i: {"rows": 1},
                       inputs={}, authority=auth, at=self.at)
        del store
        # Tamper: rewrite the step's outputs, keep valid JSON.
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        rec = json.loads(lines[-1])
        rec["outputs"] = {"rows": 999999}
        lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        try:
            wf.WorkflowStore(path=path)
        except Exception as e:  # noqa: BLE001
            self.assertEqual(getattr(e, "code", None),
                             "workflow-checkpoint-tampered")
        else:
            self.fail("tampered checkpoint loaded without refusal")

    def test_crash_tear_trailing_partial_line_ignored(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        store, path = self._file_store(tmp)
        auth = self._auth([self._root()])
        store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        store.run_step("r1", 0, "extract", lambda i: {"rows": 1},
                       inputs={}, authority=auth, at=self.at)
        del store
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"type": "step", "run_id": "r1", "seq": 1, "par')
        store2 = wf.WorkflowStore(path=path)
        self.assertEqual(len(store2.list_steps("r1")), 1)

    def test_authority_without_ledger_still_verifies(self):
        auth = self._auth([self._root()], ledger=None)
        auth.pop("revocation_ledger")
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        out, replayed = self.store.run_step(
            "r1", 0, "extract", lambda i: {"ok": True}, inputs={},
            authority=auth, at=self.at)
        self.assertEqual(out, {"ok": True})
        self.assertFalse(replayed)

    def test_ed25519_contract_pinned(self):
        msg = b"workflow-authority"
        sig = ed25519.sign(self.seed_a, msg)
        self.assertIs(ed25519.verify(self.pub_a_bytes(), msg, sig), True)
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertIs(ed25519.verify(self.pub_a_bytes(), msg, bytes(bad)),
                      False)

    def pub_a_bytes(self):
        return bytes.fromhex(self.pub_a)


class SleepNotifyTests(WorkflowTestBase):
    def test_sleep_completes_when_awake(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        awake, replayed = self.store.sleep_step(
            "r1", 0, "wait", wake_at=self.at, authority=auth, at=self.at,
            now=self.at)
        self.assertTrue(awake)
        self.assertFalse(replayed)
        awake2, replayed2 = self.store.sleep_step(
            "r1", 0, "wait", wake_at=self.at, authority=auth, at=self.at,
            now=self.at)
        self.assertTrue(awake2)
        self.assertTrue(replayed2)

    def test_sleep_pending_then_awake(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        awake, replayed = self.store.sleep_step(
            "r1", 0, "wait", wake_at=self.at + 100, authority=auth,
            at=self.at, now=self.at)
        self.assertFalse(awake)
        self.assertFalse(replayed)
        self.assertEqual(self.store.get_step("r1", 0)["status"], "pending")
        awake2, _ = self.store.sleep_step(
            "r1", 0, "wait", wake_at=self.at + 100, authority=auth,
            at=self.at + 100, now=self.at + 100)
        self.assertTrue(awake2)

    def test_notify_then_recv(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.store.notify("r1", "approval", {"decision": "yes"},
                          authority=auth, at=self.at)
        payload, replayed = self.store.recv_step(
            "r1", 0, "wait-approval", "approval", authority=auth,
            at=self.at, now=self.at)
        self.assertEqual(payload, {"decision": "yes"})
        self.assertFalse(replayed)
        payload2, replayed2 = self.store.recv_step(
            "r1", 0, "wait-approval", "approval", authority=auth,
            at=self.at, now=self.at)
        self.assertEqual(payload2, {"decision": "yes"})
        self.assertTrue(replayed2)

    def test_recv_pending_then_notification_arrives(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        payload, replayed = self.store.recv_step(
            "r1", 0, "wait-approval", "approval", authority=auth,
            at=self.at, now=self.at)
        self.assertIsNone(payload)
        self.assertFalse(replayed)
        self.store.notify("r1", "approval", {"decision": "yes"},
                          authority=auth, at=self.at + 5)
        payload2, replayed2 = self.store.recv_step(
            "r1", 0, "wait-approval", "approval", authority=auth,
            at=self.at + 5, now=self.at + 5)
        self.assertEqual(payload2, {"decision": "yes"})
        self.assertFalse(replayed2)

    def test_recv_timeout(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        payload, replayed = self.store.recv_step(
            "r1", 0, "wait-approval", "approval", authority=auth,
            at=self.at, now=self.at + 999, timeout_at=self.at + 100)
        self.assertEqual(payload, {"timeout": True})
        self.assertFalse(replayed)

    def test_recv_requires_authority(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.assertEqual(
            self._code_of(self.store.recv_step, "r1", 0, "wait-approval",
                          "approval", authority=None, at=self.at,
                          now=self.at),
            "workflow-step-unauthorized")

    def test_notify_consumes_each_event_once(self):
        auth = self._auth([self._root()])
        self.store.start_run("etl", run_id="r1", authority=auth, at=self.at)
        self.store.notify("r1", "tick", {"n": 1}, authority=auth, at=self.at)
        self.store.notify("r1", "tick", {"n": 2}, authority=auth, at=self.at)
        p1, _ = self.store.recv_step("r1", 0, "w1", "tick", authority=auth,
                                     at=self.at, now=self.at)
        p2, _ = self.store.recv_step("r1", 1, "w2", "tick", authority=auth,
                                     at=self.at, now=self.at)
        self.assertEqual(p1, {"n": 1})
        self.assertEqual(p2, {"n": 2})
