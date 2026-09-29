"""Tests for gov.durable_approval: durable approval workflows.

Red-first: written BEFORE the engine was trusted (2026-09-29). The
crash-survival properties are tested with real subprocesses and real
kill -9 / os._exit, not mocks — the durability triple (journal as
source of truth, determinism guard, durable timers) must hold under
actual process death.

Convention: stdlib unittest only (repo standard; discovered by
tests/run_tests.py).
"""

import json
import multiprocessing
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.durable_approval import (  # noqa: E402
    ACTION_CLAIMED,
    ACTION_EXECUTED,
    ActionNotIdempotent,
    DuplicateApproval,
    Engine,
    GrantRefused,
    NonDeterministicReplayError,
    find_audit_orphans,
)
from gov.durable_journal import Journal, verify_journal  # noqa: E402


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _child_request_then_wait(journal, outcomes, queue):
    eng = Engine(journal, outcomes)
    eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                action_kind="default", idempotency_key="key-a1",
                ttl_seconds=60)
    queue.put("requested")
    queue.get()  # block until killed


def _child_grant_then_wait(journal, outcomes, queue):
    eng = Engine(journal, outcomes)
    eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                action_kind="default", idempotency_key="key-a1",
                ttl_seconds=60)
    eng.grant("a1", "human-1")
    queue.put("granted")
    queue.get()


def _child_crash_after_side_effect(journal, outcomes, queue):
    eng = Engine(journal, outcomes)
    eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                action_kind="default", idempotency_key="key-a1",
                ttl_seconds=60)
    eng.grant("a1", "human-1")
    os.environ["DURABLE_CRASH_AFTER_SIDE_EFFECT"] = "1"
    queue.put("driving")
    # Flush the feeder thread BEFORE the simulated kill: Queue.put is
    # async, and os._exit(137) in the crash hook would otherwise lose
    # the buffered item in a race (the child dies correctly either
    # way, but the parent would see an empty queue).
    queue.close()
    queue.join_thread()
    eng.drive()  # claims, runs side effect, then os._exit(137)
    queue.put("survived")  # must never arrive


def _concurrent_driver(journal, outcomes, queue):
    eng = Engine(journal, outcomes)
    eng.drive()
    queue.put("done")


class EngineLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")
        self.eng = Engine(self.journal, self.outcomes)

    def _req(self, aid="a1", **kw):
        args = {"approval_id": aid, "requester": "agent-1",
                "packet_digest": "p" * 64, "action_kind": "default",
                "idempotency_key": "key-%s" % aid, "ttl_seconds": 60}
        args.update(kw)
        return self.eng.request(**args)

    def _records(self):
        return Journal(self.journal).records

    def test_request_journals_request_plus_timer_in_one_transaction(self):
        self._req()
        recs = self._records()
        self.assertEqual(
            [r["type"] for r in recs],
            ["WorkflowStarted", "ApprovalRequested", "TimerStarted"])
        txns = {r["txn"] for r in recs}
        self.assertEqual(len(txns), 1)
        self.assertNotIn(None, txns,
                         "request + timer must be ONE atomic transaction")
        self.assertEqual(self.eng.states()["a1"]["status"], "pending")

    def test_grant_then_drive_executes_action(self):
        self._req()
        self.eng.grant("a1", "human-1")
        out = self.eng.drive()
        self.assertIn(("action_executed", "a1"), out["did"])
        self.assertEqual(out["states"]["a1"]["status"], "executed")
        done = os.path.join(self.outcomes, "key-a1.done")
        self.assertTrue(os.path.exists(done))
        payload = _read_json(done)
        self.assertEqual(payload["outcome"], "ACTION_PERFORMED")

    def test_drive_is_idempotent(self):
        self._req()
        self.eng.grant("a1", "human-1")
        self.eng.drive()
        n = len(self._records())
        out = self.eng.drive()
        self.assertEqual(out["did"], [])
        self.assertEqual(len(self._records()), n)
        self.assertEqual(
            sum(1 for r in self._records() if r["type"] == ACTION_EXECUTED),
            1)

    def test_non_idempotent_action_refused_loudly(self):
        with self.assertRaises(ActionNotIdempotent):
            self._req(idempotent=False)
        self.assertEqual(self._records(), [],
                         "refused request must journal nothing")

    def test_duplicate_approval_id_refused(self):
        self._req()
        with self.assertRaises(DuplicateApproval):
            self._req()

    def test_grant_unknown_or_not_pending_refused(self):
        with self.assertRaises(GrantRefused):
            self.eng.grant("nope", "human-1")
        self._req()
        self.eng.deny("a1", "human-1", reason="no")
        with self.assertRaises(GrantRefused):
            self.eng.grant("a1", "human-2")
        self.assertEqual(self.eng.states()["a1"]["status"], "denied")

    def test_deny_vetoes(self):
        self._req()
        self.eng.deny("a1", "human-1", reason="bad idea")
        out = self.eng.drive()
        self.assertEqual(out["did"], [])
        self.assertEqual(self.eng.states()["a1"]["status"], "denied")
        self.assertFalse(
            os.path.exists(os.path.join(self.outcomes, "key-a1.done")))

    def test_claim_attempts_are_recorded(self):
        self._req()
        self.eng.grant("a1", "human-1")
        self.eng.drive()
        claims = [r for r in self._records() if r["type"] == ACTION_CLAIMED]
        self.assertGreaterEqual(len(claims), 1)
        for c in claims:
            self.assertTrue(c["body"].get("attempt"))


class CrashSurvivalTest(unittest.TestCase):
    """Real process death: kill -9 and the crash hook. Slow; each test
    spawns subprocesses."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")

    def test_kill9_while_pending_survives(self):
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=_child_request_then_wait,
                                    args=(self.journal, self.outcomes, q))
        p.start()
        self.assertEqual(q.get(timeout=30), "requested")
        os.kill(p.pid, 9)
        p.join(30)
        self.assertEqual(p.exitcode, -9)
        # Restart: the pending approval survived; nothing executed.
        eng = Engine(self.journal, self.outcomes)
        self.assertEqual(eng.states()["a1"]["status"], "pending")
        out = eng.drive()
        self.assertEqual(out["did"], [])
        # Grant after restart; drive executes exactly once.
        eng.grant("a1", "human-1")
        eng.drive()
        eng2 = Engine(self.journal, self.outcomes)
        eng2.drive()
        recs = Journal(self.journal).records
        self.assertEqual(
            sum(1 for r in recs if r["type"] == ACTION_EXECUTED), 1)
        self.assertTrue(
            os.path.exists(os.path.join(self.outcomes, "key-a1.done")))

    def test_kill9_after_grant_restart_executes_once(self):
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=_child_grant_then_wait,
                                    args=(self.journal, self.outcomes, q))
        p.start()
        self.assertEqual(q.get(timeout=30), "granted")
        os.kill(p.pid, 9)
        p.join(30)
        # Restart drives the approved workflow exactly once.
        eng = Engine(self.journal, self.outcomes)
        eng.drive()
        eng2 = Engine(self.journal, self.outcomes)
        out = eng2.drive()
        self.assertEqual(out["did"], [])
        recs = Journal(self.journal).records
        self.assertEqual(
            sum(1 for r in recs if r["type"] == ACTION_EXECUTED), 1)

    def test_crash_after_side_effect_replays_honestly(self):
        """Kill between the side effect and the ActionExecuted record.

        Honest at-least-once: the side effect runs twice (visible in the
        runs log), but the observable outcome (the .done file) is written
        exactly once and only one ActionExecuted is journaled.
        """
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=_child_crash_after_side_effect,
                                    args=(self.journal, self.outcomes, q))
        p.start()
        self.assertEqual(q.get(timeout=30), "driving")
        p.join(30)
        self.assertEqual(p.exitcode, 137, "child must die via the crash hook")
        # Restart: replay re-runs the side effect, journals ActionExecuted.
        eng = Engine(self.journal, self.outcomes)
        self.assertEqual(eng.states()["a1"]["status"], "approved")
        self.assertFalse(any(r["type"] == ACTION_EXECUTED
                             for r in eng.journal.records))
        out = eng.drive()
        self.assertIn(("action_executed", "a1"), out["did"])
        self.assertEqual(eng.states()["a1"]["status"], "executed")
        runs = open(os.path.join(self.outcomes, "side_effect_runs.log"),
                    encoding="utf-8").read().strip().split("\n")
        self.assertEqual(len(runs), 2,
                         "at-least-once replay must be honest: "
                         "the side effect ran twice")
        recs = Journal(self.journal).records
        self.assertEqual(
            sum(1 for r in recs if r["type"] == ACTION_EXECUTED), 1)
        done = _read_json(os.path.join(self.outcomes, "key-a1.done"))
        self.assertEqual(done["outcome"], "ACTION_PERFORMED")

    def test_concurrent_drivers_serialize(self):
        eng = Engine(self.journal, self.outcomes)
        eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)
        eng.grant("a1", "human-1")
        q = multiprocessing.Queue()
        procs = [multiprocessing.Process(target=_concurrent_driver,
                                         args=(self.journal, self.outcomes,
                                               q))
                 for _ in range(4)]
        for p in procs:
            p.start()
        for _ in procs:
            self.assertEqual(q.get(timeout=60), "done")
        for p in procs:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        recs = Journal(self.journal).records
        self.assertEqual(
            sum(1 for r in recs if r["type"] == ACTION_EXECUTED), 1)
        self.assertTrue(verify_journal(self.journal)[0])
        self.assertTrue(
            os.path.exists(os.path.join(self.outcomes, "key-a1.done")))


class DeterminismGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")
        self._saved = os.environ.get("GOV_DURABLE_CODE_VERSION")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("GOV_DURABLE_CODE_VERSION", None)
        else:
            os.environ["GOV_DURABLE_CODE_VERSION"] = self._saved

    def _request(self):
        eng = Engine(self.journal, self.outcomes)
        eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)

    def test_code_version_change_blocks_replay_without_mutation(self):
        os.environ["GOV_DURABLE_CODE_VERSION"] = "v1-test"
        self._request()
        with open(self.journal, "rb") as f:
            before = f.read()
        os.environ["GOV_DURABLE_CODE_VERSION"] = "v2-changed"
        with self.assertRaises(NonDeterministicReplayError):
            Engine(self.journal, self.outcomes)
        with open(self.journal, "rb") as f:
            after = f.read()
        self.assertEqual(before, after,
                         "the blocked replay must leave the journal "
                         "byte-identical")

    def test_replay_under_same_code_version_ok(self):
        os.environ["GOV_DURABLE_CODE_VERSION"] = "pinned-test"
        eng = Engine(self.journal, self.outcomes)
        eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)
        eng.grant("a1", "human-1")
        eng2 = Engine(self.journal, self.outcomes)
        eng2.drive()
        self.assertEqual(eng2.states()["a1"]["status"], "executed")


class TimerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")
        self.eng = Engine(self.journal, self.outcomes)

    def _req(self, aid="a1", ttl=1):
        return self.eng.request(aid, requester="agent-1",
                                packet_digest="p" * 64,
                                action_kind="default",
                                idempotency_key="key-%s" % aid,
                                ttl_seconds=ttl)

    def _fire_at(self, aid="a1"):
        return next(r["body"]["fire_at"] for r in self.eng.journal.records
                    if r["type"] == "TimerStarted"
                    and r["body"].get("approval_id") == aid)

    def test_timer_fires_and_grant_after_expiry_refused(self):
        self._req()
        out = self.eng.drive(now=self._fire_at() + 10)
        self.assertIn(("timer_fired", "a1"), out["did"])
        self.assertEqual(out["states"]["a1"]["status"], "expired")
        with self.assertRaises(GrantRefused):
            self.eng.grant("a1", "human-1")

    def test_timer_survives_restart(self):
        self._req(ttl=100)
        fire_at = self._fire_at()
        # "Restart": brand-new engine over the same journal.
        eng2 = Engine(self.journal, self.outcomes)
        self.assertEqual(eng2.states()["a1"]["status"], "pending")
        out = eng2.drive(now=fire_at + 1)
        self.assertIn(("timer_fired", "a1"), out["did"])
        self.assertEqual(eng2.states()["a1"]["status"], "expired")

    def test_timer_not_fired_before_deadline(self):
        self._req(ttl=100)
        out = self.eng.drive(now=self._fire_at() - 50)
        self.assertEqual(out["states"]["a1"]["status"], "pending")

    def test_timer_fired_recorded_once(self):
        self._req(ttl=1)
        fire_at = self._fire_at()
        self.eng.drive(now=fire_at + 10)
        self.eng.drive(now=fire_at + 20)
        recs = Journal(self.journal).records
        self.assertEqual(sum(1 for r in recs if r["type"] == "TimerFired"), 1)


class AuditCrossRefTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")

    def test_workflow_started_binds_audit_digest(self):
        appended = []

        def fake_audit(entry):
            appended.append(entry)
            return {"hash": "audit-chain-digest-1"}

        eng = Engine(self.journal, self.outcomes, audit_append=fake_audit)
        eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)
        self.assertEqual(len(appended), 1)
        self.assertEqual(eng.states()["a1"]["audit_hash"],
                         "audit-chain-digest-1")
        started = next(r for r in eng.journal.records
                       if r["type"] == "WorkflowStarted")
        self.assertEqual(started["body"]["audit_hash"], "audit-chain-digest-1")

    def test_find_audit_orphans(self):
        eng = Engine(self.journal, self.outcomes)
        eng.request("a1", requester="agent-1", packet_digest="p" * 64,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)
        entries = [{"kind": "durable_workflow_started", "approval_id": "a1"},
                   {"kind": "durable_workflow_started",
                    "approval_id": "ghost"},
                   {"kind": "other", "approval_id": "ghost2"}]
        orphans = find_audit_orphans(entries, eng.journal)
        self.assertEqual([o["approval_id"] for o in orphans], ["ghost"])


class CrossProcessRaceTest(unittest.TestCase):
    """grant()/deny() re-check under the journal's mutation mutex.

    A second "process" (a separate Journal handle appending directly,
    exactly what another OS process would do) transitions the approval
    between this engine's read and its write. The transition must be
    refused loudly and the journal left untouched — never a grant
    journaled on an expired approval.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")
        self.eng = Engine(self.journal, self.outcomes)
        self.eng.request("a1", requester="agent-1",
                         packet_digest="p" * 64, action_kind="default",
                         idempotency_key="key-a1", ttl_seconds=60)

    def _types(self):
        return [r["type"] for r in Journal(self.journal).records]

    def test_grant_loses_to_concurrent_timer_fire(self):
        # Another process fires the expiry timer first.
        other = Journal(self.journal)
        other.append("TimerFired",
                     {"approval_id": "a1", "fired_at": 9999999999})
        with self.assertRaises(GrantRefused):
            self.eng.grant("a1", "human-1")
        types = self._types()
        self.assertNotIn("ApprovalGranted", types)
        self.assertEqual(types.count("TimerFired"), 1)

    def test_deny_loses_to_concurrent_grant(self):
        other = Journal(self.journal)
        other.append("ApprovalGranted",
                     {"approval_id": "a1", "approver": "human-9"})
        with self.assertRaises(GrantRefused):
            self.eng.deny("a1", "human-1", reason="too late")
        types = self._types()
        self.assertNotIn("ApprovalDenied", types)
        self.assertEqual(types.count("ApprovalGranted"), 1)

    def test_grant_still_works_when_no_race(self):
        self.eng.grant("a1", "human-1")
        self.assertIn("ApprovalGranted", self._types())


class PacketDigestPinningTest(unittest.TestCase):
    """The engine pins the caller-supplied packet digest immutably.

    The digest is opaque to the engine: the caller contract (see module
    docstring) requires it to be the v5 canonical approval-packet
    digest, exactly as stored on the queue record. What this test
    proves is the engine's half of the binding — the digest is stored
    byte-identical, survives restart, and can never be altered by
    later records. (Nothing here proves the caller passed the RIGHT
    digest; that belongs to the queue-integration layer.)
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="da-")
        self.journal = os.path.join(self.tmp, "wf.journal")
        self.outcomes = os.path.join(self.tmp, "outcomes")

    def _v5_digest(self, record):
        from gov.approvals import canonical_packet, _packet_digest
        return _packet_digest(canonical_packet(record))

    def test_pinned_digest_is_byte_identical_and_immutable(self):
        record = {"tool": "deploy", "args": {"target": "prod"},
                  "agent_id": "agent-1", "role": "deployer",
                  "principal": "agent-1", "policy_id": "p1",
                  "policy_version": 3, "packet_risk_score": 42,
                  "preview": "deploy to prod"}
        digest = self._v5_digest(record)
        self.assertEqual(len(digest), 64)
        eng = Engine(self.journal, self.outcomes)
        eng.request("a1", requester="agent-1", packet_digest=digest,
                    action_kind="default", idempotency_key="key-a1",
                    ttl_seconds=60)
        # A different digest on another workflow binds differently —
        # the engine never normalizes or ignores the binding.
        other = self._v5_digest(dict(record, tool="undeploy"))
        self.assertNotEqual(other, digest)
        eng.request("a2", requester="agent-1", packet_digest=other,
                    action_kind="default", idempotency_key="key-a2",
                    ttl_seconds=60)
        # Restart: the pinned digests are unchanged and bound to the
        # right approvals.
        eng2 = Engine(self.journal, self.outcomes)
        started = {r["body"]["approval_id"]: r["body"]["packet_digest"]
                   for r in eng2.journal.records
                   if r["type"] == "WorkflowStarted"}
        self.assertEqual(started, {"a1": digest, "a2": other})


if __name__ == "__main__":
    unittest.main()
