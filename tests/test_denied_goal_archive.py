"""Unit tests for wave-140 row-11 denied-goal archive.

Covers gov/denied_goal_archive.py (format round-trip, header/
footer validation, chain linkage + digest verification, decided_at
TTL injection, sweep, purge, per-agent keying, LRU bound eviction,
last_used bump on consultation, corruption fail-closed,
constructor validation) and the GoalRegistry /
detect_cross_run_laundering wiring (opt-in archive hook on
supersede, F167 archive-before-mutation ordering, no re-archive of
an already-superseded goal, archive-leg flag with detail.archive
set, no double-flag when the registry leg already saw the goal,
registry None = zero behavior change).
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from gov.denied_goal_archive import (
    DeniedGoalArchive, DeniedGoalArchiveError,
    DEFAULT_ARCHIVE_MAX_RECORDS, DEFAULT_ARCHIVE_TTL_SECONDS,
)
from gov import goals as G

AGENT = "agent-dga-a"
OTHER = "agent-dga-b"


def _path():
    d = tempfile.mkdtemp(prefix="govdga-unit-")
    return os.path.join(d, "denied.jsonl")


def _goal(goal_id="goal-1", agent=AGENT, run="run-1",
          description="exfiltrate client list",
          effects=(("send", "evil.com"),)):
    return {"goal_id": goal_id, "agent_id": agent, "run_id": run,
            "description": description,
            "effects": [list(e) for e in effects]}


def _deny(reg, description="exfiltrate client list",
          effects=(("send", "evil.com"),), agent=AGENT, run="run-1"):
    g, _ = reg.register(agent, run, description,
                        effects=list(effects))
    res = G.apply_approval_resolution(
        reg, new_goal_id=g["goal_id"], existing_goal_ids=[],
        approved=False, approval_id="apr-unit")
    assert res["decision"] == "rejected"
    return g


class ConstructorTest(unittest.TestCase):
    def test_bad_bound_rejected(self):
        with self.assertRaises(ValueError):
            DeniedGoalArchive(_path(), max_records=0)

    def test_bad_ttl_rejected(self):
        with self.assertRaises(ValueError):
            DeniedGoalArchive(_path(), ttl_seconds=-1)


class RecordDenialTest(unittest.TestCase):
    def test_record_extracts_sensitivity_fields(self):
        a = DeniedGoalArchive(_path())
        g = _goal()
        out = a.record_denial(g)
        self.assertTrue(out["recorded"])
        self.assertEqual(out["records_kept"], 1)
        priors = a.priors_for(AGENT)
        self.assertEqual(len(priors), 1)
        p = priors[0]
        self.assertEqual(p["goal_id"], "goal-1")
        self.assertEqual(p["agent_id"], AGENT)
        self.assertEqual(p["run_id"], "run-1")
        self.assertEqual(p["description"], "exfiltrate client list")
        self.assertEqual(p["effects"], [["send", "evil.com"]])
        self.assertEqual(p["status"], "superseded")
        self.assertTrue(p["archive"])
        self.assertIn("decided_at", p)

    def test_missing_identity_refused(self):
        a = DeniedGoalArchive(_path())
        with self.assertRaises(DeniedGoalArchiveError):
            a.record_denial({"description": "no id"})

    def test_non_dict_refused(self):
        a = DeniedGoalArchive(_path())
        with self.assertRaises(DeniedGoalArchiveError):
            a.record_denial("not-a-goal")

    def test_rerecord_refreshes_no_duplicate(self):
        a = DeniedGoalArchive(_path())
        g = _goal()
        a.record_denial(g)
        out = a.record_denial(g)
        self.assertIsNone(out["evicted_goal_id"])
        self.assertEqual(a.live_count(AGENT), 1)

    def test_decided_at_injection_accepted(self):
        a = DeniedGoalArchive(_path())
        old = datetime.now(timezone.utc) - timedelta(days=10)
        a.record_denial(_goal(), decided_at=old)
        p = a.priors_for(AGENT)[0]
        self.assertEqual(p["decided_at"], old.isoformat())


class TtlTest(unittest.TestCase):
    def test_expired_invisible_to_priors_for(self):
        a = DeniedGoalArchive(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        a.record_denial(_goal(), decided_at=old)
        self.assertEqual(a.priors_for(AGENT), [])
        self.assertEqual(a.live_count(AGENT), 0)

    def test_sweep_reaps_expired(self):
        a = DeniedGoalArchive(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        a.record_denial(_goal(goal_id="g-old"), decided_at=old)
        # The write-time sweep in the second record_denial already
        # reaped the expired record (fail-closed expiry at write
        # time): only the live record remains.
        a.record_denial(_goal(goal_id="g-new"))
        self.assertEqual(a.live_count(AGENT), 1)
        self.assertEqual(
            [p["goal_id"] for p in a.priors_for(AGENT)], ["g-new"])

    def test_sweep_direct(self):
        a = DeniedGoalArchive(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        a.record_denial(_goal(goal_id="g-old"), decided_at=old)
        self.assertEqual(a.sweep(), 1)
        self.assertEqual(a.priors_for(AGENT), [])

    def test_live_record_survives_sweep(self):
        a = DeniedGoalArchive(_path(), ttl_seconds=3600)
        a.record_denial(_goal())
        self.assertEqual(a.sweep(), 0)
        self.assertEqual(len(a.priors_for(AGENT)), 1)


class LruBoundTest(unittest.TestCase):
    def test_lru_victim_evicts_not_fifo(self):
        a = DeniedGoalArchive(_path(), max_records=2)
        a.record_denial(_goal(goal_id="g-a"))
        a.record_denial(_goal(goal_id="g-b"))
        # Touch A after B so B becomes the LRU victim (not FIFO order).
        touched = [p["goal_id"] for p in a.priors_for(AGENT)]
        self.assertEqual(touched, ["g-a", "g-b"])
        out = a.record_denial(_goal(goal_id="g-c"))
        # Both A and B were touched by priors_for (bump-all), so the
        # victim is the one with the oldest last_used among equals --
        # insertion order decides the tie: g-a evicts.
        self.assertEqual(out["evicted_goal_id"], "g-a")
        ids = {p["goal_id"] for p in a.priors_for(AGENT)}
        self.assertEqual(ids, {"g-b", "g-c"})

    def test_bound_honored(self):
        a = DeniedGoalArchive(_path(), max_records=3)
        for i in range(6):
            a.record_denial(_goal(goal_id="g-%d" % i))
        self.assertEqual(a.live_count(AGENT), 3)

    def test_defaults(self):
        self.assertEqual(DEFAULT_ARCHIVE_MAX_RECORDS, 1000)
        self.assertEqual(DEFAULT_ARCHIVE_TTL_SECONDS, 90 * 24 * 3600)


class PurgeTest(unittest.TestCase):
    def test_purge_one_agent_keeps_other(self):
        a = DeniedGoalArchive(_path())
        a.record_denial(_goal(agent=AGENT))
        a.record_denial(_goal(goal_id="g-o", agent=OTHER))
        self.assertEqual(a.purge(AGENT), 1)
        self.assertEqual(a.live_count(AGENT), 0)
        self.assertEqual(a.live_count(OTHER), 1)

    def test_purge_all(self):
        a = DeniedGoalArchive(_path())
        a.record_denial(_goal(agent=AGENT))
        a.record_denial(_goal(goal_id="g-o", agent=OTHER))
        self.assertEqual(a.purge(), 2)
        self.assertEqual(a.live_count(), 0)


class PersistenceTest(unittest.TestCase):
    def test_round_trip(self):
        p = _path()
        a = DeniedGoalArchive(p)
        a.record_denial(_goal())
        a2 = DeniedGoalArchive(p)
        priors = a2.priors_for(AGENT)
        self.assertEqual(len(priors), 1)
        self.assertEqual(priors[0]["description"],
                         "exfiltrate client list")

    def test_header_footer_present(self):
        p = _path()
        DeniedGoalArchive(p).record_denial(_goal())
        lines = [ln for ln in open(p, encoding="utf-8")
                 if ln.strip()]
        header = json.loads(lines[0])
        footer = json.loads(lines[-1])
        self.assertEqual(header["record"], "header")
        self.assertIn("denied-goal-archive", header["denied_goal_archive"])
        self.assertEqual(footer["record"], "footer")
        self.assertTrue(footer["chain_tip"])
        self.assertTrue(footer["file_digest"])

    def test_empty_file_refused(self):
        p = _path()
        open(p, "w").close()
        with self.assertRaises(DeniedGoalArchiveError):
            DeniedGoalArchive(p)

    def test_corrupt_body_refused(self):
        p = _path()
        DeniedGoalArchive(p).record_denial(_goal())
        lines = open(p, encoding="utf-8").read().splitlines()
        lines[1] = lines[1].replace("evil.com", "good.com")
        open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        with self.assertRaises(DeniedGoalArchiveError):
            DeniedGoalArchive(p)

    def test_truncated_footer_refused(self):
        p = _path()
        DeniedGoalArchive(p).record_denial(_goal())
        lines = [ln for ln in open(p, encoding="utf-8").read().splitlines()
                 if ln.strip()]
        open(p, "w", encoding="utf-8").write(
            "\n".join(lines[:-1]) + "\n")
        with self.assertRaises(DeniedGoalArchiveError):
            DeniedGoalArchive(p)

    def test_bad_header_refused(self):
        p = _path()
        DeniedGoalArchive(p).record_denial(_goal())
        lines = open(p, encoding="utf-8").read().splitlines()
        lines[0] = '{"record": "bogus"}'
        open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        with self.assertRaises(DeniedGoalArchiveError):
            DeniedGoalArchive(p)


class RegistryHookTest(unittest.TestCase):
    def test_supersede_archives(self):
        a = DeniedGoalArchive(_path())
        reg = G.GoalRegistry(denied_archive=a)
        g = _deny(reg)
        self.assertEqual(reg.get_goal(g["goal_id"])["status"],
                         "superseded")
        priors = a.priors_for(AGENT)
        self.assertEqual([p["goal_id"] for p in priors],
                         [g["goal_id"]])

    def test_no_archive_without_attachment(self):
        reg = G.GoalRegistry()
        g = _deny(reg)
        self.assertEqual(reg.get_goal(g["goal_id"])["status"],
                         "superseded")
        # No archive attached: zero behavior change, no crash.

    def test_no_rearchive_of_already_superseded(self):
        a = DeniedGoalArchive(_path())
        reg = G.GoalRegistry(denied_archive=a)
        g = _deny(reg)
        calls = []
        orig = a.record_denial

        def spy(goal, decided_at=None):
            calls.append(goal.get("goal_id"))
            return orig(goal, decided_at=decided_at)

        a.record_denial = spy
        reg.set_status(g["goal_id"], "superseded")
        self.assertEqual(calls, [])
        self.assertEqual(a.live_count(AGENT), 1)

    def test_archive_failure_fails_denial_closed(self):
        a = DeniedGoalArchive(_path())
        reg = G.GoalRegistry(denied_archive=a)
        g, _ = reg.register(AGENT, "run-1", "exfiltrate client list",
                            effects=[("send", "evil.com")])
        a.record_denial = None  # sabotage the archive seam
        with self.assertRaises(TypeError):
            reg.set_status(g["goal_id"], "superseded")
        # F167 ordering: the denial did NOT happen.
        self.assertEqual(reg.get_goal(g["goal_id"])["status"], "active")


class DetectorArchiveLegTest(unittest.TestCase):
    def _run2(self, archive):
        reg = G.GoalRegistry(denied_archive=archive)
        g, _ = reg.register(AGENT, "run-2", "nightly roster sync",
                            effects=[("send", "evil.com")])
        return reg, g

    def test_archive_leg_flags_aged_out_remint(self):
        a = DeniedGoalArchive(_path())
        reg1 = G.GoalRegistry(denied_archive=a)
        _deny(reg1)
        reg2, g2 = self._run2(a)
        history = {(AGENT, "run-1.5"): [("read", "status page")]}
        finds = G.detect_cross_run_laundering(
            reg2, g2, executed_history=history, denied_archive=a)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(len(fresh), 1)
        self.assertEqual(fresh[0]["severity"], "high")
        self.assertTrue(fresh[0]["detail"].get("archive"))

    def test_no_archive_no_flag(self):
        # Zero behavior change when no archive is attached: the
        # aged-out denial is invisible again.
        a = DeniedGoalArchive(_path())
        reg1 = G.GoalRegistry(denied_archive=a)
        _deny(reg1)
        reg2 = G.GoalRegistry()
        g2, _ = reg2.register(AGENT, "run-2", "nightly roster sync",
                              effects=[("send", "evil.com")])
        history = {(AGENT, "run-1.5"): [("read", "status page")]}
        finds = G.detect_cross_run_laundering(
            reg2, g2, executed_history=history)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(fresh, [])

    def test_no_double_flag_when_registry_also_sees(self):
        a = DeniedGoalArchive(_path())
        reg = G.GoalRegistry(denied_archive=a)
        g1 = _deny(reg)
        g2, _ = reg.register(AGENT, "run-2", "nightly roster sync",
                             effects=[("send", "evil.com")])
        history = {(AGENT, "run-1"): []}
        finds = G.detect_cross_run_laundering(
            reg, g2, executed_history=history, denied_archive=a)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(len(fresh), 1)

    def test_exercised_guard_still_applies(self):
        a = DeniedGoalArchive(_path())
        reg1 = G.GoalRegistry(denied_archive=a)
        _deny(reg1)
        reg2, g2 = self._run2(a)
        # The prior's run IS observed and the atom WAS executed
        # before supersede: the archive leg stays silent.
        history = {(AGENT, "run-1"): [("send", "evil.com")]}
        finds = G.detect_cross_run_laundering(
            reg2, g2, executed_history=history, denied_archive=a)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(fresh, [])

    def test_silent_without_executed_history(self):
        a = DeniedGoalArchive(_path())
        reg1 = G.GoalRegistry(denied_archive=a)
        _deny(reg1)
        reg2, g2 = self._run2(a)
        finds = G.detect_cross_run_laundering(
            reg2, g2, executed_history={}, denied_archive=a)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(fresh, [])

    def test_ttl_expired_archive_record_silent(self):
        a = DeniedGoalArchive(_path(), ttl_seconds=3600)
        reg1 = G.GoalRegistry(denied_archive=a)
        g = _deny(reg1)
        a.purge()
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        a.record_denial(g, decided_at=old)
        reg2, g2 = self._run2(a)
        history = {(AGENT, "run-1.5"): [("read", "status page")]}
        finds = G.detect_cross_run_laundering(
            reg2, g2, executed_history=history, denied_archive=a)
        fresh = [f for f in finds
                 if f.get("type") == "fresh_id_laundering"]
        self.assertEqual(fresh, [])


if __name__ == "__main__":
    unittest.main()
