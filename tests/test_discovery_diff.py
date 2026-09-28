#!/usr/bin/env python3
"""Red-first tests for gov/discovery_diff.py (wave-179 lane E).

osquery-pattern ADAPT: differential scheduled queries
({query, interval, removed: true}) reimplemented in stdlib — no osquery
code, no binary, no linking (pattern only).

Written RED before the implementation (tdd skill): every behavioral
test below must FAIL on the tree without gov/discovery_diff.py
(ModuleNotFoundError), then PASS after. The F197 gap probe class
documents what the CURRENT gov/discovery.py drops — it passes on
current code precisely by demonstrating the miss.
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import discovery
from gov import discovery_diff as dd


def proc(pid, name, cmdline="", exe=""):
    return {"pid": pid, "name": name, "cmdline": cmdline,
            "exe": exe or ("/usr/bin/" + name)}


def port(proto, port, pid=None):
    return {"proto": proto, "port": port, "pid": pid}


def app(name, version):
    return {"name": name, "version": version}


def const_snapshots(*snaps):
    """Collector factory: yields each snapshot dict in order, then repeats
    the last one forever (stable host)."""
    it = iter(snaps)

    def collect():
        try:
            return next(it)
        except StopIteration:
            return snaps[-1]
    return collect


def pack(proc_snaps, *, inventory=(), interval=0, removed=True):
    q = dd.DifferentialQuery(
        "processes", const_snapshots(*proc_snaps),
        interval=interval, removed=removed, unknown_agents=True)
    return dd.HostDiffer([q], inventory=set(inventory))


class AddedRemovedTest(unittest.TestCase):
    def test_added_named_exactly(self):
        """(a) snapshot t0 -> t1 with new binaries: added names EXACTLY
        the new ones, no more, no fewer."""
        d = pack([{1: proc(1, "init"), 2: proc(2, "bash")},
                  {1: proc(1, "init"), 2: proc(2, "bash"),
                   3: proc(3, "evil"), 4: proc(4, "evil2")}],
                 inventory={"init", "bash"})
        d.poll()  # baseline
        r = d.poll()
        self.assertEqual({rec["pid"] for rec in r.added["processes"]},
                         {3, 4})
        self.assertEqual(r.removed["processes"], [])

    def test_first_poll_is_baseline(self):
        """First poll establishes the baseline: nothing reported."""
        d = pack([{1: proc(1, "init"), 9: proc(9, "weird")}],
                 inventory=set())
        r = d.poll()
        self.assertEqual(r.added["processes"], [])
        self.assertEqual(r.removed["processes"], [])
        self.assertEqual(r.unknown_agents, [])

    def test_no_changes_no_findings(self):
        snap = {1: proc(1, "init"), 2: proc(2, "bash")}
        d = pack([snap, dict(snap)], inventory={"init", "bash"})
        d.poll()
        r = d.poll()
        self.assertEqual(r.added["processes"], [])
        self.assertEqual(r.removed["processes"], [])
        self.assertEqual(r.unknown_agents, [])
        self.assertEqual(r.lifecycle_events, [])


class RemovedLifecycleTest(unittest.TestCase):
    def test_removed_reported_as_lifecycle(self):
        """(b) killed binaries between intervals, removed:true ->
        lifecycle events with transition 'removed'."""
        d = pack([{1: proc(1, "init"), 2: proc(2, "bash"),
                   3: proc(3, "agent")},
                  {1: proc(1, "init")}],
                 inventory={"init", "bash", "agent"}, removed=True)
        d.poll()
        r = d.poll()
        self.assertEqual({rec["pid"] for rec in r.removed["processes"]},
                         {2, 3})
        trans = {(e["transition"], e["record"]["pid"])
                 for e in r.lifecycle_events}
        self.assertEqual(trans, {("removed", 2), ("removed", 3)})
        self.assertTrue(all(e["table"] == "processes"
                            for e in r.lifecycle_events))

    def test_removed_false_suppresses(self):
        """removed:false -> no removed rows, no lifecycle events."""
        d = pack([{1: proc(1, "init"), 2: proc(2, "bash")},
                  {1: proc(1, "init")}],
                 inventory={"init", "bash"}, removed=False)
        d.poll()
        r = d.poll()
        self.assertEqual(r.removed["processes"], [])
        self.assertEqual(r.lifecycle_events, [])


class UnknownAgentTest(unittest.TestCase):
    def test_unregistered_addition_is_unknown_agent(self):
        """(c) added binary NOT in the governed inventory -> an
        unknown-agent finding naming it exactly."""
        d = pack([{1: proc(1, "init")},
                  {1: proc(1, "init"),
                   7: proc(7, "novasync-agent",
                           cmdline="novasync-agent --daemon",
                           exe="/opt/novasync/agent")}],
                 inventory={"init"})
        d.poll()
        r = d.poll()
        self.assertEqual(len(r.unknown_agents), 1)
        f = r.unknown_agents[0]
        self.assertEqual(f["kind"], "unknown_agent")
        self.assertEqual(f["pid"], 7)
        self.assertEqual(f["name"], "novasync-agent")
        self.assertEqual(f["table"], "processes")
        self.assertIn("first_seen", f)

    def test_registered_addition_not_a_finding(self):
        d = pack([{1: proc(1, "init")},
                  {1: proc(1, "init"),
                   8: proc(8, "gov-agent", exe="/opt/gov/agent")}],
                 inventory={"init", "gov-agent", "/opt/gov/agent"})
        d.poll()
        r = d.poll()
        self.assertEqual(len(r.added["processes"]), 1)  # still listed
        self.assertEqual(r.unknown_agents, [])  # ...but not a finding

    def test_inventory_matches_exe_or_name(self):
        d = pack([{1: proc(1, "init")},
                  {1: proc(1, "init"),
                   9: proc(9, "weirdname", exe="/opt/gov/agent")}],
                 inventory={"/opt/gov/agent"})
        d.poll()
        r = d.poll()
        self.assertEqual(r.unknown_agents, [])


class PortsAppsTest(unittest.TestCase):
    def test_listening_port_added_and_removed(self):
        q = dd.DifferentialQuery(
            "listening_ports",
            const_snapshots(
                {("tcp", 80): port("tcp", 80, 100)},
                {("tcp", 80): port("tcp", 80, 100),
                 ("tcp", 443): port("tcp", 443, 101)},
                {("tcp", 443): port("tcp", 443, 101)}),
            interval=0, removed=True)
        d = dd.HostDiffer([q], inventory=set())
        d.poll()
        r = d.poll()
        self.assertEqual([rec["port"] for rec in r.added["listening_ports"]],
                         [443])
        r = d.poll()
        self.assertEqual([rec["port"]
                          for rec in r.removed["listening_ports"]], [80])
        self.assertTrue(any(e["table"] == "listening_ports" and
                            e["transition"] == "removed"
                            for e in r.lifecycle_events))

    def test_app_version_change_is_remove_add(self):
        """osquery differential semantics: a changed row is
        removed(old) + added(new)."""
        q = dd.DifferentialQuery(
            "apps",
            const_snapshots(
                {"agent": app("agent", "1.0")},
                {"agent": app("agent", "2.0")}),
            interval=0, removed=True)
        d = dd.HostDiffer([q], inventory=set())
        d.poll()
        r = d.poll()
        self.assertEqual(
            [(rec["name"], rec["version"])
             for rec in r.removed["apps"]], [("agent", "1.0")])
        self.assertEqual(
            [(rec["name"], rec["version"])
             for rec in r.added["apps"]], [("agent", "2.0")])


class FailClosedTest(unittest.TestCase):
    def test_collector_error_keeps_state(self):
        """A failed collection never shrinks state: no spurious
        removals, error recorded, next good poll diffs cleanly."""
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated /proc read failure")
            return {1: proc(1, "init")}

        q = dd.DifferentialQuery("processes", flaky, interval=0,
                                 removed=True)
        d = dd.HostDiffer([q], inventory={"init"})
        d.poll()                      # baseline ok
        r = d.poll()                  # collector raises
        self.assertEqual(len(r.errors), 1)
        self.assertEqual(r.errors[0]["query"], "processes")
        self.assertEqual(r.removed["processes"], [])  # nothing dropped
        r = d.poll()                  # collector healthy again
        self.assertEqual(r.errors, [])
        self.assertEqual(r.added["processes"], [])
        self.assertEqual(r.removed["processes"], [])


class IntervalTest(unittest.TestCase):
    def test_per_query_interval(self):
        """Queries re-run only after their own interval elapses
        (injectable clock) — cheap by construction, no busy loop."""
        now = {"t": 0.0}
        seen = {"n": 0}

        def collector():
            seen["n"] += 1
            return {1: proc(1, "init")}

        q = dd.DifferentialQuery("processes", collector, interval=100)
        d = dd.HostDiffer([q], inventory=set(),
                          clock=lambda: now["t"])
        d.poll()            # t=0 baseline, runs
        self.assertEqual(seen["n"], 1)
        now["t"] = 50.0
        r = d.poll()        # interval not elapsed: skipped
        self.assertEqual(seen["n"], 1)
        self.assertEqual(r.added["processes"], [])
        now["t"] = 110.0
        d.poll()            # interval elapsed: runs
        self.assertEqual(seen["n"], 2)


class LedgerBridgeTest(unittest.TestCase):
    def test_unknown_agent_reaches_governed_findings(self):
        """The differential's unknown-agent finding flows into the
        discovery ledger and surfaces via unregistered_candidates."""
        d = pack([{1: proc(1, "init")},
                  {1: proc(1, "init"),
                   7: proc(7, "novasync-agent",
                           exe="/opt/novasync/agent")}],
                 inventory={"init"})
        d.poll()
        r = d.poll()
        sigs = dd.to_discovery_signals(r)
        self.assertTrue(sigs)
        tmp = tempfile.mkdtemp(prefix="discdiff-bridge-")
        try:
            ledger = discovery.DiscoveryLedger(
                os.path.join(tmp, "ledger.jsonl"))
            touched = ledger.note_signals(sigs)
            self.assertTrue(touched)
            findings = discovery.unregistered_candidates(ledger)
            self.assertTrue(findings)
            self.assertTrue(all(f["kind"] == "unregistered_agent"
                                for f in findings))
            self.assertIn("unknown_agent_process",
                          findings[0]["signal_kinds"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class F197GapProbeTest(unittest.TestCase):
    """Documents the gap this lane closes in the CURRENT tree.

    gov/discovery.scan_process_list only signals on processes matching
    KNOWN harness regexes. A novel agent binary — no known-harness
    markers — yields ZERO signals: the unknown-agent mission drops it
    silently. These tests PASS on current code precisely by
    demonstrating the miss (filed as F197, closed by this lane's
    differential).
    """

    def test_current_scanner_drops_novel_harness_process(self):
        procs = [(4242, "novasync-agent",
                  "novasync-agent --daemon --port 9917")]
        sigs = discovery.scan_process_list(procs)
        kinds = {s["kind"] for s in sigs}
        self.assertNotIn("agent_process", kinds,
                         "current scanner unexpectedly sees the novel "
                         "harness (gap probe invalid)")

    def test_differential_catches_what_scanner_drops(self):
        d = pack([{1: proc(1, "init")},
                  {1: proc(1, "init"),
                   4242: proc(4242, "novasync-agent",
                              cmdline="novasync-agent --daemon",
                              exe="/opt/novasync/agent")}],
                 inventory={"init"})
        d.poll()
        r = d.poll()
        self.assertEqual(len(r.unknown_agents), 1)
        self.assertEqual(r.unknown_agents[0]["name"], "novasync-agent")


class LiveCollectorSmokeTest(unittest.TestCase):
    """Guarded smoke tests for the stdlib live collectors (skipped
    where /proc is unavailable)."""

    def test_snapshot_processes_sees_self(self):
        if not os.path.isdir("/proc"):
            self.skipTest("no /proc here")
        snap = dd.snapshot_processes()
        self.assertIn(os.getpid(), snap)
        self.assertTrue(snap[os.getpid()]["name"])

    def test_snapshot_listening_ports_shape(self):
        if not os.path.isdir("/proc/net"):
            self.skipTest("no /proc/net here")
        snap = dd.snapshot_listening_ports()
        self.assertIsInstance(snap, dict)
        for key, rec in snap.items():
            proto, port = key
            self.assertIn(proto, ("tcp", "tcp6"))
            self.assertIsInstance(port, int)

    def test_snapshot_apps_shape(self):
        snap = dd.snapshot_apps()
        self.assertIsInstance(snap, dict)


if __name__ == "__main__":
    unittest.main()
