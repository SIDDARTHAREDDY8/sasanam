"""B5 pressure ratchet: per-server listing-churn rate limits (wave-36).

F109 follow-up (named in gov/adapters/mcp_adapter.py::_f109_framing_tag
and workstreams/redteam/F109_REDESIGN.md as unsolved): with tier-1
flags firing on any key-tool description, an adversary who can
influence an MCP server's listing can flood the approval queue with
plausible flagged descriptions (alert fatigue) to bury the real
malicious tool. The mitigation is queue hardening at the listing
gate: per-server listing-churn rate limits + tool-count anomaly
flags, implemented here as gov.adapters.mcp_adapter.ListingChurnGuard
and wired into GovernedMCPClient._validate_and_pin.

Discipline: written FAIL-FIRST against the not-yet-existing guard
(ImportError = red); implementation follows.
"""

import asyncio
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.adapters.core import GovernedBinding  # noqa: E402
from gov.adapters.mcp_adapter import (  # noqa: E402
    DeterministicFakeSession,
    GovernedMCPClient,
    ListingChurnError,
    ListingChurnGuard,
    MetadataPoisoningError,
)


def _run(coro):
    return asyncio.run(coro)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def _hashes(n, tag="v1"):
    return {"tool-%d" % i: "hash-%s-%d" % (tag, i) for i in range(n)}


class TestListingChurnGuardPure(unittest.TestCase):
    """The guard itself: pure apart from the injectable clock."""

    def test_baseline_and_identical_relist_no_trip(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=5, window_s=600, now=clock)
        g.observe("srv-a", _hashes(3))
        clock.advance(10)
        out = g.observe("srv-a", _hashes(3))
        self.assertFalse(out["listing_changed"])
        self.assertFalse(out["tool_count_anomaly"])

    def test_rapid_churn_trips_fail_closed(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=5, window_s=600, now=clock)
        g.observe("srv-a", _hashes(3, "v1"))
        for i in range(2, 7):  # 5 changes: at the limit, no trip yet
            clock.advance(10)
            g.observe("srv-a", _hashes(3, "v%d" % i))
        clock.advance(10)
        with self.assertRaises(ListingChurnError):
            g.observe("srv-a", _hashes(3, "v7"))

    def test_window_expiry_forgives_old_churn(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=2, window_s=100, now=clock)
        g.observe("srv-a", _hashes(2, "v1"))
        clock.advance(10)
        g.observe("srv-a", _hashes(2, "v2"))
        clock.advance(10)
        g.observe("srv-a", _hashes(2, "v3"))  # 2 changes in window: ok
        clock.advance(200)  # window slides past all of them
        g.observe("srv-a", _hashes(2, "v4"))  # no trip
        clock.advance(10)
        g.observe("srv-a", _hashes(2, "v5"))  # still no trip

    def test_tool_count_anomaly_flagged_not_fatal(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=50, window_s=600, now=clock)
        g.observe("srv-a", _hashes(5, "v1"))
        g.note_accepted("srv-a", 5)  # validated: baseline moves
        clock.advance(10)
        out = g.observe("srv-a", _hashes(12, "v2"))
        self.assertTrue(out["tool_count_anomaly"])
        # A count jump is a flag, not a refusal: the listing still
        # processes (the anomaly rides the audit entry).

    def test_modest_growth_not_anomalous(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=50, window_s=600, now=clock)
        g.observe("srv-a", _hashes(20, "v1"))
        g.note_accepted("srv-a", 20)  # validated: baseline moves
        clock.advance(10)
        out = g.observe("srv-a", _hashes(22, "v2"))
        self.assertFalse(out["tool_count_anomaly"])

    def test_per_server_isolation(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=1, window_s=600, now=clock)
        g.observe("srv-a", _hashes(2, "v1"))
        clock.advance(10)
        g.observe("srv-a", _hashes(2, "v2"))  # 1 change: at limit
        clock.advance(10)
        g.observe("srv-b", _hashes(2, "v1"))  # other server: baseline
        clock.advance(10)
        g.observe("srv-b", _hashes(2, "v2"))  # 1 change: at limit, ok
        clock.advance(10)
        with self.assertRaises(ListingChurnError):
            g.observe("srv-a", _hashes(2, "v3"))  # 2nd change: trips

    def test_error_carries_machine_readable_detail(self):
        clock = _Clock()
        g = ListingChurnGuard(max_changes=1, window_s=600, now=clock)
        g.observe("srv-a", _hashes(1, "v1"))
        clock.advance(5)
        g.observe("srv-a", _hashes(1, "v2"))
        clock.advance(5)
        try:
            g.observe("srv-a", _hashes(1, "v3"))
            self.fail("expected ListingChurnError")
        except ListingChurnError as exc:
            self.assertEqual(exc.server_id, "srv-a")
            self.assertEqual(exc.reason, "listing_churn_rate_limited")


class TestSplitAccountingWave37(unittest.TestCase):
    """Wave-37 review: rate limit = attack-pressure accounting,
    anomaly baseline = validated-only."""

    def test_rejected_giant_does_not_pollute_anomaly_baseline(self):
        # The wave-37 exploit: one giant scan-REJECTED listing used to
        # permanently suppress anomaly flags on later accepted floods
        # smaller than the rejected giant. Rejected listings (no
        # note_accepted) must not move the validated baseline.
        clock = _Clock()
        g = ListingChurnGuard(max_changes=50, window_s=600, now=clock)
        g.observe("srv-a", _hashes(1000, "evil"))  # rejected by scan
        clock.advance(10)
        g.observe("srv-a", _hashes(400, "flood-a"))
        g.note_accepted("srv-a", 400)  # validated
        clock.advance(10)
        out = g.observe("srv-a", _hashes(800, "flood-b"))
        self.assertTrue(out["tool_count_anomaly"],
                        "800 vs validated baseline 400 must flag; the "
                        "rejected 1000-tool listing must not suppress it")

    def test_rate_limit_counts_rejected_listings(self):
        # Probing bound preserved: distinct hostile listings that the
        # scan rejects still burn the change-rate budget -- an
        # adaptive adversary does not get unlimited free probes of the
        # heuristic scanner.
        clock = _Clock()
        g = ListingChurnGuard(max_changes=5, window_s=600, now=clock)
        g.observe("srv-a", _hashes(3, "probe-0"))
        for i in range(1, 6):  # 5 changes: at the limit, no trip yet
            clock.advance(10)
            g.observe("srv-a", _hashes(3, "probe-%d" % i))
        clock.advance(10)
        with self.assertRaises(ListingChurnError):
            g.observe("srv-a", _hashes(3, "probe-6"))

    def test_note_accepted_validates_input(self):
        g = ListingChurnGuard(now=_Clock())
        with self.assertRaises(ValueError):
            g.note_accepted("srv-a", -1)
        with self.assertRaises(ValueError):
            g.note_accepted("srv-a", "12")

    def test_identical_rejected_relist_does_not_burn_budget(self):
        # A scanner false positive retried identically: last_hashes
        # tracks presented listings, so identical retries are not
        # change events (no budget burn on a stuck-but-stable server).
        clock = _Clock()
        g = ListingChurnGuard(max_changes=2, window_s=600, now=clock)
        g.observe("srv-a", _hashes(3, "v1"))
        g.note_accepted("srv-a", 3)
        clock.advance(5)
        for _ in range(6):
            out = g.observe("srv-a", _hashes(4, "fp"))
            clock.advance(5)
        self.assertFalse(out["listing_changed"])
        self.assertEqual(out["changes_in_window"], 1)


class TestListingChurnClientWiring(unittest.TestCase):
    """End to end through GovernedMCPClient.list_tools."""

    def _client(self, ctx, session, **kw):
        return GovernedMCPClient(_coder_binding(ctx), session, **kw)

    def _session(self, n=2, tag="v1"):
        return DeterministicFakeSession(
            tool_metadata={"tool-%d" % i: {
                "description": "Does thing %d revision %s." % (i, tag),
                "inputSchema": {"type": "object"}}
                for i in range(n)})

    def test_churned_server_refused_and_audited(self):
        # The flood SHAPE: the server keeps ADDING plausible tools
        # (description changes to existing tools already fail closed
        # via the P2 rug-pull guard; additions are the churn vector).
        # Each new listing passes validation, so churn accumulates in
        # the guard until the rate limit trips fail-closed.
        ctx = make_run()
        session = self._session()
        client = self._client(
            ctx, session, server_id="notes-svc",
            listing_churn_guard=ListingChurnGuard(
                max_changes=3, window_s=600))
        _run(client.list_tools())  # baseline: tool-0, tool-1
        for i in range(2, 5):
            session._tool_metadata["tool-new-%d" % i] = {
                "description": "Does auxiliary thing %d." % i,
                "inputSchema": {"type": "object"}}
            _run(client.list_tools())  # 3 changes: at the limit
        session._tool_metadata["tool-new-X"] = {
            "description": "Does auxiliary thing X.",
            "inputSchema": {"type": "object"}}
        with self.assertRaises(ListingChurnError):
            _run(client.list_tools())  # 4th change: refused
        decisions = [e.get("decision") for e in ctx["read_log"]()]
        self.assertIn("mcp_listing_churn_limited", decisions)

    def test_normal_use_never_trips(self):
        # call_tool re-lists before every dispatch; identical
        # listings are not churn.
        ctx = make_run()
        session = DeterministicFakeSession(
            results={"read_file": {"ok": True}})
        client = self._client(ctx, session, server_id="notes-svc")
        for _ in range(8):
            _run(client.call_tool("read_file", {"path": "a.txt"}))
        decisions = [e.get("decision") for e in ctx["read_log"]()]
        self.assertNotIn("mcp_listing_churn_limited", decisions)

    def test_guard_is_default_on(self):
        ctx = make_run()
        client = self._client(ctx, DeterministicFakeSession(),
                              server_id="notes-svc")
        self.assertIsInstance(client._churn_guard, ListingChurnGuard)

    def test_tool_count_anomaly_annotates_accept_audit(self):
        ctx = make_run()
        session = self._session(n=3)
        client = self._client(ctx, session, server_id="notes-svc")
        _run(client.list_tools())  # baseline: 3 tools
        # Grow the listing 4x in one step (below any churn count --
        # one change event).
        session._tool_metadata.update(
            {"tool-%d" % i: {"description": "Extra tool %d." % i,
                             "inputSchema": {"type": "object"}}
             for i in range(3, 12)})
        _run(client.list_tools())
        accepts = [e for e in ctx["read_log"]()
                   if e.get("decision") == "mcp_list_tools"]
        self.assertTrue(accepts)
        self.assertTrue(accepts[-1].get("tool_count_anomaly"),
                        "tool-count jump must ride the accept audit")

    def test_rejected_giant_leaves_validated_baseline_untouched(self):
        # End to end through list_tools: a 50-tool hostile listing
        # rejected by the content scan (non-string description --
        # observe() ran first) must not move the validated anomaly
        # baseline. The next accepted 4x growth still flags.
        ctx = make_run()
        session = self._session(n=3)
        client = self._client(ctx, session, server_id="notes-svc")
        _run(client.list_tools())  # baseline: 3 tools, validated
        session._tool_metadata.update(
            {"tool-evil-%d" % i: {"description": 12345,
                                 "inputSchema": {"type": "object"}}
             for i in range(50)})
        with self.assertRaises(MetadataPoisoningError):
            _run(client.list_tools())  # scan rejects; not validated
        for k in [k for k in session._tool_metadata
                  if k.startswith("tool-evil-")]:
            del session._tool_metadata[k]
        session._tool_metadata.update(
            {"tool-%d" % i: {"description": "Extra tool %d." % i,
                             "inputSchema": {"type": "object"}}
             for i in range(3, 12)})
        _run(client.list_tools())
        accepts = [e for e in ctx["read_log"]()
                   if e.get("decision") == "mcp_list_tools"]
        self.assertTrue(accepts)
        self.assertTrue(accepts[-1].get("tool_count_anomaly"),
                        "rejected 50-tool giant must not suppress the "
                        "anomaly flag on 3 -> 12 validated growth")


if __name__ == "__main__":
    unittest.main()
