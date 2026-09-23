"""Wave-52 P2 unit tests: sterile-cockpit channel taxonomy + window
state machine (gov/sterile.py). Prototype only — no executor
integration. Deterministic (injectable clock), $0.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.sterile import (  # noqa: E402
    ChannelRegistry, WindowPolicy, SterileController, SterilePolicyError,
    CHANNELS)


def _policy(**kw):
    block = [{
        "id": "pay",
        "on_tools": ["payment.*"],
        "suspend": ["web_fetch", "file_read"],
        "close_policy": kw.get("close_policy", "agent_declared"),
        "max_duration_s": kw.get("max_duration_s", 300),
        "rationale": "test window",
    }]
    return WindowPolicy(block)


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class TestTaxonomy(unittest.TestCase):
    def test_default_untrusted(self):
        reg = ChannelRegistry()
        for ch, rec in CHANNELS.items():
            if ch == "approval_decision":
                self.assertTrue(reg.is_trusted(ch))
            else:
                self.assertFalse(reg.is_trusted(ch), ch)

    def test_unknown_channel_fails_closed(self):
        reg = ChannelRegistry()
        with self.assertRaises(KeyError):
            reg.get("nope")

    def test_every_channel_has_rationale(self):
        for ch, rec in CHANNELS.items():
            self.assertTrue(rec["rationale"], ch)
            self.assertIn("executor_mediated", rec)


class TestPolicyValidation(unittest.TestCase):
    def test_unknown_channel_rejected(self):
        with self.assertRaises(SterilePolicyError):
            _policy().__class__([{
                "id": "x", "on_tools": ["a"], "suspend": ["nope"],
                "max_duration_s": 10, "rationale": "r"}])

    def test_trusted_channel_suspension_rejected(self):
        with self.assertRaises(SterilePolicyError):
            WindowPolicy([{
                "id": "x", "on_tools": ["a"],
                "suspend": ["approval_decision"],
                "max_duration_s": 10, "rationale": "r"}])

    def test_missing_expiry_rejected(self):
        with self.assertRaises(SterilePolicyError):
            WindowPolicy([{
                "id": "x", "on_tools": ["a"], "suspend": [],
                "rationale": "r"}])

    def test_bare_star_rejected(self):
        with self.assertRaises(SterilePolicyError):
            WindowPolicy([{
                "id": "x", "on_tools": ["*"], "suspend": [],
                "max_duration_s": 10, "rationale": "r"}])

    def test_duplicate_id_rejected(self):
        with self.assertRaises(SterilePolicyError):
            WindowPolicy([
                {"id": "x", "on_tools": ["a"], "suspend": [],
                 "max_duration_s": 10, "rationale": "r"},
                {"id": "x", "on_tools": ["b"], "suspend": [],
                 "max_duration_s": 10, "rationale": "r"},
            ])

    def test_missing_rationale_rejected(self):
        with self.assertRaises(SterilePolicyError):
            WindowPolicy([{
                "id": "x", "on_tools": ["a"], "suspend": [],
                "max_duration_s": 10}])


class TestWindowLifecycle(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.events = []
        self.ctl = SterileController(
            _policy(), audit=self.events, now=self.clock)

    def test_enter_on_pattern(self):
        evs = self.ctl.maybe_open("payment.send")
        self.assertEqual(evs[0]["event"], "sterile_window_enter")
        self.assertEqual(self.ctl.open_windows(), ["pay"])
        self.assertEqual(self.ctl.maybe_open("read_file"), [])

    def test_reenter_same_id_joins(self):
        self.ctl.maybe_open("payment.send")
        r = self.ctl.maybe_open("payment.refund")
        self.assertEqual(r[0]["reentered"], "pay")
        self.assertEqual(len([e for e in self.events
                              if e["event"] == "sterile_window_enter"]), 1)

    def test_suspension_and_audited_refusal(self):
        self.ctl.maybe_open("payment.send")
        r = self.ctl.check("read_file", "file_read")
        self.assertFalse(r["allowed"])
        self.assertEqual(r["status"], "window_suspended")
        refusals = [e for e in self.events
                    if e["event"] == "window_suspended_refusal"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["channel"], "file_read")
        # Non-suspended channel still allowed.
        self.assertTrue(self.ctl.check("write_file")["allowed"])

    def test_tool_channel_default_mapping(self):
        self.ctl.maybe_open("payment.send")
        r = self.ctl.check("api_call")  # -> web_fetch via TOOL_CHANNELS
        self.assertFalse(r["allowed"])

    def test_agent_declared_close(self):
        self.ctl.maybe_open("payment.send")
        self.ctl.check("read_file", "file_read")
        r = self.ctl.request_close()
        self.assertTrue(r["closed"])
        # Reconcile list holds the refused reads — never marked vetted.
        self.assertEqual(r["reconcile"], [("read_file", "file_read")])
        self.assertNotIn("vetted", r)
        exits = [e for e in self.events
                 if e["event"] == "sterile_window_exit"]
        self.assertEqual(exits[0]["reason"], "closed")

    def test_human_approval_close_denied_without_approval(self):
        ctl = SterileController(
            _policy(close_policy="human_approval"),
            audit=self.events, now=self.clock)
        ctl.maybe_open("payment.send")
        r = ctl.request_close()
        self.assertFalse(r["closed"])
        self.assertEqual(r["reason"], "human_approval_required")
        denied = [e for e in self.events
                  if e["event"] == "window_close_denied"]
        self.assertEqual(len(denied), 1)
        # With approval, the close is granted.
        r2 = ctl.request_close(human_approved=True)
        self.assertTrue(r2["closed"])

    def test_expiry_fails_closed(self):
        self.ctl.maybe_open("payment.send")
        self.clock.t += 301
        expired = self.ctl.tick()
        self.assertEqual(expired, ["pay"])
        self.assertEqual(self.ctl.open_windows(), [])
        exits = [e for e in self.events
                 if e["event"] == "sterile_window_exit"]
        self.assertEqual(exits[0]["reason"], "expired")
        self.assertEqual(exits[0]["task"], "incomplete")
        # Channels resume after expiry.
        self.assertTrue(self.ctl.check("read_file", "file_read")["allowed"])

    def test_close_with_no_window_denied(self):
        r = self.ctl.request_close()
        self.assertFalse(r["closed"])


class TestNesting(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.events = []
        block = [
            {"id": "outer", "on_tools": ["db.*"],
             "suspend": ["file_read"], "max_duration_s": 900,
             "rationale": "outer"},
            {"id": "inner", "on_tools": ["db.drop_table"],
             "suspend": ["web_fetch"], "max_duration_s": 300,
             "rationale": "inner"},
        ]
        self.ctl = SterileController(
            WindowPolicy(block), audit=self.events, now=self.clock)

    def test_union_suspension(self):
        self.ctl.maybe_open("db.migrate")
        self.ctl.maybe_open("db.drop_table")
        self.assertEqual(self.ctl.open_windows(), ["outer", "inner"])
        # Union: both channels suspended.
        self.assertEqual(self.ctl.suspended(), ["file_read", "web_fetch"])
        self.assertFalse(self.ctl.check("read_file", "file_read")["allowed"])
        self.assertFalse(self.ctl.check("api_call", "web_fetch")["allowed"])

    def test_lifo_close_outer_denied(self):
        self.ctl.maybe_open("db.migrate")
        self.ctl.maybe_open("db.drop_table")
        r = self.ctl.request_close(window_id="outer")
        self.assertFalse(r["closed"])
        self.assertEqual(r["reason"], "not_innermost")
        denied = [e for e in self.events
                  if e["event"] == "window_close_denied"]
        self.assertEqual(len(denied), 1)
        # Inner closes fine; then outer.
        self.assertTrue(self.ctl.request_close(window_id="inner")["closed"])
        self.assertTrue(self.ctl.request_close(window_id="outer")["closed"])
        self.assertEqual(self.ctl.open_windows(), [])

    def test_depth_bound(self):
        ctl = SterileController(_policy(), audit=self.events,
                                now=self.clock, max_depth=1)
        ctl.maybe_open("payment.send")
        # A second distinct window would exceed depth 1.
        block = [{"id": "w2", "on_tools": ["payment.*"],
                  "suspend": [], "max_duration_s": 10, "rationale": "r"}]
        ctl2 = SterileController(WindowPolicy(block), audit=self.events,
                                 now=self.clock, max_depth=0)
        r = ctl2.maybe_open("payment.send")
        self.assertEqual(r[0]["event"], "window_nesting_exceeded")


if __name__ == "__main__":
    unittest.main()
