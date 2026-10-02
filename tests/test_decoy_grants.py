"""Unit tests for gov/decoy_grants (wave-276 decoy-grant canaries).

Public-seam tests only: DecoyRegistry (is_decoy / is_decoy_identifier /
check_invocation / scan_text), trip_event, and the module constants.
Deterministic, stdlib only, no fixtures beyond the registry itself.
"""

import json
import unittest

from gov import decoy_grants as dg


class TestRegistryConstruction(unittest.TestCase):
    def test_defaults_registered(self):
        reg = dg.DecoyRegistry()
        self.assertEqual(len(reg.names), 6)
        self.assertIn("admin_shell", reg.names)

    def test_custom_names_deduped_case_insensitive(self):
        reg = dg.DecoyRegistry(["Admin_Shell", "admin_shell", "my_trap"])
        self.assertEqual(reg.names.count("admin_shell"), 1)
        self.assertIn("my_trap", reg.names)

    def test_empty_registry_matches_nothing(self):
        reg = dg.DecoyRegistry([])
        self.assertFalse(reg.is_decoy("srv", "admin_shell"))
        self.assertEqual(reg.scan_text("call admin_shell"), [])
        self.assertIsNone(reg.check_invocation("srv", "admin_shell"))

    def test_non_string_names_ignored(self):
        reg = dg.DecoyRegistry(["ok_trap", None, 42, "  "])
        self.assertEqual(reg.names, ("ok_trap",))


class TestIsDecoy(unittest.TestCase):
    def setUp(self):
        self.reg = dg.DecoyRegistry()

    def test_exact(self):
        self.assertTrue(self.reg.is_decoy("fileserver", "admin_shell"))

    def test_case_insensitive(self):
        self.assertTrue(self.reg.is_decoy("fileserver", "ADMIN_SHELL"))

    def test_scoped_form(self):
        reg = dg.DecoyRegistry(["fileserver::admin_shell"])
        self.assertTrue(reg.is_decoy("fileserver", "admin_shell"))
        # Scoped decoys do not trip on other servers' bare names.
        self.assertFalse(reg.is_decoy("otherserver", "admin_shell"))

    def test_non_decoy(self):
        self.assertFalse(self.reg.is_decoy("fileserver", "read_file"))

    def test_hostile_inputs_never_raise(self):
        for bad in (None, 42, b"admin_shell", ["admin_shell"], {"t": 1}):
            # Hostile tool values never trip and never raise.
            self.assertFalse(self.reg.is_decoy("srv", bad))
            self.assertIsNone(self.reg.check_invocation("srv", bad))
            # A bare decoy name trips regardless of the server value --
            # even a hostile one -- and never raises.
            self.assertTrue(self.reg.is_decoy(bad, "admin_shell"))

    def test_identifier_form(self):
        self.assertTrue(
            self.reg.is_decoy_identifier("fileserver::admin_shell"))
        self.assertFalse(
            self.reg.is_decoy_identifier("fileserver::read_file"))
        self.assertFalse(self.reg.is_decoy_identifier("not-an-identifier"))
        self.assertFalse(self.reg.is_decoy_identifier(None))


class TestCheckInvocation(unittest.TestCase):
    def setUp(self):
        self.reg = dg.DecoyRegistry()

    def test_trip_shape(self):
        trip = self.reg.check_invocation("fileserver", "admin_shell")
        self.assertEqual(trip["mode"], "context_invocation")
        self.assertEqual(trip["confidence"], 1.0)
        self.assertEqual(trip["confidence"], dg.CONFIDENCE_INVOCATION)
        self.assertEqual(trip["name"], "admin_shell")

    def test_no_trip_for_real_tool(self):
        self.assertIsNone(self.reg.check_invocation("srv", "read_file"))


class TestScanText(unittest.TestCase):
    def setUp(self):
        self.reg = dg.DecoyRegistry()

    def test_direct_mention(self):
        hits = self.reg.scan_text("please call admin_shell now")
        self.assertEqual([h["name"] for h in hits], ["admin_shell"])
        self.assertEqual(hits[0]["confidence"], 0.95)
        self.assertEqual(hits[0]["confidence"], dg.CONFIDENCE_TEXT_MENTION)

    def test_spaced_paraphrase(self):
        hits = self.reg.scan_text("open the internal debug console")
        self.assertEqual([h["name"] for h in hits],
                         ["internal_debug_console"])

    def test_homoglyph(self):
        hits = self.reg.scan_text("run adm1n_shell --all")
        self.assertEqual([h["name"] for h in hits], ["admin_shell"])

    def test_separator_variants(self):
        for text in ("admin-shell", "adminshell", "admin__shell",
                     "ADMIN SHELL"):
            hits = self.reg.scan_text("use %s here" % text)
            self.assertEqual([h["name"] for h in hits], ["admin_shell"],
                             text)

    def test_word_boundary_discipline(self):
        for text in ("xadmin_shell", "myadmin_shellish",
                     "the administrator shelled out"):
            self.assertEqual(self.reg.scan_text(text), [], text)

    def test_deduplicated(self):
        hits = self.reg.scan_text("admin_shell then admin_shell again")
        self.assertEqual(len(hits), 1)

    def test_position_reported(self):
        hits = self.reg.scan_text("xx admin_shell yy")
        (start, end) = hits[0]["position"]
        self.assertTrue(0 <= start < end)

    def test_hostile_inputs(self):
        for bad in (None, 42, b"admin_shell", ["x"]):
            self.assertEqual(self.reg.scan_text(bad), [])
        self.assertEqual(self.reg.scan_text(""), [])


class TestTripEvent(unittest.TestCase):
    def test_event_shape_and_serializable(self):
        reg = dg.DecoyRegistry()
        trip = reg.check_invocation("fileserver", "admin_shell")
        ev = dg.trip_event(trip, server_name="fileserver",
                           tool="admin_shell", grant_jti="jti-1")
        self.assertEqual(ev["event"], "decoy_trip")
        self.assertEqual(ev["code"], "decoy-grant-tripped")
        self.assertEqual(ev["code"], dg.DECOY_TRIP_CODE)
        self.assertEqual(ev["mode"], "context_invocation")
        self.assertEqual(ev["confidence"], 1.0)
        self.assertEqual(ev["decoy"], "admin_shell")
        self.assertEqual(ev["grant_jti"], "jti-1")
        json.dumps(ev, sort_keys=True)  # must not raise

    def test_none_grant_jti_ok(self):
        trip = {"mode": "context_invocation", "confidence": 1.0,
                "name": "admin_shell"}
        ev = dg.trip_event(trip, server_name="s", tool="t", grant_jti=None)
        self.assertIsNone(ev["grant_jti"])


class TestConstants(unittest.TestCase):
    def test_confidence_discipline(self):
        # d034's operating points, kept: invocation is certain, mention
        # is near-certain (word-bounded, never 1.0).
        self.assertEqual(dg.CONFIDENCE_INVOCATION, 1.0)
        self.assertEqual(dg.CONFIDENCE_TEXT_MENTION, 0.95)
        self.assertLess(dg.CONFIDENCE_TEXT_MENTION,
                        dg.CONFIDENCE_INVOCATION)


class TestTripFatigueTracker(unittest.TestCase):
    def test_full_then_compact(self):
        tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=2)
        r1 = tr.note_trip(decoy="admin_shell", agent_key="agent-a", now=10)
        r2 = tr.note_trip(decoy="admin_shell", agent_key="agent-a", now=20)
        r3 = tr.note_trip(decoy="admin_shell", agent_key="agent-a", now=30)
        self.assertTrue(r1["emit_full"] and r1["suppressed"] == 0)
        self.assertTrue(r2["emit_full"] and r2["suppressed"] == 0)
        self.assertFalse(r3["emit_full"])
        self.assertEqual(r3["window_count"], 3)
        self.assertEqual(r3["suppressed"], 1)

    def test_window_rollover_resets(self):
        tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=1)
        tr.note_trip(decoy="d", agent_key="a", now=10)
        r = tr.note_trip(decoy="d", agent_key="a", now=61)
        self.assertTrue(r["emit_full"])
        self.assertEqual(r["window_count"], 1)

    def test_agents_tracked_independently(self):
        tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=1)
        tr.note_trip(decoy="d", agent_key="a", now=10)
        r = tr.note_trip(decoy="d", agent_key="b", now=11)
        self.assertTrue(r["emit_full"])

    def test_decoys_tracked_independently(self):
        tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=1)
        tr.note_trip(decoy="d1", agent_key="a", now=10)
        r = tr.note_trip(decoy="d2", agent_key="a", now=11)
        self.assertTrue(r["emit_full"])

    def test_store_bounded(self):
        tr = dg.TripFatigueTracker(window_s=60, full_events_per_window=5,
                                   max_keys=3)
        for i in range(5):
            tr.note_trip(decoy="d%d" % i, agent_key="a", now=i)
        self.assertLessEqual(len(tr._store), 3)

    def test_bad_config_rejected(self):
        for kw in ({"window_s": 0}, {"full_events_per_window": -1},
                   {"max_keys": True}, {"window_s": "60"}):
            with self.assertRaises(ValueError):
                dg.TripFatigueTracker(**kw)

    def test_hostile_inputs_never_raise(self):
        tr = dg.TripFatigueTracker()
        r = tr.note_trip(decoy=None, agent_key=["x"], now="soon")
        self.assertIn("emit_full", r)


if __name__ == "__main__":
    unittest.main()
