#!/usr/bin/env python3
"""Unit tests for the wave-141 pinned declared inventory
(gov/artifact_sweep.py: pin_inventory / verify_inventory_pin /
pinned report_coverage_gaps).

Seams: the operator pinning ceremony, pin verification (fail-closed,
never raises on malformed input), the three report verdicts
(pinned/unpinned/unverifiable), and the fail-closed full-gap report.
"""

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import artifact_sweep as sweep  # noqa: E402
from gov import keyprovider as keyprovider  # noqa: E402

TEST_KEY = b"wave141-pin-test-key-32bytes!!!!"


def _pin(roots, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return sweep.pin_inventory(roots, **kw)


def _verify(pinned, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return sweep.verify_inventory_pin(pinned, **kw)


class TestPinCeremony(unittest.TestCase):
    def test_pin_round_trip_verifies(self):
        pinned = _pin(["/tmp/a", "/tmp/b"])
        ok, reason = _verify(pinned)
        self.assertTrue(ok, reason)
        self.assertEqual(pinned["pinned_inventory"],
                         sweep.PINNED_INVENTORY_VERSION)
        self.assertEqual(pinned["inventory"],
                         [os.path.realpath("/tmp/a"),
                          os.path.realpath("/tmp/b")])
        self.assertTrue(pinned["pin"])

    def test_pin_resolves_roots(self):
        pinned = _pin(["/tmp/../tmp/c"])
        self.assertEqual(pinned["inventory"],
                         [os.path.realpath("/tmp/c")])

    def test_pin_rejects_non_path(self):
        with self.assertRaises(ValueError):
            _pin(["/tmp/a", 42])

    def test_pin_empty_inventory(self):
        pinned = _pin([])
        ok, reason = _verify(pinned)
        self.assertTrue(ok, reason)
        self.assertEqual(pinned["inventory"], [])

    def test_pin_is_deterministic_for_same_inputs(self):
        # Same (inventory, pinned_at) -> same pin: recomputation at
        # verify time must match.
        pinned = _pin(["/tmp/a"])
        body = sweep._pinned_body(pinned["pinned_inventory"],
                                  pinned["inventory"],
                                  pinned["pinned_at"])
        self.assertEqual(sweep._inventory_pin_mac(TEST_KEY, body),
                         pinned["pin"])


class TestVerifyFailClosed(unittest.TestCase):
    def test_shrunk_list_fails(self):
        pinned = _pin(["/tmp/a", "/tmp/b"])
        shrunk = dict(pinned, inventory=[os.path.realpath("/tmp/a")])
        ok, reason = _verify(shrunk)
        self.assertFalse(ok)
        self.assertIn("pin mismatch", reason)

    def test_extended_list_fails(self):
        pinned = _pin(["/tmp/a"])
        extended = dict(pinned,
                        inventory=[os.path.realpath("/tmp/a"),
                                   os.path.realpath("/tmp/b")])
        ok, _ = _verify(extended)
        self.assertFalse(ok)

    def test_reordered_list_fails(self):
        pinned = _pin(["/tmp/a", "/tmp/b"])
        reordered = dict(pinned, inventory=list(reversed(
            pinned["inventory"])))
        ok, _ = _verify(reordered)
        self.assertFalse(ok)

    def test_tampered_pin_fails(self):
        pinned = _pin(["/tmp/a"])
        bad = dict(pinned, pin="0" * 64)
        ok, _ = _verify(bad)
        self.assertFalse(ok)

    def test_wrong_key_fails(self):
        pinned = _pin(["/tmp/a"])
        ok, _ = sweep.verify_inventory_pin(
            pinned, hmac_key=b"a-different-32byte-test-key!!!!!")
        self.assertFalse(ok)

    def test_tampered_pinned_at_fails(self):
        pinned = _pin(["/tmp/a"])
        bad = dict(pinned, pinned_at="2020-01-01T00:00:00+00:00")
        ok, _ = _verify(bad)
        self.assertFalse(ok)

    def test_malformed_inputs_never_raise(self):
        for bad in (None, [], "pin", 42,
                    {}, {"pin": "x"},
                    {"pinned_inventory": "bogus/9.9",
                     "inventory": [], "pinned_at": "t", "pin": "p"},
                    {"pinned_inventory": sweep.PINNED_INVENTORY_VERSION,
                     "inventory": "not-a-list",
                     "pinned_at": "t", "pin": "p"},
                    {"pinned_inventory": sweep.PINNED_INVENTORY_VERSION,
                     "inventory": ["/tmp/a"],
                     "pinned_at": "t"}):
            ok, reason = _verify(bad)
            self.assertFalse(ok, "input %r verified?!" % (bad,))
            self.assertTrue(reason)

    def test_key_unavailable_fails_closed(self):
        pinned = _pin(["/tmp/a"])
        ok, reason = sweep.verify_inventory_pin(pinned, hmac_key=b"")
        self.assertFalse(ok)
        self.assertIn("key unavailable", reason)


class TestCeremonyKeyDiscipline(unittest.TestCase):
    def test_no_key_configured_raises_fail_closed(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GOV_LOG_KEY", "GOV_KEYRING_FILE")}
        old = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(
                    keyprovider.NoKeyConfiguredError):
                sweep.pin_inventory(["/tmp/a"])
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_explicit_key_override(self):
        pinned = sweep.pin_inventory(["/tmp/a"], hmac_key=TEST_KEY)
        ok, _ = sweep.verify_inventory_pin(pinned, hmac_key=TEST_KEY)
        self.assertTrue(ok)


class TestReportVerdicts(unittest.TestCase):
    def _report(self, declared, roots):
        events = []
        rep = sweep.report_coverage_gaps(
            declared, roots, audit=events.append, run_id="u")
        return rep, events

    def _pin_live(self, roots):
        # Pin with the ambient deployment key (tests/__init__.py
        # provisions GOV_LOG_KEY): exercises the real
        # resolve_active_key() path that report_coverage_gaps
        # verifies against.
        return sweep.pin_inventory(roots)

    def test_pinned_valid_reports_pinned_verdict(self):
        pinned = self._pin_live(["/tmp/a", "/tmp/b"])
        rep, events = self._report(pinned, [])
        self.assertEqual(rep["verdict"], "pinned")
        self.assertEqual(rep["gaps"], [os.path.realpath("/tmp/a"),
                                       os.path.realpath("/tmp/b")])
        comps = [e for e in events
                 if e.get("event") == sweep.COVERAGE_COMPLETE_EVENT]
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0]["inventory_verdict"], "pinned")

    def test_unpinned_list_reports_unpinned_verdict(self):
        rep, events = self._report(["/tmp/a"], [])
        self.assertEqual(rep["verdict"], "unpinned")
        self.assertEqual(len(rep["gaps"]), 1)
        comps = [e for e in events
                 if e.get("event") == sweep.COVERAGE_COMPLETE_EVENT]
        self.assertEqual(comps[0]["inventory_verdict"], "unpinned")

    def test_unverifiable_is_loud_full_gap(self):
        pinned = self._pin_live(["/tmp/a", "/tmp/b"])
        shrunk = dict(pinned, inventory=[os.path.realpath("/tmp/a")])
        rep, events = self._report(shrunk, [])
        self.assertEqual(rep["verdict"], "unverifiable")
        # Fail-closed full-gap over the presented declared list.
        self.assertEqual(rep["gaps"], [os.path.realpath("/tmp/a")])
        self.assertEqual(rep["covered"], [])
        evs = [e for e in events
               if e.get("event") == sweep.INVENTORY_UNVERIFIABLE_EVENT]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "LOUD")
        self.assertIn("UNVERIFIABLE", evs[0]["reason"])
        # No coverage_complete summary on the unverifiable path --
        # the unverifiable event IS the terminal evidence.
        comps = [e for e in events
                 if e.get("event") == sweep.COVERAGE_COMPLETE_EVENT]
        self.assertEqual(comps, [])

    def test_pinned_empty_inventory_silent(self):
        pinned = self._pin_live([])
        rep, events = self._report(pinned, [])
        self.assertEqual(rep["verdict"], "pinned")
        self.assertEqual(events, [])

    def test_gap_events_carry_verdict(self):
        pinned = self._pin_live(["/tmp/a"])
        rep, events = self._report(pinned, [])
        gaps = [e for e in events
                if e.get("event") == sweep.COVERAGE_GAP_EVENT]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["inventory_verdict"], "pinned")

    def test_pin_stripped_dict_fails_loud_f182(self):
        # F182: a pin-shaped dict WITHOUT the "pin" key must not be
        # silently reinterpreted as an unpinned inventory of its
        # keys -- it claims the pinned envelope and fails LOUD.
        pinned = self._pin_live(["/tmp/a", "/tmp/b"])
        stripped = {k: v for k, v in pinned.items() if k != "pin"}
        rep, events = self._report(stripped, [])
        self.assertEqual(rep["verdict"], "unverifiable")
        self.assertEqual(rep["gaps"], [os.path.realpath("/tmp/a"),
                                       os.path.realpath("/tmp/b")])
        evs = [e for e in events
               if e.get("event") == sweep.INVENTORY_UNVERIFIABLE_EVENT]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "LOUD")

    def test_dict_keyed_envelope_not_silently_covered_f182(self):
        # F182 worse variant: a dict whose KEYS are covered paths
        # must not report COVERED with verdict "unpinned".
        rep, events = self._report({"/tmp/a": "junk"}, [])
        self.assertEqual(rep["verdict"], "unverifiable")
        self.assertEqual(rep["covered"], [])
        evs = [e for e in events
               if e.get("event") == sweep.INVENTORY_UNVERIFIABLE_EVENT]
        self.assertEqual(len(evs), 1)


if __name__ == "__main__":
    unittest.main()
