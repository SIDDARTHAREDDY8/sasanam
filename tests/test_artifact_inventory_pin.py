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
        # Same (inventory, pinned_at, key_epoch) -> same pin:
        # recomputation at verify time must match.
        pinned = _pin(["/tmp/a"])
        body = sweep._pinned_body(pinned["pinned_inventory"],
                                  pinned["inventory"],
                                  pinned["pinned_at"],
                                  pinned["key_epoch"])
        self.assertEqual(sweep._inventory_pin_mac(TEST_KEY, body),
                         pinned["pin"])

    def test_pin_records_explicit_override_epoch(self):
        pinned = _pin(["/tmp/a"])
        self.assertEqual(pinned["key_epoch"],
                         sweep.EXPLICIT_KEY_EPOCH)


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


class TestPinCeremonyAudit(unittest.TestCase):
    """Wave-142: the pinning ceremony is auditable -- key epoch is
    MAC-bound into the pin, pin_inventory emits a chained ceremony
    event, and stale pins (rotated epoch, expired TTL) verify as
    stale_pin_epoch, LOUD and fail-closed."""

    def _pin_live(self, roots, **kw):
        return sweep.pin_inventory(roots, **kw)

    def test_live_pin_records_ambient_epoch(self):
        pinned = self._pin_live(["/tmp/a"])
        _, epoch = keyprovider.resolve_active_key()
        self.assertEqual(pinned["key_epoch"], epoch)

    def test_ceremony_event_carries_digest_epoch_ts(self):
        events = []
        pinned = self._pin_live(["/tmp/a", "/tmp/b"],
                                audit=events.append, run_id="cer")
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], sweep.INVENTORY_PINNED_EVENT)
        self.assertEqual(ev["run_id"], "cer")
        self.assertEqual(ev["key_epoch"], pinned["key_epoch"])
        self.assertEqual(ev["pinned_at"], pinned["pinned_at"])
        self.assertEqual(ev["inventory_digest"],
                         sweep.inventory_digest(pinned))
        self.assertTrue(ev["ts"])

    def test_inventory_digest_recomputable(self):
        pinned = self._pin_live(["/tmp/a"])
        d1 = sweep.inventory_digest(pinned)
        d2 = sweep.inventory_digest(dict(pinned))
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)
        # A different inventory digests differently.
        other = self._pin_live(["/tmp/b"])
        self.assertNotEqual(d1, sweep.inventory_digest(other))
        with self.assertRaises(ValueError):
            sweep.inventory_digest({"pinned_inventory": "bogus"})

    def test_rewriting_epoch_breaks_mac(self):
        # The epoch is MAC-bound: swapping it post-ceremony is a
        # forgery, not a freshening.
        pinned = self._pin_live(["/tmp/a"])
        forged = dict(pinned, key_epoch="forged-epoch")
        ok, reason = sweep.verify_inventory_pin(forged)
        self.assertFalse(ok)
        self.assertIn("pin mismatch", reason)

    def test_rotated_epoch_is_stale(self):
        pinned = self._pin_live(["/tmp/a"])
        ok, reason = sweep.verify_inventory_pin(
            pinned, current_epoch="rotated-epoch")
        self.assertFalse(ok)
        self.assertIn("stale_pin_epoch", reason)

    def test_same_epoch_verifies(self):
        pinned = self._pin_live(["/tmp/a"])
        _, epoch = keyprovider.resolve_active_key()
        ok, reason = sweep.verify_inventory_pin(
            pinned, current_epoch=epoch)
        self.assertTrue(ok, reason)

    def test_legacy_pin_without_epoch_fails_closed(self):
        # A wave-141-shaped pin (no key_epoch) cannot prove its
        # ceremony epoch -- fail closed, re-pin.
        pinned = self._pin_live(["/tmp/a"])
        legacy = {k: v for k, v in pinned.items()
                  if k != "key_epoch"}
        ok, reason = sweep.verify_inventory_pin(legacy)
        self.assertFalse(ok)
        self.assertIn("key_epoch", reason)

    def test_ttl_expired_pin_is_stale(self):
        import datetime as _dt
        old_ts = (_dt.datetime.now(_dt.timezone.utc)
                  - _dt.timedelta(days=90)).isoformat()
        real_now = sweep._utcnow_iso
        sweep._utcnow_iso = lambda: old_ts
        try:
            pinned = self._pin_live(["/tmp/a"])
        finally:
            sweep._utcnow_iso = real_now
        # No TTL: the old pin still verifies (TTL is opt-in).
        ok, _ = sweep.verify_inventory_pin(pinned)
        self.assertTrue(ok)
        ok, reason = sweep.verify_inventory_pin(
            pinned, pin_ttl_seconds=30 * 86400)
        self.assertFalse(ok)
        self.assertIn("stale_pin_epoch", reason)
        # A generous TTL passes.
        ok, _ = sweep.verify_inventory_pin(
            pinned, pin_ttl_seconds=365 * 86400)
        self.assertTrue(ok)

    def test_garbage_ttl_fails_closed_never_raises(self):
        pinned = self._pin_live(["/tmp/a"])
        ok, reason = sweep.verify_inventory_pin(
            pinned, pin_ttl_seconds="not-a-number")
        self.assertFalse(ok)
        self.assertIn("stale_pin_epoch", reason)

    def test_report_surfaces_epoch_and_age(self):
        pinned = self._pin_live(["/tmp/a"])
        events = []
        rep = sweep.report_coverage_gaps(
            pinned, [], audit=events.append, run_id="u")
        self.assertEqual(rep["verdict"], "pinned")
        self.assertEqual(rep["key_epoch"], pinned["key_epoch"])
        self.assertIsInstance(rep["pin_age_seconds"], float)
        self.assertGreaterEqual(rep["pin_age_seconds"], 0)
        comps = [e for e in events
                 if e.get("event") == sweep.COVERAGE_COMPLETE_EVENT]
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0]["key_epoch"], pinned["key_epoch"])
        self.assertIsInstance(comps[0]["pin_age_seconds"], float)

    def test_stale_epoch_report_is_loud_full_gap(self):
        # The real rotation scenario at the report layer: same key
        # bytes, new epoch label (the operator rotated the epoch).
        pinned = self._pin_live(["/tmp/a", "/tmp/b"])
        _, epoch = keyprovider.resolve_active_key()
        saved = os.environ.get("GOV_LOG_KEY_EPOCH")
        os.environ["GOV_LOG_KEY_EPOCH"] = epoch + "-rotated"
        try:
            events = []
            rep = sweep.report_coverage_gaps(
                pinned, [], audit=events.append, run_id="u")
        finally:
            if saved is None:
                os.environ.pop("GOV_LOG_KEY_EPOCH", None)
            else:
                os.environ["GOV_LOG_KEY_EPOCH"] = saved
        self.assertEqual(rep["verdict"], "unverifiable")
        self.assertIn("stale_pin_epoch", rep["reason"])
        self.assertEqual(rep["presented_key_epoch"], epoch)
        evs = [e for e in events
               if e.get("event") == sweep.INVENTORY_UNVERIFIABLE_EVENT]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "LOUD")
        self.assertIn("stale_pin_epoch", evs[0]["reason"])
        # Fail-closed full-gap over the presented declared list.
        self.assertEqual(rep["gaps"], [os.path.realpath("/tmp/a"),
                                       os.path.realpath("/tmp/b")])
        self.assertEqual(rep["covered"], [])


if __name__ == "__main__":
    unittest.main()
