#!/usr/bin/env python3
"""Unit tests for gov.reference_time and the per-cycle atomic
reference time in gov.bundle_refresh (wave-273 lane B, phase 2).

The TUF pattern, reimplemented stdlib-only: one clock sample per
refresh cycle; every expiry check in the cycle runs against that
single reference time. These tests pin:

  - AtomicClock samples the source exactly once per sample() and
    serves the frozen value to every caller until re-sampled;
  - calling before sample() is a loud ValueError, not a None;
  - BundleRefresher.refresh() samples the clock exactly once and
    evaluates root/timestamp/snapshot/targets expiry against the
    same reference, even with a clock that advances sharply
    between checks (the skew-consistency property);
  - the per-cycle reference is cleared after refresh() (no leakage
    into the next cycle).

Deterministic (fixed seeds, fixed clocks); stdlib only plus
gov.signing for the refresh fixtures.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import reference_time as rt
from gov import bundle_refresh as br
from gov import bundle_rsl as rsl
from gov.signing import Ed25519Signer
import gov.ed25519 as _ed


class CountingSource(object):
    """A clock source that counts samples and advances per call."""

    def __init__(self, start, step):
        self.calls = 0
        self.current = start
        self.step = step

    def __call__(self):
        self.calls += 1
        value = self.current
        self.current = self.current + self.step
        return value


class TestAtomicClock(unittest.TestCase):

    def test_sample_once_serves_many_callers(self):
        src = CountingSource(1000, 500)
        clock = rt.AtomicClock(src)
        clock.sample()
        self.assertEqual([clock(), clock(), clock()], [1000, 1000, 1000])
        # One sample for the cycle, however many callers.
        self.assertEqual(src.calls, 1)

    def test_resample_next_cycle(self):
        src = CountingSource(1000, 500)
        clock = rt.AtomicClock(src)
        clock.sample()
        first = clock()
        clock.sample()  # next cycle: a fresh sample
        second = clock()
        self.assertEqual((first, second), (1000, 1500))
        self.assertEqual(src.calls, 2)

    def test_call_before_sample_raises(self):
        clock = rt.AtomicClock(lambda: 1)
        with self.assertRaises(ValueError):
            clock()

    def test_non_callable_source_refused(self):
        with self.assertRaises(TypeError):
            rt.AtomicClock(123)

    def test_frozen(self):
        clock = rt.frozen(4242)
        self.assertEqual(clock(), 4242)
        self.assertEqual(clock.value, 4242)

    def test_value_none_before_sample(self):
        clock = rt.AtomicClock(lambda: 7)
        self.assertIsNone(clock.value)
        clock.sample()
        self.assertEqual(clock.value, 7)


# ---------------------------------------------------------------------------
# BundleRefresher per-cycle atomicity
# ---------------------------------------------------------------------------

def _signers():
    return {
        "a": Ed25519Signer(b"\x11" * 32),
        "b": Ed25519Signer(b"\x22" * 32),
        "ts": Ed25519Signer(b"\x33" * 32),
    }


DECLARED = {"a": "kid-alpha", "b": "kid-beta", "ts": "kid-ts"}


def _keys_doc(kids):
    signers = _signers()
    return {DECLARED[k]: {"keytype": "ed25519",
                         "keyval": {"public": signers[k].public_key.hex()}}
            for k in kids}


class TestRefreshAtomicTime(unittest.TestCase):
    """One clock sample per refresh(); all expiry checks in the cycle
    run against it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="g273-reftime-")
        self.signers = _signers()
        self.files = {}
        # Chain expiry far in the future for the default tests.
        self.now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self._build_chain(expires=self.now + timedelta(days=365))

    def tearDown(self):
        self.tmp.cleanup()

    # -- fixture builders (same shape as test_bundle_refresh.py) --------

    def _root_doc(self, version, kids, threshold, expires):
        return {
            "_type": "root", "version": version,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "keys": _keys_doc(["a", "b", "ts"]),
            "roles": {
                "root": {"keyids": [DECLARED[k] for k in kids],
                         "threshold": threshold},
                "timestamp": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "snapshot": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "targets": {"keyids": [DECLARED["ts"]], "threshold": 1},
            },
        }

    def _build_chain(self, expires):
        doc = self._root_doc(1, ["a", "b"], 2, expires)
        self.files[("root", 1)] = br.seal_role(
            "root", doc, [(DECLARED[k], self.signers[k])
                          for k in ("a", "b")])
        tdoc = {"_type": "targets", "version": 1,
                "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "targets": {"skill:x": {"length": 10, "hashes": {
                    "sha256": "ab" * 32}}}}
        self.files[("targets", 1)] = br.seal_role(
            "targets", tdoc, [(DECLARED["ts"], self.signers["ts"])])
        sdoc = {"_type": "snapshot", "version": 1,
                "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "meta": {"targets.json": {
                    "version": 1,
                    "length": len(self.files[("targets", 1)]),
                    "hashes": {"sha256": hashlib.sha256(
                        self.files[("targets", 1)]).hexdigest()}}}}
        self.files[("snapshot", 1)] = br.seal_role(
            "snapshot", sdoc, [(DECLARED["ts"], self.signers["ts"])])
        tsdoc = {"_type": "timestamp", "version": 1,
                 "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "snapshot": {
                     "version": 1,
                     "length": len(self.files[("snapshot", 1)]),
                     "hashes": {"sha256": hashlib.sha256(
                         self.files[("snapshot", 1)]).hexdigest()}}}
        self.files[("timestamp", 1)] = br.seal_role(
            "timestamp", tsdoc, [(DECLARED["ts"], self.signers["ts"])])

    def _fetch(self, role, version):
        key = (role, version)
        if key not in self.files:
            raise br.FetchNotFound("no %s v%s" % (role, version))
        return self.files[key]

    def _refresher(self, **kw):
        kw.setdefault("clock", lambda: self.now)
        return br.BundleRefresher(
            trusted_root_wire=self.files[("root", 1)],
            fetch=self._fetch, cache_dir=self.tmp.name, **kw)

    # -- tests ----------------------------------------------------------

    def test_refresh_samples_clock_exactly_once(self):
        src = CountingSource(self.now, timedelta(seconds=3600))
        r = self._refresher(clock=src)
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        # Two samples total: one when the pinned root is checked at
        # construction (pre-existing), and exactly ONE for the whole
        # refresh cycle, however many expiry checks it runs.
        self.assertEqual(src.calls, 2)

    def test_skew_between_checks_yields_consistent_verdicts(self):
        """Attack: a clock that leaps 10s per call, with every role
        expiring 1s after the cycle's sample. Pre-fix, root is judged
        fresh at t0 while timestamp/snapshot/targets are judged
        expired at t0+10s -- contradictory verdicts inside one
        cycle. Post-fix, all four roles are judged against the
        single cycle sample and the refresh is consistently
        trusted.

        The hostile clock is installed after construction so the
        cycle's single sample lands at t0 (the constructor's own
        pinned-root check is pre-existing behavior, not the cycle).
        """
        self._build_chain(expires=self.now + timedelta(seconds=1))
        r = self._refresher()
        src = CountingSource(self.now, timedelta(seconds=10))
        r._clock = src  # white-box: isolate the cycle's sample
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        expired_warnings = [w for w in report.warnings
                            if "expired" in w]
        self.assertEqual(expired_warnings, [])
        self.assertEqual(src.calls, 1)

    def test_genuinely_expired_chain_not_masked(self):
        """Atomicity must not mask real expiry: a chain expired at
        the single reference time is loudly warned and never
        trusted. (Whether the refresher then reports stale or
        suspended is the pre-existing refresh state machine, not
        this wave's concern.)"""
        self._build_chain(expires=self.now - timedelta(seconds=1))
        r = self._refresher()
        report = r.refresh()
        self.assertNotEqual(report.state, "trusted")
        self.assertTrue(any("expired" in w for w in report.warnings))

    def test_ref_time_cleared_after_refresh(self):
        r = self._refresher()
        r.refresh()
        self.assertIsNone(r._ref_time)

    def test_two_refreshes_sample_again(self):
        src = CountingSource(self.now, timedelta(seconds=1))
        r = self._refresher(clock=src)
        r.refresh()
        r.refresh()
        # 1 construction sample + 1 per refresh cycle.
        self.assertEqual(src.calls, 3)

    def test_shared_atomic_clock_one_sample_for_cycle(self):
        """One AtomicClock sampled once serves an RSL handle AND a
        bundle refresh in the same cycle: the underlying source is
        sampled exactly once for the whole cycle."""
        src = CountingSource(1792000000, 3600)
        epoch_clock = rt.AtomicClock(src)
        epoch_clock.sample()
        # RSL side: the callable `now` (F275) observes the sample.
        seeds = [bytes([0x41]) * 32, bytes([0x42]) * 32]
        principals = {"p1": {"pub": _ed.publickey(seeds[0]).hex()},
                      "p2": {"pub": _ed.publickey(seeds[1]).hex()}}
        wire = rsl.make_rule_file(
            rule_id="rule-rt", bundle="bundle-rt",
            principals=principals,
            delegations=[{"name": "releasers", "key_ids": ["p1", "p2"],
                          "threshold": 1}],
            terminal_key_id="p1", terminal_seed=seeds[0],
            expires=1792000000 + 3600, now=1792000000)
        path = os.path.join(self.tmp.name, "rsl-rt.jsonl")
        log = rsl.open_log(path, wire, epoch_clock)
        log._check_expiry()  # reads the atomic sample
        # Refresh side: a datetime view over the SAME atomic sample.
        r = self._refresher(
            clock=lambda: datetime.fromtimestamp(
                epoch_clock(), tz=timezone.utc))
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        # The whole cycle -- RSL checks + four role expiry checks --
        # ran on ONE sample.
        self.assertEqual(src.calls, 1)


if __name__ == "__main__":
    unittest.main()
