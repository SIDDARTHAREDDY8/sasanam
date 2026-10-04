#!/usr/bin/env python3
"""Wave-326 Lane 4: unit coverage for the TUF section-5 audit of
``gov/bundle_refresh.py``.

Mirrors the break-first probes in ``evals/w326_tufaudit_probes.py`` at
the unittest seam. Two classes of test:

* Conformance pins: behaviors the audit found correct (root N+1,
  update-start-time pinning, per-role rollback, mix-and-match bindings).
  These must stay green.
* F410 known-issue tests: the post-rotation bootstrap wedge. These pin
  the CURRENT (wedged) behavior; when F410 is closed they must be
  updated to assert recovery instead.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import bundle_refresh as br  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


def _signers():
    return {
        "a": Ed25519Signer(b"\x11" * 32),
        "b": Ed25519Signer(b"\x22" * 32),
        "ts": Ed25519Signer(b"\x33" * 32),
        "tk2": Ed25519Signer(b"\x55" * 32),
        "rk3": Ed25519Signer(b"\x44" * 32),
    }


_KIDS = {"a": "kid-a", "b": "kid-b", "ts": "kid-ts",
         "tk2": "kid-tk2", "rk3": "kid-rk3"}


class AuditRepo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.signers = _signers()
        self.files = {}
        self.expires = (self.now + timedelta(days=365)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self._publish_root(1, ["a", "b"], "ts", ["a", "b"], [])
        self._publish_targets(1, "ts")
        self._publish_snapshot(1, 1, "ts")
        for v in (1, 2, 3):
            self._publish_timestamp(v, 1, "ts")

    def tearDown(self):
        self.tmp.cleanup()

    # -- builders -------------------------------------------------
    def _keys_doc(self):
        return {_KIDS[k]: {"keytype": "ed25519", "keyval": {
            "public": self.signers[k].public_key.hex()}}
            for k in ("a", "b", "ts", "tk2", "rk3")}

    def _publish_root(self, version, root_kids, ts_kid,
                      old_signers, new_signers):
        doc = {
            "_type": "root", "version": version, "expires": self.expires,
            "keys": self._keys_doc(),
            "roles": {
                "root": {"keyids": [_KIDS[k] for k in root_kids],
                         "threshold": 2},
                "timestamp": {"keyids": [_KIDS[ts_kid]], "threshold": 1},
                "snapshot": {"keyids": [_KIDS[ts_kid]], "threshold": 1},
                "targets": {"keyids": [_KIDS[ts_kid]], "threshold": 1}},
        }
        self.files[("root", version)] = br.seal_role(
            "root", doc, [(_KIDS[k], self.signers[k])
                          for k in old_signers + new_signers])

    def _publish_targets(self, version, kid):
        doc = {"_type": "targets", "version": version,
               "expires": self.expires,
               "targets": {"skill:x": {
                   "length": 10, "hashes": {"sha256": "ab" * 32}}}}
        self.files[("targets", version)] = br.seal_role(
            "targets", doc, [(_KIDS[kid], self.signers[kid])])

    def _publish_snapshot(self, version, tgt_version, kid):
        twire = self.files[("targets", tgt_version)]
        doc = {"_type": "snapshot", "version": version,
               "expires": self.expires,
               "meta": {"targets.json": {
                   "version": tgt_version, "length": len(twire),
                   "hashes": {"sha256": hashlib.sha256(
                       twire).hexdigest()}}}}
        self.files[("snapshot", version)] = br.seal_role(
            "snapshot", doc, [(_KIDS[kid], self.signers[kid])])

    def _publish_timestamp(self, version, snap_version, kid):
        swire = self.files[("snapshot", snap_version)]
        doc = {"_type": "timestamp", "version": version,
               "expires": self.expires,
               "snapshot": {"version": snap_version,
                            "length": len(swire),
                            "hashes": {"sha256": hashlib.sha256(
                                swire).hexdigest()}}}
        self.files[("timestamp", version)] = br.seal_role(
            "timestamp", doc, [(_KIDS[kid], self.signers[kid])])

    # -- harness --------------------------------------------------
    def _fetch(self, role, version):
        key = (role, version)
        if key not in self.files:
            raise br.FetchNotFound("no %s v%s" % (role, version))
        return self.files[key]

    def _refresher(self, clock=None):
        return br.BundleRefresher(
            trusted_root_wire=self.files[("root", 1)],
            fetch=self._fetch, cache_dir=self.tmp.name,
            clock=clock or (lambda: self.now))

    def _rotate(self, ts_versions):
        """Trust-changing root rotation; new timestamps under tk2."""
        self._publish_root(2, ["b", "rk3"], "tk2",
                           ["a", "b"], ["b", "rk3"])
        self._publish_targets(2, "tk2")
        self._publish_snapshot(2, 2, "tk2")
        for v in ts_versions:
            self._publish_timestamp(v, 2, "tk2")


class RootRotationAuditTest(AuditRepo):
    """Target 1: root rotation is exactly N+1, dual-threshold."""

    def test_skip_n_plus_two_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # Serve the v3 doc at the probed N+1 slot (v2 skipped).
        self._publish_root(3, ["b", "rk3"], "ts",
                           ["a", "b"], ["b", "rk3"])
        self.files[("root", 2)] = self.files.pop(("root", 3))
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("skips versions", rep.reason)

    def test_single_threshold_n_plus_one_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # v2 declares (b,rk3) but carries only old (a,b) signatures.
        self._publish_root(2, ["b", "rk3"], "ts", ["a", "b"], [])
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("threshold", rep.reason.lower())

    def test_rollback_of_root_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._publish_root(2, ["b", "rk3"], "ts",
                           ["a", "b"], ["b", "rk3"])
        self.assertEqual(r.refresh().state, "trusted")
        self.assertEqual(r._root_version, 2)
        self.files[("root", 2)] = self.files[("root", 1)]
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("older than trusted", rep.reason)


class UpdateStartTimeAuditTest(AuditRepo):
    """Target 2: the per-cycle reference time is pinned at cycle start."""

    def test_mid_cycle_clock_advance_cannot_flip_verdict(self):
        start = self.now
        repo_expires = (start + timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self.expires = repo_expires
        # Rebuild the chain with a 30-minute expiry.
        self.files.clear()
        self._publish_root(1, ["a", "b"], "ts", ["a", "b"], [])
        self._publish_targets(1, "ts")
        self._publish_snapshot(1, 1, "ts")
        self._publish_timestamp(1, 1, "ts")
        calls = []

        def clock():
            calls.append(1)
            if len(calls) <= 2:
                return start
            return start + timedelta(hours=2)

        r = self._refresher(clock=clock)
        rep = r.refresh()
        # Every expiry check in the cycle read the pinned start time.
        self.assertEqual(rep.state, "trusted")
        # The clock is sampled exactly twice total (pinned-root check at
        # init, cycle sample at refresh start) -- no per-check sampling
        # exists for a mid-cycle advance to corrupt.
        self.assertEqual(len(calls), 2)


class RollbackAuditTest(AuditRepo):
    """Target 3: rollback floors on timestamp and bound roles."""

    def test_timestamp_rollback_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self.files[("timestamp", 4)] = self.files[("timestamp", 2)]
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("older than trusted", rep.reason)

    def test_snapshot_rollback_via_newer_timestamp_refused(self):
        r = self._refresher()
        self._publish_targets(2, "ts")
        self._publish_snapshot(2, 2, "ts")
        self._publish_timestamp(4, 2, "ts")
        self.assertEqual(r.refresh().state, "trusted")
        self.assertEqual(r._chain["snapshot"]["doc"]["version"], 2)
        # Valid newer timestamp binds the OLD snapshot.
        self._publish_timestamp(5, 1, "ts")
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("older than trusted", rep.reason)

    def test_targets_rollback_via_newer_snapshot_refused(self):
        r = self._refresher()
        self._publish_targets(2, "ts")
        self._publish_snapshot(2, 2, "ts")
        self._publish_timestamp(4, 2, "ts")
        self.assertEqual(r.refresh().state, "trusted")
        self.assertEqual(r._chain["targets"]["doc"]["version"], 2)
        self._publish_snapshot(3, 1, "ts")
        self._publish_timestamp(5, 3, "ts")
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("older than trusted", rep.reason)


class MixAndMatchAuditTest(AuditRepo):
    """Target 5: parent version+digest bindings are enforced."""

    def test_snapshot_digest_mismatch_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._publish_targets(2, "ts")
        self._publish_snapshot(2, 2, "ts")
        swire = self.files[("snapshot", 2)]
        doc = {"_type": "timestamp", "version": 4,
               "expires": self.expires,
               "snapshot": {"version": 2, "length": len(swire),
                            "hashes": {"sha256": "ff" * 32}}}
        self.files[("timestamp", 4)] = br.seal_role(
            "timestamp", doc, [(_KIDS["ts"], self.signers["ts"])])
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("digest", rep.reason.lower())

    def test_snapshot_version_mismatch_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._publish_targets(2, "ts")
        self._publish_snapshot(2, 2, "ts")
        self._publish_targets(3, "ts")
        self._publish_snapshot(3, 3, "ts")
        self._publish_timestamp(4, 2, "ts")
        # Serve v3 bytes at the v2 slot.
        self.files[("snapshot", 2)] = self.files[("snapshot", 3)]
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("parent-bound", rep.reason)

    def test_targets_swap_refused_by_digest_binding(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._publish_targets(2, "ts")
        doc = {"_type": "targets", "version": 2, "expires": self.expires,
               "targets": {"skill:evil": {
                   "length": 3, "hashes": {"sha256": "cc" * 32}}}}
        evil = br.seal_role("targets", doc,
                            [(_KIDS["ts"], self.signers["ts"])])
        self._publish_snapshot(2, 2, "ts")  # binds the GOOD v2
        self._publish_timestamp(4, 2, "ts")
        self.files[("targets", 2)] = evil
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("digest", rep.reason.lower())


class PostRotationFloorAuditTest(AuditRepo):
    """Target 4 (conformant half): the pre-rotation floor is enforced."""

    def test_sub_floor_timestamp_refused(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._rotate([4])
        # Plant a new-key-signed v1 below the pre-rotation floor (v3).
        _env, doc, _payload = br._parse_envelope(
            "timestamp", self.files[("timestamp", 4)], "plant",
            br.DEFAULT_MAX_LENGTH)
        evil = dict(doc)
        evil["version"] = 1
        self.files[("timestamp", 1)] = br.seal_role(
            "timestamp", evil, [(_KIDS["tk2"], self.signers["tk2"])])
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("pre-rotation", rep.reason.lower())


class F410RegressionTest(AuditRepo):
    """F410 (CLOSED wave-327 lane 2): the post-rotation bootstrap
    tolerates a bounded run of consecutive clean timestamp-slot misses
    instead of breaking on the first one, so a repository that prunes
    old slots (or leaves gaps) no longer wedges the client.

    These tests pin the FIXED behavior: recovery to the highest
    new-key-signed timestamp >= the pre-rotation floor. The floor
    itself is still enforced (see PostRotationFloorAuditTest).
    """

    def test_pruned_pre_rotation_slots_recover(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._rotate([4, 5])
        for v in (1, 2, 3):
            self.files.pop(("timestamp", v))
        rep = r.refresh()
        self.assertEqual(rep.state, "trusted")
        self.assertEqual(rep.versions.get("timestamp"), 5)
        # A second cycle stays trusted: no permanent wedge.
        rep2 = r.refresh()
        self.assertEqual(rep2.state, "trusted")

    def test_single_gap_recovers(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._rotate([4, 5])
        self.files.pop(("timestamp", 3))
        rep = r.refresh()
        self.assertEqual(rep.state, "trusted")
        self.assertEqual(rep.versions.get("timestamp"), 5)

    def test_miss_bound_still_suspends(self):
        # Withholding past the miss bound suspends fail-closed, exactly
        # as withholding everything does (no unbounded fetching).
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._rotate([4, 5])
        for v in (1, 2, 3, 4, 5):
            self.files.pop(("timestamp", v))
        rep = r.refresh()
        self.assertEqual(rep.state, "suspended")
        self.assertIn("no timestamp version verifies", rep.reason)


if __name__ == "__main__":
    unittest.main()
