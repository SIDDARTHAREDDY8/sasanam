#!/usr/bin/env python3
"""Focused unit tests for gov.bundle_refresh (wave-206 lane B).

Public-seam tests: the canonicalization pin, the seal/verify
round-trip, dual-threshold root chaining, opaque key IDs, expiry vs
suspension, rollback, and per-role byte caps. Deterministic
(fixed seeds, fixed clock); stdlib-only plus gov.signing.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import bundle_refresh as br
from gov.signing import Ed25519Signer


def _signers():
    return {
        "a": Ed25519Signer(b"\x11" * 32),
        "b": Ed25519Signer(b"\x22" * 32),
        "ts": Ed25519Signer(b"\x33" * 32),
    }


DECLARED = {"a": "kid-alpha", "b": "kid-beta", "ts": "kid-ts"}


def _keys_doc(kids):
    return {DECLARED[k]: {"keytype": "ed25519",
                          "keyval": {"public": _signers()[k].public_key.hex()}}
            for k in kids}


class CanonicalTest(unittest.TestCase):
    def test_pin_identifier(self):
        self.assertEqual(br.CANONICALIZATION_ID,
                         "tuf-olpc-canonical-json/v1")

    def test_sorted_keys_no_whitespace(self):
        self.assertEqual(br.tuf_canonical_json({"b": 1, "a": [1, 2]}),
                         b'{"a":[1,2],"b":1}')

    def test_control_chars_use_long_escapes(self):
        # OLPC canonical JSON: \u000a, never the JCS short escape \n.
        out = br.tuf_canonical_json({"k": "x\ny"})
        self.assertEqual(out, b'{"k":"x\\u000ay"}')
        self.assertNotIn(b"\\n", out.replace(b"\\u000a", b""))

    def test_floats_refused(self):
        with self.assertRaises(br.CanonicalError):
            br.tuf_canonical_json({"k": 1.5})

    def test_bool_is_literal_not_int(self):
        self.assertEqual(br.tuf_canonical_json(True), b"true")
        self.assertEqual(br.tuf_canonical_json({"k": False}),
                         b'{"k":false}')

    def test_unsupported_type_refused(self):
        with self.assertRaises(br.CanonicalError):
            br.tuf_canonical_json({"k": object()})


class SealRoundTripTest(unittest.TestCase):
    def test_seal_uses_declared_keyids(self):
        signers = _signers()
        wire = br.seal_role(
            "timestamp", {"_type": "timestamp", "version": 1,
                          "expires": "2030-01-01T00:00:00Z",
                          "snapshot": {"version": 1, "length": 1,
                                       "hashes": {"sha256": "aa" * 32}}},
            [(DECLARED["ts"], signers["ts"])])
        env, doc, payload = br._parse_envelope(
            "timestamp", wire, "test", br.DEFAULT_MAX_LENGTH)
        self.assertEqual(doc["_type"], "timestamp")
        # The envelope carries the DECLARED id, not the derived one.
        self.assertEqual(env["signatures"][0]["keyid"], "kid-ts")
        self.assertNotEqual("kid-ts", signers["ts"].key_id)

    def test_seal_unknown_role_refused(self):
        with self.assertRaises(ValueError):
            br.seal_role("nope", {}, [(DECLARED["a"], _signers()["a"])])


class RefresherTest(unittest.TestCase):
    def setUp(self):
        self.signers = _signers()
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.files = {}
        self._build_chain(expires=self.now + timedelta(days=365))

    def tearDown(self):
        self.tmp.cleanup()

    # -- fixture builders -------------------------------------------
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

    # -- tests --------------------------------------------------------
    def test_valid_chain_trusted(self):
        r = self._refresher()
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        digest, length = r.target_digest("skill:x")
        self.assertEqual((digest, length), ("ab" * 32, 10))

    def test_suspended_before_any_refresh_with_empty_cache(self):
        r = self._refresher()
        # Fresh refresher, nothing cached yet: must refuse loudly.
        with self.assertRaises(br.SuspendedError):
            r.target_digest("skill:x")

    def test_unknown_target_keyerror(self):
        r = self._refresher()
        r.refresh()
        with self.assertRaises(KeyError):
            r.target_digest("skill:nope")

    def test_expired_everything_no_cache_suspends(self):
        self._build_chain(expires=self.now - timedelta(days=1))
        r = self._refresher()
        report = r.refresh()
        self.assertEqual(report.state, "suspended")
        with self.assertRaises(br.SuspendedError):
            r.target_digest("skill:x")

    def test_root_rollover_dual_threshold(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # Legitimate v2: signed by 2-of-2 old keys AND 2-of-2 new keys.
        doc = self._root_doc(2, ["a", "b"], 2,
                             self.now + timedelta(days=365))
        self.files[("root", 2)] = br.seal_role(
            "root", doc, [(DECLARED[k], self.signers[k])
                          for k in ("a", "b")])
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        self.assertEqual(r._root_version, 2)

    def test_root_gap_never_adopted(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # A repo that publishes v3 while v2 is missing: the sequential
        # probe stops at the v2 miss, so the gap is never adopted. The
        # refresher stays at v1 (safe), rather than suspending -- the
        # dangerous case (v3 bytes served AT the v2 slot) suspends.
        doc = self._root_doc(3, ["a", "b"], 2,
                             self.now + timedelta(days=365))
        self.files[("root", 3)] = br.seal_role(
            "root", doc, [(DECLARED[k], self.signers[k])
                          for k in ("a", "b")])
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        self.assertEqual(r._root_version, 1)
        # ...but v3 bytes at the v2 slot ARE a chain break.
        self.files[("root", 2)] = self.files[("root", 3)]
        report = r.refresh()
        self.assertEqual(report.state, "suspended")
        self.assertIn("skip", (report.reason or "").lower())

    def test_transport_error_keeps_chain(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")

        def flaky(role, version):
            raise ConnectionError("boom")

        r._fetch = flaky
        report = r.refresh()
        # Transport failure is a loud warning, not a suspension.
        self.assertEqual(report.state, "trusted")
        self.assertTrue(any("transport" in w for w in report.warnings))
        self.assertEqual(r.target_digest("skill:x")[0], "ab" * 32)

    def test_per_role_cap_override(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        tiny = self._refresher(
            max_length={"targets": 10, "root": 10**6,
                        "timestamp": 10**6, "snapshot": 10**6})
        # Fresh cache dir per refresher? No -- same dir is fine; the
        # tiny cap trips on the targets fetch during refresh.
        report = tiny.refresh()
        self.assertEqual(report.state, "suspended")
        self.assertIn("cap", (report.reason or "").lower())

    def test_canonical_error_is_chain_break(self):
        # Regression: CanonicalError used to be a plain ValueError, so a
        # mis-canonicalized file escaped _load_cache's
        # ``except RefreshError`` and crashed __init__.
        self.assertTrue(issubclass(br.CanonicalError, br.RefreshError))
        self.assertTrue(issubclass(br.CanonicalError, ValueError))

    def test_noncanonical_cached_file_discarded_at_init(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # Rewrite the cached timestamp as valid JSON that is NOT
        # canonical bytes: init must discard it, not crash.
        path = os.path.join(self.tmp.name, "timestamp.json")
        with open(path, "rb") as handle:
            envelope = json.loads(handle.read().decode("utf-8"))
        with open(path, "w") as handle:
            handle.write(json.dumps(envelope, indent=2))
        r2 = self._refresher()
        self.assertTrue(any("discarding" in w
                            for w in r2.warnings), r2.warnings)
        # A fresh refresh recovers to trusted.
        self.assertEqual(r2.refresh().state, "trusted")


# ---------------------------------------------------------------------------
# Adjacent: the additive SkillLoader bundle-refresh guard (wave-206).
# ---------------------------------------------------------------------------

class BundleRefreshGuardTest(unittest.TestCase):
    """SkillLoader's optional bundle_refresh guard.

    Without the guard, legacy pinset-only behavior is unchanged. With
    it: a suspended refresher refuses every load; a servable refresher
    requires the pin's digest to equal the refresh-bound digest
    (mix-and-match across bundle versions refuses); an unbound skill
    name refuses.
    """

    def setUp(self):
        from gov import load_gate as lg
        from gov.delegation_tokens import DelegationTrust
        from gov.signing import Ed25519Signer
        import secrets
        self.lg = lg
        h1 = Ed25519Signer(secrets.token_bytes(32))
        h2 = Ed25519Signer(secrets.token_bytes(32))
        ax = Ed25519Signer(secrets.token_bytes(32))
        ui = Ed25519Signer(secrets.token_bytes(32))
        trust = DelegationTrust(
            human_keys={h1.key_id: h1.public_key,
                        h2.key_id: h2.public_key},
            authority_keys={ax.key_id: ax.public_key},
            user_issuer_keys={ui.key_id: ui.public_key},
        )
        self.h1 = h1
        self.pinset = lg.ArtifactPinset(trust)
        self.skill_bytes = b"skill: summarize the thread, no tools"
        self.digest = "sha256:" + hashlib.sha256(
            self.skill_bytes).hexdigest()
        ts = "2026-09-23T00:00:00+00:00"
        na = lg._resolve_pin_not_after(ts, None)
        body = lg._canonical_pin_body("dev", "skill:summarize",
                                      self.digest, ts, version=1,
                                      not_after=na)
        self.pinset.pin("skill:summarize", self.digest, h1.key_id,
                        h1.sign(body).hex(), ts=ts, tier="dev",
                        version=1, not_after=na)
        self.store = {"summarize": self.skill_bytes}
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.signers = _signers()

    def tearDown(self):
        self.tmp.cleanup()

    def _chain(self, bound_hex):
        files = {}

        def fetch(role, version):
            if (role, version) not in files:
                raise br.FetchNotFound("no %s v%s" % (role, version))
            return files[(role, version)]

        exp = self.now + timedelta(days=365)
        iso = exp.strftime("%Y-%m-%dT%H:%M:%SZ")
        keys = {DECLARED[k]: {"keytype": "ed25519", "keyval": {
            "public": self.signers[k].public_key.hex()}}
            for k in ("a", "b", "ts")}
        root_doc = {
            "_type": "root", "version": 1, "expires": iso, "keys": keys,
            "roles": {
                "root": {"keyids": [DECLARED["a"], DECLARED["b"]],
                         "threshold": 2},
                "timestamp": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "snapshot": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "targets": {"keyids": [DECLARED["ts"]], "threshold": 1}},
        }
        files[("root", 1)] = br.seal_role(
            "root", root_doc,
            [(DECLARED[k], self.signers[k]) for k in ("a", "b")])
        tdoc = {"_type": "targets", "version": 1, "expires": iso,
                "targets": {"skill:summarize": {
                    "length": len(self.skill_bytes),
                    "hashes": {"sha256": bound_hex}}}}
        files[("targets", 1)] = br.seal_role(
            "targets", tdoc, [(DECLARED["ts"], self.signers["ts"])])
        sdoc = {"_type": "snapshot", "version": 1, "expires": iso,
                "meta": {"targets.json": {
                    "version": 1,
                    "length": len(files[("targets", 1)]),
                    "hashes": {"sha256": hashlib.sha256(
                        files[("targets", 1)]).hexdigest()}}}}
        files[("snapshot", 1)] = br.seal_role(
            "snapshot", sdoc, [(DECLARED["ts"], self.signers["ts"])])
        tsdoc = {"_type": "timestamp", "version": 1, "expires": iso,
                 "snapshot": {
                     "version": 1,
                     "length": len(files[("snapshot", 1)]),
                     "hashes": {"sha256": hashlib.sha256(
                         files[("snapshot", 1)]).hexdigest()}}}
        files[("timestamp", 1)] = br.seal_role(
            "timestamp", tsdoc, [(DECLARED["ts"], self.signers["ts"])])
        return br.BundleRefresher(
            trusted_root_wire=files[("root", 1)], fetch=fetch,
            cache_dir=self.tmp.name, clock=lambda: self.now)

    def test_no_guard_legacy_behavior_unchanged(self):
        loader = self.lg.SkillLoader(self.pinset, self.store)
        verified = loader.load_skill("summarize")
        self.assertEqual(verified.digest, self.digest)

    def test_matching_binding_loads(self):
        refresher = self._chain(self.digest.split(":", 1)[1])
        self.assertEqual(refresher.refresh().state, "trusted")
        loader = self.lg.SkillLoader(self.pinset, self.store,
                                     bundle_refresh=refresher)
        verified = loader.load_skill("summarize")
        self.assertEqual(verified.digest, self.digest)

    def test_mismatch_refused(self):
        refresher = self._chain("ff" * 32)  # bundle binds other bytes
        self.assertEqual(refresher.refresh().state, "trusted")
        loader = self.lg.SkillLoader(self.pinset, self.store,
                                     bundle_refresh=refresher)
        with self.assertRaises(self.lg.ArtifactRefused) as ctx:
            loader.load_skill("summarize")
        self.assertIn("bundle_refresh_mismatch", str(ctx.exception))

    def test_suspended_refresher_refuses(self):
        refresher = self._chain(self.digest.split(":", 1)[1])
        # Never refreshed: empty cache -> suspended at init.
        self.assertEqual(refresher.state, "suspended")
        loader = self.lg.SkillLoader(self.pinset, self.store,
                                     bundle_refresh=refresher)
        with self.assertRaises(self.lg.ArtifactRefused) as ctx:
            loader.load_skill("summarize")
        self.assertIn("bundle_refresh_suspended", str(ctx.exception))

    def test_unbound_skill_refused(self):
        refresher = self._chain(self.digest.split(":", 1)[1])
        self.assertEqual(refresher.refresh().state, "trusted")
        # Pin a second skill the bundle never bound.
        other = b"skill: other"
        other_digest = "sha256:" + hashlib.sha256(other).hexdigest()
        ts = "2026-09-23T00:00:00+00:00"
        na = self.lg._resolve_pin_not_after(ts, None)
        body = self.lg._canonical_pin_body(
            "dev", "skill:other", other_digest, ts, version=1,
            not_after=na)
        self.pinset.pin("skill:other", other_digest, self.h1.key_id,
                        self.h1.sign(body).hex(), ts=ts, tier="dev",
                        version=1, not_after=na)
        self.store["other"] = other
        loader = self.lg.SkillLoader(self.pinset, self.store,
                                     bundle_refresh=refresher)
        with self.assertRaises(self.lg.ArtifactRefused) as ctx:
            loader.load_skill("other")
        self.assertIn("bundle_refresh_unbound", str(ctx.exception))

    def test_helper_passes_guard_through(self):
        refresher = self._chain(self.digest.split(":", 1)[1])
        self.assertEqual(refresher.refresh().state, "trusted")
        marker = self.lg.load_skill_content(
            self.pinset, self.store, "summarize",
            bundle_refresh=refresher)
        self.assertEqual(marker._ack_context["digest"], self.digest)

    def test_bad_guard_type_rejected(self):
        with self.assertRaises(TypeError):
            self.lg.SkillLoader(self.pinset, self.store,
                                bundle_refresh=object())


# ---------------------------------------------------------------------------
# Rotation: a trust-changing root rotation re-bootstraps subordinate roles.
# ---------------------------------------------------------------------------

ROT_KIDS = {"rk3": "kid-rot-root3", "tk2": "kid-rot-ts2"}


class RotationTest(unittest.TestCase):
    """Root rotation that changes subordinate keys must not wedge.

    Before the fix, a rotation that replaced the timestamp key left the
    refresher permanently suspended: the old timestamp could not
    re-verify under the new root, and every refresh restarted the probe
    from the cached version. Now the refresher drops the old chain and
    re-bootstraps timestamp/snapshot/targets under the new root, with
    the pre-rotation versions as the rollback floor.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.signers = _signers()
        self.rk3 = Ed25519Signer(b"\x44" * 32)
        self.tk2 = Ed25519Signer(b"\x55" * 32)
        self.files = {}
        self.expires = self.now + timedelta(days=365)
        self._publish_root_v1()
        self._publish_targets(1, self.signers["ts"], DECLARED["ts"])
        self._publish_snapshot(1, 1, self.signers["ts"], DECLARED["ts"])
        self._publish_timestamp(1, 1, self.signers["ts"], DECLARED["ts"])

    def tearDown(self):
        self.tmp.cleanup()

    # -- fixture builders -------------------------------------------
    def _iso(self):
        return self.expires.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _publish_root_v1(self):
        doc = {
            "_type": "root", "version": 1, "expires": self._iso(),
            "keys": _keys_doc(["a", "b", "ts"]),
            "roles": {
                "root": {"keyids": [DECLARED["a"], DECLARED["b"]],
                         "threshold": 2},
                "timestamp": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "snapshot": {"keyids": [DECLARED["ts"]], "threshold": 1},
                "targets": {"keyids": [DECLARED["ts"]], "threshold": 1}},
        }
        self.files[("root", 1)] = br.seal_role(
            "root", doc, [(DECLARED[k], self.signers[k])
                          for k in ("a", "b")])

    def _publish_root_v2(self, subordinate_kid, with_new_sub_keys=True):
        # Rotates root key a -> rk3 AND (optionally) subordinate keys.
        keys = _keys_doc(["a", "b", "ts"])
        keys[ROT_KIDS["rk3"]] = {
            "keytype": "ed25519",
            "keyval": {"public": self.rk3.public_key.hex()}}
        if with_new_sub_keys:
            keys[ROT_KIDS["tk2"]] = {
                "keytype": "ed25519",
                "keyval": {"public": self.tk2.public_key.hex()}}
        doc = {
            "_type": "root", "version": 2, "expires": self._iso(),
            "keys": keys,
            "roles": {
                "root": {"keyids": [DECLARED["b"], ROT_KIDS["rk3"]],
                         "threshold": 2},
                "timestamp": {"keyids": [subordinate_kid],
                              "threshold": 1},
                "snapshot": {"keyids": [subordinate_kid], "threshold": 1},
                "targets": {"keyids": [subordinate_kid], "threshold": 1}},
        }
        # Dual threshold: old (a,b) 2-of-2 AND new (b,rk3) 2-of-2.
        self.files[("root", 2)] = br.seal_role(
            "root", doc, [(DECLARED["a"], self.signers["a"]),
                          (DECLARED["b"], self.signers["b"]),
                          (ROT_KIDS["rk3"], self.rk3)])

    def _publish_targets(self, version, signer, kid):
        tdoc = {"_type": "targets", "version": version,
                "expires": self._iso(),
                "targets": {"skill:x": {
                    "length": 10,
                    "hashes": {"sha256": "ab" * 32}}}}
        self.files[("targets", version)] = br.seal_role(
            "targets", tdoc, [(kid, signer)])

    def _publish_snapshot(self, version, tgt_version, signer, kid):
        twire = self.files[("targets", tgt_version)]
        sdoc = {"_type": "snapshot", "version": version,
                "expires": self._iso(),
                "meta": {"targets.json": {
                    "version": tgt_version,
                    "length": len(twire),
                    "hashes": {"sha256": hashlib.sha256(
                        twire).hexdigest()}}}}
        self.files[("snapshot", version)] = br.seal_role(
            "snapshot", sdoc, [(kid, signer)])

    def _publish_timestamp(self, version, snap_version, signer, kid):
        swire = self.files[("snapshot", snap_version)]
        tsdoc = {"_type": "timestamp", "version": version,
                 "expires": self._iso(),
                 "snapshot": {
                     "version": snap_version,
                     "length": len(swire),
                     "hashes": {"sha256": hashlib.sha256(
                         swire).hexdigest()}}}
        self.files[("timestamp", version)] = br.seal_role(
            "timestamp", tsdoc, [(kid, signer)])

    def _publish_rotated_chain(self, ts_version):
        self._publish_root_v2(ROT_KIDS["tk2"])
        self._publish_targets(2, self.tk2, ROT_KIDS["tk2"])
        self._publish_snapshot(2, 2, self.tk2, ROT_KIDS["tk2"])
        self._publish_timestamp(ts_version, 2, self.tk2,
                                ROT_KIDS["tk2"])

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

    # -- tests --------------------------------------------------------
    def test_rotation_with_subordinate_key_change_recovers(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # Old v1 files stay served (immutable versioned URLs); the new
        # v2 chain is published under the new timestamp key.
        self._publish_rotated_chain(ts_version=2)
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        self.assertEqual(r._root_version, 2)
        self.assertEqual(report.versions,
                         {"timestamp": 2, "snapshot": 2, "targets": 2})
        self.assertTrue(
            any("re-bootstrap" in w for w in report.warnings),
            report.warnings)
        digest, length = r.target_digest("skill:x")
        self.assertEqual((digest, length), ("ab" * 32, 10))

    def test_rotation_rollback_floor_refused(self):
        r = self._refresher()
        # Advance timestamp to v2 under the OLD key first: the floor.
        self._publish_timestamp(2, 1, self.signers["ts"], DECLARED["ts"])
        self.assertEqual(r.refresh().state, "trusted")
        self.assertEqual(
            r._chain["timestamp"]["doc"]["version"], 2)
        self._publish_rotated_chain(ts_version=3)
        # Attacker plants a NEW-key-signed v1 at the v1 slot: it
        # verifies, but sits below the pre-rotation floor (v2).
        _env, doc, _payload = br._parse_envelope(
            "timestamp", self.files[("timestamp", 3)], "test",
            br.DEFAULT_MAX_LENGTH)
        evil_doc = dict(doc)
        evil_doc["version"] = 1
        self.files[("timestamp", 1)] = br.seal_role(
            "timestamp", evil_doc,
            [(ROT_KIDS["tk2"], self.tk2)])
        report = r.refresh()
        self.assertEqual(report.state, "suspended")
        self.assertIn("pre-rotation", (report.reason or "").lower())
        with self.assertRaises(br.SuspendedError):
            r.target_digest("skill:x")

    def test_rotation_without_subordinate_change_keeps_chain(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        # Root-only rotation: subordinate trust is unchanged, so the
        # chain is confirmed in place -- no re-bootstrap.
        self._publish_root_v2(DECLARED["ts"], with_new_sub_keys=False)
        report = r.refresh()
        self.assertEqual(report.state, "trusted")
        self.assertEqual(r._root_version, 2)
        self.assertEqual(report.versions["timestamp"], 1)
        self.assertFalse(
            any("re-bootstrap" in w for w in report.warnings),
            report.warnings)

    def test_init_with_cached_rotation_bootstraps(self):
        r = self._refresher()
        self.assertEqual(r.refresh().state, "trusted")
        self._publish_rotated_chain(ts_version=2)
        self.assertEqual(r.refresh().state, "trusted")
        # Simulate a crash mid-rollout: only root v2 + timestamp v2
        # reached this cache.
        os.remove(os.path.join(self.tmp.name, "snapshot.json"))
        os.remove(os.path.join(self.tmp.name, "targets.json"))
        # A new process pinned to the OLD root wire replays the cached
        # rotation at init; the first refresh must re-bootstrap under
        # the new root instead of wedging on old-key history.
        r2 = br.BundleRefresher(
            trusted_root_wire=self.files[("root", 1)],
            fetch=self._fetch, cache_dir=self.tmp.name,
            clock=lambda: self.now)
        self.assertEqual(r2.state, "suspended")
        report = r2.refresh()
        self.assertEqual(report.state, "trusted")
        self.assertEqual(r2._root_version, 2)
        self.assertEqual(report.versions["timestamp"], 2)
        digest, _length = r2.target_digest("skill:x")
        self.assertEqual(digest, "ab" * 32)


if __name__ == "__main__":
    unittest.main()
