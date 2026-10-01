"""Unit tests for gov/bundle_delivery.py (wave-273 lane E).

Red-first: every attack scenario is asserted at the public seam with
the exact coded refusal; happy paths assert the verified outcome.
"""
import hashlib
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from gov import bundle_delivery as bd
from gov.bundle_refresh import (BundleRefresher, FetchNotFound,
                                RefreshError, seal_role)
from gov.signing import Ed25519Signer


FUTURE = (datetime.now(timezone.utc)
          + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (datetime.now(timezone.utc)
        - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
NOW = datetime.now(timezone.utc)


def keypair(seed_byte):
    return Ed25519Signer(bytes([seed_byte]) * 32)


def keyval(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


def make_role(name, signer, paths=None, prefixes=None, threshold=1,
              terminating=False):
    kid = "kid-" + name
    return bd.DelegatedRole(
        name, [kid], threshold, paths=paths,
        path_hash_prefixes=prefixes, terminating=terminating,
        keys={kid: keyval(signer)})


def seal(name, signer, targets, expires=FUTURE, version=1, kid=None):
    kid = kid or ("kid-" + name)
    doc = {"_type": "delegated-targets", "version": version,
           "expires": expires, "targets": targets}
    return bd.seal_delegated_targets(doc, [(kid, signer)])


def delegated_doc(top_targets, delegations):
    doc = {"_type": "targets", "version": 1, "expires": FUTURE,
           "targets": top_targets}
    if delegations:
        keys = {}
        roles = []
        for role in delegations:
            keys.update(role.keys)
            entry = {"name": role.name, "keyids": role.keyids,
                     "threshold": role.threshold,
                     "terminating": role.terminating}
            if role.paths is not None:
                entry["paths"] = role.paths
            else:
                entry["path_hash_prefixes"] = role.path_hash_prefixes
            roles.append(entry)
        doc["delegations"] = {"keys": keys, "roles": roles}
    return doc


class RoleScopeTests(unittest.TestCase):
    def test_fnmatch_per_part(self):
        role = make_role("a", keypair(1), paths=["skills/payments/*"])
        self.assertTrue(role.is_delegated_path("skills/payments/x"))
        self.assertFalse(role.is_delegated_path("skills/payments/x/y"))
        self.assertFalse(role.is_delegated_path("skills/billing/x"))

    def test_hash_bins_hide_names(self):
        digest = hashlib.sha256(b"secret-bundle").hexdigest()
        role = make_role("b", keypair(2), prefixes=[digest[:8]])
        self.assertTrue(role.is_delegated_path("secret-bundle"))
        self.assertFalse(role.is_delegated_path("other-bundle"))

    def test_exactly_one_scope(self):
        with self.assertRaises(bd.DeliveryError) as ctx:
            make_role("c", keypair(3), paths=["a/*"], prefixes=["ab"])
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")
        with self.assertRaises(bd.DeliveryError):
            make_role("c", keypair(4))

    def test_threshold_out_of_range(self):
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.DelegatedRole("c", ["k1"], 2, paths=["a/*"], keys={})
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")

    def test_bad_hex_prefix(self):
        with self.assertRaises(bd.DeliveryError) as ctx:
            make_role("c", keypair(5), prefixes=["ZZ"])
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")


class ParseTests(unittest.TestCase):
    def test_missing_block_is_empty(self):
        roles, keys = bd.parse_delegations({"targets": {}})
        self.assertEqual((roles, keys), ([], {}))

    def test_duplicate_names_refused(self):
        r1 = make_role("dup", keypair(1), paths=["a/*"])
        doc = delegated_doc({}, [r1, r1])
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.parse_delegations(doc)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")

    def test_unknown_key_refused(self):
        doc = {"delegations": {"keys": {"k1": keyval(keypair(1))},
                               "roles": [{"name": "x", "keyids": ["zzz"],
                                          "threshold": 1, "paths": ["a/*"]}]}}
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.parse_delegations(doc)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")


class LintTests(unittest.TestCase):
    def test_shadowed_is_fail_closed(self):
        # "bundles/*" provably covers every target of "bundles/x"
        # (same depth, "*" subsumes the literal).
        term = make_role("term", keypair(1), paths=["bundles/*"],
                         terminating=True)
        later = make_role("later", keypair(2), paths=["bundles/x"])
        findings = bd.lint_delegations([term, later])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "shadowed")
        self.assertEqual(findings[0]["role"], "later")

    def test_potential_shadow_when_undecidable(self):
        term = make_role("term", keypair(1), paths=["skills/a/*"],
                         terminating=True)
        later = make_role("later", keypair(2), paths=["skills/*/x"])
        findings = bd.lint_delegations([term, later])
        kinds = {f["kind"] for f in findings}
        self.assertIn("potential-shadow", kinds)

    def test_clean_when_disjoint(self):
        term = make_role("term", keypair(1), paths=["skills/a/*"],
                         terminating=True)
        later = make_role("later", keypair(2), paths=["skills/b/*"])
        self.assertEqual(bd.lint_delegations([term, later]), [])

    def test_bin_shadowing(self):
        term = make_role("term", keypair(1), prefixes=["ab"],
                         terminating=True)
        later = make_role("later", keypair(2), prefixes=["ab12"])
        findings = bd.lint_delegations([term, later])
        self.assertEqual(findings[0]["kind"], "shadowed")


class EnvelopeTests(unittest.TestCase):
    def test_seal_and_verify(self):
        s = keypair(9)
        role = make_role("leaf", s, paths=["a/*"])
        wire = seal("leaf", s, {"a/x": {"length": 1, "hashes": {
            "sha256": "00" * 32}}})
        doc = bd._verify_delegated_envelope(role, wire, NOW, "w")
        self.assertFalse(doc["_expired"])
        self.assertIn("a/x", doc["targets"])

    def test_threshold_not_met_refused(self):
        s = keypair(10)
        role = make_role("leaf", s, paths=["a/*"])
        wire = seal("leaf", keypair(11),
                    {"a/x": {"length": 1, "hashes": {"sha256": "00" * 32}}},
                    kid="kid-leaf")
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd._verify_delegated_envelope(role, wire, NOW, "w")
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-unverified")

    def test_expired_flagged_not_authoritative_at_resolution(self):
        s = keypair(12)
        role = make_role("leaf", s, paths=["a/*"])
        wire = seal("leaf", s,
                    {"a/x": {"length": 1, "hashes": {"sha256": "00" * 32}}},
                    expires=PAST)
        top = delegated_doc({}, [role])
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("a/x", top, lambda name: wire, NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-authority-refused")

    def test_noncanonical_wire_refused(self):
        s = keypair(13)
        role = make_role("leaf", s, paths=["a/*"])
        wire = seal("leaf", s, {"a/x": {"length": 1, "hashes": {
            "sha256": "00" * 32}}})
        tampered = wire.replace(b'"payloadType"', b' "payloadType"')
        self.assertNotEqual(tampered, wire)
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd._verify_delegated_envelope(role, tampered, NOW, "w")
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-malformed")


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.leaf = keypair(21)
        self.role = make_role("leaf", self.leaf, paths=["bundles/*"])

    def test_top_level_hit_never_touches_fetch(self):
        top = delegated_doc({"bundles/x": {"length": 3, "hashes": {
            "sha256": "11" * 32}}}, [self.role])
        calls = []

        def fetch(name):
            calls.append(name)
            raise FetchNotFound()
        res = bd.resolve_target("bundles/x", top, fetch, NOW)
        self.assertEqual(res.digest, "11" * 32)
        self.assertEqual(res.role, "targets")
        self.assertEqual(calls, [])

    def test_delegation_hit(self):
        top = delegated_doc({}, [self.role])
        wire = seal("leaf", self.leaf, {"bundles/x": {"length": 3,
                                                      "hashes": {
                                                          "sha256": "22"
                                                          * 32}}})
        res = bd.resolve_target("bundles/x", top, lambda n: wire, NOW)
        self.assertEqual(res.role, "leaf")
        self.assertEqual(res.digest, "22" * 32)

    def test_missing_delegated_metadata_refused(self):
        top = delegated_doc({}, [self.role])

        def fetch(name):
            raise FetchNotFound()
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/x", top, fetch, NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-unverified")

    def test_terminating_stops_backtracking(self):
        # "term" is eligible for bundles/a/x but does not bind it; it
        # is terminating, so the walk refuses without ever consulting
        # the later "leaf" delegation (which WOULD bind it).
        s_term = keypair(22)
        term = make_role("term", s_term, paths=["bundles/a/*"],
                         terminating=True)
        top = delegated_doc({}, [term, self.role])
        term_wire = seal("term", s_term, {})
        seen = []

        def fetch(name):
            seen.append(name)
            self.assertEqual(name, "term")
            return term_wire
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/a/x", top, fetch, NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-target-not-found")
        self.assertEqual(seen, ["term"])

    def test_cycle_fails_closed(self):
        s_a = keypair(23)
        role_a = make_role("a", s_a, paths=["bundles/*"])
        top = delegated_doc({}, [role_a])
        doc_a = {"_type": "delegated-targets", "version": 1,
                 "expires": FUTURE,
                 "targets": {},
                 "delegations": {"keys": role_a.keys,
                                 "roles": [{"name": "a",
                                            "keyids": role_a.keyids,
                                            "threshold": 1,
                                            "paths": ["bundles/*"]}]}}
        wire_a = bd.seal_delegated_targets(doc_a, [("kid-a", s_a)])
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/x", top, lambda n: wire_a, NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-cycle")

    def test_cap_exceeded(self):
        chain = [make_role("r%d" % i, keypair(30 + i % 200),
                           paths=["bundles/*"]) for i in range(40)]
        top = delegated_doc({}, chain)
        wires = {r.name: seal(r.name, keypair(30 + i % 200), {})
                 for i, r in enumerate(chain)}
        # Chain them: each doc delegates to the next
        docs = []
        for i, r in enumerate(chain):
            nxt = [{"name": chain[i + 1].name,
                    "keyids": chain[i + 1].keyids, "threshold": 1,
                    "paths": ["bundles/*"]}] if i + 1 < len(chain) else []
            keys = dict(chain[i].keys)
            for c in chain:
                keys.update(c.keys)
            doc = {"_type": "delegated-targets", "version": 1,
                   "expires": FUTURE, "targets": {}}
            if nxt:
                doc["delegations"] = {"keys": keys, "roles": nxt}
            wires[r.name] = bd.seal_delegated_targets(
                doc, [("kid-" + r.name, keypair(30 + i % 200))])
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/x", top,
                              lambda n: wires[n], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-delegation-cap-exceeded")

    def test_proven_shadow_fails_closed(self):
        term = make_role("term", keypair(41), paths=["bundles/*"],
                         terminating=True)
        later = make_role("later", keypair(42), paths=["bundles/x"])
        top = delegated_doc({}, [term, later])
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/x", top,
                              lambda n: (_ for _ in ()).throw(
                                  FetchNotFound()), NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-shadowed-delegation")

    def test_not_found(self):
        top = delegated_doc({}, [self.role])
        wire = seal("leaf", self.leaf, {})
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.resolve_target("bundles/x", top, lambda n: wire, NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-target-not-found")


class ConsistentSnapshotTests(unittest.TestCase):
    def test_metadata_url_mapping(self):
        self.assertEqual(bd.snapshot_metadata_url("targets", 7),
                         "v7.targets.json")
        self.assertEqual(bd.snapshot_target_url("x.bin", "ab" * 32),
                         "ab" * 32 + ".x.bin")
        with self.assertRaises(ValueError):
            bd.snapshot_metadata_url("root", 0)

    def test_delegated_role_names_map_too(self):
        # Versioned delegated-targets documents use the same scheme.
        self.assertEqual(bd.snapshot_metadata_url("team-payments", 3),
                         "v3.team-payments.json")
        with self.assertRaises(ValueError):
            bd.snapshot_metadata_url("a/b", 1)
        with self.assertRaises(ValueError):
            bd.snapshot_metadata_url("a.b", 1)
        with self.assertRaises(ValueError):
            bd.snapshot_metadata_url("", 1)

    def test_wrong_version_at_url_refused(self):
        doc = {"version": 2, "x": 1}
        import base64
        import json
        wire = json.dumps({"payload": base64.b64encode(
            json.dumps(doc).encode()).decode(), "payloadType": "t"}).encode()
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.verify_consistent_metadata("targets", 1, wire)
        self.assertEqual(ctx.exception.code, "bundle-delivery-mirror-stale")

    def test_digest_mismatch_refused(self):
        doc = {"version": 1, "x": 1}
        import base64
        import json
        wire = json.dumps({"payload": base64.b64encode(
            json.dumps(doc).encode()).decode(), "payloadType": "t"}).encode()
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.verify_consistent_metadata("targets", 1, wire,
                                          expected_digest="00" * 32)
        self.assertEqual(ctx.exception.code, "bundle-delivery-mirror-stale")

    def test_target_bytes_mismatch_refused(self):
        with self.assertRaises(bd.DeliveryError) as ctx:
            bd.verify_consistent_target("x.bin", "00" * 32, b"tampered")
        self.assertEqual(ctx.exception.code, "bundle-delivery-mirror-stale")

    def test_target_happy(self):
        data = b"bundle bytes"
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(bd.verify_consistent_target("x.bin", digest,
                                                     data), data)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.signer = keypair(51)
        self.keys = {"kid-r": keyval(self.signer)}
        self.info = {"keyids": ["kid-r"], "threshold": 1}

    def verifier(self):
        def verify(role_name, role_info, keys, wire, where):
            import base64
            import json
            from gov.bundle_refresh import PAYLOAD_TYPES
            from gov.dsse_envelope import pae
            from gov.signing import Ed25519Verifier
            env = json.loads(bytes(wire).decode("utf-8"))
            payload = base64.b64decode(env["payload"].encode("ascii"))
            pae_bytes = pae(PAYLOAD_TYPES[role_name], payload)
            seen = set()
            for entry in env["signatures"]:
                kid = entry.get("keyid")
                if kid in seen or kid not in role_info["keyids"]:
                    continue
                keyinfo = keys.get(kid)
                if not isinstance(keyinfo, dict):
                    continue
                try:
                    pub = bytes.fromhex(
                        keyinfo["keyval"]["public"])
                    sig = bytes.fromhex(entry["sig"])
                except (TypeError, ValueError, KeyError):
                    continue
                if Ed25519Verifier(pub, key_id=kid).verify(
                        pae_bytes, sig):
                    seen.add(kid)
            if len(seen) < role_info["threshold"]:
                raise bd.DeliveryError(
                    "bundle-delivery-expired-bootstrap-refused",
                    "test verifier: threshold not met")
            return json.loads(payload.decode("utf-8"))
        return verify

    def test_happy_bootstrap(self):
        expired = ({"version": 1, "expires": PAST}, self.info, self.keys)
        succ_doc = {"version": 2, "expires": FUTURE}
        wire = seal_role("root", succ_doc, [("kid-r", self.signer)])
        boot = bd.ExpiredBootstrap(self.verifier())
        adopted = boot.adopt("root", expired, [(wire, succ_doc)], NOW)
        self.assertEqual(adopted["version"], 2)

    def test_non_expired_intermediate_refused(self):
        expired = ({"version": 1, "expires": FUTURE}, self.info, self.keys)
        boot = bd.ExpiredBootstrap(lambda *a: {})
        with self.assertRaises(bd.DeliveryError) as ctx:
            boot.adopt("root", expired, [], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-bootstrap-refused")

    def test_rollback_refused(self):
        expired = ({"version": 2, "expires": PAST}, self.info, self.keys)
        replay = {"version": 1, "expires": FUTURE}
        wire = seal_role("root", replay, [("kid-r", self.signer)])
        boot = bd.ExpiredBootstrap(self.verifier())
        with self.assertRaises(bd.DeliveryError) as ctx:
            boot.adopt("root", expired, [(wire, replay)], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-bootstrap-refused")

    def test_version_skip_refused(self):
        expired = ({"version": 1, "expires": PAST}, self.info, self.keys)
        skip = {"version": 3, "expires": FUTURE}
        wire = seal_role("root", skip, [("kid-r", self.signer)])
        boot = bd.ExpiredBootstrap(self.verifier())
        with self.assertRaises(bd.DeliveryError) as ctx:
            boot.adopt("root", expired, [(wire, skip)], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-bootstrap-refused")

    def test_wrong_key_bootstrap_refused(self):
        expired = ({"version": 1, "expires": PAST}, self.info, self.keys)
        impostor = {"version": 2, "expires": FUTURE}
        wire = seal_role("root", impostor, [("kid-r", keypair(99))])
        boot = bd.ExpiredBootstrap(self.verifier())
        with self.assertRaises(bd.DeliveryError) as ctx:
            boot.adopt("root", expired, [(wire, impostor)], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-bootstrap-refused")

    @staticmethod
    def _root_keys_of(role_name, doc):
        roles = doc.get("roles") or {}
        keys = doc.get("keys") or {}
        info = roles.get(role_name)
        if not isinstance(info, dict) or not isinstance(keys, dict):
            return None
        return info, keys

    def _rotation_docs(self, s_a, s_b):
        # v1 (keys A, expired) -> v2 (keys B, expired) -> v3 (fresh).
        # Each envelope is sealed by its PREDECESSOR's key under the
        # predecessor's keyid, TUF root-rotation style.
        v1 = {"version": 1, "expires": PAST,
              "roles": {"root": {"keyids": ["kid-a"], "threshold": 1}},
              "keys": {"kid-a": keyval(s_a)}}
        v2 = {"version": 2, "expires": PAST,
              "roles": {"root": {"keyids": ["kid-b"], "threshold": 1}},
              "keys": {"kid-b": keyval(s_b)}}
        v3 = {"version": 3, "expires": FUTURE,
              "roles": {"root": {"keyids": ["kid-b"], "threshold": 1}},
              "keys": {"kid-b": keyval(s_b)}}
        w2 = seal_role("root", v2, [("kid-a", s_a)])
        return v1, v2, v3, w2

    def test_multihop_key_rotation(self):
        # The walk must follow the rotation: v2 verifies under v1's
        # keys (A), then v3 verifies under v2's keys (B).
        s_a, s_b = keypair(74), keypair(75)
        v1, v2, v3, w2 = self._rotation_docs(s_a, s_b)
        w3 = seal_role("root", v3, [("kid-b", s_b)])
        expired = (v1, {"keyids": ["kid-a"], "threshold": 1},
                   {"kid-a": keyval(s_a)})
        boot = bd.ExpiredBootstrap(self.verifier(),
                                   keys_of=self._root_keys_of)
        adopted = boot.adopt("root", expired, [(w2, v2), (w3, v3)], NOW)
        self.assertEqual(adopted["version"], 3)

    def test_multihop_stale_keys_refused(self):
        # v3 signed by the ROTATED-OUT key A must not verify: after
        # the walk adopts expired v2 (keys B), v3 has to clear B's
        # threshold.
        s_a, s_b = keypair(76), keypair(77)
        v1, v2, v3, w2 = self._rotation_docs(s_a, s_b)
        w3 = seal_role("root", v3, [("kid-a", s_a)])  # stale key A
        expired = (v1, {"keyids": ["kid-a"], "threshold": 1},
                   {"kid-a": keyval(s_a)})
        boot = bd.ExpiredBootstrap(self.verifier(),
                                   keys_of=self._root_keys_of)
        with self.assertRaises(bd.DeliveryError) as ctx:
            boot.adopt("root", expired, [(w2, v2), (w3, v3)], NOW)
        self.assertEqual(ctx.exception.code,
                         "bundle-delivery-expired-bootstrap-refused")


class ResolvePinTests(unittest.TestCase):
    def test_top_level_pin_shape(self):
        doc = delegated_doc({"b/x": {"length": 1, "hashes": {
            "sha256": "55" * 32}}}, [])

        class R:
            def verified_targets_doc(self):
                return doc
        pin = bd.resolve_pin(R(), "b/x", None, NOW)
        self.assertEqual(bd.strip_provenance(pin),
                         {"digest": "55" * 32, "chain_state": "trusted"})
        self.assertEqual(pin["_provenance_role"], "targets")

    def test_suspended_refresher_refused(self):
        class R:
            def verified_targets_doc(self):
                from gov.bundle_refresh import SuspendedError
                raise SuspendedError("suspended")
        with self.assertRaises(RefreshError):
            bd.resolve_pin(R(), "b/x", None, NOW)


class CacheLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bd-lock-")
        s = keypair(61)
        self.kid = "kid-root"
        self.keys = {self.kid: keyval(s)}
        role_info = {"keyids": [self.kid], "threshold": 1}
        now = datetime.now(timezone.utc)
        self.clock = lambda: now
        targets = {"_type": "targets", "version": 1,
                   "expires": FUTURE, "targets": {}}
        snap = {"_type": "snapshot", "version": 1, "expires": FUTURE,
                "meta": {"targets.json": {"version": 1}}}
        ts = {"_type": "timestamp", "version": 1, "expires": FUTURE,
              "snapshot_meta": {"version": 1}}
        root_doc = {"_type": "root", "version": 1, "expires": FUTURE,
                    "consistent_snapshot": True,
                    "roles": {r: dict(role_info)
                              for r in ("root", "timestamp",
                                        "snapshot", "targets")},
                    "keys": self.keys}
        self.root_wire = seal_role("root", root_doc, [(self.kid, s)])
        self.wires = {
            ("targets", 1): seal_role("targets", targets,
                                      [(self.kid, s)]),
            ("snapshot", 1): seal_role("snapshot", snap,
                                       [(self.kid, s)]),
            ("timestamp", 1): seal_role("timestamp", ts,
                                        [(self.kid, s)]),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fetch(self, role, version):
        key = (role, version)
        if key not in self.wires:
            raise FetchNotFound()
        return self.wires[key]

    def test_second_locked_refresher_refused(self):
        first = BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                clock=self.clock, cache_lock=True)
        try:
            with self.assertRaises(RefreshError) as ctx:
                BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                clock=self.clock, cache_lock=True)
            self.assertEqual(getattr(ctx.exception, "code", None),
                             "bundle-delivery-cache-locked")
        finally:
            first.close()

    def test_close_releases(self):
        first = BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                clock=self.clock, cache_lock=True)
        first.close()
        second = BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                 clock=self.clock, cache_lock=True)
        second.close()

    def test_default_is_unlocked(self):
        # test_bundle_refresh.py line 643 constructs two refreshers on
        # the same cache dir; the default must stay lock-free.
        first = BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                clock=self.clock)
        second = BundleRefresher(self.root_wire, self.fetch, self.tmp,
                                 clock=self.clock)
        first.close()
        second.close()


if __name__ == "__main__":
    unittest.main()
