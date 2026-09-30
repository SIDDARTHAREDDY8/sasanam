"""Unit tests for gov/version_manifest.py (wave-219 lane C).

Durable anti-rollback beyond expiry: atomic version manifests, distinct
refusal codes (rollback-detected vs policy-expired vs policy-unknown),
a seen-version registry with an explicit audited bootstrap, and
tighten-only wiring into the jail/measurement registries and promote()'s
quorum gate. Red-first: the battery in evals/w219_rollback_probes.py
carries the pristine GAP evidence; these tests pin the fixed behavior.
"""

import hashlib
import unittest

from gov import version_manifest as vm
from gov import jail_policy as jp
from gov import measurement_policy as mp
from gov import quorum_policy as qp
from gov import sign_deploy_namespaces as sdn
from gov import ed25519 as _ed
from gov.signing import Ed25519Signer, Ed25519Verifier

NOW = 1785000000
FULL = {"timeout", "rlimit", "netns", "pidns", "pivot_root", "seccomp",
        "privdrop"}


def _digest(name, version):
    return "sha256:" + hashlib.sha256(
        ("policy-%s-v%d" % (name, version)).encode("utf-8")).hexdigest()


def _entries(*pairs):
    return {name: {"version": v, "digest": _digest(name, v)}
            for name, v in pairs}


def _signer(seed_byte="a1"):
    return Ed25519Signer(bytes.fromhex(seed_byte * 32))


def _guard(entries, audit=None):
    signer = _signer()
    guard = vm.SeenVersionRegistry()
    guard.bootstrap(vm.make_manifest(entries, signer), signer.public_key,
                    audit=audit, now=NOW)
    return guard


class TestManifestAuthoring(unittest.TestCase):
    def test_empty_entries_refused(self):
        with self.assertRaises(vm.VersionManifestError) as cm:
            vm.make_manifest({}, _signer())
        self.assertEqual(cm.exception.code, "manifest-refused")

    def test_non_dict_entries_refused(self):
        with self.assertRaises(vm.VersionManifestError):
            vm.make_manifest([("a", 1)], _signer())

    def test_bad_version_refused(self):
        for bad in (0, -3, True, "5", 1.5):
            entries = {"p": {"version": bad, "digest": _digest("p", 1)}}
            with self.assertRaises(vm.VersionManifestError,
                                   msg="version %r" % (bad,)):
                vm.make_manifest(entries, _signer())

    def test_bad_digest_refused(self):
        for bad in ("nope", "sha256:" + "zz" * 32, "sha256:" + "ab" * 31,
                    "md5:" + "ab" * 32, None, 42):
            entries = {"p": {"version": 1, "digest": bad}}
            with self.assertRaises(vm.VersionManifestError,
                                   msg="digest %r" % (bad,)):
                vm.make_manifest(entries, _signer())

    def test_extra_entry_key_refused(self):
        entries = {"p": {"version": 1, "digest": _digest("p", 1),
                         "extra": "x"}}
        with self.assertRaises(vm.VersionManifestError) as cm:
            vm.make_manifest(entries, _signer())
        self.assertEqual(cm.exception.code, "manifest-refused")

    def test_empty_name_refused(self):
        with self.assertRaises(vm.VersionManifestError):
            vm.make_manifest({"": {"version": 1,
                                   "digest": _digest("x", 1)}}, _signer())

    def test_rogue_signature_refused(self):
        rogue = _signer("b2")
        manifest = vm.make_manifest(_entries(("p", 1)), rogue)
        guard = vm.SeenVersionRegistry()
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.bootstrap(manifest, _signer().public_key, now=NOW)
        self.assertEqual(cm.exception.code, "manifest-refused")

    def test_malformed_envelope_refused(self):
        signer = _signer()
        good = vm.make_manifest(_entries(("p", 1)), signer)
        guard = vm.SeenVersionRegistry()
        for bad in ({"body": good["body"]},  # missing signature
                    {"body": good["body"], "signature": good["signature"],
                     "extra": 1},
                    {"body": dict(good["body"], format="bogus/v9"),
                     "signature": good["signature"]}):
            with self.assertRaises(vm.VersionManifestError,
                                   msg="%r" % (bad,)):
                guard.bootstrap(bad, signer.public_key, now=NOW)

    def test_manifest_digest_stable(self):
        signer = _signer()
        m1 = vm.make_manifest(_entries(("p", 1)), signer)
        m2 = vm.make_manifest(_entries(("p", 1)), signer)
        self.assertEqual(vm.manifest_digest(m1), vm.manifest_digest(m2))
        self.assertTrue(vm.manifest_digest(m1).startswith("sha256:"))


class TestRegistryLifecycle(unittest.TestCase):
    def test_authorize_before_bootstrap(self):
        guard = vm.SeenVersionRegistry()
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.authorize_activation("p", 1, digest=_digest("p", 1),
                                       not_after=NOW + 1, now=NOW)
        self.assertEqual(cm.exception.code, "bootstrap-required")
        self.assertFalse(guard.bootstrapped)

    def test_bootstrap_audited(self):
        audit = []
        guard = _guard(_entries(("p", 5)), audit=audit)
        self.assertTrue(guard.bootstrapped)
        events = [e["event"] for e in audit]
        self.assertEqual(events, ["rollback-guard-bootstrap"])
        self.assertEqual(audit[0]["versions"], {"p": 5})

    def test_double_bootstrap_refused(self):
        guard = _guard(_entries(("p", 5)))
        signer = _signer()
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.bootstrap(vm.make_manifest(_entries(("p", 6)), signer),
                            signer.public_key, now=NOW)
        self.assertEqual(cm.exception.code, "already-bootstrapped")
        # History intact: v5 still the floor.
        with self.assertRaises(vm.VersionManifestError) as cm2:
            guard.authorize_activation("p", 4, digest=_digest("p", 4),
                                       not_after=NOW + 3600, now=NOW)
        self.assertEqual(cm2.exception.code, "rollback-detected")

    def test_update_manifest_adds_and_bumps(self):
        audit = []
        guard = _guard(_entries(("p", 5)), audit=audit)
        signer = _signer()
        pinned = guard.update_manifest(
            vm.make_manifest(_entries(("p", 6), ("q", 1)), signer),
            signer.public_key, audit=audit, now=NOW)
        self.assertEqual(pinned["p"]["version"], 6)
        self.assertIn("q", pinned)
        self.assertEqual(audit[-1]["event"],
                         "rollback-guard-manifest-update")

    def test_update_manifest_downgrade_refused(self):
        guard = _guard(_entries(("p", 5)))
        signer = _signer()
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.update_manifest(
                vm.make_manifest(_entries(("p", 4)), signer),
                signer.public_key, now=NOW)
        self.assertEqual(cm.exception.code, "manifest-downgrade-refused")
        # Old pinning still in force.
        self.assertEqual(guard.expected()["p"]["version"], 5)

    def test_update_bad_manifest_keeps_old(self):
        guard = _guard(_entries(("p", 5)))
        signer = _signer()
        bad = {"p": {"version": 6, "digest": "bogus"}}
        with self.assertRaises(vm.VersionManifestError):
            guard.update_manifest(vm.make_manifest(bad, signer),
                                  signer.public_key, now=NOW)
        self.assertEqual(guard.expected()["p"]["version"], 5)

    def test_update_before_bootstrap_refused(self):
        guard = vm.SeenVersionRegistry()
        signer = _signer()
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.update_manifest(vm.make_manifest(_entries(("p", 1)),
                                                   signer),
                                  signer.public_key, now=NOW)
        self.assertEqual(cm.exception.code, "bootstrap-required")

    def test_audit_callable_accepted(self):
        seen = []
        _guard(_entries(("p", 1)), audit=seen.append)
        self.assertEqual(len(seen), 1)

    def test_audit_bad_type_refused(self):
        guard = vm.SeenVersionRegistry()
        signer = _signer()
        with self.assertRaises(vm.VersionManifestError):
            guard.bootstrap(vm.make_manifest(_entries(("p", 1)), signer),
                            signer.public_key, audit=object(), now=NOW)

    def test_audit_bad_type_leaves_registry_unbootstrapped(self):
        # The audit-type check runs before any state commits.
        guard = vm.SeenVersionRegistry()
        signer = _signer()
        with self.assertRaises(vm.VersionManifestError):
            guard.bootstrap(vm.make_manifest(_entries(("p", 1)), signer),
                            signer.public_key, audit=object(), now=NOW)
        self.assertFalse(guard.bootstrapped)

    def test_unhashable_name_fails_closed(self):
        guard = _guard(_entries(("p", 5)))
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.authorize_activation(["p"], 5, digest=_digest("p", 5),
                                       not_after=NOW + 3600, now=NOW)
        self.assertEqual(cm.exception.code, "manifest-refused")


class TestGateSemantics(unittest.TestCase):
    def test_rollback_distinct_from_expiry_and_unknown(self):
        guard = _guard(_entries(("p", 5)))
        guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                   not_after=NOW + 3600, now=NOW)
        codes = {}
        for label, kwargs in (
                ("rollback", {"name": "p", "version": 3,
                              "not_after": NOW + 3600}),
                ("expired", {"name": "p", "version": 4,
                             "not_after": NOW - 1}),
                ("unknown", {"name": "zz", "version": 1,
                             "not_after": NOW + 3600})):
            try:
                guard.authorize_activation(
                    digest=_digest(kwargs["name"], kwargs["version"]),
                    now=NOW, **kwargs)
            except vm.VersionManifestError as exc:
                codes[label] = exc.code
        self.assertEqual(codes, {"rollback": "rollback-detected",
                                 "expired": "policy-expired",
                                 "unknown": "policy-unknown"})

    def test_upgrade_raises_floor(self):
        guard = _guard(_entries(("p", 5)))
        rep = guard.authorize_activation("p", 7, digest=_digest("p", 7),
                                         not_after=NOW + 3600, now=NOW)
        self.assertEqual(rep["floor"], 7)
        self.assertFalse(rep["replay"])
        self.assertEqual(guard.highest_seen(), {"p": 7})

    def test_replay_flag(self):
        guard = _guard(_entries(("p", 5)))
        first = guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                           not_after=NOW + 3600, now=NOW)
        second = guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                            not_after=NOW + 3600, now=NOW)
        self.assertFalse(first["replay"])
        self.assertTrue(second["replay"])

    def test_digest_tamper_on_replay(self):
        guard = _guard(_entries(("p", 5)))
        guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                   not_after=NOW + 3600, now=NOW)
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.authorize_activation("p", 5, digest="sha256:" + "00" * 32,
                                       not_after=NOW + 3600, now=NOW)
        self.assertEqual(cm.exception.code, "digest-mismatch")

    def test_no_expiry_bound_skips_expiry_check(self):
        guard = _guard(_entries(("p", 5)))
        rep = guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                         not_after=None, now=NOW)
        self.assertFalse(rep["expiry_checked"])
        self.assertEqual(rep["version"], 5)

    def test_check_use_is_non_mutating(self):
        guard = _guard(_entries(("p", 5)))
        guard.authorize_activation("p", 5, digest=_digest("p", 5),
                                   not_after=NOW + 3600, now=NOW)
        before = guard.highest_seen()
        out = guard.check_use("p", 5, digest=_digest("p", 5),
                              not_after=NOW + 3600, now=NOW)
        self.assertEqual(guard.highest_seen(), before)
        self.assertEqual(out["floor"], 5)
        with self.assertRaises(vm.VersionManifestError) as cm:
            guard.check_use("p", 3, not_after=NOW + 3600, now=NOW)
        self.assertEqual(cm.exception.code, "rollback-detected")

    def test_malformed_candidate_inputs_refused(self):
        guard = _guard(_entries(("p", 5)))
        for kwargs in ({"name": "p", "version": 0},
                       {"name": "p", "version": True},
                       {"name": "p", "version": "5"}):
            with self.assertRaises(vm.VersionManifestError,
                                   msg="%r" % (kwargs,)):
                guard.authorize_activation(digest=_digest("p", 5),
                                           not_after=NOW + 3600, now=NOW,
                                           **kwargs)


class TestWiring(unittest.TestCase):
    def _jail(self, name, version, seed, guard=None):
        body = jp.make_policy_body(policy_name=name, version=version,
                                    writable_dirs=["/output"], timeout_s=5,
                                    not_before=NOW - 3600,
                                    not_after=NOW + 3600)
        norm = jp.validate_policy_body(body)
        pub = _ed.publickey(seed)
        reg = jp.JailPolicyRegistry(pub)
        env = {"body": norm, "signature": jp.sign_policy(seed, norm)}
        return reg.activate(env, now=NOW, features=FULL,
                            rollback_guard=guard)

    def test_jail_guard_none_is_legacy(self):
        seed = _ed.generate_seed()
        body = self._jail("tool-python", 5, seed, guard=None)
        self.assertEqual(body["version"], 5)

    def test_jail_guard_type_checked(self):
        seed = _ed.generate_seed()
        body = jp.make_policy_body(policy_name="tool-python", version=5,
                                    writable_dirs=["/output"], timeout_s=5,
                                    not_before=NOW - 3600,
                                    not_after=NOW + 3600)
        norm = jp.validate_policy_body(body)
        reg = jp.JailPolicyRegistry(_ed.publickey(seed))
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.activate({"body": norm,
                          "signature": jp.sign_policy(seed, norm)},
                         now=NOW, features=FULL, rollback_guard=object())
        self.assertEqual(cm.exception.code, "registry-malformed")

    def test_measurement_guard_none_is_legacy(self):
        seed = _ed.generate_seed()
        body = mp.make_policy_body(policy_name="attest-os", version=5,
                                   required_measurements=[("os", "ab" * 32)],
                                   not_before=NOW - 3600,
                                   not_after=NOW + 3600, signer_kid="k1")
        reg = mp.MeasurementPolicyRegistry(_ed.publickey(seed))
        name, version = reg.activate(body, mp.sign_policy(seed, body),
                                     now=NOW, rollback_guard=None)
        self.assertEqual((name, version), ("attest-os", 5))

    def _promote_reg(self, guard=None, version=None):
        seed_a, seed_b = bytes.fromhex("51" * 32), bytes.fromhex("52" * 32)
        signers = [Ed25519Signer(seed_a), Ed25519Signer(seed_b)]
        verifiers = [Ed25519Verifier(s.public_key) for s in signers]
        step = qp.load_quorum_step({
            "step_name": "promote",
            "authorized_keyids": [s.key_id for s in signers],
            "threshold": 2})
        reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
        reg.stage("skill/q", b"bytes")
        reg.sign("skill/q", [signers[0]])
        links = [qp.make_link_record("promote", "ab" * 32, s)
                 for s in signers]
        kwargs = {"operator_ids": ["op1", "op2"], "quorum_policy": step,
                  "quorum_links": links}
        if guard is not None or version is not None:
            kwargs["quorum_rollback_guard"] = guard
            kwargs["quorum_policy_version"] = version
        return reg, kwargs

    def test_promote_guard_missing_version_refused(self):
        guard = _guard({"quorum:promote": {"version": 5,
                                           "digest": _digest("q", 5)}})
        reg, kwargs = self._promote_reg(guard=guard, version=None)
        with self.assertRaises(sdn.NamespaceError) as cm:
            reg.promote("skill/q", **kwargs)
        self.assertEqual(cm.exception.code, "quorum-rollback-refused")
        self.assertEqual(reg.audit[-1]["op"], "promotion-denied")

    def test_promote_guard_bad_type_refused(self):
        reg, kwargs = self._promote_reg(guard=object(), version=5)
        with self.assertRaises(sdn.NamespaceError) as cm:
            reg.promote("skill/q", **kwargs)
        self.assertEqual(cm.exception.code, "bad-quorum-rollback-guard")


if __name__ == "__main__":
    unittest.main()
