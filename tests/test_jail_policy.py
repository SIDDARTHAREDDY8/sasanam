"""Unit tests for gov/jail_policy.py (wave-216 lane B).

Covers the jail-policy manifest schema, the signed/pinned activation,
the invocation conformance check, the backend coverage-gap discipline,
and the tighten-only Sandbox wiring. Red-first: these run green on the
fixed tree; the battery in evals/w216_jail_policy_probes.py carries the
pristine GAP evidence.
"""

import unittest

from gov import jail_policy as jp
from gov import ed25519 as _ed

NOW = 1785000000
FULL = {"timeout", "rlimit", "netns", "pidns", "pivot_root", "seccomp",
        "privdrop"}


def _issuer():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _body(**kw):
    args = {"policy_name": "tool-python", "version": 1,
            "writable_dirs": ["/output"], "timeout_s": 5,
            "not_before": NOW - 3600, "not_after": NOW + 3600}
    args.update(kw)
    return jp.make_policy_body(**args)


def _envelope(body, seed):
    return {"body": jp.validate_policy_body(body),
            "signature": jp.sign_policy(seed, body)}


def _registry(seed=None, **kw):
    if seed is None:
        seed, pub = _issuer()
    else:
        pub = _ed.publickey(seed)
    reg = jp.JailPolicyRegistry(pub)
    reg.activate(_envelope(_body(**kw), seed), now=NOW, features=FULL)
    return reg


class TestBodyValidation(unittest.TestCase):
    def test_normalize_paths(self):
        body = _body(writable_dirs=["/output//sub/../out"])
        norm = jp.validate_policy_body(body)
        self.assertEqual(norm["writable_dirs"], ["/output/out"])

    def test_root_mount_refused(self):
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(_body(writable_dirs=["/"]))
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_relative_dir_refused(self):
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(_body(writable_dirs=["output"]))
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_duplicate_dirs_refused(self):
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(_body(writable_dirs=["/output", "/output"]))
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_empty_dirs_refused(self):
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(_body(writable_dirs=[]))
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_unknown_field_refused(self):
        body = _body()
        body["extra"] = True
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(body)
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_missing_field_refused(self):
        body = _body()
        del body["timeout_s"]
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(body)
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_bad_format_refused(self):
        body = _body()
        body["format"] = "sasanam-jail-policy/v999"
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(body)
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_bad_name_refused(self):
        with self.assertRaises(jp.JailPolicyError):
            jp.validate_policy_body(_body(policy_name="Bad Name!"))

    def test_timeout_bounds(self):
        with self.assertRaises(jp.JailPolicyError):
            jp.validate_policy_body(_body(timeout_s=0))
        with self.assertRaises(jp.JailPolicyError):
            jp.validate_policy_body(_body(timeout_s=3601))
        jp.validate_policy_body(_body(timeout_s=3600))

    def test_resource_limits_shape(self):
        body = _body()
        body["resource_limits"] = {"cpu_s": 10}
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.validate_policy_body(body)
        self.assertEqual(cm.exception.code, "policy-body-malformed")

    def test_no_new_privs_must_be_true(self):
        body = _body()
        body["no_new_privs"] = False
        with self.assertRaises(jp.JailPolicyError):
            jp.validate_policy_body(body)

    def test_window_order(self):
        with self.assertRaises(jp.JailPolicyError):
            jp.validate_policy_body(
                _body(not_before=NOW + 100, not_after=NOW))

    def test_digest_deterministic(self):
        self.assertEqual(jp.policy_digest(_body()),
                         jp.policy_digest(_body()))
        self.assertEqual(len(jp.policy_digest(_body())), 64)


class TestSignAndRegistry(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        body = _body()
        norm = reg.activate(_envelope(body, seed), now=NOW, features=FULL)
        self.assertEqual(norm["policy_name"], "tool-python")

    def test_wrong_key_refused(self):
        rogue, _ = _issuer()
        _real, real_pub = _issuer()
        reg = jp.JailPolicyRegistry(real_pub)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.activate(_envelope(_body(), rogue), now=NOW, features=FULL)
        self.assertEqual(cm.exception.code, "policy-signature-invalid")

    def test_short_signature_refused(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.activate({"body": jp.validate_policy_body(_body()),
                          "signature": b"short"}, now=NOW, features=FULL)
        self.assertEqual(cm.exception.code, "policy-signature-invalid")

    def test_envelope_shape(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        with self.assertRaises(jp.JailPolicyError):
            reg.activate({"body": _body()}, now=NOW, features=FULL)

    def test_registry_key_shape(self):
        with self.assertRaises(jp.JailPolicyError):
            jp.JailPolicyRegistry(b"short")
        with self.assertRaises(jp.JailPolicyError):
            jp.JailPolicyRegistry("not-bytes")

    def test_version_floor(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        reg.activate(_envelope(_body(version=2), seed), now=NOW,
                     features=FULL)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.activate(_envelope(_body(version=2), seed), now=NOW,
                         features=FULL)
        self.assertEqual(cm.exception.code, "policy-version-downgrade")
        with self.assertRaises(jp.JailPolicyError):
            reg.activate(_envelope(_body(version=1), seed), now=NOW,
                         features=FULL)
        reg.activate(_envelope(_body(version=3), seed), now=NOW,
                     features=FULL)

    def test_names_independent_floors(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        reg.activate(_envelope(_body(policy_name="a", version=5), seed),
                     now=NOW, features=FULL)
        reg.activate(_envelope(_body(policy_name="b", version=1), seed),
                     now=NOW, features=FULL)

    def test_get_explicit_version_only(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        reg.activate(_envelope(_body(version=1), seed), now=NOW,
                     features=FULL)
        reg.activate(_envelope(_body(version=2), seed), now=NOW,
                     features=FULL)
        self.assertEqual(reg.get("tool-python", 1, now=NOW)["version"], 1)
        self.assertEqual(reg.get("tool-python", 2, now=NOW)["version"], 2)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.get("tool-python", 3, now=NOW)
        self.assertEqual(cm.exception.code, "policy-unknown")

    def test_stale_at_use_refused(self):
        seed, _pub = _issuer()
        reg = _registry(seed=seed)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.get("tool-python", 1, now=NOW + 7200)
        self.assertEqual(cm.exception.code, "policy-stale")


class TestInvocationCheck(unittest.TestCase):
    def test_conforming(self):
        reg = _registry()
        rep = reg.check("tool-python", 1,
                        {"writable_dirs": ["/output"], "wants_network": False,
                         "timeout_s": 5}, now=NOW)
        self.assertTrue(rep["conforms"])
        self.assertEqual(rep["policy_name"], "tool-python")

    def test_unknown_request_field_refused(self):
        reg = _registry()
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.check("tool-python", 1,
                      {"writable_dirs": [], "wants_network": False,
                       "timeout_s": 1, "bonus": 1}, now=NOW)
        self.assertEqual(cm.exception.code, "invocation-malformed")

    def test_sibling_dir_refused(self):
        reg = _registry()
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.check("tool-python", 1,
                      {"writable_dirs": ["/outputs"], "wants_network": False,
                       "timeout_s": 1}, now=NOW)
        # "/outputs" is a prefix, not a parent -- must not match
        self.assertEqual(cm.exception.code, "invocation-writable-dir-mismatch")

    def test_multiple_mounts(self):
        reg = _registry()
        multi = _body(writable_dirs=["/output", "/tmp/work"])
        seed = _ed.generate_seed()
        pub = _ed.publickey(seed)
        r2 = jp.JailPolicyRegistry(pub)
        r2.activate(_envelope(multi, seed), now=NOW, features=FULL)
        rep = r2.check("tool-python", 1,
                       {"writable_dirs": ["/output", "/tmp/work/x"],
                        "wants_network": False, "timeout_s": 5}, now=NOW)
        self.assertTrue(rep["conforms"])


class TestBackendGap(unittest.TestCase):
    def test_named_gap(self):
        seed, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        with self.assertRaises(jp.JailPolicyError) as cm:
            reg.activate(_envelope(_body(), seed), now=NOW,
                         features=FULL - {"pivot_root"})
        self.assertEqual(cm.exception.code,
                         "policy-needs-unimplemented-feature")
        self.assertIn("pivot_root", cm.exception.detail)

    def test_satisfied(self):
        body = _body()
        needs = jp.check_backend(body, features=FULL)
        self.assertIn("seccomp", needs)
        self.assertIn("netns", needs)

    def test_backend_features_returns_set(self):
        feats = jp.backend_features()
        self.assertIsInstance(feats, set)
        self.assertIn("timeout", feats)
        self.assertIn("rlimit", feats)


class TestWiring(unittest.TestCase):
    def test_kwargs_shape(self):
        body = jp.validate_policy_body(_body())
        kw = jp.to_sandbox_kwargs(body, {"/output": "/var/tmp/g-out"})
        self.assertEqual(kw["timeout"], 5)
        self.assertEqual(kw["memory_bytes"], 256 << 20)
        self.assertEqual(kw["cpu_seconds"], 10)
        self.assertEqual(kw["max_fds"], 64)
        self.assertEqual(kw["max_procs"], 64)
        self.assertEqual(kw["cage_mode"], "strict")
        self.assertTrue(kw["require_netns"] and kw["require_pidns"]
                        and kw["require_pivot_root"]
                        and kw["require_privdrop"] and kw["require_seccomp"])
        self.assertEqual(kw["pivot_extra_mounts"],
                         {"/var/tmp/g-out": "output"})

    def test_kwargs_accepted_by_sandbox(self):
        # The mapping must be honest constructor kwargs, not a guess.
        from gov import sandbox as sb
        import inspect
        body = jp.validate_policy_body(_body())
        kw = jp.to_sandbox_kwargs(body, {"/output": "/var/tmp/g-out"})
        params = inspect.signature(sb.Sandbox.__init__).parameters
        unknown = [k for k in kw if k not in params]
        self.assertEqual(unknown, [])

    def test_unwired_mount_refused(self):
        body = jp.validate_policy_body(_body(writable_dirs=["/output", "/x"]))
        with self.assertRaises(jp.JailPolicyError) as cm:
            jp.to_sandbox_kwargs(body, {"/output": "/var/tmp/g-out"})
        self.assertEqual(cm.exception.code, "wiring-unmapped-mount")


if __name__ == "__main__":
    unittest.main()
