"""Unit tests for compile-everything-at-registration (wave-219 lane A).

Pins the wave-219 additions to gov/policy_compile.py: the FieldError
diagnostic taxonomy, PolicyCompilationError, the named compile_* front
gates, the compiled verifier classes, audit events, parity with legacy
behavior, and the compile-code / evaluation-code separation.

Note (2026-09-27 lesson, adapted): pins go through the public seams
only; no intent-ledger similarity involvement here.
"""

import json
import unittest

from gov import arap as _arap
from gov import jail_policy as _jp
from gov import policy_compile as pc
from gov import quorum_policy as _qp

NOW = 1785000000
KEY = b"deployment-key-16"


def _body(**kw):
    args = {"policy_name": "tool-python", "version": 1,
            "writable_dirs": ["/output"], "timeout_s": 5,
            "not_before": NOW - 3600, "not_after": NOW + 3600}
    args.update(kw)
    return _jp.make_policy_body(**args)


class TestFieldError(unittest.TestCase):
    def test_shape_and_json(self):
        e = pc.FieldError("step[3].authorized_keyids[2]",
                          "a non-empty string keyid", "")
        self.assertEqual(e.path, "step[3].authorized_keyids[2]")
        self.assertEqual(e.expected, "a non-empty string keyid")
        self.assertEqual(e.got, "")
        self.assertEqual(e.detail, "")
        json.dumps(e.to_dict())  # JSON-serializable

    def test_got_is_repr_safe(self):
        e = pc.FieldError("key", ">= 16 bytes", b"\x00\xff")
        self.assertIsInstance(e.got, str)
        self.assertIn("\\x00", e.got)

    def test_via_field_and_index(self):
        e = pc.FieldError("authorized_keyids[1]", "a non-empty string", 7)
        self.assertEqual(e.via_field("step").path,
                         "step.authorized_keyids[1]")
        self.assertEqual(e.via_index(3).path, "authorized_keyids[1][3]")

    def test_str_contains_expected_vs_got(self):
        e = pc.FieldError("threshold", "1 <= threshold <= 3", 0)
        text = str(e)
        self.assertIn("threshold", text)
        self.assertIn("1 <= threshold <= 3", text)


class TestPolicyCompilationError(unittest.TestCase):
    def test_code_and_errors(self):
        errors = [pc.FieldError("threshold", "1 <= t <= 3", 0)]
        exc = pc.PolicyCompilationError("quorum", errors)
        self.assertEqual(exc.code, "policy-compile-refused")
        self.assertEqual(len(exc.errors), 1)
        self.assertIsInstance(exc.errors[0], pc.FieldError)
        self.assertIn("policy-compile-refused", str(exc))

    def test_subclasses_authoring_error(self):
        from gov import identity_policy as _ip
        self.assertTrue(issubclass(pc.PolicyCompilationError,
                                  _ip.PolicyAuthoringError))

    def test_audit_on_refusal(self):
        events = []
        with self.assertRaises(pc.PolicyCompilationError):
            pc.compile_quorum_step({"step_name": "s", "authorized_keyids": [],
                                    "threshold": 0}, audit=events.append)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "policy_compile_refused")
        self.assertEqual(ev["code"], "policy-compile-refused")
        self.assertEqual(ev["policy_type"], "quorum")
        self.assertTrue(all(set(e) >= {"path", "expected", "got"}
                            for e in ev["errors"]))
        json.dumps(ev)

    def test_audit_on_success(self):
        events = []
        pc.compile_quorum_step(
            {"step_name": "s", "authorized_keyids": ["a"], "threshold": 1},
            audit=events.append)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "policy_compiled")
        self.assertEqual(ev["policy_type"], "quorum")
        self.assertEqual(len(ev["fingerprint"]), 64)
        json.dumps(ev)


class TestCompileQuorum(unittest.TestCase):
    SPEC = {"step_name": "release", "authorized_keyids": ["k1", "k2"],
            "threshold": 2}

    def test_named_gate_returns_compiled(self):
        c = pc.compile_quorum_step(dict(self.SPEC))
        self.assertIsInstance(c, pc.CompiledQuorumStep)
        self.assertEqual(len(c.fingerprint()), 64)

    def test_accepts_loaded_step(self):
        c = pc.compile_quorum_step(_qp.load_quorum_step(dict(self.SPEC)))
        self.assertEqual(c.step.step_name, "release")

    def test_rejects_garbage_constructor(self):
        with self.assertRaises(pc.PolicyCompilationError):
            pc.CompiledQuorumStep(42)

    def test_aggregates_field_errors(self):
        bad = {"step_name": "", "authorized_keyids": ["k1", "", "k1"],
               "threshold": 0, "mystery": 1}
        with self.assertRaises(pc.PolicyCompilationError) as cm:
            pc.compile_quorum_step(bad)
        paths = sorted(e.path for e in cm.exception.errors)
        self.assertEqual(paths, ["authorized_keyids[1]", "spec.mystery",
                                 "step_name", "threshold"])
        # an invalid kid entry suppresses the duplicate check (roster is
        # not valid for counting); duplicates are pinned separately in
        # test_duplicate_keyids_refused
        self.assertNotIn("authorized_keyids",
                         [e.path for e in cm.exception.errors])

    def test_duplicate_keyids_refused(self):
        bad = dict(self.SPEC); bad["authorized_keyids"] = ["k1", "k1"]
        with self.assertRaises(pc.PolicyCompilationError) as cm:
            pc.compile_quorum_step(bad)
        self.assertTrue(any(e.path == "authorized_keyids"
                            for e in cm.exception.errors))

    def test_evaluation_is_data_only(self):
        c = pc.compile_quorum_step(dict(self.SPEC))
        # bad link records raise the MODULE's evaluation error, never
        # PolicyCompilationError
        with self.assertRaises(_qp.QuorumPolicyError):
            c.verify([], {})


class TestCompileArap(unittest.TestCase):
    def test_named_gate(self):
        c = pc.compile_arap_context({"region": "us"}, key=KEY)
        self.assertIsInstance(c, pc.CompiledArapContext)
        self.assertEqual(len(c.fingerprint()), 64)

    def test_pin_excludes_key(self):
        c1 = pc.compile_arap_context({"region": "us"}, key=KEY)
        c2 = pc.compile_arap_context({"region": "us"},
                                     key=b"another-16-byte!")
        self.assertEqual(c1.fingerprint(), c2.fingerprint())
        self.assertNotIn(KEY, c1.binding.encode("latin1", "ignore")
                         if isinstance(c1.binding, str) else b"")

    def test_short_key_compile_error(self):
        with self.assertRaises(pc.PolicyCompilationError) as cm:
            pc.compile_arap_context({"a": "b"}, key=b"short")
        self.assertEqual(cm.exception.code, "policy-compile-refused")
        self.assertTrue(any(e.path == "key"
                            for e in cm.exception.errors))

    def test_wrong_eval_key_is_data_error(self):
        c = pc.compile_arap_context({"region": "us"}, key=KEY)
        with self.assertRaises(_arap.ContextNotDeclaredError) as cm:
            c.verify_binding(key=b"another-16-byte!")
        self.assertEqual(cm.exception.code, "context-key-mismatch")
        # evaluation codes are disjoint from the compile code
        self.assertNotEqual(cm.exception.code,
                            pc.PolicyCompilationError.code)

    def test_verify_binding_ok(self):
        c = pc.compile_arap_context({"region": "us"}, key=KEY)
        self.assertIsNone(c.verify_binding(key=KEY))
        self.assertTrue(c.check_cited(["region"]))

    def test_key_fingerprint_identifies_key(self):
        c = pc.compile_arap_context({"region": "us"}, key=KEY)
        self.assertEqual(len(c.key_fingerprint), 64)
        c2 = pc.compile_arap_context({"region": "us"},
                                     key=b"another-16-byte!")
        self.assertNotEqual(c.key_fingerprint, c2.key_fingerprint)


class TestCompileJail(unittest.TestCase):
    def test_named_gate(self):
        c = pc.compile_jail_policy(_body())
        self.assertIsInstance(c, pc.CompiledJailPolicy)
        self.assertEqual(c.fingerprint(),
                         _jp.policy_digest(
                             _jp.validate_policy_body(_body())))

    def test_rejects_garbage_constructor(self):
        with self.assertRaises(pc.PolicyCompilationError):
            pc.CompiledJailPolicy("not a dict")

    def test_refused_fields_pinned(self):
        bad = _body()
        bad["network"] = "host"
        bad["timeout_s"] = 99999
        with self.assertRaises(pc.PolicyCompilationError) as cm:
            pc.compile_jail_policy(bad)
        paths = sorted(e.path for e in cm.exception.errors)
        self.assertEqual(paths, ["network", "timeout_s"])

    def test_check_parity_with_legacy(self):
        c = pc.compile_jail_policy(_body())
        req = {"writable_dirs": ["/output"], "wants_network": False,
               "timeout_s": 5}
        legacy = _jp.check_invocation(_jp.validate_policy_body(_body()),
                                      req)
        self.assertEqual(c.check(req), legacy)

    def test_check_backend_named_gap(self):
        c = pc.compile_jail_policy(_body())
        with self.assertRaises(_jp.JailPolicyError) as cm:
            c.check_backend(features={"timeout"})
        self.assertEqual(cm.exception.code,
                         "policy-needs-unimplemented-feature")


class TestCompilePolicyDispatch(unittest.TestCase):
    def test_quorum_dict(self):
        c = pc.compile_policy({"step_name": "s", "authorized_keyids": ["a"],
                               "threshold": 1})
        self.assertIsInstance(c, pc.CompiledQuorumStep)

    def test_quorum_step_instance(self):
        step = _qp.load_quorum_step(
            {"step_name": "s", "authorized_keyids": ["a"], "threshold": 1})
        c = pc.compile_policy(step)
        self.assertIsInstance(c, pc.CompiledQuorumStep)

    def test_jail_body(self):
        c = pc.compile_policy(_body())
        self.assertIsInstance(c, pc.CompiledJailPolicy)

    def test_identity_unchanged(self):
        c = pc.compile_policy({"unsafeAllow": "test-only"})
        self.assertIsInstance(c, pc.CompiledIdentityPolicy)

    def test_garbage_still_refused(self):
        from gov import identity_policy as _ip
        with self.assertRaises(_ip.PolicyAuthoringError):
            pc.compile_policy(42)


if __name__ == "__main__":
    unittest.main()
