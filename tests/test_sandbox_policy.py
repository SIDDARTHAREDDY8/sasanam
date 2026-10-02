"""Unit tests for gov/sandbox_policy.py (wave-284 lane 7, nsjail STEAL)."""

import json
import os
import shutil
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import sandbox_policy as sp  # noqa: E402


GOOD_DOC = {
    "policy_schema_version": 1,
    "policy_id": "unit-test-policy",
    "namespaces": {"net": True, "pid": True},
    "rlimits": {"cpu_seconds": 30, "open_files": 64},
    "budgets": {"max_wall_seconds": 60, "max_output_bytes": 1024},
    "mounts": {"readonly": ["/usr"], "writable": [], "masked": ["/proc/kcore"]},
    "syscalls": {
        "default": "kill",
        "allow": ["read", "write"],
        "deny": ["execve"],
        "rules": [
            "POLICY mem { DEFAULT KILL "
            "ALLOW { mmap((prot & 4) == 0) } "
            "DENY { } }"
        ],
    },
}


def _doc(**overrides):
    doc = dict(GOOD_DOC)
    doc.update(overrides)
    return doc


class CompileTest(unittest.TestCase):
    def test_valid_compiles(self):
        pol = sp.compile_policy(_doc())
        self.assertEqual(pol.policy_id, "unit-test-policy")
        self.assertEqual(pol.default, "kill")
        self.assertEqual(len(pol.digest), 64)

    def test_digest_stable_across_key_order(self):
        a = sp.compile_policy(_doc())
        shuffled = {k: GOOD_DOC[k] for k in reversed(list(GOOD_DOC))}
        b = sp.compile_policy(shuffled)
        self.assertEqual(a.digest, b.digest)

    def test_no_default_refused(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["default"] = "bogus"
        doc["syscalls"] = doc_syscalls
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-no-default")

    def test_missing_default_key_refused(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        del doc_syscalls["default"]
        doc["syscalls"] = doc_syscalls
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-no-default")

    def test_malformed_rule_refused(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["rules"] = ["POLICY broken { ALLOW { mmap((prot & } }"]
        doc["syscalls"] = doc_syscalls
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def _rules_doc(self, rules):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["rules"] = rules
        doc["syscalls"] = doc_syscalls
        return doc

    def test_allow_without_space_refused_loud(self):
        # ALLOW{read} must not silently compile to a policy where
        # read is killed: the reviewer read an allowance.
        doc = self._rules_doc(
            ["POLICY x { DEFAULT KILL ALLOW{read} DENY { } }"])
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_intra_block_garbage_refused_loud(self):
        doc = self._rules_doc(
            ["POLICY x { DEFAULT KILL FOOBAR { nonsense } }"])
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_nested_policy_block_refused_loud(self):
        # An inner DEFAULT must not silently override the outer one.
        doc = self._rules_doc(
            ["POLICY outer { DEFAULT ALLOW "
             "POLICY inner { DEFAULT KILL } }"])
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_default_with_entries_refused_loud(self):
        doc = self._rules_doc(
            ["POLICY x { DEFAULT KILL { read } ALLOW { } DENY { } }"])
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_garbage_between_blocks_refused_loud(self):
        doc = self._rules_doc(
            ["POLICY a { DEFAULT KILL ALLOW { } DENY { } } trailing junk"])
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_unbalanced_braces_refused(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["rules"] = ["POLICY broken { DEFAULT KILL ALLOW { read }"]
        doc["syscalls"] = doc_syscalls
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_unknown_namespace_refused(self):
        doc = _doc()
        doc_ns = dict(doc["namespaces"])
        doc_ns["bogus"] = True
        doc["namespaces"] = doc_ns
        with self.assertRaises(sp.SandboxPolicyInvalid) as ctx:
            sp.compile_policy(doc)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_relative_mount_refused(self):
        doc = _doc()
        doc_mounts = dict(doc["mounts"])
        doc_mounts["readonly"] = ["relative/path"]
        doc["mounts"] = doc_mounts
        with self.assertRaises(sp.SandboxPolicyInvalid):
            sp.compile_policy(doc)

    def test_negative_rlimit_refused(self):
        doc = _doc()
        doc_rlimits = dict(doc["rlimits"])
        doc_rlimits["cpu_seconds"] = -1
        doc["rlimits"] = doc_rlimits
        with self.assertRaises(sp.SandboxPolicyInvalid):
            sp.compile_policy(doc)

    def test_unknown_section_refused(self):
        doc = _doc(bogus_section={})
        with self.assertRaises(sp.SandboxPolicyInvalid):
            sp.compile_policy(doc)

    def test_bad_schema_version_refused(self):
        with self.assertRaises(sp.SandboxPolicyInvalid):
            sp.compile_policy(_doc(policy_schema_version=2))

    def test_rule_default_mismatch_refused(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["default"] = "allow"
        # rules still say DEFAULT KILL -> disagreement refuses
        doc["syscalls"] = doc_syscalls
        with self.assertRaises(sp.SandboxPolicyInvalid):
            sp.compile_policy(doc)


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.pol = sp.compile_policy(_doc())

    def test_allow(self):
        self.assertEqual(self.pol.decide("read", {}), "allow")

    def test_kill_unknown(self):
        self.assertEqual(self.pol.decide("open", {}), "kill")

    def test_deny_list_kills(self):
        self.assertEqual(self.pol.decide("execve", {}), "kill")

    def test_rule_deny_kills(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["rules"] = [
            "POLICY x { DEFAULT KILL ALLOW { } DENY { ptrace } }"]
        doc["syscalls"] = doc_syscalls
        pol = sp.compile_policy(doc)
        self.assertEqual(pol.decide("ptrace", {}), "kill")

    def test_arg_filter_allows_and_kills(self):
        self.assertEqual(self.pol.decide("mmap", {"prot": 3}), "allow")
        self.assertEqual(self.pol.decide("mmap", {"prot": 5}), "kill")

    def test_missing_arg_fails_closed(self):
        self.assertEqual(self.pol.decide("mmap", {}), "kill")

    def test_wrong_typed_arg_fails_closed(self):
        self.assertEqual(self.pol.decide("mmap", {"prot": "3"}), "kill")

    def test_bad_syscall_name_kills(self):
        self.assertEqual(self.pol.decide("../../etc", {}), "kill")
        self.assertEqual(self.pol.decide("", {}), "kill")

    def test_default_allow(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["default"] = "allow"
        doc_syscalls["rules"] = [
            "POLICY x { DEFAULT ALLOW ALLOW { } DENY { execve } }"]
        doc["syscalls"] = doc_syscalls
        pol = sp.compile_policy(doc)
        self.assertEqual(pol.decide("anything_at_all", {}), "allow")
        self.assertEqual(pol.decide("execve", {}), "kill")

    def test_default_deny(self):
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["default"] = "deny"
        doc_syscalls["rules"] = [
            "POLICY x { DEFAULT DENY ALLOW { read } DENY { } }"]
        doc["syscalls"] = doc_syscalls
        pol = sp.compile_policy(doc)
        self.assertEqual(pol.decide("open", {}), "deny")
        self.assertEqual(pol.decide("read", {}), "allow")


class PinAndDiffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sp-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pin_path = os.path.join(self.tmp, "pins.json")
        self.pol = sp.compile_policy(_doc())

    def test_non_string_pin_refused_coded(self):
        # A non-str pin value must surface as a coded refusal, not a
        # bare TypeError from digest truncation (S2).
        pol = sp.compile_policy(_doc())
        pins = {pol.policy_id: 12345}
        with self.assertRaises(sp.SandboxPolicyError) as ctx:
            sp.check_policy_use(pol, pins)
        self.assertEqual(ctx.exception.code, "sandbox-policy-invalid")

    def test_unpinned_refused(self):
        with self.assertRaises(sp.SandboxPolicyRefused) as ctx:
            sp.check_policy_use(self.pol, {})
        self.assertEqual(ctx.exception.code, "sandbox-policy-unpinned")

    def test_pinned_ok(self):
        sp.pin_policy(self.pol.policy_id, self.pol.digest, self.pin_path)
        pins = sp.load_pins(self.pin_path)
        self.assertEqual(sp.check_policy_use(self.pol, pins), self.pol.digest)

    def test_drift_refused_superset(self):
        sp.pin_policy(self.pol.policy_id, self.pol.digest, self.pin_path)
        pins = sp.load_pins(self.pin_path)
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["allow"] = ["read", "write", "open"]
        doc["syscalls"] = doc_syscalls
        drifted = sp.compile_policy(doc)
        with self.assertRaises(sp.SandboxPolicyRefused) as ctx:
            sp.check_policy_use(drifted, pins)
        self.assertEqual(ctx.exception.code, "sandbox-policy-drift")

    def test_drift_refused_subset(self):
        sp.pin_policy(self.pol.policy_id, self.pol.digest, self.pin_path)
        pins = sp.load_pins(self.pin_path)
        doc = _doc()
        doc_syscalls = dict(doc["syscalls"])
        doc_syscalls["allow"] = ["read"]
        doc["syscalls"] = doc_syscalls
        drifted = sp.compile_policy(doc)
        with self.assertRaises(sp.SandboxPolicyRefused):
            sp.check_policy_use(drifted, pins)

    def test_pin_store_round_trip(self):
        sp.pin_policy("a", "0" * 64, self.pin_path)
        sp.pin_policy("b", "f" * 64, self.pin_path)
        pins = sp.load_pins(self.pin_path)
        self.assertEqual(pins, {"a": "0" * 64, "b": "f" * 64})

    def test_corrupt_pin_store_refuses(self):
        with open(self.pin_path, "w") as handle:
            handle.write("{not json")
        with self.assertRaises(sp.SandboxPolicyError):
            sp.load_pins(self.pin_path)

    def test_policy_diff(self):
        doc = _doc()
        doc_ns = dict(doc["namespaces"])
        doc_ns["net"] = False
        doc["namespaces"] = doc_ns
        other = sp.compile_policy(doc)
        diff = sp.policy_diff(self.pol, other)
        self.assertIn("namespaces.net", diff)
        self.assertEqual(sp.policy_diff(self.pol, self.pol), [])


class BindTest(unittest.TestCase):
    def setUp(self):
        self.pol = sp.compile_policy(_doc())
        self.pins = {self.pol.policy_id: self.pol.digest}

    def test_bind_ok_when_enforced(self):
        binding = sp.bind(self.pol, self.pins,
                          enforced_namespaces={"net", "pid"})
        self.assertEqual(binding.digest, self.pol.digest)
        self.assertEqual(binding.decide("read", {}), "allow")

    def test_bind_refuses_host_mismatch(self):
        with self.assertRaises(sp.SandboxPolicyRefused) as ctx:
            sp.bind(self.pol, self.pins, enforced_namespaces=set())
        self.assertEqual(ctx.exception.code, "sandbox-policy-host-mismatch")

    def test_bind_refuses_unpinned_first(self):
        with self.assertRaises(sp.SandboxPolicyRefused) as ctx:
            sp.bind(self.pol, {}, enforced_namespaces={"net", "pid"})
        self.assertEqual(ctx.exception.code, "sandbox-policy-unpinned")

    def test_bind_refuses_unknown_namespace(self):
        with self.assertRaises(sp.SandboxPolicyError):
            sp.bind(self.pol, self.pins,
                    enforced_namespaces={"net", "pid", "bogus"})


class AuditTest(unittest.TestCase):
    def test_kill_audited_with_digest(self):
        pol = sp.compile_policy(_doc())
        pins = {pol.policy_id: pol.digest}
        binding = sp.bind(pol, pins, enforced_namespaces={"net", "pid"})
        seen = []
        sp.set_emit(seen.append)
        try:
            decision = binding.decide("execve", {})
        finally:
            sp.set_emit(None)
        self.assertEqual(decision, "kill")
        self.assertEqual(len(seen), 1)
        event = seen[0]
        self.assertEqual(event["record_type"], "sandbox-policy-decision")
        self.assertEqual(event["policy_digest"], pol.digest)
        self.assertEqual(event["decision"], "kill")
        self.assertEqual(event["syscall"], "execve")

    def test_dead_sink_never_breaks(self):
        def boom(_event):
            raise RuntimeError("sink is dead")
        sp.set_emit(boom)
        try:
            sp.audit_decision("0" * 64, "read", "allow")
        finally:
            sp.set_emit(None)

    def test_dead_sink_warns_loud_once_then_silent(self):
        # One loud stderr line on the first sink failure; the rest
        # swallowed silently so a broken pipeline cannot degrade
        # into silent (H1: docstring now matches the code).
        import io
        from contextlib import redirect_stderr
        sp._emit_loud_done = False
        def boom(_event):
            raise RuntimeError("sink is dead")
        sp.set_emit(boom)
        try:
            first = io.StringIO()
            with redirect_stderr(first):
                sp.audit_decision("0" * 64, "read", "allow")
            second = io.StringIO()
            with redirect_stderr(second):
                sp.audit_decision("0" * 64, "read", "allow")
        finally:
            sp.set_emit(None)
            sp._emit_loud_done = False
        self.assertIn("sandbox-policy: audit sink failed", first.getvalue())
        self.assertEqual(second.getvalue(), "")

    def test_kill_event_carries_decision_code(self):
        pol = sp.compile_policy(_doc())
        pins = {pol.policy_id: pol.digest}
        binding = sp.bind(pol, pins, enforced_namespaces={"net", "pid"})
        seen = []
        sp.set_emit(seen.append)
        try:
            binding.decide("execve", {})
            binding.decide("read", {})
        finally:
            sp.set_emit(None)
        by_decision = {e["decision"]: e for e in seen}
        self.assertEqual(by_decision["kill"]["code"], "sandbox-policy-kill")
        self.assertNotIn("code", by_decision["allow"])


class SandboxCompositionTest(unittest.TestCase):
    """The gov/sandbox.py adapter: only PROVEN isolation counts."""

    class _FakeResult:
        def __init__(self, net, pid):
            self.network_isolated = net
            self.pid_isolated = pid

    def test_enforced_from_result(self):
        result = self._FakeResult(True, False)
        self.assertEqual(sp.enforced_from_sandbox_result(result), {"net"})

    def test_enforced_from_result_duck_typed(self):
        self.assertEqual(sp.enforced_from_sandbox_result(object()), set())

    def test_bind_result_refuses_unproven(self):
        pol = sp.compile_policy(_doc())  # requires net + pid
        pins = {pol.policy_id: pol.digest}
        result = self._FakeResult(True, False)  # pid not proven
        with self.assertRaises(sp.SandboxPolicyRefused) as ctx:
            sp.bind_result(pol, pins, result)
        self.assertEqual(ctx.exception.code, "sandbox-policy-host-mismatch")

    def test_bind_result_ok_when_proven(self):
        pol = sp.compile_policy(_doc())
        pins = {pol.policy_id: pol.digest}
        result = self._FakeResult(True, True)
        binding = sp.bind_result(pol, pins, result)
        self.assertEqual(binding.decide("read", {}), "allow")


if __name__ == "__main__":
    unittest.main()
