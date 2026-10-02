"""Unit tests for gov.tool_call_policy (wave-286 lane 8).

Covers: caller binding (fromSource), the CUSTOM->DENY->ALLOW combining
order, audit-mode prospective evidence, hash-bound runtime identity,
exception routing (SKIPPED-never-PASSED, verdict stays DENY), the
authn-layer refusal, pin/drift binding, and the tighten-only CUSTOM
contract.
"""

import hashlib
import unittest

from gov import tool_call_policy as tcp
from gov import governed_exceptions as ge


def _doc(rules, mode="enforce", selector=None):
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "unit-policy",
        "selector": selector or {"agents": ["agent-a", "agent-b"]},
        "mode": mode,
        "rules": rules,
    }


def _caller(ident="agent-a", authenticated=True, tags=None):
    return {"identity": ident, "authenticated": authenticated,
            "tags": tags or []}


def _allow_rule(**kw):
    rule = {"tool": "shell", "operation": "exec", "action": "ALLOW",
            "severity": 3, "message": "ok"}
    rule.update(kw)
    return rule


NOW = 1700000000.0


class FromSourceBindingTest(unittest.TestCase):
    def test_bound_caller_allowed(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(from_source="agent-a"),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "ALLOW")

    def test_unbound_caller_denied(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(from_source="agent-a"),
        ]))
        d = pol.decide(_caller("agent-b"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")

    def test_unbound_deny_rule_binds_everyone(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8,
                 message="no exec"),
        ]))
        for ident in ("agent-a", "agent-b"):
            d = pol.decide(_caller(ident), "shell", "exec", {})
            self.assertEqual(d.verdict, "DENY")

    def test_glob_tool_pattern(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(tool="db.*"),
        ]))
        self.assertEqual(
            pol.decide(_caller("agent-a"), "db.read", "exec", {}).verdict,
            "ALLOW")
        self.assertEqual(
            pol.decide(_caller("agent-a"), "shell", "exec", {}).verdict,
            "DENY")


class CombiningOrderTest(unittest.TestCase):
    def test_deny_beats_allow(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(),
            dict(_allow_rule(), action="DENY", severity=8, message="deny"),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.rule_index, 1)

    def test_first_deny_rule_wins(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8, message="d1"),
            dict(_allow_rule(), action="DENY", severity=9, message="d2"),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.rule_index, 0)

    def test_default_deny_divergence(self):
        # Deliberate Istio divergence: no matching rule => DENY.
        pol = tcp.compile_policy(_doc([
            _allow_rule(tool="other", operation="read"),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.code, "toolcall-no-allow")
        self.assertIsNone(d.rule_index)

    def test_deny_missing_arg_matches(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=9,
                 args={"path": {"equals": "/etc/passwd"}}),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")

    def test_allow_requires_constrained_args_present(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(args={"mode": {"equals": "read-only"}}),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertIsNone(d.rule_index)  # default deny, not the ALLOW rule
        d2 = pol.decide(_caller("agent-a"), "shell", "exec",
                        {"mode": "read-only"})
        self.assertEqual(d2.verdict, "ALLOW")
        self.assertEqual(d2.rule_index, 0)

    def test_arg_matchers(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(args={"p": {"prefix": "/tmp/"}}),
        ]))
        self.assertEqual(
            pol.decide(_caller("agent-a"), "shell", "exec",
                       {"p": "/tmp/x"}).verdict, "ALLOW")
        self.assertEqual(
            pol.decide(_caller("agent-a"), "shell", "exec",
                       {"p": "/etc/x"}).verdict, "DENY")
        pol2 = tcp.compile_policy(_doc([
            _allow_rule(args={"p": {"regex": "^[a-z]+$"}}),
        ]))
        self.assertEqual(
            pol2.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "abc"}).verdict, "ALLOW")
        self.assertEqual(
            pol2.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "ABC"}).verdict, "DENY")
        pol3 = tcp.compile_policy(_doc([
            _allow_rule(args={"p": {"any_of": ["x", "y"]}}),
        ]))
        self.assertEqual(
            pol3.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "y"}).verdict, "ALLOW")
        self.assertEqual(
            pol3.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "z"}).verdict, "DENY")


class CustomAuthorizerTest(unittest.TestCase):
    def setUp(self):
        tcp.register_authorizer("unit-strict", lambda ctx: "deny")
        tcp.register_authorizer("unit-lax", lambda ctx: "allow")
        tcp.register_authorizer("unit-boom",
                                lambda ctx: 1 / 0)  # fail-closed path

    def test_custom_deny_tightens(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(),
            {"tool": "shell", "operation": "exec", "action": "CUSTOM",
             "custom_authorizer": "unit-strict", "severity": 8,
             "message": "custom"},
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.rejection_layer, "custom")
        self.assertEqual(d.code, "toolcall-custom-denied")

    def test_custom_allow_cannot_loosen(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8),
            {"tool": "shell", "operation": "exec", "action": "CUSTOM",
             "custom_authorizer": "unit-lax", "severity": 8,
             "message": "custom"},
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.rejection_layer, "authz")

    def test_custom_error_fails_closed(self):
        pol = tcp.compile_policy(_doc([
            _allow_rule(),
            {"tool": "shell", "operation": "exec", "action": "CUSTOM",
             "custom_authorizer": "unit-boom", "severity": 8,
             "message": "custom"},
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "DENY")
        self.assertEqual(d.rejection_layer, "custom")

    def test_unregistered_custom_refused_at_compile(self):
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            tcp.compile_policy(_doc([
                {"tool": "shell", "operation": "exec", "action": "CUSTOM",
                 "custom_authorizer": "no-such-authorizer", "severity": 8,
                 "message": "custom"},
            ]))
        self.assertEqual(cm.exception.code, "toolcall-policy-invalid")


class AuthnLayerTest(unittest.TestCase):
    def test_unauthenticated_refused_loud(self):
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            pol.decide(_caller("agent-a", authenticated=False), "shell",
                       "exec", {})
        self.assertEqual(cm.exception.code,
                         "toolcall-unauthenticated-caller")
        self.assertEqual(pol.alerts()[-1]["rejection_layer"], "authn")

    def test_out_of_scope_refused_loud(self):
        pol = tcp.compile_policy(_doc([_allow_rule()],
                                      selector={"agents": ["agent-a"]}))
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            pol.decide(_caller("agent-b"), "shell", "exec", {})
        self.assertEqual(cm.exception.code, "toolcall-caller-out-of-scope")

    def test_tag_selector(self):
        pol = tcp.compile_policy(
            _doc([_allow_rule()], selector={"agent_tags": ["ops"]}))
        d = pol.decide(_caller("agent-z", tags=["ops"]), "shell", "exec",
                       {})
        self.assertEqual(d.verdict, "ALLOW")


class AuditModeTest(unittest.TestCase):
    def test_would_deny_evidence_not_enforced(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8),
        ], mode="audit"))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "ALLOW")
        self.assertEqual(d.alert["action"], "AUDIT")
        self.assertEqual(d.alert["result"], "would-deny")
        self.assertEqual(d.alert["would_have"], "deny")
        self.assertEqual(d.code, "toolcall-audit-would-deny")

    def test_set_mode_returns_new_pinned_doc(self):
        doc = _doc([_allow_rule()], mode="audit")
        flipped = tcp.set_mode(doc, "enforce")
        self.assertEqual(flipped["mode"], "enforce")
        self.assertEqual(doc["mode"], "audit")  # input untouched
        self.assertNotEqual(tcp.policy_digest(flipped),
                            tcp.policy_digest(doc))


class IdentityHashTest(unittest.TestCase):
    def test_stable_and_arg_bound(self):
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        a1 = pol.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "x"}).alert
        a2 = pol.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "x"}).alert
        a3 = pol.decide(_caller("agent-a"), "shell", "exec",
                        {"p": "y"}).alert
        self.assertEqual(a1["runtime_identity_hash"],
                         a2["runtime_identity_hash"])
        self.assertNotEqual(a1["runtime_identity_hash"],
                            a3["runtime_identity_hash"])
        self.assertEqual(len(a1["runtime_identity_hash"]), 64)

    def test_policy_bound(self):
        p1 = tcp.compile_policy(_doc([_allow_rule()], ))
        p2 = tcp.compile_policy(_doc([_allow_rule()],
                                     selector={"agents": ["agent-a"]}))
        h1 = p1.decide(_caller("agent-a"), "shell", "exec", {}).alert[
            "runtime_identity_hash"]
        h2 = p2.decide(_caller("agent-a"), "shell", "exec", {}).alert[
            "runtime_identity_hash"]
        self.assertNotEqual(h1, h2)  # different policy digests


class PinDriftTest(unittest.TestCase):
    def test_unpinned_refused(self):
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            tcp.bind(pol, None)
        self.assertEqual(cm.exception.code, "toolcall-policy-unpinned")

    def test_bind_and_decide(self):
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        binding = tcp.bind(pol, pol.digest)
        d = binding.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(d.verdict, "ALLOW")
        self.assertEqual(len(binding.decisions()), 1)

    def test_drift_refused(self):
        # F340: the compiled document is deep-frozen -- post-compile
        # mutation is blocked at the source, so no drifted document can
        # reach bind().
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        with self.assertRaises(TypeError):
            pol._doc["rules"][0]["action"] = "DENY"
        with self.assertRaises(TypeError):
            pol._doc["mode"] = "audit"

    def test_wholesale_replace_detected_at_bind_and_decide(self):
        # A freeze-bypassing wholesale _doc replacement is caught by the
        # pin re-verification at bind() and at every decide().
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        pin = pol.digest
        binding = tcp.bind(pol, pin)
        evil = dict(_doc([_allow_rule()]))
        evil["mode"] = "audit"
        object.__setattr__(pol, "_doc", evil)
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            tcp.bind(pol, pin)
        self.assertEqual(cm.exception.code, "toolcall-policy-drift")
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            binding.decide(_caller("agent-a"), "shell", "exec", {})
        self.assertEqual(cm.exception.code, "toolcall-policy-drift")


class ExceptionRoutingTest(unittest.TestCase):
    def _store(self):
        reg = ge.CheckRegistry()
        reg.register("TOOLCALL_DENY_U", "denied tool call", "policy",
                     "high", "unit check", ["tool_call"])
        store = ge.ExceptionStore(reg)
        store.set_approvers(["op-1"])
        store.grant("TOOLCALL_DENY_U", ("tool", "shell"),
                    "unit-test accepted risk with ops review", "op-1",
                    NOW + 3600, NOW, now=NOW)
        return store

    def test_suppress_skipped_never_passed(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        s = tcp.suppress_with_exception(
            pol, d.alert["runtime_identity_hash"], self._store(),
            "TOOLCALL_DENY_U", ("tool", "shell"), now=NOW)
        self.assertEqual(s["action"], "SKIPPED")
        self.assertEqual(s["result"], "suppressed")
        self.assertEqual(s["verdict"], "DENY")  # verdict never upgrades
        self.assertTrue(s["exception_digest"])
        self.assertEqual(s["code"], "toolcall-exception-suppressed")

    def test_no_live_exception_refused(self):
        pol = tcp.compile_policy(_doc([
            dict(_allow_rule(), action="DENY", severity=8),
        ]))
        d = pol.decide(_caller("agent-a"), "shell", "exec", {})
        reg = ge.CheckRegistry()
        reg.register("TOOLCALL_DENY_U", "denied tool call", "policy",
                     "high", "unit check", ["tool_call"])
        store = ge.ExceptionStore(reg)
        with self.assertRaises(tcp.ToolCallPolicyError) as cm:
            tcp.suppress_with_exception(
                pol, d.alert["runtime_identity_hash"], store,
                "TOOLCALL_DENY_U", ("tool", "shell"), now=NOW)
        self.assertEqual(cm.exception.code,
                         "toolcall-no-covering-exception")

    def test_no_adhoc_skip_parameter(self):
        import inspect
        pol = tcp.compile_policy(_doc([_allow_rule()]))
        params = set(inspect.signature(pol.decide).parameters)
        self.assertFalse(params & {"skip", "suppress", "exception",
                                   "bypass"})


class CompileValidationTest(unittest.TestCase):
    def test_bad_documents_refused(self):
        bad = [
            {"format": "nope", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce", "rules": []},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {}, "mode": "enforce",
             "rules": [_allow_rule()]},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce", "rules": []},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce",
             "rules": [dict(_allow_rule(), action="MAYBE")]},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce",
             "rules": [dict(_allow_rule(),
                            args={"x": {"frobnicates": 1}})]},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce",
             "rules": [dict(_allow_rule(),
                            args={"x": {"regex": "(["}})]},
            {"format": "sasanam-tool-call-policy/v1", "name": "p",
             "selector": {"agents": ["a"]}, "mode": "enforce",
             "rules": [dict(_allow_rule(),
                            args={"x": {"regex": "a" * 300}})]},
        ]
        for doc in bad:
            with self.assertRaises(tcp.ToolCallPolicyError) as cm:
                tcp.compile_policy(doc)
            self.assertEqual(cm.exception.code, "toolcall-policy-invalid",
                             "doc: %r" % (doc,))


if __name__ == "__main__":
    unittest.main()
