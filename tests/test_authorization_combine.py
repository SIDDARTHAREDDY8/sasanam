"""Unit tests for gov/authorization_combine.py (wave-268 lane).

Pin 1579 is asserted here; repointed by the wave-275 merge coordinator.
"""

import re
import time
import unittest

import gov.authorization_combine as ac
import gov.decision_codes as dc


def _rule(name, action, frm=None, to=None, when=None, shadow=False,
          provider=None):
    r = {"name": name, "action": action}
    if frm is not None:
        r["from"] = frm
    if to is not None:
        r["to"] = to
    if when is not None:
        r["when"] = when
    if shadow:
        r["shadow"] = True
    if provider is not None:
        r["provider"] = provider
    return r


def _bundle(rules, authorizers=None):
    doc = {"version": "sasanam-authz-bundle/v1", "rules": rules}
    if authorizers is not None:
        doc["external_authorizers"] = authorizers
    return ac.load_bundle(doc)


def _req(principal="agent:alice", action="tool.exec",
         resource="secret/db", context=None):
    return {"principal": principal, "action": action,
            "resource": resource,
            "context": dict(context) if context else {}}


class LoadValidationTests(unittest.TestCase):
    def test_non_dict_bundle_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            ac.load_bundle(["nope"])
        self.assertEqual(cm.exception.code, "authz-malformed-bundle")

    def test_wrong_version_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            ac.load_bundle({"version": "v0", "rules": []})
        self.assertEqual(cm.exception.code, "authz-malformed-bundle")

    def test_unknown_bundle_key_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            ac.load_bundle({"version": "sasanam-authz-bundle/v1",
                            "rules": [], "bogus": 1})
        self.assertEqual(cm.exception.code, "authz-malformed-bundle")

    def test_nameless_rule_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            ac.load_bundle({"version": "sasanam-authz-bundle/v1",
                            "rules": [{"action": "deny"}]})
        self.assertEqual(cm.exception.code, "authz-malformed-rule")

    def test_unknown_action_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("r", "block")])
        self.assertEqual(cm.exception.code, "authz-malformed-rule")

    def test_duplicate_rule_names_refuse(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("dup", "deny"), _rule("dup", "allow")])
        self.assertEqual(cm.exception.code, "authz-malformed-bundle")

    def test_custom_rule_needs_provider(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("c", "custom")])
        self.assertEqual(cm.exception.code, "authz-malformed-rule")

    def test_provider_on_non_custom_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("d", "deny", provider="pid")])
        self.assertEqual(cm.exception.code, "authz-malformed-rule")

    def test_bad_timeout_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("c", "custom", provider="pid")],
                    authorizers={"pid": {"timeout_ms": 0}})
        self.assertEqual(cm.exception.code, "authz-malformed-bundle")

    def test_unknown_condition_op_refuses(self):
        with self.assertRaises(ac.AuthorizationCombineError) as cm:
            _bundle([_rule("d", "deny",
                           when=[{"key": "k", "op": "regex",
                                  "value": "x"}])])
        self.assertEqual(cm.exception.code, "authz-malformed-rule")

    def test_empty_rules_loads(self):
        b = _bundle([])
        self.assertEqual(b["rules"], [])
        self.assertEqual(b["external_authorizers"], {})


class BucketOrderingTests(unittest.TestCase):
    def test_deny_beats_allow(self):
        b = _bundle([_rule("a", "allow", to={"actions": ["tool.exec"]}),
                     _rule("d", "deny", to={"actions": ["tool.exec"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-deny")
        self.assertEqual(v["matched_rules"], ["d"])

    def test_deny_beats_allow_rule_order_reversed(self):
        b = _bundle([_rule("a", "allow", to={"actions": ["tool.exec"]}),
                     _rule("d", "deny", to={"actions": ["tool.exec"]})])
        v = ac.evaluate(b, _req())
        self.assertFalse(v["admitted"])

    def test_rules_or_within_bucket(self):
        b = _bundle([_rule("d1", "deny",
                           frm={"principals": ["agent:mallory"]}),
                     _rule("d2", "deny",
                           to={"resources": ["secret/db"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["matched_rules"], ["d2"])

    def test_clauses_and_within_rule(self):
        b = _bundle([_rule("d", "deny",
                           frm={"principals": ["agent:alice"]},
                           to={"actions": ["tool.exec"]},
                           when=[{"key": "env", "op": "eq",
                                  "value": "prod"}])])
        v = ac.evaluate(b, _req(context={"env": "dev"}))
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["matched_rules"], [])
        v2 = ac.evaluate(b, _req(context={"env": "prod"}))
        self.assertEqual(v2["decision"], "deny")

    def test_resource_prefix_match(self):
        b = _bundle([_rule("d", "deny",
                           to={"resources": ["prefix:secret/"]})])
        self.assertEqual(ac.evaluate(b, _req())["decision"], "deny")
        self.assertEqual(
            ac.evaluate(b, _req(resource="public/x"))["decision"],
            "allow")

    def test_default_deny_when_allow_exists(self):
        b = _bundle([_rule("a", "allow", to={"actions": ["tool.read"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-default-deny")

    def test_default_allow_without_allow_policies(self):
        b = _bundle([_rule("d", "deny", to={"actions": ["tool.read"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["code"], "authz-allow")
        self.assertTrue(v["admitted"])

    def test_condition_ops(self):
        b = _bundle([_rule(
            "a", "allow",
            when=[{"key": "tier", "op": "in",
                   "value": ["gold", "silver"]},
                  {"key": "tool", "op": "startswith",
                   "value": "tool."},
                  {"key": "flag", "op": "present"}])])
        ok_ctx = {"tier": "gold", "tool": "tool.exec", "flag": False}
        v = ac.evaluate(b, _req(context=ok_ctx))
        self.assertEqual(v["decision"], "allow")
        bad_ctx = {"tier": "bronze", "tool": "tool.exec",
                   "flag": False}
        v2 = ac.evaluate(b, _req(context=bad_ctx))
        self.assertEqual(v2["code"], "authz-default-deny")


class AuditAndShadowTests(unittest.TestCase):
    def test_audit_hit_logged_not_enforced(self):
        b = _bundle([_rule("au", "audit",
                           to={"actions": ["tool.exec"]})])
        events = []
        v = ac.evaluate(b, _req(), journal=events.append)
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["audit_hits"], ["au"])
        self.assertTrue(any(e["event"] == "authz-audit-hit"
                            for e in events))

    def test_shadow_deny_reported_not_enforced(self):
        b = _bundle([_rule("s", "deny", shadow=True,
                           to={"actions": ["tool.exec"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["shadow_results"],
                         [{"rule": "s", "would": "deny"}])

    def test_shadow_allow_never_grants(self):
        b = _bundle([_rule("s", "allow", shadow=True,
                           to={"actions": ["tool.exec"]}),
                     _rule("a", "allow",
                           to={"actions": ["tool.read"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-default-deny")

    def test_shadow_rule_not_counted_as_allow_policy(self):
        b = _bundle([_rule("s", "allow", shadow=True,
                           to={"actions": ["tool.exec"]})])
        v = ac.evaluate(b, _req())
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["code"], "authz-allow")


class CustomProviderTests(unittest.TestCase):
    def _custom(self, timeout=500):
        return _bundle(
            [_rule("ext", "custom", provider="pid",
                   to={"actions": ["tool.exec"]}),
             _rule("a", "allow", to={"actions": ["tool.exec"]})],
            authorizers={"pid": {"timeout_ms": timeout}})

    def test_unconfigured_provider_denies_everything(self):
        b = _bundle([_rule("ext", "custom", provider="nope",
                           to={"actions": ["tool.exec"]})])
        v = ac.evaluate(b, _req(),
                        authorizer=lambda pid, req: (True, "ok"))
        self.assertEqual(v["code"], "authz-provider-misconfigured")
        self.assertFalse(v["admitted"])

    def test_absent_hook_denies(self):
        v = ac.evaluate(self._custom(), _req())
        self.assertEqual(v["code"], "authz-provider-misconfigured")

    def test_provider_error_denies(self):
        def boom(pid, req):
            raise RuntimeError("down")
        v = ac.evaluate(self._custom(), _req(), authorizer=boom)
        self.assertEqual(v["code"], "authz-provider-misconfigured")

    def test_provider_timeout_denies(self):
        def slow(pid, req):
            time.sleep(5)
            return (True, "late")
        v = ac.evaluate(self._custom(timeout=50), _req(),
                        authorizer=slow)
        self.assertEqual(v["code"], "authz-provider-misconfigured")

    def test_malformed_provider_verdict_denies(self):
        v = ac.evaluate(self._custom(), _req(),
                        authorizer=lambda pid, req: "yes")
        self.assertEqual(v["code"], "authz-provider-misconfigured")

    def test_provider_deny_short_circuits(self):
        v = ac.evaluate(self._custom(), _req(),
                        authorizer=lambda pid, req: (False, "no"))
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-deny")
        self.assertEqual(v["matched_rules"], ["ext"])

    def test_provider_allow_continues_to_allow_bucket(self):
        v = ac.evaluate(self._custom(), _req(),
                        authorizer=lambda pid, req: (True, "ok"))
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["matched_rules"], ["ext", "a"])

    def test_deny_preempts_custom_without_provider_call(self):
        b = _bundle(
            [_rule("d", "deny", to={"actions": ["tool.exec"]}),
             _rule("ext", "custom", provider="pid",
                   to={"actions": ["tool.exec"]})],
            authorizers={"pid": {"timeout_ms": 500}})
        calls = []
        v = ac.evaluate(
            b, _req(),
            authorizer=lambda pid, req: calls.append(pid)
            or (True, "ok"))
        self.assertEqual(v["code"], "authz-deny")
        self.assertEqual(calls, [])


class PartialAttributeTests(unittest.TestCase):
    def test_partial_deny_fails_toward_deny_loud(self):
        b = _bundle([_rule("d", "deny",
                           to={"actions": ["tool.exec"]},
                           when=[{"key": "mfa", "op": "eq",
                                  "value": True}])])
        v = ac.evaluate(b, _req(context={}))
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-deny")
        self.assertEqual(v["partial_attributes"],
                         [{"bucket": "deny", "rule": "d",
                           "missing": ["mfa"]}])

    def test_partial_allow_never_grants_loud_refuse(self):
        b = _bundle([_rule("a", "allow",
                           to={"actions": ["tool.exec"]},
                           when=[{"key": "mfa", "op": "eq",
                                  "value": True}]),
                     _rule("a2", "allow",
                           to={"actions": ["tool.read"]})])
        v = ac.evaluate(b, _req(context={}))
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-partial-attributes")
        self.assertEqual(v["matched_rules"], [])

    def test_partial_is_journaled(self):
        b = _bundle([_rule("a", "allow",
                           when=[{"key": "mfa", "op": "eq",
                                  "value": True}])])
        events = []
        v = ac.evaluate(b, _req(context={}), journal=events.append)
        self.assertEqual(v["code"], "authz-partial-attributes")
        self.assertTrue(any(e["event"] == "authz-partial-attributes"
                            for e in events))


class VerdictShapeTests(unittest.TestCase):
    def test_never_raises_on_garbage_request(self):
        b = _bundle([_rule("a", "allow")])
        v = ac.evaluate(b, "garbage")
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-uncheckable")

    def test_never_raises_on_garbage_bundle(self):
        v = ac.evaluate("garbage", _req())
        self.assertEqual(v["decision"], "deny")
        self.assertEqual(v["code"], "authz-uncheckable")

    def test_journal_errors_do_not_change_decision(self):
        # An audit hit emits a journal event; a failing journal must
        # not change the decision, only record the failure loudly.
        b = _bundle([_rule("au", "audit",
                           to={"actions": ["tool.exec"]})])
        def bad_journal(event):
            raise IOError("journal down")
        v = ac.evaluate(b, _req(), journal=bad_journal)
        self.assertEqual(v["decision"], "allow")
        self.assertEqual(v["audit_hits"], ["au"])
        self.assertIn("journal_errors", v["detail"])

    def test_determinism(self):
        b = _bundle([_rule("au", "audit"),
                     _rule("d", "deny",
                           when=[{"key": "h", "op": "eq",
                                  "value": 3}]),
                     _rule("a", "allow",
                           to={"actions": ["tool.exec"]})])
        req = _req(context={"h": 12})
        self.assertEqual(ac.evaluate(b, req), ac.evaluate(b, req))

    def test_evidence_digest_stable(self):
        b = _bundle([_rule("a", "allow")])
        v1 = ac.evaluate(b, _req())
        v2 = ac.evaluate(b, _req())
        self.assertEqual(v1["evidence_digest"], v2["evidence_digest"])
        self.assertEqual(len(v1["evidence_digest"]), 64)

    def test_out_of_scope_present(self):
        b = _bundle([])
        v = ac.evaluate(b, _req())
        self.assertTrue(v["out_of_scope"])
        self.assertIn("checked", v)


class RegistryTests(unittest.TestCase):
    def test_lane_pin(self):
        # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*); merge coordinator composes.
        self.assertEqual(len(dc.TAXONOMY), 2121) # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)

    def test_authz_codes_present(self):
        expected = ["authz-allow", "authz-audit-hit",
                    "authz-default-deny", "authz-deny",
                    "authz-malformed-bundle", "authz-malformed-rule",
                    "authz-partial-attributes",
                    "authz-provider-misconfigured",
                    "authz-shadow-evaluated", "authz-uncheckable"]
        for code in expected:
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "authz")

    def test_authz_literals_unique_in_source(self):
        # Wave-260 lesson: assert on raw source literals, not the
        # deduped dict.
        src = open("gov/decision_codes.py").read()
        lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
        authz = [l for l in lits if l.startswith("authz-")]
        self.assertEqual(len(authz), 10)
        self.assertEqual(len(set(authz)), 10)
        self.assertEqual(len(lits), len(set(lits)))


if __name__ == "__main__":
    unittest.main()
