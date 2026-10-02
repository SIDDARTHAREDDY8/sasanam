"""Unit tests for gov/casbin_perm.py (Casbin PERM DSL ADAPT)."""

import hashlib
import json
import os
import tempfile
import unittest

from gov import casbin_perm as cp


DENY_OVERRIDE = """\
[request_definition]
r = agent, tool, action

[policy_definition]
p = agent, tool, action, eft

[role_definition]
g = _, _

[policy_effect]
e = !some(where (p.eft == deny))

[matchers]
m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action

[policy]
p, admin, shell, exec, allow
p, blocked, shell, exec, deny

[role_policy]
g, alice, admin
g, bob, blocked
"""


class CompileTest(unittest.TestCase):
    def test_missing_section_refused(self):
        with self.assertRaises(cp.CasbinConfError) as ctx:
            cp.compile_model("[policy]\np, a, b, c, allow\n")
        self.assertEqual(ctx.exception.code, "casbin-conf-invalid")

    def test_unknown_section_refused(self):
        with self.assertRaises(cp.CasbinConfError):
            cp.compile_model(DENY_OVERRIDE + "\n[wat]\nx = 1\n")

    def test_unknown_effect_form_refused(self):
        bad = DENY_OVERRIDE.replace("e = !some(where (p.eft == deny))",
                                    "e = majority(p.eft)")
        with self.assertRaises(cp.CasbinConfError):
            cp.compile_model(bad)

    def test_unknown_matcher_function_refused(self):
        bad = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = evil(r.agent, p.agent)")
        with self.assertRaises(cp.CasbinUnknownFunctionError) as ctx:
            cp.compile_model(bad)
        self.assertEqual(ctx.exception.code, "casbin-unknown-matcher-function")

    def test_bad_eft_refused(self):
        bad = DENY_OVERRIDE.replace("p, admin, shell, exec, allow",
                                    "p, admin, shell, exec, maybe")
        with self.assertRaises(cp.CasbinConfError):
            cp.compile_model(bad)

    def test_duplicate_row_refused(self):
        dup = DENY_OVERRIDE.replace(
            "p, blocked, shell, exec, deny",
            "p, blocked, shell, exec, deny\np, blocked, shell, exec, deny")
        with self.assertRaises(cp.CasbinShadowError) as ctx:
            cp.compile_model(dup)
        self.assertEqual(ctx.exception.code, "casbin-policy-shadowed")

    def test_contradictory_row_refused_under_deny_override(self):
        bad = DENY_OVERRIDE.replace(
            "p, blocked, shell, exec, deny",
            "p, blocked, shell, exec, deny\np, blocked, shell, exec, allow")
        with self.assertRaises(cp.CasbinShadowError):
            cp.compile_model(bad)

    def test_invalid_regex_refused_at_compile(self):
        bad = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = regexMatch(r.tool, p.tool) && g(r.agent, p.agent)")
        bad = bad.replace("p, admin, shell, exec, allow",
                          "p, admin, ([invalid, exec, allow")
        with self.assertRaises(cp.CasbinConfError) as ctx:
            cp.compile_model(bad)
        self.assertEqual(ctx.exception.code, "casbin-conf-invalid")

    def test_refusal_codes_are_registered(self):
        from gov import decision_codes as dc
        for code in ("casbin-conf-invalid",
                     "casbin-unknown-matcher-function",
                     "casbin-policy-shadowed",
                     "casbin-enforce-error-fail-closed"):
            self.assertIn(code, dc.TAXONOMY)


class EffectTest(unittest.TestCase):
    def test_deny_override(self):
        m = cp.compile_model(DENY_OVERRIDE)
        self.assertTrue(cp.enforce(m, "alice", "shell", "exec"))
        self.assertFalse(cp.enforce(m, "bob", "shell", "exec"))
        self.assertFalse(cp.enforce(m, "mallory", "shell", "exec"))

    def test_allow_override(self):
        conf = DENY_OVERRIDE.replace("e = !some(where (p.eft == deny))",
                                     "e = some(where (p.eft == allow))")
        conf = conf.replace("g, bob, blocked",
                            "g, carol, admin\ng, carol, blocked")
        m = cp.compile_model(conf)
        self.assertTrue(cp.enforce(m, "carol", "shell", "exec"))

    def test_priority(self):
        conf = DENY_OVERRIDE.replace("e = !some(where (p.eft == deny))",
                                     "e = priority(p.eft)")
        conf = conf.replace("p, blocked, shell, exec, deny",
                            "p, alice, shell, delete, deny")
        m = cp.compile_model(conf)
        dec, rows = cp.enforce_ex(m, "alice", "shell", "exec")
        self.assertTrue(dec)
        self.assertEqual(rows[0]["eft"], "allow")
        self.assertFalse(cp.enforce(m, "alice", "shell", "delete"))

    def test_default_deny(self):
        m = cp.compile_model(DENY_OVERRIDE)
        dec, rows = cp.enforce_ex(m, "nobody", "shell", "exec")
        self.assertFalse(dec)
        self.assertEqual(rows, [])


class RolesTest(unittest.TestCase):
    def test_transitive_inheritance(self):
        m = cp.compile_model(DENY_OVERRIDE + "g, carol, alice\n")
        self.assertTrue(cp.enforce(m, "carol", "shell", "exec"))

    def test_cycle_terminates(self):
        m = cp.compile_model(DENY_OVERRIDE + "g, alice, bob\ng, bob, alice\n")
        # Must terminate and decide; exact verdict is less important than
        # termination (alice inherits admin via herself).
        self.assertIsInstance(cp.enforce(m, "alice", "shell", "exec"), bool)


class BuiltinsTest(unittest.TestCase):
    def _model_with(self, matcher, policy_row):
        conf = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = " + matcher)
        conf = conf.replace("p, admin, shell, exec, allow", policy_row)
        return cp.compile_model(conf)

    def test_key_match(self):
        m = self._model_with(
            "g(r.agent, p.agent) && keyMatch(r.tool, p.tool) && r.action == p.action",
            "p, admin, shell/*, exec, allow")
        self.assertTrue(cp.enforce(m, "alice", "shell/ls", "exec"))
        self.assertFalse(cp.enforce(m, "alice", "other/ls", "exec"))

    def test_key_match2(self):
        m = self._model_with(
            "g(r.agent, p.agent) && keyMatch2(r.tool, p.tool) && r.action == p.action",
            "p, admin, docs/:id, exec, allow")
        self.assertTrue(cp.enforce(m, "alice", "docs/42", "exec"))
        self.assertFalse(cp.enforce(m, "alice", "docs/42/edit", "exec"))

    def test_regex_match(self):
        m = self._model_with(
            "g(r.agent, p.agent) && regexMatch(r.tool, p.tool) && r.action == p.action",
            "p, admin, shell/(ls|cat), exec, allow")
        self.assertTrue(cp.enforce(m, "alice", "shell/ls", "exec"))
        self.assertFalse(cp.enforce(m, "alice", "shell/rm", "exec"))

    def test_ip_match(self):
        m = self._model_with(
            "g(r.agent, p.agent) && ipMatch(r.tool, p.tool) && r.action == p.action",
            "p, admin, 10.0.0.0/8, exec, allow")
        self.assertTrue(cp.enforce(m, "alice", "10.1.2.3", "exec"))
        self.assertFalse(cp.enforce(m, "alice", "192.168.1.1", "exec"))

    def test_wildcard_star(self):
        conf = DENY_OVERRIDE.replace("p, admin, shell, exec, allow",
                                     "p, admin, *, exec, allow")
        m = cp.compile_model(conf)
        self.assertTrue(cp.enforce(m, "alice", "anything", "exec"))


class FailClosedTest(unittest.TestCase):
    def test_runtime_matcher_error_denies(self):
        conf = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = regexMatch(r.tool, p.tool) && g(r.agent, p.agent)")
        m = cp.compile_model(conf)
        result = cp.evaluate(m, "alice", None, "exec")
        self.assertFalse(result["decision"])
        self.assertEqual(result["error"], "casbin-enforce-error-fail-closed")

    def test_non_string_request_denies(self):
        m = cp.compile_model(DENY_OVERRIDE)
        result = cp.evaluate(m, "alice", 42, "exec")
        self.assertFalse(result["decision"])
        self.assertEqual(result["error"], "casbin-enforce-error-fail-closed")

    def test_batch_enforce(self):
        m = cp.compile_model(DENY_OVERRIDE)
        reqs = [("alice", "shell", "exec"), ("bob", "shell", "exec")]
        self.assertEqual(cp.batch_enforce(m, reqs), [True, False])
        with self.assertRaises(ValueError):
            cp.batch_enforce(m, [("alice", "shell")])

    def test_error_carries_packet_code(self):
        m = cp.compile_model(DENY_OVERRIDE)
        result = cp.evaluate(m, "alice", None, "exec")
        self.assertEqual(cp.packet_decision_code(result),
                         "casbin-enforce-error-fail-closed")
        self.assertEqual(cp.packet_evidence(result), [])


class ShadowSoundnessTest(unittest.TestCase):
    def _shadow_conf(self, matcher, effect="some(where (p.eft == allow))"):
        return "\n".join([
            "[request_definition]", "r = agent, tool, action",
            "[policy_definition]", "p = agent, tool, action, eft",
            "[policy_effect]", "e = " + effect,
            "[matchers]", "m = " + matcher,
            "[policy]",
            "p, admin, *, exec, allow",
            "p, admin, shell, exec, allow",
        ])

    def test_nonmonotone_neq_no_false_flag(self):
        # S1: under !=, an earlier-field * matches nothing; the later row
        # is live and must load, then decide.
        m = cp.compile_model(self._shadow_conf(
            "r.agent == p.agent && r.tool != p.tool && r.action == p.action"))
        self.assertTrue(cp.enforce(m, "admin", "ls", "exec"))

    def test_nonmonotone_not_no_false_flag(self):
        m = cp.compile_model(self._shadow_conf(
            "r.agent == p.agent && !(r.tool == p.tool) && r.action == p.action"))
        self.assertTrue(cp.enforce(m, "admin", "ls", "exec"))

    def test_monotone_still_refuses(self):
        # The monotone case keeps its teeth: later row fully covered.
        with self.assertRaises(cp.CasbinShadowError):
            cp.compile_model(self._shadow_conf(
                "r.agent == p.agent && r.tool == p.tool && r.action == p.action"))


class MatcherAttrTest(unittest.TestCase):
    def test_unknown_r_attr_refused_at_compile(self):
        conf = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = g(r.agent, p.agent) && r.agnet == p.tool && r.action == p.action")
        with self.assertRaises(cp.CasbinConfError) as ctx:
            cp.compile_model(conf)
        self.assertEqual(ctx.exception.code, "casbin-conf-invalid")

    def test_row_id_not_matcher_visible(self):
        # S2: p.row_id / p.lineno are evidence metadata, not matcher attrs.
        conf = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = p.row_id == \"p:0\"")
        with self.assertRaises(cp.CasbinConfError) as ctx:
            cp.compile_model(conf)
        self.assertEqual(ctx.exception.code, "casbin-conf-invalid")

    def test_identical_rows_still_refused(self):
        dup = DENY_OVERRIDE.replace(
            "p, blocked, shell, exec, deny",
            "p, blocked, shell, exec, deny\np, blocked, shell, exec, deny")
        with self.assertRaises(cp.CasbinShadowError):
            cp.compile_model(dup)


class CompileRobustnessTest(unittest.TestCase):
    def test_deep_matcher_refused_with_code(self):
        # S3: no bare RecursionError escapes compile_model.
        nested = "!" * 5000 + "(r.tool == p.tool)"
        conf = DENY_OVERRIDE.replace(
            "m = g(r.agent, p.agent) && r.tool == p.tool && r.action == p.action",
            "m = g(r.agent, p.agent) && %s && r.action == p.action" % nested)
        with self.assertRaises(cp.CasbinConfError) as ctx:
            cp.compile_model(conf)
        self.assertEqual(ctx.exception.code, "casbin-conf-invalid")

    def test_batch_string_triple_raises(self):
        # S4: a str is not a triple — fail-fast, never silent.
        m = cp.compile_model(DENY_OVERRIDE)
        with self.assertRaises(ValueError):
            cp.batch_enforce(m, ["abc"])
        with self.assertRaises(ValueError):
            cp.batch_enforce(m, [b"abc"])
        # tuple and list triples still work
        self.assertEqual(
            cp.batch_enforce(m, [("alice", "shell", "exec"),
                                 ["bob", "shell", "exec"]]),
            [True, False])
    def test_row_digest_stable_and_recomputable(self):
        m = cp.compile_model(DENY_OVERRIDE)
        _dec, rows = cp.enforce_ex(m, "alice", "shell", "exec")
        d1 = cp.row_digest(rows[0])
        d2 = hashlib.sha256(json.dumps(
            rows[0], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)

    def test_policy_bundle_digest_is_conf_bytes(self):
        m = cp.compile_model(DENY_OVERRIDE)
        self.assertEqual(cp.policy_bundle_digest(m),
                         hashlib.sha256(DENY_OVERRIDE.encode()).hexdigest())

    def test_packet_evidence_shape(self):
        m = cp.compile_model(DENY_OVERRIDE)
        result = cp.evaluate(m, "alice", "shell", "exec")
        ev = cp.packet_evidence(result)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["row_id"], "p:0")
        self.assertEqual(ev[0]["eft"], "allow")
        self.assertEqual(ev[0]["row_digest"], cp.row_digest(result["matched_rows"][0]))

    def test_record_decision_chains_into_log(self):
        from gov.log import ActionLog
        d = tempfile.mkdtemp(prefix="g281_")
        log = ActionLog(os.path.join(d, "audit.jsonl"))
        m = cp.compile_model(DENY_OVERRIDE)
        result = cp.evaluate(m, "alice", "shell", "exec")
        entry = cp.record_decision(log, m, "alice", "shell", "exec", result)
        self.assertEqual(entry["record_type"], "casbin-decision")
        self.assertEqual(entry["decision"], "allow")
        self.assertEqual(entry["matched_row_digests"],
                         [cp.row_digest(result["matched_rows"][0])])
        self.assertEqual(entry["policy_bundle_digest"],
                         cp.policy_bundle_digest(m))
        self.assertEqual(len(entry["record_digest"]), 64)


if __name__ == "__main__":
    unittest.main()
