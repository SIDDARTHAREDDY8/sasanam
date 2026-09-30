"""Unit tests for the wave-219 named unsafe-path discipline.

gov.unsafe_paths is the central registry: every unsafe/no-op path has a
greppable ``gov.<module>...`` code, emitted through the audit path on
every execution; the registry itself fails closed on unknown codes.
"""

import os
import unittest
import warnings

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import unsafe_paths as up  # noqa: E402


class RegistryTest(unittest.TestCase):
    def test_codes_unique_and_shaped(self):
        codes = list(up.UNSAFE_PATHS)
        self.assertEqual(len(codes), len(set(codes)))
        for code in codes:
            self.assertTrue(code.startswith("gov."), code)

    def test_postures_valid(self):
        valid = {"FAIL_CLOSED", "EXPLICIT_OPT_IN", "LEGACY_ADVISORY",
                 "CONSULT_TELEMETRY"}
        for code, meta in up.UNSAFE_PATHS.items():
            self.assertIn(meta["posture"], valid, code)
            self.assertTrue(meta["description"], code)
            self.assertTrue(meta["emission"], code)

    def test_emit_rejects_unknown(self):
        with self.assertRaises(up.UnknownUnsafePathError):
            up.emit("gov.bogus.no_such_path", audit=[])

    def test_emit_appends_to_list_audit(self):
        audit = []
        code = "gov.scan_verdicts.empty_policy_no_scans_required"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ev = up.emit(code, audit=audit, detail="d", run_id="r")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["code"], code)
        self.assertEqual(audit[0]["event"], "unsafe_path_executed")
        self.assertEqual(ev["run_id"], "r")

    def test_emit_supports_callable_audit(self):
        seen = []
        code = "gov.scan_verdicts.empty_policy_no_scans_required"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            up.emit(code, audit=seen.append)
        self.assertEqual(len(seen), 1)

    def test_emit_warns_loudly_with_code(self):
        code = "gov.scan_verdicts.empty_policy_no_scans_required"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            up.emit(code, audit=[])
        self.assertTrue(any(
            issubclass(w.category, up.UnsafePathWarning)
            and code in str(w.message) for w in caught))

    def test_codes_for_posture(self):
        fc = up.codes_for_posture("FAIL_CLOSED")
        self.assertIn("gov.policy_compile.post_compile_mutation_refused", fc)
        self.assertIn("gov.anchorer.unconfigured_anchoring_disabled", fc)
        self.assertTrue(up.registered(
            "gov.identity_policy.unsafe_allow_vacuous_pass"))
        self.assertFalse(up.registered("gov.nope.missing"))


class PolicyCompileMutationTest(unittest.TestCase):
    def test_identity_mutation_refused(self):
        import gov.policy_compile as pc
        import gov.identity_policy as ip
        pol = ip.OIDCIssuer("https://good.example")
        c = pc.compile_policy(pol)
        self.assertEqual(
            c.admit({"iss": "https://good.example"})["verdict"], "pass")
        pol.issuer = "https://evil.example"
        with self.assertRaises(ip.PolicyViolation) as cm:
            c.admit({"iss": "https://evil.example"})
        self.assertEqual(cm.exception.code,
                         "gov.policy_compile.post_compile_mutation_refused")

    def test_identity_mutation_refused_on_verify(self):
        import gov.policy_compile as pc
        import gov.identity_policy as ip
        pol = ip.OIDCIssuer("https://good.example")
        c = pc.compile_policy(pol)
        pol.issuer = "https://evil.example"
        with self.assertRaises(ip.PolicyViolation):
            c.verify({"iss": "https://good.example"})

    def test_nested_mutation_refused(self):
        import gov.policy_compile as pc
        import gov.identity_policy as ip
        child = ip.ClaimEquals("a.b", 1)
        c = pc.compile_policy(ip.AllOf(child))
        child.expected = 2  # mutate a leaf the describe() omits in full
        with self.assertRaises(ip.PolicyViolation) as cm:
            c.admit({"a": {"b": 2}})
        self.assertEqual(cm.exception.code,
                         "gov.policy_compile.post_compile_mutation_refused")

    def test_unmutated_policy_keeps_working(self):
        import gov.policy_compile as pc
        import gov.identity_policy as ip
        c = pc.compile_policy({"oidcIssuer": "https://good.example"})
        for _ in range(3):
            rep = c.admit({"iss": "https://good.example"})
            self.assertEqual(rep["verdict"], "pass")

    def test_ruleset_mutation_refused(self):
        import gov.policy_compile as pc
        import gov.artifact_rules as ar
        rules = (("REQUIRE", "a.txt"), ("DISALLOW",))
        c = pc.compile_policy(rules)
        c.evaluate({"a.txt": "d" * 64}, {}, "")
        c._rules = (("REQUIRE", "zzz.txt"), ("DISALLOW",))
        with self.assertRaises(ar.ArtifactRuleError) as cm:
            c.evaluate({"a.txt": "d" * 64}, {}, "")
        self.assertIn("gov.policy_compile.post_compile_mutation_refused",
                      str(cm.exception))

    def test_unfreezable_policy_refused_at_compile(self):
        import gov.policy_compile as pc
        import gov.identity_policy as ip

        class Weird(ip.Policy):
            def __init__(self):
                self.blob = object()

            def verify(self, claims):
                return ip.PolicyVerdict("fail", "x")

            def describe(self):
                return "Weird()"

        with self.assertRaises(ip.PolicyAuthoringError):
            pc.compile_policy(Weird())

    def test_degraded_attester_reemits_per_registration(self):
        # Spec: the code is emitted EVERY time the degraded path runs,
        # not just at construction.
        from gov import attested_identity as ai

        class _Signer(object):
            key_id = "w219-unit"
            public_key = b"\x02" * 32

            def sign(self, body):
                return b"s" * 64

        att = ai.degraded_attester(_Signer())

        def _code_events():
            return [e for e in att.audit
                    if isinstance(e, dict)
                    and e.get("code")
                    == "gov.attested_identity.tier2_only_degradation"]

        before = len(_code_events())
        att.register_kernel_fact_identity(
            cgroup="/w219", uid=7, hostname="unit")
        self.assertGreater(len(_code_events()), before)


if __name__ == "__main__":
    unittest.main()
