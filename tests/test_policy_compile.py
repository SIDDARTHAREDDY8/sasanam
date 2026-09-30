"""Unit tests for gov.policy_compile (compile-policy-once front gate)
and gov.strict_xfail (strict expected-failure manifests). Wave-217
lane B.

Pins:
  * compile_policy dispatch: identity spec dicts / Policy instances
    -> CompiledIdentityPolicy; artifact rule tuples / load_rules
    output -> CompiledArtifactRuleset; anything else ->
    PolicyAuthoringError at COMPILE.
  * Authoring errors are compile-time: malformed identity specs and
    rulesets raise from compile_policy, and no evaluation path can
    raise an authoring-error class (structural: evaluation takes no
    spec/rules parameter; garbage data still fails closed).
  * Compile is a front gate, not a re-interpretation: compiled
    reports are identical to the legacy seams'.
  * Fingerprints are stable across evaluations and spec mutation.
  * strict-xfail: declared break recorded, unexpected pass loud,
    undeclared break loud, error never expected, stale/dup loud.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import artifact_rules as ar  # noqa: E402
from gov import identity_policy as ip  # noqa: E402
from gov import policy_compile as pc  # noqa: E402
from gov import strict_xfail as sx  # noqa: E402

D1 = hashlib.sha256(b"d1").hexdigest()
D2 = hashlib.sha256(b"d2").hexdigest()

CLAIMS = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:acme/app:ref:refs/heads/main",
    "sans": {"rfc822Name": ["ci@acme.dev"], "uri": [], "otherName": []},
    "extensions": {"1.3.6.1.4.1.99999.1": "builder-acme"},
}

ID_SPEC = {"allOf": [
    {"oidcIssuer": "https://token.actions.githubusercontent.com"},
    {"identity": {"identity": "ci@acme.dev",
                  "issuer": "https://token.actions.githubusercontent.com"}},
]}

RULES = [
    ("REQUIRE", "src.tar"),
    ("CREATE", "build/*.whl"),
    ("DISALLOW",),
]


def _mats_prods(i):
    return ({"src.tar": hashlib.sha256(b"m%d" % i).hexdigest()},
            {"build/p-%d.whl" % i: hashlib.sha256(b"p%d" % i).hexdigest()})


class TestCompileDispatch(unittest.TestCase):
    def test_identity_spec_dict_compiles(self):
        c = pc.compile_policy(ID_SPEC)
        self.assertIsInstance(c, pc.CompiledIdentityPolicy)

    def test_identity_policy_instance_compiles(self):
        c = pc.compile_policy(ip.OIDCIssuer("https://x.example"))
        self.assertIsInstance(c, pc.CompiledIdentityPolicy)

    def test_rule_tuples_compile(self):
        c = pc.compile_policy(RULES)
        self.assertIsInstance(c, pc.CompiledArtifactRuleset)

    def test_load_rules_output_compiles(self):
        c = pc.compile_policy(ar.load_rules(RULES))
        self.assertIsInstance(c, pc.CompiledArtifactRuleset)

    def test_garbage_spec_refused_at_compile(self):
        for bad in (42, "policy", [], (), {"a": 1, "b": 2}, None, True):
            with self.assertRaises(ip.PolicyAuthoringError, msg=repr(bad)):
                pc.compile_policy(bad)

    def test_malformed_identity_refused_at_compile(self):
        bad_specs = [
            {"nope": {}},                       # unknown predicate
            {"anyOf": []},                      # empty combinator
            {"allOf": []},
            {"unsafeAllow": ""},                # reasonless unsafe
            {"identity": {"issuer": "x"}},      # missing identity
            {"claimIn": {"path": "a", "values": []}},  # empty membership
            {"extension": {"oid": "not-an-oid", "value": 1}},
        ]
        for spec in bad_specs:
            with self.assertRaises(ip.PolicyAuthoringError, msg=repr(spec)):
                pc.compile_policy(spec)

    def test_malformed_ruleset_refused_at_compile(self):
        bad_sets = [
            [("REQUIRE", "a")],                 # no terminal DISALLOW
            [("DISALLOW",), ("REQUIRE", "a"), ("DISALLOW",)],
            [("MATCH", "a", "zzz"), ("DISALLOW",)],  # bad digest pin
            [("FROBNICATE", "a"), ("DISALLOW",)],    # unknown kind
            [("REQUIRE", "../evil"), ("DISALLOW",)],  # path-confused name
        ]
        for specs in bad_sets:
            with self.assertRaises(ar.ArtifactRuleError, msg=repr(specs)):
                pc.compile_policy(specs)


class TestCompiledIdentityPolicy(unittest.TestCase):
    def test_verify_delegates(self):
        c = pc.compile_policy(ID_SPEC)
        v = c.verify(CLAIMS)
        self.assertEqual((v.verdict, v.code), ("pass", "pass"))

    def test_admit_matches_check_admission(self):
        policy = ip.parse_policy(ID_SPEC)
        c = pc.compile_policy(ID_SPEC)
        legacy = ip.check_admission(CLAIMS, policy)
        mine = c.admit(CLAIMS)
        self.assertEqual(mine["verdict"], legacy["verdict"])
        self.assertEqual(mine["code"], legacy["code"])
        self.assertEqual(mine["vacuous"], legacy["vacuous"])

    def test_admit_refuses_fail_and_error(self):
        c = pc.compile_policy(ID_SPEC)
        bad_claims = dict(CLAIMS)
        bad_claims["iss"] = "https://evil.example"   # judged: fail
        with self.assertRaises(ip.PolicyViolation) as cm:
            c.admit(bad_claims)
        self.assertEqual(cm.exception.code, "oidc-issuer-mismatch")
        with self.assertRaises(ip.PolicyViolation) as cm2:
            c.admit(None)                            # judged: error
        self.assertEqual(cm2.exception.code, "claims-malformed")

    def test_unsafe_allow_compiles_and_warns(self):
        import warnings
        c = pc.compile_policy({"unsafeAllow": "test-only"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            rep = c.admit(CLAIMS)
        self.assertEqual(rep["code"], "pass-vacuous")
        self.assertTrue(rep["vacuous"])
        self.assertTrue(any(issubclass(w.category, ip.UnsafePolicyWarning)
                            for w in caught))

    def test_fingerprint_stable(self):
        c = pc.compile_policy(ID_SPEC)
        fp = c.fingerprint()
        for _ in range(3):
            c.verify(CLAIMS)
            self.assertEqual(c.fingerprint(), fp)
        self.assertEqual(len(fp), 64)

    def test_evaluation_has_no_spec_parameter(self):
        import inspect
        c = pc.compile_policy(ID_SPEC)
        for meth in ("verify", "admit"):
            params = inspect.signature(getattr(c, meth)).parameters
            for forbidden in ("spec", "policy", "predicate", "rules",
                              "rule_specs"):
                self.assertNotIn(forbidden, params)


class TestCompiledArtifactRuleset(unittest.TestCase):
    def test_evaluate_ok(self):
        c = pc.compile_policy(RULES)
        mats, prods = _mats_prods(7)
        rep = c.evaluate(mats, prods, context="u")
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["context"], "u")
        self.assertEqual(rep["materials"], 1)
        self.assertEqual(rep["products"], 1)

    def test_report_identical_to_legacy(self):
        c = pc.compile_policy(RULES)
        for i in range(5):
            mats, prods = _mats_prods(i)
            self.assertEqual(
                c.evaluate(mats, prods, context="x%d" % i),
                ar.verify_artifacts(mats, prods, RULES, context="x%d" % i))

    def test_violations_still_loud_at_evaluation(self):
        c = pc.compile_policy(RULES)
        mats, prods = _mats_prods(1)
        prods["stowaway"] = D1   # no rule consumes it -> DISALLOW
        with self.assertRaises(ar.ArtifactRuleError):
            c.evaluate(mats, prods)

    def test_data_errors_at_evaluation_not_authoring(self):
        c = pc.compile_policy(RULES)
        with self.assertRaises(ar.ArtifactRuleError):
            c.evaluate({"src.tar": "not-hex"}, {})

    def test_no_reparse_after_spec_mutation(self):
        specs = [tuple(s) for s in RULES]
        c = pc.compile_policy(specs)
        mats, prods = _mats_prods(3)
        before = c.evaluate(mats, prods)
        specs.append(("DISALLOW",))
        specs[0] = ("REQUIRE", "other")
        self.assertEqual(c.evaluate(mats, prods), before)

    def test_fingerprint_stable_and_pinned(self):
        c = pc.compile_policy(RULES)
        fp = c.fingerprint()
        self.assertEqual(len(fp), 64)
        for i in range(3):
            mats, prods = _mats_prods(i)
            c.evaluate(mats, prods)
            self.assertEqual(c.fingerprint(), fp)

    def test_evaluate_has_no_rules_parameter(self):
        import inspect
        params = inspect.signature(
            pc.CompiledArtifactRuleset.evaluate).parameters
        for forbidden in ("rule_specs", "spec", "rules", "policy"):
            self.assertNotIn(forbidden, params)


class TestStrictXFail(unittest.TestCase):
    def _run(self, manifest, probes):
        return manifest.run(probes)

    def test_declared_break_recorded_run_stays_green(self):
        m = sx.XFailManifest("b", xfail=("known",))
        rep = self._run(m, [("known", lambda: "break"),
                            ("fine", lambda: "held")])
        self.assertTrue(rep.ok)
        self.assertEqual(rep.expected_breaks, ["known"])
        rep.raise_if_bad()  # must not raise

    def test_unexpected_pass_fails_loudly(self):
        m = sx.XFailManifest("b", xfail=("healed",))
        rep = self._run(m, [("healed", lambda: "held")])
        self.assertFalse(rep.ok)
        self.assertEqual(rep.unexpected_passes, ["healed"])
        with self.assertRaises(sx.UnexpectedPassError):
            rep.raise_if_bad()

    def test_undeclared_break_fails_loudly(self):
        m = sx.XFailManifest("b")
        rep = self._run(m, [("sneaky", lambda: "break")])
        self.assertFalse(rep.ok)
        with self.assertRaises(sx.UnexpectedBreakError):
            rep.raise_if_bad()

    def test_error_never_expected(self):
        m = sx.XFailManifest("b", xfail=("flaky",))
        rep = self._run(m, [("flaky", lambda: "error")])
        self.assertFalse(rep.ok)
        self.assertEqual(rep.unexpected_breaks, ["flaky"])

    def test_exception_in_probe_is_error(self):
        def boom():
            raise RuntimeError("probe died")
        m = sx.XFailManifest("b")
        rep = self._run(m, [("dead", boom)])
        self.assertFalse(rep.ok)

    def test_stale_xfail_name_loud(self):
        m = sx.XFailManifest("b", xfail=("never-runs",))
        with self.assertRaises(sx.ProbeError):
            self._run(m, [("other", lambda: "held")])

    def test_duplicate_probe_loud(self):
        m = sx.XFailManifest("b")
        with self.assertRaises(sx.ProbeError):
            self._run(m, [("p", lambda: "held"), ("p", lambda: "held")])

    def test_unknown_verdict_loud(self):
        m = sx.XFailManifest("b")
        with self.assertRaises(sx.ProbeError):
            self._run(m, [("p", lambda: "maybe")])

    def test_summary_mentions_counts(self):
        m = sx.XFailManifest("b", xfail=("k",))
        rep = self._run(m, [("k", lambda: "break"), ("ok", lambda: "held")])
        s = rep.summary()
        self.assertIn("held=1", s)
        self.assertIn("expected-break=1", s)


if __name__ == "__main__":
    unittest.main()
