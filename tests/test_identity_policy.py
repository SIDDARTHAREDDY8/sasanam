#!/usr/bin/env python3
"""Unit tests for gov.identity_policy (wave-215 lane A).

Pins the verdict contract {pass, fail, error}, the non-vacuous
combinator rule (empty AnyOf/AllOf are authoring errors), typed
predicates, UnsafeAllow self-announcement, parse_policy, and
check_admission fail-closed semantics.
"""

import os
import sys
import unittest
import warnings

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import identity_policy as ip  # noqa: E402

_ISSUER = "https://token.actions.githubusercontent.com"

_CLAIMS = {
    "iss": _ISSUER,
    "sub": "repo:acme/app:ref:refs/heads/main",
    "sans": {
        "rfc822Name": ["build@acme.example"],
        "uri": ["https://github.com/acme/app"],
        "otherName": [],
    },
    "extensions": {
        "1.3.6.1.4.1.99999.1.1": "prod",
    },
}


def _claims(**over):
    out = dict(_CLAIMS)
    out.update(over)
    return out


class TestVerdictContract(unittest.TestCase):
    def test_bad_verdict_rejected(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.PolicyVerdict("maybe", "x")

    def test_violation_carries_code(self):
        v = ip.PolicyViolation("oidc-issuer-mismatch", "d")
        self.assertEqual(v.code, "oidc-issuer-mismatch")
        self.assertIsInstance(v, ValueError)

    def test_violation_is_value_error(self):
        # Sibling-module convention: loud ValueError, never silent False.
        self.assertTrue(issubclass(ip.PolicyViolation, ValueError))
        self.assertTrue(issubclass(ip.PolicyAuthoringError, ValueError))


class TestEmptyCombinators(unittest.TestCase):
    def test_empty_anyof_authoring_error(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.AnyOf()

    def test_empty_allof_authoring_error(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.AllOf()

    def test_non_policy_child_refused(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.AllOf("not-a-policy")


class TestPredicates(unittest.TestCase):
    def test_oidc_issuer(self):
        self.assertEqual(ip.OIDCIssuer(_ISSUER).verify(_claims()).verdict,
                         "pass")
        v = ip.OIDCIssuer(_ISSUER).verify(_claims(iss="https://evil.example"))
        self.assertEqual((v.verdict, v.code), ("fail", "oidc-issuer-mismatch"))

    def test_oidc_issuer_missing_iss_is_error(self):
        v = ip.OIDCIssuer(_ISSUER).verify({"sub": "x"})
        self.assertEqual((v.verdict, v.code),
                         ("error", "claims-section-missing"))

    def test_identity_san(self):
        self.assertEqual(
            ip.Identity("build@acme.example").verify(_claims()).verdict,
            "pass")
        self.assertEqual(
            ip.Identity("https://github.com/acme/app").verify(
                _claims()).verdict, "pass")

    def test_identity_with_issuer(self):
        pol = ip.Identity("build@acme.example", issuer=_ISSUER)
        self.assertEqual(pol.verify(_claims()).verdict, "pass")
        v = pol.verify(_claims(iss="https://evil.example"))
        self.assertEqual((v.verdict, v.code),
                         ("fail", "identity-issuer-mismatch"))

    def test_identity_unknown_fails(self):
        v = ip.Identity("mallory@evil.example").verify(_claims())
        self.assertEqual((v.verdict, v.code),
                         ("fail", "identity-not-in-sans"))

    def test_identity_missing_sans_is_error(self):
        v = ip.Identity("build@acme.example").verify({"iss": _ISSUER})
        self.assertEqual((v.verdict, v.code),
                         ("error", "claims-section-missing"))

    def test_extension_equals(self):
        pol = ip.ExtensionEquals("1.3.6.1.4.1.99999.1.1", "prod")
        self.assertEqual(pol.verify(_claims()).verdict, "pass")
        v = pol.verify(_claims(extensions={
            "1.3.6.1.4.1.99999.1.1": "dev"}))
        self.assertEqual((v.verdict, v.code), ("fail", "extension-mismatch"))

    def test_extension_absent_key_never_equals_none(self):
        # Absent key must not pass against an expected None: that would
        # let a missing extension satisfy a policy by accident.
        pol = ip.ExtensionEquals("1.3.6.1.4.1.99999.1.9", None)
        v = pol.verify(_claims())
        self.assertEqual(v.verdict, "fail")
        present = _claims(extensions={"1.3.6.1.4.1.99999.1.9": None})
        self.assertEqual(pol.verify(present).verdict, "pass")

    def test_extension_bad_oid(self):
        for bad in ("", "abc", "1.2.3.", None, 5):
            with self.assertRaises(ip.PolicyAuthoringError):
                ip.ExtensionEquals(bad, "v")

    def test_claim_equals(self):
        pol = ip.ClaimEquals("sub", "repo:acme/app:ref:refs/heads/main")
        self.assertEqual(pol.verify(_claims()).verdict, "pass")
        v = pol.verify(_claims(sub="other"))
        self.assertEqual((v.verdict, v.code),
                         ("fail", "claim-equals-mismatch"))
        v = pol.verify({"iss": _ISSUER})
        self.assertEqual(v.verdict, "error")

    def test_claim_in(self):
        pol = ip.ClaimIn("extensions.1.3.6.1.4.1.99999.1.1",
                         ["prod", "staging"])
        self.assertEqual(pol.verify(_claims()).verdict, "pass")
        v = pol.verify(_claims(extensions={
            "1.3.6.1.4.1.99999.1.1": "dev"}))
        self.assertEqual((v.verdict, v.code), ("fail", "claim-not-in"))

    def test_claim_in_empty_values_refused(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.ClaimIn("sub", [])

    def test_malformed_claims_is_error(self):
        for bad in ("nope", None, 42, ["x"]):
            v = ip.OIDCIssuer(_ISSUER).verify(bad)
            self.assertEqual((v.verdict, v.code),
                             ("error", "claims-malformed"))


class TestCombinators(unittest.TestCase):
    def test_allof_pass(self):
        pol = ip.AllOf(ip.OIDCIssuer(_ISSUER),
                       ip.Identity("build@acme.example"))
        v = pol.verify(_claims())
        self.assertEqual((v.verdict, v.code), ("pass", "pass"))

    def test_allof_one_failing(self):
        pol = ip.AllOf(ip.OIDCIssuer(_ISSUER),
                       ip.Identity("mallory@evil.example"))
        v = pol.verify(_claims())
        self.assertEqual(v.verdict, "fail")
        self.assertEqual(v.code, "identity-not-in-sans")

    def test_anyof_pass(self):
        pol = ip.AnyOf(ip.Identity("mallory@evil.example"),
                       ip.Identity("build@acme.example"))
        v = pol.verify(_claims())
        self.assertEqual((v.verdict, v.code), ("pass", "pass"))

    def test_anyof_no_match(self):
        pol = ip.AnyOf(ip.Identity("a@evil.example"),
                       ip.Identity("b@evil.example"))
        v = pol.verify(_claims())
        self.assertEqual((v.verdict, v.code), ("fail", "anyof-no-match"))

    def test_anyof_error_propagates_when_nothing_passes(self):
        pol = ip.AnyOf(ip.Identity("mallory@evil.example"),
                       ip.Identity("build@acme.example"))
        v = pol.verify({"iss": _ISSUER})  # no sans section
        self.assertEqual(v.verdict, "error")


class TestVacuity(unittest.TestCase):
    def test_unsafe_allow_passes_loudly(self):
        pol = ip.UnsafeAllow("unit test")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            v = pol.verify(_claims())
        self.assertEqual(v.verdict, "pass")
        self.assertEqual(v.code, "pass-vacuous")
        self.assertTrue(v.vacuous)
        self.assertTrue(any("UnsafeAllow" in str(w.message) for w in caught))
        self.assertTrue(any(isinstance(w.message, ip.UnsafePolicyWarning)
                            for w in caught))

    def test_unsafe_allow_warns_every_use(self):
        pol = ip.UnsafeAllow("unit test")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            pol.verify(_claims())
            pol.verify(_claims())
        self.assertGreaterEqual(
            sum(1 for w in caught if "UnsafeAllow" in str(w.message)), 2)

    def test_unsafe_allow_needs_reason(self):
        for bad in ("", None):
            with self.assertRaises(ip.PolicyAuthoringError):
                ip.UnsafeAllow(bad)

    def test_vacuous_only_allof_declared(self):
        pol = ip.AllOf(ip.UnsafeAllow("declared"))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            v = pol.verify(_claims())
        self.assertEqual((v.verdict, v.code), ("pass", "pass-vacuous"))

    def test_mixed_anyof_is_plain_pass(self):
        pol = ip.AnyOf(ip.UnsafeAllow("loud branch"),
                       ip.Identity("build@acme.example"))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            v = pol.verify(_claims())
        # One real predicate matched: plain pass, not vacuous.
        self.assertEqual((v.verdict, v.code), ("pass", "pass"))
        self.assertFalse(v.vacuous)


class TestParsePolicy(unittest.TestCase):
    def test_round_trip(self):
        spec = {"allOf": [
            {"oidcIssuer": _ISSUER},
            {"identity": {"identity": "build@acme.example"}},
            {"extension": {"oid": "1.3.6.1.4.1.99999.1.1",
                           "value": "prod"}},
            {"claimEquals": {"path": "sub",
                             "value": "repo:acme/app:ref:refs/heads/main"}},
            {"claimIn": {"path": "sub", "values": ["a", "b"]}},
            {"anyOf": [{"identity": {"identity": "x"}}]},
        ]}
        pol = ip.parse_policy(spec)
        self.assertIsInstance(pol, ip.AllOf)

    def test_unknown_key_refused(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.parse_policy({"bogus": 1})

    def test_multi_key_refused(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.parse_policy({"oidcIssuer": _ISSUER, "identity": {}})

    def test_empty_combinator_spec_refused(self):
        for spec in ({"anyOf": []}, {"allOf": []}):
            with self.assertRaises(ip.PolicyAuthoringError):
                ip.parse_policy(spec)

    def test_unsafe_allow_spec(self):
        pol = ip.parse_policy({"unsafeAllow": "testing only"})
        self.assertIsInstance(pol, ip.UnsafeAllow)
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.parse_policy({"unsafeAllow": ""})


class TestCheckAdmission(unittest.TestCase):
    def test_pass_returns_report(self):
        rep = ip.check_admission(_claims(), ip.OIDCIssuer(_ISSUER))
        self.assertEqual(rep["verdict"], "pass")
        self.assertEqual(rep["code"], "pass")
        self.assertIn("OIDCIssuer", rep["policy"])

    def test_fail_raises(self):
        with self.assertRaises(ip.PolicyViolation) as ctx:
            ip.check_admission(_claims(iss="https://evil.example"),
                               ip.OIDCIssuer(_ISSUER))
        self.assertEqual(ctx.exception.code, "oidc-issuer-mismatch")

    def test_error_raises(self):
        with self.assertRaises(ip.PolicyViolation) as ctx:
            ip.check_admission("garbage", ip.OIDCIssuer(_ISSUER))
        self.assertEqual(ctx.exception.code, "claims-malformed")

    def test_wrong_policy_type_refused(self):
        with self.assertRaises(ip.PolicyAuthoringError):
            ip.check_admission(_claims(), "not-a-policy")


if __name__ == "__main__":
    unittest.main()
