"""Unit tests for gov/aauth_egress.py (wave-241 lane C).

W241-3: aauth-rs fail-closed primitives (steal, not the protocol).
Primitives: policy-before-discovery, token aud binding, RFC 9421
created freshness (60s), default_deny() egress, confused-deputy
iss verification. Refusals are exact machine codes in the
decision-code taxonomy.
"""

import unittest

from gov import aauth_egress as ae
from gov import decision_codes as dc


def _code(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ae.AauthEgressError as exc:
        return exc.code
    raise AssertionError("no refusal from %s" % (fn.__name__,))


class SchemePolicyTest(unittest.TestCase):
    def test_default_deny_unknown_scheme(self):
        self.assertEqual(
            _code(ae.resolve_scheme, "urn:x:scheme", ae.SchemePolicy()),
            "aauth-scheme-not-allowed")

    def test_discovery_without_policy_refused(self):
        self.assertEqual(
            _code(ae.resolve_scheme, "urn:x:scheme", None),
            "aauth-scheme-not-allowed")

    def test_non_string_scheme_refused(self):
        policy = ae.SchemePolicy().allow_scheme("urn:x:scheme")
        self.assertEqual(
            _code(ae.resolve_scheme, 123, policy),
            "aauth-scheme-not-allowed")

    def test_explicit_allow_resolves(self):
        policy = ae.SchemePolicy().allow_scheme("urn:x:scheme")
        self.assertEqual(
            ae.resolve_scheme("urn:x:scheme", policy), "urn:x:scheme")

    def test_other_scheme_still_denied(self):
        policy = ae.SchemePolicy().allow_scheme("urn:x:scheme")
        self.assertEqual(
            _code(ae.resolve_scheme, "urn:x:other", policy),
            "aauth-scheme-not-allowed")

    def test_allow_scheme_rejects_non_string(self):
        with self.assertRaises(ae.AauthEgressError) as cm:
            ae.SchemePolicy().allow_scheme(None)
        self.assertEqual(cm.exception.code, "aauth-scheme-not-allowed")


class AudienceTest(unittest.TestCase):
    def test_mismatch_refused(self):
        self.assertEqual(
            _code(ae.check_audience, "b.example", "a.example"),
            "aauth-aud-mismatch")

    def test_missing_aud_fails_closed(self):
        self.assertEqual(
            _code(ae.check_audience, None, "a.example"),
            "aauth-aud-mismatch")

    def test_missing_expected_fails_closed(self):
        self.assertEqual(
            _code(ae.check_audience, "a.example", None),
            "aauth-aud-mismatch")

    def test_match_passes(self):
        self.assertTrue(ae.check_audience("a.example", "a.example"))


class FreshnessTest(unittest.TestCase):
    def test_window_is_60_seconds(self):
        self.assertEqual(ae.FRESHNESS_WINDOW_SECONDS, 60)

    def test_stale_past_refused(self):
        self.assertEqual(
            _code(ae.check_freshness, 1_000_000 - 61, 1_000_000),
            "aauth-stale-created")

    def test_stale_future_refused(self):
        self.assertEqual(
            _code(ae.check_freshness, 1_000_000 + 61, 1_000_000),
            "aauth-stale-created")

    def test_boundary_passes(self):
        self.assertTrue(ae.check_freshness(1_000_000 - 60, 1_000_000))
        self.assertTrue(ae.check_freshness(1_000_000 + 60, 1_000_000))

    def test_non_numeric_fails_closed(self):
        self.assertEqual(
            _code(ae.check_freshness, "yesterday", 1_000_000),
            "aauth-stale-created")

    def test_bool_is_not_a_timestamp(self):
        self.assertEqual(
            _code(ae.check_freshness, True, 1_000_000),
            "aauth-stale-created")


class EgressTest(unittest.TestCase):
    def test_loopback_v4_blocked(self):
        self.assertEqual(
            _code(ae.check_egress, "https://127.0.0.1/hook"),
            "aauth-egress-blocked")

    def test_loopback_v6_blocked(self):
        self.assertEqual(
            _code(ae.check_egress, "https://[::1]/hook"),
            "aauth-egress-blocked")

    def test_rfc1918_blocked(self):
        for url in ("https://10.0.0.5/", "https://172.16.0.1/",
                    "https://192.168.1.1/"):
            self.assertEqual(
                _code(ae.check_egress, url), "aauth-egress-blocked",
                url)

    def test_link_local_blocked(self):
        self.assertEqual(
            _code(ae.check_egress, "https://169.254.169.254/x"),
            "aauth-egress-blocked")

    def test_localhost_name_blocked(self):
        self.assertEqual(
            _code(ae.check_egress, "https://localhost/hook"),
            "aauth-egress-blocked")

    def test_http_blocked(self):
        self.assertEqual(
            _code(ae.check_egress, "http://93.184.216.34/hook"),
            "aauth-egress-blocked")

    def test_empty_target_fails_closed(self):
        self.assertEqual(
            _code(ae.check_egress, ""), "aauth-egress-blocked")

    def test_public_https_passes(self):
        self.assertTrue(ae.check_egress("https://93.184.216.34/hook"))


class IssuerTest(unittest.TestCase):
    def test_mismatch_refused(self):
        self.assertEqual(
            _code(ae.verify_issuer, "https://evil.example",
                  "https://idp.example"),
            "aauth-iss-mismatch")

    def test_missing_iss_fails_closed(self):
        self.assertEqual(
            _code(ae.verify_issuer, None, "https://idp.example"),
            "aauth-iss-mismatch")

    def test_missing_expected_fails_closed(self):
        self.assertEqual(
            _code(ae.verify_issuer, "https://idp.example", None),
            "aauth-iss-mismatch")

    def test_match_passes(self):
        self.assertTrue(ae.verify_issuer("https://idp.example",
                                        "https://idp.example"))


class TaxonomyTest(unittest.TestCase):
    def test_all_codes_mapped(self):
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1710)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        for code in ("aauth-scheme-not-allowed", "aauth-aud-mismatch",
                     "aauth-stale-created", "aauth-egress-blocked",
                     "aauth-iss-mismatch"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "aauth")


if __name__ == "__main__":
    unittest.main()
