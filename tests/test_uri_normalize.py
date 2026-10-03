"""Unit tests for gov/uri_normalize (W247-1).

Tests the shared canonical host normalization at its public seams:
normalize_host / normalize_url_host / normalize_email_host and the
UriNormalizeError contract. Behavior-flip pins (trailing-dot,
whitespace, IDNA) live in evals/w247_uri_normalize_probes.py; these
units pin the function-level contract.
"""

import unittest

from gov import decision_codes
from gov import uri_normalize as un


class NormalizeHostTests(unittest.TestCase):
    def test_plain_passthrough(self):
        self.assertEqual(un.normalize_host("trusted.example"),
                         "trusted.example")

    def test_strip_lower_dotstrip(self):
        self.assertEqual(un.normalize_host("  TRUSTED.EXAMPLE. "),
                         "trusted.example")

    def test_multiple_trailing_dots(self):
        self.assertEqual(un.normalize_host("a.b.example.."),
                         "a.b.example")

    def test_idna_unicode(self):
        self.assertEqual(un.normalize_host("m\u00fcnchen.example"),
                         "xn--mnchen-3ya.example")

    def test_idna_already_punycode(self):
        self.assertEqual(un.normalize_host("xn--mnchen-3ya.example"),
                         "xn--mnchen-3ya.example")

    def test_idna_case_insensitive(self):
        self.assertEqual(un.normalize_host("XN--MNCHEN-3YA.EXAMPLE"),
                         "xn--mnchen-3ya.example")

    def test_no_percent_decode(self):
        # Boundary: %-encoding is never decoded in host identity.
        self.assertEqual(un.normalize_host("%74rusted.example"),
                         "%74rusted.example")

    def test_idempotent(self):
        for h in ("  TRUSTED.EXAMPLE. ", "m\u00fcnchen.example",
                  "a.b.example", "%74rusted.example"):
            once = un.normalize_host(h)
            self.assertEqual(un.normalize_host(once), once, h)

    def test_empty_refused(self):
        for bad in ("", "   ", ".", "..."):
            with self.assertRaises(un.UriNormalizeError) as ctx:
                un.normalize_host(bad)
            self.assertEqual(ctx.exception.code, "uri-host-invalid")

    def test_nonstring_refused(self):
        for bad in (None, 123, b"trusted.example"):
            with self.assertRaises(un.UriNormalizeError) as ctx:
                un.normalize_host(bad)
            self.assertEqual(ctx.exception.code, "uri-host-invalid")

    def test_label_too_long_refused(self):
        # IDNA fails closed on a >63-char label.
        with self.assertRaises(un.UriNormalizeError) as ctx:
            un.normalize_host("a" * 64 + ".example")
        self.assertEqual(ctx.exception.code, "uri-host-invalid")

    def test_ip_literal_passthrough(self):
        # IP literals are ASCII and survive IDNA untouched.
        self.assertEqual(un.normalize_host("10.0.0.1"), "10.0.0.1")
        self.assertEqual(un.normalize_host("::1"), "::1")


class NormalizeUrlHostTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(
            un.normalize_url_host("https://trusted.example./x"),
            "trusted.example")

    def test_userinfo(self):
        self.assertEqual(
            un.normalize_url_host("https://user:pass@TRUSTED.EXAMPLE/x"),
            "trusted.example")

    def test_unicode(self):
        self.assertEqual(
            un.normalize_url_host("https://m\u00fcnchen.example/x"),
            "xn--mnchen-3ya.example")

    def test_malformed_refused(self):
        for bad in ("not a url", "", "https://", "https:///x"):
            with self.assertRaises(un.UriNormalizeError) as ctx:
                un.normalize_url_host(bad)
            self.assertEqual(ctx.exception.code, "uri-host-unparseable")


class NormalizeEmailHostTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(un.normalize_email_host("ops@trusted.example"),
                         "trusted.example")

    def test_normalizes(self):
        self.assertEqual(un.normalize_email_host("Ops@TRUSTED.EXAMPLE."),
                         "trusted.example")

    def test_missing_at_refused(self):
        with self.assertRaises(un.UriNormalizeError) as ctx:
            un.normalize_email_host("not-an-email")
        self.assertEqual(ctx.exception.code, "uri-host-unparseable")


class ErrorContractTests(unittest.TestCase):
    def test_code_attribute(self):
        err = un.UriNormalizeError("uri-host-invalid", "detail")
        self.assertEqual(err.code, "uri-host-invalid")
        self.assertIn("uri-host-invalid", str(err))

    def test_codes_in_taxonomy(self):
        for code in ("uri-host-invalid", "uri-host-unparseable"):
            self.assertIn(code, decision_codes.TAXONOMY, code)

    def test_taxonomy_pin_938(self):
        # Lane-local pin: 936 (wave-246) + 2 new codes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1841)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
