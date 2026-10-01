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
        self.assertEqual(len(decision_codes.TAXONOMY), 1458)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
