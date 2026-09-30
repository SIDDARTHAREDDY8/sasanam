"""Unit tests for gov/jwks_fetch.py (W245-10).

Pins the redirect-poisoning guard contract: no redirect is ever
followed, origin mismatches refuse before any transport call, and a
transport failure is never treated as key material.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import jwks_fetch as jf


class _T(object):
    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    def __call__(self, url, timeout_s):
        self.calls.append((url, timeout_s))
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


PINNED = "https://idp.example"
URL = "https://idp.example/.well-known/jwks.json"


class RedirectRefusalTest(unittest.TestCase):
    def test_302_cross_host_refused_destination_never_contacted(self):
        t = _T([(302, [("Location", "https://evil.invalid/j")], b"")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-redirect-refused")
        self.assertEqual(len(t.calls), 1)

    def test_all_3xx_refused(self):
        for status in (301, 302, 303, 307, 308):
            t = _T([(status, [("Location", "https://idp.example/x")], b"")])
            with self.assertRaises(jf.JwksFetchError) as ctx:
                jf.fetch_jwks(PINNED, URL, t)
            self.assertEqual(ctx.exception.code, "jwks-redirect-refused")

    def test_300_and_304_are_not_redirects_but_still_fail_closed(self):
        # 300/304 are not followed either; they are non-2xx transport
        # failures, never key material.
        for status in (300, 304):
            t = _T([(status, [], b"")])
            with self.assertRaises(jf.JwksFetchError) as ctx:
                jf.fetch_jwks(PINNED, URL, t)
            self.assertEqual(ctx.exception.code, "jwks-transport-failed")

    def test_location_header_case_insensitive(self):
        t = _T([(200, [("lOcAtIoN", "https://idp.example/y")], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-redirect-refused")

    def test_duplicate_location_headers_refused(self):
        t = _T([(200, [("Location", "https://idp.example/a"),
                       ("Location", "https://idp.example/b")], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-redirect-refused")


class OriginPinningTest(unittest.TestCase):
    def test_mismatch_refuses_before_transport(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, "https://other.example/jwks", t)
        self.assertEqual(ctx.exception.code, "jwks-origin-mismatch")
        self.assertEqual(t.calls, [])

    def test_scheme_downgrade_refused(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError):
            jf.fetch_jwks(PINNED, "http://idp.example/jwks", t)
        self.assertEqual(t.calls, [])

    def test_explicit_default_port_matches(self):
        t = _T([(200, [], b"{}")])
        body = jf.fetch_jwks(PINNED, "https://idp.example:443/j", t)
        self.assertEqual(body, b"{}")

    def test_non_default_port_mismatches(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, "https://idp.example:8443/j", t)
        self.assertEqual(ctx.exception.code, "jwks-origin-mismatch")

    def test_host_case_and_trailing_dot_normalized(self):
        t = _T([(200, [], b"{}")])
        body = jf.fetch_jwks(PINNED, "https://IDP.EXAMPLE./j", t)
        self.assertEqual(body, b"{}")

    def test_empty_pinned_origin_refuses_unpinned(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks("", URL, t)
        self.assertEqual(ctx.exception.code, "jwks-issuer-unpinned")

    def test_pinned_origin_with_path_refused(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks("https://idp.example/evil", URL, t)
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")


class MalformedInputTest(unittest.TestCase):
    def test_relative_url(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, "/jwks.json", t)
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")

    def test_userinfo_in_request_url(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, "https://u:p@idp.example/j", t)
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")
        self.assertEqual(t.calls, [])

    def test_fragment_refused(self):
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, "https://idp.example/j#frag", t)
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")

    def test_bool_timeout_rejected(self):
        # The True == 1 trap: a bool timeout must not pass validation.
        t = _T([(200, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t, timeout_s=True)
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")

    def test_non_callable_transport_rejected(self):
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, "not-callable")
        self.assertEqual(ctx.exception.code, "jwks-url-malformed")

    def test_code_for_maps_all_refusals(self):
        # Every refusal code must resolve in the decision taxonomy.
        from gov import decision_codes as dc
        for code in ("jwks-redirect-refused", "jwks-origin-mismatch",
                     "jwks-url-malformed", "jwks-issuer-unpinned",
                     "jwks-transport-failed"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "jwks")


class TransportFailureTest(unittest.TestCase):
    def test_raising_transport(self):
        t = _T([RuntimeError("boom")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-transport-failed")

    def test_non_bytes_body(self):
        t = _T([(200, [], '{"keys":[]}')])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-transport-failed")

    def test_bytearray_body_coerced(self):
        t = _T([(200, [], bytearray(b"{}"))])
        self.assertEqual(jf.fetch_jwks(PINNED, URL, t), b"{}")

    def test_bool_status_rejected(self):
        # Another bool trap: True == 1 must not pass as a 200 status.
        t = _T([(True, [], b"{}")])
        with self.assertRaises(jf.JwksFetchError) as ctx:
            jf.fetch_jwks(PINNED, URL, t)
        self.assertEqual(ctx.exception.code, "jwks-transport-failed")

    def test_success_returns_body_unchanged(self):
        body = b'{"keys":[{"kty":"oct","k":"abc"}]}'
        t = _T([(200, [("Content-Type", "application/json")], body)])
        out = jf.fetch_jwks(PINNED, URL, t)
        self.assertIs(out, body)
        self.assertEqual(t.calls, [(URL, 10.0)])


if __name__ == "__main__":
    unittest.main()
