"""Unit tests for gov/mcp_server_authz.py (wave-334 lane 2, F419).

Tests at the public seams: validate_bearer_request, refusal_response,
www_authenticate_challenge, http_status_for. Deterministic: `now` is
always injected; no clock reads in tests.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import mcp_server_authz as sa

NOW = 1750000000.0
SERVER = "https://mcp-b.example.com"
ISSUER = "https://as.example.com"
TOK = "tok-unit-AAAA"


def _claims(**kw):
    c = {"iss": ISSUER, "sub": "agent-7", "aud": SERVER,
         "resource": SERVER, "exp": NOW + 3600.0, "scope": "a b"}
    c.update(kw)
    return c


def _verify_ok(mapping):
    def verify(token):
        if token in mapping:
            return mapping[token]
        raise ValueError("bad signature")
    return verify


def _code_of(fn):
    try:
        fn()
    except sa.McpServerAuthzError as exc:
        return exc.code, exc.http_status
    return (None, None)


class ValidateBearerRequestTests(unittest.TestCase):
    def _ok(self, claims=None, **kw):
        claims = _claims() if claims is None else claims
        kw.setdefault("expected_issuer", ISSUER)
        kw.setdefault("now", NOW)
        return sa.validate_bearer_request(
            SERVER, "Bearer " + TOK, _verify_ok({TOK: claims}), **kw)

    def test_valid_returns_verdict(self):
        v = self._ok()
        self.assertEqual(v.resource, SERVER)
        self.assertEqual(v.issuer, ISSUER)
        self.assertEqual(v.scopes, frozenset({"a", "b"}))
        self.assertEqual(v.subject, "agent-7")
        self.assertEqual(v.token_digest,
                         hashlib.sha256(TOK.encode()).hexdigest())
        self.assertNotIn(TOK, repr(v))

    def test_cross_resource_replay_refused(self):
        code, status = _code_of(
            lambda: self._ok(_claims(aud="https://mcp-a.example.com",
                                    resource="https://mcp-a.example.com")))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_RESOURCE_MISBOUND)
        self.assertEqual(status, 401)

    def test_missing_token(self):
        for hdr in (None, "", "  "):
            code, status = _code_of(
                lambda h=hdr: sa.validate_bearer_request(
                    SERVER, h, _verify_ok({}), expected_issuer=ISSUER,
                    now=NOW))
            self.assertEqual(code, sa.MCP_SERVER_AUTH_MISSING_TOKEN, hdr)
            self.assertEqual(status, 401)

    def test_malformed_headers(self):
        for hdr in ("Basic eA==", "Bearer", "Bearer ", "Bearer a b",
                    "Bearer a$b", "Bearer\x00a"):
            code, _ = _code_of(
                lambda h=hdr: sa.validate_bearer_request(
                    SERVER, h, _verify_ok({TOK: _claims()}),
                    expected_issuer=ISSUER, now=NOW))
            self.assertEqual(code, sa.MCP_SERVER_AUTH_MALFORMED, hdr)

    def test_token_in_query_refused(self):
        code, status = _code_of(
            lambda: self._ok(query_string="access_token=" + TOK))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_TOKEN_IN_QUERY)
        self.assertEqual(status, 401)

    def test_verifier_rejection(self):
        def raising(_t):
            raise ValueError("nope")
        code, _ = _code_of(
            lambda: sa.validate_bearer_request(
                SERVER, "Bearer " + TOK, raising,
                expected_issuer=ISSUER, now=NOW))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_TOKEN_INVALID)
        code, _ = _code_of(
            lambda: sa.validate_bearer_request(
                SERVER, "Bearer " + TOK, lambda _t: [1],
                expected_issuer=ISSUER, now=NOW))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_TOKEN_INVALID)

    def test_expired_and_not_yet_valid(self):
        code, _ = _code_of(lambda: self._ok(_claims(exp=NOW - 1)))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_TOKEN_EXPIRED)
        code, _ = _code_of(lambda: self._ok(_claims(nbf=NOW + 1)))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_TOKEN_NOT_YET_VALID)
        code, _ = _code_of(lambda: self._ok(_claims(exp="x")))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_MALFORMED)

    def test_issuer(self):
        c = _claims()
        del c["iss"]
        code, _ = _code_of(lambda: self._ok(c))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_ISSUER_MISSING)
        code, _ = _code_of(
            lambda: self._ok(_claims(iss="https://evil.example.com")))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_ISSUER_MISMATCHED)

    def test_insufficient_scope_is_403(self):
        code, status = _code_of(
            lambda: self._ok(required_scopes=("a", "zzz")))
        self.assertEqual(code, sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE)
        self.assertEqual(status, 403)
        # covering scope passes
        v = self._ok(required_scopes=("a",))
        self.assertEqual(v.resource, SERVER)


class ChallengeTests(unittest.TestCase):
    def test_invalid_token_challenge(self):
        status, ch = sa.refusal_response(
            sa.MCP_SERVER_AUTH_RESOURCE_MISBOUND, "replay at B",
            resource_metadata_url="https://x.example/prm")
        self.assertEqual(status, 401)
        self.assertTrue(ch.startswith('Bearer error="invalid_token"'))
        self.assertIn("mcp-server-auth-resource-misbound", ch)
        self.assertIn('resource_metadata="https://x.example/prm"', ch)

    def test_insufficient_scope_challenge(self):
        status, ch = sa.refusal_response(
            sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE, "need zzz")
        self.assertEqual(status, 403)
        self.assertIn('error="insufficient_scope"', ch)

    def test_challenge_strips_injection(self):
        _s, ch = sa.refusal_response(
            sa.MCP_SERVER_AUTH_TOKEN_INVALID, 'a"\r\nX-Evil: 1')
        # Newlines and quotes are stripped so the detail cannot split
        # headers; the residual inline text is harmless.
        self.assertNotIn("\r", ch)
        self.assertNotIn("\n", ch)
        # The detail inside error_description="..." carries no quotes
        # (the trailing quote is the format's own delimiter).
        inner = ch.split('error_description="')[1]
        self.assertNotIn('"', inner[: inner.rfind('"')])

    def test_refusal_detail_never_carries_token(self):
        # The module's own refusal details must never echo the token:
        # exercise every failure path and assert the token is absent
        # from str(exc) and exc.detail.
        secret = "tok-secret-ZZZZ"
        def raising(_t):
            raise ValueError("bad signature")
        paths = [
            lambda: sa.validate_bearer_request(
                SERVER, "Bearer " + secret, raising,
                expected_issuer=ISSUER, now=NOW),
            lambda: sa.validate_bearer_request(
                SERVER, "Bearer " + secret,
                _verify_ok({secret: _claims(
                    aud="https://mcp-a.example.com",
                    resource="https://mcp-a.example.com")}),
                expected_issuer=ISSUER, now=NOW),
            lambda: sa.validate_bearer_request(
                SERVER, "Bearer " + secret,
                _verify_ok({secret: _claims(exp=NOW - 5)}),
                expected_issuer=ISSUER, now=NOW),
        ]
        for fn in paths:
            try:
                fn()
                self.fail("expected refusal")
            except sa.McpServerAuthzError as exc:
                self.assertNotIn(secret, str(exc))
                self.assertNotIn(secret, exc.detail)

    def test_http_status_for(self):
        self.assertEqual(
            sa.http_status_for(sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE), 403)
        for code in sa.CODES:
            if code == sa.MCP_SERVER_AUTH_INSUFFICIENT_SCOPE:
                continue
            self.assertEqual(sa.http_status_for(code), 401)


class RegistryTests(unittest.TestCase):
    def test_codes_centrally_registered(self):
        from gov import decision_codes as dc
        for code in sa.CODES:
            self.assertIn(code, dc.TAXONOMY, code)

    def test_codes_tuple_matches(self):
        self.assertEqual(len(sa.CODES), 11)
        self.assertEqual(len(set(sa.CODES)), 11)


if __name__ == "__main__":
    unittest.main()
