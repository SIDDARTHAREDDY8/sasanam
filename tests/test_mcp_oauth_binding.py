"""Units for gov/mcp_oauth_binding.py (W245-1).

Red-first: written before the module. The battery
evals/w245_mcp_oauth_binding_probes.py records the genuine red on the
pristine base (0 HELD / 10 GAP).
"""

import unittest

from gov import decision_codes as dc
from gov import mcp_oauth_binding as _mob


_KEY = b"wave245-oauth-key-0123456789abcdef"
_ISSUER = "https://as.example"
_TOKEN = "https://as.example/token"
_SERVER_A = "https://mcp-a.example"
_SERVER_B = "https://mcp-b.example"


def _sealed(issuer=_ISSUER, client_id="client-1", key=_KEY, allowlist=None):
    return _mob.seal_as_binding(issuer, client_id, key,
                                token_endpoint_allowlist=allowlist)


class SealAsBindingTest(unittest.TestCase):
    def test_round_trip(self):
        sealed = _sealed()
        self.assertEqual(sealed["binding"]["issuer"], _ISSUER)
        self.assertIn("mac", sealed)

    def test_issuer_canonicalized(self):
        sealed = _sealed(issuer="HTTPS://AS.EXAMPLE/")
        self.assertEqual(sealed["binding"]["issuer"], _ISSUER)

    def test_key_missing_refuses(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.seal_as_binding(_ISSUER, "client-1", None)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-key-missing")

    def test_http_issuer_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.seal_as_binding("http://as.example", "client-1", _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-metadata-malformed")

    def test_empty_client_id_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.seal_as_binding(_ISSUER, "", _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-metadata-malformed")


class AuthorizeTokenExchangeTest(unittest.TestCase):
    def test_happy_path(self):
        sealed = _sealed()
        verdict = _mob.authorize_token_exchange(
            sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)
        self.assertEqual(verdict.issuer, _ISSUER)
        self.assertEqual(verdict.token_endpoint, _TOKEN)

    def test_attacker_endpoint_refused(self):
        # (a) metadata names the real IdP as issuer but routes token
        # exchange to an attacker endpoint.
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, "https://evil.example/token", _KEY,
                issuer_hint=_ISSUER)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-issuer-unbound")

    def test_credential_replay_refused(self):
        # (b) credential stored under AS-X presented at AS-Y.
        sealed = _sealed(issuer="https://as-y.example")
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, "https://as-y.example/token", _KEY,
                issuer_hint="https://as-y.example",
                presented_as_issuer="https://as-x.example")
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-credential-misbound")

    def test_fix_gap_omitted_issuer_refused(self):
        # (c) issuer= omitted for a provider that requires it.
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, _TOKEN, _KEY, issuer_hint=None,
                provider_requires_issuer=True)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-fix-gap-refused")

    def test_issuer_hint_mismatch_refused(self):
        # (d) issuer hint names a different AS than bound.
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, _TOKEN, _KEY,
                issuer_hint="https://other.example")
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-issuer-unverified")

    def test_binding_tamper_refused(self):
        sealed = _sealed()
        sealed["binding"]["issuer"] = "https://evil.example"
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, _TOKEN, _KEY, issuer_hint="https://evil.example")
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-binding-tampered")

    def test_allowlisted_alternate_endpoint_allowed(self):
        sealed = _sealed(
            allowlist=["https://tokens.example/token"])
        verdict = _mob.authorize_token_exchange(
            sealed, "https://tokens.example/other", _KEY,
            issuer_hint=_ISSUER)
        self.assertEqual(verdict.issuer, _ISSUER)

    def test_allowlist_does_not_cover_attacker(self):
        sealed = _sealed(
            allowlist=["https://tokens.example/token"])
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.authorize_token_exchange(
                sealed, "https://evil.example/token", _KEY,
                issuer_hint=_ISSUER)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-issuer-unbound")


class ServerMetadataTest(unittest.TestCase):
    def test_metadata_issuer_mismatch_refused(self):
        # (d) via the discovery path: metadata names another issuer.
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_server_metadata(
                sealed,
                {"issuer": "https://other.example", "token_endpoint": _TOKEN},
                _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-issuer-unverified")

    def test_metadata_attacker_endpoint_refused(self):
        # (a) via the discovery path: issuer names the real IdP, but
        # the token endpoint routes to an attacker.
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_server_metadata(
                sealed,
                {"issuer": _ISSUER,
                 "token_endpoint": "https://evil.example/token"},
                _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-issuer-unbound")

    def test_metadata_happy_path(self):
        sealed = _sealed()
        verdict = _mob.check_server_metadata(
            sealed,
            {"issuer": _ISSUER, "token_endpoint": _TOKEN},
            _KEY)
        self.assertEqual(verdict.token_endpoint, _TOKEN)


class RunBoundExchangeTest(unittest.TestCase):
    def test_verdict_mismatch_refused(self):
        sealed = _sealed()
        verdict = _mob.authorize_token_exchange(
            sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.run_bound_exchange(
                verdict, "https://evil.example/token",
                lambda: "exchanged")
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-verdict-mismatched")

    def test_exchange_runs_on_match(self):
        sealed = _sealed()
        verdict = _mob.authorize_token_exchange(
            sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)
        self.assertEqual(
            _mob.run_bound_exchange(verdict, _TOKEN, lambda: "exchanged"),
            "exchanged")


class ValidateAuthorizationResponseTest(unittest.TestCase):
    """RFC 9207 (wave-332 lane 2)."""

    def test_rogue_iss_refused(self):
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.validate_authorization_response(
                sealed, {"code": "c", "iss": "https://rogue.example"},
                _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-iss-mismatched")

    def test_missing_iss_refused(self):
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.validate_authorization_response(
                sealed, {"code": "c"}, _KEY)
        self.assertEqual(ctx.exception.code, "mcp-oauth-iss-missing")

    def test_correct_iss_accepted_and_normalized(self):
        sealed = _sealed()
        got = _mob.validate_authorization_response(
            sealed, {"code": "c", "iss": "HTTPS://AS.EXAMPLE/"}, _KEY)
        self.assertEqual(got, _ISSUER)

    def test_non_dict_response_refused(self):
        sealed = _sealed()
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.validate_authorization_response(sealed, "iss=x", _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-metadata-malformed")

    def test_tampered_binding_refused_as_tamper(self):
        sealed = _sealed()
        sealed = {"binding": dict(sealed["binding"]), "mac": sealed["mac"]}
        sealed["binding"]["issuer"] = "https://evil.example"
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.validate_authorization_response(
                sealed, {"code": "c", "iss": _ISSUER}, _KEY)
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-binding-tampered")


class CheckTokenResourceTest(unittest.TestCase):
    """RFC 8707 presentation binding (wave-332 lane 2)."""

    def test_a_minted_token_at_b_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_resource(
                _SERVER_B, {"resource": _SERVER_A})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-resource-misbound")

    def test_resourceless_token_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_resource(_SERVER_A, {"sub": "agent-1"})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-resource-missing")

    def test_matching_resource_accepted(self):
        got = _mob.check_token_resource(
            _SERVER_A + "/", {"resource": _SERVER_A})
        self.assertEqual(got, _SERVER_A)

    def test_aud_list_containing_server_accepted(self):
        got = _mob.check_token_resource(
            _SERVER_B, {"aud": ["https://other.example", _SERVER_B]})
        self.assertEqual(got, _SERVER_B)

    def test_aud_list_without_server_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_resource(
                _SERVER_B, {"aud": ["https://other.example"]})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-resource-misbound")

    def test_non_dict_claims_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_resource(_SERVER_A, "claims")
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-metadata-malformed")

    def test_http_resource_server_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_resource(
                "http://mcp-a.example", {"resource": _SERVER_A})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-metadata-malformed")


class CheckTokenResponseResourceTest(unittest.TestCase):
    """RFC 8707 token-response echo (wave-332 lane 2)."""

    def test_substituted_resource_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_response_resource(
                _SERVER_A, {"access_token": "t", "resource": _SERVER_B})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-resource-misbound")

    def test_missing_resource_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_token_response_resource(
                _SERVER_A, {"access_token": "t"})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-resource-missing")

    def test_matching_resource_accepted(self):
        got = _mob.check_token_response_resource(
            _SERVER_A, {"access_token": "t", "resource": _SERVER_A + "/"})
        self.assertEqual(got, _SERVER_A)

    def test_request_params_builder(self):
        self.assertEqual(_mob.resource_request_params(_SERVER_A + "/"),
                         {"resource": _SERVER_A})


class CheckResponseIssTest(unittest.TestCase):
    """RFC 9207 against the verdict (wave-332 lane 2, wired path)."""

    def _verdict(self):
        sealed = _sealed()
        return _mob.authorize_token_exchange(
            sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)

    def test_rogue_iss_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_response_iss(
                self._verdict(), {"code": "c", "iss": "https://rogue.example"})
        self.assertEqual(ctx.exception.code, "mcp-oauth-iss-mismatched")

    def test_missing_iss_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_response_iss(self._verdict(), {"code": "c"})
        self.assertEqual(ctx.exception.code, "mcp-oauth-iss-missing")

    def test_correct_iss_accepted(self):
        got = _mob.check_response_iss(
            self._verdict(), {"code": "c", "iss": "HTTPS://AS.EXAMPLE/"})
        self.assertEqual(got, _ISSUER)

    def test_non_verdict_refused(self):
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.check_response_iss("not-a-verdict", {"iss": _ISSUER})
        self.assertEqual(ctx.exception.code,
                         "mcp-oauth-verdict-mismatched")


class RunBoundExchangeWithResponseTest(unittest.TestCase):
    """The choke point enforces RFC 9207 when the response is supplied."""

    def _verdict(self):
        sealed = _sealed()
        return _mob.authorize_token_exchange(
            sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)

    def test_rogue_iss_blocks_exchange(self):
        ran = []
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.run_bound_exchange(
                self._verdict(), _TOKEN, lambda: ran.append(True),
                authorization_response={"code": "c",
                                        "iss": "https://rogue.example"})
        self.assertEqual(ctx.exception.code, "mcp-oauth-iss-mismatched")
        self.assertEqual(ran, [])

    def test_missing_iss_blocks_exchange(self):
        ran = []
        with self.assertRaises(_mob.McpOAuthError) as ctx:
            _mob.run_bound_exchange(
                self._verdict(), _TOKEN, lambda: ran.append(True),
                authorization_response={"code": "c"})
        self.assertEqual(ctx.exception.code, "mcp-oauth-iss-missing")
        self.assertEqual(ran, [])

    def test_correct_iss_runs_exchange(self):
        self.assertEqual(
            _mob.run_bound_exchange(
                self._verdict(), _TOKEN, lambda: "exchanged",
                authorization_response={"code": "c", "iss": _ISSUER}),
            "exchanged")


class TaxonomyTest(unittest.TestCase):
    def test_codes_in_taxonomy(self):
        for code in _mob.CODES:
            self.assertIn(code, dc.TAXONOMY)
            # code_for returns a copy; compare the closed fields.
            record = dc.code_for(code)
            self.assertEqual(record["code"], code)
            self.assertEqual(record["domain"], "mcp-oauth")

    def test_no_code_collisions(self):
        self.assertEqual(len(set(_mob.CODES)), len(_mob.CODES))


if __name__ == "__main__":
    unittest.main()
