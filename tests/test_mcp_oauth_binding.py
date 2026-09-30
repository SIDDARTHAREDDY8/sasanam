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
