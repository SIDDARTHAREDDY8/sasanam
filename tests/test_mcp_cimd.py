#!/usr/bin/env python3
"""Unit tests for gov/mcp_cimd.py (wave-337 lane 3).

CIMD safe-subset: document emission, URL shape validation, document
binding, and the pre-registration intake. Stdlib only; all network
surface is mocked (no real DNS, no real fetch).
"""

import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import mcp_cimd as CIMD  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


def _doc(**over):
    d = {
        "client_id": "https://client.example.com/oauth/client",
        "client_name": "Example Client",
        "redirect_uris": ["https://client.example.com/cb"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://client.example.com/.well-known/jwks.json",
    }
    d.update(over)
    return d


_DEP = {"trusted_domain_patterns": ["*.example.com", "example.com"],
        "timeout_seconds": 5}


def _world(doc=None, ips=("93.184.216.34",)):
    doc = _doc() if doc is None else doc
    body = CIMD.canonical_document_bytes(doc)

    def resolver(host):
        return list(ips)

    def fetcher(url, timeout):
        if url.endswith("/oauth/client"):
            return {"status": 200, "headers": {}, "body": body}
        return {"status": 200, "headers": {},
                "body": json.dumps({"keys": []}).encode()}

    return fetcher, resolver


class CodesRegisteredTest(unittest.TestCase):
    def test_fifteen_codes_registered(self):
        self.assertEqual(len(CIMD.CIMD_CODES), 15)
        for code in CIMD.CIMD_CODES:
            self.assertIn(code, dc.TAXONOMY, code)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "mcp-oauth",
                             code)

    def test_taxonomy_pin(self):
        self.assertEqual(len(dc.TAXONOMY), 2143)  # Wave-342 lane 6: pin 2134 -> 2127 (-4 family-fallback base-class codes).; Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


class UrlShapeTest(unittest.TestCase):
    def test_rule_table(self):
        bad = [
            ("http://client.example.com/oauth/client",
             CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS),
            ("https://u@client.example.com/oauth/client",
             CIMD.MCP_OAUTH_CIMD_URL_USERINFO),
            ("https://client.example.com/a/../oauth/client",
             CIMD.MCP_OAUTH_CIMD_URL_DOT_SEGMENT),
            ("https://client.example.com/oauth/client?q=1",
             CIMD.MCP_OAUTH_CIMD_URL_QUERY),
            ("https://client.example.com/oauth/client#f",
             CIMD.MCP_OAUTH_CIMD_URL_FRAGMENT),
            ("https://client.example.com/",
             CIMD.MCP_OAUTH_CIMD_URL_ROOT_PATH),
            ("https://client.example.com:bad/oauth/client",
             CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS),
        ]
        for url, code in bad:
            with self.assertRaises(CIMD.CIMDError, msg=url) as ctx:
                CIMD.validate_client_id_url(url)
            self.assertEqual(ctx.exception.code, code, url)

    def test_control_chars_refused_never_stripped(self):
        for c in list(range(0x00, 0x20)) + [0x7F]:
            url = ("https://client.example.com/oauth/cl" + chr(c)
                   + "ient")
            with self.assertRaises(CIMD.CIMDError) as ctx:
                CIMD.validate_client_id_url(url)
            self.assertEqual(ctx.exception.code,
                             CIMD.MCP_OAUTH_CIMD_URL_NOT_HTTPS)

    def test_valid_url_passes(self):
        url = "https://client.example.com:8443/oauth/client"
        self.assertEqual(CIMD.validate_client_id_url(url), url)


class DocumentShapeTest(unittest.TestCase):
    def test_credential_smuggling_refused(self):
        with self.assertRaises(CIMD.CIMDError) as ctx:
            CIMD.validate_document_shape(_doc(client_secret="x"))
        self.assertEqual(ctx.exception.code,
                         CIMD.MCP_OAUTH_CIMD_CREDENTIAL_PRESENT)

    def test_jwks_misbinding_refused(self):
        d = _doc()
        del d["jwks_uri"]
        with self.assertRaises(CIMD.CIMDError) as ctx:
            CIMD.validate_document_shape(d)
        self.assertEqual(ctx.exception.code,
                         CIMD.MCP_OAUTH_CIMD_DOCUMENT_MALFORMED)

    def test_cross_origin_redirect_refused(self):
        with self.assertRaises(CIMD.CIMDError) as ctx:
            CIMD.validate_document_shape(
                _doc(redirect_uris=["https://evil.example/cb"]))
        self.assertEqual(ctx.exception.code,
                         CIMD.MCP_OAUTH_CIMD_REDIRECT_ORIGIN_MISMATCH)

    def test_unknown_fields_ignored(self):
        self.assertTrue(CIMD.validate_document_shape(
            _doc(software_statement="ignored")))


class EmissionTest(unittest.TestCase):
    def test_emit_shape(self):
        doc = CIMD.emit_document("client.example.com", "Example")
        self.assertEqual(doc["client_id"],
                         "https://client.example.com/oauth/client")
        self.assertNotIn("logo_uri", doc)
        self.assertTrue(CIMD.validate_document_shape(doc))

    def test_emit_fail_closed(self):
        with self.assertRaises(CIMD.CIMDError):
            CIMD.emit_document("not a domain!!", "Example")
        with self.assertRaises(CIMD.CIMDError):
            CIMD.emit_document("client.example.com", "Example",
                               redirect_uris=["https://evil.example/cb"])

    def test_serve_contract(self):
        doc = CIMD.emit_document("client.example.com", "Example")
        status, headers, body = CIMD.serve_document(doc)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body.decode())["client_id"],
                         doc["client_id"])


class IntakeTest(unittest.TestCase):
    def test_onboard_and_verify_pinned(self):
        fetcher, resolver = _world()
        rec = CIMD.onboard_cimd(
            "https://client.example.com/oauth/client",
            fetcher, _DEP, resolver=resolver)
        body = CIMD.canonical_document_bytes(rec["document"])
        self.assertTrue(CIMD.verify_pinned(
            "https://client.example.com/oauth/client", body, rec))
        with self.assertRaises(CIMD.CIMDError) as ctx:
            CIMD.verify_pinned(
                "https://client.example.com/oauth/client", b"{}", rec)
        self.assertEqual(ctx.exception.code,
                         CIMD.MCP_OAUTH_CIMD_BINDING_MISMATCH)

    def test_ssrf_range_refused(self):
        fetcher, resolver = _world(ips=("10.0.0.5",))
        with self.assertRaises(CIMD.CIMDError) as ctx:
            CIMD.onboard_cimd(
                "https://client.example.com/oauth/client",
                fetcher, _DEP, resolver=resolver)
        self.assertEqual(ctx.exception.code,
                         CIMD.MCP_OAUTH_CIMD_FETCH_SSRF_RANGE)

    def test_rotation_emits_revocation_event(self):
        fetcher, resolver = _world()
        rec = CIMD.onboard_cimd(
            "https://client.example.com/oauth/client",
            fetcher, _DEP, resolver=resolver)
        sunk = []
        rec2 = CIMD.reonboard_cimd(
            "https://client.example.com/oauth/client",
            fetcher, _DEP, rec, revocation_sink=sunk.append,
            resolver=resolver)
        # Same key material: no rotation, no event.
        self.assertIsNone(rec2["rotation"])
        self.assertEqual(sunk, [])
        evt = CIMD.build_key_rotation_event(rec, rec, "evt-12345678")
        self.assertEqual(
            evt["event_type"],
            "urn:sasanam:revocation-push:credential-revoked")
        self.assertEqual(evt["subject"]["kind"], "credential")


if __name__ == "__main__":
    unittest.main()
