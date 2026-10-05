"""Unit tests for gov/scoped_tool_listing.py (wave-262 lane 1, MCP D1 ADAPT).

Red-first: written before the module; scope-gated tool listing
(a la MCP tools/list "MAY vary by the authorization presented") +
the spec's human-in-the-loop UX contract + elicitation URL-mode
consent, paired with sentinel credential substitution.

Stdlib only. No network. Injectble clock via `now` args.
"""

import base64
import hashlib
import hmac
import os
import time
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import gov.decision_codes as dc
import gov.scoped_tool_listing as stl

UNIVERSE = frozenset({"files:read", "files:write", "files:read-admin",
                      "net:fetch", "db:query"})
ISSUER_KEY = b"wave262-lane1-test-key-32-bytes!!"


def _issuer():
    return stl.ScopeTicketIssuer(ISSUER_KEY, UNIVERSE)


def _reg():
    r = stl.ToolRegistry(UNIVERSE).bind_issuer(_issuer())
    r.register("read_file", {"files:read"},
               "Read a file from the workspace.",
               input_schema={"type": "object"})
    r.register("write_file", {"files:write"},
               "Write a file to the workspace.")
    r.register("admin_reindex", {"files:read-admin"},
               "Rebuild the file index (admin).")
    r.register("fetch_url", {"net:fetch"},
               "Fetch a URL over the network.", needs_consent=True)
    return r


class UniverseExactMatchTest(unittest.TestCase):
    def test_seal_unknown_scope_refused(self):
        with self.assertRaises(stl.ScopedListingError) as cm:
            _issuer().seal("sub-digest", {"files:read-admin-evil"}, 1000.0)
        self.assertEqual(cm.exception.code, "scope-listing-unknown-scope")

    def test_register_unknown_scope_refused(self):
        r = stl.ToolRegistry(UNIVERSE)
        with self.assertRaises(stl.ScopedListingError) as cm:
            r.register("x", {"nope"}, "x")
        self.assertEqual(cm.exception.code, "scope-listing-unknown-scope")

    def test_prefix_scope_does_not_cover(self):
        # "files:read" must never cover "files:read-admin": exact match.
        iss = _issuer()
        t = iss.seal("sub", {"files:read"}, 1000.0)
        r = _reg()
        listed = [n for n, _ in r.list_tools(t)]
        self.assertIn("read_file", listed)
        self.assertNotIn("admin_reindex", listed)
        with self.assertRaises(stl.ScopedListingError) as cm:
            r.invoke(t, "admin_reindex", lambda: "ran")
        self.assertEqual(cm.exception.code, "scope-listing-denied")

    def test_suffix_trick_does_not_cover(self):
        iss = _issuer()
        t = iss.seal("sub", {"files:read-admin"}, 1000.0)
        r = _reg()
        listed = [n for n, _ in r.list_tools(t)]
        self.assertIn("admin_reindex", listed)
        self.assertNotIn("read_file", listed)


class ListingSilenceTest(unittest.TestCase):
    def test_empty_scopes_means_empty_listing(self):
        iss = _issuer()
        t = iss.seal("sub", set(), 1000.0)
        self.assertEqual(_reg().list_tools(t), [])

    def test_none_ticket_means_empty_listing(self):
        self.assertEqual(_reg().list_tools(None), [])

    def test_unpermitted_tools_invisible(self):
        iss = _issuer()
        t = iss.seal("sub", {"files:read"}, 1000.0)
        views = _reg().list_tools(t)
        blob = repr(views)
        self.assertNotIn("admin_reindex", blob)
        self.assertNotIn("fetch_url", blob)
        self.assertNotIn("files:read-admin", blob)
        self.assertNotIn("net:fetch", blob)

    def test_listing_sorted_deterministic(self):
        iss = _issuer()
        t = iss.seal("sub", set(UNIVERSE), 1000.0)
        a = [n for n, _ in _reg().list_tools(t)]
        b = [n for n, _ in _reg().list_tools(t)]
        self.assertEqual(a, b)
        self.assertEqual(a, sorted(a))


class InvocationGateTest(unittest.TestCase):
    def test_unregistered_tool_refused(self):
        iss = _issuer()
        t = iss.seal("sub", set(UNIVERSE), 1000.0)
        with self.assertRaises(stl.ScopedListingError) as cm:
            _reg().invoke(t, "never_registered", lambda: "ran")
        self.assertEqual(cm.exception.code, "scope-listing-not-registered")

    def test_permitted_invoke_runs(self):
        iss = _issuer()
        t = iss.seal("sub", {"files:read"}, 1000.0)
        self.assertEqual(_reg().invoke(t, "read_file", lambda: "ok"), "ok")

    def test_tampered_ticket_refused(self):
        iss = _issuer()
        sealed = iss.seal("sub", {"files:read"}, 1000.0)
        body, mac = sealed.split(".")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        flipped = bytes([raw[0] ^ 1]) + raw[1:]
        tampered = (base64.urlsafe_b64encode(flipped).decode()
                    .rstrip("=") + "." + mac)
        with self.assertRaises(stl.ScopedListingError) as cm:
            _reg().list_tools(tampered)
        # ticket tamper reuses the token-scope tamper code, never a scope gap
        self.assertEqual(cm.exception.code, "scope-grant-tampered")

    def test_malformed_ticket_refused_fail_closed(self):
        with self.assertRaises(stl.ScopedListingError):
            _reg().list_tools("not-a-ticket")


class ConsentTest(unittest.TestCase):
    def _consent_issuer(self):
        return stl.ConsentIssuer(b"consent-key-32-bytes-padded-0000",
                                 ttl_seconds=300)

    def test_full_consent_flow(self):
        ci = self._consent_issuer()
        audit = []
        url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                                  "sub", 1000.0, "https://consent.local/c")
        token = url.split("ct=")[1]
        ok = ci.confirm_consent(token, "appr-1", "fetch_url", "sub", 1100.0,
                                audit.append)
        self.assertTrue(ok)
        self.assertEqual(len(audit), 1)
        ev = audit[0]
        self.assertEqual(ev["event"], "scope-consent-confirmed")
        self.assertEqual(ev["approval_id"], "appr-1")
        # digest of the token is recorded; the token itself is not
        self.assertNotIn(token, repr(ev))
        self.assertRegex(ev["consent_digest"], r"^[0-9a-f]{64}$")

    def test_forged_token_refused_and_unaudited(self):
        ci = self._consent_issuer()
        audit = []
        with self.assertRaises(stl.ScopedListingError) as cm:
            ci.confirm_consent("AAAA.BBBB", "appr-1", "fetch_url", "sub",
                               1100.0, audit.append)
        self.assertEqual(cm.exception.code, "scope-consent-forged")
        self.assertEqual(audit, [])

    def test_consent_bound_to_approval(self):
        ci = self._consent_issuer()
        audit = []
        url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                                  "sub", 1000.0, "https://consent.local/c")
        token = url.split("ct=")[1]
        with self.assertRaises(stl.ScopedListingError) as cm:
            ci.confirm_consent(token, "appr-2", "fetch_url", "sub", 1100.0,
                               audit.append)
        self.assertEqual(cm.exception.code, "scope-consent-unbound")
        self.assertEqual(audit, [])

    def test_expired_consent_refused(self):
        ci = self._consent_issuer()
        audit = []
        url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                                  "sub", 1000.0, "https://consent.local/c")
        token = url.split("ct=")[1]
        with self.assertRaises(stl.ScopedListingError) as cm:
            ci.confirm_consent(token, "appr-1", "fetch_url", "sub", 1400.0,
                               audit.append)
        self.assertEqual(cm.exception.code, "scope-consent-expired")
        self.assertEqual(audit, [])

    def test_wrong_key_refused(self):
        ci = self._consent_issuer()
        url = ci.mint_consent_url("appr-1", "fetch_url", {"net:fetch"},
                                  "sub", 1000.0, "https://consent.local/c")
        token = url.split("ct=")[1]
        other = stl.ConsentIssuer(b"different-key-32-bytes-padded-000",
                                  ttl_seconds=300)
        with self.assertRaises(stl.ScopedListingError) as cm:
            other.confirm_consent(token, "appr-1", "fetch_url", "sub",
                                  1100.0, lambda e: None)
        self.assertEqual(cm.exception.code, "scope-consent-forged")


class ApprovalShapeTest(unittest.TestCase):
    def test_shape_carries_ux_contract(self):
        iss = _issuer()
        t = iss.seal("sub", {"net:fetch"}, 1000.0)
        r = _reg()
        view = dict(r.list_tools(t))["fetch_url"]
        shape = stl.build_approval_request(
            "fetch_url", view, {"net:fetch"}, "sub",
            what_it_would_do="Fetch https://example.com/data.json and "
                             "store it in the run workspace.",
            consent_url="https://consent.local/c?ct=TOKEN",
            args={"url": "fake_value_3f9a"})
        self.assertEqual(shape["tool"], "fetch_url")
        self.assertEqual(set(shape["required_scopes"]), {"net:fetch"})
        self.assertEqual(shape["caller_subject_digest"], "sub")
        self.assertIn("https://example.com/data.json",
                      shape["what_it_would_do"])
        self.assertTrue(shape["consent_url"].startswith("https://consent"))
        # sentinel-bearing args only: real secrets never ride the shape
        self.assertEqual(shape["args"], {"url": "fake_value_3f9a"})

    def test_enqueue_wires_queue_seam(self):
        calls = []

        class StubQueue(object):
            def queue(self, action, decision=None, **kw):
                calls.append((action, kw))
                return "appr-9"

        shape = {"tool": "fetch_url", "required_scopes": ["net:fetch"],
                 "caller_subject_digest": "sub", "what_it_would_do": "do X",
                 "consent_url": "https://consent.local/c?ct=T",
                 "args": {"url": "fake_value_3f9a"}}
        ident = object()
        aid = stl.enqueue_approval(StubQueue(), shape, caller_identity=ident)
        self.assertEqual(aid, "appr-9")
        action, kw = calls[0]
        self.assertEqual(action["tool"], "fetch_url")
        self.assertIs(kw["caller_identity"], ident)
        self.assertIn("do X", kw["preview"])
        self.assertIn("fake_value_3f9a", repr(action))

    def test_enqueue_without_identity_refused(self):
        class StubQueue(object):
            def queue(self, action, **kw):
                return "appr-1"

        shape = {"tool": "t", "required_scopes": [], "what_it_would_do": "x",
                 "consent_url": "u", "args": {}}
        with self.assertRaises(stl.ScopedListingError) as cm:
            stl.enqueue_approval(StubQueue(), shape, caller_identity=None)
        self.assertEqual(cm.exception.code, "scope-listing-denied")


class TaxonomyPinTest(unittest.TestCase):
    def test_pin_is_1112(self):
        self.assertEqual(len(dc.TAXONOMY), 2130) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded) Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*). # Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)
        # Wave-262 lane 1: pin -> 1112 (1106 + 6 scope-listing codes).

    def test_new_codes_sorted_and_complete(self):
        codes = ["scope-consent-expired", "scope-consent-forged",
                 "scope-consent-unbound", "scope-listing-denied",
                 "scope-listing-not-registered", "scope-listing-unknown-scope"]
        for c in codes:
            rec = dc.TAXONOMY[c]
            self.assertEqual(rec["code"], c)
            for f in ("domain", "code", "human", "severity",
                      "evidence_kinds_required", "reverify_steps"):
                self.assertIn(f, rec)
        keys = list(dc.TAXONOMY)
        for a, b in zip(codes, codes[1:]):
            self.assertLess(keys.index(a), keys.index(b))

    def test_new_codes_replay(self):
        digests = ["0" * 64]
        for c in ["scope-listing-denied", "scope-consent-forged"]:
            mc = dc.emit(c, evidence_digests=digests)
            checked = dc.replay(mc)
            self.assertEqual(checked["refusal"], c)


if __name__ == "__main__":
    unittest.main()
