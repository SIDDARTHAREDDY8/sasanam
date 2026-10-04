"""Unit tests for gov/tool_grant.py (per-tool MCP authorization)."""
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519, tool_grant  # noqa: E402

TAXONOMY_PIN = 2035 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



ISS_SEED = bytes.fromhex("11" * 32)
HOLDER_SEED = bytes.fromhex("22" * 32)
ATTACKER_SEED = bytes.fromhex("33" * 32)
NOW = 1790000000
AUD = "https://mcp.example.internal/fileserver"
SUB = "spiffe://trust-domain/ns/prod/sa/agent-7"
LINK = "sha256:" + "ab" * 32


def _issuer():
    return tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=ISS_SEED,
                             mandate_lookup=lambda m: {"version": 7})


def _details(tool="read_file", **kw):
    d = {
        "type": "https://sasanam.dev/mcp_tool_call",
        "locations": [AUD],
        "actions": ["call"],
        "identifier": "fileserver::" + tool,
        "arg_bounds": {"path": {"predicate": "prefix",
                                "params": {"prefix": "/data/shared/"}}},
        "supply_chain": {"link_digest": LINK, "delegation_ok": True},
        "max_calls": 3,
    }
    d.update(kw)
    return d


def _issue(details, **kw):
    base = dict(sub=SUB, aud=AUD, proof_pub=ed25519.publickey(HOLDER_SEED),
                mandate_id="mnd_1", mandate_version=7, lifetime_s=600, now=NOW)
    base.update(kw)
    return _issuer().issue(details=details, **base)


def _env(**kw):
    env = dict(issuer_pub=ed25519.publickey(ISS_SEED), server_name="fileserver",
               server_uri=AUD, now=NOW, usage_store=tool_grant.UsageStore(),
               mandate_version_provider=lambda m: 7,
               link_verifier=lambda t: LINK)
    env.update(kw)
    return env


def _proof(g, seed=HOLDER_SEED, now=NOW, nonce="u1"):
    return tool_grant.make_pop_proof(seed, g, method="tools/call",
                                     uri=AUD + "/tools/call", now=now, nonce=nonce)


def _call(g, tool="read_file", args=None, **kw):
    env = _env(**kw)
    return tool_grant.enforce(g, proof=_proof(g), tool=tool,
                              args=args or {"path": "/data/shared/a.txt"}, **env)


class TestIssuance(unittest.TestCase):
    def test_round_trip(self):
        g = _issue([_details()])
        ok, code, body = tool_grant.verify_grant(
            g, issuer_pub=ed25519.publickey(ISS_SEED), now=NOW)
        self.assertTrue(ok)
        self.assertEqual(code, "ptgrant-ok")
        self.assertEqual(body["jti"], g["body"]["jti"])

    def test_deterministic_jti(self):
        a = _issue([_details()])
        b = _issue([_details()])
        self.assertEqual(a["body"]["jti"], b["body"]["jti"])

    def test_tampered_body_refused(self):
        g = _issue([_details()])
        g["body"]["aud"] = "https://evil.example/"
        ok, code, _ = tool_grant.verify_grant(
            g, issuer_pub=ed25519.publickey(ISS_SEED), now=NOW)
        self.assertFalse(ok)
        self.assertEqual(code, "ptgrant-signature-invalid")

    def test_unknown_predicate_at_issuance(self):
        d = _details()
        d["arg_bounds"] = {"path": {"predicate": "telepathy", "params": {}}}
        with self.assertRaises(tool_grant.GrantError) as ctx:
            _issue([d])
        self.assertEqual(ctx.exception.code, "ptgrant-predicate-unknown")

    def test_multi_aud_refused(self):
        with self.assertRaises(tool_grant.GrantError) as ctx:
            _issue([_details()], aud=["https://a/", "https://b/"])
        self.assertEqual(ctx.exception.code, "ptgrant-audience-mismatch")

    def test_mandate_mismatch_refused(self):
        with self.assertRaises(tool_grant.GrantError) as ctx:
            _issue([_details()], mandate_version=8)
        self.assertEqual(ctx.exception.code, "ptgrant-invalid-target")

    def test_verify_never_raises(self):
        ok, code, _ = tool_grant.verify_grant(
            {"nope": 1}, issuer_pub=ed25519.publickey(ISS_SEED), now=NOW)
        self.assertFalse(ok)
        self.assertEqual(code, "ptgrant-grant-malformed")


class TestEnforcement(unittest.TestCase):
    def test_happy_path(self):
        v = _call(_issue([_details()]))
        self.assertTrue(v["ok"])
        self.assertEqual(v["code"], "ptgrant-ok")
        self.assertIn("grant:ptgrant-ok", v["checked"])

    def test_forged_signature(self):
        iss = tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=ATTACKER_SEED,
                                mandate_lookup=lambda m: {"version": 7})
        g = iss.issue(sub=SUB, aud=AUD, proof_pub=ed25519.publickey(ATTACKER_SEED),
                      mandate_id="mnd_1", mandate_version=7,
                      details=[_details()], lifetime_s=600, now=NOW)
        v = _call(g)
        self.assertFalse(v["ok"])
        self.assertEqual(v["code"], "ptgrant-signature-invalid")

    def test_wrong_audience(self):
        v = _call(_issue([_details()]),
                  server_uri="https://mcp.example.internal/otherserver")
        self.assertEqual(v["code"], "ptgrant-audience-mismatch")

    def test_tool_not_covered(self):
        v = _call(_issue([_details()]), tool="delete_file")
        self.assertEqual(v["code"], "ptgrant-tool-not-covered")

    def test_identifier_prefix_confusion(self):
        v = _call(_issue([_details()]), tool="read_file2")
        self.assertEqual(v["code"], "ptgrant-tool-not-covered")

    def test_arg_bound_violation(self):
        v = _call(_issue([_details()]), args={"path": "/etc/passwd"})
        self.assertEqual(v["code"], "ptgrant-arg-bound-violated")

    def test_expired(self):
        v = _call(_issue([_details()], lifetime_s=60), now=NOW + 61)
        self.assertEqual(v["code"], "ptgrant-grant-expired")

    def test_mandate_drift(self):
        v = _call(_issue([_details()]),
                  mandate_version_provider=lambda m: 8)
        self.assertEqual(v["code"], "ptgrant-mandate-drift")

    def test_cnf_confusion(self):
        g = _issue([_details()])
        proof = _proof(g, seed=ATTACKER_SEED, nonce="a1")
        env = _env()
        v = tool_grant.enforce(g, proof=proof, tool="read_file",
                               args={"path": "/data/shared/a.txt"}, **env)
        self.assertEqual(v["code"], "ptgrant-pop-invalid")

    def test_link_mismatch(self):
        v = _call(_issue([_details()]),
                  link_verifier=lambda t: "sha256:" + "ff" * 32)
        self.assertEqual(v["code"], "ptgrant-supply-chain-failed")

    def test_link_unverifiable(self):
        def boom(t):
            raise RuntimeError("registry down")
        v = _call(_issue([_details()]), link_verifier=boom)
        self.assertEqual(v["code"], "ptgrant-link-unverifiable")

    def test_enforce_never_raises(self):
        v = tool_grant.enforce(None, proof=None, issuer_pub=b"\x00" * 32,
                               server_name="x", server_uri="https://x/",
                               tool="t", args={}, now=NOW,
                               usage_store=tool_grant.UsageStore(),
                               mandate_version_provider=lambda m: 0,
                               link_verifier=lambda t: None)
        self.assertFalse(v["ok"])


class TestBudget(unittest.TestCase):
    def test_max_calls(self):
        d = _details()
        d["max_calls"] = 2
        g = _issue([d])
        store = tool_grant.UsageStore()
        for i in range(2):
            env = _env(usage_store=store)
            v = tool_grant.enforce(g, proof=_proof(g, nonce="m%d" % i),
                                   tool="read_file",
                                   args={"path": "/data/shared/a.txt"}, **env)
            self.assertTrue(v["ok"], v)
        env = _env(usage_store=store)
        v = tool_grant.enforce(g, proof=_proof(g, nonce="m2"), tool="read_file",
                               args={"path": "/data/shared/a.txt"}, **env)
        self.assertEqual(v["code"], "ptgrant-max-calls-exhausted")

    def test_nonce_replay(self):
        g = _issue([_details()])
        store = tool_grant.UsageStore()
        env = _env(usage_store=store)
        proof = _proof(g, nonce="r1")
        v1 = tool_grant.enforce(g, proof=proof, tool="read_file",
                                args={"path": "/data/shared/a.txt"}, **env)
        self.assertTrue(v1["ok"])
        used1 = store.status(g["body"]["jti"], 3)["calls_used"]
        v2 = tool_grant.enforce(g, proof=proof, tool="read_file",
                                args={"path": "/data/shared/a.txt"}, **env)
        self.assertEqual(v2["code"], "ptgrant-jti-reused")
        # F253: the nonce replay check runs before budget consumption --
        # the refused replay is budget-neutral.
        self.assertEqual(used1, 1, "first call consumed exactly one")
        used2 = store.status(g["body"]["jti"], 3)["calls_used"]
        self.assertEqual(used2, used1, "refused replay burned budget")


class TestProofMinting(unittest.TestCase):
    """F254: make_pop_proof has no silent deterministic default."""

    def _mint_kw(self, g):
        return dict(seed=HOLDER_SEED, grant=g, method="tools/call",
                    uri=AUD + "/tools/call", now=NOW)

    def test_missing_nonce_refused(self):
        g = _issue([_details()])
        with self.assertRaises(tool_grant.GrantError) as ctx:
            tool_grant.make_pop_proof(**self._mint_kw(g))
        self.assertEqual(ctx.exception.code, "ptgrant-pop-invalid")

    def test_empty_nonce_refused(self):
        g = _issue([_details()])
        for bad in ("", None, b"bytes-not-str"):
            with self.assertRaises(tool_grant.GrantError) as ctx:
                tool_grant.make_pop_proof(nonce=bad, **self._mint_kw(g))
            self.assertEqual(ctx.exception.code, "ptgrant-pop-invalid")

    def test_same_second_unique_nonces_distinct(self):
        g = _issue([_details()])
        p1 = tool_grant.make_pop_proof(nonce="m1", **self._mint_kw(g))
        p2 = tool_grant.make_pop_proof(nonce="m2", **self._mint_kw(g))
        self.assertNotEqual(p1, p2)
        self.assertNotEqual(p1["sig"], p2["sig"])


class TestAttenuation(unittest.TestCase):
    def test_chain_verifies(self):
        g = _issue([_details()])
        g2 = tool_grant.attenuate(g, holder_seed=HOLDER_SEED,
                                  issuer_pub=ed25519.publickey(ISS_SEED),
                                  caveats=[{"predicate": "max_calls",
                                            "params": {"max_calls": 1}}])
        self.assertEqual(len(g2["attenuation"]), 1)
        v = _call(g2)
        self.assertTrue(v["ok"])

    def test_foreign_key_cannot_attenuate(self):
        g = _issue([_details()])
        with self.assertRaises(tool_grant.GrantError) as ctx:
            tool_grant.attenuate(g, holder_seed=ATTACKER_SEED,
                                 issuer_pub=ed25519.publickey(ISS_SEED),
                                 caveats=[{"predicate": "max_calls",
                                           "params": {"max_calls": 1}}])
        self.assertEqual(ctx.exception.code, "ptgrant-pop-invalid")

    def test_unknown_caveat_denied(self):
        g = _issue([_details()])
        with self.assertRaises(tool_grant.GrantError) as ctx:
            tool_grant.attenuate(g, holder_seed=HOLDER_SEED,
                                 issuer_pub=ed25519.publickey(ISS_SEED),
                                 caveats=[{"predicate": "mystery", "params": {}}])
        self.assertEqual(ctx.exception.code, "ptgrant-predicate-unknown")

    def test_attenuation_does_not_mutate_input(self):
        g = _issue([_details()])
        tool_grant.attenuate(g, holder_seed=HOLDER_SEED,
                             issuer_pub=ed25519.publickey(ISS_SEED),
                             caveats=[{"predicate": "max_calls",
                                       "params": {"max_calls": 1}}])
        self.assertEqual(g["attenuation"], [])


class TestExchange(unittest.TestCase):
    def test_narrowing_exchange(self):
        parent = _issue([_details(max_calls=5)])
        child = _issuer().exchange(parent, parent_holder_seed=HOLDER_SEED,
                                   details=[_details(max_calls=1)], now=NOW,
                                   proof_pub=ed25519.publickey(HOLDER_SEED),
                                   lifetime_s=60)
        v = _call(child)
        self.assertTrue(v["ok"])

    def test_widening_refused(self):
        parent = _issue([_details(max_calls=1)])
        with self.assertRaises(tool_grant.GrantError) as ctx:
            _issuer().exchange(parent, parent_holder_seed=HOLDER_SEED,
                               details=[_details(max_calls=5)], now=NOW,
                               proof_pub=ed25519.publickey(HOLDER_SEED),
                               lifetime_s=60)
        self.assertEqual(ctx.exception.code, "ptgrant-invalid-target")

    def test_parent_survives_exchange(self):
        """RFC 8693 2.1 trap: exchange does not revoke the parent."""
        parent = _issue([_details()])
        _issuer().exchange(parent, parent_holder_seed=HOLDER_SEED,
                           details=[_details(max_calls=1)], now=NOW,
                           proof_pub=ed25519.publickey(HOLDER_SEED),
                           lifetime_s=60)
        self.assertTrue(_call(parent)["ok"])


class TestProvider(unittest.TestCase):
    def test_custom_provider_shape(self):
        now = [NOW]
        prov = tool_grant.make_ptgrant_provider(
            issuer_pub=ed25519.publickey(ISS_SEED), server_name="fileserver",
            server_uri=AUD, now_fn=lambda: now[0],
            usage_store=tool_grant.UsageStore(),
            mandate_version_provider=lambda m: 7, link_verifier=lambda t: LINK)
        g = _issue([_details()])
        allowed, reason = prov("ptgrant", {"grant": g, "proof": _proof(g, nonce="p1"),
                                           "tool": "read_file",
                                           "args": {"path": "/data/shared/a.txt"}})
        self.assertTrue(allowed, reason)
        denied, reason = prov("ptgrant", {"grant": g, "proof": _proof(g, nonce="p2"),
                                          "tool": "delete_file",
                                          "args": {"path": "/data/shared/a.txt"}})
        self.assertFalse(denied)
        self.assertIn("ptgrant-tool-not-covered", reason)


class TestTaxonomy(unittest.TestCase):
    def test_pin(self):
        from gov import decision_codes
        self.assertEqual(len(decision_codes.TAXONOMY), TAXONOMY_PIN)

    def test_codes_unique_on_raw_source(self):
        import re
        with open("gov/tool_grant.py") as fh:
            src = fh.read()
        codes = re.findall(r'"(ptgrant-[a-z-]+)"', src)
        declared = sorted(set(codes))
        self.assertEqual(declared, sorted(tool_grant.PTGRANT_CODES))
        self.assertEqual(len(tool_grant.PTGRANT_CODES), 25)


if __name__ == "__main__":
    unittest.main()
