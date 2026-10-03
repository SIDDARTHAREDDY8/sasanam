#!/usr/bin/env python3
"""Wave-248 lane 5: dex-shaped federated identity unit tests.

normalize_claims (one identity shape per connector), IdentityTokenIssuer
(short-lived HMAC identity tokens), RefreshTokenStore (rotation + reuse
detection). Deterministic: fixed keys, injected clocks, no randomness in
assertions. Taxonomy pin: lane-local 951 (938 + 13 dex-identity codes);
merge coordinator recomposes.
"""

import unittest

from gov import agent_identity as ai
from gov import decision_codes as dc

_FIXED_KEY = b"k" * 32
_FIXED_NOW = 1_800_000_000

_NEW_CODES = (
    "identity-connector-unsupported",
    "identity-claims-missing-subject",
    "identity-claims-ambiguous",
    "identity-claims-malformed",
    "identity-token-malformed",
    "identity-token-tampered",
    "identity-token-expired",
    "identity-token-audience-mismatch",
    "identity-token-not-yet-valid",
    "identity-refresh-unknown",
    "identity-refresh-expired",
    "identity-refresh-reuse-detected",
    "identity-refresh-revoked",
)


def _oidc(**over):
    claims = {"sub": "agent-7", "email": "agent-7@example.com",
              "email_verified": True, "groups": ["ops", "readers"]}
    claims.update(over)
    return claims


def _static(**over):
    claims = {"username": "agent-7", "email": "agent-7@example.com",
              "groups": ["ops"]}
    claims.update(over)
    return claims


class NormalizeClaimsTests(unittest.TestCase):

    def test_oidc_happy_path(self):
        ident = ai.normalize_claims(_oidc(), "oidc")
        self.assertEqual(ident["subject"], "agent-7")
        self.assertEqual(ident["email"], "agent-7@example.com")
        self.assertTrue(ident["email_verified"])
        self.assertEqual(ident["groups"], ["ops", "readers"])
        self.assertEqual(ident["connector_id"], "oidc")

    def test_static_happy_path(self):
        ident = ai.normalize_claims(_static(), "static")
        self.assertEqual(ident["subject"], "agent-7")
        # The static connector never vouches email.
        self.assertFalse(ident["email_verified"])
        self.assertEqual(ident["connector_id"], "static")

    def test_one_shape_regardless_of_connector(self):
        oidc_ident = ai.normalize_claims(_oidc(), "oidc")
        static_ident = ai.normalize_claims(_static(), "static")
        self.assertEqual(set(oidc_ident), set(static_ident))
        self.assertEqual(set(oidc_ident),
                         {"subject", "email", "email_verified",
                          "groups", "connector_id"})

    def test_missing_subject_refused(self):
        claims = _oidc()
        del claims["sub"]
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(claims, "oidc")
        self.assertEqual(ctx.exception.code,
                         "identity-claims-missing-subject")

    def test_ambiguous_subject_refused(self):
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(_oidc(uid="someone-else"), "oidc")
        self.assertEqual(ctx.exception.code, "identity-claims-ambiguous")

    def test_consistent_duplicate_subject_ok(self):
        # Both candidates present with the SAME value: no ambiguity.
        ident = ai.normalize_claims(_oidc(uid="agent-7"), "oidc")
        self.assertEqual(ident["subject"], "agent-7")

    def test_unknown_connector_refused(self):
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(_oidc(), "github")
        self.assertEqual(ctx.exception.code,
                         "identity-connector-unsupported")

    def test_saml_refused(self):
        # The SAML connector stays OFF (unmaintained upstream).
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(_oidc(), "saml")
        self.assertEqual(ctx.exception.code,
                         "identity-connector-unsupported")
        self.assertIn("SAML", ctx.exception.detail)

    def test_non_dict_claims_refused(self):
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(["sub", "agent-7"], "oidc")
        self.assertEqual(ctx.exception.code, "identity-claims-malformed")

    def test_bad_groups_refused(self):
        with self.assertRaises(ai.ClaimNormalizationError) as ctx:
            ai.normalize_claims(_oidc(groups="ops"), "oidc")
        self.assertEqual(ctx.exception.code, "identity-claims-malformed")

    def test_groups_default_empty(self):
        claims = _oidc()
        del claims["groups"]
        ident = ai.normalize_claims(claims, "oidc")
        self.assertEqual(ident["groups"], [])

    def test_email_optional(self):
        claims = _oidc()
        del claims["email"]
        ident = ai.normalize_claims(claims, "oidc")
        self.assertIsNone(ident["email"])


class IdentityTokenIssuerTests(unittest.TestCase):

    def _issuer(self):
        return ai.IdentityTokenIssuer(_FIXED_KEY,
                                      time_fn=lambda: _FIXED_NOW)

    def _ident(self):
        return ai.normalize_claims(_oidc(), "oidc")

    def test_round_trip(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW,
                             jti="fixed-jti")
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(got["subject"], "agent-7")
        self.assertEqual(got["groups"], ["ops", "readers"])
        self.assertEqual(got["audience"], "agents")
        self.assertEqual(got["jti"], "fixed-jti")
        self.assertEqual(got["exp"] - got["iat"], 300)

    def test_default_lifetime_short(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW)
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertLessEqual(got["exp"] - got["iat"], 300)

    def test_lifetime_capped_at_max(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents",
                             lifetime_seconds=99_999, now=_FIXED_NOW)
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertLessEqual(got["exp"] - got["iat"], 3600)

    def test_expired_refused(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents",
                             now=_FIXED_NOW - 10_000)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(ctx.exception.code, "identity-token-expired")

    def test_wrong_audience_refused(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            issuer.verify_token(token, "other", now=_FIXED_NOW)
        self.assertEqual(ctx.exception.code,
                         "identity-token-audience-mismatch")

    def test_tampered_payload_refused(self):
        import base64
        import json
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW)
        head, sig = token.split(".")
        body = json.loads(base64.urlsafe_b64decode(
            head + "=" * (-len(head) % 4)).decode())
        body["sub"] = "attacker"
        forged_head = base64.urlsafe_b64encode(
            json.dumps(body, sort_keys=True,
                       separators=(",", ":")).encode()).decode().rstrip("=")
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            issuer.verify_token(forged_head + "." + sig, "agents",
                                now=_FIXED_NOW)
        self.assertEqual(ctx.exception.code, "identity-token-tampered")

    def test_wrong_key_refused(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW)
        other = ai.IdentityTokenIssuer(b"q" * 32,
                                       time_fn=lambda: _FIXED_NOW)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            other.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(ctx.exception.code, "identity-token-tampered")

    def test_malformed_refused(self):
        issuer = self._issuer()
        for bad in ("no-dots", "a.b.c", ".", "!!!.!!!"):
            with self.assertRaises(ai.IdentityTokenRejection) as ctx:
                issuer.verify_token(bad, "agents", now=_FIXED_NOW)
            self.assertEqual(ctx.exception.code,
                             "identity-token-malformed", bad)

    def test_not_yet_valid_refused(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents",
                             now=_FIXED_NOW + 10_000)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(ctx.exception.code,
                         "identity-token-not-yet-valid")

    def test_short_key_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            ai.IdentityTokenIssuer(b"short")

    def test_two_part_shape(self):
        issuer = self._issuer()
        token = issuer.issue(self._ident(), "agents", now=_FIXED_NOW)
        self.assertEqual(len(token.split(".")), 2)


class RefreshTokenStoreTests(unittest.TestCase):

    def _pair(self):
        issuer = ai.IdentityTokenIssuer(_FIXED_KEY,
                                        time_fn=lambda: _FIXED_NOW)
        store = ai.RefreshTokenStore(time_fn=lambda: _FIXED_NOW)
        return issuer, store

    def _mint(self, store, **kw):
        ident = ai.normalize_claims(_oidc(), "oidc")
        return store.mint_refresh(ident, "oidc", _oidc(), **kw)

    def test_refresh_round_trip(self):
        issuer, store = self._pair()
        rid, secret = self._mint(store)
        token, rid2, secret2 = store.refresh(issuer, rid, secret,
                                             "agents")
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(got["subject"], "agent-7")
        self.assertNotEqual(rid2, rid)

    def test_refreshed_token_is_short_lived(self):
        # The refresh token lives 24h; the identity token it mints must
        # still be short. No silent lifetime extension.
        issuer, store = self._pair()
        rid, secret = self._mint(store, lifetime_seconds=86_400)
        token, _, _ = store.refresh(issuer, rid, secret, "agents")
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertLessEqual(got["exp"] - got["iat"], 300)

    def test_refresh_renormalizes_claims(self):
        issuer, store = self._pair()
        ident = ai.normalize_claims(_oidc(), "oidc")
        # Store a claim set whose groups differ from the mint-time
        # identity: the refresh must carry the CURRENT normalized
        # claims, not a stale copy.
        rid, secret = store.mint_refresh(
            ident, "oidc", _oidc(groups=["admins"]))
        token, _, _ = store.refresh(issuer, rid, secret, "agents")
        got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
        self.assertEqual(got["groups"], ["admins"])

    def test_unknown_refresh_refused(self):
        issuer, store = self._pair()
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            store.refresh(issuer, "rt_nope", "x" * 64, "agents")
        self.assertEqual(ctx.exception.code, "identity-refresh-unknown")

    def test_wrong_secret_refused_without_oracle(self):
        issuer, store = self._pair()
        rid, _ = self._mint(store)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            store.refresh(issuer, rid, "0" * 64, "agents")
        # Same code as unknown id: no oracle.
        self.assertEqual(ctx.exception.code, "identity-refresh-unknown")

    def test_expired_refresh_refused(self):
        issuer, store = self._pair()
        rid, secret = self._mint(store, lifetime_seconds=100,
                                 now=_FIXED_NOW - 10_000)
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            store.refresh(issuer, rid, secret, "agents")
        self.assertEqual(ctx.exception.code, "identity-refresh-expired")

    def test_reuse_detected_and_chain_revoked(self):
        issuer, store = self._pair()
        rid, secret = self._mint(store)
        token, rid2, secret2 = store.refresh(issuer, rid, secret,
                                             "agents")
        self.assertIsNotNone(token)
        # Reuse of the spent token: refuse + revoke the whole chain.
        with self.assertRaises(ai.IdentityTokenRejection) as ctx:
            store.refresh(issuer, rid, secret, "agents")
        self.assertEqual(ctx.exception.code,
                         "identity-refresh-reuse-detected")
        # Even the newest token in the chain now fails.
        with self.assertRaises(ai.IdentityTokenRejection) as ctx2:
            store.refresh(issuer, rid2, secret2, "agents")
        self.assertEqual(ctx2.exception.code, "identity-refresh-revoked")

    def test_secret_stored_only_as_hash(self):
        _, store = self._pair()
        rid, secret = self._mint(store)
        rec = store._tokens[rid]
        self.assertNotIn(secret, str(rec))
        self.assertEqual(len(rec["secret_hash"]), 64)


class TaxonomyPinTests(unittest.TestCase):

    def test_taxonomy_pin_979(self):
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes: 1 breach-boundary + 9 skill-admission + 2 evidence-envelope + 6 skill-update + 13 identity + 3 combine + 7 artifact), additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1872)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        for code in _NEW_CODES:
            self.assertIn(code, dc.TAXONOMY)
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(set(dc.TAXONOMY)), 1872)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*)


if __name__ == "__main__":
    unittest.main()
