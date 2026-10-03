"""Unit tests for gov/token_hygiene.py (wave-234 lane B).

Deterministic: every clock is injected (now=). Digest expectations
come from stdlib primitives, not from the module under test.
"""

import time
import unittest

from gov import token_hygiene as th


T0 = 1790817600  # 2026-09-30T12:00:00Z


def _claims(iat=T0, ttl=600, aud="svc:policy", iss="issuer:1",
            key_id="k1", key_issued_at=T0, impact="standard"):
    return {"type": "agent-credential", "iat": iat, "exp": iat + ttl,
            "aud": aud, "iss": iss, "scope": "policy:evaluate",
            "key_id": key_id, "key_issued_at": key_issued_at,
            "impact": impact}


class IssuanceTest(unittest.TestCase):
    def setUp(self):
        self.hyg = th.TokenHygiene()

    def test_cap_exact_passes(self):
        # Exactly 3600s is the cap: the boundary belongs to the cap.
        out = self.hyg.validate_issuance(
            _claims(ttl=th.MAX_TTL_SECONDS), now=T0)
        self.assertEqual(out["exp"], T0 + 3600)

    def test_cap_plus_one_refuses(self):
        # One second over the cap refuses at ISSUANCE, not at expiry.
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(
                _claims(ttl=th.MAX_TTL_SECONDS + 1), now=T0)
        self.assertEqual(ctx.exception.code, "token-ttl-exceeded")

    def test_expiry_after_issuance_still_checked_at_issuance(self):
        # A token that is NOT yet expired is still refused when its
        # LIFETIME was too long: the cap is an issuance property.
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(_claims(ttl=7200), now=T0)
        self.assertEqual(ctx.exception.code, "token-ttl-exceeded")

    def test_widening_cap_refused_fail_closed(self):
        # The 1h cap is the invariant, not a default: widening fails.
        with self.assertRaises(th.TokenHygieneError) as ctx:
            th.TokenHygiene(max_ttl_seconds=7200)
        self.assertEqual(ctx.exception.code, "token-ttl-exceeded")

    def test_tightening_cap_allowed(self):
        strict = th.TokenHygiene(max_ttl_seconds=1800)
        with self.assertRaises(th.TokenHygieneError) as ctx:
            strict.validate_issuance(_claims(ttl=3600), now=T0)
        self.assertEqual(ctx.exception.code, "token-ttl-exceeded")

    def test_missing_audience(self):
        claims = _claims()
        del claims["aud"]
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(claims, now=T0)
        self.assertEqual(ctx.exception.code, "token-audience-missing")

    def test_empty_audience(self):
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(_claims(aud=""), now=T0)
        self.assertEqual(ctx.exception.code, "token-audience-missing")

    def test_malformed_claims(self):
        bad = [None, "x", 42, ["aud"], {"iat": "soon", "exp": T0 + 600,
                                        "aud": "a", "key_id": "k",
                                        "key_issued_at": T0}]
        for claims in bad:
            with self.assertRaises(th.TokenHygieneError) as ctx:
                self.hyg.validate_issuance(claims, now=T0)
            self.assertEqual(ctx.exception.code, "token-malformed",
                             "claims=%r" % (claims,))

    def test_exp_not_after_iat(self):
        claims = _claims()
        claims["exp"] = claims["iat"]
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(claims, now=T0)
        self.assertEqual(ctx.exception.code, "token-malformed")

    def test_base_class_defines_no_code(self):
        # Wave-233 lane-A lesson: the base class must not carry
        # product vocabulary (the w228 scanner maps class-level
        # ``code`` attributes).
        self.assertNotIn("code", vars(th.TokenHygieneError))

    def test_reason_mirrors_code(self):
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(_claims(ttl=7200), now=T0)
        self.assertEqual(ctx.exception.reason, ctx.exception.code)


class KeyRotationTest(unittest.TestCase):
    def setUp(self):
        self.hyg = th.TokenHygiene()

    def test_stale_high_impact_key_refused(self):
        stale = T0 - 91 * 86400
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(
                _claims(key_issued_at=stale, impact="high"), now=T0)
        self.assertEqual(ctx.exception.code, "token-key-stale")

    def test_fresh_high_impact_key_passes(self):
        fresh = T0 - 89 * 86400
        out = self.hyg.validate_issuance(
            _claims(key_issued_at=fresh, impact="high"), now=T0)
        self.assertEqual(out["key_id"], "k1")

    def test_stale_key_standard_impact_passes(self):
        # The 90-day window binds high-impact keys only.
        stale = T0 - 91 * 86400
        out = self.hyg.validate_issuance(
            _claims(key_issued_at=stale, impact="standard"), now=T0)
        self.assertEqual(out["impact"], "standard")

    def test_present_rechecks_key_stale(self):
        # Pinned deliberate semantics: present() re-validates the full
        # issuance policy at presentation time. A high-impact token
        # issued with a key just inside the window (89 days) presented
        # after the key crosses 90 days refuses token-key-stale.
        # (Fail-closed strictness; the 1h TTL cap bounds the drift.)
        key_birth = T0 - 89 * 86400
        issued = self.hyg.validate_issuance(
            _claims(ttl=600, key_issued_at=key_birth, impact="high"),
            now=T0)
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.present(issued, "svc:policy", now=T0 + 2 * 86400)
        self.assertEqual(ctx.exception.code, "token-key-stale")

    def test_bad_impact_refused(self):
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.validate_issuance(_claims(impact="cosmic"), now=T0)
        self.assertEqual(ctx.exception.code, "token-malformed")


class PresentationTest(unittest.TestCase):
    def setUp(self):
        self.hyg = th.TokenHygiene()

    def test_expired_refused(self):
        issued = self.hyg.validate_issuance(_claims(ttl=600), now=T0)
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.present(issued, "svc:policy", now=T0 + 601)
        self.assertEqual(ctx.exception.code, "token-expired")

    def test_expired_never_refreshed(self):
        # Retry at a later time refuses identically: there is no
        # refresh path.
        issued = self.hyg.validate_issuance(_claims(ttl=600), now=T0)
        for later in (T0 + 601, T0 + 3600, T0 + 86400):
            with self.assertRaises(th.TokenHygieneError) as ctx:
                self.hyg.present(issued, "svc:policy", now=later)
            self.assertEqual(ctx.exception.code, "token-expired",
                             "now=%d" % later)

    def test_valid_present_passes(self):
        issued = self.hyg.validate_issuance(_claims(ttl=600), now=T0)
        out = self.hyg.present(issued, "svc:policy", now=T0 + 599)
        self.assertEqual(out["aud"], "svc:policy")

    def test_audience_mismatch(self):
        issued = self.hyg.validate_issuance(_claims(ttl=600), now=T0)
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.present(issued, "svc:billing", now=T0 + 10)
        self.assertEqual(ctx.exception.code, "token-audience-mismatch")

    def test_present_rechecks_shape(self):
        issued = self.hyg.validate_issuance(_claims(ttl=600), now=T0)
        del issued["aud"]
        with self.assertRaises(th.TokenHygieneError) as ctx:
            self.hyg.present(issued, "svc:policy", now=T0 + 10)
        self.assertEqual(ctx.exception.code, "token-audience-missing")


class RegistryTest(unittest.TestCase):
    def setUp(self):
        th.clear_known_tokens()

    def tearDown(self):
        th.clear_known_tokens()

    def test_register_and_snapshot(self):
        th.register_known_token("tok-A")
        self.assertIn("tok-A", th.known_token_values())

    def test_register_rejects_empty(self):
        with self.assertRaises(th.TokenHygieneError) as ctx:
            th.register_known_token("")
        self.assertEqual(ctx.exception.code, "token-malformed")

    def test_clear(self):
        th.register_known_token("tok-A")
        th.clear_known_tokens()
        self.assertEqual(th.known_token_values(), frozenset())


class ScrubTest(unittest.TestCase):
    def setUp(self):
        th.clear_known_tokens()
        th.register_known_token("tok-SECRET-1")

    def tearDown(self):
        th.clear_known_tokens()

    def test_scrub_dict_values(self):
        out = th.token_scrub({"token": "tok-SECRET-1", "n": 1})
        self.assertEqual(out["token"], th.REDACTED_MARKER)
        self.assertEqual(out["n"], 1)

    def test_scrub_keys_untouched(self):
        # Dict keys are the log's own field names, never secrets.
        out = th.token_scrub({"tok-SECRET-1": "value"})
        self.assertIn("tok-SECRET-1", out)

    def test_scrub_nested(self):
        out = th.token_scrub(
            {"a": ["x", {"b": "prefix tok-SECRET-1 suffix"}]})
        self.assertIn(th.REDACTED_MARKER, out["a"][1]["b"])
        self.assertNotIn("tok-SECRET-1", out["a"][1]["b"])

    def test_scrub_noop_without_registration(self):
        th.clear_known_tokens()
        payload = {"token": "tok-SECRET-1"}
        self.assertIs(th.token_scrub(payload), payload)

    def test_scrub_str(self):
        self.assertIn(th.REDACTED_MARKER,
                      th.token_scrub("bearer tok-SECRET-1 here"))


class ScanTest(unittest.TestCase):
    def setUp(self):
        th.clear_known_tokens()
        th.register_known_token("tok-INCIDENT-2")

    def tearDown(self):
        th.clear_known_tokens()

    def test_assert_clean_refuses(self):
        redactor = th.TokenRedactor.from_registry()
        with self.assertRaises(th.TokenHygieneError) as ctx:
            redactor.assert_clean('{"token": "tok-INCIDENT-2"}')
        self.assertEqual(ctx.exception.code, "token-in-log")
        self.assertIn("incident", str(ctx.exception).lower())

    def test_assert_clean_passes(self):
        redactor = th.TokenRedactor.from_registry()
        self.assertIsNone(
            redactor.assert_clean('{"token": "<redacted:token>"}'))

    def test_redactor_only_scans(self):
        # The redactor has no quiet-redact path by design; redaction
        # lives at module level (token_scrub, defense-in-depth half).
        self.assertFalse(hasattr(th.TokenRedactor("x"), "scrub"))

    def test_seven_codes_in_taxonomy(self):
        from gov import decision_codes as dc
        codes = ["token-malformed", "token-ttl-exceeded", "token-expired",
                 "token-audience-missing", "token-audience-mismatch",
                 "token-key-stale", "token-in-log"]
        for code in codes:
            self.assertIn(code, dc.TAXONOMY, code)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "token_hygiene",
                             code)
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1869)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
