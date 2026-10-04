"""Unit tests for gov/transactional_tokens.py (W243-3, ADAPT pattern).

Red-first: these tests were written against the probe battery's
behavior contract before the module's edge cases were settled; they
run green only against the shipped module.
"""

import inspect
import unittest

from gov import decision_codes as dc
from gov import transactional_tokens as tt

_KEY = b"unit-test-key-64bytes-0123456789abcdef0123456789abcdef"
_NOW = 1_700_000_000


class IssueTest(unittest.TestCase):
    def setUp(self):
        self.issuer = tt.TransactionalTokenIssuer(_KEY)

    def test_issue_embeds_triple(self):
        token = self.issuer.issue("t1", "https://rs.example", 60, now=_NOW)
        self.assertEqual(token["txn_id"], "t1")
        self.assertEqual(token["aud"], "https://rs.example")
        self.assertEqual(token["iat"], _NOW)
        self.assertEqual(token["exp"], _NOW + 60)
        self.assertTrue(token["mac"])

    def test_issue_ttl_required_positionally(self):
        # ttl_seconds has no default: a caller cannot silently inherit a
        # duration config.
        sig = inspect.signature(tt.TransactionalTokenIssuer.issue)
        self.assertIs(sig.parameters["ttl_seconds"].default,
                      inspect.Parameter.empty)

    def test_issue_over_cap_refused(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self.issuer.issue("t1", "https://rs.example",
                              tt.TRANSACTION_TTL_MAX_SECONDS + 1, now=_NOW)
        self.assertEqual(ctx.exception.code, "transaction-malformed")

    def test_issue_bool_ttl_refused(self):
        # The True == 1 epoch trap: a bool is not a ttl.
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self.issuer.issue("t1", "https://rs.example", True, now=_NOW)
        self.assertEqual(ctx.exception.code, "transaction-malformed")

    def test_issue_empty_txn_id_refused(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self.issuer.issue("", "https://rs.example", 60, now=_NOW)
        self.assertEqual(ctx.exception.code, "transaction-malformed")

    def test_no_key_issue_fails_closed(self):
        issuer = tt.TransactionalTokenIssuer(None)
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            issuer.issue("t1", "https://rs.example", 60, now=_NOW)
        self.assertEqual(ctx.exception.code, "transaction-key-missing")

    def test_empty_key_bytes_fail_closed(self):
        issuer = tt.TransactionalTokenIssuer(b"")
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            issuer.issue("t1", "https://rs.example", 60, now=_NOW)
        self.assertEqual(ctx.exception.code, "transaction-key-missing")


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.issuer = tt.TransactionalTokenIssuer(_KEY)
        self.token = self.issuer.issue("t1", "https://rs.example", 60,
                                       now=_NOW)

    def _verify(self, token, txn="t1", aud="https://rs.example",
                now=_NOW + 1):
        return self.issuer.verify(token, txn, aud, now)

    def test_happy_path(self):
        body = self._verify(self.token)
        self.assertEqual(body["txn_id"], "t1")
        self.assertNotIn("mac", body)  # body only, never the MAC

    def test_verify_is_deterministic(self):
        first = self._verify(self.token)
        second = self._verify(self.token)
        self.assertEqual(first, second)

    def test_txn_reuse_refused(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(self.token, txn="t2")
        self.assertEqual(ctx.exception.code, "transaction-id-mismatch")

    def test_expired_refused(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(self.token, now=_NOW + 61)
        self.assertEqual(ctx.exception.code, "transaction-expired")

    def test_exactly_at_exp_is_expired(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(self.token, now=_NOW + 60)
        self.assertEqual(ctx.exception.code, "transaction-expired")

    def test_wrong_rs_refused(self):
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(self.token, aud="https://other.example")
        self.assertEqual(ctx.exception.code, "resource-server-mismatch")

    def test_tampered_txn_id_is_signature_invalid(self):
        tampered = dict(self.token, txn_id="t2")
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(tampered, txn="t2")
        self.assertEqual(ctx.exception.code, "transaction-signature-invalid")

    def test_tampered_exp_is_signature_invalid(self):
        tampered = dict(self.token, exp=_NOW + 3600)
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(tampered, now=_NOW + 61)
        self.assertEqual(ctx.exception.code, "transaction-signature-invalid")

    def test_wrong_key_is_signature_invalid(self):
        other = tt.TransactionalTokenIssuer(b"a-different-key")
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            other.verify(self.token, "t1", "https://rs.example", _NOW + 1)
        self.assertEqual(ctx.exception.code, "transaction-signature-invalid")

    def test_malformed_shapes(self):
        bad = [None, "string", [], {"v": 1},
               dict(self.token, txn_id=7),
               dict(self.token, exp=True),
               dict(self.token, mac="")]
        for token in bad:
            with self.assertRaises(tt.TransactionalTokenError) as ctx:
                self._verify(token)
            self.assertEqual(ctx.exception.code, "transaction-malformed",
                             token)

    def test_missing_mac_field(self):
        token = dict(self.token)
        del token["mac"]
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "transaction-malformed")

    def test_no_key_verify_fails_closed(self):
        issuer = tt.TransactionalTokenIssuer(None)
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            issuer.verify(self.token, "t1", "https://rs.example", _NOW + 1)
        self.assertEqual(ctx.exception.code, "transaction-key-missing")


class TaxonomyTest(unittest.TestCase):
    def test_codes_mapped(self):
        for code in tt.CODES:
            dc.code_for(code)

    def test_pin(self):
        # Wave-243 lane C (W243-3): re-pointed 788 -> 794
        # (6 transactional-token codes), additive only.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1945)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
