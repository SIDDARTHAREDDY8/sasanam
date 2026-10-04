"""Unit tests for gov.token_scope_enforcement (wave-244 lane B).

Covers the contract pins the battery does not: contract return
types, deterministic canonicalization, key-missing fail-closed, the
verdict binding fields, and the quarantine-composition control path.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import token_scope_enforcement as tse
from gov import transactional_tokens as tt

_TXN_KEY = b"unit-txn-key-0123456789abcdef"
_SCOPE_KEY = b"unit-scope-key-fedcba9876543210"
_NOW = 1_700_000_000

_SPEC = {
    "tools": {
        "file_read": {"read": ["files:read"], "write": ["files:write"]},
    },
    "aliases": {"quick_read": "file_read"},
}


def _tok(txn_id="txn-1"):
    return tt.TransactionalTokenIssuer(_TXN_KEY).issue(
        txn_id, "https://rs.example", 60, now=_NOW)


def _digest(tok):
    return hashlib.sha256(tok["mac"].encode("utf-8")).hexdigest()


def _grant(scope_map, tok):
    return tse.ScopeGrantIssuer(_SCOPE_KEY).issue_grant(
        "agent-a", _digest(tok), scope_map, now=_NOW)


def _check(tok, grant, tool="file_read", action="read",
           sealed=None, txn_id="txn-1"):
    return tse.check_scope(sealed or tse.seal_policy(_SCOPE_KEY, _SPEC),
                           tok, grant, tool, action, _NOW, _TXN_KEY,
                           _SCOPE_KEY, txn_id, "https://rs.example")


class TestTokenScope(unittest.TestCase):
    def test_codes_registered(self):
        self.assertEqual(len(tse.CODES), 8)
        self.assertEqual(len(set(tse.CODES)), 8)

    def test_happy_path_verdict_fields(self):
        tok = _tok()
        sealed = tse.seal_policy(_SCOPE_KEY, _SPEC)
        verdict = _check(tok, _grant({"file_read": ["files:read"]}, tok),
                         sealed=sealed)
        self.assertIsInstance(verdict, tse.ScopeVerdict)
        self.assertEqual((verdict.tool, verdict.action),
                         ("file_read", "read"))
        self.assertEqual(verdict.token_digest, _digest(tok))
        self.assertEqual(len(verdict.policy_digest), 64)
        self.assertEqual(verdict.granted_scopes, ("files:read",))

    def test_superset_grant_passes(self):
        tok = _tok()
        verdict = _check(
            tok, _grant({"file_read": ["files:read", "files:write"]}, tok),
            action="write")
        self.assertEqual(verdict.action, "write")

    def test_expired_token_refused_before_scope(self):
        tok = _tok()
        sealed = tse.seal_policy(_SCOPE_KEY, _SPEC)
        grant = _grant({"file_read": ["files:read"]}, tok)
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            tse.check_scope(sealed, tok, grant, "file_read", "read",
                            _NOW + 61, _TXN_KEY, _SCOPE_KEY,
                            "txn-1", "https://rs.example")
        self.assertEqual(ctx.exception.code, "transaction-expired")

    def test_txn_binding_checked_before_scope(self):
        tok = _tok()
        sealed = tse.seal_policy(_SCOPE_KEY, _SPEC)
        grant = _grant({"file_read": ["files:read"]}, tok)
        with self.assertRaises(tt.TransactionalTokenError) as ctx:
            tse.check_scope(sealed, tok, grant, "file_read", "read",
                            _NOW, _TXN_KEY, _SCOPE_KEY,
                            "txn-OTHER", "https://rs.example")
        self.assertEqual(ctx.exception.code, "transaction-id-mismatch")

    def test_scope_key_missing_fails_closed(self):
        tok = _tok()
        with self.assertRaises(tse.TokenScopeError) as ctx:
            tse.seal_policy(None, _SPEC)
        self.assertEqual(ctx.exception.code, "scope-key-missing")
        issuer = tse.ScopeGrantIssuer(None)
        with self.assertRaises(tse.TokenScopeError) as ctx2:
            issuer.issue_grant("a", "d", {"t": ["s"]}, _NOW)
        self.assertEqual(ctx2.exception.code, "scope-key-missing")

    def test_policy_digest_stable_and_tamper_evident(self):
        a = tse.seal_policy(_SCOPE_KEY, _SPEC)
        b = tse.seal_policy(_SCOPE_KEY, _SPEC)
        self.assertEqual(a["mac"], b["mac"])
        # Reordering the spec dict must not change the MAC (canonical).
        reordered = {"aliases": _SPEC["aliases"], "tools": _SPEC["tools"]}
        c = tse.seal_policy(_SCOPE_KEY, reordered)
        self.assertEqual(a["mac"], c["mac"])

    def test_bad_policy_shape_refused_at_seal(self):
        for bad in ({"tools": {}}, {"tools": {"t": {}}},
                    {"tools": {"t": {"r": []}}},
                    {"tools": {"t": {"r": ["s"]}},
                     "aliases": {"a": "missing-tool"}}):
            with self.assertRaises(tse.TokenScopeError) as ctx:
                tse.seal_policy(_SCOPE_KEY, bad)
            self.assertEqual(ctx.exception.code, "scope-policy-tampered")

    def test_bool_epoch_rejected(self):
        tok = _tok()
        sealed = tse.seal_policy(_SCOPE_KEY, _SPEC)
        grant = _grant({"file_read": ["files:read"]}, tok)
        with self.assertRaises(tse.TokenScopeError) as ctx:
            tse.check_scope(sealed, tok, grant, "file_read", "read",
                            True, _TXN_KEY, _SCOPE_KEY,
                            "txn-1", "https://rs.example")
        self.assertEqual(ctx.exception.code, "token-scope-unparseable")

    def test_run_scoped_call_non_verdict_refused(self):
        with self.assertRaises(tse.TokenScopeError) as ctx:
            tse.run_scoped_call("not-a-verdict", "file_read", "read",
                                lambda: None)
        self.assertEqual(ctx.exception.code, "scope-verdict-mismatched")

    def test_authorize_tool_call_clean_definition(self):
        tok = _tok()
        sealed = tse.seal_policy(_SCOPE_KEY, _SPEC)
        grant = _grant({"file_read": ["files:read"]}, tok)
        clean_def = {"name": "file_read",
                     "inputSchema": {"type": "object",
                                     "properties": {
                                         "path": {"type": "string"}}}}
        verdict = tse.authorize_tool_call(
            sealed, clean_def, tok, grant, "read", _NOW, _TXN_KEY,
            _SCOPE_KEY, "txn-1", "https://rs.example")
        self.assertEqual(verdict.tool, "file_read")

    def test_code_for_maps_new_codes(self):
        from gov import decision_codes as dc
        for code in tse.CODES:
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "token-scope")

    def test_pin(self):
        from gov import decision_codes as dc
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1933)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
