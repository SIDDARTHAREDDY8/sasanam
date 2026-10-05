"""Unit tests for gov/delegation_chain.py (wave-265).

UCAN-style attenuation-only signed delegation chains: issue-time
widening refusal, hop-by-hop verification (type -> structure ->
parent digest -> signature -> root trust -> attenuation -> time ->
action -> replay), and signed invocation receipts.

Pin is lane-local (1177 base + 9 delegation-* = 1186); the wave
merge coordinator repoints the rest of the tree.
"""

import unittest

from gov import delegation_chain as dc
from gov import decision_codes as dcd
from gov import ed25519

TAXONOMY_PIN = 2077 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-292 lane 3: pin 1715 -> 1719 (+4 delegation-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)



NOW = 4000000000.0


def _seed():
    return ed25519.generate_seed()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _caps(with_, cans):
    return [{"with": with_, "can": list(cans)}]


def _delegate(seed, held, audience, caps, parent=None, **kw):
    req = {"audience": _pub(audience),
           "capabilities": caps,
           "not_before": NOW - 100.0,
           "not_after": NOW + 3600.0,
           "ttl": 3700,
           "parent": parent}
    req.update(kw)
    return dc.delegate(seed, held, req)


class TestIssue(unittest.TestCase):
    def test_root_grant_from_own_authority(self):
        r, a = _seed(), _seed()
        sealed = _delegate(r, None, a, _caps("fs:/", ["read"]))
        body = sealed["delegation"]
        self.assertEqual(body["type"], "delegation.ucan.1")
        self.assertIsNone(body["parent_digest"])
        self.assertEqual(body["issuer"], _pub(r))

    def test_issue_widening_refused(self):
        r, a = _seed(), _seed()
        with self.assertRaises(dc.DelegationError) as ctx:
            _delegate(r, _caps("fs:/docs", ["read"]), a,
                      _caps("fs:/", ["read"]))
        self.assertEqual(ctx.exception.code, "delegation-would-widen")

    def test_issue_narrowing_accepted(self):
        r, a = _seed(), _seed()
        sealed = _delegate(r, _caps("fs:/", ["read", "write"]), a,
                           _caps("fs:/docs", ["read"]))
        self.assertEqual(sealed["delegation"]["capabilities"],
                         _caps("fs:/docs", ["read"]))

    def test_issue_malformed_window(self):
        r, a = _seed(), _seed()
        with self.assertRaises(dc.DelegationError) as ctx:
            _delegate(r, None, a, _caps("fs:/", ["read"]),
                      not_before=NOW + 10.0, not_after=NOW - 10.0)
        self.assertEqual(ctx.exception.code, "delegation-malformed")

    def test_issue_malformed_capability(self):
        r, a = _seed(), _seed()
        with self.assertRaises(dc.DelegationError) as ctx:
            _delegate(r, None, a, [{"with": "", "can": ["read"]}])
        self.assertEqual(ctx.exception.code, "delegation-malformed")

    def test_sealed_signature_verifies(self):
        r, a = _seed(), _seed()
        sealed = _delegate(r, None, a, _caps("fs:/", ["read"]))
        body = sealed["delegation"]
        import json
        canon = json.dumps(body, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
        self.assertIs(
            ed25519.verify(bytes.fromhex(body["issuer"]),
                           dc.SIGN_DOMAIN + canon,
                           bytes.fromhex(sealed["signature"])),
            True)


class TestVerify(unittest.TestCase):
    def _chain(self):
        r, a, b, c = _seed(), _seed(), _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
        mid = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                        _caps("fs:/docs", ["read"]), parent=root)
        leaf = _delegate(b, _caps("fs:/docs", ["read"]), c,
                         _caps("fs:/docs", ["read"]), parent=mid)
        return r, [root, mid, leaf]

    def test_end_to_end_receipt(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        receipt = v.verify(chain,
                           {"with": "fs:/docs/a.txt", "can": "read"},
                           now=NOW)
        self.assertEqual(receipt["decision"], "ok")
        self.assertEqual(receipt["type"], "delegation.receipt.1")
        self.assertIsNotNone(receipt["signature"])

    def test_wildcard_can(self):
        r, a = _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/", ["*"]))
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        receipt = v.verify(
            [root], {"with": "fs:/x", "can": "destroy"}, now=NOW)
        self.assertEqual(receipt["decision"], "ok")

    def test_action_outside_leaf_scope(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify(chain, {"with": "fs:/etc/passwd", "can": "read"},
                     now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-action-refused")

    def test_action_outside_leaf_can(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify(chain, {"with": "fs:/docs/a.txt", "can": "write"},
                     now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-action-refused")

    def test_replay_refused(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        action = {"with": "fs:/docs/a.txt", "can": "read"}
        v.verify(chain, action, now=NOW)
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify(chain, action, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-replay")

    def test_replay_is_per_action(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        v.verify(chain, {"with": "fs:/docs/a.txt", "can": "read"},
                 now=NOW)
        receipt = v.verify(
            chain, {"with": "fs:/docs/b.txt", "can": "read"}, now=NOW)
        self.assertEqual(receipt["decision"], "ok")

    def test_empty_chain_malformed(self):
        v = dc.DelegationVerifier([_pub(_seed())], seed=_seed())
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify([], {"with": "fs:/x", "can": "read"}, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-malformed")

    def test_empty_anchors_refuse_all(self):
        r, chain = self._chain()
        v = dc.DelegationVerifier([], seed=_seed())
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify(chain, {"with": "fs:/docs/a.txt", "can": "read"},
                     now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-root-untrusted")


class TestTaxonomyPin(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(dcd.TAXONOMY), TAXONOMY_PIN)

    def test_new_codes_present(self):
        for code in ("delegation-malformed",
                     "delegation-version-mismatch",
                     "delegation-signature-invalid",
                     "delegation-parent-mismatch",
                     "delegation-root-untrusted",
                     "delegation-attenuation-inverted",
                     "delegation-action-refused",
                     "delegation-replay",
                     "delegation-expired"):
            self.assertIn(code, dcd.TAXONOMY)

    def test_module_codes_mapped(self):
        seen = set()
        for name in dir(dc):
            obj = getattr(dc, name)
            if isinstance(obj, type) and\
                    issubclass(obj, dc.DelegationError):
                seen.add(obj.code)
        unmapped = [c for c in seen if c not in dcd.TAXONOMY]
        self.assertEqual(unmapped, [])


if __name__ == "__main__":
    unittest.main()
