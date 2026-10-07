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

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


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
