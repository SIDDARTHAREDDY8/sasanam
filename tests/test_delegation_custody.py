"""Unit tests for the F249 custody-splice closure (wave-267).

`DelegationVerifier.verify` must refuse any chain where hop i>0 has
``issuer != chain[i-1].audience`` with the machine code
``delegation-custody-splice``. Legitimate chains (issuer == parent
audience at every hop) must still verify.

Pin is lane-local (1222 base + 1 delegation-custody-splice = 1223);
the wave merge coordinator repoints the rest of the tree.
"""

import hashlib
import unittest

from gov import delegation_chain as dc
from gov import decision_codes as dcd
from gov import ed25519

TAXONOMY_PIN = 2106 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-292 lane 3: pin 1715 -> 1719 (+4 delegation-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).



NOW = 4000000000.0


def _seed(label):
    return hashlib.sha256(b"custody-" + label.encode()).digest()


def _pub(label):
    return ed25519.publickey(_seed(label)).hex()


_READ = [{"with": "fs:/docs", "can": ["read"]}]
_RWX = [{"with": "fs:/docs", "can": ["read", "write", "delete"]}]
_ALL = [{"with": "fs:/", "can": ["*"]}]


def _root(label_r, label_a, caps, nonce):
    return dc.delegate(
        _seed(label_r), None,
        {"audience": _pub(label_a), "capabilities": caps,
         "not_before": NOW - 100, "not_after": NOW + 3600,
         "ttl": 3700, "parent": None, "nonce": nonce})


def _hop(label_i, held, label_a, caps, parent, nonce):
    return dc.delegate(
        _seed(label_i), held,
        {"audience": _pub(label_a), "capabilities": caps,
         "not_before": NOW - 100, "not_after": NOW + 3600,
         "ttl": 3700, "parent": parent, "nonce": nonce})


_ACTION = {"with": "fs:/docs", "can": "read"}


class TestCustodySplice(unittest.TestCase):
    def test_splice_unrelated_issuer_refused(self):
        root = _root("R", "A", _READ, "n-root")
        splice = _hop("M", _ALL, "X", _READ, root, "n-splice")
        self.assertNotEqual(splice["delegation"]["issuer"],
                            root["delegation"]["audience"])
        v = dc.DelegationVerifier([_pub("R")])
        with self.assertRaises(dc.DelegationCustodySplice) as ctx:
            v.verify([root, splice], _ACTION, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-custody-splice")

    def test_splice_narrower_caps_still_refused(self):
        root = _root("R", "A", _RWX, "n-root")
        splice = _hop("M", _ALL, "X", _READ, root, "n-narrow")
        v = dc.DelegationVerifier([_pub("R")])
        with self.assertRaises(dc.DelegationCustodySplice):
            v.verify([root, splice], _ACTION, now=NOW)

    def test_splice_at_middle_hop_refused(self):
        root = _root("R", "A", _READ, "n-root")
        hop = _hop("A", _READ, "B", _READ, root, "n-hop")
        splice = _hop("M", _ALL, "X", _READ, hop, "n-mid")
        v = dc.DelegationVerifier([_pub("R")])
        with self.assertRaises(dc.DelegationCustodySplice):
            v.verify([root, hop, splice], _ACTION, now=NOW)

    def test_custody_refusal_is_delegation_error(self):
        self.assertTrue(
            issubclass(dc.DelegationCustodySplice, dc.DelegationError))

    def test_custody_fires_before_signature(self):
        # Documented fixed order: parent digest -> custody binding
        # -> signature. A spliced hop with a tampered signature is
        # refused as a custody splice, not as a signature failure.
        root = _root("R", "A", _READ, "n-root")
        splice = _hop("M", _ALL, "X", _READ, root, "n-tamper")
        bad = dict(splice)
        bad["signature"] = "ff" * 64
        v = dc.DelegationVerifier([_pub("R")])
        with self.assertRaises(dc.DelegationCustodySplice):
            v.verify([root, bad], _ACTION, now=NOW)

    def test_legit_chain_still_verifies(self):
        root = _root("R", "A", _READ, "n-root")
        hop = _hop("A", _READ, "B", _READ, root, "n-hop")
        v = dc.DelegationVerifier([_pub("R")], seed=_seed("v"))
        receipt = v.verify([root, hop], _ACTION, now=NOW)
        self.assertEqual(receipt["decision"], "ok")
        self.assertIsNotNone(receipt["signature"])

    def test_legit_deep_chain_still_verifies(self):
        root = _root("R", "A", _READ, "n-root")
        h1 = _hop("A", _READ, "B", _READ, root, "n-h1")
        h2 = _hop("B", _READ, "C", _READ, h1, "n-h2")
        v = dc.DelegationVerifier([_pub("R")])
        receipt = v.verify([root, h1, h2], _ACTION, now=NOW)
        self.assertEqual(receipt["decision"], "ok")

    def test_single_root_still_verifies(self):
        root = _root("R", "A", _READ, "n-root")
        v = dc.DelegationVerifier([_pub("R")])
        v.verify([root], _ACTION, now=NOW)


class TestCustodyTaxonomy(unittest.TestCase):
    def test_code_in_taxonomy(self):
        rec = dcd.TAXONOMY["delegation-custody-splice"]
        self.assertEqual(rec["domain"], "delegation")
        self.assertEqual(rec["severity"], "high")

    def test_pin(self):
        self.assertEqual(len(dcd.TAXONOMY), TAXONOMY_PIN)

    def test_code_literal_unique(self):
        import os
        import re
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "gov",
                               "decision_codes.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        lits = re.findall(r'"code":\s*[\'"]([^\'"]+)[\'"]', src)
        self.assertEqual(len(lits), TAXONOMY_PIN)
        self.assertEqual(len(set(lits)), len(lits))


if __name__ == "__main__":
    unittest.main()
