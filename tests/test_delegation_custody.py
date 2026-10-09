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

TAXONOMY_PIN = 2144  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


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
