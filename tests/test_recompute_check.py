"""Unit tests for gov/recompute_check.py (wave-241 lane B).

Vaara recomputability ADAPT (patterns only, prose re-derived; AGPL
upstream -- no code read/imported/vendored).
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import recompute_check as rc
from gov import ed25519
from gov import decision_codes as dc


def _seed():
    return ed25519.generate_seed()


def _decision(seed, decision="allow", nonce="cd" * 16):
    return rc.issue_decision_receipt(
        decision=decision, action="tool.invoke", action_digest="ab" * 32,
        nonce=nonce, key_id="key-1", seed=seed)


def _execution(seed, decision, outcome="ok"):
    return rc.issue_execution_receipt(
        backlink_digest=decision["receipt_digest"],
        backlink_nonce=decision["nonce"], evidence_digest="ef" * 32,
        outcome=outcome, nonce="01" * 16, key_id="key-2", seed=seed)


class CanonicalJsonTest(unittest.TestCase):
    def test_key_order_and_whitespace(self):
        out = rc.canonical_json({"b": 1, "a": [1, {"z": None, "y": True}]})
        self.assertEqual(out, b'{"a":[1,{"y":true,"z":null}],"b":1}')

    def test_string_escapes(self):
        out = rc.canonical_json({"k": 'a"b\\c\x01'})
        self.assertEqual(out, b'{"k":"a\\"b\\\\c\\u0001"}')

    def test_utf16_key_order(self):
        # U+00E9 (2 UTF-16 units) sorts after 'z' by code point too; the
        # astral-plane case is what differs from code-point order.
        out = rc.canonical_json({"é": 1, "z": 2})
        self.assertEqual(out, '{"z":2,"é":1}'.encode("utf-8"))

    def test_floats_refused(self):
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.canonical_json({"x": 1.5})
        self.assertEqual(ctx.exception.code, "recompute-malformed")

    def test_non_string_key_refused(self):
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.canonical_json({1: "x"})
        self.assertEqual(ctx.exception.code, "recompute-malformed")


class VerifyReceiptTest(unittest.TestCase):
    def test_valid_receipt_verifies(self):
        seed = _seed()
        receipt = _decision(seed)
        body = rc.verify_receipt(receipt, ed25519.publickey(seed))
        self.assertEqual(rc.canonical_json(
            {k: v for k, v in receipt.items()
             if k not in ("sig", "receipt_digest")}), body)

    def test_wrong_pubkey_refuses_signature(self):
        seed, other = _seed(), _seed()
        receipt = _decision(seed)
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.verify_receipt(receipt, ed25519.publickey(other))
        self.assertEqual(ctx.exception.code, "recompute-signature-invalid")

    def test_unknown_kind_refuses(self):
        seed = _seed()
        receipt = _decision(seed)
        receipt["kind"] = "mystery-receipt"
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.verify_receipt(receipt, ed25519.publickey(seed))
        self.assertEqual(ctx.exception.code, "recompute-malformed")


class CheckPairTest(unittest.TestCase):
    def test_allow_pair_accepts(self):
        d_seed, e_seed = _seed(), _seed()
        decision = _decision(d_seed)
        execution = _execution(e_seed, decision)
        verdict = rc.check_pair(decision, execution,
                                decision_pubkey=ed25519.publickey(d_seed),
                                execution_pubkey=ed25519.publickey(e_seed))
        self.assertEqual(verdict["verdict"], "accept")
        self.assertFalse(verdict["refusal_evidence"])

    def test_deny_pair_accepts(self):
        d_seed, e_seed = _seed(), _seed()
        decision = _decision(d_seed, "deny")
        execution = _execution(e_seed, decision, outcome="failed")
        verdict = rc.check_pair(decision, execution,
                                decision_pubkey=ed25519.publickey(d_seed),
                                execution_pubkey=ed25519.publickey(e_seed))
        self.assertEqual(verdict["verdict"], "accept")

    def test_backlink_nonce_mismatch_refuses(self):
        d_seed, e_seed = _seed(), _seed()
        decision = _decision(d_seed)
        execution = _execution(e_seed, decision)
        # Valid digest+signature, but the nonce names a different receipt.
        bad = rc.issue_execution_receipt(
            backlink_digest=decision["receipt_digest"],
            backlink_nonce="ff" * 16, evidence_digest="ef" * 32,
            outcome="ok", nonce="01" * 16, key_id="key-2", seed=e_seed)
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.check_pair(decision, bad,
                          decision_pubkey=ed25519.publickey(d_seed),
                          execution_pubkey=ed25519.publickey(e_seed))
        self.assertEqual(ctx.exception.code, "recompute-backlink-mismatch")

    def test_wrong_execution_key_refuses_signature(self):
        d_seed, e_seed, other = _seed(), _seed(), _seed()
        decision = _decision(d_seed)
        execution = _execution(e_seed, decision)
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.check_pair(decision, execution,
                          decision_pubkey=ed25519.publickey(d_seed),
                          execution_pubkey=ed25519.publickey(other))
        self.assertEqual(ctx.exception.code, "recompute-signature-invalid")


class AbsenceTest(unittest.TestCase):
    def test_in_coverage_accepts(self):
        verdict = rc.check_absence("tool.invoke", coverage=["tool.invoke"])
        self.assertTrue(verdict["absence_is_evidence"])

    def test_empty_coverage_refuses(self):
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.check_absence("tool.invoke", coverage=set())
        self.assertEqual(ctx.exception.code,
                         "recompute-absent-refusal-no-coverage")

    def test_blank_action_refuses_malformed(self):
        with self.assertRaises(rc.RecomputeRefusal) as ctx:
            rc.check_absence("", coverage={"tool.invoke"})
        self.assertEqual(ctx.exception.code, "recompute-malformed")


class TaxonomyTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in (rc.MALFORMED, rc.DIGEST_MISMATCH, rc.SIGNATURE_INVALID,
                     rc.BACKLINK_MISMATCH, rc.NO_EXECUTION_LINK,
                     rc.ABSENT_REFUSAL_NO_COVERAGE):
            entry = dc.code_for(code)
            self.assertEqual(entry["domain"], "recompute")

    def test_pin(self):
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
        self.assertEqual(len(dc.TAXONOMY), 1495)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
