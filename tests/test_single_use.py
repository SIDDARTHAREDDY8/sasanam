#!/usr/bin/env python3
"""Unit tests for gov/single_use.py (wave-226 lane C).

Independent spec-vector literals: expected refusal codes are asserted
from the task spec, not recomputed from the implementation.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import single_use  # noqa: E402


def _d(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


class TestIssue(unittest.TestCase):
    def test_issue_returns_bound_record(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("a1"), "issuer-x", "n-a1")
        self.assertEqual(att["v"], 1)
        self.assertEqual(att["attestation_digest"], _d("a1"))
        self.assertEqual(att["issuer"], "issuer-x")
        self.assertEqual(att["nonce"], "n-a1")
        self.assertEqual(len(att["jti"]), 64)
        # jti is deterministic over (digest, issuer, nonce)
        again = single_use.SingleUseRegistry().issue(
            _d("a1"), "issuer-x", "n-a1")
        self.assertEqual(att["jti"], again["jti"])

    def test_issue_distinct_nonces_distinct_jtis(self):
        reg = single_use.SingleUseRegistry()
        a = reg.issue(_d("a2"), "issuer-x", "n-a2a")
        b = reg.issue(_d("a2"), "issuer-x", "n-a2b")
        self.assertNotEqual(a["jti"], b["jti"])

    def test_issue_rejects_bad_digest(self):
        reg = single_use.SingleUseRegistry()
        with self.assertRaises(ValueError):
            reg.issue("not-a-digest", "issuer-x", "n-a3")

    def test_issue_rejects_empty_issuer_and_nonce(self):
        reg = single_use.SingleUseRegistry()
        with self.assertRaises(ValueError):
            reg.issue(_d("a4"), "", "n-a4")
        with self.assertRaises(ValueError):
            reg.issue(_d("a4"), "issuer-x", "")

    def test_nonce_reuse_same_digest_refuses(self):
        reg = single_use.SingleUseRegistry()
        reg.issue(_d("a5"), "issuer-x", "n-a5")
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.issue(_d("a5"), "issuer-x", "n-a5")
        self.assertEqual(ctx.exception.code, "single-use-replay-refused")

    def test_nonce_reuse_different_digest_refuses(self):
        reg = single_use.SingleUseRegistry()
        reg.issue(_d("a6"), "issuer-x", "n-a6")
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.issue(_d("different"), "issuer-x", "n-a6")
        self.assertEqual(ctx.exception.code, "single-use-replay-refused")

    def test_issuer_pubkey_digest_must_be_exact(self):
        reg = single_use.SingleUseRegistry()
        with self.assertRaises(ValueError):
            reg.issue(_d("a7"), "issuer-x", "n-a7",
                      issuer_pubkey_digest="short")

    def test_revocation_registry_must_duck_type(self):
        with self.assertRaises(ValueError):
            single_use.SingleUseRegistry(revocation_registry=object())


class TestConsume(unittest.TestCase):
    def test_consume_once_ok(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("c1"), "issuer-x", "n-c1")
        ev = reg.consume(att)
        self.assertEqual(ev["kind"], "single-use-attestation")
        self.assertEqual(ev["jti"], att["jti"])
        self.assertTrue(reg.is_consumed(att["jti"]))
        self.assertFalse(reg.is_consumed("f" * 64))

    def test_consume_twice_refuses_replay(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("c2"), "issuer-x", "n-c2")
        reg.consume(att)
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.consume(att)
        self.assertEqual(ctx.exception.code, "single-use-replay-refused")

    def test_consume_foreign_wellformed_refuses_unknown(self):
        reg_a = single_use.SingleUseRegistry()
        reg_b = single_use.SingleUseRegistry()
        foreign = reg_b.issue(_d("c3"), "issuer-x", "n-c3")
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg_a.consume(foreign)
        self.assertEqual(ctx.exception.code, "single-use-unknown")

    def test_consume_tampered_refuses_malformed(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("c4"), "issuer-x", "n-c4")
        bad = dict(att, issuer="mallory")
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.consume(bad)
        self.assertEqual(ctx.exception.code, "single-use-malformed")

    def test_consume_non_record_refuses_malformed(self):
        reg = single_use.SingleUseRegistry()
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.consume({"not": "a record"})
        self.assertEqual(ctx.exception.code, "single-use-malformed")

    def test_revoked_issuer_refuses(self):
        from gov import revocation
        import os as _os
        seed = _os.urandom(32)
        rev = revocation.RevocationList()
        key_digest = _d("issuer-key")
        rev.revoke(key_digest, issuer_id="ca", seed=seed)
        reg = single_use.SingleUseRegistry(revocation_registry=rev)
        att = reg.issue(_d("c6"), "issuer-x", "n-c6",
                        issuer_pubkey_digest=key_digest)
        with self.assertRaises(single_use.SingleUseError) as ctx:
            reg.consume(att)
        self.assertEqual(ctx.exception.code, "single-use-issuer-revoked")
        # ...and the failed consume did not mark it consumed
        self.assertFalse(reg.is_consumed(att["jti"]))

    def test_active_issuer_consumes(self):
        from gov import revocation
        rev = revocation.RevocationList()
        reg = single_use.SingleUseRegistry(revocation_registry=rev)
        att = reg.issue(_d("c7"), "issuer-x", "n-c7",
                        issuer_pubkey_digest=_d("other-key"))
        ev = reg.consume(att)
        self.assertEqual(ev["kind"], "single-use-attestation")

    def test_no_revocation_registry_no_check(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("c8"), "issuer-x", "n-c8",
                        issuer_pubkey_digest=_d("key"))
        ev = reg.consume(att)
        self.assertTrue(reg.is_consumed(ev["jti"]))


class TestEvidenceVerifier(unittest.TestCase):
    def test_verifier_accepts_own_consumed(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("v1"), "issuer-x", "n-v1")
        item = reg.consume(att)
        self.assertTrue(reg.attestation_evidence_verifier()(item))

    def test_verifier_rejects_unconsumed(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("v2"), "issuer-x", "n-v2")
        item = {"kind": "single-use-attestation", "jti": att["jti"],
                "attestation_digest": att["attestation_digest"],
                "issuer": att["issuer"]}
        self.assertFalse(reg.attestation_evidence_verifier()(item))

    def test_verifier_rejects_wrong_kind_and_shape(self):
        reg = single_use.SingleUseRegistry()
        v = reg.attestation_evidence_verifier()
        self.assertFalse(v({"kind": "packet"}))
        self.assertFalse(v("not-a-dict"))


class TestEvidenceChecker(unittest.TestCase):
    def test_complete_passes(self):
        checker = single_use.EvidenceChecker({
            "a": lambda it: True,
            "b": lambda it: True,
        })
        out = checker.require_complete([{"kind": "a"}, {"kind": "b"}],
                                       ["a", "b"])
        self.assertEqual(out["kinds"], ["a", "b"])

    def test_missing_kind_incomplete(self):
        checker = single_use.EvidenceChecker({"a": lambda it: True})
        with self.assertRaises(single_use.EvidenceError) as ctx:
            checker.require_complete([{"kind": "a"}], ["a", "b"])
        self.assertEqual(ctx.exception.code, "evidence-incomplete")

    def test_unverifiable_item_is_not_incomplete(self):
        checker = single_use.EvidenceChecker(
            {"a": lambda it: it.get("ok") is True})
        with self.assertRaises(single_use.EvidenceError) as ctx:
            checker.require_complete([{"kind": "a", "ok": False}], ["a"])
        self.assertEqual(ctx.exception.code, "evidence-unverifiable-item")

    def test_no_verifier_is_unverifiable(self):
        checker = single_use.EvidenceChecker()
        with self.assertRaises(single_use.EvidenceError) as ctx:
            checker.require_complete([{"kind": "a"}], ["a"])
        self.assertEqual(ctx.exception.code, "evidence-unverifiable-item")

    def test_raising_verifier_fails_closed(self):
        def boom(item):
            raise RuntimeError("verifier blew up")

        checker = single_use.EvidenceChecker({"a": boom})
        with self.assertRaises(single_use.EvidenceError) as ctx:
            checker.require_complete([{"kind": "a"}], ["a"])
        self.assertEqual(ctx.exception.code, "evidence-unverifiable-item")

    def test_register_additive(self):
        checker = single_use.EvidenceChecker({"a": lambda it: True})
        checker.register("b", lambda it: True)
        out = checker.require_complete([{"kind": "a"}, {"kind": "b"}],
                                       ["a", "b"])
        self.assertEqual(set(out["kinds"]), {"a", "b"})

    def test_end_to_end_single_use_evidence(self):
        reg = single_use.SingleUseRegistry()
        att = reg.issue(_d("e1"), "issuer-x", "n-e1")
        item = reg.consume(att)
        checker = single_use.EvidenceChecker(
            {"single-use-attestation":
             reg.attestation_evidence_verifier()})
        out = checker.require_complete([item], ["single-use-attestation"])
        self.assertEqual(out["kinds"], ["single-use-attestation"])


if __name__ == "__main__":
    unittest.main()
