"""Unit tests for delegation decay with theft lineage (wave-292).

Tests the public seams of gov/delegation_chain.py: ttl-gated
issuance, per-hop decay, rotation/succession, and the verifier's
bounded retirement lineage. Complements
evals/w292_delegation_decay_probes.py (red-first battery).
"""

import hashlib
import unittest

from gov import delegation_chain as dc
from gov import ed25519

NOW = 1700000000.0
WINDOW = {"not_before": NOW - 100.0, "not_after": NOW + 3600.0}
ACTION = {"with": "fs:/docs/report", "can": "read"}


def _seed(label):
    return hashlib.sha256(b"ut-decay-" + label.encode()).digest()


def _pub(label):
    return ed25519.publickey(_seed(label)).hex()


def _caps(with_, cans):
    return [{"with": with_, "can": list(cans)}]


def _delegate(seed, held, audience_pub, caps, parent=None, ttl=3700,
              **kw):
    req = dict(WINDOW)
    req.update({"audience": audience_pub, "capabilities": caps,
                "not_before": NOW - 100.0,
                "not_after": NOW - 100.0 + ttl,
                "ttl": ttl, "parent": parent})
    req.update(kw)
    return dc.delegate(seed, held, req)


def _chain3():
    r, a, b, c = (_seed("r"), _seed("a"), _seed("b"), _seed("c"))
    root = _delegate(r, None, _pub("a"), _caps("fs:/", ["read", "write"]))
    mid = _delegate(a, _caps("fs:/", ["read", "write"]), _pub("b"),
                    _caps("fs:/", ["read", "write"]), parent=root)
    leaf = _delegate(b, _caps("fs:/", ["read", "write"]), _pub("c"),
                     _caps("fs:/docs", ["read"]), parent=mid)
    v = dc.DelegationVerifier([_pub("r")], seed=_seed("vseed"))
    return (r, a, b, c), [root, mid, leaf], v


def _rotate_leaf(keys, chain, v, **kw):
    r, a, b, c = keys
    root, mid, leaf = chain
    req = dict(WINDOW)
    req.update({"audience": _pub("c"), "ttl": 3700})
    req.update(kw)
    succ, succession = dc.rotate(_seed("b"), mid, leaf, req)
    v.register_succession(leaf, succ, succession)
    return succ, succession


class TestTtlIssuance(unittest.TestCase):
    def test_ttl_required(self):
        req = dict(WINDOW)
        req.update({"audience": _pub("a"),
                    "capabilities": _caps("fs:/", ["read"]),
                    "parent": None})
        with self.assertRaises(dc.DelegationMalformed):
            dc.delegate(_seed("r"), None, req)

    def test_ttl_zero_refused(self):
        with self.assertRaises(dc.DelegationMalformed):
            _delegate(_seed("r"), None, _pub("a"),
                      _caps("fs:/", ["read"]), ttl=0)

    def test_ttl_bool_refused(self):
        with self.assertRaises(dc.DelegationMalformed):
            _delegate(_seed("r"), None, _pub("a"),
                      _caps("fs:/", ["read"]), ttl=True)

    def test_ttl_excessive_refused(self):
        with self.assertRaises(dc.DelegationMalformed):
            _delegate(_seed("r"), None, _pub("a"),
                      _caps("fs:/", ["read"]), ttl=2 ** 40 + 1)

    def test_ttl_max_ok(self):
        sealed = _delegate(_seed("r"), None, _pub("a"),
                           _caps("fs:/", ["read"]), ttl=2 ** 40,
                           not_before=0.0,
                           not_after=float(2 ** 40))
        self.assertEqual(sealed["delegation"]["ttl_seconds"], 2 ** 40)

    def test_body_carries_decay_fields(self):
        sealed = _delegate(_seed("r"), None, _pub("a"),
                           _caps("fs:/", ["read"]))
        body = sealed["delegation"]
        self.assertEqual(body["issued_at"], NOW - 100.0)
        self.assertEqual(body["ttl_seconds"], 3700)
        self.assertEqual(body["generation"], 0)

    def test_explicit_issued_at(self):
        sealed = _delegate(_seed("r"), None, _pub("a"),
                           _caps("fs:/", ["read"]),
                           issued_at=NOW - 50.0,
                           not_before=NOW - 100.0,
                           not_after=NOW - 50.0 + 3700)
        self.assertEqual(sealed["delegation"]["issued_at"], NOW - 50.0)

    def test_window_ttl_disagreement_refused(self):
        with self.assertRaises(dc.DelegationMalformed):
            _delegate(_seed("r"), None, _pub("a"),
                      _caps("fs:/", ["read"]),
                      not_after=NOW + 99999.0)

    def test_issued_at_before_not_before_refused(self):
        with self.assertRaises(dc.DelegationMalformed):
            _delegate(_seed("r"), None, _pub("a"),
                      _caps("fs:/", ["read"]),
                      issued_at=NOW - 200.0)


class TestDecayVerification(unittest.TestCase):
    def test_expired_ttl_refused_coded(self):
        keys, chain, v = _chain3()
        with self.assertRaises(dc.DelegationExpired) as ctx:
            v.verify(chain, ACTION, now=NOW + 5000.0)
        self.assertEqual(ctx.exception.code, "delegation-expired")

    def test_valid_ttl_verifies(self):
        keys, chain, v = _chain3()
        receipt = v.verify(chain, ACTION, now=NOW)
        self.assertEqual(receipt["decision"], "ok")

    def test_legacy_record_refused_coded(self):
        keys, chain, v = _chain3()
        r = keys[0]
        sealed = _delegate(r, None, _pub("a"), _caps("fs:/", ["read"]))
        legacy_body = {k: val for k, val in sealed["delegation"].items()
                       if k not in ("issued_at", "ttl_seconds",
                                    "generation")}
        sig = ed25519.sign(
            r, dc.SIGN_DOMAIN + dc._canonical(legacy_body)).hex()
        with self.assertRaises(dc.DelegationExpired) as ctx:
            v.verify([{"delegation": legacy_body, "signature": sig}],
                     ACTION, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-expired")

    def test_tampered_ttl_breaks_signature(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        tampered = dict(leaf["delegation"])
        tampered["ttl_seconds"] = 999999
        with self.assertRaises(dc.DelegationError):
            v.verify([root, mid, {"delegation": tampered,
                                  "signature": leaf["signature"]}],
                     ACTION, now=NOW)


class TestRotation(unittest.TestCase):
    def test_rotate_mints_successor_and_succession(self):
        keys, chain, v = _chain3()
        r, a, b, c = keys
        root, mid, leaf = chain
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700})
        succ, succession = dc.rotate(_seed("b"), mid, leaf, req)
        sbody = succ["delegation"]
        self.assertEqual(sbody["generation"], 1)
        self.assertEqual(sbody["parent_digest"],
                         leaf["delegation"]["parent_digest"])
        self.assertEqual(sbody["issuer"], leaf["delegation"]["issuer"])
        self.assertEqual(
            succession["delegation"]["retired_digest"],
            dc.digest_of(leaf["delegation"]))
        self.assertEqual(
            succession["delegation"]["successor_digest"],
            dc.digest_of(sbody))

    def test_rotate_wrong_seed_refused(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700})
        with self.assertRaises(dc.DelegationMalformed):
            dc.rotate(_seed("a"), mid, leaf, req)

    def test_rotate_widening_refused(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700,
                    "capabilities": _caps("fs:/", ["read", "write"])})
        with self.assertRaises(dc.DelegationWouldWiden):
            dc.rotate(_seed("b"), mid, leaf, req)

    def test_rotate_narrowing_ok(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700,
                    "capabilities": _caps("fs:/docs", ["read"])})
        succ, succession = dc.rotate(_seed("b"), mid, leaf, req)
        self.assertEqual(succ["delegation"]["capabilities"],
                         _caps("fs:/docs", ["read"]))

    def test_successor_chain_verifies(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        receipt = v.verify([root, mid, succ], ACTION, now=NOW)
        self.assertEqual(receipt["decision"], "ok")

    def test_succession_forgery_refused(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700})
        succ, succession = dc.rotate(_seed("b"), mid, leaf, req)
        forged = dict(succession)
        forged_body = dict(succession["delegation"])
        forged["delegation"] = forged_body
        forged["signature"] = ed25519.sign(
            _seed("evil"),
            dc.SUCCESSION_DOMAIN + dc._canonical(forged_body)).hex()
        with self.assertRaises(dc.DelegationSignatureInvalid) as ctx:
            v.register_succession(leaf, succ, forged)
        self.assertEqual(ctx.exception.code,
                         "delegation-signature-invalid")

    def test_conflicting_succession_refused(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        req = dict(WINDOW)
        req.update({"audience": _pub("d"), "ttl": 3700,
                    "nonce": "other"})
        succ2, succession2 = dc.rotate(_seed("b"), mid, leaf, req)
        with self.assertRaises(dc.DelegationMalformed):
            v.register_succession(leaf, succ2, succession2)

    def test_idempotent_reregistration(self):
        keys, chain, v = _chain3()
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        digest = v.register_succession(leaf, succ, succession)
        self.assertEqual(digest, dc.digest_of(leaf["delegation"]))


class TestTheftLineage(unittest.TestCase):
    def test_recent_prev_tolerated_once_with_note(self):
        keys, chain, v = _chain3()
        succ, succession = _rotate_leaf(keys, chain, v)
        receipt = v.verify(chain, ACTION, now=NOW)
        self.assertEqual(receipt.get("lineage"), "recent-prev-tolerated")
        self.assertTrue(receipt.get("signature"))

    def test_second_presentation_is_revocation_event(self):
        keys, chain, v = _chain3()
        succ, succession = _rotate_leaf(keys, chain, v)
        v.verify(chain, ACTION, now=NOW)
        with self.assertRaises(dc.DelegationRetiredReuse) as ctx:
            v.verify(chain, ACTION, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-retired-reuse")

    def test_orphaned_branch_refused(self):
        keys, chain, v = _chain3()
        r, a, b, c = keys
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        fork = _delegate(_seed("c"), _caps("fs:/docs", ["read"]),
                         _pub("d"), _caps("fs:/docs", ["read"]),
                         parent=leaf)
        with self.assertRaises(dc.DelegationOrphanedBranch) as ctx:
            v.verify([root, mid, leaf, fork], ACTION, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-orphaned-branch")

    def test_stale_lineage_refused(self):
        keys, chain, v = _chain3()
        r, a, b, c = keys
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700})
        succ2, succession2 = dc.rotate(_seed("b"), mid, succ, req)
        v.register_succession(succ, succ2, succession2)
        with self.assertRaises(dc.DelegationStaleLineage) as ctx:
            v.verify(chain, ACTION, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-stale-lineage")

    def test_second_generation_tolerated_once(self):
        keys, chain, v = _chain3()
        r, a, b, c = keys
        root, mid, leaf = chain
        succ, succession = _rotate_leaf(keys, chain, v)
        req = dict(WINDOW)
        req.update({"audience": _pub("c"), "ttl": 3700})
        succ2, succession2 = dc.rotate(_seed("b"), mid, succ, req)
        v.register_succession(succ, succ2, succession2)
        receipt = v.verify([root, mid, succ], ACTION, now=NOW)
        self.assertEqual(receipt.get("lineage"), "recent-prev-tolerated")

    def test_lineage_overflow_failclosed(self):
        v = dc.DelegationVerifier([_pub("r")])
        prev = _delegate(_seed("r"), None, _pub("a"),
                         _caps("fs:/", ["read"]))
        for i in range(dc._LINEAGE_MAX):
            req = dict(WINDOW)
            req.update({"audience": _pub("a"), "ttl": 3700,
                        "nonce": "t%d" % i})
            succ, succession = dc.rotate(_seed("r"), None, prev, req)
            v.register_succession(prev, succ, succession)
            prev = succ
        req = dict(WINDOW)
        req.update({"audience": _pub("a"), "ttl": 3700,
                    "nonce": "overflow"})
        succ, succession = dc.rotate(_seed("r"), None, prev, req)
        with self.assertRaises(dc.DelegationLineageOverflow) as ctx:
            v.register_succession(prev, succ, succession)
        self.assertEqual(ctx.exception.code,
                         "delegation-lineage-overflow")
        # The lineage was NOT evicted: the oldest entry still works.
        self.assertEqual(len(v._retired), dc._LINEAGE_MAX)

    def test_unregistered_leaf_not_a_revocation(self):
        keys, chain, v = _chain3()
        # No succession registered: the leaf verifies normally.
        receipt = v.verify(chain, ACTION, now=NOW)
        self.assertNotIn("lineage", receipt)

    def test_verify_invocation_lineage_applies(self):
        keys, chain, v = _chain3()
        r, a, b, c = keys
        succ, succession = _rotate_leaf(keys, chain, v)
        challenge = b"invocation-lineage-01"
        leaf_digest = dc.digest_of(chain[-1]["delegation"])
        pop_sig = ed25519.sign(
            _seed("c"),
            dc.POP_DOMAIN + dc._canonical(
                {"invoker": _pub("c"), "challenge": challenge.hex(),
                 "chain_digest": leaf_digest})).hex()
        receipt = v.verify_invocation(
            chain, ACTION, invoker_pubkey_hex=_pub("c"),
            pop_challenge=challenge, pop_signature_hex=pop_sig, now=NOW)
        self.assertEqual(receipt.get("lineage"), "recent-prev-tolerated")


if __name__ == "__main__":
    unittest.main()
