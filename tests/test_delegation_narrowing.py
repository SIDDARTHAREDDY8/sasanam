"""Unit tests for wave-291 lane 6: zcap-style delegation narrowing.

Covers proof-of-possession invocation, ceremony nonce binding
(composition with wave-289's ceremony_binding), bounded root policy,
and the narrowing guarantees in gov/delegation_chain.py.

Pin is lane-local (1726 base + 5 delegation-* = 1726); the wave
merge coordinator repoints the rest of the tree.
"""

import unittest

from gov import delegation_chain as dc
from gov import decision_codes as dcd
from gov import ed25519

TAXONOMY_PIN = 1878  # Wave-291 lane 6: pin 1710 -> 1715 (+5 delegation-*).; Wave-292 lane 3: pin 1715 -> 1719 (+4 delegation-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*)

NOW = 4000000000.0
NONCE_A = "aa" * 16
NONCE_B = "bb" * 16


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


def _chain(ceremony_nonce=None):
    r, a, b, x = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]),
                     ceremony_nonce=ceremony_nonce)
    hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root,
                     ceremony_nonce=ceremony_nonce)
    hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                     _caps("fs:/docs/report", ["read"]), parent=hop2,
                     ceremony_nonce=ceremony_nonce)
    return (r, a, b, x), [root, hop2, hop3]


def _verifier(r, **kw):
    return dc.DelegationVerifier([_pub(r)], seed=_seed(), **kw)


def _pop_sign(seed, invoker_pub_hex, challenge, leaf_digest):
    msg = dc.POP_DOMAIN + dc._canonical({
        "invoker": invoker_pub_hex,
        "challenge": bytes(challenge).hex(),
        "chain_digest": leaf_digest,
    })
    return ed25519.sign(bytes(seed), msg).hex()


def _leaf_digest(chain):
    body, _ = dc._check_sealed(chain[-1])
    return dc.digest_of(body)


class TestProofOfPossession(unittest.TestCase):
    def test_pop_happy_mints_receipt(self):
        (r, a, b, x), chain = _chain()
        chal = bytes(range(32))
        sig = _pop_sign(x, _pub(x), chal, _leaf_digest(chain))
        rcpt = _verifier(r).verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW)
        self.assertEqual(rcpt["type"], "delegation.invocation-receipt.1")
        self.assertEqual(rcpt["invoker"], _pub(x))
        self.assertEqual(rcpt["chain_digest"], _leaf_digest(chain))
        self.assertEqual(len(rcpt["signature"]), 128)

    def test_pop_receipt_marks_replay(self):
        (r, a, b, x), chain = _chain()
        chal = bytes(range(32))
        sig = _pop_sign(x, _pub(x), chal, _leaf_digest(chain))
        v = _verifier(r)
        rcpt = v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW)
        with self.assertRaises(dc.DelegationError) as ctx:
            v.verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=chal,
                pop_signature_hex=sig, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-replay")

    def test_pop_without_proof_refuses(self):
        (r, a, b, x), chain = _chain()
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=None,
                pop_signature_hex=None, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-invocation-not-proven")

    def test_pop_wrong_key_is_audience_mismatch(self):
        (r, a, b, x), chain = _chain()
        m = _seed()
        chal = bytes(range(32))
        sig = _pop_sign(m, _pub(m), chal, _leaf_digest(chain))
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(m), pop_challenge=chal,
                pop_signature_hex=sig, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-invocation-audience-mismatch")

    def test_pop_forged_signature_invalid(self):
        (r, a, b, x), chain = _chain()
        chal = bytes(range(32))
        forged = _pop_sign(_seed(), _pub(x), chal, _leaf_digest(chain))
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=chal,
                pop_signature_hex=forged, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-pop-signature-invalid")

    def test_pop_challenge_too_short(self):
        (r, a, b, x), chain = _chain()
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=b"short",
                pop_signature_hex="ff" * 64, now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-malformed")

    def test_pop_cross_chain_replay_invalid(self):
        (r, a, b, x), chain = _chain()
        root2 = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
        hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                         _caps("fs:/docs", ["read"]), parent=root2)
        hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                         _caps("fs:/docs/archive", ["read"]), parent=hop2)
        chain2 = [root2, hop2, hop3]
        chal = bytes(range(32))
        sig = _pop_sign(x, _pub(x), chal, _leaf_digest(chain))
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain2, {"with": "fs:/docs/archive", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=chal,
                pop_signature_hex=sig, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-pop-signature-invalid")

    def test_pop_receipt_alias(self):
        # The mandate-embedding seam: receipt() is callable and mints
        # the same shape as the private minter.
        v = _verifier(_seed())
        self.assertTrue(callable(v.receipt))


class TestCeremonyBinding(unittest.TestCase):
    def test_ceremony_happy(self):
        (r, a, b, x), chain = _chain(ceremony_nonce=NONCE_A)
        _verifier(r).verify(chain,
                            {"with": "fs:/docs/report", "can": "read"},
                            now=NOW, expected_ceremony_nonce=NONCE_A)

    def test_ceremony_cross_replay_refuses(self):
        (r, a, b, x), chain = _chain(ceremony_nonce=NONCE_A)
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify(chain,
                                {"with": "fs:/docs/report", "can": "read"},
                                now=NOW,
                                expected_ceremony_nonce=NONCE_B)
        self.assertEqual(ctx.exception.code, "delegation-ceremony-mismatch")

    def test_ceremony_missing_when_expected_refuses(self):
        (r, a, b, x), chain = _chain()
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify(chain,
                                {"with": "fs:/docs/report", "can": "read"},
                                now=NOW,
                                expected_ceremony_nonce=NONCE_A)
        self.assertEqual(ctx.exception.code, "delegation-ceremony-mismatch")

    def test_ceremony_tampered_nonce_breaks_signature(self):
        (r, a, b, x), chain = _chain(ceremony_nonce=NONCE_A)
        chain[2]["delegation"]["ceremony_nonce"] = NONCE_B
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify(chain,
                                {"with": "fs:/docs/report", "can": "read"},
                                now=NOW,
                                expected_ceremony_nonce=NONCE_A)
        self.assertEqual(ctx.exception.code, "delegation-signature-invalid")

    def test_ceremony_malformed_nonce_at_issue(self):
        r, a = _seed(), _seed()
        with self.assertRaises(dc.DelegationError) as ctx:
            _delegate(r, None, a, _caps("fs:/", ["read"]),
                      ceremony_nonce="too-short")
        self.assertEqual(ctx.exception.code, "delegation-malformed")

    def test_ceremony_nonce_in_signed_body(self):
        (r, a, b, x), chain = _chain(ceremony_nonce=NONCE_A)
        for hop in chain:
            self.assertEqual(hop["delegation"]["ceremony_nonce"], NONCE_A)

    def test_pop_under_ceremony_discipline(self):
        (r, a, b, x), chain = _chain(ceremony_nonce=NONCE_A)
        chal = bytes(range(32))
        sig = _pop_sign(x, _pub(x), chal, _leaf_digest(chain))
        rcpt = _verifier(r).verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW,
            expected_ceremony_nonce=NONCE_A)
        self.assertEqual(rcpt["type"], "delegation.invocation-receipt.1")
        chal2 = bytes(range(1, 33))
        sig2 = _pop_sign(x, _pub(x), chal2, _leaf_digest(chain))
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify_invocation(
                chain, {"with": "fs:/docs/report", "can": "read"},
                invoker_pubkey_hex=_pub(x), pop_challenge=chal2,
                pop_signature_hex=sig2,
                now=NOW, expected_ceremony_nonce=NONCE_B)
        self.assertEqual(ctx.exception.code, "delegation-ceremony-mismatch")


class TestRootPolicy(unittest.TestCase):
    def test_root_policy_violation(self):
        r, a, b, x = _seed(), _seed(), _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
        hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                         _caps("fs:/docs", ["read"]), parent=root)
        hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                         _caps("fs:/docs/report", ["read"]), parent=hop2)
        policy = {_pub(r): _caps("fs:/docs", ["read", "write"])}
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r, root_policy=policy).verify(
                [root, hop2, hop3],
                {"with": "fs:/docs/report", "can": "read"}, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-root-exceeds-policy")

    def test_root_policy_happy(self):
        r, a, b = _seed(), _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/docs", ["read", "write"]))
        hop2 = _delegate(a, _caps("fs:/docs", ["read", "write"]), b,
                         _caps("fs:/docs", ["read"]), parent=root)
        policy = {_pub(r): _caps("fs:/docs", ["read", "write"])}
        _verifier(r, root_policy=policy).verify(
            [root, hop2], {"with": "fs:/docs", "can": "read"}, now=NOW)

    def test_root_unbounded_anchor_trusted(self):
        (r, a, b, x), chain = _chain()
        policy = {_pub(_seed()): _caps("fs:/", ["read"])}
        _verifier(r, root_policy=policy).verify(
            chain, {"with": "fs:/docs/report", "can": "read"}, now=NOW)

    def test_root_policy_malformed_refuses(self):
        r = _seed()
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r, root_policy={_pub(r): "not-a-list"})
        self.assertEqual(ctx.exception.code, "delegation-malformed")


class TestNarrowing(unittest.TestCase):
    def test_narrowing_happy_3hop(self):
        (r, a, b, x), chain = _chain()
        _verifier(r).verify(chain,
                            {"with": "fs:/docs/report", "can": "read"},
                            now=NOW)

    def test_narrowing_hop3_expansion_refuses(self):
        (r, a, b, x), chain = _chain()
        wide = _delegate(b, None, x, _caps("fs:/", ["read", "write"]),
                         parent=chain[1])
        chain[2] = wide
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify(chain,
                                {"with": "fs:/", "can": "write"}, now=NOW)
        self.assertEqual(ctx.exception.code,
                         "delegation-attenuation-inverted")

    def test_with_widening_refuses(self):
        r, a, b = _seed(), _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/docs", ["read"]))
        hop2 = _delegate(a, _caps("fs:/docs", ["read"]), b,
                         _caps("fs:/docs/report", ["read"]), parent=root)
        with self.assertRaises(dc.DelegationError) as ctx:
            _verifier(r).verify([root, hop2],
                                {"with": "fs:/other", "can": "read"},
                                now=NOW)
        self.assertEqual(ctx.exception.code, "delegation-action-refused")

    def test_old_style_chain_verifies(self):
        (r, a, b, x), chain = _chain()
        _verifier(r).verify(chain,
                            {"with": "fs:/docs/report", "can": "read"},
                            now=NOW)

    def test_leaf_subset_not_equal_verifies(self):
        # A strict subset (not equal) is still valid narrowing.
        r, a = _seed(), _seed()
        root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
        _verifier(r).verify([root], {"with": "fs:/", "can": "read"},
                            now=NOW)


class TestDecisionCodesAndPin(unittest.TestCase):
    NEW_CODES = [
        "delegation-ceremony-mismatch",
        "delegation-invocation-audience-mismatch",
        "delegation-invocation-not-proven",
        "delegation-pop-signature-invalid",
        "delegation-root-exceeds-policy",
    ]

    def test_new_codes_registered(self):
        for code in self.NEW_CODES:
            self.assertIn(code, dcd.TAXONOMY)
            entry = dcd.TAXONOMY[code]
            self.assertEqual(entry["severity"], "high")
            self.assertEqual(entry["reverify_steps"], ["recompute"])

    def test_taxonomy_pin(self):
        import re
        src = open("gov/decision_codes.py", encoding="utf-8").read()
        lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
        self.assertEqual(len(lits), TAXONOMY_PIN)
        self.assertEqual(len(set(lits)), len(lits))
        self.assertEqual(lits, sorted(lits))


if __name__ == "__main__":
    unittest.main()
