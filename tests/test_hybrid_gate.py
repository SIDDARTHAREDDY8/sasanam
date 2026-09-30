#!/usr/bin/env python3
"""Unit tests for gov/hybrid_gate.py: hybrid family gate + verifier-pinned
suite acceptance.

Independent spec-vector literals (no calls into the module under test
to derive expectations): refusal codes are asserted as literal
strings, digests as literals recomputed from stdlib hashlib over
fixed test keys.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import alg_registry as alg  # noqa: E402
from gov import hybrid_gate as hg  # noqa: E402
from gov import key_identity as ki  # noqa: E402

ED = "ed25519-rfc8032"

# Fixed test keys (arbitrary non-secret vectors; secrets are generated
# fresh per test, these bytes are only identity fixtures).
PUB_C = b"wave228-test-pubkey-classical-01"
PUB_Q1 = b"wave228-test-pubkey-pqc-one--02"
PUB_Q2 = b"wave228-test-pubkey-pqc-two--03"
DIGEST_C_SHA256 = hashlib.sha256(PUB_C).hexdigest()
MSG = b"unit test message for hybrid gate"

POLICY_DICT = {
    "v": 1,
    "accepted_suites": {
        "hyb-suite": {"declared_entries": [
            {"key_id": "hyb", "key_type": ED, "role": "pqc"}]},
        "classical-suite": {"declared_entries": [
            {"key_id": "c1", "key_type": ED, "role": "classical"}]},
    },
}


def _code_of(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None)
    return None


def _fresh_ed():
    reg = alg.default_registry()
    seed, pub = reg.keygen(ED)
    return reg, seed, pub


def _world():
    """Fresh registry + policy + gate: classical leaf c1, pqc leaves
    q1/q2, hybrid record 'hyb' over (q1, q2)."""
    reg, seed_c1, pub_c1 = _fresh_ed()
    seed_q1, pub_q1 = reg.keygen(ED)
    seed_q2, pub_q2 = reg.keygen(ED)
    kreg = ki.KeyRegistry()
    for kid, pub in (("c1", pub_c1), ("q1", pub_q1), ("q2", pub_q2)):
        kreg.register(ki.RegisteredKey.build(kid, ED, "sha256", pub))
    kreg.register(ki.RegisteredKey.build(
        "hyb", ED, "sha256", pub_q1, hybrid_of=("q1", "q2")))
    policy = hg.FamilyPolicy(POLICY_DICT)
    gate = hg.FamilyGate(policy, kreg)
    return reg, gate, policy, {
        "c1": (seed_c1, pub_c1), "q1": (seed_q1, pub_q1),
        "q2": (seed_q2, pub_q2)}


def _hyb_sigs(reg, keys, msg, bad_leg=None):
    seed_q1, pub_q1 = keys["q1"]
    seed_q2, pub_q2 = keys["q2"]
    return {"hyb": {
        "sig_a": b"\x00" * 64 if bad_leg == "a"
        else reg.sign(ED, msg, seed_q1),
        "pubkey_a": pub_q1,
        "sig_b": b"\x00" * 64 if bad_leg == "b"
        else reg.sign(ED, msg, seed_q2),
        "pubkey_b": pub_q2}}


def _leaf_sigs(reg, seed, pub, msg):
    return {"c1": {"signature": reg.sign(ED, msg, seed), "pubkey": pub}}


class PolicyPinTests(unittest.TestCase):
    def test_policy_digest_is_sha256_of_canonical_suites(self):
        # Independent spec-vector literal: the pin is the SHA-256 of the
        # JCS-style canonical encoding of accepted_suites (sorted keys,
        # no whitespace). Written out by hand, not via the module.
        policy = hg.FamilyPolicy(POLICY_DICT)
        canonical = ('{"classical-suite":{"declared_entries":'
                     '[{"key_id":"c1","key_type":"ed25519-rfc8032",'
                     '"role":"classical"}]},"hyb-suite":'
                     '{"declared_entries":[{"key_id":"hyb","key_type":'
                     '"ed25519-rfc8032","role":"pqc"}]}}')
        expect = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.assertEqual(policy.digest(), expect)

    def test_policy_suites_pinned(self):
        policy = hg.FamilyPolicy(POLICY_DICT)
        self.assertEqual(set(policy.suites()),
                         {"hyb-suite", "classical-suite"})

    def test_policy_rejects_empty_suites(self):
        self.assertEqual(
            _code_of(lambda: hg.FamilyPolicy(
                {"v": 1, "accepted_suites": {}})),
            "hybrid-gate-malformed")

    def test_policy_rejects_bad_role(self):
        bad = {"v": 1, "accepted_suites": {
            "s": {"declared_entries": [
                {"key_id": "k", "key_type": ED, "role": "quantum"}]}}}
        self.assertEqual(_code_of(lambda: hg.FamilyPolicy(bad)),
                         "hybrid-gate-malformed")

    def test_policy_rejects_duplicate_key_id(self):
        bad = {"v": 1, "accepted_suites": {
            "s": {"declared_entries": [
                {"key_id": "k", "key_type": ED, "role": "classical"},
                {"key_id": "k", "key_type": ED, "role": "pqc"}]}}}
        self.assertEqual(_code_of(lambda: hg.FamilyPolicy(bad)),
                         "hybrid-gate-malformed")


class AdmitTests(unittest.TestCase):
    def test_hybrid_suite_admits(self):
        reg, gate, policy, keys = _world()
        rec = gate.admit("hyb-suite", [{"key_id": "hyb", "key_type": ED}],
                         MSG, _hyb_sigs(reg, keys, MSG),
                         admitted_at=1700000000.0)
        self.assertEqual(rec["suite_id"], "hyb-suite")
        self.assertEqual(rec["policy_digest"], policy.digest())
        self.assertEqual(rec["message_digest"],
                         hashlib.sha256(MSG).hexdigest())
        self.assertEqual(rec["admitted_at"], 1700000000.0)
        self.assertEqual([e["key_id"] for e in rec["admitted_entries"]],
                         ["hyb"])

    def test_classical_suite_admits(self):
        reg, gate, policy, keys = _world()
        seed_c1, pub_c1 = keys["c1"]
        rec = gate.admit("classical-suite",
                         [{"key_id": "c1", "key_type": ED}], MSG,
                         _leaf_sigs(reg, seed_c1, pub_c1, MSG),
                         admitted_at=1700000000.0)
        self.assertEqual(rec["suite_id"], "classical-suite")

    def test_unknown_suite_refused(self):
        reg, gate, policy, keys = _world()
        seed_c1, pub_c1 = keys["c1"]
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "token-chosen-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, _leaf_sigs(reg, seed_c1, pub_c1, MSG),
                admitted_at=1700000000.0)),
            "hybrid-suite-not-accepted")

    def test_undeclared_presented_key_refused(self):
        reg, gate, policy, keys = _world()
        seed_q1, pub_q1 = keys["q1"]
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite",
                [{"key_id": "q1", "key_type": ED}], MSG,
                {"q1": {"signature": reg.sign(ED, MSG, seed_q1),
                        "pubkey": pub_q1}},
                admitted_at=1700000000.0)),
            "hybrid-entry-mismatch")

    def test_failing_hybrid_leg_refused(self):
        reg, gate, policy, keys = _world()
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "hyb-suite", [{"key_id": "hyb", "key_type": ED}], MSG,
                _hyb_sigs(reg, keys, MSG, bad_leg="a"),
                admitted_at=1700000000.0)),
            "hybrid-leg-failed")

    def test_failing_leaf_signature_refused(self):
        reg, gate, policy, keys = _world()
        _seed_c1, pub_c1 = keys["c1"]
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, {"c1": {"signature": b"\x00" * 64,
                             "pubkey": pub_c1}},
                admitted_at=1700000000.0)),
            "hybrid-leg-failed")

    def test_wrong_pubkey_binding_refused(self):
        # Presenting a signature under a DIFFERENT key than the
        # registered pubkey_digest refuses hybrid-leg-invalid, not a
        # signature failure.
        reg, gate, policy, keys = _world()
        _seed_c1, _pub_c1 = keys["c1"]
        _reg2, impostor_seed, impostor_pub = _fresh_ed()
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, {"c1": {
                    "signature": reg.sign(ED, MSG, impostor_seed),
                    "pubkey": impostor_pub}},
                admitted_at=1700000000.0)),
            "hybrid-leg-invalid")

    def test_unregistered_key_refused(self):
        reg, gate, policy, keys = _world()
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, {"c1": {"signature": b"\x00" * 64,
                             "pubkey": b"unregistered-bytes"}},
                admitted_at=1700000000.0)),
            "hybrid-leg-invalid")  # pubkey digest does not bind

    def test_mac_tier_entry_refused(self):
        reg, gate, _policy, keys = _world()
        mac_key, _mac_pub = reg.keygen("hmac-sha256-mac")
        kreg = ki.KeyRegistry()
        kreg.register(ki.RegisteredKey.build(
            "m1", "hmac-sha256-mac", "sha256", mac_key))
        pol = hg.FamilyPolicy({"v": 1, "accepted_suites": {
            "mac-suite": {"declared_entries": [
                {"key_id": "m1", "key_type": "hmac-sha256-mac",
                 "role": "classical"}]}}})
        g = hg.FamilyGate(pol, kreg)
        self.assertEqual(
            _code_of(lambda: g.admit(
                "mac-suite",
                [{"key_id": "m1", "key_type": "hmac-sha256-mac"}],
                MSG, {"m1": {"signature": b"\x00" * 32,
                             "pubkey": mac_key}},
                admitted_at=1700000000.0)),
            "hybrid-leg-invalid")

    def test_revoked_key_refused(self):
        import gov.revocation as rev
        reg, _gate, policy, keys = _world()
        seed_c1, pub_c1 = keys["c1"]
        rlist = rev.RevocationList()
        rlist.revoke(hashlib.sha256(pub_c1).hexdigest(),
                     issuer_id="ca", seed=os.urandom(32))
        kreg = ki.KeyRegistry(revocation_registry=rlist)
        kreg.register(ki.RegisteredKey.build("c1", ED, "sha256", pub_c1))
        g = hg.FamilyGate(policy, kreg)
        self.assertEqual(
            _code_of(lambda: g.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, _leaf_sigs(reg, seed_c1, pub_c1, MSG),
                admitted_at=1700000000.0)),
            "key-identity-revoked")

    def test_bad_admitted_at_refused(self):
        reg, gate, policy, keys = _world()
        seed_c1, pub_c1 = keys["c1"]
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, _leaf_sigs(reg, seed_c1, pub_c1, MSG),
                admitted_at=float("nan"))),
            "hybrid-gate-malformed")

    def test_empty_presented_bundle_is_leg_failed(self):
        # A PRESENTED entry with empty signature material is a failing
        # leg (hybrid-leg-failed), not a missing entry: hybrid-incomplete
        # is reserved for material that never arrived.
        reg, gate, policy, keys = _world()
        _seed_c1, pub_c1 = keys["c1"]
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "classical-suite", [{"key_id": "c1", "key_type": ED}],
                MSG, {"c1": {"signature": b"", "pubkey": pub_c1}},
                admitted_at=1700000000.0)),
            "hybrid-leg-failed")

    def test_empty_hybrid_leg_is_leg_failed(self):
        reg, gate, policy, keys = _world()
        bad = _hyb_sigs(reg, keys, MSG)
        bad["hyb"]["sig_a"] = b""
        self.assertEqual(
            _code_of(lambda: gate.admit(
                "hyb-suite", [{"key_id": "hyb", "key_type": ED}], MSG, bad,
                admitted_at=1700000000.0)),
            "hybrid-leg-failed")

    def test_policy_rejects_non_v1(self):
        bad = dict(POLICY_DICT)
        bad["v"] = 2
        self.assertEqual(_code_of(lambda: hg.FamilyPolicy(bad)),
                         "hybrid-gate-malformed")

    def test_admission_not_authorization(self):
        reg, gate, policy, keys = _world()
        seed_c1, pub_c1 = keys["c1"]
        rec = gate.admit("classical-suite",
                         [{"key_id": "c1", "key_type": ED}], MSG,
                         _leaf_sigs(reg, seed_c1, pub_c1, MSG),
                         admitted_at=1700000000.0)
        self.assertEqual(_code_of(lambda: gate.deny_authority_use(rec)),
                         "hybrid-gate-not-authorization")

    def test_deny_authority_malformed_input(self):
        _reg, gate, _policy, _keys = _world()
        self.assertEqual(
            _code_of(lambda: gate.deny_authority_use({"nope": True})),
            "hybrid-gate-malformed")


if __name__ == "__main__":
    unittest.main()
