"""Unit tests for gov/export_witness (wave-323 lane 3).

Contracts pinned here (public seams):
- build/verify round-trip on the good path;
- canonical bytes are deterministic;
- bundle_leaf_hash binds (digest, index) and is 32 bytes;
- proof builders produce proofs the verifier accepts;
- the small-carrier budget constant and refusal;
- every refusal carries an export-witness-* code (never a bare
  exception, never a soft False).
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import export_witness as EW
from gov import witness_policy as WP
from gov import witness_log as WL
from gov import checkpoint_note as CN
from gov.signing import Ed25519Signer

_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-export-witness-test/v1"
_BUNDLE = b"unit-test-bundle"
_DIGEST = hashlib.sha256(_BUNDLE).hexdigest()
_NLEAF = 8


def _signer(seed):
    return Ed25519Signer(seed)


def _op_vkey():
    s = _signer(_SEED_OP)
    return CN.vkey_string(
        "op", CN.derive_key_id("op", CN.SIG_TYPE_ED25519, s.public_key),
        CN.SIG_TYPE_ED25519, s.public_key)


def _wit_vkey(name, seed):
    s = _signer(seed)
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               s.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, s.public_key)


def _sealed():
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    body = {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": 1,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
        "threshold": 2,
        "log": {"name": "op", "vkey": _op_vkey()},
        "witnesses": [
            {"name": "w1", "vkey": _wit_vkey("w1", _SEED_W1),
             "operator": "w1-op", "contact": "w1@x.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
            {"name": "w2", "vkey": _wit_vkey("w2", _SEED_W2),
             "operator": "w2-op", "contact": "w2@x.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
        ],
        "policy_signers": [{"key_id": s.public_key.hex(),
                            "public_key": s.public_key.hex()}
                           for s in (p1, p2)],
        "policy_threshold": 2,
        "max_checkpoint_staleness_seconds": 10800,
    }
    return WP.seal_policy(body, [p1, p2])


def _anchor():
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    return {"policy_signers": [{"key_id": s.public_key.hex(),
                                "public_key": s.public_key.hex()}
                               for s in (p1, p2)],
            "policy_threshold": 2}


def _leaves():
    d = bytes.fromhex(_DIGEST)
    return [EW.bundle_leaf_hash(d, i) for i in range(_NLEAF)]


def _note(leaves):
    root = WL._calc_root(leaves)
    note = CN.emit_checkpoint(_ORIGIN, len(leaves), root, "op",
                              _SEED_OP)
    for w, seed in (("w1", _SEED_W1), ("w2", _SEED_W2)):
        line = CN.emit_cosignature_line(w, _signer(seed), _ORIGIN,
                                        len(leaves), root, _NOW - 100)
        note += (line + "\n").encode("utf-8")
    return note.decode("utf-8")


def _layer():
    leaves = _leaves()
    return EW.build_witness_layer(
        _DIGEST, checkpoint=_note(leaves), policy_doc=_sealed(),
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0)],
        now=_NOW)


class TestBundleLeafHash(unittest.TestCase):
    def test_is_32_bytes(self):
        h = EW.bundle_leaf_hash(bytes.fromhex(_DIGEST), 0)
        self.assertEqual(len(h), 32)

    def test_binds_digest_and_index(self):
        d = bytes.fromhex(_DIGEST)
        self.assertNotEqual(EW.bundle_leaf_hash(d, 0),
                            EW.bundle_leaf_hash(d, 1))
        other = hashlib.sha256(b"other").digest()
        self.assertNotEqual(EW.bundle_leaf_hash(d, 0),
                            EW.bundle_leaf_hash(other, 0))

    def test_deterministic(self):
        d = bytes.fromhex(_DIGEST)
        self.assertEqual(EW.bundle_leaf_hash(d, 3),
                         EW.bundle_leaf_hash(d, 3))

    def test_rejects_bad_inputs(self):
        with self.assertRaises(EW.ExportWitnessError) as ctx:
            EW.bundle_leaf_hash(b"short", 0)
        self.assertEqual(ctx.exception.code,
                         "export-witness-malformed")
        with self.assertRaises(EW.ExportWitnessError):
            EW.bundle_leaf_hash(bytes.fromhex(_DIGEST), -1)


class TestProofBuilders(unittest.TestCase):
    def test_consistency_proof_verifies(self):
        leaves = _leaves()
        proof = EW.make_consistency_proof(leaves, 3)
        root = WL._calc_root(leaves)
        # The verifier's internal check, exercised end to end via
        # verify_witness_layer in TestVerify; here assert shape.
        self.assertEqual(proof["from_size"], 3)
        self.assertEqual(proof["to_size"], _NLEAF)
        self.assertEqual(proof["from_root"],
                         WL._calc_root(leaves[:3]).hex())
        self.assertTrue(proof["nodes"])

    def test_inclusion_proof_verifies(self):
        leaves = _leaves()
        proof = EW.make_inclusion_proof(leaves, 5)
        self.assertEqual(proof["leaf_index"], 5)
        self.assertEqual(proof["tree_size"], _NLEAF)
        self.assertEqual(len(proof["path"]),
                         WL._audit_path_len(5, _NLEAF))

    def test_trivial_consistency_proof(self):
        # from_size == to_size: empty nodes, identical roots (the
        # builder and verifier must agree on the trivial case).
        leaves = _leaves()
        proof = EW.make_consistency_proof(leaves, _NLEAF)
        self.assertEqual(proof["nodes"], [])
        root = WL._calc_root(leaves)
        self.assertEqual(proof["from_root"], root.hex())
        # End to end: a layer with a trivial proof verifies.
        layer = EW.build_witness_layer(
            _DIGEST, checkpoint=_note(leaves), policy_doc=_sealed(),
            trust_anchor=_anchor(), consistency_proof=proof,
            inclusion_proofs=[EW.make_inclusion_proof(leaves, 0)],
            now=_NOW)
        out = EW.verify_witness_layer(layer, _anchor(),
                                      bundle_digest=_DIGEST, now=_NOW)
        self.assertEqual(out["bundle_digest"], _DIGEST)

    def test_builders_reject_bad_inputs(self):
        with self.assertRaises(EW.ExportWitnessError):
            EW.make_consistency_proof([], 0)
        with self.assertRaises(EW.ExportWitnessError):
            EW.make_inclusion_proof(_leaves(), 99)


class TestBuildVerify(unittest.TestCase):
    def test_round_trip(self):
        layer = _layer()
        out = EW.verify_witness_layer(layer, _anchor(),
                                      bundle_digest=_DIGEST, now=_NOW)
        self.assertEqual(out["bundle_digest"], _DIGEST)
        self.assertEqual(out["witnesses"], ["w1", "w2"])
        self.assertEqual(out["policy_version"], 1)

    def test_canonical_bytes_deterministic(self):
        a, b = _layer(), _layer()
        self.assertEqual(EW.canonical_layer_bytes(a),
                         EW.canonical_layer_bytes(b))

    def test_never_soft_false(self):
        # Every refusal is a coded ExportWitnessError, never False/None.
        with self.assertRaises(EW.ExportWitnessError) as ctx:
            EW.verify_witness_layer({}, _anchor(),
                                    bundle_digest=_DIGEST, now=_NOW)
        self.assertTrue(ctx.exception.code.startswith("export-witness-"))


class TestSmallCarrier(unittest.TestCase):
    def test_budget_constant(self):
        self.assertEqual(EW.SMALL_CARRIER_MAX_BYTES, 3072)

    def test_round_trip_under_budget(self):
        layer = _layer()
        blob = EW.encode_small_carrier(layer, exported_at=_NOW - 10)
        self.assertLess(len(blob), EW.SMALL_CARRIER_MAX_BYTES)
        out = EW.decode_small_carrier(blob, _sealed(), _anchor(),
                                      now=_NOW)
        self.assertEqual(out["policy_version"], 1)

    def test_oversize_refuses_coded(self):
        layer = _layer()
        # Pad the checkpoint with junk cosignature-looking lines is
        # not possible (they would fail parse); instead shrink the
        # budget via monkeypatching is dishonest -- assert the real
        # path: a layer whose checkpoint is large refuses.
        big_note = _note(_leaves()) + ("— pad " + "x" * 4000 + "\n")
        big = dict(layer)
        big["checkpoint"] = big_note
        with self.assertRaises(EW.ExportWitnessError) as ctx:
            EW.encode_small_carrier(big, exported_at=_NOW)
        self.assertEqual(ctx.exception.code,
                         "export-witness-carrier-oversize")


def _sealed_v3():
    """A sealed policy identical to _sealed() but with version=3."""
    p1, p2 = _signer(_SEED_P1), _signer(_SEED_P2)
    body = {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": 3,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
        "threshold": 2,
        "log": {"name": "op", "vkey": _op_vkey()},
        "witnesses": [
            {"name": "w1", "vkey": _wit_vkey("w1", _SEED_W1),
             "operator": "w1-op", "contact": "w1@x.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
            {"name": "w2", "vkey": _wit_vkey("w2", _SEED_W2),
             "operator": "w2-op", "contact": "w2@x.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
        ],
        "policy_signers": [{"key_id": s.public_key.hex(),
                            "public_key": s.public_key.hex()}
                           for s in (p1, p2)],
        "policy_threshold": 2,
        "max_checkpoint_staleness_seconds": 10800,
    }
    return WP.seal_policy(body, [p1, p2])


def _layer_v3():
    leaves = _leaves()
    return EW.build_witness_layer(
        _DIGEST, checkpoint=_note(leaves), policy_doc=_sealed_v3(),
        trust_anchor=_anchor(),
        consistency_proof=EW.make_consistency_proof(leaves, 3),
        inclusion_proofs=[EW.make_inclusion_proof(leaves, 0)],
        now=_NOW)


class TestPolicyVersionFloor(unittest.TestCase):
    """Wave-325 residual 4: verifier_inputs()["policy_version"] is
    consumed by the auditor-pinned floor."""

    def test_floor_above_version_refuses_coded(self):
        layer = _layer_v3()
        with self.assertRaises(EW.ExportWitnessError) as ctx:
            EW.verify_witness_layer(layer, _anchor(),
                                    bundle_digest=_DIGEST, now=_NOW,
                                    min_policy_version=5)
        self.assertEqual(ctx.exception.code,
                         "export-witness-policy-version-below-minimum")

    def test_floor_equal_or_below_verifies(self):
        layer = _layer_v3()
        out = EW.verify_witness_layer(layer, _anchor(),
                                      bundle_digest=_DIGEST, now=_NOW,
                                      min_policy_version=3)
        self.assertEqual(out["policy_version"], 3)
        out = EW.verify_witness_layer(layer, _anchor(),
                                      bundle_digest=_DIGEST, now=_NOW,
                                      min_policy_version=1)
        self.assertEqual(out["policy_version"], 3)

    def test_no_floor_is_back_compat(self):
        layer = _layer_v3()
        out = EW.verify_witness_layer(layer, _anchor(),
                                      bundle_digest=_DIGEST, now=_NOW)
        self.assertEqual(out["policy_version"], 3)

    def test_bad_floor_type_is_malformed(self):
        layer = _layer_v3()
        for bad in ("3", 0, True, 2.5):
            with self.assertRaises(EW.ExportWitnessError) as ctx:
                EW.verify_witness_layer(layer, _anchor(),
                                        bundle_digest=_DIGEST, now=_NOW,
                                        min_policy_version=bad)
            self.assertEqual(ctx.exception.code,
                             "export-witness-malformed")

    def test_carrier_floor_refuses_coded(self):
        layer = _layer_v3()
        doc = _sealed_v3()
        blob = EW.encode_small_carrier(layer, exported_at=_NOW - 10)
        with self.assertRaises(EW.ExportWitnessError) as ctx:
            EW.decode_small_carrier(blob, doc, _anchor(), now=_NOW,
                                    min_policy_version=5)
        self.assertEqual(ctx.exception.code,
                         "export-witness-policy-version-below-minimum")
        out = EW.decode_small_carrier(blob, doc, _anchor(), now=_NOW,
                                      min_policy_version=3)
        self.assertEqual(out["policy_version"], 3)


if __name__ == "__main__":
    unittest.main()
