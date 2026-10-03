"""Unit tests for gov.witness_log (wave-312 lane D).

The persistent append-only transparency log: RFC 6962-style Merkle
tree (stdlib hashlib only), signed checkpoints (checkpoint signature
verified FIRST; sizes/hashes parsed only from the verified
checkpoint), inclusion proofs, and consistency proofs.

Red-first: the forgery cases below refuse with the coded WitnessError;
the embedded Ed25519 verifier is cross-tested against gov.ed25519;
the third-party acceptance test re-verifies a checkpoint + inclusion
proof in a subprocess with a sys.meta_path import blocker -- no
Sasanam import is possible in the child ("sell evidence, not the
engine").
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import witness_log as wl
from gov import ed25519 as ref_ed25519
from gov.signing import Ed25519Signer

WITNESS_SEED = bytes([77]) * 32
OTHER_SEED = bytes([78]) * 32
T0 = 1791528600


def _signer(seed=WITNESS_SEED):
    return Ed25519Signer(seed)


def _log(n, seed=WITNESS_SEED, prefix=b"leaf"):
    log = wl.WitnessLog(_signer(seed).public_key)
    for i in range(n):
        log.append(prefix + b"-%d" % i)
    return log


class TestCanonicalBytes(unittest.TestCase):
    def test_deterministic(self):
        a = wl.canonical_bytes({"b": 1, "a": [1, 2]})
        b = wl.canonical_bytes({"a": [1, 2], "b": 1})
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":[1,2],"b":1}')

    def test_unserializable_refuses(self):
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.canonical_bytes({"x": object()})
        self.assertEqual(ctx.exception.code, "witness-log-malformed")


class TestMerkleHashing(unittest.TestCase):
    def test_domain_separation(self):
        # A leaf hash can never equal a node hash over the same bytes.
        lh = wl.leaf_hash(b"same")
        nh = wl.node_hash(wl.leaf_hash(b"same"), wl.leaf_hash(b"same"))
        self.assertNotEqual(lh, nh)

    def test_two_leaf_root_by_hand(self):
        h0 = hashlib.sha256(b"\x00a").digest()
        h1 = hashlib.sha256(b"\x00b").digest()
        want = hashlib.sha256(b"\x01" + h0 + h1).digest()
        log = wl.WitnessLog(_signer().public_key)
        log.append(b"a")
        log.append(b"b")
        self.assertEqual(log.root_hash(), want)

    def test_single_leaf_root_is_leaf_hash(self):
        log = _log(1)
        self.assertEqual(log.root_hash(), wl.leaf_hash(b"leaf-0"))

    def test_bad_inputs_refuse(self):
        with self.assertRaises(wl.WitnessError):
            wl.leaf_hash("")
        with self.assertRaises(wl.WitnessError):
            wl.leaf_hash(b"")
        with self.assertRaises(wl.WitnessError):
            wl.node_hash(b"short", b"x" * 32)


class TestEd25519Embedded(unittest.TestCase):
    def test_cross_check_against_vendored(self):
        # The embedded verifier must agree with gov.ed25519 on valid
        # and tampered signatures (the two implementations are
        # independent; agreement is the test).
        for _ in range(25):
            seed = secrets.token_bytes(32)
            pub = ref_ed25519.publickey(seed)
            msg = secrets.token_bytes(secrets.randbelow(300))
            sig = ref_ed25519.sign(seed, msg)
            self.assertTrue(wl._ed25519_verify(pub, msg, sig))
            bad = bytearray(sig)
            bad[secrets.randbelow(64)] ^= 1
            self.assertFalse(wl._ed25519_verify(pub, msg, bytes(bad)))
            self.assertFalse(wl._ed25519_verify(pub, msg + b"!", sig))

    def test_malformed_never_raises(self):
        self.assertFalse(wl._ed25519_verify(b"short", b"m", b"x" * 64))
        self.assertFalse(wl._ed25519_verify(b"x" * 32, b"m", b"y" * 63))
        self.assertFalse(wl._ed25519_verify(b"x" * 31 + b"y", b"m",
                                            b"z" * 64))


class TestAppend(unittest.TestCase):
    def test_indices_sequential(self):
        log = wl.WitnessLog(_signer().public_key)
        self.assertEqual(log.append(b"a"), 0)
        self.assertEqual(log.append(b"b"), 1)
        self.assertEqual(log.tree_size, 2)

    def test_bad_leaf_refuses(self):
        log = wl.WitnessLog(_signer().public_key)
        for bad in ("str", b"", None, 123):
            with self.assertRaises(wl.WitnessError) as ctx:
                log.append(bad)
            self.assertEqual(ctx.exception.code, "witness-log-malformed")

    def test_bad_pubkey_refuses(self):
        with self.assertRaises(wl.WitnessError):
            wl.WitnessLog(b"short")

    def test_log_id_is_key_digest(self):
        key = _signer()
        log = wl.WitnessLog(key.public_key)
        self.assertEqual(log.log_id,
                         hashlib.sha256(key.public_key).hexdigest())


class TestCheckpoint(unittest.TestCase):
    def test_roundtrip(self):
        key = _signer()
        log = _log(3)
        sealed = log.sealed_checkpoint(T0, key)
        cp = wl.verify_checkpoint(sealed, key.public_key)
        self.assertEqual(cp["treeSize"], 3)
        self.assertEqual(cp["timestamp"], T0)
        self.assertEqual(cp["logId"], log.log_id)
        self.assertEqual(bytes.fromhex(cp["rootHash"]), log.root_hash())

    def test_empty_log_refuses(self):
        log = wl.WitnessLog(_signer().public_key)
        with self.assertRaises(wl.WitnessError) as ctx:
            log.sealed_checkpoint(T0, _signer())
        self.assertEqual(ctx.exception.code, "witness-log-empty")

    def test_foreign_signer_refuses(self):
        log = _log(2)
        with self.assertRaises(wl.WitnessError) as ctx:
            log.sealed_checkpoint(T0, _signer(OTHER_SEED))
        self.assertEqual(ctx.exception.code, "witness-log-key-mismatch")

    def test_tampered_signature_refuses(self):
        key = _signer()
        log = _log(2)
        sealed = log.sealed_checkpoint(T0, key)
        bad = copy.deepcopy(sealed)
        sig = bytearray(base64.b64decode(bad["signature"]))
        sig[0] ^= 1
        bad["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_checkpoint(bad, key.public_key)
        self.assertEqual(ctx.exception.code,
                         "witness-log-checkpoint-signature-invalid")

    def test_wrong_key_refuses(self):
        log = _log(2)
        sealed = log.sealed_checkpoint(T0, _signer())
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_checkpoint(sealed, _signer(OTHER_SEED).public_key)
        self.assertEqual(ctx.exception.code,
                         "witness-log-checkpoint-signature-invalid")

    def test_tampered_body_fails_at_signature(self):
        # Flipping a checkpoint field invalidates the signature; the
        # verifier parses nothing before the signature check.
        key = _signer()
        log = _log(2)
        sealed = log.sealed_checkpoint(T0, key)
        bad = copy.deepcopy(sealed)
        bad["checkpoint"]["treeSize"] = 999
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_checkpoint(bad, key.public_key)
        self.assertEqual(ctx.exception.code,
                         "witness-log-checkpoint-signature-invalid")

    def test_malformed_checkpoint_after_valid_sig(self):
        # A checkpoint with a VALID signature but bad fields refuses
        # at parse (sign-then-mutate is impossible without the key, so
        # this is a white-box parse test via a re-signed bad doc).
        key = _signer()
        log = _log(2)
        cp = log.checkpoint(T0)
        cp["treeSize"] = 0  # bad, then re-sign with the test key
        sig = key.sign(wl.canonical_bytes(cp))
        sealed = {"checkpoint": cp,
                  "signature": base64.b64encode(sig).decode("ascii")}
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_checkpoint(sealed, key.public_key)
        self.assertEqual(ctx.exception.code,
                         "witness-log-checkpoint-malformed")

    def test_log_id_mismatch_refuses(self):
        key = _signer()
        log = _log(2)
        cp = log.checkpoint(T0)
        cp["logId"] = "00" * 32  # wrong log, re-signed
        sig = key.sign(wl.canonical_bytes(cp))
        sealed = {"checkpoint": cp,
                  "signature": base64.b64encode(sig).decode("ascii")}
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_checkpoint(sealed, key.public_key)
        self.assertEqual(ctx.exception.code,
                         "witness-log-checkpoint-malformed")


class TestInclusion(unittest.TestCase):
    def test_all_indices_sizes_1_to_16(self):
        for n in range(1, 17):
            log = _log(n)
            root = log.root_hash()
            for m in range(n):
                proof = log.inclusion_proof(m)
                wl.verify_inclusion(b"leaf-%d" % m, proof["leaf_index"],
                                    proof["path"], proof["tree_size"],
                                    root)

    def test_tampered_sibling_refuses(self):
        log = _log(6)
        root = log.root_hash()
        proof = log.inclusion_proof(4)
        bad = copy.deepcopy(proof)
        h = bytearray(bytes.fromhex(bad["path"][0]["hash"]))
        h[0] ^= 1
        bad["path"][0]["hash"] = bytes(h).hex()
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_inclusion(b"leaf-4", bad["leaf_index"],
                                bad["path"], bad["tree_size"], root)
        self.assertEqual(ctx.exception.code, "witness-log-inclusion-invalid")

    def test_wrong_leaf_refuses(self):
        log = _log(4)
        root = log.root_hash()
        proof = log.inclusion_proof(1)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_inclusion(b"other-bytes", proof["leaf_index"],
                                proof["path"], proof["tree_size"], root)
        self.assertEqual(ctx.exception.code, "witness-log-inclusion-invalid")

    def test_swapped_index_refuses(self):
        # Position binding: a proof for leaf 2 presented as leaf 5
        # refuses even though the bytes+path fold to the root.
        log = _log(7)
        root = log.root_hash()
        proof = log.inclusion_proof(2)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_inclusion(b"leaf-2", 5, proof["path"],
                                proof["tree_size"], root)
        self.assertEqual(ctx.exception.code, "witness-log-inclusion-invalid")

    def test_wrong_root_refuses(self):
        log = _log(4)
        other = _log(4, prefix=b"different")
        proof = log.inclusion_proof(1)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_inclusion(b"leaf-1", proof["leaf_index"],
                                proof["path"], proof["tree_size"],
                                other.root_hash())
        self.assertEqual(ctx.exception.code, "witness-log-inclusion-invalid")

    def test_index_out_of_range_refuses(self):
        log = _log(3)
        root = log.root_hash()
        proof = log.inclusion_proof(0)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_inclusion(b"leaf-0", 3, proof["path"], 3, root)
        self.assertEqual(ctx.exception.code, "witness-log-inclusion-invalid")

    def test_empty_log_refuses(self):
        log = wl.WitnessLog(_signer().public_key)
        with self.assertRaises(wl.WitnessError) as ctx:
            log.inclusion_proof(0)
        self.assertEqual(ctx.exception.code, "witness-log-empty")


class TestConsistency(unittest.TestCase):
    def _roots(self, n, prefix=b"c"):
        roots = []
        for m in range(1, n + 1):
            roots.append(_log(m, prefix=prefix).root_hash())
        return roots

    def test_brute_force_all_pairs_to_16(self):
        for n in range(2, 17):
            log = _log(n)
            roots = self._roots(n, prefix=b"leaf")
            for m in range(1, n):
                proof = log.consistency_proof(m, n)
                wl.verify_consistency(m, roots[m - 1], n, roots[n - 1],
                                     proof["hashes"])

    def test_forked_logs_have_no_consistency(self):
        key = _signer().public_key
        log_a = wl.WitnessLog(key)
        log_b = wl.WitnessLog(key)
        for i in range(4):
            log_a.append(b"a-%d" % i)
            log_b.append(b"b-%d" % i)
        old_a = wl.WitnessLog(key)
        old_a.append(b"a-0")
        old_a.append(b"a-1")
        proof = log_a.consistency_proof(2, 4)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_consistency(2, old_a.root_hash(), 4,
                                  log_b.root_hash(), proof["hashes"])
        self.assertEqual(ctx.exception.code,
                         "witness-log-consistency-invalid")

    def test_tampered_proof_hash_refuses(self):
        log = _log(8)
        roots = self._roots(8)
        proof = log.consistency_proof(3, 8)
        bad = copy.deepcopy(proof)
        h = bytearray(bytes.fromhex(bad["hashes"][0]))
        h[0] ^= 1
        bad["hashes"][0] = bytes(h).hex()
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_consistency(3, roots[2], 8, roots[7],
                                  bad["hashes"])
        self.assertEqual(ctx.exception.code,
                         "witness-log-consistency-invalid")

    def test_wrong_old_root_refuses(self):
        log = _log(8)
        roots = self._roots(8)
        other_roots = self._roots(8, prefix=b"zz")
        proof = log.consistency_proof(3, 8)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_consistency(3, other_roots[2], 8, roots[7],
                                  proof["hashes"])
        self.assertEqual(ctx.exception.code,
                         "witness-log-consistency-invalid")

    def test_bad_sizes_refuse(self):
        log = _log(5)
        with self.assertRaises(wl.WitnessError):
            log.consistency_proof(5, 5)
        with self.assertRaises(wl.WitnessError):
            log.consistency_proof(0, 5)
        with self.assertRaises(wl.WitnessError):
            log.consistency_proof(3, 99)

    def test_equal_sizes_refuse(self):
        log = _log(5)
        proof = log.consistency_proof(2, 5)
        with self.assertRaises(wl.WitnessError) as ctx:
            wl.verify_consistency(5, log.root_hash(), 5,
                                  log.root_hash(), proof["hashes"])
        self.assertEqual(ctx.exception.code,
                         "witness-log-consistency-invalid")


class TestExportImport(unittest.TestCase):
    def test_roundtrip(self):
        log = _log(6)
        log2 = wl.WitnessLog.import_log(log.export())
        self.assertEqual(log2.root_hash(), log.root_hash())
        self.assertEqual(log2.log_id, log.log_id)
        self.assertEqual(log2.entries(), log.entries())

    def test_malformed_export_refuses(self):
        with self.assertRaises(wl.WitnessError):
            wl.WitnessLog.import_log({"nope": True})
        with self.assertRaises(wl.WitnessError):
            wl.WitnessLog.import_log({"witness_public_key": "zz",
                                      "entries": []})

    def test_imported_log_verifies(self):
        log = _log(4)
        log2 = wl.WitnessLog.import_log(log.export())
        key = _signer()
        sealed = log2.sealed_checkpoint(T0, key)
        cp = wl.verify_checkpoint(sealed, key.public_key)
        proof = log2.inclusion_proof(2)
        wl.verify_inclusion(b"leaf-2", proof["leaf_index"],
                            proof["path"], cp["treeSize"],
                            bytes.fromhex(cp["rootHash"]))


class TestThirdPartyAcceptance(unittest.TestCase):
    def test_stdlib_only_subprocess(self):
        """The acceptance script verifies a checkpoint + inclusion
        proof with NO Sasanam import -- enforced by a sys.meta_path
        import blocker in the child."""
        key = _signer()
        log = _log(5)
        sealed = log.sealed_checkpoint(T0, key)
        proof = log.inclusion_proof(3)
        script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "evals", "w312_thirdparty_witness_accept.py")
        with tempfile.TemporaryDirectory() as d:
            leaf_p = os.path.join(d, "leaf.bin")
            cp_p = os.path.join(d, "checkpoint.json")
            proof_p = os.path.join(d, "proof.json")
            with open(leaf_p, "wb") as fh:
                fh.write(b"leaf-3")
            with open(cp_p, "w", encoding="utf-8") as fh:
                json.dump(sealed, fh)
            with open(proof_p, "w", encoding="utf-8") as fh:
                json.dump(proof, fh)
            driver = (
                "import sys\n"
                "class _Block:\n"
                "    def find_module(self, name, path=None):\n"
                "        if name == 'gov' or name.startswith('gov.'):\n"
                "            return self\n"
                "    def load_module(self, name):\n"
                "        raise ImportError('blocked: ' + name)\n"
                "sys.meta_path.insert(0, _Block())\n"
                "sys.argv = ['accept', '--checkpoint', %r,\n"
                "            '--pubkey', %r, '--leaf', %r,\n"
                "            '--proof', %r]\n"
                "src = open(%r).read()\n"
                "exec(compile(src, 'accept', 'exec'),\n"
                "     {'__name__': '__main__'})\n"
                % (cp_p, key.public_key.hex(), leaf_p, proof_p, script))
            env = {k: v for k, v in os.environ.items()
                   if k not in ("PYTHONPATH", "PYTHONHOME")}
            proc = subprocess.run(
                [sys.executable, "-c", driver], cwd="/tmp", env=env,
                capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0,
                         "stderr: %s" % proc.stderr[-500:])
        self.assertIn("THIRDPARTY_WITNESS_VALID", proc.stdout)


if __name__ == "__main__":
    unittest.main()
