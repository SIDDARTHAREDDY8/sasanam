"""F203 closure: RekorBackend Ed25519ph/sha512 hashedrekord shape.

Wave-198 lane A. ``RekorBackend.submit`` used to emit raw Ed25519 /
SHA-256 hashedrekord envelopes, which real Rekor v1.5.4 rejects with
HTTP 400 ``unsupported hash algorithm: "SHA-256" not in [SHA-512]``
(F203). The fixed shape, measured live against Rekor v1.5.4:

  * signature = Ed25519ph (RFC 8032 5.1, SHA-512 prehash, empty
    context) over the 32-byte anchor hash;
  * envelope data.hash = {"algorithm": "sha512",
    "value": hex(sha512(anchor_hash))}.

Hermetic: recording fake transport, no network. Deterministic except
wall-clock ``submitted_at`` (never asserted on).
"""

import base64
import hashlib
import json
import os
import sys
import time
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import anchor_backend as _ab  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _h_leaf(b):
    return hashlib.sha256(b"\x00" + b).digest()


def _h_node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def _subtree_root(leaf_hashes, lo, n):
    if n == 1:
        return leaf_hashes[lo]
    k = 1
    while 2 * k < n:
        k *= 2
    return _h_node(_subtree_root(leaf_hashes, lo, k),
                   _subtree_root(leaf_hashes, lo + k, n - k))


def _inclusion_proof(leaf_hashes, idx, n):
    if n == 1:
        return []
    k = 1
    while 2 * k < n:
        k *= 2
    if idx < k:
        return _inclusion_proof(leaf_hashes, idx, k) + [
            _subtree_root(leaf_hashes, k, n - k)]
    return _inclusion_proof(leaf_hashes, idx - k, n - k) + [
        _subtree_root(leaf_hashes, 0, k)]


class FakeRekor154:
    """Deterministic fake enforcing the v1.5.4 envelope contract for
    the F203 shape: sha512 declaration required (anything else gets
    the real server's 400); well-formed entries otherwise."""

    def __init__(self, log_id="f203-test-log"):
        self.log_id = log_id
        self.bodies = []
        self.last_proposed = None

    def _entry_for(self, idx):
        leaf_hashes = [_h_leaf(b) for b in self.bodies]
        proof = _inclusion_proof(leaf_hashes, idx, len(self.bodies))
        return {
            "body": base64.b64encode(self.bodies[idx]).decode("ascii"),
            "integratedTime": int(time.time()),
            "logIndex": idx,
            "logID": self.log_id,
            "verification": {
                "inclusionProof": {
                    "hashes": [h.hex() for h in proof],
                    "rootHash": _subtree_root(
                        leaf_hashes, 0, len(self.bodies)).hex(),
                    "treeSize": len(self.bodies),
                    "logIndex": idx,
                },
                "signedEntryTimestamp": "fake-set-%d" % idx,
            },
        }

    def __call__(self, request):
        proposed = json.loads(request["body"])
        self.last_proposed = proposed
        if proposed["spec"]["data"]["hash"]["algorithm"] != "sha512":
            raise _ab.WitnessDownError(
                "rekor HTTP 400: unsupported hash algorithm")
        body = json.dumps({"kind": proposed["kind"],
                           "apiVersion": proposed["apiVersion"],
                           "spec": proposed["spec"]},
                          separators=(",", ":")).encode("utf-8")
        self.bodies.append(body)
        idx = len(self.bodies) - 1
        return {"status": 201,
                "body": json.dumps({"fakeuuid%06d" % idx:
                                    self._entry_for(idx)})}


def _backend(n=11, log_id="f203-test-log", transport=None):
    seed = _seed(n)
    be = _ab.RekorBackend(url="http://fake:3000", log_id=log_id,
                          transport=transport, anchor_seed=seed,
                          anchor_pubkey=_ed.publickey(seed))
    return be, seed


class TestEd25519Ph(unittest.TestCase):
    def test_rfc8032_ph_vector_byte_exact(self):
        # The primitive the whole fix rests on: byte-exact against
        # RFC 8032 section 7.3 TEST 1, or nothing below means anything.
        self.assertTrue(_ed.rfc8032_ph_selftest())

    def test_ph_round_trip_on_digest_shape(self):
        seed = _seed(12)
        pub = _ed.publickey(seed)
        digest = bytes(range(32))
        sig = _ed.sign_ph(seed, digest)
        self.assertTrue(_ed.verify_ph(pub, digest, sig))

    def test_raw_and_ph_never_cross_verify(self):
        seed = _seed(13)
        pub = _ed.publickey(seed)
        digest = bytes(range(32))
        ph_sig = _ed.sign_ph(seed, digest)
        raw_sig = _ed.sign(seed, digest)
        self.assertFalse(_ed.verify(pub, digest, ph_sig),
                         "raw verifier must reject ph signatures")
        self.assertFalse(_ed.verify_ph(pub, digest, raw_sig),
                         "ph verifier must reject raw signatures")


class TestF203SubmitShape(unittest.TestCase):
    def test_happy_path_receipt_verifies(self):
        fake = FakeRekor154()
        be, _s = _backend(transport=fake)
        ahash = hashlib.sha256(b"f203-unit-happy").hexdigest()
        receipt = be.submit(ahash)
        self.assertEqual(receipt["anchor_hash"], ahash)
        self.assertEqual(receipt["anchor_algorithm"],
                         _ab.ANCHOR_ALGORITHM_ED25519PH_SHA512)
        ok, why = be.verify_receipt(receipt, anchor_hash=ahash)
        self.assertTrue(ok, why)

    def test_envelope_declares_sha512_of_anchor_hash(self):
        fake = FakeRekor154()
        be, seed = _backend(transport=fake)
        ahash = hashlib.sha256(b"f203-unit-envelope").hexdigest()
        be.submit(ahash)
        proposed = fake.last_proposed
        self.assertEqual(proposed["kind"], "hashedrekord")
        self.assertEqual(proposed["apiVersion"], "0.0.1")
        self.assertEqual(proposed["spec"]["data"]["hash"]["algorithm"],
                         "sha512")
        self.assertEqual(
            proposed["spec"]["data"]["hash"]["value"],
            hashlib.sha512(bytes.fromhex(ahash)).hexdigest())

    def test_envelope_signature_is_ed25519ph_over_anchor_hash(self):
        fake = FakeRekor154()
        be, seed = _backend(transport=fake)
        pub = _ed.publickey(seed)
        ahash = hashlib.sha256(b"f203-unit-sig").hexdigest()
        be.submit(ahash)
        sig = base64.b64decode(
            fake.last_proposed["spec"]["signature"]["content"])
        # Ed25519ph over the 32-byte anchor hash (the live-proven
        # shape) ...
        self.assertTrue(_ed.verify_ph(pub, bytes.fromhex(ahash), sig))
        # ... and never the raw-Ed25519 shape Rekor rejects.
        self.assertFalse(_ed.verify(pub, bytes.fromhex(ahash), sig))
        pk_pem = base64.b64decode(
            fake.last_proposed["spec"]["signature"]["publicKey"]
            ["content"]).decode()
        self.assertEqual(pk_pem, _ab.anchor_spki_pem(pub))

    def test_tampered_entry_refused(self):
        fake = FakeRekor154()
        be, _s = _backend(transport=fake)
        be.submit(hashlib.sha256(b"f203-unit-t1").hexdigest())
        ahash = hashlib.sha256(b"f203-unit-tamper").hexdigest()
        receipt = be.submit(ahash)
        # Flipped proof sibling.
        r1 = dict(receipt)
        p1 = dict(r1["inclusion_proof"])
        h = bytearray(bytes.fromhex(p1["hashes"][0]))
        h[0] ^= 0xFF
        p1["hashes"] = [bytes(h).hex()]
        r1["inclusion_proof"] = p1
        ok, _ = be.verify_receipt(r1, anchor_hash=ahash)
        self.assertFalse(ok, "flipped sibling verified?!")
        # Wrong root.
        r2 = dict(receipt)
        p2 = dict(r2["inclusion_proof"])
        p2["root_hash"] = "00" * 32
        r2["inclusion_proof"] = p2
        ok, _ = be.verify_receipt(r2, anchor_hash=ahash)
        self.assertFalse(ok, "wrong root verified?!")
        # Body hash swapped.
        r3 = dict(receipt)
        body = json.loads(base64.b64decode(r3["body"]).decode())
        body["spec"]["data"]["hash"]["value"] = "ff" * 64
        r3["body"] = base64.b64encode(json.dumps(body).encode()).decode()
        ok, _ = be.verify_receipt(r3, anchor_hash=ahash)
        self.assertFalse(ok, "swapped body hash verified?!")
        # Non-sha512 body declaration.
        r4 = dict(receipt)
        body4 = json.loads(base64.b64decode(r4["body"]).decode())
        body4["spec"]["data"]["hash"]["algorithm"] = "sha256"
        r4["body"] = base64.b64encode(json.dumps(body4).encode()).decode()
        ok, _ = be.verify_receipt(r4, anchor_hash=ahash)
        self.assertFalse(ok, "sha256-declared body verified?!")
        # Forged envelope signature (the receipt must be self-contained:
        # the anchor signature is re-checked, not just the proof).
        r5 = dict(receipt)
        body5 = json.loads(base64.b64decode(r5["body"]).decode())
        sig = bytearray(base64.b64decode(
            body5["spec"]["signature"]["content"]))
        sig[0] ^= 0xFF
        body5["spec"]["signature"]["content"] = base64.b64encode(
            bytes(sig)).decode()
        r5["body"] = base64.b64encode(json.dumps(body5).encode()).decode()
        ok, why = be.verify_receipt(r5, anchor_hash=ahash)
        self.assertFalse(ok, "forged envelope signature verified?!")
        self.assertEqual(why, "anchor signature does not verify")

    def test_wrong_key_refused(self):
        fake = FakeRekor154()
        be, _s = _backend(transport=fake)
        ahash = hashlib.sha256(b"f203-unit-wrongkey").hexdigest()
        receipt = be.submit(ahash)
        # A different transparency log.
        be2, _s2 = _backend(log_id="another-log", transport=fake)
        ok, _ = be2.verify_receipt(receipt, anchor_hash=ahash)
        self.assertFalse(ok, "foreign log_id verified?!")
        # A different anchor.
        ok, _ = be.verify_receipt(receipt, anchor_hash="00" * 32)
        self.assertFalse(ok, "cross-anchor verified?!")
        # A receipt claiming an unknown anchor algorithm.
        r3 = dict(receipt)
        r3["anchor_algorithm"] = "raw-ed25519-sha256"
        ok, _ = be.verify_receipt(r3, anchor_hash=ahash)
        self.assertFalse(ok, "unknown algorithm verified?!")

    def test_stale_proof_guard(self):
        # The receipt's proof must be consistent with its claimed
        # tree size: a proof minted at size 1 replayed against a
        # size-2 claim (the tree grew -- the stale case) is refused,
        # and vice versa.
        fake = FakeRekor154()
        be, _s = _backend(transport=fake)
        ah1 = hashlib.sha256(b"f203-unit-stale-1").hexdigest()
        r1 = be.submit(ah1)
        be.submit(hashlib.sha256(b"f203-unit-stale-2").hexdigest())
        stale = dict(r1)
        p = dict(stale["inclusion_proof"])
        p["tree_size"] = 2
        stale["inclusion_proof"] = p
        ok, _ = be.verify_receipt(stale, anchor_hash=ah1)
        self.assertFalse(ok, "stale (grown-tree) proof verified?!")
        ah3 = hashlib.sha256(b"f203-unit-stale-3").hexdigest()
        r3 = be.submit(ah3)
        shrunk = dict(r3)
        p3 = dict(shrunk["inclusion_proof"])
        p3["tree_size"] = 1
        shrunk["inclusion_proof"] = p3
        ok, _ = be.verify_receipt(shrunk, anchor_hash=ah3)
        self.assertFalse(ok, "shrunk-tree proof verified?!")

    def test_missing_key_material_refused_loud(self):
        be = _ab.RekorBackend(
            transport=lambda req: {"status": 500, "body": "{}"})
        with self.assertRaises(_ab.WitnessError):
            be.submit("ab" * 32)


if __name__ == "__main__":
    unittest.main()
