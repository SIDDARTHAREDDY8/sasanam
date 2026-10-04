"""Unit tests for gov.witness_publish (wave-322 lane 3).

Seam-level coverage: publish/verify round trip, byte-for-byte
determinism, the endpoint contract, atomic file writes, the
witness-set seam (plain {name: vkey} map), rotation grace/drop, and
the bool/exception contracts (verify functions raise coded errors,
never soft False; programmer errors raise ValueError).
"""

import base64
import hashlib
import os
import tempfile
import unittest

from gov import witness_publish as WP
from gov import checkpoint_note as CN
from gov import ed25519 as ED
from gov.witness_log import WitnessLog
from gov.signing import Ed25519Signer

NOW = 1798765432
SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
SEED_W1_NEW = bytes([(i * 13) % 256 for i in range(32)])
ORIGIN = "sasanam-witpub-test/v1"


def _signer(seed):
    return Ed25519Signer(seed)


def _vkey(name, signer):
    # Witness vkeys pin signature type 0x04 (cosignature/v1): the key
    # ID binds the type, so a 0x04 vkey differs from the same key's
    # 0x01 vkey. The operator vkey stays 0x01 (signatures over the
    # note text).
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _op_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


class WitnessPublishTest(unittest.TestCase):
    def setUp(self):
        self.op = _signer(SEED_OP)
        self.w1 = _signer(SEED_W1)
        self.w2 = _signer(SEED_W2)
        self.log = WitnessLog(self.op.public_key)
        for i in range(5):
            self.log.append(b"leaf-%d" % i)
        self.op_vk = [_op_vkey("op", self.op)]
        self.wit_vk = {"w1": _vkey("w1", self.w1),
                       "w2": _vkey("w2", self.w2)}

    def _publish(self, **kw):
        args = dict(log=self.log, origin=ORIGIN, log_key_name="op",
                    log_signer=self.op,
                    witness_signers=[("w1", self.w1), ("w2", self.w2)],
                    operator_vkeys=self.op_vk, witness_vkeys=self.wit_vk,
                    quorum_k=2, timestamp=NOW - 100)
        args.update(kw)
        return WP.publish_checkpoint(**args)

    def _verify(self, note, **kw):
        args = dict(operator_vkeys=self.op_vk, witness_vkeys=self.wit_vk,
                    quorum_k=2, allowed_origins={ORIGIN},
                    now=NOW, max_age=3600)
        args.update(kw)
        return WP.verify_published_checkpoint(note, **args)

    # -- round trip ----------------------------------------------------

    def test_round_trip(self):
        note = self._publish()
        out = self._verify(note, last_seen=(5, self.log.root_hash()))
        self.assertEqual(out["tree_size"], 5)
        self.assertEqual(out["root_hash"], self.log.root_hash().hex())
        self.assertEqual(sorted(out["witnesses"]), ["w1", "w2"])
        self.assertEqual(out["freshness"]["timestamp"], NOW - 100)

    def test_deterministic_bytes(self):
        a = self._publish()
        b = self._publish()
        self.assertEqual(a, b)
        self.assertIsInstance(a, bytes)

    def test_note_is_c2sp_shape(self):
        note = self._publish()
        text = note.decode("utf-8")
        lines = text.split("\n")
        self.assertEqual(lines[0], ORIGIN)
        self.assertEqual(lines[1], "5")
        self.assertEqual(lines[2],
                         base64.b64encode(self.log.root_hash()).decode())
        self.assertTrue(lines[3].startswith("timestamp "))
        self.assertEqual(lines[4], "")  # blank separator
        self.assertTrue(lines[5].startswith("— op "))
        # cosignature/v1 lines: 76-byte blobs
        # (keyID(4) || u64BE timestamp(8) || sig(64)); the signature is
        # over the domain-separated cosignature statement, NOT the note
        # text -- the production Rekor v2 witness format.
        ts = NOW - 100
        statement = CN.cosignature_v1_statement(
            ORIGIN, 5, self.log.root_hash(), ts)
        pubs = {"w1": self.w1.public_key, "w2": self.w2.public_key}
        # The note text is everything before the blank separator line.
        note_text = note.split(b"\n\n")[0]
        for ln in (lines[6], lines[7]):
            parts = ln.split(" ")
            blob = base64.b64decode(parts[2])
            self.assertEqual(len(blob), 76)
            self.assertEqual(int.from_bytes(blob[4:12], "big"), ts)
            pub = pubs[parts[1]]
            self.assertTrue(ED.verify(pub, statement, blob[12:]))
            self.assertFalse(ED.verify(pub, note_text, blob[12:]))

    def test_cosignature_timestamp_bound(self):
        # Flipping a timestamp byte breaks the signature: the embedded
        # time is inside the signed statement, not alongside it.
        note = self._publish()
        lines = note.decode("utf-8").split("\n")
        fixed = []
        for ln in lines:
            parts = ln.split(" ")
            if len(parts) == 3 and parts[1] == "w1":
                blob = bytearray(base64.b64decode(parts[2]))
                blob[7] ^= 0xFF
                parts[2] = base64.b64encode(bytes(blob)).decode()
                ln = " ".join(parts)
            fixed.append(ln)
        forged = "\n".join(fixed).encode()
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(forged)
        self.assertEqual(cm.exception.code, "witness-cosignature-invalid")

    def test_legacy_0x01_witness_line_ignored(self):
        # A legacy 0x01 witness line (signature over the note text) is
        # an unknown key under 0x04-pinned vkeys: the key ID binds the
        # signature type, so it MUST-ignores -- it neither verifies nor
        # counts toward quorum.
        note = self._publish(witness_signers=[("w2", self.w2)], quorum_k=1)
        note_text = note.split(b"\n\n")[0]  # before the blank separator
        key_id = CN.derive_key_id("w1", CN.SIG_TYPE_ED25519,
                                  self.w1.public_key)
        sig = self.w1.sign(note_text)
        legacy = "— w1 %s\n" % base64.b64encode(key_id + sig).decode()
        mixed = note + legacy.encode()
        out = self._verify(mixed, quorum_k=1)
        self.assertEqual(out["witnesses"], ["w2"])
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(mixed, quorum_k=2)
        self.assertEqual(cm.exception.code, "witness-quorum-unmet")

    # -- endpoint contract ----------------------------------------------

    def test_endpoint_contract_exact(self):
        note = self._publish()
        c = WP.endpoint_contract(note)
        self.assertEqual(c, {
            "method": "GET",
            "path": "/checkpoint",
            "content_type": "text/plain; charset=utf-8",
            "cache_control": "no-cache",
            "etag": '"%s"' % hashlib.sha256(note).hexdigest(),
            "note_sha256": hashlib.sha256(note).hexdigest(),
            "storage": "object-store-backed static file; the CDN is "
                       "untrusted storage",
        })

    def test_write_checkpoint_file_atomic(self):
        note = self._publish()
        d = tempfile.mkdtemp(prefix="witpub-ut-")
        p = os.path.join(d, "checkpoint")
        self.assertEqual(WP.write_checkpoint_file(note, p), p)
        with open(p, "rb") as fh:
            self.assertEqual(fh.read(), note)
        self.assertEqual([f for f in os.listdir(d)
                          if f.endswith(".tmp")], [])

    # -- coded refusals --------------------------------------------------

    def test_publish_quorum_unmet(self):
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._publish(witness_signers=[("w1", self.w1)], quorum_k=2)
        self.assertEqual(cm.exception.code, "witness-publish-quorum-unmet")

    def test_verify_quorum_unmet(self):
        note = self._publish(witness_signers=[("w1", self.w1)], quorum_k=1)
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(note, quorum_k=2)
        self.assertEqual(cm.exception.code, "witness-quorum-unmet")

    def test_rollback(self):
        note = self._publish()
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(note, last_seen=(9, bytes(32)))
        self.assertEqual(cm.exception.code, "witness-publish-rollback")

    def test_equivocation(self):
        note = self._publish()
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(note, last_seen=(5, bytes(32)))
        self.assertEqual(cm.exception.code,
                         "witness-consistency-fork-detected")

    def test_unknown_origin(self):
        note = self._publish(origin="other-log/v1")
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(note)
        self.assertEqual(cm.exception.code,
                         "witness-checkpoint-unknown-origin")

    def test_stale(self):
        note = self._publish(timestamp=NOW - 7200)
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(note, now=NOW, max_age=3600)
        self.assertEqual(cm.exception.code, "witness-checkpoint-stale")

    def test_malformed(self):
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(b"\x00\x01 garbage")
        self.assertEqual(cm.exception.code, "witness-note-malformed")

    def test_forged_cosignature(self):
        note = self._publish()
        lines = note.decode("utf-8").split("\n")
        fixed = []
        for ln in lines:
            parts = ln.split(" ")
            if len(parts) == 3 and parts[1] == "w1":
                blob = bytearray(base64.b64decode(parts[2]))
                blob[20] ^= 0xFF
                parts[2] = base64.b64encode(bytes(blob)).decode()
                ln = " ".join(parts)
            fixed.append(ln)
        forged = "\n".join(fixed).encode()
        with self.assertRaises(WP.WitnessPublishError) as cm:
            self._verify(forged)
        self.assertEqual(cm.exception.code, "witness-cosignature-invalid")

    # -- rotation ----------------------------------------------------------

    def test_rotation_grace_and_drop(self):
        w1n = _signer(SEED_W1_NEW)
        both = {"w1": _vkey("w1", w1n),
                "w1-old": _vkey("w1-old", self.w1),
                "w2": _vkey("w2", self.w2)}
        new_only = {"w1": _vkey("w1", w1n),
                    "w2": _vkey("w2", self.w2)}
        # grace: both keys verify
        for signer, name in ((w1n, "w1"), (self.w1, "w1-old")):
            note = WP.publish_checkpoint(
                self.log, ORIGIN, "op", self.op, [(name, signer)],
                operator_vkeys=self.op_vk, witness_vkeys=both,
                quorum_k=1, timestamp=NOW - 100)
            out = WP.verify_published_checkpoint(
                note, operator_vkeys=self.op_vk, witness_vkeys=both,
                quorum_k=1, allowed_origins={ORIGIN})
            self.assertIn(name, out["witnesses"])
        # drop: old-key-only checkpoint no longer meets quorum
        note = WP.publish_checkpoint(
            self.log, ORIGIN, "op", self.op, [("w1-old", self.w1)],
            operator_vkeys=self.op_vk, witness_vkeys=both,
            quorum_k=1, timestamp=NOW - 100)
        with self.assertRaises(WP.WitnessPublishError) as cm:
            WP.verify_published_checkpoint(
                note, operator_vkeys=self.op_vk,
                witness_vkeys=new_only, quorum_k=2,
                allowed_origins={ORIGIN})
        self.assertEqual(cm.exception.code, "witness-quorum-unmet")

    # -- contracts -----------------------------------------------------------

    def test_programmer_errors_raise_valueerror(self):
        note = self._publish()
        with self.assertRaises(ValueError):
            WP.verify_published_checkpoint(
                note, operator_vkeys=self.op_vk,
                witness_vkeys=self.wit_vk, quorum_k=2,
                allowed_origins=set())  # empty origins
        with self.assertRaises(ValueError):
            WP.verify_published_checkpoint(
                note, operator_vkeys=self.op_vk,
                witness_vkeys=self.wit_vk, quorum_k=2,
                allowed_origins={ORIGIN}, now=NOW)  # max_age missing
        with self.assertRaises(ValueError):
            WP.publish_checkpoint(
                self.log, ORIGIN, "op", self.op, "not-a-list",
                operator_vkeys=self.op_vk, witness_vkeys=self.wit_vk,
                quorum_k=2)

    def test_codes_registered_and_sorted(self):
        self.assertEqual(WP.WITNESS_PUBLISH_CODES,
                         tuple(sorted(WP.WITNESS_PUBLISH_CODES)))
        self.assertEqual(len(WP.WITNESS_PUBLISH_CODES), 3)


if __name__ == "__main__":
    unittest.main()
