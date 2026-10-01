"""Unit tests for gov/encrypted_envelopes.py (wave-257 lane 1).

Contracts pinned here:
* seal/open round-trip for 1..N recipients; meta carries digests,
  recipient_id, payload_signed.
* fail-closed machine codes: envelope-malformed, envelope-open-refused
  (single generic code for wrong key / unknown recipient / tampered
  tag), envelope-recipient-refused, envelope-seal-refused,
  envelope-version-unknown.
* journal carries digests only -- never plaintext, never key material.
* fresh envelope key per seal (ciphertexts differ).
* taxonomy pin 1092.
"""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes
from gov import encrypted_envelopes as ee


class EnvelopeContracts(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="test-env-")
        self.vault = ee.EnvelopeVault(os.path.join(d, "j.jsonl"))
        self.journal_path = os.path.join(d, "j.jsonl")

    def _recips(self, n=2):
        return [ee.Recipient("r%d" % i, b"unit-key-%d" % i * 8)
                for i in range(n)]

    def test_taxonomy_pin(self):
        # Wave-258 merge: pin -> 1080.
        self.assertEqual(len(decision_codes.TAXONOMY), 1092)
        for c in ("envelope-malformed", "envelope-open-refused",
                  "envelope-recipient-refused", "envelope-seal-refused",
                  "envelope-version-unknown"):
            self.assertEqual(decision_codes.code_for(c)["code"], c)

    def test_roundtrip_and_meta(self):
        payload = b'{"evidence": 1}'
        env = self.vault.seal(payload, self._recips(1),
                              payload_signed=True)
        out, meta = self.vault.open(env, b"unit-key-0" * 8)
        self.assertEqual(out, payload)
        self.assertEqual(meta["payload_digest"],
                         hashlib.sha256(payload).hexdigest())
        self.assertEqual(meta["envelope_digest"],
                         hashlib.sha256(env).hexdigest())
        self.assertEqual(meta["recipient_id"], "r0")
        self.assertTrue(meta["payload_signed"])

    def test_payload_signed_default_false(self):
        env = self.vault.seal(b"x", self._recips(1))
        _out, meta = self.vault.open(env, b"unit-key-0" * 8)
        self.assertFalse(meta["payload_signed"])

    def test_each_recipient_independent(self):
        env = self.vault.seal(b"multi", self._recips(3))
        for i in range(3):
            out, meta = self.vault.open(env, b"unit-key-%d" % i * 8)
            self.assertEqual(out, b"multi")
            self.assertEqual(meta["recipient_id"], "r%d" % i)

    def test_tampered_tag_generic_code(self):
        env = bytearray(self.vault.seal(b"p", self._recips(1)))
        env[-1] ^= 0xFF
        with self.assertRaises(ee.EnvelopeError) as cm:
            self.vault.open(bytes(env), b"unit-key-0" * 8)
        self.assertEqual(cm.exception.code, "envelope-open-refused")

    def test_tampered_header_generic_code(self):
        env = bytearray(self.vault.seal(b"p", self._recips(1)))
        env[13] ^= 0x01  # inside recipient section
        with self.assertRaises(ee.EnvelopeError) as cm:
            self.vault.open(bytes(env), b"unit-key-0" * 8)
        # header is tag-covered: wrong-key-shaped or malformed, both
        # fail closed; never a raw exception.
        self.assertIsInstance(cm.exception, ee.EnvelopeError)

    def test_wrong_key_generic_code(self):
        env = self.vault.seal(b"p", self._recips(1))
        with self.assertRaises(ee.EnvelopeError) as cm:
            self.vault.open(env, b"wrong-wrong-wrong!")
        self.assertEqual(cm.exception.code, "envelope-open-refused")

    def test_truncated_is_malformed(self):
        env = self.vault.seal(b"p", self._recips(1))
        with self.assertRaises(ee.EnvelopeMalformed) as cm:
            self.vault.open(env[:40], b"unit-key-0" * 8)
        self.assertEqual(cm.exception.code, "envelope-malformed")

    def test_bad_magic_is_malformed(self):
        env = bytearray(self.vault.seal(b"p", self._recips(1)))
        env[0] ^= 0xFF
        with self.assertRaises(ee.EnvelopeMalformed):
            self.vault.open(bytes(env), b"unit-key-0" * 8)

    def test_unknown_version_refused(self):
        env = bytearray(self.vault.seal(b"p", self._recips(1)))
        env[8:10] = b"\x00\x7f"
        with self.assertRaises(ee.EnvelopeError) as cm:
            self.vault.open(bytes(env), b"unit-key-0" * 8)
        self.assertEqual(cm.exception.code, "envelope-version-unknown")

    def test_seal_refuses_empty_recipients(self):
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"p", [])
        self.assertEqual(cm.exception.code, "envelope-seal-refused")

    def test_seal_refuses_duplicate_ids(self):
        dup = [ee.Recipient("same", b"k" * 16),
               ee.Recipient("same", b"j" * 16)]
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"p", dup)
        self.assertEqual(cm.exception.code, "envelope-seal-refused")

    def test_seal_refuses_empty_key_material(self):
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"p", [ee.Recipient("r", b"")])
        self.assertEqual(cm.exception.code, "envelope-recipient-refused")

    def test_seal_refuses_short_key_material(self):
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"p", [ee.Recipient("r", b"short")])
        self.assertEqual(cm.exception.code, "envelope-recipient-refused")

    def test_seal_refuses_empty_payload(self):
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"", self._recips(1))
        self.assertEqual(cm.exception.code, "envelope-seal-refused")

    def test_seal_refuses_non_bytes_payload(self):
        with self.assertRaises(ee.EnvelopeRefusal):
            self.vault.seal("not-bytes", self._recips(1))

    def test_fresh_key_per_seal(self):
        e1 = self.vault.seal(b"same", self._recips(1))
        e2 = self.vault.seal(b"same", self._recips(1))
        self.assertNotEqual(e1, e2)

    def test_journal_digest_only(self):
        payload = b"journal-secrecy-probe-payload"
        key = b"journal-key-material" * 2
        env = self.vault.seal(payload, [ee.Recipient("aud", key)])
        self.vault.open(env, key)
        with open(self.journal_path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(payload, raw)
        self.assertNotIn(key, raw)
        self.assertIn(hashlib.sha256(env).hexdigest().encode(), raw)
        self.assertIn(hashlib.sha256(payload).hexdigest().encode(),
                      raw)

    def test_open_refusal_journaled(self):
        env = self.vault.seal(b"p", self._recips(1))
        with self.assertRaises(ee.EnvelopeError):
            self.vault.open(env, b"wrong-wrong-wrong!")
        with open(self.journal_path, "rb") as fh:
            raw = fh.read()
        self.assertIn(b"open_refused", raw)

    def test_malformed_open_journaled(self):
        env = self.vault.seal(b"p", self._recips(1))
        bad = env[:len(env) // 2]
        with self.assertRaises(ee.EnvelopeMalformed):
            self.vault.open(bad, b"unit-key-0" * 8)
        with open(self.journal_path, "rb") as fh:
            raw = fh.read()
        self.assertIn(b"open_refused", raw)
        self.assertIn(b"envelope-malformed", raw)
        self.assertIn(hashlib.sha256(bad).hexdigest().encode(), raw)
        self.assertNotIn(b"unit-key-0", raw)

    def test_error_carries_code_and_detail(self):
        env = self.vault.seal(b"p", self._recips(1))
        try:
            self.vault.open(env, b"wrong-wrong-wrong!")
        except ee.EnvelopeError as exc:
            self.assertEqual(exc.code, "envelope-open-refused")
            self.assertTrue(exc.detail)
        else:
            self.fail("no raise")

    def test_non_recipient_object_refused(self):
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            self.vault.seal(b"p", [("r", b"k" * 16)])
        self.assertEqual(cm.exception.code, "envelope-recipient-refused")


if __name__ == "__main__":
    unittest.main()
