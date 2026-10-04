"""Unit tests for gov/key_groups.py (wave-259 lane 2).

Contracts pinned here:
* seal/open round-trip for key groups; quorum-per-group,
  one-group-sufficient (SOPS data-key-shares semantic).
* scope-bound wraps: each entry binds key_id -> scope into the wrap
  KDF; swapped caller scope -> keygroup-scope-mismatch.
* fail-closed machine codes: keygroup-malformed,
  keygroup-open-refused (single generic code for wrong material /
  sub-quorum / tampered tag/header), keygroup-seal-refused,
  keygroup-unknown-key-id, keygroup-scope-mismatch,
  keygroup-version-unknown.
* journal carries digests/ids/scopes only -- never plaintext, never
  key material.
* fresh data key per seal (seals differ).
* taxonomy pin 1106.
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes
from gov import key_groups as kg


def _mat(tag):
    return (b"keymat-" + tag.encode("utf-8")) * 4


class KeyGroupContracts(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="test-kg-")
        self.vault = kg.GroupVault(os.path.join(d, "j.jsonl"))
        self.journal_path = os.path.join(d, "j.jsonl")

    def _groups(self):
        return [
            kg.KeyGroup([kg.KeyShare("key-A", _mat("A")),
                         kg.KeyShare("key-B", _mat("B"))],
                        quorum=2, name="ops"),
            kg.KeyGroup([kg.KeyShare("key-C", _mat("C"))],
                        quorum=1, name="auditor"),
        ]

    # -- taxonomy ----------------------------------------------------

    def test_taxonomy_pin(self):
        # Wave-259 merge: pin -> 1080.
        self.assertEqual(len(decision_codes.TAXONOMY), 1945)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        for c in ("keygroup-malformed", "keygroup-open-refused",
                  "keygroup-scope-mismatch", "keygroup-seal-refused",
                  "keygroup-unknown-key-id", "keygroup-version-unknown"):
            self.assertEqual(decision_codes.TAXONOMY[c]["code"], c)

    # -- positive contract -------------------------------------------

    def test_roundtrip_and_meta(self):
        payload = b'{"evidence": 1}'
        env = self.vault.seal(payload, self._groups(),
                              scope="audit-read", payload_signed=True)
        out, meta = self.vault.open(env, {"key-A": _mat("A"),
                                          "key-B": _mat("B")})
        self.assertEqual(out, payload)
        self.assertEqual(meta["payload_digest"],
                         hashlib.sha256(payload).hexdigest())
        self.assertEqual(meta["envelope_digest"],
                         hashlib.sha256(env).hexdigest())
        self.assertEqual(meta["group_index"], 0)
        self.assertEqual(sorted(meta["key_ids"]), ["key-A", "key-B"])
        self.assertEqual(meta["scopes"], ["audit-read"])
        self.assertTrue(meta["payload_signed"])

    def test_default_quorum_is_full(self):
        groups = [kg.KeyGroup([kg.KeyShare("A", _mat("A")),
                               kg.KeyShare("B", _mat("B"))])]
        env = self.vault.seal(b"p", groups, scope="s")
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(env, {"A": _mat("A")})
        self.assertEqual(cm.exception.code, "keygroup-open-refused")
        out, _m = self.vault.open(env, {"A": _mat("A"), "B": _mat("B")})
        self.assertEqual(out, b"p")

    def test_one_group_sufficient(self):
        env = self.vault.seal(b"p", self._groups(), scope="s")
        out, meta = self.vault.open(env, {"key-C": _mat("C")})
        self.assertEqual(out, b"p")
        self.assertEqual(meta["group_index"], 1)

    def test_first_quorum_group_wins(self):
        groups = [kg.KeyGroup([kg.KeyShare("A", _mat("A"))], quorum=1),
                  kg.KeyGroup([kg.KeyShare("B", _mat("B"))], quorum=1)]
        env = self.vault.seal(b"p", groups, scope="s")
        _out, meta = self.vault.open(env, {"A": _mat("A"),
                                           "B": _mat("B")})
        self.assertEqual(meta["group_index"], 0)

    def test_explicit_scope_gate_allows(self):
        env = self.vault.seal(b"p", self._groups(), scope="audit-read")
        out, _m = self.vault.open(env, {"key-C": _mat("C")},
                                  scope="audit-read")
        self.assertEqual(out, b"p")

    def test_mixed_scope_envelope(self):
        groups = [
            kg.KeyGroup([kg.KeyShare("A", _mat("A"),
                                     scope="incident-response")]),
            kg.KeyGroup([kg.KeyShare("C", _mat("C"),
                                     scope="audit-read")]),
        ]
        env = self.vault.seal(b"p", groups, scope="audit-read")
        out, meta = self.vault.open(env, {"A": _mat("A")},
                                    scope="incident-response")
        self.assertEqual(out, b"p")
        self.assertEqual(meta["scopes"], ["incident-response"])
        # Without a caller scope both entries are usable under their
        # own declared scopes.
        out, _m = self.vault.open(env, {"C": _mat("C")})
        self.assertEqual(out, b"p")

    def test_kem_seam(self):
        v = kg.GroupVault(self.journal_path + ".2",
                          kem=kg.GroupKeyWrap())
        env = v.seal(b"p", self._groups(), scope="s")
        out, _m = v.open(env, {"key-C": _mat("C")})
        self.assertEqual(out, b"p")

    # -- scope binding ------------------------------------------------

    def test_scope_label_swapped(self):
        env = self.vault.seal(b"p", self._groups(), scope="audit-read")
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(env, {"key-C": _mat("C")},
                            scope="audit-write")
        self.assertEqual(cm.exception.code, "keygroup-scope-mismatch")

    def test_scope_gated_entry_unusable(self):
        # Caller scope matches group 2 only; group 0's entries are not
        # attempted even with correct material for them.
        groups = [
            kg.KeyGroup([kg.KeyShare("A", _mat("A"),
                                     scope="incident-response")],
                        quorum=1),
            kg.KeyGroup([kg.KeyShare("C", _mat("C"),
                                     scope="audit-read")],
                        quorum=1),
        ]
        env = self.vault.seal(b"p", groups, scope="audit-read")
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(env, {"A": _mat("A")}, scope="audit-read")
        self.assertEqual(cm.exception.code, "keygroup-open-refused")

    # -- seal refusals -------------------------------------------------

    def test_seal_refusals(self):
        bad = [
            ([], "s", "empty groups"),
            ([kg.KeyGroup([])], "s", "empty members"),
            ([kg.KeyGroup([kg.KeyShare("A", _mat("A"))], quorum=0)],
             "s", "quorum 0"),
            ([kg.KeyGroup([kg.KeyShare("A", _mat("A"))], quorum=2)],
             "s", "quorum > members"),
            ([kg.KeyGroup([kg.KeyShare("A", _mat("A")),
                           kg.KeyShare("A", _mat("A"))], quorum=2)],
             "s", "duplicate key in group"),
            ([kg.KeyGroup([kg.KeyShare("A", _mat("A"),
                                       scope="s1")]),
              kg.KeyGroup([kg.KeyShare("A", _mat("A"),
                                       scope="s2")])],
             "s1", "conflicting scopes"),
            ([kg.KeyGroup([kg.KeyShare("A", b"short")])],
             "s", "weak material"),
            ([kg.KeyGroup([kg.KeyShare("", _mat("A"))])],
             "s", "empty key id"),
        ]
        for groups, scope, label in bad:
            with self.assertRaises(kg.KeyGroupError,
                                   msg=label) as cm:
                self.vault.seal(b"x", groups, scope=scope)
            self.assertEqual(cm.exception.code, "keygroup-seal-refused",
                             msg=label)
        for payload in (b"", b"x" * (kg.MAX_PAYLOAD_BYTES + 1)):
            with self.assertRaises(kg.KeyGroupError) as cm:
                self.vault.seal(payload, self._groups(), scope="s")
            self.assertEqual(cm.exception.code, "keygroup-seal-refused")
        for scope in ("", None):
            with self.assertRaises(kg.KeyGroupError) as cm:
                self.vault.seal(b"x", self._groups(), scope=scope)
            self.assertEqual(cm.exception.code, "keygroup-seal-refused")

    # -- open refusals --------------------------------------------------

    def test_unknown_key_id(self):
        env = self.vault.seal(b"p", self._groups(), scope="s")
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(env, {"key-Z": b"z" * 16})
        self.assertEqual(cm.exception.code, "keygroup-unknown-key-id")

    def test_cross_identity_material(self):
        env = self.vault.seal(b"p", self._groups(), scope="s")
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(env, {"key-A": _mat("A"),
                                  "key-B": _mat("A")})
        self.assertEqual(cm.exception.code, "keygroup-open-refused")

    def test_tampered_tag_generic_code(self):
        env = bytearray(self.vault.seal(b"p", self._groups(),
                                        scope="s"))
        env[-1] ^= 0xFF
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(bytes(env), {"key-C": _mat("C")})
        self.assertEqual(cm.exception.code, "keygroup-open-refused")

    def test_tampered_ciphertext_generic_code(self):
        env = bytearray(self.vault.seal(b"p", self._groups(),
                                        scope="s"))
        env[-33] ^= 0x01  # last ciphertext byte (tag is last 32)
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(bytes(env), {"key-C": _mat("C")})
        self.assertEqual(cm.exception.code, "keygroup-open-refused")

    def test_malformed(self):
        env = bytearray(self.vault.seal(b"p", self._groups(),
                                        scope="s"))
        env[0] ^= 0xFF  # magic
        for blob in (b"", b"SASKEYG1", bytes(env)):
            with self.assertRaises(kg.KeyGroupError) as cm:
                self.vault.open(blob, {"key-C": _mat("C")})
            self.assertEqual(cm.exception.code, "keygroup-malformed")

    def test_version_unknown(self):
        env = bytearray(self.vault.seal(b"p", self._groups(),
                                        scope="s"))
        struct.pack_into(">H", env, 8, 2)  # version 2
        with self.assertRaises(kg.KeyGroupError) as cm:
            self.vault.open(bytes(env), {"key-C": _mat("C")})
        self.assertEqual(cm.exception.code,
                         "keygroup-version-unknown")

    def test_open_refusals_journaled(self):
        env = self.vault.seal(b"p", self._groups(), scope="s")
        try:
            self.vault.open(env, {"key-Z": b"z" * 16})
        except kg.KeyGroupError:
            pass
        raw = open(self.journal_path, "rb").read()
        self.assertIn(b"keygroup-open-refused", raw)
        self.assertIn(b"keygroup-unknown-key-id", raw)

    # -- hygiene --------------------------------------------------------

    def test_journal_digest_only(self):
        payload = b"journal-plaintext-marker"
        env = self.vault.seal(payload, self._groups(),
                              scope="audit-read")
        self.vault.open(env, {"key-C": _mat("C")})
        raw = open(self.journal_path, "rb").read()
        for secret in (payload, _mat("A"), _mat("B"), _mat("C")):
            self.assertNotIn(secret, raw)
        # Key ids and scopes are wire-public by design: logged.
        self.assertIn(b"key-A", raw)
        self.assertIn(b"audit-read", raw)

    def test_fresh_data_key_per_seal(self):
        e1 = self.vault.seal(b"same", self._groups(), scope="s")
        e2 = self.vault.seal(b"same", self._groups(), scope="s")
        self.assertNotEqual(e1, e2)

    def test_wire_magic_and_version(self):
        env = self.vault.seal(b"p", self._groups(), scope="s")
        self.assertEqual(env[:8], b"SASKEYG1")
        self.assertEqual(struct.unpack(">H", env[8:10])[0], 1)


if __name__ == "__main__":
    unittest.main()
