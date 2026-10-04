#!/usr/bin/env python3
"""Unit tests for gov/checkpoint_note.py (wave-238 lane A).

C2SP tlog-checkpoint wire format: emission, strict parsing, key-ID
derivation and collision rules, verifier-key handling, whole-note
verification, the equivocation journal, and the hermetic-log adapter.
Includes the C2SP spec's own example verifier key and signed note as a
third-party test vector (it verifies under our parser).
Stdlib + gov.checkpoint_note (+ gov.ed25519 as the raw primitive) only.
"""

import base64
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import checkpoint_note as cn  # noqa: E402
from gov import ed25519 as ed  # noqa: E402

ORIGIN = "sasanam.test/hermetic-log"

# Third-party test vector straight from c2sp.org/signed-note (fetched
# 2026-09-30): the spec's example verifier key and example signed note.
SPEC_VKEY = ("example.com/foo+530d903a+"
             "AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
SPEC_NOTE = (
    "This is an example message.\n"
    "\n"
    "\u2014 example.com/foo "
    "Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXm"
    "RKuwHjG1Yu72IneyaQM=\n"
).encode("utf-8")


def _keypair():
    seed = ed.generate_seed()
    return seed, ed.publickey(seed)


def _vkey_for(name, pub):
    kid = cn.derive_key_id(name, cn.SIG_TYPE_ED25519, pub)
    return cn.vkey_string(name, kid, cn.SIG_TYPE_ED25519, pub)


def _emit(name=ORIGIN, size=3, root=None, key_name=ORIGIN, seed=None):
    if root is None:
        root = hashlib.sha256(b"root").digest()
    if seed is None:
        seed, _ = _keypair()
    return seed, cn.emit_checkpoint(name, size, root, key_name, seed)


class SpecVectorTest(unittest.TestCase):
    def test_spec_example_vkey_parses_and_key_id_recomputes(self):
        # Independent recomputation of the spec's key-ID formula.
        parsed = cn.parse_vkey(SPEC_VKEY)
        expect = hashlib.sha256(
            b"example.com/foo" + b"\x0a" + b"\x01"
            + parsed["public_key"]).digest()[:4]
        self.assertEqual(parsed["key_id"], expect)
        self.assertEqual(parsed["key_id"].hex(), "530d903a")

    def test_spec_example_note_parses_and_verifies(self):
        # The spec's own signed note verifies under our implementation:
        # byte-compat with C2SP, not self-attestation.
        text, sigs = cn._split_note(SPEC_NOTE)
        self.assertEqual(text, b"This is an example message.\n")
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["key_name"], "example.com/foo")
        self.assertEqual(sigs[0]["key_id"].hex(), "530d903a")
        parsed = cn.parse_vkey(SPEC_VKEY)
        self.assertTrue(ed.verify(parsed["public_key"], text,
                                 sigs[0]["signature"]))

    def test_spec_example_note_is_not_a_checkpoint(self):
        # A validly-signed note that is not the checkpoint format is
        # refused by the checkpoint path.
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            cn.parse_checkpoint(SPEC_NOTE)
        self.assertEqual(ctx.exception.code, "checkpoint-not-c2sp")


class KeyIdTest(unittest.TestCase):
    def test_derivation_matches_spec_formula(self):
        seed, pub = _keypair()
        got = cn.derive_key_id("example.com/log42", 0x01, pub)
        expect = hashlib.sha256(
            b"example.com/log42" + b"\x0a" + b"\x01" + pub).digest()[:4]
        self.assertEqual(got, expect)
        self.assertEqual(len(got), 4)

    def test_name_change_changes_id(self):
        _seed, pub = _keypair()
        a = cn.derive_key_id("a.example/log", 0x01, pub)
        b = cn.derive_key_id("b.example/log", 0x01, pub)
        self.assertNotEqual(a, b)

    def test_vkey_round_trip(self):
        _seed, pub = _keypair()
        vkey = _vkey_for("example.com/log42", pub)
        parsed = cn.parse_vkey(vkey)
        self.assertEqual(parsed["name"], "example.com/log42")
        self.assertEqual(parsed["public_key"], pub)

    def test_vkey_with_tampered_key_id_is_config_error(self):
        _seed, pub = _keypair()
        vkey = _vkey_for("example.com/log42", pub)
        name, kid, rest = vkey.split("+", 2)
        bad = "%s+%s+%s" % (name, "00000000", rest)
        with self.assertRaises(ValueError):
            cn.parse_vkey(bad)

    def test_vkey_unsupported_sigtype_is_config_error(self):
        _seed, pub = _keypair()
        kid = cn.derive_key_id("example.com/log42", 0x02, pub)
        vkey = cn.vkey_string("example.com/log42", kid, 0x02, pub)
        with self.assertRaises(ValueError):
            cn.parse_vkey(vkey)


class EmissionTest(unittest.TestCase):
    def test_emit_is_deterministic(self):
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        a = cn.emit_checkpoint(ORIGIN, 3, root, ORIGIN, seed)
        b = cn.emit_checkpoint(ORIGIN, 3, root, ORIGIN, seed)
        self.assertEqual(a, b)

    def test_emit_wire_shape(self):
        seed, _pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 20852163, root, ORIGIN, seed)
        lines = note.decode("utf-8").split("\n")
        self.assertEqual(lines[0], ORIGIN)
        self.assertEqual(lines[1], "20852163")
        self.assertEqual(lines[2], base64.b64encode(root).decode())
        self.assertEqual(lines[3], "")
        self.assertTrue(lines[4].startswith("\u2014 " + ORIGIN + " "))
        sig = base64.b64decode(lines[4].split(" ")[2], validate=True)
        self.assertEqual(len(sig), 4 + 64)  # key ID + Ed25519 sig

    def test_emit_empty_origin_refused(self):
        seed, _pub = _keypair()
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            cn.emit_checkpoint("", 1, hashlib.sha256(b"r").digest(),
                               ORIGIN, seed)
        self.assertEqual(ctx.exception.code, "checkpoint-origin-empty")

    def test_emit_origin_with_space_refused(self):
        seed, _pub = _keypair()
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            cn.emit_checkpoint("has space.example/log", 1,
                               hashlib.sha256(b"r").digest(),
                               ORIGIN, seed)
        self.assertEqual(ctx.exception.code, "checkpoint-origin-empty")

    def test_emit_bad_key_name_is_config_error(self):
        # The key name is signer configuration, not a checkpoint
        # field: a bad key name is a programming error, the same
        # convention as derive_key_id / vkey_string / parse_vkey.
        seed, _pub = _keypair()
        with self.assertRaises(ValueError):
            cn.emit_checkpoint(ORIGIN, 1, hashlib.sha256(b"r").digest(),
                               "", seed)
        with self.assertRaises(ValueError):
            cn.emit_checkpoint(ORIGIN, 1, hashlib.sha256(b"r").digest(),
                               "has space", seed)


    def test_emit_bad_size_refused(self):
        seed, _pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        for bad in (-1, "3", 3.0, True):
            with self.assertRaises(cn.CheckpointNoteError) as ctx:
                cn.emit_checkpoint(ORIGIN, bad, root, ORIGIN, seed)
            self.assertEqual(ctx.exception.code,
                             "checkpoint-size-malformed")

    def test_emit_bad_root_refused(self):
        seed, _pub = _keypair()
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            cn.emit_checkpoint(ORIGIN, 1, b"short", ORIGIN, seed)
        self.assertEqual(ctx.exception.code, "checkpoint-root-malformed")


class ParseVerifyTest(unittest.TestCase):
    def test_round_trip(self):
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 7, root, ORIGIN, seed)
        fields = cn.parse_checkpoint(note)
        self.assertEqual(fields["origin"], ORIGIN)
        self.assertEqual(fields["tree_size"], 7)
        self.assertEqual(fields["root_hash"], root)
        self.assertEqual(fields["extensions"], ())
        verified = cn.verify_checkpoint(note, [_vkey_for(ORIGIN, pub)])
        self.assertEqual(verified["verified_by"], [ORIGIN])

    def test_unknown_signature_ignored_when_known_verifies(self):
        # Unknown sigs are IGNORED, never failures: a note with one
        # unknown sig and one good known sig verifies.
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 2, root, ORIGIN, seed)
        lines = note.decode("utf-8").split("\n")
        sig_idx = next(i for i, ln in enumerate(lines)
                       if ln.startswith("\u2014"))
        body = lines[:sig_idx]
        text = ("\n".join(body) + "\n").encode("utf-8")
        evil_seed, evil_pub = _keypair()
        evil_id = cn.derive_key_id("evil.example/x",
                                  cn.SIG_TYPE_ED25519, evil_pub)
        evil_line = ("\u2014 evil.example/x " + base64.b64encode(
            evil_id + ed.sign(evil_seed, text)).decode())
        mixed = ("\n".join(body + [evil_line, lines[sig_idx], ""])
                 ).encode("utf-8")
        verified = cn.verify_checkpoint(mixed, [_vkey_for(ORIGIN, pub)])
        self.assertEqual(verified["verified_by"], [ORIGIN])

    def test_malformed_notes(self):
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 3, root, ORIGIN, seed)
        vkey = _vkey_for(ORIGIN, pub)
        bad_cases = [
            b"\xff\xfe binary",                       # not UTF-8
            b"line\x01with control\n\nsig\n",         # control char
            b"no trailing newline",                   # no final newline
            b"body only, no blank line\n"
            b"\u2014 name AQIDBA==\n",                # no separator
        ]
        for bad in bad_cases:
            with self.assertRaises(cn.CheckpointNoteError) as ctx:
                cn.parse_checkpoint(bad)
            self.assertEqual(ctx.exception.code,
                             "checkpoint-note-malformed",
                             "case %r" % (bad[:20],))

    def test_bad_field_grammar(self):
        seed, _pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 3, root, ORIGIN, seed)
        lines = note.decode("utf-8").split("\n")
        sig_idx = next(i for i, ln in enumerate(lines)
                       if ln.startswith("\u2014"))
        head, tail = lines[:sig_idx], lines[sig_idx:]

        def rebuild(body_lines):
            # Keep the blank separator line between body and sigs.
            return ("\n".join(body_lines + [""] + tail)).encode("utf-8")

        cases = [
            (["", "3", base64.b64encode(root).decode()],
             "checkpoint-origin-empty"),
            (["", "", ""], "checkpoint-origin-empty"),
            ([ORIGIN, "03", base64.b64encode(root).decode()],
             "checkpoint-size-malformed"),
            ([ORIGIN, "-1", base64.b64encode(root).decode()],
             "checkpoint-size-malformed"),
            ([ORIGIN, "3x", base64.b64encode(root).decode()],
             "checkpoint-size-malformed"),
            ([ORIGIN, "3", "not-base64!!"],
             "checkpoint-root-malformed"),
            ([ORIGIN, "3", base64.b64encode(b"short").decode()],
             "checkpoint-root-malformed"),
            ([ORIGIN, "3", base64.b64encode(root).decode(), ""],
             "checkpoint-extension-empty"),
        ]
        for body_lines, code in cases:
            with self.assertRaises(cn.CheckpointNoteError) as ctx:
                cn.parse_checkpoint(rebuild(body_lines))
            self.assertEqual(ctx.exception.code, code,
                             "body %r" % (body_lines,))

    def test_extension_lines_accepted_but_surfaced(self):
        # Extensions are legal per the spec but NOT RECOMMENDED and
        # not auditable: the parser surfaces them explicitly.
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 3, root, ORIGIN, seed)
        lines = note.decode("utf-8").split("\n")
        sig_idx = next(i for i, ln in enumerate(lines)
                       if ln.startswith("\u2014"))
        head, tail = lines[:sig_idx], lines[sig_idx:]
        forged = ("\n".join(head[:3] + ["ext: 1", ""] + tail)).encode()
        # The hand-added extension breaks the signature (expected):
        # parse still works and surfaces the extension.
        fields = cn.parse_checkpoint(forged)
        self.assertEqual(fields["extensions"], ("ext: 1",))

    def test_size_zero_round_trips(self):
        seed, pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        note = cn.emit_checkpoint(ORIGIN, 0, root, ORIGIN, seed)
        fields = cn.verify_checkpoint(note, [_vkey_for(ORIGIN, pub)])
        self.assertEqual(fields["tree_size"], 0)


class JournalTest(unittest.TestCase):
    def test_idempotent_reissue(self):
        journal = cn.CheckpointJournal()
        seed, _pub = _keypair()
        root = hashlib.sha256(b"r").digest()
        a = journal.issue(ORIGIN, 3, root, ORIGIN, seed)
        b = journal.issue(ORIGIN, 3, root, ORIGIN, seed)
        self.assertEqual(a, b)

    def test_equivocation_refused(self):
        journal = cn.CheckpointJournal()
        seed, _pub = _keypair()
        journal.issue(ORIGIN, 3, hashlib.sha256(b"r1").digest(),
                      ORIGIN, seed)
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            journal.issue(ORIGIN, 3, hashlib.sha256(b"r2").digest(),
                          ORIGIN, seed)
        self.assertEqual(ctx.exception.code, "checkpoint-inconsistent")

    def test_different_size_may_advance(self):
        journal = cn.CheckpointJournal()
        seed, _pub = _keypair()
        journal.issue(ORIGIN, 3, hashlib.sha256(b"r1").digest(),
                      ORIGIN, seed)
        note = journal.issue(ORIGIN, 4, hashlib.sha256(b"r2").digest(),
                             ORIGIN, seed)
        self.assertEqual(cn.parse_checkpoint(note)["tree_size"], 4)


class LogAdapterTest(unittest.TestCase):
    class _StubLog(object):
        def __init__(self, size, root):
            self._size = size
            self._root = root

        def current_root(self):
            return {"tree_size": self._size,
                    "root_hash": self._root.hex()}

    def test_checkpoint_binds_current_tree_head(self):
        seed, pub = _keypair()
        root = hashlib.sha256(b"real-tree").digest()
        note = cn.checkpoint_for_log(self._StubLog(9, root), ORIGIN,
                                     ORIGIN, seed)
        fields = cn.verify_checkpoint(note, [_vkey_for(ORIGIN, pub)])
        self.assertEqual(fields["tree_size"], 9)
        self.assertEqual(fields["root_hash"], root)

    def test_empty_log_refused(self):
        seed, _pub = _keypair()
        log = self._StubLog(0, hashlib.sha256(b"x").digest())
        with self.assertRaises(cn.CheckpointNoteError) as ctx:
            cn.checkpoint_for_log(log, ORIGIN, ORIGIN, seed)
        self.assertEqual(ctx.exception.code, "checkpoint-log-empty")


class TaxonomyPinTest(unittest.TestCase):
    def test_checkpoint_codes_mapped(self):
        from gov import decision_codes as dc
        for code in cn.CHECKPOINT_CODES:
            self.assertIn(code, dc.TAXONOMY)
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2018)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        # Wave-239 merge: re-pointed 695 -> 718 (23 new codes
        # across four lanes: 8 AAuth R3 + 6 claim-at-dispatch +
        # 3 refusal-oracle guard + 6 AER-1 provenance non-upgrade),
        # composed from the four lane commits by direct
        # byte-verification.
        # 667 = wave-237 merge pin; + 28 wave-238 merge codes (10 lane-A
        # C2SP checkpoint, 8 lane-B bundle-verify invariant,
        # 4 lane-C attested-vs-asserted, 6 lane-D corroboration);
        # re-pointed at merge. Lane-local lane-A pin was 677
        # (= 667 + 10 lane-A C2SP
        # checkpoint codes (checkpoint-origin-empty,
        # checkpoint-size-malformed, checkpoint-root-malformed,
        # checkpoint-extension-empty, checkpoint-note-malformed,
        # checkpoint-not-c2sp, checkpoint-known-signature-invalid,
        # checkpoint-no-trusted-signature, checkpoint-log-empty,
        # checkpoint-inconsistent), additive, zero deletions, zero
        # key collisions.


if __name__ == "__main__":
    unittest.main()
