"""Unit tests for gov.witness_consistency (wave-319 lane 3).

Seam-level coverage: note emission/cosigning, quorum counting, the
signed-note collision rules, freshness boundaries, proof-size binding,
error-vocabulary mapping, cross-tests against gov.checkpoint_note
(the note format must verify under the real parser), and the offline
verifier's optional-but-fail-closed witness-consistency stage.
"""

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from gov import witness_consistency as WC
from gov import checkpoint_note as CN
from gov.witness_log import WitnessLog
from gov.signing import Ed25519Signer
from gov import evidence_verify_offline as v
from gov import ed25519

NOW = 1798765432
SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
ORIGIN = "sasanam-witness-test/v1"


def _signer(seed):
    return Ed25519Signer(seed)


def _vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


def _op_vkeys():
    return [_vkey("op", _signer(SEED_OP))]


def _wit_vkeys():
    return {"w1": _vkey("w1", _signer(SEED_W1)),
            "w2": _vkey("w2", _signer(SEED_W2))}


def _log_with_notes(sizes=(3, 5)):
    signer = _signer(SEED_OP)
    log = WitnessLog(signer.public_key)
    notes = {}
    n = 0
    for size in sizes:
        while n < size:
            log.append(b"leaf-%d" % n)
            n += 1
        notes[size] = WC.issue_checkpoint_note(
            log, ORIGIN, "op", signer, timestamp=NOW - 100)
    return log, signer, notes


class TestNoteEmission(unittest.TestCase):
    def test_note_text_shape(self):
        text = WC.note_text(ORIGIN, 3, bytes(32), NOW)
        lines = text.decode("utf-8").split("\n")
        self.assertEqual(lines[0], ORIGIN)
        self.assertEqual(lines[1], "3")
        self.assertEqual(lines[2], base64.b64encode(bytes(32)).decode())
        self.assertEqual(lines[3], "timestamp %d" % NOW)

    def test_issued_note_verifies_under_checkpoint_note(self):
        # The cross-test: my emitted notes must verify under the real
        # C2SP parser (no bespoke format).
        log, signer, notes = _log_with_notes()
        fields = CN.verify_checkpoint(notes[3], _op_vkeys())
        self.assertEqual(fields["tree_size"], 3)
        self.assertEqual(fields["origin"], ORIGIN)
        self.assertEqual(fields["verified_by"], ["op"])

    def test_empty_log_refuses(self):
        signer = _signer(SEED_OP)
        log = WitnessLog(signer.public_key)
        with self.assertRaises(Exception):
            WC.issue_checkpoint_note(log, ORIGIN, "op", signer,
                                     timestamp=NOW)

    def test_cosign_appends_and_verifies(self):
        log, signer, notes = _log_with_notes()
        note = WC.cosign_note(notes[5], "w1", _signer(SEED_W1))
        fields = CN.verify_checkpoint(
            note, _op_vkeys() + [_vkey("w1", _signer(SEED_W1))])
        self.assertEqual(sorted(fields["verified_by"]), ["op", "w1"])

    def test_note_text_of_agrees_with_parser(self):
        # My _note_text_of must recover exactly the bytes the real
        # parser verifies signatures over (else cosignatures would
        # sign the wrong preimage).
        log, signer, notes = _log_with_notes()
        note = WC.cosign_note(notes[5], "w1", _signer(SEED_W1))
        recovered = WC._note_text_of(note)
        # A signature over `recovered` with a fresh key must verify
        # when appended as a line: proves the preimage is right.
        line = WC._signature_line("w2", _signer(SEED_W2), recovered)
        note2 = note + line.encode("utf-8") + b"\n"
        fields = CN.verify_checkpoint(
            note2, _op_vkeys() + [_vkey("w1", _signer(SEED_W1)),
                                 _vkey("w2", _signer(SEED_W2))])
        self.assertEqual(sorted(fields["verified_by"]),
                         ["op", "w1", "w2"])


class TestQuorum(unittest.TestCase):
    def _cosigned(self, k):
        log, signer, notes = _log_with_notes()
        note = notes[5]
        seeds = [SEED_W1, SEED_W2]
        for i in range(k):
            note = WC.cosign_note(note, "w%d" % (i + 1),
                                  _signer(seeds[i]))
        return note

    def test_quorum_met(self):
        out = WC.require_cosignatures(
            self._cosigned(2), operator_vkeys=_op_vkeys(),
            witness_vkeys=_wit_vkeys(), quorum_k=2)
        self.assertEqual(out["cosignatures"], 2)
        self.assertEqual(out["witnesses"], ["w1", "w2"])

    def test_quorum_unmet(self):
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.require_cosignatures(
                self._cosigned(1), operator_vkeys=_op_vkeys(),
                witness_vkeys=_wit_vkeys(), quorum_k=2)
        self.assertEqual(ctx.exception.code, "witness-quorum-unmet")

    def test_unknown_key_ignored_not_counted(self):
        # A cosignature from an UNCONFIGURED key is ignored per the
        # signed-note collision rules -- it neither counts nor refuses.
        log, signer, notes = _log_with_notes()
        note = WC.cosign_note(notes[5], "mallory",
                              _signer(bytes([9] * 32)))
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.require_cosignatures(
                note, operator_vkeys=_op_vkeys(),
                witness_vkeys=_wit_vkeys(), quorum_k=1)
        self.assertEqual(ctx.exception.code, "witness-quorum-unmet")

    def test_operator_name_does_not_count(self):
        # The operator's own key in the witness set must not inflate
        # the quorum.
        log, signer, notes = _log_with_notes()
        vkeys = dict(_wit_vkeys())
        vkeys["op"] = _op_vkeys()[0]
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.require_cosignatures(
                notes[5], operator_vkeys=_op_vkeys(),
                witness_vkeys=vkeys, quorum_k=1)
        self.assertEqual(ctx.exception.code, "witness-quorum-unmet")

    def test_bad_quorum_k_is_policy_malformed(self):
        log, signer, notes = _log_with_notes()
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.require_cosignatures(
                notes[5], operator_vkeys=_op_vkeys(),
                witness_vkeys=_wit_vkeys(), quorum_k=0)
        self.assertEqual(ctx.exception.code, "witness-policy-malformed")


class TestFreshness(unittest.TestCase):
    def _fields(self, age):
        log, signer, notes = _log_with_notes()
        note = WC.issue_checkpoint_note(log, ORIGIN, "op", signer,
                                        timestamp=NOW - age)
        return CN.verify_checkpoint(note, _op_vkeys())

    def test_fresh(self):
        out = WC.check_freshness(self._fields(100), now=NOW, max_age=3600)
        self.assertEqual(out["age"], 100)

    def test_boundary_age_equals_max(self):
        out = WC.check_freshness(self._fields(3600), now=NOW, max_age=3600)
        self.assertEqual(out["age"], 3600)

    def test_stale(self):
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.check_freshness(self._fields(3601), now=NOW, max_age=3600)
        self.assertEqual(ctx.exception.code, "witness-checkpoint-stale")

    def test_future(self):
        log, signer = _log_with_notes()[0:2]
        note = WC.issue_checkpoint_note(log, ORIGIN, "op", signer,
                                        timestamp=NOW + 1)
        fields = CN.verify_checkpoint(note, _op_vkeys())
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.check_freshness(fields, now=NOW, max_age=3600)
        self.assertEqual(ctx.exception.code, "witness-checkpoint-stale")

    def test_timeless_note_refuses(self):
        # A note with no timestamp extension cannot be
        # freshness-checked -- fail closed, never "fresh by default".
        text = ("%s\n3\n%s\n" % (
            ORIGIN, base64.b64encode(bytes(32)).decode())).encode("utf-8")
        signer = _signer(SEED_OP)
        sig = signer.sign(text)
        key_id = CN.derive_key_id("op", CN.SIG_TYPE_ED25519,
                                  signer.public_key)
        note = (text + b"\n" + ("\u2014 op " + base64.b64encode(
            key_id + sig).decode("ascii") + "\n").encode("utf-8"))
        fields = CN.verify_checkpoint(note, _op_vkeys())
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.check_freshness(fields, now=NOW, max_age=3600)
        self.assertEqual(ctx.exception.code, "witness-checkpoint-stale")


class TestConsistency(unittest.TestCase):
    def test_growth_verifies(self):
        log, _, notes = _log_with_notes()
        proof = log.consistency_proof(3, 5)["hashes"]
        out = WC.verify_checkpoint_consistency(
            notes[3], notes[5], proof, operator_vkeys=_op_vkeys())
        self.assertTrue(out["consistent"])

    def test_same_size_same_root_is_consistent(self):
        _, _, notes = _log_with_notes()
        out = WC.verify_checkpoint_consistency(
            notes[3], notes[3], [], operator_vkeys=_op_vkeys())
        self.assertTrue(out["consistent"])

    def test_old_greater_than_new_refuses(self):
        log, _, notes = _log_with_notes()
        proof = log.consistency_proof(3, 5)["hashes"]
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.verify_checkpoint_consistency(
                notes[5], notes[3], proof, operator_vkeys=_op_vkeys())
        self.assertEqual(ctx.exception.code, "witness-consistency-invalid")

    def test_proof_size_bound(self):
        # A proof for 3->5 presented for 3->4 refuses even if the
        # hashes look plausible (sizes come from verified notes).
        log, _, notes = _log_with_notes()
        proof = log.consistency_proof(3, 5)["hashes"]
        log4, signer4, _ = _log_with_notes(sizes=(4,))
        note4 = WC.issue_checkpoint_note(log4, ORIGIN, "op", signer4,
                                         timestamp=NOW)
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.verify_checkpoint_consistency(
                notes[3], note4, proof, operator_vkeys=_op_vkeys())
        self.assertEqual(ctx.exception.code, "witness-consistency-invalid")


class TestGossip(unittest.TestCase):
    def _view(self, name, seed, tag, size=5):
        signer = _signer(seed)
        log = WitnessLog(signer.public_key)
        for i in range(size):
            log.append(tag + b"-%d" % i)
        return {"witness_name": name,
                "note": WC.issue_checkpoint_note(log, ORIGIN, name,
                                                 signer, timestamp=NOW)}

    def test_agreeing_views(self):
        views = [self._view("w1", SEED_W1, b"leaf"),
                 self._view("w2", SEED_W2, b"leaf")]
        out = WC.gossip(views, witness_vkeys=_wit_vkeys())
        self.assertEqual(out["max_tree_size"], 5)

    def test_different_sizes_agree(self):
        # Views at different sizes are not a conflict (growth is the
        # auditor's own consistency check, not gossip's).
        views = [self._view("w1", SEED_W1, b"leaf", size=5),
                 self._view("w2", SEED_W2, b"leaf", size=3)]
        out = WC.gossip(views, witness_vkeys=_wit_vkeys())
        self.assertEqual(out["max_tree_size"], 5)

    def test_unconfigured_view_refuses_loud(self):
        views = [self._view("w1", SEED_W1, b"leaf"),
                 self._view("w2", SEED_W2, b"leaf"),
                 self._view("mallory", bytes([9] * 32), b"leaf")]
        with self.assertRaises(WC.WitnessConsistencyError) as ctx:
            WC.gossip(views, witness_vkeys=_wit_vkeys())
        self.assertEqual(ctx.exception.code, "witness-policy-malformed")


# ---------------------------------------------------------------------------
# The offline verifier's optional-but-fail-closed stage.
# ---------------------------------------------------------------------------

ANCHOR_SEED = "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6"
EV_SEED = "11" * 32
TSA_SEED = "22" * 32
BUNDLE_BYTES = b'{"evidence":"witness-consistency-unit"}\n'
PREDICATE_TYPE = "https://sasanam.dev/evidence-predicate/v1"
NOW_DT = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)


def _v_signer(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    keyid = hashlib.sha256(pub).hexdigest()[:16]

    class _S(object):
        def keyid(self):
            return keyid

        def pubkey_hex(self):
            return pub.hex()

        def sign(self, msg):
            return ed25519.sign(seed, msg)

    return _S()


def _seal(payload, ptype, signers):
    msg = v.pae(ptype, payload)
    return {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": ptype,
        "signatures": [
            {"keyid": s.keyid(),
             "sig": base64.b64encode(s.sign(msg)).decode("ascii")}
            for s in signers
        ],
    }


def _wc_bundle(with_evidence):
    """A minimal bundle whose policy configures witness_consistency."""
    ev = _v_signer(EV_SEED)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                .hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = v.canonical(stmt)
    anchor = _v_signer(ANCHOR_SEED)
    # The witness world: operator + 2 witnesses, notes at 3 and 5.
    op = _signer(SEED_OP)
    log = WitnessLog(op.public_key)
    for i in range(3):
        log.append(b"leaf-%d" % i)
    ts = int(NOW_DT.timestamp())
    old = WC.issue_checkpoint_note(log, ORIGIN, "op", op,
                                   timestamp=ts - 100)
    for i in range(3, 5):
        log.append(b"leaf-%d" % i)
    head = WC.issue_checkpoint_note(log, ORIGIN, "op", op, timestamp=ts)
    head = WC.cosign_note(head, "w1", _signer(SEED_W1))
    head = WC.cosign_note(head, "w2", _signer(SEED_W2))
    policy = {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "wc-unit-policy",
        "expires": "2026-10-13T12:00:00Z",
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": ev.keyid(), "pubkey_hex": ev.pubkey_hex()}],
        },
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "timestamp_authorities": [],
        "witness_consistency": {
            "operator_vkeys": _op_vkeys(),
            "witness_vkeys": _wit_vkeys(),
            "quorum_k": 2,
            "max_checkpoint_age": 3600,
            "accepted_head": {
                "note_b64": base64.b64encode(old).decode("ascii")},
        },
    }
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": _seal(payload, v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        "policy": _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                        [anchor]),
        "timestamps": [],
    }
    if with_evidence:
        vb["consistency_evidence"] = {
            "head_note_b64": base64.b64encode(head).decode("ascii"),
            "consistency_proof": log.consistency_proof(3, 5)["hashes"],
        }
    return vb


def json_loads_policy(vb):
    import json
    return json.loads(base64.b64decode(
        vb["policy"]["payload"]).decode("utf-8"))


class TestVerifierWiring(unittest.TestCase):
    def _clock(self):
        return v.FixedClock("unit-clock", NOW_DT)

    def test_mode_off_keeps_legacy_behavior(self):
        # No witness_consistency section: byte-identical legacy path.
        vb = _wc_bundle(with_evidence=False)
        del vb["policy"]  # rebuild without the wc section below
        ev = _v_signer(EV_SEED)
        stmt = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact.bin",
                         "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                    .hexdigest()}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": {"window": "2026-10-03T00:00:00Z"},
        }
        payload = v.canonical(stmt)
        anchor = _v_signer(ANCHOR_SEED)
        policy = {
            "version": "sasanam-verification-policy/v1",
            "policy_id": "wc-unit-policy-legacy",
            "expires": "2026-10-13T12:00:00Z",
            "required_predicate_type": PREDICATE_TYPE,
            "required_predicate_claims": ["window"],
            "evidence_signing": {
                "threshold": 1,
                "keys": [{"keyid": ev.keyid(),
                          "pubkey_hex": ev.pubkey_hex()}],
            },
            "observer_timestamps": {"min": 0, "max_age_hours": 168},
            "timestamp_authorities": [],
        }
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [anchor])
        rep = v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(rep["status"], "VALID")
        self.assertIsNone(rep["witness_consistency"])
        steps = [c["step"] for c in rep["checks"]]
        self.assertNotIn("witness-consistency", steps)

    def test_configured_without_evidence_refuses(self):
        vb = _wc_bundle(with_evidence=False)
        with self.assertRaises(v.VerificationError) as ctx:
            v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(ctx.exception.code, "witness-consistency-missing")

    def test_configured_with_evidence_passes(self):
        vb = _wc_bundle(with_evidence=True)
        rep = v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(rep["status"], "VALID")
        self.assertEqual(rep["witness_consistency"]["cosignatures"], 2)
        self.assertEqual(
            rep["witness_consistency"]["growth"]["new_size"], 5)
        steps = [c["step"] for c in rep["checks"]]
        self.assertIn("witness-consistency", steps)

    def test_bad_policy_section_is_policy_malformed(self):
        vb = _wc_bundle(with_evidence=True)
        pol = json_loads_policy(vb)
        pol["witness_consistency"]["quorum_k"] = 0
        vb["policy"] = _seal(v.canonical(pol), v.POLICY_PAYLOAD_TYPE,
                             [_v_signer(ANCHOR_SEED)])
        with self.assertRaises(v.VerificationError) as ctx:
            v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(ctx.exception.code, "POLICY_MALFORMED")

    def test_no_accepted_head_skips_growth(self):
        # accepted_head is optional: quorum + freshness still enforced,
        # growth is None (steady state, no proof needed).
        vb = _wc_bundle(with_evidence=True)
        pol = json_loads_policy(vb)
        del pol["witness_consistency"]["accepted_head"]
        vb["policy"] = _seal(v.canonical(pol), v.POLICY_PAYLOAD_TYPE,
                             [_v_signer(ANCHOR_SEED)])
        # Evidence without a proof (steady state needs none).
        del vb["consistency_evidence"]["consistency_proof"]
        rep = v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(rep["status"], "VALID")
        self.assertIsNone(rep["witness_consistency"]["growth"])
        self.assertEqual(rep["witness_consistency"]["cosignatures"], 2)

    def test_transplanted_proof_refuses(self):
        # CVE-2026-22703: the growth proof must bind the receipt's
        # checkpoint. A proof whose old note does not match the anchored
        # receipt checkpoint refuses witness-consistency-invalid.
        import gov.witness_consistency as wc
        # Build a second, independent log and take its head as the
        # "accepted" old note -- it will NOT match the receipt's
        # checkpoint (which anchors the real log's head).
        from gov.witness_log import WitnessLog
        other = WitnessLog(_signer(SEED_OP).public_key)
        other.append(b"other-leaf")
        other_note = wc.issue_checkpoint_note(
            other, "test-origin", "op", _signer(SEED_OP),
            timestamp=int(NOW_DT.timestamp()))
        vb = _wc_bundle(with_evidence=True)
        pol = json_loads_policy(vb)
        pol["witness_consistency"]["accepted_head"] = {
            "note_b64": base64.b64encode(other_note).decode("ascii")}
        vb["policy"] = _seal(v.canonical(pol), v.POLICY_PAYLOAD_TYPE,
                             [_v_signer(ANCHOR_SEED)])
        with self.assertRaises(v.VerificationError) as ctx:
            v.verify(BUNDLE_BYTES, vb, time_source=self._clock())
        self.assertEqual(ctx.exception.code,
                         "witness-consistency-invalid")


if __name__ == "__main__":
    unittest.main()
