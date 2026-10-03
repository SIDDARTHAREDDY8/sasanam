"""Unit tests for gov/key_succession.py (wave-293 lane 3).

The declared, phased key-rotation ceremony: none -> preparing ->
prepared -> completing -> completed, with signed key-succession/v1
records, a mandatory bounded overlap window, union-of-trust during
overlap, and LOUD revocation events on retired-key reuse.

Red-first: the eval battery evals/w293_key_succession_probes.py broke
10+ probes against the pristine base (feature absent) before this
module existed; these unit tests pin the seam contract.
"""

import copy
import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import key_succession as ks
from gov.key_succession import KeySuccession, KeySuccessionError


SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(33, 65))
SEED_C = bytes(range(65, 97))


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _fresh():
    return KeySuccession("authority-1", _pub(SEED_A))


def _to_prepared():
    c = _fresh()
    c.begin(_pub(SEED_B), old_seed=SEED_A)
    c.announce(old_seed=SEED_A)
    return c


def _to_completing(window=3600):
    c = _to_prepared()
    c.advance(old_seed=SEED_A, overlap_window_seconds=window)
    return c


class CeremonyFlowTest(unittest.TestCase):
    def test_full_ceremony_reaches_completed(self):
        c = _to_completing()
        c.finalize(old_seed=SEED_A)
        self.assertEqual(c.phase, "completed")

    def test_phases_are_exact_and_ordered(self):
        c = _fresh()
        self.assertEqual(c.phase, "none")
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        self.assertEqual(c.phase, "preparing")
        c.announce(old_seed=SEED_A)
        self.assertEqual(c.phase, "prepared")
        c.advance(old_seed=SEED_A, overlap_window_seconds=60)
        self.assertEqual(c.phase, "completing")
        c.finalize(old_seed=SEED_A)
        self.assertEqual(c.phase, "completed")

    def test_begin_record_format_bound(self):
        c = _fresh()
        env = c.begin(_pub(SEED_B), old_seed=SEED_A)
        self.assertEqual(env["record"]["record_format"],
                         "sasanam-key-succession/1")
        self.assertEqual(env["record"]["phase_to"], "preparing")
        self.assertEqual(env["record"]["new_pubkey"], _pub(SEED_B))

    def test_transition_records_verify_under_old_key(self):
        c = _fresh()
        for name in ("begin", "announce"):
            env = {"begin": lambda: c.begin(_pub(SEED_B), old_seed=SEED_A),
                   "announce": lambda: c.announce(old_seed=SEED_A)}[name]()
            self.assertIs(c.verify_transition(env), True)
        env = c.advance(old_seed=SEED_A, overlap_window_seconds=60)
        self.assertIs(c.verify_transition(env), True)
        env = c.finalize(old_seed=SEED_A)
        self.assertIs(c.verify_transition(env), True)

    def test_verify_transition_returns_bool_not_raises(self):
        # wave-243 lesson: pin the contract -- verify_transition
        # returns True on success (asserted with `is True`) and
        # refuses CODED on failure (never a bare False).
        c = _fresh()
        env = c.begin(_pub(SEED_B), old_seed=SEED_A)
        self.assertIs(c.verify_transition(env), True)
        bad = copy.deepcopy(env)
        bad["record"]["phase_to"] = "completing"
        with self.assertRaises(KeySuccessionError) as ctx:
            c.verify_transition(bad)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")


class PhaseSkipTest(unittest.TestCase):
    def test_skip_none_to_completing_refused(self):
        c = _fresh()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.advance(old_seed=SEED_A, overlap_window_seconds=60)
        self.assertEqual(ctx.exception.code, "keysuccession-phase-skipped")

    def test_skip_preparing_to_completed_refused(self):
        c = _fresh()
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        with self.assertRaises(KeySuccessionError) as ctx:
            c.finalize(old_seed=SEED_A)
        self.assertEqual(ctx.exception.code, "keysuccession-phase-skipped")

    def test_skip_prepared_to_completed_refused(self):
        c = _to_prepared()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.finalize(old_seed=SEED_A)
        self.assertEqual(ctx.exception.code, "keysuccession-phase-skipped")

    def test_double_begin_is_invalid_transition(self):
        c = _fresh()
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        with self.assertRaises(KeySuccessionError) as ctx:
            c.begin(_pub(SEED_C), old_seed=SEED_A)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")


class WindowTest(unittest.TestCase):
    def test_missing_window_refused(self):
        c = _to_prepared()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.advance(old_seed=SEED_A, overlap_window_seconds=None)
        self.assertEqual(ctx.exception.code, "keysuccession-window-missing")

    def test_unbounded_window_refused(self):
        c = _to_prepared()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.advance(old_seed=SEED_A,
                      overlap_window_seconds=10 ** 12)  # ~31k years
        self.assertEqual(ctx.exception.code, "keysuccession-window-missing")

    def test_nonpositive_window_refused(self):
        c = _to_prepared()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.advance(old_seed=SEED_A, overlap_window_seconds=0)
        self.assertEqual(ctx.exception.code, "keysuccession-window-missing")

    def test_window_recorded_on_advance(self):
        c = _to_completing(window=600)
        self.assertEqual(c.overlap_window_seconds, 600)


class UnionOfTrustTest(unittest.TestCase):
    def test_old_key_material_verifies_during_overlap(self):
        c = _to_completing()
        payload = {"kind": "in-flight", "n": 1}
        sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "old-key"}
        ok, detail = c.verify_envelope(env)
        self.assertTrue(ok)
        self.assertEqual(detail["signed_by"], "old-key")
        self.assertIs(detail["during_overlap"], True)

    def test_new_key_material_verifies_during_overlap(self):
        c = _to_completing()
        payload = {"kind": "new-issuance", "n": 2}
        sig = ed25519.sign(SEED_B, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "new-key"}
        ok, detail = c.verify_envelope(env)
        self.assertTrue(ok)
        self.assertEqual(detail["signed_by"], "new-key")

    def test_old_key_use_during_overlap_emits_signed_note(self):
        c = _to_completing()
        captured = []
        original = ks._EMIT
        ks._EMIT = lambda event, fields: captured.append((event, fields))
        try:
            payload = {"kind": "in-flight", "n": 3}
            sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
            env = {"record": payload, "signature": sig, "keyid": "old-key"}
            ok, detail = c.verify_envelope(env, overlap_note="in-flight-42")
        finally:
            ks._EMIT = original
        self.assertTrue(ok)
        self.assertIs(detail["note_emitted"], True)
        self.assertTrue(any(e == "keysuccession-overlap-use"
                            for e, _ in captured))
        # The note is a structured declaration emitted to the audit
        # sink (the sink event is the signed note -- the audit log is
        # HMAC-chained); the returned envelope is the declaration, not
        # a transition record.
        note = detail["overlap_note"]
        self.assertEqual(note["record"]["record_format"],
                         "sasanam-key-succession-overlap-note/1")
        self.assertEqual(note["record"]["key_used"], "old-key")
        self.assertEqual(note["record"]["declared"], "in-flight-42")
        self.assertEqual(note["record"]["authority_id"], "authority-1")

    def test_old_key_after_overlap_expiry_is_revocation_event(self):
        c = _to_completing(window=600)
        payload = {"kind": "late", "n": 4}
        sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "old-key"}
        with self.assertRaises(KeySuccessionError) as ctx:
            c.verify_envelope(env, checked_at=1000 + 601)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-retired-reuse")
        self.assertTrue(ctx.exception.is_revocation_event)

    def test_retired_reuse_after_completed_is_revocation_event(self):
        c = _to_completing()
        c.finalize(old_seed=SEED_A)
        payload = {"kind": "post-retirement", "n": 5}
        sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "old-key"}
        with self.assertRaises(KeySuccessionError) as ctx:
            c.verify_envelope(env)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-retired-reuse")
        self.assertTrue(ctx.exception.is_revocation_event)

    def test_new_key_still_verifies_after_completed(self):
        c = _to_completing()
        c.finalize(old_seed=SEED_A)
        payload = {"kind": "new-issuance", "n": 6}
        sig = ed25519.sign(SEED_B, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "new-key"}
        ok, detail = c.verify_envelope(env)
        self.assertTrue(ok)
        self.assertEqual(detail["signed_by"], "new-key")

    def test_successor_cannot_sign_before_completing(self):
        c = _to_prepared()
        payload = {"kind": "early", "n": 7}
        sig = ed25519.sign(SEED_B, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "new-key"}
        with self.assertRaises(KeySuccessionError) as ctx:
            c.verify_envelope(env)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")

    def test_stranger_key_refused_coded(self):
        c = _to_completing()
        payload = {"kind": "stranger", "n": 8}
        sig = ed25519.sign(SEED_C, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": "stranger"}
        with self.assertRaises(KeySuccessionError) as ctx:
            c.verify_envelope(env)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")


class ForgeryTest(unittest.TestCase):
    def test_forged_transition_record_refused(self):
        c = _fresh()
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        rec = c._build_record("preparing", "prepared", 1001)
        forged = {"record": rec, "signature": None, "keyid": "old"}
        forged["signature"] = ed25519.sign(SEED_C,
                                           ks._canonical(rec)).hex()
        with self.assertRaises(KeySuccessionError) as ctx:
            c.announce(record=forged)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")

    def test_tampered_record_refused(self):
        c = _fresh()
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        env = c.announce(old_seed=SEED_A)
        tampered = copy.deepcopy(env)
        tampered["record"]["new_pubkey"] = _pub(SEED_C)
        c2 = _fresh()
        c2.begin(_pub(SEED_B), old_seed=SEED_A)
        with self.assertRaises(KeySuccessionError) as ctx:
            c2.announce(record=tampered)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")

    def test_replayed_record_refused(self):
        c = _fresh()
        c.begin(_pub(SEED_B), old_seed=SEED_A)
        env = c.announce(old_seed=SEED_A)
        with self.assertRaises(KeySuccessionError) as ctx:
            c.announce(record=env)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")

    def test_from_records_replays_auditor_view(self):
        c = _to_completing()
        recs = [c.begin_record, c.announce_record, c.advance_record]
        c2 = KeySuccession.from_records("authority-1", _pub(SEED_A), recs)
        self.assertEqual(c2.phase, "completing")
        self.assertEqual(c2.overlap_window_seconds, 3600)
        self.assertEqual(c2.new_pubkey, _pub(SEED_B))

    def test_malformed_pubkey_refused_coded(self):
        with self.assertRaises(KeySuccessionError) as ctx:
            KeySuccession("authority-1", "not-hex")
        self.assertEqual(ctx.exception.code,
                         "keysuccession-invalid-transition")


class SinkIsolationTest(unittest.TestCase):
    def test_broken_overlap_sink_does_not_break_verification(self):
        c = _to_completing()
        original = ks._EMIT
        def _boom(event):
            raise RuntimeError("sink down")
        try:
            ks._EMIT = _boom
            payload = {"kind": "in-flight", "n": 9}
            sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
            env = {"record": payload, "signature": sig, "keyid": "old-key"}
            ok, detail = c.verify_envelope(env, overlap_note="x")
            self.assertTrue(ok)
            self.assertIs(detail["note_emitted"], False)
        finally:
            ks._EMIT = original


class RegistryWiringTest(unittest.TestCase):
    def test_registry_rotation_ceremony(self):
        from gov import revocation_status
        reg = revocation_status.RevocationRegistry("reg-1", SEED_A)
        old_pub = reg.registry_pubkey_hex()
        succession = reg.begin_key_rotation(SEED_B)
        self.assertEqual(succession.phase, "prepared")
        self.assertIs(reg.key_succession, succession)
        reg.advance_key_rotation(600)
        # New registry material is successor-signed during completing.
        cred = reg.issue("cred-x", _pub(SEED_A), 1000, 2000)
        self.assertEqual(reg.registry_pubkey_hex(), _pub(SEED_B))
        reg.finalize_key_rotation()
        self.assertEqual(succession.phase, "completed")
        # Old registry key material is a revocation event now.
        payload = {"format": "sasanam-revocation-status/1",
                   "registry_id": "reg-1", "rid": "cred-x",
                   "state": "valid", "issued_at": 1000}
        sig = ed25519.sign(SEED_A, ks._canonical(payload)).hex()
        env = {"record": payload, "signature": sig, "keyid": old_pub}
        with self.assertRaises(KeySuccessionError) as ctx:
            succession.verify_envelope(env)
        self.assertEqual(ctx.exception.code,
                         "keysuccession-retired-reuse")

    def test_double_begin_refused(self):
        from gov import revocation_status
        reg = revocation_status.RevocationRegistry("reg-2", SEED_A)
        reg.begin_key_rotation(SEED_B)
        with self.assertRaises(revocation_status.RevocationError):
            reg.begin_key_rotation(SEED_C)


class DecisionCodeTest(unittest.TestCase):
    def test_new_codes_registered(self):
        from gov import decision_codes
        for code in ("keysuccession-phase-skipped",
                     "keysuccession-window-missing",
                     "keysuccession-retired-reuse",
                     "keysuccession-invalid-transition"):
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_pin_is_1727(self):
        from gov import decision_codes
        import re as _re
        src = open(os.path.join(os.path.dirname(__file__), "..",
                                "gov", "decision_codes.py")).read()
        codes = _re.findall(r"\"code\":\s*'([a-z][a-z0-9-_.]*)'", src)
        self.assertEqual(len(codes), 1878)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        self.assertEqual(len(set(codes)), 1878)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        self.assertEqual(codes, sorted(codes))


if __name__ == "__main__":
    unittest.main()
