"""Unit tests for gov/timestamp_authority.py (wave-287 lane 6).

Deterministic: explicit gen_time/nonce everywhere; no wall-clock
equality assertions (future-skew tests pin `now` explicitly).
"""
import os
import tempfile
import unittest

from gov import ed25519 as _ed25519
from gov import evidence_anchor as _ea
from gov import evidence_receipt as _er
from gov import timestamp_authority as tsa

TAXONOMY_PIN = 2052 # Wave-287 lane 6: pin 1660 -> 1667 (+7 tsa-*).; Wave-287 merge: pin 1667 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*); Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



TSA_SEED = bytes(range(32))
TSA_PUB = _ed25519.publickey(TSA_SEED).hex()
TSA_KEYID = "wave287-tsa-test-key"

OP_SEED = bytes([0xA5] * 32)
OP_PUB = _ed25519.publickey(OP_SEED).hex()

ORIGIN = "test-log"
SIZE = 7
ROOT = "ab" * 32
OP_SIG = "cd" * 64
GEN = 1780000000  # fixed, deterministic
NONCE = "01" * 16  # 16 bytes


def _checkpoint(gen_time=GEN, nonce=NONCE):
    return {"origin": ORIGIN, "size": SIZE, "root": ROOT,
            "operator_sig": OP_SIG}


def _issue(gen_time=GEN, nonce=NONCE, **kw):
    args = dict(operator_sig_hex=OP_SIG, origin=ORIGIN, size=SIZE,
                root_hex=ROOT, nonce=nonce, tsa_seed=TSA_SEED,
                tsa_keyid=TSA_KEYID, gen_time=gen_time)
    args.update(kw)
    return tsa.issue_token(**args)


class TestIssueVerifyRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        token = _issue()
        self.assertEqual(token["token_format"], tsa.TOKEN_FORMAT)
        payload = tsa.verify_token(token, TSA_PUB, now=GEN + 10,
                                   expected_nonce=NONCE)
        self.assertEqual(payload["origin"], ORIGIN)
        self.assertEqual(payload["size"], SIZE)
        self.assertEqual(payload["root"], ROOT)
        self.assertEqual(payload["genTime"], GEN)
        self.assertEqual(payload["nonce"], NONCE)
        self.assertEqual(payload["v"], 1)
        self.assertRegex(payload["messageImprint"], r"^[0-9a-f]{64}$")

    def test_generated_nonce_has_16_bytes(self):
        token = tsa.issue_token(operator_sig_hex=OP_SIG, origin=ORIGIN,
                                size=SIZE, root_hex=ROOT, tsa_seed=TSA_SEED,
                                tsa_keyid=TSA_KEYID, gen_time=GEN)
        self.assertGreaterEqual(len(bytes.fromhex(token["payload"]["nonce"])),
                                16)
        # and it verifies without an expected nonce
        tsa.verify_token(token, TSA_PUB, now=GEN)

    def test_imprint_binds_operator_signature(self):
        imprint = tsa._compute_imprint(ORIGIN, SIZE, ROOT, OP_SIG)
        other = tsa._compute_imprint(ORIGIN, SIZE, ROOT, "ef" * 64)
        self.assertNotEqual(imprint, other)
        # against the documented formula
        import hashlib
        want = hashlib.sha256(
            bytes.fromhex(ROOT) + SIZE.to_bytes(8, "big")
            + hashlib.sha256(ORIGIN.encode()).digest()
            + hashlib.sha256(bytes.fromhex(OP_SIG)).digest()).hexdigest()
        self.assertEqual(imprint, want)

    def test_audit_emit(self):
        events = []
        tsa.set_emit(events.append)
        try:
            _issue()
        finally:
            tsa.set_emit(None)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "tsa-token-issued")
        self.assertEqual(ev["origin"], ORIGIN)
        self.assertEqual(ev["size"], SIZE)
        self.assertEqual(ev["genTime"], GEN)
        # digests/ids only: no seed, no signature bytes
        self.assertNotIn("tsa_seed", ev)


class TestGenTimeValidation(unittest.TestCase):
    def test_future_refused(self):
        token = _issue(gen_time=GEN)
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN - 1000)
        self.assertEqual(cm.exception.code, "tsa-gentime-in-future")

    def test_future_skew_boundary(self):
        token = _issue(gen_time=GEN + 300)
        tsa.verify_token(token, TSA_PUB, now=GEN)  # exactly at skew: ok
        token2 = _issue(gen_time=GEN + 301)
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token2, TSA_PUB, now=GEN)
        self.assertEqual(cm.exception.code, "tsa-gentime-in-future")

    def test_non_int_gentime_malformed(self):
        token = _issue()
        token["payload"]["genTime"] = "1780000000"
        # signature covers the tampered payload, but shape check fails
        # first -> malformed (fail closed either way)
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN + 100)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_zero_gentime_rejected_at_issue(self):
        with self.assertRaises(tsa.TsaError) as cm:
            _issue(gen_time=0)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_tampered_zero_gentime_is_signature_invalid(self):
        # Any genTime change after issuance breaks the TSA signature;
        # the tamper is caught before the value check, which is correct:
        # a "validly signed zero genTime" cannot exist because issuance
        # refuses zero.
        token = _issue()
        token["payload"]["genTime"] = 0
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN)
        self.assertEqual(cm.exception.code, "tsa-signature-invalid")

    def test_issue_rejects_bad_gen_time(self):
        for bad in (True, -5, "x", 1.5):
            with self.assertRaises(tsa.TsaError, msg=repr(bad)) as cm:
                _issue(gen_time=bad)
            self.assertEqual(cm.exception.code, "tsa-token-malformed")


class TestNonceBinding(unittest.TestCase):
    def test_wrong_expected_nonce(self):
        token = _issue()
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN + 10,
                             expected_nonce="ff" * 16)
        self.assertEqual(cm.exception.code, "tsa-nonce-mismatch")

    def test_short_nonce_rejected_at_issue(self):
        with self.assertRaises(tsa.TsaError) as cm:
            _issue(nonce="abcd")  # 2 bytes < 16
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_non_hex_nonce_rejected(self):
        with self.assertRaises(tsa.TsaError) as cm:
            _issue(nonce="zz" * 16)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")


class TestTimeForgery(unittest.TestCase):
    def test_tampered_gentime_signature_invalid(self):
        token = _issue()
        # re-sign is impossible without the TSA seed; any byte change in
        # the payload breaks the TSA signature
        token["payload"]["genTime"] = GEN - 86400
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN + 100)
        self.assertEqual(cm.exception.code, "tsa-signature-invalid")

    def test_tampered_imprint_signature_invalid(self):
        token = _issue()
        token["payload"]["messageImprint"] = "00" * 32
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN + 100)
        self.assertEqual(cm.exception.code, "tsa-signature-invalid")

    def test_wrong_tsa_key_signature_invalid(self):
        token = _issue()
        other_pub = _ed25519.publickey(bytes([7] * 32)).hex()
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, other_pub, now=GEN + 100)
        self.assertEqual(cm.exception.code, "tsa-signature-invalid")


class TestLedgerBackdate(unittest.TestCase):
    def test_backdated_token_refused(self):
        ledger = tsa.FirstObservedLedger()
        ledger.record(ORIGIN, SIZE, GEN)
        token = _issue(gen_time=GEN - 10)
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN + 100, ledger=ledger)
        self.assertEqual(cm.exception.code, "tsa-gentime-backdated")

    def test_not_backdated_when_equal_or_later(self):
        ledger = tsa.FirstObservedLedger()
        ledger.record(ORIGIN, SIZE, GEN)
        tsa.verify_token(_issue(gen_time=GEN), TSA_PUB, now=GEN + 100,
                         ledger=ledger)
        tsa.verify_token(_issue(gen_time=GEN + 50), TSA_PUB, now=GEN + 100,
                         ledger=ledger)

    def test_no_ledger_no_backdate_check(self):
        tsa.verify_token(_issue(gen_time=GEN - 10**6), TSA_PUB,
                         now=GEN + 100)  # ancient but unledgered: held

    def test_earliest_wins(self):
        ledger = tsa.FirstObservedLedger()
        ledger.record(ORIGIN, SIZE, GEN + 100)
        ledger.record(ORIGIN, SIZE, GEN)       # earlier
        ledger.record(ORIGIN, SIZE, GEN + 50)  # later, ignored
        self.assertEqual(ledger.first_seen(ORIGIN, SIZE), GEN)

    def test_first_seen_none_when_unseen(self):
        ledger = tsa.FirstObservedLedger()
        self.assertIsNone(ledger.first_seen("nope", 1))

    def test_record_malformed(self):
        ledger = tsa.FirstObservedLedger()
        for args in (("", 1, GEN), (ORIGIN, True, GEN), (ORIGIN, 1, 0),
                     (ORIGIN, 1, True), (ORIGIN, -1, GEN)):
            with self.assertRaises(tsa.TsaError, msg=repr(args)) as cm:
                ledger.record(*args)
            self.assertEqual(cm.exception.code, "tsa-token-malformed")
        with self.assertRaises(tsa.TsaError):
            ledger.first_seen("", 1)


class TestMalformedShapes(unittest.TestCase):
    def test_missing_fields(self):
        for token in ({}, {"token_format": tsa.TOKEN_FORMAT},
                      {"token_format": tsa.TOKEN_FORMAT,
                       "protected": {}, "payload": {}}):
            with self.assertRaises(tsa.TsaError, msg=repr(token)) as cm:
                tsa.verify_token(token, TSA_PUB, now=GEN)
            self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_wrong_token_format(self):
        token = _issue()
        token["token_format"] = "gov/other/1"
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_bad_hex(self):
        token = _issue()
        token["signature"] = "zz" * 64
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(token, TSA_PUB, now=GEN)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(_issue(), "nothex", now=GEN)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_issue_malformed_args(self):
        base = dict(operator_sig_hex=OP_SIG, origin=ORIGIN, size=SIZE,
                    root_hex=ROOT, tsa_seed=TSA_SEED, tsa_keyid=TSA_KEYID,
                    gen_time=GEN)
        bads = [
            dict(operator_sig_hex="zz" * 64),
            dict(operator_sig_hex="ab" * 32),  # short
            dict(origin=""),
            dict(origin="x" * 129),
            dict(origin=123),
            dict(size=True),
            dict(size=-1),
            dict(size="7"),
            dict(root_hex="ab" * 31),
            dict(root_hex="zz" * 32),
            dict(tsa_seed=b"short"),
            dict(tsa_seed="x" * 32),
            dict(tsa_keyid=""),
            dict(tsa_keyid="k" * 129),
        ]
        for bad in bads:
            args = dict(base)
            args.update(bad)
            with self.assertRaises(tsa.TsaError, msg=repr(bad)) as cm:
                tsa.issue_token(**args)
            self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_payload_field_types(self):
        token = _issue()
        for field, bad in (("v", 2), ("size", True), ("root", "zz" * 32),
                           ("origin", 5), ("nonce", "")):
            t = {"token_format": token["token_format"],
                 "protected": dict(token["protected"]),
                 "payload": dict(token["payload"]),
                 "signature": token["signature"]}
            t["payload"][field] = bad
            with self.assertRaises(tsa.TsaError, msg=field) as cm:
                tsa.verify_token(t, TSA_PUB, now=GEN)
            self.assertEqual(cm.exception.code, "tsa-token-malformed")


class TestCheckpointAttachVerify(unittest.TestCase):
    def test_round_trip(self):
        cp = _checkpoint()
        stamped = tsa.timestamp_checkpoint(cp, TSA_SEED, TSA_KEYID,
                                           gen_time=GEN, nonce=NONCE)
        # original untouched, new dict returned
        self.assertNotIn("tsa_token", cp)
        self.assertIsNot(cp, stamped)
        payload = tsa.verify_timestamped_checkpoint(
            stamped, OP_PUB, TSA_PUB, now=GEN + 10, expected_nonce=NONCE)
        self.assertEqual(payload["genTime"], GEN)

    def test_swapped_operator_sig_imprint_mismatch(self):
        stamped = tsa.timestamp_checkpoint(_checkpoint(), TSA_SEED,
                                           TSA_KEYID, gen_time=GEN,
                                           nonce=NONCE)
        stamped = dict(stamped)
        stamped["operator_sig"] = "ef" * 64  # attack: swap the op sig
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_timestamped_checkpoint(stamped, OP_PUB, TSA_PUB,
                                              now=GEN + 10)
        self.assertEqual(cm.exception.code, "tsa-imprint-mismatch")

    def test_swapped_root_imprint_mismatch(self):
        stamped = tsa.timestamp_checkpoint(_checkpoint(), TSA_SEED,
                                           TSA_KEYID, gen_time=GEN,
                                           nonce=NONCE)
        stamped = dict(stamped)
        stamped["root"] = "00" * 32
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_timestamped_checkpoint(stamped, OP_PUB, TSA_PUB,
                                              now=GEN + 10)
        self.assertEqual(cm.exception.code, "tsa-imprint-mismatch")

    def test_missing_token_malformed(self):
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_timestamped_checkpoint(_checkpoint(), OP_PUB,
                                              TSA_PUB, now=GEN)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_malformed_checkpoint(self):
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.timestamp_checkpoint({"origin": ORIGIN}, TSA_SEED,
                                     TSA_KEYID)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")


class TestReceiptAttachVerify(unittest.TestCase):
    def _receipt(self):
        tmp = tempfile.mkdtemp(prefix="tsa-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            tmp, ignore_errors=True))
        log = _ea.TransparencyLog(tmp, "test-log", "op-keyid",
                                  signer_seed=OP_SEED)
        digest = (b"\x00" * 32).hex()
        return _er.issue_receipt(log, digest, OP_SEED)

    def test_round_trip(self):
        receipt = self._receipt()
        stamped = tsa.timestamp_receipt(receipt, TSA_SEED, TSA_KEYID,
                                        gen_time=GEN, nonce=NONCE)
        self.assertNotIn("tsa_token", receipt["payload"])
        self.assertIsNot(stamped, receipt)
        self.assertIsNot(stamped["payload"], receipt["payload"])
        out = tsa.verify_receipt_with_tsa(stamped, OP_PUB, TSA_PUB,
                                          now=GEN + 10,
                                          expected_nonce=NONCE)
        self.assertTrue(out["receipt"])  # offline verify result
        self.assertEqual(out["tsa_payload"]["genTime"], GEN)
        self.assertEqual(out["tsa_payload"]["origin"], "test-log")

    def test_mismatched_token_imprint_mismatch(self):
        # The receipt itself is intact (offline verify passes), but the
        # embedded token was minted over a DIFFERENT operator signature
        # than the receipt's own -> countersign binding refuses.
        receipt = self._receipt()
        foreign = tsa.issue_token(operator_sig_hex=OP_SIG, origin="test-log",
                                  size=receipt["payload"]["tree_size"],
                                  root_hex=receipt["payload"]["root"],
                                  nonce=NONCE, tsa_seed=TSA_SEED,
                                  tsa_keyid=TSA_KEYID, gen_time=GEN)
        stamped = dict(receipt)
        stamped["payload"] = dict(receipt["payload"])
        stamped["payload"]["tsa_token"] = foreign
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_receipt_with_tsa(stamped, OP_PUB, TSA_PUB,
                                        now=GEN + 10)
        self.assertEqual(cm.exception.code, "tsa-imprint-mismatch")

    def test_missing_token_malformed(self):
        receipt = self._receipt()
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_receipt_with_tsa(receipt, OP_PUB, TSA_PUB,
                                        now=GEN + 10)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_offline_errors_propagate(self):
        receipt = self._receipt()
        stamped = tsa.timestamp_receipt(receipt, TSA_SEED, TSA_KEYID,
                                        gen_time=GEN, nonce=NONCE)
        stamped = dict(stamped)
        stamped["signature"] = "ef" * 64  # breaks operator signature
        with self.assertRaises(Exception) as cm:
            tsa.verify_receipt_with_tsa(stamped, OP_PUB, TSA_PUB,
                                        now=GEN + 10)
        self.assertNotIsInstance(cm.exception, tsa.TsaError)

    def test_malformed_receipt(self):
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.timestamp_receipt({"payload": {}}, TSA_SEED, TSA_KEYID)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")


class TestReviewRegression(unittest.TestCase):
    """Wave-287 two-axis review findings: every public seam fails
    coded (TsaError), never with an uncoded builtin exception."""

    def _bad_imprint_token(self):
        tok = _issue()
        tok["payload"] = dict(tok["payload"])
        tok["payload"]["messageImprint"] = 12345
        return tok

    def test_non_str_imprint_verify_token_coded(self):
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(self._bad_imprint_token(), TSA_PUB)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_non_str_imprint_checkpoint_verify_coded(self):
        cp = dict(_checkpoint())
        cp["tsa_token"] = self._bad_imprint_token()
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_timestamped_checkpoint(cp, OP_PUB, TSA_PUB)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_ledger_without_first_seen_coded(self):
        tok = _issue()
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_token(tok, TSA_PUB, ledger={})
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_size_overflow_coded(self):
        with self.assertRaises(tsa.TsaError) as cm:
            _issue(size=2 ** 64)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_garbage_operator_pubkey_checkpoint_coded(self):
        cp = tsa.timestamp_checkpoint(_checkpoint(), TSA_SEED, TSA_KEYID)
        with self.assertRaises(tsa.TsaError) as cm:
            tsa.verify_timestamped_checkpoint(cp, "zz", TSA_PUB)
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_surrogate_origin_coded(self):
        with self.assertRaises(tsa.TsaError) as cm:
            _issue(origin="a\ud800")
        self.assertEqual(cm.exception.code, "tsa-token-malformed")

    def test_bad_now_coded(self):
        tok = _issue()
        for bad in ("x", 0, -5, True, 1.5):
            with self.assertRaises(tsa.TsaError) as cm:
                tsa.verify_token(tok, TSA_PUB, now=bad)
            self.assertEqual(cm.exception.code, "tsa-gentime-invalid")


class TestTaxonomyPin(unittest.TestCase):
    def test_pin(self):
        import gov.decision_codes as dc
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)
        for code in ("tsa-token-malformed", "tsa-signature-invalid",
                     "tsa-gentime-invalid", "tsa-gentime-in-future",
                     "tsa-gentime-backdated", "tsa-nonce-mismatch",
                     "tsa-imprint-mismatch"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "tsa")


if __name__ == "__main__":
    unittest.main()
