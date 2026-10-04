"""Unit tests for gov.evidence_verify_offline (wave-311 lane E).

Seam-level coverage: taxonomy shape, canonical bytes, the trust-root
pin, the 9-step pipeline (positive + typed negatives), the witness
stage (log-backed entry: checkpoint-first verify, inclusion proof,
body binding; all coded negatives), transcript / machine-report
rendering, the CLI contract, and the stdlib-only third-party
acceptance script (run in a subprocess with no Sasanam import,
fixtures in a tmp dir).

The vendored Ed25519 inside the acceptance script is pinned by
contract in a fresh interpreter: a good signature verifies
``is True`` and a forged one verifies ``is False`` (the wave-243
lesson: never assume a verify() raises -- check the return).
"""

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

from gov import ed25519
from gov import evidence_verify_offline as v

NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
EV_SEED = "11" * 32
TSA_SEED = "22" * 32
BUNDLE_BYTES = b'{"evidence":"offline-verifier-unit"}\n'
PREDICATE_TYPE = "https://sasanam.dev/evidence-predicate/v1"
# TEST-ONLY policy-anchor seed: seals test policies. Synthetic
# placeholder; NEVER in the module (the module pins only the pubkey).
ANCHOR_SEED = "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6"


def _signer(seed_hex):
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


def _policy_doc(ev, tsa, expires):
    return {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "unit-test-policy",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": s.keyid(), "pubkey_hex": s.pubkey_hex()}
                     for s in ev],
        },
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "timestamp_authorities": [
            {"authority_id": s.keyid(), "pubkey_hex": s.pubkey_hex(),
             "valid_for": {
                 "not_before": (NOW - timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "not_after": (NOW + timedelta(days=30))
                 .strftime("%Y-%m-%dT%H:%M:%SZ")}}
            for s in tsa
        ],
    }


def _good_bundle():
    ev = _signer(EV_SEED)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                .hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = v.canonical(stmt)
    policy = _policy_doc([ev], [_signer(TSA_SEED)],
                         NOW + timedelta(days=10))
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": _seal(payload, v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        "policy": _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                        [_signer(ANCHOR_SEED)]),
        "timestamps": [],
    }
    return vb, BUNDLE_BYTES


class TestTaxonomyShape(unittest.TestCase):
    def test_thirty_three_codes(self):
        # Wave-312 adds the five WITNESS_* witness-stage codes (11 -> 16);
        # the eleven base codes are unchanged and keep their slots.
        # Wave-318 lane 3 adds the six trust-root-* chain codes (16 -> 22).
        # Wave-318 lane 2 adds EXTENSION_SCHEMA_INVALID (22 -> 23).
        # Wave-318 merge: 16 -> 23.
        # Wave-319 lane 3 adds the ten witness-consistency/gossip codes
        # (23 -> 33).
        self.assertEqual(len(v.FAILURE_CODES), 33)

    def test_exit_codes_and_categories(self):
        exits = {c["exit"] for c in v.FAILURE_CODES.values()}
        self.assertEqual(exits, {40, 41, 42, 43, 44})
        for code, meta in v.FAILURE_CODES.items():
            self.assertIn(meta["category"],
                          {"parse", "crypto", "unsupported", "consistency",
                           "policy"})
            self.assertTrue(meta["reason"])
            self.assertTrue(meta["remedy"])

    def test_error_carries_typed_fields(self):
        e = v.VerificationError("SUBJECT_DIGEST_MISMATCH",
                                expected="a", actual="b")
        self.assertEqual(e.code, "SUBJECT_DIGEST_MISMATCH")
        self.assertEqual(e.exit_code, 43)
        self.assertEqual(e.expected, "a")
        self.assertEqual(e.actual, "b")
        self.assertTrue(e.reason and e.remedy)

    def test_unknown_code_is_internal(self):
        with self.assertRaises(v.InternalError):
            v.VerificationError("NO_SUCH_CODE")


class TestCanonicalBytes(unittest.TestCase):
    def test_deterministic_and_compact(self):
        obj = {"b": 1, "a": [1, 2]}
        self.assertEqual(v.canonical(obj), b'{"a":[1,2],"b":1}')
        self.assertEqual(v.canonical(obj), v.canonical({"a": [1, 2],
                                                        "b": 1}))

    def test_non_serializable_rejected(self):
        with self.assertRaises(v.InternalError):
            v.canonical(object())


class TestTrustRootPin(unittest.TestCase):
    def test_pin_matches_compiled_root(self):
        digest = hashlib.sha256(
            v.canonical(v.COMPILED_TRUST_ROOT)).hexdigest()
        self.assertEqual(digest, v.COMPILED_TRUST_ROOT_SHA256)

    def test_tampered_root_refused(self):
        bad = dict(v.COMPILED_TRUST_ROOT)
        bad["policy_keys"] = []
        with self.assertRaises(v.InternalError):
            v._check_trust_root_shape(bad)

    def test_pin_mismatch_refuses_to_run(self):
        real = v.COMPILED_TRUST_ROOT_SHA256
        v.COMPILED_TRUST_ROOT_SHA256 = "0" * 64
        try:
            vb, bb = _good_bundle()
            with self.assertRaises(v.InternalError):
                v.verify(bb, vb, time_source=v.FixedClock("t", NOW))
        finally:
            v.COMPILED_TRUST_ROOT_SHA256 = real


class TestPAE(unittest.TestCase):
    def test_pae_format(self):
        self.assertEqual(v.pae("t", b"body"),
                         b"DSSEv1 1 t 4 body")

    def test_pae_binds_payload_type(self):
        self.assertNotEqual(v.pae("a", b"x"), v.pae("b", b"x"))


class TestPipeline(unittest.TestCase):
    def _clock(self, when=NOW):
        return v.FixedClock("unit-clock", when)

    def test_positive_nine_checks(self):
        vb, bb = _good_bundle()
        rep = v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(rep["status"], "VALID")
        self.assertEqual(rep["verificationResult"], "PASSED")
        self.assertEqual([c["step"] for c in rep["checks"]],
                         ["parse", "payloadType", "signature", "statement",
                          "predicate", "digest", "subject", "policy",
                          "transcript"])
        self.assertTrue(all(c["result"] == "pass"
                            for c in rep["checks"]))

    def test_altered_artifact_bytes(self):
        vb, _ = _good_bundle()
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(b"tampered", vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "SUBJECT_DIGEST_MISMATCH")
        self.assertEqual(cm.exception.exit_code, 43)

    def test_wrong_evidence_key(self):
        vb, bb = _good_bundle()
        other = _signer("33" * 32)
        stmt = json.loads(base64.b64decode(vb["envelope"]["payload"]))
        vb["envelope"] = _seal(v.canonical(stmt),
                               v.ENVELOPE_PAYLOAD_TYPE, [other])
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "ENVELOPE_SIGNATURE_INVALID")

    def test_expired_policy_always_fails(self):
        vb, bb = _good_bundle()
        ev = _signer(EV_SEED)
        policy = _policy_doc([ev], [_signer(TSA_SEED)],
                             NOW - timedelta(seconds=1))
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [_signer(ANCHOR_SEED)])
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "TEMPORAL_UNSATISFIED")
        self.assertEqual(cm.exception.exit_code, 44)

    def test_no_time_source_fails_closed(self):
        vb, bb = _good_bundle()
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=None)
        self.assertEqual(cm.exception.code, "TEMPORAL_UNSATISFIED")

    def test_unsupported_payload_type(self):
        vb, bb = _good_bundle()
        vb["envelope"]["payloadType"] = "application/json"
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "UNSUPPORTED_PAYLOAD_TYPE")

    def test_witness_entries_refused(self):
        vb, bb = _good_bundle()
        vb["witness_entries"] = [{"kind": "x"}]
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "UNSUPPORTED_BUNDLE_VERSION")

    def test_existence_only_is_labeled(self):
        vb, bb = _good_bundle()
        rep = v.verify(bb, vb, time_source=self._clock(),
                       existence_only=True)
        self.assertTrue(rep["existenceOnly"])
        rep2 = v.verify(bb, vb, time_source=self._clock())
        self.assertFalse(rep2["existenceOnly"])

    def test_malformed_bundle(self):
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(b"{}", {"nope": 1}, time_source=self._clock())
        self.assertEqual(cm.exception.code, "BUNDLE_MALFORMED")

    def test_duplicate_evidence_keyid_refused(self):
        vb, bb = _good_bundle()
        ev = _signer(EV_SEED)
        policy = _policy_doc([ev], [_signer(TSA_SEED)],
                             NOW + timedelta(days=10))
        policy["evidence_signing"]["keys"].append(
            {"keyid": ev.keyid(), "pubkey_hex": ev.pubkey_hex()})
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [_signer(ANCHOR_SEED)])
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "POLICY_MALFORMED")

    def test_duplicate_trust_root_keyid_refuses_to_run(self):
        vb, bb = _good_bundle()
        root = {"version": "sasanam-offline-trust-root/v1",
                "policy_keys": [
                    {"keyid": "k", "pubkey_hex": "ab" * 32},
                    {"keyid": "k", "pubkey_hex": "cd" * 32}]}
        with self.assertRaises(v.InternalError):
            v.verify(bb, vb, time_source=self._clock(), trust_root=root)


class TestTranscript(unittest.TestCase):
    def test_human_transcript_has_banner(self):
        vb, bb = _good_bundle()
        rep = v.verify(bb, vb, time_source=v.FixedClock("t", NOW))
        text = v.render_transcript(rep)
        self.assertIn("PASSED", text)
        self.assertIn("PASSED != ALLOW", text)
        self.assertIn("[pass] signature:", text)

    def test_machine_report_failure_shape(self):
        e = v.VerificationError("BUNDLE_MALFORMED",
                                detail="x", checks=[])
        doc = v.machine_report(e)
        self.assertEqual(doc["status"], "INVALID")
        self.assertEqual(doc["code"], "BUNDLE_MALFORMED")
        self.assertEqual(doc["exit_code"], 40)
        self.assertTrue(doc["remedy"])


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ovf-cli-")
        vb, bb = _good_bundle()
        self.bp = os.path.join(self.tmp, "b.json")
        self.ap = os.path.join(self.tmp, "a.bin")
        open(self.bp, "w").write(json.dumps(vb))
        open(self.ap, "wb").write(bb)
        self.base = ["--bundle", self.bp, "--artifact", self.ap,
                     "--clock", "test:2026-10-03T12:00:00Z"]

    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = v.main(argv)
        return rc, buf.getvalue()

    def test_success_transcript(self):
        rc, out = self._run(self.base)
        self.assertEqual(rc, 0)
        self.assertIn("PASSED", out)
        self.assertIn("PASSED != ALLOW", out)

    def test_json_machine_output(self):
        rc, out = self._run(self.base + ["--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc["status"], "VALID")

    def test_failure_exit_code_and_remedy(self):
        open(self.ap, "wb").write(b"tampered")
        rc, out = self._run(self.base)
        self.assertEqual(rc, 43)
        doc = json.loads(out)
        self.assertEqual(doc["code"], "SUBJECT_DIGEST_MISMATCH")
        self.assertTrue(doc["remedy"])

    def test_no_private_infrastructure_flag(self):
        with self.assertRaises(SystemExit) as cm:
            v.main(self.base + ["--private-infrastructure"])
        self.assertEqual(cm.exception.code, 2)

    def test_internal_error_exits_one(self):
        open(self.bp, "w").write("{not json")
        rc, out = self._run(self.base)
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        self.assertEqual(doc["code"], "INTERNAL_ERROR")


def _clean_env():
    """Subprocess env without import-path leaks."""
    return {k: val for k, val in os.environ.items()
            if k not in ("PYTHONPATH", "PYTHONHOME")}


class TestThirdPartyAccept(unittest.TestCase):
    """The stdlib-only acceptance script, in a subprocess with no gov."""

    SCRIPT = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "evals", "w311_thirdparty_accept.py")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ovf-tp-")
        vb, bb = _good_bundle()
        self.bp = os.path.join(self.tmp, "b.json")
        self.ap = os.path.join(self.tmp, "a.bin")
        self.tp = os.path.join(self.tmp, "t.json")
        open(self.bp, "w").write(json.dumps(vb))
        open(self.ap, "wb").write(bb)
        open(self.tp, "w").write(json.dumps(v.COMPILED_TRUST_ROOT))

    def _run(self):
        env = _clean_env()
        proc = subprocess.run(
            [sys.executable, self.SCRIPT, "--bundle", self.bp,
             "--artifact", self.ap, "--trust-root", self.tp],
            cwd="/tmp", env=env, capture_output=True, text=True,
            timeout=180)
        return proc

    def test_valid_bundle(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("THIRDPARTY_VALID", proc.stdout)

    def test_tampered_artifact_rejected(self):
        open(self.ap, "wb").write(b"tampered")
        proc = self._run()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("THIRDPARTY_INVALID", proc.stdout)

    def test_vendored_ed25519_contract(self):
        # Fresh interpreter (no gov importable): good verifies is
        # True, forged verifies is False -- the return is checked,
        # never assumed.
        driver = (
            "import importlib.util\n"
            "spec = importlib.util.spec_from_file_location(\n"
            "    'tpa', %r)\n" % (self.SCRIPT,) +
            "tpa = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(tpa)\n"
            "from gov import ed25519 as _ge\n"
            "import sys; sys.modules.pop('gov', None)\n"
            "seed = bytes.fromhex('02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6')\n"
            "pub = _ge.publickey(seed); msg = b'contract'\n"
            "sig = _ge.sign(seed, msg)\n"
            "assert tpa.ed25519_verify(pub, msg, sig) is True\n"
            "assert tpa.ed25519_verify(pub, b'forged', sig) is False\n"
            "assert tpa.ed25519_verify(pub, msg, b'\\\\x00' * 64) is False\n"
            "print('ED25519_CONTRACT_OK')\n"
        )
        env = _clean_env()
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = repo  # only for the gov side of the check
        proc = subprocess.run([sys.executable, "-c", driver],
                              cwd="/tmp", env=env, capture_output=True,
                              text=True, timeout=120)
        self.assertIn("ED25519_CONTRACT_OK",
                      proc.stdout, proc.stdout + proc.stderr)



class TestWitnessStage(unittest.TestCase):
    """Wave-312: the log-backed witness stage in the offline verifier.

    Positive: seal a witness entry against a real WitnessLog, attach
    it, and verify -- the witness step runs checkpoint-signature
    first, then inclusion proof vs the checkpoint root, then entry
    body binding. Negatives: every stage fails closed with its coded
    refusal.
    """

    WIT_SEED = "77" * 32  # TEST-ONLY witness seed (see file header style)

    def _clock(self, when=NOW):
        return v.FixedClock("unit-clock", when)

    def _wit(self, seed=WIT_SEED):
        s = _signer(seed)

        class _W(object):
            pass
        w = _W()
        w.public_key = bytes.fromhex(s.pubkey_hex())
        w.key_id = s.keyid()
        w.sign = s.sign
        return w

    def _witness_bundle(self, t0=None, wit=None, policy_extra=None,
                        valid_days=30):
        ev = _signer(EV_SEED)
        vb, bb = _good_bundle()
        wit = wit or self._wit()
        policy = _policy_doc([ev], [_signer(TSA_SEED)],
                             NOW + timedelta(days=10))
        policy["witness_log_keys"] = [{
            "keyid": wit.key_id,
            "pubkey_hex": wit.public_key.hex(),
            "valid_for": {
                "not_before": (NOW - timedelta(days=valid_days))
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "not_after": (NOW + timedelta(days=valid_days))
                .strftime("%Y-%m-%dT%H:%M:%SZ")}}]
        if policy_extra:
            policy.update(policy_extra)
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [_signer(ANCHOR_SEED)])
        t0 = t0 if t0 is not None else int(NOW.timestamp())
        return vb, bb, ev, wit, t0, policy

    def _attach_entry(self, vb, ev, wit, wlog, t0, policy):
        entry = v.seal_witness_entry(
            wlog, wit,
            artifact_digest=hashlib.sha256(BUNDLE_BYTES).hexdigest(),
            signatures=vb["envelope"]["signatures"],
            verified_keyids=[ev.keyid()],
            policy_digest=hashlib.sha256(
                v.canonical(policy)).hexdigest(),
            integrated_time=t0)
        vb = copy.deepcopy(vb)
        vb["witness_entries"] = [entry]
        return vb, entry

    def test_witness_positive(self):
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle()
        wlog = witness_log.WitnessLog(wit.public_key)
        vb, _ = self._attach_entry(vb, ev, wit, wlog, t0, policy)
        rep = v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(rep["status"], "VALID")
        steps = [c["step"] for c in rep["checks"]]
        self.assertEqual(steps,
                         ["parse", "payloadType", "signature", "statement",
                          "predicate", "digest", "subject", "policy",
                          "witness", "transcript"])
        self.assertIsNotNone(rep["witness"])
        self.assertEqual(rep["witness"]["tree_size"], 1)
        self.assertEqual(rep["witness"]["log_index"], 0)

    def test_witness_tampered_checkpoint_signature(self):
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle()
        wlog = witness_log.WitnessLog(wit.public_key)
        vb, entry = self._attach_entry(vb, ev, wit, wlog, t0, policy)
        sig = bytearray(base64.b64decode(
            vb["witness_entries"][0]["checkpoint_signature"]))
        sig[0] ^= 1
        vb["witness_entries"][0]["checkpoint_signature"] = (
            base64.b64encode(bytes(sig)).decode("ascii"))
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "WITNESS_CHECKPOINT_INVALID")
        self.assertEqual(cm.exception.exit_code, 41)

    def test_witness_tampered_inclusion_path(self):
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle()
        wlog = witness_log.WitnessLog(wit.public_key)
        # A second entry so the audit path is non-empty.
        v.seal_witness_entry(
            wlog, wit,
            artifact_digest=hashlib.sha256(BUNDLE_BYTES).hexdigest(),
            signatures=vb["envelope"]["signatures"],
            verified_keyids=[ev.keyid()],
            policy_digest=hashlib.sha256(
                v.canonical(policy)).hexdigest(),
            integrated_time=t0)
        vb, entry = self._attach_entry(vb, ev, wit, wlog, t0, policy)
        path = vb["witness_entries"][0]["inclusion_path"]
        h = bytearray(bytes.fromhex(path[0]["hash"]))
        h[0] ^= 1
        path[0]["hash"] = bytes(h).hex()
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "WITNESS_INCLUSION_INVALID")
        self.assertEqual(cm.exception.exit_code, 43)

    def test_witness_entry_unbound_wrong_digest(self):
        # The entry is sealed honestly (inclusion verifies) but for
        # DIFFERENT artifact bytes -- the binding check catches it.
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle()
        wlog = witness_log.WitnessLog(wit.public_key)
        entry = v.seal_witness_entry(
            wlog, wit,
            artifact_digest=hashlib.sha256(b"other-bytes").hexdigest(),
            signatures=vb["envelope"]["signatures"],
            verified_keyids=[ev.keyid()],
            policy_digest=hashlib.sha256(
                v.canonical(policy)).hexdigest(),
            integrated_time=t0)
        vb = copy.deepcopy(vb)
        vb["witness_entries"] = [entry]
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "WITNESS_ENTRY_UNBOUND")

    def test_witness_key_not_in_policy(self):
        # Bundle carries a witness entry but the signed policy pins no
        # witness_log_keys at all.
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle()
        del policy["witness_log_keys"]
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [_signer(ANCHOR_SEED)])
        wlog = witness_log.WitnessLog(wit.public_key)
        vb, _ = self._attach_entry(vb, ev, wit, wlog, t0, policy)
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "WITNESS_KEY_UNAVAILABLE")

    def test_witness_future_checkpoint_refused(self):
        from gov import witness_log
        wit = self._wit()
        vb, bb, ev, wit, t0, policy = self._witness_bundle(
            t0=int(NOW.timestamp()) + 3600)
        wlog = witness_log.WitnessLog(wit.public_key)
        vb, _ = self._attach_entry(vb, ev, wit, wlog, t0, policy)
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "TEMPORAL_UNSATISFIED")

    def test_witness_unknown_kind_still_refused(self):
        vb, bb = _good_bundle()
        vb = copy.deepcopy(vb)
        vb["witness_entries"] = [{"kind": "witness-entry/future-kind"}]
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "UNSUPPORTED_BUNDLE_VERSION")

    def test_witness_required_unmet(self):
        vb, bb = _good_bundle()
        vb = copy.deepcopy(vb)
        policy = _policy_doc([_signer(EV_SEED)], [_signer(TSA_SEED)],
                             NOW + timedelta(days=10))
        policy["witness_required"] = True
        vb["policy"] = _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                             [_signer(ANCHOR_SEED)])
        with self.assertRaises(v.VerificationError) as cm:
            v.verify(bb, vb, time_source=self._clock())
        self.assertEqual(cm.exception.code, "WITNESS_REQUIRED_UNMET")
        self.assertEqual(cm.exception.exit_code, 44)

    def test_no_entries_no_witness_step(self):
        # Bundles without witness evidence keep the exact 9-step
        # transcript (lane-E regression pin).
        vb, bb = _good_bundle()
        rep = v.verify(bb, vb, time_source=self._clock())
        self.assertEqual([c["step"] for c in rep["checks"]],
                         ["parse", "payloadType", "signature", "statement",
                          "predicate", "digest", "subject", "policy",
                          "transcript"])
        self.assertIsNone(rep["witness"])


if __name__ == "__main__":
    unittest.main()
