"""Unit tests for the wave-216 digest-binding consumption seam.

Covers gov.scan_verdicts.digest_of_bytes and ScanGate.check_bytes:
the digest context for gate consultation is derived from the exact
bytes being promoted, never from a caller-supplied digest string
(the npm/PyPI attestation digest-binding lesson -- idea only).
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gov.scan_verdicts as sv
from gov.signing import Ed25519Signer, Ed25519Verifier

_NOW = 1700000000
_SEED = bytes.fromhex("a1" * 32)
_BYTES_V1 = b"widget-1.0.0-tarball-bytes"
_BYTES_V2 = b"widget-2.0.0-tarball-bytes"
_DIGEST_V1 = "sha256:" + hashlib.sha256(_BYTES_V1).hexdigest()
_RULESET = "sha256:" + "cc" * 32


def _signer():
    s = Ed25519Signer(_SEED)
    return s, [Ed25519Verifier(s.public_key)]


def _emit(signer, target):
    return sv.emit_scan_verdict(
        scanner_name="trivy", scanner_version="0.58.2",
        scan_target_digest=target, verdict="pass",
        ruleset_digest=_RULESET, scanned_at=_NOW - 3600,
        expires_at=_NOW + 86400, signer=signer, now=_NOW)


def _gate(verifiers):
    return sv.ScanGate(sv.ScanPolicy(required_scans=["trivy"]),
                       {"trivy": verifiers})


class DigestOfBytesTest(unittest.TestCase):
    def test_pins_canonical_shape(self):
        self.assertEqual(sv.digest_of_bytes(_BYTES_V1), _DIGEST_V1)

    def test_empty_bytes_well_defined(self):
        self.assertEqual(sv.digest_of_bytes(b""),
                         "sha256:" + hashlib.sha256(b"").hexdigest())

    def test_bytearray_and_memoryview_accepted(self):
        self.assertEqual(sv.digest_of_bytes(bytearray(_BYTES_V1)),
                         _DIGEST_V1)
        self.assertEqual(sv.digest_of_bytes(memoryview(_BYTES_V1)),
                         _DIGEST_V1)

    def test_str_refused_never_coerced(self):
        # A digest string where bytes belong must not be hashed into a
        # new binding -- loud refusal, never coercion.
        with self.assertRaises(sv.ScanVerdictError):
            sv.digest_of_bytes(_DIGEST_V1)

    def test_none_and_int_refused(self):
        with self.assertRaises(sv.ScanVerdictError):
            sv.digest_of_bytes(None)
        with self.assertRaises(sv.ScanVerdictError):
            sv.digest_of_bytes(12345)


class CheckBytesTest(unittest.TestCase):
    def test_happy_path(self):
        signer, verifiers = _signer()
        env = _emit(signer, _DIGEST_V1)
        result = _gate(verifiers).check_bytes(_BYTES_V1, [env], now=_NOW)
        self.assertTrue(result["ok"])
        self.assertIn("trivy", result["checked"])

    def test_tampered_bytes_refuse(self):
        signer, verifiers = _signer()
        env = _emit(signer, _DIGEST_V1)
        flipped = bytearray(_BYTES_V1)
        flipped[-1] ^= 0x01
        with self.assertRaises(sv.ScanVerdictError) as ctx:
            _gate(verifiers).check_bytes(bytes(flipped), [env], now=_NOW)
        self.assertIn("target_mismatch", str(ctx.exception))

    def test_wrong_version_refuses(self):
        signer, verifiers = _signer()
        env = _emit(signer, _DIGEST_V1)
        with self.assertRaises(sv.ScanVerdictError) as ctx:
            _gate(verifiers).check_bytes(_BYTES_V2, [env], now=_NOW)
        self.assertIn("target_mismatch", str(ctx.exception))

    def test_non_bytes_refused_loudly(self):
        signer, verifiers = _signer()
        env = _emit(signer, _DIGEST_V1)
        gate = _gate(verifiers)
        for bad in (_DIGEST_V1, None, 42, ["x"]):
            with self.assertRaises(sv.ScanVerdictError, msg=repr(bad)):
                gate.check_bytes(bad, [env], now=_NOW)

    def test_refusal_codes_match_string_api(self):
        # check_bytes must surface the same refusal codes as check()
        # with the derived digest -- purely additive, no new codes.
        signer, verifiers = _signer()
        env = _emit(signer, _DIGEST_V1)
        gate = _gate(verifiers)
        try:
            gate.check_bytes(_BYTES_V2, [env], now=_NOW)
        except sv.ScanVerdictError as e_bytes:
            code_bytes = str(e_bytes).split(":")[0]
        else:
            self.fail("expected refusal")
        digest_v2 = "sha256:" + hashlib.sha256(_BYTES_V2).hexdigest()
        try:
            gate.check(digest_v2, [env], now=_NOW)
        except sv.ScanVerdictError as e_str:
            code_str = str(e_str).split(":")[0]
        else:
            self.fail("expected refusal")
        self.assertEqual(code_bytes, code_str)

    def test_exported(self):
        self.assertIn("digest_of_bytes", sv.__all__)
        self.assertTrue(hasattr(sv.ScanGate, "check_bytes"))


if __name__ == "__main__":
    unittest.main()
