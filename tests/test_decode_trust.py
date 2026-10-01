"""Unit tests for gov/decode_trust.py (wave-274 lane 3).

Seams: seal_evidence / require_trust / TrustEvidence at the public
API. Expected values are literals, never recomputed by the code
under test.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import decode_trust as dt


class TestSeal(unittest.TestCase):
    def test_seal_roundtrip(self):
        digest = hashlib.sha256(b"wire").hexdigest()
        ev = dt.seal_evidence(scope="s", digest=digest, kind="signature",
                              signer="k1")
        self.assertIsInstance(ev, dt.TrustEvidence)
        self.assertEqual(ev.scope, "s")
        self.assertEqual(ev.digest, digest)
        self.assertEqual(ev.kind, "signature")
        self.assertEqual(ev.signer, "k1")

    def test_seal_rejects_bad_digest(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.seal_evidence(scope="s", digest="not-hex", kind="k",
                             signer="x")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-malformed-evidence")

    def test_seal_rejects_empty_scope(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.seal_evidence(scope="", digest="ab" * 32, kind="k",
                             signer="x")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-malformed-evidence")

    def test_evidence_immutable(self):
        ev = dt.seal_evidence(scope="s", digest="ab" * 32, kind="k",
                              signer="x")
        # Immutability is a programming-error contract (AttributeError,
        # like a frozen dataclass) -- not a decodetrust-* trust
        # refusal, which would misfile the event and break
        # copy/deepcopy/pickle of sealed evidence.
        with self.assertRaises(AttributeError):
            ev.scope = "other"
        self.assertEqual(ev.scope, "s")

    def test_evidence_deepcopyable(self):
        import copy
        ev = dt.seal_evidence(scope="s", digest="ab" * 32, kind="k",
                              signer="x")
        dup = copy.deepcopy(ev)
        self.assertEqual(dup.scope, "s")
        self.assertEqual(dup.digest, "ab" * 32)

    def test_unknown_code_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            dt.DecodeTrustError("not-a-code", "x")


class TestRequire(unittest.TestCase):
    def _ev(self, scope="s", digest=None):
        digest = digest or hashlib.sha256(b"wire").hexdigest()
        return dt.seal_evidence(scope=scope, digest=digest, kind="k",
                                signer="x")

    def test_require_ok(self):
        self.assertIsNone(dt.require_trust(self._ev(), b"wire", scope="s"))

    def test_require_none_evidence(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.require_trust(None, b"wire", scope="s")
        self.assertEqual(ctx.exception.code, "decodetrust-no-evidence")

    def test_require_wrong_type(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.require_trust({"scope": "s"}, b"wire", scope="s")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-malformed-evidence")

    def test_require_scope_mismatch(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.require_trust(self._ev(scope="a"), b"wire", scope="b")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-binding-mismatch")

    def test_require_digest_mismatch(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.require_trust(self._ev(), b"other-wire", scope="s")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-binding-mismatch")

    def test_require_non_bytes(self):
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            dt.require_trust(self._ev(), "wire", scope="s")
        self.assertEqual(ctx.exception.code,
                         "decodetrust-malformed-evidence")

    def test_expected_codes_complete(self):
        self.assertEqual(set(dt.EXPECTED_CODES),
                         {"decodetrust-no-evidence",
                          "decodetrust-malformed-evidence",
                          "decodetrust-binding-mismatch"})


class TestTrustedPathOrdering(unittest.TestCase):
    """The trusted-decode paths refuse no-evidence BEFORE inspecting
    the wire shape: a hostile wire with no evidence must surface
    decodetrust-no-evidence, never a binding/shape code (wave-274
    lane 3 regression pin for the manifest path)."""

    def test_manifest_no_evidence_before_shape(self):
        from gov import replay_manifest as rm
        hostile = {"format": "replay-manifest.v1", "links": "not-a-list"}
        with self.assertRaises(dt.DecodeTrustError) as ctx:
            rm.decode_trusted_manifest(hostile, None)
        self.assertEqual(ctx.exception.code, "decodetrust-no-evidence")


if __name__ == "__main__":
    unittest.main()
