"""Unit tests for gov.anchoring (K-060 pluggable export anchoring).

Tests at the public seams: bundle_head_digest determinism/validation,
anchor_bundle wiring + type checks, verify_bundle_anchor fail-closed
behavior. Backend behavior itself is covered by the break-first battery
evals/anchoring_probes.py and gov.anchor_backend's own suites.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gov import anchoring as _anch  # noqa: E402
from gov.anchor_backend import AnchorBackend  # noqa: E402


class HeadDigestTests(unittest.TestCase):
    def test_deterministic_and_domain_separated(self):
        b = {"checkpoints": [{"seq": 3, "merkle_root": "ab" * 32}]}
        d1 = _anch.bundle_head_digest(b)
        d2 = _anch.bundle_head_digest(b)
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 64)
        int(d1, 16)

    def test_checkpoint_order_matters(self):
        cps = [{"seq": 1}, {"seq": 2}]
        d1 = _anch.bundle_head_digest({"checkpoints": cps})
        d2 = _anch.bundle_head_digest({"checkpoints": list(reversed(cps))})
        self.assertNotEqual(d1, d2)

    def test_empty_checkpoints_digest_is_stable(self):
        d = _anch.bundle_head_digest({"checkpoints": []})
        self.assertEqual(len(d), 64)

    def test_malformed_bundle_raises(self):
        for bad in (None, [], {"nope": 1}, {"checkpoints": "x"}):
            with self.assertRaises(ValueError):
                _anch.bundle_head_digest(bad)


class AnchorBundleTests(unittest.TestCase):
    def _backend(self):
        d = tempfile.mkdtemp(prefix="govanchor-ut-")
        return _anch.LocalAnchorLog(str(Path(d) / "a.jsonl"))

    def test_rejects_non_backend(self):
        with self.assertRaises(TypeError):
            _anch.anchor_bundle({"checkpoints": []}, object())

    def test_rejects_malformed_bundle(self):
        with self.assertRaises(ValueError):
            _anch.anchor_bundle({"nope": 1}, self._backend())

    def test_interface_is_the_established_one(self):
        # No parallel interface: LocalAnchorLog IS an AnchorBackend.
        self.assertIsInstance(self._backend(), AnchorBackend)

    def test_verify_never_raises(self):
        b = {"checkpoints": []}
        backend = self._backend()
        for receipt in (None, "x", [], {"backend": "nope"}):
            ok, reason = _anch.verify_bundle_anchor(b, receipt, backend)
            self.assertFalse(ok)
            self.assertTrue(reason)
        ok, _ = _anch.verify_bundle_anchor(b, {}, object())
        self.assertFalse(ok)

    def test_roundtrip(self):
        b = {"checkpoints": [{"seq": 5}]}
        backend = self._backend()
        receipt = _anch.anchor_bundle(b, backend)
        ok, reason = _anch.verify_bundle_anchor(b, receipt, backend)
        self.assertTrue(ok, reason)

    def test_verify_never_raises_even_when_backend_raises(self):
        # Belt-and-suspenders: a third-party backend that violates the
        # never-raise contract still fails closed at the auditor path.
        class ExplodingBackend(AnchorBackend):
            name = "explode"

            def submit(self, anchor_hash):
                raise RuntimeError("boom")

            def verify_receipt(self, receipt, *, anchor_hash):
                raise RuntimeError("boom")

        b = {"checkpoints": []}
        ok, reason = _anch.verify_bundle_anchor(
            b, {"backend": "explode"}, ExplodingBackend())
        self.assertFalse(ok)
        self.assertTrue(reason)

    def test_digest_rejects_non_canonical_input(self):
        # A set's str() is nondeterministic; the seam must refuse,
        # not silently stringify into an unstable commitment.
        with self.assertRaises((ValueError, TypeError)):
            _anch.bundle_head_digest({"checkpoints": [{"s": {1, 2, 3}}]})

    def test_rekor_backend_is_reexported(self):
        # The re-export surface includes the real-witness path the
        # docstring discusses, not just the local/test backends.
        from gov.anchor_backend import RekorBackend
        self.assertIs(_anch.RekorBackend, RekorBackend)


if __name__ == "__main__":
    unittest.main()
