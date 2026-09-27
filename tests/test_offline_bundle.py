"""Red-first unit tests for gov/offline_bundle.py (offline evidence bundle).

Public seams only: the exporter output shape, and its fail-closed
refusals (broken source chain, unsigned entries, reserved redaction
fields, gapped window, missing entry-signer pubkey). The verifier is
covered break-first by evals/offline_bundle_adversarial.py. Deterministic,
synthetic, $0.
"""

import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.keyfixture import provision_test_key
from gov.offline_bundle import (
    export_offline_bundle,
    OfflineBundleError,
    REQUIRED_FILES,
)


def _signer(seed=b"offline-bundle-unit-test-signer"):
    from gov.signing import Ed25519Signer
    return Ed25519Signer(hashlib.sha256(seed).digest())


def _build_log(path, signer, n=4):
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer)
    for i in range(n):
        log.append({"event": "tool_call", "tool": "t%d" % i,
                    "decision": "allow"})
    return log


def _adapter(seed=b"offline-bundle-unit-test-log"):
    from gov.anchor_adapter import FakeLogAdapter
    return FakeLogAdapter(hashlib.sha256(seed).digest())


class OfflineBundleExportTest(unittest.TestCase):
    def setUp(self):
        provision_test_key()
        self.tmp = tempfile.mkdtemp(prefix="ob_ut_")
        self.signer = _signer()
        self.log_path = os.path.join(self.tmp, "audit.jsonl")
        _build_log(self.log_path, self.signer)
        self.adapter = _adapter()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _export(self, **kw):
        kw.setdefault("entry_signer_pubkey", self.signer.public_key)
        return export_offline_bundle(
            self.log_path, os.path.join(self.tmp, "bundle"),
            self.adapter, **kw)

    def test_output_shape(self):
        d = self._export()
        for f in REQUIRED_FILES:
            self.assertTrue(os.path.isfile(os.path.join(d, f)), f)
        with open(os.path.join(d, "manifest.json"),
                  encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["bundle_format"],
                         "offline-evidence-bundle/1.0")
        self.assertEqual(manifest["window"]["entry_count"], 4)
        self.assertIn("redaction_report", manifest)
        self.assertIn("trust", manifest)
        with open(os.path.join(d, "ledger.jsonl"),
                  encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()]
        self.assertEqual(len(lines), 4)
        for ln in lines:
            e = json.loads(ln)
            self.assertIn("export_hash", e)
            self.assertFalse(e["redacted"])

    def test_refuses_broken_source_chain(self):
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write('{"seq": 999, "bogus": true}\n')
        with self.assertRaises(OfflineBundleError):
            self._export()

    def test_refuses_unsigned_entries(self):
        from gov.log import ActionLog
        os.remove(self.log_path)
        ActionLog(self.log_path).append(
            {"event": "tool_call", "tool": "x"})  # no signer
        with self.assertRaises(OfflineBundleError):
            self._export()

    def test_refuses_reserved_redaction_fields(self):
        for field in ("seq", "hash", "prev_hash", "ed_sig"):
            with self.assertRaises(OfflineBundleError):
                export_offline_bundle(
                    self.log_path, os.path.join(self.tmp, "b2"),
                    self.adapter,
                    entry_signer_pubkey=self.signer.public_key,
                    redact_fields=(field,))

    def test_refuses_gapped_window(self):
        with self.assertRaises(OfflineBundleError):
            self._export(from_seq=2, to_seq=99)

    def test_requires_entry_signer_pubkey(self):
        with self.assertRaises(OfflineBundleError):
            export_offline_bundle(
                self.log_path, os.path.join(self.tmp, "b3"),
                self.adapter, entry_signer_pubkey=None)

    def test_wrong_entry_signer_pubkey(self):
        from gov.signing import Ed25519Signer
        other = Ed25519Signer(hashlib.sha256(b"someone-else").digest())
        with self.assertRaises(OfflineBundleError):
            export_offline_bundle(
                self.log_path, os.path.join(self.tmp, "b4"),
                self.adapter, entry_signer_pubkey=other.public_key)

    def test_redaction_listed_and_absent(self):
        d = self._export(redact_fields=("tool",))
        with open(os.path.join(d, "manifest.json"),
                  encoding="utf-8") as f:
            manifest = json.load(f)
        rr = manifest["redaction_report"]
        self.assertEqual(rr["entries_redacted"], 4)
        with open(os.path.join(d, "ledger.jsonl"),
                  encoding="utf-8") as f:
            for ln in f:
                if not ln.strip():
                    continue
                e = json.loads(ln)
                self.assertTrue(e["redacted"])
                self.assertNotIn("tool", e)
                self.assertNotIn("ed_sig", e)

    def test_refuses_invalid_entry_signature(self):
        # Corrupt one entry's signature (HMAC chain still verifies, so
        # this isolates the export-time Ed25519 check).
        with open(self.log_path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        e = json.loads(lines[1])
        e["ed_sig"] = "ff" * 64
        lines[1] = json.dumps(e)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        with self.assertRaises(OfflineBundleError):
            self._export()

    def test_window_subslice(self):
        d = self._export(from_seq=2, to_seq=3)
        with open(os.path.join(d, "ledger.jsonl"),
                  encoding="utf-8") as f:
            seqs = [json.loads(ln)["seq"] for ln in f if ln.strip()]
        self.assertEqual(seqs, [2, 3])
        with open(os.path.join(d, "manifest.json"),
                  encoding="utf-8") as f:
            rr = json.load(f)["redaction_report"]
        self.assertEqual(rr["window_withheld"]["before_from_seq"], 1)
        self.assertEqual(rr["window_withheld"]["after_to_seq"], 1)


if __name__ == "__main__":
    unittest.main()
