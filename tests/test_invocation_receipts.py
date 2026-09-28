"""Unit tests for gov.invocation_receipts (wave-175 lane 1).

Module-level: key resolution (keyprovider idiom, no dev fallback),
receipt build/countersign/verify round-trip, tamper resistance, pinned
authorship, and the never-raises verifier contract. Executor integration
lives in evals/invocation_receipt_battery.py.
"""

import copy
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import ed25519 as _ed
from gov import evidence_verify as _ev
from gov import invocation_receipts as ir


SEED = bytes.fromhex("11" * 32)
PUB = _ed.publickey(SEED)
PUB_HEX = PUB.hex()
KID = hashlib.sha256(PUB).digest()[:16].hex()


def _body(**over):
    body = ir.build_receipt(
        holder={"agent_id": "a1", "role": "coder", "principal": "dev-org",
                "run_id": "run-1"},
        challenge="appr-1",
        action_tool="delete_file",
        action_args={"path": "data/x.txt"},
        canonical_target="/sandbox/data/x.txt",
        policy_decision="execution_authorized",
        approval_id="appr-1",
        policy_id="pol-1",
        preview_text="delete data/x.txt",
        outcome_status="executed",
        result={"status": "executed"},
        key_id=KID,
        pubkey_hex=PUB_HEX,
        issued_at="2026-09-28T00:00:00+00:00")
    body.update(over)
    return body


class TestKeyResolution(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k)
                       for k in ("GOV_RECEIPT_KEY", "GOV_RECEIPT_KEY_FILE")}
        os.environ.pop("GOV_RECEIPT_KEY", None)
        os.environ.pop("GOV_RECEIPT_KEY_FILE", None)
        self.tmp = tempfile.mkdtemp(prefix="receipt-key-")

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_explicit_seed(self):
        k = ir.resolve_receipt_key(explicit=SEED.hex())
        self.assertEqual(k["key_id"], KID)
        self.assertEqual(k["pubkey_hex"], PUB_HEX)

    def test_env_key(self):
        os.environ["GOV_RECEIPT_KEY"] = SEED.hex()
        k = ir.resolve_receipt_key()
        self.assertEqual(k["key_id"], KID)

    def test_env_key_beats_nothing(self):
        with self.assertRaises(ir.NoReceiptKeyError):
            ir.resolve_receipt_key()

    def test_malformed_env_key(self):
        os.environ["GOV_RECEIPT_KEY"] = "zz"
        with self.assertRaises(ir.NoReceiptKeyError):
            ir.resolve_receipt_key()

    def test_short_env_key(self):
        os.environ["GOV_RECEIPT_KEY"] = "00" * 31
        with self.assertRaises(ir.NoReceiptKeyError):
            ir.resolve_receipt_key()

    def test_key_file(self):
        p = os.path.join(self.tmp, "receipt.key")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SEED.hex() + "\n")
        os.chmod(p, 0o600)
        os.environ["GOV_RECEIPT_KEY_FILE"] = p
        k = ir.resolve_receipt_key()
        self.assertEqual(k["key_id"], KID)

    def test_key_file_bad_permissions_refused(self):
        p = os.path.join(self.tmp, "receipt.key")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SEED.hex())
        os.chmod(p, 0o644)
        os.environ["GOV_RECEIPT_KEY_FILE"] = p
        with self.assertRaises(ir.NoReceiptKeyError):
            ir.resolve_receipt_key()

    def test_key_file_missing_refused(self):
        os.environ["GOV_RECEIPT_KEY_FILE"] = os.path.join(
            self.tmp, "nope.key")
        with self.assertRaises(ir.NoReceiptKeyError):
            ir.resolve_receipt_key()


class TestRoundTrip(unittest.TestCase):
    def test_build_countersign_verify(self):
        body = _body()
        self.assertNotIn("signature", body)
        receipt = ir.countersign(body, SEED)
        self.assertIn("signature", receipt)
        # build_receipt must not mutate / must not sign in place.
        self.assertNotIn("signature", body)
        ok, reason = ir.verify_receipt(receipt)
        self.assertTrue(ok, reason)

    def test_signing_input_deterministic_and_domained(self):
        body = _body()
        a = ir.signing_input(body)
        b = ir.signing_input(copy.deepcopy(body))
        self.assertEqual(a, b)
        self.assertTrue(
            a.startswith(b"agent-governance/invocation-receipt/v1."))

    def test_args_digest_binds_exact_args(self):
        body = _body()
        from gov import precommit as pc
        self.assertEqual(body["action"]["args_digest"],
                         pc.args_digest("delete_file",
                                        {"path": "data/x.txt"}))

    def test_result_digested_not_embedded(self):
        receipt = ir.countersign(_body(), SEED)
        blob = str(receipt["outcome"])
        self.assertIn("result_digest", blob)
        # The raw result dict is not embedded anywhere in the receipt.
        self.assertNotIn("executed", str(receipt["outcome"]["result_digest"]))


class TestTamper(unittest.TestCase):
    def setUp(self):
        self.receipt = ir.countersign(_body(), SEED)

    def _tampered(self, *path, value):
        r = copy.deepcopy(self.receipt)
        node = r
        for p in path[:-1]:
            node = node[p]
        node[path[-1]] = value
        return r

    def test_tamper_args_digest(self):
        ok, _ = ir.verify_receipt(
            self._tampered("action", "args_digest", value="0" * 64))
        self.assertFalse(ok)

    def test_tamper_canonical_target(self):
        ok, _ = ir.verify_receipt(
            self._tampered("action", "canonical_target",
                           value="/etc/other"))
        self.assertFalse(ok)

    def test_tamper_policy_decision(self):
        ok, _ = ir.verify_receipt(
            self._tampered("policy", "decision",
                           value="execution_refused"))
        self.assertFalse(ok)

    def test_tamper_preview_digest(self):
        ok, _ = ir.verify_receipt(
            self._tampered("preview_digest", value="f" * 64))
        self.assertFalse(ok)

    def test_tamper_challenge(self):
        ok, _ = ir.verify_receipt(
            self._tampered("challenge", value="appr-evil"))
        self.assertFalse(ok)

    def test_tamper_outcome(self):
        ok, _ = ir.verify_receipt(
            self._tampered("outcome", "status", value="refused"))
        self.assertFalse(ok)

    def test_tamper_holder(self):
        ok, _ = ir.verify_receipt(
            self._tampered("holder", "agent_id", value="mallory"))
        self.assertFalse(ok)

    def test_strip_signature(self):
        r = copy.deepcopy(self.receipt)
        del r["signature"]
        ok, _ = ir.verify_receipt(r)
        self.assertFalse(ok)

    def test_swap_key_id(self):
        r = self._tampered("authority", "kid", value="00" * 8)
        ok, _ = ir.verify_receipt(r)
        self.assertFalse(ok)

    def test_wrong_key(self):
        other = _ed.publickey(bytes.fromhex("22" * 32))
        r = copy.deepcopy(self.receipt)
        r["authority"]["pubkey"] = other.hex()
        r["authority"]["kid"] = hashlib.sha256(
            other).digest()[:16].hex()
        ok, reason = ir.verify_receipt(r)
        self.assertFalse(ok, reason)

    def test_audience_mismatch(self):
        ok, _ = ir.verify_receipt(
            self._tampered("audience", value="other"))
        self.assertFalse(ok)

    def test_unsupported_version(self):
        ok, _ = ir.verify_receipt(
            self._tampered("receipt_version", value=999))
        self.assertFalse(ok)


class TestNeverRaises(unittest.TestCase):
    def test_garbage_inputs(self):
        for bad in (None, "x", 42, [], {},
                    {"receipt_version": 1},
                    {"receipt_version": 1, "signature": "!!!"}):
            ok, reason = ir.verify_receipt(bad)
            self.assertFalse(ok, bad)
            self.assertIsInstance(reason, str)


class TestPinned(unittest.TestCase):
    """Pinned authorship lives in the stdlib-only verifier
    (_verify_receipt_pinned_standalone) so the offline path and V17 share
    one implementation."""

    def setUp(self):
        self.receipt = ir.countersign(_body(), SEED)

    def test_pinned_ok(self):
        ok, _ = _ev._verify_receipt_pinned_standalone(self.receipt, PUB_HEX)
        self.assertTrue(ok)

    def test_pinned_ok_case_insensitive(self):
        ok, _ = _ev._verify_receipt_pinned_standalone(
            self.receipt, PUB_HEX.upper())
        self.assertTrue(ok)

    def test_pinned_wrong_key(self):
        ok, reason = _ev._verify_receipt_pinned_standalone(
            self.receipt, "22" * 32)
        self.assertFalse(ok)
        self.assertIn("pinned", reason)

    def test_pinned_malformed(self):
        ok, _ = _ev._verify_receipt_pinned_standalone(self.receipt, "zz")
        self.assertFalse(ok)

    def test_pinned_rejects_bad_receipt(self):
        r = copy.deepcopy(self.receipt)
        r["action"]["args_digest"] = "0" * 64
        ok, _ = _ev._verify_receipt_pinned_standalone(r, PUB_HEX)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
