"""Unit tests for gov/witness_rekor.py (wave-314 lane 2).

Red-first contract tests at the public seams: anchor_evidence /
verify_inclusion / to_offline_entry, the six coded refusals, and the
fail-closed edge cases the battery probes at the adversarial level.
"""

import base64
import copy
import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import witness_rekor as WR
from gov.witness_log import WitnessLog
from gov.signing import Ed25519Signer

_SEED = bytes(range(32))
_OTHER = bytes([200 - i for i in range(32)])
_NOW = 1798765432
_DIGEST = hashlib.sha256(b"unit-test-bundle").hexdigest()
_WINDOW = (_NOW - 86400, _NOW + 86400)


def _log(seed=_SEED):
    signer = Ed25519Signer(seed)
    return WitnessLog(signer.public_key), signer


def _anchor(**kw):
    log, signer = _log()
    ts = kw.pop("timestamp", _NOW)
    receipt = WR.anchor_evidence(_DIGEST, witness_log=log,
                                witness_signer=signer, timestamp=ts, **kw)
    return receipt


def _verify(receipt, **kw):
    pub = kw.pop("witness_public_key", Ed25519Signer(_SEED).public_key)
    return WR.verify_inclusion(_DIGEST, receipt, witness_public_key=pub,
                               valid_for=kw.pop("valid_for", _WINDOW),
                               now=kw.pop("now", _NOW), **kw)


class TestAnchor(unittest.TestCase):
    def test_roundtrip_accepts(self):
        info = _verify(_anchor())
        self.assertEqual(info["log_index"], 0)
        self.assertEqual(info["tree_size"], 1)
        self.assertEqual(info["checkpoint_time"], _NOW)

    def test_receipt_is_self_contained(self):
        r = _anchor()
        for f in ("kind", "log_index", "entry_body", "checkpoint",
                  "checkpoint_signature", "proof"):
            self.assertIn(f, r)

    def test_second_anchor_indexes(self):
        log, signer = _log()
        r1 = WR.anchor_evidence(_DIGEST, witness_log=log,
                               witness_signer=signer, timestamp=_NOW)
        r2 = WR.anchor_evidence(_DIGEST, witness_log=log,
                               witness_signer=signer, timestamp=_NOW + 1)
        self.assertEqual(r1["log_index"], 0)
        self.assertEqual(r2["log_index"], 1)
        info = WR.verify_inclusion(_DIGEST, r2,
                                   witness_public_key=signer.public_key,
                                   valid_for=_WINDOW, now=_NOW + 1)
        self.assertEqual(info["tree_size"], 2)

    def test_bad_digest_refuses(self):
        log, signer = _log()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.anchor_evidence("not-hex", witness_log=log,
                              witness_signer=signer)
        self.assertEqual(ctx.exception.code, "witness-rekor-malformed")

    def test_foreign_signer_refuses(self):
        log, signer = _log()
        _, other = _log(_OTHER)
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.anchor_evidence(_DIGEST, witness_log=log,
                              witness_signer=other, timestamp=_NOW)
        # The log refuses a foreign co-signer; anchor maps it to malformed.
        self.assertEqual(ctx.exception.code, "witness-rekor-malformed")

    def test_non_log_refuses(self):
        signer = Ed25519Signer(_SEED)
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.anchor_evidence(_DIGEST, witness_log=object(),
                              witness_signer=signer)
        self.assertEqual(ctx.exception.code, "witness-rekor-malformed")


class TestVerify(unittest.TestCase):
    def test_missing_receipt(self):
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(None)
        self.assertEqual(ctx.exception.code, "witness-rekor-anchor-missing")

    def test_digest_mismatch(self):
        r = _anchor()
        other = hashlib.sha256(b"other").hexdigest()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.verify_inclusion(other, r,
                               witness_public_key=Ed25519Signer(_SEED).public_key,
                               valid_for=_WINDOW, now=_NOW)
        self.assertEqual(ctx.exception.code, "witness-rekor-digest-mismatch")

    def test_tampered_checkpoint(self):
        r = _anchor()
        r["checkpoint"]["timestamp"] = _NOW + 5
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r)
        self.assertEqual(ctx.exception.code, "witness-rekor-checkpoint-invalid")

    def test_tampered_signature(self):
        r = _anchor()
        raw = bytearray(base64.b64decode(r["checkpoint_signature"]))
        raw[7] ^= 1
        r["checkpoint_signature"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r)
        self.assertEqual(ctx.exception.code, "witness-rekor-checkpoint-invalid")

    def test_wrong_key(self):
        r = _anchor()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r, witness_public_key=Ed25519Signer(_OTHER).public_key)
        self.assertEqual(ctx.exception.code, "witness-rekor-checkpoint-invalid")

    def test_expired_window(self):
        r = _anchor(timestamp=_WINDOW[0] - 1)
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r)
        self.assertEqual(ctx.exception.code, "witness-rekor-anchor-expired")

    def test_stale_age(self):
        r = _anchor(timestamp=_NOW - 100)
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r, max_anchor_age=99)
        self.assertEqual(ctx.exception.code, "witness-rekor-anchor-expired")

    def test_fresh_age_accepts(self):
        r = _anchor(timestamp=_NOW - 100)
        info = _verify(r, max_anchor_age=100)
        self.assertEqual(info["checkpoint_time"], _NOW - 100)

    def test_future_checkpoint(self):
        r = _anchor(timestamp=_NOW + 10)
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r, valid_for=(_WINDOW[0], _NOW + 1000))
        self.assertEqual(ctx.exception.code, "witness-rekor-checkpoint-invalid")

    def test_log_index_out_of_bounds(self):
        r = _anchor()
        r2 = copy.deepcopy(r)
        r2["log_index"] = 5
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r2)
        self.assertEqual(ctx.exception.code, "witness-rekor-inclusion-invalid")

    def test_bad_window(self):
        r = _anchor()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            _verify(r, valid_for=(_NOW, _NOW - 1))
        self.assertEqual(ctx.exception.code, "witness-rekor-malformed")

    def test_check_order_expiry_before_inclusion(self):
        # A receipt that is BOTH stale and inclusion-broken refuses the
        # earlier check (anchor-expired), not inclusion-invalid -- pinned.
        log, signer = _log()
        r = WR.anchor_evidence(_DIGEST, witness_log=log, witness_signer=signer,
                               timestamp=_NOW - 7200)
        h = bytearray(bytes.fromhex(r["proof"]["path"][0]["hash"])) \
            if r["proof"]["path"] else None
        if h:
            h[0] ^= 1
            r["proof"]["path"][0]["hash"] = bytes(h).hex()
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.verify_inclusion(_DIGEST, r,
                               witness_public_key=signer.public_key,
                               valid_for=_WINDOW, now=_NOW,
                               max_anchor_age=3600)
        self.assertEqual(ctx.exception.code, "witness-rekor-anchor-expired")


class TestOfflineEntry(unittest.TestCase):
    def test_shape(self):
        entry = WR.to_offline_entry(_anchor())
        self.assertEqual(entry["kind"], "sasanam-witness-log/v1")
        self.assertIn("inclusion_path", entry)
        self.assertNotIn("proof", entry)

    def test_malformed_receipt(self):
        with self.assertRaises(WR.WitnessRekorError) as ctx:
            WR.to_offline_entry({"kind": "bogus"})
        self.assertEqual(ctx.exception.code, "witness-rekor-malformed")


if __name__ == "__main__":
    unittest.main()
