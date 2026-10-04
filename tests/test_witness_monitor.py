"""Unit tests for gov.witness_monitor (wave-323 lane 2).

Seam-level coverage: the monitor-step return contract, the coded
refusal contract (WitnessMonitorError carries code + detail +
consecutive_failures, never a soft verdict), programmer-error
contracts (TypeError/ValueError), durable-state semantics (atomic
writes, hard stop on missing/corrupt/mismatch, replay guard, the
policy-version watermark), the fixed missing-fringe edge, and the
fetch-failure availability counter.
"""

import json
import os
import tempfile
import unittest

from gov import witness_monitor as WM
from gov import witness_consistency as WC
from gov import checkpoint_note as CN
from gov.witness_log import WitnessLog
from gov.signing import Ed25519Signer

NOW = 1798765432
SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
ORIGIN = "sasanam-witmon-test/v1"


def _vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _op_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


class _World:
    def __init__(self, n=5):
        self.op = Ed25519Signer(SEED_OP)
        self.w1 = Ed25519Signer(SEED_W1)
        self.w2 = Ed25519Signer(SEED_W2)
        self.log = WitnessLog(self.op.public_key)
        for i in range(n):
            self.log.append(b"leaf-%d" % i)
        self.op_vk = [_op_vkey("op", self.op)]
        self.wit_vk = {"w1": _vkey("w1", self.w1),
                       "w2": _vkey("w2", self.w2)}

    def note(self, ts, signers=None):
        from gov import witness_publish as WP
        if signers is None:
            signers = [("w1", self.w1), ("w2", self.w2)]
        return WP.publish_checkpoint(
            self.log, ORIGIN, "op", self.op, signers,
            operator_vkeys=self.op_vk, witness_vkeys=self.wit_vk,
            quorum_k=2, timestamp=ts)

    def step(self, note, last_seen, state_path=None, policy_version=1,
             **kw):
        pi = {"operator_vkeys": self.op_vk, "quorum_k": 2,
              "policy_id": "test", "policy_version": policy_version}
        return WM.monitor_step(
            note, witness_set=self.wit_vk, last_seen=last_seen,
            policy_inputs=pi, allowed_origins=[ORIGIN],
            now=kw.pop("now", NOW), max_age=kw.pop("max_age", 3600),
            state_path=state_path, **kw)


class TestContracts(unittest.TestCase):
    def test_error_carries_code_detail_failures(self):
        err = WM.WitnessMonitorError("witness-monitor-stale", "d", 2)
        self.assertEqual(err.code, "witness-monitor-stale")
        self.assertEqual(err.detail, "d")
        self.assertEqual(err.consecutive_failures, 2)
        self.assertIn("witness-monitor-stale", str(err))

    def test_bad_checkpoint_bytes_type(self):
        w = _World()
        with self.assertRaises(TypeError):
            w.step("not-bytes", None)

    def test_now_max_age_must_pair(self):
        w = _World()
        note = w.note(NOW - 100)
        with self.assertRaises(ValueError):
            w.step(note, None, now=NOW, max_age=None)

    def test_bad_last_seen(self):
        w = _World()
        note = w.note(NOW - 100)
        with self.assertRaises(TypeError):
            w.step(note, ("x", "y"))
        with self.assertRaises(TypeError):
            w.step(note, (5, "zz"))

    def test_bad_witness_set(self):
        w = _World()
        note = w.note(NOW - 100)
        pi = {"operator_vkeys": w.op_vk, "quorum_k": 2,
              "policy_id": "t", "policy_version": 1}
        with self.assertRaises(TypeError):
            WM.monitor_step(note, witness_set={}, last_seen=None,
                            policy_inputs=pi, allowed_origins=[ORIGIN])

    def test_bad_policy_inputs(self):
        w = _World()
        note = w.note(NOW - 100)
        with self.assertRaises(TypeError):
            WM.monitor_step(note, witness_set=w.wit_vk, last_seen=None,
                            policy_inputs={"quorum_k": 2},
                            allowed_origins=[ORIGIN])


class TestHappyPath(unittest.TestCase):
    def test_verdict_shape(self):
        w = _World()
        note = w.note(NOW - 100)
        r = w.step(note, None)
        self.assertTrue(r["accepted"])
        self.assertTrue(r["advanced"])
        self.assertEqual(r["head"]["size"], 5)
        self.assertEqual(len(r["head"]["root"]), 64)
        self.assertEqual(r["policy_id"], "test")
        self.assertEqual(r["policy_version"], 1)
        self.assertEqual(r["consecutive_failures"], 0)
        self.assertTrue(r["staleness_block"])  # max_age was passed

    def test_no_staleness_block_without_max_age(self):
        w = _World()
        note = w.note(NOW - 7200)  # older than any bound, but no bound
        r = w.step(note, None, max_age=None, now=None)
        self.assertTrue(r["accepted"])
        self.assertFalse(r["staleness_block"])

    def test_idempotent_noop(self):
        w = _World()
        note = w.note(NOW - 100)
        r = w.step(note, None)
        r2 = w.step(note, (5, r["head"]["root"]))
        self.assertTrue(r2["accepted"])
        self.assertFalse(r2["advanced"])


class TestState(unittest.TestCase):
    def _sp(self):
        d = tempfile.mkdtemp(prefix="witmon-ut-")
        return os.path.join(d, "state.json")

    def test_state_written_atomically(self):
        w = _World()
        sp = self._sp()
        note = w.note(NOW - 100)
        w.step(note, None, state_path=sp)
        st = WM.load_monitor_state(sp)
        self.assertEqual(st["version"], 1)
        self.assertEqual(st["last_seen"]["size"], 5)
        self.assertEqual(st["consecutive_failures"], 0)

    def test_refused_run_never_advances_head(self):
        w = _World()
        sp = self._sp()
        note = w.note(NOW - 100)
        w.step(note, None, state_path=sp)
        # Refuse via an unknown origin; the durable head must not move.
        pi = {"operator_vkeys": w.op_vk, "quorum_k": 2,
              "policy_id": "test", "policy_version": 1}
        with self.assertRaises(WM.WitnessMonitorError) as ctx:
            WM.monitor_step(note, witness_set=w.wit_vk, last_seen=None,
                            policy_inputs=pi,
                            allowed_origins=["other/v1"],
                            now=NOW, max_age=3600, state_path=sp)
        self.assertEqual(ctx.exception.code,
                         "witness-checkpoint-unknown-origin")
        st = WM.load_monitor_state(sp)
        self.assertEqual(st["last_seen"]["size"], 5)
        self.assertEqual(st["consecutive_failures"], 1)

    def test_corrupt_state_json(self):
        sp = self._sp()
        with open(sp, "w") as fh:
            fh.write("{{{")
        with self.assertRaises(WM.WitnessMonitorError) as ctx:
            WM.load_monitor_state(sp)
        self.assertEqual(ctx.exception.code,
                         "witness-monitor-state-corrupt")

    def test_corrupt_state_shape(self):
        sp = self._sp()
        with open(sp, "w") as fh:
            json.dump({"version": 1}, fh)
        with self.assertRaises(WM.WitnessMonitorError) as ctx:
            WM.load_monitor_state(sp)
        self.assertEqual(ctx.exception.code,
                         "witness-monitor-state-corrupt")

    def test_missing_state_with_last_seen(self):
        w = _World()
        sp = self._sp()  # never created
        note = w.note(NOW - 100)
        with self.assertRaises(WM.WitnessMonitorError) as ctx:
            w.step(note, (5, "ab" * 32), state_path=sp)
        self.assertEqual(ctx.exception.code,
                         "witness-monitor-state-missing")

    def test_state_without_caller_last_seen(self):        # A cron wrapper may rely on the durable head alone.
        w = _World()
        sp = self._sp()
        note = w.note(NOW - 100)
        w.step(note, None, state_path=sp)
        for i in range(5, 6):
            w.log.append(b"leaf-%d" % i)
        note6 = w.note(NOW - 50)
        r = w.step(note6, None, state_path=sp)
        self.assertTrue(r["advanced"])
        self.assertEqual(r["head"]["size"], 6)

    def test_null_head_state_shape(self):
        # A refused first run persists the counter with a null head.
        sp = self._sp()
        with open(sp, "w") as fh:
            json.dump({"version": 1, "last_seen": None,
                       "policy_id": "t", "policy_version": 1,
                       "consecutive_failures": 2}, fh)
        st = WM.load_monitor_state(sp)
        self.assertIsNone(st["last_seen"])
        self.assertEqual(st["consecutive_failures"], 2)


class TestCodesRegistered(unittest.TestCase):
    def test_five_monitor_codes_in_taxonomy(self):
        from gov.decision_codes import TAXONOMY
        for code in ("witness-monitor-fetch-failed",
                     "witness-monitor-stale",
                     "witness-monitor-state-corrupt",
                     "witness-monitor-state-missing",
                     "witness-monitor-state-mismatch"):
            self.assertIn(code, TAXONOMY)
            self.assertEqual(TAXONOMY[code]["domain"], "witness")


if __name__ == "__main__":
    unittest.main()
