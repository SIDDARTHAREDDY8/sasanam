#!/usr/bin/env python3
"""Wave-201 lane B: unit tests for gov.rotation_policy (public seams).

Hermetic: FakeKmsProvider, injected clock, fake head pinner, tmp dirs.
The tests/__init__ harness provisions the audit-log HMAC key
process-wide; no test touches the network.
"""

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from gov import rotation_policy as rp
from gov.kms import FakeKmsProvider, KmsError


class _Clock:
    def __init__(self, start=1_700_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _Pinner:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, log_path, seq, head_hash):
        self.calls.append((log_path, seq, head_hash))
        if self.fail:
            raise RuntimeError("simulated pinner outage")
        return {"pinned_seq": seq, "head_hash": head_hash}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rotunit-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True))
        self.clock = _Clock()
        self.pinner = _Pinner()
        self.provider = FakeKmsProvider(["master-1"])

    def _ring(self, **kw):
        kw.setdefault("policy", {"grace_period_s": 100})
        return rp.VersionedRing.bootstrap(
            str(self.tmp / "keyring.json"), self.provider, "master-1",
            "alice",
            audit_log_path=str(self.tmp / "audit.jsonl"),
            deployment_mode="staging",
            head_pinner=kw.pop("head_pinner", self.pinner),
            clock=self.clock, **kw)

    def _log(self):
        with io.open(str(self.tmp / "audit.jsonl"),
                     encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def _events(self):
        return [e["event"] for e in self._log()]


class BootstrapTest(_Base):
    def test_bootstrap_chains_ceremony_and_pins(self):
        ring = self._ring()
        d = ring.describe()
        self.assertEqual(d["active_epoch"], "epoch-1")
        self.assertEqual(d["version_floor"], 1)
        self.assertEqual(
            [v["epoch"] for v in d["versions"]], ["epoch-1"])
        self.assertEqual(d["versions"][0]["state"], "active")
        self.assertIn("keyring_bootstrap", self._events())
        self.assertIn("rotation_head_pinned", self._events())
        self.assertTrue(self.pinner.calls)

    def test_bootstrap_requires_audit_log_path(self):
        with self.assertRaises(rp.RotationError):
            rp.VersionedRing(
                str(self.tmp / "k.json"),
                audit_log_path=None, deployment_mode="staging")

    def test_bootstrap_no_pinner_refuses_before_mutation(self):
        with self.assertRaises(rp.RotationError) as cm:
            rp.VersionedRing.bootstrap(
                str(self.tmp / "keyring.json"), self.provider,
                "master-1", "alice",
                audit_log_path=str(self.tmp / "audit.jsonl"),
                deployment_mode="staging", head_pinner=None,
                clock=self.clock,
                policy={"grace_period_s": 100,
                        "require_head_pin": True})
        self.assertIn("head_pinner", str(cm.exception))
        self.assertFalse((self.tmp / "keyring.json").exists())

    def test_sidecar_and_keyring_are_0600(self):
        self._ring()
        for name in ("keyring.json", "keyring.json.rotation.json"):
            mode = stat.S_IMODE((self.tmp / name).stat().st_mode)
            self.assertEqual(mode, 0o600, name)


class CeremonyTest(_Base):
    def _rotated(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        new_epoch = ring.approve_pending(pid, "bob", self.provider)
        return ring, new_epoch

    def test_happy_path(self):
        ring, new_epoch = self._rotated()
        self.assertEqual(new_epoch, "epoch-2")
        d = ring.describe()
        states = {v["epoch"]: v["state"] for v in d["versions"]}
        self.assertEqual(states, {"epoch-1": "decrypt_only",
                                  "epoch-2": "active"})
        self.assertIsNone(d["pending"])
        self.assertFalse(d["stuck"])
        for want in ("rotation_proposed", "rotation_wrapped_new",
                     "rotation_complete", "rotation_head_pinned"):
            self.assertIn(want, self._events())

    def test_self_approval_refused(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        with self.assertRaises(rp.RotationError) as cm:
            ring.approve_pending(pid, "alice", self.provider)
        self.assertIn("self-approval", str(cm.exception))
        self.assertEqual(ring.describe()["active_epoch"], "epoch-1")

    def test_quorumless_and_mismatched_refused(self):
        ring = self._ring()
        with self.assertRaises(rp.RotationError):
            ring.approve_pending("nope", "bob", self.provider)
        pid = ring.begin_rotation("alice")
        with self.assertRaises(rp.RotationError):
            ring.approve_pending("wrong-id", "bob", self.provider)

    def test_double_begin_refused(self):
        ring = self._ring()
        ring.begin_rotation("alice")
        with self.assertRaises(rp.RotationError) as cm:
            ring.begin_rotation("carol")
        self.assertIn("already pending", str(cm.exception))

    def test_empty_operators_refused(self):
        ring = self._ring()
        for bad in ("", "   ", None, 123):
            with self.assertRaises(rp.RotationError):
                ring.begin_rotation(bad)
        pid = ring.begin_rotation("alice")
        for bad in ("", "   ", None, 123):
            with self.assertRaises(rp.RotationError):
                ring.approve_pending(pid, bad, self.provider)

    def test_kms_outage_fails_closed(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        self.provider.outage = True
        try:
            with self.assertRaises(KmsError):
                ring.approve_pending(pid, "bob", self.provider)
        finally:
            self.provider.outage = False
        d = ring.describe()
        self.assertEqual(d["active_epoch"], "epoch-1")
        self.assertEqual(d["pending"]["state"], "proposed")

    def test_missing_pinner_refuses_before_mutation(self):
        ring = self._ring()
        ring._head_pinner = None
        pid = ring.begin_rotation("alice")
        with self.assertRaises(rp.RotationError) as cm:
            ring.approve_pending(pid, "bob", self.provider)
        self.assertIn("head_pinner", str(cm.exception))
        self.assertEqual(ring.describe()["active_epoch"], "epoch-1")


class GraceFloorDestroyTest(_Base):
    def test_grace_unwrap_then_sweep(self):
        ring = self._ring()
        before = ring.unwrap_epoch(self.provider, "epoch-1")
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        self.assertEqual(ring.unwrap_epoch(self.provider, "epoch-1"),
                         before)
        self.clock.advance(101)
        self.assertEqual(ring.sweep_grace(), ["epoch-1"])
        states = {v["epoch"]: v["state"]
                  for v in ring.describe()["versions"]}
        self.assertEqual(states["epoch-1"], "retired")
        # History stays verifiable below the floor.
        self.assertEqual(len(ring.unwrap_epoch(self.provider,
                                               "epoch-1")), 32)
        self.assertIn("grace_expired", self._events())

    def test_lazy_sweep_on_unwrap_path(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        self.clock.advance(101)
        ring.unwrap_epoch(self.provider, "epoch-1")  # sweeps lazily
        states = {v["epoch"]: v["state"]
                  for v in ring.describe()["versions"]}
        self.assertEqual(states["epoch-1"], "retired")

    def test_destroy(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        with self.assertRaises(rp.RotationError):
            ring.destroy_version("epoch-2", "carol")  # active
        ring.destroy_version("epoch-1", "carol")
        with self.assertRaises(rp.RotationError) as cm:
            ring.unwrap_epoch(self.provider, "epoch-1")
        self.assertIn("destroyed", str(cm.exception))
        self.assertIn("version_destroyed", self._events())

    def test_floor(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        self.assertEqual(ring.set_floor(2), 2)
        with self.assertRaises(rp.RotationError) as cm:
            ring.unwrap_epoch(self.provider, "epoch-1")
        self.assertIn("below version floor", str(cm.exception))
        self.assertEqual(len(ring.unwrap_epoch(self.provider,
                                               "epoch-2")), 32)
        with self.assertRaises(rp.RotationError):
            ring.set_floor(1)  # lowering refused
        for bad in (0, -1, "2", 2.0, True):
            with self.assertRaises(rp.RotationError):
                ring.set_floor(bad)

    def test_unknown_version_refused(self):
        ring = self._ring()
        with self.assertRaises(rp.RotationError) as cm:
            ring.unwrap_epoch(self.provider, "epoch-99")
        self.assertIn("unknown version", str(cm.exception))


class StuckTest(_Base):
    def _crashed(self):
        """A ring whose approve died between wrap and activate."""
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        orig = rp.VersionedRing._activate_locked

        def _crash(*a, **k):
            raise RuntimeError("simulated kill -9")

        rp.VersionedRing._activate_locked = _crash
        try:
            with self.assertRaises(RuntimeError):
                ring.approve_pending(pid, "bob", self.provider)
        finally:
            rp.VersionedRing._activate_locked = orig
        return ring

    def _reloaded(self, ring):
        return rp.VersionedRing.load(
            str(self.tmp / "keyring.json"),
            audit_log_path=str(self.tmp / "audit.jsonl"),
            deployment_mode="staging", head_pinner=self.pinner,
            clock=self.clock)

    def test_stuck_reconcile(self):
        ring2 = self._reloaded(self._crashed())
        d = ring2.describe()
        self.assertTrue(d["stuck"])
        self.assertEqual(d["active_epoch"], "epoch-1")  # no silent switch
        self.assertIn("epoch-1", d["pending"]["stuck_reason"])
        self.assertIn("epoch-2", d["pending"]["stuck_reason"])
        self.assertIn("rotation_stuck", self._events())
        with self.assertRaises(rp.RotationError) as cm:
            ring2.begin_rotation("carol")
        self.assertIn("STUCK", str(cm.exception))

    def test_complete_stuck(self):
        ring2 = self._reloaded(self._crashed())
        with self.assertRaises(rp.RotationError):  # quorum still applies
            ring2.complete_stuck(self.provider, "alice")
        self.assertEqual(ring2.complete_stuck(self.provider, "bob"),
                         "epoch-2")
        d = ring2.describe()
        self.assertFalse(d["stuck"])
        self.assertEqual(d["active_epoch"], "epoch-2")
        self.assertEqual(ring2.audit_no_silent_swap()["violations"], [])

    def test_discard_stuck(self):
        ring2 = self._reloaded(self._crashed())
        self.assertEqual(
            ring2.discard_stuck("bad timing", "carol"), "epoch-2")
        d = ring2.describe()
        self.assertFalse(d["stuck"])
        self.assertIsNone(d["pending"])
        self.assertEqual(d["active_epoch"], "epoch-1")
        self.assertNotIn("epoch-2",
                         [v["epoch"] for v in d["versions"]])
        self.assertIn("rotation_discarded", self._events())

    def test_pinner_failure_keeps_journal(self):
        ring = self._ring()
        ring._head_pinner = _Pinner(fail=True)
        pid = ring.begin_rotation("alice")
        with self.assertRaises(rp.RotationError) as cm:
            ring.approve_pending(pid, "bob", self.provider)
        self.assertIn("head_pinner failed", str(cm.exception))
        ring2 = self._reloaded(ring)
        self.assertTrue(ring2.describe()["stuck"])
        ring2.complete_stuck(self.provider, "bob")  # good pinner now
        self.assertEqual(ring2.describe()["active_epoch"], "epoch-2")


class AuditTest(_Base):
    def test_no_silent_swap_clean(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        report = ring.audit_no_silent_swap()
        self.assertEqual(report["violations"], [])

    def test_silent_swap_flagged(self):
        from gov.keys import rotation_lock
        from gov.kms import EnvelopeKeyRing
        ring = self._ring()
        evil = EnvelopeKeyRing._wrap_new(self.provider, "master-1",
                                         "epoch-9")
        with rotation_lock(str(self.tmp / "keyring.json")):
            ring._ring._wrapped["epoch-9"] = evil
            ring._versions["epoch-9"] = {
                "state": "active", "grace_deadline": None,
                "key_id": evil.key_id, "kms_key_id": "master-1",
                "created_at": self.clock(),
            }
            ring._save_all()
        with self.assertRaises(rp.RotationError) as cm:
            ring.audit_no_silent_swap()
        self.assertIn("no chained ceremony", str(cm.exception))

    def test_log_tamper_detected(self):
        ring = self._ring()
        path = str(self.tmp / "audit.jsonl")
        lines = io.open(path, encoding="utf-8").read().splitlines()
        rec = json.loads(lines[0])
        rec["event"] = "forged"
        lines[0] = json.dumps(rec)
        io.open(path, "w", encoding="utf-8").write(
            "\n".join(lines) + "\n")
        with self.assertRaises(rp.RotationError) as cm:
            ring.audit_no_silent_swap()
        self.assertIn("chain", str(cm.exception))

    def test_unpinned_head_flagged(self):
        ring = rp.VersionedRing.bootstrap(
            str(self.tmp / "keyring.json"), self.provider, "master-1",
            "alice",
            audit_log_path=str(self.tmp / "audit.jsonl"),
            deployment_mode="staging", head_pinner=None,
            clock=self.clock,
            policy={"grace_period_s": 100, "require_head_pin": False})
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        self.assertIn("rotation_head_unpinned", self._events())
        with self.assertRaises(rp.RotationError) as cm:
            ring.audit_no_silent_swap()
        self.assertIn("unpinned", str(cm.exception))

    def test_material_free(self):
        ring = self._ring()
        pid = ring.begin_rotation("alice")
        ring.approve_pending(pid, "bob", self.provider)
        blobs = {ring._ring.get(ep).wrapped_blob.hex()
                 for ep in ("epoch-1", "epoch-2")}
        desc_text = json.dumps(ring.describe())
        log_text = io.open(str(self.tmp / "audit.jsonl"),
                           encoding="utf-8").read()
        for b in blobs:
            self.assertNotIn(b, desc_text)
            self.assertNotIn(b, log_text)

    def test_due_for_rotation(self):
        ring = rp.VersionedRing.bootstrap(
            str(self.tmp / "keyring.json"), self.provider, "master-1",
            "alice",
            audit_log_path=str(self.tmp / "audit.jsonl"),
            deployment_mode="staging", head_pinner=self.pinner,
            clock=self.clock,
            policy={"grace_period_s": 100,
                    "auto_rotate_period_s": 50})
        self.assertFalse(ring.due_for_rotation())
        self.clock.advance(50)
        self.assertTrue(ring.due_for_rotation())
        manual = self._ring()  # no auto period
        self.clock.advance(10 ** 6)
        self.assertFalse(manual.due_for_rotation())


if __name__ == "__main__":
    unittest.main()
