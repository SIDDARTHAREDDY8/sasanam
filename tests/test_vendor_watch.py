#!/usr/bin/env python3
"""Unit tests for gov/vendor_watch.py (watcher v1).

Stdlib + gov.vendor_watch only. Deterministic: fixed timestamps,
temp dirs, synthetic Ed25519 seed. No network, no paid calls.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import vendor_watch as vw  # noqa: E402

NOW = "2026-10-07T12:00:00+00:00"

def _open_pending_id(store):
    for pid, rec in store.pending.items():
        if rec["status"] in ("pending", "refused"):
            return pid
    raise AssertionError("no open pending record")

SEED = bytes(range(32))


def _artifact(artifact_id="mcp:files", version="1.2.0", content=None,
              tools=None):
    return {
        "artifact_id": artifact_id,
        "kind": "mcp-server-config",
        "version": version,
        "content": content if content is not None else {
            "endpoint": "https://files.vendor.example/mcp"},
        "tools": tools if tools is not None else [
            {"name": "read_file", "description": "read a file",
             "schema": {}}],
    }


class StoreTest(unittest.TestCase):
    def test_round_trip(self):
        d = tempfile.mkdtemp(prefix="vw-store-")
        s1 = vw.VendorWatchStore(state_dir=d)
        s1.snapshots["a"] = vw.snapshot_artifact(
            _artifact("a"), "op", NOW)
        s1.save()
        s2 = vw.VendorWatchStore(state_dir=d)
        self.assertEqual(s2.snapshots["a"]["content_hash"],
                         s1.snapshots["a"]["content_hash"])

    def test_unreadable_state_fails_closed(self):
        d = tempfile.mkdtemp(prefix="vw-store-")
        with open(os.path.join(d, "vendor_watch_snapshots.json"),
                  "w") as f:
            f.write("{not json")
        with self.assertRaises(vw.VendorWatchError) as cm:
            vw.VendorWatchStore(state_dir=d)
        self.assertEqual(cm.exception.code,
                         "vendor-update-unverifiable")


class DigestTest(unittest.TestCase):
    def test_canonical_stable(self):
        h1 = vw.content_digest({"b": 1, "a": [1, 2]})
        h2 = vw.content_digest({"a": [1, 2], "b": 1})
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_tools_digest_order_insensitive(self):
        t1 = [{"name": "b", "description": "", "schema": {}},
              {"name": "a", "description": "", "schema": {}}]
        t2 = list(reversed(t1))
        self.assertEqual(vw.tools_digest(t1), vw.tools_digest(t2))

    def test_tools_digest_semantics_sensitive(self):
        t1 = [{"name": "a", "description": "x", "schema": {}}]
        t2 = [{"name": "a", "description": "y", "schema": {}}]
        self.assertNotEqual(vw.tools_digest(t1), vw.tools_digest(t2))


class DiffTest(unittest.TestCase):
    def _approved(self, artifact=None):
        d = tempfile.mkdtemp(prefix="vw-diff-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([artifact or _artifact()]),
                    now=NOW)
        for pid in list(store.pending):
            vw.approve_pending(store, pid, "op", now=NOW)
        return store

    def test_no_change(self):
        store = self._approved()
        dets = vw.scan(store, vw.DictSource([_artifact()]), now=NOW)
        self.assertEqual(dets, [])

    def test_hash_drift(self):
        store = self._approved()
        drifted = _artifact(content={"endpoint": "https://x.example"})
        dets = vw.scan(store, vw.DictSource([drifted]), now=NOW)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0]["outcome"], "HASH_DRIFT")
        self.assertEqual(dets[0]["code"], "vendor-hash-drift")

    def test_version_bump(self):
        store = self._approved()
        dets = vw.scan(store, vw.DictSource([_artifact(version="2.0")]),
                       now=NOW)
        self.assertEqual(dets[0]["outcome"], "VERSION_BUMP")

    def test_new_and_removed(self):
        store = self._approved()
        dets = vw.scan(store, vw.DictSource(
            [_artifact("other")]), now=NOW)
        outcomes = sorted(d["outcome"] for d in dets)
        self.assertEqual(outcomes, ["ARTIFACT_NEW", "ARTIFACT_REMOVED"])

    def test_rescan_idempotent(self):
        store = self._approved()
        src = vw.DictSource([_artifact(version="2.0")])
        vw.scan(store, src, now=NOW)
        vw.scan(store, src, now=NOW)
        open_recs = [r for r in store.pending.values()
                     if r["status"] in ("pending", "refused")]
        self.assertEqual(len(open_recs), 1)

    def test_rollback_resolves(self):
        store = self._approved()
        vw.scan(store, vw.DictSource([_artifact(version="2.0")]),
                now=NOW)
        pid = _open_pending_id(store)
        vw.reject_pending(store, pid, "op", "not approved", now=NOW)
        vw.scan(store, vw.DictSource([_artifact()]), now=NOW)
        self.assertEqual(store.pending[pid]["status"], "resolved")

    def test_source_failure_unverifiable(self):
        store = self._approved()

        class _Bad(vw.ArtifactSource):
            def list_current(self):
                raise vw.VendorWatchSourceError("boom")

        dets = vw.scan(store, _Bad(), now=NOW)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0]["code"], "vendor-update-unverifiable")
        self.assertEqual(store.meta["last_scan_status"], "unverifiable")


class GateTest(unittest.TestCase):
    def _approved(self):
        d = tempfile.mkdtemp(prefix="vw-gate-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([_artifact()]), now=NOW)
        for pid in list(store.pending):
            vw.approve_pending(store, pid, "op", now=NOW)
        return store

    def test_allow_clean(self):
        gate = vw.VendorWatchGate(self._approved())
        rec = gate.check_tool("mcp:files", "read_file")
        self.assertEqual(rec["verdict"], "allow")

    def test_deny_pending(self):
        store = self._approved()
        vw.scan(store, vw.DictSource([_artifact(version="9.9")]),
                now=NOW)
        gate = vw.VendorWatchGate(store)
        with self.assertRaises(vw.VendorWatchError) as cm:
            gate.check_tool("mcp:files", "read_file")
        self.assertEqual(cm.exception.code, "vendor-update-detected")

    def test_deny_refused(self):
        store = self._approved()
        vw.scan(store, vw.DictSource([_artifact(version="9.9")]),
                now=NOW)
        pid = _open_pending_id(store)
        vw.reject_pending(store, pid, "op", "no", now=NOW)
        gate = vw.VendorWatchGate(store)
        with self.assertRaises(vw.VendorWatchError):
            gate.check_tool("mcp:files")

    def test_not_watched_passes_through(self):
        gate = vw.VendorWatchGate(self._approved())
        rec = gate.check_tool("mcp:unknown")
        self.assertEqual(rec["watcher"], "not-watched")

    def test_unverifiable_scan_denies_all(self):
        store = self._approved()
        store.meta["last_scan_status"] = "unverifiable"
        gate = vw.VendorWatchGate(store)
        with self.assertRaises(vw.VendorWatchError) as cm:
            gate.check_tool("mcp:files")
        self.assertEqual(cm.exception.code,
                         "vendor-update-unverifiable")

    def test_pending_baseline_denied(self):
        d = tempfile.mkdtemp(prefix="vw-gate-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([_artifact()]), now=NOW)
        gate = vw.VendorWatchGate(store)
        with self.assertRaises(vw.VendorWatchError) as cm:
            gate.check_tool("mcp:files")
        self.assertEqual(cm.exception.code, "vendor-artifact-new")


class EvidenceTest(unittest.TestCase):
    def test_sign_verify(self):
        det = {"detection_id": "x", "artifact_id": "a"}
        env = vw.signed_detection_record(det, SEED)
        self.assertTrue(vw.verify_detection_record(env))

    def test_forged_record_refused(self):
        env = vw.signed_detection_record({"a": 1}, SEED)
        env["record"] = {"a": 2}
        self.assertFalse(vw.verify_detection_record(env))

    def test_malformed_envelope_refused(self):
        self.assertFalse(vw.verify_detection_record({}))
        self.assertFalse(vw.verify_detection_record(
            {"record": {}, "signature": "zz", "pubkey": "zz"}))

    def test_seed_shape_checked(self):
        with self.assertRaises(ValueError):
            vw.signed_detection_record({}, b"short")

    def test_log_detection_shape(self):
        class _Log(object):
            def __init__(self):
                self.events = []

            def append(self, event):
                self.events.append(event)
                return event

        lg = _Log()
        det = {"detection_id": "d1", "code": "vendor-hash-drift"}
        vw.log_detection(lg, det)
        self.assertEqual(lg.events[0]["event"],
                         "vendor-watch-detection")
        self.assertEqual(lg.events[0]["flag"], "vendor-hash-drift")


class ApproveTest(unittest.TestCase):
    def _pending_store(self):
        d = tempfile.mkdtemp(prefix="vw-appr-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([_artifact()]), now=NOW)
        return store

    def test_approve_requires_approver(self):
        store = self._pending_store()
        pid = _open_pending_id(store)
        with self.assertRaises(ValueError):
            vw.approve_pending(store, pid, "")

    def test_reject_requires_reason(self):
        store = self._pending_store()
        pid = _open_pending_id(store)
        with self.assertRaises(ValueError):
            vw.reject_pending(store, pid, "op", "")

    def test_approve_removal_drops_snapshot(self):
        d = tempfile.mkdtemp(prefix="vw-appr-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([_artifact()]), now=NOW)
        for pid in list(store.pending):
            vw.approve_pending(store, pid, "op", now=NOW)
        vw.scan(store, vw.DictSource([]), now=NOW)
        pid = _open_pending_id(store)
        vw.approve_pending(store, pid, "op", now=NOW)
        self.assertNotIn("mcp:files", store.snapshots)

    def test_approve_unverifiable_refused(self):
        d = tempfile.mkdtemp(prefix="vw-appr-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.baseline(store, vw.DictSource([_artifact()]), now=NOW)
        for pid in list(store.pending):
            vw.approve_pending(store, pid, "op", now=NOW)
        evil = _artifact()
        evil["content"] = {"f": object()}
        vw.scan(store, vw.DictSource([evil]), now=NOW)
        pid = _open_pending_id(store)
        with self.assertRaises(ValueError):
            vw.approve_pending(store, pid, "op", now=NOW)

    def test_new_artifact_approve_keeps_tools_digest(self):
        d = tempfile.mkdtemp(prefix="vw-appr-")
        store = vw.VendorWatchStore(state_dir=d)
        vw.scan(store, vw.DictSource([_artifact("mcp:new")]), now=NOW)
        pid = _open_pending_id(store)
        vw.approve_pending(store, pid, "op", now=NOW)
        snap = store.snapshots["mcp:new"]
        self.assertNotEqual(snap["tools_digest"], "")
        dets = vw.scan(store, vw.DictSource([_artifact("mcp:new")]),
                       now=NOW)
        self.assertEqual(dets, [])


class CliTest(unittest.TestCase):
    def test_scan_cli(self):
        d = tempfile.mkdtemp(prefix="vw-cli-")
        src = os.path.join(d, "source.json")
        with open(src, "w") as f:
            json.dump({"artifacts": [_artifact()]}, f)
        rc = vw.main(["baseline", "--state-dir", os.path.join(d, "st"),
                      "--source", src])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
