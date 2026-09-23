"""Wave-90 (S6): infection-lineage substrate unit tests (F137).

Covers gov/lineage.LineageTracker in isolation (fast, hermetic) plus
the executor's fail-closed unlineaged-execution gate. The adversarial
battery lives in evals/s6repl_break.py; these are the load-bearing
invariants the canonical suite pins.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.lineage import LineageError, LineageTracker  # noqa: E402


class _StubLog(object):
    def __init__(self):
        self.events = []

    def append(self, entry):
        self.events.append(entry)
        return {"seq": len(self.events) - 1}


class _T(object):
    """Fresh tracker on a temp run dir."""

    def __init__(self, test):
        self._td = tempfile.TemporaryDirectory(prefix="govs6-")
        test.addCleanup(self._td.cleanup)
        self.run_dir = Path(self._td.name) / "run"
        self.run_dir.mkdir()
        self.log = _StubLog()
        self.tracker = LineageTracker(self.run_dir, self.log)

    def events(self, name):
        return [e for e in self.log.events if e.get("event") == name]


def _sha(b):
    return hashlib.sha256(b).hexdigest()


BIG = "x" * 128  # over the 64-byte replication-watch floor


class TestBirthCertificates(unittest.TestCase):
    def test_genesis_birth_verify_chain(self):
        t = _T(self).tracker
        t.genesis("a")
        t.birth("a", "b")
        t.birth("b", "c")
        for agent in ("a", "b", "c"):
            self.assertTrue(t.verify(agent))
        cb = t.certificate("b")
        self.assertEqual(cb["parent"], "a")
        self.assertEqual(t.certificate("c")["depth"], 2)
        self.assertNotEqual(cb["lineage_id"],
                            t.certificate("c")["lineage_id"])

    def test_genesis_idempotent_same_agent_second_root_refused(self):
        t = _T(self).tracker
        t.genesis("a")
        t.genesis("a")  # idempotent
        with self.assertRaises(LineageError):
            t.genesis("z")

    def test_birth_unregistered_parent_refused(self):
        t = _T(self).tracker
        t.genesis("a")
        with self.assertRaises(LineageError):
            t.birth("ghost", "child")

    def test_double_birth_refused(self):
        t = _T(self).tracker
        t.genesis("a")
        t.birth("a", "b")
        with self.assertRaises(LineageError):
            t.birth("a", "b")

    def test_verify_unknown_agent_false(self):
        t = _T(self).tracker
        t.genesis("a")
        self.assertFalse(t.verify("nobody"))

    def test_hereditary_taint(self):
        t = _T(self).tracker
        t.genesis("a")
        t.mark_infected("a", "test")
        t.birth("a", "b")
        cert = t.certificate("b")
        self.assertTrue(cert["infected"])
        self.assertIn("hereditary", cert["infected_reason"])
        self.assertTrue(t.is_infected("b"))

    def test_registry_chain_chained_and_reloadable(self):
        w = _T(self)
        w.tracker.genesis("a")
        w.tracker.birth("a", "b")
        recs = (w.run_dir / "lineage" / "registry.jsonl").read_text(
            encoding="utf-8").splitlines()
        self.assertEqual(len(recs), 2)
        r0, r1 = (json.loads(x) for x in recs)
        self.assertEqual(r1["prev"], r0["record_hash"])
        t2 = LineageTracker(w.run_dir, _StubLog())
        self.assertTrue(t2.verify("b"))

    def test_registry_tamper_fails_closed(self):
        w = _T(self)
        w.tracker.genesis("a")
        w.tracker.birth("a", "b")
        reg = w.run_dir / "lineage" / "registry.jsonl"
        lines = reg.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["agent_id"] = "mallory"
        lines[0] = json.dumps(rec, sort_keys=True)
        reg.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(LineageError):
            LineageTracker(w.run_dir, _StubLog())

    def test_taint_survives_reload(self):
        w = _T(self)
        w.tracker.genesis("a")
        w.tracker.birth("a", "b")
        w.tracker.mark_infected("a", "test")
        t2 = LineageTracker(w.run_dir, _StubLog())
        self.assertTrue(t2.is_infected("a"))
        # ... and stays hereditary after reload.
        t2.birth("a", "c")
        self.assertTrue(t2.is_infected("c"))


class TestFileStamps(unittest.TestCase):
    def test_stamp_roundtrip_contact(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        stamp = w.tracker.stamp_write("writer", f, sha, len(BIG))
        self.assertTrue(stamp["hmac"])
        self.assertFalse(stamp["infected"])
        status, back = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "contact")
        self.assertEqual(back["writer"], "writer")
        contacts = w.events("lineage_contact")
        self.assertEqual(len(contacts), 1)

    def test_tainted_write_propagates_on_read(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        w.tracker.mark_infected("writer", "test")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        stamp = w.tracker.stamp_write("writer", f, sha, len(BIG))
        self.assertTrue(stamp["infected"])
        status, _ = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "tainted")
        self.assertTrue(w.tracker.is_infected("reader"))

    def test_live_writer_taint_after_write(self):
        # Stamp written clean; writer tainted later; later readers are
        # still tainted via live writer-taint evaluation.
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        w.tracker.stamp_write("writer", f, sha, len(BIG))
        w.tracker.mark_infected("writer", "late detection")
        status, _ = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "tainted")

    def test_forged_stamp_taints_reader(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        w.tracker.stamp_write("writer", f, sha, len(BIG))
        sp = Path(str(f) + ".lineage.json")
        forged = json.loads(sp.read_text(encoding="utf-8"))
        forged["infected"] = False
        forged["writer"] = "innocent"
        sp.write_text(json.dumps(forged), encoding="utf-8")  # HMAC now bad
        status, _ = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "forged")
        self.assertTrue(w.tracker.is_infected("reader"))
        self.assertTrue(w.events("lineage_stamp_forged"))

    def test_unknown_stamp_version_treated_as_hostile(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        stamp = w.tracker.stamp_write("writer", f, sha, len(BIG))
        stamp["v"] = 999
        stamp["hmac"] = w.tracker._sign_stamp(
            {k: v for k, v in stamp.items() if k != "hmac"})
        Path(str(f) + ".lineage.json").write_text(
            json.dumps(stamp, sort_keys=True), encoding="utf-8")
        status, _ = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "forged")
        self.assertTrue(w.tracker.is_infected("reader"))

    def test_bytes_mismatch_detected(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        w.tracker.stamp_write("writer", f, sha, len(BIG))
        f.write_text("different bytes " * 16, encoding="utf-8")
        status, _ = w.tracker.note_read(
            "reader", f, _sha(("different bytes " * 16).encode("utf-8")),
            len(BIG))
        self.assertEqual(status, "forged")
        self.assertTrue(w.tracker.is_infected("reader"))

    def test_unstamped_read_informational(self):
        w = _T(self)
        w.tracker.genesis("a")
        f = w.run_dir / "legacy.txt"
        f.write_text(BIG, encoding="utf-8")
        status, stamp = w.tracker.note_read("a", f)
        self.assertEqual(status, "unstamped")
        self.assertIsNone(stamp)
        self.assertTrue(w.events("lineage_unstamped_read"))
        self.assertFalse(w.tracker.is_infected("a"))

    def test_strip_detected_and_rewrite_supersedes(self):
        w = _T(self)
        w.tracker.genesis("writer")
        w.tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        w.tracker.stamp_write("writer", f, sha, len(BIG))
        w.tracker.note_delete("writer", Path(str(f) + ".lineage.json"))
        status, _ = w.tracker.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "forged")
        self.assertTrue(any(
            e.get("flag") == "lineage_stamp_stripped"
            for e in w.events("lineage_stamp_forged")))
        # Fresh stamp supersedes the strip.
        w.tracker.stamp_write("writer", f, sha, len(BIG))
        w.tracker.birth("writer", "reader2")
        status, _ = w.tracker.note_read("reader2", f, sha, len(BIG))
        self.assertEqual(status, "contact")

    def test_strip_replay_order_exact(self):
        # Strip, then a governed rewrite, then restart: the strip
        # record must NOT resurrect — the next read is a clean
        # contact, not a stale strip flag. (Real ActionLog: replay
        # reads actions.jsonl.)
        from gov.log import ActionLog
        w = _T(self)
        log = ActionLog(w.run_dir / "actions.jsonl")
        tracker = LineageTracker(w.run_dir, log)
        tracker.genesis("writer")
        tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        tracker.stamp_write("writer", f, sha, len(BIG))
        Path(str(f) + ".lineage.json").unlink()  # tool deletes it
        tracker.note_delete("writer", Path(str(f) + ".lineage.json"))
        tracker.stamp_write("writer", f, sha, len(BIG))
        t2 = LineageTracker(w.run_dir,
                            ActionLog(w.run_dir / "actions.jsonl"))
        status, _ = t2.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "contact")
        self.assertFalse(t2.is_infected("reader"))

    def test_suffix_collision_no_false_strip(self):
        # A legitimate user file that merely ends in ".lineage.json"
        # is NOT our sidecar: deleting it records no strip, and a
        # pre-existing base file still reads as informational.
        w = _T(self)
        w.tracker.genesis("a")
        f = w.run_dir / "notes.lineage.json"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        w.tracker.stamp_write("a", f, sha, len(BIG))
        base = w.run_dir / "notes"
        base.write_text(BIG, encoding="utf-8")
        f.unlink()  # the tool deletes the file; the hook only books
        w.tracker.note_delete("a", f)
        self.assertEqual(w.tracker._stripped, set())
        status, _ = w.tracker.note_read("a", base, sha, len(BIG))
        self.assertEqual(status, "unstamped")
        self.assertFalse(w.tracker.is_infected("a"))
        self.assertFalse(w.events("lineage_stamp_forged"))

    def test_strip_after_restart_still_detected(self):
        # The live-stamp set is rebuilt from the audit log: a sidecar
        # deleted after a restart is still recognized as stripping.
        # (Real ActionLog here: replay reads actions.jsonl.)
        from gov.log import ActionLog
        w = _T(self)
        log = ActionLog(w.run_dir / "actions.jsonl")
        tracker = LineageTracker(w.run_dir, log)
        tracker.genesis("writer")
        tracker.birth("writer", "reader")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        sha = _sha(BIG.encode("utf-8"))
        tracker.stamp_write("writer", f, sha, len(BIG))
        t2 = LineageTracker(w.run_dir,
                            ActionLog(w.run_dir / "actions.jsonl"))
        Path(str(f) + ".lineage.json").unlink()  # tool deletes it
        t2.note_delete("writer", Path(str(f) + ".lineage.json"))
        status, _ = t2.note_read("reader", f, sha, len(BIG))
        self.assertEqual(status, "forged")
        self.assertTrue(t2.is_infected("reader"))

    def test_delete_file_clears_stamp(self):
        w = _T(self)
        w.tracker.genesis("a")
        f = w.run_dir / "f.txt"
        f.write_text(BIG, encoding="utf-8")
        w.tracker.stamp_write("a", f, _sha(BIG.encode("utf-8")), len(BIG))
        sp = Path(str(f) + ".lineage.json")
        self.assertTrue(sp.is_file())
        w.tracker.note_delete("a", f)
        self.assertFalse(sp.exists())


class TestReplicationWatch(unittest.TestCase):
    def test_fires_at_three_distinct_agents_once(self):
        w = _T(self)
        t = w.tracker
        t.genesis("a")
        sha = _sha(BIG.encode("utf-8"))
        self.assertFalse(t.observe_content(sha, "a", len(BIG)))
        self.assertFalse(t.observe_content(sha, "b", len(BIG)))
        self.assertTrue(t.observe_content(sha, "c", len(BIG)))
        self.assertTrue(t.is_infected("a"))  # origin taint-marked
        susp = w.events("infection_suspected")
        self.assertEqual(len(susp), 1)
        self.assertEqual(sorted(susp[0]["agents"]), ["a", "b", "c"])
        # Once per campaign.
        self.assertFalse(t.observe_content(sha, "d", len(BIG)))
        self.assertEqual(len(w.events("infection_suspected")), 1)

    def test_tiny_content_ignored(self):
        w = _T(self)
        t = w.tracker
        t.genesis("a")
        for agent in ("a", "b", "c"):
            self.assertFalse(t.observe_content(_sha(b"ok"), agent, 2))
        self.assertEqual(w.events("infection_suspected"), [])


class TestExecutorLineageGate(unittest.TestCase):
    def test_unlineaged_identity_refused(self):
        from tests.keyfixture import provision_test_key
        provision_test_key()
        os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
        from tests import harness
        ctx = harness.make_run()
        self.addCleanup(harness.cleanup_run_dirs)
        ex = ctx["executor"]
        tracker = LineageTracker(ctx["run_dir"], ctx["log"])
        ex._lineage_tracker = tracker
        tracker.genesis("coder-1", role="coder", principal="dev-org")
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        # Lineaged: works.
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertIn(r["status"], ("executed", "denied"))
        # Unlineaged: refused fail-closed.
        ghost = ctx["mint_identity"]("ghost", "coder", "dev-org")
        with self.assertRaises(LineageError):
            ex.call(ghost, "read_file", path="notes.txt")

    def test_no_tracker_zero_behavior_change(self):
        from tests.keyfixture import provision_test_key
        provision_test_key()
        os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
        from tests import harness
        ctx = harness.make_run()
        self.addCleanup(harness.cleanup_run_dirs)
        ex = ctx["executor"]
        self.assertIsNone(ex._lineage_tracker)
        ghost = ctx["mint_identity"]("ghost", "coder", "dev-org")
        # No tracker: the gate does not exist (pre-wave-90 behavior).
        r = ex.call(ghost, "read_file", path="notes.txt")
        self.assertNotEqual(r.get("status"), "denied-by-lineage")


if __name__ == "__main__":
    unittest.main(verbosity=2)
