"""Continuous skill/MCP supply-chain verification (wave-92 integration).

Part 1 adapts the stream-C prototype battery (29 tests) against
``gov.skill_watch``. Part 2 covers the integration seams the prototype
did not have: executor call-path wiring, the HMAC-chained audit sink,
the MCP server -> skill-id mapping, persistent pins (restart
semantics), and the scheduled sweep trigger.
"""

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import skill_watch
from gov.skill_watch import (
    SkillWatch, SkillWatchError, PinStore, PinStoreError, ContentSource,
    FileContentSource, CallableContentSource, skill_id_for_tool,
    sweep_due, SWEEP_INTERVAL_SECONDS,
)

ORIGIN = {"registry_url": "https://registry.synthetic.local/s/weather",
          "installer_identity": "operator:alice",
          "installed_at": "2026-09-23T15:00:00+00:00"}

V1 = b"skill v1 benign content"
V2 = b"skill v2 MUTATED content"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def file_origin(path):
    o = dict(ORIGIN)
    o["content_path"] = str(path)
    return o


class CountingSource(CallableContentSource):
    def __init__(self, content):
        self.content = content
        self.reads = 0
        super().__init__(self._read)

    def _read(self):
        self.reads += 1
        return self.content


class ForgedStatFileSource(FileContentSource):
    """Adversarial: file content changes but stat hint is forged stale."""

    def __init__(self, path, forged_stat):
        super().__init__(path)
        self._forged = forged_stat

    def stat_hint(self):
        return self._forged


# ---------------------------------------------------------------------------
# Part 1: prototype battery, adapted
# ---------------------------------------------------------------------------

class TestRegistration(unittest.TestCase):
    def setUp(self):
        self.watch = SkillWatch()

    def test_register_pins_digest_and_emits_event(self):
        src = CountingSource(V1)
        digest = self.watch.register_skill("weather", src, origin=ORIGIN)
        self.assertEqual(digest, sha(V1))
        self.assertEqual(src.reads, 1)
        evs = [e for e in self.watch.events
               if e["event_type"] == "skill_registered"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["pinned_digest"], sha(V1))
        self.assertEqual(evs[0]["origin"]["installer_identity"],
                         "operator:alice")

    def test_register_requires_provenance(self):
        for bad_origin in ({}, {"registry_url": "x"},
                           {"registry_url": "x", "installer_identity": "y"}):
            with self.assertRaises(SkillWatchError):
                self.watch.register_skill("s%d" % len(bad_origin),
                                          CountingSource(V1),
                                          origin=bad_origin)

    def test_register_rejects_bad_skill_ids(self):
        for bad in ("", "../escape", "a" * 200, "has space", None, 123):
            with self.assertRaises(SkillWatchError):
                self.watch.register_skill(bad, CountingSource(V1),
                                          origin=ORIGIN)

    def test_reregistration_refused(self):
        self.watch.register_skill("weather", CountingSource(V1),
                                  origin=ORIGIN)
        with self.assertRaises(SkillWatchError):
            self.watch.register_skill("weather", CountingSource(V2),
                                      origin=ORIGIN)

    def test_unreadable_content_refused(self):
        class Boom(ContentSource):
            def read_bytes(self):
                raise OSError("disk gone")
        with self.assertRaises(SkillWatchError):
            self.watch.register_skill("weather", Boom(), origin=ORIGIN)
        self.assertEqual(self.watch.registered_skills(), [])

    def test_empty_content_refused(self):
        with self.assertRaises(SkillWatchError):
            self.watch.register_skill("weather", CountingSource(b""),
                                      origin=ORIGIN)

    def test_non_source_refused(self):
        with self.assertRaises(SkillWatchError):
            self.watch.register_skill("weather", V1, origin=ORIGIN)


class TestSweep(unittest.TestCase):
    def setUp(self):
        self.watch = SkillWatch()
        self.src_a = CountingSource(V1)
        self.src_b = CountingSource(b"other skill")
        self.watch.register_skill("a", self.src_a, origin=ORIGIN)
        self.watch.register_skill("b", self.src_b, origin=ORIGIN)

    def test_clean_sweep(self):
        report = self.watch.verify_all()
        self.assertEqual(report,
                         {"checked": 2, "clean": ["a", "b"],
                          "mutated": [], "unverifiable": []})
        self.assertFalse(self.watch.is_quarantined("a"))
        sweep_evs = [e for e in self.watch.events
                     if e["event_type"] == "skill_sweep_completed"]
        self.assertEqual(len(sweep_evs), 1)
        self.assertEqual(sweep_evs[0]["checked"], 2)

    def test_sweep_detects_mutation_and_quarantines(self):
        self.src_a.content = V2
        report = self.watch.verify_all()
        self.assertEqual(report["mutated"], ["a"])
        self.assertEqual(report["clean"], ["b"])
        self.assertTrue(self.watch.is_quarantined("a"))
        self.assertFalse(self.watch.is_quarantined("b"))
        evs = [e for e in self.watch.events
               if e["event_type"] == "skill_mutated"]
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev["previous_digest"], sha(V1))
        self.assertEqual(ev["observed_digest"], sha(V2))
        self.assertTrue(ev["quarantined"])
        # No content in the event, only digests.
        self.assertNotIn(V1, str(ev).encode())
        self.assertNotIn(V2, str(ev).encode())

    def test_sweep_detects_unreadable(self):
        def boom():
            raise OSError("gone")
        self.src_b._fn = boom
        report = self.watch.verify_all()
        self.assertEqual(report["unverifiable"], ["b"])
        self.assertTrue(self.watch.is_quarantined("b"))
        evs = [e for e in self.watch.events
               if e["event_type"] == "skill_unverifiable"]
        self.assertEqual(len(evs), 1)

    def test_sweep_catches_forged_stat(self):
        """Layered defense: forged mtime/size defeats the prefilter but
        the sweep always re-hashes."""
        tmpdir = tempfile.mkdtemp(prefix="t-")
        path = os.path.join(tmpdir, "s.skill")
        with open(path, "wb") as f:
            f.write(V1)
        st = os.stat(path)
        forged = (st.st_mtime_ns, st.st_size)
        src = ForgedStatFileSource(path, forged)
        w = SkillWatch()
        w.register_skill("s", src, origin=ORIGIN)
        with open(path, "wb") as f:
            f.write(V1)
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(b"X")
        ok, detail = w.check_at_use("s")
        self.assertTrue(ok, detail)  # prefilter fooled: honest residual
        report = w.verify_all()
        self.assertEqual(report["mutated"], ["s"])
        self.assertTrue(w.is_quarantined("s"))


class TestCheckAtUse(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="t-")
        self.path = os.path.join(self.tmpdir, "w.skill")
        with open(self.path, "wb") as f:
            f.write(V1)
        self.watch = SkillWatch()
        self.watch.register_skill("w", FileContentSource(self.path),
                                  origin=ORIGIN)

    def _touch(self):
        os.utime(self.path, (os.path.getatime(self.path), 9999999999))

    def test_clean_use(self):
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (True, "clean"))

    def test_stat_change_triggers_rehash_and_catch(self):
        with open(self.path, "wb") as f:
            f.write(V2)
        self._touch()
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (False, "mutated-quarantined"))
        self.assertTrue(self.watch.is_quarantined("w"))

    def test_stat_change_but_same_content_stays_clean(self):
        self._touch()
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (True, "clean"))

    def test_quarantined_stays_denied(self):
        with open(self.path, "wb") as f:
            f.write(V2)
        self._touch()
        self.watch.check_at_use("w")
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (False, "quarantined"))

    def test_unregistered_is_not_the_inventorys_refusal(self):
        ok, detail = self.watch.check_at_use("never-registered")
        self.assertEqual((ok, detail), (True, "unregistered"))

    def test_missing_file_quarantines(self):
        os.unlink(self.path)
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (False, "unverifiable-quarantined"))


class TestRepin(unittest.TestCase):
    def setUp(self):
        self.src = CountingSource(V1)
        self.watch = SkillWatch()
        self.watch.register_skill("w", self.src, origin=ORIGIN)
        self.src.content = V2
        self.watch.verify_all()
        self.assertTrue(self.watch.is_quarantined("w"))

    def _approve(self, digest):
        return {"operator": "operator:alice", "new_digest": digest,
                "reason": "reviewed change"}

    def test_approve_without_request_refused(self):
        with self.assertRaises(SkillWatchError):
            self.watch.approve_repin("w", self._approve(sha(V2)))

    def test_approve_with_incomplete_approval_refused(self):
        self.watch.request_repin("w", operator="operator:alice")
        for bad in ({}, {"operator": "x"}, {"operator": "x",
                                            "new_digest": sha(V2)}):
            with self.assertRaises(SkillWatchError):
                self.watch.approve_repin("w", bad)

    def test_approve_with_wrong_digest_refused(self):
        self.watch.request_repin("w", operator="operator:alice")
        with self.assertRaises(SkillWatchError):
            self.watch.approve_repin("w", self._approve(sha(V1)))
        self.assertTrue(self.watch.is_quarantined("w"))

    def test_approve_with_non_string_digest_refused(self):
        self.watch.request_repin("w", operator="operator:alice")
        with self.assertRaises(SkillWatchError):
            self.watch.approve_repin("w", self._approve(None))

    def test_bait_and_switch_refused(self):
        self.watch.request_repin("w", operator="operator:alice")
        self.src.content = V2 + b"// again"
        with self.assertRaises(SkillWatchError) as ctx:
            self.watch.approve_repin("w", self._approve(sha(V2)))
        self.assertIn("bait-and-switch", str(ctx.exception))
        self.assertTrue(self.watch.is_quarantined("w"))

    def test_legitimate_repin(self):
        req_id = self.watch.request_repin("w", operator="operator:alice")
        self.assertTrue(req_id.startswith("w:"))
        req_evs = [e for e in self.watch.events
                   if e["event_type"] == "skill_repin_requested"]
        self.assertEqual(len(req_evs), 1)
        self.assertEqual(req_evs[0]["observed_digest"], sha(V2))
        new = self.watch.approve_repin("w", self._approve(sha(V2)))
        self.assertEqual(new, sha(V2))
        self.assertFalse(self.watch.is_quarantined("w"))
        ok, detail = self.watch.check_at_use("w")
        self.assertEqual((ok, detail), (True, "clean"))
        evs = [e for e in self.watch.events
               if e["event_type"] == "skill_repinned"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["previous_digest"], sha(V1))
        self.assertEqual(evs[0]["new_digest"], sha(V2))

    def test_repin_request_on_unverifiable_refused(self):
        def boom():
            raise OSError("gone")
        self.src._fn = boom
        with self.assertRaises(SkillWatchError):
            self.watch.request_repin("w", operator="operator:alice")

    def test_request_requires_operator(self):
        with self.assertRaises(SkillWatchError):
            self.watch.request_repin("w", operator="")

    def test_unknown_skill(self):
        with self.assertRaises(SkillWatchError):
            self.watch.request_repin("nope", operator="operator:alice")
        with self.assertRaises(SkillWatchError):
            self.watch.approve_repin("nope", self._approve(sha(V2)))


class TestMisc(unittest.TestCase):
    def test_provenance_returns_copy(self):
        w = SkillWatch()
        w.register_skill("w", CountingSource(V1), origin=ORIGIN)
        prov = w.provenance_for("w")
        self.assertEqual(prov["registry_url"], ORIGIN["registry_url"])
        prov["registry_url"] = "evil"
        self.assertNotEqual(w.provenance_for("w")["registry_url"], "evil")
        self.assertIsNone(w.provenance_for("unknown"))

    def test_custom_emit_sink(self):
        seen = []
        w = SkillWatch(emit=seen.append)
        w.register_skill("w", CountingSource(V1), origin=ORIGIN)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["event_type"], "skill_registered")
        self.assertEqual(w.events, [])

    def test_is_quarantined_unknown_is_false(self):
        self.assertFalse(SkillWatch().is_quarantined("nope"))


# ---------------------------------------------------------------------------
# Part 2: integration seams
# ---------------------------------------------------------------------------

class TestStatFailureNeverEscapes(unittest.TestCase):
    """The _current_digest fail-closed fix: a stat failure on the
    re-hash path must quarantine, never propagate out of the check."""

    def test_check_at_use_stat_failure_inside_rehash_quarantines(self):
        class FlakyStat(CallableContentSource):
            def __init__(self, content):
                self.content = content
                self.calls = 0
                super().__init__(lambda: self.content)

            def stat_hint(self):
                self.calls += 1
                if self.calls > 2:
                    raise OSError("stat gone")
                # changing hint forces the re-hash path every check
                return (self.calls, len(self.content))

        w = SkillWatch()
        w.register_skill("w", FlakyStat(V1), origin=ORIGIN)
        # First check: hint changes -> re-hash -> stat fails INSIDE
        # _current_digest. Must quarantine, not raise.
        ok, detail = w.check_at_use("w")
        self.assertEqual((ok, detail), (False, "unverifiable-quarantined"))
        self.assertTrue(w.is_quarantined("w"))

    def test_verify_all_stat_failure_is_unverifiable(self):
        class DeadStat(CallableContentSource):
            def __init__(self, content):
                self.content = content
                self.calls = 0
                super().__init__(lambda: self.content)

            def stat_hint(self):
                self.calls += 1
                if self.calls > 1:
                    raise OSError("stat gone")
                return (1, 1)

        w = SkillWatch()
        w.register_skill("w", DeadStat(V1), origin=ORIGIN)
        report = w.verify_all()  # must not raise
        self.assertEqual(report["unverifiable"], ["w"])
        self.assertTrue(w.is_quarantined("w"))


class TestSetEmit(unittest.TestCase):
    def test_set_emit_replays_buffered_events(self):
        w = SkillWatch()
        w.register_skill("w", CountingSource(V1), origin=ORIGIN)
        self.assertEqual(len(w.events), 1)
        seen = []
        w.set_emit(seen.append)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["event_type"], "skill_registered")
        w.verify_all()
        self.assertEqual(seen[-1]["event_type"], "skill_sweep_completed")
        self.assertEqual(w.events, [])  # buffer drained into new sink

    def test_set_emit_rejects_non_callable(self):
        with self.assertRaises(SkillWatchError):
            SkillWatch().set_emit("not-callable")


class TestSkillIdForTool(unittest.TestCase):
    def test_explicit_tool_map_wins(self):
        self.assertEqual(
            skill_id_for_tool("read_file",
                              tool_to_skill={"read_file": "fs-skill"},
                              mcp_server="notes-svc"),
            "fs-skill")

    def test_mcp_default_convention(self):
        self.assertEqual(skill_id_for_tool("write_file",
                                           mcp_server="notes-svc"),
                         "mcp/notes-svc")

    def test_mcp_explicit_server_map(self):
        self.assertEqual(
            skill_id_for_tool("write_file", mcp_server="notes-svc",
                              mcp_server_to_skill={"notes-svc": "notes"}),
            "notes")

    def test_mcp_explicit_none_opts_out(self):
        self.assertIsNone(
            skill_id_for_tool("write_file", mcp_server="notes-svc",
                              mcp_server_to_skill={"notes-svc": None}))

    def test_unmapped_server_falls_back_to_convention(self):
        self.assertEqual(
            skill_id_for_tool("write_file", mcp_server="other-svc",
                              mcp_server_to_skill={"notes-svc": "notes"}),
            "mcp/other-svc")

    def test_unattributed_tool_is_none(self):
        self.assertIsNone(skill_id_for_tool("read_file"))

    def test_invalid_ids_raise_loud(self):
        with self.assertRaises(SkillWatchError):
            skill_id_for_tool("t", tool_to_skill={"t": "../escape"})
        with self.assertRaises(SkillWatchError):
            skill_id_for_tool("t", mcp_server="bad server!")


class TestSweepDue(unittest.TestCase):
    def test_never_swept_is_due(self):
        self.assertTrue(sweep_due(None))

    def test_recent_sweep_not_due(self):
        self.assertFalse(sweep_due(1000.0, now=1000.0 + 60,
                                   interval=300))

    def test_old_sweep_due(self):
        self.assertTrue(sweep_due(1000.0, now=1000.0 + 301,
                                  interval=300))

    def test_default_interval_is_documented(self):
        self.assertEqual(SWEEP_INTERVAL_SECONDS, 300)

    def test_unparseable_state_sweeps(self):
        self.assertTrue(sweep_due("garbage", now=1000.0))


class TestPinStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pins-")
        self.path = os.path.join(self.tmpdir, "skill_pins.json")
        self.skill_path = os.path.join(self.tmpdir, "w.skill")
        with open(self.skill_path, "wb") as f:
            f.write(V1)

    def _watch(self):
        w = SkillWatch()
        w.register_skill("w", FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        return w

    def test_save_and_load_roundtrip(self):
        w = self._watch()
        PinStore.save(w, self.path)
        w2 = PinStore.load(self.path)
        self.assertEqual(w2.registered_skills(), ["w"])
        self.assertEqual(w2.provenance_for("w")["installer_identity"],
                         "operator:alice")
        ok, detail = w2.check_at_use("w")
        self.assertEqual((ok, detail), (True, "clean"))

    def test_quarantine_survives_restart(self):
        w = self._watch()
        with open(self.skill_path, "wb") as f:
            f.write(V2)
        os.utime(self.skill_path, None)
        w.check_at_use("w")
        self.assertTrue(w.is_quarantined("w"))
        PinStore.save(w, self.path)
        # Fresh process: pins + quarantine restored from disk.
        w2 = PinStore.load(self.path)
        self.assertTrue(w2.is_quarantined("w"))
        ok, detail = w2.check_at_use("w")
        self.assertEqual((ok, detail), (False, "quarantined"))
        # The mutation is still detected against the ORIGINAL pin.
        rep = w2.verify_all()
        self.assertEqual(rep["mutated"], ["w"])

    def test_mutation_count_survives_restart(self):
        w = self._watch()
        with open(self.skill_path, "wb") as f:
            f.write(V2)
        w.verify_all()
        PinStore.save(w, self.path)
        data = PinStore.peek(self.path)
        self.assertEqual(data["pins"]["w"]["mutation_count"], 1)
        self.assertEqual(data["quarantined"], ["w"])

    def test_pin_file_is_0600(self):
        PinStore.save(self._watch(), self.path)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_corrupt_pin_file_fails_loud(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        with self.assertRaises(PinStoreError):
            PinStore.peek(self.path)
        with self.assertRaises(PinStoreError):
            PinStore.load(self.path)

    def test_wrong_format_fails_loud(self):
        with open(self.path, "w") as f:
            json.dump({"format": "other/9", "pins": {}}, f)
        with self.assertRaises(PinStoreError):
            PinStore.peek(self.path)

    def test_quarantined_unknown_skill_fails_loud(self):
        with open(self.path, "w") as f:
            json.dump({"format": "skill-pins/1", "pins": {},
                       "quarantined": ["ghost"]}, f)
        with self.assertRaises(PinStoreError):
            PinStore.peek(self.path)

    def test_load_without_content_path_needs_factory(self):
        w = SkillWatch()
        w.register_skill("w", CountingSource(V1), origin=ORIGIN)
        PinStore.save(w, self.path)
        with self.assertRaises(PinStoreError):
            PinStore.load(self.path)  # default factory: no content_path
        # A deployment factory re-attaches the source.
        src = CountingSource(V1)
        w2 = PinStore.load(self.path,
                           source_factory=lambda sid, origin: src)
        self.assertEqual(w2.registered_skills(), ["w"])

    def test_load_with_broken_factory_fails_loud(self):
        PinStore.save(self._watch(), self.path)
        def bad_factory(sid, origin):
            raise RuntimeError("nope")
        with self.assertRaises(PinStoreError):
            PinStore.load(self.path, source_factory=bad_factory)

    def test_save_non_watch_fails(self):
        with self.assertRaises(PinStoreError):
            PinStore.save(object(), self.path)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Part 3: executor call-path wiring
# ---------------------------------------------------------------------------

from gov.policy import PolicyEngine
from gov.log import ActionLog, read_entries
from gov.approvals import ApprovalQueue
from gov.executor import ToolExecutor

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

_UNGOVERNED_ACK = ("synthetic test: exercises the raw pre-wave-74/75 "
                   "pipeline by design; the bypass is declared, not silent")


def _make_executor(run_dir, skill_watch_obj=None, skill_tool_map=None,
                   skill_mcp_map=None, skill_pin_path=None):
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=run_dir / "egress_ledger.jsonl",
        skill_watch=skill_watch_obj,
        skill_tool_map=skill_tool_map,
        skill_mcp_map=skill_mcp_map,
        skill_pin_path=skill_pin_path,
        ungoverned_ack=_UNGOVERNED_ACK)
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    return ex, ident, log


def _skill_events(run_dir):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if e.get("event") == "skill_watch"]


class TestExecutorSkillWiring(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="exsw-")
        self.run_dir = Path(self.tmpdir) / "run"
        self.run_dir.mkdir()
        self.skill_path = os.path.join(self.tmpdir, "weather.skill")
        with open(self.skill_path, "wb") as f:
            f.write(V1)

    def _wired(self, **kw):
        w = SkillWatch()
        w.register_skill("weather", FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        kw.setdefault("skill_tool_map", {"read_file": "weather"})
        ex, ident, _ = _make_executor(self.run_dir, w, **kw)
        return ex, ident, w

    def _mutate(self, content=V2):
        with open(self.skill_path, "wb") as f:
            f.write(content)
        os.utime(self.skill_path, None)

    def test_clean_skill_call_executes(self):
        ex, ident, _ = self._wired()
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")
        self.assertEqual(ex._executed.get("read_file", 0), 1)

    def test_mutated_skill_denies_on_call_path(self):
        ex, ident, w = self._wired()
        before = ex._executed.get("read_file", 0)
        self._mutate()
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "skill-watch")
        # The tool NEVER executed.
        self.assertEqual(ex._executed.get("read_file", 0), before)
        # Loud audit entry on the tool_call record.
        denied = [e for e in read_entries(self.run_dir / "actions.jsonl")
                  if e.get("decision") == "denied"
                  and e.get("policy_id") == "skill-watch"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["flag"], "skill_quarantined")
        self.assertEqual(denied[0]["skill_id"], "weather")
        self.assertTrue(w.is_quarantined("weather"))

    def test_watcher_error_denies_fail_closed(self):
        ex, ident, w = self._wired()

        def boom(skill_id):
            raise RuntimeError("watcher exploded")
        w.check_at_use = boom
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "skill-watch")
        self.assertIn("watcher-error", r["reason"])

    def test_unregistered_skill_is_not_refused(self):
        # The inventory refuses to invent a refusal for a skill it never
        # pinned: the policy's unknown-skill handling decides those.
        ex, ident, _ = self._wired(
            skill_tool_map={"read_file": "never-registered"})
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    def test_unattributed_tool_untouched(self):
        ex, ident, _ = self._wired(skill_tool_map={})
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    def test_no_watcher_zero_behavior_change(self):
        ex, ident, _ = _make_executor(self.run_dir)
        r = ex.call(ident, "read_file", path="notes.txt",
                    mcp_server="notes-svc")
        self.assertEqual(r["status"], "executed")
        self.assertEqual(_skill_events(self.run_dir), [])

    def test_mcp_server_attribution_denies_on_mutation(self):
        w = SkillWatch()
        w.register_skill("mcp/notes-svc",
                         FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        ex, ident, _ = _make_executor(
            self.run_dir, w, skill_mcp_map={"notes-svc": "mcp/notes-svc"})
        r = ex.call(ident, "read_file", path="notes.txt",
                    mcp_server="notes-svc")
        self.assertEqual(r["status"], "executed")
        self._mutate()
        r2 = ex.call(ident, "read_file", path="notes.txt",
                     mcp_server="notes-svc")
        self.assertEqual(r2["status"], "denied")
        self.assertEqual(r2["policy_id"], "skill-watch")

    def test_mcp_framing_kwarg_never_reaches_tool(self):
        # mcp_server is popped like other framing kwargs: the tool's
        # recorded args never contain it.
        w = SkillWatch()
        w.register_skill("mcp/notes-svc",
                         FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        ex, ident, _ = _make_executor(
            self.run_dir, w, skill_mcp_map={"notes-svc": "mcp/notes-svc"})
        r = ex.call(ident, "read_file", path="notes.txt",
                    mcp_server="notes-svc")
        self.assertEqual(r["status"], "executed")
        executed = [e for e in read_entries(self.run_dir / "actions.jsonl")
                    if e.get("decision") == "allowed_executed"]
        self.assertEqual(len(executed), 1)
        self.assertNotIn("mcp_server", executed[0].get("args", {}))
        self.assertEqual(executed[0]["args"].get("path"), "notes.txt")

    def test_events_chained_into_hmac_log(self):
        ex, ident, w = self._wired()
        self._mutate()
        ex.call(ident, "read_file", path="notes.txt")
        evs = _skill_events(self.run_dir)
        types = {e["event_type"] for e in evs}
        self.assertIn("skill_registered", types)
        self.assertIn("skill_mutated", types)
        mutated = [e for e in evs if e["event_type"] == "skill_mutated"][0]
        self.assertEqual(mutated["previous_digest"], sha(V1))
        self.assertEqual(mutated["observed_digest"], sha(V2))
        self.assertTrue(mutated["quarantined"])
        # Digests only: raw skill bytes never land in the chained log.
        blob = (self.run_dir / "actions.jsonl").read_bytes()
        self.assertNotIn(V1, blob)
        self.assertNotIn(V2, blob)

    def test_run_skill_sweep_detects_and_persists(self):
        pin_path = os.path.join(self.tmpdir, "pins.json")
        ex, ident, w = self._wired(skill_pin_path=pin_path)
        self._mutate()
        report = ex.run_skill_sweep()
        self.assertEqual(report["mutated"], ["weather"])
        self.assertTrue(w.is_quarantined("weather"))
        # Pins persisted automatically by the sweep.
        self.assertTrue(os.path.exists(pin_path))
        data = PinStore.peek(pin_path)
        self.assertEqual(data["quarantined"], ["weather"])
        # Sweep completion is audit-logged.
        evs = [e for e in _skill_events(self.run_dir)
               if e["event_type"] == "skill_sweep_completed"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["checked"], 1)
        # The quarantined skill now denies on the call path too.
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")

    def test_run_skill_sweep_without_watcher(self):
        ex, ident, _ = _make_executor(self.run_dir)
        report = ex.run_skill_sweep()
        self.assertEqual(report["watcher"], "not-installed")

    def test_restart_preserves_quarantine_and_denies(self):
        pin_path = os.path.join(self.tmpdir, "pins.json")
        ex, ident, w = self._wired(skill_pin_path=pin_path)
        self._mutate()
        ex.run_skill_sweep()  # quarantines + persists
        # Fresh process: deployment loads pins, builds a new executor.
        w2 = PinStore.load(pin_path)
        run_dir2 = Path(self.tmpdir) / "run2"
        run_dir2.mkdir()
        ex2, ident2, _ = _make_executor(
            run_dir2, w2, skill_tool_map={"read_file": "weather"},
            skill_pin_path=pin_path)
        r = ex2.call(ident2, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "skill-watch")

    def test_corrupt_pin_file_refuses_construction(self):
        pin_path = os.path.join(self.tmpdir, "pins.json")
        with open(pin_path, "w") as f:
            f.write("corrupt")
        w = SkillWatch()
        with self.assertRaises(SkillWatchError):
            _make_executor(self.run_dir, w, skill_pin_path=pin_path)

    def test_missing_pin_file_is_fresh_registry(self):
        pin_path = os.path.join(self.tmpdir, "pins.json")
        ex, ident, _ = self._wired(skill_pin_path=pin_path)
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "executed")

    def test_persist_skill_pins_noop_without_path(self):
        ex, ident, w = self._wired()
        self.assertIsNone(ex.persist_skill_pins())

    def test_repin_lifts_quarantine_on_call_path(self):
        ex, ident, w = self._wired()
        self._mutate()
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")
        w.request_repin("weather", operator="operator:alice")
        w.approve_repin("weather", {
            "operator": "operator:alice",
            "new_digest": sha(V2),
            "reason": "reviewed: legitimate update"})
        r2 = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r2["status"], "executed")
