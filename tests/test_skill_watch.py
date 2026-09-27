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
from gov import keyprovider as _keyprovider


def _pin_key():
    """Resolve the operator key the executor uses to MAC the pin file (H22)."""
    key, _ = _keyprovider.resolve_active_key()
    return key

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
                          "mutated": [], "unverifiable": [],
                          "reference_drift": [], "identity_drift": [],
                          "version_drift": []})
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

    def test_unregistered_skill_denies_fail_closed(self):
        # F143: an id the watcher never pinned must not read as a pass.
        # Fail-closed at the seam: (False, "unregistered-no-pin"), and
        # no quarantine state is invented for the unknown id — a later
        # registration must still verify clean.
        ok, detail = self.watch.check_at_use("never-registered")
        self.assertEqual((ok, detail), (False, "unregistered-no-pin"))
        self.assertFalse(self.watch.is_quarantined("never-registered"))
        path2 = os.path.join(self.tmpdir, "later.skill")
        with open(path2, "wb") as f:
            f.write(V1)
        self.watch.register_skill("never-registered",
                                  FileContentSource(path2),
                                  origin=ORIGIN)
        ok2, detail2 = self.watch.check_at_use("never-registered")
        self.assertEqual((ok2, detail2), (True, "clean"))

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


class TestF176F177PinAuth(unittest.TestCase):
    """Regression: H22 pin-file authentication bypasses (F176, F177).

    F176: a keyed deployment must never silently accept an unsigned
    trust anchor (MAC-stripping downgrade).
    F177: (mtime_ns, size) restoration must not bypass MAC
    re-verification (TOCTOU).
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="f176f177-")
        self.path = os.path.join(self.tmpdir, "skill_pins.json")
        self.skill_path = os.path.join(self.tmpdir, "w.skill")
        with open(self.skill_path, "wb") as f:
            f.write(V1)
        self.key = _pin_key()

    def _watch(self):
        w = SkillWatch()
        w.register_skill("w", FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        return w

    def test_f176_keyed_peek_refuses_unsigned_manifest(self):
        """Stripping manifest_mac from a signed file is refused LOUD."""
        PinStore.save(self._watch(), self.path, mac_key=self.key)
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("manifest_mac", data)
        del data["manifest_mac"]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        with self.assertRaises(PinStoreError) as cm:
            PinStore.peek(self.path, mac_key=self.key)
        self.assertIn("tamper", str(cm.exception).lower())
        with self.assertRaises(PinStoreError):
            PinStore.load(self.path, mac_key=self.key)

    def test_f176_unsigned_still_loads_without_key(self):
        """Pre-H22 unsigned files load when no key is given (compat)."""
        PinStore.save(self._watch(), self.path)
        data = PinStore.peek(self.path)
        self.assertNotIn("manifest_mac", data)

    def test_f177_stat_restoration_does_not_bypass_reverify(self):
        """Rewritten pins + restored (mtime_ns, size) are caught."""
        PinStore.save(self._watch(), self.path, mac_key=self.key)
        w2 = PinStore.load(
            self.path, mac_key=self.key,
            source_factory=lambda sid, o: FileContentSource(
                self.skill_path))
        # Baseline: clean check takes the content-bound cheap path.
        ok, _ = w2.check_at_use("w")
        self.assertTrue(ok)
        # Attacker: flip a digest, pad to original size, restore mtime.
        st = os.stat(self.path)
        orig_mtime_ns, orig_size = st.st_mtime_ns, st.st_size
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["pins"]["w"]["pinned_digest"] = "0" * 64
        payload = (json.dumps(data, indent=2, sort_keys=True)
                   .encode("utf-8") + b"\n")
        if len(payload) < orig_size:
            payload = payload + b" " * (orig_size - len(payload))
        else:
            payload = payload[:orig_size]
        with open(self.path, "wb") as f:
            f.write(payload)
        os.utime(self.path, ns=(orig_mtime_ns, orig_mtime_ns))
        # Stat is restored, but revalidation must still fail closed.
        self.assertFalse(w2._revalidate_pin_file())
        self.assertTrue(w2.is_quarantined("w"))

    def test_f177_cheap_path_survives_untouched_file(self):
        """Unchanged file still revalidates cheaply with no quarantine."""
        PinStore.save(self._watch(), self.path, mac_key=self.key)
        w2 = PinStore.load(
            self.path, mac_key=self.key,
            source_factory=lambda sid, o: FileContentSource(
                self.skill_path))
        self.assertTrue(w2._revalidate_pin_file())
        self.assertFalse(w2.is_quarantined("w"))
        ok, detail = w2.check_at_use("w")
        self.assertEqual((ok, detail), (True, "clean"))


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

    def test_unregistered_skill_is_refused(self):
        # F143: fail-closed. A tool mapped to a skill id the watcher
        # never pinned is DENIED with a loud audit entry, and the tool
        # never executes.
        ex, ident, _ = self._wired(
            skill_tool_map={"read_file": "never-registered"})
        # Construction warned LOUD about the map referencing an id
        # with no pin (chained audit entry, not a crash).
        warnings = [e for e in read_entries(self.run_dir / "actions.jsonl")
                    if e.get("decision") == "warning"
                    and e.get("flag") == "skill_map_unregistered_id"]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["skill_id"], "never-registered")
        self.assertEqual(warnings[0]["policy_id"], "skill-watch")
        before = ex._executed.get("read_file", 0)
        r = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "skill-watch")
        self.assertEqual(ex._executed.get("read_file", 0), before)
        denied = [e for e in read_entries(self.run_dir / "actions.jsonl")
                  if e.get("decision") == "denied"
                  and e.get("policy_id") == "skill-watch"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["flag"], "skill_quarantined")
        self.assertEqual(denied[0]["skill_id"], "never-registered")
        self.assertEqual(denied[0]["skill_check"], "unregistered-no-pin")

    def test_mcp_default_convention_unregistered_is_refused(self):
        # F143 second leg: with no deployment map at all, the
        # "mcp/<server>" default convention manufactures an
        # unregistered id — also DENIED fail-closed.
        ex, ident, _ = self._wired(skill_tool_map={})
        r = ex.call(ident, "read_file", path="notes.txt",
                    mcp_server="ghost-server")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "skill-watch")
        denied = [e for e in read_entries(self.run_dir / "actions.jsonl")
                  if e.get("decision") == "denied"
                  and e.get("policy_id") == "skill-watch"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["skill_id"], "mcp/ghost-server")
        self.assertEqual(denied[0]["skill_check"], "unregistered-no-pin")

    def test_construction_warning_only_for_unregistered_ids(self):
        # Registered ids and explicit None opt-outs stay silent;
        # one warning per DISTINCT unregistered id across both maps.
        w = SkillWatch()
        w.register_skill("weather", FileContentSource(self.skill_path),
                         origin=file_origin(self.skill_path))
        ex, ident, _ = _make_executor(
            self.run_dir, w,
            skill_tool_map={"read_file": "weather",
                            "api_call": "ghost-skill"},
            skill_mcp_map={"notes-svc": None,
                           "ghost-server": "ghost-skill"})
        warnings = [e for e in read_entries(self.run_dir / "actions.jsonl")
                    if e.get("decision") == "warning"
                    and e.get("flag") == "skill_map_unregistered_id"]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["skill_id"], "ghost-skill")
        self.assertEqual(warnings[0]["map_source"],
                         "skill_tool_map,skill_mcp_map")

    def test_mcp_explicit_none_opt_out_still_permits_unattributed(self):
        # The legitimate "policy decides" posture survives: an
        # explicit None entry in skill_mcp_map opts the server OUT of
        # skill verification, and the tool executes unattributed.
        ex, ident, _ = self._wired(
            skill_mcp_map={"notes-svc": None})
        r = ex.call(ident, "read_file", path="notes.txt",
                    mcp_server="notes-svc")
        self.assertEqual(r["status"], "executed")
        self.assertEqual(ex._executed.get("read_file", 0), 1)

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
        # Pins persisted automatically by the sweep (H22: MAC-authenticated).
        self.assertTrue(os.path.exists(pin_path))
        data = PinStore.peek(pin_path, mac_key=_pin_key())
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
        # H22: the deployment verifies the MAC with the operator key.
        w2 = PinStore.load(pin_path, mac_key=_pin_key())
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


# ---------------------------------------------------------------------------
# F142 Leg B: referenced-URL content binding (dead-link / rug-pull TOCTOU)
# ---------------------------------------------------------------------------

REF_URL = "https://dead-link.synthetic.local/skill.md"
REF_V1 = b"reference content v1: benign instructions"
REF_V2 = b"reference content v2: ATTACKER instructions"


class FakeResolver(skill_watch.ReferenceResolver):
    """In-memory URL -> bytes map; raises on unknown URLs."""

    def __init__(self, mapping=None):
        self.mapping = dict(mapping or {})
        self.calls = []

    def resolve(self, url):
        self.calls.append(url)
        if url in self.mapping:
            return self.mapping[url]
        raise skill_watch.ReferenceResolutionError(
            "no such URL in fake resolver: %s" % url)


def _manifest_with_ref(url=REF_URL):
    return ("skill: link-skill\ninstructions_url: %s\n" % url).encode("utf-8")


def _register_link_skill(watch, resolver_mapping=None, url=REF_URL):
    src = CallableContentSource(lambda: _manifest_with_ref(url))
    return watch.register_skill("link-skill", src, origin=dict(ORIGIN))


class TestReferenceBinding(unittest.TestCase):
    def test_default_resolver_refuses_no_network(self):
        # The default resolver never touches the network: a referenced
        # URL stays unverified.
        with self.assertRaises(skill_watch.ReferenceResolutionError):
            skill_watch.RefusingResolver().resolve(
                "https://example.com/x.md")

    def test_bind_at_registration(self):
        w = SkillWatch(
            reference_resolver=FakeResolver({REF_URL: REF_V1}))
        _register_link_skill(w)
        refs = w._skills["link-skill"]["references"]
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["url"], REF_URL)
        self.assertEqual(refs[0]["status"], "bound")
        self.assertEqual(refs[0]["bound_sha256"], sha(REF_V1))
        self.assertIn("bound_at", refs[0])

    def test_unresolvable_at_registration_is_unverified_not_blocked(self):
        # Default posture: no resolver -> unverified, audited, and the
        # skill still registers (fail-open at install; enforced only
        # when a binding exists).
        w = SkillWatch()
        _register_link_skill(w)
        refs = w._skills["link-skill"]["references"]
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["status"], "unverified")
        self.assertIsNone(refs[0]["bound_sha256"])
        ok, _ = w.check_at_use("link-skill")
        self.assertTrue(ok)
        # The unverified reference was audited.
        kinds = [e["event_type"] for e in w.events]
        self.assertIn("skill_reference_unverified", kinds)

    def test_reference_url_cap_25(self):
        urls = ["https://h.test/%d.md" % i for i in range(30)]
        body = ("\n".join("ref: " + u for u in urls)).encode("utf-8")
        w = SkillWatch(reference_resolver=FakeResolver({}))
        w.register_skill("many-refs", CallableContentSource(lambda: body),
                         origin=dict(ORIGIN))
        self.assertEqual(len(w._skills["many-refs"]["references"]), 25)

    def test_use_time_drift_quarantines(self):
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        ok, _ = w.check_at_use("link-skill")
        self.assertTrue(ok)
        # Post-approval rug-pull: the referenced URL now serves attacker
        # bytes. The manifest digest is unchanged.
        resolver.mapping[REF_URL] = REF_V2
        ok, detail = w.check_at_use("link-skill")
        self.assertFalse(ok)
        self.assertIn("reference", detail)
        self.assertTrue(w.is_quarantined("link-skill"))
        kinds = [e["event_type"] for e in w.events]
        self.assertIn("skill_reference_drift", kinds)

    def test_stat_prefilter_fast_path_still_rechecks_references(self):
        # Regression: the stat prefilter short-circuited check_at_use
        # before _verify_references, so a drifted reference behind a
        # byte-identical manifest passed as "clean" — the exact rug-pull
        # shape. A real file-backed source engages the prefilter (unlike
        # CallableContentSource above, which has no stat hint).
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        tmp = Path(tempfile.mkdtemp(prefix="gov-skillwatch-"))
        manifest = tmp / "manifest.txt"
        manifest.write_bytes(_manifest_with_ref())
        w.register_skill("link-skill", FileContentSource(str(manifest)),
                         origin=dict(ORIGIN))
        ok, detail = w.check_at_use("link-skill")
        self.assertTrue(ok)
        self.assertEqual(detail, "clean")  # prefilter fast path
        resolver.mapping[REF_URL] = REF_V2  # manifest untouched
        ok, detail = w.check_at_use("link-skill")
        self.assertFalse(ok)
        self.assertIn("reference-drift", detail)
        self.assertTrue(w.is_quarantined("link-skill"))

    def test_bound_target_going_dark_quarantines(self):
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        del resolver.mapping[REF_URL]
        ok, _ = w.check_at_use("link-skill")
        self.assertFalse(ok)
        self.assertTrue(w.is_quarantined("link-skill"))

    def test_unverified_reference_never_blocks_use(self):
        w = SkillWatch()  # default refusing resolver
        _register_link_skill(w)
        ok, detail = w.check_at_use("link-skill")
        self.assertTrue(ok)
        self.assertEqual(detail, "clean")

    def test_verify_all_detects_reference_drift(self):
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        resolver.mapping[REF_URL] = REF_V2
        report = w.verify_all()
        self.assertIn("link-skill", report["reference_drift"])
        self.assertTrue(w.is_quarantined("link-skill"))

    def test_repin_flow_with_reference_hashes(self):
        # Benign reference update -> drift quarantines -> operator
        # reviews and re-pins the new reference hash -> use passes.
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        resolver.mapping[REF_URL] = REF_V2
        ok, _ = w.check_at_use("link-skill")
        self.assertFalse(ok)
        req_id = w.request_repin("link-skill", operator="operator:alice")
        self.assertTrue(req_id)
        w.approve_repin("link-skill", {
            "operator": "operator:alice",
            "new_digest": w._skills["link-skill"]["pinned_digest"],
            "new_reference_hashes": {REF_URL: sha(REF_V2)},
            "reason": "reviewed: legitimate reference update"})
        self.assertFalse(w.is_quarantined("link-skill"))
        ok, _ = w.check_at_use("link-skill")
        self.assertTrue(ok)
        refs = w._skills["link-skill"]["references"]
        self.assertEqual(refs[0]["bound_sha256"], sha(REF_V2))

    def test_stale_reference_hash_after_reswap_is_refused(self):
        # Bait-and-switch on the reference: the operator reviews v2,
        # the attacker swaps to v3 before approval; the stale v2 hash
        # must not bind.
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        resolver.mapping[REF_URL] = REF_V2
        w.check_at_use("link-skill")
        w.request_repin("link-skill", operator="operator:alice")
        resolver.mapping[REF_URL] = b"reference content v3: attacker again"
        with self.assertRaises(SkillWatchError):
            w.approve_repin("link-skill", {
                "operator": "operator:alice",
                "new_digest": w._skills["link-skill"]["pinned_digest"],
                "new_reference_hashes": {REF_URL: sha(REF_V2)},
                "reason": "reviewed v2"})
        self.assertTrue(w.is_quarantined("link-skill"))

    def test_pinstore_persists_references(self):
        resolver = FakeResolver({REF_URL: REF_V1})
        w = SkillWatch(reference_resolver=resolver)
        _register_link_skill(w)
        with tempfile.TemporaryDirectory() as d:
            pin_path = os.path.join(d, "pins.json")
            PinStore.save(w, pin_path)
            w2 = PinStore.load(pin_path, source_factory=lambda sid, o: (
                CallableContentSource(lambda: _manifest_with_ref())))
            refs = w2._skills["link-skill"]["references"]
            self.assertEqual(len(refs), 1)
            self.assertEqual(refs[0]["url"], REF_URL)
            self.assertEqual(refs[0]["status"], "bound")
            self.assertEqual(refs[0]["bound_sha256"], sha(REF_V1))


# ---------------------------------------------------------------------------
# GAP-5: use-time wire-identity + version bindings
# ---------------------------------------------------------------------------

class _WireSource(ContentSource):
    """Test source observing a mutable live wire (identity + version)."""

    def __init__(self, content, wire):
        self._content = content
        self._wire = wire

    def read_bytes(self):
        if isinstance(self._content, Exception):
            raise self._content
        return self._content

    def stat_hint(self):
        return None

    def identity_bytes(self):
        mode = self._wire.get("identity_mode", "ok")
        if mode == "raise":
            raise OSError("wire dark")
        if mode == "none":
            return None
        if mode == "malformed":
            return "not-bytes"
        return self._wire["identity"]

    def version_hint(self):
        mode = self._wire.get("version_mode", "ok")
        if mode == "raise":
            raise OSError("version unreadable")
        return self._wire.get("version")


def _gap5_origin(version="1.0"):
    o = dict(ORIGIN)
    if version is None:
        o.pop("version", None)
    else:
        o["version"] = version
    return o


def _gap5_register(w, skill_id="mcp/svc", content=b"approved artifact",
                   identity=b"wire-identity-X", version="1.0"):
    wire = {"identity": identity, "version": version}
    w.register_skill(skill_id, _WireSource(content, wire),
                     origin=_gap5_origin(version))
    return wire


class TestGap5Registration(unittest.TestCase):
    def test_binds_version_and_identity(self):
        w = SkillWatch()
        _gap5_register(w)
        rec = w._skills["mcp/svc"]
        self.assertEqual(rec["pinned_version"], "1.0")
        self.assertEqual(rec["identity_digest"], sha(b"wire-identity-X"))
        registered = [e for e in w.events
                      if e["event_type"] == "skill_registered"]
        self.assertEqual(registered[0]["pinned_version"], "1.0")
        self.assertTrue(registered[0]["identity_bound"])

    def test_version_pinned_but_unobservable_refused(self):
        w = SkillWatch()
        wire = {"identity": b"id", "version": None}
        with self.assertRaises(SkillWatchError):
            w.register_skill("s", _WireSource(b"c", wire),
                             origin=_gap5_origin("1.0"))
        self.assertNotIn("s", w.registered_skills())

    def test_version_mismatch_at_registration_refused(self):
        w = SkillWatch()
        # Origin claims 2.0 but the wire reports 1.0: the binding does
        # not agree with itself at install -- refuse loudly.
        wire = {"identity": b"wire-identity-X", "version": "1.0"}
        with self.assertRaises(SkillWatchError):
            w.register_skill("mcp/svc", _WireSource(b"c", wire),
                             origin=_gap5_origin("2.0"))
        self.assertNotIn("mcp/svc", w.registered_skills())

    def test_identity_unreadable_at_registration_refused(self):
        w = SkillWatch()
        wire = {"identity": b"id", "version": "1.0",
                "identity_mode": "raise"}
        with self.assertRaises(SkillWatchError):
            w.register_skill("s", _WireSource(b"c", wire),
                             origin=_gap5_origin("1.0"))

    def test_no_version_no_identity_stays_unbound(self):
        w = SkillWatch()
        wire = {"identity_mode": "none", "version": None}
        w.register_skill("plain", _WireSource(b"c", wire),
                         origin=_gap5_origin(None))
        rec = w._skills["plain"]
        self.assertIsNone(rec["pinned_version"])
        self.assertIsNone(rec["identity_digest"])
        ok, _ = w.check_at_use("plain")
        self.assertTrue(ok)


class TestGap5CheckAtUse(unittest.TestCase):
    def test_identity_drift_quarantines(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["identity"] = b"wire-identity-Y"
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail), (False, "identity-drift-quarantined"))
        self.assertTrue(w.is_quarantined("mcp/svc"))
        drift = [e for e in w.events
                 if e["event_type"] == "skill_server_identity_drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["previous_identity_digest"],
                         sha(b"wire-identity-X"))
        self.assertEqual(drift[0]["observed_identity_digest"],
                         sha(b"wire-identity-Y"))

    def test_version_drift_quarantines(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["version"] = "2.0"
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail), (False, "version-drift-quarantined"))
        self.assertTrue(w.is_quarantined("mcp/svc"))
        drift = [e for e in w.events
                 if e["event_type"] == "skill_version_drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["previous_version"], "1.0")
        self.assertEqual(drift[0]["observed_version"], "2.0")

    def test_dark_wire_quarantines_fail_closed(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["identity_mode"] = "raise"
        ok, detail = w.check_at_use("mcp/svc")
        self.assertFalse(ok)
        self.assertIn("unverifiable", detail)
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_withdrawn_identity_quarantines(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["identity_mode"] = "none"
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail),
                         (False, "identity-unverifiable-quarantined"))
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_unobservable_version_quarantines(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["version"] = None
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail),
                         (False, "version-unverifiable-quarantined"))
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_clean_wire_passes(self):
        w = SkillWatch()
        _gap5_register(w)
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail), (True, "clean"))

    def test_fast_path_rechecks_bindings(self):
        # The stat prefilter covers only the manifest file: a wire
        # identity swap that never touches the manifest must still
        # quarantine on the fast path (Leg B reasoning for references).
        class Stable(_WireSource):
            def stat_hint(self):
                return (123, 456)

        w = SkillWatch()
        wire = {"identity": b"wire-identity-X", "version": "1.0"}
        w.register_skill("mcp/svc", Stable(b"approved artifact", wire),
                         origin=_gap5_origin("1.0"))
        ok, _ = w.check_at_use("mcp/svc")
        self.assertTrue(ok)  # fast path, everything clean
        wire["identity"] = b"wire-identity-Y"
        ok, detail = w.check_at_use("mcp/svc")
        self.assertEqual((ok, detail), (False, "identity-drift-quarantined"))
        self.assertTrue(w.is_quarantined("mcp/svc"))
        # And the version binding on the fast path too.
        w2 = SkillWatch()
        wire2 = {"identity": b"wire-identity-X", "version": "1.0"}
        w2.register_skill("mcp/svc", Stable(b"approved artifact", wire2),
                          origin=_gap5_origin("1.0"))
        w2.check_at_use("mcp/svc")
        wire2["version"] = "2.0"
        ok, detail = w2.check_at_use("mcp/svc")
        self.assertEqual((ok, detail), (False, "version-drift-quarantined"))

    def test_sweep_reports_binding_drift(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        _gap5_register(w, skill_id="mcp/other", identity=b"id-other",
                       version="1.0")
        wire["identity"] = b"wire-identity-Y"
        rep = w.verify_all()
        self.assertEqual(rep["identity_drift"], ["mcp/svc"])
        self.assertEqual(rep["version_drift"], [])
        self.assertNotIn("mcp/svc", rep["clean"])
        self.assertIn("mcp/other", rep["clean"])


class TestGap5Repin(unittest.TestCase):
    def _drifted(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["identity"] = b"wire-identity-Y"
        wire["version"] = "2.0"
        w.check_at_use("mcp/svc")
        self.assertTrue(w.is_quarantined("mcp/svc"))
        w.request_repin("mcp/svc", operator="operator:alice")
        return w, wire

    def test_repin_rebinds_identity_and_version(self):
        w, wire = self._drifted()
        w.approve_repin("mcp/svc", {
            "operator": "operator:alice",
            "new_digest": sha(b"approved artifact"),
            "new_identity_digest": sha(b"wire-identity-Y"),
            "new_version": "2.0",
            "reason": "reviewed upgrade"})
        self.assertFalse(w.is_quarantined("mcp/svc"))
        rec = w._skills["mcp/svc"]
        self.assertEqual(rec["identity_digest"], sha(b"wire-identity-Y"))
        self.assertEqual(rec["pinned_version"], "2.0")
        ok, _ = w.check_at_use("mcp/svc")
        self.assertTrue(ok)

    def test_repin_refuses_stale_identity(self):
        w, wire = self._drifted()
        wire["identity"] = b"wire-identity-Z"  # moved under review
        with self.assertRaises(SkillWatchError):
            w.approve_repin("mcp/svc", {
                "operator": "operator:alice",
                "new_digest": sha(b"approved artifact"),
                "new_identity_digest": sha(b"wire-identity-Y"),
                "new_version": "2.0",
                "reason": "reviewed Y"})
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_refused_approval_mutates_nothing(self):
        # A refused approval must not partially apply: the version and
        # identity pins are assigned only when the whole approval
        # commits. The version check passes here (wire serves 2.0) but
        # the identity check refuses -- the pin record must be left
        # exactly as it was.
        w, wire = self._drifted()
        wire["identity"] = b"wire-identity-Z"  # moved under review
        with self.assertRaises(SkillWatchError):
            w.approve_repin("mcp/svc", {
                "operator": "operator:alice",
                "new_digest": sha(b"approved artifact"),
                "new_identity_digest": sha(b"wire-identity-Y"),
                "new_version": "2.0",
                "reason": "reviewed Y"})
        self.assertTrue(w.is_quarantined("mcp/svc"))
        rec = w._skills["mcp/svc"]
        self.assertEqual(rec["pinned_version"], "1.0")
        self.assertEqual(rec["identity_digest"], sha(b"wire-identity-X"))

    def test_refused_approval_on_dark_wire_mutates_nothing(self):
        # Same atomicity guarantee when the wire goes dark under
        # review: version_hint still serves 2.0 but identity_bytes
        # raises at approval time.
        w, wire = self._drifted()
        wire["identity_mode"] = "raise"
        with self.assertRaises(SkillWatchError):
            w.approve_repin("mcp/svc", {
                "operator": "operator:alice",
                "new_digest": sha(b"approved artifact"),
                "new_identity_digest": sha(b"wire-identity-Y"),
                "new_version": "2.0",
                "reason": "reviewed Y"})
        self.assertTrue(w.is_quarantined("mcp/svc"))
        rec = w._skills["mcp/svc"]
        self.assertEqual(rec["pinned_version"], "1.0")
        self.assertEqual(rec["identity_digest"], sha(b"wire-identity-X"))

    def test_repin_refuses_version_drift_without_new_version(self):
        w = SkillWatch()
        wire = _gap5_register(w)
        wire["version"] = "2.0"
        w.check_at_use("mcp/svc")
        w.request_repin("mcp/svc", operator="operator:alice")
        # Approval names no new_version: the moved label is not approved.
        with self.assertRaises(SkillWatchError):
            w.approve_repin("mcp/svc", {
                "operator": "operator:alice",
                "new_digest": sha(b"approved artifact"),
                "new_identity_digest": sha(b"wire-identity-X"),
                "reason": "manifest-only re-pin"})
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_repin_refuses_wrong_new_version(self):
        w, wire = self._drifted()
        with self.assertRaises(SkillWatchError):
            w.approve_repin("mcp/svc", {
                "operator": "operator:alice",
                "new_digest": sha(b"approved artifact"),
                "new_identity_digest": sha(b"wire-identity-Y"),
                "new_version": "9.9",  # wire serves 2.0
                "reason": "typo'd version"})
        self.assertTrue(w.is_quarantined("mcp/svc"))

    def test_repin_without_bindings_untouched(self):
        # A skill that never bound identity/version re-pins exactly as
        # before (no new fields required).
        w = SkillWatch()
        content = {"bytes": b"c1"}
        src = CallableContentSource(lambda: content["bytes"])
        w.register_skill("plain", src, origin=dict(ORIGIN))
        content["bytes"] = b"c2"
        w.check_at_use("plain")
        w.request_repin("plain", operator="operator:alice")
        w.approve_repin("plain", {
            "operator": "operator:alice",
            "new_digest": sha(b"c2"),
            "reason": "routine"})
        self.assertFalse(w.is_quarantined("plain"))


class TestGap5PinStore(unittest.TestCase):
    def test_roundtrip_preserves_bindings(self):
        w = SkillWatch()
        _gap5_register(w)
        with tempfile.TemporaryDirectory() as d:
            pin_path = os.path.join(d, "pins.json")
            PinStore.save(w, pin_path)
            data = PinStore.peek(pin_path)
            rec = data["pins"]["mcp/svc"]
            self.assertEqual(rec["pinned_version"], "1.0")
            self.assertEqual(rec["identity_digest"],
                             sha(b"wire-identity-X"))
            w2 = PinStore.load(
                pin_path,
                source_factory=lambda sid, o: _WireSource(
                    b"approved artifact",
                    {"identity": b"wire-identity-X", "version": "1.0"}))
            ok, _ = w2.check_at_use("mcp/svc")
            self.assertTrue(ok)

    def test_pre_gap5_pin_file_loads_unbound(self):
        w = SkillWatch()
        _gap5_register(w)
        with tempfile.TemporaryDirectory() as d:
            pin_path = os.path.join(d, "pins.json")
            PinStore.save(w, pin_path)
            with open(pin_path) as f:
                data = json.load(f)
            del data["pins"]["mcp/svc"]["pinned_version"]
            del data["pins"]["mcp/svc"]["identity_digest"]
            with open(pin_path, "w") as f:
                json.dump(data, f)
            w2 = PinStore.load(
                pin_path,
                source_factory=lambda sid, o: _WireSource(
                    b"approved artifact",
                    {"identity": b"wire-identity-X", "version": "1.0"}))
            rec = w2._skills["mcp/svc"]
            self.assertIsNone(rec["pinned_version"])
            self.assertIsNone(rec["identity_digest"])

    def test_corrupt_binding_fields_fail_loud(self):
        w = SkillWatch()
        _gap5_register(w)
        with tempfile.TemporaryDirectory() as d:
            pin_path = os.path.join(d, "pins.json")
            PinStore.save(w, pin_path)
            with open(pin_path) as f:
                data = json.load(f)
            data["pins"]["mcp/svc"]["identity_digest"] = "not-hex"
            with open(pin_path, "w") as f:
                json.dump(data, f)
            with self.assertRaises(PinStoreError):
                PinStore.peek(pin_path)
            # 64 chars but not hex: the length check alone would pass.
            data["pins"]["mcp/svc"]["identity_digest"] = "z" * 64
            with open(pin_path, "w") as f:
                json.dump(data, f)
            with self.assertRaises(PinStoreError):
                PinStore.peek(pin_path)
