"""S6 battery: infection lineage across spawn hops + raw file channels (F137).

F137 (HIGH, OPEN): a self-replicating payload crosses spawn hops through
RAW FILE communication with zero infection-lineage records — the S2
governed bus is opt-in, so the file channel bypasses every lineage
control.

This battery replays the F137 shape against the wave-90 lineage
substrate (gov/lineage.py + executor wiring) and hardens it:

  B1  F137 replay: A writes payload file, A spawns B, B reads it, B
      spawns C, C reads it -> lineage birth records + chained
      lineage_birth events at EVERY hop; lineage_contact on each read;
      the writer's stamp is on the file.
  B2  replication watch: the same payload bytes under 3 distinct agent
      lineages -> infection_suspected + origin taint-marked.
  B3  taint propagation: infected A -> B reads A's file -> B infected ->
      C born from B -> born infected (hereditary).
  B4  unlineaged execution refused: minted-but-never-born agent ->
      LineageError on call(); birth from unregistered parent refused.
  B5  symlink hop: write via symlink stamps the REAL file; read via
      either path records contact.
  B6  env-var channel: infected parent spawns child with zero file
      contact -> child born infected (lineage survives the channel the
      content does not).
  B7  renamed payload: same bytes under a new name still correlate by
      content hash.
  B8  forged sidecar: attacker rewrites the stamp -> lineage_stamp_forged,
      reader taint-marked, content treated as tainted.
  B9  stamp/bytes mismatch: file bytes replaced around a valid stamp ->
      lineage_stamp_mismatch, reader tainted.
  B10 executor restart: fresh tracker on the same run_dir preserves
      lineage + taint (registry is the source of truth).
  B11 registry tamper: corrupted registry.jsonl -> LineageError on load
      (fail closed).
  B12 delete removes the stamp; recreated-unstamped reads are
      informational, never refused.
  B13 positive control: benign A->B->C chain works; no false
      infection_suspected; no taint.
  B14 pre-existing unstamped files read fine (informational only).
  B15 governed spawn wiring: spawn_sub_agent mints the birth
      certificate, the child carries it, agent_spawn binds lineage ids.
  B16 tiny content (< 64 bytes) is not replication-correlated.
  B17 second genesis / double birth refused (one root, unique ids).
  B18 outside-sandbox write: stamped at the quarantine path.
  B19 stamp stripping (sidecar deleted, file kept) -> lineage_stamp_stripped,
      reader tainted — not a quiet downgrade to "pre-existing".
  B20 rewrite after strip re-stamps: the strip record is superseded.
  B21 strip record survives executor restart (replayed from the chain).
  B22 file contact across a governed spawn hop: parent writes a
      stamped file, spawned child reads it -> contact recorded
      against the parent's birth lineage; taint flows parent->child.
  B23 failed spawn leaves no orphan birth record (birth is minted
      after key registration + child-token creation succeed).
  B24 long files: the tool truncates reads to 4000 chars but the
      stamp covers full bytes — the hook hashes actual file bytes,
      no false forgery.
  B25 full F137 replay end-to-end on the governed spawn path:
      agent-a writes payload -> spawned agent-b reads + replicates
      -> agent-b's spawned agent-c reads the copy. Birth records at
      every hop, contact records on every read, infection_suspected
      fires across the three lineages.

The "payload" below is a synthetic distinctive string — a test
fixture standing in for replicating bytes. It carries no instructions;
what the battery exercises is lineage propagation, not payload
semantics.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from tests.keyfixture import provision_test_key
except ImportError:
    from keyfixture import provision_test_key
provision_test_key()
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.executor import ToolExecutor  # noqa: E402
from gov.lineage import LineageError, LineageTracker  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from tests import harness  # noqa: E402

# Synthetic distinctive payload: stands in for replicating bytes. No
# instructions, just a recognizable marker the lineage must follow.
PAYLOAD = ("SYNTHETIC-LINEAGE-TEST-PAYLOAD marker=7f3a91c4 "
           "replicate-this-string-to-test-hop-lineage " * 4)
assert len(PAYLOAD.encode("utf-8")) >= 64


def _sha(b):
    return hashlib.sha256(b).hexdigest()


class _World(object):
    """One governed run with the lineage tracker installed."""

    def __init__(self, test, agents=("agent-A", "agent-B", "agent-C")):
        self.ctx = harness.make_run()
        test.addCleanup(harness.cleanup_run_dirs)
        self.ex = self.ctx["executor"]
        self.run_dir = self.ctx["run_dir"]
        self.tracker = LineageTracker(self.run_dir, self.ctx["log"])
        # Deployment act: install the tracker on the executor.
        self.ex._lineage_tracker = self.tracker
        self.tracker.genesis(agents[0], role="coder", principal="test")
        for parent, child in zip(agents, agents[1:]):
            self.tracker.birth(parent, child, role="coder",
                               principal="test")
        self.ids = {a: self.ctx["mint_identity"](a, "coder", "test")
                    for a in agents}

    def events(self, name):
        return [e for e in read_entries(self.run_dir / "actions.jsonl")
                if e.get("event") == name]

    def call(self, agent, tool, **kw):
        return self.ex.call(self.ids[agent], tool, **kw)


class TestS6ReplicationLineage(unittest.TestCase):
    # -- B1: F137 replay -------------------------------------------------

    def test_b1_f137_replay_lineage_at_every_hop(self):
        w = _World(self)
        r = w.call("agent-A", "write_file", path="payload.txt",
                   content=PAYLOAD)
        self.assertEqual(r["status"], "executed")
        w.call("agent-B", "read_file", path="payload.txt")
        w.call("agent-C", "read_file", path="payload.txt")

        # Birth records at every hop, parent-linked, verifying.
        for a in ("agent-A", "agent-B", "agent-C"):
            self.assertTrue(w.tracker.verify(a), a)
        cert_b = w.tracker.certificate("agent-B")
        cert_c = w.tracker.certificate("agent-C")
        self.assertEqual(cert_b["parent"], "agent-A")
        self.assertEqual(cert_c["parent"], "agent-B")
        self.assertEqual(cert_c["depth"], 2)

        # Chained lineage_birth events: genesis + 2 births.
        births = w.events("lineage_birth")
        self.assertEqual(len(births), 3)
        self.assertEqual(
            sorted(b["event"] for b in births), ["lineage_birth"] * 3)

        # The writer's stamp is on the file (sidecar next to it).
        stamp_path = (w.run_dir / "sandbox" / "payload.txt.lineage.json")
        self.assertTrue(stamp_path.is_file())
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        self.assertEqual(stamp["writer"], "agent-A")
        self.assertEqual(stamp["content_sha256"],
                         _sha(PAYLOAD.encode("utf-8")))
        self.assertIn("hmac", stamp)

        # lineage_contact on each downstream read, naming the writer.
        contacts = w.events("lineage_contact")
        readers = sorted(c["agent_id"] for c in contacts)
        self.assertEqual(readers, ["agent-B", "agent-C"])
        for c in contacts:
            self.assertEqual(c["writer"], "agent-A")

        # lineage_file_write chained for the write.
        writes = w.events("lineage_file_write")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["agent_id"], "agent-A")

    # -- B2: replication watch -------------------------------------------

    def test_b2_replication_watch_fires_at_three_lineages(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="p.txt", content=PAYLOAD)
        w.call("agent-B", "read_file", path="p.txt")
        # Third distinct lineage touches the same bytes -> alarm.
        w.call("agent-C", "read_file", path="p.txt")
        susp = w.events("infection_suspected")
        self.assertEqual(len(susp), 1)
        self.assertEqual(susp[0]["agent_id"], "agent-A")  # origin
        self.assertEqual(sorted(susp[0]["agents"]),
                         ["agent-A", "agent-B", "agent-C"])
        # Origin taint-marked by the watch.
        self.assertTrue(w.tracker.is_infected("agent-A"))
        # Fires once per campaign, not per extra touch — but a later
        # reader of the now-tainted writer's file is still tainted via
        # live writer taint.
        w.tracker.birth("agent-C", "agent-D", role="coder",
                        principal="test")
        d = w.ctx["mint_identity"]("agent-D", "coder", "test")
        w.ex.call(d, "read_file", path="p.txt")
        self.assertEqual(len(w.events("infection_suspected")), 1)
        self.assertTrue(w.tracker.is_infected("agent-D"))

    # -- B3: taint propagation -------------------------------------------

    def test_b3_taint_propagates_through_file_and_birth(self):
        w = _World(self)
        w.tracker.mark_infected("agent-A", "test: known-bad origin")
        w.call("agent-A", "write_file", path="evil.txt", content=PAYLOAD)
        # Stamp carries the taint bit.
        stamp = json.loads((w.run_dir / "sandbox"
                            / "evil.txt.lineage.json").read_text(
                                encoding="utf-8"))
        self.assertTrue(stamp["infected"])
        # B reads an infected file -> B infected.
        w.call("agent-B", "read_file", path="evil.txt")
        self.assertTrue(w.tracker.is_infected("agent-B"))
        # C was born from B AFTER B's infection... (C born clean here;
        # re-birth a fresh child to test hereditary taint at birth).
        w.tracker.birth("agent-B", "agent-E", role="coder",
                        principal="test")
        cert_e = w.tracker.certificate("agent-E")
        self.assertTrue(cert_e["infected"])
        self.assertIn("hereditary", cert_e["infected_reason"])

    # -- B4: unlineaged execution refused ---------------------------------

    def test_b4_unlineaged_execution_refused(self):
        w = _World(self)
        ghost = w.ctx["mint_identity"]("ghost", "coder", "test")
        with self.assertRaises(LineageError):
            w.ex.call(ghost, "read_file", path="payload.txt")
        denied = w.events("lineage_unregistered")
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["agent_id"], "ghost")
        # Birth from an unregistered parent is refused too.
        with self.assertRaises(LineageError):
            w.tracker.birth("ghost", "ghost-child")

    # -- B5: symlink hop ---------------------------------------------------

    def test_b5_symlink_hop_keeps_lineage(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="real.txt", content=PAYLOAD)
        real = w.run_dir / "sandbox" / "real.txt"
        link = w.run_dir / "sandbox" / "link.txt"
        os.symlink(real, link)
        # Read via the symlink: the stamp is found through resolution.
        w.call("agent-B", "read_file", path="link.txt")
        contacts = w.events("lineage_contact")
        self.assertEqual(len(contacts), 1)
        self.assertEqual(contacts[0]["agent_id"], "agent-B")
        # Reverse: write via symlink stamps the REAL file.
        link2 = w.run_dir / "sandbox" / "link2.txt"
        os.symlink(real, link2)
        w.call("agent-A", "write_file", path="link2.txt",
               content=PAYLOAD + "v2")
        stamp = json.loads((w.run_dir / "sandbox"
                            / "real.txt.lineage.json").read_text(
                                encoding="utf-8"))
        self.assertEqual(stamp["content_sha256"],
                         _sha((PAYLOAD + "v2").encode("utf-8")))

    # -- B6: env-var channel (hereditary taint, no file contact) -----------

    def test_b6_env_var_channel_child_born_infected(self):
        w = _World(self, agents=("agent-A",))
        w.tracker.mark_infected("agent-A", "test: env-channel origin")
        # The child never touches a file: taint arrives via birth.
        w.tracker.birth("agent-A", "agent-B", role="coder",
                        principal="test")
        self.assertTrue(w.tracker.is_infected("agent-B"))
        # And the child's own writes are stamped infected.
        b = w.ctx["mint_identity"]("agent-B", "coder", "test")
        w.ex.call(b, "write_file", path="b.txt", content=PAYLOAD)
        stamp = json.loads((w.run_dir / "sandbox"
                            / "b.txt.lineage.json").read_text(
                                encoding="utf-8"))
        self.assertTrue(stamp["infected"])

    # -- B7: renamed payload -----------------------------------------------

    def test_b7_renamed_payload_still_correlates(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="one.txt", content=PAYLOAD)
        # B "renames" by copying the same bytes to a new name.
        w.call("agent-B", "write_file", path="totally_new_name.bin",
               content=PAYLOAD)
        w.call("agent-C", "read_file", path="totally_new_name.bin")
        susp = w.events("infection_suspected")
        self.assertEqual(len(susp), 1)
        self.assertEqual(susp[0]["content_sha256"],
                         _sha(PAYLOAD.encode("utf-8")))

    # -- B8: forged sidecar --------------------------------------------------

    def test_b8_forged_sidecar_detected(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="f.txt", content=PAYLOAD)
        # Attacker with raw host access rewrites the stamp claiming
        # clean bytes from a fake writer.
        sp = w.run_dir / "sandbox" / "f.txt.lineage.json"
        sp.write_text(json.dumps({"v": 1, "writer": "nobody",
                                  "lineage_id": "lin_fake",
                                  "content_sha256":
                                      _sha(PAYLOAD.encode("utf-8")),
                                  "infected": False,
                                  "hmac": "0" * 64}),
                      encoding="utf-8")
        w.call("agent-B", "read_file", path="f.txt")
        forged = w.events("lineage_stamp_forged")
        self.assertEqual(len(forged), 1)
        # The reader is taint-marked: forged provenance reads as hostile.
        self.assertTrue(w.tracker.is_infected("agent-B"))

    # -- B9: stamp/bytes mismatch --------------------------------------------

    def test_b9_bytes_replaced_around_valid_stamp(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="g.txt", content=PAYLOAD)
        # Attacker swaps the file bytes but keeps the valid stamp.
        (w.run_dir / "sandbox" / "g.txt").write_text(
            "COMPLETELY DIFFERENT BYTES " * 8, encoding="utf-8")
        w.call("agent-B", "read_file", path="g.txt")
        mism = [e for e in w.events("lineage_stamp_forged")
                if e.get("flag") == "lineage_stamp_mismatch"]
        self.assertEqual(len(mism), 1)
        self.assertTrue(w.tracker.is_infected("agent-B"))

    # -- B10: restart ----------------------------------------------------------

    def test_b10_restart_preserves_lineage_and_taint(self):
        w = _World(self)
        w.tracker.mark_infected("agent-A", "test: pre-restart taint")
        w.call("agent-A", "write_file", path="h.txt", content=PAYLOAD)
        # Fresh tracker = executor restart: registry is the source of truth.
        t2 = LineageTracker(w.run_dir, ActionLog(w.run_dir / "actions.jsonl"))
        self.assertTrue(t2.verify("agent-B"))
        self.assertTrue(t2.verify("agent-C"))
        self.assertTrue(t2.is_infected("agent-A"))
        self.assertEqual(t2.certificate("agent-B")["parent"], "agent-A")
        # The reloaded tracker still gates execution.
        w.ex._lineage_tracker = t2
        ghost = w.ctx["mint_identity"]("ghost2", "coder", "test")
        with self.assertRaises(LineageError):
            w.ex.call(ghost, "read_file", path="h.txt")

    # -- B11: registry tamper ----------------------------------------------------

    def test_b11_registry_tamper_fails_closed(self):
        w = _World(self)
        reg = w.run_dir / "lineage" / "registry.jsonl"
        lines = reg.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[1])
        rec["agent_id"] = "mallory"  # tamper, keep the old hash
        lines[1] = json.dumps(rec, sort_keys=True)
        reg.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(LineageError):
            LineageTracker(w.run_dir,
                           ActionLog(w.run_dir / "actions.jsonl"))

    # -- B12: delete ---------------------------------------------------------------

    def test_b12_delete_removes_stamp(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="d.txt", content=PAYLOAD)
        sp = w.run_dir / "sandbox" / "d.txt.lineage.json"
        self.assertTrue(sp.is_file())
        r = w.call("agent-A", "delete_file", path="d.txt")
        self.assertEqual(r["status"], "executed")
        self.assertFalse(sp.exists())
        # A recreated-but-unstamped file reads fine (informational).
        (w.run_dir / "sandbox" / "d.txt").write_text(
            "fresh bytes, no stamp, " * 8, encoding="utf-8")
        r = w.call("agent-B", "read_file", path="d.txt")
        self.assertEqual(r["status"], "executed")
        unstamped = w.events("lineage_unstamped_read")
        self.assertTrue(any(e["agent_id"] == "agent-B" for e in unstamped))

    # -- B13: positive control ---------------------------------------------------------

    def test_b13_benign_chain_works_no_false_alarm(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="notes.txt",
               content="Benign operational notes for the run. " * 8)
        w.call("agent-B", "read_file", path="notes.txt")
        w.call("agent-B", "write_file", path="summary.txt",
               content="Summary of notes. " * 8)
        w.call("agent-C", "read_file", path="summary.txt")
        self.assertEqual(w.events("infection_suspected"), [])
        for a in ("agent-A", "agent-B", "agent-C"):
            self.assertFalse(w.tracker.is_infected(a))
            self.assertTrue(w.tracker.verify(a))

    # -- B14: pre-existing files --------------------------------------------------------------

    def test_b14_preexisting_unstamped_read_allowed(self):
        w = _World(self)
        p = w.run_dir / "sandbox" / "legacy.txt"
        p.write_text("legacy data predating the lineage layer. " * 8,
                     encoding="utf-8")
        r = w.call("agent-A", "read_file", path="legacy.txt")
        self.assertEqual(r["status"], "executed")
        self.assertTrue(w.events("lineage_unstamped_read"))

    # -- B16: tiny content ---------------------------------------------------------------------

    def test_b16_tiny_content_not_correlated(self):
        w = _World(self)
        for a, name in (("agent-A", "t1.txt"), ("agent-B", "t2.txt"),
                        ("agent-C", "t3.txt")):
            w.call(a, "write_file", path=name, content="ok")
        self.assertEqual(w.events("infection_suspected"), [])

    # -- B17: genesis/birth uniqueness ----------------------------------------------------------------

    def test_b17_second_genesis_and_double_birth_refused(self):
        w = _World(self)
        with self.assertRaises(LineageError):
            w.tracker.genesis("agent-Z")
        # Idempotent for the SAME agent.
        w.tracker.genesis("agent-A")
        with self.assertRaises(LineageError):
            w.tracker.birth("agent-A", "agent-B")

    # -- B18: outside-sandbox write stamped at quarantine -------------------------------------

    def test_b18_outside_sandbox_write_stamped(self):
        w = _World(self)
        # Direct tracker-level check: the hook stamps result["path"],
        # which for outside-sandbox writes is the quarantine location.
        q = w.run_dir / "quarantine" / "exfil.txt"
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_text(PAYLOAD, encoding="utf-8")
        w.tracker.stamp_write("agent-A", q, _sha(PAYLOAD.encode("utf-8")),
                              len(PAYLOAD.encode("utf-8")))
        status, stamp = w.tracker.note_read("agent-B", q,
                                            _sha(PAYLOAD.encode("utf-8")),
                                            len(PAYLOAD.encode("utf-8")))
        self.assertEqual(status, "contact")
        self.assertEqual(stamp["writer"], "agent-A")

    # -- B19: stamp stripping -------------------------------------------------

    def test_b19_stamp_stripping_detected(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="s.txt", content=PAYLOAD)
        # Attacker deletes just the sidecar through the governed tool.
        r = w.call("agent-A", "delete_file", path="s.txt.lineage.json")
        self.assertEqual(r["status"], "executed")
        self.assertFalse((w.run_dir / "sandbox"
                          / "s.txt.lineage.json").exists())
        # The file is kept — the next read is LOUD, not "pre-existing".
        w.call("agent-B", "read_file", path="s.txt")
        stripped = [e for e in w.events("lineage_stamp_forged")
                    if e.get("flag") == "lineage_stamp_stripped"]
        self.assertEqual(len(stripped), 1)
        self.assertTrue(w.tracker.is_infected("agent-B"))

    def test_b20_rewrite_after_strip_supersedes(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="s2.txt", content=PAYLOAD)
        w.call("agent-A", "delete_file", path="s2.txt.lineage.json")
        # Fresh write re-stamps: the strip record is stale, reads are
        # clean contacts again.
        w.call("agent-A", "write_file", path="s2.txt", content=PAYLOAD)
        w.call("agent-B", "read_file", path="s2.txt")
        stripped = [e for e in w.events("lineage_stamp_forged")
                    if e.get("flag") == "lineage_stamp_stripped"]
        self.assertEqual(stripped, [])
        contacts = [e for e in w.events("lineage_contact")
                    if e["agent_id"] == "agent-B"]
        self.assertEqual(len(contacts), 1)
        self.assertFalse(w.tracker.is_infected("agent-B"))

    def test_b21_strip_survives_restart(self):
        w = _World(self)
        w.call("agent-A", "write_file", path="s3.txt", content=PAYLOAD)
        w.call("agent-A", "delete_file", path="s3.txt.lineage.json")
        t2 = LineageTracker(w.run_dir, ActionLog(w.run_dir / "actions.jsonl"))
        w.ex._lineage_tracker = t2
        w.call("agent-B", "read_file", path="s3.txt")
        stripped = [e for e in w.events("lineage_stamp_forged")
                    if e.get("flag") == "lineage_stamp_stripped"]
        self.assertEqual(len(stripped), 1)
        self.assertTrue(t2.is_infected("agent-B"))

    def test_b24_long_file_no_false_forge(self):
        """Critical: the tool result truncates reads to 4000 chars,
        but the write stamp covers the full bytes. A >4000 char file
        must read back as a clean contact — hashing the truncation
        would false-positive every long file as forged."""
        w = _World(self)
        big = "0123456789abcdef" * 600  # 9600 chars
        w.call("agent-A", "write_file", path="big.txt", content=big)
        w.call("agent-B", "read_file", path="big.txt")
        forged = [e for e in w.events("lineage_stamp_forged")]
        self.assertEqual(forged, [])
        contacts = [e for e in w.events("lineage_contact")
                    if e["agent_id"] == "agent-B"]
        self.assertEqual(len(contacts), 1)
        self.assertFalse(w.tracker.is_infected("agent-B"))


class TestS6GovernedSpawnWiring(unittest.TestCase):
    """B15: spawn_sub_agent mints the birth certificate on the REAL
    governed spawn path (bound delegation context, w86 scaffold)."""

    def test_b15_spawn_mints_birth_certificate(self):
        from tests.test_w86_identity import (_Keys, _Run, _bound_ctx,
                                             _Quiet)
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name)
        tracker = LineageTracker(r.run_dir, r.log)
        tracker.genesis("agent-a", role="scout", principal="alice")
        with _Quiet(self):
            ex = r.build(ctx, session_identity=("agent-a", "scout",
                                                "alice"),
                         lineage_tracker=tracker)
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
        # Birth record minted by the spawn path itself.
        self.assertTrue(tracker.is_registered("agent-b"))
        cert = tracker.certificate("agent-b")
        self.assertEqual(cert["parent"], "agent-a")
        self.assertTrue(tracker.verify("agent-b"))
        # The child carries its certificate.
        self.assertEqual(child_ex._lineage_cert["agent_id"], "agent-b")
        self.assertIs(child_ex._lineage_tracker, tracker)
        # The agent_spawn event binds lineage ids into the hash chain.
        spawns = [e for e in r.entries()
                  if e.get("event") == "agent_spawn"]
        self.assertEqual(len(spawns), 1)
        self.assertEqual(spawns[0]["lineage_id"], cert["lineage_id"])
        self.assertEqual(spawns[0]["sub_agent_id"], "agent-b")
        # The child executes under lineage (grandchild hop too).
        with _Quiet(self):
            grandchild_ex = child_ex.spawn_sub_agent(
                "agent-c", ["tool:read_file"], keys.parent[0])
        self.assertTrue(tracker.verify("agent-c"))
        self.assertEqual(tracker.certificate("agent-c")["depth"], 2)
        self.assertIsNotNone(grandchild_ex._lineage_cert)

    def test_b22_file_contact_across_spawn_hop(self):
        """End-to-end F137 shape on the governed spawn path: the parent
        writes a (stamped) payload file, the spawned child reads it —
        the read records lineage contact against the parent's birth
        lineage, and taint flows parent -> child through the file."""
        from tests.test_w86_identity import (_Keys, _Run, _bound_ctx,
                                             _Quiet)
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name)
        tracker = LineageTracker(r.run_dir, r.log)
        tracker.genesis("agent-a", role="scout", principal="alice")
        payload = "SYNTHETIC-SPAWN-HOP-PAYLOAD " * 8
        # Parent's agent-driven write (raw bytes + hook-equivalent stamp).
        (r.run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
        (r.run_dir / "sandbox" / "drop.txt").write_text(
            payload, encoding="utf-8")
        import hashlib as _hl
        tracker.stamp_write("agent-a", r.run_dir / "sandbox" / "drop.txt",
                            _hl.sha256(payload.encode("utf-8")).hexdigest(),
                            len(payload.encode("utf-8")))
        with _Quiet(self):
            ex = r.build(ctx, session_identity=("agent-a", "scout",
                                                "alice"),
                         lineage_tracker=tracker)
            child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                          keys.parent[0])
            child_ident = child_ex.mint_identity("agent-b", "scout",
                                                 "alice")
            res = child_ex.call(child_ident, "read_file", path="drop.txt")
        self.assertEqual(res["status"], "executed")
        contacts = [e for e in r.entries()
                    if e.get("event") == "lineage_contact"]
        self.assertEqual(len(contacts), 1)
        self.assertEqual(contacts[0]["agent_id"], "agent-b")
        self.assertEqual(contacts[0]["writer"], "agent-a")
        # Taint the parent, spawn again: the new child's read taints it.
        tracker.mark_infected("agent-a", "b22 test")
        with _Quiet(self):
            child2_ex = ex.spawn_sub_agent("agent-c", ["tool:read_file"],
                                           keys.parent[0])
            child2_ident = child2_ex.mint_identity("agent-c", "scout",
                                                   "alice")
            child2_ex.call(child2_ident, "read_file", path="drop.txt")
        self.assertTrue(tracker.is_infected("agent-c"))

    def test_b23_failed_spawn_leaves_no_birth(self):
        """Birth is minted AFTER key registration and child-token
        creation succeed: a refused spawn (here, parent-signature key
        swap) leaves no orphan birth record and no lineage_birth
        event for the child that never existed."""
        from tests.test_w86_identity import (_Keys, _Run, _bound_ctx,
                                             _Quiet)
        from gov import delegation_tokens as _dt
        keys = _Keys()
        r = _Run(self, keys)
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name)
        tracker = LineageTracker(r.run_dir, r.log)
        tracker.genesis("agent-a", role="scout", principal="alice")
        with _Quiet(self):
            ex = r.build(ctx, session_identity=("agent-a", "scout",
                                                "alice"),
                         lineage_tracker=tracker)
            ex.spawn_sub_agent("agent-ok", ["tool:read_file"],
                               keys.parent[0])
            self.assertTrue(tracker.is_registered("agent-ok"))
            with self.assertRaises(_dt.DelegationSignatureError):
                ex.spawn_sub_agent("agent-orphan", ["tool:read_file"],
                                   keys.authority[0])
        self.assertFalse(tracker.is_registered("agent-orphan"))
        births = [e for e in r.entries()
                  if e.get("event") == "lineage_birth"
                  and e.get("sub_agent_id") == "agent-orphan"]
        self.assertEqual(births, [])

    def test_b25_full_f137_replay_end_to_end(self):
        """The complete F137 shape on the governed path: agent-a
        writes a payload file; spawned agent-b reads it and
        replicates it to a second file; agent-b's spawned agent-c
        reads the copy. Every hop mints lineage, every file contact
        is recorded, and the population watch fires
        infection_suspected across the three distinct lineages —
        the exact scenario that previously crossed with ZERO
        infection-lineage records."""
        from tests.test_w86_identity import (_Keys, _Run, _bound_ctx,
                                             _Quiet)
        from gov.executor import ToolExecutor
        from gov import policy_change as _pc
        mule_policy = ("version: 2\nroles:\n"
                       "  mule: [read_file, write_file]\npolicies:\n"
                       "  - id: allow-mule-rw\n    effect: allow\n"
                       "    match:\n      tool: [read_file, write_file]\n"
                       "    reason: s6 b25 fixture\n")
        keys = _Keys()
        r = _Run(self, keys)
        scope = ("tool:read_file", "tool:write_file")
        with _Quiet(self):
            ctx, _ = _bound_ctx(keys, trust=r.trust,
                                session=r.run_dir.name,
                                user_scope=scope, agent_scope=scope,
                                deleg_scope=scope)
        tracker = LineageTracker(r.run_dir, r.log)
        tracker.genesis("agent-a", role="mule", principal="alice")
        payload = "SYNTHETIC-F137-E2E-PAYLOAD " * 8  # 208 bytes
        with _Quiet(self):
            # Governed core intact: a second policy store bootstrapped
            # with the mule policy (no construction-gate bypass).
            store = _pc.GovernedPolicyStore(
                deployment_mode="dev", trust=r.trust, log=r.log,
                session_id="sess-s6b25")
            store.bootstrap(mule_policy, keys.human[0], "alice",
                            "s6 b25 fixture",
                            approver_signers=[keys.human[0]])
            ex = ToolExecutor(
                r.run_dir, r.engine, r.log, r.approvals,
                policy_store=store, delegation_context=ctx,
                # The capability gate is off-by-default and loud. This
                # battery's subject is S6 replication, not the
                # capability gate; declared, not silent.
                capability_ungoverned_ack=(
                    "s6repl battery: subject under test is "
                    "self-replication, not the capability gate; "
                    "declared, not silent"),
                session_identity=("agent-a", "mule", "alice"),
                lineage_tracker=tracker)
            ident_a = ex.mint_identity("agent-a", "mule", "alice")
            w1 = ex.call(ident_a, "write_file", path="payload.txt",
                         content=payload)
            self.assertEqual(w1["status"], "executed")
            child_ex = ex.spawn_sub_agent("agent-b", list(scope),
                                          keys.parent[0])
            ident_b = child_ex.mint_identity("agent-b", "mule", "alice")
            r1 = child_ex.call(ident_b, "read_file", path="payload.txt")
            self.assertEqual(r1["status"], "executed")
            w2 = child_ex.call(ident_b, "write_file", path="copy.txt",
                               content=payload)
            self.assertEqual(w2["status"], "executed")
            gchild_ex = child_ex.spawn_sub_agent("agent-c", list(scope),
                                                 keys.parent[0])
            ident_c = gchild_ex.mint_identity("agent-c", "mule",
                                              "alice")
            r2 = gchild_ex.call(ident_c, "read_file", path="copy.txt")
            self.assertEqual(r2["status"], "executed")
        # Every spawn hop has a birth record resolving to genesis.
        for agent in ("agent-a", "agent-b", "agent-c"):
            self.assertTrue(tracker.verify(agent))
        self.assertEqual(tracker.certificate("agent-c")["depth"], 2)
        # Every file contact recorded with writer lineage.
        contacts = [e for e in r.entries()
                    if e.get("event") == "lineage_contact"]
        writers = {e["writer"] for e in contacts}
        self.assertEqual(writers, {"agent-a", "agent-b"})
        # The population watch fired on the third distinct lineage.
        alarms = [e for e in r.entries()
                  if e.get("event") == "infection_suspected"]
        self.assertEqual(len(alarms), 1)
        self.assertEqual(sorted(alarms[0]["agents"]),
                         ["agent-a", "agent-b", "agent-c"])
        self.assertTrue(tracker.is_infected("agent-a"))  # origin marked


if __name__ == "__main__":
    unittest.main(verbosity=2)
