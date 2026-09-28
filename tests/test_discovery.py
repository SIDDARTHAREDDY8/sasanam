"""Tests for gov.discovery (STREAM-A integration).

Repo convention: unittest-style, stdlib only. Run from the repo root:
    TMPDIR=/tmp/gov-int-a-<pid> ~/workspace/.gov-venv/bin/python \
        -m unittest tests.test_discovery -v
$0 spend, synthetic/local only, no network. The scanner is NEVER pointed
at a real home directory — synthetic fixtures under TMPDIR only, and the
fixture guard itself is under test.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

from gov import discovery
from gov.discovery import (DiscoveryLedger, LedgerCorruptError,
                           candidate_id_for_sig, report_unregistered,
                           scan_directory, scan_file_content,
                           scan_mcp_config, scan_process_list, signal,
                           unregistered_candidates)
from gov.identity import PrincipalRegistry
from gov.log import ActionLog, read_entries

try:
    from tests.keyfixture import provision_test_key
except ImportError:  # pragma: no cover - direct module run
    from keyfixture import provision_test_key

# AWS's own documented EXAMPLE key — not real, never was.
EXAMPLE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def plant_fixtures(root):
    """Plant four unregistered-agent footprints. Returns the fixture dir.

    (Folded in from the STREAM-A break probes; break_probes.py stays in
    the stream directory as the pre-fix record.)
    """
    proj = os.path.join(root, "proj")
    os.makedirs(os.path.join(proj, ".claude"), exist_ok=True)
    with open(os.path.join(proj, ".claude", "settings.json"), "w") as f:
        json.dump({"model": "opus", "permissions": {"allow": ["Bash"]}}, f)
    os.makedirs(os.path.join(proj, ".cursor"), exist_ok=True)
    with open(os.path.join(proj, ".cursor", "mcp.json"), "w") as f:
        json.dump({"mcpServers": {
            "shadow-gh": {"command": "npx",
                          "args": ["-y", "shadow-mcp-server"]}}}, f)
    with open(os.path.join(proj, ".env"), "w") as f:
        f.write("AWS_ACCESS_KEY_ID=%s\n" % EXAMPLE_AWS_KEY)
    with open(os.path.join(proj, "CLAUDE.md"), "w") as f:
        f.write("# Agent instructions\nYou are a coding agent.\n")
    return proj


def scan(root, **kw):
    """scan_directory with the fixture base bound to the fixture root."""
    return scan_directory(root, allowed_base=root, **kw)


class BreakProbeRerunTest(unittest.TestCase):
    """The break probes' gap assertions, re-run against the integration."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="discovery-test-")
        self.proj = plant_fixtures(self.tmp)
        self.ledger_path = os.path.join(self.tmp, "ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_p1_discovery_module_in_tree(self):
        """P1 CLOSED: gov.discovery is in the main tree."""
        for name in ("scan_directory", "DiscoveryLedger",
                     "unregistered_candidates", "report_unregistered",
                     "FINDING_KIND", "SIGNAL_WEIGHTS"):
            self.assertTrue(hasattr(discovery, name), name)
        self.assertEqual(discovery.FINDING_KIND, "unregistered_agent")

    def test_p2_footprints_now_detected(self):
        """P2 CLOSED: planted footprints become candidates + findings."""
        sigs = scan(self.proj)
        kinds = {s["kind"] for s in sigs}
        for expected in ("harness_config", "mcp_server", "credential",
                         "prompt_footprint"):
            self.assertIn(expected, kinds,
                          "signal kind %s missing" % expected)
        ledger = DiscoveryLedger(self.ledger_path)
        touched = ledger.note_signals(sigs)
        self.assertTrue(touched)
        findings = unregistered_candidates(ledger)
        self.assertTrue(findings)
        self.assertTrue(all(f["kind"] == "unregistered_agent"
                            for f in findings))

    def test_p3_finding_schema_stable(self):
        """P3 functional close: findings carry the documented schema."""
        sigs = scan(self.proj)
        ledger = DiscoveryLedger(self.ledger_path)
        ledger.note_signals(sigs)
        findings = unregistered_candidates(ledger)
        for f in findings:
            for key in ("kind", "candidate_id", "strength",
                        "signal_kinds", "sources", "first_seen",
                        "last_seen"):
                self.assertIn(key, f)
            self.assertEqual(f["kind"], "unregistered_agent")

    def test_p4_registry_wiring(self):
        """P4 functional close: a registry check suppresses known agents."""
        sigs = scan(self.proj)
        ledger = DiscoveryLedger(self.ledger_path)
        ledger.note_signals(sigs)
        all_findings = unregistered_candidates(ledger)
        self.assertTrue(all_findings)
        # Simulate a deployment registry that knows the first candidate.
        known = {all_findings[0]["candidate_id"]}
        filtered = unregistered_candidates(
            ledger, is_registered=lambda v: v["candidate_id"] in known)
        self.assertEqual(len(filtered), len(all_findings) - 1)
        self.assertNotIn(all_findings[0]["candidate_id"],
                         {f["candidate_id"] for f in filtered})


class FixtureGuardTest(unittest.TestCase):
    """The scanner refuses any root outside the fixture base — it is
    never pointed at a real home directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="discovery-guard-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_inside_base_allowed(self):
        root = os.path.join(self.tmp, "proj")
        os.makedirs(root)
        sigs = scan_directory(root, allowed_base=self.tmp)
        self.assertIsInstance(sigs, list)

    def test_scan_default_base_allows_temp(self):
        root = os.path.join(self.tmp, "proj")
        os.makedirs(root)
        # No allowed_base: defaults to the OS temp area, which covers it.
        sigs = scan_directory(root)
        self.assertIsInstance(sigs, list)

    def test_scan_outside_base_refused(self):
        outside = tempfile.mkdtemp(prefix="discovery-elsewhere-")
        self.addCleanup(shutil.rmtree, outside, True)
        with self.assertRaises(discovery.DiscoveryError):
            scan_directory(outside, allowed_base=self.tmp)

    def test_allowed_base_outside_temp_refused(self):
        # Even an operator-designated base is refused when it is not a
        # fixture area: allowed_base must live in the OS temp area.
        home = os.path.expanduser("~")
        with self.assertRaises(discovery.DiscoveryError):
            scan_directory(home, allowed_base=home)

    def test_real_home_scan_refused(self):
        # The hard case the guard exists for: a scan request aimed at
        # the real user home fails CLOSED.
        home = os.path.expanduser("~")
        with self.assertRaises(discovery.DiscoveryError):
            scan_directory(home)

    def test_relative_escape_refused(self):
        # .. traversal in the root cannot escape the base either.
        escaped = os.path.join(self.tmp, "proj", "..", "proj")
        with self.assertRaises(discovery.DiscoveryError):
            scan_directory(os.path.join(self.tmp, ".."),
                           allowed_base=self.tmp)


class ScannerTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="discovery-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, data):
        full = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(full, mode) as f:
            f.write(data)
        return full

    def test_harness_config_signal(self):
        self._write(".claude/settings.json", "{}")
        sigs = scan(self.tmp)
        kinds = [s["kind"] for s in sigs]
        self.assertIn("harness_config", kinds)

    def test_mcp_server_extraction(self):
        self._write("mcp.json", json.dumps(
            {"mcpServers": {"evil": {"command": "npx"}}}))
        sigs = scan(self.tmp)
        mcp = [s for s in sigs if s["kind"] == "mcp_server"]
        self.assertEqual(len(mcp), 1)
        self.assertEqual(mcp[0]["detail"]["server"], "evil")

    def test_mcp_malformed_json_no_crash(self):
        self._write("mcp.json", "{not json")
        sigs = scan(self.tmp)  # must not raise
        self.assertFalse([s for s in sigs if s["kind"] == "mcp_server"])

    def test_credential_value_never_stored(self):
        secret = EXAMPLE_AWS_KEY
        self._write(".env", "AWS_ACCESS_KEY_ID=%s\n" % secret)
        sigs = scan(self.tmp)
        cred = [s for s in sigs if s["kind"] == "credential"]
        self.assertTrue(cred)
        blob = json.dumps(sigs)
        self.assertNotIn(secret, blob)
        self.assertIn("dlp-aws-access-key",
                      [s["detail"]["rule"] for s in cred])

    def test_binary_and_oversize_skipped(self):
        self._write("blob.bin", b"\x00\x01\x02binary")
        self._write("big.txt", "x" * (discovery.MAX_FILE_BYTES + 10))
        sigs = scan(self.tmp)
        self.assertFalse([s for s in sigs
                          if s["source"].endswith(("blob.bin",
                                                   "big.txt"))])

    def test_symlink_escape_not_followed(self):
        outside = tempfile.mkdtemp(prefix="discovery-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        with open(os.path.join(outside, "secret.txt"), "w") as f:
            f.write("nothing")
        os.symlink(outside, os.path.join(self.tmp, "evil-link"))
        sigs = scan(self.tmp)
        # The escape itself is recorded (fail-loud); nothing under the
        # escaped target may become a candidate signal.
        self.assertFalse([s for s in sigs
                          if "evil-link" in s["source"]
                          and s["kind"] != "scan_error"])
        self.assertFalse([s for s in sigs if "secret.txt" in s["source"]])
        self.assertTrue([s for s in sigs if s["kind"] == "scan_error"])

    def test_unreadable_file_becomes_scan_error(self):
        full = self._write("noperm.txt", "x")
        os.chmod(full, 0)
        try:
            sigs = scan(self.tmp)  # must not raise
        finally:
            os.chmod(full, 0o644)
        # root may still read it; either way no exception escapes
        self.assertIsInstance(sigs, list)

    def test_process_snapshot_signals(self):
        sigs = scan_process_list([
            (123, "codex", "codex --yolo"),
            (456, "bash", "-c ls"),
        ])
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["kind"], "agent_process")

    def test_scan_missing_root_raises(self):
        with self.assertRaises(discovery.DiscoveryError):
            scan_directory(os.path.join(self.tmp, "nope"),
                           allowed_base=self.tmp)

    def test_file_cap_error_recorded_once(self):
        """The cap is recorded once and the walk stops (integration fix:
        the prototype emitted one scan_error per directory)."""
        old = discovery.MAX_FILES_PER_SCAN
        discovery.MAX_FILES_PER_SCAN = 2
        self.addCleanup(setattr, discovery, "MAX_FILES_PER_SCAN", old)
        for i in range(4):
            self._write("d%d/f%d.txt" % (i, i), "x")
        sigs = scan(self.tmp)
        cap_errors = [s for s in sigs
                      if s["kind"] == "scan_error"
                      and "file cap" in s["detail"]["error"]]
        self.assertEqual(len(cap_errors), 1)


class LedgerTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="discovery-test-")
        self.path = os.path.join(self.tmp, "ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sigs(self):
        return [signal("harness_config", "/tmp/x/.claude",
                       {"dir": ".claude"}),
                signal("prompt_footprint", "/tmp/x/CLAUDE.md",
                       {"file": "CLAUDE.md"})]

    def test_sighting_then_merge_dedups(self):
        ledger = DiscoveryLedger(self.path)
        first = ledger.note_signals(self._sigs())
        second = ledger.note_signals(self._sigs())
        self.assertEqual(sorted(first), sorted(second))
        self.assertEqual(len(ledger.candidates()), len(first))
        # Re-sight with an extra signal: merged, not duplicated.
        extra = self._sigs() + [signal("credential", "/tmp/x/.env",
                                      {"rule": "r", "fp": "ab"})]
        ledger.note_signals(extra)
        views = {v["candidate_id"]: v for v in ledger.candidates()}
        self.assertEqual(len(views), len(first) + 1)
        self.assertGreaterEqual(views[first[0]]["last_seen"],
                                views[first[0]]["first_seen"])

    def test_chain_verifies_and_tamper_raises(self):
        ledger = DiscoveryLedger(self.path)
        ledger.note_signals(self._sigs())
        self.assertGreater(ledger.verify(), 0)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write('{"seq": 99, "forged": true}\n')
        with self.assertRaises(LedgerCorruptError):
            DiscoveryLedger(self.path)
        with open(self.path, "r+", encoding="utf-8") as f:
            lines = f.readlines()
            lines[0] = lines[0].replace("harness_config", "tampered!!")
            f.seek(0)
            f.writelines(lines)
            f.truncate()
        with self.assertRaises(LedgerCorruptError):
            DiscoveryLedger(self.path)

    def test_only_explicit_operator_transitions(self):
        ledger = DiscoveryLedger(self.path)
        cids = ledger.note_signals(self._sigs())
        # Re-scanning never changes status.
        ledger.note_signals(self._sigs())
        self.assertTrue(all(v["status"] == "candidate"
                            for v in ledger.candidates()))
        ledger.mark_registered(cids[0], operator="ops-team")
        ledger.mark_dismissed(cids[1], operator="ops-team",
                             reason="test fixture")
        statuses = {v["candidate_id"]: v["status"]
                    for v in ledger.candidates()}
        self.assertEqual(statuses[cids[0]], "registered")
        self.assertEqual(statuses[cids[1]], "dismissed")
        with self.assertRaises(discovery.DiscoveryError):
            ledger.mark_registered("nope", operator="x")

    def test_registered_and_dismissed_excluded_from_findings(self):
        ledger = DiscoveryLedger(self.path)
        cids = ledger.note_signals(self._sigs())
        ledger.mark_registered(cids[0], operator="ops")
        findings = unregistered_candidates(ledger)
        self.assertNotIn(cids[0],
                         {f["candidate_id"] for f in findings})
        self.assertIn(cids[1], {f["candidate_id"] for f in findings})

    def test_findings_sorted_by_strength(self):
        ledger = DiscoveryLedger(self.path)
        ledger.note_signals(self._sigs())
        findings = unregistered_candidates(ledger)
        strengths = [f["strength"] for f in findings]
        self.assertEqual(strengths, sorted(strengths, reverse=True))

    def test_broken_registry_check_keeps_finding(self):
        ledger = DiscoveryLedger(self.path)
        ledger.note_signals(self._sigs())

        def boom(view):
            raise RuntimeError("registry down")

        findings = unregistered_candidates(ledger, is_registered=boom)
        self.assertTrue(findings)  # fail-loud, not fail-silent

    def test_reload_rebuilds_inventory(self):
        """Durability: a fresh ledger on the same file replays every
        sighting/merge/transition exactly."""
        ledger = DiscoveryLedger(self.path)
        cids = ledger.note_signals(self._sigs())
        ledger.note_signals(self._sigs())  # merge pass
        ledger.mark_dismissed(cids[1], operator="ops", reason="x")
        reloaded = DiscoveryLedger(self.path)
        self.assertEqual(reloaded.verify(), ledger.verify())
        views = {v["candidate_id"]: v for v in reloaded.candidates()}
        self.assertEqual(set(views), set(cids))
        self.assertEqual(views[cids[1]]["status"], "dismissed")
        self.assertEqual(views[cids[0]]["status"], "candidate")
        # No duplicate candidates after replay.
        self.assertEqual(len(reloaded.candidates()), len(cids))

    def test_crash_between_sighting_and_merge_is_consistent(self):
        """Append-only: every completed _append is replayable; a crash
        can only lose the in-flight record, never corrupt the chain."""
        ledger = DiscoveryLedger(self.path)
        ledger.note_signals(self._sigs())
        n = ledger.verify()
        # Simulate: more signals noted, then "crash" (drop the object).
        ledger.note_signals(self._sigs())
        del ledger
        reloaded = DiscoveryLedger(self.path)
        self.assertEqual(reloaded.verify(), n + len(self._sigs()))
        self.assertEqual(len(reloaded.candidates()), len(self._sigs()))

    def test_secret_values_never_in_ledger_file(self):
        secret = EXAMPLE_AWS_KEY
        ledger = DiscoveryLedger(self.path)
        ledger.note_signals(scan_file_content("/tmp/x/.env",
                                             "KEY=%s" % secret))
        with open(self.path, encoding="utf-8") as f:
            blob = f.read()
        self.assertNotIn(secret, blob)

    def test_scan_error_never_clears_inventory(self):
        ledger = DiscoveryLedger(self.path)
        cids = ledger.note_signals(self._sigs())
        n_before = len(ledger.candidates())
        ledger.note_signals([signal("scan_error", "/tmp/x",
                                   {"error": "boom"}, strength=0)])
        self.assertEqual(len(ledger.candidates()), n_before)
        self.assertEqual(
            sorted(v["candidate_id"] for v in ledger.candidates()),
            sorted(cids))

    def test_candidate_id_stable(self):
        s1 = signal("harness_config", "/tmp/x/.claude", {"dir": ".claude"})
        s2 = signal("harness_config", "/tmp/x/.claude", {"dir": ".claude"})
        self.assertEqual(candidate_id_for_sig(s1), candidate_id_for_sig(s2))
        p1 = signal("agent_process", "pid:1", {"name": "codex"})
        p2 = signal("agent_process", "pid:2", {"name": "codex"})
        self.assertNotEqual(candidate_id_for_sig(p1),
                            candidate_id_for_sig(p2))
        self.assertIsNone(candidate_id_for_sig(
            signal("scan_error", "/tmp", {"error": "x"}, strength=0)))


class HandoffTest(unittest.TestCase):
    """The discovery -> governed-identity handoff: unregistered_agent
    sightings reach the audit log as audit events."""

    def setUp(self):
        provision_test_key()
        self.tmp = tempfile.mkdtemp(prefix="discovery-handoff-")
        self.proj = plant_fixtures(self.tmp)
        self.ledger = DiscoveryLedger(
            os.path.join(self.tmp, "ledger.jsonl"))
        self.ledger.note_signals(scan(self.proj))
        self.log_path = os.path.join(self.tmp, "audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_findings_mirrored_to_audit_log(self):
        log = ActionLog(self.log_path)
        findings, appended = report_unregistered(self.ledger,
                                                audit_log=log,
                                                operator="ops-team")
        self.assertTrue(findings)
        self.assertEqual(appended, len(findings))
        entries = [e for e in read_entries(self.log_path)
                   if e.get("event") == "unregistered_agent"]
        self.assertEqual(len(entries), len(findings))
        for e in entries:
            self.assertEqual(e["event"], "unregistered_agent")
            self.assertIn("candidate_id", e)
            # No secret material leaks into the audit event.
            self.assertNotIn(EXAMPLE_AWS_KEY, json.dumps(e))

    def test_no_audit_log_no_write(self):
        findings, appended = report_unregistered(self.ledger)
        self.assertTrue(findings)
        self.assertEqual(appended, 0)
        self.assertFalse(os.path.exists(self.log_path))

    def test_registry_authorized_candidate_suppressed(self):
        registry = PrincipalRegistry({"acme": ["coder"]})
        views = self.ledger.candidates(status="candidate")
        known_cid = views[0]["candidate_id"]
        log = ActionLog(self.log_path)
        findings, appended = report_unregistered(
            self.ledger, audit_log=log, registry=registry,
            principal_for=lambda v: ("acme", "coder", None)
            if v["candidate_id"] == known_cid else None)
        self.assertNotIn(known_cid, {f["candidate_id"] for f in findings})
        self.assertEqual(appended, len(findings))
        events = [e for e in read_entries(self.log_path)
                  if e.get("event") == "unregistered_agent"]
        self.assertNotIn(known_cid,
                         {e["candidate_id"] for e in events})

    def test_false_registration_claim_kept_loud(self):
        # A claim the registry REJECTS keeps the finding: a false
        # registration claim is exactly what must surface.
        registry = PrincipalRegistry({"acme": ["coder"]})
        log = ActionLog(self.log_path)
        findings, appended = report_unregistered(
            self.ledger, audit_log=log, registry=registry,
            principal_for=lambda v: ("impostor", "coder", None))
        self.assertTrue(findings)
        self.assertEqual(appended, len(findings))
        self.assertTrue(all(f["kind"] == "unregistered_agent"
                            for f in findings))

    def test_registry_without_mapping_reports_everything(self):
        # Registry present but no candidate->principal mapping: loud,
        # not silent (no mechanical mapping exists).
        registry = PrincipalRegistry({"acme": ["coder"]})
        findings, _ = report_unregistered(self.ledger, registry=registry)
        self.assertTrue(findings)

    def test_handoff_never_auto_registers(self):
        log = ActionLog(self.log_path)
        report_unregistered(self.ledger, audit_log=log)
        self.assertTrue(all(v["status"] == "candidate"
                            for v in self.ledger.candidates()))


class ShadowScanSeamTest(unittest.TestCase):
    """Behavioral shadow scan over the audit trail (prospecting R6 #1).

    scan_action_log() closes the surface scan_directory cannot see:
    an unregistered agent acting through the governed executor at
    machine rate. Signals, not verdicts — findings are sightings.
    """

    BASE = 1_788_000_000  # fixed epoch: deterministic

    def _machine(self, principal, cadence_s=45, n=60, t0=None):
        entries = []
        t = self.BASE if t0 is None else t0
        for _ in range(n):
            t += cadence_s
            entries.append({"ts": t, "principal": principal,
                            "tool": "list_documents",
                            "event": "enumerate"})
            for k in range(3):
                entries.append({"ts": t + 1 + k, "principal": principal,
                                "tool": "read_document",
                                "event": "read %d" % k})
        return entries

    def test_machine_rate_unregistered_is_sighted(self):
        from gov.discovery import scan_action_log
        entries = self._machine("svc-indexer")
        with tempfile.TemporaryDirectory() as d:
            ledger = DiscoveryLedger(os.path.join(d, "ledger.jsonl"))
            sigs = scan_action_log(entries, set())
            self.assertTrue(sigs)
            self.assertTrue(all(s["kind"] in
                                discovery.SHADOW_SIGNAL_KINDS
                                for s in sigs))
            self.assertTrue(all(s["source"] ==
                                "principal:svc-indexer" for s in sigs))
            cids = ledger.note_signals(sigs)
            self.assertEqual(len(cids), 1)
            self.assertTrue(cids[0].startswith("shadow:"))
            findings = unregistered_candidates(ledger)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["sources"],
                             ["principal:svc-indexer"])
            ledger.verify()

    def test_registered_principal_excluded(self):
        from gov.discovery import scan_action_log
        sigs = scan_action_log(self._machine("svc-indexer"),
                               {"svc-indexer"})
        self.assertEqual(sigs, [])

    def test_human_burst_not_sighted(self):
        from gov.discovery import scan_action_log
        entries = [{"ts": self.BASE + i * 3, "principal": "human-op",
                    "tool": "read_file", "event": "paste"}
                   for i in range(40)]  # 40 reads in 2 min: span gate
        self.assertEqual(scan_action_log(entries, set()), [])

    def test_malformed_entries_skipped_not_trusted(self):
        from gov.discovery import scan_action_log
        entries = self._machine("svc-indexer")
        entries += [{"principal": "svc-indexer", "tool": "read_file"},
                    {"ts": "not-a-time", "principal": "svc-indexer",
                     "tool": "read_file"}]
        sigs = scan_action_log(entries, set())
        self.assertTrue(sigs)  # the 240 good entries still fingerprint
        self.assertTrue(all(s["source"] == "principal:svc-indexer"
                            for s in sigs))

    def test_shadow_candidate_id_never_collides_with_fs(self):
        from gov.discovery import scan_action_log
        sigs = scan_action_log(self._machine("svc-indexer"), set())
        for s in sigs:
            cid = candidate_id_for_sig(s)
            self.assertTrue(cid.startswith("shadow:"))
            self.assertFalse(cid.startswith("fs:"))

    def test_empty_log_no_signals(self):
        from gov.discovery import scan_action_log
        self.assertEqual(scan_action_log([], set()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
