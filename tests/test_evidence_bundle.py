"""Red-first tests for gov/evidence_bundle.py (W3 evidence bundle build).

Public seams only: EvidenceBundle.build() output shape + honesty-contract
properties, seal() refusal on unverifiable chains, assembler
byte-determinism, and the tools/evidence-verify <-> gov/evidence_verify.py
drift guard. Deterministic, synthetic, $0.
"""

import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.keyfixture import provision_test_key, scrub_key_env


def _signer():
    from gov.signing import Ed25519Signer
    return Ed25519Signer(secrets.token_bytes(32))


def _append(log, event, **kw):
    rec = {"event": event}
    rec.update(kw)
    return log.append(rec)


def _build_log(path, signer=None, roster=None):
    """Synthetic governed-deployment log exercising every payload section."""
    from gov.log import ActionLog
    kw = {"signer": signer}
    if roster is not None:
        kw["roster"] = roster
        kw["deployment_mode"] = "staging"
    log = ActionLog(path, **kw)
    _append(log, "policy_loaded", run_id="r1", agent_id="system",
            decision="policy_loaded", policy_id="policy-pin",
            policy_path="/etc/gov/policy.yaml", policy_hash="ab" * 32,
            pinned=True,
            reason="Policy loaded for run r1")
    _append(log, "tool_call", tool="read_file", agent_id="a1", run_id="r1",
            decision="allow", policy_id="p-default")
    _append(log, "tool_call", tool="send_email", agent_id="a1", run_id="r1",
            decision="queued_pending", policy_id="p-critical",
            approval_id="A-1")
    _append(log, "approval_decision", agent_id="human", run_id="r1",
            decision="approved", approval_id="A-1", policy_id="p-critical")
    _append(log, "approval_break_glass", agent_id="human", run_id="r1",
            decision="break_glass", ticket_id="BG-7")
    _append(log, "detector_trip", agent_id="monitor", run_id="r1",
            decision="escalated", signal="velocity_breaker",
            reason="velocity breaker tripped")
    _append(log, "detector_trip", agent_id="monitor", run_id="r1",
            decision="escalated", signal="self_planted_citation",
            session_id="sess-1",
            reason="self-planted citation detected")
    _append(log, "eval_integrity", signal="citation_check_completed",
            session_id="sess-1", session_open="2026-09-25T00:00:00+00:00",
            policy_version="eval-integrity-s4", n_citations=3,
            n_self_planted=0,
            verdict_counts={"INDEPENDENT": 2, "UNKNOWN": 1},
            accepted=True)
    _append(log, "safeguard_benchmark_sealed", report_id="SAR-deadbeef",
            export_sha256="00" * 32, schema_version="safeguard-assessment/1.0",
            chain_verified_at_seal=True)
    return log


class _EBTestBase(unittest.TestCase):
    def setUp(self):
        # Hermetic key provisioning via the shared tests/keyfixture.py
        # (explicit production env-backend path, fresh random key).
        self._restore = scrub_key_env()
        provision_test_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")

    def tearDown(self):
        self.tmp.cleanup()
        self._restore()

    def _bundle(self, signer=None, **kw):
        from gov.evidence_bundle import EvidenceBundle
        return EvidenceBundle(self.log_path, **kw)


class TestEvidenceBundleBuild(_EBTestBase):
    def test_no_policy_loaded_yields_operator_must_supply(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="x", decision="allow")
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        pol = payload["policy"]
        self.assertIsNone(pol["policy_version"]["value"])
        self.assertTrue(pol["policy_version"]["operator_must_supply"])

    def test_broken_chain_refuses(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write('{"seq": 999, "hash": "forged"}\n')
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path).build()

    def test_empty_log_refuses(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        ActionLog(self.log_path)  # creates, no entries
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path).build()

    def test_window_must_end_at_tip(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path,
                           window={"from_seq": 1, "to_seq": 2}).build()

    def test_decisions_section_counts_with_seq_hash_refs(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        payload = EvidenceBundle(self.log_path).build()
        by_event = payload["decisions"]["by_event"]
        self.assertEqual(by_event["tool_call"], 2)
        self.assertEqual(by_event["approval_decision"], 1)
        for ref in payload["decisions"]["refs"]:
            self.assertIn("seq", ref)
            self.assertIn("hash", ref)
            self.assertEqual(len(ref["hash"]), 64)

    def test_approvals_section_vocabulary(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        payload = EvidenceBundle(self.log_path).build()
        appr = payload["approvals"]
        self.assertEqual(len(appr["approval_decision"]), 1)
        self.assertEqual(len(appr["approval_break_glass"]), 1)
        self.assertEqual(appr["approval_decision"][0]["seq"], 4)

    def test_citations_section_and_unchecked_sessions(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        payload = EvidenceBundle(self.log_path).build()
        cit = payload["citations"]
        self.assertEqual(len(cit["citation_checks"]), 1)
        chk = cit["citation_checks"][0]
        self.assertEqual(chk["session_id"], "sess-1")
        self.assertTrue(chk["accepted"])
        self.assertEqual(len(cit["self_planted_violations"]), 1)
        # sess-2 was never checked: listed as unchecked, not as clean
        payload2 = EvidenceBundle(
            self.log_path, eval_session_ids=["sess-1", "sess-2"]).build()
        self.assertIn("sess-2",
                      payload2["citations"]["sessions_without_checkpoints"])

    def test_kms_attestation_carries_no_key_material(self):
        from gov.evidence_bundle import EvidenceBundle
        from gov import keyprovider as _kp
        _build_log(self.log_path)
        kp = _kp.EnvKeyProvider()
        payload = EvidenceBundle(self.log_path, key_provider=kp).build()
        att = payload["kms_attestation"]
        self.assertEqual(att["provider"], "env")
        self.assertIn("key_id", att)
        blob = json.dumps(payload).encode()
        raw_hex = os.environ["GOV_LOG_KEY"].encode()
        self.assertNotIn(raw_hex, blob)
        self.assertNotIn(os.environ["GOV_LOG_KEY"].encode(), blob)

    def test_kms_attestation_absent_is_labeled(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        payload = EvidenceBundle(self.log_path).build()
        self.assertIsNone(payload["kms_attestation"])
        self.assertTrue(
            payload["sections_meta"]["kms_attestation"]
            ["operator_must_supply"])

    def test_retention_manifest_absent_is_labeled(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        payload = EvidenceBundle(self.log_path).build()
        self.assertIsNone(payload["retention_manifest"]["value"])
        self.assertTrue(
            payload["retention_manifest"]["operator_must_supply"])

    def test_retention_manifest_schema_checked(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        good = {"retention_policy": "90d", "window_coverage": "full",
                "archive_locations": ["s3://x"]}
        payload = EvidenceBundle(
            self.log_path, retention_manifest=good).build()
        self.assertEqual(payload["retention_manifest"]["value"], good)
        bad = {"retention_policy": "90d"}
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path,
                           retention_manifest=bad).build()

    def test_benchmark_unsealed_is_labeled(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="x", decision="allow")
        payload = EvidenceBundle(self.log_path).build()
        self.assertEqual(payload["benchmark"]["seal_status"], "unsealed")

    def test_benchmark_sealed_with_matching_sar_manifest(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        sar = {"schema_version": "safeguard-assessment/1.0",
               "report_id": "SAR-deadbeef",
               "aggregate_verdict": "SUFFICIENT",
               "per_category": {}, "thresholds": {},
               "taxonomy": "provisional-v1"}
        payload = EvidenceBundle(self.log_path, sar_manifest=sar).build()
        self.assertEqual(payload["benchmark"]["seal_status"], "sealed")
        self.assertEqual(payload["benchmark"]["aggregate_verdict"]["value"],
                         "SUFFICIENT")

    def test_bundle_id_deterministic(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        # Same inputs => same bundle id (fixed exported_at; wall-clock
        # time is not part of the deterministic identity).
        kw = {"exported_at": "2026-09-26T00:00:00+00:00"}
        p1 = EvidenceBundle(self.log_path, **kw).build()
        p2 = EvidenceBundle(self.log_path, **kw).build()
        self.assertEqual(p1["bundle_meta"]["bundle_id"],
                         p2["bundle_meta"]["bundle_id"])
        self.assertTrue(
            p1["bundle_meta"]["bundle_id"].startswith("EVB-"))


class TestEvidenceBundleSeal(_EBTestBase):
    def _sealed(self, signer):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path, signer=signer)
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        manifest = eb.seal(payload, signer=signer)
        return eb, payload, manifest

    def test_seal_requires_signer_no_none_option(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        with self.assertRaises(EvidenceBundleError):
            eb.seal(payload, signer=None)

    def test_manifest_binds_payload_digest(self):
        s = _signer()
        eb, payload, manifest = self._sealed(s)
        expect = hashlib.sha256(eb.canonical(payload)).hexdigest()
        self.assertEqual(manifest["export_sha256"], expect)
        self.assertTrue(manifest["chain_verified"])
        self.assertIsNone(manifest["chain_broken_seq"])

    def test_signature_verifies_with_envelope_key(self):
        from gov import ed25519 as _e
        s = _signer()
        eb, payload, manifest = self._sealed(s)
        sig = manifest["signing"]
        self.assertEqual(sig["scheme"], "ed25519")
        self.assertEqual(sig["domain"], "evidence-bundle/v2")
        self.assertEqual(sig["key_id"], s.key_id)
        body = eb.signed_body(manifest)
        self.assertTrue(_e.verify(s.public_key, body,
                                 bytes.fromhex(sig["signature_hex"])))

    def test_seal_refuses_tampered_chain(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        s = _signer()
        _build_log(self.log_path, signer=s)
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        # tamper after build: flip a byte in the stored log
        with open(self.log_path, "r+b") as f:
            data = bytearray(f.read())
        idx = data.find(b"read_file")
        data[idx:idx + 4] = b"XXXX"
        with open(self.log_path, "wb") as f:
            f.write(bytes(data))
        with self.assertRaises(EvidenceBundleError):
            eb.seal(payload, signer=s)

    def test_inclusion_coverage_full_with_signed_checkpoints(self):
        s = _signer()
        eb, payload, manifest = self._sealed(s)
        cov = manifest["inclusion_coverage"]
        self.assertEqual(cov["with_bundle"], cov["entries"])
        self.assertGreater(cov["entries"], 0)
        for b in manifest["inclusion_bundles"]:
            self.assertIsNone(b["unavailable_reason"])
            self.assertIsNotNone(b["bundle"])

    def test_hmac_only_log_names_unavailable_reasons(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)  # no signer: HMAC-only
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        s = _signer()
        manifest = eb.seal(payload, signer=s)
        cov = manifest["inclusion_coverage"]
        self.assertEqual(cov["with_bundle"], 0)
        for b in manifest["inclusion_bundles"]:
            self.assertIsNotNone(b["unavailable_reason"])
            self.assertIsNone(b["bundle"])

    def test_receipt_chains_onto_window_tip(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        s = _signer()
        _build_log(self.log_path, signer=s)
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        manifest = eb.seal(payload, signer=s)
        entry = log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=s), signer=s)
        self.assertEqual(entry["event"], "evidence_bundle_sealed")
        self.assertEqual(entry["prev_hash"],
                         manifest["window"]["tip_hash"])
        self.assertEqual(entry["export_sha256"],
                         manifest["export_sha256"])


class TestEvidenceBundleAssemble(_EBTestBase):
    def _assembled(self, name, signer=None, exported_at=None):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        from gov.signing import Ed25519Signer
        s = signer or Ed25519Signer(bytes.fromhex("11" * 32))
        _build_log(self.log_path, signer=s)
        eb = EvidenceBundle(self.log_path, exported_at=exported_at)
        payload = eb.build()
        manifest = eb.seal(payload, signer=s)
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=s), signer=s)
        op = {"key_id": s.key_id,
              "public_key_hex": s.public_key.hex()}
        out = os.path.join(self.tmp.name, name)
        info = eb.assemble(payload, manifest, operator_key=op,
                           checkpoint_keys=[dict(op)], out_dir=out)
        return out, info, s

    def test_layout_has_all_files(self):
        out, info, _s = self._assembled("b1")
        expected = {"VERSION", "evidence.json", "manifest.json",
                    "log_slice.jsonl", "checkpoints.jsonl", "receipt.json",
                    "keys/operator_ed25519.json",
                    "keys/checkpoint_keys.json", "VERIFY.txt",
                    "BUNDLE_DIGEST.sha256"}
        found = set()
        for root, _d, names in os.walk(out):
            for n in names:
                found.add(os.path.relpath(os.path.join(root, n), out))
        self.assertEqual(found, expected)

    def test_deterministic_byte_identical(self):
        from datetime import datetime, timezone
        from gov.signing import Ed25519Signer
        import gov.log as _logmod
        fixed = Ed25519Signer(bytes.fromhex("22" * 32))
        ts = "2026-09-26T00:00:00+00:00"
        real_utcnow = _logmod._utcnow
        _logmod._utcnow = lambda: datetime(2026, 9, 26, tzinfo=timezone.utc)
        try:
            out1, info1, _ = self._assembled("d1", signer=fixed,
                                             exported_at=ts)
            # rebuild from scratch: same inputs -> same bytes
            import shutil
            shutil.rmtree(self.tmp.name)
            self.tmp = tempfile.TemporaryDirectory()
            self.log_path = os.path.join(self.tmp.name, "audit.log")
            out2, info2, _ = self._assembled("d2", signer=fixed,
                                             exported_at=ts)
        finally:
            _logmod._utcnow = real_utcnow
        self.assertEqual(info1["bundle_digest"], info2["bundle_digest"])

    def test_assembler_refuses_wrong_operator_key(self):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, EvidenceBundleError,
            log_evidence_bundle_receipt)
        s = _signer()
        other = _signer()
        _build_log(self.log_path, signer=s)
        eb = EvidenceBundle(self.log_path)
        payload = eb.build()
        manifest = eb.seal(payload, signer=s)
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=s), signer=s)
        wrong = {"key_id": other.key_id,
                 "public_key_hex": other.public_key.hex()}
        with self.assertRaises(EvidenceBundleError):
            eb.assemble(payload, manifest, operator_key=wrong,
                        checkpoint_keys=[wrong],
                        out_dir=os.path.join(self.tmp.name, "bad"))

    def test_threshold_checkpoint_bundle_verifies(self):
        # A5 k-of-n: build a bundle from a log with threshold checkpoints,
        # ship the roster, and verify the k-of-n signatures pass V8.
        from gov.signing import ThresholdSigner, make_roster
        from gov.evidence_bundle import EvidenceBundle
        s1, s2, s3 = _signer(), _signer(), _signer()
        root = _signer()
        roster = make_roster([s1, s2, s3], 2, root)
        tsigner = ThresholdSigner([s1, s2, s3], 2)
        _build_log(self.log_path, signer=tsigner, roster=roster)
        eb = EvidenceBundle(self.log_path, roster=roster)
        payload = eb.build()
        manifest = eb.seal(payload, signer=s1)
        from gov.log import ActionLog
        from gov.evidence_bundle import log_evidence_bundle_receipt
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=tsigner,
                                roster=roster,
                                deployment_mode="staging"),
            signer=s1)
        op = {"key_id": s1.key_id,
              "public_key_hex": s1.public_key.hex()}
        out_dir = os.path.join(self.tmp.name, "threshold")
        info = eb.assemble(payload, manifest, operator_key=op,
                           checkpoint_keys=[
                               {"key_id": s.key_id,
                                "public_key_hex": s.public_key.hex()}
                               for s in (s1, s2, s3)],
                           out_dir=out_dir)
        # The roster must be shipped.
        rpath = os.path.join(out_dir, "keys", "checkpoint_roster.json")
        self.assertTrue(os.path.isfile(rpath))
        # Verify with the standalone verifier.
        import subprocess, sys
        repo = os.path.join(os.path.dirname(__file__), "..")
        script = os.path.join(repo, "tools", "evidence-verify")
        r = subprocess.run(
            [sys.executable, script, out_dir, "--format", "json"],
            capture_output=True, text=True)
        doc = json.loads(r.stdout)
        v8 = [c for c in doc["checks"] if c["id"] == "V8"][0]
        # V8 must pass: the k-of-n threshold signatures verify against
        # the shipped roster. (V11/V12 may fail on the synthetic log's
        # policy/receipt details; the threshold mechanism is what this
        # test exercises.)
        self.assertTrue(v8["ok"], v8["detail"])
        self.assertIn("threshold", v8["detail"].lower())

    def test_threshold_seal_refuses_without_roster(self):
        # Fail-closed: threshold heads without a roster cannot be sealed.
        from gov.signing import ThresholdSigner, make_roster
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        s1, s2, s3 = _signer(), _signer(), _signer()
        root = _signer()
        roster = make_roster([s1, s2, s3], 2, root)  # not passed to bundle
        tsigner = ThresholdSigner([s1, s2, s3], 2)
        _build_log(self.log_path, signer=tsigner, roster=roster)
        eb = EvidenceBundle(self.log_path)  # no roster
        payload = eb.build()
        with self.assertRaises(EvidenceBundleError):
            eb.seal(payload, signer=s1)

    def test_verifier_copy_drift_guard(self):
        repo = os.path.join(os.path.dirname(__file__), "..")
        a = os.path.join(repo, "tools", "evidence-verify")
        b = os.path.join(repo, "gov", "evidence_verify.py")
        with open(a, "rb") as f:
            va = f.read()
        with open(b, "rb") as f:
            vb = f.read()
        # both start with the same marker line identifying the source
        self.assertEqual(va, vb)


# ---------------------------------------------------------------------------
# H5 (wave-117): unknown-agent discovery snapshot in the evidence bundle.
# ---------------------------------------------------------------------------

class TestDiscoverySnapshot(_EBTestBase):
    def _ledger_path_with(self, kinds_by_candidate):
        """Build a DiscoveryLedger file with one candidate per entry.

        kinds_by_candidate: list of signal-kind lists; each inner list
        becomes one candidate (distinct source -> distinct candidate).
        Returns the ledger path.
        """
        from gov.discovery import DiscoveryLedger
        path = os.path.join(self.tmp.name, "discovery.jsonl")
        ledger = DiscoveryLedger(path)
        for i, kinds in enumerate(kinds_by_candidate):
            sigs = [{"kind": k, "source": "scanner-%d" % i,
                     "strength": 1.0,
                     "detail": {"path": "/proj/agent-%d" % i}}
                    for k in kinds]
            self.assertTrue(ledger.note_signals(sigs),
                            "signals became candidates")
        if not kinds_by_candidate:
            # A wired discovery integration owns its ledger path: the
            # file exists even when nothing was ever sighted (a missing
            # file is a misconfiguration, which the builder refuses).
            # Touch the empty ledger to model the legitimate zero.
            open(path, "a", encoding="utf-8").close()
        return path

    def _build_test_log(self):
        _build_log(self.log_path)

    def test_discovery_snapshot_present_with_candidates(self):
        self._build_test_log()
        lp = self._ledger_path_with([["harness_config"],
                                     ["mcp_server", "credential"]])
        b = self._bundle(discovery_ledger_path=lp)
        payload = b.build()
        snap = payload["discovery"]
        self.assertIsNotNone(snap)
        self.assertEqual(snap["inventoried_count"], 2)
        self.assertEqual(snap["unregistered_candidate_count"], 2)
        self.assertEqual(sorted(snap["candidate_kinds"]),
                         ["credential", "harness_config", "mcp_server"])
        # Privacy: counts and kinds only -- no candidate ids, sources,
        # details, or PII.
        blob = json.dumps(snap)
        self.assertNotIn("scanner-", blob)
        self.assertNotIn("agent-", blob)

    def test_discovery_snapshot_zero_candidates(self):
        self._build_test_log()
        lp = self._ledger_path_with([])
        b = self._bundle(discovery_ledger_path=lp)
        snap = b.build()["discovery"]
        self.assertEqual(snap["inventoried_count"], 0)
        self.assertEqual(snap["unregistered_candidate_count"], 0)
        self.assertEqual(snap["candidate_kinds"], [])

    def test_discovery_absent_without_ledger_input(self):
        self._build_test_log()
        payload = self._bundle().build()
        self.assertIsNone(payload.get("discovery"))

    def test_discovery_corrupt_ledger_fails_closed(self):
        self._build_test_log()
        lp = self._ledger_path_with([["harness_config"]])
        with open(lp, "a", encoding="utf-8") as f:
            f.write('{"kind": "sighting", "tampered": true}\n')
        from gov.evidence_bundle import EvidenceBundleError
        with self.assertRaises(EvidenceBundleError):
            self._bundle(discovery_ledger_path=lp).build()

    def test_discovery_registered_candidate_not_unregistered(self):
        from gov.discovery import DiscoveryLedger
        self._build_test_log()
        lp = self._ledger_path_with([["harness_config"], ["mcp_server"]])
        ledger = DiscoveryLedger(lp)
        cands = ledger.candidates(status="candidate")
        ledger.mark_registered(cands[0]["candidate_id"], "operator-1")
        snap = self._bundle(discovery_ledger_path=lp).build()["discovery"]
        self.assertEqual(snap["inventoried_count"], 2)
        self.assertEqual(snap["unregistered_candidate_count"], 1)
        self.assertEqual(snap["candidate_kinds"], ["mcp_server"])

    def test_discovery_missing_path_fails_closed(self):
        # An explicitly supplied ledger path that does not exist is a
        # misconfiguration, not a zero count: DiscoveryLedger over a
        # missing path silently represents "no candidates".
        from gov.evidence_bundle import EvidenceBundleError
        self._build_test_log()
        missing = os.path.join(self.tmp.name, "no-such-ledger.jsonl")
        with self.assertRaises(EvidenceBundleError) as cm:
            self._bundle(discovery_ledger_path=missing).build()
        self.assertIn("does not exist", str(cm.exception))

    def test_discovery_snapshot_has_exactly_acceptance_fields(self):
        # H5 acceptance names exactly three fields; no timestamp,
        # chain flag, or provenance wrapper at the signed boundary.
        self._build_test_log()
        lp = self._ledger_path_with([["harness_config"]])
        snap = self._bundle(discovery_ledger_path=lp).build()["discovery"]
        self.assertEqual(sorted(snap.keys()),
                         ["candidate_kinds", "inventoried_count",
                          "unregistered_candidate_count"])


class TestDiscoveryVerifyRendering(_EBTestBase):
    """H5: the verifier renders the discovery snapshot loudly when
    nonzero, quietly for the zero control."""

    def _assembled_with_discovery(self, name, kinds_by_candidate,
                                  provide_ledger=True):
        from gov.log import ActionLog
        from gov.evidence_bundle import (
            EvidenceBundle, log_evidence_bundle_receipt)
        from gov.signing import Ed25519Signer
        s = Ed25519Signer(bytes.fromhex("33" * 32))
        _build_log(self.log_path, signer=s)
        kw = {}
        if provide_ledger:
            kw["discovery_ledger_path"] = self._ledger_path_with(
                kinds_by_candidate)
        eb = EvidenceBundle(self.log_path, **kw)
        payload = eb.build()
        manifest = eb.seal(payload, signer=s)
        log_evidence_bundle_receipt(
            manifest, ActionLog(self.log_path, signer=s), signer=s)
        op = {"key_id": s.key_id, "public_key_hex": s.public_key.hex()}
        out = os.path.join(self.tmp.name, name)
        eb.assemble(payload, manifest, operator_key=op,
                    checkpoint_keys=[dict(op)], out_dir=out)
        return out

    def _ledger_path_with(self, kinds_by_candidate):
        from gov.discovery import DiscoveryLedger
        path = os.path.join(self.tmp.name, "discovery.jsonl")
        ledger = DiscoveryLedger(path)
        for i, kinds in enumerate(kinds_by_candidate):
            sigs = [{"kind": k, "source": "scanner-%d" % i,
                     "strength": 1.0,
                     "detail": {"path": "/proj/agent-%d" % i}}
                    for k in kinds]
            ledger.note_signals(sigs)
        if not kinds_by_candidate:
            # A wired discovery integration owns its ledger path: the
            # file exists even when nothing was ever sighted (a missing
            # file is a misconfiguration, which the builder refuses).
            open(path, "a", encoding="utf-8").close()
        return path

    def test_verify_summary_carries_discovery(self):
        from gov.evidence_verify import verify_bundle
        out = self._assembled_with_discovery(
            "d1", [["harness_config"], ["mcp_server"]])
        code, checks, summary = verify_bundle(out)
        disc = summary["discovery"]
        self.assertIsNotNone(disc)
        self.assertEqual(disc["unregistered_candidate_count"], 2)
        self.assertEqual(disc["inventoried_count"], 2)
        self.assertEqual(sorted(disc["candidate_kinds"]),
                         ["harness_config", "mcp_server"])

    def test_verify_text_loud_when_nonzero(self):
        import io
        from contextlib import redirect_stdout
        from gov.evidence_verify import main
        out = self._assembled_with_discovery("d2", [["harness_config"]])
        buf = io.StringIO()
        with redirect_stdout(buf):
            main([out])
        text = buf.getvalue()
        self.assertIn("1 unregistered candidates at export time", text)
        self.assertIn("UNREGISTERED AGENTS PRESENT", text)

    def test_verify_text_quiet_when_zero(self):
        import io
        from contextlib import redirect_stdout
        from gov.evidence_verify import main
        out = self._assembled_with_discovery("d3", [])
        buf = io.StringIO()
        with redirect_stdout(buf):
            main([out])
        text = buf.getvalue()
        self.assertIn("no unregistered candidates at export time", text)
        self.assertNotIn("UNREGISTERED AGENTS PRESENT", text)

    def test_verify_summary_none_without_ledger(self):
        from gov.evidence_verify import verify_bundle
        out = self._assembled_with_discovery(
            "d4", [], provide_ledger=False)
        code, checks, summary = verify_bundle(out)
        self.assertIsNone(summary["discovery"])


# ---------------------------------------------------------------------------
# H6 (wave-117): seal-time KMS/retention claims bound against the live
# deployment config.
# ---------------------------------------------------------------------------

class TestLiveConfigBinding(_EBTestBase):
    def _kp(self):
        from gov import keyprovider as _kp
        return _kp.EnvKeyProvider()

    def _live_kms(self, kp, **over):
        import hashlib as _h
        key_bytes, epoch = kp.resolve()
        cfg = {"provider": kp.provider_name,
               "key_id": _h.sha256(bytes(key_bytes)).hexdigest()[:16],
               "epoch": epoch}
        cfg.update(over)
        return cfg

    def _manifest(self):
        return {"retention_policy": "90d", "window_coverage": "full",
                "archive_locations": ["s3://vault/evidence"]}

    def test_matching_live_config_builds_and_binds(self):
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        kp = self._kp()
        live = {"kms": self._live_kms(kp),
                "retention": dict(self._manifest())}
        payload = EvidenceBundle(
            self.log_path, key_provider=kp,
            retention_manifest=self._manifest(),
            live_config=live).build()
        att = payload["kms_attestation"]
        self.assertEqual(att["live_config_binding"]["result"], "match")
        ret = payload["retention_manifest"]
        self.assertEqual(ret["live_config_binding"]["result"], "match")

    def test_mismatched_key_id_refuses(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        kp = self._kp()
        live = {"kms": self._live_kms(kp, key_id="0" * 16)}
        with self.assertRaises(EvidenceBundleError) as cm:
            EvidenceBundle(self.log_path, key_provider=kp,
                           live_config=live).build()
        self.assertIn("key_id", str(cm.exception))

    def test_mismatched_epoch_refuses(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        kp = self._kp()
        live = {"kms": self._live_kms(kp, epoch="epoch-tampered")}
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path, key_provider=kp,
                           live_config=live).build()

    def test_mismatched_provider_refuses(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        kp = self._kp()
        live = {"kms": self._live_kms(kp, provider="vault")}
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path, key_provider=kp,
                           live_config=live).build()

    def test_tampered_retention_manifest_refuses(self):
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
        _build_log(self.log_path)
        kp = self._kp()
        tampered = dict(self._manifest())
        tampered["retention_policy"] = "7d"
        live = {"kms": self._live_kms(kp), "retention": self._manifest()}
        with self.assertRaises(EvidenceBundleError):
            EvidenceBundle(self.log_path, key_provider=kp,
                           retention_manifest=tampered,
                           live_config=live).build()

    def test_no_live_config_unchanged_behavior(self):
        # Without live_config the builder behaves exactly as before:
        # attestation derived, manifest asserted, no binding claim.
        from gov.evidence_bundle import EvidenceBundle
        _build_log(self.log_path)
        kp = self._kp()
        payload = EvidenceBundle(
            self.log_path, key_provider=kp,
            retention_manifest=self._manifest()).build()
        self.assertNotIn("live_config_binding",
                         payload["kms_attestation"])
        self.assertNotIn("live_config_binding",
                         payload["retention_manifest"])


if __name__ == "__main__":
    unittest.main()
