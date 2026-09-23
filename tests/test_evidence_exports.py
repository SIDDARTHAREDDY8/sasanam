"""Tests for gov/evidence_exports (integrated STREAM-B).

EU AI Act Art. 73 draft incident-report generator + sealed export
manifest + hash-chained export receipt + ISO/IEC 42001 Annex A
provisional mapping.

$0 spend, synthetic/local only. Keys are fresh random per test via the
explicit GOV_LOG_KEY env backend (same production path tests use).
"""

import json
import os
import secrets
import tempfile
import unittest
from datetime import datetime, timedelta

from gov.evidence_exports import (  # noqa: E402
    ART3_49_LIMBS,
    IncidentReport,
    IncidentReportError,
    log_export_receipt,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_ISO_JSON = os.path.join(_ROOT, "docs", "iso42001-mapping.json")

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _provision_key():
    saved = {k: os.environ.get(k) for k in _KEY_VARS}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def _build_incident_log(path, signer=None):
    """Synthetic log: benign traffic, then a detector trip, infection
    escalation, and a quarantine mitigation."""
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer)
    log.append({"event": "tool_call", "agent_id": "agent-1",
                "run_id": "run-9", "tool": "read_file",
                "decision": "allow", "policy_id": "p-default"})
    log.append({"event": "approval_decision", "agent_id": "agent-1",
                "run_id": "run-9", "decision": "approved",
                "policy_id": "p-critical"})
    trip = log.append({"event": "detector_trip", "agent_id": "monitor",
                       "run_id": "run-9", "decision": "escalated",
                       "policy_id": "detection-breaker",
                       "reason": "velocity breaker: 42 tool calls in 60s "
                                 "from agent-7"})
    log.append({"event": "infection_suspected", "agent_id": "agent-7",
                "run_id": "run-9", "decision": "escalated",
                "policy_id": "infection-monitor",
                "reason": "near_duplicate_replication: payload replicated "
                          "across 3 distinct senders; auto-quarantining "
                          "origin lineage"})
    log.append({"event": "lineage_quarantine", "agent_id": "agent-7",
                "run_id": "run-9", "decision": "quarantined",
                "policy_id": "infection-monitor",
                "reason": "quarantined origin lineage of agent-7"})
    return log, trip


class TestIncidentReport(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")

    def tearDown(self):
        self.tmp.cleanup()
        self._restore()

    def test_report_renders_from_synthetic_incident(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build()
        # Anchor is the detector_trip at seq 3.
        anchor = rep["incident_anchor"]["value"]
        self.assertEqual(anchor["event"], "detector_trip")
        self.assertEqual(anchor["seq"], 3)
        # Timeline covers the incident window, every entry hash-cited.
        tl = rep["timeline"]["value"]
        self.assertEqual([t["seq"] for t in tl], [3, 4, 5])
        from gov.log import read_entries
        entries = {e["seq"]: e for e in read_entries(self.log_path)}
        for t in tl:
            self.assertEqual(t["hash"], entries[t["seq"]]["hash"])
            self.assertEqual(t["ts"], entries[t["seq"]]["ts"])
        # Description comes from the anchor's reason, traced to the log.
        desc = rep["incident_description"]
        self.assertIn("velocity breaker", desc["value"])
        self.assertEqual(desc["provenance"]["kind"], "log")
        self.assertEqual(desc["provenance"]["seq"], 3)
        # Mitigations observed: the quarantine entry.
        mit = rep["corrective_measures_taken"]["value"]
        self.assertEqual(len(mit), 1)
        self.assertEqual(mit[0]["event"], "lineage_quarantine")

    def test_operator_fields_are_null_never_invented(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build()
        for fname in ("affected_member_states", "individuals_affected",
                      "serious_incident_classification",
                      "corrective_measures_planned", "provider_contact",
                      "deployer_contact"):
            f = rep[fname]
            self.assertIsNone(f["value"], fname)
            self.assertEqual(f["provenance"]["kind"],
                             "operator_must_supply", fname)
        # Deadline selection is also operator-supplied.
        dl = rep["reporting_deadlines"]["value"]
        self.assertIsNone(dl["selection"])
        self.assertIn("a", ART3_49_LIMBS)

    def test_report_json_is_deterministic(self):
        _build_incident_log(self.log_path)
        gen = IncidentReport(self.log_path)
        r1 = gen.build()
        # Rebuild from scratch: report_id differs (uuid) but the canonical
        # form of the log-derived sections is stable.
        r2 = IncidentReport(self.log_path).build()
        for r in (r1, r2):
            r["report_id"]["value"] = "FIXED"
        self.assertEqual(IncidentReport.canonical(r1),
                         IncidentReport.canonical(r2))

    def test_tampered_log_refused(self):
        _build_incident_log(self.log_path)
        with open(self.log_path, "r+b") as f:
            data = f.read()
            # Flip a byte inside a JSON string value (keeps JSON valid,
            # breaks the HMAC chain).
            idx = data.find(b"velocity breaker")
            f.seek(idx)
            f.write(b"X")
        with self.assertRaises(IncidentReportError) as cm:
            IncidentReport(self.log_path).build()
        self.assertIn("does not verify", str(cm.exception))

    def test_no_anchor_raises(self):
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        log.append({"event": "tool_call", "agent_id": "agent-1",
                    "decision": "allow"})
        with self.assertRaises(IncidentReportError) as cm:
            IncidentReport(self.log_path).build()
        self.assertIn("no incident anchor", str(cm.exception))

    def test_wrong_anchor_seq_rejected(self):
        _build_incident_log(self.log_path)
        with self.assertRaises(IncidentReportError):
            IncidentReport(self.log_path).build(anchor_seq=1)  # tool_call
        with self.assertRaises(IncidentReportError):
            IncidentReport(self.log_path).build(anchor_seq=999)

    def test_explicit_anchor_seq(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build(anchor_seq=4)
        self.assertEqual(rep["incident_anchor"]["value"]["event"],
                         "infection_suspected")
        self.assertEqual([t["seq"] for t in rep["timeline"]["value"]],
                         [4, 5])

    def test_deadline_table(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build()
        dl = rep["reporting_deadlines"]["value"]
        aware = datetime.fromisoformat(dl["awareness_ts"])
        self.assertEqual(datetime.fromisoformat(dl["two_day"]) - aware,
                         timedelta(days=2))
        self.assertEqual(datetime.fromisoformat(dl["ten_day"]) - aware,
                         timedelta(days=10))
        self.assertEqual(datetime.fromisoformat(dl["fifteen_day"]) - aware,
                         timedelta(days=15))

    def test_markdown_marks_operator_fields(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build()
        md = IncidentReport.to_markdown(rep)
        self.assertIn("DRAFT", md)
        self.assertIn("Art. 73", md)
        self.assertIn("[OPERATOR]", md)
        self.assertIn("NOT FILED", md)

    def test_legal_basis_corrects_article(self):
        _build_incident_log(self.log_path)
        rep = IncidentReport(self.log_path).build()
        lb = rep["legal_basis"]
        self.assertIn("Article 73", lb["value"])
        self.assertNotIn("Article 55", lb["value"])
        self.assertIn("correction", lb["provenance"])


class TestExportIntegrity(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")

    def tearDown(self):
        self.tmp.cleanup()
        self._restore()

    def test_seal_manifest_verifies(self):
        _build_incident_log(self.log_path)
        gen = IncidentReport(self.log_path)
        rep = gen.build()
        manifest = gen.seal(rep)
        # Export digest recomputes.
        import hashlib
        self.assertEqual(
            manifest["export_sha256"],
            hashlib.sha256(gen.canonical(rep)).hexdigest())
        self.assertTrue(manifest["chain_verified"])
        # HMAC-only log: no inclusion bundles, and the manifest says so
        # explicitly instead of implying coverage.
        self.assertEqual(manifest["inclusion_coverage"]["with_bundle"], 0)
        from gov.log import read_entries
        entries = {e["seq"]: e for e in read_entries(self.log_path)}
        tl = {t["seq"]: t for t in rep["timeline"]["value"]}
        self.assertEqual(len(manifest["inclusion_bundles"]), len(tl))
        for item in manifest["inclusion_bundles"]:
            self.assertIsNone(item["bundle"])
            self.assertIn("signed checkpoint",
                          item["unavailable_reason"])
            seq = item["seq"]
            self.assertEqual(tl[seq]["hash"], entries[seq]["hash"])
        # No signer configured: stated explicitly, not implied.
        self.assertEqual(manifest["signing"]["scheme"], "none")

    def test_seal_with_signer_embeds_signature(self):
        from gov.log import ActionLog, verify_inclusion_bundle
        from gov.signing import Ed25519Signer
        seed = secrets.token_bytes(32)
        signer = Ed25519Signer(seed)
        _build_incident_log(self.log_path, signer=signer)
        gen = IncidentReport(self.log_path)
        rep = gen.build()
        manifest = gen.seal(rep, signer=signer)
        sig = manifest["signing"]
        self.assertEqual(sig["scheme"], "ed25519")
        self.assertEqual(sig["key_id"], signer.key_id)
        # The signature verifies over the export digest.
        from gov import ed25519 as _e
        self.assertTrue(_e.verify(
            signer.public_key,
            manifest["export_sha256"].encode("ascii"),
            bytes.fromhex(sig["signature_hex"])))
        # Inclusion bundles verify end-to-end against the trusted key.
        trusted = {signer.key_id: signer.public_key}
        for item in manifest["inclusion_bundles"]:
            ok, err = verify_inclusion_bundle(item["bundle"],
                                             trusted_keys=trusted)
            self.assertTrue(ok, "seq %d: %s" % (item["seq"], err))

    def test_seal_requires_build_first(self):
        _build_incident_log(self.log_path)
        with self.assertRaises(IncidentReportError):
            IncidentReport(self.log_path).seal({})

    def test_seal_after_tamper_fails_chain(self):
        _build_incident_log(self.log_path)
        gen = IncidentReport(self.log_path)
        rep = gen.build()
        with open(self.log_path, "r+b") as f:
            data = f.read()
            idx = data.find(b"agent-7")
            f.seek(idx)
            f.write(b"X")
        manifest = gen.seal(rep)
        self.assertFalse(manifest["chain_verified"])
        self.assertIsNotNone(manifest["chain_broken_seq"])

    def test_export_receipt_is_chained(self):
        """The sealed export gets a hash-chained receipt in the same log."""
        from gov.log import ActionLog, read_entries, verify_chain
        _build_incident_log(self.log_path)
        gen = IncidentReport(self.log_path)
        rep = gen.build()
        manifest = gen.seal(rep)
        log = ActionLog(self.log_path)  # re-open the same log
        receipt = log_export_receipt(manifest, log)
        self.assertEqual(receipt["event"], "evidence_export_sealed")
        self.assertEqual(receipt["export_sha256"],
                         manifest["export_sha256"])
        self.assertEqual(receipt["report_id"], manifest["report_id"])
        # Chain still verifies with the receipt appended.
        ok, broken, count = verify_chain(self.log_path)
        self.assertTrue(ok, broken)
        self.assertEqual(count, 6)
        entries = read_entries(self.log_path)
        self.assertEqual(entries[-1]["hash"], receipt["hash"])
        self.assertEqual(entries[-1]["export_sha256"],
                         manifest["export_sha256"])

    def test_export_receipt_commits_to_verified_seal(self):
        """Receipt records whether the log verified at seal time."""
        from gov.log import ActionLog, read_entries
        _build_incident_log(self.log_path)
        gen = IncidentReport(self.log_path)
        manifest = gen.seal(gen.build())
        receipt = log_export_receipt(manifest, ActionLog(self.log_path))
        self.assertTrue(receipt["chain_verified_at_seal"])
        self.assertTrue(
            any(e.get("event") == "evidence_export_sealed"
                for e in read_entries(self.log_path)))


class TestIsoMapping(unittest.TestCase):
    def test_mapping_loads_and_schema_holds(self):
        with open(_ISO_JSON) as f:
            m = json.load(f)
        self.assertTrue(m["meta"]["provisional"])
        self.assertIn("paywalled", m["meta"]["caveats"][0])
        self.assertTrue(m["unaccounted_controls"])
        seen = set()
        for c in m["controls"]:
            cid = c.get("id") or "/".join(c.get("id_candidates", []))
            self.assertNotIn(cid, seen, "duplicate control %s" % cid)
            seen.add(cid)
            self.assertIn(c["status"],
                          ("mapped", "partial", "organizational", "gap"))
            self.assertIn("note", c)
            if c["status"] in ("mapped", "partial"):
                self.assertTrue(c["product_mechanisms"],
                                "%s claims coverage with no mechanism" % cid)
        # Status summary is consistent with the control list.
        counts = {}
        for c in m["controls"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        total = sum(len(v) for v in m["status_summary"].values())
        self.assertEqual(total, sum(counts.values()))

    def test_cited_modules_and_tests_exist(self):
        with open(_ISO_JSON) as f:
            m = json.load(f)
        for c in m["controls"]:
            cid = c.get("id") or "/".join(c.get("id_candidates", []))
            for mech in c["product_mechanisms"]:
                mod = mech.split(":")[0].strip().rstrip("/")
                self.assertTrue(
                    os.path.exists(os.path.join(_ROOT, mod)),
                    "%s cites missing module %s" % (cid, mod))
            for t in c["tests"]:
                self.assertTrue(
                    os.path.exists(os.path.join(_ROOT, t)),
                    "%s cites missing test %s" % (cid, t))

    def test_gaps_listed_honestly(self):
        with open(_ISO_JSON) as f:
            m = json.load(f)
        gaps = m["status_summary"]["gap"]
        # The honest gaps the direction check named must appear.
        for expected in ("A.4.2", "A.5.2", "A.7.2"):
            self.assertIn(expected, gaps)
        for c in m["controls"]:
            if c["status"] == "gap":
                self.assertFalse(c["product_mechanisms"])
                self.assertFalse(c["tests"])


if __name__ == "__main__":
    unittest.main()
