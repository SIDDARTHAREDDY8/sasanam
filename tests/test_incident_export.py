"""Unit tests for gov/incident_export.py.

Contract under test: export_incident produces a regulator-shaped
artifact (Art. 73 template / Art. 50 provenance) with a causally curated
timeline, a completeness claim, and an anchor; verify_incident detects
omitted events, forged attestations, nonexistent runs, and reordered
timelines.
"""
import hashlib
import json
import os
import shutil
import tempfile
import unittest

from gov.log import ActionLog
from gov.signing import Ed25519Signer
from gov.anchor_adapter import FakeLogAdapter
from gov import incident_export as ie
from tests.keyfixture import provision_test_key


def _make_log(tmp, run_id="R1", extra=None, signer=None):
    signer = signer or Ed25519Signer(hashlib.sha256(b"unittest").digest())
    logp = os.path.join(tmp, "audit.jsonl")
    log = ActionLog(logp, signer=signer)
    log.append({"event": "policy_loaded", "policy_version": "v41",
                "policy_digest": "abc123"})
    log.append({"event": "identity_minted", "agent_id": "a1",
                "role": "sender", "principal": "acme", "run_id": run_id})
    log.append({"event": "agent_spawn", "agent_id": "a1", "run_id": run_id})
    log.append({"event": "approval_decision", "approval_id": "ap1",
                "agent_id": "a1", "run_id": run_id, "decision": "allow",
                "tool": "send_email"})
    log.append({"event": "tool_call", "agent_id": "a1", "run_id": run_id,
                "tool": "send_email", "decision": "allow",
                "approval_id": "ap1",
                "args": {"to": "x@y.z", "body": "top secret"}})
    log.append({"event": "canary_trip", "agent_id": "a1", "run_id": run_id,
                "canary_id": "c9", "tool": "send_email"})
    log.append({"event": "memory_quarantine", "agent_id": "a1",
                "run_id": run_id, "reason": "canary"})
    log.append({"event": "decision_refused", "agent_id": "a1",
                "run_id": run_id, "tool": "send_email"})
    for ev in (extra or []):
        log.append(ev)
    return logp, signer


def _export(tmp, run_id="R1", **kw):
    provision_test_key()
    logp, signer = _make_log(tmp, run_id=run_id)
    adapter = FakeLogAdapter(hashlib.sha256(b"anchor").digest())
    out = os.path.join(tmp, "incident")
    kw.setdefault("entry_signer_pubkey", signer.public_key)
    ie.export_incident(logp, out, adapter, run_id=run_id, **kw)
    return out, logp, signer, adapter


class ExportHappyPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="inctest_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_verifies(self):
        out, logp, signer, adapter = _export(self.tmp)
        ok, findings = ie.verify_incident(
            out, logp, entry_signer_pubkey=signer.public_key,
            anchor_pubkey=adapter.public_key)
        self.assertTrue(ok, [f for f in findings if not f["ok"]])

    def test_class_detected_and_report_fields(self):
        out, _logp, _s, _a = _export(self.tmp)
        inc = json.load(open(os.path.join(out, "incident.json")))
        self.assertEqual(inc["incident_format"], "incident-report/1.0")
        self.assertEqual(inc["incident"]["class"], "exfiltration_attempt")
        self.assertEqual(inc["incident"]["run_id"], "R1")
        self.assertEqual(inc["system"]["policy_version_at_incident"],
                         "v41")
        roles = [c["role"] for c in inc["causal_chain"]]
        self.assertIn("trigger", roles)
        self.assertIn("containment", roles)
        trig = [c for c in inc["causal_chain"] if c["role"] == "trigger"]
        self.assertEqual(trig[0]["event"], "canary_trip")
        # Art. 73-shaped sections exist.
        for section in ("reporter", "system", "incident", "harm",
                        "causation", "containment", "followup"):
            self.assertIn(section, inc, section)
        self.assertIn("50", inc["regulatory_basis"]["articles"])
        self.assertIn("73", inc["regulatory_basis"]["articles"])
        # Agent identity + principal (Art. 50(1) "on whose behalf").
        self.assertEqual(inc["agent"]["agent_id"], "a1")
        self.assertEqual(inc["agent"]["role"], "sender")
        self.assertEqual(inc["agent"]["principal"], "acme")
        # Human approvals roll-up.
        self.assertEqual(len(inc["approvals"]), 1)
        self.assertEqual(inc["approvals"][0]["approval_id"], "ap1")
        self.assertEqual(inc["approvals"][0]["decision"], "allow")

    def test_raw_args_never_ship(self):
        out, _logp, _s, _a = _export(self.tmp)
        raw = open(os.path.join(out, "timeline.jsonl")).read()
        self.assertNotIn("top secret", raw)
        self.assertNotIn('"args"', raw)
        inc = json.load(open(os.path.join(out, "incident.json")))
        red = inc["evidence"]["redaction_report"]
        self.assertGreater(red["entries_redacted"], 0)

    def test_nonexistent_run_refused(self):
        provision_test_key()
        logp, _s = _make_log(self.tmp)
        adapter = FakeLogAdapter(hashlib.sha256(b"x").digest())
        with self.assertRaises(ie.IncidentExportError):
            ie.export_incident(logp, os.path.join(self.tmp, "no"),
                               adapter, run_id="GHOST")

    def test_no_trigger_refused(self):
        provision_test_key()
        logp = os.path.join(self.tmp, "quiet.jsonl")
        log = ActionLog(logp, signer=Ed25519Signer(
            hashlib.sha256(b"q").digest()))
        log.append({"event": "policy_loaded"})
        log.append({"event": "identity_minted", "agent_id": "a1",
                    "run_id": "Q"})
        adapter = FakeLogAdapter(hashlib.sha256(b"x").digest())
        with self.assertRaises(ie.IncidentExportError):
            ie.export_incident(logp, os.path.join(self.tmp, "no"),
                               adapter, run_id="Q")

    def test_broken_source_log_refused(self):
        provision_test_key()
        logp, signer = _make_log(self.tmp)
        with open(logp, "a", encoding="utf-8") as f:
            f.write('{"seq": 999, "event": "forged", "bogus": true}\n')
        adapter = FakeLogAdapter(hashlib.sha256(b"x").digest())
        with self.assertRaises(ie.IncidentExportError):
            ie.export_incident(logp, os.path.join(self.tmp, "no"),
                               adapter, run_id="R1",
                               entry_signer_pubkey=signer.public_key)

    def test_unsigned_window_refused(self):
        from gov.log import ActionLog as _AL
        from gov.signing import Ed25519Signer as _ES
        provision_test_key()
        logp = os.path.join(self.tmp, "unsigned.jsonl")
        # No signer: entries have no per-entry Ed25519 signatures.
        log = _AL(logp)
        log.append({"event": "canary_trip", "run_id": "R1"})
        adapter = FakeLogAdapter(hashlib.sha256(b"x").digest())
        with self.assertRaises(ie.IncidentExportError):
            ie.export_incident(logp, os.path.join(self.tmp, "no"),
                               adapter, run_id="R1")

    def test_deadline_tier_death(self):
        out, _l, _s, _a = _export(self.tmp,
                                  harm={"outcome_type": "death"})
        inc = json.load(open(os.path.join(out, "incident.json")))
        self.assertEqual(inc["incident"]["suggested_deadline_tier_days"],
                         10)

    def test_detect_incidents(self):
        provision_test_key()
        logp, _s = _make_log(self.tmp)
        cands = ie.detect_incidents(logp, run_id="R1")
        self.assertTrue(cands)
        self.assertEqual(cands[0]["incident_class"],
                         "exfiltration_attempt")
        self.assertEqual(cands[0]["trigger_seq"], 6)


class VerifierAttacks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="incatt_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _good(self):
        return _export(self.tmp)

    def _verify_fails(self, out, logp, signer, adapter):
        ok, findings = ie.verify_incident(
            out, logp, entry_signer_pubkey=signer.public_key,
            anchor_pubkey=adapter.public_key)
        self.assertFalse(ok)
        return [f["check"] for f in findings if not f["ok"]]

    def _retamper_digest(self, out):
        """Model a competent attacker who fixes the transport digest
        after tampering, so the verifier must catch the attack at the
        integrity/completeness/anchor layer, not just transport."""
        digest = ie._transport_digest(out)
        with open(os.path.join(out, "INCIDENT_DIGEST.sha256"), "w",
                  encoding="utf-8") as f:
            f.write(digest + "\n")

    def test_omit_event_from_timeline(self):
        out, logp, signer, adapter = self._good()
        tl = os.path.join(out, "timeline.jsonl")
        lines = [l for l in open(tl).read().splitlines() if l.strip()]
        # Drop the canary_trip (the incriminating event).
        kept = [l for l in lines if json.loads(l)["event"] != "canary_trip"]
        self.assertLess(len(kept), len(lines))
        with open(tl, "w", encoding="utf-8") as f:
            f.write("\n".join(kept) + "\n")
        self._retamper_digest(out)
        bad = self._verify_fails(out, logp, signer, adapter)
        self.assertTrue(any(c in ("I1", "I3", "C2") for c in bad), bad)

    def test_reorder_timeline(self):
        out, logp, signer, adapter = self._good()
        tl = os.path.join(out, "timeline.jsonl")
        lines = [l for l in open(tl).read().splitlines() if l.strip()]
        lines[0], lines[-1] = lines[-1], lines[0]
        with open(tl, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self._retamper_digest(out)
        bad = self._verify_fails(out, logp, signer, adapter)
        self.assertTrue(any(c in ("I1", "I2") for c in bad), bad)

    def test_forge_anchor_attestation(self):
        out, logp, signer, adapter = self._good()
        rp = os.path.join(out, "anchor_receipt.json")
        # Sub-attack 1: receipt from a different log key.
        other = FakeLogAdapter(hashlib.sha256(b"evil").digest())
        json.dump(other.anchor({"not": "this incident"}), open(rp, "w"))
        self._retamper_digest(out)
        bad = self._verify_fails(out, logp, signer, adapter)
        self.assertIn("A1", bad)
        # Sub-attack 2: a receipt for DIFFERENT bytes anchored on the
        # SAME log key (attacker holds the anchor key too). The
        # statement will not match this incident's digests.
        same_key_receipt = adapter.anchor(
            ie._anchor_input("inc-forged", {"from_seq": 1, "to_seq": 2},
                             "R1", "00" * 32, "11" * 32, "22" * 32,
                             "33" * 32))
        json.dump(same_key_receipt, open(rp, "w"))
        self._retamper_digest(out)
        bad = self._verify_fails(out, logp, signer, adapter)
        self.assertIn("A1", bad)

    def test_tamper_report_text(self):
        out, logp, signer, adapter = self._good()
        ip = os.path.join(out, "incident.json")
        inc = json.load(open(ip))
        inc["incident"]["narrative"] = "nothing happened"
        with open(ip, "w", encoding="utf-8") as f:
            json.dump(inc, f)
        bad = self._verify_fails(out, logp, signer, adapter)
        self.assertTrue(any(c in ("T1", "A1") for c in bad), bad)


if __name__ == "__main__":
    unittest.main()
