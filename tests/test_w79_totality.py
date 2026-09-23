"""Wave-79: the totality gate.

TOTAL means: every decision record the system emits carries
`policy_version` (non-empty string) and `matched_rules` (list of
strings). This test fails the build if any covered decision record is
missing either field. Covered families (design §2(a)): executor
verdict-path entries, approval-subsystem decision entries, recovery
decisions, load-gate decisions, and provenance records.

`matched_rules` may be empty only when no policy-engine rule fired
(structural refusals, human/governor decisions); an engine verdict
always carries a non-empty list ("default_deny" sentinel when the
fail-closed default fired).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gov import load_gate, provenance
from gov.recovery import RecoveryController, RECOVERY_FRAMEWORK_VERSION
from harness import make_run, plant_file


def _assert_total(testcase, entry, where):
    testcase.assertIn("policy_version", entry,
                      "%s: missing policy_version" % where)
    testcase.assertIsInstance(entry["policy_version"], str, where)
    testcase.assertTrue(entry["policy_version"],
                        "%s: empty policy_version" % where)
    testcase.assertIn("matched_rules", entry,
                      "%s: missing matched_rules" % where)
    testcase.assertIsInstance(entry["matched_rules"], list, where)
    for rule in entry["matched_rules"]:
        testcase.assertIsInstance(rule, str, where)


class TestEngineVerdictTotality(unittest.TestCase):
    def test_allow_verdict_total(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("triage-1", "triage", "ops-org")
        plant_file(ctx, "data/n.txt", "hello")
        r = ctx["executor"].call(ident, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "executed")
        entries = ctx["read_log"]()
        auth = [e for e in entries
                if e.get("decision") == "execution_authorized"]
        self.assertTrue(auth)
        _assert_total(self, auth[-1], "execution_authorized")
        # An engine verdict ALWAYS names the rule(s) that fired.
        self.assertTrue(auth[-1]["matched_rules"])
        self.assertIn("allow-sandbox-reads", auth[-1]["matched_rules"])

    def test_deny_verdict_total(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        r = ctx["executor"].call(
            ident, "api_call",
            endpoint="https://evil.example/v1/x", params={})
        self.assertEqual(r["status"], "denied")
        entries = ctx["read_log"]()
        denied = [e for e in entries if e.get("decision") == "denied"]
        self.assertTrue(denied)
        _assert_total(self, denied[-1], "denied")
        self.assertTrue(denied[-1]["matched_rules"])

    def test_default_deny_sentinel(self):
        ctx = make_run()
        policy = ctx["policy"]
        d = policy.evaluate(
            {"tool": "definitely_not_a_tool", "role": "triage",
             "agent_id": "a", "args": {}},
            {"role": "triage"})
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.matched_rules, ["default_deny"])

    def test_queued_verdict_total(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("support-1", "support", "helpdesk-org")
        r = ctx["executor"].call(
            ident, "send_email", to="ed@synthetic.local",
            subject="t", body="hello")
        self.assertEqual(r["status"], "queued")
        entries = ctx["read_log"]()
        queued = [e for e in entries
                  if e.get("decision") == "queued_pending"]
        self.assertTrue(queued)
        _assert_total(self, queued[-1], "queued_pending")
        self.assertTrue(queued[-1]["matched_rules"])

    def test_structural_refusal_total(self):
        # No policy rule fired (identity rejected before evaluation):
        # matched_rules is honestly empty, policy_version still names
        # the engine version in force.
        ctx = make_run()
        ident = ctx["mint_identity"]("triage-1", "triage", "ops-org")
        bad = ctx["executor"].mint_identity("ghost", "triage", "ops-org")
        # Forge an unminted identity object: call with a *different*
        # executor's identity so _check_identity refuses.
        ctx2 = make_run()
        foreign = ctx2["mint_identity"]("triage-1", "triage", "ops-org")
        r = ctx["executor"].call(foreign, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "denied")
        entries = ctx["read_log"]()
        denied = [e for e in entries if e.get("decision") == "denied"]
        self.assertTrue(denied)
        _assert_total(self, denied[-1], "structural denied")
        self.assertEqual(denied[-1]["matched_rules"], [])


class TestApprovalTotality(unittest.TestCase):
    def test_approval_outcome_names_queuing_rule(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("support-1", "support", "helpdesk-org")
        r = ctx["executor"].call(
            ident, "send_email", to="ed@synthetic.local",
            subject="t", body="hello")
        self.assertEqual(r["status"], "queued")
        approval_id = r["approval_id"]
        ctx["approvals"].decide(approval_id, True, "test approve",
                                decided_by="human-op")
        entries = ctx["read_log"]()
        outcomes = [e for e in entries
                    if e.get("event") == "approval_decision"]
        self.assertTrue(outcomes)
        _assert_total(self, outcomes[-1], "approval_decision")
        # The outcome names the rule that queued the ticket.
        self.assertTrue(outcomes[-1]["matched_rules"])
        self.assertEqual(outcomes[-1]["policy_version"], "2")

    def test_ticket_carries_queuing_provenance(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("support-1", "support", "helpdesk-org")
        r = ctx["executor"].call(
            ident, "send_email", to="ed@synthetic.local",
            subject="t", body="hello")
        recs = ctx["approvals"].all()
        rec = [x for x in recs if x["id"] == r["approval_id"]][0]
        self.assertEqual(rec["policy_version"], "2")
        self.assertTrue(rec["matched_rules"])


class TestRecoveryTotality(unittest.TestCase):
    def test_resume_or_halt_decision_total(self):
        ctx = make_run()
        rc = RecoveryController(ctx["log"], ctx["run_dir"])
        rc.decide("agent-1", decision="keep_halted",
                  operator_principal="op-1",
                  evidence={"note": "test"})
        entries = ctx["read_log"]()
        dec = [e for e in entries
               if e.get("event") == "resume_or_halt_decision"]
        self.assertTrue(dec)
        _assert_total(self, dec[-1], "resume_or_halt_decision")
        self.assertEqual(dec[-1]["policy_version"],
                         RECOVERY_FRAMEWORK_VERSION)
        self.assertEqual(dec[-1]["matched_rules"], [])


class TestLoadGateTotality(unittest.TestCase):
    def test_artifact_load_refused_total(self):
        ctx = make_run()
        load_gate._refused(ctx["log"], "skill-x", "digest_mismatch",
                           "test detail")
        entries = ctx["read_log"]()
        refused = [e for e in entries
                   if e.get("event") == "artifact_load_refused"]
        self.assertTrue(refused)
        _assert_total(self, refused[-1], "artifact_load_refused")
        self.assertEqual(refused[-1]["policy_version"], "supplychain-w78")
        self.assertEqual(refused[-1]["matched_rules"], [])


class TestProvenanceTotality(unittest.TestCase):
    def _base_prov(self):
        return {
            "schema_version": 1,
            "session_id": "s-1",
            "session_open": "2026-09-22T00:00:00+00:00",
            "clock_source": "test",
            "principal": {"kind": "service", "ref": "governor-test"},
            "delegation": {"delegation_schema_version": 1, "hops": [],
                           "no_delegation_reason": "test"},
            "record_type": "decision",
            "action": {"tool": "read_file"},
            "outcome": {"status": "ok"},
            "payload_tier": "decision",
            "retention": {"class": "decision",
                          "until": "2027-09-22T00:00:00+00:00",
                          "policy": "test"},
        }

    def test_missing_policy_version_refused(self):
        from gov.log import ActionLog
        import tempfile
        d = tempfile.mkdtemp()
        log = ActionLog(str(Path(d) / "a.jsonl"))
        prov = self._base_prov()
        prov["matched_rules"] = ["some-rule"]
        with self.assertRaises(provenance.ProvenanceError):
            provenance.append_provenance(
                log, {"event": "x", "prov": prov})

    def test_missing_matched_rules_refused(self):
        from gov.log import ActionLog
        import tempfile
        d = tempfile.mkdtemp()
        log = ActionLog(str(Path(d) / "a.jsonl"))
        prov = self._base_prov()
        prov["policy_version"] = "2"
        with self.assertRaises(provenance.ProvenanceError):
            provenance.append_provenance(
                log, {"event": "x", "prov": prov})


class TestWholeLogSweep(unittest.TestCase):
    def test_every_decision_entry_in_run_is_total(self):
        # The build-fails gate in its strongest form: run a mixed
        # workload, then sweep EVERY chained entry carrying a decision
        # key in the covered families and assert totality.
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(ctx, "data/n.txt", "hello")
        ctx["executor"].call(ident, "read_file", path="data/n.txt")
        ctx["executor"].call(
            ident, "api_call",
            endpoint="https://synthetic.local/v1/data", params={})
        ctx["executor"].call(
            ident, "api_call",
            endpoint="https://evil.example/v1/x", params={})
        for e in ctx["read_log"]():
            if "decision" in e and e.get("event") in (
                    "tool_call", "approval_decision",
                    "approval_decision_attempt"):
                _assert_total(self, e,
                              "sweep %s/%s" % (e.get("event"),
                                               e.get("decision")))


if __name__ == "__main__":
    unittest.main()
