"""Unit tests for gov/policy_report.py (wave-199).

Public seams only: build_report / project_result / seal_report /
verify_report / emit_policy_report. Deterministic (seeded clock).
"""

import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import mode_ledger as ml  # noqa: E402
from gov import policy_report as pr  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402


def _ledger():
    t = [1700000000.0]

    def clock():
        t[0] += 1.0
        return t[0]

    ledger = ml.ModeLedger(clock=clock)
    ledger.register_rule("o", mode="observe")
    ledger.register_rule("w", mode="warn")
    ledger.observe("o", mode="observe", matched=True,
                   nominal_effect="deny", request_digest="dig-o")
    ledger.observe("w", mode="warn", matched=True,
                   nominal_effect="queue", request_digest="dig-w")
    return ledger


class ProjectResultTest(unittest.TestCase):
    def test_observe_projects_skip(self):
        ledger = _ledger()
        rec = next(r for r in ledger._chain if r["rule_id"] == "o")
        res = pr.project_result(rec, policy_name="pol")
        self.assertEqual(res["result"], "skip")
        self.assertEqual(res["source"], pr.DEFAULT_SOURCE)
        self.assertEqual(res["policy"], "pol")
        self.assertEqual(res["rule"], "o")
        self.assertEqual(res["resources"],
                         [{"kind": "sasanam/request", "uid": "dig-o"}])
        self.assertIn("diagnostic only", res["message"])

    def test_warn_projects_warn(self):
        ledger = _ledger()
        rec = next(r for r in ledger._chain if r["rule_id"] == "w")
        res = pr.project_result(rec, policy_name="pol")
        self.assertEqual(res["result"], "warn")
        self.assertEqual(res["properties"]["nominal_effect"], "queue")
        self.assertIn("admitted with warning", res["message"])

    def test_mode_change_projects_pass(self):
        t = [1700000000.0]
        ledger = ml.ModeLedger(
            clock=lambda: t.__setitem__(0, t[0] + 1.0) or t[0])
        ledger.register_rule("o", mode="observe")
        ledger.observe("o", mode="observe", matched=True,
                       nominal_effect="deny", request_digest="d")
        ledger._apply_mode_change("o", "warn", ["amy", "bo"],
                                  "graduation", None)
        rec = next(r for r in ledger._chain
                   if "old_mode" in r and "new_mode" in r)
        res = pr.project_result(rec, policy_name="pol")
        self.assertEqual(res["result"], "pass")
        self.assertEqual(res["category"], "ladder")
        self.assertEqual(res["properties"]["old_mode"], "observe")
        self.assertEqual(res["properties"]["new_mode"], "warn")
        self.assertEqual(res["properties"]["approvers"], ["amy", "bo"])

    def test_unknown_transition_label_still_projects(self):
        # A future transition label must never silently drop out of
        # the report: detection is structural (old_mode/new_mode),
        # not by kind string.
        rec = {"kind": "some_future_transition", "rule_id": "o",
               "old_mode": "warn", "new_mode": "deny",
               "at": 1700000002.0, "approvers": ["amy"],
               "stats": {"evaluated": 1},
               "seq": 1, "digest": "x", "rule_seq": 1, "rule_prev": "G"}
        res = pr.project_result(rec, policy_name="pol")
        self.assertEqual(res["result"], "pass")
        self.assertEqual(res["properties"]["transition"],
                         "some_future_transition")

    def test_unreportable_kind_refuses(self):
        with self.assertRaises(pr.PolicyReportError):
            pr.project_result({"kind": "heartbeat", "rule_id": "o"},
                              policy_name="pol")

    def test_bad_violation_mode_refuses(self):
        with self.assertRaises(pr.PolicyReportError):
            pr.project_result({"kind": "violation", "rule_id": "o",
                               "mode": "deny", "at": 1.0},
                              policy_name="pol")

    def test_empty_policy_name_refuses(self):
        ledger = _ledger()
        rec = ledger._chain[0]
        with self.assertRaises(pr.PolicyReportError):
            pr.project_result(rec, policy_name="")

    def test_missing_request_digest_empty_resources(self):
        rec = {"kind": "violation", "rule_id": "o", "mode": "observe",
               "nominal_effect": "deny", "at": 1700000002.0,
               "seq": 1, "digest": "x", "rule_seq": 1, "rule_prev": "G"}
        res = pr.project_result(rec, policy_name="pol")
        self.assertEqual(res["resources"], [])


class BuildReportTest(unittest.TestCase):
    def test_summary_counts(self):
        report = pr.build_report(_ledger(), policy_name="pol")
        self.assertEqual(report["kind"], "PolicyReport")
        self.assertEqual(report["reportVersion"], pr.REPORT_VERSION)
        self.assertEqual(report["summary"]["skip"], 1)
        self.assertEqual(report["summary"]["warn"], 1)
        self.assertEqual(report["summary"]["total"], 2)

    def test_rule_filter(self):
        report = pr.build_report(_ledger(), policy_name="pol",
                                 rule_ids=["w"])
        self.assertEqual([r["rule"] for r in report["results"]], ["w"])

    def test_rule_stats_covers_all_rules(self):
        ledger = _ledger()
        ledger.register_rule("quiet", mode="observe")
        ledger.observe("quiet", mode="observe", matched=False)
        ledger.record_warnings("w", 2)
        report = pr.build_report(ledger, policy_name="pol")
        stats = report["ruleStats"]
        self.assertEqual(set(stats), {"o", "w", "quiet"})
        self.assertEqual(stats["quiet"]["evaluated"], 1)
        self.assertEqual(stats["quiet"]["violations"], 0)
        self.assertEqual(stats["w"]["warnings_surfaced"], 2)
        self.assertEqual(stats["o"]["mode"], "observe")

    def test_rejects_non_ledger(self):
        with self.assertRaises(pr.PolicyReportError):
            pr.build_report(object(), policy_name="pol")


class SealVerifyTest(unittest.TestCase):
    def _envelope(self):
        signer = Ed25519Signer(bytes(range(32)))
        report = pr.build_report(_ledger(), policy_name="pol")
        return signer, pr.seal_report(report, signer)

    def test_roundtrip(self):
        signer, env = self._envelope()
        self.assertTrue(pr.verify_report(env, signer.public_key))

    def test_tamper_fails(self):
        import copy
        signer, env = self._envelope()
        bad = copy.deepcopy(env)
        bad["report"]["summary"]["total"] = 999
        self.assertFalse(pr.verify_report(bad, signer.public_key))

    def test_wrong_key_fails(self):
        signer, env = self._envelope()
        other = Ed25519Signer(bytes([9]) * 32)
        self.assertFalse(pr.verify_report(env, other.public_key))

    def test_domain_mismatch_fails(self):
        import copy
        signer, env = self._envelope()
        bad = copy.deepcopy(env)
        bad["signing"]["domain"] = "evidence-bundle/v2"
        self.assertFalse(pr.verify_report(bad, signer.public_key))

    def test_malformed_fails_closed(self):
        for bad in (None, {}, {"report": {}}, {"report": {"kind": "x"},
                                               "signing": {}}):
            self.assertFalse(pr.verify_report(bad, b"\x00" * 32))

    def test_seal_rejects_non_report(self):
        signer = Ed25519Signer(bytes(range(32)))
        with self.assertRaises(pr.PolicyReportError):
            pr.seal_report({"kind": "nope"}, signer)


class EmitTest(unittest.TestCase):
    def test_emit_writes_verifiable_artifact(self):
        signer = Ed25519Signer(bytes(range(32)))
        with tempfile.TemporaryDirectory() as tmp:
            path = pr.emit_policy_report(
                _ledger(), policy_name="genesis", signer=signer,
                out_dir=tmp, window_end=1700000100.0)
            self.assertIn("policy-report-genesis", path)
            envelope = json.loads(open(path, "rb").read().decode("utf-8"))
            self.assertTrue(
                pr.verify_report(envelope, signer.public_key))

    def test_emit_without_signer_refuses(self):
        saved = {}
        for var in ("GOV_ANCHOR_KEY", "GOV_ANCHOR_KEY_FILE"):
            saved[var] = os.environ.pop(var, None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(pr.PolicyReportError):
                    pr.emit_policy_report(_ledger(), policy_name="p",
                                          out_dir=tmp)
        finally:
            for var, val in saved.items():
                if val is not None:
                    os.environ[var] = val


if __name__ == "__main__":
    unittest.main()
