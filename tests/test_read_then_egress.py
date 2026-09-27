#!/usr/bin/env python3
"""Unit tests for the wave-137 behavioral tier in gov/rare_token.py
and its executor wiring.

Seams: RareTokenTracker.check_egress (behavioral_flag verdict),
ToolExecutor.check_rare_token_carryover (read_then_egress_novel
audit shape), and the precedence/no-token-strings invariants.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import rare_token as rt  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

DOC = ("Customer account review Zephyrcorp Industries. "
       "Account reference ZX-88142, renewal code QX-22901. "
       "Primary contact: Marlowe Finch.")
FULL_REWRITE = ("The client account is due for renewal. Please reach out "
                "to the primary contact to confirm the details.")
PARAPHRASE = ("Please process the renewal for Zephyrcorp Industries "
              "(account ZX-88142). Marlowe Finch confirmed code QX-22901.")
NOVEL = "https://exfil-collector.synthetic.local/intake"
KNOWN = "https://vendor.synthetic.local/sync"


def _egress(t, agent, url, payload):
    return t.check_egress(agent, "http_post",
                          {"url": url, "data": payload},
                          payload_text=payload)


def _session(tracker=None):
    """Minimal executor session with an optional rare-token tracker.

    Local to this file (does not touch the shared harness): builds
    the executor directly, mirroring evals/rare_token_probes.py.
    """
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    Path(tmpdir).mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="govreadegress-test-",
                                    dir=tmpdir))
    policy = PolicyEngine(str(Path(REPO_ROOT) / "policies"
                              / "default.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      rare_token_tracker=tracker,
                      ungoverned_ack=(
                          "read-then-egress unit tests: synthetic "
                          "harness; raw pipeline declared"))
    return {"run_dir": run_dir, "executor": ex, "log": log,
            "approvals": approvals}


def _read_log(ctx):
    return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
            if isinstance(e, dict)]


class TestBehavioralFlag(unittest.TestCase):
    def test_zero_overlap_read_then_novel_egress_flags(self):
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", DOC)
        r = _egress(t, "a1", NOVEL, FULL_REWRITE)
        self.assertEqual(r["verdict"], "behavioral_flag")
        self.assertEqual(r["overlap"], 0)
        self.assertGreaterEqual(r["docs_read"], 1)
        self.assertEqual(r["destination"], NOVEL)
        self.assertTrue(r["destination_novel"])
        self.assertIn("doc-1", r["source_ids"])

    def test_single_low_token_doc_still_flags(self):
        # Behavioral, not content-thresholded: even one rare token
        # in the read doc is enough (documented FP tradeoff).
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", "Report on Zephyrcorp only.")
        r = _egress(t, "a1", NOVEL, FULL_REWRITE)
        self.assertEqual(r["verdict"], "behavioral_flag")

    def test_known_destination_silent(self):
        t = rt.RareTokenTracker()
        self.assertEqual(
            _egress(t, "a1", KNOWN, "Weekly status.").get("verdict"),
            "allow")
        t.observe_read("a1", "doc-1", DOC)
        r = _egress(t, "a1", KNOWN, FULL_REWRITE)
        self.assertEqual(r["verdict"], "allow")

    def test_no_reads_silent(self):
        t = rt.RareTokenTracker()
        r = _egress(t, "a1", NOVEL, FULL_REWRITE)
        self.assertEqual(r["verdict"], "allow")

    def test_no_destination_silent(self):
        # FP control: the behavioral tier needs a concrete novel
        # destination; destination-less tool calls stay silent.
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", DOC)
        r = t.check_egress("a1", "api_call", {"params": {"q": FULL_REWRITE}},
                           payload_text=FULL_REWRITE)
        self.assertEqual(r["verdict"], "allow")

    def test_content_tier_takes_precedence(self):
        # Overlap >= K to a novel dest: require_approval, never
        # degraded to behavioral_flag.
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", DOC)
        r = _egress(t, "a1", NOVEL, PARAPHRASE)
        self.assertEqual(r["verdict"], "require_approval")
        self.assertGreaterEqual(r["overlap"], 3)

    def test_token_bearing_zero_doc_does_not_flag(self):
        # A read with zero rare tokens is not a "token-bearing"
        # document: the behavioral tier stays silent.
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", "The report is due soon.")
        r = _egress(t, "a1", NOVEL, FULL_REWRITE)
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["docs_read"], 0)

    def test_agents_isolated(self):
        t = rt.RareTokenTracker()
        t.observe_read("a1", "doc-1", DOC)
        r = _egress(t, "a2", NOVEL, FULL_REWRITE)
        self.assertEqual(r["verdict"], "allow")


class TestBehavioralExecutorWiring(unittest.TestCase):
    def test_behavioral_flag_audits_loud_and_proceeds(self):
        ctx = _session(rt.RareTokenTracker())
        ex = ctx["executor"]
        ident = ex.mint_identity("a1", "coder", "user-1")
        ex.note_read_output("a1", "doc-1", DOC)
        res = ex.check_rare_token_carryover(
            "a1", "http_post", {"url": NOVEL, "data": FULL_REWRITE},
            payload_text=FULL_REWRITE, identity=ident)
        self.assertEqual(res["verdict"], "behavioral_flag")
        evs = [e for e in _read_log(ctx)
               if e.get("event") == "read_then_egress_novel"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["flag"], "read_then_egress")
        self.assertEqual(evs[0]["destination"], NOVEL)
        self.assertGreaterEqual(evs[0]["docs_read"], 1)
        # No approval queued, no identity needed for the triage path.
        reviews = [r for r in ctx["approvals"].all()
                   if r.get("tool") == "rare_token_review"]
        self.assertEqual(reviews, [])
        # Privacy: no token strings in the audit trail.
        blob = str(_read_log(ctx))
        for tok in ("zephyrcorp", "marlowe", "finch", "88142", "22901"):
            self.assertNotIn(tok, blob)

    def test_behavioral_flag_needs_no_identity(self):
        ctx = _session(rt.RareTokenTracker())
        ex = ctx["executor"]
        ex.note_read_output("a1", "doc-1", DOC)
        res = ex.check_rare_token_carryover(
            "a1", "http_post", {"url": NOVEL, "data": FULL_REWRITE},
            payload_text=FULL_REWRITE, identity=None)
        self.assertEqual(res["verdict"], "behavioral_flag")

    def test_no_tracker_zero_behavior_change(self):
        ctx = _session()
        ex = ctx["executor"]
        res = ex.check_rare_token_carryover(
            "a1", "http_post", {"url": NOVEL, "data": FULL_REWRITE},
            payload_text=FULL_REWRITE)
        self.assertEqual(res["verdict"], "allow")
        evs = [e for e in _read_log(ctx)
               if str(e.get("event", "")).startswith("read_then_egress")]
        self.assertEqual(evs, [])


if __name__ == "__main__":
    unittest.main()
