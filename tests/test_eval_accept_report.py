#!/usr/bin/env python3
"""Unit tests for the governed eval-report acceptance checkpoint (F141)."""

import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test-eval-accept")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov import eval_integrity as ei  # noqa: E402
from gov import citation_provenance as cp  # noqa: E402
from gov.detection import BehavioralMonitor, identity_key_of  # noqa: E402

PLANT_URL = "https://pastebin.synthetic.local/claims/study-9"


def _ctx():
    tmp = tempfile.mkdtemp(prefix="govevalaccept-")
    ctx = make_run(ledger_path=os.path.join(tmp, "egress.jsonl"))
    ident = ctx["executor"].mint_identity("eval-agent-1", "researcher",
                                          "eval-principal")
    monitor = BehavioralMonitor()
    return ctx, ident, monitor


def _accept_args(ctx, ident, monitor, session_id, **kw):
    args = dict(
        monitor=monitor, log=ctx["log"], identity=ident,
        identity_key=identity_key_of(ident),
        session_id=session_id, session_open="2026-09-23T00:00:00Z",
        log_entries=list(ctx["read_log"]()),
        ledger=ctx["executor"]._ledger)
    args.update(kw)
    return args


def _planted_index():
    idx = cp.CitationIndex()
    idx.add_log_entries([{
        "event": "tool_call", "tool": "http_post",
        "decision": "allowed_executed", "run_id": "run-1",
        "agent_id": "eval-agent-1", "principal": "eval-principal",
        "seq": 3,
        "args": {"url": PLANT_URL,
                 "payload": {"bytes": 100,
                             "sha256_prefix": "deadbeef01234567"}},
    }])
    return idx


class AcceptReportTests(unittest.TestCase):
    def test_clean_report_accepted_and_check_chained(self):
        ctx, ident, monitor = _ctx()
        res = ei.accept_report(
            "Finding: retention improves 12 percent. No citations.",
            **_accept_args(ctx, ident, monitor, "sess-clean"))
        self.assertTrue(res["accepted"])
        self.assertEqual(res["check"]["n_self_planted"], 0)
        checks = [e for e in ctx["read_log"]()
                  if isinstance(e, dict)
                  and e.get("signal") == "citation_check_completed"
                  and e.get("session_id") == "sess-clean"]
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["accepted"])

    def test_tainted_report_refused_and_violation_filed(self):
        ctx, ident, monitor = _ctx()
        res = ei.accept_report(
            "Corroborated independently: " + PLANT_URL,
            **_accept_args(ctx, ident, monitor, "sess-tainted",
                           citation_index=_planted_index()))
        self.assertFalse(res["accepted"])
        self.assertEqual(res["check"]["n_self_planted"], 1)
        self.assertEqual(len(res["check"]["violations"]), 1)
        # The detector_trip record nests the signal at
        # prov.detector_trip.signal.
        trips = [e for e in ctx["read_log"]()
                 if isinstance(e, dict)
                 and ((e.get("prov") or {}).get("detector_trip") or {})
                     .get("signal") == "self_planted_citation"]
        self.assertTrue(trips)
        checks = [e for e in ctx["read_log"]()
                  if isinstance(e, dict)
                  and e.get("signal") == "citation_check_completed"
                  and e.get("session_id") == "sess-tainted"]
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["accepted"])
        self.assertEqual(checks[0]["n_self_planted"], 1)

    def test_unknown_citations_never_violate(self):
        ctx, ident, monitor = _ctx()
        res = ei.accept_report(
            "See https://example.com/unverifiable-claim",
            **_accept_args(ctx, ident, monitor, "sess-unknown"))
        self.assertTrue(res["accepted"])
        self.assertEqual(
            [c["verdict"] for c in res["check"]["citations"]], ["UNKNOWN"])
        self.assertEqual(res["check"]["violations"], [])


class MissingCheckLintTests(unittest.TestCase):
    def test_lists_only_unchecked_sessions(self):
        ctx, ident, monitor = _ctx()
        ei.accept_report(
            "Nothing cited.", **_accept_args(ctx, ident, monitor,
                                             "sess-checked"))
        entries = list(ctx["read_log"]())
        missing = ei.eval_sessions_missing_citation_check(
            entries, session_ids=["sess-checked", "sess-skipped"])
        self.assertEqual(missing, ["sess-skipped"])

    def test_empty_when_all_checked(self):
        ctx, ident, monitor = _ctx()
        ei.accept_report(
            "Nothing cited.", **_accept_args(ctx, ident, monitor,
                                             "sess-a"))
        entries = list(ctx["read_log"]())
        self.assertEqual(
            ei.eval_sessions_missing_citation_check(entries,
                                                    session_ids=["sess-a"]),
            [])

    def test_empty_input_is_empty(self):
        self.assertEqual(
            ei.eval_sessions_missing_citation_check([], session_ids=[]), [])
        self.assertEqual(
            ei.eval_sessions_missing_citation_check(
                [], session_ids=["s1"]), ["s1"])


if __name__ == "__main__":
    unittest.main()
