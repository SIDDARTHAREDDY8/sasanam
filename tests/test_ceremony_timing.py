"""Unit tests: ceremony-timing telemetry + advisory rubber-stamp signals.

Wave-173 Lane 3. Tests live at the public seams:
  - ApprovalQueue.decide() records the review-timing triple.
  - gov.ceremony_integrity.check_review_timing_consistency(record)
    reports "consistent" / "corrupt" / "invalid" / "unobserved".
  - Six advisory signal functions report ("flag"|"clear"|"unobserved",
    note) and never refuse or alter a decision.
  - Wave-171 gates (reason_empty, reason_contradicts_decision) still
    refuse and re-present.

stdlib unittest only. $0 spend, synthetic/local, deterministic.
Real product code only.
"""

import copy
import os
import sys
import time
import unittest
from datetime import timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if os.path.join(REPO_ROOT, "tests") not in sys.path:
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))

from gov import ceremony_integrity as ci  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402
from harness import make_run  # noqa: E402


# ------------------------------------------------------------- helpers

def _iso(epoch):
    from datetime import datetime
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(
        timespec="milliseconds")


def _timed(opened_epoch, latency_ms, decided_by="op-rios",
           reason="verified the diff and the destination path",
           risk_tier="high", opened_iso=None, resolved_iso=None):
    resolved_epoch = opened_epoch + latency_ms / 1000.0
    return {
        "id": "apr-%d" % int(opened_epoch * 1000),
        "status": "approved",
        "decided_by": decided_by,
        "decision_reason": reason,
        "risk_tier": risk_tier,
        "review_opened_at": opened_iso or _iso(opened_epoch),
        "review_resolved_at": resolved_iso or _iso(resolved_epoch),
        "review_latency_ms": latency_ms,
    }


def _queue_one(q, ident):
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "identity": ident.as_dict(),
              "agent_justification": "timing unit",
              "redactions": []}
    return q.queue(action,
                   PolicyDecision("require_approval", "timing unit",
                                  policy_id="timing-unit", flag="b"),
                   "agent_direct", "preview", caller_identity=ident)


def _queue_and_decide(review_opened_at=None):
    ctx = make_run()
    q = ctx["approvals"]
    ident = ctx["mint_identity"]("agent-1", "researcher", "user-1")
    aid = _queue_one(q, ident)
    rec, entry = q.decide(aid, True,
                          "verified the diff and the destination path",
                          decided_by="op-rios",
                          review_opened_at=review_opened_at)
    return q, q.get(aid), entry


def _fleet(n_fast=6, n_slow=4, approver="op-rios", base=1_700_000_000.0):
    recs = []
    for i in range(n_fast):
        recs.append(_timed(base + i * 600, 300, decided_by=approver))
    for i in range(n_slow):
        recs.append(_timed(base + 3600 + i * 600, 183_000,
                           decided_by=approver))
    return recs


# ------------------------------------------------- consistency check

class TestCheckReviewTimingConsistency(unittest.TestCase):
    def test_all_null_is_unobserved(self):
        rec = {"review_opened_at": None, "review_resolved_at": None,
               "review_latency_ms": None}
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "unobserved")

    def test_missing_fields_are_unobserved(self):
        self.assertEqual(ci.check_review_timing_consistency({}),
                         "unobserved")

    def test_consistent_triple(self):
        rec = _timed(1_700_000_000.0, 183_000)
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "consistent")

    def test_doctored_latency_is_corrupt(self):
        rec = _timed(1_700_000_000.0, 183_000)
        rec["review_latency_ms"] = 300  # tampered post-hoc
        self.assertEqual(ci.check_review_timing_consistency(rec), "corrupt")

    def test_partial_triple_is_invalid(self):
        rec = _timed(1_700_000_000.0, 183_000)
        rec["review_resolved_at"] = None
        self.assertEqual(ci.check_review_timing_consistency(rec), "invalid")

    def test_negative_latency_is_corrupt(self):
        rec = _timed(1_700_000_000.0, 183_000)
        rec["review_opened_at"] = _iso(1_700_000_000.0)
        rec["review_resolved_at"] = _iso(1_700_000_000.0 - 5.0)
        rec["review_latency_ms"] = -5000
        self.assertEqual(ci.check_review_timing_consistency(rec), "corrupt")

    def test_unparseable_timestamp_is_corrupt(self):
        rec = _timed(1_700_000_000.0, 183_000)
        rec["review_opened_at"] = "not-a-timestamp"
        self.assertEqual(ci.check_review_timing_consistency(rec), "corrupt")

    def test_tolerance_boundary(self):
        # |resolved-opened - latency| == 999 ms -> consistent;
        # 1002 ms -> corrupt (tolerance 1000 ms, no rounding).
        rec = _timed(1_700_000_000.0, 183_000)
        rec["review_resolved_at"] = _iso(1_700_000_000.0 + 183.999)
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "consistent")
        rec2 = _timed(1_700_000_000.0, 183_000)
        rec2["review_resolved_at"] = _iso(1_700_000_000.0 + 184.002)
        self.assertEqual(ci.check_review_timing_consistency(rec2), "corrupt")


# ------------------------------------------------- decide() stamping

class TestDecideTimingStamp(unittest.TestCase):
    def test_timed_decision_records_triple(self):
        t0 = time.time() - 183.4
        _, rec, _ = _queue_and_decide(review_opened_at=t0)
        self.assertIsNotNone(rec["review_opened_at"])
        self.assertIsNotNone(rec["review_resolved_at"])
        self.assertIsNotNone(rec["review_latency_ms"])
        self.assertGreaterEqual(rec["review_latency_ms"], 182_000)
        self.assertLessEqual(rec["review_latency_ms"], 186_000)
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "consistent")

    def test_untimed_decision_records_explicit_nulls(self):
        _, rec, _ = _queue_and_decide()
        self.assertIsNone(rec["review_opened_at"])
        self.assertIsNone(rec["review_resolved_at"])
        self.assertIsNone(rec["review_latency_ms"])
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "unobserved")

    def test_future_opened_at_fails_safe_to_nulls(self):
        _, rec, _ = _queue_and_decide(
            review_opened_at=time.time() + 3600)
        self.assertIsNone(rec["review_opened_at"])
        self.assertIsNone(rec["review_resolved_at"])
        self.assertIsNone(rec["review_latency_ms"])

    def test_non_numeric_opened_at_fails_safe_to_nulls(self):
        _, rec, _ = _queue_and_decide(review_opened_at="soon")
        self.assertIsNone(rec["review_latency_ms"])
        self.assertEqual(ci.check_review_timing_consistency(rec),
                         "unobserved")

    def test_timing_fields_bound_in_record_mac(self):
        t0 = time.time() - 61.0
        _, rec, _ = _queue_and_decide(review_opened_at=t0)
        from gov.approvals import approval_record_digest
        mac1 = approval_record_digest(rec)
        tampered = copy.deepcopy(rec)
        tampered["review_latency_ms"] = 250
        mac2 = approval_record_digest(tampered)
        self.assertNotEqual(mac1, mac2)
        self.assertEqual(rec["args_digest"], mac1)

    def test_timing_fields_in_decision_log_entry(self):
        t0 = time.time() - 61.0
        _, _, entry = _queue_and_decide(review_opened_at=t0)
        self.assertIn("review_latency_ms", entry)
        self.assertGreaterEqual(entry["review_latency_ms"], 59_000)
        self.assertLessEqual(entry["review_latency_ms"], 65_000)


# ------------------------------------------------- wave-171 gates hold

class TestWave171GatesHold(unittest.TestCase):
    def _ctx(self):
        ctx = make_run()
        q = ctx["approvals"]
        ident = ctx["mint_identity"]("agent-1", "researcher", "user-1")
        aid = _queue_one(q, ident)
        return q, aid

    def test_empty_reason_still_bounces(self):
        q, aid = self._ctx()
        with self.assertRaises(ValueError):
            q.decide(aid, True, "   ", decided_by="op-rios",
                     review_opened_at=time.time() - 5)
        self.assertEqual(q.get(aid)["status"], "pending")

    def test_contradictory_reason_still_bounces(self):
        q, aid = self._ctx()
        with self.assertRaises(ValueError):
            q.decide(aid, True, "deny this, it is unsafe",
                     decided_by="op-rios",
                     review_opened_at=time.time() - 5)
        self.assertEqual(q.get(aid)["status"], "pending")


# ------------------------------------------------- advisory signals

class TestAdvisorySignals(unittest.TestCase):
    def test_latency_cluster_flags_fast_cluster(self):
        verdict, note = ci.sig_latency_cluster_under_1s(_fleet())
        self.assertEqual(verdict, "flag")
        self.assertTrue("60%" in note or "0.60" in note)

    def test_latency_cluster_clears_careful_fleet(self):
        recs = [_timed(1_700_000_000.0 + i * 600, 183_000)
                for i in range(6)]
        verdict, _ = ci.sig_latency_cluster_under_1s(recs)
        self.assertEqual(verdict, "clear")

    def test_latency_cluster_unobserved_without_timing(self):
        recs = [{"id": "a", "review_latency_ms": None}]
        verdict, _ = ci.sig_latency_cluster_under_1s(recs)
        self.assertEqual(verdict, "unobserved")

    def test_latency_cluster_needs_minimum_records(self):
        recs = [_timed(1_700_000_000.0 + i, 300) for i in range(3)]
        verdict, _ = ci.sig_latency_cluster_under_1s(recs)
        self.assertEqual(verdict, "unobserved")

    def test_approver_dominance_flags(self):
        recs = _fleet(n_fast=7, n_slow=3)
        verdict, note = ci.sig_approver_dominance(recs)
        self.assertEqual(verdict, "flag")
        self.assertIn("op-rios", note)

    def test_approver_dominance_clears_split_fleet(self):
        recs = (_fleet(n_fast=3, n_slow=2, approver="op-rios")
                + _fleet(n_fast=3, n_slow=2, approver="op-chen",
                         base=1_700_100_000.0))
        verdict, _ = ci.sig_approver_dominance(recs)
        self.assertEqual(verdict, "clear")

    def test_after_hours_flags_late_decisions(self):
        # 23:30 UTC on five consecutive days.
        recs = [_timed(1_700_004_600.0 + i * 86400, 183_000)
                for i in range(5)]
        verdict, _ = ci.sig_after_hours(recs, tzinfo=timezone.utc)
        self.assertEqual(verdict, "flag")

    def test_after_hours_clears_daytime(self):
        # 14:00 UTC on five consecutive days.
        recs = [_timed(1_700_056_800.0 + i * 86400, 183_000)
                for i in range(5)]
        verdict, _ = ci.sig_after_hours(recs, tzinfo=timezone.utc)
        self.assertEqual(verdict, "clear")

    def test_after_hours_unobserved_without_timing(self):
        recs = [{"id": "a", "review_resolved_at": None}]
        verdict, _ = ci.sig_after_hours(recs, tzinfo=timezone.utc)
        self.assertEqual(verdict, "unobserved")

    def test_approver_stall_flags_p90_above_threshold(self):
        recs = [_timed(1_700_000_000.0 + i * 600, 400_000)
                for i in range(6)]
        verdict, _ = ci.sig_approver_stall(recs, p90_threshold_ms=300_000)
        self.assertEqual(verdict, "flag")

    def test_approver_stall_clears_fast_fleet(self):
        verdict, _ = ci.sig_approver_stall(_fleet(), p90_threshold_ms=300_000)
        self.assertEqual(verdict, "clear")

    def test_tier3_terse_flags(self):
        recs = [_timed(1_700_000_000.0 + i * 600, 300,
                       reason="ok", risk_tier="critical")
                for i in range(3)]
        verdict, _ = ci.sig_tier3_terse(recs)
        self.assertEqual(verdict, "flag")

    def test_tier3_terse_clears_verbose_critical(self):
        recs = [_timed(1_700_000_000.0 + i * 600, 183_000,
                       reason="verified the destination path is inside "
                              "the project dir and the diff is scoped",
                       risk_tier="critical")
                for i in range(3)]
        verdict, _ = ci.sig_tier3_terse(recs)
        self.assertEqual(verdict, "clear")

    def test_tier3_terse_clears_terse_low_tier(self):
        recs = [_timed(1_700_000_000.0 + i * 600, 300,
                       reason="ok", risk_tier="low")
                for i in range(3)]
        verdict, _ = ci.sig_tier3_terse(recs)
        self.assertEqual(verdict, "clear")

    def test_allow_list_growth_flags(self):
        verdict, note = ci.sig_allow_list_growth(12, 25, days=7)
        self.assertEqual(verdict, "flag")
        self.assertIn("13", note)

    def test_allow_list_growth_clears_small_delta(self):
        verdict, _ = ci.sig_allow_list_growth(12, 15, days=7)
        self.assertEqual(verdict, "clear")

    def test_signals_never_refuse_a_decision(self):
        # Advisory-only contract: the signal layer has no path back
        # into decide(). A flagged fleet must still decide normally.
        flagged = _fleet()
        self.assertEqual(ci.sig_latency_cluster_under_1s(flagged)[0], "flag")
        _, rec, _ = _queue_and_decide(review_opened_at=time.time() - 0.3)
        self.assertEqual(rec["status"], "approved")


if __name__ == "__main__":
    unittest.main()
