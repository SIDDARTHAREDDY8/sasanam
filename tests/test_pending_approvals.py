"""Unit tests for gov/pending_approvals.py (wave-281 lane 6).

LangGraph ADAPT (durable-approval mechanism only). Synthetic/local,
deterministic; sqlite files live under a fresh /var/tmp dir per test.
"""

import json
import os
import sqlite3
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import pending_approvals as pa  # noqa: E402


def _tmpdir():
    d = tempfile.mkdtemp(prefix="g281_pa_ut_", dir="/var/tmp")
    os.makedirs(d, exist_ok=True)
    return d


def _proposal(args=None):
    return {"tool": "write_file",
            "args": args if args is not None else {"path": "/tmp/x"},
            "run_id": "run-1",
            "agent_id": "agent-7",
            "policy_id": "human-approval-contract"}


class ParkTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmpdir()
        self.ledger = pa.PendingApprovalLedger(
            os.path.join(self.d, "p.db"))

    def tearDown(self):
        self.ledger.close()

    def test_park_returns_digests(self):
        r = self.ledger.park("a1", _proposal(), ttl_s=60)
        self.assertEqual(r["approval_id"], "a1")
        self.assertRegex(r["proposal_digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(r["args_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(r["ttl_s"], 60.0)

    def test_duplicate_park_is_programming_error(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        with self.assertRaises(ValueError):
            self.ledger.park("a1", _proposal(), ttl_s=60)

    def test_malformed_proposal_fails_fast(self):
        for bad in (None, "x", {"args": {}},
                    {"tool": "", "args": {}},
                    {"tool": "t", "args": {"k": object()}}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.ledger.park("bad", bad, ttl_s=60)

    def test_bad_ttl_fails_fast(self):
        for bad in (0, -1, float("nan"), float("inf"), True, "60"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.ledger.park("bad", _proposal(), ttl_s=bad)

    def test_bad_id_fails_fast(self):
        for bad in ("", "  ", None, 123):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.ledger.park(bad, _proposal(), ttl_s=60)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmpdir()
        self.ledger = pa.PendingApprovalLedger(
            os.path.join(self.d, "p.db"))

    def tearDown(self):
        self.ledger.close()

    def test_approve_roundtrip(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        rv = self.ledger.resume("a1", "approved", decided_by="op")
        self.assertEqual(rv["decision"], "approved")
        self.assertEqual(rv["args"], {"path": "/tmp/x"})
        self.assertFalse(rv["edited"])
        self.assertEqual(self.ledger.status("a1")["status"], "approved")

    def test_deny_carries_no_args(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        rv = self.ledger.resume("a1", "denied", decided_by="op")
        self.assertEqual(rv["decision"], "denied")
        self.assertIsNone(rv["args"])
        self.assertIsNone(rv["final_args_digest"])

    def test_edit_returns_edited_args(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        rv = self.ledger.resume("a1", "approved",
                               edited_args={"path": "/tmp/y"},
                               decided_by="op")
        self.assertTrue(rv["edited"])
        self.assertEqual(rv["args"], {"path": "/tmp/y"})
        self.assertNotEqual(rv["final_args_digest"],
                            rv["proposal_digest"])

    def test_unknown_id_refused_coded(self):
        with self.assertRaises(pa.PendingApprovalError) as cm:
            self.ledger.resume("nope", "approved")
        self.assertEqual(cm.exception.code,
                         "pending-approval-resume-refused")
        self.assertEqual(cm.exception.detail, "unknown_approval_id")

    def test_double_resume_refused(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        self.ledger.resume("a1", "approved")
        with self.assertRaises(pa.PendingApprovalError) as cm:
            self.ledger.resume("a1", "denied")
        self.assertEqual(cm.exception.detail, "already_decided")
        self.assertEqual(self.ledger.status("a1")["decision"], "approved")

    def test_bad_decision_refused_coded(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        with self.assertRaises(pa.PendingApprovalError) as cm:
            self.ledger.resume("a1", "maybe")
        self.assertEqual(cm.exception.detail, "bad_decision")
        self.assertEqual(self.ledger.status("a1")["status"], "parked")

    def test_bad_edited_args_refused_coded(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        with self.assertRaises(pa.PendingApprovalError) as cm:
            self.ledger.resume("a1", "approved", edited_args=["x"])
        self.assertEqual(cm.exception.detail, "bad_edited_args")

    def test_tampered_snapshot_refuses_and_stays_parked(self):
        self.ledger.park("a1", _proposal(), ttl_s=60)
        conn = sqlite3.connect(os.path.join(self.d, "p.db"))
        conn.execute("UPDATE pending_approvals SET proposal_json=? "
                     "WHERE approval_id='a1'",
                     (json.dumps({"tool": "evil", "args": {}}, ),))
        conn.commit()
        conn.close()
        with self.assertRaises(pa.SnapshotTamperedError) as cm:
            self.ledger.resume("a1", "approved")
        self.assertEqual(cm.exception.code,
                         "pending-approval-snapshot-tampered")
        self.assertEqual(self.ledger.status("a1")["status"], "parked")

    def test_unparseable_snapshot_refused_coded(self):
        # Store-level corruption the digest check alone cannot catch:
        # unparseable bytes with a consistently recomputed digest.
        import hashlib
        self.ledger.park("a1", _proposal(), ttl_s=60)
        bad = "{not valid json"
        digest = hashlib.sha256(bad.encode("utf-8")).hexdigest()
        conn = sqlite3.connect(os.path.join(self.d, "p.db"))
        conn.execute("UPDATE pending_approvals SET proposal_json=?,"
                     " proposal_digest=? WHERE approval_id='a1'",
                     (bad, digest))
        conn.commit()
        conn.close()
        with self.assertRaises(pa.SnapshotTamperedError) as cm:
            self.ledger.resume("a1", "approved")
        self.assertEqual(cm.exception.code,
                         "pending-approval-snapshot-tampered")
        st = self.ledger.status("a1")
        self.assertTrue(st["tampered"])
        self.assertEqual(st["status"], "parked")
        rec = self.ledger.recover()
        self.assertIn("a1", rec["tampered"])
        self.assertNotIn("a1", rec["parked"])

    def test_non_dict_snapshot_refused_coded(self):
        import hashlib
        self.ledger.park("a1", _proposal(), ttl_s=60)
        bad = json.dumps([1, 2, 3])
        digest = hashlib.sha256(bad.encode("utf-8")).hexdigest()
        conn = sqlite3.connect(os.path.join(self.d, "p.db"))
        conn.execute("UPDATE pending_approvals SET proposal_json=?,"
                     " proposal_digest=? WHERE approval_id='a1'",
                     (bad, digest))
        conn.commit()
        conn.close()
        with self.assertRaises(pa.SnapshotTamperedError):
            self.ledger.resume("a1", "approved")

    def test_race_loser_leaves_refusal_trace(self):
        # Two ledger instances, same db: L2 wins, L1's conditional
        # UPDATE hits zero rows -> coded refusal WITH a forensic
        # resume_refused trace (no silent loss).
        db = os.path.join(self.d, "p.db")
        self.ledger.park("a1", _proposal(), ttl_s=60)
        other = pa.PendingApprovalLedger(db)
        try:
            other.resume("a1", "approved", decided_by="winner")
            with self.assertRaises(pa.PendingApprovalError) as cm:
                self.ledger.resume("a1", "denied", decided_by="loser")
            self.assertEqual(cm.exception.detail, "already_decided")
            events = other._conn.execute(
                "SELECT event, detail_json FROM approval_events"
                " WHERE approval_id='a1' ORDER BY seq").fetchall()
            kinds = [e["event"] for e in events]
            self.assertIn("resumed", kinds)
            refused = [e for e in events if e["event"] == "resume_refused"]
            self.assertEqual(len(refused), 1)
            self.assertIn("already_decided", refused[0]["detail_json"])
            # Winner's decision stands; exactly one resumed event.
            self.assertEqual(
                [e["event"] for e in events].count("resumed"), 1)
            self.assertEqual(self.ledger.status("a1")["decision"],
                             "approved")
        finally:
            other.close()

    def test_expired_refused_at_use(self):
        self.ledger.park("a1", _proposal(), ttl_s=3600)
        conn = sqlite3.connect(os.path.join(self.d, "p.db"))
        conn.execute("UPDATE pending_approvals SET parked_at=? "
                     "WHERE approval_id='a1'", (0.0,))
        conn.commit()
        conn.close()
        self.assertTrue(self.ledger.status("a1")["expired"])
        with self.assertRaises(pa.PendingApprovalError) as cm:
            self.ledger.resume("a1", "approved")
        self.assertEqual(cm.exception.detail, "expired")

    def test_error_is_exception_with_code_attr(self):
        # Contract pin: verify() never raises -- callers check the
        # return; here the dual: refusal codes are attributes, and the
        # tamper error subclasses the resume refusal.
        self.assertTrue(issubclass(pa.SnapshotTamperedError,
                                   pa.PendingApprovalError))
        self.assertEqual(pa.PendingApprovalError.code,
                         "pending-approval-resume-refused")
        self.assertEqual(pa.SnapshotTamperedError.code,
                         "pending-approval-snapshot-tampered")


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmpdir()
        self.ledger = pa.PendingApprovalLedger(
            os.path.join(self.d, "p.db"))

    def tearDown(self):
        self.ledger.close()

    def test_list_parked_ordered_and_projected(self):
        self.ledger.park("b", _proposal(), ttl_s=60)
        self.ledger.park("a", _proposal(), ttl_s=60)
        parked = self.ledger.list_parked()
        self.assertEqual([p["approval_id"] for p in parked], ["b", "a"])
        self.assertEqual(parked[0]["tool"], "write_file")
        self.assertFalse(parked[0]["expired"])

    def test_status_unknown_is_none(self):
        self.assertIsNone(self.ledger.status("missing"))

    def test_recover_reports_tampered(self):
        self.ledger.park("good", _proposal(), ttl_s=60)
        self.ledger.park("bad", _proposal(), ttl_s=60)
        conn = sqlite3.connect(os.path.join(self.d, "p.db"))
        conn.execute("UPDATE pending_approvals SET proposal_json='{}' "
                     "WHERE approval_id='bad'")
        conn.commit()
        conn.close()
        rec = self.ledger.recover()
        self.assertEqual(rec["parked"], ["good"])
        self.assertEqual(rec["tampered"], ["bad"])


class DigestHelperTests(unittest.TestCase):
    def test_args_digest_stable(self):
        self.assertEqual(pa.args_digest({"b": 1, "a": 2}),
                         pa.args_digest({"a": 2, "b": 1}))
        self.assertRegex(pa.args_digest({}), r"^[0-9a-f]{64}$")

    def test_proposal_digest_of_matches_park(self):
        d = _tmpdir()
        ledger = pa.PendingApprovalLedger(os.path.join(d, "p.db"))
        try:
            prop = _proposal()
            r = ledger.park("a1", prop, ttl_s=60)
            self.assertEqual(r["proposal_digest"],
                             pa.proposal_digest_of(prop))
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
