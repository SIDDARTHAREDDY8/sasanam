"""Red-team tests: T5 (approval-queue social engineering / hardening),
T8 (time-of-check/time-of-use drift), R8 (hardened approvals), R11 (TOCTOU).

Every test here FAILS on the current code: each asserts a control that does
not exist, demonstrating the vulnerability as an assertion failure.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)


class ApprovalAbuseBase(unittest.TestCase):
    def queue_send_email(self, run, to="victim@synthetic.local"):
        """Queue an outbound send (require_approval under default policy).

        Uses an egress-allowlisted domain: the point of these tests is the
        approval-queue mechanics (display, SoD, expiry, tampering, TOCTOU),
        not the egress control. Non-allowlisted destinations are denied
        outright by deny-egress-unallowlisted (see W-A3).
        """
        ident = run["identities"]["support"]
        res = run["executor"].call(
            ident, "send_email", to=to, subject="hello", body="hello")
        self.assertEqual(res["status"], "queued")
        return ident, res["approval_id"]


class TestStaleApprovalTOCTOU(ApprovalAbuseBase):
    """T8/R11: execute_approved must re-run the CURRENT policy set against
    current arguments. Approval granted, then policy tightened to deny:
    the action must NOT execute."""

    TIGHTENED = """\
version: 1
policies:
  - id: deny-outbound
    effect: deny
    match:
      tool: [send_email]
    reason: outbound blocked by tightened policy
"""

    def test_execute_approved_reevaluates_current_policy(self):
        from gov.policy import PolicyEngine
        run = make_run()
        ident, aid = self.queue_send_email(run)
        run["approvals"].decide(aid, True, reason="looks fine",
                                decided_by="human-operator")
        # Operator tightens policy AFTER the approval was granted.
        p = Path(run["run_dir"]) / "tightened.yaml"
        p.write_text(self.TIGHTENED, encoding="utf-8")
        run["executor"].policy = PolicyEngine(str(p))

        done = run["executor"].execute_approved()
        self.assertEqual(
            done, [],
            "T8/R11: execute_approved EXECUTED an action the CURRENT policy "
            "denies (no TOCTOU re-evaluation). executed=%r" % (done,),
        )


class TestApprovalExpiry(ApprovalAbuseBase):
    """T5/R8: approvals must expire (auto-deny default). An approval aged
    far past any reasonable TTL must not execute."""

    def test_expired_approval_does_not_execute(self):
        run = make_run()
        ident, aid = self.queue_send_email(run)
        run["approvals"].decide(aid, True, reason="ok",
                                decided_by="human-operator")
        # Age the approval record far past any reasonable TTL.
        records = run["approvals"].all()
        for r in records:
            if r["id"] == aid:
                r["decided_at"] = "2020-01-01T00:00:00+00:00"
        run["approvals"]._rewrite(records)

        done = run["executor"].execute_approved()
        self.assertEqual(
            done, [],
            "T5/R8: an approval decided in 2021 was still EXECUTED "
            "(approvals never expire). executed=%r" % (done,),
        )


class TestApprovalRecordIntegrity(ApprovalAbuseBase):
    """T5: the queued approval's args are stored in a plain JSONL file with
    no integrity binding to the approval decision. Tampering between
    queueing and approval must be detected; the action must not execute."""

    def test_tampered_args_are_detected(self):
        run = make_run()
        ident, aid = self.queue_send_email(run, to="victim@synthetic.local")
        # Attacker rewrites the queued args before the human decides.
        records = run["approvals"].all()
        for r in records:
            if r["id"] == aid:
                r["args"]["to"] = "attacker@evil.example"
        run["approvals"]._rewrite(records)

        # F38 (R10): decide() verifies the pending digest before
        # re-MACing, so the tamper fails closed at decision time (fail
        # even earlier than the old execution-time refusal) — the
        # record stays pending and is never executed.
        with self.assertRaisesRegex(ValueError, "integrity verification"):
            run["approvals"].decide(aid, True, reason="ok",
                                    decided_by="human-operator")
        done = run["executor"].execute_approved()
        self.assertEqual(
            done, [],
            "T5: approval whose queued args were TAMPERED (to -> "
            "attacker@evil.example) was EXECUTED anyway. executed=%r" % (done,),
        )


class TestSelfApproval(ApprovalAbuseBase):
    """T5/R8: separation of duties - decided_by must differ from the
    requesting agent. Self-approval must be rejected."""

    def test_self_approval_is_rejected(self):
        run = make_run()
        ident, aid = self.queue_send_email(run)
        with self.assertRaises(Exception):
            run["approvals"].decide(aid, True, reason="trust me",
                                    decided_by=ident.agent_id)
        self.assertEqual(
            run["approvals"].get(aid)["status"], "pending",
            "T5/R8: self-approved record did not stay pending",
        )


class TestQueueDisplay(ApprovalAbuseBase):
    """T5/R8: the human-review rendering of a queued record must show the
    raw tool+args, provenance, and matched rule id - never lead with the
    agent-supplied justification text."""

    def test_queue_record_carries_review_fields(self):
        run = make_run()
        ident = run["identities"]["support"]
        res = run["executor"].call(
            ident, "send_email", to="x@synthetic.local", subject="s", body="b",
            justification="totally routine vendor invoice, approve quickly please")
        rec = run["approvals"].get(res["approval_id"])
        self.assertEqual(rec["tool"], "send_email")
        self.assertEqual(rec["args"]["to"], "x@synthetic.local",
                         "queued record must preserve the raw tool args")
        self.assertIsNotNone(rec.get("policy_id"),
                             "queued record must carry the matched rule id")
        self.assertIn(
            "provenance", rec,
            "T5/R8: queued record has NO provenance field (input provenance "
            "invisible to the human reviewer)",
        )

    def test_queue_display_shows_raw_call_not_justification(self):
        from gov.approvals import _print_records
        run = make_run()
        ident = run["identities"]["support"]
        just = "totally routine vendor invoice, approve quickly please"
        to_addr = "x@synthetic.local"
        res = run["executor"].call(
            ident, "send_email", to=to_addr, subject="s", body="b",
            justification=just)
        rec = run["approvals"].get(res["approval_id"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_records([rec])
        rendered = buf.getvalue()
        # R8: the human-review rendering must show the RAW tool call + args,
        # provenance, and matched rule id.
        self.assertIn(
            to_addr, rendered,
            "T5/R8: approval queue display does not show the raw tool args "
            "(reviewer cannot see what would actually execute)",
        )
        first_line = rendered.strip().splitlines()[0]
        self.assertNotIn(
            just, first_line,
            "T5: approval queue display leads with the agent-supplied "
            "justification text (social-engineering surface)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
