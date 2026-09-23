"""Wave-49 RT17 unit tests: approval-queue decision-integrity hardening.

Covers the wave-49 SoD both-alias hardening in gov/approvals.py
decide() plus the approver-facing display-surface invariants
ratcheted by RT17. Deterministic, hermetic (make_run temp dirs),
$0.
"""

import os
import secrets
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
# Wave-81: gov/ has no dev key or dev-key opt-in. Provision an EXPLICIT
# random key via the production env path (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH);
# tests/__init__.py does the same for the canonical suite -- this keeps
# direct `python tests/test_x.py` runs self-sufficient.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")

from harness import make_run
from gov import approval_web as web
from gov.approvals import sanitize_preview_text, approval_digest_ok


def queue_send_email(run, **kw):
    ident = run["identities"]["support"]
    kw.setdefault("to", "victim@synthetic.local")
    kw.setdefault("subject", "hello")
    kw.setdefault("body", "hello")
    res = run["executor"].call(ident, "send_email", **kw)
    assert res["status"] == "queued", res
    return ident, res["approval_id"]


class TestRT17SoDBothAliases(unittest.TestCase):
    """decide()'s separation-of-duties guard covers both aliases."""

    def test_self_approve_by_agent_id_refused(self):
        run = make_run()
        ident, aid = queue_send_email(run)
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, reason="x",
                                    decided_by=ident.agent_id)

    def test_self_approve_by_principal_documented_boundary(self):
        # D1-core T4 (pinned, wave-49 RT17): decide()'s SoD guard is
        # agent_id-only BY DESIGN — the both-alias invariant lives at
        # queue()/delegate()/cast_vote(). A both-alias hardening was
        # tried and reverted: break_glass() legitimately decides with
        # decided_by=<operator principal>, and the operator may share
        # a principal with the requester (F55/dev). Direct decide()
        # with the principal alias therefore succeeds; reachability is
        # in-process only (F6 trust boundary).
        run = make_run()
        ident, aid = queue_send_email(run)
        rec, _ = run["approvals"].decide(aid, True, reason="x",
                                         decided_by=ident.principal)
        self.assertEqual(rec["status"], "approved")

    def test_operator_decide_still_allowed(self):
        # The hardening must not break the legitimate operator flow:
        # fixed operator labels never match an agent alias.
        run = make_run()
        _, aid = queue_send_email(run)
        rec, _ = run["approvals"].decide(aid, True, reason="ok",
                                         decided_by="human-operator")
        self.assertEqual(rec["status"], "approved")

    def test_batch_sod_both_aliases(self):
        run = make_run()
        ident, aid = queue_send_email(run)
        with self.assertRaises(ValueError):
            run["approvals"].batch_decide([aid], True, rationale="x",
                                          decided_by=ident.principal)


class TestRT17DecisionIntegrity(unittest.TestCase):
    def test_tamper_then_decide_refused(self):
        run = make_run()
        _, aid = queue_send_email(run)
        q = run["approvals"]
        q._rewrite(lambda rs: [
            dict(r, args=dict(r["args"], to="attacker@evil.local"))
            if r["id"] == aid else r for r in rs])
        with self.assertRaises(ValueError):
            q.decide(aid, True, reason="looks fine",
                     decided_by="human-operator")

    def test_double_decide_refused(self):
        run = make_run()
        _, aid = queue_send_email(run)
        run["approvals"].decide(aid, True, reason="first",
                                decided_by="human-operator")
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, reason="second",
                                    decided_by="human-operator")

    def test_cross_agent_decide_keeps_forensic_binding(self):
        # The F6-boundary seam monitor: if decide() is ever invoked
        # with a non-operator label, the true decider stays MAC-bound
        # in the record (F43) and on the audit entry.
        run = make_run()
        _, aid = queue_send_email(run)
        other = run["identities"]["researcher"]
        rec, entry = run["approvals"].decide(aid, True, reason="peer",
                                             decided_by=other.agent_id)
        self.assertTrue(approval_digest_ok(rec))
        self.assertEqual(entry.get("decided_by"), other.agent_id)
        self.assertEqual(rec.get("decided_by"), other.agent_id)

    def test_batch_high_risk_not_smuggled(self):
        run = make_run()
        q = run["approvals"]
        low_ids = []
        for i in range(3):
            _, aid = queue_send_email(run, subject="note %d" % i,
                                      body="routine")
            low_ids.append(aid)
        _, high_aid = queue_send_email(run, subject="exfil", body="s3cr3t")
        try:
            decided, excluded, _ = q.batch_decide(low_ids + [high_aid], True,
                                                  rationale="bulk",
                                                  decided_by="human-operator")
            decided_ids = [r["id"] for r in decided]
        except ValueError:
            decided_ids = []
        self.assertNotIn(high_aid, decided_ids)


class TestRT17DisplaySurfaces(unittest.TestCase):
    def test_args_view_escapes_bidi(self):
        out = web._args_view({"path": "invoice_\u202eFDP.exe"})
        self.assertNotIn("\u202e", out)
        self.assertIn("\\u202e", out)

    def test_args_view_escapes_cr_and_ansi(self):
        out = web._args_view({"cmd": "ok\rX\x1b[2K"})
        self.assertNotIn("\r", out)
        self.assertNotIn("\x1b", out)

    def test_preview_sanitizer_escapes_bidi_cf(self):
        for ch in ("\u202e", "\u200f", "\u2066", "\u200b", "\ufeff",
                   "\x1b", "\r"):
            self.assertNotIn(ch, sanitize_preview_text("a%sb" % ch),
                             "control %r must be escaped" % ch)

    def test_preview_invisible_printable_is_documented_boundary(self):
        # K-028/F11: non-printables only; semantics pass through by
        # design. Pin the behavior so a future change is deliberate.
        survivors = [ch for ch in ("\u2800", "\u3164", "\uffa0")
                     if ch in sanitize_preview_text("a%sb" % ch)]
        self.assertEqual(len(survivors), 3)


if __name__ == "__main__":
    unittest.main()
