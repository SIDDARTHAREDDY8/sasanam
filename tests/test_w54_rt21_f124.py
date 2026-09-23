"""Wave-54 RT21: F124 (window-close approval replay) closure tests + RT21
hardening pins.

F124: a human_approval window-close approval was not consumed on use —
an approved close approval could be re-presented to close a NEW entry
of the same window id in the same run with no fresh human decision
(probe rt21.c2). Fix: single-use consumption — the record is flagged
``window_close_consumed`` and re-MACed on successful close (F38/F57
pattern); a second presentation fails closed in _verify_close_approval.

RT21 a6: attaching the loop contract while windows are open now audits
``loop_contract_attached_with_windows_open`` (the open windows are NOT
retro-engaged; their entry-time unenforceable declarations stand).

Deterministic, hermetic (make_run temp dirs), $0.
"""

import os
import secrets
import sys
import tempfile
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

from harness import make_run  # noqa: E402
from gov.sterile import LoopContract  # noqa: E402
from gov.approvals import approval_digest_ok  # noqa: E402

_POLICY_TMPL = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
critical_windows:
%s
policies: []
"""


def _window_block(**kw):
    lines = ["  - id: %s" % kw.get("id", "pay")]
    lines.append('    on_tools: [%s]' % ", ".join(
        '"%s"' % p for p in kw.get("on_tools", ["http_post"])))
    lines.append("    suspend: [%s]" % ", ".join(
        kw.get("suspend", ["web_fetch"])))
    lines.append("    close_policy: %s" % kw.get("close_policy",
                                                "agent_declared"))
    lines.append("    max_duration_s: %s" % kw.get("max_duration_s", 300))
    lines.append('    rationale: "%s"' % kw.get("rationale", "test"))
    return "\n".join(lines)


_REPO_ROOT = os.path.dirname(_TESTS_DIR)


def _run_with_windows(multi=None, **kw):
    with open(os.path.join(_REPO_ROOT, "policies", "default.yaml")) as f:
        base = f.read()
    blocks = "\n".join(_window_block(**w) for w in (multi or [kw]))
    path = tempfile.mktemp(suffix=".yaml", prefix="govw54-")
    with open(path, "w") as f:
        f.write(base + "\ncritical_windows:\n" + blocks + "\n")
    run = make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _log_events(run, name):
    from gov.log import read_entries
    return [e for e in read_entries(run["log"].path)
            if e.get("event") == name]


def _approve_close(run, ident):
    """Queue a close, human-approve it, return the approval id."""
    ex = run["executor"]
    q = ex.request_window_close(ident)
    assert q.get("status") == "queued", q
    aid = q["approval_id"]
    ex.approvals.decide(aid, True, "looks done")
    return aid


class FakeLoop(LoopContract):
    def freeze_context(self, snapshot_ref):
        return None

    def withhold(self, channel):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        return []


class TestF124ReplayDenied(unittest.TestCase):
    def test_replay_old_approval_on_new_entry_denied(self):
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid = _approve_close(run, ident)
        out1 = ex.request_window_close(ident, approval_id=aid)
        self.assertTrue(out1["closed"], out1)
        # A new critical task opens the SAME window id again.
        ex.call(ident, "http_post", url="https://synthetic.local/z",
                data="d2")
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        # Re-presenting the old approval must NOT close.
        out2 = ex.request_window_close(ident, approval_id=aid)
        self.assertFalse(out2["closed"])
        self.assertIn("already used", out2["reason"])
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        denied = _log_events(run, "window_close_denied")
        self.assertTrue(any("already used" in d.get("reason", "")
                            for d in denied))

    def test_consumption_audited_and_digest_bound(self):
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid = _approve_close(run, ident)
        ex.request_window_close(ident, approval_id=aid)
        consumed = _log_events(run, "window_close_approval_consumed")
        self.assertEqual(len(consumed), 1)
        self.assertEqual(consumed[0]["approval_id"], aid)
        self.assertEqual(consumed[0]["window"], "pay")
        rec = ex.approvals.get(aid)
        self.assertTrue(rec.get("window_close_consumed"))
        # The re-MAC after consumption still verifies...
        self.assertTrue(approval_digest_ok(rec))
        # ...and flipping the flag back without the key breaks it.
        def _flip(records):
            for r in records:
                if r["id"] == aid:
                    r["window_close_consumed"] = False
            return records
        ex.approvals._rewrite(_flip)
        rec2 = ex.approvals.get(aid)
        self.assertFalse(approval_digest_ok(rec2))

    def test_fresh_approval_per_entry_still_works(self):
        # The fix must not break the legitimate flow: two window
        # entries, two separate human approvals, both close.
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid1 = _approve_close(run, ident)
        self.assertTrue(
            ex.request_window_close(ident, approval_id=aid1)["closed"])
        ex.call(ident, "http_post", url="https://synthetic.local/z",
                data="d2")
        aid2 = _approve_close(run, ident)
        self.assertNotEqual(aid1, aid2)
        out = ex.request_window_close(ident, approval_id=aid2)
        self.assertTrue(out["closed"], out)
        self.assertEqual(ex.sterile.open_windows(), [])

    def test_failed_close_does_not_burn_approval(self):
        run, ident = _run_with_windows(multi=[
            {"id": "pay", "on_tools": ["http_post"],
             "suspend": ["web_fetch"], "close_policy": "human_approval",
             "rationale": "p"},
            {"id": "pay2", "on_tools": ["send_email"],
             "suspend": ["web_fetch"], "close_policy": "human_approval",
             "rationale": "p2"},
        ])
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid = _approve_close(run, ident)
        # Present for the wrong window: denied, approval NOT consumed.
        bad = ex.request_window_close(ident, window_id="other",
                                      approval_id=aid)
        self.assertFalse(bad["closed"])
        rec = ex.approvals.get(aid)
        self.assertFalse(rec.get("window_close_consumed"))
        # The same approval still closes the right window.
        out = ex.request_window_close(ident, window_id="pay",
                                      approval_id=aid)
        self.assertTrue(out["closed"], out)

    def test_agent_declared_close_unaffected(self):
        # agent_declared closes never touch approvals: no consumption
        # events, no behavior change.
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        for rec in ex.approvals.pending():
            ex.approvals.decide(rec["id"], True, "ok")
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        self.assertEqual(_log_events(run,
                                    "window_close_approval_consumed"),
                         [])


class TestLateAttachAudit(unittest.TestCase):
    def test_attach_with_open_windows_audited(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        ex.attach_loop_contract(FakeLoop())
        evs = _log_events(run, "loop_contract_attached_with_windows_open")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["windows"], ["pay"])

    def test_attach_before_any_window_no_extra_audit(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.attach_loop_contract(FakeLoop())
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        self.assertEqual(
            _log_events(run, "loop_contract_attached_with_windows_open"),
            [])

    def test_consumption_failure_is_loud_not_silent(self):
        # F124 ordering residual: if the queue rewrite fails AFTER the
        # window is closed, the approval stays unconsumed. That must
        # land a LOUD audit event and fail closed — never silently.
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid = _approve_close(run, ident)
        real_rewrite = ex.approvals._rewrite

        def _boom(records_fn):
            raise IOError("disk full (simulated)")

        ex.approvals._rewrite = _boom
        try:
            with self.assertRaises(IOError):
                ex.request_window_close(ident, approval_id=aid)
        finally:
            ex.approvals._rewrite = real_rewrite
        # The window IS closed (controller already closed it)...
        self.assertEqual(ex.sterile.open_windows(), [])
        # ...the approval is NOT consumed...
        self.assertFalse(
            (ex.approvals.get(aid) or {}).get("window_close_consumed"))
        # ...but the failure is LOUD in the audit log, naming the
        # suspect approval.
        failed = _log_events(
            run, "window_close_approval_consumption_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["approval_id"], aid)
        self.assertEqual(failed[0]["window"], "pay")
        self.assertIn("disk full", failed[0]["reason"])
        # And no consumption event was emitted.
        self.assertEqual(
            _log_events(run, "window_close_approval_consumed"), [])


if __name__ == "__main__":
    unittest.main()
