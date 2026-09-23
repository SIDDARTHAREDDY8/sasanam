"""Wave-53 P1 unit tests: sterile-cockpit executor integration.

Pins workstreams/architect/STERILE_COCKPIT_INTEGRATION.md:
default-off zero behavior change, fail-closed policy load, window
entry/refusal through ToolExecutor.call(), unknown-tool fail-closed,
the window_close governance primitive (agent_declared + human_approval
via the approval queue), expiry, refusal telemetry, entry re-scan,
loop-contract degraded mode, and the R4 never-vetted invariant.

Deterministic, hermetic (make_run temp dirs), $0.
"""

import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_DEV_KEYS", "1")

from gov.log import enable_dev_keys  # noqa: E402
enable_dev_keys()

from harness import make_run  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.sterile import (  # noqa: E402
    SterilePolicyError, LoopContract, lint_windows)

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
    if kw.get("entry_rescan"):
        lines.append("    entry_rescan: true")
    if kw.get("refusal_alert_after") is not None:
        lines.append("    refusal_alert_after: %d"
                     % kw["refusal_alert_after"])
    return "\n".join(lines)


_REPO_ROOT = os.path.dirname(_TESTS_DIR)


def _run_with_windows(multi=None, **kw):
    with open(os.path.join(_REPO_ROOT, "policies", "default.yaml")) as f:
        base = f.read()
    blocks = "\n".join(_window_block(**w) for w in (multi or [kw]))
    path = tempfile.mktemp(suffix=".yaml", prefix="govw53-")
    with open(path, "w") as f:
        f.write(base + "\ncritical_windows:\n" + blocks + "\n")
    run = make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _log_events(run, name):
    from gov.log import read_entries
    return [e for e in read_entries(run["log"].path)
            if e.get("event") == name]


def _decide_all_pending(run, approve=True):
    """Decide every pending approval (test human)."""
    ex = run["executor"]
    for rec in ex.approvals.pending():
        ex.approvals.decide(rec["id"], approve, "test decision")


class FakeLoop(LoopContract):
    def __init__(self):
        self.reissued = None
        self.frozen = []      # snapshot_refs passed to freeze_context
        self.withheld = []    # channels withheld
        self.released = []    # channels released

    def freeze_context(self, snapshot_ref):
        self.frozen.append(snapshot_ref)
        return None

    def withhold(self, channel):
        self.withheld.append(channel)
        return None

    def release(self, channel):
        self.released.append(channel)
        return None

    def reissue_reads(self, reads):
        self.reissued = list(reads)
        return [{"tool": t, "channel": c, "result_summary": "reissued",
                 "delta_vs_snapshot": False} for t, c in reads]


class HalfLoop(LoopContract):
    """A half-implemented loop: withhold left as the base stub."""

    def freeze_context(self, snapshot_ref):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        return []


class TestDefaultOff(unittest.TestCase):
    def test_no_block_no_controller(self):
        run = make_run()
        ident = run["mint_identity"]("agent-1", "researcher", "op-1")
        self.assertIsNone(run["executor"].sterile)
        # Behavior identical to wave-52: reads and posts proceed.
        r = run["executor"].call(ident, "api_call",
                                endpoint="https://synthetic.local/v1",
                                params={"q": "x"})
        self.assertEqual(r["status"], "executed")

    def test_invalid_block_fails_closed_at_load(self):
        path = tempfile.mktemp(suffix=".yaml", prefix="govw53bad-")
        with open(path, "w") as f:
            f.write(_POLICY_TMPL % _window_block(suspend=["nope"]))
        with self.assertRaises(SterilePolicyError):
            PolicyEngine(path)


class TestEntryAndRefusal(unittest.TestCase):
    def test_enter_on_pattern_and_suspend(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        r = ex.call(ident, "http_post",
                    url="https://synthetic.local/x", data="d")
        # The default policy may queue http_post for approval — the
        # window opens on the attempt either way (critical intent).
        self.assertIn(r["status"], ("executed", "queued",
                                    "auto_approved_executed"))
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        enters = _log_events(run, "sterile_window_enter")
        self.assertEqual(len(enters), 1)
        self.assertEqual(enters[0]["window"], "pay")
        # Suspended channel refuses; the call never executes.
        r2 = ex.call(ident, "api_call",
                     endpoint="https://synthetic.local/v1",
                     params={"q": "x"})
        self.assertEqual(r2["status"], "window_suspended")
        self.assertEqual(r2["window"], "pay")
        refusals = _log_events(run, "window_suspended_refusal")
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["channel"], "web_fetch")

    def test_non_suspended_tool_proceeds(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        r = ex.call(ident, "send_email", to="op@synthetic.local",
                    subject="t", body="hello")
        # Not refused by the window (tool_result not suspended) — the
        # normal pipeline (queue/deny/execute) decides.
        self.assertNotEqual(r.get("status"), "window_suspended")
        self.assertEqual(ex.sterile.open_windows(), ["pay"])

    def test_unknown_tool_refused_fail_closed_in_window(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        r = ex.call(ident, "mystery_tool", x="1")
        self.assertEqual(r["status"], "window_suspended")
        self.assertEqual(r["channel"], "unknown_tool")
        # Outside a window the same unknown tool falls through to the
        # normal pipeline (role denial), not a sterile refusal.
        # (The trigger call queued an approval under the default
        # policy — decide it first: agent_declared close requires no
        # pending in-window approvals, integration §3.2.)
        _decide_all_pending(run)
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        r2 = ex.call(ident, "mystery_tool", x="1")
        self.assertNotEqual(r2.get("status"), "window_suspended")

    def test_window_close_tool_name_reserved(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        r = ex.call(ident, "window_close")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "sterile-reserved")
        denied = _log_events(run, "window_close_denied")
        self.assertTrue(any(d.get("reason") == "reserved_tool_name" or
                            "governance primitive" in d.get("reason", "")
                            for d in denied))


class TestClosePrimitive(unittest.TestCase):
    def test_agent_declared_close_with_reconcile(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"q": 1})
        # The trigger call queued an approval under the default
        # policy — decide it first: agent_declared close requires no
        # pending in-window approvals (integration §3.2).
        _decide_all_pending(run)
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        self.assertEqual(out["window"], "pay")
        # The refused read is listed for reconciliation...
        self.assertEqual(out["reconcile"], [("api_call", "web_fetch")])
        # ...and NEVER marked vetted (R4 invariant).
        self.assertFalse(out["reconciled_vetted"])
        self.assertEqual(ex.sterile.open_windows(), [])
        exits = _log_events(run, "sterile_window_exit")
        self.assertTrue(any(e.get("window") == "pay" and
                            e.get("reconciled_vetted") is False
                            for e in exits))
        # Channels resume after close.
        r = ex.call(ident, "api_call",
                    endpoint="https://synthetic.local/v1",
                    params={"q": "x"})
        self.assertEqual(r["status"], "executed")

    def test_close_no_window_denied(self):
        run, ident = _run_with_windows()
        out = run["executor"].request_window_close(ident)
        self.assertFalse(out["closed"])
        self.assertEqual(out["reason"], "no_window_open")

    def test_non_lifo_close_denied(self):
        # Real two-window policy (paper-review round 2: the old test
        # mutated controller internals instead of declaring two
        # windows).
        run, ident = _run_with_windows(multi=[
            {"id": "outer", "on_tools": ["http_post"],
             "suspend": ["web_fetch"], "rationale": "outer"},
            {"id": "inner", "on_tools": ["send_email"],
             "suspend": ["file_read"], "rationale": "inner"},
        ])
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "send_email", to="a@synthetic.local",
                subject="s", body="b")
        self.assertEqual(ex.sterile.open_windows(), ["outer", "inner"])
        out = ex.request_window_close(ident, window_id="outer")
        self.assertFalse(out["closed"])
        self.assertEqual(out["reason"], "not_innermost")

    def test_human_approval_round_trip(self):
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        q = ex.request_window_close(ident)
        self.assertFalse(q["closed"])
        self.assertEqual(q["status"], "queued")
        aid = q["approval_id"]
        # Presenting the still-pending approval does not close.
        q2 = ex.request_window_close(ident, approval_id=aid)
        self.assertFalse(q2["closed"])
        # Human approves; presenting the approved record closes.
        rec, _ = ex.approvals.decide(aid, True, "looks done")
        self.assertEqual(rec["status"], "approved")
        out = ex.request_window_close(ident, approval_id=aid)
        self.assertTrue(out["closed"])
        self.assertEqual(out["approval_id"], aid)
        self.assertEqual(ex.sterile.open_windows(), [])

    def test_human_approval_wrong_window_denied(self):
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        q = ex.request_window_close(ident)
        ex.approvals.decide(q["approval_id"], True, "ok")
        out = ex.request_window_close(ident, window_id="other",
                                      approval_id=q["approval_id"])
        self.assertFalse(out["closed"])

    def test_close_approval_post_decision_tamper_denied(self):
        # Wave-53 review: ApprovalQueue.get()/all() do NOT verify the
        # record MAC on read — the digest is verified at decide() time.
        # A post-decision rewrite of the queue file (e.g. laundering a
        # different decider) must fail closed at window close, same as
        # execute_approved(): _verify_close_approval verifies the
        # keyed digest (F34/F43 invariant).
        run, ident = _run_with_windows(close_policy="human_approval")
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        q = ex.request_window_close(ident)
        aid = q["approval_id"]
        ex.approvals.decide(aid, True, "looks done")
        # Tamper post-decision: rewrite the decider (MAC-covered field).
        def _tamper(records):
            for r in records:
                if r["id"] == aid:
                    r["decided_by"] = "agent-1"
            return records
        ex.approvals._rewrite(_tamper)
        out = ex.request_window_close(ident, approval_id=aid)
        self.assertFalse(out["closed"])
        self.assertIn("digest", out["reason"])
        self.assertNotEqual(ex.sterile.open_windows(), [])


class TestExpiryAndTelemetry(unittest.TestCase):
    def test_expiry_fail_closed(self):
        run, ident = _run_with_windows(max_duration_s=60)
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        expired = ex.sterile_tick(t=10 ** 12)
        self.assertEqual(expired, ["pay"])
        exits = _log_events(run, "sterile_window_exit")
        self.assertTrue(any(e.get("reason") == "expired" and
                            e.get("task") == "incomplete"
                            for e in exits))
        # Channels resume after expiry.
        r = ex.call(ident, "api_call",
                    endpoint="https://synthetic.local/v1",
                    params={"q": "x"})
        self.assertEqual(r["status"], "executed")

    def test_refusal_alert_threshold(self):
        run, ident = _run_with_windows(refusal_alert_after=1)
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"a": 1})
        self.assertEqual(_log_events(run, "window_refusal_rate_alert"),
                         [])
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"a": 2})
        alerts = _log_events(run, "window_refusal_rate_alert")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["window"], "pay")
        summary = ex.sterile_refusal_summary()
        self.assertEqual(summary["pay"]["refusals"], 2)
        self.assertEqual(summary["pay"]["enters"], 1)


class TestLoopContract(unittest.TestCase):
    def test_absent_loop_declared_in_audit(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        absent = _log_events(run, "loop_contract_absent")
        self.assertEqual(len(absent), 1)
        # Declared once per run, not once per call.
        ex.call(ident, "http_post", url="https://synthetic.local/y",
                data="d")
        self.assertEqual(len(_log_events(run, "loop_contract_absent")),
                         1)

    def test_loop_reissue_on_close(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        loop = FakeLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        self.assertEqual(_log_events(run, "loop_contract_absent"), [])
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"q": 1})
        _decide_all_pending(run)
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        self.assertEqual(loop.reissued, [("api_call", "web_fetch")])
        exits = _log_events(run, "sterile_window_exit")
        delta = [e for e in exits
                 if e.get("post_window_delta")]
        self.assertEqual(len(delta), 1)
        # R4: re-issued content is flagged, never marked vetted.
        self.assertFalse(delta[0]["reconciled_vetted"])

    def test_entry_rescan_flags_stale_stack_hit(self):
        run, ident = _run_with_windows(entry_rescan=True)
        ex = run["executor"]
        # White-box: pre-window delivered content the current stack
        # now judges sensitive.
        ex._read_contents.append("aws key AKIAIOSFODNN7EXAMPLE leaked")
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        hits = _log_events(run, "window_entry_rescan_hit")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["window"], "pay")
        # The content itself is never logged, only a hash prefix.
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(hits[0]))

    def test_entry_rescan_off_by_default(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex._read_contents.append("aws key AKIAIOSFODNN7EXAMPLE leaked")
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        self.assertEqual(_log_events(run, "window_entry_rescan_hit"),
                         [])


class TestLoopWiring(unittest.TestCase):
    """Paper-review round 2: the loop contract is actually wired.

    freeze_context/withhold on entry, release on close/expiry (union
    semantics for nested windows), snapshot_ref on the enter event,
    per-channel unenforceable declarations, agent_declared
    pending-approval check, half-loop rejection, and a single merged
    exit event.
    """

    def test_entry_freezes_context_and_withholds_owned_channels(self):
        run, ident = _run_with_windows(
            suspend=["web_fetch", "user_message"])
        ex = run["executor"]
        loop = FakeLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        # freeze_context called once, with a snapshot_ref carrying the
        # policy hash and a sane log-seq range.
        self.assertEqual(len(loop.frozen), 1)
        ref = loop.frozen[0]
        self.assertEqual(ref["policy_hash"], ex.policy.policy_hash)
        self.assertLessEqual(ref["log_seq_first"], ref["log_seq_last"])
        # Only the loop-owned channel is withheld; web_fetch is
        # executor-mediated and enforced by the gate itself.
        self.assertEqual(loop.withheld, ["user_message"])

    def test_enter_event_carries_snapshot_ref(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.attach_loop_contract(FakeLoop())
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        enters = _log_events(run, "sterile_window_enter")
        self.assertEqual(len(enters), 1)
        ref = enters[0]["snapshot_ref"]
        self.assertEqual(ref["policy_hash"], ex.policy.policy_hash)
        self.assertLessEqual(ref["log_seq_first"], ref["log_seq_last"])

    def test_close_releases_withheld_channels(self):
        run, ident = _run_with_windows(
            suspend=["web_fetch", "user_message"])
        ex = run["executor"]
        loop = FakeLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        _decide_all_pending(run)
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        self.assertEqual(loop.released, ["user_message"])

    def test_nested_windows_union_release(self):
        run, ident = _run_with_windows(multi=[
            {"id": "outer", "on_tools": ["http_post"],
             "suspend": ["user_message"], "rationale": "outer"},
            {"id": "inner", "on_tools": ["send_email"],
             "suspend": ["user_message", "skill_content"],
             "rationale": "inner"},
        ])
        ex = run["executor"]
        loop = FakeLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "send_email", to="a@synthetic.local",
                subject="s", body="b")
        # Inner entry withholds only skill_content: user_message is
        # already held by the outer window.
        self.assertEqual(loop.withheld, ["user_message",
                                         "skill_content"])
        _decide_all_pending(run)
        out = ex.request_window_close(ident, window_id="inner")
        self.assertTrue(out["closed"])
        # user_message still needed by outer — not released yet.
        self.assertEqual(loop.released, ["skill_content"])
        out = ex.request_window_close(ident, window_id="outer")
        self.assertTrue(out["closed"])
        self.assertEqual(loop.released, ["skill_content",
                                         "user_message"])

    def test_expiry_releases_and_reissues(self):
        run, ident = _run_with_windows(max_duration_s=60,
                                       suspend=["web_fetch",
                                                "user_message"])
        ex = run["executor"]
        loop = FakeLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"q": 1})
        expired = ex.sterile_tick(t=10 ** 12)
        self.assertEqual(expired, ["pay"])
        self.assertEqual(loop.released, ["user_message"])
        # Refused-during-window reads are re-issued through the loop,
        # never silently dropped — and never marked vetted (R4).
        self.assertEqual(loop.reissued, [("api_call", "web_fetch")])
        exits = _log_events(run, "sterile_window_exit")
        expired_exits = [e for e in exits
                         if e.get("reason") == "expired"]
        self.assertEqual(len(expired_exits), 1)
        ee = expired_exits[0]
        self.assertEqual(ee["task"], "incomplete")
        self.assertEqual(ee["reconcile"], [["api_call", "web_fetch"]])
        self.assertFalse(ee["reconciled_vetted"])
        self.assertEqual(ee["released_channels"], ["user_message"])
        self.assertTrue(ee["post_window_delta"])

    def test_agent_declared_close_denied_with_pending_approval(self):
        from gov.policy import PolicyDecision
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        aid = ex.approvals.queue(
            action={"tool": "write_file",
                    "args": {"path": "/tmp/synthetic-x"}},
            decision=PolicyDecision("require_approval", "test",
                                    policy_id="t"),
            policy_hash=ex.policy.policy_hash,
            caller_identity=ident)
        out = ex.request_window_close(ident)
        self.assertFalse(out["closed"])
        self.assertEqual(out["reason"], "pending_approval_in_window")
        # Both the trigger call's queued approval (default policy
        # requires approval for outbound sends) and the in-window
        # write_file approval block the close.
        self.assertIn(aid, out["approval_ids"])
        self.assertEqual(len(out["approval_ids"]), 2)
        denied = _log_events(run, "window_close_denied")
        self.assertTrue(any(
            e.get("window") == "pay" and
            e.get("reason", "").startswith("agent_declared close denied")
            for e in denied))
        # The window is still open — nothing was mutated.
        self.assertEqual(ex.sterile.open_windows(), ["pay"])
        # Once the human decides the pending approval, close proceeds.
        _decide_all_pending(run)
        out2 = ex.request_window_close(ident)
        self.assertTrue(out2["closed"])

    def test_half_implemented_loop_rejected(self):
        run, _ident = _run_with_windows()
        ex = run["executor"]
        with self.assertRaises(TypeError):
            ex.attach_loop_contract(HalfLoop())
        self.assertIsNone(ex._sterile_loop)

    def test_window_declared_unenforceable_per_channel(self):
        run, ident = _run_with_windows(
            suspend=["web_fetch", "user_message", "skill_content"])
        ex = run["executor"]
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        # Still exactly one loop_contract_absent per run...
        self.assertEqual(len(_log_events(run, "loop_contract_absent")),
                         1)
        # ...plus one per-channel unenforceable declaration for each
        # suspended loop-owned channel (not for executor-mediated
        # web_fetch, which the gate enforces itself).
        unenf = _log_events(run, "window_declared_unenforceable")
        self.assertEqual(sorted(e["channel"] for e in unenf),
                         ["skill_content", "user_message"])
        self.assertTrue(all(e["window"] == "pay" for e in unenf))

    def test_single_exit_event_on_close(self):
        run, ident = _run_with_windows()
        ex = run["executor"]
        ex.attach_loop_contract(FakeLoop())
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        _decide_all_pending(run)
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        exits = [e for e in _log_events(run, "sterile_window_exit")
                 if e.get("window") == "pay"]
        self.assertEqual(len(exits), 1)
        self.assertFalse(exits[0]["reconciled_vetted"])

    def test_loop_error_audited_not_silent(self):
        class FlakyLoop(FakeLoop):
            def withhold(self, channel):
                raise RuntimeError("loop blew up")

        run, ident = _run_with_windows(suspend=["user_message"])
        ex = run["executor"]
        loop = FlakyLoop()
        ex.attach_loop_contract(loop)
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        errs = _log_events(run, "loop_contract_error")
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0]["phase"], "withhold:user_message")
        # Executor-side enforcement still holds despite the loop
        # failure: the window is open and its gate refuses.
        self.assertEqual(ex.sterile.open_windows(), ["pay"])


class TestLint(unittest.TestCase):
    def test_lint_warns(self):
        block = [{"id": "w", "on_tools": ["payment.send"],
                  "suspend": [], "close_policy": "agent_declared",
                  "max_duration_s": 7200, "rationale": "r"}]
        warns = lint_windows(block, known_tools=["read_file"])
        self.assertTrue(any("suspends no channels" in w for w in warns))
        self.assertTrue(any("matches no known tool" in w for w in warns))
        self.assertTrue(any("agent_declared close over irreversible"
                            in w for w in warns))
        self.assertTrue(any("exceeds one hour" in w for w in warns))

    def test_lint_quiet_on_sane_block(self):
        block = [{"id": "w", "on_tools": ["http_post"],
                  "suspend": ["web_fetch"],
                  "close_policy": "human_approval",
                  "max_duration_s": 300, "rationale": "r"}]
        self.assertEqual(lint_windows(block, known_tools=["http_post"]),
                         [])


if __name__ == "__main__":
    unittest.main()
