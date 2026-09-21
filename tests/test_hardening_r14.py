"""Hardening round-14 regression tests: wave-15 findings F59-F64.

F59 (CRITICAL): the session-identity anchor is a READ-ONLY property
    (no setter) on ApprovalQueue — casual ``q._session_identity = X``
    raises AttributeError instead of silently swapping the break-glass
    entitlement anchor. break_glass compares with TRUE OBJECT
    IDENTITY (``is``): a separately minted identity with identical
    (agent_id, role, principal) fields (provenance="minted") is
    refused even though it compares structurally equal. The
    provisioned object still consumes.
F60 (HIGH):     a corruption/deletion loop on the shared coalescing
    state file no longer re-audits every sweep: missing/corrupt state
    derives the suppression decision from the tamper-evident action
    log (a recent refusal for the flag means "already audited") while
    the sweep still refuses fail-closed. Clean state is rewritten
    best-effort; ordinary first-audit/coalescing behavior is
    unchanged.
F61 (MEDIUM):   the human decision view shows the FULL canonical args
    (never truncated) plus args_sha256 over the exact bytes the
    digest covers — in list output and before every approve/reject,
    batch, and break-glass decision. A marker past the old 400-char
    cut is visible verbatim.
F62 (HIGH):     the real LangChain shim preserves undeclared kwargs
    (extra="allow") into mediation — a credential smuggled in ``bcc``
    is denied by DLP, never silently clean-queued. The real OpenAI
    loop shims fails fast on denial (on_denied="raise"), matching the
    provisional ["denied"] shape.
F63 (HIGH):     malformed action-log lines (non-JSON, or valid JSON
    that is not an object) no longer crash sweeps: reconciliation
    skips-and-counts them (audited once per newly observed count)
    and verifies the signed chain of the valid entries tolerantly;
    the default verifier stays fail-closed (F28). The demo prints an
    honest RESULT: FAILURE summary and returns nonzero on unexpected
    exceptions instead of dying with no RESULT line.
F64 (MEDIUM):   break_glass in registry mode WITHOUT a provisioned
    session identity warns LOUDLY (stderr + audited
    break_glass_unprotected entry, once per queue) instead of taking
    the weak pre-R13 path silently. With a session identity, no
    warning is emitted.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    _canonical_dumps,
    _print_decision_target,
    _print_records,
)
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.log import (  # noqa: E402
    _verify,
    read_entries,
    read_entries_with_stats,
)
from gov.policy import PolicyEngine  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def _registry():
    return PrincipalRegistry({
        "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
        "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
        "research-org": {"roles": ["researcher"],
                         "agent_ids": ["researcher-1"]},
        "ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
        "duty-reviewer": {"roles": ["reviewer"],
                          "agent_ids": ["rev-1"]},
    })


def _tickets():
    return [("T-OP", "ops-lead", "duty-reviewer")]


def _queue_api_call(ctx, caller, args):
    q, ex = ctx["approvals"], ctx["executor"]
    return q.queue(
        {"tool": "api_call", "args": args, "redactions": [],
         "agent_justification": "r14 test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="endpoint only", policy_hash=ex.policy.policy_hash,
        caller_identity=caller)


class TestF59IdentityAnchor(unittest.TestCase):
    def _ctx(self):
        return make_run(principal_registry=_registry(),
                        break_glass_tickets=_tickets(),
                        session_identity=("op-1", "operator", "ops-lead"))

    def test_assignment_to_anchor_raises(self):
        ctx = self._ctx()
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        with self.assertRaises(AttributeError):
            q._session_identity = evil
        # The anchor is untouched: still the provisioned object.
        self.assertIs(q._session_identity, ctx["session_identity"])

    def test_structurally_equal_mint_refused_by_identity(self):
        ctx = self._ctx()
        q = ctx["approvals"]
        evil = ctx["executor"].mint_identity("op-1", "operator",
                                             "ops-lead")
        self.assertEqual(
            (evil.agent_id, evil.role, evil.principal),
            (ctx["session_identity"].agent_id,
             ctx["session_identity"].role,
             ctx["session_identity"].principal))
        aid = _queue_api_call(ctx, evil, {"endpoint": "https://e.local",
                                          "params": {}})
        with self.assertRaises(ValueError):
            q.break_glass(aid, "x", operator_identity=evil,
                          ticket_id="T-OP")

    def test_provisioned_object_still_consumes(self):
        ctx = self._ctx()
        q = ctx["approvals"]
        prov = ctx["session_identity"]
        aid = _queue_api_call(ctx, prov, {"endpoint": "https://e.local",
                                          "params": {}})
        rec, _ = q.break_glass(aid, "x", operator_identity=prov,
                               ticket_id="T-OP")
        self.assertEqual(rec["status"], "approved")
        self.assertTrue(rec.get("break_glass"))

    def test_anchor_docstring_documents_residual(self):
        doc = type(
            make_run()["approvals"])._session_identity.__doc__
        self.assertIn("object.__setattr__", doc)


class TestF60CoalescingCorruptionLoop(unittest.TestCase):
    def _sweep_run(self, disturb, n=8):
        from evals.w15_probes import _fresh_executor  # local import: evals
        policy = PolicyEngine(str(REPO_ROOT / "policies" / "default.yaml"))
        run_dir = Path(tempfile.mkdtemp(prefix="r14t60-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            run_dir, ignore_errors=True))
        (run_dir / "approvals.lock").mkdir()
        for _ in range(n):
            disturb(run_dir)
            done = _fresh_executor(run_dir, policy).execute_approved()
            self.assertEqual(done, [])  # every sweep refuses fail-closed
        return [e for e in read_entries(run_dir / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"
                and e.get("flag") == "queue_lock_invalid"]

    def test_corrupt_state_loop_bounded_audits(self):
        entries = self._sweep_run(
            lambda rd: (rd / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8"))
        self.assertLessEqual(len(entries), 1)

    def test_missing_state_loop_bounded_audits(self):
        entries = self._sweep_run(
            lambda rd: (rd / "lock_refusal_coalesce.json").unlink(
                missing_ok=True))
        self.assertLessEqual(len(entries), 1)

    def test_undisturbed_first_audit_and_coalescing_unchanged(self):
        entries = self._sweep_run(lambda rd: None)
        self.assertEqual(len(entries), 1)

    def test_poisoned_log_plus_unusable_state_does_not_crash(self):
        # F63 x F60 interaction: a malformed action-log line combined
        # with a missing coalescing sidecar must not crash the sweep
        # (the suppression check skips malformed lines, fail-loud).
        from evals.w15_probes import _fresh_executor
        policy = PolicyEngine(str(REPO_ROOT / "policies" / "default.yaml"))
        run_dir = Path(tempfile.mkdtemp(prefix="r14t60x-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            run_dir, ignore_errors=True))
        (run_dir / "approvals.lock").mkdir()
        (run_dir / "actions.jsonl").write_text("THIS IS NOT JSON\n",
                                               encoding="utf-8")
        for _ in range(2):
            done = _fresh_executor(run_dir, policy).execute_approved()
            self.assertEqual(done, [])  # refuses fail-closed, no crash
        entries, n_malformed = read_entries_with_stats(
            run_dir / "actions.jsonl")
        self.assertEqual(n_malformed, 1)
        refusals = [e for e in entries
                    if e.get("event") == "approval_sweep_refused"]
        self.assertEqual(len(refusals), 1)


class TestF61HumanView(unittest.TestCase):
    MARKER = "MARKER_PAST_CUT_9f2c"

    def _ctx_with_long_args(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        ident = ctx["mint_identity"]("support-1", "support",
                                     "customer-org")
        args = {"endpoint": "https://api.synthetic.local/v1/run",
                "params": {"payload": "x" * 560 + self.MARKER + "y" * 200,
                           "mode": "live"}}
        aid = _queue_api_call(ctx, ident, args)
        rec = [r for r in q.all() if r["id"] == aid][0]
        return ctx, rec, args

    def test_full_args_and_hash_in_list_view(self):
        ctx, rec, args = self._ctx_with_long_args()
        canon = _canonical_dumps(args)
        self.assertGreater(canon.index(self.MARKER), 587)
        expected = sha256(canon.encode("utf-8")).hexdigest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_records([rec], ctx["approvals"])
        out = buf.getvalue()
        self.assertIn(self.MARKER, out)  # verbatim, past the old cut
        self.assertIn("args_sha256: " + expected, out)

    def test_decision_target_renderer_matches_canonical_bytes(self):
        _, rec, args = self._ctx_with_long_args()
        canon = _canonical_dumps(args)
        expected = sha256(canon.encode("utf-8")).hexdigest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_decision_target(rec)
        out = buf.getvalue()
        self.assertIn(canon, out)
        self.assertIn("args_sha256: " + expected, out)

    def test_cli_approve_redisplays_target_before_decision(self):
        from gov.approvals import main
        ctx, rec, _ = self._ctx_with_long_args()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--rundir", str(ctx["run_dir"]), "approve",
                       rec["id"], "--reason", "r14 test"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertLess(out.index(self.MARKER),
                        out.index("Approved approval"))


class TestF62AdapterDivergence(unittest.TestCase):
    def _shim(self, real, name):
        from evals.provisional_adapters import (
            ADAPTER_CLASSES, DEFAULT_MCP_REGISTRY)
        from evals.real_adapters import REAL_ADAPTER_CLASSES
        ctx = make_run()
        ident = ctx["identities"]["support"]
        cls = (REAL_ADAPTER_CLASSES if real else ADAPTER_CLASSES)[name]
        return ctx, cls(ctx["executor"], ident,
                        registry=dict(DEFAULT_MCP_REGISTRY))

    def test_real_langchain_bcc_credential_reaches_dlp(self):
        # AWS-docs example key: synthetic, triggers the DLP pattern.
        kw = {"to": "x@synthetic.local", "subject": "s", "body": "routine",
              "bcc": "AKIAIOSFODNN7EXAMPLE"}
        ctx, real = self._shim(True, "langchain")
        r = real.call("send_email", **kw)
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "dlp-credential-block")

    def test_provisional_langchain_unchanged(self):
        kw = {"to": "x@synthetic.local", "subject": "s", "body": "routine",
              "bcc": "AKIAIOSFODNN7EXAMPLE"}
        _, prov = self._shim(False, "langchain")
        r = prov.call("send_email", **kw)
        self.assertEqual((r["status"], r["policy_id"]),
                         ("denied", "dlp-credential-block"))

    def test_real_openai_loop_fails_fast(self):
        turn = [{"name": "send_email",
                 "arguments": {"to": "x@attacker.example", "subject": "s",
                               "body": "routine"}},
                {"name": "read_file",
                 "arguments": {"path": "notes.txt"}}]
        _, real = self._shim(True, "openai-loop")
        self.assertEqual([r["status"] for r in real.run_tool_calls(turn)],
                         ["denied"])
        _, prov = self._shim(False, "openai-loop")
        self.assertEqual([r["status"] for r in prov.run_tool_calls(turn)],
                         ["denied"])


class TestF63MalformedLogLines(unittest.TestCase):
    def _poisoned_run(self):
        from evals.w15_probes import _fresh_executor
        policy = PolicyEngine(str(REPO_ROOT / "policies" / "default.yaml"))
        run_dir = Path(tempfile.mkdtemp(prefix="r14t63-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(
            run_dir, ignore_errors=True))
        ex = _fresh_executor(run_dir, policy)
        self.assertEqual(ex.execute_approved(), [])
        with open(run_dir / "actions.jsonl", "a",
                  encoding="utf-8") as f:
            f.write("THIS IS NOT JSON\n[1,2]\n")
        return run_dir, policy

    def test_sweep_survives_poison_and_audits_skip_once(self):
        from evals.w15_probes import _fresh_executor
        run_dir, policy = self._poisoned_run()
        for _ in range(3):
            ex = _fresh_executor(run_dir, policy)
            self.assertEqual(ex.execute_approved(), [])
        entries, n = read_entries_with_stats(run_dir / "actions.jsonl")
        self.assertEqual(n, 2)
        skips = [e for e in entries
                 if e.get("event") == "action_log_malformed_lines_skipped"]
        self.assertEqual(len(skips), 1)
        self.assertEqual(skips[0]["malformed_count"], 2)

    def test_default_verify_still_fail_closed(self):
        run_dir, _ = self._poisoned_run()
        v = _verify(str(run_dir / "actions.jsonl"))
        self.assertFalse(v["ok"])

    def test_tolerant_verify_strict_on_valid_chain(self):
        run_dir, _ = self._poisoned_run()
        v = _verify(str(run_dir / "actions.jsonl"),
                    _skip_malformed=True)
        self.assertTrue(v["ok"])
        self.assertEqual(v["malformed_skipped"], 2)
        # Tampering a VALID entry still fails closed in tolerant mode.
        lines = (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e, dict):
                e["reason"] = (e.get("reason") or "") + " [forged]"
                lines[i] = json.dumps(e)
                break
        (run_dir / "actions.jsonl").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")
        v2 = _verify(str(run_dir / "actions.jsonl"),
                     _skip_malformed=True)
        self.assertFalse(v2["ok"])

    def test_genuine_interrupted_claim_reconciles_under_poison(self):
        from evals.w15_probes import _fresh_executor
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        ident = ctx["mint_identity"]("support-1", "support",
                                     "customer-org")
        aid = q.queue(
            {"tool": "read_file", "args": {"path": "notes.txt"},
             "redactions": [], "agent_justification": "t"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="t", policy_hash=ex.policy.policy_hash,
            caller_identity=ident)
        q.decide(aid, True, "ok", decided_by="human-op")
        with mock.patch.object(ex, "_simulate",
                               side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                ex.execute_approved()
        with open(ctx["run_dir"] / "actions.jsonl", "a",
                  encoding="utf-8") as f:
            f.write("NOT JSON\n")
        policy = PolicyEngine(str(REPO_ROOT / "policies" / "default.yaml"))
        ex2 = _fresh_executor(ctx["run_dir"], policy)
        self.assertEqual(ex2.execute_approved(), [])
        rec = [r for r in ex2.approvals.all() if r["id"] == aid][0]
        self.assertEqual(rec["status"], "pending")
        self.assertFalse(rec.get("executed"))
        self.assertIn("MAY ALREADY HAVE",
                      rec.get("execution_interrupted_warning", ""))
        entries, _ = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        self.assertEqual(
            sum(1 for e in entries
                if e.get("event") == "approval_execution_interrupted"), 1)

    def test_demo_failure_is_honest_and_nonzero(self):
        import demo.attack_scenario as atk
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with mock.patch.object(atk, "_run_demo",
                                   side_effect=RuntimeError("boom")):
                rc = atk.main()
        out = buf.getvalue()
        self.assertEqual(rc, 1)
        results = [l for l in out.splitlines()
                   if l.startswith("RESULT:")]
        self.assertEqual(len(results), 1)
        self.assertIn("FAILURE", results[0])
        self.assertIn("no successful outcome is claimed", out)


class TestF64RegistryWeakMode(unittest.TestCase):
    def _break_glass_once(self, ctx):
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        aid = q.queue(
            {"tool": "send_email",
             "args": {"to": "x@synthetic.local"},
             "redactions": [], "agent_justification": "t"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="t", policy_hash=ex.policy.policy_hash,
            caller_identity=evil)
        return q, aid, evil

    def test_registry_without_session_identity_warns_loudly(self):
        ctx = make_run(principal_registry=_registry(),
                       break_glass_tickets=_tickets())
        q, aid, evil = self._break_glass_once(ctx)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _ = q.break_glass(aid, "x", operator_identity=evil,
                                   ticket_id="T-OP")
        self.assertIn("GOVERNANCE WARNING", err.getvalue())
        self.assertIn("WITHOUT identity entitlement checks",
                      err.getvalue())
        # The weak-mode residual is documented AND audited...
        entries, _ = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        warned = [e for e in entries
                  if e.get("event") == "break_glass_unprotected"]
        self.assertEqual(len(warned), 1)
        # ...and the warning fires only once per queue.
        evil2 = ctx["executor"].mint_identity("op-1", "operator",
                                              "ops-lead")
        q2aid = q.queue(
            {"tool": "send_email",
             "args": {"to": "x@synthetic.local"},
             "redactions": [], "agent_justification": "t"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="t", policy_hash=ctx["executor"].policy.policy_hash,
            caller_identity=evil2)
        err2 = io.StringIO()
        with contextlib.redirect_stderr(err2):
            with self.assertRaises(ValueError):
                q.break_glass(q2aid, "x", operator_identity=evil2,
                              ticket_id="T-OP")  # ticket already consumed
        self.assertEqual(err2.getvalue(), "")

    def test_with_session_identity_no_warning(self):
        ctx = make_run(principal_registry=_registry(),
                       break_glass_tickets=_tickets(),
                       session_identity=("op-1", "operator", "ops-lead"))
        q = ctx["approvals"]
        prov = ctx["session_identity"]
        aid = q.queue(
            {"tool": "send_email",
             "args": {"to": "x@synthetic.local"},
             "redactions": [], "agent_justification": "t"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="t", policy_hash=ctx["executor"].policy.policy_hash,
            caller_identity=prov)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _ = q.break_glass(aid, "x", operator_identity=prov,
                                   ticket_id="T-OP")
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(rec["status"], "approved")
        entries, _ = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        self.assertEqual(
            sum(1 for e in entries
                if e.get("event") == "break_glass_unprotected"), 0)


if __name__ == "__main__":
    unittest.main()
