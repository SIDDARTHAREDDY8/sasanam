"""Hardening round-13 regression tests: wave-14 findings F55-F58.

F55 (CRITICAL): break-glass entitlement is bound to the ONE
    deployment-provisioned session identity (provenance="provisioned",
    created at ToolExecutor construction), not to a mintable tuple.
    A mid-run mint_identity() of the registered operator tuple
    (provenance="minted") is refused at break_glass with an audited
    ``break_glass_refused`` entry; the provisioned identity still
    consumes. Without a provisioned session identity the pre-R13 dev
    behavior is unchanged.
F56 (HIGH):     lock-refusal audit coalescing is file-backed in the run
    dir, so executor rotation (fresh executor per sweep, multi-process
    sweeps) cannot reset the window: N fresh executors under a
    lock-path attack still produce a bounded number of
    ``approval_sweep_refused`` entries. State-file deletion degrades to
    a single re-audit, never an exception; the state file stays tiny.
F57 (HIGH):     break-glass single-use is enforced against the VERIFIED
    action log (``ticket_consumed`` event), not just the ticket store:
    restoring a pre-consume store snapshot cannot resurrect a consumed
    ticket. The ticket HMAC binds the used state (re-signed on consume),
    so flipping used=False without the keyring key fails verification.
    The F54 fork race still yields exactly one winner.
F58 (MEDIUM):   demo/attack_scenario.py computes its RESULT summary from
    measured verdict booleans — no hard-coded "4 blocked" literal, so a
    weakened policy honestly reports allowed attacks.
"""

import contextlib
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    SessionIdentityAlreadySetError,
    _read_verified_ticket_store,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.identity import (  # noqa: E402
    PrincipalRegistry,
    UnregisteredPrincipalError,
)
from gov.log import read_entries  # noqa: E402


def _queued(q, caller, policy_hash, tool="send_email", args=None):
    return q.queue(
        {"tool": tool,
         "args": args or {"to": "x@synthetic.local", "subject": "s",
                          "body": "b"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test preview",
        policy_hash=policy_hash,
        caller_identity=caller)


# The harness mints STANDARD_AGENTS at make_run() time; a strict test
# registry must authorize those too, or make_run itself is refused.
_HARNESS_PRINCIPALS = {
    "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
    "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
    "research-org": {"roles": ["researcher"], "agent_ids": ["researcher-1"]},
}

_OPERATOR_REGISTRY = PrincipalRegistry(dict(
    _HARNESS_PRINCIPALS,
    **{"ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
       "duty-reviewer": {"roles": ["reviewer"], "agent_ids": ["rev-1"]}}))


def _operator_run(**kwargs):
    """make_run with the operator registry, the provisioned session
    identity, and one operator ticket — the F55/F57 fixture."""
    kwargs.setdefault("principal_registry", _OPERATOR_REGISTRY)
    kwargs.setdefault("session_identity", ("op-1", "operator", "ops-lead"))
    kwargs.setdefault("break_glass_tickets",
                      [("T-OP", "ops-lead", "duty-reviewer")])
    return make_run(**kwargs)


# ---------------------------------------------------------------------------
# F55 — break-glass entitlement is the provisioned session identity.
# ---------------------------------------------------------------------------

class TestF55SessionIdentityEntitlement(unittest.TestCase):
    def test_midrun_mint_cannot_consume_operator_ticket(self):
        ctx = _operator_run()
        q, ex = ctx["approvals"], ctx["executor"]
        # Attacker: in-process code holding the executor mints the
        # REGISTERED operator tuple mid-run — the exact F55 scenario.
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        self.assertEqual(evil.provenance, "minted")
        aid = _queued(q, evil, ex.policy.policy_hash)
        with self.assertRaises(ValueError):
            q.break_glass(aid, "incident-9", operator_identity=evil,
                          ticket_id="T-OP")
        # Refusal is audited ...
        refused = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                   if e.get("event") == "break_glass_refused"]
        self.assertEqual(len(refused), 1)
        self.assertIn("F55", refused[0].get("reason", ""))
        # ... and the ticket is still unconsumed (usable by the real
        # operator afterwards).
        self.assertFalse(q._bg_ticket_snapshot["T-OP"]["used"])

    def test_provisioned_session_identity_consumes(self):
        ctx = _operator_run()
        q, ex = ctx["approvals"], ctx["executor"]
        good = ctx["session_identity"]
        self.assertEqual(good.provenance, "provisioned")
        aid = _queued(q, good, ex.policy.policy_hash)
        record, _ticket = q.break_glass(aid, "real incident",
                                        operator_identity=good,
                                        ticket_id="T-OP")
        self.assertEqual(record["status"], "approved")
        self.assertTrue(record.get("break_glass"))

    def test_no_session_identity_keeps_dev_behavior(self):
        # Without a provisioned session identity (dev / legacy mode) the
        # pre-R13 behavior is unchanged: a minted operator identity can
        # still consume a ticket.
        ctx = make_run(
            break_glass_tickets=[("T-DEV", "ops-lead", "duty-reviewer")])
        q, ex = ctx["approvals"], ctx["executor"]
        op = ctx["mint_identity"]("op-1", "operator", "ops-lead")
        aid = _queued(q, op, ex.policy.policy_hash)
        record, _ticket = q.break_glass(aid, "dev incident",
                                        operator_identity=op,
                                        ticket_id="T-DEV")
        self.assertEqual(record["status"], "approved")

    def test_session_identity_install_is_write_once(self):
        ctx = _operator_run()
        q = ctx["approvals"]
        other = ctx["executor"].mint_identity("op-1", "operator",
                                              "ops-lead")
        with self.assertRaises(SessionIdentityAlreadySetError):
            q.set_session_identity(other)
        # The original provisioned identity is untouched.
        self.assertIs(q._session_identity, ctx["session_identity"])

    def test_unregistered_session_identity_fails_closed(self):
        with self.assertRaises(UnregisteredPrincipalError):
            make_run(principal_registry=_OPERATOR_REGISTRY,
                     session_identity=("op-1", "operator", "intruder"))

    def test_provenance_distinguishes_mint_from_provisioned(self):
        ctx = _operator_run()
        ex = ctx["executor"]
        minted = ex.mint_identity("op-1", "operator", "ops-lead")
        provisioned = ctx["session_identity"]
        self.assertEqual(minted.provenance, "minted")
        self.assertEqual(provisioned.provenance, "provisioned")
        # Same tuple, different provenance -> NOT equal: tuple-equality
        # can no longer impersonate the operator.
        self.assertNotEqual(minted, provisioned)


# ---------------------------------------------------------------------------
# F56 — file-backed lock-refusal coalescing shared across executors.
# ---------------------------------------------------------------------------

class TestF56SharedRefusalCoalescing(unittest.TestCase):
    def _fresh(self, ctx):
        return ToolExecutor(ctx["run_dir"], ctx["policy"], ctx["log"],
                            ctx["approvals"])

    def _refused(self, ctx):
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"]

    def test_rotation_coalesces_across_instances(self):
        ctx = make_run()
        # Eight FRESH executors (rotation / multi-process), one refusal
        # each — the pre-R13 code would audit all eight.
        for i in range(8):
            self._fresh(ctx)._audit_lock_refusal("queue_lock_timeout",
                                                 "storm-%d" % i)
        self.assertLessEqual(len(self._refused(ctx)), 2)
        # The shared state folded the repeats.
        state = json.loads(
            (ctx["run_dir"] / "lock_refusal_coalesce.json")
            .read_text(encoding="utf-8"))
        self.assertGreaterEqual(
            state["queue_lock_timeout"]["suppressed"], 6)

    def test_single_executor_still_coalesces(self):
        ctx = make_run()
        ex = ctx["executor"]
        self.assertTrue(ex._audit_lock_refusal("queue_lock_timeout", "t1"))
        self.assertFalse(ex._audit_lock_refusal("queue_lock_timeout", "t2"))
        self.assertFalse(ex._audit_lock_refusal("queue_lock_timeout", "t3"))
        self.assertEqual(len(self._refused(ctx)), 1)
        # The legacy in-memory attrs mirror the shared state.
        self.assertEqual(ex._lock_refusal_suppressed, 2)

    def test_state_deletion_degrades_without_exception(self):
        ctx = make_run()
        ex = ctx["executor"]
        ex._audit_lock_refusal("queue_lock_timeout", "t1")
        self.assertEqual(len(self._refused(ctx)), 1)
        # Attacker deletes the state file mid-window: no exception, at
        # most one re-audit (the documented fail-closed residual), and
        # the state file is recreated.
        (ctx["run_dir"] / "lock_refusal_coalesce.json").unlink()
        try:
            self._fresh(ctx)._audit_lock_refusal("queue_lock_timeout",
                                                 "t2")
        except Exception as e:  # noqa: BLE001
            self.fail("state deletion raised: %r" % e)
        self.assertLessEqual(len(self._refused(ctx)), 2)
        self.assertTrue(
            (ctx["run_dir"] / "lock_refusal_coalesce.json").exists())

    def test_state_file_stays_tiny_and_bounded(self):
        ctx = make_run()
        for i in range(3):
            self._fresh(ctx)._audit_lock_refusal("queue_lock_timeout",
                                                 "x" * 5000)
        for flag in ("queue_lock_invalid", "queue_lock_invalidated"):
            self._fresh(ctx)._audit_lock_refusal(flag, "y" * 5000)
        state_path = ctx["run_dir"] / "lock_refusal_coalesce.json"
        raw = state_path.read_text(encoding="utf-8")
        # Long reasons never reach the state file; only the bounded set
        # of known flags is stored.
        self.assertLess(len(raw), 1024)
        state = json.loads(raw)
        self.assertLessEqual(set(state),
                             {"queue_lock_invalid", "queue_lock_invalidated",
                              "queue_lock_timeout"})
        for rec in state.values():
            self.assertEqual(set(rec), {"last_audit", "suppressed"})


# ---------------------------------------------------------------------------
# F57 — the verified action log is the authoritative consumed memory.
# ---------------------------------------------------------------------------

class TestF57TicketReplayResistance(unittest.TestCase):
    def _consumed(self, ctx, ticket_id="T-OP"):
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "ticket_consumed"
                and e.get("ticket_id") == ticket_id]

    def test_one_time_consume_then_refused(self):
        ctx = _operator_run()
        q, ex = ctx["approvals"], ctx["executor"]
        op = ctx["session_identity"]
        aid = _queued(q, op, ex.policy.policy_hash)
        q.break_glass(aid, "incident", operator_identity=op, ticket_id="T-OP")
        self.assertEqual(len(self._consumed(ctx)), 1)
        # Immediate reuse is refused (store check).
        aid2 = _queued(q, op, ex.policy.policy_hash)
        with self.assertRaises(ValueError):
            q.break_glass(aid2, "again", operator_identity=op,
                          ticket_id="T-OP")
        self.assertEqual(len(self._consumed(ctx)), 1)

    def test_replayed_preconsume_store_refused_by_log(self):
        ctx = _operator_run()
        q, ex = ctx["approvals"], ctx["executor"]
        op = ctx["session_identity"]
        store = q._ticket_store_path()
        pre_consume = store.read_bytes()
        aid = _queued(q, op, ex.policy.policy_hash)
        q.break_glass(aid, "incident", operator_identity=op, ticket_id="T-OP")
        self.assertEqual(len(self._consumed(ctx)), 1)
        # Attacker restores the pre-consume store snapshot AND drops the
        # in-process snapshot (fresh process / CLI path): the store
        # genuinely says "unused" again.
        store.write_bytes(pre_consume)
        q._bg_ticket_snapshot = None
        aid2 = _queued(q, op, ex.policy.policy_hash)
        with self.assertRaises(ValueError) as cm:
            q.break_glass(aid2, "incident-2", operator_identity=op,
                          ticket_id="T-OP")
        self.assertIn("verified action log", str(cm.exception))
        # Exactly one consumed marker; the refusal is audited.
        self.assertEqual(len(self._consumed(ctx)), 1)
        refused = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                   if e.get("event") == "break_glass_refused"
                   and e.get("ticket_id") == "T-OP"]
        self.assertEqual(len(refused), 1)

    def test_used_flip_without_resign_fails_hmac(self):
        ctx = _operator_run()
        q, ex = ctx["approvals"], ctx["executor"]
        op = ctx["session_identity"]
        aid = _queued(q, op, ex.policy.policy_hash)
        q.break_glass(aid, "incident", operator_identity=op, ticket_id="T-OP")
        # Attacker flips used=False on the consumed line but cannot
        # re-sign (no keyring key): the entry must fail verification.
        lines = []
        for line in q._ticket_store_path().read_text(
                encoding="utf-8").splitlines():
            e = json.loads(line)
            if isinstance(e, dict) and e.get("ticket_id") == "T-OP":
                e["used"] = False
                line = json.dumps(e)
            lines.append(line)
        q._ticket_store_path().write_text("\n".join(lines) + "\n",
                                          encoding="utf-8")
        valid = _read_verified_ticket_store(q._ticket_store_path())
        self.assertNotIn("T-OP", valid)

    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork()")
    def test_fork_race_still_single_winner(self):
        """The F54 fork race under the F57 log-authority: exactly one
        winner, exactly one ticket_consumed marker."""
        ctx = make_run(
            break_glass_tickets=[("T-FORK57", "human-op", "human-rev")])
        q, ex = ctx["approvals"], ctx["executor"]
        aids = [_queued(q, ctx["mint_identity"]("a%d" % i, "researcher",
                                                "org"),
                        ex.policy.policy_hash) for i in range(2)]
        r_ready, w_ready = os.pipe()
        r_go, w_go = os.pipe()
        pids = []
        try:
            for aid in aids:
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(r_ready)
                        os.close(w_go)
                        ident = ctx["mint_identity"](
                            "opchild", "operator", "human-op")
                        os.write(w_ready, b"R")
                        os.close(w_ready)
                        os.read(r_go, 1)
                        os.close(r_go)
                        q.break_glass(aid, "emergency now", ident,
                                      ticket_id="T-FORK57")
                        os._exit(0)
                    except ValueError:
                        os._exit(3)
                    except BaseException:  # noqa: BLE001
                        os._exit(9)
                pids.append(pid)
            os.close(w_ready)
            os.close(r_go)
            os.read(r_ready, 1)
            os.read(r_ready, 1)
            os.close(r_ready)
            os.write(w_go, b"G")
            os.write(w_go, b"G")
            os.close(w_go)
            codes = sorted(os.waitpid(p, 0)[1] >> 8 for p in pids)
        finally:
            for fd in (r_ready, w_ready, r_go, w_go):
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.assertEqual(codes, [0, 3])
        self.assertEqual(len(self._consumed(ctx, "T-FORK57")), 1)


# ---------------------------------------------------------------------------
# F58 — the demo RESULT line is computed from measured verdicts.
# ---------------------------------------------------------------------------

class TestF58HonestDemoSummary(unittest.TestCase):
    def test_summary_computed_from_verdicts(self):
        from demo.attack_scenario import summarize_results
        self.assertEqual(
            summarize_results([True, True, True, True], True),
            "RESULT: 4 attack attempts blocked, 0 allowed, "
            "1 tampering detected.")
        weakened = summarize_results([True, False, True, True], False)
        self.assertIn("1 allowed", weakened)
        self.assertNotIn("4 attack attempts blocked", weakened)
        self.assertNotIn("1 tampering detected", weakened)
        total_loss = summarize_results([False, False, False, False], False)
        self.assertIn("0 attack attempts blocked, 4 allowed", total_loss)

    def test_no_hardcoded_result_literal_in_demo(self):
        demo_path = (Path(__file__).resolve().parent.parent
                     / "demo" / "attack_scenario.py")
        src = demo_path.read_text(encoding="utf-8")
        self.assertNotIn('"RESULT: 4 attack attempts blocked', src)
        self.assertNotIn("'RESULT: 4 attack attempts blocked", src)
        # The summary helper exists and main() uses it.
        self.assertIn("def summarize_results", src)
        self.assertIn("summarize_results(blocked, tamper_detected)", src)


if __name__ == "__main__":
    unittest.main()
