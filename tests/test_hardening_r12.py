"""Hardening round-12 regression tests: wave-13 findings F50-F54.

F50 (CRITICAL): the principal registry is a real identity trust anchor —
    each principal maps to the roles (and optionally agent_ids) it may
    mint. Unregistered (principal, role) pairs are refused AND audited
    (``identity_mint_refused``); refusals never consume mint budget. With
    no registry, dev mode still mints but discloses self-assertion loudly
    (one stderr warning per process).
F51 (HIGH):     a non-file at the approval-queue lock path (e.g. a
    directory) is a fail-closed AUDITED refusal (``queue_lock_invalid``),
    never an uncaught IsADirectoryError; repeated lock refusals are
    audit-coalesced so an unlink loop cannot flood the tamper-evident log.
F52 (HIGH):     interrupted-execution reconciliation verifies the
    action-log chain before trusting any execution_authorized marker; a
    forged marker yields an audited ``reconciliation_marker_invalid``
    refusal (no reconciliation, no interruption), while genuine
    interrupted markers still reconcile to pending.
F53 (MEDIUM):   the policy pin hashes and parses the SAME single read of
    the policy file — no TOCTOU window between pinning and parsing.
F54 (HIGH):     break-glass ticket consumption holds an exclusive
    cross-process flock across resolve -> validate -> decide -> consume,
    and re-checks the LIVE ticket store inside the lock: a fork race for
    one ticket yields exactly one winner.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import make_run, DEFAULT_POLICY  # noqa: E402
import gov.identity as identity_mod  # noqa: E402
from gov.approvals import (  # noqa: E402
    QueueLockError,
    QueueLockPathError,
)
from gov.identity import (  # noqa: E402
    PrincipalRegistry,
    UnregisteredPrincipalError,
    UnregisteredRoleError,
)
from gov.log import read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402


def _queued(q, caller, policy_hash, tool="read_file", args=None):
    return q.queue(
        {"tool": tool, "args": args or {"path": "notes.txt"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test preview",
        policy_hash=policy_hash,
        caller_identity=caller)


def _refused(ents):
    return [e for e in ents
            if e.get("event") == "approval_sweep_refused"]


# The harness mints STANDARD_AGENTS at make_run() time; a strict test
# registry must authorize those too, or make_run itself is refused.
_HARNESS_PRINCIPALS = {
    "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
    "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
    "research-org": {"roles": ["researcher"],
                     "agent_ids": ["researcher-1"]},
}


def _registry(extra):
    merged = dict(_HARNESS_PRINCIPALS)
    merged.update(extra)
    return PrincipalRegistry(merged)


# ---------------------------------------------------------------------------
# F50 — the registry is a real identity trust anchor.
# ---------------------------------------------------------------------------

class TestF50IdentityTrustAnchor(unittest.TestCase):
    def test_unregistered_role_refused_and_audited(self):
        reg = _registry(
            {"victim-org": {"roles": ["researcher"],
                            "agent_ids": ["victim-agent"]}})
        ctx = make_run(principal_registry=reg)
        ex = ctx["executor"]
        before = ex._mint_count
        with self.assertRaises(UnregisteredRoleError):
            ex.mint_identity("evil-agent", "coder", "victim-org")
        # The refusal never consumes mint budget.
        self.assertEqual(ex._mint_count, before)
        refused = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                   if e.get("event") == "identity_mint_refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["decision"], "refused")
        self.assertEqual(refused[0]["role"], "coder")

    def test_unregistered_agent_id_refused(self):
        reg = _registry(
            {"victim-org": {"roles": ["researcher"],
                            "agent_ids": ["victim-agent"]}})
        ctx = make_run(principal_registry=reg)
        # Agent-id violations raise UnregisteredPrincipalError — the
        # DISTINCT UnregisteredRoleError is reserved for role
        # violations, so operators can tell the two apart.
        with self.assertRaises(UnregisteredPrincipalError) as cm:
            ctx["executor"].mint_identity("other-agent", "researcher",
                                          "victim-org")
        self.assertNotIsInstance(cm.exception, UnregisteredRoleError)

    def test_registered_pair_mints_and_audits(self):
        reg = _registry(
            {"victim-org": {"roles": ["researcher"],
                            "agent_ids": ["victim-agent"]}})
        ctx = make_run(principal_registry=reg)
        ident = ctx["executor"].mint_identity("victim-agent", "researcher",
                                              "victim-org")
        self.assertEqual((ident.agent_id, ident.role, ident.principal),
                         ("victim-agent", "researcher", "victim-org"))
        minted = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                  if e.get("event") == "identity_minted"]
        self.assertTrue(
            any(e.get("agent_id") == "victim-agent" for e in minted))

    def test_registry_blocks_researcher_to_coder_escalation(self):
        """The F50 attack: a researcher minting a coder identity for the
        same principal to reach write_file is refused at issuance."""
        reg = _registry({"victim-org": {"roles": ["researcher"]}})
        ctx = make_run(principal_registry=reg)
        ok = ctx["mint_identity"]("victim-agent", "researcher", "victim-org")
        self.assertEqual(ok.role, "researcher")
        with self.assertRaises(UnregisteredRoleError):
            ctx["executor"].mint_identity("evil-agent", "coder",
                                           "victim-org")

    def test_unknown_principal_still_refused_as_principal_error(self):
        reg = _registry({"victim-org": {"roles": ["researcher"]}})
        ctx = make_run(principal_registry=reg)
        with self.assertRaises(UnregisteredPrincipalError):
            ctx["executor"].mint_identity("a", "researcher", "fresh-org")

    def test_role_error_is_a_principal_error(self):
        """Back-compat: handlers catching UnregisteredPrincipalError keep
        catching registry refusals."""
        self.assertTrue(
            issubclass(UnregisteredRoleError, UnregisteredPrincipalError))

    def test_legacy_set_form_means_unrestricted_roles(self):
        """The F17b set form keeps its old meaning: principals with no
        role/agent_id restrictions."""
        reg = PrincipalRegistry({"org"})
        self.assertTrue(reg.check_identity("org", "any-role", "any-id"))
        self.assertIsNone(reg.allowed_roles("org"))

    def test_dev_mode_warns_once_and_still_mints(self):
        """No registry: minting still works (permissive demo default) but
        the self-assertion is disclosed loudly, once per process."""
        ctx = make_run()
        identity_mod._self_asserted_warned = False
        try:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                i1 = ctx["mint_identity"]("a1", "researcher", "org")
                i2 = ctx["mint_identity"]("a2", "coder", "org")
            self.assertEqual(i1.agent_id, "a1")
            self.assertEqual(i2.role, "coder")
            self.assertEqual(buf.getvalue().count("SELF-ASSERTED"), 1)
        finally:
            identity_mod._self_asserted_warned = False


# ---------------------------------------------------------------------------
# F51 — the lock path itself is fail-closed and audited.
# ---------------------------------------------------------------------------

class TestF51LockPathHardening(unittest.TestCase):
    def _approved(self, ctx, tool="read_file"):
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued(q, caller, ex.policy.policy_hash, tool=tool)
        q.decide(aid, True, "human says ok", decided_by="human-operator")
        return aid

    def test_directory_at_lock_path_refused_and_audited(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(ctx)
        lockp = q._lock_path()
        lockp.unlink(missing_ok=True)
        lockp.mkdir()
        try:
            # F51 final spec: a directory (or any non-file) at the lock
            # path is absorbed as an empty sweep — no exception escapes,
            # the refusal is audited exactly once.
            self.assertEqual(ex.execute_approved(), [])
            self.assertEqual(ex.execute_approved(), [])
            evts = [e for e in _refused(
                read_entries(ctx["run_dir"] / "actions.jsonl"))
                if e.get("flag") == "queue_lock_invalid"]
            self.assertEqual(len(evts), 1)
            rec = q.get(aid)
            self.assertIsNot(rec.get("executed"), True)
            self.assertEqual(rec["status"], "approved")
        finally:
            shutil.rmtree(lockp, ignore_errors=True)
        # Recovery: removing the directory restores clean sweeping.
        self.assertEqual(len(ex.execute_approved()), 1)
        self.assertTrue(q.get(aid)["executed"])

    def test_unlink_loop_cannot_flood_audit(self):
        """A sustained lock disturbance refuses every sweep but the audit
        trail stays bounded (coalesced)."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        self._approved(ctx)
        lockp = q._lock_path()
        stop = threading.Event()

        def _unlink_loop():
            while not stop.is_set():
                with contextlib.suppress(OSError):
                    lockp.unlink(missing_ok=True)

        t = threading.Thread(target=_unlink_loop, daemon=True)
        t.start()
        try:
            for _ in range(15):
                try:
                    ex.execute_approved()
                except QueueLockError:
                    pass
                except Exception as e:  # noqa: BLE001
                    self.fail("uncaught exception during lock storm: %r" % e)
        finally:
            stop.set()
            t.join()
        n = len(_refused(read_entries(ctx["run_dir"] / "actions.jsonl")))
        self.assertLessEqual(n, 1)

    def test_lock_refusal_audit_coalescing(self):
        ctx = make_run()
        ex = ctx["executor"]
        self.assertTrue(ex._audit_lock_refusal("queue_lock_timeout", "t1"))
        self.assertFalse(ex._audit_lock_refusal("queue_lock_timeout", "t2"))
        self.assertFalse(ex._audit_lock_refusal("queue_lock_timeout", "t3"))
        evts = _refused(read_entries(ctx["run_dir"] / "actions.jsonl"))
        self.assertEqual(len(evts), 1)
        self.assertEqual(ex._lock_refusal_suppressed, 2)
        # The next emitted entry reports the folded repeats and flags a
        # storm at the threshold.
        ex._lock_refusal_suppressed = 10
        ex._lock_refusal_last_audit = 0.0
        self.assertTrue(ex._audit_lock_refusal("queue_lock_timeout", "t4"))
        evts = _refused(read_entries(ctx["run_dir"] / "actions.jsonl"))
        self.assertEqual(evts[-1]["suppressed_repeats"], 10)
        self.assertTrue(evts[-1]["refusal_storm"])


# ---------------------------------------------------------------------------
# F52 — reconciliation verifies the chain before trusting markers.
# ---------------------------------------------------------------------------

class TestF52ReconciliationVerifiesChain(unittest.TestCase):
    def _plant_forged(self, logp, aid, seq, run_id):
        with open(logp, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "event": "tool_call", "decision": "execution_authorized",
                "approval_id": aid, "seq": seq, "run_id": run_id}) + "\n")

    def _approved(self, ctx):
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued(q, caller, ex.policy.policy_hash)
        q.decide(aid, True, "human says ok", decided_by="human-operator")
        return aid

    def test_forged_marker_refused_not_reconciled(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(ctx)
        self._plant_forged(ctx["run_dir"] / "actions.jsonl", aid, 999,
                           ex.run_id)
        done = ex.execute_approved()
        ents = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in ents
                   if e.get("event") == "reconciliation_marker_invalid"]
        interrupted = [e for e in ents
                       if e.get("event") == "approval_execution_interrupted"]
        # The forged marker is refused: audited, no phantom interruption,
        # and the record is NOT reset to pending on its say-so.
        self.assertEqual(len(refused), 1)
        self.assertEqual(len(interrupted), 0)
        # The refusal is about the MARKER, not the approval: the
        # legitimately-approved record (valid approval digest) still
        # executes normally instead of being starved in pending.
        self.assertEqual(len(done), 1)
        rec = q.get(aid)
        self.assertTrue(rec.get("executed"))

    def test_genuine_interrupted_marker_still_reconciles(self):
        """A real crashed run (HMAC'd marker + durable claim, never
        completed) still reconciles to pending with its audit."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(ctx)
        rec = q.get(aid)
        ctx["log"].append({
            "event": "tool_call", "run_id": ex.run_id,
            "agent_id": rec.get("agent_id"), "role": rec.get("role"),
            "principal": (rec.get("identity") or {}).get("principal"),
            "tool": rec["tool"], "args": rec["args"],
            "decision": "execution_authorized",
            "policy_id": rec.get("policy_id"), "approval_id": aid,
            "reason": "Human approval authorized execution."})
        q.mark_executed(aid)  # the durable claim, before the "crash"
        self.assertEqual(ex.execute_approved(), [])
        rec = q.get(aid)
        self.assertEqual(rec["status"], "pending")
        self.assertFalse(rec.get("executed"))
        ents = read_entries(ctx["run_dir"] / "actions.jsonl")
        self.assertEqual(sum(1 for e in ents if e.get(
            "event") == "approval_execution_interrupted"), 1)
        self.assertEqual(sum(1 for e in ents if e.get(
            "event") == "reconciliation_marker_invalid"), 0)

    def test_forged_higher_seq_cannot_force_interruption(self):
        """A forged higher-seq marker next to a genuine interrupted
        marker poisons reconciliation: nothing is reconciled."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(ctx)
        rec = q.get(aid)
        ctx["log"].append({
            "event": "tool_call", "run_id": ex.run_id,
            "agent_id": rec.get("agent_id"), "role": rec.get("role"),
            "principal": (rec.get("identity") or {}).get("principal"),
            "tool": rec["tool"], "args": rec["args"],
            "decision": "execution_authorized",
            "policy_id": rec.get("policy_id"), "approval_id": aid,
            "reason": "Human approval authorized execution."})
        q.mark_executed(aid)
        self._plant_forged(ctx["run_dir"] / "actions.jsonl", aid, 99999,
                           ex.run_id)
        self.assertEqual(ex.execute_approved(), [])
        ents = read_entries(ctx["run_dir"] / "actions.jsonl")
        self.assertEqual(sum(1 for e in ents if e.get(
            "event") == "approval_execution_interrupted"), 0)
        self.assertEqual(sum(1 for e in ents if e.get(
            "event") == "reconciliation_marker_invalid"), 1)


# ---------------------------------------------------------------------------
# F53 — the policy pin reads the file exactly once.
# ---------------------------------------------------------------------------

class TestF53PolicyPinSingleRead(unittest.TestCase):
    def test_pin_hashes_and_parses_one_read(self):
        calls = []
        real = Path.read_bytes

        def counting(self):
            calls.append(str(self))
            return real(self)

        with mock.patch.object(Path, "read_bytes", counting):
            eng = PolicyEngine(str(DEFAULT_POLICY))
        self.assertEqual(len(calls), 1)
        pristine = real(Path(str(DEFAULT_POLICY)))
        self.assertEqual(eng.policy_hash, sha256(pristine).hexdigest())
        # The parsed policy is the pinned bytes' policy.
        self.assertTrue(eng.policy_hash)

    def test_mid_load_swap_has_no_window(self):
        """Even if a second read WOULD return attacker bytes, it never
        happens: the pin and the parse share one read."""
        pristine = Path(str(DEFAULT_POLICY)).read_bytes()
        attacker = b"attacker_controlled: true\n"
        with mock.patch.object(Path, "read_bytes",
                               side_effect=[pristine, attacker]) as m:
            eng = PolicyEngine(str(DEFAULT_POLICY))
        self.assertEqual(m.call_count, 1)
        self.assertEqual(eng.policy_hash, sha256(pristine).hexdigest())


# ---------------------------------------------------------------------------
# F54 — cross-process break-glass ticket consumption is single-use.
# ---------------------------------------------------------------------------

class TestF54CrossProcessTicketConsumption(unittest.TestCase):
    def _two_pending(self, ctx):
        q, ex = ctx["approvals"], ctx["executor"]
        aids = []
        for i in range(2):
            caller = ctx["mint_identity"]("a%d" % i, "researcher", "org")
            aids.append(_queued(
                q, caller, ex.policy.policy_hash, tool="send_email",
                args={"to": "x@y.z", "subject": "s", "body": "b"}))
        return aids

    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork()")
    def test_fork_race_single_ticket_single_winner(self):
        """Two forked processes racing for one ticket: exactly one
        break_glass succeeds, exactly one approval_break_glass audit."""
        ctx = make_run(
            break_glass_tickets=[("T-FORK", "human-op", "human-rev")])
        q = ctx["approvals"]
        aids = self._two_pending(ctx)
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
                                      ticket_id="T-FORK")
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
        bg = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
              if e.get("event") == "approval_break_glass"]
        self.assertEqual(len(bg), 1)

    def test_sequential_ticket_reuse_still_refused(self):
        ctx = make_run(break_glass_tickets=[("T1", "human-op", "human-rev")])
        q = ctx["approvals"]
        aids = self._two_pending(ctx)
        op = ctx["mint_identity"]("op", "operator", "human-op")
        q.break_glass(aids[0], "emergency", op, ticket_id="T1")
        with self.assertRaises(ValueError):
            q.break_glass(aids[1], "emergency again", op, ticket_id="T1")


if __name__ == "__main__":
    unittest.main()
