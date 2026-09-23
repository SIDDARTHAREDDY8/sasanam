"""Round-11 closure probes (HARDENING ROUND-11, 2026-09-21).

Each ``_r11_*`` function asserts that a Wave-12 finding (F42-F49) is
CLOSED by the Round-11 hardening: True means the defense held and the
attack step no longer succeeds. ``evals/run_evals.py`` registers this
module AFTER ``evals/w12_probes.py`` (the historical attack baseline),
so these closure assertions override sit67-sit73.

Probes are hermetic: temp dirs, no network, no repo mutation.
Read-only on ``gov/`` and everything else.

``evals/w12_probes.py`` is preserved UNCHANGED as the historical
wave-12 attack record; its sit67-73 playbooks are superseded here.
"""

import fcntl
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT)
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
tests_path = str(REPO_ROOT / "tests")
if tests_path not in sys.path:
    sys.path.insert(0, tests_path)

from tests.harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    BREAK_GLASS_TICKET_FILENAME,
    QueueLockInvalidatedError,
    approval_digest_ok,
    provision_break_glass_ticket,
)
from gov.executor import PolicyPinMismatchError  # noqa: E402
from gov.identity import PrincipalRegistry, UnmintedIdentityError  # noqa: E402
from gov.log import read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402


def _queued(ctx, tool="read_file", args=None, caller=None):
    q = ctx["approvals"]
    caller = caller or ctx["mint_identity"]("a1", "researcher", "org")
    return q.queue(
        {"tool": tool, "args": args or {"path": "notes.txt"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test",
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=caller)


def _r11_queue_oracle():
    """Round-11 closure for F42 (sit67).

    The wave-12 oracle (``_w12_queue_oracle``) minted keyed digests over
    an attacker-chosen identity dict via ``ApprovalQueue.queue()``.
    F42 requires a verifier-authenticated caller identity: queue()
    without one raises TypeError; an unminted identity raises
    UnmintedIdentityError; and the record is stamped from the
    AUTHENTICATED identity — the attacker-supplied action["identity"]
    dict is ignored, so a planted oracle record cannot launder a
    victim run_id or role.
    """
    o = {}
    ctx = make_run()
    q = ctx["approvals"]
    # 1. No caller identity: fail-closed TypeError.
    try:
        q.queue({"tool": "read_file", "args": {"path": "x"}},
                SimpleNamespace(policy_id="p", reason="r", flag=None))
        o["missing_identity_fails_closed"] = False
    except TypeError:
        o["missing_identity_fails_closed"] = True
    # 2. Unminted identity: refused.
    from gov.identity import AgentIdentity
    fake = AgentIdentity(agent_id="mallory", role="researcher",
                         run_id=q.run_dir.name, principal="mallory")
    try:
        q.queue({"tool": "read_file", "args": {"path": "x"}},
                SimpleNamespace(policy_id="p", reason="r", flag=None),
                caller_identity=fake)
        o["unminted_identity_refused"] = False
    except UnmintedIdentityError:
        o["unminted_identity_refused"] = True
    # 3. Spoofed action["identity"] is ignored; the stamped record
    # carries the authenticated caller.
    caller = ctx["mint_identity"]("real-agent", "researcher", "real-org")
    aid = q.queue(
        {"tool": "read_file", "args": {"path": "notes.txt"},
         "identity": {"agent_id": "scout-x", "role": "admin",
                      "run_id": "VICTIM-RUN", "principal": "adversary-org"},
         "redactions": [], "agent_justification": "x"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test", caller_identity=caller)
    rec = q.get(aid)
    o["spoofed_identity_ignored"] = (
        rec["agent_id"] == "real-agent" and rec["role"] == "researcher"
        and rec["principal"] == "real-org"
        and rec["run_id"] == q.run_dir.name)
    return o


def _r11_pending_mac_metadata():
    """Round-11 closure for F43 (sit68).

    The wave-12 probe (``_w12_pending_mac_metadata``) rewrote the
    preview / policy_context / identity between queue() and decide().
    F43 binds the full security record into the pending MAC:
    decide() raises fail-closed and audits the rejected attempt, and
    execution-time tampering is refused with
    approval_integrity_violation.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    # 1. Preview rewrite between queue and decide: refused at decide.
    aid = _queued(ctx)
    q._rewrite(lambda rs: [
        dict(r, preview="TAMPERED") if r["id"] == aid else r for r in rs])
    try:
        q.decide(aid, True, "ok", decided_by="human-operator")
        o["preview_tamper_refused_at_decide"] = False
    except ValueError:
        o["preview_tamper_refused_at_decide"] = (
            q.get(aid)["status"] == "pending")
    attempts = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_decision_attempt"]
    o["rejected_attempt_audited"] = any(
        e.get("decision") == "rejected_attempt" and
        e.get("approval_id") == aid for e in attempts)
    # 2. policy_context rewrite after decide: refused at execution.
    aid2 = _queued(ctx)
    q.decide(aid2, True, "ok", decided_by="human-operator")
    q._rewrite(lambda rs: [
        dict(r, policy_context={"domain_allowlisted": False})
        if r["id"] == aid2 else r for r in rs])
    o["execution_time_tamper_refused"] = (ex.execute_approved() == [])
    refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_execution_refused"]
    o["integrity_violation_flagged"] = any(
        e.get("flag") == "approval_integrity_violation" and
        e.get("approval_id") == aid2 for e in refusals)
    return o


def _r11_execute_boundary():
    """Round-11 closure for F44/F45 (sit69).

    F44: deleting ``approvals.lock`` mid-acquisition raises
    QueueLockInvalidatedError (not a silent double sweep) and the
    executor audits a DISTINCT ``queue_lock_invalidated`` refusal.
    F45: an interrupted execution (authorized + claimed, never
    completed) reconciles to pending with a loud audit event and is
    never auto-executed.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    # F44: delete the lock file between open() and flock().
    lock_path = q._lock_path()
    real_flock = fcntl.flock

    def evil_flock(fd, op):
        if op & fcntl.LOCK_EX:
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                pass
        return real_flock(fd, op)

    with mock.patch("fcntl.flock", evil_flock):
        try:
            ex.execute_approved()
            o["deleted_lock_raises_invalidated"] = False
        except QueueLockInvalidatedError:
            o["deleted_lock_raises_invalidated"] = True
    refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"]
    o["invalidated_flag_distinct"] = any(
        e.get("flag") == "queue_lock_invalidated" for e in refusals)
    # F45: simulate a crash between claim and completion.
    ctx2 = make_run()
    q2, ex2 = ctx2["approvals"], ctx2["executor"]
    aid = _queued(ctx2)
    q2.decide(aid, True, "ok", decided_by="human-operator")
    rec = q2.get(aid)
    ctx2["log"].append({"event": "tool_call", "run_id": ex2.run_id,
                        "agent_id": rec.get("agent_id"),
                        "role": rec.get("role"), "tool": rec["tool"],
                        "args": rec["args"],
                        "decision": "execution_authorized",
                        "approval_id": aid})
    q2.mark_executed(aid)
    o["interrupted_not_auto_executed"] = (ex2.execute_approved() == [])
    rec2 = q2.get(aid)
    o["interrupted_reconciled_to_pending"] = (
        rec2["status"] == "pending" and not rec2.get("executed"))
    events = [e.get("event") for e in
              read_entries(ctx2["run_dir"] / "actions.jsonl")]
    o["interruption_audited"] = (
        "approval_execution_interrupted" in events)
    return o


def _r11_quorum_cost():
    """Round-11 closure for F46 (sit70).

    The wave-12 probe (``_w12_quorum_cost``) showed the F41 quorum
    could be primed with same-run multi-call bursts. F46 requires
    multi-run continuity: same-run priming does NOT establish a
    principal, so a fresh principal's matching shape executes;
    a genuine multi-run campaign still fires the quorum.
    """
    o = {}
    with tempfile.TemporaryDirectory(prefix="r11qc-") as td:
        led = str(Path(td) / "egress_ledger.jsonl")

        def _call(principal):
            c = make_run(ledger_path=led)
            ident = c["mint_identity"]("agent", "researcher", principal)
            return c["executor"].call(
                ident, "api_call",
                endpoint="https://shard0.collector.synthetic.local/x",
                params={"blob": "A1B2C3D4E5F6G7H8!", "seq": 1})

        # Same-run burst: 5 calls, one principal, one run.
        c0 = make_run(ledger_path=led)
        ident0 = c0["mint_identity"]("agent", "researcher", "primer")
        for _ in range(5):
            c0["executor"].call(
                ident0, "api_call",
                endpoint="https://shard0.collector.synthetic.local/x",
                params={"blob": "A1B2C3D4E5F6G7H8!", "seq": 1})
        r = _call("fresh")
        o["same_run_priming_does_not_establish"] = (
            r["status"] == "executed")
        # Multi-run campaign: 3 principals x 2 runs.
        st = []
        for _ in range(2):
            for p in ("c1", "c2", "c3"):
                st.append(_call(p)["status"])
        o["multi_run_campaign_still_fires"] = ("queued" in st)
    return o


def _r11_privilege_smuggle():
    """Round-11 closure for F47 (sit71).

    The wave-12 probe (``_w12_privilege_smuggle``) showed the R2 role
    allowlist was not re-checked at execution. F47 checks
    ``policy.role_allows(rec["role"], rec["tool"])`` before policy
    evaluation or side effects: a researcher-smuggled write_file is
    refused with role_allowlist_violation; a coder's write_file
    executes.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    low = ctx["mint_identity"]("lowpriv", "researcher", "org")
    aid = q.queue(
        {"tool": "write_file",
         "args": {"path": "out.txt", "content": "pwned"},
         "redactions": [], "agent_justification": "t"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="write", policy_hash=ex.policy.policy_hash,
        caller_identity=low)
    q.decide(aid, True, "looks benign", decided_by="human-operator")
    o["smuggled_tool_refused"] = (ex.execute_approved() == [])
    refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_execution_refused"]
    o["allowlist_violation_flagged"] = any(
        e.get("flag") == "role_allowlist_violation" and
        e.get("policy_id") == "role-allowlist" for e in refusals)
    # Control: same-role approval executes.
    ctx2 = make_run()
    q2, ex2 = ctx2["approvals"], ctx2["executor"]
    coder = ctx2["mint_identity"]("dev", "coder", "org")
    aid2 = q2.queue(
        {"tool": "write_file",
         "args": {"path": "out.txt", "content": "hello"},
         "redactions": [], "agent_justification": "t"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="write", policy_hash=ex2.policy.policy_hash,
        caller_identity=coder)
    q2.decide(aid2, True, "ok", decided_by="human-operator")
    done = ex2.execute_approved()
    o["same_role_executes"] = (
        len(done) == 1 and q2.get(aid2).get("executed") is True)
    return o


def _r11_policy_substitution():
    """Round-11 closure for F48 (sit72).

    The wave-12 probe (``_w12_policy_substitution``) swapped the
    policy file across runs with no detection. F48 always audits
    ``policy_loaded`` with path + hash; a GOV_POLICY_HASH mismatch
    refuses construction (PolicyPinMismatchError) with a
    ``policy_pin_mismatch`` audit; an unpinned policy logs an
    explicit ``policy_pin_absent`` warning.
    """
    o = {}
    from gov.log import ActionLog
    from gov.approvals import ApprovalQueue
    from gov.executor import ToolExecutor
    pol_hash = PolicyEngine(
        str(REPO_ROOT / "policies" / "default.yaml")).policy_hash
    # Matching pin: constructs, audits policy_loaded pinned.
    os.environ["GOV_POLICY_HASH"] = pol_hash
    try:
        ctx = make_run()
    finally:
        os.environ.pop("GOV_POLICY_HASH", None)
    entries = read_entries(ctx["run_dir"] / "actions.jsonl")
    loaded = [e for e in entries if e["event"] == "policy_loaded"]
    o["matching_pin_constructs"] = bool(loaded) and loaded[0]["pinned"]
    # Mismatch: refuses construction, audits the mismatch.
    os.environ["GOV_POLICY_HASH"] = "wrong-pin"
    try:
        with tempfile.TemporaryDirectory(prefix="r11ps-") as td:
            run_dir = Path(td) / "run"
            run_dir.mkdir()
            log = ActionLog(run_dir / "actions.jsonl")
            aq = ApprovalQueue(run_dir, log)
            pol = PolicyEngine(
                str(REPO_ROOT / "policies" / "default.yaml"))
            try:
                # Wave-85: the pin-refusal cell needs the pin machinery
                # reached, so the raw pipeline is declared here (the
                # bypass is chained, never silent).
                ToolExecutor(run_dir, pol, log, aq, ungoverned_ack=(
                    "round-11 closure battery: raw pipeline by design; "
                    "this cell exercises the F48 pin-refusal path"))
                o["mismatch_refuses_construction"] = False
            except PolicyPinMismatchError:
                o["mismatch_refuses_construction"] = True
            evts = [e["event"] for e in
                    read_entries(run_dir / "actions.jsonl")]
            o["mismatch_audited"] = ("policy_pin_mismatch" in evts)
    finally:
        os.environ.pop("GOV_POLICY_HASH", None)
    # Absent pin: explicit warning.
    old = os.environ.pop("GOV_POLICY_HASH", None)
    try:
        ctx2 = make_run()
    finally:
        if old is not None:
            os.environ["GOV_POLICY_HASH"] = old
    entries2 = read_entries(ctx2["run_dir"] / "actions.jsonl")
    o["absent_pin_warns"] = any(
        e["event"] == "policy_pin_absent" for e in entries2)
    return o


def _r11_breakglass_lifecycle():
    """Round-11 closure for F49 (sit73).

    The wave-12 probe (``_w12_breakglass_lifecycle``) showed
    ``break_glass()`` accepted agent-minted tickets. F49 requires a
    human-provisioned ticket: missing/unknown/wrong-operator tickets
    are refused; a valid ticket approves; used tickets cannot be
    reused; mid-run provisioned tickets are outside the run-start
    snapshot and refused.
    """
    o = {}
    ctx = make_run(break_glass_tickets=[("T-1", "ops-lead",
                                         "duty-reviewer")])
    q = ctx["approvals"]
    operator = ctx["mint_identity"]("op-1", "operator", "ops-lead")

    def _pending():
        return _queued(ctx, tool="api_call",
                       args={"endpoint": "https://y.synthetic.local/"})

    # 1. No ticket: refused.
    aid = _pending()
    try:
        q.break_glass(aid, "incident", operator_identity=operator)
        o["missing_ticket_refused"] = False
    except ValueError:
        o["missing_ticket_refused"] = (
            q.get(aid)["status"] == "pending")
    # 2. Wrong operator principal: refused.
    aid2 = _pending()
    mallory = ctx["mint_identity"]("mallory", "operator", "mallory")
    try:
        q.break_glass(aid2, "incident", operator_identity=mallory,
                      ticket_id="T-1")
        o["wrong_operator_refused"] = False
    except ValueError:
        o["wrong_operator_refused"] = (
            q.get(aid2)["status"] == "pending")
    # 3. Valid ticket: approves, binds the provisioned ticket.
    aid3 = _pending()
    record, _ = q.break_glass(aid3, "incident",
                              operator_identity=operator,
                              ticket_id="T-1")
    o["valid_ticket_approves"] = (
        record["status"] == "approved" and record["break_glass"])
    bg = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
          if e.get("event") == "approval_break_glass"]
    o["provisioned_ticket_bound"] = any(
        e.get("provision_ticket_id") == "T-1" for e in bg)
    # 4. Mid-run provisioned ticket: refused (outside snapshot).
    provision_break_glass_ticket(
        ctx["run_dir"] / BREAK_GLASS_TICKET_FILENAME,
        "T-LATE", "ops-lead", "duty-reviewer")
    aid4 = _pending()
    try:
        q.break_glass(aid4, "incident", operator_identity=operator,
                      ticket_id="T-LATE")
        o["mid_run_ticket_refused"] = False
    except ValueError:
        o["mid_run_ticket_refused"] = (
            q.get(aid4)["status"] == "pending")
    return o


PROBES = {
    "queue_oracle": _r11_queue_oracle,
    "pending_mac_metadata": _r11_pending_mac_metadata,
    "execute_boundary": _r11_execute_boundary,
    "quorum_cost": _r11_quorum_cost,
    "privilege_smuggle": _r11_privilege_smuggle,
    "policy_substitution": _r11_policy_substitution,
    "breakglass_lifecycle": _r11_breakglass_lifecycle,
}

R11_WIRE = (
    ("sit67", "r11a", "queue_oracle", "qo2_"),
    ("sit68", "r11b", "pending_mac_metadata", "pm2_"),
    ("sit69", "r11c", "execute_boundary", "eb2_"),
    ("sit70", "r11d", "quorum_cost", "qc2_"),
    ("sit71", "r11e", "privilege_smuggle", "ps2_"),
    ("sit72", "r11f", "policy_substitution", "pl2_"),
    ("sit73", "r11g", "breakglass_lifecycle", "bg2_"),
)


def register_r11(playbooks, w7_playbook):
    """Wire the round-11 closure probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w12: the closure assertions override
    the wave-12 attack baseline for sit67-sit73 (F42-F49 CLOSED).
    ``evals/w12_probes.py`` stays on disk UNCHANGED as the historical
    wave-12 attack record; its sit67-73 playbooks are superseded here
    and never execute.
    """
    for sid, mk, pk, pre in R11_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
