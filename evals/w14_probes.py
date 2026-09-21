"""Wave-14 attack probes (TEAM ADVERSARY, 2026-09-21).

Each ``_w14_*`` function measures a Wave-14 brief item against the
Round-12-hardened product. Observation keys use attacker-active
phrasing: True means the ATTACK STEP SUCCEEDED (a finding), True on a
defense key means the defense held as documented (an honest cell).
``evals/run_evals.py`` registers this module AFTER
``evals/r12_probes.py``; sit81-sit88 are new situations (no overrides).

Probes are hermetic: temp dirs, no network, no repo mutation.
Read-only on ``gov/`` and everything else outside evals/.

Brief map:
  sit81 (brief 1) -- registry minting authorization: in-process code
      holding the executor mints the REGISTERED operator identity and
      consumes a break-glass ticket as the operator (F55).
  sit82 (brief 2) -- coalescing bypass: a fresh executor per sweep
      defeats the F51 per-executor refusal coalescing; the
      tamper-evident log floods anyway (F56).
  sit83 (brief 3a) -- chain-break vs reconciliation: one bad-HMAC entry
      blocks a GENUINE interrupted claim's recovery (documented F52
      residual #1; honest cell, no new finding).
  sit84 (brief 3b) -- full-chain verify cost at 20k entries + the
      per-sweep re-verify/re-audit loop (documented F52 residual #2;
      honest cell with measured numbers, no new finding).
  sit85 (brief 4) -- ticket-store replacement: restoring a pre-consume
      store snapshot re-arms a consumed single-use ticket (the used
      flag is not HMAC-bound); the resolve->consume sequence detects
      no substitution (F57). Deleting the store fails closed (honest
      sub-observation).
  sit86 (brief 5) -- demo honesty: demo/attack_scenario.py's final
      RESULT line is unconditional -- under a weakened policy it
      prints "4 attack attempts blocked" while its own verdicts print
      "ALLOWED?!" (F58).
  sit87 (brief 6) -- install-time behavior: pyproject.toml has no
      install-time code execution (honest cell, no finding).
  sit88 (brief 7) -- F45 x F33: crash after claim, reconcile re-queues,
      human re-approves, execution succeeds -- the egress budget is
      charged exactly once (honest defense cell, no finding).
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
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
    ApprovalQueue,
    BREAK_GLASS_TICKET_FILENAME,
    provision_break_glass_ticket,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.log import ActionLog, _verify, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

_HARNESS_PRINCIPALS = {
    "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
    "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
    "research-org": {"roles": ["researcher"],
                     "agent_ids": ["researcher-1"]},
}


def _queued(ctx, tool="send_email", args=None, caller=None):
    q = ctx["approvals"]
    caller = caller or ctx["mint_identity"]("a1", "researcher", "org")
    return q.queue(
        {"tool": tool, "args": args or {"to": "x@synthetic.local"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test",
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=caller)


def _w14_operator_mint_impersonation():
    """Brief 1 (sit81): minting is capability-unchecked.

    The F50 registry gates the (principal, role, agent_id) TUPLE, but
    nothing checks that the code calling mint_identity() is entitled
    to the identity it mints. Attack code holding the executor mints
    the REGISTERED operator identity (op-1/operator/ops-lead), queues
    an approval stamped as the operator, and consumes a real
    break-glass ticket as the operator: emergency approval granted.
    Every step passes the executor-installed identity verifier,
    because the identity WAS minted by this executor.
    """
    o = {}
    reg = PrincipalRegistry(dict(
        _HARNESS_PRINCIPALS,
        **{"ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
           "duty-reviewer": {"roles": ["reviewer"],
                             "agent_ids": ["rev-1"]}}))
    ctx = make_run(principal_registry=reg,
                   break_glass_tickets=[("T-OP", "ops-lead",
                                        "duty-reviewer")])
    q, ex = ctx["approvals"], ctx["executor"]
    # 1. The attacker mints the registered operator identity.
    evil_op = ex.mint_identity("op-1", "operator", "ops-lead")
    o["attacker_mints_registered_operator_identity"] = (
        evil_op.agent_id == "op-1" and evil_op.role == "operator"
        and evil_op.principal == "ops-lead")
    # 2. ... and queues an approval stamped as the operator.
    aid = _queued(ctx, caller=evil_op)
    rec = q.get(aid)
    o["attacker_queues_approvals_as_operator"] = (
        rec["agent_id"] == "op-1" and rec["role"] == "operator"
        and rec["principal"] == "ops-lead")
    # 3. ... and consumes a human-provisioned break-glass ticket as
    # the operator: the emergency approval goes through.
    record, _ticket = q.break_glass(
        aid, "incident-9", operator_identity=evil_op, ticket_id="T-OP")
    o["attacker_consumes_break_glass_as_operator"] = (
        record["status"] == "approved"
        and record.get("break_glass") is True)
    return o


def _fresh_executor(run_dir, policy):
    """A brand-new executor on the same run dir (simulates a fresh
    process: new in-memory coalescing state, same on-disk state)."""
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    return ToolExecutor(run_dir, policy, log, approvals,
                        ledger_path=run_dir / "egress_ledger.jsonl")


def _lock_refusals(run_dir):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if e.get("event") == "approval_sweep_refused"
            and e.get("flag") == "queue_lock_invalid"]


def _w14_coalescing_bypass():
    """Brief 2 (sit82): fresh executor per sweep defeats F51 coalescing.

    The 5s refusal-coalescing window (``_lock_refusal_last_audit`` /
    ``_lock_refusal_suppressed``) is pure per-executor-instance state,
    initialized in ``ToolExecutor.__init__``. A fresh executor per
    sweep -- or two processes sharing the run dir, the F54 threat
    shape -- each logs its own ``approval_sweep_refused`` entry, so a
    sustained lock disturbance floods the tamper-evident log anyway.
    """
    o = {}
    policy = PolicyEngine(str(DEFAULT_POLICY))
    N = 8

    # Attack: N sweeps, each on a FRESH executor, same run dir, with a
    # directory swapped in at the lock path (the F51 attack shape).
    run_dir = Path(tempfile.mkdtemp(prefix="w14coal-"))
    try:
        (run_dir / "approvals.lock").mkdir()
        for _ in range(N):
            _fresh_executor(run_dir, policy).execute_approved()
        o["fresh_executor_per_sweep_logs_own_refusal"] = (
            len(_lock_refusals(run_dir)) == N)
        # The coalescing window lives only on the instance: a second
        # executor's sweep does not touch the first executor's window.
        ex1 = _fresh_executor(run_dir, policy)
        ex2 = _fresh_executor(run_dir, policy)
        ex2.execute_approved()
        o["no_cross_executor_coalescing_state"] = (
            ex1._lock_refusal_last_audit == 0.0
            and ex1._lock_refusal_suppressed == 0)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    # Control: the same executor coalesces (the R12 fix works in-
    # process) -- the bypass is strictly cross-instance.
    run_dir2 = Path(tempfile.mkdtemp(prefix="w14coalc-"))
    try:
        (run_dir2 / "approvals.lock").mkdir()
        ex = _fresh_executor(run_dir2, policy)
        for _ in range(N):
            ex.execute_approved()
        o["same_executor_coalesces_control"] = (
            len(_lock_refusals(run_dir2)) == 1
            and ex._lock_refusal_suppressed == N - 1)
    finally:
        shutil.rmtree(run_dir2, ignore_errors=True)
    return o


def _w14_chainbreak_blocks_recovery():
    """Brief 3a (sit83): one bad-HMAC entry blocks genuine recovery.

    A GENUINE interrupted claim (approved + execution_authorized +
    durable claim, crashed before completion) is pending when a
    run-dir writer appends ONE bad-HMAC entry. Reconciliation verifies
    the full chain before honoring any marker, so the whole sweep's
    reconciliation refuses: the legitimate claim is neither executed
    nor re-queued for the human -- it sits approved/executed=True
    until an operator repairs the chain. This is F52's documented
    honest residual #1; the cell confirms the measurement, no new
    finding.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    aid = _queued(ctx)
    q.decide(aid, True, "ok", decided_by="human-operator")
    # Genuine interrupted claim: authorized + durably claimed, no
    # completion marker (crashed before the side effect finished).
    q.log.append({
        "event": "tool_call", "run_id": ex.run_id, "agent_id": "a1",
        "role": "researcher", "tool": "send_email",
        "args": {"to": "x@synthetic.local"},
        "decision": "execution_authorized", "approval_id": aid,
        "policy_id": "p", "reason": "crash-sim"})
    q.mark_executed(aid)
    # The forger appends one bad-HMAC line (F52's documented shape).
    logp = ctx["run_dir"] / "actions.jsonl"
    with open(logp, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "event": "tool_call", "seq": 999,
            "ts": "2030-01-01T00:00:00Z", "run_id": ex.run_id,
            "agent_id": "forger", "role": "researcher",
            "tool": "send_email", "args": {"to": "evil@x.zz"},
            "decision": "execution_authorized", "approval_id": "fake",
            "hash": "forged-not-a-real-mac"}) + "\n")
    ex.execute_approved()
    ents = read_entries(logp)
    o["single_bad_entry_blocks_genuine_recovery"] = (
        sum(1 for e in ents
            if e.get("event") == "reconciliation_marker_invalid") == 1)
    o["no_phantom_interruption_on_refusal"] = (
        sum(1 for e in ents
            if e.get("event") == "approval_execution_interrupted") == 0)
    rec = q.get(aid)
    o["legitimate_claim_left_unreconciled"] = (
        rec["status"] == "approved" and rec["executed"] is True)
    return o


def _w14_verify_cost_scale():
    """Brief 3b (sit84): full-chain verify cost at 20k entries.

    Measures the per-sweep tax a log-flooding attacker imposes: one
    forged execution_authorized marker (bad HMAC, fake approval id)
    keeps ``interrupted`` non-empty, so EVERY sweep pays a full-chain
    ``_verify`` and appends another ``reconciliation_marker_invalid``
    audit entry -- no dedup (F52's documented honest residual #2).
    The cell pins the measured numbers; no new finding.
    """
    o = {}
    ctx = make_run()
    logp = ctx["run_dir"] / "actions.jsonl"
    N = 20000
    for i in range(N):
        ctx["log"].append({
            "event": "tool_call", "agent_id": "a", "role": "researcher",
            "principal": "p", "tool": "read_file",
            "args": {"path": "x-%d" % i},
            "decision": "allowed_executed"})
    t0 = time.perf_counter()
    verdict = _verify(logp)
    verify_ms = (time.perf_counter() - t0) * 1000.0
    o["verify_completes_at_20k_entries"] = bool(verdict["ok"])
    o["verify_cost_bounded_not_pathological"] = verify_ms < 5000.0
    # One forged marker -> every sweep re-verifies and re-audits.
    with open(logp, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "event": "tool_call", "seq": N + 999,
            "ts": "2030-01-01T00:00:00Z", "run_id": ctx["executor"].run_id,
            "agent_id": "forger", "role": "researcher",
            "tool": "send_email", "args": {"to": "evil@x.zz"},
            "decision": "execution_authorized", "approval_id": "fake-aid",
            "hash": "forged-not-a-real-mac"}) + "\n")
    before = len(read_entries(logp))
    for _ in range(3):
        ctx["executor"].execute_approved()
    after = len(read_entries(logp))
    ents = read_entries(logp)
    o["forged_marker_forces_per_sweep_reverify"] = (
        sum(1 for e in ents
            if e.get("event") == "reconciliation_marker_invalid") == 3)
    # The refusal audit itself grows the chain: each sweep's verify
    # walks a longer log than the last (self-feeding loop).
    o["refusal_audits_grow_the_chain"] = (after - before == 3)
    return o


def _w14_ticket_store_replacement():
    """Brief 4 (sit85): replacing the TICKET STORE file re-arms tickets.

    The F54 flock serializes cooperating processes, but it is
    advisory: a run-dir writer (F52's in-model attacker) replaces the
    ticket STORE file itself. The ticket HMAC covers (ticket_id,
    operator/reviewer principals, purpose, created_at) -- NOT the
    ``used`` flag -- so restoring a pre-consume store snapshot
    replays as a valid UNUSED ticket. The resolve->consume sequence
    performs no substitution detection (no generation counter, no
    MAC over ``used``): a fresh process consumes the same ticket_id a
    second time. Deleting the store mid-race fails closed (the live
    re-read finds nothing), which the probe confirms as an honest
    sub-observation.
    """
    o = {}
    policy = PolicyEngine(str(DEFAULT_POLICY))
    run_dir = Path(tempfile.mkdtemp(prefix="w14tsr-"))
    try:
        store = run_dir / BREAK_GLASS_TICKET_FILENAME
        provision_break_glass_ticket(store, "T-1", "ops-lead",
                                    "duty-reviewer")
        ex_a, q_a = _fresh_pair(run_dir, policy)
        pre_consume = store.read_bytes()
        op_a = ex_a.mint_identity("op-1", "operator", "ops-lead")
        aid1 = _queued_on(q_a, ex_a, op_a)
        rec1, _t1 = q_a.break_glass(aid1, "incident-1",
                                    operator_identity=op_a,
                                    ticket_id="T-1")
        o["first_consume_succeeds"] = (
            rec1["status"] == "approved"
            and rec1.get("break_glass") is True)
        # The attacker restores the pre-consume store snapshot: valid
        # HMACs, used=False. No key needed -- it is a replay.
        store.write_bytes(pre_consume)
        # The operator legitimately resolves the first post-review, so
        # the stacked-break-glass gate cannot mask the ticket check.
        rev = ex_a.mint_identity("rev-1", "reviewer", "duty-reviewer")
        q_a.resolve_review("PRV-%s" % aid1, "reviewed ok",
                           reviewer_identity=rev)
        # Process B: fresh executor AFTER the restore, so its run-start
        # snapshot seals the replayed ticket as unused.
        ex_b, q_b = _fresh_pair(run_dir, policy)
        op_b = ex_b.mint_identity("op-1", "operator", "ops-lead")
        aid2 = _queued_on(q_b, ex_b, op_b)
        try:
            rec2, _t2 = q_b.break_glass(aid2, "incident-2",
                                        operator_identity=op_b,
                                        ticket_id="T-1")
            double_spent = (rec2["status"] == "approved"
                            and rec2.get("break_glass") is True)
        except ValueError:
            double_spent = False
        o["attacker_double_spends_single_use_ticket"] = double_spent
        o["store_substitution_undetected_by_resolve_consume"] = (
            double_spent)
        n_bg = sum(1 for e in read_entries(run_dir / "actions.jsonl")
                   if e.get("event") == "approval_break_glass")
        o["two_emergency_approvals_one_ticket"] = (n_bg == 2)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    # Deletion variant: a missing store fails closed (live re-read
    # finds no ticket), it does not silently skip the consume.
    run_dir2 = Path(tempfile.mkdtemp(prefix="w14tsrd-"))
    try:
        store2 = run_dir2 / BREAK_GLASS_TICKET_FILENAME
        provision_break_glass_ticket(store2, "T-9", "ops-lead",
                                    "duty-reviewer")
        ex_c, q_c = _fresh_pair(run_dir2, policy)
        store2.unlink()  # attacker deletes the store mid-race
        ex_d, q_d = _fresh_pair(run_dir2, policy)
        op_d = ex_d.mint_identity("op-1", "operator", "ops-lead")
        aid9 = _queued_on(q_d, ex_d, op_d)
        try:
            q_d.break_glass(aid9, "incident-9", operator_identity=op_d,
                            ticket_id="T-9")
            refused = False
        except ValueError:
            refused = True
        o["deleted_store_fails_closed"] = refused
    finally:
        shutil.rmtree(run_dir2, ignore_errors=True)
    return o


def _fresh_pair(run_dir, policy):
    log = ActionLog(run_dir / "actions.jsonl")
    q = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, q,
                      ledger_path=run_dir / "egress_ledger.jsonl")
    return ex, q


def _queued_on(q, ex, caller, tool="send_email"):
    return q.queue(
        {"tool": tool, "args": {"to": "x@synthetic.local"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test", policy_hash=ex.policy.policy_hash,
        caller_identity=caller)


def _w14_demo_summary_honesty():
    """Brief 5 (sit86): demo/attack_scenario.py's RESULT line is
    unconditional.

    The per-attempt verdicts() DO check the real returned status --
    under a weakened policy (attacker domain allowlisted, outbound
    sends allowed, DLP neutered) attempt 1 prints "ALLOWED?!", the
    demo's own standard for "not stopped". But the final
    ``RESULT: 4 attack attempts blocked, 1 tampering detected.`` line
    is a literal print with no dependency on any verdict: the demo
    asserts success from scripted expectations, not from measured
    outcomes. A stranger running the sales artifact against a
    misconfigured deployment gets a success story over an exfil.
    """
    o = {}
    import demo.attack_scenario as atk
    import gov.dlp as dlp
    td = Path(tempfile.mkdtemp(prefix="w14dh-"))
    try:
        weak = td / "weak-policy.yaml"
        text = DEFAULT_POLICY.read_text(encoding="utf-8")
        text = text.replace(
            "domain_allowlist: [synthetic.local, localhost, 127.0.0.1]",
            "domain_allowlist: [synthetic.local, localhost, 127.0.0.1, "
            "attacker.example]")
        text = text.replace(
            "  - id: approval-outbound-sends\n"
            "    description: All outbound sends and posts need a human.\n"
            "    effect: require_approval",
            "  - id: approval-outbound-sends\n"
            "    description: All outbound sends and posts need a human.\n"
            "    effect: allow")
        assert "attacker.example" in text and "effect: allow" in text
        weak.write_text(text, encoding="utf-8")
        buf = io.StringIO()
        old_cwd, old_argv = os.getcwd(), sys.argv[:]
        os.chdir(td)  # the demo writes ./runs/<id>
        try:
            with contextlib.redirect_stdout(buf), \
                 mock.patch.object(atk, "default_policy_path",
                                   lambda: str(weak)), \
                 mock.patch.object(dlp, "scan_tool_args",
                                   lambda tool, kwargs: (False, None,
                                                         kwargs, [])):
                atk.main()
        finally:
            os.chdir(old_cwd)
            sys.argv = old_argv
        out = buf.getvalue()
        o["weakened_policy_allows_exfil_attempt"] = ("ALLOWED?!" in out)
        o["demo_summary_claims_blocked_regardless"] = (
            "RESULT: 4 attack attempts blocked, 1 tampering detected."
            in out)
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return o


def _w14_install_time():
    """Brief 6 (sit87): install-time behavior (read-only assessment).

    pyproject.toml uses stock setuptools.build_meta, declares no
    setup.py, no [tool.setuptools.cmdclass], no custom install
    commands -- ``pip install`` executes no project code. A
    compromised build backend is out of scope for this assessment
    (that is the build-backend trust boundary, unchanged).
    """
    o = {}
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    o["no_setup_py"] = not (REPO_ROOT / "setup.py").exists()
    o["no_setup_cfg_hooks"] = not (REPO_ROOT / "setup.cfg").exists()
    o["no_custom_install_commands"] = (
        "cmdclass" not in text and "install_commands" not in text)
    o["stock_build_backend"] = (
        'build-backend = "setuptools.build_meta"' in text)
    return o


def _w14_budget_single_charge():
    """Brief 7 (sit88): F45 x F33 -- the budget is charged once.

    Crash between the durable claim and the side effect: the crashed
    sweep charges NOTHING (the charge sits after _simulate). The next
    sweep reconciles loudly (record back to pending, human must
    re-decide), the human re-approves, the execution succeeds -- and
    the send budget counts exactly ONE execution for the single
    actual send. No double-charge.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    aid = _queued(ctx)
    q.decide(aid, True, "ok", decided_by="human-operator")

    def _crash(tool, args, call_ctx):
        raise RuntimeError("crash-sim: died between claim and effect")

    with mock.patch.object(ex, "_simulate", _crash):
        try:
            ex.execute_approved()
            o["crashed_sweep_charges_no_budget"] = False
        except RuntimeError:
            o["crashed_sweep_charges_no_budget"] = (
                ex._executed.get("send_email", 0) == 0)
    # Next sweep reconciles at sweep start: loud, back to pending.
    done = ex.execute_approved()
    rec = q.get(aid)
    ents = read_entries(ctx["run_dir"] / "actions.jsonl")
    o["interrupted_claim_requeued_loudly"] = (
        rec["status"] == "pending" and rec["executed"] is False
        and done == []
        and sum(1 for e in ents
                if e.get("event")
                == "approval_execution_interrupted") == 1)
    # Human re-decides; the execution succeeds; budget charged once.
    q.decide(aid, True, "re-approved after investigation",
             decided_by="human-operator")
    done2 = ex.execute_approved()
    ents2 = read_entries(ctx["run_dir"] / "actions.jsonl")
    o["redecision_charges_budget_once"] = (
        len(done2) == 1
        and ex._executed.get("send_email", 0) == 1
        and sum(1 for e in ents2
                if e.get("decision") == "approved_executed") == 1)
    return o


PROBES = {
    "operator_mint_impersonation": _w14_operator_mint_impersonation,
    "coalescing_bypass": _w14_coalescing_bypass,
    "chainbreak_blocks_recovery": _w14_chainbreak_blocks_recovery,
    "verify_cost_scale": _w14_verify_cost_scale,
    "ticket_store_replacement": _w14_ticket_store_replacement,
    "demo_summary_honesty": _w14_demo_summary_honesty,
    "install_time": _w14_install_time,
    "budget_single_charge": _w14_budget_single_charge,
}

W14_WIRE = (
    ("sit81", "w14-opmint", "operator_mint_impersonation", "opm_"),
    ("sit82", "w14-coal", "coalescing_bypass", "coal_"),
    ("sit83", "w14-chainbreak", "chainbreak_blocks_recovery", "cb_"),
    ("sit84", "w14-verifycost", "verify_cost_scale", "vc_"),
    ("sit85", "w14-ticketstore", "ticket_store_replacement", "tsr_"),
    ("sit86", "w14-demohonesty", "demo_summary_honesty", "dh_"),
    ("sit87", "w14-install", "install_time", "ins_"),
    ("sit88", "w14-budget", "budget_single_charge", "bud_"),
)


def register_w14(playbooks, w7_playbook):
    """Wire the wave-14 probes into run_evals.PLAYBOOKS.

    Registered AFTER register_r12: sit81-sit88 are new situations
    (no overrides of earlier playbooks). ``evals/r12_probes.py`` and
    ``evals/w13_probes.py`` stay UNCHANGED as the historical record.
    """
    for sid, mk, pk, pre in W14_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
