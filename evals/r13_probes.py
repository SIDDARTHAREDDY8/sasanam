"""Round-13 closure probes (HARDENING ROUND-13, 2026-09-21).

Each ``_r13_*`` function asserts that a Wave-14 finding (F55-F58) is
CLOSED by the Round-13 hardening: every observation True means the
defense held and the attack step no longer succeeds.

``evals/run_evals.py`` registers this module AFTER
``evals/w14_probes.py`` (the historical wave-14 attack baseline), so
these closure assertions override sit81, sit82, sit85, sit86.

Probes are hermetic: temp dirs, no network, no repo mutation.
Read-only on ``gov/`` and everything else.

``evals/w14_probes.py`` is preserved UNCHANGED as the historical
wave-14 attack record; its sit81/82/85/86 playbooks are superseded
here and never execute.
"""

import contextlib
import io
import json
import os
import shutil
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT)
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
tests_path = str(REPO_ROOT / "tests")
if tests_path not in sys.path:
    sys.path.insert(0, tests_path)

from tests.harness import make_run  # noqa: E402
from gov.approvals import (  # noqa: E402
    SessionIdentityAlreadySetError,
    _read_verified_ticket_store,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.log import read_entries  # noqa: E402


def _queued(ctx, tool="send_email", args=None, caller=None):
    q = ctx["approvals"]
    caller = caller or ctx["mint_identity"]("a1", "researcher", "org")
    return q.queue(
        {"tool": tool,
         "args": args or {"to": "x@synthetic.local", "subject": "s",
                          "body": "b"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test",
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=caller)


_HARNESS_PRINCIPALS = {
    "customer-org": {"roles": ["support"], "agent_ids": ["support-1"]},
    "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
    "research-org": {"roles": ["researcher"],
                     "agent_ids": ["researcher-1"]},
}

_OPERATOR_REGISTRY = PrincipalRegistry(dict(
    _HARNESS_PRINCIPALS,
    **{"ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
       "duty-reviewer": {"roles": ["reviewer"], "agent_ids": ["rev-1"]}}))


def _operator_run(**kwargs):
    kwargs.setdefault("principal_registry", _OPERATOR_REGISTRY)
    kwargs.setdefault("session_identity", ("op-1", "operator", "ops-lead"))
    kwargs.setdefault("break_glass_tickets",
                      [("T-OP", "ops-lead", "duty-reviewer")])
    return make_run(**kwargs)


def _r13_session_identity():
    """Round-13 closure for F55 (sit81).

    The Wave-14 attack — in-process code minting the registered
    operator tuple mid-run and consuming the human-provisioned
    break-glass ticket — is refused: break_glass requires the ONE
    deployment-provisioned session identity (provenance="provisioned"),
    a mid-run mint (provenance="minted") is not equal to it, the
    refusal is audited as break_glass_refused, and the ticket stays
    usable. The provisioned identity still consumes; registry/dev mode
    without a session identity keeps the pre-R13 behavior.
    """
    o = {}
    ctx = _operator_run()
    q, ex = ctx["approvals"], ctx["executor"]

    # 1. The F55 attack: mid-run mint of the registered operator tuple.
    evil = ex.mint_identity("op-1", "operator", "ops-lead")
    aid = _queued(ctx, caller=evil)
    try:
        q.break_glass(aid, "incident-9", operator_identity=evil,
                      ticket_id="T-OP")
        o["midrun_mint_refused"] = False
    except ValueError:
        o["midrun_mint_refused"] = True
    refused = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
               if e.get("event") == "break_glass_refused"]
    o["refusal_audited"] = (len(refused) == 1
                            and "F55" in refused[0].get("reason", ""))
    o["ticket_still_unused"] = (
        q._bg_ticket_snapshot["T-OP"]["used"] is False)

    # 2. The provisioned session identity still consumes.
    good = ctx["session_identity"]
    aid2 = _queued(ctx, caller=good)
    try:
        record, _t = q.break_glass(aid2, "real incident",
                                   operator_identity=good, ticket_id="T-OP")
        o["provisioned_consumes"] = (
            record["status"] == "approved" and record.get("break_glass"))
    except ValueError:
        o["provisioned_consumes"] = False

    # 3. Dev mode (no session identity): pre-R13 behavior unchanged.
    ctx2 = make_run(
        break_glass_tickets=[("T-DEV", "ops-lead", "duty-reviewer")])
    q2, ex2 = ctx2["approvals"], ctx2["executor"]
    op2 = ctx2["mint_identity"]("op-1", "operator", "ops-lead")
    aid3 = _queued(ctx2, caller=op2)
    try:
        rec3, _t3 = q2.break_glass(aid3, "dev incident",
                                   operator_identity=op2, ticket_id="T-DEV")
        o["dev_mode_unchanged"] = (rec3["status"] == "approved")
    except ValueError:
        o["dev_mode_unchanged"] = False
    return o


def _r13_shared_coalescing():
    """Round-13 closure for F56 (sit82).

    The Wave-14 attack — rotating to a fresh executor per sweep to
    reset the per-instance coalescing window and flood the
    tamper-evident log with approval_sweep_refused entries — is
    closed: the window is file-backed in the run dir, so N fresh
    executors still coalesce. State-file deletion degrades to a
    single re-audit (never an exception); the state file stays tiny
    and bounded to the known refusal flags.
    """
    o = {}
    ctx = make_run()

    def _fresh():
        # Wave-85: round-13 closure battery — raw pipeline by design;
        # the bypass is declared and chained, never silent.
        return ToolExecutor(ctx["run_dir"], ctx["policy"], ctx["log"],
                            ctx["approvals"],
                            ungoverned_ack=(
                                "round-13 closure battery: raw pipeline "
                                "by design"))

    def _refusals():
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_sweep_refused"]

    state_path = ctx["run_dir"] / "lock_refusal_coalesce.json"

    # 1. Eight fresh executors, one refusal each: bounded entries.
    for i in range(8):
        _fresh()._audit_lock_refusal("queue_lock_timeout", "storm-%d" % i)
    o["rotation_attack_bounded"] = (len(_refusals()) <= 2)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    o["repeats_folded_in_shared_state"] = (
        state["queue_lock_timeout"]["suppressed"] >= 6)

    # 2. Deleting the state file: no exception, bounded degradation.
    state_path.unlink()
    try:
        _fresh()._audit_lock_refusal("queue_lock_timeout", "post-delete")
        o["deletion_no_exception"] = True
    except Exception:  # noqa: BLE001
        o["deletion_no_exception"] = False
    o["deletion_bounded"] = (len(_refusals()) <= 3
                             and state_path.exists())

    # 3. The state file stays tiny and bounded to known flags.
    raw = state_path.read_text(encoding="utf-8")
    state = json.loads(raw)
    o["state_tiny"] = (len(raw) < 1024)
    o["state_bounded_flags"] = set(state) <= {
        "queue_lock_invalid", "queue_lock_invalidated",
        "queue_lock_timeout"}

    # 4. One executor still coalesces (F51 behavior preserved).
    ctx2 = make_run()
    ex2 = ctx2["executor"]
    results = [ex2._audit_lock_refusal("queue_lock_timeout", "t%d" % i)
               for i in range(3)]
    n2 = len([e for e in read_entries(ctx2["run_dir"] / "actions.jsonl")
              if e.get("event") == "approval_sweep_refused"])
    o["single_executor_coalesces"] = (results == [True, False, False]
                                      and n2 == 1)
    return o


def _r13_ticket_replay():
    """Round-13 closure for F57 (sit85).

    The Wave-14 attack — restoring a pre-consume ticket-store snapshot
    over the live store to resurrect a consumed break-glass ticket —
    is refused: single-use is enforced against the VERIFIED action
    log (the append-only ticket_consumed event survives the replay),
    not just the store. The ticket HMAC binds the used state
    (re-signed on consume), so flipping used=False without the keyring
    key fails verification. The F54 fork race still yields exactly
    one winner with exactly one ticket_consumed marker.
    """
    o = {}
    ctx = _operator_run()
    q, ex = ctx["approvals"], ctx["executor"]
    op = ctx["session_identity"]
    store = q._ticket_store_path()
    pre_consume = store.read_bytes()

    def _consumed():
        return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "ticket_consumed"
                and e.get("ticket_id") == "T-OP"]

    # 1. Normal one-time consume: exactly one consumed marker.
    aid = _queued(ctx, caller=op)
    q.break_glass(aid, "incident", operator_identity=op, ticket_id="T-OP")
    o["one_time_consume"] = (len(_consumed()) == 1)

    # 2. Replay the pre-consume store (fresh-process path: drop the
    # in-memory snapshot too): refused by the verified action log.
    store.write_bytes(pre_consume)
    q._bg_ticket_snapshot = None
    aid2 = _queued(ctx, caller=op)
    try:
        q.break_glass(aid2, "incident-2", operator_identity=op,
                      ticket_id="T-OP")
        o["replay_refused_by_log"] = False
    except ValueError as e:
        o["replay_refused_by_log"] = ("verified action log" in str(e))
    o["single_consumed_marker"] = (len(_consumed()) == 1)

    # 3. Flipping used=False on the consumed line without re-signing
    # fails HMAC verification (used state is HMAC-bound).
    q2ctx = _operator_run(
        break_glass_tickets=[("T-HM", "ops-lead", "duty-reviewer")])
    q2, ex2 = q2ctx["approvals"], q2ctx["executor"]
    op2 = q2ctx["session_identity"]
    q2.break_glass(_queued(q2ctx, caller=op2), "x", operator_identity=op2,
                   ticket_id="T-HM")
    lines = []
    for line in q2._ticket_store_path().read_text(
            encoding="utf-8").splitlines():
        e = json.loads(line)
        if isinstance(e, dict) and e.get("ticket_id") == "T-HM":
            e["used"] = False
            line = json.dumps(e)
        lines.append(line)
    q2._ticket_store_path().write_text("\n".join(lines) + "\n",
                                       encoding="utf-8")
    o["used_flip_fails_hmac"] = (
        "T-HM" not in _read_verified_ticket_store(
            q2._ticket_store_path()))

    # 4. F54 fork race under the F57 log authority: one winner, one
    # consumed marker (deterministic pipe choreography, no sleeps).
    if not hasattr(os, "fork"):
        o["fork_race_single_winner"] = True
        return o
    fctx = make_run(
        break_glass_tickets=[("T-FORK85", "human-op", "human-rev")])
    fq, fex = fctx["approvals"], fctx["executor"]
    aids = [_queued(fctx, caller=fctx["mint_identity"](
        "a%d" % i, "researcher", "org")) for i in range(2)]
    r_ready, w_ready = os.pipe()
    r_go, w_go = os.pipe()
    pids = []
    try:
        for faid in aids:
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(r_ready)
                    os.close(w_go)
                    ident = fctx["mint_identity"](
                        "opchild", "operator", "human-op")
                    os.write(w_ready, b"R")
                    os.close(w_ready)
                    os.read(r_go, 1)
                    os.close(r_go)
                    fq.break_glass(faid, "emergency now", ident,
                                   ticket_id="T-FORK85")
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
    consumed85 = [e for e in read_entries(
        fctx["run_dir"] / "actions.jsonl")
        if e.get("event") == "ticket_consumed"
        and e.get("ticket_id") == "T-FORK85"]
    o["fork_race_single_winner"] = (codes == [0, 3]
                                    and len(consumed85) == 1)
    return o


def _r13_demo_honesty():
    """Round-13 closure for F58 (sit86).

    The Wave-14 finding — demo/attack_scenario.py printing a
    hard-coded "RESULT: 4 attack attempts blocked" literal that would
    stay green even if an attack got through — is closed: the RESULT
    line is computed from measured verdict booleans
    (summarize_results). The default run prints "4 attack attempts
    blocked, 0 allowed, 1 tampering detected."; weakened inputs
    honestly report allowed attacks.
    """
    o = {}
    from demo.attack_scenario import summarize_results, main

    # 1. Default shape, computed from all-blocked verdicts.
    o["default_shape"] = (
        summarize_results([True, True, True, True], True)
        == "RESULT: 4 attack attempts blocked, 0 allowed, "
           "1 tampering detected.")
    # 2. Weakened inputs: allowed attacks are reported, never hidden.
    weakened = summarize_results([True, False, True, True], False)
    o["weakened_honest"] = ("1 allowed" in weakened
                            and "4 attack attempts blocked" not in weakened
                            and "0 allowed" not in weakened)
    # 3. No hard-coded RESULT literal survives in the demo source.
    src = (REPO_ROOT / "demo" / "attack_scenario.py").read_text(
        encoding="utf-8")
    o["no_hardcoded_literal"] = (
        '"RESULT: 4 attack attempts blocked' not in src
        and "'RESULT: 4 attack attempts blocked" not in src)
    # 4. End-to-end demo run prints the computed default shape.
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="gov-r13-demo-")
    prev = os.getcwd()
    try:
        os.chdir(tmpd)
        buf = io.StringIO()
        with redirect_stdout(buf):
            # Wave-174: pass argv=[] explicitly — the demo's main()
            # reads sys.argv by default, which carries the matrix
            # harness's own flags (e.g. --matrix) and would print
            # usage instead of running the scenario.
            main([])
        out = buf.getvalue()
    finally:
        os.chdir(prev)
        # F65 (R15): the demo scratch dir was never removed (one
        # gov-r13-demo-* dir leaked per gate run). Clean it here.
        shutil.rmtree(tmpd, ignore_errors=True)
    result_lines = [l for l in out.splitlines()
                    if l.startswith("RESULT:")]
    o["e2e_default_shape"] = (
        result_lines
        == ["RESULT: 4 attack attempts blocked, 0 allowed, "
            "1 tampering detected."])
    return o


PROBES = {
    "session_identity": _r13_session_identity,
    "shared_coalescing": _r13_shared_coalescing,
    "ticket_replay": _r13_ticket_replay,
    "demo_honesty": _r13_demo_honesty,
}

R13_WIRE = (
    ("sit81", "r13a", "session_identity", "si2_"),
    ("sit82", "r13b", "shared_coalescing", "sc2_"),
    ("sit85", "r13c", "ticket_replay", "tr2_"),
    ("sit86", "r13d", "demo_honesty", "dh2_"),
)


def register_r13(playbooks, w7_playbook):
    """Wire the round-13 closure probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w14: the closure assertions override
    the wave-14 attack baseline for sit81, sit82, sit85, sit86
    (F55-F58 CLOSED). ``evals/w14_probes.py`` stays on disk UNCHANGED
    as the historical wave-14 attack record; its sit81/82/85/86
    playbooks are superseded here and never execute.
    """
    for sid, mk, pk, pre in R13_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
