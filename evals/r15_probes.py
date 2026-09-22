"""Round-15 closure probes (HARDENING ROUND-15, 2026-09-22).

Each ``_r15_*`` function asserts that a Wave-16 finding (F65-F68) is
CLOSED by the Round-15 hardening: every observation True means the
defense held and the attack step no longer succeeds. sit96-sit98
re-run the Wave-16 defense chains unchanged (reconfirm).

``evals/run_evals.py`` registers this module AFTER
``evals/w16_probes.py`` (the historical wave-16 attack baseline), so
these closure assertions override sit96-sit103.

Probes are hermetic: temp dirs (cleaned in ``finally``), no network,
no repo mutation. Read-only on ``gov/`` and everything else.

``evals/w16_probes.py`` is preserved UNCHANGED as the historical
wave-16 attack record; its sit96-sit103 playbooks are superseded here
and never execute.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
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
from gov.approvals import _print_decision_target  # noqa: E402
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.log import read_entries_with_stats  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from evals.w16_probes import (  # noqa: E402
    _fresh_executor,
    _w16_f55_chain,
    _w16_f57_chain,
    _w16_f63_chain,
)

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")


def _reg_with_operators():
    return PrincipalRegistry({
        "customer-org": {"roles": ["support"],
                         "agent_ids": ["support-1"]},
        "dev-org": {"roles": ["coder"], "agent_ids": ["coder-1"]},
        "research-org": {"roles": ["researcher"],
                         "agent_ids": ["researcher-1"]},
        "ops-lead": {"roles": ["operator"], "agent_ids": ["op-1"]},
        "duty-reviewer": {"roles": ["reviewer"],
                          "agent_ids": ["rev-1"]},
    })


def _queued(ctx, tool="send_email", args=None, caller=None):
    q = ctx["approvals"]
    caller = caller or ctx["mint_identity"]("support-1", "support",
                                            "customer-org")
    return q.queue(
        {"tool": tool,
         "args": args or {"to": "x@synthetic.local", "subject": "s",
                          "body": "b"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="endpoint only",
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=caller)


# ------------------------------------------------------------------ sit96

def _r15_f55_chain_reconfirm():
    """Round-15 reconfirm for sit96 (no finding in Wave-16).

    Re-runs the Wave-16 F55 complete-chain defense cell unchanged:
    mid-run mint of the registered operator tuple, anchor assignment
    raising, minted consume refused + audited, provisioned object
    still consumes.
    """
    return _w16_f55_chain()


# ------------------------------------------------------------------ sit97

def _r15_f57_chain_reconfirm():
    """Round-15 reconfirm for sit97 (no finding in Wave-16).

    Re-runs the Wave-16 F57 store-snapshot-replay defense cell
    unchanged.
    """
    return _w16_f57_chain()


# ------------------------------------------------------------------ sit98

def _r15_f63_chain_reconfirm():
    """Round-15 reconfirm for sit98 (no finding in Wave-16).

    Re-runs the Wave-16 F63 poisoned-log defense cell unchanged.
    """
    return _w16_f63_chain()


# ------------------------------------------------------------------ sit99

def _r15_f60_chain_verified_suppression():
    """Round-15 closure for the F60 follow-up (sit99).

    The R14 residual is closed: lock-refusal re-audit suppression now
    requires the tamper-evident action log to FULLY verify. A planted
    MAC-invalid same-flag line no longer suppresses (loud re-audit);
    a genuine chain-verified refusal entry still suppresses.
    """
    o = {}
    run_dir = Path(tempfile.mkdtemp(prefix="r15f60-"))
    try:
        (run_dir / "approvals.lock").mkdir()
        policy = PolicyEngine(DEFAULT_POLICY)
        # One genuine sweep: audits exactly once.
        _fresh_executor(run_dir, policy).execute_approved()
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = _fresh_executor(run_dir, policy)
        o["genuine_verified_entry_suppresses"] = (
            ex._log_shows_recent_lock_refusal("queue_lock_invalid")
            is True)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    # The planted-line residual, now closed: MAC-invalid same-flag
    # line + corrupt state must NOT suppress.
    run_dir2 = Path(tempfile.mkdtemp(prefix="r15f60p-"))
    try:
        (run_dir2 / "approvals.lock").mkdir()
        planted = {"event": "approval_sweep_refused",
                   "flag": "queue_lock_invalid",
                   "ts": datetime.now(timezone.utc).isoformat(),
                   "seq": 1, "hash": "0" * 64, "prev_hash": "0" * 64}
        (run_dir2 / "actions.jsonl").write_text(
            json.dumps(planted) + "\n", encoding="utf-8")
        (run_dir2 / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex2 = _fresh_executor(run_dir2, PolicyEngine(DEFAULT_POLICY))
        o["planted_mac_invalid_line_does_not_suppress"] = (
            ex2._log_shows_recent_lock_refusal("queue_lock_invalid")
            is False)
        o["planted_line_triggers_loud_reaudit"] = bool(
            ex2._audit_lock_refusal("queue_lock_invalid", "probe"))
    finally:
        shutil.rmtree(run_dir2, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit100

def _r15_f66_bounded_render():
    """Round-15 closure for F66 (sit100).

    The human decision view is bounded at 64KB by default: a 5MB args
    blob renders truncated with an explicit marker (shown/total byte
    counts), the args_sha256 covers the FULL exact bytes, and
    GOV_FULL_ARGS=1 restores the full verbatim render. Small payloads
    still render in full.
    """
    o = {}
    big = "3MB_" + "x" * (3 * 1024 * 1024) + "_MARKER_" + "y" * (2 * 1024 * 1024)
    rec = {"id": "a1", "tool": "api_call",
           "args": {"blob": big, "note": "r15"}}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_decision_target(rec)
    out = buf.getvalue()
    total = len(json.dumps(rec["args"], sort_keys=True,
                           separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))
    o["five_mb_blob_truncated_by_default"] = (
        "TRUNCATED" in out and len(out.encode("utf-8")) < total)
    o["marker_states_shown_and_total_bytes"] = (
        "showing" in out and "of %d bytes" % total in out)
    digest = sha256(json.dumps(
        rec["args"], sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    o["sha256_covers_full_bytes"] = digest in out
    o["truncated_blob_not_rendered_verbatim"] = big not in out

    buf2 = io.StringIO()
    with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "1"}):
        with contextlib.redirect_stdout(buf2):
            _print_decision_target(rec)
    out2 = buf2.getvalue()
    o["full_args_env_restores_verbatim_render"] = big in out2

    small = {"id": "a2", "tool": "api_call",
             "args": {"endpoint": "https://api.synthetic.local/v1"}}
    buf3 = io.StringIO()
    with contextlib.redirect_stdout(buf3):
        _print_decision_target(small)
    o["small_payload_still_full_render"] = (
        "TRUNCATED" not in buf3.getvalue()
        and "https://api.synthetic.local/v1" in buf3.getvalue())
    return o


# ----------------------------------------------------------------- sit101

def _r15_f65_tmpdir_tracking():
    """Round-15 closure for F65 (sit101).

    The harness tracks per-cell temp dirs explicitly: dirs registered
    via ``_cell_make_run`` are removed by ``_cleanup_cell_dirs``
    regardless of prefix; the tmpdir sweep removes unregistered
    probe-internal scratch; dirs outside the active temp root are
    never removed.
    """
    import evals.run_evals as re  # noqa: E402
    o = {}
    before = list(re._CELL_DIRS)
    ctx = None
    d = None
    odd = None
    scratch = None
    victim = None
    try:
        ctx = re._cell_make_run()
        d = Path(ctx["run_dir"])
        o["cell_make_run_registers_dir"] = str(d) in re._CELL_DIRS
        odd = Path(tempfile.mkdtemp(prefix="r15odd-"))
        re._CELL_DIRS.append(str(odd))
        re._cleanup_cell_dirs(*re._CELL_DIRS)
        o["tracked_dirs_removed_regardless_of_prefix"] = (
            not odd.exists() and not d.exists())
        tmp = tempfile.gettempdir()
        scratch = Path(tempfile.mkdtemp(prefix="r15scratch-"))
        snap = set(os.listdir(tmp)) - {scratch.name}
        re._sweep_new_tmpdirs(tmp, snap)
        o["sweep_removes_unregistered_scratch"] = not scratch.exists()
        scratch = None
        victim_dir = Path(tempfile.mkdtemp(prefix="r15victim-"))
        victim = victim_dir / "victim"
        victim.mkdir()
        with mock.patch("tempfile.gettempdir",
                        return_value="/nonexistent-tmp-root-r15"):
            re._cleanup_cell_dirs(str(victim))
        o["outside_temp_root_never_removed"] = victim.exists()
    finally:
        re._CELL_DIRS[:] = before
        for p in (ctx["run_dir"] if ctx else None, odd, scratch):
            if p is not None:
                shutil.rmtree(str(p), ignore_errors=True)
        if victim is not None:
            shutil.rmtree(str(victim.parent), ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit102

def _r15_f67_warn_flag_hardened():
    """Round-15 closure for F67 (sit102).

    The weak-mode warning flag is now a read-only property backed by
    a name-mangled slot: ordinary assignment raises, pre-setting the
    old public flag cannot silence the warning/audit, and the first
    weak-mode break_glass still warns LOUDLY on stderr with exactly
    one audited ``break_glass_unprotected`` entry. The F59 residual
    (object.__setattr__ slot write / __class__-swap property shadow)
    is unchanged and stays the documented boundary.
    """
    o = {}
    tickets = [("T-OP", "ops-lead", "duty-reviewer")]
    ctx = make_run(principal_registry=_reg_with_operators(),
                   break_glass_tickets=tickets)
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        try:
            q._break_glass_unprotected_warned = True
            o["plain_assignment_raises"] = False
        except AttributeError:
            o["plain_assignment_raises"] = True
        # Pre-setting the OLD public flag must not silence anything.
        ctx2 = make_run(principal_registry=_reg_with_operators(),
                        break_glass_tickets=[("T-OP2", "ops-lead",
                                              "duty-reviewer")])
        try:
            q2, ex2 = ctx2["approvals"], ctx2["executor"]
            q2.__dict__["_break_glass_unprotected_warned"] = True
            evil2 = ex2.mint_identity("op-1", "operator", "ops-lead")
            aid = _queued(ctx2, tool="send_email",
                          args={"to": "x@synthetic.local", "subject": "s",
                                "body": "b"},
                          caller=evil2)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rec, _t = q2.break_glass(aid, "incident-9",
                                         operator_identity=evil2,
                                         ticket_id="T-OP2")
            entries, _ = read_entries_with_stats(
                ctx2["run_dir"] / "actions.jsonl")
            warned = sum(1 for e in entries
                         if e.get("event") == "break_glass_unprotected")
            o["preset_old_flag_does_not_silence"] = (
                "GOVERNANCE WARNING" in err.getvalue() and warned == 1
                and rec["status"] == "approved")
        finally:
            shutil.rmtree(ctx2["run_dir"], ignore_errors=True)
        # Control: first weak-mode consume is loud, exactly once.
        aid3 = _queued(ctx, tool="send_email",
                       args={"to": "x@synthetic.local", "subject": "s",
                             "body": "b"},
                       caller=evil)
        err3 = io.StringIO()
        with contextlib.redirect_stderr(err3):
            rec3, _t3 = q.break_glass(aid3, "incident-9",
                                      operator_identity=evil,
                                      ticket_id="T-OP")
        entries3, _ = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        o["weak_mode_still_loud_exactly_once"] = (
            "GOVERNANCE WARNING" in err3.getvalue()
            and sum(1 for e in entries3
                    if e.get("event") == "break_glass_unprotected") == 1
            and rec3["status"] == "approved")
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit103

def _r15_f68_mediation_recheck():
    """Round-15 closure for F68 (sit103).

    The langchain adapter re-checks the live ``args_schema`` for
    undeclared-extra handling at mediation time (the common
    ``_mediate`` funnel for sync and async paths): an
    ``object.__setattr__`` schema swap and a post-construction
    ``model_config`` mutation + rebuild both fail CLOSED instead of
    silently dropping the smuggled kwarg. A genuine ``extra="allow"``
    schema still works and the smuggled kwarg reaches DLP.
    """
    o = {}
    from pydantic import BaseModel, ConfigDict  # noqa: E402
    from gov.adapters.core import GovernedBinding  # noqa: E402
    from gov.adapters.langchain_tools import (  # noqa: E402
        make_governed_tool)

    key = "AKIAIOSFODNN7EXAMPLE"  # AWS-docs example key (synthetic)

    class _AllowSchema(BaseModel):
        model_config = ConfigDict(extra="allow")
        to: str
        subject: str = ""
        body: str = ""

    class _StrictSchema(BaseModel):
        to: str
        subject: str = ""
        body: str = ""

    def _fresh_tool(schema_cls=_AllowSchema):
        c = make_run()
        ident = c["identities"]["support"]
        binding = GovernedBinding(c["executor"], ident)
        tool = make_governed_tool(
            binding, "send_email", "send email", args_schema=schema_cls,
            on_denied="return", on_queued="return")
        return c, tool

    def _invoke(tool):
        raw = tool.invoke({"to": "x@synthetic.local", "subject": "s",
                           "body": "routine", "bcc": key})
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return {"parse_error": raw[:120]}

    # Control: smuggled kwarg reaches mediation and is denied by DLP.
    c, tool = _fresh_tool()
    try:
        r = _invoke(tool)
        o["control_bcc_denied_by_dlp"] = (
            r.get("status") == "denied"
            and r.get("policy_id") == "dlp-credential-block")
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Attack 1: object.__setattr__ schema swap -> fail closed.
    c, tool = _fresh_tool()
    try:
        object.__setattr__(tool, "args_schema", _StrictSchema)
        try:
            tool.invoke({"to": "x@synthetic.local", "subject": "s",
                         "body": "b"})
            o["setattr_schema_swap_fails_closed"] = False
        except ValueError:
            o["setattr_schema_swap_fails_closed"] = True
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Attack 2: model_config mutation + rebuild -> fail closed.
    c, tool = _fresh_tool()
    try:
        _AllowSchema.model_config["extra"] = "ignore"
        _AllowSchema.model_rebuild(force=True)
        try:
            tool.invoke({"to": "x@synthetic.local", "subject": "s",
                         "body": "b"})
            o["model_config_mutation_fails_closed"] = False
        except ValueError:
            o["model_config_mutation_fails_closed"] = True
    finally:
        _AllowSchema.model_config["extra"] = "allow"
        _AllowSchema.model_rebuild(force=True)
        shutil.rmtree(c["run_dir"], ignore_errors=True)
    return o


PROBES = {
    "f55_chain_reconfirm": _r15_f55_chain_reconfirm,
    "f57_chain_reconfirm": _r15_f57_chain_reconfirm,
    "f63_chain_reconfirm": _r15_f63_chain_reconfirm,
    "f60_chain_verified_suppression": _r15_f60_chain_verified_suppression,
    "f66_bounded_render": _r15_f66_bounded_render,
    "f65_tmpdir_tracking": _r15_f65_tmpdir_tracking,
    "f67_warn_flag_hardened": _r15_f67_warn_flag_hardened,
    "f68_mediation_recheck": _r15_f68_mediation_recheck,
}

R15_WIRE = (
    ("sit96", "r15a", "f55_chain_reconfirm", "f55d_"),
    ("sit97", "r15b", "f57_chain_reconfirm", "f57d_"),
    ("sit98", "r15c", "f63_chain_reconfirm", "f63d_"),
    ("sit99", "r15d", "f60_chain_verified_suppression", "f60v_"),
    ("sit100", "r15e", "f66_bounded_render", "f66c_"),
    ("sit101", "r15f", "f65_tmpdir_tracking", "tmpc_"),
    ("sit102", "r15g", "f67_warn_flag_hardened", "id67_"),
    ("sit103", "r15h", "f68_mediation_recheck", "f68c_"),
)


def register_r15(playbooks, w7_playbook):
    """Wire the round-15 closure probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w16: the closure assertions override
    the wave-16 attack baseline for sit96-sit103 (F65-F68 CLOSED;
    sit96-sit98 reconfirmed). ``evals/w16_probes.py`` stays on disk
    UNCHANGED as the historical wave-16 attack record; its
    sit96-sit103 playbooks are superseded here and never execute.
    """
    for sid, mk, pk, pre in R15_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
