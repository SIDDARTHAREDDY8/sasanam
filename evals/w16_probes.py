"""Wave-16 probes (TEAM ADVERSARY, 2026-09-21).

Brief map:
  sit96 (brief 7) -- F55 complete attack chain re-run, hardened posture
      (session identity provisioned): mid-run mint of the registered
      operator tuple, queue-as-operator, consume attempt. Every step
      must now fail loudly; the provisioned object still consumes.
      Clean pass = defense cell (no regression).
  sit97 (brief 7) -- F57 complete attack chain re-run, verbatim
      (``_w14_ticket_store_replacement``): pre-consume store snapshot
      replay must be refused via the verified action log; the
      deletion variant still fails closed. Clean pass = defense cell.
  sit98 (brief 7) -- F63 poisoned-log sweep chain re-run: malformed
      lines no longer crash sweeps; the skip is audited; the default
      verifier stays fail-closed and the tolerant verifier passes.
      Clean pass = defense cell.
  sit99 (brief 2) -- F60 suppression-confusion matrix: which log lines
      suppress a lock-refusal re-audit. Cross-flag confusion is
      absent (defense); a planted MAC-invalid same-flag line DOES
      suppress (the documented F60 residual, reconfirmed with
      numbers); malformed and future-dated lines do not.
  sit100 (brief 3) -- F61 unbounded rendering: a 1MB args blob renders
      fully to the human decision view (list + CLI approve path),
      unbounded by design (R14). FINDING F66 (LOW): the human decision
      path has no render cap — an agent that can queue approvals can
      flood the operator's terminal with megabytes before the
      decision is recorded.
  sit101 (brief 1) -- /tmp scatter mechanism: the gate's per-cell
      cleanup only removes ``govred-*`` / ``govcell-ledger-*`` dirs,
      so probe-created scratch (other prefixes, and probe-internal
      ``make_run()`` dirs never passed to the cleanup) accumulates in
      a shared TMPDIR across runs. FINDING F65 (gate reliability),
      numbers measured at the gate level.
  sit102 (brief 5) -- F59/F64 residual confirmation. The documented
      ``object.__setattr__`` bypass of the session-identity anchor is
      reconfirmed (documented residual, no new number); a
      ``__class__``-swap + property-shadowing subclass is a SECOND,
      previously undocumented bypass path (F59 residual extension).
      Sealed-setter re-invocation raises; executor-side mutation is
      inert. F64: the first weak-mode consume warns + audits once
      (defense); flipping ``_break_glass_unprotected_warned``
      silences BOTH the stderr warning and the audit entry while the
      ticket still consumes. FINDING F67 (LOW): weak-mode break-glass
      audit evasion via a plain-attribute flip.
  sit103 (brief 6) -- F62 post-construction schema mutation: the
      ``__setattr__`` guard blocks plain reassignment (defense), but
      ``object.__setattr__(tool, "args_schema", StrictSchema)`` and a
      post-construction ``model_config`` mutation + rebuild BOTH
      reopen the silent-drop hole (the smuggled kwarg vanishes before
      mediation; the approval record shows clean args). FINDING F68
      (LOW). The deployment-boundary residual (deployer building their
      own plain StructuredTool) is unchanged and stays the boundary.

Observation keys use attacker-active phrasing: True on an attack key
means the ATTACK STEP SUCCEEDED (a finding); True on a defense key
means the defense held (an honest cell).

``evals/run_evals.py`` registers this module AFTER
``evals/r14_probes.py``; sit96-sit103 are new situations (no
overrides). Probes are hermetic: temp dirs (cleaned), no network, no
repo mutation. Read-only on ``gov/`` and everything else outside
evals/.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
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
    ApprovalQueue,
    SessionIdentityAlreadySetError,
    _print_records,
    main as approve_main,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.identity import PrincipalRegistry  # noqa: E402
from gov.log import (  # noqa: E402
    ActionLog,
    _verify,
    read_entries_with_stats,
)
from gov.policy import PolicyEngine  # noqa: E402
from evals.w14_probes import (  # noqa: E402
    _w14_ticket_store_replacement,
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


def _operator_run(**kwargs):
    kwargs.setdefault("principal_registry", _reg_with_operators())
    kwargs.setdefault("break_glass_tickets",
                      [("T-OP", "ops-lead", "duty-reviewer")])
    kwargs.setdefault("session_identity", ("op-1", "operator", "ops-lead"))
    return make_run(**kwargs)


def _fresh_executor(run_dir, policy):
    log = ActionLog(run_dir / "actions.jsonl")
    q = ApprovalQueue(run_dir, log)
    # Wave-85: wave-16 probe battery — raw pipeline by design; the
    # bypass is declared and chained, never silent.
    return ToolExecutor(run_dir, policy, log, q,
                        ledger_path=run_dir / "egress_ledger.jsonl",
                        ungoverned_ack=(
                            "wave-16 probe battery: raw pipeline by "
                            "design"))


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


# ----------------------------------------------------------------- sit96

def _w16_f55_chain():
    """Brief 7: F55 (minted-operator break-glass) complete chain,
    hardened posture. The original wave-14 attack — mint the registered
    operator tuple mid-run, queue as the operator, consume the
    human-provisioned ticket — must now fail loudly at every step;
    the provisioned session identity object still consumes."""
    o = {}
    ctx = _operator_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        o["attacker_mints_registered_operator_tuple"] = (
            evil.agent_id == "op-1" and evil.role == "operator"
            and evil.principal == "ops-lead")
        aid = _queued(ctx, caller=evil)
        # The w15 attack-1 shape: plain assignment to the anchor.
        try:
            q._session_identity = evil
            o["anchor_assignment_raises"] = False
        except AttributeError:
            o["anchor_assignment_raises"] = True
        # The original w14 consume attempt.
        try:
            q.break_glass(aid, "incident-9", operator_identity=evil,
                          ticket_id="T-OP")
            o["minted_operator_consume_refused"] = False
        except ValueError:
            o["minted_operator_consume_refused"] = True
        entries, _ = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in entries
                   if e.get("event") == "break_glass_refused"]
        o["refusal_audited_once"] = len(refused) == 1
        o["ticket_still_unused"] = (
            q._bg_ticket_snapshot["T-OP"]["used"] is False)
        # The provisioned object still consumes.
        good = ctx["session_identity"]
        aid2 = _queued(ctx, caller=good)
        try:
            rec, _t = q.break_glass(aid2, "real incident",
                                    operator_identity=good,
                                    ticket_id="T-OP")
            o["provisioned_object_consumes"] = (
                rec["status"] == "approved" and rec.get("break_glass"))
        except ValueError:
            o["provisioned_object_consumes"] = False
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit97

def _w16_f57_chain():
    """Brief 7: F57 (store-snapshot replay) complete chain, verbatim
    re-run of the wave-14 attack. The pre-consume store snapshot
    replay must be refused via the verified action log; the
    deletion variant still fails closed."""
    raw = _w14_ticket_store_replacement()
    return {
        "first_consume_succeeds": bool(
            raw.get("first_consume_succeeds")),
        "replay_double_spend_refused": not bool(
            raw.get("attacker_double_spends_single_use_ticket")),
        "no_second_emergency_approval": not bool(
            raw.get("two_emergency_approvals_one_ticket")),
        "deleted_store_fails_closed": bool(
            raw.get("deleted_store_fails_closed")),
    }


# ----------------------------------------------------------------- sit98

def _w16_f63_chain():
    """Brief 7: F63 (poisoned-log sweep) chain re-run. Malformed lines
    no longer crash sweeps; the skip is audited once; the default
    verifier stays fail-closed and the tolerant verifier passes."""
    o = {}
    ctx = make_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        aid = _queued(ctx)
        q.decide(aid, True, "ok", decided_by="human-operator")
        with open(ctx["run_dir"] / "actions.jsonl", "a",
                  encoding="utf-8") as fh:
            fh.write("NOT JSON AT ALL\n[1,2]\n")
        policy = PolicyEngine(DEFAULT_POLICY)
        crashed = False
        try:
            for _ in range(3):
                _fresh_executor(ctx["run_dir"], policy).execute_approved()
        except Exception:  # noqa: BLE001 -- crash shape is data
            crashed = True
        o["poisoned_sweep_proceeds_no_crash"] = not crashed
        entries, n = read_entries_with_stats(
            ctx["run_dir"] / "actions.jsonl")
        skips = [e for e in entries
                 if e.get("event") == "action_log_malformed_lines_skipped"]
        o["skip_audited_once"] = (
            len(skips) == 1 and skips[0]["malformed_count"] == n == 2)
        o["default_verify_still_fail_closed"] = not _verify(
            str(ctx["run_dir"] / "actions.jsonl"))["ok"]
        v = _verify(str(ctx["run_dir"] / "actions.jsonl"),
                    _skip_malformed=True)
        o["tolerant_verify_passes_valid_chain"] = (
            v["ok"] and v["malformed_skipped"] == 2)
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit99

def _w16_f60_suppression_matrix():
    """Brief 2: which log lines suppress a lock-refusal re-audit.

    Cross-flag confusion is absent (a genuine refusal for flag A does
    not suppress flag B's audit). A planted MAC-invalid same-flag line
    DOES suppress the re-audit — the documented F60 residual,
    reconfirmed here with numbers (the sweep still refuses
    fail-closed; the planted line fails default ``_verify`` loudly).
    Malformed and future-dated lines never suppress (fail-loud: the
    sweep audits once)."""
    o = {}
    policy = PolicyEngine(DEFAULT_POLICY)

    def _refusals(run_dir, flag):
        es, _ = read_entries_with_stats(run_dir / "actions.jsonl")
        return [e for e in es
                if e.get("event") == "approval_sweep_refused"
                and e.get("flag") == flag]

    def _corrupt_state(run_dir):
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")

    # (a) cross-flag: genuine A entry, then a refusal for B.
    rd = Path(tempfile.mkdtemp(prefix="w16f60a-"))
    try:
        _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_invalid", "genuine-A")
        _corrupt_state(rd)
        wrote = _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_timeout", "sweep-B")
        o["crossflag_genuine_A_does_not_suppress_B"] = (
            wrote is True and len(_refusals(rd, "queue_lock_timeout"))
            == 1)
    finally:
        shutil.rmtree(rd, ignore_errors=True)

    # (b) planted MAC-invalid same-flag line suppresses the re-audit.
    rd = Path(tempfile.mkdtemp(prefix="w16f60b-"))
    try:
        ex = _fresh_executor(rd, policy)
        es, _ = read_entries_with_stats(rd / "actions.jsonl")
        seq = (es[-1]["seq"] + 1) if es else 1
        prev = es[-1]["hash"] if es else "GENESIS"
        planted = {"seq": seq, "prev_hash": prev, "format_version": 1,
                   "key_epoch": "dev", "event": "approval_sweep_refused",
                   "flag": "queue_lock_timeout", "reason": "planted",
                   "ts": datetime.now(timezone.utc).isoformat(
                       timespec="seconds"),
                   "hash": "f" * 64}
        with open(rd / "actions.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(planted) + "\n")
        _corrupt_state(rd)
        wrote = _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_timeout", "real-sweep")
        o["planted_mac_invalid_sameflag_suppresses_reaudit"] = (
            wrote is False
            and len(_refusals(rd, "queue_lock_timeout")) == 1)
        o["planted_line_detected_by_default_verify"] = not _verify(
            str(rd / "actions.jsonl"))["ok"]
    finally:
        shutil.rmtree(rd, ignore_errors=True)

    # (c) malformed line does NOT suppress (fail-loud audits once).
    rd = Path(tempfile.mkdtemp(prefix="w16f60c-"))
    try:
        with open(rd / "actions.jsonl", "a", encoding="utf-8") as fh:
            fh.write("THIS IS NOT JSON\n")
        _corrupt_state(rd)
        wrote = _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_timeout", "real")
        o["malformed_line_does_not_suppress"] = (
            wrote is True
            and len(_refusals(rd, "queue_lock_timeout")) == 1)
    finally:
        shutil.rmtree(rd, ignore_errors=True)

    # (d) future-dated entry does NOT suppress.
    rd = Path(tempfile.mkdtemp(prefix="w16f60d-"))
    try:
        _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_timeout", "genuine")
        es, _ = read_entries_with_stats(rd / "actions.jsonl")
        future = dict(es[-1])
        future["ts"] = (datetime.now(timezone.utc)
                        + timedelta(hours=1)).isoformat(timespec="seconds")
        lines = (rd / "actions.jsonl").read_text(
            encoding="utf-8").splitlines()
        lines[-1] = json.dumps(future)
        (rd / "actions.jsonl").write_text("\n".join(lines) + "\n",
                                         encoding="utf-8")
        _corrupt_state(rd)
        wrote = _fresh_executor(rd, policy)._audit_lock_refusal(
            "queue_lock_timeout", "real")
        o["future_dated_entry_does_not_suppress"] = (wrote is True)
    finally:
        shutil.rmtree(rd, ignore_errors=True)
    return o


# ---------------------------------------------------------------- sit100

def _w16_f61_render_flood():
    """Brief 3: the human decision view renders args unbounded.

    A 1MB args blob is printed in full by ``_print_records`` and again
    by the CLI ``approve`` path before the decision is recorded — no
    cap, no truncation (R14 made full rendering deliberate so the
    operator sees the exact digested bytes). FINDING F66 (LOW): an
    agent that can queue approvals can flood the operator's terminal
    with megabytes on the human decision path; the measured 5MB and
    20MB shapes are in the finding."""
    o = {}
    ctx = make_run()
    try:
        q = ctx["approvals"]
        ident = ctx["mint_identity"]("support-1", "support",
                                    "customer-org")
        blob = "x" * (1024 * 1024)
        aid = _queued(
            ctx, args={"endpoint": "https://api.synthetic.local/v1/run",
                       "params": {"blob": blob}}, caller=ident)
        rec = [r for r in q.all() if r["id"] == aid][0]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_records([rec], q)
        rendered = buf.getvalue()
        o["list_view_renders_full_1MB_blob"] = (
            len(rendered) >= 1024 * 1024 and blob[:1000] in rendered)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc = approve_main(["--rundir", str(ctx["run_dir"]), "approve",
                               aid, "--reason", "w16"])
        out2 = buf2.getvalue()
        o["cli_approve_renders_full_blob_before_decision"] = (
            rc == 0 and out2.index(blob[:1000])
            < out2.index("Approved approval"))
        o["render_has_no_cap_bytes"] = len(out2) >= 1024 * 1024
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)
    return o


# ---------------------------------------------------------------- sit101

def _w16_tmp_scatter():
    """Brief 1: the gate's per-cell cleanup only removes
    ``govred-*`` / ``govcell-ledger-*`` dirs, so probe-created scratch
    with any other prefix — and probe-internal ``make_run()`` dirs that
    are never passed to the cleanup — accumulates in a shared TMPDIR
    across runs. FINDING F65 (gate reliability): per-run leftover
    counts and the tmpfs-exhaustion extrapolation are in the finding."""
    o = {}
    import evals.run_evals as re  # lazy: avoids the circular import
    # The cleanup honors its prefix allowlist ...
    d_keep = Path(tempfile.mkdtemp(prefix="w16probe-"))
    d_drop = Path(tempfile.mkdtemp(prefix="govred-w16test-"))
    try:
        re._cleanup_cell_dirs(str(d_keep), str(d_drop))
        o["cleanup_ignores_probe_prefix_dirs"] = d_keep.exists()
        o["cleanup_removes_matching_prefix_dirs"] = not d_drop.exists()
    finally:
        shutil.rmtree(d_keep, ignore_errors=True)
        shutil.rmtree(d_drop, ignore_errors=True)
    # ... and mkdtemp names are unique, so leftovers never collide,
    # they only accumulate.
    a = Path(tempfile.mkdtemp(prefix="w16probe-"))
    b = Path(tempfile.mkdtemp(prefix="w16probe-"))
    try:
        o["mkdtemp_names_unique_no_collision"] = (a.name != b.name)
    finally:
        shutil.rmtree(a, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True)
    return o


# ---------------------------------------------------------------- sit102

def _w16_f59_f64_residuals():
    """Brief 5: F59/F64 residual confirmation.

    F59: the documented ``object.__setattr__`` bypass of the
    read-only session-identity anchor is reconfirmed (documented
    residual, no new number); a ``__class__``-swap + subclass that
    shadows the property with a plain attribute is a SECOND,
    previously undocumented bypass path (F59 residual extension —
    same hostile-in-process class, now measured). Re-invoking the
    sealed setter raises; executor-side mutation is inert.
    F64: the first weak-mode consume warns on stderr and audits
    ``break_glass_unprotected`` exactly once (defense); flipping the
    plain attribute ``_break_glass_unprotected_warned`` silences BOTH
    the warning and the audit entry while the ticket still consumes.
    FINDING F67 (LOW)."""
    o = {}
    # --- F59a: documented object.__setattr__ bypass, reconfirmed -------
    ctx = _operator_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        object.__setattr__(q, "_ApprovalQueue__session_identity", evil)
        aid = _queued(ctx, caller=evil)
        try:
            rec, _ = q.break_glass(aid, "incident",
                                   operator_identity=evil, ticket_id="T-OP")
            o["documented_residual_object_setattr_bypass_confirmed"] = (
                rec["status"] == "approved" and rec.get("break_glass"))
        except ValueError:
            o["documented_residual_object_setattr_bypass_confirmed"] = False
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # --- F59b: __class__ swap + property shadowing (new path) -----------
    ctx = _operator_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")

        class _ShadowQ(ApprovalQueue):
            _session_identity = None  # plain attr shadows the property

        q.__class__ = _ShadowQ
        q._session_identity = evil  # instance-dict write, no error
        aid = _queued(ctx, caller=evil)
        try:
            rec, _ = q.break_glass(aid, "incident",
                                   operator_identity=evil, ticket_id="T-OP")
            o["class_swap_shadow_bypass_also_consumes"] = (
                rec["status"] == "approved" and rec.get("break_glass"))
        except ValueError:
            o["class_swap_shadow_bypass_also_consumes"] = False
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # --- F59c: sealed setter re-invocation raises ------------------------
    ctx = _operator_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        try:
            q.set_session_identity(evil)
            o["sealed_setter_reinvoke_raises"] = False
        except SessionIdentityAlreadySetError:
            o["sealed_setter_reinvoke_raises"] = True
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # --- F59d: executor-side mutation is inert ---------------------------
    ctx = _operator_run()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        ex._session_identity = evil
        aid = _queued(ctx, caller=evil)
        try:
            q.break_glass(aid, "incident", operator_identity=evil,
                          ticket_id="T-OP")
            o["executor_side_mutation_refused"] = False
        except ValueError:
            o["executor_side_mutation_refused"] = True
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # --- F64a: weak-mode consume warns + audits once (defense) -----------
    def _weak_ctx():
        return make_run(
            principal_registry=_reg_with_operators(),
            break_glass_tickets=[("T-W", "ops-lead", "duty-reviewer")])

    def _unprotected_count(c):
        es, _ = read_entries_with_stats(c["run_dir"] / "actions.jsonl")
        return sum(1 for e in es
                   if e.get("event") == "break_glass_unprotected")

    ctx = _weak_ctx()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        op = ex.mint_identity("op-1", "operator", "ops-lead")
        aid = _queued(ctx, caller=op)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _ = q.break_glass(aid, "i1", operator_identity=op,
                                   ticket_id="T-W")
        o["weakmode_first_consume_warns_and_audits_once"] = (
            rec["status"] == "approved" and _unprotected_count(ctx) == 1
            and "GOVERNANCE WARNING" in err.getvalue())
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # --- F64b: flag-flip silences warning AND audit entry (F67) ---------
    ctx = _weak_ctx()
    try:
        q, ex = ctx["approvals"], ctx["executor"]
        q._break_glass_unprotected_warned = True  # plain attribute
        op = ex.mint_identity("op-1", "operator", "ops-lead")
        aid = _queued(ctx, caller=op)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _ = q.break_glass(aid, "i1", operator_identity=op,
                                   ticket_id="T-W")
        o["flagflip_silences_warning_and_audit_entry"] = (
            err.getvalue() == "" and _unprotected_count(ctx) == 0
            and rec["status"] == "approved" and rec.get("break_glass"))
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)
    return o


# ---------------------------------------------------------------- sit103

def _w16_f62_schema_mutation():
    """Brief 6: F62 post-construction schema mutation.

    The ``__setattr__`` guard blocks plain reassignment (defense), but
    ``object.__setattr__(tool, "args_schema", StrictSchema)`` and a
    post-construction ``model_config`` mutation + ``model_rebuild``
    BOTH reopen the silent-drop hole: the smuggled kwarg vanishes
    before mediation and the approval record shows clean args.
    FINDING F68 (LOW). The deployment-boundary residual (a deployer
    building their own plain StructuredTool) is unchanged and stays
    the documented boundary."""
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

    def _record_args(c):
        recs = c["approvals"].all()
        return recs[0]["args"] if recs else {}

    # Control: the smuggled kwarg reaches mediation and is denied.
    c, tool = _fresh_tool()
    try:
        r = _invoke(tool)
        o["control_bcc_denied_by_dlp"] = (
            r.get("status") == "denied"
            and r.get("policy_id") == "dlp-credential-block")
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Plain reassignment is still blocked by the __setattr__ guard.
    c, tool = _fresh_tool()
    try:
        try:
            tool.args_schema = _StrictSchema
            o["normal_setattr_still_raises"] = False
        except ValueError:
            o["normal_setattr_still_raises"] = True
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Attack 1: object.__setattr__ swaps in a strict schema.
    c, tool = _fresh_tool()
    try:
        object.__setattr__(tool, "args_schema", _StrictSchema)
        r = _invoke(tool)
        args = _record_args(c)
        o["object_setattr_reopens_silent_drop"] = (
            r.get("status") == "queued"
            and r.get("policy_id") == "approval-outbound-sends"
            and "bcc" not in json.dumps(args))
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Attack 2: mutate the schema class's model_config, then rebuild.
    c, tool = _fresh_tool()
    try:
        _AllowSchema.model_config["extra"] = "ignore"
        _AllowSchema.model_rebuild(force=True)
        r = _invoke(tool)
        args = _record_args(c)
        o["model_config_mutation_reopens_silent_drop"] = (
            r.get("status") == "queued"
            and r.get("policy_id") == "approval-outbound-sends"
            and "bcc" not in json.dumps(args))
    finally:
        _AllowSchema.model_config["extra"] = "allow"
        _AllowSchema.model_rebuild(force=True)
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # The deployment boundary is unchanged: a deployer-built plain
    # StructuredTool bypasses governance entirely (documented in the
    # module docstring; not re-filed).
    import gov.adapters.langchain_tools as lct  # noqa: E402
    o["deployment_boundary_still_documented"] = (
        "builds its *own* plain" in lct.__doc__)
    return o


PROBES = {
    "f55_chain": _w16_f55_chain,
    "f57_chain": _w16_f57_chain,
    "f63_chain": _w16_f63_chain,
    "f60_suppression_matrix": _w16_f60_suppression_matrix,
    "f61_render_flood": _w16_f61_render_flood,
    "tmp_scatter": _w16_tmp_scatter,
    "f59_f64_residuals": _w16_f59_f64_residuals,
    "f62_schema_mutation": _w16_f62_schema_mutation,
}

W16_WIRE = (
    ("sit96", "w16a", "f55_chain", "f55c_"),
    ("sit97", "w16b", "f57_chain", "f57c_"),
    ("sit98", "w16c", "f63_chain", "f63c_"),
    ("sit99", "w16d", "f60_suppression_matrix", "f60m_"),
    ("sit100", "w16e", "f61_render_flood", "f61f_"),
    ("sit101", "w16f", "tmp_scatter", "tmp_"),
    ("sit102", "w16g", "f59_f64_residuals", "id64_"),
    ("sit103", "w16h", "f62_schema_mutation", "f62m_"),
)


def register_w16(playbooks, w7_playbook):
    """Wire the wave-16 probes into run_evals.PLAYBOOKS.

    Registered AFTER register_r14: sit96-sit103 are new situations
    (no overrides of earlier waves). Every probe returns observation
    keys in attacker-active phrasing; True on an attack key means the
    attack step succeeded (a finding: F65-F68), True on a defense key
    means the defense held (an honest cell).
    """
    for sid, mk, pk, pre in W16_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
