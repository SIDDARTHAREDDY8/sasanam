"""Wave-17 adversary probes (TEAM ADVERSARY, 2026-09-22).

Seven new situations (sit104-sit110), registered AFTER register_r15() —
see register_w17() below. evals/r15_probes.py stays UNCHANGED as the
historical round-15 record; the wave-16 attack record in
evals/w16_probes.py is likewise untouched.

Wave-17 briefs (all measured 2026-09-22, scratch copies outside the
repo unless noted):

- sit104 — Brief 1 (F66 cap vs human behavior): the 64KB cap is NOT
  undocumented — the truncated view states TRUNCATED, shown/total byte
  counts, and the GOV_FULL_ARGS=1 affordance, and the hash covers the
  full bytes. This probe pins the byte-70,000 marker case: a marker
  past the cap is not rendered, the marker counts are exact, and the
  displayed digest is independently recomputed over the FULL canonical
  bytes. Honest cell (no finding).
- sit105 — Brief 2 (F60 chain-verification cost): the F60 fallback
  (full verify_chain + full log read per refused sweep while the
  coalescing sidecar is missing/corrupt) scales linearly with log
  size: ~50ms at 2k entries, ~330ms at 10k, ~700ms at 20k. FINDING F69
  (LOW) — CPU amplification, fail-closed preserved, audit stays
  bounded. This probe pins the functional properties (refuse
  fail-closed, exactly one audit entry) and records the suppressed-
  sweep cost with a sub-quadratic scaling bound.
- sit106 — Brief 3 (F68 mediation coverage): every invocation path
  (invoke/run/batch/ainvoke/arun/abatch) funnels through the sync
  _run -> _mediate funnel, so the R15 mediation-time schema re-check
  covers sync AND async. object.__setattr__(tool, "_run", rogue)
  bypasses mediation for BOTH paths (documented F59-class
  hostile-in-process residual — honest cell, not a finding);
  swapping _arun alone does NOT bypass (it is never called when
  coroutine=None). The dict-schema carve-out is correct (undeclared
  kwargs reach DLP); a callable schema swap fails closed (TypeError).
- sit107 — Brief 4 (F67 warning completeness): ApprovalQueue.
  break_glass() is the ONLY product path that can run in
  registry-without-session mode; the CLI constructs a bare queue
  (never registry-configured) and announces BREAK-GLASS loudly on
  stdout. This probe pins exactly-once warning+audit across a direct
  consume and a refused second consume, and documents the CLI
  trust-root boundary. Honest cell (no finding).
- sit108 — Brief 5 (R15 closure-probe honesty): meta-probe. Each of
  the 8 round-15 closure probes was verified non-vacuous on a scratch
  copy (exactly one product fix reverted per copy; all 8 probes fail
  when their fix is gone — see BUILD_LOG.md). Reverting inside the
  gate is impossible (the gate runs the real product), so this probe
  asserts the weaker-but-checkable property: each documented revert
  snippet still occurs EXACTLY ONCE in the current product tree. If
  the product code drifts, the snippet count changes and this probe
  fails, flagging that the honesty evidence must be re-verified.
- sit109 — Brief 6 (F65 cleanup edge cases): an attack probe that
  registers an outside-temp-root directory in the tracked registry
  cannot trigger its removal — the realpath containment check
  refuses it, and cleanup does not crash. (The KEEP-mode
  accumulation measurement — 3 consecutive full gates with
  GOV_KEEP_CELL_DIRS=1 — is recorded in BUILD_LOG.md; it cannot run
  inside a gate cell.)
- sit110 — Brief 7 (demo honesty with >64KB approval): the demo's
  RESULT line is computed by summarize_results() from the verdict
  booleans, never hard-coded — a weakened policy cannot claim a
  clean sweep. The quarantined send_email approval surfaces its
  large body via the DLP descriptor (bytes + sha256_prefix), not
  hidden bytes. Honest cell (no finding).

Conventions: each probe returns a dict of observation keys; the
_w7_playbook turns truthy keys into "observed" cells and falsy keys
into "missing" (which fails the gate). Defense-held keys are phrased
as defenses (True = held); documented-residual keys are
attacker-active (True = the residual reproduces — an honest cell,
not a finding). Probes are memoized per gate via _w7(key, fn), so
each runs once per gate process.
"""

import asyncio
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
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
from gov.approvals import (  # noqa: E402
    _canonical_dumps,
    _print_decision_target,
    main as approvals_main,
    ApprovalQueue,
)
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries_with_stats  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from evals.w16_probes import _fresh_executor  # noqa: E402
from evals.r15_probes import (  # noqa: E402
    _reg_with_operators,
    _queued,
)

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")
_SYNTH_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS-docs example key (synthetic)


# ----------------------------------------------------------------- sit104

def _w17_f66_marker_beyond_cap():
    """Brief 1: byte-70,000 marker case for the 64KB decision-view cap.

    A marker placed past the cap must NOT be rendered in the default
    view; the marker must state exact shown/total byte counts plus the
    GOV_FULL_ARGS=1 affordance; the displayed args_sha256 must equal
    an independently recomputed digest over the FULL canonical bytes;
    GOV_FULL_ARGS=1 must reveal the marker verbatim.
    """
    o = {}
    marker = "W17_MARKER_AT_BYTE_70000"
    blob = "x" * 70000 + marker + "y" * 75000
    rec = {"id": "w17a", "tool": "api_call", "args": {"blob": blob}}
    canon = _canonical_dumps(rec["args"])
    total = len(canon.encode("utf-8"))
    assert total > 70000 + len(marker), "marker must sit past the cap"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_decision_target(rec)
    out = buf.getvalue()
    o["truncated_marker_present"] = "TRUNCATED" in out
    o["marker_states_shown_and_total_bytes"] = (
        "showing" in out and "of %d bytes" % total in out)
    o["full_args_hint_present"] = "GOV_FULL_ARGS=1" in out
    o["marker_beyond_cap_not_rendered"] = marker not in out
    digest = sha256(canon.encode("utf-8")).hexdigest()
    o["digest_covers_full_bytes_independently"] = digest in out
    buf2 = io.StringIO()
    with mock.patch.dict(os.environ, {"GOV_FULL_ARGS": "1"}):
        with contextlib.redirect_stdout(buf2):
            _print_decision_target(rec)
    out2 = buf2.getvalue()
    o["full_view_reveals_marker_verbatim"] = marker in out2
    o["full_view_not_truncated"] = "TRUNCATED" not in out2
    return o


# ----------------------------------------------------------------- sit105

def _w17_f60_fallback_cost():
    """Brief 2: F60 fallback cost — functional pins + scaling bound.

    While the coalescing sidecar is missing/corrupt, each refused
    sweep pays a full verify_chain + full log read. Measured
    2026-09-22: ~50ms at 2k entries, ~330ms at 10k, ~700ms at 20k
    (linear; FINDING F69, LOW). This probe pins the safety
    properties (refuse fail-closed, exactly one audit entry) and
    records the suppressed-sweep wall time with a generous
    sub-quadratic scaling bound (4x entries must cost well under 16x
    time + 2s slack).
    """
    o = {}
    policy = PolicyEngine(DEFAULT_POLICY)
    times = {}
    for n in (500, 2000):
        run_dir = Path(tempfile.mkdtemp(prefix="w17f60c-"))
        try:
            (run_dir / "approvals.lock").mkdir()
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(n):
                log.append({"event": "w17_setup", "i": i})
            # F60 attack shape: corrupt the sidecar before each sweep.
            (run_dir / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8")
            _fresh_executor(run_dir, policy).execute_approved()
            (run_dir / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8")
            ex = _fresh_executor(run_dir, policy)
            t0 = time.perf_counter()
            ret = ex.execute_approved()
            times[n] = time.perf_counter() - t0
            o["sweep_refuses_fail_closed_n%d" % n] = ret == []
            entries, _ = read_entries_with_stats(
                run_dir / "actions.jsonl")
            o["exactly_one_refusal_entry_n%d" % n] = (
                sum(1 for e in entries
                    if e.get("event") == "approval_sweep_refused") == 1)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
    # Timing observations are truthy floats: recorded, never "missing".
    o["suppressed_sweep_wall_ms_n500"] = times[500] * 1000.0 or 0.001
    o["suppressed_sweep_wall_ms_n2000"] = times[2000] * 1000.0 or 0.001
    o["suppressed_sweep_completes"] = times[2000] < 30.0
    o["cost_scales_subquadratically"] = (
        times[2000] < times[500] * 16 + 2.0)
    return o


# ----------------------------------------------------------------- sit106

def _w17_f68_sync_async_mediation():
    """Brief 3: mediation coverage across sync AND async paths.

    Every invocation path (invoke/run/batch/ainvoke/arun/abatch)
    funnels through the sync _run -> _mediate funnel, so the R15
    mediation-time schema re-check covers async too. Documented
    residuals (honest cells): object.__setattr__(tool, "_run", rogue)
    bypasses mediation for BOTH paths (F59-class hostile in-process);
    swapping _arun alone bypasses nothing (dead code when
    coroutine=None). The dict-schema carve-out is correct (undeclared
    kwargs reach DLP); a callable schema swap fails closed loudly.
    """
    o = {}
    from pydantic import BaseModel, ConfigDict  # noqa: E402
    from gov.adapters.core import GovernedBinding  # noqa: E402
    from gov.adapters.langchain_tools import make_governed_tool  # noqa: E402

    class _AllowSchema(BaseModel):
        model_config = ConfigDict(extra="allow")
        to: str
        subject: str = ""
        body: str = ""

    def _fresh_tool():
        c = make_run()
        binding = GovernedBinding(c["executor"],
                                  c["identities"]["support"])
        tool = make_governed_tool(
            binding, "send_email", "send email",
            args_schema=_AllowSchema,
            on_denied="return", on_queued="return")
        return c, tool

    def _invoke(tool):
        raw = tool.invoke({"to": "x@synthetic.local", "subject": "s",
                           "body": "routine", "bcc": _SYNTH_KEY})
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return {"parse_error": raw[:120]}

    # Control: smuggled kwarg reaches mediation; DLP denies.
    c, tool = _fresh_tool()
    try:
        r = _invoke(tool)
        o["control_bcc_denied_by_dlp"] = (
            r.get("status") == "denied"
            and r.get("policy_id") == "dlp-credential-block")
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Dict-schema carve-out is correct: bcc still reaches DLP.
    c, tool = _fresh_tool()
    try:
        object.__setattr__(tool, "args_schema",
                           {"type": "object",
                            "properties": {"to": {"type": "string"}}})
        r = _invoke(tool)
        o["dict_schema_carveout_reaches_dlp"] = (
            r.get("status") == "denied"
            and r.get("policy_id") == "dlp-credential-block")
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Callable schema swap fails closed loudly (TypeError), never
    # silently drops.
    c, tool = _fresh_tool()
    try:
        object.__setattr__(tool, "args_schema", lambda x: x)
        try:
            tool.invoke({"to": "x@synthetic.local", "subject": "s",
                         "body": "b"})
            o["callable_schema_swap_fails_closed"] = False
        except TypeError:
            o["callable_schema_swap_fails_closed"] = True
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Documented residual (attacker-active, honest cell): swapping
    # _run bypasses mediation entirely — and leaves NO governed audit.
    c, tool = _fresh_tool()
    try:
        before, _ = read_entries_with_stats(
            Path(c["run_dir"]) / "actions.jsonl")
        object.__setattr__(
            tool, "_run",
            lambda *a, **k: json.dumps({"status": "executed",
                                        "rogue": True}))
        r = _invoke(tool)
        after, _ = read_entries_with_stats(
            Path(c["run_dir"]) / "actions.jsonl")
        o["setattr_run_swap_bypasses_mediation"] = (
            r.get("rogue") is True)
        o["run_swap_leaves_no_governed_audit"] = (
            len(after) == len(before))
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # The same _run swap bypasses the ASYNC path too: ainvoke funnels
    # through the sync _run when coroutine=None.
    c, tool = _fresh_tool()
    try:
        object.__setattr__(
            tool, "_run",
            lambda *a, **k: json.dumps({"status": "executed",
                                        "rogue": True}))
        raw = asyncio.run(tool.ainvoke({"to": "x@synthetic.local",
                                        "subject": "s", "body": "b"}))
        o["async_path_funnels_through_sync_run"] = (
            json.loads(raw).get("rogue") is True)
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Swapping _arun alone bypasses NOTHING: ainvoke still mediates
    # (queues under approval-outbound-sends).
    c, tool = _fresh_tool()
    try:
        async def _arogue(*a, **k):
            return json.dumps({"status": "executed", "rogue": True})

        object.__setattr__(tool, "_arun", _arogue)
        raw = asyncio.run(tool.ainvoke({"to": "x@synthetic.local",
                                        "subject": "s", "body": "b"}))
        r = json.loads(raw)
        o["arun_swap_alone_does_not_bypass"] = (
            r.get("policy_id") == "approval-outbound-sends"
            and "approval_id" in r)
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)

    # Async batch also funnels through mediation.
    c, tool = _fresh_tool()
    try:
        from gov.adapters.langchain_tools import (  # noqa: E402
            GovernedStructuredTool)
        calls = []
        orig = tool._mediate
        object.__setattr__(
            tool, "_mediate",
            lambda kw: (calls.append(1), orig(kw))[1])
        asyncio.run(tool.abatch([{"to": "x@synthetic.local",
                                  "subject": "s", "body": "b"}] * 2))
        o["async_batch_hits_mediation"] = len(calls) == 2
        assert isinstance(tool, GovernedStructuredTool)
    finally:
        shutil.rmtree(c["run_dir"], ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit107

def _w17_f67_warn_once_total():
    """Brief 4: the weak-mode warning fires exactly once per queue,
    across direct AND refused consumptions; the CLI path is the
    documented trust-root boundary (never registry-configured,
    announces BREAK-GLASS loudly, no weak-mode signal — not silent).
    """
    o = {}
    tickets = [("T-D1", "ops-lead", "duty-reviewer"),
               ("T-D2", "ops-lead", "duty-reviewer")]
    ctx = make_run(principal_registry=_reg_with_operators(),
                   break_glass_tickets=tickets)
    try:
        run_dir = Path(ctx["run_dir"])
        q, ex = ctx["approvals"], ctx["executor"]
        evil = ex.mint_identity("op-1", "operator", "ops-lead")
        a1 = _queued(ctx, caller=evil)
        a2 = _queued(ctx, caller=evil)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rec, _t = q.break_glass(a1, "incident-1",
                                    operator_identity=evil,
                                    ticket_id="T-D1")
            try:
                q.break_glass(a2, "incident-2",
                              operator_identity=evil,
                              ticket_id="T-D2")
                o["second_consume_refused_post_review"] = False
            except ValueError:
                o["second_consume_refused_post_review"] = True
        entries, _ = read_entries_with_stats(run_dir / "actions.jsonl")
        o["direct_consume_warns_exactly_once"] = (
            err.getvalue().count("GOVERNANCE WARNING") == 1)
        o["direct_consume_audits_exactly_once"] = (
            sum(1 for e in entries
                if e.get("event") == "break_glass_unprotected") == 1)
        o["first_consume_approved"] = rec["status"] == "approved"
    finally:
        shutil.rmtree(ctx["run_dir"], ignore_errors=True)

    # CLI path: a fresh CLI-constructed queue is never
    # registry-configured; break-glass announces loudly on stdout.
    ctx2 = make_run(principal_registry=_reg_with_operators(),
                    break_glass_tickets=[("T-C1", "ops-lead",
                                          "duty-reviewer")])
    try:
        run_dir2 = Path(ctx2["run_dir"])
        q2, ex2 = ctx2["approvals"], ctx2["executor"]
        assert q2._registry_configured is True
        evil2 = ex2.mint_identity("op-1", "operator", "ops-lead")
        aid = _queued(ctx2, caller=evil2)
        cli_q = ApprovalQueue(run_dir2,
                              ActionLog(run_dir2 / "actions.jsonl"))
        o["cli_queue_never_registry_configured"] = (
            cli_q._registry_configured is False)
        err2, out2 = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err2), \
                contextlib.redirect_stdout(out2):
            rc = approvals_main(
                ["--rundir", str(run_dir2), "break-glass", aid,
                 "--reason", "incident-3", "--ticket", "T-C1",
                 "--by", "ops-lead"])
        o["cli_break_glass_succeeds"] = rc == 0
        o["cli_emits_no_weak_mode_warning"] = (
            "GOVERNANCE WARNING" not in err2.getvalue())
        o["cli_announces_loudly_on_stdout"] = (
            "BREAK-GLASS" in out2.getvalue())
        entries2, _ = read_entries_with_stats(
            run_dir2 / "actions.jsonl")
        o["cli_writes_no_unprotected_audit"] = (
            sum(1 for e in entries2
                if e.get("event") == "break_glass_unprotected") == 0)
    finally:
        shutil.rmtree(ctx2["run_dir"], ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit108

# Brief 5: the exact one-fix revert snippets applied on scratch
# copies (never the repo) to verify each round-15 closure probe is
# non-vacuous. The gate runs the real product, so this probe asserts
# the checkable property: each snippet's old-text occurs EXACTLY
# ONCE in the current product tree. Measured 2026-09-22: all 8
# probes fail when their fix is reverted (see BUILD_LOG.md).
_W17_REVERT_SNIPPETS = (
    ("f55", "gov/approvals.py",
     "            if operator_identity is not self._session_identity:"),
    ("f57", "gov/approvals.py",
     "                if self._ticket_consumed_in_log(ticket_id):"),
    ("f63", "gov/log.py",
     "        except ValueError:\n"
     "            malformed += 1\n"
     "            continue"),
    ("f60", "gov/executor.py",
     "            ok, _broken_seq, _n = verify_chain(self.log.path)"),
    ("f66", "gov/approvals.py",
     "_DECISION_TARGET_CAP_BYTES = 65536"),
    ("f65", "evals/run_evals.py",
     '    if os.environ.get("GOV_KEEP_CELL_DIRS") == "1":'),
    ("f67", "gov/approvals.py",
     "        return self.__break_glass_unprotected_warned\n"
     "\n"
     "    def _break_glass_unprotected_warn_once(self):"),
    ("f68", "gov/adapters/langchain_tools.py",
     "        if not _args_schema_allows_undeclared(self.args_schema):\n"
     "            raise ValueError(_f62_schema_error(self.args_schema))\n"
     "        if self._facade is None:"),
)


def _w17_closure_revert_honesty():
    """Brief 5: every documented one-fix revert snippet still occurs
    exactly once in the current product tree, so the scratch-copy
    honesty evidence (BUILD_LOG.md) stays applicable. A count != 1
    means the product code drifted and the snippet must be
    re-derived before the next honesty check.
    """
    o = {}
    for name, rel, old in _W17_REVERT_SNIPPETS:
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        o["snippet_%s_occurs_once" % name] = src.count(old) == 1
    return o


# ----------------------------------------------------------------- sit109

def _w17_f65_outside_root_attack():
    """Brief 6: an attack probe that registers an outside-temp-root
    directory in the tracked registry cannot trigger its removal —
    the realpath containment check refuses it, and cleanup does not
    crash. (The R15 sit101 cell covers the non-registered shape;
    this is the registered/attack shape.)
    """
    import evals.run_evals as re  # noqa: E402
    o = {}
    before = list(re._CELL_DIRS)
    victim = None
    try:
        victim = Path(tempfile.mkdtemp(prefix="w17victim-"))
        target = victim / "precious"
        target.mkdir()
        (target / "keep.txt").write_text("precious", encoding="utf-8")
        # Attack shape: the outside-root path IS in the tracked
        # registry (as if a compromised probe registered it).
        re._CELL_DIRS.append(str(target))
        with mock.patch("tempfile.gettempdir",
                        return_value="/nonexistent-tmp-root-w17"):
            try:
                re._cleanup_cell_dirs(*re._CELL_DIRS)
                o["cleanup_does_not_raise"] = True
            except Exception:  # noqa: BLE001
                o["cleanup_does_not_raise"] = False
        o["registered_outside_root_not_removed"] = target.exists()
        o["outside_root_contents_intact"] = (
            (target / "keep.txt").read_text(encoding="utf-8")
            == "precious") if target.exists() else False
    finally:
        re._CELL_DIRS[:] = before
        if victim is not None:
            shutil.rmtree(str(victim), ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit110

def _w17_demo_result_honesty():
    """Brief 7: the demo's RESULT line is computed from the verdict
    booleans by summarize_results() — never hard-coded — so a
    weakened policy cannot claim a clean sweep. The quarantined
    send_email approval surfaces its large body via the DLP
    descriptor (bytes + sha256_prefix), not hidden bytes.
    """
    o = {}
    from demo.attack_scenario import (  # noqa: E402
        _run_demo, summarize_results)
    # Behavioral: the RESULT line is a pure function of verdicts.
    o["result_computed_all_blocked"] = (
        summarize_results([True, True, True, True], True)
        == "RESULT: 4 attack attempts blocked, 0 allowed, "
           "1 tampering detected.")
    o["result_computed_one_allowed"] = (
        summarize_results([True, True, False, True], False)
        == "RESULT: 3 attack attempts blocked, 1 allowed, "
           "0 tampering detected.")
    src = (REPO_ROOT / "demo" / "attack_scenario.py").read_text(
        encoding="utf-8")
    o["no_hardcoded_result_literal"] = (
        '"RESULT: 4 attack attempts blocked' not in src
        and "'RESULT: 4 attack attempts blocked" not in src)
    # Run the demo in a temp cwd (its runs/ output stays out of the
    # repo) and check the printed RESULT equals the computed line.
    work = Path(tempfile.mkdtemp(prefix="w17demo-"))
    old_cwd = os.getcwd()
    buf = io.StringIO()
    try:
        os.chdir(work)
        with contextlib.redirect_stdout(buf):
            _run_demo()
        out = buf.getvalue()
        m = re.search(r"^RESULT: .*\.?$", out, re.M)
        o["demo_prints_result_line"] = m is not None
        if m:
            o["demo_result_matches_computed"] = (
                m.group(0).strip()
                == summarize_results([True, True, True, True], True))
        rundirs = sorted((work / "runs").glob("attack-*"))
        o["demo_run_dir_created"] = len(rundirs) == 1
        if rundirs:
            recs = [json.loads(line) for line in
                    (rundirs[0] / "approvals.jsonl").read_text(
                        encoding="utf-8").splitlines() if line.strip()]
            queued = [r for r in recs if r["status"] == "pending"]
            o["demo_quarantines_exfil_attempt"] = len(queued) == 1
            if queued:
                body = queued[0]["args"].get("body")
                o["large_body_surfaced_as_descriptor"] = (
                    isinstance(body, dict)
                    and "bytes" in body and "sha256_prefix" in body)
                vbuf = io.StringIO()
                with contextlib.redirect_stdout(vbuf):
                    _print_decision_target(queued[0])
                o["descriptor_visible_in_decision_view"] = (
                    "sha256_prefix" in vbuf.getvalue())
    finally:
        os.chdir(old_cwd)
        shutil.rmtree(work, ignore_errors=True)
    return o


PROBES = {
    "f66_marker_beyond_cap": _w17_f66_marker_beyond_cap,
    "f60_fallback_cost": _w17_f60_fallback_cost,
    "f68_sync_async_mediation": _w17_f68_sync_async_mediation,
    "f67_warn_once_total": _w17_f67_warn_once_total,
    "closure_revert_honesty": _w17_closure_revert_honesty,
    "f65_outside_root_attack": _w17_f65_outside_root_attack,
    "demo_result_honesty": _w17_demo_result_honesty,
}

W17_WIRE = (
    ("sit104", "w17a", "f66_marker_beyond_cap", "f66m_"),
    ("sit105", "w17b", "f60_fallback_cost", "f60c_"),
    ("sit106", "w17c", "f68_sync_async_mediation", "f68s_"),
    ("sit107", "w17d", "f67_warn_once_total", "id67t_"),
    ("sit108", "w17e", "closure_revert_honesty", "hon_"),
    ("sit109", "w17f", "f65_outside_root_attack", "tmpa_"),
    ("sit110", "w17g", "demo_result_honesty", "dem_"),
)


def register_w17(playbooks, w7_playbook):
    """Wire the wave-17 probes into run_evals.PLAYBOOKS.

    Registered AFTER register_r15: sit104-sit110 are new situations
    (no overrides of earlier waves). Every probe returns observation
    keys; truthy keys become "observed" cells via _w7_playbook.
    evals/r15_probes.py and evals/w16_probes.py stay UNCHANGED as the
    historical record.
    """
    for sid, mk, pk, pre in W17_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
