"""Hardening round-16 closure probes (2026-09-22).

Registered AFTER register_w17(): the closure assertions override the
wave-17 attack baseline for sit105 (F69) and sit110 (demo). evals/
w17_probes.py stays UNCHANGED as the historical wave-17 record; its
sit105/sit110 playbooks are superseded here and never execute.

- sit105 — F69 CLOSED: the F60 fallback's full chain verification per
  refused sweep is replaced by MAC-authenticated incremental
  chain-tip verification (gov/log.py verify_chain_tip). This probe
  pins the fix: a cold sweep seeds the tip, warm refused sweeps at
  20k entries stay under 150ms (measured worst 73ms across 3 trials
  on this VM; the wave-17 baseline was ~580-690ms), sweeps refuse
  fail-closed with exactly one audit entry, a segment forgery and a
  tail truncation go loud, and a deleted/corrupt tip degrades to full
  verification (fail-loud, never silent trust).
- sit110 — demo direct-invocation closure: keeps every wave-17 demo
  honesty observation (RESULT computed, never hard-coded) and adds
  the R16 fix pins — ``python3 demo/attack_scenario.py`` exits 0
  with an honest RESULT line (the __main__ guard used to sit above
  main()'s def -> NameError), and the gov-attack-demo entry point
  (demo.attack_scenario:main) still works.

Conventions: each probe returns a dict of observation keys; the
_w7_playbook turns truthy keys into "observed" cells and falsy keys
into "missing" (which fails the gate). Probes are memoized per gate
via _w7(key, fn), so each runs once per gate process.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT)
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
tests_path = str(REPO_ROOT / "tests")
if tests_path not in sys.path:
    sys.path.insert(0, tests_path)

from gov.log import (  # noqa: E402
    ActionLog,
    _read_tip_cache,
    _tip_cache_path,
    verify_chain,
    verify_chain_tip,
)
from gov.policy import PolicyEngine  # noqa: E402
from evals.w16_probes import _fresh_executor  # noqa: E402
from evals.w17_probes import _w17_demo_result_honesty  # noqa: E402

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")

# Measured 2026-09-22 (this VM): worst warm refused sweep at 20k
# entries was 73ms across 3 trials (typical 30-50ms). The bound
# carries ~2x headroom; it pins the F69 fix, not the hardware.
_R16_WARM_BOUND_SECS = 0.150
_R16_N = 20000


def _r16_refused_sweep(run_dir, policy):
    (run_dir / "lock_refusal_coalesce.json").write_text(
        '{"broken": true', encoding="utf-8")
    ex = _fresh_executor(run_dir, policy)
    t0 = time.perf_counter()
    ret = ex.execute_approved()
    return ret, time.perf_counter() - t0, ex


def _r16_refusal_audits(run_dir):
    n = 0
    for line in (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("event") == "approval_sweep_refused" \
                and e.get("decision") == "refused":
            n += 1
    return n


# ----------------------------------------------------------------- sit105

def _r16_f69_tip_closure():
    """Round-16 closure for F69 (sit105).

    The wave-17 baseline measured ~35ms/1k entries per refused sweep
    (~700ms at 20k) while the coalesce state file was held corrupt.
    The fix verifies incrementally from a MAC-authenticated chain
    tip: the action-log read is O(new bytes) via byte offsets, so a
    warm sweep costs milliseconds. Any tip/segment failure degrades
    to full verification (fail-loud).
    """
    o = {}
    policy = PolicyEngine(DEFAULT_POLICY)
    run_dir = Path(tempfile.mkdtemp(prefix="r16f69-"))
    try:
        (run_dir / "approvals.lock").mkdir()
        log = ActionLog(run_dir / "actions.jsonl")
        for i in range(_R16_N):
            log.append({"event": "r16_setup", "i": i})
        # Cold sweep: pays one full verification, seeds the tip.
        ret, _dt, _ex = _r16_refused_sweep(run_dir, policy)
        o["cold_sweep_refuses_fail_closed"] = ret == []
        o["tip_seeded_on_cold_sweep"] = (
            _read_tip_cache(run_dir / "actions.jsonl") is not None)
        # Warm sweeps under the sustained-corruption attack shape.
        worst = 0.0
        all_closed = True
        for _ in range(5):
            ret, dt, _ex = _r16_refused_sweep(run_dir, policy)
            all_closed = all_closed and ret == []
            worst = max(worst, dt)
        o["warm_sweeps_refuse_fail_closed"] = all_closed
        o["warm_sweep_worst_ms"] = worst * 1000.0 or 0.001
        o["warm_sweep_under_150ms_at_20k"] = (
            worst < _R16_WARM_BOUND_SECS)
        o["exactly_one_refusal_entry"] = (
            _r16_refusal_audits(run_dir) == 1)
        # Back-to-back incremental verifies with no new entries (the
        # stored checkpoint anchor must carry its key_epoch).
        ok3 = True
        for _ in range(3):
            v = verify_chain_tip(run_dir / "actions.jsonl",
                                 flags=("queue_lock_invalid",))
            ok3 = ok3 and v is not None and v["ok"]
        o["repeated_tip_verify_ok"] = ok3
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    # Segment forgery after the tip -> incremental rejects, full
    # verify reports the tamper, refusal audits loud.
    run_dir = Path(tempfile.mkdtemp(prefix="r16f69f-"))
    try:
        (run_dir / "approvals.lock").mkdir()
        log = ActionLog(run_dir / "actions.jsonl")
        for i in range(3000):
            log.append({"event": "r16_setup", "i": i})
        _r16_refused_sweep(run_dir, policy)
        with open(run_dir / "actions.jsonl", "a",
                  encoding="utf-8") as f:
            f.write('{"seq": 3002, "event": "approval_sweep_refused", '
                    '"flag": "queue_lock_invalid", "hash": "00", '
                    '"prev_hash": "00", "format_version": 1, '
                    '"key_epoch": "dev"}\n')
        o["segment_forgery_rejected_incrementally"] = (
            verify_chain_tip(run_dir / "actions.jsonl") is None)
        ok, broken, _n = verify_chain(run_dir / "actions.jsonl")
        o["segment_forgery_detected_by_full_verify"] = (
            not ok and broken is not None)
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = _fresh_executor(run_dir, policy)
        o["forgery_does_not_suppress"] = (
            ex._log_shows_recent_lock_refusal("queue_lock_invalid")
            is False)
        o["forgery_audits_loud"] = bool(
            ex._audit_lock_refusal("queue_lock_invalid", "r16-probe"))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    # Deleted/corrupt tip -> full-verify fallback, still fail-closed.
    for mode in ("deleted", "corrupt"):
        run_dir = Path(tempfile.mkdtemp(prefix="r16f69t-"))
        try:
            (run_dir / "approvals.lock").mkdir()
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(3000):
                log.append({"event": "r16_setup", "i": i})
            _r16_refused_sweep(run_dir, policy)
            tip_path = _tip_cache_path(run_dir / "actions.jsonl")
            if mode == "deleted":
                tip_path.unlink()
            else:
                tip_path.write_text("garbage{{{", encoding="utf-8")
            ret, _dt, _ex = _r16_refused_sweep(run_dir, policy)
            o["%s_tip_refuses_fail_closed" % mode] = ret == []
            o["%s_tip_audits_exactly_once" % mode] = (
                _r16_refusal_audits(run_dir) == 1)
            o["%s_tip_reseeded" % mode] = (
                _read_tip_cache(run_dir / "actions.jsonl") is not None)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    # Tail truncation past the checkpoint anchor -> loud.
    run_dir = Path(tempfile.mkdtemp(prefix="r16f69d-"))
    try:
        (run_dir / "approvals.lock").mkdir()
        log = ActionLog(run_dir / "actions.jsonl")
        for i in range(3000):
            log.append({"event": "r16_setup", "i": i})
        _r16_refused_sweep(run_dir, policy)
        log_path = run_dir / "actions.jsonl"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n".join(lines[:1500]) + "\n",
                            encoding="utf-8")
        o["truncation_defeats_tip"] = (
            verify_chain_tip(log_path) is None)
        (run_dir / "lock_refusal_coalesce.json").write_text(
            '{"broken": true', encoding="utf-8")
        ex = _fresh_executor(run_dir, policy)
        o["truncation_audits_loud"] = bool(
            ex._audit_lock_refusal("queue_lock_invalid", "r16-probe"))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit110

def _r16_demo_direct_invocation():
    """Round-16 closure for the demo invocation wart (sit110).

    Keeps every wave-17 demo-honesty observation and adds the R16
    fix: ``python3 demo/attack_scenario.py`` exits 0 with an honest
    RESULT line (the __main__ guard used to sit above main()'s def,
    raising NameError), and the gov-attack-demo console-script target
    (demo.attack_scenario:main) still works.
    """
    o = _w17_demo_result_honesty()
    work = Path(tempfile.mkdtemp(prefix="r16demo-"))
    try:
        proc = subprocess.run(
            [sys.executable,
             str(REPO_ROOT / "demo" / "attack_scenario.py")],
            cwd=str(work), capture_output=True, text=True, timeout=120)
        o["direct_invocation_exit_zero"] = proc.returncode == 0
        m = None
        if proc.returncode == 0:
            import re
            m = re.search(r"^RESULT: .*\.?$", proc.stdout, re.M)
        o["direct_invocation_prints_result"] = m is not None
        o["direct_invocation_no_traceback"] = (
            "Traceback" not in proc.stderr
            and "NameError" not in proc.stderr)

        ep = Path(tempfile.mkdtemp(prefix="r16demoep-"))
        try:
            proc2 = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); "
                 "from demo.attack_scenario import main; "
                 "raise SystemExit(main())" % str(REPO_ROOT)],
                cwd=str(ep), capture_output=True, text=True,
                timeout=120)
            o["entry_point_still_works"] = (
                proc2.returncode == 0
                and "Traceback" not in proc2.stderr)
        finally:
            shutil.rmtree(ep, ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return o


PROBES = {
    "f69_tip_closure": _r16_f69_tip_closure,
    "demo_direct_invocation": _r16_demo_direct_invocation,
}

R16_WIRE = (
    ("sit105", "r16a", "f69_tip_closure", "f69t_"),
    ("sit110", "r16b", "demo_direct_invocation", "dem16_"),
)


def register_r16(playbooks, w7_playbook):
    """Wire the round-16 closure probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w17: the closure assertions override
    the wave-17 attack baseline for sit105 (F69 CLOSED) and sit110
    (demo direct invocation). evals/w17_probes.py stays UNCHANGED as
    the historical wave-17 record; its sit105/sit110 playbooks are
    superseded here and never execute.
    """
    for sid, mk, pk, pre in R16_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
