#!/usr/bin/env python3
"""Row-9 cumulative sub-threshold drift budget probes (wave-138 lane).

Row 9's measured residual: slow drift where each individual run stays
under the WARN threshold never escalates -- an attacker can boil the
frog in 0.4-threshold steps forever. This battery exercises the
``gov.drift_budget`` seam: each run contributes its drift distance
(reusing ``gov.drift.fingerprint_tool_distance`` -- the wave-134
population-baseline fingerprinting machinery, not duplicated) to a
per-agent budget. N consecutive sub-threshold-but-nonzero deviations
within a run window escalate to a LOUD ``drift_budget_tripped``
evidence event. Accumulation is never silent: every contributing run
emits a chained ``drift_budget_accrue`` audit event. The existing
single-run WARN path (``gov.drift.detect_drift``) is unchanged.

  b1_frog_boil_escalates: 5 runs, each 0.4 x warn_distance, same
     direction -> budget trips (cumulative 2.0 >= 1.0) with a LOUD
     ``drift_budget_tripped`` event; every run was audited (never
     silent accumulation).
  b2_single_big_run_unchanged: one 0.9 x warn_distance run -> the
     EXISTING single-run path (``gov.drift.detect_drift``) still
     fires WARN (no regression); the budget does NOT trip on a single
     run (budget is cumulative, single runs are detect_drift's job).
  b3_oscillation_no_escalation: 10 runs alternating +/-8-call mirror
     shifts around the baseline -> cumulative unsigned accrual is
     large (would trip on magnitude alone) but net direction cancels
     (consistency ~ 0) -> NO trip. Plus: 6 runs of sub-noise-floor
     +/-1 jitter contribute nothing at all.
  b4a_clean_run_resets: 2 x 0.4 contributing runs, then a clean run
     (distance 0, at/below the noise floor) -> the budget is cleared
     to 0, a ``drift_budget_reset`` event is audited, no trip.
     (Design choice documented: a clean run defuses the budget.)
  b4b_window_expiry: window_runs=4; a 0.4 contribution at seq 1, then
     four above-WARN runs (the budget ignores them -- that is the
     single-run path's job; they neither contribute nor reset) -> by
     seq 5 the seq-1 contribution has expired out of the sliding
     window -> cumulative 0, no trip.
  b5_threshold_gaming_ceiling: EXPECTED, not a feature BREAK. An
     attacker who knows the policy (two 0.4 contributions, then a
     clean run to defuse, repeated) never trips the budget. This is
     the pinned honest ceiling: threshold-aware pacing defeats any
     fixed budget; window/N/policy are operator trade-offs, not
     proofs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

If ``gov.drift_budget`` cannot be imported, every probe is BREAK
("not implemented"): the gap is pinned red (pre-feature state).

Honest ceilings (also in the module docstring):
- window/N/budget_limit/noise_floor are operator policy. An attacker
  who knows N and the window can stay under them (b5) -- the
  threshold-gaming residual stands.
- Tuning trade-off: a lower noise floor / smaller window detects
  slower boils later (detection latency up) but tolerates less
  benign jitter; a higher floor / larger window is the reverse.
- The budget measures sustained directional drift in the
  tool-distribution fingerprint only -- content-level and
  destination-level drift are other modules' jobs.

$0 spend, synthetic/local, deterministic (no RNG; no wall-clock in
verdicts; float math is exact-deterministic on one machine; the
battery is self-calibrating from measured distances). Stdlib only.

Run:
  mkdir -p /tmp/gov-driftbudget
  TMPDIR=/tmp/gov-driftbudget ~/workspace/.gov-venv/bin/python \
    evals/drift_budget_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-driftbudgetb \\
    ~/workspace/.gov-venv/bin/python evals/drift_budget_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "driftbudget-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-driftbudget-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import drift as _drift  # noqa: E402
    from gov import drift_budget as _budget  # noqa: E402
    _HAVE = True
    _IMPORT_ERROR = ""
except ImportError as _e:  # noqa: E402
    _drift = None
    _budget = None
    _HAVE = False
    _IMPORT_ERROR = str(_e)

_HAVE_SEAM = _HAVE and all(
    hasattr(_budget, n)
    for n in ("BudgetPolicy", "BudgetStore", "BudgetCheck",
              "BudgetContribution"))

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _need_seam(name):
    if not _HAVE_SEAM:
        _record(name, "BREAK",
                "gov.drift_budget seam missing: %s" % _IMPORT_ERROR)
        return False
    return True


# ------------------------------------------------------------ fixtures

_BASE_TOOLS = {"search": 90, "summarize": 80, "email": 60,
               "read_file": 40, "http_post": 10}


def _fp(tools, run_seq=0, run_id="r"):
    return _drift.RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": 0},
        approvals_requested=0, approvals_granted=0, approvals_denied=0,
        egress_events=1, egress_bytes=1000,
        run_seq=run_seq, run_id="%s-%d" % (run_id, run_seq))


def _shifted(x):
    """Move x calls search -> http_post (the boil direction)."""
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["http_post"] += x
    return t


_BASE_FP = None


def _base_fp():
    global _BASE_FP
    if _BASE_FP is None:
        _BASE_FP = _fp(_BASE_TOOLS)
    return _BASE_FP


def _calibrate():
    """Self-calibrating policy: warn_distance from a measured 0.4 step.

    warn_distance = D(shift 10) / 0.4, so a 10-call shift is exactly
    0.4 threshold-equivalents. Deterministic: distances are exact
    computations on fixed fixtures.
    """
    d10 = _drift.fingerprint_tool_distance(_fp(_shifted(10)), _base_fp())
    warn = d10 / 0.4
    return warn


def _scan_below(warn, ceiling=1.0, lo=1, hi=80):
    """Largest shift x with D(x)/warn < ceiling (for the 0.9 run)."""
    best = None
    for x in range(lo, hi + 1):
        d = _drift.fingerprint_tool_distance(_fp(_shifted(x)), _base_fp())
        if d / warn < ceiling:
            best = (x, d / warn)
    return best


def _scan_at_or_above(warn, floor=1.2, lo=1, hi=120):
    """Smallest shift x with D(x)/warn >= floor (above-WARN run)."""
    for x in range(lo, hi + 1):
        d = _drift.fingerprint_tool_distance(_fp(_shifted(x)), _base_fp())
        if d / warn >= floor:
            return (x, d / warn)
    return None


class _Ctx:
    """Fresh store + event sink per probe."""

    def __init__(self, tag, policy):
        self.events = []
        root = Path(tempfile.mkdtemp(prefix="driftbudget_%s_" % tag,
                                     dir=os.environ["TMPDIR"]))
        self.store = _budget.BudgetStore(root / "budget",
                                         audit=self._audit)
        self.policy = policy

    def _audit(self, event):
        self.events.append(dict(event))

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq,
                                         run_id="run-%d" % seq),
                                     _base_fp(), self.policy)

    def check(self, agent):
        return self.store.check(agent, self.policy)

    def event_names(self):
        return [e.get("event") for e in self.events]


def _policy(warn, **kw):
    args = dict(warn_distance=warn, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5)
    args.update(kw)
    return _budget.BudgetPolicy(**args)


# ---------------------------------------------------------------- probes

def b1_frog_boil_escalates():
    name = "b1_frog_boil_escalates"
    if not _need_seam(name):
        return
    warn = _calibrate()
    ctx = _Ctx("b1", _policy(warn))
    first_trip = None
    for i in range(5):
        contrib = ctx.record("agent-frog", _shifted(10), i + 1)
        if abs(contrib.threshold_equivalents - 0.4) > 1e-9:
            _record(name, "BREAK",
                    "run %d contributed %.4g threshold-equivs, want 0.4"
                    % (i + 1, contrib.threshold_equivalents))
            return
        chk = ctx.check("agent-frog")
        if chk.status == "tripped" and first_trip is None:
            first_trip = i + 1
    chk = ctx.check("agent-frog")
    if chk.status != "tripped":
        _record(name, "BREAK",
                "5x 0.4-threshold drifts did not trip the budget "
                "(cumulative=%.3f)" % chk.cumulative)
        return
    if "drift_budget_tripped" not in ctx.event_names():
        _record(name, "BREAK", "budget tripped but no LOUD "
                "drift_budget_tripped evidence event")
        return
    accrues = [e for e in ctx.events
               if e.get("event") == "drift_budget_accrue"
               and e.get("contributes")]
    if len(accrues) != 5:
        _record(name, "BREAK",
                "accumulation not fully audited: %d/5 accrue events"
                % len(accrues))
        return
    _record(name, "HELD",
            "tripped after run %d (cumulative=%.2f); LOUD event present; "
            "5/5 runs audited" % (first_trip, chk.cumulative))


def b2_single_big_run_unchanged():
    name = "b2_single_big_run_unchanged"
    if not _need_seam(name):
        return
    warn = _calibrate()
    found = _scan_below(warn, ceiling=1.0)
    if found is None:
        _record(name, "ERROR", "calibration scan found no sub-WARN shift")
        return
    x, ratio = found
    if ratio < 0.85:
        _record(name, "ERROR",
                "best sub-WARN shift only %.3f threshold-equivs (<0.85)"
                % ratio)
        return
    ctx = _Ctx("b2", _policy(warn))
    contrib = ctx.record("agent-spike", _shifted(x), 1)
    if not contrib.contributes:
        _record(name, "BREAK",
                "0.97-threshold run did not contribute to the budget")
        return
    chk = ctx.check("agent-spike")
    if chk.status == "tripped":
        _record(name, "BREAK",
                "budget tripped on a SINGLE run -- budget must be "
                "cumulative-only")
        return
    # The existing single-run path must still fire (no regression).
    dstore = _drift.DriftStore(
        Path(tempfile.mkdtemp(prefix="driftbudget_b2d_",
                              dir=os.environ["TMPDIR"])))
    for i in range(5):
        dstore.record_run("agent-spike", "p", _fp(_BASE_TOOLS, run_seq=i))
    dstore.record_run("agent-spike", "p", _fp(_shifted(x), run_seq=5))
    res = _drift.detect_drift(dstore, "agent-spike", window=1,
                              baseline_runs=4)
    if res.level not in ("warn", "hold"):
        _record(name, "BREAK",
                "single-run path regressed: detect_drift=%s (want warn/hold)"
                % res.level)
        return
    _record(name, "HELD",
            "single %.2f-threshold run: budget silent (cumulative=%.2f), "
            "detect_drift still %s"
            % (ratio, chk.cumulative, res.level))


def b3_oscillation_no_escalation():
    name = "b3_oscillation_no_escalation"
    if not _need_seam(name):
        return
    warn = _calibrate()
    ctx = _Ctx("b3", _policy(warn))

    def osc(sign, m=8):
        t = dict(_BASE_TOOLS)
        t["search"] -= sign * m
        t["http_post"] += sign * m
        return t

    for i in range(10):
        tools = osc(1 if i % 2 == 0 else -1)
        contrib = ctx.record("agent-noisy", tools, i + 1)
        if not contrib.contributes:
            _record(name, "BREAK",
                    "oscillating run %d above noise floor did not "
                    "contribute (audit gap)" % (i + 1))
            return
    chk = ctx.check("agent-noisy")
    if chk.status == "tripped":
        _record(name, "BREAK",
                "budget tripped on directionless oscillation "
                "(consistency=%.3f) -- direction gate failed"
                % chk.consistency)
        return
    if chk.cumulative < 1.0:
        _record(name, "ERROR",
                "oscillation cumulative only %.3f -- probe too weak to "
                "test the gate" % chk.cumulative)
        return
    # Sub-noise-floor jitter must contribute nothing at all.
    ctx2 = _Ctx("b3b", _policy(warn))
    for i in range(6):
        c = ctx2.record("agent-jitter", osc(1 if i % 2 == 0 else -1, m=1),
                        i + 1)
        if c.contributes or c.threshold_equivalents != 0.0:
            _record(name, "BREAK",
                    "sub-noise-floor jitter contributed %.4g" %
                    c.threshold_equivalents)
            return
    chk2 = ctx2.check("agent-jitter")
    if chk2.cumulative != 0.0:
        _record(name, "BREAK", "jitter left cumulative=%.4g"
                % chk2.cumulative)
        return
    _record(name, "HELD",
            "10 alternating runs: cumulative=%.2f but consistency=%.3f "
            "-> no trip; jitter contributes 0" %
            (chk.cumulative, chk.consistency))


def b4a_clean_run_resets():
    name = "b4a_clean_run_resets"
    if not _need_seam(name):
        return
    warn = _calibrate()
    ctx = _Ctx("b4a", _policy(warn))
    ctx.record("agent-reset", _shifted(10), 1)
    ctx.record("agent-reset", _shifted(10), 2)
    mid = ctx.check("agent-reset")
    if abs(mid.cumulative - 0.8) > 1e-9:
        _record(name, "BREAK", "pre-reset cumulative=%.4g, want 0.8"
                % mid.cumulative)
        return
    clean = ctx.record("agent-reset", dict(_BASE_TOOLS), 3)
    if clean.contributes:
        _record(name, "BREAK", "clean run contributed to the budget")
        return
    chk = ctx.check("agent-reset")
    if chk.cumulative != 0.0 or chk.status == "tripped":
        _record(name, "BREAK",
                "budget not cleared by clean run (cumulative=%.4g, %s)"
                % (chk.cumulative, chk.status))
        return
    if "drift_budget_reset" not in ctx.event_names():
        _record(name, "BREAK", "reset happened but no drift_budget_reset "
                "event was audited")
        return
    _record(name, "HELD",
            "clean run defused 0.8 cumulative -> 0.0; reset audited "
            "(documented design choice)")


def b4b_window_expiry():
    name = "b4b_window_expiry"
    if not _need_seam(name):
        return
    warn = _calibrate()
    ctx = _Ctx("b4b", _policy(warn, window_runs=4))
    ctx.record("agent-window", _shifted(10), 1)  # 0.4, in window at first
    big = _scan_at_or_above(warn, floor=1.2)
    if big is None:
        _record(name, "ERROR", "calibration scan found no above-WARN shift")
        return
    bx, bratio = big
    for seq in (2, 3, 4, 5):
        c = ctx.record("agent-window", _shifted(bx), seq)
        if c.contributes:
            _record(name, "BREAK",
                    "above-WARN run (%.2f x) contributed to the budget -- "
                    "single-run territory must not accrue" % bratio)
            return
    chk = ctx.check("agent-window")
    if chk.cumulative != 0.0 or chk.status == "tripped":
        _record(name, "BREAK",
                "stale seq-1 contribution not expired (cumulative=%.4g)"
                % chk.cumulative)
        return
    _record(name, "HELD",
            "seq-1 0.4 contribution expired out of window_runs=4; "
            "above-WARN runs ignored by budget (cumulative=0.0)")


def b5_threshold_gaming_ceiling():
    name = "b5_threshold_gaming_ceiling"
    if not _need_seam(name):
        return
    warn = _calibrate()
    ctx = _Ctx("b5", _policy(warn))
    # Threshold-aware attacker: two 0.4 contributions (0.8 < 1.0),
    # then a clean run to defuse, repeated 3x. Knows the policy.
    for cycle in range(3):
        base = cycle * 3
        ctx.record("agent-gamer", _shifted(10), base + 1)
        ctx.record("agent-gamer", _shifted(10), base + 2)
        ctx.record("agent-gamer", dict(_BASE_TOOLS), base + 3)  # defuse
        chk = ctx.check("agent-gamer")
        if chk.status == "tripped":
            _record(name, "BREAK",
                    "gaming attacker tripped the budget in cycle %d -- "
                    "either the probe or the defuse is wrong" % (cycle + 1))
            return
        if chk.cumulative != 0.0:
            _record(name, "BREAK",
                    "clean run did not defuse in cycle %d (%.4g)"
                    % (cycle + 1, chk.cumulative))
            return
    _record(name, "EXPECTED",
            "policy-aware pacing (0.4+0.4 then clean defuse, x3) never "
            "trips -- threshold gaming is a documented residual, not a "
            "feature break")


def main():
    if not _HAVE:
        for name in ("b1_frog_boil_escalates",
                     "b2_single_big_run_unchanged",
                     "b3_oscillation_no_escalation",
                     "b4a_clean_run_resets",
                     "b4b_window_expiry",
                     "b5_threshold_gaming_ceiling"):
            _record(name, "BREAK",
                    "gov.drift_budget not importable: %s" % _IMPORT_ERROR)
    else:
        b1_frog_boil_escalates()
        b2_single_big_run_unchanged()
        b3_oscillation_no_escalation()
        b4a_clean_run_resets()
        b4b_window_expiry()
        b5_threshold_gaming_ceiling()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("drift_budget_probes: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
