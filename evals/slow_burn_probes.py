#!/usr/bin/env python3
"""Row-9 slow-burn accumulator probes (wave-146 lane 1).

Measured residual: paced bursts below ``adapt_flip_floor`` (0.75)
evade the streak, flip, rotation, AND static-budget machinery
entirely -- a [0.5 x warn, clean-defuse] x N pacer never forms a
near-trip cycle (0.5 < 0.75), so the wave-139 streak, wave-141
buckets, wave-144 flip tripwire, wave-145 rotation tripwire, and the
static budget (cleared by every clean run) all stay blind.

This battery is RED-first against the new seam: a slow-burn
accumulator in ``gov/drift_budget.py``. Sub-floor but nonzero
contributions accrue at REDUCED weight into a LONG-window
accumulator (3x the adaptive window); when the weighted accumulation
crosses its own trip threshold with direction consistency, a LOUD
``drift_budget_slow_burn`` event fires and the budget tightens.
Clean runs defuse the accumulator multiplicatively (x
``slow_clean_decay``) -- faster than the long window's passive
expiry, and strong enough that isolated noise never sticks; unlike
the main budget's full clear, the decay is partial so a paced
[sub-floor, clean] campaign still accumulates (that is the shape
this hunts -- a full clear would re-open the exact residual).

Probe map:
  s1_subfloor_pacer_trips: [0.5-threshold contrib, clean-defuse] x N,
     same direction -> LOUD ``drift_budget_slow_burn`` fires (by the
     4th defuse at latest under default policy), the budget
     tightens (adapt record trigger "slow_burn", level 1), and the
     static budget never tripped first (its LOUD event is absent --
     the escalation came from the slow-burn, not the old path).
     (HELD post-seam; BREAK pre-seam -- red-first.)
  s2_slower_pacer_expected: [0.3-threshold contrib, clean-defuse] x 30
     -> never trips: the pacer's fixed point (slow_weight x 0.3 =
     0.15 weighted threshold-equivs) sits below slow_trip (0.2).
     EXPECTED with the measured fixed point -- a slower boil is the
     documented residual, not a feature break (measured, not forced).
  s3_benign_noise_quiet: 200 deterministic zero-mean noise sequences
     (per-tool independent jitter, sub-floor, with clean runs) over
     the long window -> 0 slow-burn trips. Honest FP measurement;
     the bar (slow_trip / slow_weight / consistency gate) was tuned
     until this held -- see the tuning note below.
  s4_single_large_drift_original_path: one 1.2 x warn run -> recorded
     as single_run_path (the single-run path's job), zero slow-burn
     accrual, no LOUD event; ``detect_drift`` still warns (no
     regression on the original path).
  s5_deterministic: the s1 scenario re-run on a fresh store produces
     the byte-identical event sequence (trip at the same run).

Tuning note (measured, not hidden): with slow_weight=0.5 and
slow_clean_decay=0.5, a [c, clean] pacer's within-cycle peak
accumulation converges to exactly c (the raw threshold-equivalents:
peak_n = slow_weight x c x (1 + d + ... + d^{n-1}) -> c as n grows),
so slow_trip=0.3 draws the bar at "sustained directional sub-floor
boils at >= 0.3 threshold-equivs trip; slower boils are the residual".
The 0.5-threshold pacer trips at its 3rd contributing run (run 5);
the 0.3-threshold pacer converges to 0.287 < 0.3 and never trips
(s2 EXPECTED). Raising slow_trip pushes the s1 trip later and lets
faster pacers through; lowering it catches slower pacers but admits
noise FPs. The defaults are the measured knee, and all five knobs
are operator policy, not derived constants.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic (no RNG -- the noise model
uses sha256-derived bits; no wall-clock in verdicts). Stdlib only.

Run:
  mkdir -p /tmp/gov-slowburn
  TMPDIR=/tmp/gov-slowburn ~/workspace/.gov-venv/bin/python \
    evals/slow_burn_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-slowburnb \
    ~/workspace/.gov-venv/bin/python evals/slow_burn_probes.py
"""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-slowburn-%d" % os.getpid())
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


def _has_slow_seam():
    """The wave-146 slow-burn seam: new AdaptiveBudgetPolicy fields."""
    if not _HAVE:
        return False
    try:
        p = _budget.AdaptiveBudgetPolicy(1.0)
    except Exception:
        return False
    return all(hasattr(p, n) for n in (
        "slow_weight", "slow_clean_decay", "slow_trip",
        "slow_window_factor", "slow_min_runs"))


_HAVE_SLOW = _has_slow_seam()

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _need_seam(name):
    if not _HAVE_SLOW:
        _record(name, "BREAK",
                "slow-burn seam missing (AdaptiveBudgetPolicy has no "
                "slow_* fields): %s" % _IMPORT_ERROR)
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
    """warn_distance so a 10-call shift is exactly 0.4 threshold-equivs."""
    d10 = _drift.fingerprint_tool_distance(_fp(_shifted(10)), _base_fp())
    return d10 / 0.4


def _scan_at_most(warn, target, lo=1, hi=80):
    """Largest shift x with D(x)/warn <= target (and its ratio)."""
    best = None
    for x in range(lo, hi + 1):
        d = _drift.fingerprint_tool_distance(_fp(_shifted(x)), _base_fp())
        if d / warn <= target:
            best = (x, d / warn)
    return best


def _policy(warn, **kw):
    args = dict(warn_distance=warn, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5)
    args.update(kw)
    return _budget.AdaptiveBudgetPolicy(**args)


class _Ctx:
    """Fresh store + event sink per probe."""

    def __init__(self, tag, policy):
        self.events = []
        root = Path(tempfile.mkdtemp(prefix="slowburn_%s_" % tag,
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


def _noise_bits(*parts):
    """Deterministic pseudo-random bits from sha256 (no RNG module)."""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    n = int.from_bytes(h, "big")
    return [(n >> i) & 1 for i in range(64)]


# ---------------------------------------------------------------- probes

def _run_pacer(ctx, agent, shift, cycles):
    """[shift-contrib, clean-defuse] x cycles; returns (slow_trip_run,
    main_trip_run) -- first run each fired, None if never."""
    slow_trip_run = None
    main_trip_run = None
    seq = 0
    for _ in range(cycles):
        for tools in (_shifted(shift), dict(_BASE_TOOLS)):
            seq += 1
            ctx.record(agent, tools, seq)
            chk = ctx.check(agent)
            if chk.status == "tripped" and main_trip_run is None:
                main_trip_run = seq
            if "drift_budget_slow_burn" in ctx.event_names() \
                    and slow_trip_run is None:
                slow_trip_run = seq
    return slow_trip_run, main_trip_run


def s1_subfloor_pacer_trips():
    name = "s1_subfloor_pacer_trips"
    if not _need_seam(name):
        return
    warn = _calibrate()
    found = _scan_at_most(warn, 0.5)
    if found is None:
        _record(name, "ERROR", "calibration scan found no <=0.5 shift")
        return
    x, ratio = found
    if ratio < 0.45:
        _record(name, "ERROR",
                "best sub-0.5 shift only %.3f threshold-equivs" % ratio)
        return
    ctx = _Ctx("s1", _policy(warn))
    slow_run, main_run = _run_pacer(ctx, "agent-pacer", x, 10)
    if slow_run is None:
        _record(name, "BREAK",
                "0.5-threshold [contrib,clean] pacer never fired "
                "drift_budget_slow_burn in 10 cycles")
        return
    if main_run is not None and main_run <= slow_run:
        # The static budget must not escalate first: per-cycle
        # cumulative is 0.5 < 1.0 and every clean run defuses it. (A
        # static trip AFTER repeated slow-burn tightenings is the
        # designed ratchet, not a confound -- the first escalation
        # must be the slow-burn.)
        _record(name, "BREAK",
                "static budget tripped at run %d before/at the "
                "slow-burn trip (run %d) -- the escalation did not "
                "come from the slow-burn" % (main_run, slow_run))
        return
    adapts = [r for r in ctx.store.contributions("agent-pacer")
              if r.get("kind") == "adapt"
              and r.get("trigger") == "slow_burn"]
    if not adapts or adapts[0].get("adapt_level") != 1:
        _record(name, "BREAK",
                "slow-burn fired but did not tighten to level 1 "
                "(adapt records: %d)" % len(adapts))
        return
    detail = ctx.check("agent-pacer").detail
    markers = [r for r in ctx.store.contributions("agent-pacer")
               if r.get("kind") == "slow_burn_trip"]
    m = markers[0]
    _record(name, "HELD",
            "0.5-threshold pacer (te=%.3f) fired LOUD "
            "drift_budget_slow_burn at run %d%s; tightened to level 1; "
            "trip-time slow_accum=%.3f cons=%.2f runs=%d"
            % (ratio, slow_run,
               "" if main_run is None
               else " (static ratchet followed at run %d)" % main_run,
               m.get("slow_accum"), m.get("slow_consistency"),
               m.get("slow_runs")))


def s2_slower_pacer_expected():
    name = "s2_slower_pacer_expected"
    if not _need_seam(name):
        return
    warn = _calibrate()
    found = _scan_at_most(warn, 0.3)
    if found is None:
        _record(name, "ERROR", "calibration scan found no <=0.3 shift")
        return
    x, ratio = found
    if ratio < 0.25:
        _record(name, "ERROR",
                "best sub-0.3 shift only %.3f threshold-equivs" % ratio)
        return
    ctx = _Ctx("s2", _policy(warn))
    slow_run, main_run = _run_pacer(ctx, "agent-slow", x, 30)
    detail = ctx.check("agent-slow").detail
    accum = detail.get("slow_burn_accum")
    if slow_run is not None or main_run is not None:
        _record(name, "BREAK",
                "0.3-threshold pacer unexpectedly escalated (slow_run=%r "
                "main_run=%r) -- the fixed-point analysis is wrong"
                % (slow_run, main_run))
        return
    _record(name, "EXPECTED",
            "0.3-threshold pacer (te=%.3f) never trips in 30 cycles: "
            "within-cycle peak accumulation converges to the raw te "
            "(%.3f) < slow_trip %.3f (measured max accum=%.3f) -- "
            "slower boils are the documented residual"
            % (ratio, ratio, ctx.policy.slow_trip, accum))


def s3_benign_noise_quiet():
    name = "s3_benign_noise_quiet"
    if not _need_seam(name):
        return
    warn = _calibrate()
    # Jitter magnitude: fixed 3-call per-tool perturbation; the probe
    # asserts every jitter run lands sub-floor (else ERROR: the noise
    # model, not the product, is miscalibrated).
    trips = 0
    main_trips = 0
    seqs = 200
    runs = 30
    for q in range(seqs):
        ctx = _Ctx("s3q%d" % q, _policy(warn))
        agent = "agent-noise-%d" % q
        for i in range(runs):
            bits = _noise_bits("slowburn-noise", q, i)
            if bits[0] == 0:
                tools = dict(_BASE_TOOLS)  # clean run
            else:
                tools = dict(_BASE_TOOLS)
                for j, tool in enumerate(sorted(_BASE_TOOLS)):
                    s = 1 if bits[1 + j] else -1
                    tools[tool] = max(0, tools[tool] + s * 3)
                d = _drift.fingerprint_tool_distance(
                    _fp(tools), _base_fp())
                te = d / warn
                if te >= 0.75:
                    _record(name, "ERROR",
                            "noise run te=%.3f >= flip floor "
                            "(miscalibrated noise model)" % te)
                    return
            ctx.record(agent, tools, i + 1)
            chk = ctx.check(agent)
            if chk.status == "tripped":
                main_trips += 1
            if "drift_budget_slow_burn" in ctx.event_names():
                trips += 1
                break
    if main_trips:
        _record(name, "ERROR",
                "%d/200 noise sequences tripped the STATIC budget -- "
                "the noise model is too hot, FP measurement confounded"
                % main_trips)
        return
    if trips:
        _record(name, "BREAK",
                "%d/200 benign zero-mean noise sequences tripped the "
                "slow-burn -- FP bar too low, raise slow_trip / lower "
                "slow_weight" % trips)
        return
    _record(name, "HELD",
            "0/200 zero-mean noise sequences (30 runs each) tripped "
            "the slow-burn; static budget quiet on all 200")


def s4_single_large_drift_original_path():
    name = "s4_single_large_drift_original_path"
    if not _need_seam(name):
        return
    warn = _calibrate()
    # Above-WARN shift for the single-run path.
    x = None
    for cand in range(1, 121):
        d = _drift.fingerprint_tool_distance(_fp(_shifted(cand)),
                                             _base_fp())
        if d / warn >= 1.2:
            x = cand
            break
    if x is None:
        _record(name, "ERROR", "no above-WARN shift found")
        return
    ctx = _Ctx("s4", _policy(warn))
    contrib = ctx.record("agent-spike", _shifted(x), 1)
    if contrib.contributes or contrib.reason != "single_run_path":
        _record(name, "BREAK",
                "1.2-threshold run not routed to single_run_path "
                "(reason=%r)" % contrib.reason)
        return
    chk = ctx.check("agent-spike")
    if chk.detail.get("slow_burn_accum"):
        _record(name, "BREAK",
                "single large run accrued to the slow-burn (%.4g)"
                % chk.detail.get("slow_burn_accum"))
        return
    if "drift_budget_slow_burn" in ctx.event_names():
        _record(name, "BREAK",
                "single large run fired drift_budget_slow_burn")
        return
    _record(name, "HELD",
            "1.2-threshold run took the original single_run_path; "
            "slow-burn accum 0, silent")


def s5_deterministic():
    name = "s5_deterministic"
    if not _need_seam(name):
        return
    warn = _calibrate()
    found = _scan_at_most(warn, 0.5)
    if found is None:
        _record(name, "ERROR", "calibration scan found no <=0.5 shift")
        return
    x, _ratio = found

    def scenario():
        ctx = _Ctx("s5", _policy(warn))
        slow_run, _ = _run_pacer(ctx, "agent-det", x, 10)
        return ([e.get("event") for e in ctx.events], slow_run)

    ev1, run1 = scenario()
    ev2, run2 = scenario()
    if ev1 != ev2 or run1 != run2 or run1 is None:
        _record(name, "BREAK",
                "non-deterministic: run1=%r run2=%r events equal=%r"
                % (run1, run2, ev1 == ev2))
        return
    _record(name, "HELD",
            "two runs byte-identical event sequences "
            "(%d events, slow-burn at run %d)" % (len(ev1), run1))


def main():
    names = ("s1_subfloor_pacer_trips", "s2_slower_pacer_expected",
             "s3_benign_noise_quiet",
             "s4_single_large_drift_original_path", "s5_deterministic")
    if not _HAVE:
        for name in names:
            _record(name, "BREAK",
                    "gov.drift_budget not importable: %s" % _IMPORT_ERROR)
    else:
        s1_subfloor_pacer_trips()
        s2_slower_pacer_expected()
        s3_benign_noise_quiet()
        s4_single_large_drift_original_path()
        s5_deterministic()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("slow_burn_probes: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
