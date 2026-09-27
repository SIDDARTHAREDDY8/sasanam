#!/usr/bin/env python3
"""Break-first probes for wave-145 row-9 N-period rotation pacing.

Wave-144 residual (stated ROC gap): the flip-confirmation tripwire
closes only 2-period (A/B/A) oscillations; 3+-period rotations were
said to evade it. Break-first measurement refined the premise:

- ODD-period paced rotations are ALREADY covered -- by the
  wave-139 direction-aware near-trip streak, via a parity
  argument: for the streak to stay blind every consecutive paced
  pair must cancel (L_{i+1} ≈ -L_i on the large components) while
  periodicity demands L_{i+p} = L_i; for odd p this forces
  L_i ≈ 0, contradicting "paced". A bounded randomized search
  over ~125k paced burst shapes found ZERO 3-period
  streak+flip-evading constructions. The naive A/B/C 3-period
  pacer trips at run 7 via ``near_trip_cycle`` (r2 pins this).
- EVEN-period is the true residual: a 4-period "wobble" rotation
  (pairwise-canceling ~0.9x bursts whose small wobble moves morph
  the direction signature each cycle: X,Y,Z,W distinct sigs, every
  consecutive pair canceling >=50% in L1) evades the streak (pairs
  cancel), the flip tripwire (signatures never close a 2-period),
  and the static budget -- only the wave-141 per-direction
  buckets catch it, at ~run 42.

Wave-145 extends the seam: paced defuse cycles (near-trip at >=
``adapt_flip_floor`` -- the SAME floor and the SAME
direction-consistency gating the flip detector uses; sub-floor
alternating bursts never enter the rotation history) append their
direction signature to a rotation history riding the chained
reset records. For periods p in 3..K (K=4), a trailing window
whose last 2p signatures are two clean back-to-back repetitions
of one period-p pattern (autocorrelation at lag p = 1.0) with at
least two distinct directions inside the period confirms pacing
LOUD with trigger ``rotation_pacing_confirmed`` -- exactly like a
confirmed flip (same floor, same tightening: reset_streak +
reset_directions) -- and the next contributing run trips under
the tightened limit. Period 2 stays the flip tripwire's
(byte-identical); period 1 (single direction) stays the
near-trip streak's.

Probes:
  r1_rotation4_wobble_confirms: 4-period wobble pacer at ~0.9x
     ([X, clean, Y, clean, Z, clean, W, clean] x2 + [X]) confirms
     at the 8th paced cycle's defuse (run 16) via LOUD
     ``rotation_pacing_confirmed`` (period 4) and trips on the
     next contributing run (run 17). BREAK pre-seam (evades: 0
     adaptations through run 17; buckets only at ~run 42).
  r2_period3_streak_covers: naive 3-period A/B/C pacer at ~0.9x
     trips at run 7 via the EXISTING ``near_trip_cycle`` streak --
     the "3-period evasion" premise does not hold against the
     full budget (parity argument above). HELD pre- AND post-seam;
     asserts no ``rotation_pacing_confirmed`` fires (the streak
     owns period 3) and the trip run is unchanged.
  r3_two_period_no_regression: the wave-144 f1 shape
     ([fwd, clean, rev, clean] x4) still trips at run 7 via LOUD
     ``direction_pacing_confirmed`` (NOT the rotation trigger) --
     the 2-period path is byte-identical. HELD pre- and post-seam.
  r4_random_benign_quiet: >=200 deterministic random benign
     sequences (random directions/magnitudes, random cleans,
     occasional near-threshold bursts) -> 0
     ``rotation_pacing_confirmed`` adaptations; the count is
     reported honestly. HELD pre- and post-seam.
  r5_documented_tradeoff: a sustained benign 4-task wobble
     rotation at ~0.9x adapts via ``rotation_pacing_confirmed`` --
     the DELIBERATE, documented FP: sustained rotating
     near-threshold bursts are pacing-indistinguishable from the
     attack by construction. BREAK pre-seam (stays quiet), HELD
     post-seam (pins the price).
  r6_subfloor_rotation_quiet: 4-period wobble at ~0.5x (below the
     0.75 pacing floor) x8 paced cycles -> 0 adaptations, 0 trips;
     the rotation history never accumulates. HELD pre/post.
  r7_breaker_cycles_clear: paced wobble cycles separated by
     sub-floor breaker defuse cycles (alternating exact-opposite
     directions, net zero -- a same-direction breaker train is the
     slow-burn accumulator's attack shape, so the scaffolding stays
     direction-inert) -> 0 adaptations (non-paced cycles clear the
     history). HELD pre/post.
  r8_deterministic_x2: r1+r2+r3 verdicts byte-identical across two
     runs.

Honest ceilings (documented, not tested away):
- The confirmation needs an EXACT tail repetition (agreement 1.0)
  over two full periods at >= the pacing floor: morph the
  direction signatures (not just magnitudes -- the key is
  sign-pattern only), pace any cycle sub-0.75, never repeat a
  fixed rotation, or break consecutiveness with sub-floor cycles,
  and the tripwire stays blind. Threshold-gaming mutates, it does
  not die.
- 5+-period rotations still evade the confirmation (the wave-141
  buckets remain the backstop, later). A benign workload that
  persistently rotates near-threshold bursts WILL adapt early (r5)
  -- the measured price of the earlier trip.

$0 spend, synthetic/local, deterministic (seeded RNG only in r4;
no wall-clock in verdicts; the battery is self-calibrating from
measured distances). Stdlib only.

Run:
  mkdir -p /tmp/gov-rotpacing
  TMPDIR=/tmp/gov-rotpacing ~/workspace/.gov-venv/bin/python \\
    evals/rotation_pacing_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-rotpacingb \\
    ~/workspace/.gov-venv/bin/python evals/rotation_pacing_probes.py
"""
import os
import random
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-rotpacing-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import drift as _drift  # noqa: E402
    from gov import drift_budget as _budget  # noqa: E402
    _HAVE = True
except ImportError:
    _drift = None
    _budget = None
    _HAVE = False

_HAVE_ADAPTIVE = _HAVE and hasattr(_budget, "AdaptiveBudgetPolicy")
_HAVE_ROTATION = (_HAVE_ADAPTIVE and hasattr(_budget.BudgetStore,
                                             "_rotation_fold"))

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


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


# --- wobble rotation bursts (period-4 residual shape) ---
# X/Z: search->email main move plus a small wobble move (in opposite
# wobble directions); Y/W: the canceling email->search main move,
# W with the X-side wobble. All four direction signatures are
# distinct, and every consecutive pair (X,Y),(Y,Z),(Z,W),(W,X)
# cancels >=50% in L1, so the direction-aware streak stays blind
# while the flip tripwire never closes a 2-period.
def _wob_x(x, w):
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    t["read_file"] -= w
    t["http_post"] += w
    return t


def _wob_y(x):
    t = dict(_BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    return t


def _wob_z(x, w):
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    t["read_file"] += w
    t["http_post"] -= w
    return t


def _wob_w(x, w):
    t = dict(_BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    t["read_file"] -= w
    t["http_post"] += w
    return t


def _wob_e(x):
    # Breaker direction (r7): email -> summarize, distinct sig.
    t = dict(_BASE_TOOLS)
    t["email"] -= x
    t["summarize"] += x
    return t


def _wob_e_rev(x):
    # Exact opposite of _wob_e (r7): summarize -> email. Alternating
    # the two keeps a breaker train net-zero in direction so the
    # wave-146 slow-burn accumulator (which hunts sustained
    # single-direction sub-floor campaigns) stays quiet on the
    # scaffolding; a same-direction breaker train is that seam's
    # attack shape and it legitimately fires on it.
    t = dict(_BASE_TOOLS)
    t["email"] += x
    t["summarize"] -= x
    return t


def _abc_a(x):
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    return t


def _abc_b(x):
    t = dict(_BASE_TOOLS)
    t["email"] -= x
    t["search"] += x
    return t


def _abc_c(x):
    t = dict(_BASE_TOOLS)
    t["search"] -= x
    t["summarize"] += x
    return t


_WOBBLE_FNS = (_wob_x, _wob_y, _wob_z, _wob_w)


def _wobble_tools(fn, x, w):
    if fn is _wob_y:
        return fn(x)
    return fn(x, w)


_BASE_FP = None


def _base_fp():
    global _BASE_FP
    if _BASE_FP is None:
        _BASE_FP = _fp(_BASE_TOOLS)
    return _BASE_FP


def _frac(warn, tools):
    return _drift.fingerprint_tool_distance(
        _fp(tools), _base_fp()) / warn


def _calibrate():
    d10 = _drift.fingerprint_tool_distance(
        _fp(_abc_a(10)), _base_fp())
    return d10 / 0.4


def _scan_below(warn, shift_fn, ceiling=1.0, want_at_least=0.85,
                lo=1, hi=59):
    best = None
    for x in range(lo, hi + 1):
        f = _frac(warn, shift_fn(x))
        if f < ceiling:
            best = (x, f)
    if best is None or best[1] < want_at_least:
        return None
    return best


def _scan_wobble(warn, ceiling=1.0, want_at_least=0.85, w=1,
                 lo=1, hi=59):
    """Largest uniform x with ALL FOUR wobble bursts under ceiling.

    Uniform x keeps the pairwise cancellation math clean; the
    wobble w is fixed and small (x >> w).
    """
    best = None
    for x in range(lo, hi + 1):
        frs = [_frac(warn, _wobble_tools(fn, x, w))
               for fn in _WOBBLE_FNS]
        if all(f < ceiling for f in frs):
            best = (x, frs)
    if best is None or min(best[1]) < want_at_least:
        return None
    return best


class _Ctx:
    def __init__(self, tag, policy):
        self.events = []
        root = Path(tempfile.mkdtemp(prefix="rotpacing_%s_" % tag,
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

    def chain_ok(self, agent):
        return self.store.verify_chain(agent)

    def rotation_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "rotation_pacing_confirmed"
                and e.get("severity") == "LOUD"]

    def streak_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "near_trip_cycle"]

    def flip_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "direction_pacing_confirmed"
                and e.get("severity") == "LOUD"]

    def any_adapt(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"]


def _policy(warn):
    return _budget.AdaptiveBudgetPolicy(
        warn_distance=warn, budget_limit=1.0, window_runs=8,
        noise_floor=0.1, min_consistency=0.5)


def _drive(ctx, agent, tools_seq):
    """Record a tools sequence; return (tripped_seq or None, check)."""
    seq = 0
    for tools in tools_seq:
        seq += 1
        ctx.record(agent, tools, seq)
        chk = ctx.check(agent)
        if chk.status == "tripped":
            return seq, chk
    return None, ctx.check(agent)


def r1_rotation4_wobble_confirms():
    name = "r1_rotation4_wobble_confirms"
    warn = _calibrate()
    found = _scan_wobble(warn, ceiling=1.0, want_at_least=0.85)
    if found is None:
        _record(name, "ERROR", "wobble calibration found no ~0.9x shape")
        return
    x, frs = found
    w = 1
    ctx = _Ctx("r1", _policy(warn))
    seq_tools = []
    for _ in range(2):
        for fn in _WOBBLE_FNS:
            seq_tools += [_wobble_tools(fn, x, w), dict(_BASE_TOOLS)]
    seq_tools += [_wobble_tools(_wob_x, x, w)]  # trips after confirm
    tripped_at, chk = _drive(ctx, "agent-rot4", seq_tools)
    if tripped_at is None:
        _record(name, "BREAK",
                "4-period wobble [%.2f/%.2f/%.2f/%.2f, clean] x2 "
                "evaded the budget entirely (no rotation tripwire)"
                % tuple(round(f, 2) for f in frs))
        return
    confirmed = ctx.rotation_adapts()
    if not confirmed:
        _record(name, "BREAK",
                "tripped at run %d with no LOUD "
                "rotation_pacing_confirmed adaptation "
                "(seam %s)" % (tripped_at,
                               "missing -- not implemented"
                               if not _HAVE_ROTATION else
                               "present but did not fire"))
        return
    if "drift_budget_tripped" not in ctx.event_names():
        _record(name, "BREAK", "adapted but never LOUD-tripped")
        return
    if not ctx.chain_ok("agent-rot4"):
        _record(name, "BREAK", "hash chain broken after adapt+trip")
        return
    if tripped_at != 17:
        _record(name, "BREAK",
                "wobble rotation tripped at run %d, expected run 17 "
                "(confirm at 8th paced cycle's defuse = run 16, trip "
                "on next contributing run)" % tripped_at)
        return
    ev = confirmed[0].get("evidence", {})
    if ev.get("rotation_period") != 4:
        _record(name, "BREAK",
                "rotation evidence names period %r, expected 4"
                % ev.get("rotation_period"))
        return
    _record(name, "HELD",
            "4-period wobble [%.2f/%.2f/%.2f/%.2f, clean] x2 "
            "confirmed at run 16 via LOUD rotation_pacing_confirmed "
            "(period 4), tripped at run 17; chain intact"
            % tuple(round(f, 2) for f in frs))


def r2_period3_streak_covers():
    name = "r2_period3_streak_covers"
    warn = _calibrate()
    # Parity finding: odd-period paced rotations cannot evade the
    # direction-aware near-trip streak (consecutive pairs must
    # cancel, forcing an even period). The naive A/B/C 3-period
    # pacer therefore trips at run 7 via near_trip_cycle -- pre-
    # AND post-seam. This probe pins that the "3-period evasion"
    # premise does not hold against the full budget, and that the
    # rotation seam stays silent on period 3 (the streak owns it).
    xa, fa = _scan_below(warn, _abc_a) or (None, None)
    xb, fb = _scan_below(warn, _abc_b) or (None, None)
    xc, fc = _scan_below(warn, _abc_c) or (None, None)
    if None in (xa, xb, xc):
        _record(name, "ERROR", "calibration scan found no ~0.9 bursts")
        return
    ctx = _Ctx("r2", _policy(warn))
    seq_tools = []
    for _ in range(3):
        for fn, bx in ((_abc_a, xa), (_abc_b, xb), (_abc_c, xc)):
            seq_tools += [fn(bx), dict(_BASE_TOOLS)]
    tripped_at, chk = _drive(ctx, "agent-per3", seq_tools)
    if tripped_at != 7:
        _record(name, "BREAK",
                "3-period A/B/C [%.2f/%.2f/%.2f] tripped at run %s, "
                "expected run 7 via the near-trip streak"
                % (fa, fb, fc, tripped_at))
        return
    if not ctx.streak_adapts():
        _record(name, "BREAK",
                "3-period pacer tripped without the near_trip_cycle "
                "streak adaptation -- seam changed unexpectedly")
        return
    if ctx.rotation_adapts():
        _record(name, "BREAK",
                "3-period pacer fired rotation_pacing_confirmed -- "
                "unexpected (streak should own period 3 here)")
        return
    _record(name, "HELD",
            "3-period A/B/C [%.2f/%.2f/%.2f, clean] x3 trips at run 7 "
            "via LOUD near_trip_cycle (parity: odd periods cannot "
            "evade the streak); rotation seam silent"
            % (fa, fb, fc))


def r3_two_period_no_regression():
    name = "r3_two_period_no_regression"
    warn = _calibrate()
    xa, fa = _scan_below(warn, _abc_a) or (None, None)
    xb, fb = _scan_below(warn, _abc_b) or (None, None)
    if None in (xa, xb):
        _record(name, "ERROR", "calibration scan found no ~0.9 bursts")
        return
    ctx = _Ctx("r3", _policy(warn))
    seq_tools = []
    for _ in range(4):
        seq_tools += [_abc_a(xa), dict(_BASE_TOOLS),
                      _abc_b(xb), dict(_BASE_TOOLS)]
    tripped_at, chk = _drive(ctx, "agent-flip", seq_tools)
    if tripped_at is None:
        _record(name, "BREAK",
                "2-period [%.2f/%.2f, clean] x4 pacer no longer trips "
                "-- wave-144 seam regressed" % (fa, fb))
        return
    if tripped_at != 7:
        _record(name, "BREAK",
                "2-period [%.2f/%.2f, clean] x4 tripped at run %d, "
                "expected run 7 (wave-144 number moved)" % (fa, fb,
                                                            tripped_at))
        return
    if not ctx.flip_adapts():
        _record(name, "BREAK",
                "2-period pacer tripped without LOUD "
                "direction_pacing_confirmed -- 2-period path changed")
        return
    if ctx.rotation_adapts():
        _record(name, "BREAK",
                "2-period pacer fired rotation_pacing_confirmed -- "
                "the rotation seam must not own period 2")
        return
    _record(name, "HELD",
            "2-period [%.2f/%.2f, clean] x4 still trips at run 7 via "
            "LOUD direction_pacing_confirmed (rotation seam silent)"
            % (fa, fb))


def r4_random_benign_quiet():
    name = "r4_random_benign_quiet"
    warn = _calibrate()
    rng = random.Random(0x145)
    dirs = [_abc_a, _abc_b, _abc_c, _wob_e,
            lambda x: _wob_x(x, 1), lambda x: _wob_z(x, 1)]
    n_seq = 200
    rot_fires = 0
    other_adapts = 0
    trips = 0
    for s in range(n_seq):
        ctx = _Ctx("r4_%d" % s, _policy(warn))
        seq_tools = []
        for _ in range(20):  # 20 runs: 8 paced cycles (the
            # confirmation depth) must be reachable, or the
            # FP count is trivially 0
            roll = rng.random()
            if roll < 0.30:
                seq_tools.append(dict(_BASE_TOOLS))  # clean
            else:
                fn = dirs[rng.randrange(len(dirs))]
                # magnitudes spanning sub-floor .. near-threshold
                # (some bursts ARE paced, with random directions)
                x = rng.randint(1, 45)
                seq_tools.append(fn(x))
        tripped_at, _chk = _drive(ctx, "agent-rnd-%d" % s, seq_tools)
        n_rot = len(ctx.rotation_adapts())
        rot_fires += n_rot
        other_adapts += len(ctx.any_adapt()) - n_rot
        if tripped_at is not None:
            trips += 1
    detail = ("%d sequences: rotation_pacing_confirmed x%d, other "
              "adaptations x%d, trips x%d"
              % (n_seq, rot_fires, other_adapts, trips))
    if rot_fires:
        _record(name, "BREAK",
                "FALSE POSITIVE: " + detail)
        return
    _record(name, "HELD", "0 rotation FPs -- " + detail)


def r5_documented_tradeoff():
    name = "r5_documented_tradeoff"
    warn = _calibrate()
    # A sustained BENIGN 4-task wobble rotation at ~0.9x:
    # mathematically identical to the r1 attack shape --
    # pacing-indistinguishable by construction. The seam treats it
    # as pacing (the measured price, mirroring wave-144 f6).
    found = _scan_wobble(warn, ceiling=1.0, want_at_least=0.85)
    if found is None:
        _record(name, "ERROR", "wobble calibration found no ~0.9x shape")
        return
    x, frs = found
    w = 1
    ctx = _Ctx("r5", _policy(warn))
    seq_tools = []
    for _ in range(2):
        for fn in _WOBBLE_FNS:
            seq_tools += [_wobble_tools(fn, x, w), dict(_BASE_TOOLS)]
    tripped_at, chk = _drive(ctx, "agent-tradeoff", seq_tools)
    confirmed = ctx.rotation_adapts()
    if not confirmed:
        _record(name, "BREAK",
                "benign 4-task wobble rotation produced no "
                "rotation_pacing_confirmed adaptation "
                "(seam %s)" % ("missing -- not implemented"
                               if not _HAVE_ROTATION else
                               "present but did not fire"))
        return
    _record(name, "HELD",
            "documented tradeoff pinned: benign 4-task wobble "
            "[%.2f/%.2f/%.2f/%.2f] adapts via LOUD "
            "rotation_pacing_confirmed x%d (sustained rotating "
            "near-threshold bursts are pacing-indistinguishable by "
            "design)" % (tuple(round(f, 2) for f in frs)
                         + (len(confirmed),)))


def r6_subfloor_rotation_quiet():
    name = "r6_subfloor_rotation_quiet"
    warn = _calibrate()
    found = _scan_wobble(warn, ceiling=0.6, want_at_least=0.4)
    if found is None:
        _record(name, "ERROR",
                "wobble calibration found no sub-floor shape")
        return
    x, frs = found
    w = 1
    if max(frs) >= 0.75:
        _record(name, "ERROR",
                "sub-floor scan escaped the 0.75 pacing floor")
        return
    ctx = _Ctx("r6", _policy(warn))
    seq_tools = []
    for _ in range(8):
        for fn in _WOBBLE_FNS:
            seq_tools += [_wobble_tools(fn, x, w), dict(_BASE_TOOLS)]
    tripped_at, chk = _drive(ctx, "agent-subfloor", seq_tools)
    n_adapt = len(ctx.any_adapt())
    if tripped_at is not None or n_adapt:
        _record(name, "BREAK",
                "sub-floor wobble rotation tripped=%s adapted=%d "
                "(FP below the pacing floor)" % (tripped_at, n_adapt))
        return
    _record(name, "HELD",
            "32 sub-floor wobble bursts [%.2f/%.2f/%.2f/%.2f] "
            "(< 0.75 floor): 0 trips, 0 adaptations (cumulative=%.3f)"
            % (tuple(round(f, 2) for f in frs) + (chk.cumulative,)))


def r7_breaker_cycles_clear():
    name = "r7_breaker_cycles_clear"
    warn = _calibrate()
    found = _scan_wobble(warn, ceiling=1.0, want_at_least=0.85)
    if found is None:
        _record(name, "ERROR", "wobble calibration found no ~0.9x shape")
        return
    x, frs = found
    w = 1
    # Sub-floor breaker in a distinct direction E: its defuse cycle
    # is not paced, so it must clear the rotation history.
    be = _scan_below(warn, _wob_e, ceiling=0.6, want_at_least=0.4)
    if be is None:
        _record(name, "ERROR", "breaker calibration found no shape")
        return
    xe, fe = be
    ctx = _Ctx("r7", _policy(warn))
    seq_tools = []
    # Breaker direction alternates E / reverse-E (net zero): the
    # breakers are non-paced scaffolding whose job is clearing the
    # rotation history, and this probe's contract needs them
    # direction-inert. (A same-direction breaker train is the
    # slow-burn accumulator's attack shape; that seam legitimately
    # fires on it, so the fixture does not hand it one.)
    bi = 0
    for fn in _WOBBLE_FNS:
        brk = _wob_e(xe) if bi % 2 == 0 else _wob_e_rev(xe)
        bi += 1
        seq_tools += [_wobble_tools(fn, x, w), dict(_BASE_TOOLS),
                      brk, dict(_BASE_TOOLS)]
    tripped_at, chk = _drive(ctx, "agent-breaker", seq_tools)
    n_adapt = len(ctx.any_adapt())
    if tripped_at is not None or n_adapt:
        _record(name, "BREAK",
                "breaker-separated wobble tripped=%s adapted=%d "
                "(non-paced cycles must clear the history)"
                % (tripped_at, n_adapt))
        return
    _record(name, "HELD",
            "paced wobble [%.2f/%.2f/%.2f/%.2f] separated by "
            "sub-floor breaker cycles [%.2f]: 0 trips, 0 adaptations"
            % (tuple(round(f, 2) for f in frs) + (round(fe, 2),)))


def r8_deterministic_x2():
    name = "r8_deterministic_x2"
    runs = []
    for _ in range(2):
        n_before = len(_RESULTS)
        r1_rotation4_wobble_confirms()
        r2_period3_streak_covers()
        r3_two_period_no_regression()
        runs.append(tuple(_RESULTS[n_before:]))
        del _RESULTS[n_before:]
    ok = runs[0] == runs[1]
    _record(name, "HELD" if ok else "BREAK",
            "r1+r2+r3 byte-identical across 2 runs" if ok
            else "NONDETERMINISTIC: %r vs %r" % (runs[0], runs[1]))


def _main():
    if not _HAVE:
        print("rotation_pacing_probes: import failed")
        return 2
    r1_rotation4_wobble_confirms()
    r2_period3_streak_covers()
    r3_two_period_no_regression()
    r4_random_benign_quiet()
    r5_documented_tradeoff()
    r6_subfloor_rotation_quiet()
    r7_breaker_cycles_clear()
    r8_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    broke = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("rotation_pacing_probes: %d HELD / %d BREAK / %d ERROR"
          % (held, broke, errors))
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(_main())
