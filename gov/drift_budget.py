"""Per-agent cumulative drift budget (row 9, wave-138).

Row 9's measured residual: slow drift where each individual run stays
under the WARN threshold never escalates -- an attacker can boil the
frog in 0.4-threshold steps forever. ``gov.drift.detect_drift`` judges
one window against a baseline; it has no memory of *how many*
consecutive sub-threshold deviations an agent has accumulated. This
module adds that memory.

Design (per agent):
  - Each recorded run contributes its drift distance to a budget. The
    distance is ``gov.drift.fingerprint_tool_distance`` -- the
    symmetric chi-square tool-distribution distance from the
    population-baseline fingerprinting lineage (wave-134) -- reused,
    not duplicated. Contributions are measured in
    *threshold-equivalents*: ``distance / policy.warn_distance``.
  - Only sub-threshold-but-nonzero runs accrue: ``noise_floor <
    distance < warn_distance``. A run at/above ``warn_distance`` is
    the single-run path's job (``detect_drift``) and is recorded but
    does not accrue; a run at/below the noise floor is *clean* and
    defuses the budget (see resets below).
  - Escalation: when the cumulative threshold-equivalents inside the
    sliding window reach ``policy.budget_limit`` AND the net drift has
    a sustained direction (``consistency >= policy.min_consistency``),
    the budget trips: status ``tripped`` plus a LOUD
    ``drift_budget_tripped`` evidence event. Consistency is
    ``sum_c |net_c| / sum_i sum_c |delta_ic|`` over per-tool signed
    deltas vs the baseline expectation -- alternating +/- noise
    cancels to ~0 and cannot trip, while a sustained same-direction
    boil scores ~1.
  - Resets (documented design choice): a clean run (distance at/below
    the noise floor) clears the budget immediately -- the boil
    stopped, so the accumulated state is defused. Independently,
    contributions older than ``policy.window_runs`` recorded runs fall
    out of the sliding window. A manual ``reset()`` clears on operator
    demand. Trip state is sticky until a reset.
  - Never silent accumulation: every contributing run is hash-chained
    into the store with a ``drift_budget_accrue`` audit event; resets
    emit ``drift_budget_reset``; the trip emits the LOUD
    ``drift_budget_tripped`` event (once per trip -- re-checks while
    tripped do not re-emit). Audit runs BEFORE local mutation (the
    F167 lesson, inherited from ``ChainedStore``): an audit failure
    aborts the record and the store is unchanged.

What this is NOT (honest ceilings):
  - window_runs / budget_limit / noise_floor / min_consistency /
    warn_distance are OPERATOR POLICY, not derived constants. An
    attacker who knows N and the window can pace just under them --
    the threshold-gaming residual stands (pinned EXPECTED in
    ``evals/drift_budget_probes.py`` b5). The budget is a tripwire
    with memory, not a proof.
  - Tuning trade-off: a lower noise floor or a larger window catches
    slower boils but tolerates less benign jitter (FP pressure up,
    detection latency down); a higher floor or a smaller window is
    the reverse. There is no setting that is both maximally tolerant
    and maximally sensitive.
  - Tool-distribution only: the distance and the signed deltas reuse
    the behavioral fingerprint's tool counts. Egress-volume,
    decision-outcome, and argument-framing drift are other modules'
    jobs (``gov.drift`` signals B/C, ``gov.framing``).
  - The budget trusts its baseline the same way ``detect_drift``
    does: a from-birth malicious agent has nothing to drift from
    (row-9 p4 ceiling, unchanged).
  - ``warn_distance`` must be calibrated to the agent's call volume
    (distances are chi-square-statistic units, volume-dependent).
    The default is a starting point; operators should calibrate from
    measured benign runs.

$0, stdlib only, deterministic (exact computations, no RNG; no
wall-clock in verdicts -- ``recorded_at`` is bookkeeping only).
Privacy: the store holds fingerprints and per-tool count deltas,
never prompts, tool outputs, or log contents.

The existing single-run WARN path (``gov.drift.detect_drift``) is
unchanged -- this module is additive and standalone.

Adaptive pacing-aware extension (wave-139): ``AdaptiveBudgetPolicy``
opts one agent's budget into pacing-aware adaptation. Two triggers,
both consistency-gated and both audited with a LOUD
``drift_budget_adapted`` evidence event:

  1. contribution streak: ``adapt_strikes`` consecutive contributing
     runs each at/above ``adapt_contrib_floor`` x warn_distance, with
     direction consistency >= min_consistency;
  2. near-trip cycles: a defuse cycle (contributing runs between two
     resets) whose cumulative reached ``adapt_near_floor`` x the
     effective trip limit with consistency >= min_consistency counts
     as a near-trip; ``adapt_cycles`` consecutive near-trip cycles in
     a sustained direction (direction-aware streak: a cycle whose
     direction cancels the streak's net direction restarts the streak
     at 1 instead of extending it) adapts.

On adaptation the agent's effective trip limit is multiplied by
``adapt_factor`` and the window shrinks by one run (floor 2), up to
``adapt_max_level`` tightenings; the trip then also accepts a single
contributing run (the adaptation level itself encodes the prior
multi-cycle evidence). A benign (non-near-trip) cycle relaxes one
level, audited as ``drift_budget_relaxed``. Clean runs still defuse
the accumulator; expiry still applies to the (possibly shrunk)
window; a plain ``BudgetPolicy`` disables all of this (zero behavior
change). All adaptation decisions are ``adapt``-kind hash-chained
records, written audit-before-mutation like everything else here.

Honest ceilings (updated): the adaptation parameters
(adapt_near_floor / adapt_cycles / adapt_factor / adapt_contrib_floor
/ adapt_strikes) are new operator calibration targets -- the
threshold-gaming residual MUTATES, it does not die: an attacker who
learns the adapted limit paces under that instead, flips direction
between cycles to break the streak, or spaces cycles so each stays
sub-near-trip. Repeated same-direction near-threshold bursts with
defuses are indistinguishable from a paced boil by construction --
the adaptation fires on both (pinned EXPECTED b2 in
``evals/adaptive_drift_probes.py``).

Flip-direction pacing (wave-141): ``AdaptiveBudgetPolicy`` also
carries per-direction pacing buckets (``adapt_dir_decay`` /
``adapt_dir_threshold``). Each defuse cycle with a near-trip
accrues its threshold-equivalents into the bucket keyed by the
cycle's deterministic direction signature (``_direction_key``: the
sign pattern of the net signed tool deltas); every bucket decays by
``adapt_dir_decay`` each defuse instead of resetting on a direction
flip. A bucket reaching ``adapt_dir_threshold`` on a near-trip cycle
tightens LOUD (trigger ``direction_pacing``) exactly like the
streak trigger, and the buckets zero on the tightening. This catches
the alternating-direction pacer the aggregate consistency gate and
the direction-aware streak both miss -- but it is a COUNT of
persistent directional near-trips, not a proof of malice: an
attacker who learns the parameters paces at most ~3 near-trip cycles
per direction (or keeps every cycle sub-near-trip), and the
threshold/decay are new operator calibration targets. The direction
key is sign-pattern only; magnitude accrues but does not key.

Confirmed flip pacing (wave-144): the wave-141 buckets need ~4
near-trip cycles per direction before they fill (the exact-opposite
0.9x pacer trips at run 15). ``AdaptiveBudgetPolicy`` now also
carries a flip-confirmation tripwire (``adapt_flip_floor``): when a
defuse cycle is paced (near-trip at >= ``adapt_flip_floor``
threshold-equivalents) AND its direction signature flips from the
previous paced cycle's signature AND flips back to the one before
that -- i.e. the second consecutive direction-flip cycle closing a
genuine A/B/A 2-period oscillation at near-threshold magnitudes --
the budget tightens LOUD immediately (trigger
``direction_pacing_confirmed``), exactly like the other tightenings,
and the next contributing run trips under the tightened limit. The
flip state (previous two paced cycles' signatures) rides the chained
reset records and is folded like the streak; any non-paced cycle
(sub-floor, non-near-trip, or directionless) breaks consecutiveness
and clears it, and a same-direction paced cycle restarts it. This is
deliberately narrower than "any two consecutive flips": a sustained
ALTERNATING pattern confirms pacing, while inconsistent directions
(A/B/C/... never closing a 2-period) stay quiet. The price is
measured, not hidden: sustained alternating near-threshold bursts
(>= the flip floor) are pacing-indistinguishable from the attack by
construction, so a benign workload that persistently alternates
near-threshold bursts WILL be adapted early (pinned by
``evals/flip_pacing_probes.py`` f6). ``adapt_flip_floor`` is operator
calibration like every other adaptation parameter.

N-period rotation pacing (wave-145): the wave-144 flip tripwire
closes only 2-period (A/B/A) oscillations, and the wave-139
direction-aware near-trip streak provably covers odd-period paced
rotations (parity argument: for the streak to stay blind every
consecutive paced pair must cancel, so the large components
satisfy L_{i+1} ≈ -L_i while periodicity demands L_{i+p} = L_i;
for odd p this forces L_i ≈ 0, contradicting "paced" -- a bounded
randomized search over ~125k paced burst shapes found zero
3-period streak+flip-evading constructions). The remaining
residual is EVEN-period: a 4-period "wobble" rotation
(pairwise-canceling bursts whose small wobble moves morph the
direction signature each cycle) evades the streak (every
consecutive pair cancels ≥50% in L1), the flip tripwire (the
signatures never close a 2-period), and the static budget -- only
the wave-141 buckets catch it, at ~run 42. ``AdaptiveBudgetPolicy``
therefore carries a rotation-confirmation tripwire for periods
3..K (K=4, a fixed conservative bound, not operator policy; longer
rotations stay with the buckets): paced defuse cycles (near-trip
at >= ``adapt_flip_floor`` -- the SAME floor and the SAME
direction-consistency gating the flip detector uses, reusing that
machinery rather than a parallel one; sub-floor alternating
bursts never enter the history) append their direction signature
to a rotation history riding the chained reset records (capped at
2K entries; any non-paced cycle clears it, exactly like the flip
state; folded by ``BudgetStore._rotation_fold``, kept out of
``_adapt_fold`` whose return arity is frozen by the wave-144
tests). When the trailing window's last 2p signatures are two
clean back-to-back repetitions of one period-p pattern
(autocorrelation at lag p = 1.0 via ``_rotation_period_score``)
with at least two distinct directions inside the period (period 1
-- a single repeated direction -- belongs to the near-trip
streak; period 2 belongs to the flip tripwire, which fires first
on any A/B/A subsequence), pacing confirms LOUD with trigger
``rotation_pacing_confirmed`` -- exactly like a confirmed flip
(same floor, same tightening: ``reset_streak`` +
``reset_directions``), and the next contributing run trips under
the tightened limit. The 4-period wobble pacer now confirms at
the 8th paced cycle's defuse (run 16) and trips at run 17. The
price is measured, not hidden: a benign workload that
persistently rotates near-threshold bursts WILL adapt early
(pinned by ``evals/rotation_pacing_probes.py`` r5) -- sustained
rotating near-threshold bursts are pacing-indistinguishable from
the attack by construction. 5+-period rotations still evade the
confirmation (buckets remain the backstop); sub-floor pacing,
state-breaking cycles, many-shot framing drift, and from-birth
baseline poisoning are unchanged residuals.
"""

from collections import Counter
from pathlib import Path

from gov.chained_store import ChainedStore
from gov.drift import RunFingerprint, fingerprint_tool_distance

__all__ = [
    "BudgetPolicy",
    "AdaptiveBudgetPolicy",
    "BudgetStore",
    "BudgetCheck",
    "BudgetContribution",
    "default_store_dir",
    "signed_tool_deltas",
]

_BUDGET_VERSION = 1

_ROTATION_MAX_PERIOD = 4
"""Max period of the wave-145 rotation-confirmation tripwire.

The rotation detector confirms periods 3..``_ROTATION_MAX_PERIOD``.
Period 2 is the wave-144 flip tripwire's (it fires first on any
A/B/A subsequence); period 1 -- a single repeated direction -- is
the wave-139 near-trip streak's. K=4 is a fixed conservative
bound, not operator policy: 5+-period rotations stay with the
wave-141 per-direction buckets (which catch them later).
"""


def default_store_dir():
    """Default on-disk home for budget stores (operator-overridable)."""
    return Path.home() / ".agent-governance-demo" / "drift_budget"


class BudgetPolicy:
    """Operator policy for one cumulative drift budget.

    ``warn_distance``: per-run drift distance (same units as
    ``fingerprint_tool_distance``) at/above which a single run is the
    single-run path's job -- such runs are recorded but never accrue.
    ``budget_limit``: cumulative threshold-equivalents that trip the
    budget (default 1.0 -- one full single-run threshold, accrued in
    pieces). ``window_runs``: sliding window in recorded budget runs.
    ``noise_floor``: fraction of ``warn_distance`` at/below which a
    run is clean (0 contribution, and it defuses the budget).
    ``min_consistency``: minimum net-direction consistency for a trip.
    ``min_contributing_runs``: trips need at least this many
    contributing runs -- a single run, however large below WARN, is
    ``detect_drift``'s territory, never the budget's.
    """

    __slots__ = ("warn_distance", "budget_limit", "window_runs",
                 "noise_floor", "min_consistency",
                 "min_contributing_runs")

    def __init__(self, warn_distance, budget_limit=1.0, window_runs=8,
                 noise_floor=0.1, min_consistency=0.5,
                 min_contributing_runs=2):
        if not isinstance(warn_distance, (int, float)) or \
                not warn_distance > 0:
            raise ValueError("warn_distance must be a positive number, "
                             "got %r" % (warn_distance,))
        if not isinstance(budget_limit, (int, float)) or \
                not budget_limit > 0:
            raise ValueError("budget_limit must be a positive number, "
                             "got %r" % (budget_limit,))
        if not isinstance(window_runs, int) or window_runs < 2:
            raise ValueError("window_runs must be an int >= 2, got %r"
                             % (window_runs,))
        if not isinstance(noise_floor, (int, float)) or \
                not 0 <= noise_floor < 1:
            raise ValueError("noise_floor must be in [0, 1), got %r"
                             % (noise_floor,))
        if not isinstance(min_consistency, (int, float)) or \
                not 0 <= min_consistency <= 1:
            raise ValueError("min_consistency must be in [0, 1], got %r"
                             % (min_consistency,))
        if not isinstance(min_contributing_runs, int) or \
                min_contributing_runs < 1:
            raise ValueError("min_contributing_runs must be an int >= 1, "
                             "got %r" % (min_contributing_runs,))
        self.warn_distance = float(warn_distance)
        self.budget_limit = float(budget_limit)
        self.window_runs = window_runs
        self.noise_floor = float(noise_floor)
        self.min_consistency = float(min_consistency)
        self.min_contributing_runs = min_contributing_runs

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class AdaptiveBudgetPolicy(BudgetPolicy):
    """Pacing-aware extension of BudgetPolicy (wave-139).

    All ``BudgetPolicy`` fields keep their meaning; a plain
    ``BudgetPolicy`` disables adaptation entirely. New fields:

    ``adapt_near_floor``: fraction of the effective trip limit; a
    defuse cycle whose cumulative reached this fraction (with
    direction consistency >= min_consistency) counts as a near-trip.
    ``adapt_cycles``: consecutive sustained-direction near-trip
    cycles that trigger a tightening. ``adapt_factor``: trip-limit
    multiplier applied per tightening (in (0, 1)). ``adapt_strikes``:
    consecutive contributing runs each at/above
    ``adapt_contrib_floor`` x warn_distance (consistency-gated) that
    trigger a tightening mid-cycle. ``adapt_max_level``: cap on
    tightenings. Each tightening also shrinks the window by one run
    (floor 2) and, while level >= 1, lets a single contributing run
    trip (the level encodes the prior multi-cycle evidence).
    ``adapt_dir_decay`` (wave-141): per-defuse-cycle multiplicative
    decay applied to every per-direction pacing bucket, in (0, 1).
    ``adapt_dir_threshold`` (wave-141): a per-direction bucket at or
    above this (in threshold-equivalents) on a near-trip cycle
    triggers a tightening -- the flip-direction pacing tripwire.
    ``adapt_flip_floor`` (wave-144): per-cycle threshold-equivalents
    floor (fraction of the effective trip limit, in (0, 1]) for a
    near-trip cycle to count as "paced" in the flip-confirmation
    tripwire -- the second consecutive direction-flip cycle at or
    above this floor, closing a genuine A/B/A 2-period oscillation,
    tightens LOUD with trigger ``direction_pacing_confirmed``.
    All three are operator calibration, like every other adaptation
    parameter.

    Wave-145 adds the rotation-confirmation tripwire (no new policy
    fields): paced defuse cycles -- near-trip at >=
    ``adapt_flip_floor``, the SAME floor and direction-consistency
    gating the flip detector uses -- append their direction
    signature to a rotation history (capped at ``2*K`` entries,
    ``K=4`` fixed). A trailing window whose last ``2p`` signatures
    are two clean repetitions of one period-``p`` pattern
    (``p`` in 3..K, >= 2 distinct directions) tightens LOUD with
    trigger ``rotation_pacing_confirmed``, exactly like a confirmed
    flip.

    Wave-146 adds the slow-burn accumulator (new policy fields
    ``slow_weight`` / ``slow_clean_decay`` / ``slow_trip`` /
    ``slow_window_factor`` / ``slow_min_runs``, all operator
    calibration): sub-floor (below ``adapt_flip_floor`` x the
    effective limit) but nonzero contributions accrue at REDUCED
    weight (``slow_weight``) into a LONG-window accumulator
    (``slow_window_factor`` x the effective adaptive window). When
    the weighted accumulation crosses ``slow_trip`` with direction
    consistency >= ``min_consistency`` over at least
    ``slow_min_runs`` sub-floor runs, the budget emits a LOUD
    ``drift_budget_slow_burn`` event and tightens exactly like the
    other pacing triggers (trigger ``slow_burn``). Clean runs defuse
    the accumulator multiplicatively (x ``slow_clean_decay``) --
    faster than the long window's passive expiry, and strong enough
    that isolated noise never sticks; unlike the main budget's full
    clear, the decay is partial so a paced [sub-floor, clean]
    campaign still accumulates (that campaign is the shape this
    hunts -- a full clear would re-open the exact residual). The
    accumulator epoch restarts on every tightening, every manual
    reset, and every slow-burn trip marker, so old evidence never
    double-counts. A plain ``BudgetPolicy`` has no slow-burn fields
    and zero behavior change.
    """

    __slots__ = ("adapt_near_floor", "adapt_cycles", "adapt_factor",
                 "adapt_contrib_floor", "adapt_strikes",
                 "adapt_max_level", "adapt_dir_decay",
                 "adapt_dir_threshold", "adapt_flip_floor",
                 "slow_weight", "slow_clean_decay", "slow_trip",
                 "slow_window_factor", "slow_min_runs")

    def __init__(self, warn_distance, adapt_near_floor=0.75,
                 adapt_cycles=2, adapt_factor=0.6,
                 adapt_contrib_floor=0.75, adapt_strikes=3,
                 adapt_max_level=3, adapt_dir_decay=0.9,
                 adapt_dir_threshold=2.4, adapt_flip_floor=0.75,
                 slow_weight=0.5, slow_clean_decay=0.5, slow_trip=0.3,
                 slow_window_factor=3, slow_min_runs=3, **kw):
        super(AdaptiveBudgetPolicy, self).__init__(warn_distance, **kw)
        if not isinstance(adapt_near_floor, (int, float)) or \
                not 0 < adapt_near_floor <= 1:
            raise ValueError("adapt_near_floor must be in (0, 1], got %r"
                             % (adapt_near_floor,))
        if not isinstance(adapt_cycles, int) or adapt_cycles < 1:
            raise ValueError("adapt_cycles must be an int >= 1, got %r"
                             % (adapt_cycles,))
        if not isinstance(adapt_factor, (int, float)) or \
                not 0 < adapt_factor < 1:
            raise ValueError("adapt_factor must be in (0, 1), got %r"
                             % (adapt_factor,))
        if not isinstance(adapt_contrib_floor, (int, float)) or \
                not 0 < adapt_contrib_floor < 1:
            raise ValueError("adapt_contrib_floor must be in (0, 1), "
                             "got %r" % (adapt_contrib_floor,))
        if not isinstance(adapt_strikes, int) or adapt_strikes < 2:
            raise ValueError("adapt_strikes must be an int >= 2, got %r"
                             % (adapt_strikes,))
        if not isinstance(adapt_max_level, int) or adapt_max_level < 1:
            raise ValueError("adapt_max_level must be an int >= 1, got %r"
                             % (adapt_max_level,))
        if not isinstance(adapt_dir_decay, (int, float)) or \
                not 0 < adapt_dir_decay < 1:
            raise ValueError("adapt_dir_decay must be in (0, 1), got %r"
                             % (adapt_dir_decay,))
        if not isinstance(adapt_dir_threshold, (int, float)) or \
                not adapt_dir_threshold > 0:
            raise ValueError("adapt_dir_threshold must be positive, got %r"
                             % (adapt_dir_threshold,))
        if not isinstance(adapt_flip_floor, (int, float)) or \
                not 0 < adapt_flip_floor <= 1:
            raise ValueError("adapt_flip_floor must be in (0, 1], got %r"
                             % (adapt_flip_floor,))
        self.adapt_near_floor = float(adapt_near_floor)
        self.adapt_cycles = adapt_cycles
        self.adapt_factor = float(adapt_factor)
        self.adapt_contrib_floor = float(adapt_contrib_floor)
        self.adapt_strikes = adapt_strikes
        self.adapt_max_level = adapt_max_level
        self.adapt_dir_decay = float(adapt_dir_decay)
        self.adapt_dir_threshold = float(adapt_dir_threshold)
        self.adapt_flip_floor = float(adapt_flip_floor)
        if not isinstance(slow_weight, (int, float)) or \
                not 0 < slow_weight <= 1:
            raise ValueError("slow_weight must be in (0, 1], got %r"
                             % (slow_weight,))
        if not isinstance(slow_clean_decay, (int, float)) or \
                not 0 < slow_clean_decay < 1:
            raise ValueError("slow_clean_decay must be in (0, 1), got %r"
                             % (slow_clean_decay,))
        if not isinstance(slow_trip, (int, float)) or \
                not slow_trip > 0:
            raise ValueError("slow_trip must be positive, got %r"
                             % (slow_trip,))
        if not isinstance(slow_window_factor, int) or \
                slow_window_factor < 2:
            raise ValueError("slow_window_factor must be an int >= 2, "
                             "got %r" % (slow_window_factor,))
        if not isinstance(slow_min_runs, int) or slow_min_runs < 2:
            raise ValueError("slow_min_runs must be an int >= 2, got %r"
                             % (slow_min_runs,))
        self.slow_weight = float(slow_weight)
        self.slow_clean_decay = float(slow_clean_decay)
        self.slow_trip = float(slow_trip)
        self.slow_window_factor = slow_window_factor
        self.slow_min_runs = slow_min_runs

    def to_dict(self):
        d = {k: getattr(self, k) for k in BudgetPolicy.__slots__}
        d.update({k: getattr(self, k)
                  for k in AdaptiveBudgetPolicy.__slots__})
        return d


def signed_tool_deltas(run_fp, baseline_fp):
    """Per-tool signed count deltas of a run vs a baseline.

    ``expected_c = baseline_c / baseline_total * run_total``;
    ``delta_c = observed_c - expected_c``. Positive means the run used
    the tool more than the baseline profile predicts. Returned as a
    plain dict of rounded floats (deterministic, JSON-safe).
    """
    base = dict(baseline_fp.tool_counts)
    obs = dict(run_fp.tool_counts)
    base_total = sum(base.values())
    run_total = sum(obs.values())
    deltas = {}
    for tool in sorted(set(base) | set(obs)):
        expected = (base.get(tool, 0) / base_total * run_total
                    if base_total > 0 else 0.0)
        deltas[tool] = round(obs.get(tool, 0) - expected, 6)
    return deltas


def _direction_key(net):
    """Deterministic direction signature from net signed deltas.

    The sign pattern of the nonzero net tool deltas, sorted by tool
    name: e.g. ``"email:+1|search:-1"``. Two cycles whose net drift
    points the same way (same tools up/down) share a key; a
    direction flip changes the key. Magnitude is NOT part of the
    key -- only of the accumulated threshold-equivalents. Empty
    net (no drift) yields ``""``. Deterministic and JSON-safe.
    """
    parts = ["%s:%+d" % (tool, 1 if v > 0 else -1)
             for tool, v in sorted(net.items()) if v != 0]
    return "|".join(parts)


def _rotation_period_score(history, period):
    """Agreement fraction of the trailing window at lag ``period``.

    1.0 means the last ``2*period`` paced-cycle direction signatures
    are two clean back-to-back repetitions of one period-``period``
    pattern -- autocorrelation at lag ``period`` over the trailing
    window. Histories shorter than two full periods score 0.0. Pure
    and deterministic (exact signature equality; the confirmation
    bar is deliberately at its maximum).
    """
    n = len(history)
    if period < 1 or n < 2 * period:
        return 0.0
    tail = history[-2 * period:]
    agree = sum(1 for i in range(period)
                if tail[i] == tail[i + period])
    return agree / period


class BudgetContribution:
    """Assessment of one recorded run against the budget."""

    __slots__ = ("contributes", "distance", "threshold_equivalents",
                 "reason", "clean", "run_seq", "agent_id")

    _REASONS = ("sub_threshold", "clean", "single_run_path",
                "insufficient_data")

    def __init__(self, contributes, distance=None,
                 threshold_equivalents=0.0, reason="sub_threshold",
                 clean=False, run_seq=0, agent_id=""):
        if reason not in self._REASONS:
            raise ValueError("unknown contribution reason %r" % (reason,))
        self.contributes = bool(contributes)
        self.distance = distance
        self.threshold_equivalents = float(threshold_equivalents)
        self.reason = reason
        self.clean = bool(clean)
        self.run_seq = int(run_seq)
        self.agent_id = str(agent_id)

    def to_dict(self):
        return {"contributes": self.contributes,
                "distance": self.distance,
                "threshold_equivalents": self.threshold_equivalents,
                "reason": self.reason, "clean": self.clean,
                "run_seq": self.run_seq, "agent_id": self.agent_id}


class BudgetCheck:
    """Outcome of a budget check: status in {"ok", "tripped"}."""

    __slots__ = ("status", "agent_id", "cumulative", "consistency",
                 "contributing_runs", "window_n", "tripped_run_seq",
                 "detail")

    _STATUSES = ("ok", "tripped")

    def __init__(self, status, agent_id="", cumulative=0.0,
                 consistency=0.0, contributing_runs=0, window_n=0,
                 tripped_run_seq=None, detail=None):
        if status not in self._STATUSES:
            raise ValueError("unknown budget status %r" % (status,))
        self.status = status
        self.agent_id = str(agent_id)
        self.cumulative = float(cumulative)
        self.consistency = float(consistency)
        self.contributing_runs = int(contributing_runs)
        self.window_n = int(window_n)
        self.tripped_run_seq = tripped_run_seq
        self.detail = dict(detail) if detail else {}

    def to_dict(self):
        return {"status": self.status, "agent_id": self.agent_id,
                "cumulative": self.cumulative,
                "consistency": self.consistency,
                "contributing_runs": self.contributing_runs,
                "window_n": self.window_n,
                "tripped_run_seq": self.tripped_run_seq,
                "detail": dict(self.detail)}


class BudgetStore(ChainedStore):
    """Durable per-agent cumulative drift budget store.

    One hash-chained JSONL file per agent under ``store_dir``.
    Record kinds: ``contribution`` (one run's budget assessment),
    ``reset`` (budget cleared -- clean run or manual), ``trip``
    (marker; the LOUD evidence is the ``drift_budget_tripped`` audit
    event emitted when the marker is first written). Audit runs
    BEFORE local mutation: an audit failure aborts the append and the
    store is unchanged (fail-closed).
    """

    _record_version_key = "drift_budget_version"
    _record_version = _BUDGET_VERSION
    _record_event = "drift_budget_accrue"
    _fingerprint_cls = RunFingerprint

    # ---------------------------------------------------------- writes

    def _write(self, agent_id, record, audit_event, audit):
        auditor = self._audit if audit is None else audit
        return self._append_chained(agent_id, record, audit_event,
                                   auditor)

    def _check_fingerprint(self, fp, what):
        if not isinstance(fp, RunFingerprint):
            raise TypeError("%s must be a RunFingerprint, got %r"
                            % (what, type(fp).__name__))

    @staticmethod
    def _check_seq(run_seq):
        if not isinstance(run_seq, int) or run_seq < 0:
            raise ValueError("run_seq must be a non-negative int, got %r"
                             % (run_seq,))

    # ------------------------------------------- pacing-aware adaptation

    @staticmethod
    def _is_adaptive(policy):
        return isinstance(policy, AdaptiveBudgetPolicy)

    def _adapt_fold(self, records):
        """Fold adapt/reset records to current adaptation state.

        Returns ``(level, streak, streak_net, streak_gross,
        last_adapt_seq, direction_scores, flip_prev, flip_prev2)``.
        Each reset record carries the post-reset streak, the
        post-reset per-direction scores, and the post-reset flip
        state (the previous two paced cycles' direction signatures);
        a cycle-triggered tightening (``reset_streak`` /
        ``reset_directions``) zeroes them. Records from ``reset()``
        predate the adaptive fields and are treated as streak 0 /
        empty scores / no flip state (level is operator policy state
        and survives a manual reset -- it decays via benign cycles).
        Deterministic: pure fold over the chained log.
        """
        level = 0
        streak = 0
        streak_net = {}
        streak_gross = 0.0
        last_adapt_seq = -1
        direction_scores = {}
        flip_prev = None
        flip_prev2 = None
        for r in records:
            kind = r.get("kind")
            if kind == "adapt":
                level = int(r.get("adapt_level", level))
                last_adapt_seq = max(last_adapt_seq,
                                     int(r.get("run_seq", -1)))
                if r.get("reset_streak"):
                    streak = 0
                    streak_net = {}
                    streak_gross = 0.0
                if r.get("reset_directions"):
                    direction_scores = {}
                    flip_prev = None
                    flip_prev2 = None
            elif kind == "reset":
                streak = int(r.get("streak", 0))
                streak_net = {k: float(v) for k, v in
                              r.get("streak_net", {}).items()}
                streak_gross = float(r.get("streak_gross", 0.0))
                direction_scores = {
                    str(k): float(v) for k, v in
                    r.get("direction_scores", {}).items()}
                flip_prev = r.get("flip_prev")
                flip_prev2 = r.get("flip_prev2")
        return (level, streak, streak_net, streak_gross, last_adapt_seq,
                direction_scores, flip_prev, flip_prev2)

    @staticmethod
    def _rotation_fold(records):
        """Fold reset/adapt records to the rotation signature history.

        The history is the paced-cycle direction signatures since
        the last non-paced defuse cycle, capped at
        ``2*_ROTATION_MAX_PERIOD`` entries; an adapt record with
        ``reset_directions`` zeroes it (a confirmed pacing
        tightening restarts the hunt). It is folded separately
        from ``_adapt_fold`` -- that tuple's arity is frozen by the
        wave-144 tests, so the rotation state rides alongside it,
        not inside it. Logs predating wave-145 carry no
        ``rot_history`` and fold to []. Deterministic: pure fold
        over the chained log.
        """
        history = []
        cap = 2 * _ROTATION_MAX_PERIOD
        for r in records:
            kind = r.get("kind")
            if kind == "adapt":
                if r.get("reset_directions"):
                    history = []
            elif kind == "reset":
                raw = r.get("rot_history") or []
                history = [s for s in raw
                           if isinstance(s, str) and s][:cap]
        return history

    @staticmethod
    def _effective(policy, level):
        """Effective (trip limit, window) at an adaptation level."""
        limit = policy.budget_limit * (policy.adapt_factor ** level)
        window = max(2, policy.window_runs - level)
        return round(limit, 9), window

    @staticmethod
    def _slow_burn_state(records, policy, level):
        """Fold the chained log to the slow-burn accumulator state.

        Returns ``(accum, consistency, subfloor_runs, long_window)``.
        Only meaningful for ``AdaptiveBudgetPolicy`` (the sub-floor
        is ``adapt_flip_floor`` x the effective limit, both in
        threshold-equivalents). Sub-floor but nonzero contributions
        accrue at ``slow_weight``; clean-run defuses decay the
        accumulator multiplicatively by ``slow_clean_decay`` -- the
        accumulator alone forgives, so a boil must sustain to trip.
        The net direction and gross magnitude do NOT decay:
        decaying them lets the most recent contribution dominate, so
        alternating exact-opposite directions (which net to zero)
        still show high consistency -- the wave-146 f3/r7 break-first
        runs proved this fires on direction-inert scaffolding.
        Consistency is direction agreement of the accruing
        contributions in the window, undecayed. Contributions
        at/above the flip floor are the adapted machinery's job and
        do not accrue here. The epoch restarts (accumulator zeroed)
        on every ``slow_burn_trip`` marker, every manual reset, and
        every adapt tightening -- old evidence never double-counts.
        Only the last ``slow_window_factor`` x effective-window
        relevant records in the current epoch are folded.
        Deterministic: pure fold over the chained log, exact
        arithmetic with the same rounding discipline as the other
        folds.
        """
        eff_limit, eff_window = BudgetStore._effective(policy, level)
        floor_te = policy.adapt_flip_floor * eff_limit
        long_window = eff_window * policy.slow_window_factor
        epoch = []
        for r in records:
            kind = r.get("kind")
            if kind == "slow_burn_trip":
                epoch = []
            elif kind == "reset" and r.get("trigger") == "manual":
                epoch = []
            elif kind == "adapt" and (r.get("reset_streak")
                                     or r.get("reset_directions")):
                epoch = []
            elif kind in ("contribution", "reset"):
                epoch.append(r)
        accum = 0.0
        net = {}
        gross = 0.0
        runs = 0
        weight = policy.slow_weight
        decay = policy.slow_clean_decay
        for r in epoch[-long_window:]:
            kind = r.get("kind")
            if kind == "contribution" and r.get("contributes"):
                te = float(r.get("threshold_equivalents", 0.0))
                if 0.0 < te < floor_te:
                    accum = round(accum + weight * te, 9)
                    for tool, delta in \
                            r.get("signed_deltas", {}).items():
                        net[tool] = net.get(tool, 0.0) + delta
                    gross += sum(abs(v) for v in
                                 r.get("signed_deltas", {}).values())
                    runs += 1
            elif kind == "reset":
                # Clean-run defuse: decay the accumulator only, not
                # the direction ledger. Decaying net/gross together
                # lets the most recent contribution dominate, so
                # alternating exact-opposite directions (net zero)
                # still read as consistent -- a false positive the
                # wave-146 f3/r7 break-first runs caught. Manual
                # resets restart the epoch above instead.
                accum = round(accum * decay, 9)
        consistency = (sum(abs(v) for v in net.values()) / gross
                       if gross > 0 else 0.0)
        return accum, consistency, runs, long_window

    def _cycle_contributions(self, records, window):
        """Contributing records after the last reset, within the window.

        Returns ``(contributing, last_reset_seq, window_n)`` where
        ``window_n`` counts every contribution-kind record in the
        window (contributing or not), matching the historical
        ``BudgetCheck.window_n`` semantics.
        """
        last_reset_seq = -1
        for r in records:
            if r.get("kind") == "reset":
                last_reset_seq = max(last_reset_seq,
                                     int(r.get("run_seq", -1)))
        windowed = [r for r in records
                    if r.get("kind") == "contribution"
                    and int(r.get("run_seq", -1)) > last_reset_seq]
        windowed = windowed[-window:]
        contributing = [r for r in windowed if r.get("contributes")]
        return contributing, last_reset_seq, len(windowed)

    @staticmethod
    def _window_stats(contributing):
        """(cumulative, consistency, net dict, gross) over contributions."""
        cumulative = round(sum(r.get("threshold_equivalents", 0.0)
                               for r in contributing), 9)
        net = Counter()
        gross = 0.0
        for r in contributing:
            for tool, delta in r.get("signed_deltas", {}).items():
                net[tool] += delta
                gross += abs(delta)
        consistency = (sum(abs(v) for v in net.values()) / gross
                       if gross > 0 else 0.0)
        return cumulative, consistency, dict(net), gross

    def _write_adapt(self, agent_id, run_seq, level, direction, trigger,
                     eff_limit, eff_window, evidence, audit,
                     reset_streak=False, reset_directions=False):
        """Write an ``adapt`` record + audit event (audit-before-write).

        Tightenings emit the LOUD ``drift_budget_adapted`` evidence
        event; relaxations emit the audited (non-LOUD)
        ``drift_budget_relaxed`` event.
        """
        record = {"kind": "adapt", "agent_id": agent_id,
                  "run_seq": run_seq,
                  "drift_budget_version": _BUDGET_VERSION,
                  "adapt_level": level, "direction": direction,
                  "trigger": trigger, "effective_limit": eff_limit,
                  "effective_window": eff_window,
                  "reset_streak": bool(reset_streak),
                  "reset_directions": bool(reset_directions),
                  "evidence": dict(evidence)}
        event = {"event": "drift_budget_adapted"
                           if direction == "tighten"
                           else "drift_budget_relaxed",
                 "agent_id": agent_id, "run_seq": run_seq,
                 "adapt_level": level, "direction": direction,
                 "trigger": trigger, "effective_limit": eff_limit,
                 "effective_window": eff_window,
                 "evidence": dict(evidence)}
        if direction == "tighten":
            event["severity"] = "LOUD"
        return self._write(agent_id, record, event, audit)

    def record_run(self, agent_id, run_seq, run_id, fingerprint,
                   baseline, policy, principal="", audit=None):
        """Assess one run against the agent's budget; store the result.

        Returns a ``BudgetContribution``. Sub-threshold-but-nonzero
        runs accrue (audited ``drift_budget_accrue`` -- never silent).
        Clean runs (distance at/below the noise floor) defuse the
        budget: a ``reset`` record is stored with a
        ``drift_budget_reset`` audit event. Runs at/above
        ``warn_distance`` are recorded as non-contributing
        (``single_run_path``) -- that territory belongs to
        ``detect_drift``, unchanged.
        """
        self._check_fingerprint(fingerprint, "fingerprint")
        self._check_fingerprint(baseline, "baseline")
        if not isinstance(policy, BudgetPolicy):
            raise TypeError("policy must be a BudgetPolicy, got %r"
                            % type(policy).__name__)
        self._check_seq(run_seq)
        agent_id = str(agent_id)

        distance = fingerprint_tool_distance(fingerprint, baseline)
        if distance is None:
            record = {"kind": "contribution", "agent_id": agent_id,
                      "run_seq": run_seq, "run_id": str(run_id),
                      "principal": str(principal),
                      "drift_budget_version": _BUDGET_VERSION,
                      "contributes": False,
                      "reason": "insufficient_data",
                      "distance": None, "threshold_equivalents": 0.0,
                      "signed_deltas": {}}
            self._write(agent_id, record,
                        {"event": self._record_event, "agent_id": agent_id,
                         "run_seq": run_seq, "contributes": False,
                         "reason": "insufficient_data"}, audit)
            return BudgetContribution(False, None, 0.0,
                                      "insufficient_data", False,
                                      run_seq, agent_id)

        fraction = distance / policy.warn_distance
        if distance >= policy.warn_distance:
            record = {"kind": "contribution", "agent_id": agent_id,
                      "run_seq": run_seq, "run_id": str(run_id),
                      "principal": str(principal),
                      "drift_budget_version": _BUDGET_VERSION,
                      "contributes": False,
                      "reason": "single_run_path",
                      "distance": distance,
                      "threshold_equivalents": round(fraction, 9),
                      "signed_deltas": signed_tool_deltas(fingerprint,
                                                          baseline)}
            self._write(agent_id, record,
                        {"event": self._record_event, "agent_id": agent_id,
                         "run_seq": run_seq, "contributes": False,
                         "reason": "single_run_path",
                         "threshold_equivalents": round(fraction, 9)},
                        audit)
            return BudgetContribution(False, distance, fraction,
                                      "single_run_path", False,
                                      run_seq, agent_id)

        if distance <= policy.noise_floor * policy.warn_distance:
            # Clean run: defuse the budget (documented design choice).
            record = {"kind": "reset", "agent_id": agent_id,
                      "run_seq": run_seq, "run_id": str(run_id),
                      "principal": str(principal),
                      "drift_budget_version": _BUDGET_VERSION,
                      "trigger": "clean_run", "distance": distance}
            audit_event = {"event": "drift_budget_reset",
                           "agent_id": agent_id, "run_seq": run_seq,
                           "trigger": "clean_run", "distance": distance}
            if self._is_adaptive(policy):
                self._adaptive_defuse(agent_id, run_seq, record,
                                      audit_event, policy, audit)
            else:
                self._write(agent_id, record, audit_event, audit)
            return BudgetContribution(False, distance, 0.0, "clean",
                                      True, run_seq, agent_id)

        deltas = signed_tool_deltas(fingerprint, baseline)
        record = {"kind": "contribution", "agent_id": agent_id,
                  "run_seq": run_seq, "run_id": str(run_id),
                  "principal": str(principal),
                  "drift_budget_version": _BUDGET_VERSION,
                  "contributes": True, "reason": "sub_threshold",
                  "distance": distance,
                  "threshold_equivalents": round(fraction, 9),
                  "signed_deltas": deltas}
        self._write(agent_id, record,
                    {"event": self._record_event, "agent_id": agent_id,
                     "run_seq": run_seq, "contributes": True,
                     "threshold_equivalents": round(fraction, 9),
                     "distance": distance}, audit)
        if self._is_adaptive(policy):
            self._adaptive_streak_check(agent_id, run_seq, policy, audit)
        return BudgetContribution(True, distance, fraction,
                                  "sub_threshold", False,
                                  run_seq, agent_id)

    def _adaptive_defuse(self, agent_id, run_seq, record, audit_event,
                         policy, audit):
        """Evaluate the defused cycle for pacing; adapt or relax.

        Computes the just-ended cycle's cumulative/consistency from
        the chained log (pre-reset state), decides near-trip with a
        direction-aware streak, writes the reset record carrying the
        post-reset streak, then tightens (LOUD ``drift_budget_adapted``)
        or relaxes (``drift_budget_relaxed``) as decided. Audit runs
        before every mutation; a failure aborts and the store is
        unchanged.
        """
        records = self._read_all(agent_id)
        level, streak, s_net, s_gross, _, dir_scores, flip_prev, \
            flip_prev2 = self._adapt_fold(records)
        rot_history = self._rotation_fold(records)
        eff_limit, eff_window = self._effective(policy, level)
        cycle, _, _ = self._cycle_contributions(records, eff_window)
        cum, cons, net, gross = self._window_stats(cycle)
        near_trip = (len(cycle) >= 1
                     and cum >= policy.adapt_near_floor * eff_limit
                     and cons >= policy.min_consistency)
        if near_trip:
            # Direction-aware streak: a cycle whose direction cancels
            # the streak's net direction restarts the streak at 1
            # instead of extending it (alternating benign bursts never
            # accumulate).
            cand_net = dict(s_net)
            for tool, delta in net.items():
                cand_net[tool] = cand_net.get(tool, 0.0) + delta
            cand_gross = s_gross + gross
            cand_cons = (sum(abs(v) for v in cand_net.values())
                         / cand_gross if cand_gross > 0 else 0.0)
            if cand_cons >= policy.min_consistency:
                new_streak, new_net = streak + 1, cand_net
            else:
                new_streak, new_net = 1, dict(net)
            new_gross = cand_gross if new_streak > 1 else gross
        else:
            new_streak, new_net, new_gross = 0, {}, 0.0
        # Wave-141 (row 9): per-direction pacing buckets. A near-trip
        # cycle accrues its threshold-equivalents into the bucket keyed
        # by the cycle's deterministic direction signature; EVERY
        # bucket decays slowly each defuse cycle instead of resetting
        # merely because the direction flipped. Persistent flip pacing
        # (repeated near-trip cycles in alternating directions) trips
        # a bucket while the aggregate consistency gate and the
        # direction-aware streak above both stay blind. Buckets are
        # carried on the chained reset records (audited evidence) and
        # zeroed by a direction-triggered tightening.
        sig = _direction_key(net) if near_trip else ""
        decay = policy.adapt_dir_decay
        new_scores = {}
        for skey, sval in dir_scores.items():
            dval = round(sval * decay, 9)
            if dval > 0:
                new_scores[skey] = dval
        if near_trip and sig:
            new_scores[sig] = round(new_scores.get(sig, 0.0) + cum, 9)
        # The tripping bucket is the max one at/above threshold (it is
        # usually the current cycle's, but a decayed bucket from a
        # recently blocked tightening can still be the evidence).
        trip_sig, trip_score = "", 0.0
        for skey, sval in new_scores.items():
            if (sval >= policy.adapt_dir_threshold
                    and sval > trip_score):
                trip_sig, trip_score = skey, sval
        dir_trip = near_trip and bool(trip_sig)
        # Wave-144 (row 9): flip confirmation. A paced cycle is a
        # near-trip cycle at/above the flip floor; only paced cycles
        # feed the flip state, and any non-paced cycle (sub-floor,
        # non-near-trip, or directionless) breaks consecutiveness and
        # clears it. The confirmation fires when the current paced
        # cycle's signature flips from the previous paced cycle's AND
        # flips back to the one before that -- the second consecutive
        # direction-flip cycle closing a genuine A/B/A 2-period
        # oscillation at near-threshold magnitudes. Inconsistent
        # directions (A/B/C/... never closing a 2-period) and
        # same-direction repeats never confirm.
        paced = (near_trip and sig
                 and cum >= policy.adapt_flip_floor * eff_limit)
        flip_confirmed = False
        new_flip_prev, new_flip_prev2 = flip_prev, flip_prev2
        if paced:
            if flip_prev is None:
                new_flip_prev, new_flip_prev2 = sig, None
            elif sig == flip_prev:
                # Same direction: restarts the alternation hunt.
                new_flip_prev, new_flip_prev2 = sig, None
            elif flip_prev2 is not None and sig == flip_prev2:
                flip_confirmed = True
                new_flip_prev, new_flip_prev2 = None, None
            else:
                # First flip of a potential oscillation (A->B):
                # remember both, confirm only if the next cycle
                # closes the 2-period.
                new_flip_prev, new_flip_prev2 = sig, flip_prev
        else:
            new_flip_prev, new_flip_prev2 = None, None
        # Wave-145 (row 9): N-period rotation confirmation. Paced
        # cycles append their direction signature to the rotation
        # history (capped at 2K entries); any non-paced cycle
        # clears it -- consecutiveness, exactly like the flip
        # state above, and gated by the SAME "paced" definition
        # (the flip detector's floor + direction-consistency
        # gating, reused, not a parallel mechanism). For periods
        # p in 3..K, a trailing window whose last 2p signatures
        # are two clean back-to-back repetitions of one period-p
        # pattern (autocorrelation at lag p = 1.0) with at least
        # two distinct directions inside the period confirms
        # pacing: period 2 is the flip tripwire's (it fires first
        # on any A/B/A subsequence, so the rotation check is
        # skipped when the flip confirms), and a single repeated
        # direction (period 1) belongs to the near-trip streak.
        rotation_confirmed = False
        rotation_period = 0
        rotation_pattern = []
        if paced:
            new_rot_history = ((rot_history + [sig])
                               [-2 * _ROTATION_MAX_PERIOD:])
            if not flip_confirmed:
                for p in range(3, _ROTATION_MAX_PERIOD + 1):
                    if (_rotation_period_score(new_rot_history, p)
                            == 1.0):
                        period_sigs = new_rot_history[-p:]
                        if len(set(period_sigs)) >= 2:
                            rotation_confirmed = True
                            rotation_period = p
                            rotation_pattern = list(period_sigs)
                            break
                if rotation_confirmed:
                    # Tightens exactly like a confirmed flip: both
                    # hunts restart from zero.
                    new_rot_history = []
                    new_flip_prev, new_flip_prev2 = None, None
        else:
            new_rot_history = []
        record.update({
            "near_trip": near_trip, "streak": new_streak,
            "cycle_cumulative": cum,
            "cycle_consistency": round(cons, 6),
            "streak_net": {k: round(v, 6) for k, v in new_net.items()},
            "streak_gross": round(new_gross, 6),
            "direction_sig": sig,
            "direction_scores": {k: round(v, 6)
                                 for k, v in new_scores.items()},
            "direction_trip": bool(dir_trip),
            "flip_paced": bool(paced),
            "flip_prev": new_flip_prev,
            "flip_prev2": new_flip_prev2,
            "flip_confirmed": bool(flip_confirmed),
            "rot_history": list(new_rot_history),
            "rotation_confirmed": bool(rotation_confirmed),
            "rotation_period": rotation_period})
        audit_event["near_trip"] = near_trip
        audit_event["near_streak"] = new_streak
        audit_event["direction_trip"] = bool(dir_trip)
        audit_event["flip_confirmed"] = bool(flip_confirmed)
        audit_event["rotation_confirmed"] = bool(rotation_confirmed)
        self._write(agent_id, record, audit_event, audit)
        if flip_confirmed and level < policy.adapt_max_level:
            new_level = level + 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(
                agent_id, run_seq, new_level, "tighten",
                "direction_pacing_confirmed", nl, nw,
                {"flip_sig": sig,
                 "flip_prev": flip_prev, "flip_prev2": flip_prev2,
                 "flip_floor": policy.adapt_flip_floor,
                 "cycle_cumulative": cum,
                 "cycle_consistency": round(cons, 6)}, audit,
                reset_streak=True, reset_directions=True)
        elif (rotation_confirmed and level < policy.adapt_max_level):
            new_level = level + 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(
                agent_id, run_seq, new_level, "tighten",
                "rotation_pacing_confirmed", nl, nw,
                {"rotation_period": rotation_period,
                 "rotation_pattern": rotation_pattern,
                 "rotation_sig": sig,
                 "pacing_floor": policy.adapt_flip_floor,
                 "cycle_cumulative": cum,
                 "cycle_consistency": round(cons, 6)}, audit,
                reset_streak=True, reset_directions=True)
        elif (near_trip and new_streak >= policy.adapt_cycles
                and level < policy.adapt_max_level):
            new_level = level + 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(
                agent_id, run_seq, new_level, "tighten",
                "near_trip_cycle", nl, nw,
                {"near_streak": new_streak, "cycle_cumulative": cum,
                 "cycle_consistency": round(cons, 6)}, audit,
                reset_streak=True)
        elif dir_trip and level < policy.adapt_max_level:
            new_level = level + 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(
                agent_id, run_seq, new_level, "tighten",
                "direction_pacing", nl, nw,
                {"direction_sig": trip_sig,
                 "direction_score": round(trip_score, 6),
                 "direction_threshold": policy.adapt_dir_threshold,
                 "cycle_cumulative": cum,
                 "cycle_consistency": round(cons, 6)}, audit,
                reset_streak=True, reset_directions=True)
        elif not near_trip and level > 0:
            new_level = level - 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(agent_id, run_seq, new_level, "relax",
                              "benign_cycle", nl, nw,
                              {"cycle_cumulative": cum}, audit)


    def _adaptive_streak_check(self, agent_id, run_seq, policy, audit):
        """Mid-cycle trigger: N consecutive near-threshold contributions.

        ``adapt_strikes`` consecutive contributing runs (after the last
        reset, inside the window, all newer than the last adaptation),
        each at/above ``adapt_contrib_floor`` threshold-equivalents
        with direction consistency >= min_consistency, tighten the
        budget LOUD. Under the default policy the static trip usually
        fires first; this trigger is load-bearing under operator
        policies with a higher budget_limit.
        """
        records = self._read_all(agent_id)
        level, _, _, _, last_adapt_seq, _, _, _ = self._adapt_fold(
            records)
        if level >= policy.adapt_max_level:
            return
        _, eff_window = self._effective(policy, level)
        cycle, _, _ = self._cycle_contributions(records, eff_window)
        tail = cycle[-policy.adapt_strikes:]
        if len(tail) != policy.adapt_strikes:
            return
        if not all(int(r.get("run_seq", -1)) > last_adapt_seq
                   for r in tail):
            return
        fracs = [r.get("threshold_equivalents", 0.0) for r in tail]
        if min(fracs) < policy.adapt_contrib_floor:
            return
        _, cons, _, _ = self._window_stats(tail)
        if cons < policy.min_consistency:
            return
        new_level = level + 1
        nl, nw = self._effective(policy, new_level)
        self._write_adapt(
            agent_id, run_seq, new_level, "tighten",
            "contribution_streak", nl, nw,
            {"streak": policy.adapt_strikes,
             "min_fraction": round(min(fracs), 6),
             "consistency": round(cons, 6)}, audit)

    def reset(self, agent_id, reason="manual", audit=None):
        """Clear the agent's budget on operator demand (audited)."""
        agent_id = str(agent_id)
        records = self._read_all(agent_id)
        last_seq = max([r.get("run_seq", -1) for r in records] + [-1])
        record = {"kind": "reset", "agent_id": agent_id,
                  "run_seq": last_seq,
                  "drift_budget_version": _BUDGET_VERSION,
                  "trigger": "manual", "reason": str(reason)}
        return self._write(agent_id, record,
                           {"event": "drift_budget_reset",
                            "agent_id": agent_id, "trigger": "manual",
                            "reason": str(reason)}, audit)

    # ----------------------------------------------------------- reads

    def contributions(self, agent_id):
        """All stored budget records for the agent, oldest first."""
        return self._read_all(str(agent_id))

    def check(self, agent_id, policy, audit=None):
        """Evaluate the agent's budget; trip LOUD on escalation.

        Sums threshold-equivalents of contributing runs after the
        last reset, within the last ``policy.window_runs`` recorded
        runs. Trips (status ``tripped``) iff cumulative >=
        ``budget_limit`` AND direction consistency >=
        ``min_consistency`` AND at least ``min_contributing_runs``
        contributing runs. The first trip writes a ``trip`` marker
        and emits the LOUD ``drift_budget_tripped`` evidence event
        (audit-before-write); later checks while tripped re-report
        the status without re-emitting.
        """
        if not isinstance(policy, BudgetPolicy):
            raise TypeError("policy must be a BudgetPolicy, got %r"
                            % type(policy).__name__)
        agent_id = str(agent_id)
        records = self._read_all(agent_id)

        adaptive = self._is_adaptive(policy)
        adapt_level = 0
        eff_limit, eff_window = policy.budget_limit, policy.window_runs
        if adaptive:
            adapt_level, _, _, _, _, _, _, _ = self._adapt_fold(records)
            eff_limit, eff_window = self._effective(policy, adapt_level)

        contributing, last_reset_seq, window_n = self._cycle_contributions(
            records, eff_window)
        cumulative, consistency, _, _ = self._window_stats(contributing)

        n = len(contributing)
        # While adapted (level >= 1) the level itself encodes the prior
        # multi-cycle pacing evidence, so a single fresh contributing
        # run at/above the lowered limit trips.
        enough_runs = (n >= policy.min_contributing_runs
                       or (adaptive and adapt_level >= 1 and n >= 1))
        tripped = (cumulative >= eff_limit
                   and consistency >= policy.min_consistency
                   and enough_runs)

        trip_seqs = [int(r.get("run_seq", -1)) for r in records
                     if r.get("kind") == "trip"
                     and int(r.get("run_seq", -1)) > last_reset_seq]
        last_trip_seq = max(trip_seqs) if trip_seqs else -1
        tripped_seq = None
        if tripped:
            if contributing:
                tripped_seq = max(int(r.get("run_seq", 0))
                                  for r in contributing)
            else:
                tripped_seq = last_reset_seq
            # Emit the LOUD event on a fresh trip, or on a re-trip
            # driven by contributions that arrived after the last
            # trip marker. Re-checks while continuously tripped do
            # not re-emit.
            if tripped_seq > last_trip_seq:
                marker = {"kind": "trip", "agent_id": agent_id,
                          "run_seq": tripped_seq,
                          "drift_budget_version": _BUDGET_VERSION,
                          "cumulative": cumulative,
                          "consistency": round(consistency, 6),
                          "contributing_runs": n}
                self._write(agent_id, marker,
                            {"event": "drift_budget_tripped",
                             "severity": "LOUD",
                             "agent_id": agent_id,
                             "cumulative": cumulative,
                             "consistency": round(consistency, 6),
                             "contributing_runs": n,
                             "window_runs": eff_window,
                             "budget_limit": eff_limit,
                             "adapt_level": adapt_level},
                            audit)

        status = "tripped" if tripped else "ok"

        # Wave-146 (row 9): the slow-burn accumulator. Sub-floor paced
        # bursts with clean defuses evade every other tripwire; the
        # long-window accumulator catches them. On a trip: a LOUD
        # ``drift_budget_slow_burn`` event plus a tightening exactly
        # like the other pacing triggers (trigger "slow_burn"). The
        # trip marker restarts the accumulator epoch, so one epoch
        # trips at most once; the status still reflects the main
        # budget -- the LOUD event is the escalation signal, and the
        # tightened level makes the next contributing run trip under
        # the lowered limit per the existing level>=1 semantics.
        slow_detail = {"slow_burn_tripped": False,
                       "slow_burn_accum": 0.0,
                       "slow_burn_consistency": 0.0,
                       "slow_burn_runs": 0,
                       "slow_burn_threshold": None,
                       "slow_burn_window_runs": None}
        if adaptive:
            accum, scons, sruns, slong = self._slow_burn_state(
                records, policy, adapt_level)
            slow_detail.update(
                slow_burn_accum=accum,
                slow_burn_consistency=round(scons, 6),
                slow_burn_runs=sruns,
                slow_burn_threshold=policy.slow_trip,
                slow_burn_window_runs=slong)
            if (accum >= policy.slow_trip
                    and scons >= policy.min_consistency
                    and sruns >= policy.slow_min_runs):
                slow_detail["slow_burn_tripped"] = True
                seqs = [int(r.get("run_seq", -1)) for r in records
                        if r.get("kind") == "contribution"
                        and r.get("contributes")]
                slow_seq = max(seqs) if seqs else last_reset_seq
                marker = {"kind": "slow_burn_trip", "agent_id": agent_id,
                          "run_seq": slow_seq,
                          "drift_budget_version": _BUDGET_VERSION,
                          "slow_accum": accum,
                          "slow_consistency": round(scons, 6),
                          "slow_runs": sruns}
                self._write(agent_id, marker,
                            {"event": "drift_budget_slow_burn",
                             "severity": "LOUD",
                             "agent_id": agent_id,
                             "slow_accum": accum,
                             "slow_consistency": round(scons, 6),
                             "slow_runs": sruns,
                             "slow_window_runs": slong,
                             "slow_trip": policy.slow_trip,
                             "adapt_level_before": adapt_level},
                            audit)
                if adapt_level < policy.adapt_max_level:
                    new_level = adapt_level + 1
                    nl, nw = self._effective(policy, new_level)
                    self._write_adapt(
                        agent_id, slow_seq, new_level, "tighten",
                        "slow_burn", nl, nw,
                        {"slow_accum": accum,
                         "slow_consistency": round(scons, 6),
                         "slow_runs": sruns,
                         "slow_window_runs": slong}, audit,
                        reset_streak=True, reset_directions=True)

        return BudgetCheck(
            status, agent_id=agent_id, cumulative=cumulative,
            consistency=round(consistency, 6),
            contributing_runs=n, window_n=window_n,
            tripped_run_seq=tripped_seq if status == "tripped" else None,
            detail={"budget_limit": policy.budget_limit,
                    "window_runs": policy.window_runs,
                    "min_consistency": policy.min_consistency,
                    "warn_distance": policy.warn_distance,
                    "adapt_level": adapt_level,
                    "effective_limit": eff_limit,
                    "effective_window": eff_window,
                    **slow_detail})
