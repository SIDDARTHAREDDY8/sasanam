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
    """

    __slots__ = ("adapt_near_floor", "adapt_cycles", "adapt_factor",
                 "adapt_contrib_floor", "adapt_strikes",
                 "adapt_max_level")

    def __init__(self, warn_distance, adapt_near_floor=0.75,
                 adapt_cycles=2, adapt_factor=0.6,
                 adapt_contrib_floor=0.75, adapt_strikes=3,
                 adapt_max_level=3, **kw):
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
        self.adapt_near_floor = float(adapt_near_floor)
        self.adapt_cycles = adapt_cycles
        self.adapt_factor = float(adapt_factor)
        self.adapt_contrib_floor = float(adapt_contrib_floor)
        self.adapt_strikes = adapt_strikes
        self.adapt_max_level = adapt_max_level

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
        last_adapt_seq)``. Each reset record carries the post-reset
        streak; a cycle-triggered tightening (``reset_streak``) zeroes
        it. Records from ``reset()`` predate the adaptive fields and
        are treated as streak 0 (level is operator policy state and
        survives a manual reset -- it decays via benign cycles).
        Deterministic: pure fold over the chained log.
        """
        level = 0
        streak = 0
        streak_net = {}
        streak_gross = 0.0
        last_adapt_seq = -1
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
            elif kind == "reset":
                streak = int(r.get("streak", 0))
                streak_net = {k: float(v) for k, v in
                              r.get("streak_net", {}).items()}
                streak_gross = float(r.get("streak_gross", 0.0))
        return level, streak, streak_net, streak_gross, last_adapt_seq

    @staticmethod
    def _effective(policy, level):
        """Effective (trip limit, window) at an adaptation level."""
        limit = policy.budget_limit * (policy.adapt_factor ** level)
        window = max(2, policy.window_runs - level)
        return round(limit, 9), window

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
                     reset_streak=False):
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
        level, streak, s_net, s_gross, _ = self._adapt_fold(records)
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
        record.update({
            "near_trip": near_trip, "streak": new_streak,
            "cycle_cumulative": cum,
            "cycle_consistency": round(cons, 6),
            "streak_net": {k: round(v, 6) for k, v in new_net.items()},
            "streak_gross": round(new_gross, 6)})
        audit_event["near_trip"] = near_trip
        audit_event["near_streak"] = new_streak
        self._write(agent_id, record, audit_event, audit)
        if (near_trip and new_streak >= policy.adapt_cycles
                and level < policy.adapt_max_level):
            new_level = level + 1
            nl, nw = self._effective(policy, new_level)
            self._write_adapt(
                agent_id, run_seq, new_level, "tighten",
                "near_trip_cycle", nl, nw,
                {"near_streak": new_streak, "cycle_cumulative": cum,
                 "cycle_consistency": round(cons, 6)}, audit,
                reset_streak=True)
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
        level, _, _, _, last_adapt_seq = self._adapt_fold(records)
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
            adapt_level, _, _, _, _ = self._adapt_fold(records)
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
                    "effective_window": eff_window})
