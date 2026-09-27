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
"""

from collections import Counter
from pathlib import Path

from gov.chained_store import ChainedStore
from gov.drift import RunFingerprint, fingerprint_tool_distance

__all__ = [
    "BudgetPolicy",
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
            self._write(agent_id, record,
                        {"event": "drift_budget_reset",
                         "agent_id": agent_id, "run_seq": run_seq,
                         "trigger": "clean_run", "distance": distance},
                        audit)
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
        return BudgetContribution(True, distance, fraction,
                                  "sub_threshold", False,
                                  run_seq, agent_id)

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

        last_reset_seq = -1
        for r in records:
            if r.get("kind") == "reset":
                last_reset_seq = max(last_reset_seq,
                                     int(r.get("run_seq", -1)))
        windowed = [r for r in records
                    if r.get("kind") == "contribution"
                    and int(r.get("run_seq", -1)) > last_reset_seq]
        windowed = windowed[-policy.window_runs:]
        contributing = [r for r in windowed if r.get("contributes")]

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

        n = len(contributing)
        tripped = (cumulative >= policy.budget_limit
                   and consistency >= policy.min_consistency
                   and n >= policy.min_contributing_runs)

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
                             "window_runs": policy.window_runs,
                             "budget_limit": policy.budget_limit},
                            audit)

        status = "tripped" if tripped else "ok"
        return BudgetCheck(
            status, agent_id=agent_id, cumulative=cumulative,
            consistency=round(consistency, 6),
            contributing_runs=n, window_n=len(windowed),
            tripped_run_seq=tripped_seq if status == "tripped" else None,
            detail={"budget_limit": policy.budget_limit,
                    "window_runs": policy.window_runs,
                    "min_consistency": policy.min_consistency,
                    "warn_distance": policy.warn_distance})
