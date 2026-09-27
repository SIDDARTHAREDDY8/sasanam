"""Cross-run semantic drift detection (row 9).

Row 9's pinned gap (H7 Phase A, wave-117): gradual behavioral erosion
across runs is invisible when each individual run looks benign. Phase B
(wave-119) built the per-run ``TrajectoryErosionMonitor`` in
``gov/detection.py``; cross-run erosion stays open. This module closes
the *cross-run* half: per agent/principal, each run records a compact
behavioral fingerprint, and ``detect_drift`` compares a recent window
against that agent's own baseline with three deterministic signals:

  A. tool-distribution shift (chi-square on tool counts);
  B. deny/approval-rate change (abrupt rate deltas);
  C. egress-volume trend (Mann-Kendall, one-sided increasing).

The response is graduated, never a binary block: SILENT -> WATCH (a
chained audit event) -> WARN (LOUD audit event for the operator) ->
HOLD (a ``drift_review`` approval is queued -- a human resolves; the
run is never auto-denied by this layer).

What this is NOT (honest ceilings):
- Not a badness detector. It measures CHANGE against the agent's own
  baseline. An agent that exfiltrates heavily from run 1 poisons its
  baseline and never drifts -- ``p4`` in the battery pins this red as
  MISS-DOCUMENTED. Cross-run *badness* without *change* is out of
  scope for this module.
- Not semantic. The fingerprint is behavioral aggregates (tool
  counts, decision outcomes, approval patterns, egress volume), not
  content. Many-shot *framing* drift (row-9 e4) is untouched.
- Slow-enough drift under the statistical thresholds is invisible by
  design. The battery measures detection latency (runs to HOLD) for a
  representative ramp; a shallower ramp takes longer or never trips.
- Novel-tool adoption is capped at weak by construction: a shift
  dominated by tools the baseline never saw is benign evolution until
  corroborated by the deny or egress signals. An adversary who ramps
  exfiltration through a *brand-new* tool gets at most WARN from the
  distribution signal alone -- the egress/deny signals must carry it
  to HOLD. Documented, not hidden.

Privacy: the store holds behavioral fingerprints (counts), never raw
prompts, tool outputs, or log contents. Treat the store directory as
sensitive operational data (same posture as the audit logs).

Population-relative baseline validation (wave-134): ``PopulationStore``
+ ``validate_baseline_against_population`` compare a new agent's
baseline fingerprint against OTHER agents' baselines (median symmetric
chi-square tool-distribution distance vs the 99th percentile of
pairwise peer distances). Extreme outliers are stored
``provisional_untrusted`` (LOUD ``baseline_population_outlier``
event); ``cap_drift_verdict`` forces every drift verdict against a
provisional baseline to WARN -- never SILENT, never HOLD -- until a
human confirms it or K subsequent runs converge toward the
population. Honest ceilings: Sybil (a uniformly poisoned population
validates poison into trust), the threshold game (a baseline shaped
just inside the envelope passes), >= 3 peers required, and the
comparison is tool-distribution only.

$0, stdlib only, deterministic. All statistics are exact
deterministic computations (no sampling, no RNG). Fingerprint
validation is fail-closed: negative counts or unknown decision keys
raise ValueError rather than being silently accepted.
"""

import json
import math
import hmac
import tempfile
from collections import Counter
from pathlib import Path

__all__ = [
    "RunFingerprint",
    "DriftStore",
    "DriftSignal",
    "DriftResult",
    "detect_drift",
    "fingerprint_from_entries",
    "default_store_dir",
    "chi_square_sf",
    "mann_kendall_z",
    # Wave-134 (row 9): population-relative baseline validation.
    "PopulationStore",
    "PopulationCorruptedError",
    "BaselineValidationResult",
    "validate_baseline_against_population",
    "cap_drift_verdict",
    "fingerprint_tool_distance",
]

_DRIFT_VERSION = 1

# Minimum window egress (bytes) for the trend signal to be considered at
# all: guards against "infinite ratio" noise when the baseline egressed
# nothing and the window egresses a handful of bytes.
EGRESS_FLOOR_BYTES = 10_000

# Minimum sample mass for the rate/distribution signals: tiny
# denominators make rates and chi-square meaningless (FP risk).
_MIN_DECISIONS_FOR_RATE = 20
_MIN_TOOL_CALLS_FOR_CHISQ = 20

# Novel-tool cap: when more than this fraction of the chi-square
# statistic comes from tool categories the baseline never saw, the
# shift is treated as benign evolution (new capability adoption) and
# the distribution signal is capped at weak.
_NOVEL_FRACTION_CAP = 0.5


# ---------------------------------------------------------------- math

def _gser(a, x):
    """Regularized lower incomplete gamma P(a,x) via series expansion."""
    gln = math.lgamma(a)
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(700):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-14:
            break
    return total * math.exp(-x + a * math.log(x) - gln)


def _gcf(a, x):
    """Regularized upper incomplete gamma Q(a,x) via continued fraction."""
    gln = math.lgamma(a)
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 700):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = c * d
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def chi_square_sf(stat, df):
    """Survival function P(ChiSq_df > stat), deterministic, stdlib.

    Returns 1.0 for non-positive statistics. Clamped to [0, 1].
    """
    if df < 1:
        raise ValueError("chi_square_sf requires df >= 1, got %r" % (df,))
    if stat <= 0:
        return 1.0
    a = df / 2.0
    x = stat / 2.0
    if x < a + 1.0:
        return max(0.0, min(1.0, 1.0 - _gser(a, x)))
    return max(0.0, min(1.0, _gcf(a, x)))


def mann_kendall_z(values):
    """Mann-Kendall trend statistic (one-sided, increasing), as a z-score.

    Distribution-free: no normality assumption on the per-run volumes.
    Returns 0.0 for fewer than 4 points, constant series, or degenerate
    variance. Positive z = increasing trend.
    """
    vals = list(values)
    n = len(vals)
    if n < 4:
        return 0.0
    s = 0
    for i in range(n):
        vi = vals[i]
        for j in range(i + 1, n):
            vj = vals[j]
            if vj > vi:
                s += 1
            elif vj < vi:
                s -= 1
    tie = sum(t * (t - 1) * (2 * t + 5)
              for t in Counter(vals).values() if t > 1)
    var = (n * (n - 1) * (2 * n + 5) - tie) / 18.0
    if var <= 0:
        return 0.0
    if s > 0:
        return (s - 1) / math.sqrt(var)
    if s < 0:
        return (s + 1) / math.sqrt(var)
    return 0.0


def _normal_sf(z):
    """P(Z > z) for standard normal, via erf. z may be negative."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


# ------------------------------------------------------- fingerprint

_DECISION_KEYS = ("allow", "require_approval", "deny")


def _check_counts(mapping, what):
    if not isinstance(mapping, dict):
        raise ValueError("%s must be a dict, got %r" % (what, mapping))
    out = {}
    for k, v in mapping.items():
        if not isinstance(k, str) or not k:
            raise ValueError("%s keys must be non-empty strings, got %r"
                             % (what, k))
        if not isinstance(v, int) or v < 0:
            raise ValueError("%s[%r] must be a non-negative int, got %r"
                             % (what, k, v))
        out[k] = v
    return out


class RunFingerprint:
    """Compact behavioral fingerprint for one run.

    Aggregates only -- tool call distribution, policy decision
    outcomes, approval request patterns, egress volume. No prompts, no
    tool outputs, no log contents: the store is privacy-preserving by
    construction (counts, not content).
    """

    __slots__ = ("tool_counts", "decisions", "approvals_requested",
                 "approvals_granted", "approvals_denied", "egress_events",
                 "egress_bytes", "run_seq", "run_id")

    def __init__(self, tool_counts, decisions,
                 approvals_requested=0, approvals_granted=0,
                 approvals_denied=0, egress_events=0, egress_bytes=0,
                 run_seq=0, run_id=""):
        self.tool_counts = _check_counts(tool_counts, "tool_counts")
        decisions = _check_counts(decisions, "decisions")
        unknown = set(decisions) - set(_DECISION_KEYS)
        if unknown:
            raise ValueError("unknown decision keys %r: known keys are %s"
                             % (sorted(unknown), ", ".join(_DECISION_KEYS)))
        self.decisions = {k: decisions.get(k, 0) for k in _DECISION_KEYS}
        for name, v in (("approvals_requested", approvals_requested),
                        ("approvals_granted", approvals_granted),
                        ("approvals_denied", approvals_denied),
                        ("egress_events", egress_events),
                        ("egress_bytes", egress_bytes)):
            if not isinstance(v, int) or v < 0:
                raise ValueError("%s must be a non-negative int, got %r"
                                 % (name, v))
        self.approvals_requested = approvals_requested
        self.approvals_granted = approvals_granted
        self.approvals_denied = approvals_denied
        self.egress_events = egress_events
        self.egress_bytes = egress_bytes
        if not isinstance(run_seq, int) or run_seq < 0:
            raise ValueError("run_seq must be a non-negative int, got %r"
                             % (run_seq,))
        self.run_seq = run_seq
        self.run_id = str(run_id)

    def to_dict(self):
        return {
            "tool_counts": dict(self.tool_counts),
            "decisions": dict(self.decisions),
            "approvals_requested": self.approvals_requested,
            "approvals_granted": self.approvals_granted,
            "approvals_denied": self.approvals_denied,
            "egress_events": self.egress_events,
            "egress_bytes": self.egress_bytes,
            "run_seq": self.run_seq,
            "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            tool_counts=d.get("tool_counts", {}),
            decisions=d.get("decisions", {}),
            approvals_requested=d.get("approvals_requested", 0),
            approvals_granted=d.get("approvals_granted", 0),
            approvals_denied=d.get("approvals_denied", 0),
            egress_events=d.get("egress_events", 0),
            egress_bytes=d.get("egress_bytes", 0),
            run_seq=d.get("run_seq", 0),
            run_id=d.get("run_id", ""),
        )


def fingerprint_from_entries(entries):
    """Fold raw audit-log entries into a RunFingerprint (documented
    heuristic).

    Recognized shapes (anything else is ignored, never guessed):
    - tool calls: entries with a ``tool`` field and ``event`` in
      {"tool_call", "call", "action"} -> tool_counts[tool] += 1
    - decisions: entries with ``decision`` in
      {"allow", "require_approval", "deny"} -> decisions[decision] += 1
    - approvals: ``event`` in {"approval_requested",
      "approval_granted", "approval_denied"}
    - egress: ``event`` == "egress" -> egress_events += 1,
      egress_bytes += int(entry.get("bytes", 0))

    ``run_seq``/``run_id`` are left at 0/"": the caller sets them.
    """
    tools = Counter()
    decisions = Counter()
    req = gra = den = 0
    ev = 0
    ebytes = 0
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        kind = e.get("event")
        tool = e.get("tool")
        if tool and kind in ("tool_call", "call", "action"):
            tools[str(tool)] += 1
        dec = e.get("decision")
        if dec in _DECISION_KEYS:
            decisions[dec] += 1
        if kind == "approval_requested":
            req += 1
        elif kind == "approval_granted":
            gra += 1
        elif kind == "approval_denied":
            den += 1
        elif kind == "egress":
            ev += 1
            try:
                ebytes += max(0, int(e.get("bytes", 0)))
            except (TypeError, ValueError):
                pass
    return RunFingerprint(
        tool_counts=dict(tools),
        decisions={k: decisions.get(k, 0) for k in _DECISION_KEYS},
        approvals_requested=req, approvals_granted=gra,
        approvals_denied=den, egress_events=ev, egress_bytes=ebytes,
    )


# ------------------------------------------------------------ store

from gov.chained_store import ChainedStore
# Single canonical home for the chain primitives (wave-134 cleanup).
# The local aliases keep this module's private references (e.g.
# PopulationStore) unchanged.
from gov.chained_store import (
    canonical as _canonical,
    sha256_hex as _sha256_hex,
    utcnow_iso as _utcnow_iso,
    resolve_chain_key as _resolve_chain_key,
    chain_domain as _chain_domain,
    keyed_digest as _keyed_digest,
)
from gov.keys import NoKeyConfiguredError as _NoKeyConfiguredError

# MAC domain for the population chain (distinct from the drift and
# framing run-chain domains).
_POP_CHAIN_DOMAIN = _chain_domain("population")


def default_store_dir():
    """Default on-disk home for drift profiles (operator override via
    constructor). Kept out of any run TMPDIR: profiles must survive
    across runs -- that is the entire point of the store."""
    return Path.home() / ".agent-governance-demo" / "drift"


class DriftStore(ChainedStore):
    """Durable per-agent cross-run profile store.

    One JSONL file per agent under ``store_dir``. Every record is
    hash-chained (``prev_digest`` linkage): new records carry
    ``chain_keyed: true`` and a HMAC-SHA256 digest under the deployment
    key, pre-upgrade records carry the legacy unkeyed SHA-256 digest
    and still verify. ``verify_chain`` rejects tampered payloads,
    dropped records, and broken linkage. Audit runs BEFORE local
    mutation (F167 lesson): a logging failure leaves the store
    unchanged.

    Storage mechanics live in ``gov.chained_store.ChainedStore``; this
    class only declares the drift record schema (``drift_version`` /
    ``drift_run_recorded`` / ``RunFingerprint``). The on-disk format is
    identical to the pre-extraction store.
    """

    _record_version_key = "drift_version"
    _record_version = _DRIFT_VERSION
    _record_event = "drift_run_recorded"
    _fingerprint_cls = RunFingerprint


# ---------------------------------------------------------- signals

class DriftSignal:
    """One fired drift signal: kind, strength, and an explanation."""

    __slots__ = ("kind", "strength", "detail", "explanation")

    def __init__(self, kind, strength, detail, explanation):
        if kind not in ("tool_distribution", "deny_rate", "egress_trend"):
            raise ValueError("unknown signal kind %r" % (kind,))
        if strength not in ("weak", "strong"):
            raise ValueError("strength must be weak|strong, got %r"
                             % (strength,))
        self.kind = kind
        self.strength = strength
        self.detail = dict(detail)
        self.explanation = str(explanation)

    def to_dict(self):
        return {"kind": self.kind, "strength": self.strength,
                "detail": self.detail, "explanation": self.explanation}


class DriftResult:
    """Outcome of detect_drift: level in {silent, watch, warn, hold}."""

    __slots__ = ("level", "signals", "agent_id", "baseline_n", "window_n",
                 "reason")

    def __init__(self, level, signals=(), agent_id="", baseline_n=0,
                 window_n=0, reason=""):
        if level not in ("silent", "watch", "warn", "hold"):
            raise ValueError("unknown drift level %r" % (level,))
        self.level = level
        self.signals = list(signals)
        self.agent_id = str(agent_id)
        self.baseline_n = baseline_n
        self.window_n = window_n
        self.reason = str(reason)

    def to_dict(self):
        return {"level": self.level, "agent_id": self.agent_id,
                "baseline_n": self.baseline_n, "window_n": self.window_n,
                "reason": self.reason,
                "signals": [s.to_dict() for s in self.signals]}


def _chi2_stat(expected_counts, observed_counts):
    """Chi-square statistic of observed vs expected tool counts.

    Laplace (+1) smoothing avoids zero expected counts. Returns
    ``(stat, df, novel_fraction)`` where novel_fraction is the share
    of the statistic contributed by categories the expected side
    never saw, or None when the call mass is too small to measure
    (FP guard) or fewer than two categories exist.
    """
    exp_total = sum(expected_counts.values())
    obs_total = sum(observed_counts.values())
    if exp_total < _MIN_TOOL_CALLS_FOR_CHISQ or \
            obs_total < _MIN_TOOL_CALLS_FOR_CHISQ:
        return None
    cats = sorted(set(expected_counts) | set(observed_counts))
    if len(cats) < 2:
        return None
    smooth_total = exp_total + len(cats)  # Laplace +1 per category
    stat = 0.0
    novel_stat = 0.0
    for c in cats:
        expected = (expected_counts.get(c, 0) + 1) / smooth_total * obs_total
        observed = observed_counts.get(c, 0)
        contrib = (observed - expected) ** 2 / expected
        stat += contrib
        if expected_counts.get(c, 0) == 0:
            novel_stat += contrib
    return stat, len(cats) - 1, (novel_stat / stat if stat > 0 else 0.0)


def _signal_tool_distribution(baseline_fps, window_fps):
    """Chi-square shift in the tool-call distribution.

    A shift whose statistic is dominated by tool categories the
    baseline never saw is capped at weak: novel-tool adoption is
    benign evolution until corroborated by another signal.
    """
    base = Counter()
    for fp in baseline_fps:
        base.update(fp["fingerprint"]["tool_counts"])
    win = Counter()
    for fp in window_fps:
        win.update(fp["fingerprint"]["tool_counts"])
    res = _chi2_stat(dict(base), dict(win))
    if res is None:
        return None
    stat, df, novel_fraction = res
    p = chi_square_sf(stat, df)
    if p >= 0.05:
        return None
    strength = "strong" if p < 0.001 else "weak"
    capped = False
    if novel_fraction > _NOVEL_FRACTION_CAP:
        strength = "weak"
        capped = True
    return DriftSignal(
        "tool_distribution", strength,
        {"chi_square": stat, "df": df, "p_value": p,
         "novel_fraction": novel_fraction, "novel_capped": capped,
         "baseline_tools": dict(base), "window_tools": dict(win)},
        "tool-call distribution shifted vs baseline (chi2=%.1f, df=%d, "
        "p=%.4g%s)" % (stat, df, p,
                       "; novel-tool dominated, capped at weak"
                       if capped else ""))


def _rate(num, den):
    return num / den if den else 0.0


def _signal_deny_rate(baseline_fps, window_fps):
    """Abrupt change in deny rate or approval-denial rate."""
    def agg(fps):
        deny = allow = req = den = 0
        for fp in fps:
            d = fp["fingerprint"]["decisions"]
            deny += d.get("deny", 0)
            allow += d.get("allow", 0) + d.get("require_approval", 0)
            f = fp["fingerprint"]
            req += f.get("approvals_requested", 0)
            den += f.get("approvals_denied", 0)
        return deny, allow, req, den

    b_deny, b_allow, b_req, b_den = agg(baseline_fps)
    w_deny, w_allow, w_req, w_den = agg(window_fps)
    b_total = b_deny + b_allow
    w_total = w_deny + w_allow
    best = None  # (strength_rank, kind_detail, explanation)
    if b_total >= _MIN_DECISIONS_FOR_RATE and \
            w_total >= _MIN_DECISIONS_FOR_RATE:
        delta = abs(_rate(w_deny, w_total) - _rate(b_deny, b_total))
        if delta > 0.35:
            best = (2, "deny_rate", delta)
        elif delta > 0.15:
            best = (1, "deny_rate", delta)
    if b_req >= 5 and w_req >= 5:
        delta = abs(_rate(w_den, w_req) - _rate(b_den, b_req))
        rank = 2 if delta > 0.4 else (1 if delta > 0.2 else 0)
        if rank and (best is None or rank > best[0]):
            best = (rank, "approval_denial_rate", delta)
    if best is None:
        return None
    rank, sub, delta = best
    return DriftSignal(
        "deny_rate", "strong" if rank == 2 else "weak",
        {"sub_signal": sub, "abs_delta": delta,
         "baseline_deny": b_deny, "baseline_total": b_total,
         "window_deny": w_deny, "window_total": w_total},
        "%s changed abruptly vs baseline (|delta|=%.3f)" % (sub, delta))


def _signal_egress_trend(baseline_fps, window_fps):
    """Increasing egress-volume trend (Mann-Kendall, one-sided).

    Requires both statistical significance AND a material relative
    increase over the baseline mean, plus an absolute floor, so
    trivial growth (10 bytes -> 20 bytes) never fires.
    """
    vols = [fp["fingerprint"]["egress_bytes"] for fp in window_fps]
    if max(vols, default=0) < EGRESS_FLOOR_BYTES:
        return None
    z = mann_kendall_z(vols)
    p = _normal_sf(z)  # one-sided increasing
    if p >= 0.05:
        return None
    base_mean = (sum(fp["fingerprint"]["egress_bytes"]
                     for fp in baseline_fps) / len(baseline_fps)
                 if baseline_fps else 0.0)
    win_mean = sum(vols) / len(vols)
    ratio = (win_mean / base_mean) if base_mean > 0 else float("inf")
    if p < 0.005 and ratio >= 2.0:
        strength = "strong"
    elif ratio >= 1.5:
        strength = "weak"
    else:
        return None
    return DriftSignal(
        "egress_trend", strength,
        {"mann_kendall_z": z, "p_value": p,
         "window_mean_bytes": win_mean,
         "baseline_mean_bytes": base_mean,
         "ratio": ratio if ratio != float("inf") else "inf"},
        "egress volume trending up (MK z=%.2f, p=%.4g, "
        "window/baseline=%.2f)" % (z, p, ratio))


def detect_drift(store, agent_id, window=8, baseline_runs=5):
    """Compare the agent's recent window against its own baseline.

    ``window``: most recent runs to evaluate (default 8).
    ``baseline_runs``: runs immediately preceding the window that form
    the baseline (default 5). Needs at least ``baseline_runs + 2``
    runs total, else SILENT with reason "insufficient_data".

    Level combination: 2+ strong signals or 3+ total -> hold;
    1 strong or 2 total -> warn; 1 total -> watch; 0 -> silent.
    """
    if not isinstance(store, DriftStore):
        raise TypeError("store must be a DriftStore, got %r"
                        % type(store).__name__)
    runs = store.runs(agent_id)
    n = len(runs)
    if n < baseline_runs + 2:
        return DriftResult("silent", agent_id=agent_id,
                           baseline_n=0, window_n=0,
                           reason="insufficient_data")
    w = min(window, n - baseline_runs)
    window_runs = runs[n - w:]
    baseline_list = runs[n - w - baseline_runs:n - w]

    signals = []
    for fn in (_signal_tool_distribution, _signal_deny_rate,
               _signal_egress_trend):
        sig = fn(baseline_list, window_runs)
        if sig is not None:
            signals.append(sig)

    strong = sum(1 for s in signals if s.strength == "strong")
    total = len(signals)
    if strong >= 2 or total >= 3:
        level = "hold"
    elif strong >= 1 or total >= 2:
        level = "warn"
    elif total >= 1:
        level = "watch"
    else:
        level = "silent"
    return DriftResult(level, signals, agent_id=agent_id,
                       baseline_n=len(baseline_list),
                       window_n=len(window_runs),
                       reason="evaluated" if signals else "no_signal")


# --------------------------------- population-relative baseline check
# Wave-134 (row 9): the cross-run detector measures CHANGE against the
# agent's own baseline, so a from-birth malicious agent poisons its
# baseline and never drifts (pinned MISS-DOCUMENTED in
# evals/drift_probes.py p4). This section narrows that gap with a
# population-relative check: a new agent's baseline fingerprint is
# compared against the baselines of OTHER agents. An extreme outlier
# is marked provisional_untrusted (LOUD baseline_population_outlier
# event); drift verdicts against a provisional baseline are forced to
# WARN -- never SILENT (a poisoned baseline could be hiding badness),
# never HOLD (a meaningless baseline should not queue a human
# review) -- until a human confirms it or K subsequent runs converge
# toward the population.
#
# Honest ceilings (documented, not hidden):
# - Sybil: a uniformly poisoned population validates poison into
#   trust. This mechanism measures deviance from the population, not
#   badness; it says nothing when the population itself is bad.
# - Threshold game: an attacker who shapes a baseline to sit just
#   inside the population envelope defeats a percentile test by
#   construction. The percentile is a tripwire, not a proof.
# - Needs >= 3 peers (default) for a meaningful percentile; with
#   fewer, validation is skipped and the baseline stays trusted with
#   a no_population note (fail-open on absence, fail-closed on
#   corruption).
# - Tool-distribution only: the distance reuses the chi-square
#   machinery on tool counts. Egress volume, decision outcomes, and
#   argument framing are not part of the population comparison.
# - Slow convergence gaming: an attacker can converge K runs toward
#   the population and then deviate; the auto-confirm only attests
#   that the baseline once looked normal.

class PopulationCorruptedError(Exception):
    """The population file failed chain verification: fail closed."""


_POP_VERSION = 1

# Runs that must consecutively validate as population-conforming
# before a provisional baseline auto-confirms to trusted.
_AUTO_CONFIRM_RUNS = 3


def _quantile(sorted_vals, q):
    """q-th quantile of an ascending-sorted list (nearest-rank)."""
    if not sorted_vals:
        raise ValueError("_quantile of empty list")
    idx = math.ceil(q * len(sorted_vals)) - 1
    return sorted_vals[max(0, min(idx, len(sorted_vals) - 1))]


def _median(sorted_vals):
    """Median of an ascending-sorted list."""
    if not sorted_vals:
        raise ValueError("_median of empty list")
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0


def fingerprint_tool_distance(fp_a, fp_b):
    """Symmetric chi-square distance between two tool distributions.

    Mean of the chi-square statistic in both directions (each side
    serves as the expected distribution once), reusing the same
    Laplace-smoothed machinery as the drift signal. Returns None when
    either side has too few tool calls to measure
    (< _MIN_TOOL_CALLS_FOR_CHISQ); 0.0 when both fingerprints use a
    single identical tool category (no measurable shape difference).
    """
    if not isinstance(fp_a, RunFingerprint) or \
            not isinstance(fp_b, RunFingerprint):
        raise TypeError("fingerprint_tool_distance needs RunFingerprints")
    a = dict(fp_a.tool_counts)
    b = dict(fp_b.tool_counts)
    if sum(a.values()) < _MIN_TOOL_CALLS_FOR_CHISQ or \
            sum(b.values()) < _MIN_TOOL_CALLS_FOR_CHISQ:
        return None
    if len(set(a) | set(b)) < 2:
        return 0.0
    fwd = _chi2_stat(b, a)  # a observed against b expected
    rev = _chi2_stat(a, b)  # b observed against a expected
    # Both non-None here: mass checked above, >= 2 categories.
    return (fwd[0] + rev[0]) / 2.0


class BaselineValidationResult:
    """Outcome of validate_baseline_against_population.

    status in {"trusted", "provisional_untrusted",
    "unvalidated_no_population", "unvalidated_insufficient_data"}.
    """

    __slots__ = ("status", "agent_id", "threshold", "agent_distance",
                 "n_peers", "n_pairs", "detail")

    _STATUSES = ("trusted", "provisional_untrusted",
                 "unvalidated_no_population",
                 "unvalidated_insufficient_data")

    def __init__(self, status, agent_id="", threshold=None,
                 agent_distance=None, n_peers=0, n_pairs=0, detail=None):
        if status not in self._STATUSES:
            raise ValueError("unknown baseline validation status %r"
                             % (status,))
        self.status = status
        self.agent_id = str(agent_id)
        self.threshold = threshold
        self.agent_distance = agent_distance
        self.n_peers = int(n_peers)
        self.n_pairs = int(n_pairs)
        self.detail = dict(detail) if detail else {}

    def to_dict(self):
        return {"status": self.status, "agent_id": self.agent_id,
                "threshold": self.threshold,
                "agent_distance": self.agent_distance,
                "n_peers": self.n_peers, "n_pairs": self.n_pairs,
                "detail": dict(self.detail)}


def validate_baseline_against_population(agent_id, fingerprint, population,
                                         outlier_quantile=0.99,
                                         min_peers=3):
    """Compare a new baseline fingerprint against a peer population.

    ``population``: iterable of (agent_id, RunFingerprint) from OTHER
    agents (the agent itself is excluded defensively). The distance
    from the new fingerprint to the population is the median of the
    symmetric chi-square tool-distribution distances to each peer;
    the outlier threshold is the ``outlier_quantile`` quantile
    (default 99th percentile) of the pairwise peer distances. Beyond
    the threshold -> provisional_untrusted, else trusted.

    Peers with too few tool calls to measure are excluded; with
    fewer than ``min_peers`` measurable peers the check is skipped
    (unvalidated_no_population). A new fingerprint with too little
    mass is unvalidated_insufficient_data. Pure function: no I/O,
    deterministic.
    """
    if not isinstance(fingerprint, RunFingerprint):
        raise TypeError("fingerprint must be a RunFingerprint, got %r"
                        % type(fingerprint).__name__)
    if not 0.0 < outlier_quantile <= 1.0:
        raise ValueError("outlier_quantile must be in (0, 1], got %r"
                         % (outlier_quantile,))
    peers = [(str(a), fp) for (a, fp) in population
             if str(a) != str(agent_id)
             and isinstance(fp, RunFingerprint)
             and sum(fp.tool_counts.values()) >= _MIN_TOOL_CALLS_FOR_CHISQ]
    if sum(fingerprint.tool_counts.values()) < _MIN_TOOL_CALLS_FOR_CHISQ:
        return BaselineValidationResult(
            "unvalidated_insufficient_data", agent_id=agent_id,
            n_peers=len(peers),
            detail={"note": "new fingerprint has too few tool calls "
                            "to measure a distance"})
    if len(peers) < min_peers:
        return BaselineValidationResult(
            "unvalidated_no_population", agent_id=agent_id,
            n_peers=len(peers),
            detail={"note": "no_population: fewer than %d measurable "
                            "peers; cannot validate against nothing"
                            % (min_peers,)})
    pair_dists = []
    for i in range(len(peers)):
        for j in range(i + 1, len(peers)):
            d = fingerprint_tool_distance(peers[i][1], peers[j][1])
            if d is not None:
                pair_dists.append(d)
    if not pair_dists:
        return BaselineValidationResult(
            "unvalidated_insufficient_data", agent_id=agent_id,
            n_peers=len(peers),
            detail={"note": "no measurable peer pairs"})
    pair_dists.sort()
    threshold = _quantile(pair_dists, outlier_quantile)
    dists = []
    for _, fp in peers:
        d = fingerprint_tool_distance(fingerprint, fp)
        if d is not None:
            dists.append(d)
    dists.sort()
    agent_distance = _median(dists)
    status = ("provisional_untrusted" if agent_distance > threshold
              else "trusted")
    return BaselineValidationResult(
        status, agent_id=agent_id, threshold=threshold,
        agent_distance=agent_distance, n_peers=len(peers),
        n_pairs=len(pair_dists),
        detail={"outlier_quantile": outlier_quantile,
                "distance": "median symmetric chi-square of tool "
                            "distributions vs each peer",
                "threshold": "%.4g-quantile of %d pairwise peer "
                             "distances" % (outlier_quantile,
                                            len(pair_dists))})


def cap_drift_verdict(result):
    """Force a DriftResult to WARN for a provisional baseline.

    While an agent's baseline is provisional_untrusted, no verdict
    computed against it can be trusted: SILENT might be a poisoned
    baseline hiding badness, and HOLD would queue a human review
    against a possibly-meaningless baseline. Every verdict becomes
    WARN (LOUD operator attention, no review auto-queued). The
    underlying signals are preserved for the human.
    """
    if not isinstance(result, DriftResult):
        raise TypeError("cap_drift_verdict needs a DriftResult, got %r"
                        % type(result).__name__)
    return DriftResult(
        "warn", signals=result.signals, agent_id=result.agent_id,
        baseline_n=result.baseline_n, window_n=result.window_n,
        reason="provisional_baseline: " + result.reason)


class PopulationStore:
    """Durable population of agent baseline fingerprints.

    One JSONL file (``population.jsonl``) under ``store_dir``; every
    record is hash-chained (prev_digest linkage) with the same
    audit-before-mutation discipline as DriftStore. New records carry
    ``chain_keyed: true`` and a HMAC-SHA256 digest under the deployment
    key (resolved via ``gov.keyprovider``, the audit log's idiom — no
    new key story); pre-upgrade records verify under the legacy
    unkeyed scheme. Record kinds:

    - "baseline": one per agent (latest wins); carries the
      fingerprint and its trust state ("trusted" | "provisional").
    - "trust": a trust transition (human confirm or auto-converge).
    - "convergence": consecutive population-conforming run counter
      for a provisional agent.

    Fail-closed: ``verify_chain()`` False -> ``all_baselines()``,
    ``trust_of()``, ``record_baseline()``, ``confirm_baseline()`` and
    ``note_run()`` raise PopulationCorruptedError.
    """

    def __init__(self, store_dir, audit=None):
        self.store_dir = Path(store_dir)
        self._audit = audit
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._head_cache = None

    def _path(self):
        return self.store_dir / "population.jsonl"

    def _read_all(self):
        p = self._path()
        if not p.exists():
            return []
        records = []
        try:
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            # A truncated or garbage file is indistinguishable from
            # tampering: fail closed, never silently skip records.
            raise PopulationCorruptedError(
                "population file %s is unreadable (%r): treating every "
                "new baseline as untrusted" % (p, e))
        return records

    def _head(self):
        if self._head_cache is None:
            records = self._read_all()
            self._head_cache = records[-1]["digest"] if records else ""
        return self._head_cache

    def verify_chain(self):
        """True iff the chain is intact (digests + linkage).

        The digest scheme is selected per record: records carrying
        ``chain_keyed: true`` verify under the HMAC scheme (the key is
        resolved; if no key is configured a keyed record cannot verify
        and the chain fails closed), older records verify under the
        legacy unkeyed scheme. Mixed chains verify per-record.
        """
        try:
            records = self._read_all()
        except PopulationCorruptedError:
            return False
        prev = ""
        for rec in records:
            if rec.get("prev_digest") != prev:
                return False
            digest = rec.get("digest")
            if rec.get("chain_keyed"):
                try:
                    key, _epoch = _resolve_chain_key()
                except _NoKeyConfiguredError:
                    # A keyed record with no key configured cannot be
                    # verified: fail closed, never treat as intact.
                    return False
                expect = _keyed_digest(rec, key, _POP_CHAIN_DOMAIN)
            else:
                expect = _sha256_hex(_canonical(
                    {k: v for k, v in rec.items() if k != "digest"}))
            if not isinstance(digest, str) or \
                    not hmac.compare_digest(digest, expect):
                return False
            prev = digest
        return True

    def _require_intact(self):
        if not self.verify_chain():
            raise PopulationCorruptedError(
                "population file %s failed chain verification: "
                "treating every new baseline as untrusted"
                % (self._path(),))

    def _append(self, record, audit, event):
        self._require_intact()
        auditor = self._audit if audit is None else audit
        # Keyed chain: the deployment key is resolved here and
        # NoKeyConfiguredError propagates (fail-closed — an append
        # without a configured key refuses loudly, never silently
        # falls back to the unkeyed scheme).
        key, epoch = _resolve_chain_key()
        prev = self._head()
        record = dict(record)
        record["pop_version"] = _POP_VERSION
        record["recorded_at"] = _utcnow_iso()
        record["prev_digest"] = prev
        record["chain_keyed"] = True
        record["key_epoch"] = epoch
        record["digest"] = _keyed_digest(record, key, _POP_CHAIN_DOMAIN)
        if auditor is not None:
            evt = {"event": event, "prev_digest": prev,
                   "digest": record["digest"]}
            evt.update({k: v for k, v in record.items()
                        if k not in ("digest", "prev_digest",
                                     "fingerprint")})
            auditor(evt)
        with self._path().open("a", encoding="utf-8") as f:
            f.write(_canonical(record) + "\n")
        self._head_cache = record["digest"]
        return record

    def record_baseline(self, agent_id, principal, fingerprint, audit=None,
                        validation=None):
        """Record an agent's baseline fingerprint with its trust state.

        ``validation`` is an optional BaselineValidationResult; a
        provisional_untrusted verdict stores trust "provisional",
        anything else stores "trusted" (with the validation status
        noted). Audit (``baseline_recorded``) runs before the write;
        an audit failure aborts the record (fail-closed).
        """
        if not isinstance(fingerprint, RunFingerprint):
            raise TypeError("fingerprint must be a RunFingerprint, got %r"
                            % type(fingerprint).__name__)
        if validation is not None and not isinstance(
                validation, BaselineValidationResult):
            raise TypeError("validation must be a BaselineValidationResult")
        trust = ("provisional"
                 if validation is not None
                 and validation.status == "provisional_untrusted"
                 else "trusted")
        return self._append(
            {"kind": "baseline",
             "agent_id": str(agent_id),
             "principal": str(principal),
             "fingerprint": fingerprint.to_dict(),
             "baseline_trust": trust,
             "validation_status": (validation.status
                                   if validation is not None
                                   else "unvalidated"),
             "validation": (validation.to_dict()
                            if validation is not None else None)},
            audit, "baseline_recorded")

    def all_baselines(self):
        """Latest baseline per agent, trusted agents only.

        Returns [(agent_id, RunFingerprint)] for agents whose CURRENT
        trust is "trusted" (the baseline record's trust as overridden
        by any later "trust" record — human confirm / auto-converge).
        Provisional agents are EXCLUDED: a provisional (unvalidated,
        possibly poisoned) fingerprint must never vote on whether a NEW
        agent's baseline is trusted. With too few trusted peers,
        ``validate_baseline_against_population`` fails closed to
        ``unvalidated_no_population`` — never silent inclusion.

        Fail-closed: raises PopulationCorruptedError when the chain
        does not verify.
        """
        self._require_intact()
        latest = {}  # agent_id -> [RunFingerprint, effective trust]
        order = []
        for rec in self._read_all():
            aid = rec.get("agent_id")
            kind = rec.get("kind")
            if kind == "baseline":
                if aid not in latest:
                    order.append(aid)
                latest[aid] = [RunFingerprint.from_dict(
                    rec["fingerprint"]),
                    rec.get("baseline_trust", "trusted")]
            elif kind == "trust" and aid in latest:
                latest[aid][1] = rec.get("new_trust",
                                         latest[aid][1])
        return [(aid, latest[aid][0]) for aid in order
                if latest[aid][1] == "trusted"]

    def trust_of(self, agent_id):
        """(trust, detail) for an agent: latest baseline trust as
        overridden by any later trust record.

        Fail-closed: raises PopulationCorruptedError when the chain
        does not verify.
        """
        self._require_intact()
        aid = str(agent_id)
        trust = None
        detail = {"note": "no_baseline_recorded"}
        for rec in self._read_all():
            if rec.get("agent_id") != aid:
                continue
            kind = rec.get("kind")
            if kind == "baseline":
                trust = rec.get("baseline_trust", "trusted")
                detail = {"validation_status": rec.get(
                    "validation_status", "unvalidated")}
            elif kind == "trust":
                trust = rec.get("new_trust", trust)
                detail = {"reason": rec.get("reason", ""),
                          "at": rec.get("recorded_at", "")}
        if trust is None:
            return "trusted", {"note": "no_baseline_recorded"}
        return trust, detail

    def confirm_baseline(self, agent_id, reason="human_confirm", audit=None):
        """Human (or operator) confirmation: provisional -> trusted."""
        return self._append(
            {"kind": "trust",
             "agent_id": str(agent_id),
             "new_trust": "trusted",
             "reason": str(reason)},
            audit, "baseline_confirmed")

    def note_run(self, agent_id, fingerprint, peers, auto_confirm_runs=None,
                 audit=None):
        """Track one subsequent run toward auto-confirmation.

        ``peers``: [(agent_id, RunFingerprint)] excluding this agent.
        The supplied peers are DEFENSIVELY intersected with the store's
        current trusted fold: a direct caller cannot reintroduce
        provisional (unvalidated) agents as validators, even if it
        passes their fingerprints. When the run validates as
        population-conforming, the consecutive counter increments; at
        ``auto_confirm_runs`` (default 3) consecutive conforming runs a
        provisional baseline auto-confirms to trusted
        (``baseline_auto_confirmed`` audit event). A non-conforming
        run resets the counter. Already-trusted agents are a no-op.
        Returns (trust, detail).
        """
        if not isinstance(fingerprint, RunFingerprint):
            raise TypeError("fingerprint must be a RunFingerprint, got %r"
                            % type(fingerprint).__name__)
        if auto_confirm_runs is None:
            auto_confirm_runs = _AUTO_CONFIRM_RUNS
        trust, _ = self.trust_of(agent_id)
        if trust == "trusted":
            return "trusted", {"already_trusted": True}
        # Defensive: only currently-trusted agents may validate a run.
        # Caller-supplied tuples carry no trust state, so the store's
        # own trusted fold is authoritative here.
        trusted_ids = {aid for aid, _ in self.all_baselines()}
        trusted_peers = [(aid, fp) for aid, fp in peers
                         if aid in trusted_ids and aid != str(agent_id)]
        res = validate_baseline_against_population(agent_id, fingerprint,
                                                  trusted_peers)
        count = 0
        for rec in self._read_all():
            if rec.get("kind") == "convergence" and \
                    rec.get("agent_id") == str(agent_id):
                count = rec.get("consecutive_trusted", 0)
        count = count + 1 if res.status == "trusted" else 0
        self._append(
            {"kind": "convergence",
             "agent_id": str(agent_id),
             "consecutive_trusted": count,
             "validation_status": res.status},
            audit, "baseline_convergence_noted")
        if count >= auto_confirm_runs:
            self._append(
                {"kind": "trust",
                 "agent_id": str(agent_id),
                 "new_trust": "trusted",
                 "reason": "auto_converged",
                 "consecutive_runs": count},
                audit, "baseline_auto_confirmed")
            return "trusted", {"auto_converged": True,
                               "consecutive_trusted": count}
        return "provisional", {"consecutive_trusted": count,
                               "validation_status": res.status}
