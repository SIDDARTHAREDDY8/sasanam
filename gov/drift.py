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

$0, stdlib only, deterministic. All statistics are exact
deterministic computations (no sampling, no RNG). Fingerprint
validation is fail-closed: negative counts or unknown decision keys
raise ValueError rather than being silently accepted.
"""

import hashlib
import json
import math
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
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


def _canonical(obj):
    """Canonical JSON for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=repr)


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


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

_AGENT_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _sanitize_agent(agent_id):
    s = _AGENT_RE.sub("_", str(agent_id)).strip("_")[:64]
    if not s:
        raise ValueError("agent_id sanitizes to empty, got %r" % (agent_id,))
    return s


def default_store_dir():
    """Default on-disk home for drift profiles (operator override via
    constructor). Kept out of any run TMPDIR: profiles must survive
    across runs -- that is the entire point of the store."""
    return Path.home() / ".agent-governance-demo" / "drift"


class DriftStore:
    """Durable per-agent cross-run profile store.

    One JSONL file per agent under ``store_dir``. Every record is
    hash-chained (``prev_digest`` linkage, SHA-256 over the canonical
    record): ``verify_chain`` rejects tampered payloads, dropped
    records, and broken linkage. Audit runs BEFORE local mutation
    (F167 lesson): a logging failure leaves the store unchanged.
    """

    def __init__(self, store_dir, audit=None):
        self.store_dir = Path(store_dir)
        self._audit = audit
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._heads = {}  # agent_id -> last digest (cache)

    def _path(self, agent_id):
        return self.store_dir / (_sanitize_agent(agent_id) + ".jsonl")

    def _head(self, agent_id):
        if agent_id not in self._heads:
            runs = self._read_all(agent_id)
            self._heads[agent_id] = runs[-1]["digest"] if runs else ""
        return self._heads[agent_id]

    def _read_all(self, agent_id):
        p = self._path(agent_id)
        if not p.exists():
            return []
        records = []
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def record_run(self, agent_id, principal, fingerprint, audit=None):
        """Append one run's fingerprint. Returns the stored record.

        ``fingerprint`` is a RunFingerprint. The audit event
        (``drift_run_recorded``) is appended BEFORE the file write;
        an audit failure aborts the record (fail-closed). ``audit``
        overrides the construction-time audit callable for this call
        (e.g. the executor routes drift events into its run log).
        """
        if not isinstance(fingerprint, RunFingerprint):
            raise TypeError("fingerprint must be a RunFingerprint, got %r"
                            % type(fingerprint).__name__)
        auditor = self._audit if audit is None else audit
        prev = self._head(agent_id)
        record = {
            "drift_version": _DRIFT_VERSION,
            "agent_id": str(agent_id),
            "principal": str(principal),
            "recorded_at": _utcnow_iso(),
            "fingerprint": fingerprint.to_dict(),
            "prev_digest": prev,
        }
        record["digest"] = _sha256_hex(_canonical(
            {k: v for k, v in record.items() if k != "digest"}))
        if auditor is not None:
            auditor({
                "event": "drift_run_recorded",
                "agent_id": str(agent_id),
                "principal": str(principal),
                "run_id": fingerprint.run_id,
                "run_seq": fingerprint.run_seq,
                "digest": record["digest"],
                "prev_digest": prev,
            })
        with self._path(agent_id).open("a", encoding="utf-8") as f:
            f.write(_canonical(record) + "\n")
        self._heads[agent_id] = record["digest"]
        return record

    def runs(self, agent_id):
        """All stored run records for the agent, oldest first."""
        return self._read_all(agent_id)

    def verify_chain(self, agent_id):
        """True iff the agent's chain is intact (digests + linkage)."""
        prev = ""
        for rec in self._read_all(agent_id):
            if rec.get("prev_digest") != prev:
                return False
            digest = rec.get("digest")
            if digest != _sha256_hex(_canonical(
                    {k: v for k, v in rec.items() if k != "digest"})):
                return False
            prev = digest
        return True


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


def _signal_tool_distribution(baseline_fps, window_fps):
    """Chi-square shift in the tool-call distribution.

    Laplace (+1) smoothing avoids zero expected counts. A shift whose
    statistic is dominated by tool categories the baseline never saw
    is capped at weak: novel-tool adoption is benign evolution until
    corroborated by another signal.
    """
    base = Counter()
    for fp in baseline_fps:
        base.update(fp["fingerprint"]["tool_counts"])
    win = Counter()
    for fp in window_fps:
        win.update(fp["fingerprint"]["tool_counts"])
    base_total = sum(base.values())
    win_total = sum(win.values())
    if base_total < _MIN_TOOL_CALLS_FOR_CHISQ or \
            win_total < _MIN_TOOL_CALLS_FOR_CHISQ:
        return None
    cats = sorted(set(base) | set(win))
    if len(cats) < 2:
        return None
    smooth_base_total = base_total + len(cats)  # Laplace +1 per category
    stat = 0.0
    novel_stat = 0.0
    for c in cats:
        expected = (base.get(c, 0) + 1) / smooth_base_total * win_total
        observed = win.get(c, 0)
        contrib = (observed - expected) ** 2 / expected
        stat += contrib
        if base.get(c, 0) == 0:
            novel_stat += contrib
    p = chi_square_sf(stat, len(cats) - 1)
    if p >= 0.05:
        return None
    strength = "strong" if p < 0.001 else "weak"
    novel_fraction = novel_stat / stat if stat > 0 else 0.0
    capped = False
    if novel_fraction > _NOVEL_FRACTION_CAP:
        strength = "weak"
        capped = True
    return DriftSignal(
        "tool_distribution", strength,
        {"chi_square": stat, "df": len(cats) - 1, "p_value": p,
         "novel_fraction": novel_fraction, "novel_capped": capped,
         "baseline_tools": dict(base), "window_tools": dict(win)},
        "tool-call distribution shifted vs baseline (chi2=%.1f, df=%d, "
        "p=%.4g%s)" % (stat, len(cats) - 1, p,
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
