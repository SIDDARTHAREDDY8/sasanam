"""Wave-76 (Part 5: detection) -- behavioral circuit breakers over the audit stream.

THE HONEST FRAMING (also stated in
``workstreams/architect/DETECTION_DESIGN.md`` §0): detection is NOT a
wall. The math is commoditized -- EWMA for spikes + CUSUM for gradual
drift (the standard pair: authensor's Sentinel, the ACR framework's
z > 2.5 / EWMA alpha=0.3, Montgomery's CUSUM k=0.5σ / h=5σ). The build
here is (a) wiring drift trips into enforcement (breaker opens →
high-risk actions route to the human approval queue, fail-closed) and
(b) batterying the monitor against deception. Slow-boil limits are
stated, not hidden: CUSUM catches gradual drift *eventually*, but a
patient adversary under the threshold never trips -- the export shows
the operative baseline windows and thresholds so an auditor sees what
drift WOULDN'T trip. If the monitor can't survive its own battery, it's
theater -- see ``evals/w76_probes.py`` for the battery results.

Trust boundary: the monitor is READ-ONLY over the chained audit
stream. It never executes tools, never approves queue items, never
writes queue records (the queue requires an executor-minted
``caller_identity`` -- an agent-unreachable authority -- so the monitor
has no queue seam by construction). Trip records are emitted as
chained ``detector_trip`` provenance records appended through the
operator's append path. The baseline store lives in the operator's run
directory, never in agent-writable space. The monitor must never run
inside the agent's trust domain.
"""

import json
import math
import os
from collections import deque
from datetime import datetime, timedelta, timezone

__all__ = [
    "EWMA_ALPHA",
    "SPIKE_Z",
    "CUSUM_K",
    "CUSUM_H",
    "BUCKET_SECONDS",
    "WINDOW_BUCKETS",
    "MIN_TRAINING_BUCKETS",
    "SIGMA_FLOOR",
    "WINSOR_SIGMAS",
    "HALF_OPEN_QUIET_BUCKETS",
    "SIGNAL_NAMES",
    "SIGNAL_CONFIGS",
    "PURPOSE_GROUP_DEFAULTS",
    "HIGH_RISK_TOOLS",
    "EGRESS_SIGNAL_TOOLS",
    "PRIV_ESC_FLAGS",
    "identity_key_of",
    "extract_signals",
    "StreamingStats",
    "Ewma",
    "Cusum",
    "SignalState",
    "CircuitBreaker",
    "BehavioralMonitor",
    "build_detector_trip",
    "TRIP_KINDS",
]

# ---------------------------------------------------------------------------
# Parameters (commoditized -- cited as prior art, not invention).
# Rendered verbatim into the demo export (demo/make_report.py) so an
# auditor sees the operative thresholds, not hand-copied claims.
# ---------------------------------------------------------------------------

#: EWMA smoothing factor (ACR framework documents alpha=0.3).
EWMA_ALPHA = 0.3
#: Spike rule: one-sided z > 2.5 on the harmful direction (ACR's
#: documented threshold).
SPIKE_Z = 2.5
#: CUSUM reference value, in baseline sigmas (Montgomery's textbook pair).
CUSUM_K = 0.5
#: CUSUM decision interval, in baseline sigmas.
CUSUM_H = 5.0
#: Bucket width in seconds (ACR's 5-minute window).
BUCKET_SECONDS = 300
#: Retention: rolling baseline window in buckets (288 x 5 min = 24 h).
WINDOW_BUCKETS = 288
#: Cold start: identities with fewer than this many observed buckets use
#: the purpose-group default and are NOT trained on (no train-on-attacker
#: path during the default window).
MIN_TRAINING_BUCKETS = 12
#: Sigma floor: baseline sigmas below this are treated as this, so a
#: perfectly-quiet baseline cannot make a single event an infinite
#: z-score (desensitization in the other direction).
SIGMA_FLOOR = 0.5
#: Winsorization bound for baseline updates (monitor-blinding
#: resistance): observations outside mean +/- 5 sigma are clipped
#: before training. Flooding the log moves the baseline at most
#: this far per bucket.
WINSOR_SIGMAS = 5.0
#: Half-open: consecutive clean buckets required to close the breaker
#: after a human reset. CUSUM state is carried through (never zeroed).
HALF_OPEN_QUIET_BUCKETS = 6
#: Half-open: at most this many high-risk actions are admitted as
#: measured probes while half-open; beyond that they queue.
HALF_OPEN_PROBE_QUOTA = 3

TRIP_KINDS = ("ewma_spike", "cusum_drift", "boolean_tripwire")

# ---------------------------------------------------------------------------
# Signal set (the founder directive's original P3 shape).
# ---------------------------------------------------------------------------

SIGNAL_NAMES = (
    "tool_call_rate",
    "priv_escalation_attempts",
    "egress_attempts",
    "denial_rate",
    "approval_denials",
    "anchor_downgrades",
)

#: Per-signal config: the harmful direction. Every signal here is
#: up-only: direction-of-badness filtering (staffops) is applied before
#: alerting -- a symmetric z-score would fire on improvement too.
SIGNAL_CONFIGS = {
    "tool_call_rate": {
        "direction": "up",
        "desc": "decision records per bucket (all tools)",
    },
    "priv_escalation_attempts": {
        "direction": "up",
        "desc": ("decision/denial records carrying escalation markers "
                 "(delegation_refused, unscoped delegation, break-glass)"),
    },
    "egress_attempts": {
        "direction": "up",
        "desc": "calls to egress tools (send_email/http_post/api_call)",
    },
    "denial_rate": {
        "direction": "up",
        "desc": "decision records with denied outcomes per bucket",
    },
    "approval_denials": {
        "direction": "up",
        "desc": ("approval-queue decision records with denied outcomes "
                 "-- the unseen tripwire: the agent shapes requests but "
                 "cannot control human approver decisions"),
    },
    "anchor_downgrades": {
        "direction": "event",
        "desc": ("boolean tripwire: anchor audit epoch where the chain "
                 "verifies in-chain but head_match=False "
                 "(operator-attested-only downgrade)"),
    },
}

# ---------------------------------------------------------------------------
# Purpose-group defaults for cold start (stated as approximate).
# The profile is the QUIET end of the role's observed range --
# conservative by design: a new identity misbehaving in the default
# window trips fast and lands in the approval queue. Defaults are
# applied, never trained on, until MIN_TRAINING_BUCKETS samples exist.
# ---------------------------------------------------------------------------

#: role -> signal -> (mean, sigma) per 5-minute bucket. Approximate;
#: the export marks cold-start thresholds as basis=purpose-group-default.
PURPOSE_GROUP_DEFAULTS = {
    "scout": {
        "tool_call_rate": (4.0, 2.0),
        "priv_escalation_attempts": (0.0, 0.5),
        "egress_attempts": (0.2, 0.5),
        "denial_rate": (0.3, 0.6),
        "approval_denials": (0.1, 0.5),
    },
    "coder": {
        "tool_call_rate": (10.0, 4.0),
        "priv_escalation_attempts": (0.0, 0.5),
        "egress_attempts": (0.3, 0.6),
        "denial_rate": (0.5, 0.8),
        "approval_denials": (0.2, 0.6),
    },
    "reviewer": {
        "tool_call_rate": (6.0, 3.0),
        "priv_escalation_attempts": (0.0, 0.5),
        "egress_attempts": (0.5, 0.7),
        "denial_rate": (1.0, 1.0),
        "approval_denials": (0.5, 0.8),
    },
    "operator": {
        "tool_call_rate": (3.0, 2.0),
        "priv_escalation_attempts": (0.1, 0.5),
        "egress_attempts": (0.4, 0.7),
        "denial_rate": (0.2, 0.5),
        "approval_denials": (0.3, 0.7),
    },
}
#: Roles not listed here inherit this generic quiet profile.
_DEFAULT_GROUP = {
    "tool_call_rate": (5.0, 3.0),
    "priv_escalation_attempts": (0.0, 0.5),
    "egress_attempts": (0.3, 0.6),
    "denial_rate": (0.3, 0.6),
    "approval_denials": (0.2, 0.6),
}

# ---------------------------------------------------------------------------
# High-risk tools for breaker routing. Mirrors gov.executor's mutating +
# egress tool sets as data (gov.detection never imports gov.executor --
# the executor consults the monitor, not vice versa).
# ---------------------------------------------------------------------------

#: Tools whose allowed verdicts route to the approval queue while the
#: breaker's OPEN (or count against the half-open probe quota).
HIGH_RISK_TOOLS = frozenset({
    "write_file", "delete_file", "send_email", "http_post", "api_call",
    "execute_shell", "install_package", "window_close",
})

#: Tools counted by the egress_attempts signal (gov.executor._EGRESS_TOOLS).
EGRESS_SIGNAL_TOOLS = frozenset({"send_email", "http_post", "api_call"})

#: Decision flags/events that count as privilege-escalation attempts.
#: A heuristic aggregator over already-governed denial shapes --
#: documented as approximate, never as a privilege oracle.
PRIV_ESC_FLAGS = frozenset({
    "delegation_refused",
    "delegation_gate_refused",
    "unscoped_delegation_denied",
    "role_allowlist_violation",
})
PRIV_ESC_EVENTS = frozenset({
    "delegation_invocation_refused",
    "approval_break_glass",
})


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Identity keys (Wave-74 refs).
# ---------------------------------------------------------------------------

def identity_key_of(entry_or_identity):
    """Canonical per-identity key for baselines.

    Prefers the Wave-74 three-token refs (the provenance v2 ``tokens``
    slots, or the executor-stamped ``identity_token_refs`` on call
    entries): ``u:<user_ref>/a:<agent_ref>/d:<delegation_ref>``. Falls
    back to ``u:<principal>/a:<agent_id>/d:<run>`` for AgentIdentity
    objects and v1 log entries. One key = one human, one agent
    instance, one delegation.
    """
    obj = entry_or_identity
    # AgentIdentity (executor call path).
    if type(obj).__name__ == "AgentIdentity":
        return "u:%s/a:%s/d:%s" % (
            getattr(obj, "principal", "?"), getattr(obj, "agent_id", "?"),
            getattr(obj, "run_id", "?"))
    if isinstance(obj, dict):
        # Executor-stamped refs on tool_call entries (wave-74 refs on
        # the live call path).
        refs = obj.get("identity_token_refs")
        if isinstance(refs, dict):
            return "u:%s/a:%s/d:%s" % (
                refs.get("user_token_ref", "?"),
                refs.get("agent_token_ref", "?"),
                refs.get("delegation_token_ref", "?"))
        # Provenance delegation v2: leaf hop's tokens slot.
        prov = obj.get("prov")
        if isinstance(prov, dict):
            deleg = prov.get("delegation") or {}
            hops = deleg.get("hops") or []
            if hops:
                tokens = hops[-1].get("tokens")
                if isinstance(tokens, dict):
                    return "u:%s/a:%s/d:%s" % (
                        tokens.get("user_token_ref", "?"),
                        tokens.get("agent_token_ref", "?"),
                        tokens.get("delegation_token_ref", "?"))
        # v1 log entries: agent-side fields.
        agent_id = obj.get("agent_id") or "?"
        principal = obj.get("principal") or "?"
        run_id = obj.get("run_id") or "?"
        return "u:%s/a:%s/d:%s" % (principal, agent_id, run_id)
    raise TypeError("identity_key_of: expected AgentIdentity or entry dict, "
                    "got %r" % type(obj).__name__)


def role_of(entry_or_identity):
    """Best-effort role for purpose-group defaults (approximate)."""
    obj = entry_or_identity
    if type(obj).__name__ == "AgentIdentity":
        return getattr(obj, "role", None) or "unknown"
    if isinstance(obj, dict):
        return obj.get("role") or "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# Signal extraction from audit-stream entries.
# ---------------------------------------------------------------------------

def extract_signals(entry):
    """Extract per-bucket signal contributions from one log entry.

    Returns ``{signal: count}`` (only nonzero signals). Reads the
    chained audit entry shapes this tree emits: ``tool_call`` decision
    entries, ``approval_decision`` entries, and ``detector_trip``
    records (ignored -- the monitor never trains on its own trips).
    Unknown entry shapes contribute nothing (fail-open on extraction,
    fail-closed on alerting: the monitor trips only on signals it
    positively observed).
    """
    if not isinstance(entry, dict):
        return {}
    if (entry.get("prov") or {}).get("record_type") == "detector_trip":
        return {}  # never train on our own trips
    out = {}
    event = entry.get("event")
    if event == "tool_call":
        out["tool_call_rate"] = 1
        tool = entry.get("tool")
        if tool in EGRESS_SIGNAL_TOOLS:
            out["egress_attempts"] = 1
        elif entry.get("egress_bytes"):
            out["egress_attempts"] = 1
        if entry.get("decision") == "denied":
            out["denial_rate"] = 1
        flag = entry.get("flag") or ""
        if flag in PRIV_ESC_FLAGS or event in PRIV_ESC_EVENTS:
            out["priv_escalation_attempts"] = 1
    elif event == "approval_decision":
        if entry.get("approved") is False:
            out["approval_denials"] = 1
    elif event in PRIV_ESC_EVENTS:
        out["priv_escalation_attempts"] = 1
    elif event == "window_close_queued":
        out["priv_escalation_attempts"] = 0  # not an escalation; explicit
    return {k: v for k, v in out.items() if v}


# ---------------------------------------------------------------------------
# Streaming statistics: Welford mean/variance, EWMA, one-sided CUSUM.
# ---------------------------------------------------------------------------

class StreamingStats:
    """Welford streaming mean/variance over a BOUNDED rolling window.

    Retention semantics (enforced, not metadata): the last
    ``WINDOW_BUCKETS`` trained bucket values are kept in a deque; the
    Welford state folds new values incrementally and is recomputed
    exactly from the deque whenever an old value evicts (removing an
    observation from Welford state in place is numerically unstable,
    so the recompute path is exact). A virtual prior (pseudo-count
    seeding from the purpose-group default) anchors the fresh
    baseline; it is reapplied on every recompute and survives
    eviction by design -- the conservative default never washes out
    of a quiet identity entirely.
    """

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.values = deque(maxlen=WINDOW_BUCKETS)
        # Virtual prior (pseudo-counts); (0, 0.0, 0.0) = no prior.
        self.prior_n = 0
        self.prior_mean = 0.0
        self.prior_m2 = 0.0

    def seed_prior(self, n, mean, sigma):
        """Anchor the baseline on the purpose-group default."""
        sigma = max(sigma, SIGMA_FLOOR)
        self.prior_n = int(n)
        self.prior_mean = float(mean)
        self.prior_m2 = sigma * sigma * max(int(n) - 1, 0)
        self._recompute()

    def _fold(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    def _recompute(self):
        """Exact rebuild from the virtual prior + retained window."""
        self.n = self.prior_n
        self.mean = self.prior_mean
        self.m2 = self.prior_m2
        for v in self.values:
            self._fold(v)

    def update(self, x):
        # Winsorized by the caller (SignalState) before this runs.
        evicted = len(self.values) == self.values.maxlen
        self.values.append(float(x))
        if evicted:
            # An old value left the window: exact recompute (Welford
            # has no stable in-place removal).
            self._recompute()
        else:
            self._fold(x)

    def clear_window(self):
        """Drop retained observations, keep the virtual prior."""
        self.values.clear()
        self._recompute()

    @property
    def retained(self):
        return len(self.values)

    def variance(self):
        if self.n < 2:
            return SIGMA_FLOOR ** 2
        return max(self.m2 / (self.n - 1), SIGMA_FLOOR ** 2)

    def sigma(self):
        return math.sqrt(self.variance())

    def to_dict(self):
        return {"n": self.n, "mean": self.mean, "m2": self.m2,
                "values": list(self.values),
                "prior_n": self.prior_n, "prior_mean": self.prior_mean,
                "prior_m2": self.prior_m2}

    @classmethod
    def from_dict(cls, d):
        st = cls()
        st.prior_n = int(d.get("prior_n", 0) or 0)
        st.prior_mean = float(d.get("prior_mean", 0.0) or 0.0)
        st.prior_m2 = float(d.get("prior_m2", 0.0) or 0.0)
        if "values" in d:
            vals = [float(v) for v in (d.get("values") or [])]
            st.values = deque(vals[-WINDOW_BUCKETS:],
                              maxlen=WINDOW_BUCKETS)
            st._recompute()
        else:
            # Pre-window persistence format: restore the raw moments
            # (no retained values; the window refills from here).
            st.n = int(d.get("n", 0) or 0)
            st.mean = float(d.get("mean", 0.0) or 0.0)
            st.m2 = float(d.get("m2", 0.0) or 0.0)
        return st


class Ewma:
    """Exponentially weighted moving average (alpha=0.3 prior art)."""

    def __init__(self, alpha=EWMA_ALPHA):
        self.alpha = alpha
        self.z = None

    def update(self, x):
        if self.z is None:
            self.z = float(x)
        else:
            self.z = self.alpha * float(x) + (1.0 - self.alpha) * self.z
        return self.z


class Cusum:
    """One-sided upper CUSUM: sh = max(0, sh + x - mean - k*sigma).

    Trips when sh > h*sigma. Standardized by the BASELINE sigma (not a
    running one) so drift cannot inflate its own denominator.
    """

    def __init__(self, k=CUSUM_K, h=CUSUM_H):
        self.k = k
        self.h = h
        self.sh = 0.0

    def update(self, x, mean, sigma):
        sigma = max(sigma, SIGMA_FLOOR)
        self.sh = max(0.0, self.sh + (x - mean - self.k * sigma))
        return self.sh

    def tripped(self, sigma):
        return self.sh > self.h * max(sigma, SIGMA_FLOOR)


class SignalState:
    """Per-identity, per-signal detector state."""

    def __init__(self, role):
        self.role = role
        self.stats = StreamingStats()
        self.ewma = Ewma()
        self.cusum = Cusum()
        self.buckets_seen = 0  # buckets evaluated (cold-start gate)

    def reference(self):
        """(mean, sigma, basis): group default until trained."""
        if self.buckets_seen < MIN_TRAINING_BUCKETS:
            grp = PURPOSE_GROUP_DEFAULTS.get(self.role) or _DEFAULT_GROUP
            mean, sigma = grp.get(self._signal, (0.0, SIGMA_FLOOR))
            return mean, max(sigma, SIGMA_FLOOR), \
                "purpose-group-default (approximate)"
        return self.stats.mean, self.stats.sigma(), "per-identity"

    def evaluate(self, x):
        """Evaluate one bucket value WITHOUT training. Returns trips.

        Evaluation and training are split (see :meth:`train_after`) so
        the monitor can freeze baseline updates while CUSUM suspicion
        is active: an adaptive baseline that trains on drift absorbs
        the drift and the CUSUM never fires -- the desensitization
        shape. Training resumes only when suspicion clears (sh == 0).
        """
        mean, sigma, basis = self.reference()
        sigma = max(sigma, SIGMA_FLOOR)
        trips = []
        # EWMA spike (harmful direction only: up). The test is on the
        # smoothed statistic, with its own control limit
        # sigma_ewma = sigma * sqrt(alpha/(2-alpha)) -- the ACR pair.
        z_now = self.ewma.update(x)
        sigma_ewma = sigma * math.sqrt(
            self.ewma.alpha / (2.0 - self.ewma.alpha))
        if (z_now - mean) / sigma_ewma > SPIKE_Z and z_now > mean:
            trips.append({
                "trip_kind": "ewma_spike",
                "observed": x,
                "threshold": mean + SPIKE_Z * sigma_ewma,
                "baseline_mean": mean,
                "baseline_sigma": sigma,
                "basis": basis,
            })
        # CUSUM drift.
        self.cusum.update(x, mean, sigma)
        if self.cusum.tripped(sigma):
            trips.append({
                "trip_kind": "cusum_drift",
                "observed": x,
                "threshold": CUSUM_H * sigma,
                "baseline_mean": mean,
                "baseline_sigma": sigma,
                "basis": basis,
            })
        self.buckets_seen += 1
        if self.buckets_seen == MIN_TRAINING_BUCKETS:
            self._seed_from_default()
        return trips

    def _seed_from_default(self):
        """Seed the streaming baseline from the group default.

        Pseudo-count seeding (not raw observations): the first
        MIN_TRAINING_BUCKETS buckets are evaluated but never trained
        on, so attacker-shaped cold-start traffic cannot become the
        baseline by construction.
        """
        grp = PURPOSE_GROUP_DEFAULTS.get(self.role) or _DEFAULT_GROUP
        mean, sigma = grp.get(self._signal, (0.0, SIGMA_FLOOR))
        sigma = max(sigma, SIGMA_FLOOR)
        self.stats.seed_prior(MIN_TRAINING_BUCKETS, mean, sigma)

    def train_after(self, x, frozen=False):
        """Winsorized baseline update, called after evaluation.

        Skipped when ``frozen`` (breaker not CLOSED), while CUSUM
        suspicion is active (``cusum.sh > 0`` -- training on drift
        would absorb it), and during cold start. Benign blips whose
        suspicion decays back to 0 resume training; only a named human
        re-baseline (``BehavioralMonitor.rebaseline``) adopts a
        sustained new level.
        """
        if frozen or self.cusum.sh > 0:
            return
        if self.buckets_seen <= MIN_TRAINING_BUCKETS:
            # Cold start: evaluated against defaults, never trained on.
            return
        mean, sigma, _ = self.reference()
        lo = mean - WINSOR_SIGMAS * sigma
        hi = mean + WINSOR_SIGMAS * sigma
        self.stats.update(min(max(x, lo), hi))


# SignalState.reference needs the signal name; set post-construction
# (kept out of __init__ so the state stays JSON-serializable).
def _bind_signal(state, signal):
    state._signal = signal
    return state


# ---------------------------------------------------------------------------
# The circuit breaker (Nygard: closed / open / half-open, human reset).
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Per-identity breaker. Human reset only; half-open probing."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self):
        self.state = self.CLOSED
        self.consecutive_opens = 0
        self.half_open_buckets = 0
        self.half_open_probes = 0
        self.last_trip = None

    def trip(self, trip_detail):
        was = self.state
        self.state = self.OPEN
        self.consecutive_opens += 1 if was != self.OPEN else 0
        self.last_trip = trip_detail
        self.half_open_buckets = 0
        self.half_open_probes = 0
        return was  # caller emits the trip record only on CLOSED->OPEN

    def reset(self, reset_by):
        """Human reset: OPEN -> HALF_OPEN. The monitor reseeds EWMA to
        the baseline mean and carries CUSUM forward only for drift
        trips (see BehavioralMonitor.reset)."""
        if self.state != self.OPEN:
            return False
        self.state = self.HALF_OPEN
        self.half_open_buckets = 0
        self.half_open_probes = 0
        self.last_trip = dict(self.last_trip or {}, reset_by=reset_by)
        return True

    def half_open_tick(self, tripped_now):
        """Advance the half-open probe window. Returns new state."""
        if self.state != self.HALF_OPEN:
            return self.state
        if tripped_now:
            self.state = self.OPEN
            self.consecutive_opens += 1
            self.half_open_buckets = 0
            self.half_open_probes = 0
            return self.state
        self.half_open_buckets += 1
        if self.half_open_buckets >= HALF_OPEN_QUIET_BUCKETS:
            self.state = self.CLOSED
            self.consecutive_opens = 0
        return self.state


# ---------------------------------------------------------------------------
# The monitor.
# ---------------------------------------------------------------------------

class BehavioralMonitor:
    """Runtime behavioral monitor over the audit stream.

    Read-only: ``ingest_*`` updates baselines and breaker state;
    ``build_detector_trip`` returns the chained record for the caller
    to append via ``provenance.append_provenance`` (the monitor never
    writes the log itself). ``route_action`` is the enforcement seam
    the executor consults on its verdict path.
    """

    def __init__(self, run_dir=None):
        self.run_dir = run_dir
        # identity_key -> {signal: SignalState}
        self._signals = {}
        # identity_key -> CircuitBreaker
        self._breakers = {}
        # identity_key -> role (first-seen role sticks; role changes are
        # themselves suspicious and handled by the identity layer)
        self._roles = {}
        # Monitor-level anchor latch: an anchor downgrade means the
        # log's external anchor no longer matches -- every baseline is
        # suspect until an operator clears it.
        self._anchor_alarm = None
        # Trip records emitted (dedupe: one per breaker-open transition).
        self._trips_emitted = []

    # -- identity / state plumbing --------------------------------------

    def _state(self, identity_key, role, signal):
        per = self._signals.setdefault(identity_key, {})
        if identity_key not in self._roles:
            self._roles[identity_key] = role
        st = per.get(signal)
        if st is None:
            st = _bind_signal(SignalState(self._roles[identity_key]),
                              signal)
            per[signal] = st
        return st

    def _breaker(self, identity_key):
        return self._breakers.setdefault(identity_key, CircuitBreaker())

    def breaker_state(self, identity_key):
        if self._anchor_alarm is not None:
            return CircuitBreaker.OPEN
        return self._breakers.get(identity_key,
                                  CircuitBreaker()).state

    # -- observation ----------------------------------------------------

    def observe_bucket(self, entry_or_identity, counts):
        """Evaluate one closed bucket of signal counts for an identity.

        ``counts``: {signal: value} for one BUCKET_SECONDS window.
        Returns the list of trip dicts (each names signal, trip_kind,
        observed, threshold, baseline window, basis). Trips the
        breaker on the first trip (emitting at most one trip record
        per open transition -- the denial-storm bound).
        """
        identity_key = identity_key_of(entry_or_identity)
        role = role_of(entry_or_identity)
        breaker = self._breaker(identity_key)
        evaluated = []
        trips = []
        for signal, value in counts.items():
            if signal not in SIGNAL_NAMES or signal == "anchor_downgrades":
                continue
            st = self._state(identity_key, role, signal)
            for t in st.evaluate(value) or []:
                t = dict(t, identity_key=identity_key, signal=signal,
                         buckets_seen=st.buckets_seen,
                         window_buckets=min(st.buckets_seen,
                                            WINDOW_BUCKETS))
                trips.append(t)
            evaluated.append((st, value))
        if trips:
            first = trips[0]
            was = breaker.trip(first)
            if was != CircuitBreaker.OPEN:
                # One trip record per open transition (denial-storm
                # bound); half-open re-trips re-open silently on the
                # record side but the breaker state still moves.
                self._trips_emitted.append(first)
            frozen = True
        else:
            # Advance half-open probing on clean buckets.
            breaker.half_open_tick(False)
            frozen = breaker.state != CircuitBreaker.CLOSED
        # Train AFTER evaluation: never on drift. Training is skipped
        # while the breaker is not CLOSED and while any signal carries
        # CUSUM suspicion (sh > 0) -- an adaptive baseline must not
        # absorb the drift it is meant to catch.
        for st, value in evaluated:
            st.train_after(value, frozen=frozen)
        return trips

    def ingest_record(self, entry):
        """Accumulate one audit-stream entry into the current bucket.

        Bucketing is by entry ``ts`` (ISO-8601); a record arriving in a
        new bucket closes the previous bucket and evaluates it. Call
        ``flush()`` at the end of a stream to close the final bucket.
        """
        key = identity_key_of(entry)
        ts = entry.get("ts")
        try:
            when = datetime.fromisoformat(ts) if ts else None
        except ValueError:
            when = None
        bucket = (int(when.timestamp() // BUCKET_SECONDS)
                  if when is not None else 0)
        if not hasattr(self, "_pending"):
            self._pending = {}
        pend = self._pending.setdefault(
            key, {"bucket": bucket, "counts": {}, "role_src": entry})
        if bucket != pend["bucket"]:
            self.observe_bucket(pend["role_src"], pend["counts"])
            pend["bucket"] = bucket
            pend["counts"] = {}
            pend["role_src"] = entry
        for sig, val in extract_signals(entry).items():
            pend["counts"][sig] = pend["counts"].get(sig, 0) + val
        return []

    def flush(self):
        """Close all pending buckets (end of stream)."""
        for key, pend in getattr(self, "_pending", {}).items():
            if pend["counts"]:
                self.observe_bucket(pend["role_src"], pend["counts"])
        self._pending = {}

    # -- anchor-downgrade tripwire (the unseen tripwire) ------------------

    def ingest_anchor_audit(self, epoch_results):
        """Ingest Wave-72 ``audit_anchors`` grading output.

        Any epoch where the chain verifies in-chain but
        ``head_match`` is False (operator-attested-only downgrade) is a
        boolean tripwire: a key-holder's backdate/reforge attempt shows
        up here, and the agent cannot predict when the operator audits
        anchors. Raises the monitor-level anchor latch: every breaker's
        ``breaker_state`` reads OPEN until an operator clears it.
        Returns the trip dict, or None.
        """
        for ep in epoch_results or []:
            checks = (ep.get("checks") or {})
            chain_ok = checks.get("chain_ok", True)
            head_match = checks.get("head_match")
            if chain_ok and head_match is False:
                trip = {
                    "trip_kind": "boolean_tripwire",
                    "identity_key": "*",
                    "signal": "anchor_downgrades",
                    "observed": "head_match=False on epoch %s"
                                % ep.get("epoch_id", "?"),
                    "threshold": "head_match=True required",
                    "baseline_mean": None,
                    "baseline_sigma": None,
                    "basis": "n/a (boolean tripwire)",
                    "buckets_seen": 0,
                    "window_buckets": 0,
                }
                if self._anchor_alarm is None:
                    self._anchor_alarm = trip
                    self._trips_emitted.append(trip)
                    return trip
                return None
        return None

    def clear_anchor_alarm(self, reset_by):
        """Operator clears the anchor latch (chained, named resetter)."""
        if self._anchor_alarm is None:
            return False
        self._anchor_alarm = dict(self._anchor_alarm,
                                  cleared_by=reset_by)
        self._trips_emitted.append(dict(self._anchor_alarm,
                                        cleared=True))
        self._anchor_alarm = None
        return True

    # -- enforcement seam ------------------------------------------------

    def route_action(self, entry_or_identity, tool):
        """Verdict-path routing for the executor.

        Returns "execute" | "queue" | "half_open_probe". Fail-closed is
        the CALLER's job: the executor treats a monitor exception as
        "queue".
        """
        identity_key = identity_key_of(entry_or_identity)
        state = self.breaker_state(identity_key)
        if state == CircuitBreaker.CLOSED:
            return "execute"
        if state == CircuitBreaker.HALF_OPEN:
            br = self._breaker(identity_key)
            if tool in HIGH_RISK_TOOLS:
                if br.half_open_probes < HALF_OPEN_PROBE_QUOTA:
                    br.half_open_probes += 1
                    return "half_open_probe"
                return "queue"
            return "execute"
        # OPEN: high-risk actions queue for a human; low-risk actions
        # still execute but stay observed (the probing channel that
        # lets half-open ever close).
        return "queue" if tool in HIGH_RISK_TOOLS else "execute"

    def reset(self, entry_or_identity, reset_by):
        """Human reset: OPEN -> HALF_OPEN (named, auditable resetter).

        Returns the operator-action payload the operator MUST chain
        (naming the resetter); None if the breaker was not OPEN.
        The EWMA level tracker is reseeded to the baseline mean (the
        human judged the spike over). CUSUM suspicion is carried
        forward only when the opening trip was a drift trip (a reset
        must not restart the drift clock); a spike trip's incidental
        accumulation is zeroed. If the new level is legitimate, the
        operator uses :meth:`rebaseline` (also chained, also named).
        """
        identity_key = identity_key_of(entry_or_identity)
        br = self._breaker(identity_key)
        last_kind = (br.last_trip or {}).get("trip_kind")
        if not br.reset(reset_by):
            return None
        # The human judged the spike over: reseed the EWMA level
        # tracker to the baseline mean so the decaying memory of the
        # old spike cannot phantom re-trip the half-open window. A
        # CONTINUING spike re-trips on fresh evidence (the next bucket
        # still exceeds the limit).
        # CUSUM suspicion is carried forward ONLY when the opening trip
        # was a drift trip: that is the anti-laundering property (a
        # reset must not restart the drift clock). A spike trip's
        # incidental CUSUM accumulation is zeroed -- the spike is over
        # by human judgment, and a huge stale sh would otherwise make
        # half-open unclosable (phantom re-trips for dozens of
        # buckets). A new drift still re-trips within the measured lag.
        for st in self._signals.get(identity_key, {}).values():
            mean, _, _ = st.reference()
            st.ewma.z = mean
            if last_kind != "cusum_drift":
                st.cusum.sh = 0.0
        return {
            "action": "breaker_reset",
            "identity_key": identity_key,
            "reset_by": reset_by,
            "at": _utcnow(),
            "new_state": CircuitBreaker.HALF_OPEN,
            "prior_trip_kind": last_kind,
            "cusum_carried": last_kind == "cusum_drift",
            "note": ("EWMA reseeded to baseline mean; CUSUM carried "
                     "forward only for drift trips; re-baseline is a "
                     "separate named operator action"),
        }

    def rebaseline(self, entry_or_identity, reset_by, signal=None):
        """Human re-baseline: adopt the current level as the new normal.

        For benign level shifts (the new traffic level is legitimate):
        sets each signal's baseline mean to its current EWMA level,
        keeps sigma, zeroes CUSUM suspicion. Returns the payload the
        operator MUST chain. THIS is the one operator action that can
        launder drift into the baseline -- which is why it requires a
        named human and is chained: the audit shows who moved the
        goalposts, from what to what, and when.
        """
        identity_key = identity_key_of(entry_or_identity)
        per = self._signals.get(identity_key, {})
        moved = {}
        for sig, st in per.items():
            if signal is not None and sig != signal:
                continue
            if st.ewma.z is None:
                continue
            old_mean = st.stats.mean
            new_mean = float(st.ewma.z)
            # Adopt the new level: re-anchor the virtual prior on it
            # and drop the retained window -- the old traffic is no
            # longer "normal". Sigma is kept (the operator judged the
            # level, not the noise).
            st.stats.values.clear()
            st.stats.seed_prior(MIN_TRAINING_BUCKETS, new_mean,
                                st.stats.sigma())
            st.cusum.sh = 0.0
            moved[sig] = {"old_mean": old_mean, "new_mean": new_mean,
                          "sigma": st.stats.sigma()}
        return {
            "action": "rebaseline",
            "identity_key": identity_key,
            "reset_by": reset_by,
            "at": _utcnow(),
            "signals": moved,
        }

    # -- trip records ----------------------------------------------------

    def pending_trips(self):
        """Trip dicts emitted since the last drain (one per transition)."""
        trips, self._trips_emitted = self._trips_emitted, []
        return trips

    def requeue_trips(self, trips):
        """Put trips back at the head of the pending queue.

        Wave-77 (recovery): the recovery trigger drains trips and then
        chains a trigger record per trip. If the trigger-record write
        fails AFTER the drain, the unprocessed remainder must not be
        lost — the trigger re-queues it here so the next drain sees it
        again. Idempotency lives on the recovery side (seen case ids),
        so a re-queued trip can never double-trigger.
        """
        trips = list(trips)
        if trips:
            self._trips_emitted = trips + self._trips_emitted
        return len(trips)

    # -- persistence ------------------------------------------------------

    def baseline_path(self):
        if not self.run_dir:
            return None
        return os.path.join(str(self.run_dir), "detection",
                            "baselines.json")

    def save_baselines(self):
        """Persist per-identity detector state to the operator run dir.

        Never inside agent-writable space: ``<run_dir>/detection/`` is
        operator-owned. The agent has no write seam here (proven by the
        trip-suppression battery).
        """
        path = self.baseline_path()
        if path is None:
            return None
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {"identities": {}}
        for key, per in self._signals.items():
            entry = {"role": self._roles.get(key), "signals": {},
                     "breaker": self._breaker(key).state,
                     "consecutive_opens":
                         self._breaker(key).consecutive_opens}
            for sig, st in per.items():
                entry["signals"][sig] = dict(
                    st.stats.to_dict(),
                    ewma_z=st.ewma.z,
                    cusum_sh=st.cusum.sh,
                    buckets_seen=st.buckets_seen,
                )
            data["identities"][key] = entry
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, sort_keys=True)
        os.replace(tmp, path)
        return path

    def load_baselines(self):
        path = self.baseline_path()
        if path is None or not os.path.exists(path):
            return False
        with open(path) as f:
            data = json.load(f)
        for key, entry in (data.get("identities") or {}).items():
            self._roles[key] = entry.get("role") or "unknown"
            br = self._breaker(key)
            if entry.get("breaker") in (CircuitBreaker.OPEN,
                                        CircuitBreaker.HALF_OPEN):
                # A persisted OPEN/HALF_OPEN restores as OPEN: a restart
                # must never silently close a tripped breaker.
                br.state = CircuitBreaker.OPEN
            br.consecutive_opens = int(
                entry.get("consecutive_opens", 0) or 0)
            for sig, s in (entry.get("signals") or {}).items():
                st = _bind_signal(SignalState(self._roles[key]), sig)
                st.stats = StreamingStats.from_dict(s)
                st.ewma.z = s.get("ewma_z")
                st.cusum.sh = float(s.get("cusum_sh", 0.0) or 0.0)
                st.buckets_seen = int(s.get("buckets_seen", 0) or 0)
                self._signals.setdefault(key, {})[sig] = st
        return True

    # -- export surface (the slow-boil boundary, rendered) -----------------

    def export_boundary(self):
        """The operative detection parameters for the demo export.

        ``demo/make_report.py`` renders this verbatim: baseline
        windows, thresholds, measured lag, and the slow-boil sentence.
        """
        return {
            "signals": {
                sig: dict(cfg,
                          ewma_alpha=EWMA_ALPHA,
                          spike_z=SPIKE_Z,
                          cusum_k=CUSUM_K,
                          cusum_h=CUSUM_H,
                          bucket_seconds=BUCKET_SECONDS,
                          window_buckets=WINDOW_BUCKETS,
                          min_training_buckets=MIN_TRAINING_BUCKETS)
                for sig, cfg in SIGNAL_CONFIGS.items()
            },
            "measured_cusum_lag_buckets": MEASURED_CUSUM_LAG_BUCKETS,
            "measured_cusum_lag_note": MEASURED_CUSUM_LAG_NOTE,
            "slow_boil": ("A drift engineered to stay under the CUSUM "
                          "decision interval (h=%s sigma, k=%s sigma) "
                          "never trips. The thresholds above are what "
                          "that drift stays under."
                          % (CUSUM_H, CUSUM_K)),
        }


#: Measured CUSUM detection lag for a sustained +1.0 sigma shift in
#: ``egress_attempts`` (deterministic synthetic battery,
#: ``evals/w76_probes.py::sit_slowboil_cusum_lag``). A measured value,
#: not a theory number; updated if the battery re-measures it.
MEASURED_CUSUM_LAG_BUCKETS = 11
MEASURED_CUSUM_LAG_NOTE = (
    "measured on the deterministic synthetic battery 2026-09-22: a "
    "sustained +1.0-sigma shift in egress_attempts (scout role, 12 "
    "cold-start buckets, baseline frozen while CUSUM suspicion is "
    "active) trips the CUSUM (k=0.5, h=5.0) after 11 buckets; EWMA "
    "spike does not fire on this gradual shape in the first 8 buckets "
    "(by design -- that is why the pair exists). Textbook expectation "
    "h/(delta-k) = 10 buckets; the +1 is the strict-inequality trip "
    "rule.")


def build_detector_trip(trip, *, session_id, session_open,
                        policy_version="detection-wave76",
                        principal_ref="governance-monitor"):
    """Build a chained ``detector_trip`` provenance record.

    The caller appends it via ``provenance.append_provenance`` (the
    monitor never writes the log itself). ``trip`` is a trip dict from
    ``observe_bucket`` / ``ingest_anchor_audit``.
    """
    from .provenance import build_delegation
    now = _utcnow()
    return {
        "event": "detector_trip",
        "ts": now,
        "prov": {
            "schema_version": 1,
            "record_type": "detector_trip",
            "session_id": session_id,
            "session_open": session_open,
            "clock_source": "operator-monitor",
            "principal": {"kind": "service", "ref": principal_ref},
            # The monitor acts as operator infrastructure, not as a
            # delegated agent: no delegation path, stated reason.
            "delegation": build_delegation(
                [], no_delegation_reason=(
                    "detector-trip: operator-issued monitor record; "
                    "no agent delegation path exists by construction")),
            "policy_version": policy_version,
            "matched_rules": ["detection-breaker"],
            "payload_tier": "decision",
            "retention": {
                "class": "decision",
                "until": (datetime.now(timezone.utc)
                          + timedelta(days=183)).isoformat(),
                "policy": "art12-default",
            },
            "detector_trip": {
                "identity_key": str(trip.get("identity_key")),
                "signal": str(trip.get("signal")),
                "trip_kind": str(trip.get("trip_kind")),
                "observed": str(trip.get("observed")),
                "threshold": str(trip.get("threshold")),
                "baseline_mean": str(trip.get("baseline_mean")),
                "baseline_sigma": str(trip.get("baseline_sigma")),
                "basis": str(trip.get("basis")),
                "buckets_seen": int(trip.get("buckets_seen") or 0),
                "window_buckets": int(trip.get("window_buckets") or 0),
            },
        },
    }
