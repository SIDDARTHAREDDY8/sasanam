"""Covert-channel detection BASELINE for inter-agent messages.

Statistical anomaly monitor, per sender: it flags anomalous channel
usage as incidents FOR HUMAN REVIEW -- entropy spikes in free-text
fields vs the sender's own baseline, inter-message timing too uniform
for the declared traffic class, and populated fields outside the
agent's declared schema. Findings are review incidents, never verdicts
of guilt.

What this module is NOT: a proof of no-covert-channel. It is
statistical and WILL miss low-and-slow channels (a bit per message
encoded in synonym choice, timing jitter inside the normal band,
paraphrase-semantic stego). The battery measures the false-negative
rate on seeded payloads and reports it; ship the number, not a claim.

Baselines are per sender, not global: agents have legitimately
different text profiles, and a global entropy threshold would drown in
false positives. Timing analysis is relative to the DECLARED traffic
class: a heartbeat agent is legitimately periodic, a chat agent is
not -- regularity is only anomalous against a non-periodic
declaration.

HONEST RESIDUALS (never claimed away):

* Baseline poisoning: flagged messages do not train the baseline, but
  an adversary who stays under the thresholds can drift the baseline
  slowly. This is inherent to adaptive baselines; the mitigation is
  human review of the incidents plus periodic baseline resets, both
  outside this module.
* Shared-state side channels OUTSIDE the message path (file channels,
  spawn lineage, tool-mediated channels, Schelling-point coordination)
  are an explicit boundary: this module only sees (sender, fields, ts)
  triples handed to ``process``.
* Timing needs the declared traffic class to be honest: a lying
  declaration ("periodic" for a chat agent) blinds the timing check.
  Declarations are a deployment input, not verified here.

$0 spend, synthetic/local only. No credentials, no network.
"""

import math
from collections import deque

# A spike must be both statistically significant (z) and practically
# significant (absolute delta in bits): with tiny baseline variance a
# trivially small shift would otherwise z-spike.
_DEFAULT_ENTROPY_Z = 4.0
_DEFAULT_MIN_ENTROPY_DELTA = 0.5
# Coefficient of variation below this over a full window of intervals
# is implausibly uniform for non-periodic traffic.
_DEFAULT_TIMING_CV_MAX = 0.15
_DEFAULT_TIMING_WINDOW = 8
_DEFAULT_MIN_BASELINE_SAMPLES = 10
_DEFAULT_MAX_HISTORY = 512
# Free-text fields shorter than this have noisy entropy; skip them.
_MIN_TEXT_LEN = 16

_TRAFFIC_CLASSES = ("chat", "periodic", "bursty")


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class _Welford(object):
    """Running mean/variance (Welford's algorithm)."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, x):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def variance(self):
        return self.m2 / self.n if self.n > 1 else 0.0

    @property
    def std(self):
        return math.sqrt(self.variance)


class _SenderState(object):
    __slots__ = ("fields", "traffic_class", "entropy", "timestamps")

    def __init__(self, fields, traffic_class):
        self.fields = set(fields)
        self.traffic_class = traffic_class
        self.entropy = {}  # field -> _Welford over entropy values
        self.timestamps = deque(maxlen=_DEFAULT_MAX_HISTORY)


class CovertChannelMonitor(object):
    """Per-sender statistical baseline monitor.

    ``declare_agent(agent_id, fields, traffic_class)`` registers the
    agent's declared message schema (the field set it may populate)
    and its traffic class (``"chat"``, ``"periodic"``, ``"bursty"``).
    ``process(agent_id, fields, ts, log=None, run_id="")`` evaluates one
    message (a ``{field: value}`` dict at timestamp ``ts``) against the
    CURRENT baseline, returns a list of incident dicts (empty = clean),
    then trains the baseline on the message ONLY if it was clean.
    """

    def __init__(self, entropy_z=_DEFAULT_ENTROPY_Z,
                 min_entropy_delta=_DEFAULT_MIN_ENTROPY_DELTA,
                 timing_cv_max=_DEFAULT_TIMING_CV_MAX,
                 timing_window=_DEFAULT_TIMING_WINDOW,
                 min_baseline_samples=_DEFAULT_MIN_BASELINE_SAMPLES):
        self._entropy_z = entropy_z
        self._min_entropy_delta = min_entropy_delta
        self._timing_cv_max = timing_cv_max
        self._timing_window = timing_window
        self._min_baseline = min_baseline_samples
        self._senders = {}

    def declare_agent(self, agent_id, fields=(), traffic_class="chat"):
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if traffic_class not in _TRAFFIC_CLASSES:
            raise ValueError("traffic_class must be one of %s"
                             % (_TRAFFIC_CLASSES,))
        for f in fields:
            if not isinstance(f, str) or not f:
                raise ValueError("declared fields must be non-empty "
                                 "strings")
        self._senders[agent_id] = _SenderState(fields, traffic_class)

    def _incident(self, kind, agent_id, ts, detail):
        return {"kind": kind, "agent_id": agent_id, "ts": ts,
                "severity": "review", "detail": detail}

    def process(self, agent_id, fields, ts, log=None, run_id=""):
        """Evaluate one message; return incident dicts (empty = clean).

        ``fields``: ``{field_name: value}``. ``ts``: message timestamp
        (float, same clock for a sender's stream). Evaluates against the
        current baseline FIRST, then trains on clean messages only.
        When ``log`` is supplied, one chained
        ``covert_channel_incident`` audit event is appended per message
        that produced findings.
        """
        if not isinstance(fields, dict):
            raise TypeError("fields must be a dict")
        state = self._senders.get(agent_id)
        incidents = []
        if state is None:
            incidents.append(self._incident(
                "undeclared_agent", agent_id, ts,
                "sender %r has no declared schema/traffic class" %
                (agent_id,)))
            state = _SenderState((), "chat")
            self._senders[agent_id] = state

        # 1. unexpected field usage: populated fields outside the
        # declared schema.
        for name, value in fields.items():
            if value is None or value == "":
                continue
            if name not in state.fields:
                incidents.append(self._incident(
                    "unexpected_field", agent_id, ts,
                    "field %r populated but not in declared schema %s"
                    % (name, sorted(state.fields))))

        # 2. entropy spikes in free-text fields vs sender baseline.
        for name, value in fields.items():
            if not isinstance(value, str) or len(value) < _MIN_TEXT_LEN:
                continue
            base = state.entropy.get(name)
            if base is None or base.n < self._min_baseline:
                continue
            e = _shannon_entropy(value)
            std = base.std
            if std <= 0:
                continue
            z = (e - base.mean) / std
            if z > self._entropy_z and \
                    (e - base.mean) > self._min_entropy_delta:
                incidents.append(self._incident(
                    "entropy_spike", agent_id, ts,
                    "field %r entropy %.2f bits vs baseline mean %.2f "
                    "(z=%.1f, n=%d)" % (
                        name, e, base.mean, z, base.n)))

        # 3. timing regularity vs declared traffic class.
        state.timestamps.append(ts)
        hist = state.timestamps
        w = self._timing_window
        if state.traffic_class != "periodic" and len(hist) >= w + 1:
            ivals = [hist[i + 1] - hist[i]
                     for i in range(len(hist) - w - 1, len(hist) - 1)]
            if all(iv > 0 for iv in ivals):
                mean = sum(ivals) / len(ivals)
                var = sum((iv - mean) ** 2 for iv in ivals) / len(ivals)
                cv = math.sqrt(var) / mean if mean > 0 else 0.0
                if cv < self._timing_cv_max:
                    incidents.append(self._incident(
                        "timing_regularity", agent_id, ts,
                        "%d consecutive intervals mean %.2fs CV %.3f "
                        "(<%s) for traffic class %r: implausibly uniform"
                        % (len(ivals), mean, cv, self._timing_cv_max,
                           state.traffic_class)))

        # Train on clean messages only (flagged messages must not move
        # the baseline toward the anomaly).
        if not incidents:
            for name, value in fields.items():
                if isinstance(value, str) and len(value) >= _MIN_TEXT_LEN:
                    base = state.entropy.setdefault(name, _Welford())
                    base.add(_shannon_entropy(value))

        if incidents and log is not None:
            log.append({
                "event": "covert_channel_incident",
                "run_id": run_id,
                "agent_id": agent_id,
                "decision": "flagged_for_review",
                "policy_id": "covert-channel-baseline",
                "reason": "%d channel anomaly finding(s) for human review"
                          % len(incidents),
                "findings": incidents,
            })
        return incidents
