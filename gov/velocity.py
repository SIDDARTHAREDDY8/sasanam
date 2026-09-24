"""F162 (HIGH): per-run, per-action-class time-window tempo tripwires.

The tree's existing guards (F33 volume caps, S2 budgets, S5 cross-run
velocity) are per-run CUMULATIVE totals with no notion of rate, and they
are opt-in / fail-open. A run dumping thousands of ``api_call`` token
sets in an hour (GTG-50014 shape) or trickling exfiltration under every
total (low-and-slow) trips nothing under default config.

This module holds the tempo state machine the executor routes through
at the two F33 execution boundaries (direct allow path AND the
approved-execution sweep). Deterministic thresholds only — no ML
anomaly detection (explicit non-goal). The clock is injectable
(``TempoWire(clock=...)``); production uses ``time.monotonic``.

Action-class taxonomy (tools that move at machine speed):
  read   = {read_file}                                  -- bulk harvest
  write  = {write_file, delete_file}                    -- bulk staging
  egress = {send_email, http_post, api_call}            -- exfiltration
``install_package`` and any unlisted tool are outside tempo scope
(their own gates bind them; same scoping pattern as S5's
``_VELOCITY_TOOLS``). This is a documented residual.

Fail-closed semantics live in the executor: ``TempoWire.charge()``
raises ``VelocityTempoTripError`` naming the class, window, threshold
and observed count; the executor then pauses the whole run (sticky),
chains the trip record, files a human ``velocity_resume`` approval, and
re-raises. The agent can never clear the wire, the pause, or the clock.
"""

import time

# Action-class taxonomy. A tool belongs to exactly one class for
# tempo counting (deterministic; no double counting).
ACTION_CLASSES = {
    "read": frozenset(("read_file",)),
    "write": frozenset(("write_file", "delete_file")),
    "egress": frozenset(("send_email", "http_post", "api_call")),
}

_TOOL_TO_CLASS = {}
for _cls, _tools in ACTION_CLASSES.items():
    for _t in _tools:
        _TOOL_TO_CLASS[_t] = _cls


def action_class_of(tool):
    """The tempo class for a tool, or None when out of tempo scope."""
    return _TOOL_TO_CLASS.get(tool)


class VelocityError(Exception):
    """Base class for F162 velocity/tempo fail-closed errors."""


class VelocityTempoTripError(VelocityError):
    """A per-class tempo tripwire fired: windowed count > threshold.

    Raised by TempoWire.charge(); the executor translates it into a
    run pause + human re-approval demand. Never caught to continue.
    """


class VelocityRunPausedError(VelocityError):
    """The run is paused by a velocity control: no calls execute.

    Sticky: catching it and calling again still raises (the canary
    pattern). Only a human-approved resume clears it.
    """


class TempoWire:
    """Per-run sliding-window tempo counters, one deque per class.

    ``charge(tool)`` records one EXECUTION of a tool at ``clock()`` and
    returns the observed windowed count; when the count exceeds the
    class threshold it raises ``VelocityTempoTripError`` fail-closed.
    Timestamps older than the window are evicted on every charge, so
    memory is bounded by (thresholds x classes), not by run length.

    ``max_per_class`` maps class -> non-negative int threshold;
    ``window_secs`` is a positive number. Both are deployment-set
    (policy), never agent-set: the executor passes them in.
    """

    def __init__(self, window_secs, max_per_class, clock=None):
        if (isinstance(window_secs, bool)
                or not isinstance(window_secs, (int, float))
                or window_secs <= 0):
            raise ValueError(
                "window_secs must be a positive number, got %r"
                % (window_secs,))
        self.window_secs = float(window_secs)
        self.max_per_class = {}
        for cls, limit in (max_per_class or {}).items():
            if cls not in ACTION_CLASSES:
                raise ValueError("unknown tempo class %r" % (cls,))
            if (isinstance(limit, bool) or not isinstance(limit, int)
                    or limit < 0):
                raise ValueError(
                    "tempo threshold for %r must be a non-negative int, "
                    "got %r" % (cls, limit))
            self.max_per_class[cls] = limit
        self._clock = clock if clock is not None else time.monotonic
        # class -> list of monotonic timestamps (append-only, evicted
        # from the head on charge; bounded by the threshold).
        self._hits = {cls: [] for cls in ACTION_CLASSES}

    def _evict(self, cls, now):
        cutoff = now - self.window_secs
        hits = self._hits[cls]
        # hits is time-ordered (monotonic clock); drop the stale head.
        idx = 0
        while idx < len(hits) and hits[idx] <= cutoff:
            idx += 1
        if idx:
            del hits[:idx]
        return len(hits)

    def windowed_count(self, cls):
        """Current in-window execution count for a class (read-only)."""
        if cls not in ACTION_CLASSES:
            raise ValueError("unknown tempo class %r" % (cls,))
        return self._evict(cls, self._clock())

    def charge(self, tool):
        """Record one execution of ``tool``; fail closed on trip.

        Tools outside the taxonomy are ignored (no charge, no trip).
        Returns the windowed count for the tool's class. Raises
        ``VelocityTempoTripError`` when the count exceeds the class
        threshold (the offending execution is recorded, then refused).
        """
        cls = action_class_of(tool)
        if cls is None:
            return 0
        now = self._clock()
        hits = self._hits[cls]
        hits.append(now)
        count = self._evict(cls, now)
        limit = self.max_per_class.get(cls)
        if limit is not None and count > limit:
            raise VelocityTempoTripError(
                "tempo tripwire: %d %s-class executions inside %.0fs "
                "window (threshold %d); run paused fail-closed"
                % (count, cls, self.window_secs, limit))
        return count

    def reset(self, cls=None):
        """Clear recorded events for one class (or all when ``cls`` is
        None). Used when a human approves a velocity resume: the burst
        was reviewed and continuation authorized, so the tripped
        class starts a fresh window. Never called automatically."""
        if cls is None:
            for key in self._hits:
                self._hits[key] = []
        else:
            self._hits[cls] = []

    def snapshot(self):
        """Read-only per-class in-window counts (metering)."""
        now = self._clock()
        return {cls: self._evict(cls, now) for cls in ACTION_CLASSES}


# -- synthetic usage metering (S2-GAP-1 wiring) ---------------------------
# The executor mints deterministic usage on every simulated result
# (governed side) and accrues it on the RESULT path only (never call
# kwargs). Real adapters must route real results through
# ingest_foreign_result to accrue.

_USAGE_BASE_TOKENS = {
    "read_file": 40,
    "write_file": 20,
    "delete_file": 10,
    "api_call": 80,
    "http_post": 60,
    "send_email": 50,
    "install_package": 30,
}
_DEFAULT_BASE_TOKENS = 20


def mint_usage(tool, args, result):
    """Deterministic synthetic token usage for one executed tool call.

    Returns ``{"tokens": int, "spend": 0.0}`` — the spend leg is priced
    by the executor (``spend_for``) from the deployment's
    ``price_per_1k_tokens``. Pure function of (tool, args, result) —
    never of caller kwargs (the ``_usage`` call kwarg is ignored: the
    agent cannot forge or deflate its meter).
    """
    base = _USAGE_BASE_TOKENS.get(tool, _DEFAULT_BASE_TOKENS)
    content_bytes = 0
    if isinstance(args, dict):
        for key in ("content", "payload", "body", "params"):
            val = args.get(key)
            if isinstance(val, str):
                content_bytes = max(content_bytes, len(val))
            elif val is not None:
                content_bytes = max(content_bytes, len(str(val)))
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, str):
            content_bytes = max(content_bytes, len(content))
    tokens = base + content_bytes // 4
    return {"tokens": int(tokens), "spend": 0.0}


def spend_for(tokens, price_per_1k_tokens):
    """Convert accrued tokens to spend at the configured price."""
    try:
        price = float(price_per_1k_tokens or 0.0)
    except (TypeError, ValueError):
        price = 0.0
    if price < 0:
        price = 0.0
    return float(tokens) / 1000.0 * price
