"""F421 (LOW): per-tool sliding-window rate limiting.

The tree's F162 tempo tripwire bounds per-action-CLASS aggregates
(read 300/60s, write 60/60s, egress 30/60s) and answers with a
whole-run pause demanding human resume. That is the right response
for class-level abuse, but it leaves two gaps:

1. An agent hammering ONE sensitive tool just under the class
   threshold (29 ``http_post``/60s, sustained indefinitely) meets no
   coded intervention at all -- no refusal, no log flag.
2. Deployments have no per-tool dial: the only knob is the coarse
   class threshold.

This module holds the per-tool sliding-window wire the executor
routes through at the two F33 execution boundaries (direct allow
path AND the approved-execution sweep), BEFORE the class tempo
charge: the finer, more specific refusal fires first; an agent that
persists by rotating tools still meets the class tripwire.

Wave-337 (R8, AG2 TealTiger pattern adapted): limit keys may be
exact tool names OR fnmatch glob families (``db.*`` bounds the whole
family with one line). A tool matching several keys charges every
matching bucket -- one timestamp per DISTINCT bucket per call (the
TealTiger double-count lesson: overlapping exact+glob matches must
not record two timestamps in the same bucket, and the finest limit
refuses first). There is deliberately no shadowing: an exact rule
never exempts a tool from a family rule, so a family bucket cannot
be bypassed by adding an exact key.

Semantics:
* ``ToolRateWire.charge(tool)`` records one EXECUTION of ``tool``
  against every matching bucket and returns the finest bucket's
  observed windowed count; when a bucket's count exceeds its limit
  it raises code-first ``ToolRateLimitExceeded``
  (``tool-rate-limit-exceeded``). The call is refused; the run
  continues -- deliberately finer than the F162 whole-run pause.
  Matching buckets are checked finest-first so the most specific
  refusal is the one raised.
* Limits are deployment-set (policy ``tool_rate_limits:`` section),
  never agent-set. Absent section = conservative built-in defaults
  for the sensitive set (default-enforced, never opt-in -- F162
  precedent). A tool matching no key is uncharged (documented
  residual, same scoping pattern as F162's taxonomy).
* Fail-closed: malformed deployment config raises code-first
  ``ToolRateConfigError`` (``tool-rate-limit-config-invalid``) at
  construction; any unexpected limiter failure at call time is
  translated by the executor into ``ToolRateLimiterUnavailable``
  (``tool-rate-limiter-unavailable``) -- a broken limiter denies,
  never allows unlimited.
* The clock is monotonic and injectable (``clock=``); production
  uses ``time.monotonic``. Timestamps older than the window are
  evicted on every charge, so memory is bounded by
  (buckets x matched tools), not by run length.
"""

import fnmatch
import time

import gov.decision_codes as _dc

# Characters that make a limit key a glob family rather than an
# exact tool name (fnmatch magic). A key containing any of these is
# matched with fnmatchcase against tool names; anything else is an
# exact key. (Adapted pattern, not code: AG2 TealTiger shipped
# fnmatch scoping in ag2 v1.0.6, Apache-2.0.)
_GLOB_MAGIC = frozenset("*?[]")


def is_pattern_key(key):
    """True when a limit key is a glob family (contains fnmatch magic)."""
    return any(ch in _GLOB_MAGIC for ch in key)


def matching_buckets(tool, limits):
    """Config keys (buckets) matching ``tool``, finest-first.

    A key matches when it equals the tool name exactly, or when it
    is a glob family matching via ``fnmatch.fnmatchcase``. Each key
    appears at most once (a key is one bucket -- the TealTiger
    double-count guard). Sorted by (max_calls, window_secs, key) so
    the finest, most specific limit is checked first and its refusal
    is the one raised.
    """
    hits = []
    for key, (window_secs, max_calls) in limits.items():
        if key == tool or (is_pattern_key(key)
                           and fnmatch.fnmatchcase(tool, key)):
            hits.append((max_calls, window_secs, key))
    hits.sort()
    return [key for _, _, key in hits]

# Default per-tool limits: tool -> (window_secs, max_calls). These are
# the tools where a per-tool limit is STRICTER than the F162 class
# tripwire, so the finer refusal fires first: hammering any one of
# them at machine speed is never legitimate. ``api_call`` is
# deliberately NOT defaulted: the egress class tripwire (30/60s)
# already bounds api_call bursts more tightly than any default that
# would not break legitimate use, so a default could never fire
# first -- it stays configurable per deployment via
# ``tool_rate_limits:``.
DEFAULT_TOOL_LIMITS = {
    "send_email": (60.0, 5),
    "http_post": (60.0, 10),
    "delete_file": (60.0, 10),
    "write_file": (60.0, 30),
    "read_file": (60.0, 120),
}


class ToolRateLimitError(Exception):
    """Base class for F421 per-tool rate-limit fail-closed errors."""


class ToolRateLimitExceeded(ToolRateLimitError):
    """A per-tool rate limit fired: windowed count > the tool's limit.

    Code-first: ``code`` is the taxonomy machine code
    ``tool-rate-limit-exceeded``. Raised by ``ToolRateWire.charge()``;
    the executor records the chained refusal and re-raises. The run
    is NOT paused -- only this call is refused.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolRateLimitExceeded, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class ToolRateLimiterUnavailable(ToolRateLimitError):
    """The limiter itself failed: fail closed, deny the call.

    Code-first (``tool-rate-limiter-unavailable``). Raised by the
    executor when the wire raises anything unexpected -- a broken
    limiter denies, never allows unlimited.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolRateLimiterUnavailable, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class ToolRateConfigError(ToolRateLimitError):
    """Malformed deployment rate-limit config: fail closed at load.

    Code-first (``tool-rate-limit-config-invalid``). Raised while
    normalizing the ``tool_rate_limits:`` policy section or building
    the wire -- the executor never constructs on bad config.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolRateConfigError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _fail(code, detail):
    raise ToolRateLimitExceeded(code, detail)


def _check_window(window_secs, where):
    if (isinstance(window_secs, bool)
            or not isinstance(window_secs, (int, float))
            or window_secs <= 0):
        raise ToolRateConfigError(
            "tool-rate-limit-config-invalid",
            "%s: window_secs must be a positive number, got %r"
            % (where, window_secs))
    return float(window_secs)


def _check_max_calls(max_calls, where):
    if isinstance(max_calls, bool) or not isinstance(max_calls, int) \
            or max_calls < 0:
        raise ToolRateConfigError(
            "tool-rate-limit-config-invalid",
            "%s: max_calls must be a non-negative integer, got %r"
            % (where, max_calls))
    return max_calls


def normalize_section(section):
    """Normalize a ``tool_rate_limits:`` policy section.

    Shape: ``{tool_or_glob: {window_secs: <positive number>,
    max_calls: <non-negative int>}}``. Keys may be exact tool names
    or fnmatch glob families (a key containing ``*?[]`` is a
    family). Returns ``{key: (window_secs, max_calls)}``. ``None``
    (absent section) -> ``{}`` (the executor applies the built-in
    defaults). Anything malformed raises ``ToolRateConfigError``
    fail-closed.
    """
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ToolRateConfigError(
            "tool-rate-limit-config-invalid",
            "tool_rate_limits must be a mapping, got %r" % (section,))
    out = {}
    for tool, spec in section.items():
        where = "tool_rate_limits[%r]" % (tool,)
        if not isinstance(tool, str) or not tool:
            raise ToolRateConfigError(
                "tool-rate-limit-config-invalid",
                "tool name must be a non-empty string, got %r" % (tool,))
        if not isinstance(spec, dict):
            raise ToolRateConfigError(
                "tool-rate-limit-config-invalid",
                "%s must be a mapping, got %r" % (where, spec))
        for key in spec:
            if key not in ("window_secs", "max_calls"):
                raise ToolRateConfigError(
                    "tool-rate-limit-config-invalid",
                    "%s: unknown key %r" % (where, key))
        if "window_secs" not in spec or "max_calls" not in spec:
            raise ToolRateConfigError(
                "tool-rate-limit-config-invalid",
                "%s: need both window_secs and max_calls" % (where,))
        out[tool] = (_check_window(spec["window_secs"], where),
                     _check_max_calls(spec["max_calls"], where))
    return out


class ToolRateWire:
    """Per-tool sliding-window rate counters, one deque per bucket.

    ``limits`` maps key -> (window_secs, max_calls); keys may be
    exact tool names or fnmatch glob families; both validated
    fail-closed at construction. ``charge(tool)`` records one
    EXECUTION against every bucket matching ``tool`` -- exactly one
    timestamp per distinct bucket -- and returns the finest
    bucket's observed windowed count; when a bucket's count exceeds
    its limit it raises ``ToolRateLimitExceeded`` (the offending
    execution is recorded, then refused). Tools matching no key are
    ignored (no charge, no trip).
    """

    def __init__(self, limits, clock=None):
        self.limits = {}
        for tool, spec in (limits or {}).items():
            if not isinstance(tool, str) or not tool:
                raise ToolRateConfigError(
                    "tool-rate-limit-config-invalid",
                    "tool name must be a non-empty string, got %r"
                    % (tool,))
            try:
                window_secs, max_calls = spec
            except (TypeError, ValueError):
                raise ToolRateConfigError(
                    "tool-rate-limit-config-invalid",
                    "limit for %r must be a (window_secs, max_calls) "
                    "pair, got %r" % (tool, spec))
            self.limits[tool] = (_check_window(window_secs, tool),
                                 _check_max_calls(max_calls, tool))
        self._clock = clock if clock is not None else time.monotonic
        # tool -> list of monotonic timestamps (append-only, evicted
        # from the head on charge; bounded by the tool's limit).
        # Single-threaded executor ownership: no lock (charge/reset
        # run on the executor thread).
        self._hits = {tool: [] for tool in self.limits}

    def _evict(self, tool, now):
        window_secs, _ = self.limits[tool]
        cutoff = now - window_secs
        hits = self._hits[tool]
        # hits is time-ordered (monotonic clock); drop the stale head.
        idx = 0
        while idx < len(hits) and hits[idx] <= cutoff:
            idx += 1
        if idx:
            del hits[:idx]
        return len(hits)

    def windowed_count(self, tool):
        """Current in-window execution count for a tool (read-only).

        Reports the finest matching bucket's count. Raises
        ``ToolRateConfigError`` when the tool matches no bucket.
        """
        buckets = matching_buckets(tool, self.limits)
        if not buckets:
            raise ToolRateConfigError(
                "tool-rate-limit-config-invalid",
                "no rate limit configured for tool %r" % (tool,))
        return self._evict(buckets[0], self._clock())

    def limit_for(self, tool):
        """Finest matching bucket's (window_secs, max_calls) for a tool.

        Returns ``(0.0, 0)`` when the tool matches no bucket (used
        for refusal-record diagnostics).
        """
        buckets = matching_buckets(tool, self.limits)
        if not buckets:
            return (0.0, 0)
        return self.limits[buckets[0]]

    def reset_tool(self, tool):
        """Forget all in-window hits for ``tool`` (fresh window).

        Resets every bucket matching ``tool`` (exact and family).
        Used on F162 human-approved resume: the tripped class's
        tools start fresh, mirroring the tempo wire's class reset,
        so the very next call does not hit a still-hot per-tool
        window and make the resume useless.
        """
        for key in matching_buckets(tool, self.limits):
            self._hits[key] = []

    def configured_tools(self):
        """Limit keys carrying a rate limit (sorted, read-only).

        Keys may be exact tool names or glob families.
        """
        return sorted(self.limits)

    def charge(self, tool):
        """Record one execution of ``tool``; fail closed on exceed.

        Charges every bucket matching ``tool`` -- exactly one
        timestamp per distinct bucket (the TealTiger double-count
        guard). Returns the finest bucket's windowed count. Raises
        ``ToolRateLimitExceeded`` when a bucket's count exceeds its
        limit; buckets are checked finest-first so the most
        specific refusal is raised. Tools matching no key are
        ignored (no charge, no trip); returns 0.
        """
        buckets = matching_buckets(tool, self.limits)
        if not buckets:
            return 0
        now = self._clock()
        first_exceeded = None
        for key in buckets:
            hits = self._hits[key]
            hits.append(now)
            count = self._evict(key, now)
            window_secs, max_calls = self.limits[key]
            if count > max_calls and first_exceeded is None:
                first_exceeded = (key, count, window_secs, max_calls)
        if first_exceeded is not None:
            key, count, window_secs, max_calls = first_exceeded
            _fail("tool-rate-limit-exceeded",
                  "tool %r (bucket %r) exceeded its rate limit: %d "
                  "executions in %.1fs window (limit %d)"
                  % (tool, key, count, window_secs, max_calls))
        return self._evict(buckets[0], now)
