"""Wave-337 (R12, loopers-oss pattern adapted): per-tool budget enforcement.

The frequency axis (``gov.tool_rate_limit``, F422) bounds VELOCITY:
how fast an agent may call a tool. It does not bound how MUCH an
agent may spend: an agent pacing ``http_post`` at exactly 10/60s --
the published rate limit -- accumulates unbounded total volume with
no coded intervention at all (the wave-336 attack round-4 WATCH
note). This module adds the orthogonal COST axis: the deployment
declares a per-tool (or tool-family) budget in abstract cost units,
and every execution charges its declared cost against the budget.
Exhaustion refuses coded ``tool-budget-exhausted``; the run
continues -- the same per-call granularity as the rate wire,
deliberately finer than the F162 whole-run pause.

Semantics:
* ``ToolBudgetWire.charge(tool)`` charges the tool's declared cost
  against every budget bucket matching the tool (exact name or
  fnmatch family -- the same scoping as the rate wire, R8). When a
  bucket's cumulative spend would exceed its budget, the call is
  refused coded ``tool-budget-exhausted``. The charge is ATOMIC:
  check-then-record across all matching buckets, so a refused call
  records no spend anywhere (unlike the rate wire, which records
  the offending execution before refusing).
* Budgets are deployment-set (policy ``tool_budgets:`` section),
  never agent-set. Absent section = NO budgets: unlike the rate
  wire's conservative built-ins, there is no legitimate universal
  default spend cap, so the budget axis is strictly opt-in per
  deployment -- an absent section can never surprise-break an
  existing deployment. A tool matching no budget key is uncharged
  (documented residual).
* Costs are abstract units; the deployment maps units to currency.
  ``cost_per_call`` defaults to 1 unit per execution and may be
  set per key (a Snowflake-query-shaped tool costs more than a
  read-shaped tool).
* Spend is cumulative per run (no window): the budget bounds TOTAL
  volume, which is exactly what the frequency axis cannot see.
  Reset on F162 human-approved resume mirrors the rate wire: the
  tripped class's tool budgets start fresh, so a human-approved
  resume is not immediately re-refused by the still-exhausted
  budget.
* Fail-closed: malformed deployment config raises code-first
  ``ToolBudgetConfigError`` (``tool-budget-config-invalid``) at
  construction -- non-positive/non-finite budgets and costs refuse
  here, never at call time; any unexpected budget-wire failure at
  call time is translated by the executor into
  ``ToolBudgetUnavailable`` (``tool-budget-unavailable``) -- a
  broken budget denies, never allows unlimited spend.

Stdlib only. Deterministic (no clock: cumulative spend needs none).
"""

import math

import gov.decision_codes as _dc
from gov.tool_rate_limit import is_pattern_key, matching_buckets


class ToolBudgetError(Exception):
    """Base class for wave-337 per-tool budget fail-closed errors."""


class ToolBudgetExhausted(ToolBudgetError):
    """A per-tool budget is exhausted: cumulative spend would exceed it.

    Code-first: ``code`` is the taxonomy machine code
    ``tool-budget-exhausted``. Raised by ``ToolBudgetWire.charge()``;
    the executor records the chained refusal and re-raises. The run
    is NOT paused -- only this call is refused.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolBudgetExhausted, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class ToolBudgetUnavailable(ToolBudgetError):
    """The budget wire itself failed: fail closed, deny the call.

    Code-first (``tool-budget-unavailable``). Raised by the
    executor when the wire raises anything unexpected -- a broken
    budget denies, never allows unlimited spend.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolBudgetUnavailable, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class ToolBudgetConfigError(ToolBudgetError):
    """Malformed deployment budget config: fail closed at load.

    Code-first (``tool-budget-config-invalid``). Raised while
    normalizing the ``tool_budgets:`` policy section or building the
    wire -- the executor never constructs on uninterpretable budget
    policy.
    """

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ToolBudgetConfigError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _fail_exhausted(code, detail):
    raise ToolBudgetExhausted(code, detail)


def _positive_finite(value, what, where):
    if (isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0):
        raise ToolBudgetConfigError(
            "tool-budget-config-invalid",
            "%s: %s must be a positive finite number, got %r"
            % (where, what, value))
    return float(value)


def normalize_section(section):
    """Normalize a ``tool_budgets:`` policy section.

    Shape: ``{tool_or_glob: {budget: <positive finite number>,
    cost_per_call: <positive finite number, default 1>}}``. Keys
    may be exact tool names or fnmatch glob families (a key
    containing ``*?[]`` is a family). Returns ``{key: (budget,
    cost_per_call)}``. ``None`` (absent section) -> ``{}`` (no
    budgets -- strictly opt-in, never default-enforced). Anything
    malformed raises ``ToolBudgetConfigError`` fail-closed.
    """
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ToolBudgetConfigError(
            "tool-budget-config-invalid",
            "tool_budgets must be a mapping, got %r" % (section,))
    out = {}
    for tool, spec in section.items():
        where = "tool_budgets[%r]" % (tool,)
        if not isinstance(tool, str) or not tool:
            raise ToolBudgetConfigError(
                "tool-budget-config-invalid",
                "tool name must be a non-empty string, got %r"
                % (tool,))
        if not isinstance(spec, dict):
            raise ToolBudgetConfigError(
                "tool-budget-config-invalid",
                "%s must be a mapping, got %r" % (where, spec))
        for key in spec:
            if key not in ("budget", "cost_per_call"):
                raise ToolBudgetConfigError(
                    "tool-budget-config-invalid",
                    "%s: unknown key %r" % (where, key))
        if "budget" not in spec:
            raise ToolBudgetConfigError(
                "tool-budget-config-invalid",
                "%s: need budget" % (where,))
        budget = _positive_finite(spec["budget"], "budget", where)
        cost = _positive_finite(spec.get("cost_per_call", 1),
                                "cost_per_call", where)
        out[tool] = (budget, cost)
    return out


class ToolBudgetWire:
    """Per-tool cumulative budget counters, one ledger per bucket.

    ``budgets`` maps key -> (budget, cost_per_call); keys may be
    exact tool names or fnmatch glob families; both validated
    fail-closed at construction. ``charge(tool)`` charges the
    declared cost against every bucket matching ``tool`` --
    atomically (check-then-record: a refused call records no spend
    anywhere) -- and returns the finest bucket's cumulative spend.
    Raises ``ToolBudgetExhausted`` when a bucket's spend would
    exceed its budget. Tools matching no key are ignored (no
    charge, no trip).
    """

    def __init__(self, budgets):
        self.budgets = {}
        for tool, spec in (budgets or {}).items():
            if not isinstance(tool, str) or not tool:
                raise ToolBudgetConfigError(
                    "tool-budget-config-invalid",
                    "tool name must be a non-empty string, got %r"
                    % (tool,))
            try:
                budget, cost_per_call = spec
            except (TypeError, ValueError):
                raise ToolBudgetConfigError(
                    "tool-budget-config-invalid",
                    "budget for %r must be a (budget, cost_per_call) "
                    "pair, got %r" % (tool, spec))
            where = "tool_budgets[%r]" % (tool,)
            self.budgets[tool] = (
                _positive_finite(budget, "budget", where),
                _positive_finite(cost_per_call, "cost_per_call", where))
        # key -> cumulative units spent (float). Single-threaded
        # executor ownership: no lock (charge/reset run on the
        # executor thread).
        self._spent = {key: 0.0 for key in self.budgets}

    def budget_state(self, tool):
        """Cumulative spend per matching bucket (read-only).

        Returns ``{bucket: {"spent", "budget", "cost_per_call"}}``.
        Raises ``ToolBudgetConfigError`` when the tool matches no
        bucket.
        """
        buckets = matching_buckets(tool, self.budgets)
        if not buckets:
            raise ToolBudgetConfigError(
                "tool-budget-config-invalid",
                "no budget configured for tool %r" % (tool,))
        return {key: {"spent": self._spent[key],
                      "budget": self.budgets[key][0],
                      "cost_per_call": self.budgets[key][1]}
                for key in buckets}

    def limit_for(self, tool):
        """Finest matching bucket's (budget, cost_per_call) for a tool.

        Returns ``(0.0, 0.0)`` when the tool matches no bucket (used
        for refusal-record diagnostics).
        """
        buckets = matching_buckets(tool, self.budgets)
        if not buckets:
            return (0.0, 0.0)
        return self.budgets[buckets[0]]

    def reset_tool(self, tool):
        """Zero the cumulative spend for ``tool`` (fresh budget).

        Resets every bucket matching ``tool`` (exact and family).
        Used on F162 human-approved resume: the tripped class's
        tool budgets start fresh, mirroring the rate wire's reset,
        so a human-approved resume is not immediately re-refused by
        the still-exhausted budget.
        """
        for key in matching_buckets(tool, self.budgets):
            self._spent[key] = 0.0

    def configured_tools(self):
        """Budget keys (sorted, read-only). Keys may be exact tool
        names or glob families."""
        return sorted(self.budgets)

    def charge(self, tool):
        """Charge one execution's cost against matching budgets.

        Charges every bucket matching ``tool`` its declared
        ``cost_per_call`` -- atomically: every bucket is checked
        first, and only when no bucket would be exceeded is the
        spend recorded. Raises ``ToolBudgetExhausted`` when a
        bucket's cumulative spend would exceed its budget; buckets
        are checked finest-first so the most specific refusal is
        raised. Tools matching no key are ignored (no charge, no
        trip); returns 0.0. Returns the finest bucket's cumulative
        spend.
        """
        buckets = matching_buckets(tool, self.budgets)
        if not buckets:
            return 0.0
        first_exceeded = None
        for key in buckets:
            budget, cost_per_call = self.budgets[key]
            spent = self._spent[key]
            if spent + cost_per_call > budget and first_exceeded is None:
                first_exceeded = (key, spent, budget, cost_per_call)
        if first_exceeded is not None:
            key, spent, budget, cost_per_call = first_exceeded
            _fail_exhausted(
                "tool-budget-exhausted",
                "tool %r (bucket %r) would exceed its budget: "
                "cumulative spend %.1f + cost %.1f > budget %.1f"
                % (tool, key, spent, cost_per_call, budget))
        for key in buckets:
            self._spent[key] += self.budgets[key][1]
        return self._spent[buckets[0]]


# Re-export the shared scoping helpers so budget consumers read from
# one place; the canonical definitions live in gov.tool_rate_limit.
__all__ = [
    "ToolBudgetError",
    "ToolBudgetExhausted",
    "ToolBudgetUnavailable",
    "ToolBudgetConfigError",
    "ToolBudgetWire",
    "normalize_section",
    "is_pattern_key",
]
