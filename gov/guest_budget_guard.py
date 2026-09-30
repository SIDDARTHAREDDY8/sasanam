"""Guest->host budget non-amplification guard (wave-244, W244-3).

ADAPT of the RustSec 0311-0316 wasmtime guest->host cluster (Sept
2026: fuel amplification, memory exhaustion, host panic), patterns
only -- no upstream code vendored or imported, no advisory text
copied. The wasmtime lesson the prospectus names: the meter must be
outside the guest's reach.

Mechanism: a budget envelope is declared at guest ENTRY by the HOST
(the agent never declares or negotiates it). The host measures the
guest's actual spend -- fuel units, memory bytes, wall-clock seconds
-- and reports it to this guard. Guest-observed consumption must not
exceed declared + a small bounded ACCOUNTING_SLACK. ACCOUNTING_SLACK
is a module-level constant: it is a deployment measurement tolerance,
never agent-supplied; an envelope declaration that tries to supply
its own slack is refused malformed.

Any amplification beyond the slack -- fuel, memory, or wall-clock --
fails closed: the guest is TERMINATED, not re-budgeted. There is no
negotiation with a guest that just lied about its spend. Termination
is sticky: once a scope is terminated, effect-commit and further
measurement calls on it refuse ``guest-budget-amplified`` forever.

The guard integrates with ``gov.aggregate_budget``: each declared
envelope opens a per-guest-scope aggregate (scope keyed by the guest
scope alone), and host-measured fuel is charged against it. Two
guests never share a scope, so one guest's overrun can never be
covered by another's envelope -- no pooling.

Honest residuals:
- The guard enforces the policy on host-supplied measurements; the
  meter itself is deployment-owned. A host that lies to the guard
  about what it measured gets correct enforcement over lies. (Same
  boundary as obsigna's deployment-vouched peer identity.)
- The store is in-memory; persistence and cross-node atomicity are
  deployment-owned (same boundary as the consumption ledger).
- Wall-clock metering is monotonic-clock elapsed, not scheduler
  truth; the deadline is a bound, not a proof of preemption.

Stdlib only. Deterministic: clock arrives as an explicit ``now``.
"""

import math
import os
import uuid

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import aggregate_budget as _aggregate_budget

GUEST_BUDGET_AMPLIFIED = "guest-budget-amplified"
GUEST_BUDGET_ENVELOPE_MALFORMED = "guest-budget-envelope-malformed"
GUEST_BUDGET_DEADLINE_FIRED = "guest-budget-deadline-fired"
GUEST_BUDGET_SCOPE_UNDECLARED = "guest-budget-scope-undeclared"

# Declared measurement tolerance: fuel units, memory bytes,
# wall-clock seconds. Module-level constant -- the host declares an
# envelope; the guest/agent never supplies slack. Passed-in "slack"
# in any envelope call is refused malformed, not read.
ACCOUNTING_SLACK = {
    "fuel_units": 16,
    "memory_bytes": 65536,
    "wall_clock_seconds": 0.5,
}

__all__ = [
    "BudgetLedger",
    "BudgetGuardError",
    "GUEST_BUDGET_AMPLIFIED",
    "GUEST_BUDGET_ENVELOPE_MALFORMED",
    "GUEST_BUDGET_DEADLINE_FIRED",
    "GUEST_BUDGET_SCOPE_UNDECLARED",
    "ACCOUNTING_SLACK",
]


class BudgetGuardError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(BudgetGuardError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise BudgetGuardError(code, detail)


def _positive_number(value, what):
    # bool is rejected explicitly: True == 1 must not pass as fuel.
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value <= 0:
        _refuse(GUEST_BUDGET_ENVELOPE_MALFORMED,
                "%s must be a positive finite number, got %r"
                % (what, value))


def _non_negative_number(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0:
        _refuse(GUEST_BUDGET_ENVELOPE_MALFORMED,
                "%s must be a non-negative finite number, got %r"
                % (what, value))


def _non_empty_str(value, what):
    if not isinstance(value, str) or not value:
        _refuse(GUEST_BUDGET_ENVELOPE_MALFORMED,
                "%s must be a non-empty string, got %r" % (what, value))


class BudgetLedger:
    """Host-side budget envelopes for guest scopes.

    The host declares the envelope, the host measures consumption, and
    this ledger enforces the non-amplification invariant. Per-guest
    scopes are isolated: a scope's envelope can never cover another
    scope's spend.
    """

    def __init__(self, now=None):
        self._now = now if callable(now) else None
        # scope -> {"fuel_units", "memory_bytes",
        #           "wall_clock_seconds", "start", "peak_memory",
        #           "reported_fuel", "terminated"}
        self._envelopes = {}
        self._aggregate = _aggregate_budget.AggregateBudget(
            now=now if callable(now) else None)

    def _t(self):
        import time
        return self._now() if self._now is not None else time.time()

    def _envelope(self, guest_scope):
        env = self._envelopes.get(guest_scope)
        if env is None:
            _refuse(GUEST_BUDGET_SCOPE_UNDECLARED,
                    "no envelope declared for guest scope %r"
                    % (guest_scope,))
        return env

    def _check_terminated(self, guest_scope, env):
        if env["terminated"]:
            _refuse(GUEST_BUDGET_AMPLIFIED,
                    "guest scope %r is terminated; no further spend "
                    "or effect commit is admitted" % (guest_scope,))

    def declare_envelope(self, *, guest_scope, fuel_units, memory_bytes,
                         wall_clock_seconds, **kwargs):
        """The host declares a guest's budget envelope.

        ``kwargs`` exist only to falsify agent-supplied slack: any
        ``slack`` (or anything else unexpected) in the declaration is
        refused malformed, never read.
        """
        if kwargs:
            _refuse(GUEST_BUDGET_ENVELOPE_MALFORMED,
                    "envelope declaration takes no extra parameters; "
                    "got %r" % (sorted(kwargs),))
        _non_empty_str(guest_scope, "guest_scope")
        _positive_number(fuel_units, "fuel_units")
        _positive_number(memory_bytes, "memory_bytes")
        _positive_number(wall_clock_seconds, "wall_clock_seconds")
        if guest_scope in self._envelopes:
            _refuse(GUEST_BUDGET_ENVELOPE_MALFORMED,
                    "guest scope %r already has an envelope; envelopes "
                    "are never renegotiated" % (guest_scope,))
        # The per-guest aggregate cap is declared + slack: a legal
        # measurement inside the accounting tolerance must never trip
        # the aggregate. Per-scope keying is what stops pooling:
        # scope A can never spend scope B's aggregate.
        self._aggregate.declare_scope(
            guest_scope,
            fuel_units + ACCOUNTING_SLACK["fuel_units"],
            window_seconds=wall_clock_seconds)
        self._envelopes[guest_scope] = {
            "fuel_units": float(fuel_units),
            "memory_bytes": float(memory_bytes),
            "wall_clock_seconds": float(wall_clock_seconds),
            "start": self._t(),
            "peak_memory": 0.0,
            "reported_fuel": 0.0,
            "terminated": False,
        }
        return self.state(guest_scope)

    def allocate(self, *, guest_scope, memory_bytes):
        """Pre-allocation check at the allocation point: refuses BEFORE
        the host spends, so a guest cannot drive host memory past the
        envelope (the 0313 shape)."""
        _non_empty_str(guest_scope, "guest_scope")
        env = self._envelope(guest_scope)
        self._check_terminated(guest_scope, env)
        _non_negative_number(memory_bytes, "memory_bytes")
        limit = env["memory_bytes"] + ACCOUNTING_SLACK["memory_bytes"]
        if float(memory_bytes) > limit:
            env["terminated"] = True
            _refuse(GUEST_BUDGET_AMPLIFIED,
                    "guest scope %r requested %r memory bytes against "
                    "an envelope of %r (+ slack %r); refused at the "
                    "allocation point; guest terminated"
                    % (guest_scope, memory_bytes, env["memory_bytes"],
                       ACCOUNTING_SLACK["memory_bytes"]))
        if float(memory_bytes) > env["peak_memory"]:
            env["peak_memory"] = float(memory_bytes)
        return self.state(guest_scope)

    def report_consumption(self, *, guest_scope, fuel_units,
                           memory_bytes, elapsed_seconds):
        """The host reports measured consumption. Any dimension beyond
        declared + slack terminates the guest with
        ``guest-budget-amplified`` (wall-clock blowout refuses
        ``guest-budget-deadline-fired``)."""
        _non_empty_str(guest_scope, "guest_scope")
        env = self._envelope(guest_scope)
        self._check_terminated(guest_scope, env)
        _non_negative_number(fuel_units, "fuel_units")
        _non_negative_number(memory_bytes, "memory_bytes")
        _non_negative_number(elapsed_seconds, "elapsed_seconds")
        if float(elapsed_seconds) > env["wall_clock_seconds"] + \
                ACCOUNTING_SLACK["wall_clock_seconds"]:
            env["terminated"] = True
            _refuse(GUEST_BUDGET_DEADLINE_FIRED,
                    "guest scope %r blew its %r s wall-clock bound "
                    "(elapsed %r s); guest terminated; in-flight "
                    "effects are NOT committed"
                    % (guest_scope, env["wall_clock_seconds"],
                       elapsed_seconds))
        if float(fuel_units) > env["fuel_units"] + \
                ACCOUNTING_SLACK["fuel_units"]:
            env["terminated"] = True
            _refuse(GUEST_BUDGET_AMPLIFIED,
                    "guest scope %r measured %r fuel units against an "
                    "envelope of %r (+ slack %r); guest terminated, "
                    "never re-budgeted"
                    % (guest_scope, fuel_units, env["fuel_units"],
                       ACCOUNTING_SLACK["fuel_units"]))
        if float(memory_bytes) > env["memory_bytes"] + \
                ACCOUNTING_SLACK["memory_bytes"]:
            env["terminated"] = True
            _refuse(GUEST_BUDGET_AMPLIFIED,
                    "guest scope %r measured %r memory bytes against "
                    "an envelope of %r (+ slack %r); guest terminated"
                    % (guest_scope, memory_bytes, env["memory_bytes"],
                       ACCOUNTING_SLACK["memory_bytes"]))
        if float(memory_bytes) > env["peak_memory"]:
            env["peak_memory"] = float(memory_bytes)
        # Host-measured fuel charges the per-guest aggregate as a
        # DELTA from the previously reported measurement: reports are
        # cumulative host readings, charging each one in full would
        # double-count. A zero or non-increasing report charges
        # nothing (the aggregate ledger only tracks positive amounts).
        delta = float(fuel_units) - env["reported_fuel"]
        if delta > 0:
            try:
                self._aggregate.charge(
                    guest_scope, "guest-budget-guard",
                    uuid.uuid4().hex, delta)
            except _aggregate_budget.AggregateBudgetError as exc:
                env["terminated"] = True
                _refuse(GUEST_BUDGET_AMPLIFIED,
                        "guest scope %r aggregate charge refused (%s); "
                        "guest terminated" % (guest_scope, exc.code))
        env["reported_fuel"] = float(fuel_units)
        return self.state(guest_scope)

    def check_deadline(self, *, guest_scope, elapsed_seconds):
        """Explicit wall-clock check: host deadline fires fail-closed;
        in-flight effects are never committed after it."""
        _non_empty_str(guest_scope, "guest_scope")
        env = self._envelope(guest_scope)
        self._check_terminated(guest_scope, env)
        _non_negative_number(elapsed_seconds, "elapsed_seconds")
        if float(elapsed_seconds) > env["wall_clock_seconds"] + \
                ACCOUNTING_SLACK["wall_clock_seconds"]:
            env["terminated"] = True
            _refuse(GUEST_BUDGET_DEADLINE_FIRED,
                    "guest scope %r deadline fired at %r s against a "
                    "%r s bound; guest terminated; in-flight effects "
                    "are NOT committed"
                    % (guest_scope, elapsed_seconds,
                       env["wall_clock_seconds"]))
        return self.state(guest_scope)

    def commit_effect(self, *, guest_scope, effect):
        """Commit a guest effect. On a terminated scope this refuses:
        a blown guest's effects are never partially committed."""
        _non_empty_str(guest_scope, "guest_scope")
        env = self._envelope(guest_scope)
        self._check_terminated(guest_scope, env)
        return {"guest_scope": guest_scope,
                "committed": True,
                "effect": effect}

    def state(self, guest_scope):
        """Envelope + measured-peak state. Terminated flag included."""
        env = self._envelope(guest_scope)
        return {
            "guest_scope": guest_scope,
            "fuel_units": env["fuel_units"],
            "memory_bytes": env["memory_bytes"],
            "wall_clock_seconds": env["wall_clock_seconds"],
            "peak_memory": env["peak_memory"],
            "reported_fuel": env["reported_fuel"],
            "terminated": env["terminated"],
            "aggregate": self._aggregate.state(guest_scope),
        }
