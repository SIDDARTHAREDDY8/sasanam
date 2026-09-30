"""Cumulative cross-act budget keyed by (scope, window).

Wave-242 lane A (W242-1, das EP-14 adapted).

The per-(iss, jti) ``BudgetLedger`` in ``gov.bound_permit`` cannot see
N individually-permitted acts composing into an impermissible
aggregate. ``AggregateBudget`` is the cross-act complement: the
deployment declares a cap per scope per window, and every act charges
its amount against the aggregate. A charge that would push the
aggregate past the cap refuses ``aggregate-budget-exhausted`` even
though the act's own permit is individually within budget.

Window semantics: each scope has a fixed-length window. When a
charge (or an explicit ``roll_window``) observes the window expired,
the aggregate total resets to zero and a new window opens. The
per-(iss, jti) charge entries PERSIST across rollover: a permit
already charged is never re-chargeable
(``aggregate-budget-already-charged``), while a new permit may spend
again in the new window. Aggregate total and per-permit entries are
separate books; window rollover releases one without releasing the
other.

Charging an undeclared scope refuses
``aggregate-budget-scope-undeclared``; non-positive caps or windows,
non-positive/non-numeric amounts refuse
``aggregate-budget-malformed``.

Honest boundaries: this ledger is in-memory and single-node; shared
accounting across nodes is deployment-owned. Amounts are plain
numbers (int/float); currency/unit semantics belong to the
deployment's scope declarations.

Stdlib only. Deterministic (injectable clock for tests).
"""

import math
import os
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

__all__ = [
    "AggregateBudget",
    "AggregateBudgetError",
    "EXHAUSTED",
    "SCOPE_UNDECLARED",
    "MALFORMED",
    "ALREADY_CHARGED",
]

EXHAUSTED = "aggregate-budget-exhausted"
SCOPE_UNDECLARED = "aggregate-budget-scope-undeclared"
MALFORMED = "aggregate-budget-malformed"
ALREADY_CHARGED = "aggregate-budget-already-charged"


class AggregateBudgetError(Exception):
    """Base class for aggregate-budget refusals. Subclasses set the
    machine-readable ``code``."""

    code = None


class _AggregateBudgetExhausted(AggregateBudgetError):
    code = EXHAUSTED


class _AggregateBudgetScopeUndeclared(AggregateBudgetError):
    code = SCOPE_UNDECLARED


class _AggregateBudgetMalformed(AggregateBudgetError):
    code = MALFORMED


class _AggregateBudgetAlreadyCharged(AggregateBudgetError):
    code = ALREADY_CHARGED


def _positive_number(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value <= 0:
        raise _AggregateBudgetMalformed(
            "%s: %s must be a positive finite number, got %r"
            % (MALFORMED, what, value))


def _non_empty_str(value, what):
    if not isinstance(value, str) or not value:
        raise _AggregateBudgetMalformed(
            "%s: %s must be a non-empty string, got %r"
            % (MALFORMED, what, value))


class AggregateBudget:
    """Cumulative cross-act budget keyed by (scope, window)."""

    def __init__(self, now=None):
        self._now = now if callable(now) else time.time
        self._scopes = {}  # scope -> {"cap", "window_seconds",
        #                    "window_start", "aggregate_total"}
        self._entries = {}  # (scope, iss, jti) -> amount

    def declare_scope(self, scope, cap, *, window_seconds):
        """Declare an aggregate cap for a scope. Idempotent on the
        SAME declaration values is NOT allowed: re-declaration
        refuses ``aggregate-budget-malformed`` (a cap change mid-wave
        is a deployment decision, not a runtime mutation)."""
        _non_empty_str(scope, "scope")
        _positive_number(cap, "cap")
        _positive_number(window_seconds, "window_seconds")
        if scope in self._scopes:
            raise _AggregateBudgetMalformed(
                "%s: scope %r is already declared" % (MALFORMED, scope))
        self._scopes[scope] = {
            "cap": float(cap),
            "window_seconds": float(window_seconds),
            "window_start": self._now(),
            "aggregate_total": 0.0,
        }
        return dict(self._scopes[scope])

    def _maybe_roll(self, scope):
        cfg = self._scopes[scope]
        if self._now() >= cfg["window_start"] + cfg["window_seconds"]:
            cfg["window_start"] = self._now()
            cfg["aggregate_total"] = 0.0
            return True
        return False

    def charge(self, scope, iss, jti, amount):
        """Charge ``amount`` against the scope's aggregate. Refuses
        ``aggregate-budget-exhausted`` when the aggregate would exceed
        the cap; ``aggregate-budget-already-charged`` when this
        (iss, jti) was already charged in this scope (no replay)."""
        cfg = self._scopes.get(scope)
        if cfg is None:
            raise _AggregateBudgetScopeUndeclared(
                "%s: scope %r was never declared"
                % (SCOPE_UNDECLARED, scope))
        _non_empty_str(iss, "iss")
        _non_empty_str(jti, "jti")
        _positive_number(amount, "amount")
        self._maybe_roll(scope)
        key = (scope, iss, jti)
        if key in self._entries:
            raise _AggregateBudgetAlreadyCharged(
                "%s: (%r, %r, %r) was already charged in this scope"
                % (ALREADY_CHARGED, scope, iss, jti))
        if cfg["aggregate_total"] + amount > cfg["cap"]:
            raise _AggregateBudgetExhausted(
                "%s: charging %r would push scope %r past its cap %r "
                "(aggregate total %r)"
                % (EXHAUSTED, amount, scope, cfg["cap"],
                   cfg["aggregate_total"]))
        self._entries[key] = float(amount)
        cfg["aggregate_total"] += float(amount)
        return {
            "scope": scope,
            "iss": iss,
            "jti": jti,
            "amount": float(amount),
            "aggregate_total": cfg["aggregate_total"],
            "cap": cfg["cap"],
        }

    def roll_window(self, scope):
        """Close the current window and open a new one: the aggregate
        total resets to zero. Per-(iss, jti) entries PERSIST -- this
        releases the aggregate, not the per-permit book."""
        cfg = self._scopes.get(scope)
        if cfg is None:
            raise _AggregateBudgetScopeUndeclared(
                "%s: scope %r was never declared"
                % (SCOPE_UNDECLARED, scope))
        cfg["window_start"] = self._now()
        cfg["aggregate_total"] = 0.0
        return dict(cfg)

    def state(self, scope):
        """The scope's aggregate state (copy). Per-permit entries are
        not exposed here; the aggregate total is the policy surface."""
        cfg = self._scopes.get(scope)
        if cfg is None:
            raise _AggregateBudgetScopeUndeclared(
                "%s: scope %r was never declared"
                % (SCOPE_UNDECLARED, scope))
        return dict(cfg)
