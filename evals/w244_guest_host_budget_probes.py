"""Wave-244 guest->host budget non-amplification probes (W244-3, red-first).

ADAPT of the RustSec 0311-0316 wasmtime guest->host cluster (Sept 2026:
fuel amplification, memory exhaustion, host panic), patterns only --
no upstream code vendored or imported, no advisory text copied. The
wasmtime lesson: the meter must be outside the guest's reach.

  fuel-amplification-refused -- guest declares fuel 100, host measures
      150 -> refused guest-budget-amplified; guest TERMINATED, not
      re-budgeted; effect commit on the terminated scope refuses.
  memory-exhaustion-refused-at-allocation -- allocation beyond the
      declared envelope is refused AT THE ALLOCATION POINT, before
      the host spends (the 0313 shape).
  wall-clock-blowout-no-commit -- host deadline fires past the bound ->
      refused guest-budget-deadline-fired; in-flight effects are NOT
      committed (fail closed, never partial-commit).
  exact-envelope-passes -- declared N, measured exactly N -> passes;
      the guard is a bound, not a hair-trigger.
  slack-tolerance-accepted -- declared N, measured N + slack -> passes;
      a measurement inside the declared tolerance is legal spend.
  slack-is-declared-constant -- the accounting slack is a module-level
      constant, never agent-supplied: an envelope declaration that
      tries to supply its own slack is refused
      guest-budget-envelope-malformed.
  no-pooling-between-guests -- two guests A (fuel 50) and B (fuel 50):
      A blows its envelope -> A terminated; B is unaffected and its
      own envelope still admits; the per-guest aggregates are isolated
      (A's overrun never spends B's budget).
  re-declaration-never-negotiated -- a second envelope for the same
      scope is refused envelope-malformed: envelopes are never
      renegotiated, and termination is sticky.

Stdlib only (+ in-repo gov.aggregate_budget, reused not duplicated).
Deterministic: injectable clock. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_GB = False
try:
    from gov import guest_budget_guard as _gb
    HAVE_GB = all(hasattr(_gb, n) for n in (
        "BudgetLedger", "BudgetGuardError", "ACCOUNTING_SLACK",
        "GUEST_BUDGET_AMPLIFIED", "GUEST_BUDGET_ENVELOPE_MALFORMED",
        "GUEST_BUDGET_DEADLINE_FIRED",
        "GUEST_BUDGET_SCOPE_UNDECLARED"))
except ImportError:
    _gb = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "fuel-amplification-refused",
    "memory-exhaustion-refused-at-allocation",
    "wall-clock-blowout-no-commit",
    "exact-envelope-passes",
    "slack-tolerance-accepted",
    "slack-is-declared-constant",
    "no-pooling-between-guests",
    "re-declaration-never-negotiated",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect(code, fn):
    try:
        fn()
    except _gb.BudgetGuardError as exc:
        assert exc.code == code, "code %r != %r" % (exc.code, code)
        return exc
    raise AssertionError("expected BudgetGuardError %r; allowed" % (code,))


def _ledger():
    return _gb.BudgetLedger(now=lambda: 1000.0)


def _p_fuel_amplification():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-a", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    _expect("guest-budget-amplified", lambda: g.report_consumption(
        guest_scope="guest-a", fuel_units=150,
        memory_bytes=1 << 19, elapsed_seconds=1.0))
    assert g.state("guest-a")["terminated"] is True, "not terminated"
    _expect("guest-budget-amplified", lambda: g.commit_effect(
        guest_scope="guest-a", effect={"op": "write"}))
    # No re-budgeting: a fresh envelope on the same scope is refused.
    _expect("guest-budget-envelope-malformed", lambda: g.declare_envelope(
        guest_scope="guest-a", fuel_units=10 ** 9,
        memory_bytes=1 << 20, wall_clock_seconds=10))
    return "150 fuel vs 100 declared: refused, terminated, sticky"


def _p_memory_allocation():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-b", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    # Within the declared tolerance: admitted.
    g.allocate(guest_scope="guest-b", memory_bytes=1 << 20)
    # Beyond declared + slack: refused at the allocation point.
    _expect("guest-budget-amplified", lambda: g.allocate(
        guest_scope="guest-b",
        memory_bytes=(1 << 20) + _gb.ACCOUNTING_SLACK["memory_bytes"] + 1))
    assert g.state("guest-b")["terminated"] is True, "not terminated"
    return "2x allocation refused at the allocation point"


def _p_wall_clock():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-c", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    _expect("guest-budget-deadline-fired", lambda: g.check_deadline(
        guest_scope="guest-c", elapsed_seconds=60.0))
    assert g.state("guest-c")["terminated"] is True, "not terminated"
    _expect("guest-budget-amplified", lambda: g.commit_effect(
        guest_scope="guest-c", effect={"op": "write"}))
    return "60s vs 10s bound: deadline fired, effects uncommitted"


def _p_exact_envelope():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-d", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    st = g.report_consumption(guest_scope="guest-d", fuel_units=100,
                              memory_bytes=1 << 20, elapsed_seconds=10.0)
    assert st["terminated"] is False, "exact use must pass"
    out = g.commit_effect(guest_scope="guest-d", effect={"op": "read"})
    assert out["committed"] is True, "commit must succeed"
    return "declared N, measured exactly N: admitted"


def _p_slack_tolerance():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-e", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    slack = _gb.ACCOUNTING_SLACK
    st = g.report_consumption(
        guest_scope="guest-e",
        fuel_units=100 + slack["fuel_units"],
        memory_bytes=(1 << 20) + slack["memory_bytes"],
        elapsed_seconds=10.0 + slack["wall_clock_seconds"])
    assert st["terminated"] is False, "in-tolerance use must pass"
    return "N + declared slack: legal spend, not amplification"


def _p_slack_constant():
    g = _ledger()
    _expect("guest-budget-envelope-malformed",
            lambda: g.declare_envelope(
                guest_scope="guest-f", fuel_units=100,
                memory_bytes=1 << 20, wall_clock_seconds=10,
                slack={"fuel_units": 10 ** 9}))
    slack = _gb.ACCOUNTING_SLACK
    assert isinstance(slack, dict), "slack must be a module constant"
    assert slack["fuel_units"] == 16, "slack value must be declared"
    return "agent-supplied slack refused malformed; constant is 16/64KiB/0.5s"


def _p_no_pooling():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-a1", fuel_units=50,
                       memory_bytes=1 << 20, wall_clock_seconds=60)
    g.declare_envelope(guest_scope="guest-b1", fuel_units=50,
                       memory_bytes=1 << 20, wall_clock_seconds=60)
    g.report_consumption(guest_scope="guest-b1", fuel_units=40,
                         memory_bytes=1 << 19, elapsed_seconds=1.0)
    _expect("guest-budget-amplified", lambda: g.report_consumption(
        guest_scope="guest-a1", fuel_units=500,
        memory_bytes=1 << 19, elapsed_seconds=1.0))
    assert g.state("guest-a1")["terminated"] is True
    assert g.state("guest-b1")["terminated"] is False
    # B's aggregate only ever saw B's own charges: isolation holds.
    b_agg = g.state("guest-b1")["aggregate"]["aggregate_total"]
    a_agg = g.state("guest-a1")["aggregate"]["aggregate_total"]
    assert b_agg == 40.0, "B aggregate polluted: %r" % (b_agg,)
    assert a_agg == 0.0, "A aggregate charged before termination: %r" % (
        a_agg,)
    # B can still spend and commit; A cannot.
    g.report_consumption(guest_scope="guest-b1", fuel_units=45,
                         memory_bytes=1 << 19, elapsed_seconds=2.0)
    assert g.commit_effect(guest_scope="guest-b1",
                           effect={"op": "ok"})["committed"] is True
    _expect("guest-budget-amplified", lambda: g.commit_effect(
        guest_scope="guest-a1", effect={"op": "write"}))
    return "A terminated; B isolated, still spends and commits"


def _p_no_renegotiation():
    g = _ledger()
    g.declare_envelope(guest_scope="guest-g", fuel_units=100,
                       memory_bytes=1 << 20, wall_clock_seconds=10)
    _expect("guest-budget-envelope-malformed",
            lambda: g.declare_envelope(
                guest_scope="guest-g", fuel_units=10 ** 9,
                memory_bytes=1 << 20, wall_clock_seconds=10))
    # Malformed declarations also refuse: bool is not fuel.
    _expect("guest-budget-envelope-malformed",
            lambda: g.declare_envelope(
                guest_scope="guest-h", fuel_units=True,
                memory_bytes=1 << 20, wall_clock_seconds=10))
    _expect("guest-budget-scope-undeclared",
            lambda: g.report_consumption(
                guest_scope="never-declared", fuel_units=1,
                memory_bytes=1, elapsed_seconds=0.1))
    return "envelopes never renegotiated; bool rejected; unknown scope fails"


_PROBES = {
    "fuel-amplification-refused": (_p_fuel_amplification, HAVE_GB),
    "memory-exhaustion-refused-at-allocation": (_p_memory_allocation,
                                               HAVE_GB),
    "wall-clock-blowout-no-commit": (_p_wall_clock, HAVE_GB),
    "exact-envelope-passes": (_p_exact_envelope, HAVE_GB),
    "slack-tolerance-accepted": (_p_slack_tolerance, HAVE_GB),
    "slack-is-declared-constant": (_p_slack_constant, HAVE_GB),
    "no-pooling-between-guests": (_p_no_pooling, HAVE_GB),
    "re-declaration-never-negotiated": (_p_no_renegotiation, HAVE_GB),
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("guest-budget-amplified",
                     "guest-budget-envelope-malformed",
                     "guest-budget-deadline-fired",
                     "guest-budget-scope-undeclared"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-244 guest->host budget probes (guest_budget_guard: %s)"
          % (HAVE_GB,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
