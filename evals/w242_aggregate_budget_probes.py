"""Wave-242 aggregate-budget control probes (W242-1, red-first).

das EP-14 (adapted): our per-(iss, jti) BudgetLedger cannot see N
individually-permitted acts composing into an impermissible
aggregate. ``gov.aggregate_budget.AggregateBudget`` is a cumulative
cross-act budget keyed by (scope, window): it refuses
``aggregate-budget-exhausted`` when the aggregate would exceed the
cap even though each act is within its own budget.

Probes:
  aggregate-ten-permits-exhausts-cap -- declare cap 100 / window
      3600; charge ten permits of 10 each -> the aggregate fills to
      exactly the cap (exact-cap charge passes: exhaustion is
      strictly-greater); an 11th charge refuses
      aggregate-budget-exhausted; re-charging any earlier jti refuses
      aggregate-budget-already-charged (none re-executable after).
  aggregate-split-jti-still-refused -- one act split into two permits
      with different jtis under the same (iss, scope): charge jti-A
      60, then jti-B 60 under cap 100 -> the second charge refuses
      aggregate-budget-exhausted (falsifies jti-scoped-only
      accounting).
  aggregate-window-rollover-releases-total -- charge 90 of cap 100,
      advance the clock past the window, roll: aggregate total
      resets, a NEW jti charging 90 passes, but re-charging an old
      jti still refuses aggregate-budget-already-charged
      (per-permit entries persist across rollover; falsifies
      shared-entry confusion).
  aggregate-undeclared-scope-refused -- charging a scope that was
      never declared refuses aggregate-budget-scope-undeclared.
  aggregate-malformed-charge-refused -- zero, negative, and
      non-numeric amounts refuse aggregate-budget-malformed; a
      non-positive cap refuses at declare time.

Stdlib only. Deterministic (injectable clock). No in-repo git
subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import aggregate_budget as _ab
    HAVE_NEW_API = all(hasattr(_ab, n) for n in (
        "AggregateBudget", "AggregateBudgetError"))
except ImportError:
    _ab = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "aggregate-ten-permits-exhausts-cap",
    "aggregate-split-jti-still-refused",
    "aggregate-window-rollover-releases-total",
    "aggregate-undeclared-scope-refused",
    "aggregate-malformed-charge-refused",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_code(fn, code):
    """fn must raise AggregateBudgetError with .code == code."""
    try:
        fn()
    except _ab.AggregateBudgetError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


class _Clock(object):
    """Deterministic injectable clock (seconds)."""

    def __init__(self, start=1_000_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_ten_permits_exhausts_cap():
    clock = _Clock()
    agg = _ab.AggregateBudget(now=clock)
    agg.declare_scope("deploy", 100, window_seconds=3600)
    for n in range(10):
        entry = agg.charge("deploy", "iss-a", "jti-%02d" % n, 10)
        assert entry["aggregate_total"] == (n + 1) * 10, entry
    # Cap filled exactly: the 11th charge exceeds and refuses.
    note = _expect_code(
        lambda: agg.charge("deploy", "iss-a", "jti-10", 1),
        "aggregate-budget-exhausted")
    # None re-executable after: every earlier jti refuses duplicate.
    for n in range(10):
        _expect_code(
            lambda: agg.charge("deploy", "iss-a", "jti-%02d" % n, 10),
            "aggregate-budget-already-charged")
    return "%s; 10 charged, 11th refused, replays refused" % note


def _probe_split_jti_still_refused():
    clock = _Clock()
    agg = _ab.AggregateBudget(now=clock)
    agg.declare_scope("deploy", 100, window_seconds=3600)
    agg.charge("deploy", "iss-a", "jti-split-A", 60)
    note = _expect_code(
        lambda: agg.charge("deploy", "iss-a", "jti-split-B", 60),
        "aggregate-budget-exhausted")
    return "%s (different jti, same scope)" % note


def _probe_window_rollover_releases_total():
    clock = _Clock()
    agg = _ab.AggregateBudget(now=clock)
    agg.declare_scope("deploy", 100, window_seconds=60)
    agg.charge("deploy", "iss-a", "jti-old", 90)
    clock.advance(61)  # past the window
    rolled = agg.roll_window("deploy")
    assert rolled["aggregate_total"] == 0, rolled
    # Aggregate released: a NEW jti can charge again.
    entry = agg.charge("deploy", "iss-a", "jti-new", 90)
    assert entry["aggregate_total"] == 90, entry
    # But the per-permit entry persisted: old jti still refused.
    note = _expect_code(
        lambda: agg.charge("deploy", "iss-a", "jti-old", 10),
        "aggregate-budget-already-charged")
    return "%s; aggregate reset, entries persisted" % note


def _probe_undeclared_scope_refused():
    clock = _Clock()
    agg = _ab.AggregateBudget(now=clock)
    note = _expect_code(
        lambda: agg.charge("never-declared", "iss-a", "jti-1", 10),
        "aggregate-budget-scope-undeclared")
    return note


def _probe_malformed_charge_refused():
    clock = _Clock()
    agg = _ab.AggregateBudget(now=clock)
    agg.declare_scope("deploy", 100, window_seconds=3600)
    for bad in (0, -5, "ten", None, float("nan")):
        _expect_code(
            lambda bad=bad: agg.charge("deploy", "iss-a", "jti-bad", bad),
            "aggregate-budget-malformed")
    _expect_code(lambda: agg.declare_scope("bad", 0, window_seconds=60),
                 "aggregate-budget-malformed")
    _expect_code(lambda: agg.declare_scope("bad2", 100, window_seconds=0),
                 "aggregate-budget-malformed")
    return "zero/negative/non-numeric refused; bad caps refused"


_PROBES = {
    "aggregate-ten-permits-exhausts-cap": _probe_ten_permits_exhausts_cap,
    "aggregate-split-jti-still-refused": _probe_split_jti_still_refused,
    "aggregate-window-rollover-releases-total":
        _probe_window_rollover_releases_total,
    "aggregate-undeclared-scope-refused": _probe_undeclared_scope_refused,
    "aggregate-malformed-charge-refused": _probe_malformed_charge_refused,
}


def main():
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, s, _ in results if s == "HELD")
    gap = sum(1 for _, s, _ in results if s == "GAP")
    for name, status, note in results:
        print("%s %s: %s" % (status, name, note.splitlines()[0]))
    print("w242-aggregate-budget: %d HELD / %d GAP / %d total"
          % (held, gap, len(results)))
    return 0 if all(s in ("HELD", "GAP") for _, s, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
