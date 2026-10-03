"""Wave-278 F299 closure battery (break-first audit of the fix).

F299 (LOW): TripFatigueTracker.note_trip's docstring promises "a non-int
`now` starts a fresh window rather than raising", but the implementation
computed window=None for any non-int now (e.g. float time.time()), so
every call shared one eternal window: after full_events_per_window trips
the gateway emitted compact summaries forever and per-trip forensic
detail was never restored. The denial itself is never suppressed
(enforce() does not consult the tracker) -- evidence-granularity
degradation, not a bypass.

Close-when criteria (from the F299 entry):
  (1) a non-int `now` either starts a genuinely fresh window (e.g. coerce
      int(now)) or is refused loudly -- matching the documented contract;
  (2) probe dc-fatigue-float-eternal flips to HELD;
  (3) int-`now` windowing unchanged;
  (4) adjacent battery evals/w276_decoy_probes.py stays green.

The fix (gov/decoy_grants.py): a total _window_of() helper -- finite
floats coerce via int() so window ids match their int counterparts;
bools, non-finite floats, and non-numeric `now` start a fresh window per
call (the docstring's promise); never raises (total on hostile input).

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed inputs, no random);
fresh unique /var/tmp/g278* TMPDIR (`mkdir -p` first); depth-1 green
checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib
only.
"""

import math
import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g278-f299-%d-" % os.getpid(), dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import decoy_grants as dg  # noqa: E402

TAXONOMY_PIN = 1780  # Wave-277 merge pin; this lane adds no codes.; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)
GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


def _new_tracker():
    return dg.TripFatigueTracker(window_s=300, full_events_per_window=5)


# ---------------------------------------------------------------------------
# F299: the defect
# ---------------------------------------------------------------------------

def f299a_float_rolls():
    """Float `now` at 400s intervals falls in fresh windows (the F299
    defect: on base, window=None is eternal, so trips 6-12 emit compact
    summaries forever and window_count climbs to 12)."""
    t = _new_tracker()
    res = [t.note_trip(decoy="admin_shell", agent_key="agent-1",
                       now=100.0 + i * 400.0) for i in range(12)]
    if all(r["emit_full"] for r in res):
        return "HELD", "float now rolls windows (F299 fixed)"
    if (all(not r["emit_full"] for r in res[5:])
            and res[-1]["window_count"] == 12):
        return ("BREAK", "F299: float now -> eternal window; "
                "emit_full=False forever after 5 trips (window_count=%d)"
                % res[-1]["window_count"])
    return "HELD", "unexpected tracker shape: %r" % (res[-1],)


def f299b_int_unchanged():
    """Int `now` windowing is unchanged (defense pin; holds on base)."""
    t = _new_tracker()
    res = [t.note_trip(decoy="admin_shell", agent_key="agent-1",
                       now=100 + i * 400) for i in range(12)]
    if all(r["emit_full"] and r["window_count"] == 1 for r in res):
        return "HELD", "int now: 12 trips, 12 fresh windows, all full"
    return "BREAK", "int-now windowing changed: %r" % (res,)


def f299c_float_int_parity():
    """Floats in one window compact exactly like ints in the same window:
    first 5 full, then compact with window_count == 6."""
    seq_f = [1000.0, 1100.5, 1199.9, 1000.1, 1150.25, 1100.75]
    seq_i = [1000, 1100, 1199, 1000, 1150, 1100]
    tf, ti = _new_tracker(), _new_tracker()
    rf = [tf.note_trip(decoy="d", agent_key="a", now=n) for n in seq_f]
    ri = [ti.note_trip(decoy="d", agent_key="a", now=n) for n in seq_i]
    shape_f = [(r["emit_full"], r["window_count"]) for r in rf]
    shape_i = [(r["emit_full"], r["window_count"]) for r in ri]
    want = [(True, 1), (True, 2), (True, 3), (True, 4), (True, 5),
            (False, 6)]
    if shape_f == want and shape_i == want:
        return "HELD", "float/int same-window parity; compaction at 6th"
    return "BREAK", "parity/shape mismatch float=%r int=%r" % (shape_f,
                                                             shape_i)


def f299d_nonnumeric_fresh():
    """Non-numeric `now` starts a fresh window per call (the docstring's
    promise; on base it joins the eternal window)."""
    t = _new_tracker()
    res = [t.note_trip(decoy="d", agent_key="a",
                       now="2026-10-01T00:00:00+00:00")
           for _ in range(8)]
    if all(r["emit_full"] and r["window_count"] == 1 for r in res):
        return "HELD", "non-numeric now: fresh window per call"
    return ("BREAK", "non-numeric now joined an eternal window: %r"
            % (res[-1],))


def f299e_bool_fresh():
    """Bool `now` is excluded from int windowing and starts a fresh
    window per call (docstring: non-int now)."""
    t = _new_tracker()
    res = [t.note_trip(decoy="d", agent_key="a", now=True)
           for _ in range(8)]
    if all(r["emit_full"] and r["window_count"] == 1 for r in res):
        return "HELD", "bool now: fresh window per call"
    return "BREAK", "bool now joined an eternal window: %r" % (res[-1],)


def f299f_nonfinite_total():
    """Non-finite floats never raise (total on hostile input) and start
    fresh windows rather than collapsing into one."""
    t = _new_tracker()
    res = [t.note_trip(decoy="d", agent_key="a", now=n)
           for n in (math.nan, math.inf, -math.inf, math.nan)]
    if all(r["emit_full"] and r["window_count"] == 1 for r in res):
        return "HELD", "nan/inf: no raise, fresh window per call"
    return "BREAK", "non-finite now mishandled: %r" % (res[-1],)


def f299g_negative_float_parity():
    """Negative floats coerce via int() exactly like their int
    counterparts (truncation toward zero, then floor division)."""
    tf, ti = _new_tracker(), _new_tracker()
    rf = [tf.note_trip(decoy="d", agent_key="a", now=n)
          for n in (-1.5, -1.9, -400.5)]
    ri = [ti.note_trip(decoy="d", agent_key="a", now=n)
          for n in (-1, -1, -400)]
    shape_f = [(r["emit_full"], r["window_count"]) for r in rf]
    shape_i = [(r["emit_full"], r["window_count"]) for r in ri]
    # -1.5 and -1.9 truncate to -1: same window as int -1 (count 1,2);
    # -400.5 truncates to -400: same window as int -400 (count 1).
    want_f = [(True, 1), (True, 2), (True, 1)]
    want_i = [(True, 1), (True, 2), (True, 1)]
    if shape_f == want_f and shape_i == want_i:
        return "HELD", "negative float/int parity via int() coercion"
    return "BREAK", "negative parity mismatch float=%r int=%r" % (shape_f,
                                                                shape_i)


def f299h_fatigue_still_compacts():
    """The fatigue discipline survives the fix: rapid int trips in one
    window still compact after full_events_per_window (the canary's
    anti-log-DoS property is intact)."""
    t = _new_tracker()
    res = [t.note_trip(decoy="d", agent_key="a", now=100 + i)
           for i in range(8)]
    if (all(r["emit_full"] for r in res[:5])
            and not any(r["emit_full"] for r in res[5:])
            and res[-1]["suppressed"] == 3):
        return "HELD", "same-window trips compact after 5 (anti-log-DoS)"
    return "BREAK", "fatigue discipline broken: %r" % (res[-1],)


PROBES = [
    ("f299a-float-rolls", "HELD", f299a_float_rolls),
    ("f299b-int-unchanged", "HELD", f299b_int_unchanged),
    ("f299c-float-int-parity", "HELD", f299c_float_int_parity),
    ("f299d-nonnumeric-fresh", "HELD", f299d_nonnumeric_fresh),
    ("f299e-bool-fresh", "HELD", f299e_bool_fresh),
    ("f299f-nonfinite-total", "HELD", f299f_nonfinite_total),
    ("f299g-negative-float-parity", "HELD", f299g_negative_float_parity),
    ("f299h-fatigue-still-compacts", "HELD", f299h_fatigue_still_compacts),
]


def green_check():
    """Depth-1: run the adjacent wave-276 decoy battery with
    GOV_SKIP_GREEN=1 in the child env (never recurse)."""
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "skip")]
    results = []
    adjacent = [
        (["evals/w276_decoy_probes.py"], "w276_decoy"),
    ]
    for argv, name in adjacent:
        tmp = tempfile.mkdtemp(prefix="g278-green-%s-" % name, dir="/var/tmp")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        try:
            p = subprocess.run(
                [sys.executable] + argv, cwd=REPO, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=600, text=True)
            tail = p.stdout.strip().splitlines()
            summary = tail[-1] if tail else ""
            ok = (p.returncode == 0 and "0 failures" in p.stdout)
            results.append((name, "HELD" if ok else "BREAK",
                            "rc=%d %s" % (p.returncode, summary[:160])))
        except Exception as exc:  # noqa: BLE001
            results.append((name, "BREAK", "%s" % exc))
    return results


def main():
    pin_verdict, pin_note = _pin_check()
    _RESULTS.append(("pin-taxonomy-1493", "HELD", pin_verdict,
                     pin_verdict == "HELD", pin_note))
    for pid, expected, fn in PROBES:
        _run(pid, expected, fn)
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    n_mismatch = sum(1 for r in _RESULTS if not r[3])
    for pid, expected, verdict, ok, note in _RESULTS:
        print("[%s] %-28s expected=%-5s got=%-5s %s"
              % ("ok " if ok else "FAIL", pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in green_check():
        print("[%s] %s %s" % ("ok " if verdict == "HELD" else "FAIL",
                              name, note))
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, n_mismatch))
    return 0 if (n_err == 0 and n_mismatch == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
