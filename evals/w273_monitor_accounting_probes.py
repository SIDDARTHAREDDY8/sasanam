"""Wave-273 monitor-but-count verdict accounting battery.

Tests the monitor-but-count verdict accounting added to
gov/gate_hardening.py: each protect enforcement point has a mirrored
monitor-path counter (per-code would-deny counts + a would-allow
count), and the audit scanner reports "what protect would deny today"
with counts. Pattern is Tetragon's observe-first graduation
discipline, reimplemented stdlib-only.

Red-first: on the wave-273 base these probes BREAK (no accounting API);
they flip to HELD with the implementation. Probes m01-m09 are the
accounting contract; x01/x02 are informational foils documenting the
HONEST LIMIT (in-process, verdict-level counting, not kernel
enforcement).

Deterministic: explicit now/clock everywhere. Module-level staging
default. Depth-1 green check honoring GOV_SKIP_GREEN. No in-repo git
subprocesses. The green check uses a mkdtemp TMPDIR (no sandbox jails
in this battery, so the /var/tmp chown convention does not apply).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess  # noqa: E402
import tempfile  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import gate_hardening as gh  # noqa: E402

TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


NOW = 1700000000

RESULTS = []


def _policy(predicate, policy_id="p", deadline_s=None, callbacks=()):
    return gh.compile_policy({
        "policy_id": policy_id,
        "predicate_name": getattr(predicate, "__name__", "p"),
        "predicate": predicate,
        "deadline_s": deadline_s,
        "host_callbacks": list(callbacks),
    })


class _Clock(object):
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _gate(**kw):
    kw.setdefault("global_deadline_s", 60.0)
    kw.setdefault("now", lambda: NOW)
    return gh.Gate(**kw)


def _mon_gate(**kw):
    """Build a monitor-mode gate; returns (gate, None) on this tree or
    (None, break-detail) when the accounting API is absent (red on base).
    """
    g = _gate(mode="monitor", **kw)
    if not hasattr(g, "monitor_deny_counts")\
            or not hasattr(g, "monitor_report")\
            or not hasattr(g, "scan_summary"):
        return None, "no monitor-but-count accounting on this tree"
    return g, None


# ---------------------------------------------------------------------------
# Accounting contract: must be HELD
# ---------------------------------------------------------------------------

def m01_monitor_policy_denied_counted():
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: False, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is True
          and v["code"] == "gatehard-monitor-would-deny"
          and v["would_deny_code"] == "gatehard-policy-denied"
          and g.monitor_deny_counts.get("gatehard-policy-denied") == 1)
    return ok, "would-deny counted: %r"\
        % (dict(g.monitor_deny_counts),)


def m02_monitor_callback_denied_counted():
    g, missing = _mon_gate(host_allowlist=frozenset({"ok"}))
    if g is None:
        return False, missing
    def pred(rt):
        rt.host_callback("evil", "x")
        return True
    g.register_policy(_policy(pred, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is True
          and v["would_deny_code"] == "gatehard-host-callback-denied"
          and g.monitor_deny_counts.get("gatehard-host-callback-denied") == 1)
    return ok, "host-callback would-deny counted: %r"\
        % (dict(g.monitor_deny_counts),)


def m03_monitor_timeout_counted():
    clock = _Clock()
    g = gh.Gate(mode="monitor", global_deadline_s=5.0, now=lambda: NOW,
                clock=clock)
    if not hasattr(g, "monitor_deny_counts"):
        return False, "no monitor-but-count accounting on this tree"

    def pred(rt):
        clock.advance(9.0)
        return True
    g.register_policy(_policy(pred, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is True
          and v["would_deny_code"] == "gatehard-gate-timeout"
          and g.monitor_deny_counts.get("gatehard-gate-timeout") == 1)
    return ok, "timeout would-deny counted: %r"\
        % (dict(g.monitor_deny_counts),)


def m04_monitor_gate_error_counted():
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    def pred(rt):
        raise RuntimeError("boom")
    g.register_policy(_policy(pred, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is True
          and v["would_deny_code"] == "gatehard-gate-error"
          and g.monitor_deny_counts.get("gatehard-gate-error") == 1)
    return ok, "gate-error would-deny counted: %r"\
        % (dict(g.monitor_deny_counts),)


def m05_monitor_allow_counted():
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: True, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is True
          and g.monitor_allow_count == 1
          and len(g.monitor_deny_counts) == 0)
    return ok, "would-allow=%d deny-codes=%r"\
        % (g.monitor_allow_count, dict(g.monitor_deny_counts))


def m06_protect_mode_not_counted():
    """Protect-mode denials must NOT land in the monitor counters --
    monitor accounting mirrors monitor mode only, no cross-contamination.
    """
    g = _gate(mode="protect")
    if not hasattr(g, "monitor_deny_counts"):
        return False, "no monitor-but-count accounting on this tree"
    g.register_policy(_policy(lambda rt: False, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    ok = (v["allowed"] is False
          and v["code"] == "gatehard-policy-denied"
          and len(g.monitor_deny_counts) == 0
          and g.monitor_allow_count == 0)
    return ok, "protect deny kept out of monitor counters: %r"\
        % (dict(g.monitor_deny_counts),)


def m07_monitor_report_totals():
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: rt.request["k"] == "ok",
                              policy_id="p"))
    for i in range(3):
        g.evaluate({"request_id": "a%d" % i, "k": "ok"})
    for i in range(2):
        g.evaluate({"request_id": "d%d" % i, "k": "nope"})
    r = g.monitor_report()
    ok = (r["monitor_would_allow"] == 3
          and r["monitor_would_deny"].get("gatehard-policy-denied") == 2
          and r["monitor_would_deny_total"] == 2
          and r["monitor_evaluations"] == 5
          and r["mode"] == "monitor")
    return ok, "report=%r" % (r,)


def m08_scan_summary_counts():
    """The audit scanner reports 'what protect would deny today' with
    counts, per policy-denied code family."""
    g = _gate(mode="protect")
    if not hasattr(g, "scan_summary"):
        return False, "no monitor-but-count accounting on this tree"
    g.register_policy(_policy(lambda rt: rt.request["k"] == "ok",
                              policy_id="deny-p"))
    reqs = [{"request_id": "a1", "k": "ok"},
            {"request_id": "a2", "k": "ok"},
            {"request_id": "d1", "k": "nope"},
            {"request_id": "d2", "k": "nope"}]
    s = g.scan_summary(reqs)
    ok = (s["would_deny"].get("gatehard-policy-denied") == 2
          and s["would_allow"] == 2)
    return ok, "summary=%r" % (s,)


def m09_scan_summary_does_not_mutate_counters():
    """scan_summary() is a pure read: running the scanner must not add
    to the live monitor counters (no double counting)."""
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: rt.request["k"] == "ok",
                              policy_id="p"))
    g.evaluate({"request_id": "r1", "k": "nope"})  # one would-deny
    before = dict(g.monitor_deny_counts)
    s = g.scan_summary([{"request_id": "s1", "k": "nope"},
                        {"request_id": "s2", "k": "ok"}])
    ok = (dict(g.monitor_deny_counts) == before
          and s["would_deny"].get("gatehard-policy-denied") == 1
          and s["would_allow"] == 1)
    return ok, "counters unchanged=%r summary=%r"\
        % (dict(g.monitor_deny_counts), s)


# ---------------------------------------------------------------------------
# Honest-limit foils (INFO): the documented boundary of the accounting
# ---------------------------------------------------------------------------

def x01_counters_are_in_process():
    """Accounting lives in-process: it is lost on gate restart. Not a
    durability violation -- the honest limit is documented in the
    Gate docstring."""
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: True, policy_id="p"))
    g.evaluate({"request_id": "r1"})
    fresh = _gate(mode="monitor")
    ok = (g.monitor_allow_count == 1
          and fresh.monitor_allow_count == 0)
    return ok, "in-process counters: old gate=1, fresh gate=0 (restart loses)"


def x02_monitor_mode_never_denies():
    """Monitor-but-count never enforces: even a fully-denied traffic
    mix still returns allowed=True verdicts. The counters say what
    protect WOULD do; they are verdict-level, not kernel enforcement."""
    g, missing = _mon_gate()
    if g is None:
        return False, missing
    g.register_policy(_policy(lambda rt: False, policy_id="p"))
    vs = [g.evaluate({"request_id": "r%d" % i}) for i in range(3)]
    ok = (all(v["allowed"] is True for v in vs)
          and sum(g.monitor_deny_counts.values()) == 3)
    return ok, "allowed=True x3 while would-deny=3 (observed, not enforced)"


def x03_side_effects_invisible_to_counters():
    """Break-first foil for the honest limit: the counters count
    VERDICTS, not effects. In monitor mode a predicate performs a
    side effect through an allowlisted host callback and then denies;
    the verdict is allowed=True with the would-deny counted, but the
    side effect already executed and no counter can see or revert it.
    This BREAK is permanent by design: it is what 'verdict-level
    counting, not kernel enforcement' means in practice. (Filed as the
    honest limit, not a defect -- monitor mode never enforces.)"""
    g, missing = _mon_gate(host_allowlist=frozenset({"side_effect"}))
    if g is None:
        return False, missing
    fired = []

    def pred(rt):
        rt.host_callback("side_effect")
        fired.append("fired")
        return False
    g.register_policy(_policy(pred, policy_id="p"))
    v = g.evaluate({"request_id": "r1"})
    observed_gap = (v["allowed"] is True
                    and v["would_deny_code"] == "gatehard-policy-denied"
                    and g.monitor_deny_counts.get("gatehard-policy-denied") == 1
                    and fired == ["fired"])
    return (not observed_gap,
            "verdict counted=%r but side effect executed anyway: %r"
            % (dict(g.monitor_deny_counts), fired))


def c_pin_check():
    import re
    src = open(os.path.join(os.path.dirname(__file__), "..",
                            "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    held = (len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN)
    return held, "%d/%d unique, pin %d" % (len(codes), len(set(codes)),
                                           TAXONOMY_PIN)


def green_check():
    """Depth-1: adjacent battery + unit suites with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "skipped (GOV_SKIP_GREEN=1)"
    root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="g273-green-")
    env["TMPDIR"] = tmp
    env["GOV_RUN_ROOT"] = tmp
    py = sys.executable
    ok = True
    notes = []
    for cmd in (
        [py, "evals/w271_gatehard_probes.py"],
        [py, "-m", "unittest", "tests.test_gate_hardening", "-v"],
        [py, "-m", "unittest", "tests.test_gatehard_closures_w273"],
    ):
        r = subprocess.run(cmd, cwd=root, env=env, capture_output=True,
                           text=True, timeout=600)
        good = (r.returncode == 0)
        ok = ok and good
        notes.append("%s rc=%d" % (" ".join(cmd[-1:]), r.returncode))
    return ok, "; ".join(notes)


def probe(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "HELD" if held else "BREAK", detail))


def info(name, fn):
    try:
        _, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "INFO", detail))


def main():
    for name, fn in [
        ("m01-monitor-policy-denied-counted", m01_monitor_policy_denied_counted),
        ("m02-monitor-callback-denied-counted",
         m02_monitor_callback_denied_counted),
        ("m03-monitor-timeout-counted", m03_monitor_timeout_counted),
        ("m04-monitor-gate-error-counted", m04_monitor_gate_error_counted),
        ("m05-monitor-allow-counted", m05_monitor_allow_counted),
        ("m06-protect-mode-not-counted", m06_protect_mode_not_counted),
        ("m07-monitor-report-totals", m07_monitor_report_totals),
        ("m08-scan-summary-counts", m08_scan_summary_counts),
        ("m09-scan-summary-no-counter-mutation",
         m09_scan_summary_does_not_mutate_counters),
        ("c-pin-check", c_pin_check),
    ]:
        probe(name, fn)
    for name, fn in [
        ("x01-counters-are-in-process", x01_counters_are_in_process),
        ("x02-monitor-mode-never-denies", x02_monitor_mode_never_denies),
    ]:
        info(name, fn)
    # x03 is the break-first honest-limit foil: it demonstrates the
    # gap live (side effects invisible to verdict counters), so it is
    # a BREAK probe by design, not informational.
    probe("x03-side-effects-invisible-to-counters",
          x03_side_effects_invisible_to_counters)
    held_n = sum(1 for _, s, _ in RESULTS if s == "HELD")
    break_n = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    err_n = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    print("== w273 monitor-but-count accounting ==")
    # Named exception (INFO is not in D1): info() records "INFO" for
    # informational probes. SKIP is the canonical informational verdict
    # (uncounted, as the old summary tallied only HELD/BREAK/ERROR).
    # Exit-neutral: the exit consults only err_n and g_held.
    display = [(n, ("SKIP" if s == "INFO" else s), d)
               for n, s, d in RESULTS]
    probe_lines.emit(display)
    print("w273 monitor-but-count accounting: %d BREAK / %d HELD / %d ERROR"
          % (break_n, held_n, err_n))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        display, break_n, held_n, err_n)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    g_held, g_detail = green_check()
    print("green-check: %s (%s)" % ("HELD" if g_held else "BREAK", g_detail))
    print("RESULT %s: %d HELD / %d BREAK / %d ERROR (+green %s)" % (
        "OK" if err_n == 0 and g_held else "FAIL",
        held_n, break_n, err_n, "HELD" if g_held else "BREAK"))
    return 0 if (err_n == 0 and g_held) else 1


if __name__ == "__main__":
    sys.exit(main())
