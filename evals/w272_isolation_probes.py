"""Wave-272 isolation audit battery: enforcement-path isolation guarantees.

Audits gov/gate_hardening.py (wave-271) against a MALICIOUS in-process
predicate threat model. The module documents its honest limit:
"in-process Python predicates are trusted code; fresh discarded runtime
is API-level discipline, not WASM-grade memory isolation."

This battery pins the claimed guarantees (probes i01-i08, i13: must be
HELD) and demonstrates where claimed guarantees break under a hostile
predicate (probes i09-i12: BREAK -> filed as F256/F257/F258). Probes
x01/x02 are informational: they demonstrate the DOCUMENTED trust
boundary (predicates are trusted code), not violations.

Deterministic: explicit now/clock everywhere. Module-level staging
default. Depth-1 green check honoring GOV_SKIP_GREEN. No in-repo git
subprocesses. Fresh /var/tmp/g272* TMPDIRs.
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

TAXONOMY_PIN = 1951 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

NOW = 1700000000


def _gate(**kw):
    kw.setdefault("global_deadline_s", 60.0)
    kw.setdefault("now", lambda: NOW)
    return gh.Gate(**kw)


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


RESULTS = []


def probe(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "HELD" if held else "BREAK", detail))


# ---------------------------------------------------------------------------
# Claimed guarantees: must be HELD
# ---------------------------------------------------------------------------

def i01_callback_denied():
    def pred(rt):
        rt.host_callback("evil-cb")
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    v = g.evaluate({"request_id": "r1"})
    held = (v["allowed"] is False
            and v["code"] == "gatehard-host-callback-denied")
    return held, "verdict=%s" % (v["code"],)


def i02_callback_allowed():
    seen = {}

    def pred(rt):
        seen["out"] = rt.host_callback("ok-cb", "arg1")
        return True

    g = _gate(host_allowlist=frozenset({"ok-cb"}))
    g.register_policy(_policy(pred, callbacks=["ok-cb"]))
    v = g.evaluate({"request_id": "r1"})
    held = v["allowed"] is True and seen.get("out") == "cb:ok-cb:arg1"
    return held, "allowed=%s out=%r" % (v["allowed"], seen.get("out"))


def i03_deadline_deny():
    clock = _Clock()

    def pred(rt):
        clock.advance(20.0)
        return True

    g = _gate(global_deadline_s=10.0, clock=clock)
    g.register_policy(_policy(pred))
    v = g.evaluate({"request_id": "r1"})
    held = (v["allowed"] is False
            and v["code"] == "gatehard-gate-timeout")
    return held, "verdict=%s" % (v["code"],)


def i04_error_deny():
    def pred(rt):
        raise ValueError("boom")

    g = _gate()
    g.register_policy(_policy(pred))
    v = g.evaluate({"request_id": "r1"})
    held = (v["allowed"] is False
            and v["code"] == "gatehard-gate-error")
    return held, "verdict=%s" % (v["code"],)


def i05_ctx_fresh():
    ids = []

    def pred(rt):
        ids.append(id(rt.ctx))
        rt.ctx["scratch"] = "x"
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    g.evaluate({"request_id": "r1"})
    g.evaluate({"request_id": "r2"})
    held = len(ids) == 2 and ids[0] != ids[1]
    return held, "ctx ids distinct=%s" % (ids[0] != ids[1],)


def i06_no_runtime_retained():
    def pred(rt):
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    g.evaluate({"request_id": "r1"})
    held = g._runtime_after_eval_is_none() is True
    return held, "_last_runtime is None=%s" % held


def i07_shallow_top_level():
    def pred(rt):
        rt.request["injected"] = True
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    caller = {"request_id": "r1"}
    g.evaluate(caller)
    held = "injected" not in caller
    return held, "caller top-level unmutated=%s" % held


def i08_private_callback_path():
    def pred(rt):
        rt._host_callback("evil-cb")
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    v = g.evaluate({"request_id": "r1"})
    held = (v["allowed"] is False
            and v["code"] == "gatehard-host-callback-denied")
    return held, "private path still allowlisted, verdict=%s" % v["code"]


def i13_scan_readonly():
    def pred(rt):
        return rt.request.get("request_id") != "deny-me"

    g = _gate()
    g.register_policy(_policy(pred))
    g.evaluate({"request_id": "warm"})
    before = len(g.audit_log())
    out = g.scan([{"request_id": "deny-me"}, {"request_id": "ok-1"}])
    after = len(g.audit_log())
    held = (before == after
            and out[0]["request_id"] == "deny-me"
            and out[0] == {"request_id": "deny-me", "would": "deny",
                           "code": "gatehard-policy-denied"}
            and out[1]["would"] == "allow")
    return held, "audit %d->%d, deterministic order=%s" % (
        before, after, out[0]["request_id"] == "deny-me")


# ---------------------------------------------------------------------------
# Claimed-guarantee violations under a hostile predicate -> findings
# ---------------------------------------------------------------------------

def i09_systemexit_escapes():
    def pred(rt):
        raise SystemExit(3)

    g = _gate()
    g.register_policy(_policy(pred))
    try:
        g.evaluate({"request_id": "r1"})
    except SystemExit:
        return False, "SystemExit propagated out of evaluate() (F256)"
    except BaseException as e:  # noqa: BLE001
        return False, "BaseException %r propagated (F256)" % (e,)
    return True, "evaluate() contained SystemExit"


def i10_keyboardinterrupt_escapes():
    def pred(rt):
        raise KeyboardInterrupt()

    g = _gate()
    g.register_policy(_policy(pred))
    try:
        g.evaluate({"request_id": "r1"})
    except KeyboardInterrupt:
        return False, "KeyboardInterrupt propagated out of evaluate() (F256)"
    except BaseException as e:  # noqa: BLE001
        return False, "BaseException %r propagated (F256)" % (e,)
    return True, "evaluate() contained KeyboardInterrupt"


def i11_audit_unbounded():
    def pred(rt):
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    for i in range(5000):
        g.evaluate({"request_id": "r%d" % i})
    n = len(g.audit_log())
    # No bound exists: every evaluation appends; a deployment under
    # request volume grows memory without limit.
    held = n < 5000
    return held, "audit entries after 5000 evals: %d (F257)" % n


def i12_nested_aliasing():
    def pred(rt):
        rt.request["nested"]["k"] = "pwned"
        return True

    g = _gate()
    g.register_policy(_policy(pred))
    caller = {"request_id": "r1", "nested": {"k": "v"}}
    g.evaluate(caller)
    held = caller["nested"]["k"] == "v"
    return held, "caller nested value=%r (F258)" % caller["nested"]["k"]


# ---------------------------------------------------------------------------
# Informational: documented trust boundary, not findings
# ---------------------------------------------------------------------------

def x01_closure_gate_escape():
    """Predicate closing over the gate object can demote/alter it.
    The module documents predicates as trusted code; this demonstrates
    the boundary is API-level, not isolation."""
    box = {}

    def pred(rt):
        box["gate"].demote_to_monitor(reason="pwned")
        return True

    g = _gate()
    box["gate"] = g
    g.register_policy(_policy(pred))
    g.evaluate({"request_id": "r1"})
    escaped = (g.mode == "monitor")
    return (not escaped),\
        "closure reached gate, mode=%s (documented trust boundary)" % g.mode


def x02_clock_tamper():
    """Predicate monkeypatching the clock module-globally defeats the
    deadline budget. Trusted-code assumption; subprocess isolation
    would fix it."""
    import time as _time

    real = _time.monotonic

    def pred(rt):
        _time.monotonic = lambda: 0.0  # noqa: E731
        try:
            return True
        finally:
            _time.monotonic = real

    g = _gate(global_deadline_s=0.001)  # real clock, not injected
    g.register_policy(_policy(pred))
    v = g.evaluate({"request_id": "r1"})
    tampered = _time.monotonic is real and v["allowed"] is True
    return (not tampered),\
        "global clock tamper defeated deadline, allowed=%s" % v["allowed"]


def c_pin_check():
    import re
    src = open(os.path.join(os.path.dirname(__file__), "..",
                            "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    held = (len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN)
    return held, "%d/%d unique, pin %d" % (len(codes), len(set(codes)),
                                           TAXONOMY_PIN)


def green_check():
    """Depth-1: adjacent battery + unit suite with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "skipped (GOV_SKIP_GREEN=1)"
    root = os.path.join(os.path.dirname(__file__), "..")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="g272-green-")
    env["TMPDIR"] = tmp
    env["GOV_RUN_ROOT"] = tmp
    py = sys.executable
    ok = True
    notes = []
    for cmd in (
        [py, "evals/w271_gatehard_probes.py"],
        [py, "-m", "unittest", "tests.test_gate_hardening", "-v"],
    ):
        r = subprocess.run(cmd, cwd=root, env=env, capture_output=True,
                           text=True, timeout=600)
        good = (r.returncode == 0)
        ok = ok and good
        notes.append("%s rc=%d" % (" ".join(cmd[-1:]), r.returncode))
    return ok, "; ".join(notes)


def info(name, fn):
    try:
        _, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "INFO", detail))


def main():
    for name, fn in [
        ("i01-callback-denied", i01_callback_denied),
        ("i02-callback-allowed", i02_callback_allowed),
        ("i03-deadline-deny", i03_deadline_deny),
        ("i04-error-deny", i04_error_deny),
        ("i05-ctx-fresh", i05_ctx_fresh),
        ("i06-no-runtime-retained", i06_no_runtime_retained),
        ("i07-shallow-top-level", i07_shallow_top_level),
        ("i08-private-callback-path", i08_private_callback_path),
        ("i13-scan-readonly", i13_scan_readonly),
        ("i09-systemexit-escapes", i09_systemexit_escapes),
        ("i10-keyboardinterrupt-escapes", i10_keyboardinterrupt_escapes),
        ("i11-audit-unbounded", i11_audit_unbounded),
        ("i12-nested-aliasing", i12_nested_aliasing),
        ("c-pin-check", c_pin_check),
    ]:
        probe(name, fn)
    for name, fn in [
        ("x01-closure-gate-escape", x01_closure_gate_escape),
        ("x02-clock-tamper", x02_clock_tamper),
    ]:
        info(name, fn)
    held_n = sum(1 for _, s, _ in RESULTS if s == "HELD")
    break_n = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    err_n = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    print("== w272 isolation audit ==")
    # Named exception (INFO is not in D1): info() records "INFO" for
    # informational probes. SKIP is the canonical informational verdict
    # (uncounted, as the old summary tallied only HELD/BREAK/ERROR).
    # Exit-neutral: the exit consults only err_n and g_held.
    display = [(n, ("SKIP" if s == "INFO" else s), d)
               for n, s, d in RESULTS]
    probe_lines.emit(display)
    print("w272 isolation audit: %d BREAK / %d HELD / %d ERROR"
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
