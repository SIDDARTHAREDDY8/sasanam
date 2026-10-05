"""Wave-288 lane 3 red-first battery: F338 + F339 closures (tool_call_policy).

F338 (MEDIUM): DENY arg carve-outs evaded by explicit null / wrong-typed
args -- {"cmd": None} -> ALLOW defeats an explicit DENY carve-out.
Close-when: under DENY semantics, null/ill-typed arg values are treated
as missing (fail-closed match).

F339 (MEDIUM): ReDoS residual independently exploitable -- the F325 gate
(_check_regex_safety) is not routed into toolpolicy's arg-matcher regexes.
Close-when: arg-matcher regexes pass through the F325 gate at compile
time, refusing the dangerous pattern class coded.

Base: wave-287 push add3e92aa02e68daf6a2288c302a27fd3dfa4690
(verified via git rev-parse HEAD before work).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g288-f338 && TMPDIR=/var/tmp/g288-f338 \
    ~/workspace/.gov-venv/bin/python evals/w288_f338_f339_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g288-f338b \
    ~/workspace/.gov-venv/bin/python evals/w288_f338_f339_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-288 lane 3: pin 1684 -> 1685 (+1 toolcall-regex-unsafe).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*)
TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


def _broad_allow_narrow_deny(carve):
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w288f338",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "shell", "operation": "run",
             "severity": 5, "tags": []},
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": [], "args": carve},
        ],
    }


def _decide_denied(tp, comp, args):
    """Return True iff decide() DENYs (or refuses coded) for args."""
    caller = {"authenticated": True, "identity": "agent-1"}
    try:
        d = comp.decide(caller, "shell", "run", args=args)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        return True, "coded refusal: %s" % (code,)
    return d.verdict == "DENY", "verdict=%s" % (d.verdict,)


# ---------------------------------------------------------------------------
# F338: null / wrong-typed args must not dodge DENY carve-outs.
# ---------------------------------------------------------------------------

def p_f338_null_evicts():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(
        _broad_allow_narrow_deny({"cmd": {"regex": "^rm -rf /"}}))
    denied, note = _decide_denied(tp, comp, {"cmd": None})
    if denied:
        return _record("f338-null", "HELD",
                       "explicit null hits the DENY carve-out (%s)" % note)
    _record("f338-null", "BREAK",
            "explicit null evaded the DENY carve-out -> ALLOW "
            "(wire-equivalent of under-specification)")


def p_f338_wrong_typed():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(
        _broad_allow_narrow_deny({"cmd": {"regex": "^rm -rf /"}}))
    for v in (5, ["rm -rf /"], {"cmd": "rm -rf /"}):
        denied, note = _decide_denied(tp, comp, {"cmd": v})
        if not denied:
            return _record("f338-wrong-typed", "BREAK",
                           "wrong-typed arg %r evaded the DENY carve-out"
                           % (v,))
    _record("f338-wrong-typed", "HELD",
            "wrong-typed args (int/list/dict) all hit the DENY carve-out")


def p_f338_prefix_dodge():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(
        _broad_allow_narrow_deny({"path": {"regex": "^/etc/.*"}}))
    denied, note = _decide_denied(tp, comp, {"path": None})
    if denied:
        return _record("f338-prefix-dodge", "HELD",
                       "path=None hits the DENY carve-out (%s)" % note)
    _record("f338-prefix-dodge", "BREAK",
            "path=None dodged the ^/etc/.* DENY carve-out")


def p_f338_missing_still_deny():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(
        _broad_allow_narrow_deny({"cmd": {"regex": "^rm -rf /"}}))
    denied, note = _decide_denied(tp, comp, {})
    if denied:
        return _record("f338-missing", "HELD",
                       "missing arg still matches DENY (%s)" % note)
    _record("f338-missing", "BREAK",
            "missing-arg fail-closed regressed: %s" % note)


def p_f338_benign_untouched():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(
        _broad_allow_narrow_deny({"cmd": {"regex": "^rm -rf /"}}))
    caller = {"authenticated": True, "identity": "agent-1"}
    d = comp.decide(caller, "shell", "run", args={"cmd": "ls -la"})
    if d.verdict == "ALLOW":
        return _record("f338-benign", "HELD",
                       "well-typed non-matching arg still ALLOWs")
    _record("f338-benign", "BREAK",
            "over-refusal: benign well-typed arg -> %s" % (d.verdict,))


def p_f338_allow_path_failclosed():
    # The ALLOW path must stay fail-closed on ill-typed args (unchanged).
    from gov import tool_call_policy as tp
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w288f338b",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "shell", "operation": "run",
             "severity": 5, "tags": [],
             "args": {"cmd": {"equals": "ls"}}},
        ],
    }
    comp = tp.compile_policy(doc)
    caller = {"authenticated": True, "identity": "agent-1"}
    d = comp.decide(caller, "shell", "run", args={"cmd": None})
    if d.verdict != "ALLOW":
        return _record("f338-allow-failclosed", "HELD",
                       "ALLOW rule still refuses ill-typed arg (%s)"
                       % (d.verdict,))
    _record("f338-allow-failclosed", "BREAK",
            "ALLOW rule granted on ill-typed arg")


# ---------------------------------------------------------------------------
# F339: arg-matcher regexes must pass the F325 safety gate at compile.
# ---------------------------------------------------------------------------

_EVIL = "^([a-z]+)*$"


def p_f339_redos():
    from gov import tool_call_policy as tp
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w288f339",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "shell", "operation": "run",
             "severity": 5, "tags": []},
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": [],
             "args": {"cmd": {"regex": _EVIL}}},
        ],
    }
    try:
        comp = tp.compile_policy(doc)
    except Exception as e:  # noqa: BLE001
        return _record("f339-redos", "HELD",
                       "evil pattern refused at compile: %s"
                       % getattr(e, "code", type(e).__name__))
    # Pattern compiled: prove the backtracking is live and exponential
    # with two bounded measurements (n=18 vs n=22; exponential => ~16x).
    caller = {"authenticated": True, "identity": "agent-1"}
    t0 = time.time()
    comp.decide(caller, "shell", "run", args={"cmd": "a" * 18 + "!"})
    d18 = time.time() - t0
    t0 = time.time()
    comp.decide(caller, "shell", "run", args={"cmd": "a" * 22 + "!"})
    d22 = time.time() - t0
    if d18 > 0.005 and d22 / max(d18, 1e-9) > 4.0:
        return _record("f339-redos", "BREAK",
                       "caller arg triggers exponential backtracking "
                       "(n=18: %.2fs, n=22: %.2fs); F325 gate not routed"
                       % (d18, d22))
    _record("f339-redos", "HELD",
            "bounded-time decide on adversarial arg (%.2f/%.2fs)"
            % (d18, d22))


def p_f339_safe_patterns_compile():
    # The True-biased gate must not refuse ordinary anchored patterns.
    from gov import tool_call_policy as tp
    for pat in (r"^rm -rf /$", r"^/etc/.*", r"^\d{4}$", r"^(ab|cd)+$"):
        doc = {
            "format": "sasanam-tool-call-policy/v1",
            "name": "w288f339safe",
            "selector": {"agents": ["agent-1"]},
            "mode": "enforce",
            "rules": [
                {"action": "DENY", "tool": "shell", "operation": "run",
                 "severity": 9, "tags": [],
                 "args": {"cmd": {"regex": pat}}},
            ],
        }
        try:
            tp.compile_policy(doc)
        except Exception as e:  # noqa: BLE001
            return _record("f339-safe", "BREAK",
                           "over-refusal: safe pattern %r refused: %s"
                           % (pat, getattr(e, "code",
                                           type(e).__name__)))
    _record("f339-safe", "HELD",
            "ordinary anchored patterns still compile")


# ---------------------------------------------------------------------------
# Depth-1 green checks: adjacent batteries must stay green.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w286_toolpolicy_probes.py",
        "evals/w287_redteam_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Take the LAST "N BREAK" match: the footer. Earlier lines carry
        # per-probe "0 BREAK as expected" notes (wave-286 redteam lesson).
        matches = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(matches[-1]) if matches else -1
        base = os.path.basename(rel)
        if base == "w287_redteam_probes.py":
            # Wave-288 merge: F334-F342 all closed -> 0 BREAK expected.
            expected = 0
            want_note = "expected 0 (F334-F342 all closed at merge)"
        else:
            expected = 0
            want_note = "expected 0"
        if nbreak == expected:
            _record(base, "HELD",
                    "green check: %d BREAK as expected (%s)" % (nbreak,
                                                               want_note))
        else:
            _record(base, "BREAK",
                    "green check: %d BREAK, %s" % (nbreak, want_note))


def main():
    p_taxonomy_pin()
    p_f338_null_evicts()
    p_f338_wrong_typed()
    p_f338_prefix_dodge()
    p_f338_missing_still_deny()
    p_f338_benign_untouched()
    p_f338_allow_path_failclosed()
    p_f339_redos()
    p_f339_safe_patterns_compile()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w288_f338_f339: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
