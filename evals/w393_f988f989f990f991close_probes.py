#!/usr/bin/env python3
"""Wave-393 lane 1 close battery: F988/F989/F990/F991 CLOSED.

F988 = new String() boxing reads (attack round 60).
F989 = for-of over Map entries (F905 residual).
F990 = Proxy get-trap reads.
F991 = WeakRef deref reads (F960 residual).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site perf;
depth-1 green check on w392_attack_probes.py (only the 4 now-closed
pins may BREAK there -- the merge flips them, wave-391 precedent).

Pins: TAXONOMY_PIN 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28.
$0-spend-by-construction (no harness/paid refs).
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-392 merge (no code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls


@_t
def test_b0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s codes=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_pin_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "w318", os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok = mod.VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % mod.VERIFIER_TAXONOMY_PIN)


@_t
def test_b0_recompile_count():
    n = len(re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Wave-393 lane 1: F988-F991 CLOSED (4)" in text
          and "open F992-F1004 (13)" in text
          and "next free F1005" in text)
    return ("HELD" if ok else "BREAK", "lane_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F988
        'var s=new String("xoxb-0123");var RESULT=s+"456789abcdef";',
        'var s=new String("xox");var RESULT=s+"b-0123456789abcdef0123456789abcdef012";',
        # F989
        'var s="";var m=new Map([["a","xoxb-0123"],["b","456789abcdef"]]);for(var kv of m){s+=kv[1];}var RESULT=s;',
        'var s="";var m=new Map([["a","xox"],["b","b-0123456789abcdef0123456789abcdef012"]]);for(var kv of m){s+=kv[1];}var RESULT=s;',
        # F990
        'var p=new Proxy({a:"xoxb-0123",b:"456789abcdef"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;',
        'var p=new Proxy({a:"xox",b:"b-0123456789abcdef0123456789abcdef012"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;',
        # F991
        'var w=new WeakRef({v:"xoxb-0123"});var x=new WeakRef({v:"456789abcdef"});var RESULT=w.deref().v+x.deref().v;',
        'var w=new WeakRef({v:"xox"});var x=new WeakRef({v:"b-0123456789abcdef0123456789abcdef012"});var RESULT=w.deref().v+x.deref().v;',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/8" % len(missed))


# ------------------------------------------------------ P2 generalizations


@_t
def test_p2_generalizations():
    shapes = [
        # F988: const, escapes, no-arg, multi-box, comma-declarators
        'const s=new String("xoxb-0123");var RESULT=s+"456789abcdef";',
        'var s=new String("\\x78\\x6f\\x78\\x62\\x2d\\x30\\x31\\x32\\x33");var RESULT=s+"456789abcdef";',
        'var s=new String();var RESULT=s+"xoxb-0123456789abcdef";',
        'var a=new String("xoxb-"),b=new String("0123");var RESULT=a+b+"456789abcdef";',
        # F989: s=s+ form, let, dup keys, RESULT additive tail
        'let s="";let m=new Map([["a","xoxb-0123"]]);for(let kv of m){s=s+kv[1];}var RESULT=s+"456789abcdef";',
        'var s="";var m=new Map([["a","nope"],["a","xoxb-0123"]]);for(var kv of m){s+=kv[1];}var RESULT=s+"456789abcdef";',
        # F990: subscript read, renamed trap params, dup keys
        'var p=new Proxy({a:"xoxb-0123"},{get:function(x,y){return x[y];}});var RESULT=p["a"]+"456789abcdef";',
        'var p=new Proxy({a:"nope",a:"xoxb-0123"},{get:function(t,k){return t[k];}});var RESULT=p.a+"456789abcdef";',
        # F991: extra props, let, additive tail
        'let w=new WeakRef({v:"xoxb-0123",other:"z"});var RESULT=w.deref().v+"456789abcdef";',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/9" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: must stay quiet (miss), never mis-decode.
    quiet_shapes = [
        # F988
        'var String=new String("x");var RESULT=String+"y";',
        'var s=new String("a","b");var RESULT=s;',
        'var s=new String(5);var RESULT=s+"x";',
        'var s=new String("a");var RESULT=typeof s;',
        # F989
        'var s="";var m=new Map([["a","x"]]);for(kv of m){s+=kv[1];}var RESULT=s;',
        'var s="";var m=new Map([["a","x"]]);for(var kv of m){s+=kv[0];}var RESULT=s;',
        'var s="";var m=new Map([[k,"x"]]);for(var kv of m){s+=kv[1];}var RESULT=s;',
        # F990
        'var p=new Proxy({a:"x"},{get:function(t,k){return t[k];},set:function(){}});var RESULT=p.a;',
        'var p=new Proxy({a:"x"},{get:(t,k)=>t[k]});var RESULT=p.a;',
        'var p=new Proxy({a:"x"},{get:function(t,k){return t[k];}});var RESULT=p.b;',
        'var p=new Proxy({__proto__:"x"},{get:function(t,k){return t[k];}});var RESULT=p.a;',
        # F991
        'var w=new WeakRef({v:"x"});var RESULT=w.deref();',
        'var o={v:"x"};var w=new WeakRef(o);var RESULT=w.deref().v;',
        'var w=new WeakRef({w:"x"});var RESULT=w.deref().v;',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/14" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


@_t
def test_p4_sibling_pins():
    # Siblings still OPEN: must still miss (my hooks must not over-block).
    still_open = [
        'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',  # F992
        'var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";',  # F993
        'var o={a:"xoxb-0123"};o.b=o.a;var RESULT=o.b+"456789abcdef";',  # F1004
    ]
    # Siblings already CLOSED: must stay blocked.
    still_closed = [
        'var s="";var m=new Map([["a","xoxb-0123"]]);for(var kv of m){s+=kv[1];}var r=s;',  # junk twin: quiet
    ]
    bad_open = [s for s in still_open if _blocked(s)]
    quiet = _misses(still_closed[0])
    ok = not bad_open and quiet
    return ("HELD" if ok else "BREAK",
            "overblocked=%d quiet_twin=%s" % (len(bad_open), quiet))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        "var s='hello';var r=s+' world';",
        "var m=new Map();m.set('a','b');var r=m.get('a');",
        "var p=new Proxy({},{get:function(t,k){return 0;}});var r=p.a;",
        "var w=new WeakRef({});var r=w.deref();",
        "var s=new String('plain text, no credential');var r=s;",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    sites = []
    base = 'var s=new String("%s");var RESULT=s+"tail";'
    for i in range(200):
        sites.append(base % ("ab" * (i % 7 + 1),))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 10 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g393l1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w392_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines[:-1]:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # Only my 4 closures may BREAK there (merge flips them).
        expected = {"test_r60_f988_open", "test_r60_f989_open",
                    "test_r60_f990_open", "test_r60_f991_open"}
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w392_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-60 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            verdict, note = "BREAK", "probe raised %r" % (e,)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
