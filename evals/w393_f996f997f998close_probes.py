#!/usr/bin/env python3
"""Wave-393 lane 3 close battery: F996/F997/F998 CLOSED.

F996 = .map(Number) over string-code arrays (attack round 60, F952 residual).
F997 = slice-trimmed code arrays (attack round 60).
F998 = globalThis stash reads (attack round 60).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0, 35-case differential, 0 mis-decodes); fail-closed
bounds stay quiet (miss, never mis-decode); sibling pins unaffected;
honest text quiet; 200-site perf; depth-1 green check on
w392_attack_probes.py (only the 3 now-closed pins may BREAK there --
the merge flips them, wave-391/392 precedent).

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
_C = "xox" + "b-0123456789abcdef0123456789abcdef012"  # 40-char split

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
    """Merged footer (wave-393): F988-F1004 CLOSED; F1005-F1024 OPEN; next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "lane_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F996 (filed 2026-10-09 18:38 UTC, attack round 60)
        'var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102"].map(Number));',
        'var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102","48","49","50"].map(Number));',
        # F997
        'var RESULT=String.fromCharCode.apply(null,[0,120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,0].slice(1,-1));',
        'var RESULT=String.fromCharCode.apply(null,[0,120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,0].slice(1,-1));',
        # F998
        'globalThis.x="xoxb-0123";globalThis.y="456789abcdef";var RESULT=globalThis.x+globalThis.y;',
        'globalThis.x="xox";globalThis.y="b-0123456789abcdef0123456789abcdef012";var RESULT=globalThis.x+globalThis.y;',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/6" % len(missed))


# ------------------------------------------------------ P2 generalizations


def _codes(s):
    return ",".join('"%d"' % ord(c) for c in s)


def _icodes(s):
    return ",".join(str(ord(c)) for c in s)


@_t
def test_p2_generalizations():
    # All decode to credential values; node-exactness proven separately
    # by the 35-case v24.20.0 differential (0 mis-decodes). ws / const /
    # let / trailing-comma / later-wins / literal-mix variants.
    C21 = _codes(_A + _B)
    I21 = _icodes(_A + _B)
    shapes = [
        # F996: ws, const, trailing comma, let
        'var RESULT = String.fromCharCode.apply( null , [ %s ] .map( Number ) ) ;' % C21,
        'const RESULT=String.fromCharCode.apply(null,[%s,].map(Number));' % C21,
        'let RESULT=String.fromCharCode.apply(null,[%s].map(Number));' % C21,
        # F997: ws, let, const
        'var RESULT=String.fromCharCode.apply( null , [ 0 , %s , 0 ] .slice( 1 , -1 ) ) ;' % I21,
        'let RESULT=String.fromCharCode.apply(null,[0,%s,0].slice(1,-1));' % I21,
        'const RESULT=String.fromCharCode.apply(null,[0,%s,0].slice(1,-1));' % I21,
        # F998: 3 fragments, later-wins, literal+member mix, let
        'globalThis.a="%s";globalThis.b="%s";globalThis.c="abcdef";var RESULT=globalThis.a+globalThis.b+globalThis.c;' % (_A, _B[:6]),
        'globalThis.a="nope";globalThis.a="%s";var RESULT=globalThis.a+"%s";' % (_A, _B),
        'globalThis.a="%s";var RESULT="x"+globalThis.a+"y";' % (_A + _B),
        'globalThis.a="%s";let RESULT=globalThis.a;' % (_A + _B),
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/10" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: must stay quiet (miss), never mis-decode.
    # (Each paired with the node semantic in the 35-case differential.)
    quiet_shapes = [
        # F996: wrong callback, non-null thisArg, non-digit elems,
        # empty array, backslash literal, declared-array form
        'var RESULT=String.fromCharCode.apply(null,["65"].map(String));',
        'var RESULT=String.fromCharCode.apply(undefined,["65"].map(Number));',
        'var RESULT=String.fromCharCode.apply(null,["6a","66"].map(Number));',
        'var RESULT=String.fromCharCode.apply(null,[].map(Number));',
        'var RESULT=String.fromCharCode.apply(null,["6\\\\5"].map(Number));',
        'var A=["65"];var RESULT=String.fromCharCode.apply(null,A.map(Number));',
        # F997: wrong trim, negative retained, big code, surrogate
        'var RESULT=String.fromCharCode.apply(null,[0,65,0].slice(0,-1));',
        'var RESULT=String.fromCharCode.apply(null,[0,65,0].slice(1));',
        'var RESULT=String.fromCharCode.apply(null,[0,-1,65,0].slice(1,-1));',
        'var RESULT=String.fromCharCode.apply(null,[0,1114111,0].slice(1,-1));',
        'var RESULT=String.fromCharCode.apply(null,[0,55296,0].slice(1,-1));',
        # F998: __proto__, unbound read, bracket read, backslash,
        # no member reads, reserved name, RESULT stash name, extra stmt
        'globalThis.__proto__="A";var RESULT=globalThis.__proto__;',
        'globalThis.a="A";var RESULT=globalThis.b;',
        'globalThis.a="A";var RESULT=globalThis["a"];',
        'globalThis.a="A\\\\nB";var RESULT=globalThis.a;',
        'globalThis.a="A";var RESULT="plain";',
        'globalThis.var="A";var RESULT=globalThis.var;',
        'globalThis.RESULT="A";var RESULT=globalThis.RESULT;',
        'globalThis.a="A";var q=1;var RESULT=globalThis.a;',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/19" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


@_t
def test_p4_sibling_pins():
    # Siblings still OPEN: must still miss (my hooks must not over-block).
    # Wave-393 merge: all wave-393 siblings are CLOSED now (lanes 1/2/4/5).
    still_open = [
    ]
    # Siblings already CLOSED: must stay blocked.
    still_closed = [
        'var RESULT=String.fromCharCode.apply(null,[0,120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,0].slice(1,-1));',  # F997 self-check shape
        'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',  # F992
        'var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";',  # F993
        '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xoxb-0123","456789abcdef");',  # F994
        '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xoxb-0123","456789abcdef");',  # F995
        'var o={};Object.defineProperties(o,{a:{value:"xoxb-0123",enumerable:true},b:{value:"456789abcdef",enumerable:true}});var RESULT=o.a+o.b;',  # F999
        'var s="";s||="xoxb-0123";s+="456789abcdef";var RESULT=s;',  # F1000
        'var RESULT=Reflect.apply(String.prototype.concat,"xoxb-0123",["456789abcdef"]);',  # F1001
        'var p={v:"xoxb-0123"};var o=Object.create(p);o.w="456789abcdef";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;',  # F1002
        'var s;s="xoxb-0123",s+="456789abcdef";var RESULT=s;',  # F1003
        'var o={a:"xoxb-0123"};o.b=o.a;var RESULT=o.b+"456789abcdef";',  # F1004
    ]
    bad_open = [s for s in still_open if _blocked(s)]
    closed_ok = all(_blocked(s) for s in still_closed)
    ok = not bad_open and closed_ok
    return ("HELD" if ok else "BREAK",
            "overblocked=%d closed_ok=%s" % (len(bad_open), closed_ok))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        "var nums=['1','2','3'];var r=nums.map(Number);",
        "var a=[1,2,3,4];var r=a.slice(1,-1);",
        "globalThis.counter=0;var r=globalThis.counter;",
        "var s='hello';var r=s+' world';",
        "var RESULT=String.fromCharCode.apply(null,['72','105'].map(Number));",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    sites = []
    base = 'globalThis.x%s="ab";var RESULT=globalThis.x%s+"tail";'
    for i in range(200):
        sites.append(base % (i, i))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 10 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g393l3-green-", dir="/var/tmp")
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
        # Wave-393 merge: my closures are flipped to _closed pins -- none may
        # BREAK there; the flipped pins must be present.
        names = set(ln.split(":")[0] for ln in lines[:-1])
        expected_closed = {"test_r60_f996_closed", "test_r60_f997_closed",
                    "test_r60_f998_closed"}
        ok = set(broken) == set() and expected_closed <= names
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
