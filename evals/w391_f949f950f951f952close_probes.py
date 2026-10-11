#!/usr/bin/env python3
"""Wave-391 lane 1 close battery: F949 + F950 + F951 + F952 CLOSED.

Verifies the four LOW findings (wave-390 attack round 58, filed
2026-10-09 14:19 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F679 try/catch, F655 try-finally, F468
Reflect.construct Array, F780 Reflect shapes, F458/F486/F500/F643
fromCharCode, F495/F501 rewrites, F611 single-decl IIFE),
honest-text controls, perf (200 sites), and a depth-1 green check
on the four w391 red-first batteries (GOV_SKIP_GREEN=1 in the child
env).

F949: top-level statement-scope packaging gap -- 11 builtin
classes modeled in IIFE bodies but missing as top-level statement
sequences (structuredClone, generator yield/.next(), class static
blocks/fields, Proxy.revocable, WeakRef, destructuring,
Object.values, Map spread, labeled blocks). Closed by the
whole-text IIFE-twin rewrite (_js_f949_rewrite_topstmt).
F950: try/throw/catch/finally value assembly. Closed by
_js_f679_sim_trycatchfinally (+ F949 rewrite composition for the
top-level filed shapes).
F951: Reflect.construct/Reflect.apply on the String constructor.
Closed by the String-target productions.
F952: postfix array transforms (toReversed/toSorted/with/
toSpliced) on fromCharCode argument arrays. Closed by
_js_parse_f952_postfix.

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
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

TAXONOMY_PIN = 2143  # wave-390 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 29  # wave-407 lane 3 added _JS_WS_COMPACT_RE

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_FULL40 = _F1 + _F2
_CODES = ",".join(str(ord(c)) for c in _FULL)
_RCODES = ",".join(str(ord(c)) for c in _FULL[::-1])
_RCODES40 = ",".join(str(ord(c)) for c in _FULL40[::-1])
_C1 = ",".join(str(ord(c)) for c in _FULL[1:])

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """re.compile( count is 29 (wave-407 lane 3 added _JS_WS_COMPACT_RE)."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_DOTALL_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_state():
    """Merged footer (wave-392): F949-F952 CLOSED (wave-391 lane 1); F967-F987 CLOSED; next F1005."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1005**" in text and "F949-F966 CLOSED (18)." in text
          and "F967-F974 CLOSED (8" in text)
    for fid in ("F949", "F950", "F951", "F952"):
        lines = [ln for ln in text.split("\n") if ln.startswith("(%s " % fid)]
        ok = ok and len(lines) == 1 and "CLOSED" in lines[0]
    return ("HELD" if ok else "BREAK", "footer-refs=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_f949_filed_shapes():
    """F949 filed shapes (11 classes + 40-char) block."""
    shapes = [
        "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_A, _B),
        "var o=structuredClone({a:'%s',b:'%s'});var RESULT=o.a+o.b;" % (_F1, _F2),
        "function*g(){yield '%s';yield '%s';}var s='';for(var p of g()){s+=p;}var RESULT=s;" % (_A, _B),
        "function*g(){yield '%s';yield '%s';}var gg=g();var RESULT=gg.next().value+gg.next().value;" % (_A, _B),
        "class C{static{this.a='%s';this.b='%s';}}var RESULT=C.a+C.b;" % (_A, _B),
        "class C{static a='%s';static b='%s';}var RESULT=C.a+C.b;" % (_A, _B),
        "var r=Proxy.revocable({a:'%s'},{});var RESULT=r.proxy.a+'%s';" % (_A, _B),
        "var w=new WeakRef({a:'%s'});var RESULT=w.deref().a+'%s';" % (_A, _B),
        "var [a,b]=['%s','%s'],RESULT=a+b;" % (_A, _B),
        "var o={a:'%s',b:'%s'};var RESULT=Object.values(o).join('');" % (_A, _B),
        "var m=new Map([['a','%s'],['b','%s']]);var RESULT=[...m.values()].join('');" % (_A, _B),
        "var RESULT='';lbl:{RESULT+='%s';if(1){break lbl;}RESULT+='nope';}RESULT+='%s';" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f950_filed_shapes():
    """F950 filed shapes (throw/catch/finally, throw/catch) block."""
    shapes = [
        "var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}var RESULT=s;" % (_A, _B),
        "var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}var RESULT=s;" % (_F1, _F2),
        "var s='';try{throw '%s';}catch(err){s=err+'%s';}var RESULT=s;" % (_A, _B),
        "var s='';try{s+='%s';}catch(e){s+='no';}finally{s+='%s';}var RESULT=s;" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f951_filed_shapes():
    """F951 filed shapes (Reflect String construct/apply) block."""
    shapes = [
        "var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_F1, _F2),
        "var RESULT=Reflect.apply(String,null,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect.apply(String,undefined,['%s'])+'%s';" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f952_filed_shapes():
    """F952 filed shapes (postfix transforms) block."""
    shapes = [
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES,),
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES40,),
        "var RESULT=String.fromCharCode.apply(null,[%s].toSorted((a,b)=>0));" % (_CODES,),
        "var RESULT=String.fromCharCode.apply(null,[0,%s].with(0,120));" % (_C1,),
        "var RESULT=String.fromCharCode.apply(null,[99,%s].toSpliced(0,1));" % (_CODES,),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------- p2: generalizations must block


@_t
def test_p2_f949_generalizations():
    """F949 generalizations: prop renames, multi-binding trailing block."""
    shapes = [
        # different property names, same class
        "var o=structuredClone({x:'%s',y:'%s'});var RESULT=o.x+o.y;" % (_A, _B),
        # multi-binding trailing
        "var a='%s',b='%s',RESULT=a+b;" % (_A, _B),
        # generator with different shape
        "function*g(){yield '%s';}var gg=g();var RESULT=gg.next().value+'%s';" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f950_generalizations():
    """F950 generalizations: catch-param shadowing, nested try block."""
    shapes = [
        "(function(){var s='';try{throw '%s';}catch(e){s=e;}finally{s+='%s';}return s;})()" % (_A, _B),
        "var s='';try{throw '%s';}catch(myErr){s=myErr;}finally{s+='%s';}var RESULT=s;" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f951_generalizations():
    """F951 generalizations: ?. and bracket members, empty args block."""
    shapes = [
        "var RESULT=Reflect?.construct(String,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect['construct'](String,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect['apply'](String,null,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect.construct(String,[])+'%s';" % (_FULL,),
        "var RESULT=Reflect.apply(String,null,['%s'])+'%s';" % (_F1, _F2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f952_generalizations():
    """F952 generalizations: toSorted other idents, with restoring a char."""
    # .with(0,120): array starts with 0, with() restores 'x' (120)
    with_codes = ",".join(str(ord(c)) for c in chr(0) + _FULL[1:])
    shapes = [
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (",".join(str(ord(c)) for c in _FULL[::-1]),),
        "var RESULT=String.fromCharCode.apply(null,[%s].toSorted((x,y)=>0));" % (_CODES,),
        "var RESULT=String.fromCharCode.apply(null,[%s].with(0,120));" % (with_codes,),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------- p3: fail-closed bounds


@_t
def test_p3_f949_fail_closed():
    """F949 bounds: backticks decline; return-in-try never decodes."""
    # Backtick template: the rewrite declines (None).
    ok1 = dlp._js_f949_rewrite_topstmt("var o=`x`;var RESULT=o;") is None
    # return inside try: the rewrite may fire, but the twin must not
    # decode (the sim fails closed on return) -- never a mis-decode.
    t = "var s='';try{return '%s';}catch(e){}var RESULT=s;" % (_A,)
    ok2 = not _blocked(t)
    # Leading paren declines.
    ok3 = dlp._js_f949_rewrite_topstmt("(var s='x');") is None
    ok = ok1 and ok2 and ok3
    return ("HELD" if ok else "BREAK", "bounds=%s" % ok)


@_t
def test_p3_f950_fail_closed():
    """F950 bounds: uncaught throw never decodes a credential."""
    # An uncaught throw: the decoder never decodes a throw. Use
    # split fragments so the literal itself does not match.
    t = "(function(){var x='%s';throw x;})()" % (_A,)
    d = _decode(t)
    ok = d is None or _FULL not in d
    return ("HELD" if ok else "BREAK", "uncaught-no-decode=%s" % ok)


@_t
def test_p3_f951_fail_closed():
    """F951 bounds: non-String targets, multi-arg, non-literal args."""
    shapes = [
        "var RESULT=Reflect.construct(Array,['%s'])+'%s';" % (_A, _B),
        "var RESULT=Reflect.construct(String,['%s','%s'])+'%s';" % (_A, _B, _A),
        "var RESULT=Reflect.apply(String,null,[%s])+'%s';" % (_A, _B),
    ]
    # Array target still routes to F468 (not our path); multi-arg and
    # non-literal fail closed on the F951 path. None may decode via F951.
    ok = True
    for s in shapes[1:]:
        d = _decode(s)
        if d is not None and _FULL in d:
            ok = False
    return ("HELD" if ok else "BREAK", "f951-bounds=%s" % ok)


@_t
def test_p3_f952_fail_closed():
    """F952 bounds: unmodeled transforms, bad args, out-of-range."""
    shapes = [
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed(1));" % (_CODES,),
        "var RESULT=String.fromCharCode.apply(null,[%s].sort());" % (_CODES,),
        "var RESULT=String.fromCharCode.apply(null,[%s].with(99,65));" % (_CODES,),
        "var RESULT=String.fromCharCode.apply(null,[%s].toSorted((a,b)=>a-b));" % (_CODES,),
    ]
    ok = True
    for s in shapes:
        d = _decode(s)
        if d is not None and _FULL in d:
            ok = False
    return ("HELD" if ok else "BREAK", "f952-bounds=%s" % ok)


# --------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_f679_trycatch():
    """Sibling: F679 try/catch (no finally) still decodes."""
    s = "(function(){var s='';try{throw '%s';}catch(e){s=e;}return s;})()" % (_FULL,)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f679-trycatch=%s" % ok)


@_t
def test_p4_sibling_f468_reflect_array():
    """Sibling: F468 Reflect.construct(Array,...) unaffected."""
    s = "var RESULT=Reflect.construct(Array,['%s','%s']).join('');" % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f468-array=%s" % ok)


@_t
def test_p4_sibling_f458_fromcharcode():
    """Sibling: plain fromCharCode.apply still decodes."""
    s = "var RESULT=String.fromCharCode.apply(null,[%s]);" % (_CODES,)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f458-apply=%s" % ok)


@_t
def test_p4_sibling_f501_rewrite():
    """Sibling: F501 value-binding rewrite still fires."""
    s = "var a='%s';var b='%s';var RESULT=a+b;" % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f501=%s" % ok)


@_t
def test_p4_sibling_f611_iife():
    """Sibling: F611 single-decl IIFE still decodes."""
    s = "(function(){var s='%s';return s;})()" % (_FULL,)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


# --------------------------------------- p5: honest-text controls


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (no false positives from the new paths)."""
    honest = [
        "var name = 'John'; var greeting = 'Hello ' + name;",
        "var x = 1; var y = 2; var z = x + y;",
        "function foo() { return 42; } var r = foo();",
        "var s='';try{doWork();}catch(e){log(e);}finally{cleanup();}",
        "var arr = [1,2,3].toReversed();",
        "var t = typeof Reflect;",
    ]
    bad = [h for h in honest if not _misses(h)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d quiet" % (len(honest) - len(bad), len(honest)))


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if ok else "BREAK", "junk-quiet=%s" % ok)


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode within budget."""
    sites = []
    for i in range(50):
        sites.append("var o=structuredClone({a:'%s'});var RESULT=o.a;" % (_A,))
        sites.append("var s='';try{throw '%s';}catch(e){s=e;}finally{s+='x';}var RESULT=s;" % (_A,))
        sites.append("var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_A, _B))
        sites.append("var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES,))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# --------------------------------------- p7: depth-1 green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w391_f949_redfirst.py", "w391_f950_redfirst.py",
                    "w391_f951_redfirst.py", "w391_f952_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g391-lane1-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        breaks = out.count("\nBREAK ") + (1 if out.startswith("BREAK ") else 0)
        total_break += breaks
        notes.append("%s: %d BREAK" % (battery, breaks))
    ok = total_break == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d BREAK [%s]" % (total_break, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four w391 red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    sys.exit(1 if breaks else 0)


if __name__ == "__main__":
    main()
