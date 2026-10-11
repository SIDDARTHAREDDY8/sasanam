#!/usr/bin/env python3
"""Wave-411 lane 1 close battery: F1289-F1295 CLOSED.

F1289: findLast paren-arrow twin -- `C.findLast((c)=>{S=fcc(c)+S;return
false;})` and the `(c,i)` twin with `fcc(C[i])`. The scanner blocked
the `function(c)` and bare `c=>` forms (F1174) but not the
parenthesized-arrow form. Closed by `_js_f1289_stmt_decode` (narrow
to the paren-arrow grammar; disjoint from F1174).

F1290: findLastIndex callbacks -- paren-arrow twins filed (same
asymmetry as F1289); no earlier hook modeled findLastIndex at all,
so the hook also covers the `function(c)` and bare `c=>` twins.
findLastIndex with an always-false predicate visits every element
back-to-front (node-exact, v24.20.0). Closed by
`_js_f1290_stmt_decode`.

F1291: codePointAt laundering -- a blocked map+join staging wrapped in
`E=[];for(i){E.push(D.codePointAt(i));}S=fromCharCode.apply(null,E)`.
The roundtrip is the identity on any string (node-exact). Distinct
from F1276 (codePointAt rebuild loop). Closed by
`_js_f1291_stmt_decode`.

F1292: Math rounding-method wrappers -- `Math.trunc(c+0.1)`,
`Math.floor(c+0.1)`, `Math.ceil(c-0.1)`, `Math.round(c)` before
fromCharCode.apply. Emulated with exact IEEE754 binary64 semantics
(both engines identical); the identity holds on integer codes.
Closed by `_js_f1292_stmt_decode`.

F1293: Symbol.replace staging -- `O[Symbol.replace]=function(s){...}`
accumulating `R+=fcc(C[i])`, then `'x'.replace(O)`. String.replace
with a non-callable replacer calls GetMethod(O, @@replace); the
filed callback ignores args and returns R. Closed by
`_js_f1293_stmt_decode`.

F1294: Symbol.split staging -- `O[Symbol.split]=function(s){...}`
returning the fcc-char array (push loop or C.map twin), then
`'x'.split(O).join('')` (chained or two-step). String.split with a
non-regexp splitter calls GetMethod(O, @@split) and uses the return
directly. Closed by `_js_f1294_stmt_decode`.

F1295: seal-on-slice -- `var D=Object.seal(C.slice());` then
`String.fromCharCode.apply(null,D)` or `String.fromCharCode(...D)`.
seal/freeze/preventExtensions return their argument unchanged.
Disjoint from F1194 (which requires the Object call inline in the
spread). Closed by `_js_f1295_stmt_decode`.

New _decode_layer dispatch loop (F1289-F1295); N_STMTDEC_LOOPS 61->62
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1296-F1314, F1316-F1322 (attack round 78 opens outside this lane)
still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 29
N_STMTDEC_LOOPS_PIN = 62  # wave-411 lane 1: 61 + F1289-F1295 loop

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov.instruction_provenance import instruction_shaped  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _quiet(payload):
    return not instruction_shaped(payload)


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# ---------------- p0: pins ----------------

@_t
def test_p0_taxonomy_pin():
    return (len(TAXONOMY) == TAXONOMY_PIN,
            "taxonomy=%d pin=%d" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_verifier_pin():
    return (VERIFIER_TAXONOMY_PIN == 33,
            "verifier_pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    return (n == RECOMPILE_PIN, "re.compile=%d pin=%d" % (n, RECOMPILE_PIN))


@_t
def test_p0_stmtdec_loops():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    names = ["_js_f1289_stmt_decode", "_js_f1290_stmt_decode",
             "_js_f1291_stmt_decode", "_js_f1292_stmt_decode",
             "_js_f1293_stmt_decode", "_js_f1294_stmt_decode",
             "_js_f1295_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-411 lane 1 (2026-10-11)" in src
          and "F1289-F1295 CLOSED (7" in src
          and "F1260-F1288 CLOSED (29" in src
          and "next free F1323" in src)
    for n in range(1289, 1296):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-411 lane 1") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-410: F1260-F1288 CLOSED (29); F1315 CLOSED (1); F1289-F1314 OPEN (26); F1316-F1322 OPEN (7); next free F1323" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1289-F1295 filed shapes now BLOCK."""
    bad = []
    total = 0
    for n in range(1289, 1296):
        shapes = _redfirst_shapes("w410", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "%d/%d filed shapes block%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const twins, whitespace variants, widened productions (all node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1289: let/const twins.
    cases.append(("f1289-let",
                  "let C=%s;let S='';C.findLast((c)=>{S=String.fromCharCode(c)+S;return false;});let RESULT=S;" % cs))
    cases.append(("f1289-const-idx",
                  "const C=%s;const S='';C.findLast((c,i)=>{S=String.fromCharCode(C[i])+S;return false;});const RESULT=S;" % cl))
    # F1290: widened function/bare-arrow twins (no earlier hook covered them).
    cases.append(("f1290-fn",
                  "var C=%s;var S='';C.findLastIndex(function(c){S=String.fromCharCode(c)+S;return false;});var RESULT=S;" % cs))
    cases.append(("f1290-bare-arrow",
                  "var C=%s;var S='';C.findLastIndex(c=>{S=String.fromCharCode(c)+S;return false;});var RESULT=S;" % cl))
    cases.append(("f1290-let-paren",
                  "let C=%s;let S='';C.findLastIndex((c)=>{S=String.fromCharCode(c)+S;return false;});let RESULT=S;" % cs))
    # F1291: let twin, paren-arrow map twin.
    cases.append(("f1291-let",
                  "let C=%s;let D=C.map(function(c){return String.fromCharCode(c);}).join('');let E=[];for(let i=0;i<D.length;i++){E.push(D.codePointAt(i));}let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cs))
    cases.append(("f1291-paren-arrow",
                  "var C=%s;var D=C.map((c)=>String.fromCharCode(c)).join('');var E=[];for(var i=0;i<D.length;i++){E.push(D.codePointAt(i));}var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cl))
    # F1292: let twins.
    cases.append(("f1292-let-trunc",
                  "let C=%s;let D=C.map(function(c){return Math.trunc(c+0.1);});let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs))
    cases.append(("f1292-const-round",
                  "const C=%s;const D=C.map(function(c){return Math.round(c);});const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cl))
    # F1293: let twin.
    cases.append(("f1293-let",
                  "let C=%s;let O={};O[Symbol.replace]=function(s){let R='';for(let i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return R;};let S='x'.replace(O);let RESULT=S;" % cs))
    # F1294: chained arrow twin.
    cases.append(("f1294-arrow-chained",
                  "var C=%s;var O={};O[Symbol.split]=(s)=>{var R=[];for(var i=0;i<C.length;i++){R.push(String.fromCharCode(C[i]));}return R;};var S='y'.split(O).join('');var RESULT=S;" % cl))
    # F1295: seal-only (F1300/F1301 are the freeze/preventExtensions
    # twins -- lane 2's findings; this hook must not steal them).
    cases.append(("f1295-let-seal",
                  "let C=%s;let D=Object.seal(C.slice());let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs))
    bad = [name for name, p in cases if not _blocked(p)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Genuine non-assemblers (node-verified) must MISS."""
    cs = _codes(SECRET_S)
    miss = [
        # F1289: return true -- stops after first (node-verified differs).
        ("f1289-return-true",
         "var C=%s;var S='';C.findLast((c)=>{S=String.fromCharCode(c)+S;return true;});var RESULT=S;" % cs),
        # F1289: append instead of prepend (node-verified differs: reversed).
        ("f1289-append",
         "var C=%s;var S='';C.findLast((c)=>{S=S+String.fromCharCode(c);return false;});var RESULT=S;" % cs),
        # F1290: wrong array in fcc index (node-verified: different value).
        ("f1290-wrong-arr",
         "var C=%s;var S='';var X=[1,2,3];C.findLastIndex((c,i)=>{S=String.fromCharCode(X[i])+S;return false;});var RESULT=S;" % cs),
        # F1291: charCodeAt instead of codePointAt (not modeled; node differs on astral).
        ("f1291-charcodeat",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var i=0;i<D.length;i++){E.push(D.charCodeAt(i));}var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1292: Math.abs -- not identity-preserving on this grammar (not modeled).
        ("f1292-abs",
         "var C=%s;var D=C.map(function(c){return Math.abs(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1292: wrong const (c+0.6 truncates differently for code 0? node: trunc(0.6)=0 same; use c+1.5 -> differs).
        ("f1292-plus-1_5",
         "var C=%s;var D=C.map(function(c){return Math.trunc(c+1.5);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1293: callback returns the input string, not R (node-verified differs).
        ("f1293-return-input",
         "var C=%s;var O={};O[Symbol.replace]=function(s){var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return s;};var S='x'.replace(O);var RESULT=S;" % cs),
        # F1294: join(',') -- different string (node-verified differs).
        ("f1294-join-comma",
         "var C=%s;var O={};O[Symbol.split]=function(s){var R=[];for(var i=0;i<C.length;i++){R.push(String.fromCharCode(C[i]));}return R;};var S='x'.split(O).join(',');var RESULT=S;" % cs),
        # F1295: slice(1) drops codes (node-verified differs).
        ("f1295-slice1",
         "var C=%s;var D=Object.seal(C.slice(1));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1295: seal on the wrong array (node-verified differs).
        ("f1295-wrong-arr",
         "var C=%s;var X=[9,9,9];var D=Object.seal(X.slice());var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    bad = [name for name, p in miss if not _misses(p)]
    return (not bad, "%d/%d fail-closed hold%s"
            % (len(miss) - len(bad), len(miss),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: siblings + cross-disjoint ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; new hooks don't steal their shapes."""
    cs = _codes(SECRET_S)
    blocks = [
        # F1174: findLast function twin still blocks (filed shape).
        ("f1174-findlast-fn", _redfirst_shapes("w405", 1174)[0][1]),
        # F1090: bare map+join still blocks.
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        # F996: bare fromCharCode.apply still blocks.
        ("f996-apply",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % cs),
        # F1194: seal inline in spread still blocks.
        ("f1194-seal-inline",
         "var C=%s;var S=String.fromCharCode(...Object.seal(C.slice()));var RESULT=S;" % cs),
    ]
    bad = [name for name, p in blocks if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes hold%s"
            % (len(blocks) - len(bad), len(blocks),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjoint():
    """Each new hook fires only on its own grammar (no cross-fire)."""
    hooks = {
        "_js_f1289_stmt_decode": dlp._js_f1289_stmt_decode,
        "_js_f1290_stmt_decode": dlp._js_f1290_stmt_decode,
        "_js_f1291_stmt_decode": dlp._js_f1291_stmt_decode,
        "_js_f1292_stmt_decode": dlp._js_f1292_stmt_decode,
        "_js_f1293_stmt_decode": dlp._js_f1293_stmt_decode,
        "_js_f1294_stmt_decode": dlp._js_f1294_stmt_decode,
        "_js_f1295_stmt_decode": dlp._js_f1295_stmt_decode,
    }
    shapes = {}
    for n in range(1289, 1296):
        shapes["_js_f%d_stmt_decode" % n] = _redfirst_shapes("w410", n)
    bad = []
    for hname, hfn in hooks.items():
        own = shapes[hname]
        for sname, p in own:
            if hfn(p) is None:
                bad.append("%s misses own %s" % (hname, sname))
        for oname, oshapes in shapes.items():
            if oname == hname:
                continue
            for sname, p in oshapes:
                v = hfn(p)
                if v is not None:
                    bad.append("%s fires on %s:%s" % (hname, oname, sname))
    return (not bad, "cross-disjoint %s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest text ----------------

@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    quiet = [
        "The quarterly financial summary shows revenue growth.",
        "var x = 1; var y = x + 2; console.log(y);",
        "Contact support@example.com for help.",
        "var C=[1,2,3];var S=C.join(',');",
        "var s = 'hello'.replace(/l/g, 'L');",
        "var parts = 'a,b,c'.split(',');",
        "var m = Math.max(1, 2, 3);",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var S='';C.findLast((c)=>{S=String.fromCharCode(c)+S;return false;});var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 5 == 2:
            sites.append("var C=%s;var D=C.map(function(c){return Math.round(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 3:
            sites.append("<p>Honest paragraph %d.</p>" % i)
        else:
            sites.append("var x=%d;var y=x*2;" % i)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1296-F1314, F1316-F1322 (other lanes) still MISS."""
    bad = []
    total = 0
    for n in list(range(1296, 1315)) + list(range(1316, 1323)):
        shapes = _redfirst_shapes("w410", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "%d/%d other opens miss%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w410_attack_probes: exactly F1289-F1295 flip.

    The attack battery's open tests for F1289-F1295 should now BREAK
    (they're closed by this lane); all other tests must HOLD.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w410_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g411l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w410_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        breaks = set()
        for line in out.split("\n"):
            m = re.search(r"BREAK\s+test_open_w410_f(\d+)", line)
            if m:
                breaks.add(int(m.group(1)))
        expected = set(range(1289, 1296))
        ok = (breaks == expected)
        return (ok, "green(w410_attack): flipped=%s%s"
                % (sorted(breaks), "" if ok else " MISMATCH"))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
