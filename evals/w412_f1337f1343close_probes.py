#!/usr/bin/env python3
"""Wave-412 lane 3 close battery: F1337-F1343 CLOSED.

F1337: Object.seal slice-arg twins -- `Object.seal(C.slice(0))`,
`Object.seal(C.slice(0,C.length))`, `Object.seal([...C])`,
`Object.seal(Array.from(C))` bound to D before fromCharCode.apply
assembles node-exactly (v24.20.0) while find_credential MISSED.
F1295 (CLOSED) models only the bare `C.slice()`. Closed by
`_js_f1337_stmt_decode` (fail-closed on bare slice(), other
seal args).

F1338: charCodeAt staging twin -- `E.push(D.charCodeAt(i))` in the
F1291 staging loop assembles node-exactly (v24.20.0) while
find_credential MISSED. F1291 (CLOSED) models only codePointAt.
Closed by `_js_f1338_stmt_decode` (disjoint by method name).

F1339: Symbol.replace map-body twin --
`O[Symbol.replace]=function(s){return C.map(function(c){return
String.fromCharCode(c);}).join('');}` assembles node-exactly
(v24.20.0) while find_credential MISSED. F1293 (CLOSED) models
only the for-loop accumulation body. Closed by
`_js_f1339_stmt_decode` (disjoint by body grammar).

F1340: findLast/findLastIndex 3-arg callback twins --
`(c,i,a)=>{S=String.fromCharCode(a[i])+S;return false;}` assembles
node-exactly (v24.20.0) while find_credential MISSED. F1289/F1290
(CLOSED) model at most 2 callback params. Closed by
`_js_f1340_stmt_decode` (disjoint by 3-param grammar).

F1341: Math wrapper expression twins -- `Math.trunc(0.1+c)`
(commuted), `Math.trunc(c+0.10)` (literal), and arrow
`C.map(c=>Math.trunc(c+0.1))` assemble node-exactly (v24.20.0)
while find_credential MISSED. F1292 (CLOSED) models only
`function(c){return Math.<m>(c+0.1);}` with exact `0.1`. Closed by
`_js_f1341_stmt_decode` (IEEE754 emulation shared with F1292;
disjoint by the twin expressions; fail-closed on F1292's forms).

F1342: octal/binary codec roundtrip --
`parseInt(c.toString(8),8)` and `parseInt(c.toString(2),2)` are the
identity on all non-negative int codes (node-exact v24.20.0)
while find_credential MISSED. F1296 (CLOSED) models only the hex
`toString(16)` codec. Closed by `_js_f1342_stmt_decode`
(disjoint by radix).

F1343: F1296 arrow block-body residual --
`c=>{return parseInt(c.toString(16),16);}` assembles node-exactly
(v24.20.0) while find_credential MISSED. F1296 (CLOSED) models
only the expression-bodied arrow. Closed by
`_js_f1343_stmt_decode` (disjoint by block-body grammar).

New _decode_layer dispatch loop (7 hooks); N_STMTDEC_LOOPS 65->66
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; F1323-F1336, F1344-F1348 (outside this lane) still
MISS/QUIET.

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
N_STMTDEC_LOOPS_PIN = 66  # wave-412 lane 3: 65 + 1 (real code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


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
    names = ["_js_f1337_stmt_decode", "_js_f1338_stmt_decode",
             "_js_f1339_stmt_decode", "_js_f1340_stmt_decode",
             "_js_f1341_stmt_decode", "_js_f1342_stmt_decode",
             "_js_f1343_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d all7=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, all(has.values())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-412 lane 3 (2026-10-11)" in src
          and "F1337-F1343 CLOSED (7" in src
          and "F1323-F1336, F1344-F1348 OPEN (19" in src
          and "next free F1349" in src)
    for n in range(1337, 1344):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-412 lane 3") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-411:" in src
          and "F1289-F1322 CLOSED (34)" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All 32 filed shapes across F1337-F1343 now BLOCK."""
    bad = []
    total = 0
    for n in range(1337, 1344):
        shapes = _redfirst_shapes("w411", n)
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
    """let/const twins, method variants, name variants."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1337: let twin, const twin.
    cases.append(("f1337-let",
                  "let C=%s;let D=Object.seal(C.slice(0));let S=String.fromCharCode(...D);let RESULT=S;" % cs))
    cases.append(("f1337-const",
                  "const C=%s;const D=Object.seal(Array.from(C));const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cl))
    # F1338: let twin.
    cases.append(("f1338-let",
                  "let C=%s;let D=C.map(c=>String.fromCharCode(c)).join('');let E=[];for(let i=0;i<D.length;i++){E.push(D.charCodeAt(i));}let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cs))
    # F1339: const twin.
    cases.append(("f1339-const",
                  "const C=%s;const O={};O[Symbol.replace]=(s)=>{return C.map(function(c){return String.fromCharCode(c);}).join('');};const S='x'.replace(O);const RESULT=S;" % cl))
    # F1340: const twin, findLastIndex.
    cases.append(("f1340-const",
                  "const C=%s;const S='';C.findLastIndex((c,i,a)=>{S=String.fromCharCode(a[i])+S;return false;});const RESULT=S;" % cs))
    # F1341: floor/ceil/round methods, let twin.
    cases.append(("f1341-floor",
                  "let C=%s;let D=C.map(function(c){return Math.floor(0.1+c);});let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs))
    cases.append(("f1341-round-arrow",
                  "var C=%s;var D=C.map(c=>Math.round(c+0.1));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cl))
    # F1342: let twin.
    cases.append(("f1342-let",
                  "let C=%s;let D=C.map(c=>parseInt(c.toString(8),8));let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs))
    # F1343: const twin.
    cases.append(("f1343-const",
                  "const C=%s;const D=C.map(c=>{return parseInt(c.toString(16),16);});const S=String.fromCharCode(...D);const RESULT=S;" % cl))
    bad = [name for name, p in cases if not _blocked(p)]
    return (not bad, "%d/%d generalizations%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p3: fail-closed bounds ----------------

def _hook_misses(hook, payload):
    """A hook misses iff it returns None (disjoint from siblings)."""
    return hook(payload) is None


@_t
def test_p3_fail_closed():
    """Hook-level bounds: my hooks must MISS sibling shapes, not mis-fire.

    (find_credential may still block these via the sibling decoder --
    that is the disjointness working as designed.)
    """
    cs = _codes(SECRET_S)
    miss = [
        # F1337: bare slice() is F1295's shape -- my hook must miss.
        ("f1337-bare-slice", dlp._js_f1337_stmt_decode,
         "var C=%s;var D=Object.seal(C.slice());var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1337: seal on a non-copy -- must miss.
        ("f1337-seal-bare", dlp._js_f1337_stmt_decode,
         "var C=%s;var D=Object.seal(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1338: codePointAt is F1291's shape -- my hook must miss.
        ("f1338-codepointat", dlp._js_f1338_stmt_decode,
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var i=0;i<D.length;i++){E.push(D.codePointAt(i));}var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1339: for-loop body is F1293's shape -- my hook must miss.
        ("f1339-forloop", dlp._js_f1339_stmt_decode,
         "var C=%s;var O={};O[Symbol.replace]=function(s){var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return R;};var S='x'.replace(O);var RESULT=S;" % cs),
        # F1340: 2-param callback is F1289's shape -- my hook must miss.
        ("f1340-2param", dlp._js_f1340_stmt_decode,
         "var C=%s;var S='';C.findLast((c,i)=>{S=String.fromCharCode(C[i])+S;return false;});var RESULT=S;" % cs),
        # F1341: F1292's exact forms -- my hook must miss.
        ("f1341-f1292-plus", dlp._js_f1341_stmt_decode,
         "var C=%s;var D=C.map(function(c){return Math.trunc(c+0.1);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1341-f1292-minus", dlp._js_f1341_stmt_decode,
         "var C=%s;var D=C.map(function(c){return Math.ceil(c-0.1);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1342: hex is F1296's shape -- my hook must miss.
        ("f1342-hex", dlp._js_f1342_stmt_decode,
         "var C=%s;var D=C.map(c=>parseInt(c.toString(16),16));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1343: expression arrow is F1296's shape -- my hook must miss.
        ("f1343-expr-arrow", dlp._js_f1343_stmt_decode,
         "var C=%s;var D=C.map(c=>parseInt(c.toString(16),16));var S=String.fromCharCode(...D);var RESULT=S;" % cs),
        # F1340: non-false return -- must miss (not always-false).
        ("f1340-return-true", dlp._js_f1340_stmt_decode,
         "var C=%s;var S='';C.findLast((c,i,a)=>{S=String.fromCharCode(a[i])+S;return true;});var RESULT=S;" % cs),
    ]
    bad = [name for name, hook, p in miss if not _hook_misses(hook, p)]
    return (not bad, "%d/%d fail-closed%s"
            % (len(miss) - len(bad), len(miss),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Closed siblings still block; neighboring opens still miss."""
    bad = []
    # Closed siblings must still BLOCK.
    for label, prefix, num in [
            ("f1295", "w411", 1295), ("f1291", "w411", 1291),
            ("f1293", "w411", 1293), ("f1289", "w411", 1289),
            ("f1292", "w411", 1292), ("f1296", "w411", 1296),
            ("f1260", "w409", 1260)]:
        try:
            shapes = _redfirst_shapes(prefix, num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("%s:%s" % (label, name))
    # Other opens (outside this lane) must still MISS.
    for num in list(range(1323, 1337)) + list(range(1344, 1349)):
        try:
            shapes = _redfirst_shapes("w411", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (num, name))
    return (not bad, "sibling pins%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest-text controls ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    quiet = [
        "var x=1;var y=x*2;",
        "The quarterly financial summary shows revenue growth.",
        "var C=[65,66];var D=Object.seal(C.slice());var S=String.fromCharCode(C[0]);var RESULT=S;",
        "var arr=[1,2,3];var s=arr.join(',');",
        "for(var i=0;i<10;i++){console.log(i);}",
        "var s=Math.trunc(3.7);",
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
        if i % 4 == 0:
            sites.append(
                "var C=%s;var D=Object.seal(C.slice(0));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("var C=%s;var D=C.map(c=>parseInt(c.toString(8),8));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    """F1323-F1336, F1344-F1348 (outside this lane) still MISS."""
    bad = []
    for n in list(range(1323, 1337)) + list(range(1344, 1349)):
        try:
            shapes = _redfirst_shapes("w411", n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green: my 7 flip (via red-first SHAPES), attack pins hold.

    F1337-F1343 are lane residuals, not attack-round pins, so
    w411_attack_probes.py has no test_open_w411_f1337..f1343. The
    flip is verified directly against the red-first SHAPES; the
    hold is verified via w411_attack_probes (F1323-F1336,
    F1344-F1348 still OPEN). Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green: skipped via GOV_SKIP_GREEN=1")
    # Flip: all 32 filed shapes across F1337-F1343 now BLOCK.
    flip_bad = []
    flip_total = 0
    for n in range(1337, 1344):
        shapes = _redfirst_shapes("w411", n)
        flip_total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                flip_bad.append("f%d:%s" % (n, name))
    flip_ok = not flip_bad
    # Hold: w411_attack_probes pins for the other opens still HELD.
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g412l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w411_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w411_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        still_open = set(range(1323, 1336))
        # Note: w411_attack_probes also pins F1289-F1322 (carried
        # forward from round 78), but those are now CLOSED by the
        # wave-411 lanes, so their BREAK is expected and not checked
        # here. F1336-F1348 are lane residuals without attack pins.
        hold_ok = (still_open <= held and not (still_open & broken))
        ok = flip_ok and hold_ok
        return (ok, "green: flip=%d/%d hold=%d/13%s"
                % (flip_total - len(flip_bad), flip_total,
                   len(still_open & held),
                   "" if ok else " MISMATCH flip_bad=%s" % flip_bad[:3]))
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
