#!/usr/bin/env python3
"""Wave-404 lane 2 close battery: F1124-F1130 CLOSED.

F1124: side-effect higher-order callbacks -- staging credential
assembly through side-effect callbacks on higher-order methods
beyond F1090's forEach/every coverage: `find`/`some`
(never-satisfied predicate), `filter` (always-true), `flatMap`
(empty return), and bare `map` with accumulation in the callback
and the result discarded.

F1125: arrow-function callback twins -- F1090's higher-order hooks
anchor on `function`-expression callbacks: the arrow-function twins
of its forEach/every/flatMap+join/map+join/find productions.

F1126: Object.entries staged assembly -- staging through
`Object.entries(C)` index/value pairs: map+join over `p[1]`, for-of
over the pairs, reduce with destructured pair, and the
`Object.fromEntries`/`Object.values` roundtrip.

F1127: push-then-join accumulation -- accumulating chars with
`Array.push` (indexed loop or forEach) then `join('')`.

F1128: reverse-iteration prepend accumulation -- reverse-order
iteration with prepend accumulation (`for` from `length-1`, the
`i--` idiom, `while`+`pop` over a copy).

F1129: template-literal accumulation -- accumulating with
template-literal reassignment
(``S=`${S}${String.fromCharCode(C[i])}` ``).

F1130: manual iterator .next() loop -- driving the iteration
protocol manually (`.next()` loop over `C[Symbol.iterator]()` or
`C.entries()`).

All filed 2026-10-10 18:13 UTC by wave-403 attack round 71 (local
node validation, $0.00 model spend (0 paid calls); LOW, OPEN).

Closed by _js_f1124_stmt_decode through _js_f1130_stmt_decode
(whole-text _stmtdec hooks, one new _decode_layer dispatch loop,
N_STMTDEC_LOOPS 38->39). Node-exact 46/46 filed + 15/15
generalizations (short + 40-char, v24.20.0); fail-closed 14/14
hook-level (incl. cross-disjointness 0/276 both directions vs the
other six new hooks and 0 hits on sibling shapes).

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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 41  # wave-404 merge: 38 + 3 loops (lanes 2,3,4) -> 41

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


_NEW_HOOKS = ("_js_f1124_stmt_decode", "_js_f1125_stmt_decode",
              "_js_f1126_stmt_decode", "_js_f1127_stmt_decode",
              "_js_f1128_stmt_decode", "_js_f1129_stmt_decode",
              "_js_f1130_stmt_decode")


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
    mine = [lp for lp in loops if "_js_f1124_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-404 lane 2 (2026-10-10)" in src
          and "F1124-F1130 CLOSED (7" in src
          and "F1123, F1131-F1141 OPEN (12" in src
          and "next free F1142" in src)
    for n in (1124, 1125, 1126, 1127, 1128, 1129, 1130):
        ok = ok and src.count("(F%d filed" % n) == 1
        ok = ok and ("[CLOSED 2026-10-10 wave-404 lane 2" in src)
    ok = ok and src.count("[CLOSED 2026-10-10 wave-404 lane 2") == 7
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1142**" in src
          and "# Wave-403: F1111-F1122 CLOSED (12); F1123-F1141 OPEN (19); next free F1142" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1124_filed_block():
    shapes = _redfirst_shapes("w403", 1124)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1125_filed_block():
    shapes = _redfirst_shapes("w403", 1125)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1126_filed_block():
    shapes = _redfirst_shapes("w403", 1126)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1127_filed_block():
    shapes = _redfirst_shapes("w403", 1127)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1128_filed_block():
    shapes = _redfirst_shapes("w403", 1128)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1129_filed_block():
    shapes = _redfirst_shapes("w403", 1129)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1130_filed_block():
    shapes = _redfirst_shapes("w403", 1130)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-verified) ----------------

_GEN = [
    # (name, template with {I} for the int array; all node-exact v24.20.0)
    ("f1124-let",
     "let C={I};let S='';C.find(function(c){{S+=String.fromCharCode(c);return false;}});let RESULT=S;"),
    ("f1124-names",
     "var D={I};var T='';D.some(function(c){{T+=String.fromCharCode(c);return false;}});var RESULT=T;"),
    ("f1124-additive",
     "var C={I};var S='';C.filter(function(c){{S+=String.fromCharCode(c);return true;}});var RESULT='pre:'+S;"),
    ("f1125-let",
     "let C={I};let S='';C.forEach((c)=>{{S+=String.fromCharCode(c);}});let RESULT=S;"),
    ("f1125-names",
     "var D={I};var T='';D.every((c)=>{{T+=String.fromCharCode(c);return true;}});var RESULT=T;"),
    ("f1125-additive",
     "var C={I};var S=C.map((c)=>String.fromCharCode(c)).join('');var RESULT=S+'!';"),
    ("f1126-let",
     "let C={I};let S=Object.entries(C).map(function(p){{return String.fromCharCode(p[1]);}}).join('');let RESULT=S;"),
    ("f1126-names",
     "var D={I};var T='';for(var q of Object.entries(D)){{T+=String.fromCharCode(q[1]);}}var RESULT=T;"),
    ("f1127-let",
     "let C={I};let A=[];for(let i=0;i<C.length;i++){{A.push(String.fromCharCode(C[i]));}}let S=A.join('');let RESULT=S;"),
    ("f1127-names",
     "var D={I};var B=[];D.forEach(function(c){{B.push(String.fromCharCode(c));}});var T=B.join('');var RESULT=T;"),
    ("f1128-let",
     "let C={I};let S='';for(let i=C.length-1;i>=0;i--){{S=String.fromCharCode(C[i])+S;}}let RESULT=S;"),
    ("f1128-names",
     "var D={I};var T='';for(var j=D.length;j--;){{T=String.fromCharCode(D[j])+T;}}var RESULT=T;"),
    ("f1129-let",
     "let C={I};let S='';for(let i=0;i<C.length;i++){{S=`${{S}}${{String.fromCharCode(C[i])}}`;}}let RESULT=S;"),
    ("f1130-let",
     "let C={I};let S='';let it=C[Symbol.iterator]();let r;while(!(r=it.next()).done){{S+=String.fromCharCode(r.value);}}let RESULT=S;"),
    ("f1130-names",
     "var D={I};var T='';var it2=D.entries();var r2;while(!(r2=it2.next()).done){{T+=String.fromCharCode(r2.value[1]);}}var RESULT=T;"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # (name, hook-attr, template with %s for the int-array codes)
    ("f1124-find-return-true", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return true;});var RESULT=S;"),
    ("f1124-foreach-not-mine", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1124-nonempty-acc", "_js_f1124_stmt_decode",
     "var C=%s;var S='x';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("f1124-bad-param", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.find(function(x){S+=String.fromCharCode(x);return false;});var RESULT=S;"),
    ("f1125-function-not-arrow", "_js_f1125_stmt_decode",
     "var C=%s;var S='';C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1125-every-return-false", "_js_f1125_stmt_decode",
     "var C=%s;var S='';C.every((c)=>{S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("f1126-centries-not-mine", "_js_f1126_stmt_decode",
     "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
    ("f1126-wrong-index", "_js_f1126_stmt_decode",
     "var C=%s;var S='';for(var p of Object.entries(C)){S+=String.fromCharCode(p[0]);}var RESULT=S;"),
    ("f1127-join-comma", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var S=A.join(',');var RESULT=S;"),
    ("f1128-forward-prepend", "_js_f1128_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S=String.fromCharCode(C[i])+S;}var RESULT=S;"),
    ("f1128-plus-equals", "_js_f1128_stmt_decode",
     "var C=%s;var S='';for(var i=C.length-1;i>=0;i--){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1129-plus-equals", "_js_f1129_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1129-template-extra", "_js_f1129_stmt_decode",
     "var C=%s;var S='';for(var i=0;i<C.length;i++){S=`${S}!${String.fromCharCode(C[i])}`;}var RESULT=S;"),
    ("f1130-forof-not-mine", "_js_f1130_stmt_decode",
     "var C=%s;var S='';for(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        p = tmpl % c
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_cross_disjoint():
    # No new hook hits another new finding's shapes (both directions).
    bad = []
    for n in (1124, 1125, 1126, 1127, 1128, 1129, 1130):
        shapes = _redfirst_shapes("w403", n)
        for m_attr in _NEW_HOOKS:
            if m_attr == "_js_f%d_stmt_decode" % n:
                continue
            hook = getattr(dlp, m_attr)
            for name, p in shapes:
                if hook(p) is not None:
                    bad.append("%s-on-%s" % (m_attr, name))
    return (not bad, "cross-disjoint 0 hits%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p4: sibling pins ----------------

_SIBS = [
    # (finding, red-first prefix, sibling hook attr or None)
    (1090, "w400", "_js_f1090_stmt_decode"),
    (1091, "w400", "_js_f1091_stmt_decode"),
    (1074, "w398", None),
    (1075, "w398", None),
    (1119, "w403", "_js_f1119_stmt_decode"),
    (1110, "w402", "_js_f1110_stmt_decode"),
    (1057, "w396", None),
    (996, "w392", None),
]


@_t
def test_p4_siblings():
    bad = []
    for num, prefix, _hook_attr in _SIBS:
        shapes = _redfirst_shapes(prefix, num)
        for name, p in shapes:
            if not _blocked(p):
                bad.append("unblocked-%s" % name)
            for m_attr in _NEW_HOOKS:
                hook = getattr(dlp, m_attr)
                if hook(p) is not None:
                    bad.append("newhook-%s-on-%s" % (m_attr, name))
    return (not bad, "siblings block, 0 new-hook hits%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-foreach",
     "var xs=[1,2];var t='';xs.forEach(function(x){t+=x;});"),
    ("honest-arrow",
     "var xs=[1,2];var t=xs.map((x)=>x*2);"),
    ("honest-entries",
     "var o={a:1};for(var k of Object.keys(o)){console.log(k);}"),
    ("honest-push-join",
     "var a=[];a.push('x');var s=a.join(',');"),
    ("honest-template",
     "var n='world';var s=`hello ${n}`;"),
    ("honest-prose",
     "the side-effect callback accumulates characters in order"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet"
            % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';C.find(function(c)"
            "{S+=String.fromCharCode(c);return false;});var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: still-open pins ----------------

@_t
def test_p7_open_f1123_f1131_1141():
    # Merged tree: F1123 and F1131-F1141 are now CLOSED (wave-404 lanes
    # 1, 3, 4); all their red-first shapes must BLOCK. (On the lane tree
    # they were still OPEN.)
    bad = []
    for n in (1123, 1131, 1132, 1133, 1134, 1135, 1136, 1137,
              1138, 1139, 1140, 1141):
        shapes = _redfirst_shapes("w403", n)
        bad += [name for name, payload in shapes if _misses(payload)]
    return (not bad, "F1123,F1131-F1141 now closed%s"
            % ("" if not bad else " (missed): " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w403's attack battery (F1123-F1140 flipped
    to CLOSED on the merged tree). Honor GOV_SKIP_GREEN. All 18 closed
    pins must HELD (every shape blocks)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w403_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g404l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w403_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = []   # closed pins that HELD (all shapes block) -- expect all 18
        broke = []  # closed pins that BREAK (a shape still misses) -- bad
        for line in r.stdout.split("\n"):
            # lines are "HELD  test_closed_w403_f1123 (22 shapes)" (two spaces)
            if "test_closed_w403_f" not in line:
                continue
            is_break = line.lstrip().startswith("BREAK")
            is_held = line.lstrip().startswith("HELD")
            if not (is_break or is_held):
                continue
            m = re.search(r"test_closed_w403_f(\d+)", line)
            if not m:
                continue
            n = int(m.group(1))
            (held if is_held else broke).append(n)
        ok = (sorted(held) == list(range(1123, 1141)) and not broke)
        return (ok, "green(w403_attack): closed-held=%d (%s)"
                % (len(held), "ok" if ok else "BAD broke=%s" % broke))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

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
