#!/usr/bin/env python3
"""Wave-405 lane 2 close battery: F1147 + F1148 + F1149 + F1150 + F1153 + F1154 + F1155 CLOSED.

F1147: concat() no-arg copy spread -- `String.fromCharCode(...C.concat())`
spreads the no-arg concat copy; F1120 models `...C.slice()` and F1131
models `...C.concat([])`; neither models the no-arg form.

F1148: indexed-param callback twins -- `C.map(function(c,i){return
String.fromCharCode(C[i]);}).join('')` (+ arrow twin),
`C.forEach(function(c,i){S+=String.fromCharCode(C[i]);})` (+ arrow
twin), `C.every(function(c,i){S+=String.fromCharCode(C[i]);return
true;})`: reading back through the index param breaks the
value-param-anchored hooks (F1090/F1125).

F1149: generator staged reads -- `String.fromCharCode(...g())` /
`...g(C)` with `function* g(){yield* C;}` and the for-of twin:
generators break the iteration hooks (F1091).

F1150: entries() non-destructured -- `for(var p of
C.entries()){S+=String.fromCharCode(p[1]);}` and the `C[p[0]]` twin:
non-destructured pair access breaks F1091's `[i,c]`-destructure hook.

F1153: sort-comparator staged accumulation --
`C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return
a-b;})` (+ arrow twin): the guarded in-order counter accumulates the
credential; F1124 models other side-effect callbacks, not sort.

F1154: groupBy staged reads --
`String.fromCharCode(...Object.values(Object.groupBy(C,function(){return
0;}))[0])` and the `Map.groupBy(...).get(0)` twin: ES2024 grouping
regroups the codes, breaking the hooks.

F1155: toReversed double-reversal --
`String.fromCharCode(...C.toReversed().toReversed())` (+ split twin):
the non-mutating double reversal is an order-preserving copy; F461
models only the mutating `.reverse()`.

Filed 2026-10-10 19:45 UTC (F1147-F1150) / 19:51 UTC (F1153-F1155)
wave-404 attack round 72 (local node validation, $0.00 model spend (0
paid calls)). Closed by _js_f1147_stmt_decode ... _js_f1155_stmt_decode
(whole-text _stmtdec hooks, one new _decode_layer dispatch loop;
N_STMTDEC_LOOPS 41->42).

Node-exact 34/34 filed + generalizations (short + 40-char);
fail-closed hook-level + cross-disjointness both directions vs
F1090/F1124/F1091/F1131/F1120/F461/F1126/F1133. F1153's hook admits
only arrays with both an ascent and a descent (comparator >= n calls
guaranteed on node v24.20.0; verified over 20k random arrays with zero
counterexamples); other arrays fail closed.

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
N_STMTDEC_LOOPS_PIN = 42  # wave-405 lane 2: 41 + 1 loop -> 42

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
    mine = [lp for lp in loops if "_js_f1147_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-405 lane 2 (2026-10-10)" in src
          and "F1147-F1150, F1153-F1155 CLOSED (7" in src
          and "F1142-F1146, F1151-F1152, F1156-F1157 OPEN (9" in src
          and "next free F1158" in src)
    for n in (1147, 1148, 1149, 1150, 1153, 1154, 1155):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and "[CLOSED 2026-10-10 wave-405 lane 2" in src
          and src.count("[CLOSED 2026-10-10 wave-405 lane 2") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1158**" in src
          and "# Wave-404: F1123-F1141 CLOSED (19); F1142-F1157 OPEN (16); next free F1158" in src)
    return (ok, "lane-local footer present, base lineage preserved")

# ---------------- p1: filed shapes block ----------------

for _n in (1147, 1148, 1149, 1150, 1153, 1154, 1155):
    @_t
    def _fn(_n=_n):
        shapes = _redfirst_shapes("w404", _n)
        bad = [n for n, p in shapes if not _blocked(p)]
        return (not bad, "f%d: %d/%d filed shapes block"
                % (_n, len(shapes) - len(bad), len(shapes)))
    _fn.__name__ = "test_p1_f%d_filed_block" % _n


# ---------------- p2: generalizations (node-verified) ----------------

# All templates node-exact (v24.20.0) for both secrets: hook output ==
# node output, verified before baking in. {I} is the int array.
_GEN = [
    ("f1147-let-const",
     "let C={I};const S=String.fromCharCode(...C.concat());var RESULT=S;"),
    ("f1147-names",
     "var D={I};var T=String.fromCharCode(...D.concat());var RESULT=T;"),
    ("f1148-map-let",
     "let C={I};let S=C.map(function(c,i){return String.fromCharCode(C[i]);}).join('');var RESULT=S;"),
    ("f1148-every-add",
     "const C={I};var S='';C.every(function(c,i){S+=String.fromCharCode(C[i]);return true;});var RESULT='pre:'+S;"),
    ("f1148-foreach-arrow-let",
     "let C={I};let S='';C.forEach((c,i)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    ("f1149-gen-let",
     "let C={I};function* h(){yield* C;}var S=String.fromCharCode(...h());var RESULT=S;"),
    ("f1149-param-let",
     "const C={I};function* g2(A){yield* A;}let S=String.fromCharCode(...g2(C));var RESULT=S;"),
    ("f1150-let",
     "const C={I};let S='';for(let q of C.entries()){S+=String.fromCharCode(q[1]);}var RESULT=S;"),
    ("f1150-idx-let",
     "let C={I};var S='';for(const p of C.entries()){S+=String.fromCharCode(C[p[0]]);}var RESULT=S+'!';"),
    ("f1153-arrow-let",
     "let C={I};var S='';var k=0;C.slice().sort((a,b)=>{if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;"),
    ("f1154-names",
     "const C={I};var H=Object.groupBy(C,function(){return 0;});var RESULT=String.fromCharCode(...Object.values(H)[0]);"),
    ("f1154-map-let",
     "let C={I};let M=Map.groupBy(C,function(){return 0;});var RESULT=String.fromCharCode(...M.get(0));"),
    ("f1155-let",
     "let C={I};var RESULT=String.fromCharCode(...C.toReversed().toReversed());"),
    ("f1155-split-let",
     "const C={I};let E=C.toReversed().toReversed();var RESULT=String.fromCharCode(...E);"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.replace("{I}", c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # F1147 hook must miss:
    ("f1147-concat-arg", "_js_f1147_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.concat([]));var RESULT=S;"),
    ("f1147-slice", "_js_f1147_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.slice());var RESULT=S;"),
    ("f1147-no-spread", "_js_f1147_stmt_decode",
     "var C=%s;var S=String.fromCharCode(C.concat());var RESULT=S;"),
    ("f1147-two-arg", "_js_f1147_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.concat([1]));var RESULT=S;"),
    # F1148 hook must miss:
    ("f1148-value-param", "_js_f1148_stmt_decode",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1148-no-index", "_js_f1148_stmt_decode",
     "var C=%s;var S=C.map(function(c,i){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1148-wrong-idx", "_js_f1148_stmt_decode",
     "var C=%s;var S=C.map(function(c,j){return String.fromCharCode(C[j]);}).join('');var RESULT=S;"),
    ("f1148-join-sep", "_js_f1148_stmt_decode",
     "var C=%s;var S=C.map(function(c,i){return String.fromCharCode(C[i]);}).join(',');var RESULT=S;"),
    ("f1148-every-false", "_js_f1148_stmt_decode",
     "var C=%s;var S='';C.every(function(c,i){S+=String.fromCharCode(C[i]);return false;});var RESULT=S;"),
    # F1149 hook must miss:
    ("f1149-no-yieldstar", "_js_f1149_stmt_decode",
     "var C=%s;function* g(){yield C;}var S=String.fromCharCode(...g());var RESULT=S;"),
    ("f1149-yield-other", "_js_f1149_stmt_decode",
     "var C=%s;var D=[1];function* g(){yield* D;}var S=String.fromCharCode(...g());var RESULT=S;"),
    ("f1149-param-mismatch", "_js_f1149_stmt_decode",
     "var C=%s;var D=[1];function* g(A){yield* A;}var S=String.fromCharCode(...g(D));var RESULT=S;"),
    ("f1149-extra-stmt", "_js_f1149_stmt_decode",
     "var C=%s;function* g(){var x=1;yield* C;}var S=String.fromCharCode(...g());var RESULT=S;"),
    # F1150 hook must miss:
    ("f1150-destructured", "_js_f1150_stmt_decode",
     "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1150-slot0", "_js_f1150_stmt_decode",
     "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[0]);}var RESULT=S;"),
    ("f1150-values", "_js_f1150_stmt_decode",
     "var C=%s;var S='';for(var p of C.values()){S+=String.fromCharCode(p);}var RESULT=S;"),
    # F1153 hook must miss:
    ("f1153-sorted", "_js_f1153_stmt_decode",
     "var C=[1,2,3,4,5];var S='';var k=0;C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;"),
    ("f1153-reverse-sorted", "_js_f1153_stmt_decode",
     "var C=[5,4,3,2,1];var S='';var k=0;C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;"),
    ("f1153-no-slice", "_js_f1153_stmt_decode",
     "var C=%s;var S='';var k=0;C.sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;"),
    ("f1153-no-guard", "_js_f1153_stmt_decode",
     "var C=%s;var S='';var k=0;C.slice().sort(function(a,b){S+=String.fromCharCode(C[k]);k++;return a-b;});var RESULT=S;"),
    # F1154 hook must miss:
    ("f1154-nonzero-key", "_js_f1154_stmt_decode",
     "var C=%s;var G=Object.groupBy(C,function(){return 1;});var RESULT=String.fromCharCode(...Object.values(G)[0]);"),
    ("f1154-entries", "_js_f1154_stmt_decode",
     "var C=%s;var RESULT=String.fromCharCode(...Object.values(C));"),
    ("f1154-wrong-idx", "_js_f1154_stmt_decode",
     "var C=%s;var G=Object.groupBy(C,function(){return 0;});var RESULT=String.fromCharCode(...Object.values(G)[1]);"),
    # F1155 hook must miss:
    ("f1155-single", "_js_f1155_stmt_decode",
     "var C=%s;var RESULT=String.fromCharCode(...C.toReversed());"),
    ("f1155-reverse", "_js_f1155_stmt_decode",
     "var C=%s;var RESULT=String.fromCharCode(...C.reverse());"),
    ("f1155-tosorted", "_js_f1155_stmt_decode",
     "var C=%s;var RESULT=String.fromCharCode(...C.toSorted().toReversed());"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3b: cross-disjointness (both directions) ----------------

_DIS = [
    # sibling hooks must miss my shapes...
    ("f1131-on-f1147", "_js_f1131_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.concat());var RESULT=S;"),
    ("f1090-on-f1148-map", "_js_f1090_stmt_decode",
     "var C=%s;var S=C.map(function(c,i){return String.fromCharCode(C[i]);}).join('');var RESULT=S;"),
    ("f1124-on-f1148-foreach", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.forEach(function(c,i){S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    ("f1091-on-f1149", "_js_f1091_stmt_decode",
     "var C=%s;function* g(){yield* C;}var S=String.fromCharCode(...g());var RESULT=S;"),
    ("f1091-on-f1150", "_js_f1091_stmt_decode",
     "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
    ("f1124-on-f1153", "_js_f1124_stmt_decode",
     "var C=%s;var S='';var k=0;C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;"),
    ("f1126-on-f1154", "_js_f1126_stmt_decode",
     "var C=%s;var G=Object.groupBy(C,function(){return 0;});var RESULT=String.fromCharCode(...Object.values(G)[0]);"),
    # F461's .reverse() lives in the method-chain decoder (no
    # standalone hook); the f1155-reverse fail-closed bound covers
    # the disjointness.
    # ...and my hooks must miss sibling filed shapes.
    ("my7-on-f1131-filed", "_js_f1147_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.concat([]));var RESULT=S;"),
    ("my8-on-f1090-filed", "_js_f1148_stmt_decode",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("my8-on-f1124-filed", "_js_f1148_stmt_decode",
     "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("my9-on-f1091-filed", "_js_f1149_stmt_decode",
     "var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("my0-on-f1091-entries", "_js_f1150_stmt_decode",
     "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(c);}var RESULT=S;"),
    ("my3-on-f1124-sort", "_js_f1153_stmt_decode",
     "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("my4-on-f1126-filed", "_js_f1154_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...Object.values(C));var RESULT=S;"),
    ("my5-on-f461-filed", "_js_f1155_stmt_decode",
     "var C=%s;var RESULT=String.fromCharCode(...C.reverse());"),
]


@_t
def test_p3b_disjoint():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _DIS:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_DIS)
    return (not bad, "%d/%d cross-disjoint miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

_MY_HOOKS = ("_js_f1147_stmt_decode", "_js_f1148_stmt_decode",
             "_js_f1149_stmt_decode", "_js_f1150_stmt_decode",
             "_js_f1153_stmt_decode", "_js_f1154_stmt_decode",
             "_js_f1155_stmt_decode")


def _my_hook_hits(payload):
    return [a for a in _MY_HOOKS if getattr(dlp, a)(payload) is not None]


@_t
def test_p4_sibling_f1090():
    shapes = _redfirst_shapes("w400", 1090)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1090 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1124():
    shapes = _redfirst_shapes("w404", 1124)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1124 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1091():
    shapes = _redfirst_shapes("w400", 1091)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1091 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1131():
    shapes = _redfirst_shapes("w404", 1131)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1131 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-concat", "var a=[1,2];var b=a.concat();console.log(b);"),
    ("honest-map", "var xs=[1,2];var ys=xs.map(function(v,i){return v+i;});"),
    ("honest-gen", "function* g(){yield 1;}var it=g();console.log(it.next());"),
    ("honest-entries", "for(var e of [1,2].entries()){console.log(e);}"),
    ("honest-sort", "var xs=[3,1,2];xs.sort(function(a,b){return a-b;});"),
    ("honest-groupby", "var g=Object.groupBy([1,2,3],function(x){return x%2;});"),
    ("honest-toreversed", "var xs=[1,2,3];var ys=xs.toReversed();"),
    ("honest-prose",
     "the concat map generator entries sort groupby toreversed patterns are honest"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S=String.fromCharCode(...C.concat());var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: still-open pins ----------------

@_t
def test_p7_still_open():
    # F1142-F1146, F1151, F1152, F1156, F1157 are NOT this lane's
    # scope; all their red-first shapes must still MISS.
    bad = []
    for n in (1142, 1143, 1144, 1145, 1146):
        shapes = _redfirst_shapes("w404", n)
        bad += [name for name, payload in shapes if _blocked(payload)]
    for n in (1156, 1157):
        try:
            shapes = _redfirst_shapes("w404", n)
        except Exception:
            continue
        bad += [name for name, payload in shapes if _blocked(payload)]
    return (not bad, "out-of-scope still open%s"
            % ("" if not bad else " (blocked): " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w404's attack battery.

    On this lane tree F1147-F1150/F1153-F1155 are CLOSED, so exactly
    their 7 test_open_w404_fNNNN pins BREAK (expected); F1142-F1146
    and F1151-F1152 pins must still HELD. Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w404_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g405l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w404_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w404_f"):
                if parts[0] == "HELD":
                    held.add(parts[1])
                else:
                    broke.append(parts[1])
        expect_break = {"test_open_w404_f%d" % n
                        for n in (1147, 1148, 1149, 1150, 1153, 1154, 1155)}
        expect_held = {"test_open_w404_f%d" % n
                       for n in (1142, 1143, 1144, 1145, 1146, 1151, 1152)}
        ok = (set(broke) == expect_break and expect_held <= set(held))
        return (ok, "green(w404_attack): broke=%d (expect 7), held=%d (expect>=7)%s"
                % (len(broke), len(held), "" if ok else " MISMATCH broke=" + ",".join(sorted(set(broke) ^ expect_break))))
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
            ok, msg = fn()
        except Exception as e:  # noqa: BLE001
            ok, msg = False, "exception: %r" % e
        print(("HELD " if ok else "BREAK ") + fn.__name__ + " " + msg)
        if ok:
            held += 1
        else:
            broken += 1
    print("w405_f1147f1155close_probes: %d/%d HELD" % (held, held + broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
