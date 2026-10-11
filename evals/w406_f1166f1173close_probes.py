#!/usr/bin/env python3
"""Wave-406 lane 2 close battery: F1166-F1173 CLOSED (8).

F1166: double reverse() on copy -- `C.slice().reverse().reverse()`
(chained) or `C.slice();D.reverse();D.reverse();` (statement-split):
the double reversal is a no-op, so spreading the copy assembles the
credential. F1139 models single C.reverse(); F1155 models
toReversed().toReversed().

F1167: decodeURI percent-decoding assembly --
`C.map(function(c){return '%'+c.toString(16);}).join('')` (+ arrow
twin) then `decodeURI(E)`. F1138 models unescape(); decodeURI is a
different function. Codes restricted to [0x10,0x7F] excluding
decodeURI-reserved (%23 %24 %26 %2B %2C %2F %3A %3B %3D %3F %40);
codes < 0x10 or >= 0x80 make decodeURI throw, so they fail closed.

F1168: rest-destructuring staged copy -- `var [...R]=C` then
`String.fromCharCode(...R)` or an indexed `R[i]` loop. F1120 models
`...[...C]`, `[].concat(C)`, `Array.of(...C)`; the rest-destructure
form is unmodeled.

F1169: copyWithin staged reads -- `[pad].concat([codes])`,
`D=C.slice();D.copyWithin(0,K)` (K == len(pad)),
`String.fromCharCode(...D.slice(0,N))` (N == len(codes)). No existing
hook models copyWithin.

F1170: replace/replaceAll function-replacer accumulation --
`T='<1char>'.repeat(C.length)` then `T.replace(/./g,fn)` or
`T.replaceAll('<ch>',fn)` where fn appends
`String.fromCharCode(C[i])` per match. F1124 models array-method
side-effect callbacks; the String.replace family is unmodeled. The
replaceAll search char must equal the repeated T char.

F1171: with()/toSpliced() no-op copies -- `C.with(0,C[0])` and
`C.toSpliced(0,0)` are order-preserving copies; spreading assembles
the credential. Only the exact no-op argument shapes are modeled.

F1172: Array.from staged copies -- `Array.from(C)` or
`Array.from(C,<identity>)`; F1120 models `[].concat(C)`, `C.slice()`,
`Array.of(...C)`. Only the identity mapFn is modeled.

F1173: entries()/values() decoupled-index reads --
`for(var [i] of C.entries()){S+=String.fromCharCode(C[i]);}` or
`V=C.values()` with a separate counter. F1091 anchors on the loop
variable carrying the value; F1150 models p[1]/C[p[0]] pair access.

Filed 2026-10-11 00:30 UTC wave-405 attack round 73 (local node
validation, $0.00 model spend (0 paid calls)). Closed by
_js_f1166_stmt_decode ... _js_f1173_stmt_decode (whole-text _stmtdec
hooks, one new _decode_layer dispatch loop; N_STMTDEC_LOOPS 43->44).

Node-exact 32/32 filed + generalizations (short + 40-char);
fail-closed hook-level + cross-disjointness both directions vs
F1139/F1155/F1138/F1120/F1124/F1090/F1091/F1150/F1136.

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
N_STMTDEC_LOOPS_PIN = 44  # wave-406 lane 2: 43 + 1 loop -> 44

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
    mine = [lp for lp in loops if "_js_f1166_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-406 lane 2 (2026-10-11)" in src
          and "F1166-F1173 CLOSED (8" in src
          and "F1159-F1165, F1174-F1181 OPEN (15" in src
          and "next free F1182" in src)
    for n in range(1166, 1174):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and "[CLOSED 2026-10-11 wave-406 lane 2" in src
          and src.count("[CLOSED 2026-10-11 wave-406 lane 2") == 8)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1182**" in src
          and "# Wave-405: F1142-F1158 CLOSED (17); F1159-F1181 OPEN (23); next free F1182" in src)
    return (ok, "lane-local footer present, base lineage preserved")

# ---------------- p1: filed shapes block ----------------

for _n in range(1166, 1174):
    @_t
    def _fn(_n=_n):
        shapes = _redfirst_shapes("w405", _n)
        bad = [n for n, p in shapes if not _blocked(p)]
        return (not bad, "f%d: %d/%d filed shapes block"
                % (_n, len(shapes) - len(bad), len(shapes)))
    _fn.__name__ = "test_p1_f%d_filed_block" % _n


# ---------------- p2: generalizations (node-verified) ----------------

# All templates node-exact (v24.20.0): hook output == node RESULT,
# verified before baking in. {I} is the int array, {N} its length.
_GEN = [
    ("f1166-let-const",
     "let C={I};const D=C.slice().reverse().reverse();let S=String.fromCharCode(...D);var RESULT='pre:'+S;"),
    ("f1166-names",
     "var A={I};var B=A.slice();B.reverse();B.reverse();var T=String.fromCharCode(...B);var RESULT=T;"),
    ("f1167-const-arrow",
     "const C={I};let E=C.map(x=>'%'+x.toString(16)).join('');const S=decodeURI(E);var RESULT=S+'!';"),
    ("f1167-names",
     "var A={I};var E2=A.map(function(q){return '%'+q.toString(16);}).join('');var T=decodeURI(E2);var RESULT=T;"),
    ("f1168-let-loop",
     "let C={I};const [...R]=C;let S='';for(let j=0;j<R.length;j++){S=S+String.fromCharCode(R[j]);}var RESULT=S;"),
    ("f1168-names",
     "var A={I};var [...B]=A;var T=String.fromCharCode(...B);var RESULT=T;"),
    ("f1169-four-pad",
     "const C=[0,0,0,0].concat({I});const D=C.slice();D.copyWithin(0,4);const S=String.fromCharCode(...D.slice(0,{N}));var RESULT=S;"),
    ("f1169-names",
     "var A=[0,0].concat({I});var B=A.slice();B.copyWithin(0,2);var T=String.fromCharCode(...B.slice(0,{N}));var RESULT=T;"),
    ("f1170-x-char",
     "let C={I};const T='x'.repeat(C.length);let S='';T.replaceAll('x',function(a,b){S+=String.fromCharCode(C[b]);return a;});var RESULT=S;"),
    ("f1170-regex-let",
     "const C={I};var T='q'.repeat(C.length);var S='';T.replace(/./g,function(m,i){S=S+String.fromCharCode(C[i]);return m;});var RESULT=S;"),
    ("f1171-names",
     "var A={I};var B=A.with(0,A[0]);var T=String.fromCharCode(...B);var RESULT=T;"),
    ("f1171-tospliced-let",
     "let C={I};let D=C.toSpliced(0,0);let S=String.fromCharCode(...D);var RESULT='!'+S;"),
    ("f1172-arrow",
     "let C={I};var D=Array.from(C,c=>c);let S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1172-names",
     "var A={I};var B=Array.from(A);var T=String.fromCharCode(...B);var RESULT=T;"),
    ("f1173-const-key",
     "const C={I};let S='';for(const [k] of C.entries()){S+=String.fromCharCode(C[k]);}var RESULT=S;"),
    ("f1173-values-names",
     "var A={I};var W=A.values();var T='';var j=0;for(var y of W){T=T+String.fromCharCode(A[j]);j++;}var RESULT=T;"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.replace("{I}", c).replace("{N}", str(len(secret)))
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # F1166 hook must miss:
    ("f1166-single-reverse", "_js_f1166_stmt_decode",
     "var C=%s;var D=C.slice().reverse();var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1166-no-slice", "_js_f1166_stmt_decode",
     "var C=%s;var D=C.reverse().reverse();var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1166-triple", "_js_f1166_stmt_decode",
     "var C=%s;var D=C.slice().reverse().reverse().reverse();var S=String.fromCharCode(...D);var RESULT=S;"),
    # F1167 hook must miss:
    ("f1167-unescape", "_js_f1167_stmt_decode",
     "var C=%s;var E=C.map(function(c){return '%'+c.toString(16);}).join('');var S=unescape(E);var RESULT=S;"),
    ("f1167-low-code", "_js_f1167_stmt_decode",
     "var C=[10];var E=C.map(function(c){return '%'+c.toString(16);}).join('');var S=decodeURI(E);var RESULT=S;"),
    ("f1167-reserved", "_js_f1167_stmt_decode",
     "var C=[35];var E=C.map(function(c){return '%'+c.toString(16);}).join('');var S=decodeURI(E);var RESULT=S;"),
    ("f1167-high-code", "_js_f1167_stmt_decode",
     "var C=[200];var E=C.map(function(c){return '%'+c.toString(16);}).join('');var S=decodeURI(E);var RESULT=S;"),
    ("f1167-join-comma", "_js_f1167_stmt_decode",
     "var C=%s;var E=C.map(function(c){return '%'+c.toString(16);}).join(',');var S=decodeURI(E);var RESULT=S;"),
    # F1168 hook must miss:
    ("f1168-no-rest", "_js_f1168_stmt_decode",
     "var C=%s;var [R]=C;var S=String.fromCharCode(...R);var RESULT=S;"),
    ("f1168-spread-src", "_js_f1168_stmt_decode",
     "var C=%s;var [...R]=[...C];var S=String.fromCharCode(...R);var RESULT=S;"),
    # F1169 hook must miss:
    ("f1169-offset-mismatch", "_js_f1169_stmt_decode",
     "var C=[0].concat(%s);var D=C.slice();D.copyWithin(0,2);var S=String.fromCharCode(...D.slice(0,20));var RESULT=S;"),
    ("f1169-len-mismatch", "_js_f1169_stmt_decode",
     "var C=[0].concat(%s);var D=C.slice();D.copyWithin(0,1);var S=String.fromCharCode(...D.slice(0,3));var RESULT=S;"),
    ("f1169-no-concat", "_js_f1169_stmt_decode",
     "var C=%s;var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode(...D.slice(0,20));var RESULT=S;"),
    # F1170 hook must miss:
    ("f1170-two-char", "_js_f1170_stmt_decode",
     "var C=%s;var T='..'.repeat(C.length);var S='';T.replace(/./g,function(m,i){S+=String.fromCharCode(C[i]);return m;});var RESULT=S;"),
    ("f1170-no-g-flag", "_js_f1170_stmt_decode",
     "var C=%s;var T='.'.repeat(C.length);var S='';T.replace(/./,function(m,i){S+=String.fromCharCode(C[i]);return m;});var RESULT=S;"),
    ("f1170-search-mismatch", "_js_f1170_stmt_decode",
     "var C=%s;var T='x'.repeat(C.length);var S='';T.replaceAll('y',function(m,i){S+=String.fromCharCode(C[i]);return m;});var RESULT=S;"),
    ("f1170-no-return", "_js_f1170_stmt_decode",
     "var C=%s;var T='.'.repeat(C.length);var S='';T.replace(/./g,function(m,i){S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1171 hook must miss:
    ("f1171-with-value", "_js_f1171_stmt_decode",
     "var C=%s;var D=C.with(1,99);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1171-tospliced-del", "_js_f1171_stmt_decode",
     "var C=%s;var D=C.toSpliced(0,1);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1171-with-idx", "_js_f1171_stmt_decode",
     "var C=%s;var D=C.with(0,1);var S=String.fromCharCode(...D);var RESULT=S;"),
    # F1172 hook must miss:
    ("f1172-nonidentity", "_js_f1172_stmt_decode",
     "var C=%s;var D=Array.from(C,function(c){return c+1;});var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1172-of", "_js_f1172_stmt_decode",
     "var C=%s;var D=Array.of(...C);var S=String.fromCharCode(...D);var RESULT=S;"),
    # F1173 hook must miss:
    ("f1173-destructured", "_js_f1173_stmt_decode",
     "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1173-pair-access", "_js_f1173_stmt_decode",
     "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
    ("f1173-values-direct", "_js_f1173_stmt_decode",
     "var C=%s;var S='';for(var x of C.values()){S+=String.fromCharCode(x);}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        # NOTE: templates contain literal '%' (F1167), so use
        # str.replace instead of %-formatting.
        p = tmpl.replace("%s", c)
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3b: cross-disjointness (both directions) ----------------

_DIS = [
    # sibling hooks must miss my shapes...
    ("f1139-on-f1166", "_js_f1139_stmt_decode",
     "var C=%s;var D=C.slice().reverse().reverse();var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1155-on-f1166", "_js_f1155_stmt_decode",
     "var C=%s;var D=C.slice().reverse().reverse();var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1138-on-f1167", "_js_f1138_stmt_decode",
     "var C=%s;var E=C.map(function(c){return '%'+c.toString(16);}).join('');var S=decodeURI(E);var RESULT=S;"),
    ("f1120-on-f1168", "_js_f1120_stmt_decode",
     "var C=%s;var [...R]=C;var S=String.fromCharCode(...R);var RESULT=S;"),
    ("f1120-on-f1171", "_js_f1120_stmt_decode",
     "var C=%s;var D=C.with(0,C[0]);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1120-on-f1172", "_js_f1120_stmt_decode",
     "var C=%s;var D=Array.from(C);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1124-on-f1170", "_js_f1124_stmt_decode",
     "var C=%s;var T='.'.repeat(C.length);var S='';T.replace(/./g,function(m,i){S+=String.fromCharCode(C[i]);return m;});var RESULT=S;"),
    ("f1091-on-f1173a", "_js_f1091_stmt_decode",
     "var C=%s;var S='';for(var [i] of C.entries()){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1091-on-f1173b", "_js_f1091_stmt_decode",
     "var C=%s;var V=C.values();var S='';var i=0;for(var x of V){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;"),
    ("f1150-on-f1173a", "_js_f1150_stmt_decode",
     "var C=%s;var S='';for(var [i] of C.entries()){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    # ...and my hooks must miss sibling filed shapes.
    ("my6-on-f1139-filed", "_js_f1166_stmt_decode",
     "var C=%s;C.reverse();var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}S=S.split('').reverse().join('');var RESULT=S;"),
    ("my7-on-f1138-filed", "_js_f1167_stmt_decode",
     "var C=%s;var S=unescape(C.map(function(c){return '%'+c.toString(16);}).join(''));var RESULT=S;"),
    ("my8-on-f1120-filed", "_js_f1168_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...[...C]);var RESULT=S;"),
    ("my0-on-f1124-filed", "_js_f1170_stmt_decode",
     "var C=%s;var S='';C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("my1-on-f1120-filed", "_js_f1171_stmt_decode",
     "var C=%s;var S=String.fromCharCode(...C.slice());var RESULT=S;"),
    ("my2-on-f1120-filed", "_js_f1172_stmt_decode",
     "var C=%s;var D=[].concat(C);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("my3-on-f1091-filed", "_js_f1173_stmt_decode",
     "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(c);}var RESULT=S;"),
    ("my3-on-f1150-filed", "_js_f1173_stmt_decode",
     "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
]


@_t
def test_p3b_disjoint():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _DIS:
        # NOTE: templates contain literal '%' (F1167), so use
        # str.replace instead of %-formatting.
        p = tmpl.replace("%s", c)
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_DIS)
    return (not bad, "%d/%d cross-disjoint miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

_MY_HOOKS = ("_js_f1166_stmt_decode", "_js_f1167_stmt_decode",
             "_js_f1168_stmt_decode", "_js_f1169_stmt_decode",
             "_js_f1170_stmt_decode", "_js_f1171_stmt_decode",
             "_js_f1172_stmt_decode", "_js_f1173_stmt_decode")


def _my_hook_hits(payload):
    return [a for a in _MY_HOOKS if getattr(dlp, a)(payload) is not None]


@_t
def test_p4_sibling_f1139():
    shapes = _redfirst_shapes("w403", 1139)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1139 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1138():
    shapes = _redfirst_shapes("w404", 1138)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1138 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1120():
    shapes = _redfirst_shapes("w403", 1120)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1120 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1090():
    shapes = _redfirst_shapes("w400", 1090)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1090 blocked=%d/%d, new-hook hits=%d"
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
def test_p4_sibling_f1124():
    shapes = _redfirst_shapes("w404", 1124)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if _my_hook_hits(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1124 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "The quarterly financial summary shows revenue growth."),
    ("honest-reverse", "var a=[3,1,2];a.reverse();console.log(a);"),
    ("honest-decodeuri", "var u=decodeURI('%20%21');console.log(u);"),
    ("honest-destructure", "var [a,...rest]=[1,2,3];console.log(rest);"),
    ("honest-copywithin", "var a=[1,2,3];a.copyWithin(0,1);"),
    ("honest-replace", "var s='hello';var t=s.replace(/l/g,'L');"),
    ("honest-with", "var a=[1,2];var b=a.with(0,9);"),
    ("honest-arrayfrom", "var b=Array.from([1,2,3]);"),
    ("honest-entries", "for(var e of [1,2].entries()){console.log(e);}"),
    ("honest-prose",
     "the reverse decodeuri destructure copywithin replace with arrayfrom entries patterns are honest"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var D=C.slice().reverse().reverse();var S=String.fromCharCode(...D);var RESULT=S;" % c)
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
    # F1159-F1165, F1174-F1181 are NOT this lane's scope; all their
    # red-first shapes must still MISS.
    bad = []
    for n in list(range(1159, 1166)) + list(range(1174, 1180)):
        shapes = _redfirst_shapes("w405", n)
        bad += [name for name, payload in shapes if _blocked(payload)]
    for n in (1180, 1181):
        # provenance seam: instruction_shaped must stay QUIET
        from gov.instruction_provenance import instruction_shaped
        path = os.path.join(REPO_ROOT, "evals", "w405_f%d_redfirst.py" % n)
        spec = importlib.util.spec_from_file_location("w405_f%d_rf" % n, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        bad += [name for name, payload in mod.SHAPES
                if instruction_shaped(payload)]
    return (not bad, "out-of-scope still open%s"
            % ("" if not bad else " (hit): " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w405's attack battery.

    On this lane tree F1166-F1173 are CLOSED, so exactly their 8
    test_open_w405_fNNNN pins BREAK (expected); F1159-F1165,
    F1174-F1179 and the F1180-F1181 provenance pins must still HELD.
    Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w405_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g406l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w405_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and (parts[1].startswith("test_open_w405_f")
                                    or parts[1].startswith("test_open_prov_w405_f")):
                if parts[0] == "HELD":
                    held.add(parts[1])
                else:
                    broke.append(parts[1])
        expect_break = {"test_open_w405_f%d" % n for n in range(1166, 1174)}
        expect_held = ({"test_open_w405_f%d" % n for n in range(1159, 1166)}
                       | {"test_open_w405_f%d" % n for n in range(1174, 1180)}
                       | {"test_open_prov_w405_f%d" % n for n in (1180, 1181)})
        ok = (set(broke) == expect_break and expect_held <= set(held))
        return (ok, "green(w405_attack): broke=%d (expect 8), held=%d (expect>=15)%s"
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
    print("w406_f1166f1173close_probes: %d/%d HELD" % (held, held + broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
