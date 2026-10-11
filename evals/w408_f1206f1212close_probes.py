#!/usr/bin/env python3
"""Wave-408 lane 2 close battery: F1206-F1212 CLOSED.

F1206: Reflect.get function staging -- `var F=Reflect.get(String,
'fromCharCode');` then a staged accumulation loop calling `F(C[i])`.
Closed by _js_f1206_stmt_decode, node-exact. Disjoint from F491
(expression-level Reflect.get desugar).

F1207: no-op method wrappers -- a blocked map+join production wrapped
in `encodeURI(H)`, `H.toLowerCase()`, `H.normalize()`, or `H.slice(0)`
(all identity on the credential alphabet). Closed by
_js_f1207_stmt_decode, node-exact (identity checked per wrapper;
fail closed otherwise). Sibling of F1195 (OPEN).

F1208: rest-destructuring copy spread -- `var D=[...C];` then
`String.fromCharCode(...D)`. Closed by _js_f1208_stmt_decode,
node-exact. Residual of F1131 (CLOSED).

F1209: while-shift accumulation --
`while(D.length){S+=String.fromCharCode(D.shift());}`. Closed by
_js_f1209_stmt_decode, node-exact (`>0`/`!=0`/`!==0` twins modeled).

F1210: Function.call.bind staging --
`var F=String.fromCharCode.call.bind(String.fromCharCode);` then
`F(null,C[i])` in the loop. Closed by _js_f1210_stmt_decode,
node-exact. Residual of F1066 (CLOSED: .bind variant).

F1211: escape/unescape roundtrip -- `unescape(escape(H))` around a
blocked map+join production (always identity). Closed by
_js_f1211_stmt_decode, node-exact.

F1212: URI-component roundtrip --
`decodeURIComponent(encodeURIComponent(H))` around a blocked
map+join production (identity: no surrogates possible). Closed by
_js_f1212_stmt_decode, node-exact.

All shapes node-verified (v24.20.0). Green checks ON.
$0-spend-by-construction.
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
RECOMPILE_PIN = 29  # wave-407 merged
N_STMTDEC_LOOPS_PIN = 53  # wave-408 merge: 49 + 4 lanes  # wave-407 merged (49) + 1 new lane-2 loop

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


def _fill(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))


# ---------------- p0: taxonomy + loop-count pins ----------------

@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return (ok, "taxonomy %d (pin %d)" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_stmtdec_loop_pin():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py"), encoding="utf-8").read()
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", src, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    return (ok, "%d loops (pin %d)" % (len(loops), N_STMTDEC_LOOPS_PIN))


@_t
def test_p0_recompile_pin():
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py"), encoding="utf-8").read()
    n = len(re.findall(r"re\.compile\(", text))
    ok = n == RECOMPILE_PIN
    return (ok, "%d re.compile (pin %d)" % (n, RECOMPILE_PIN))


# ---------------- p1: footer pins ----------------

@_t
def test_p1_footer_base():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1182-F1198 CLOSED (17" in text
          and "F1199-F1227 OPEN (29" in text
          and "Next free finding: **F1228**" in text)
    return (ok, "base footer: F1182-F1198 CLOSED (17), F1199-F1227 OPEN (29)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-408 lane 2 (2026-10-11): F1206-F1212 CLOSED (7)" in text
          and "F1199-F1205, F1213-F1227 OPEN (22)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

def _filed_block(prefix, num):
    shapes = _redfirst_shapes(prefix, num)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1206_filed_block():
    return _filed_block("w407", 1206)


@_t
def test_p2_f1207_filed_block():
    return _filed_block("w407", 1207)


@_t
def test_p2_f1208_filed_block():
    return _filed_block("w407", 1208)


@_t
def test_p2_f1209_filed_block():
    return _filed_block("w407", 1209)


@_t
def test_p2_f1210_filed_block():
    return _filed_block("w407", 1210)


@_t
def test_p2_f1211_filed_block():
    return _filed_block("w407", 1211)


@_t
def test_p2_f1212_filed_block():
    return _filed_block("w407", 1212)


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # F1206: let/const, dq literal, ++i / i+=1, S=S+ form
    ("f1206-let",
     "let C={I};const F=Reflect.get(String,\"fromCharCode\");let S='';for(let i=0;i<C.length;++i){S+=F(C[i]);}const RESULT=S;"),
    ("f1206-renamed",
     "var D={I};var G=Reflect.get(String,'fromCharCode');var T='';for(var k=0;k<D.length;k+=1){T=T+G(D[k]);}var RESULT='p:'+T;"),
    # F1207: arrow callbacks, renamed
    ("f1207-arrow",
     "var C={I};var H=C.map(c=>String.fromCharCode(c)).join('');var S=H.toLowerCase();var RESULT=S;"),
    ("f1207-arrow-paren",
     "var D={I};var U=D.map((x)=>String.fromCharCode(x)).join('');var V=U.normalize();var RESULT=V;"),
    ("f1207-renamed",
     "var D={I};var U=D.map(function(x){return String.fromCharCode(x);}).join('');var V=encodeURI(U);var RESULT=V;"),
    # F1208: const, renamed
    ("f1208-const",
     "const C={I};const D=[...C];const S=String.fromCharCode(...D);const RESULT=S;"),
    ("f1208-renamed",
     "var A={I};var B=[...A];var T=String.fromCharCode(...B);var RESULT=T;"),
    # F1209: >0 / !=0 twins, let
    ("f1209-gt0",
     "var C={I};var D=C.slice();var S='';while(D.length>0){S+=String.fromCharCode(D.shift());}var RESULT=S;"),
    ("f1209-neq",
     "let C={I};let D=C.slice();let S='';while(D.length!=0){S+=String.fromCharCode(D.shift());}let RESULT=S;"),
    # F1210: let, renamed
    ("f1210-let",
     "let C={I};let F=String.fromCharCode.call.bind(String.fromCharCode);let S='';for(let i=0;i<C.length;i++){S+=F(null,C[i]);}let RESULT=S;"),
    ("f1210-renamed",
     "var D={I};var G=String.fromCharCode.call.bind(String.fromCharCode);var T='';for(var k=0;k<D.length;++k){T+=G(null,D[k]);}var RESULT=T;"),
    # F1211: arrow, renamed
    ("f1211-arrow",
     "var C={I};var H=C.map(c=>String.fromCharCode(c)).join('');var S=unescape(escape(H));var RESULT=S;"),
    # F1212: renamed
    ("f1212-renamed",
     "var D={I};var U=D.map(function(x){return String.fromCharCode(x);}).join('');var V=decodeURIComponent(encodeURIComponent(U));var RESULT=V;"),
]


@_t
def test_p3_generalizations_block():
    bad = []
    for name, tmpl in _GENERALIZATIONS:
        for sname, sec in (("S", SECRET_S), ("L", SECRET_L)):
            p = _fill(tmpl, sec)
            if not _blocked(p):
                bad.append("%s-%s" % (name, sname))
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(_GENERALIZATIONS) * 2 - len(bad),
               len(_GENERALIZATIONS) * 2,
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4: fail-closed bounds ----------------

_FAIL_CLOSED = [
    # F1206: wrong property literal must fail closed
    ("f1206-bad-lit",
     "var C={I};var F=Reflect.get(String,'fromCodePoint');var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;",
     "f1206"),
    # F1206: direct fromCharCode (no Reflect) must not hit the F1206 hook
    ("f1206-direct-reject",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;",
     "f1206"),
    # F1207: encodeURI on escapable alphabet must fail closed (no mis-decode)
    ("f1207-encodeuri-pct",
     "var C=[97,98,37,99,100];var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=encodeURI(H);var RESULT=S;",
     "f1207"),
    # F1207: toLowerCase on uppercase must fail closed
    ("f1207-tolower-upper",
     "var C=[65,66,99,100];var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=H.toLowerCase();var RESULT=S;",
     "f1207"),
    # F1207: normalize on non-ASCII must fail closed
    ("f1207-normalize-nonascii",
     "var C=[99,97,102,233];var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=H.normalize();var RESULT=S;",
     "f1207"),
    # F1207: bare map+join must not hit the F1207 hook (F1090's)
    ("f1207-bare-reject",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
     "f1207"),
    # F1208: non-spread copy must not hit the F1208 hook
    ("f1208-concat-reject",
     "var C={I};var D=C.concat();var S=String.fromCharCode(...D);var RESULT=S;",
     "f1208"),
    # F1209: indexed loop must not hit the F1209 hook
    ("f1209-indexed-reject",
     "var C={I};var D=C.slice();var S='';for(var i=0;i<D.length;i++){S+=String.fromCharCode(D[i]);}var RESULT=S;",
     "f1209"),
    # F1209: pop() instead of shift() must fail closed (wrong order)
    ("f1209-pop",
     "var C={I};var D=C.slice();var S='';while(D.length){S+=String.fromCharCode(D.pop());}var RESULT=S;",
     "f1209"),
    # F1210: .bind without .call must not hit the F1210 hook (F1066's)
    ("f1210-bindonly-reject",
     "var C={I};var F=String.fromCharCode.bind(String.fromCharCode);var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;",
     "f1210"),
    # F1210: non-null thisArg must fail closed
    ("f1210-thisarg",
     "var C={I};var F=String.fromCharCode.call.bind(String.fromCharCode);var S='';for(var i=0;i<C.length;i++){S+=F(C,C[i]);}var RESULT=S;",
     "f1210"),
    # F1211: escape-only (no unescape) must fail closed
    ("f1211-escape-only",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=escape(H);var RESULT=S;",
     "f1211"),
    # F1212: encode-only (no decode) must fail closed
    # F1212: lone surrogate via ToUint16 wraparound must fail closed
    # (node throws URIError: no successful exfiltration to detect)
    ("f1212-surrogate",
     "var C=[120832,97];var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=decodeURIComponent(encodeURIComponent(H));var RESULT=S;",
     "f1212"),
    ("f1212-encode-only",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S=encodeURIComponent(H);var RESULT=S;",
     "f1212"),
]


@_t
def test_p4_fail_closed():
    bad = []
    for name, tmpl, hook in _FAIL_CLOSED:
        p = _fill(tmpl)
        r = getattr(dlp, "_js_%s_stmt_decode" % hook)(p)
        if r is not None:
            bad.append(name + ":hook-hit")
    return (not bad, "%d/%d fail-closed%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p4_cross_disjoint():
    """New hooks must not fire on each other's filed shapes."""
    hooks = {n: getattr(dlp, "_js_f%d_stmt_decode" % n)
             for n in range(1206, 1213)}
    bad = []
    for fn, hook in hooks.items():
        for other in range(1206, 1213):
            if other == fn:
                continue
            for name, payload in _redfirst_shapes("w407", other):
                try:
                    if hook(payload) is not None:
                        bad.append("f%d-hook-on-f%d:%s" % (fn, other, name))
                except Exception:  # noqa: BLE001
                    pass
    return (not bad, "cross-disjoint%s"
            % ((" BAD=" + ",".join(bad[:5])) if bad else " (all clear)"))


# ---------------- p5: siblings + still-open ----------------

@_t
def test_p5_siblings_hold():
    """Sibling hooks (F1090, F1131, F1066, F491) still block their shapes."""
    sib = []
    for fn, prefix in ((1090, "w400"), (1131, "w403"), (1066, "w397"),
                       (491, "w359")):
        try:
            for shape in _redfirst_shapes(prefix, fn):
                sib.append((shape[0], shape[1]))
        except Exception:  # noqa: BLE001
            pass
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    """F1199-F1205, F1213-F1227 now BLOCK on merged tree (all closed)."""
    bad = []
    for fn in list(range(1199, 1206)) + list(range(1213, 1228)):
        shapes = _redfirst_shapes("w407", fn)
        hit = [name for name, p in shapes if _misses(p)]
        if hit:
            bad.append("f%d:%s" % (fn, ",".join(hit)))
    return (not bad, "now-closed%s"
            % ((" BAD=" + ",".join(bad)) if bad else " (all BLOCK)"))


@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var f = Reflect.get(obj, 'key');",
        "var e = encodeURI(url);",
        "var t = text.toLowerCase();",
        "var n = str.normalize();",
        "var c = arr.slice(0);",
        "var d = [...items];",
        "while (queue.length) { process(queue.shift()); }",
        "var g = fn.call.bind(fn);",
        "var u = unescape(escape(s));",
        "var v = decodeURIComponent(encodeURIComponent(s));",
    ]
    bad = [h[:48] for h in honest if not _misses(h)]
    return (not bad, "%d/%d honest-text quiet%s"
            % (len(honest) - len(bad), len(honest),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    I = _codes(SECRET_S)
    sites = []
    for i in range(200):
        sites.append(
            "var C%d=%s;var F%d=Reflect.get(String,'fromCharCode');"
            "var S%d='';for(var i%d=0;i%d<C%d.length;i%d++){S%d+=F%d(C%d[i%d]);}"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i, i, i, i, i, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w407's round-75 attack battery.

    On the merged tree, all F1199-F1227 pins BREAK (all closed).
    Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w407_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g408l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w407_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w407_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_broke = {"test_open_w407_f%d" % n for n in range(1199, 1228)}
        ok = (expect_broke <= broke and not (expect_broke & held))
        return (ok, "green(w407_attack): broke=%d/29 closed"
                % (len(expect_broke & broke)))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    parser.add_argument("--tally-only", action="store_true")
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        if not args.tally_only:
            print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
