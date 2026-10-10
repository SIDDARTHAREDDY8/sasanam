#!/usr/bin/env python3
"""Wave-403 lane 3 close battery: F1117/F1118/F1119 CLOSED.

F1117: with-scope staged spread reads -- `with({})` or `with({C:C})`
wrapping `S=String.fromCharCode(...C);` assembles node-exactly
(v24.20.0, sloppy mode) while find_credential MISSES. Distinct from
F1089 (member-expression spread receivers). Filed 2026-10-10 16:52 UTC
wave-402 (attack round 70, local validation, $0.00 model spend).

F1118: arguments-object staged spread reads --
`function f(){var S=String.fromCharCode(...arguments);return S;}`
`var C=[codes];var RESULT=f(...C);` assembles node-exactly
(v24.20.0) while find_credential MISSES. Filed 2026-10-10 16:52 UTC
wave-402 (attack round 70, local validation, $0.00 model spend).

F1119: Symbol.iterator explicit iteration staged reads --
`for(var x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}` (and
the for-await async-IIFE twin) assemble node-exactly (v24.20.0) while
find_credential MISSES. F1091 (CLOSED wave-401 lane 1) models
for[-await]...of over C / C.values() / C.entries() but not the
explicit Symbol.iterator call. Filed 2026-10-10 16:52 UTC wave-402
(attack round 70, local validation, $0.00 model spend).

Closed by _js_f1117_stmt_decode / _js_f1118_stmt_decode /
_js_f1119_stmt_decode (whole-text _stmtdec hooks, one new
_decode_layer dispatch loop, N_STMTDEC_LOOPS 34->35). Node-exact
filed shapes + generalizations; fail-closed bounds; disjoint from
F1089/F1091/F1110 both directions.

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
N_STMTDEC_LOOPS_PIN = 38  # wave-403 merge: 34 + 4 loops -> 38 (was lane 3-local 35)

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
    mine = [lp for lp in loops if "_js_f1117_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-403 lane 3 (2026-10-10)" in src
          and "F1117, F1118, F1119 CLOSED (3" in src
          and "F1111-F1116, F1120-F1122 OPEN (9" in src
          and "next free F1123" in src)
    ok = (ok and src.count("(F1117 filed") == 1
          and src.count("(F1118 filed") == 1
          and src.count("(F1119 filed") == 1)
    ok = (ok and "[CLOSED 2026-10-10 wave-403 lane 3" in src
          and src.count("[CLOSED 2026-10-10 wave-403 lane 3") == 3)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1123**" in src
          and "F1111-F1122 OPEN (12" in src
          and "# Wave-402: F1103-F1110 CLOSED (8); F1111-F1122 OPEN (12); next free F1123" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1117_filed_block():
    shapes = _redfirst_shapes("w403", 1117)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1118_filed_block():
    shapes = _redfirst_shapes("w403", 1118)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1119_filed_block():
    shapes = _redfirst_shapes("w403", 1119)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-verified) ----------------

_GEN = [
    # (name, hook-prefix-tag, template with {I} for the int array;
    #  literal JS braces are doubled for str.format)
    ("f1117", "with-empty-let",
     "let C={I};let S='';with({{}}){{S=String.fromCharCode(...C);}}let RESULT=S;"),
    ("f1117", "with-alias-additive",
     "var C={I};var S='';with({{C:C}}){{S=String.fromCharCode(...C);}}var RESULT='x:'+S+'!';"),
    ("f1117", "with-empty-const",
     "const C={I};var S='';with({{}}){{S=String.fromCharCode(...C);}}const RESULT=S;"),
    ("f1117", "with-spaced",
     "var C={I};var S='';with ({{}}){{S=String.fromCharCode(...C);}}var RESULT=S;"),
    ("f1118", "fn-named-long",
     "function gather(){{var acc=String.fromCharCode(...arguments);return acc;}}"
     "var C={I};var RESULT=gather(...C);"),
    ("f1118", "fn-let-acc",
     "function f(){{let S=String.fromCharCode(...arguments);return S;}}"
     "var C={I};var RESULT=f(...C);"),
    ("f1119", "symiter-let",
     "let C={I};let S='';for(let x of C[Symbol.iterator]()){{S+=String.fromCharCode(x);}}let RESULT=S;"),
    ("f1119", "symiter-arrow-iife",
     "(async()=>{{var C={I};var S='';for await (var x of C[Symbol.iterator]())"
     "{{S+=String.fromCharCode(x);}}globalThis.RESULT=S;}})();"),
    ("f1119", "symiter-additive",
     "var C={I};var S='';for(var x of C[Symbol.iterator]()){{S+=String.fromCharCode(x);}}"
     "var RESULT=S+'-tail';"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for fnum, name, tmpl in _GEN:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s-%s" % (fnum, tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # (hook attr, name, template with %s for codes)
    ("_js_f1117_stmt_decode", "with-diff-arr",
     "var C=%s;var S='';with({C:[9]}){S=String.fromCharCode(...C);}var RESULT=S;"),
    ("_js_f1117_stmt_decode", "with-diff-key",
     "var C=%s;var S='';with({D:C}){S=String.fromCharCode(...C);}var RESULT=S;"),
    ("_js_f1117_stmt_decode", "with-bare-obj",
     "var C=%s;var S='';with(C){S=String.fromCharCode(...C);}var RESULT=S;"),
    ("_js_f1117_stmt_decode", "with-unbraced",
     "var C=%s;var S='';with({})S=String.fromCharCode(...C);var RESULT=S;"),
    ("_js_f1117_stmt_decode", "with-nested",
     "var C=%s;var S='';with({}){with({}){S=String.fromCharCode(...C);}}var RESULT=S;"),
    ("_js_f1118_stmt_decode", "arrow-fn",
     "var f=()=>{var S=String.fromCharCode(...arguments);return S;};"
     "var C=%s;var RESULT=f(...C);"),
    ("_js_f1118_stmt_decode", "with-param",
     "function f(a){var S=String.fromCharCode(...arguments);return S;}"
     "var C=%s;var RESULT=f(...C);"),
    ("_js_f1118_stmt_decode", "indexed-args",
     "function f(){var S=String.fromCharCode(arguments[0]);return S;}"
     "var C=%s;var RESULT=f(...C);"),
    ("_js_f1118_stmt_decode", "call-mismatch",
     "function f(){var S=String.fromCharCode(...arguments);return S;}"
     "var C=%s;var RESULT=g(...C);"),
    ("_js_f1118_stmt_decode", "no-spread-call",
     "function f(){var S=String.fromCharCode(...arguments);return S;}"
     "var C=%s;var RESULT=f(C);"),
    ("_js_f1119_stmt_decode", "plain-C",
     "var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "values-call",
     "var C=%s;var S='';for(var x of C.values()){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "keys-call",
     "var C=%s;var S='';for(var x of C.keys()){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "no-call",
     "var C=%s;var S='';for(var x of C[Symbol.iterator]){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "destructure",
     "var C=%s;var S='';for(var [i,x] of C[Symbol.iterator]()){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "bare-loopvar",
     "var C=%s;var S='';for(x of C[Symbol.iterator]()){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("_js_f1119_stmt_decode", "entries-call",
     "var C=%s;var S='';for(var [i,x] of C.entries()){S+=String.fromCharCode(x);}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for attr, name, tmpl in _FC:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1089():
    # F1089's filed shapes still block (via F1089's own hook); the new
    # F1117 hook never hits any of them (disjoint both directions).
    shapes = _redfirst_shapes("w400", 1089)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1117_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1089 blocked=%d/%d, f1117-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1091():
    # F1091's filed shapes still block (via F1091's own hook); the new
    # F1119 hook never hits any of them.
    shapes = _redfirst_shapes("w400", 1091)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1119_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1091 blocked=%d/%d, f1119-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1110():
    # F1110's filed shapes still block (via F1110's own hook); the new
    # F1119 hook never hits any of them.
    shapes = _redfirst_shapes("w402", 1110)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1119_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1110 blocked=%d/%d, f1119-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_mine_miss_f1089_f1091():
    # My filed shapes miss the F1089/F1091/F1110 hooks (disjoint).
    bad = []
    for fnum in (1117, 1118, 1119):
        for n, p in _redfirst_shapes("w403", fnum):
            for attr, hname in (("_js_f1089_stmt_decode", "f1089"),
                                ("_js_f1091_stmt_decode", "f1091"),
                                ("_js_f1110_stmt_decode", "f1110")):
                if getattr(dlp, attr)(p) is not None:
                    bad.append("%s/%s" % (n, hname))
    return (not bad, "sibling hooks miss my shapes%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-with", "with(obj){console.log(obj.x);}"),
    ("honest-arguments", "function f(){return arguments.length;}"),
    ("honest-symiter", "var it=arr[Symbol.iterator]();var v=it.next();"),
    ("honest-prose",
     "the with statement and arguments object are honest patterns"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';with({}){S=String.fromCharCode(...C);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: still-open pins ----------------

@_t
def test_p7_open_rest():
    # F1111-F1116, F1120-F1122 must still MISS on this tree.
    bad = []
    for fnum in (1111, 1112, 1113, 1114, 1115, 1116, 1120, 1121, 1122):
        for n, p in _redfirst_shapes("w402", fnum):
            if not _misses(p):
                bad.append("f%d/%s" % (fnum, n))
    return (not bad, "still-open shapes miss%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w402's attack battery (carries
    F1111-F1122 pins). Honor GOV_SKIP_GREEN. On this lane tree
    F1117/F1118/F1119 are closed, so expect exactly those 3 pins to
    show as broken; everything else must hold."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w402_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g403l3-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w402_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "BREAK":
                real.append(parts[1])
        expect_break = {"test_open_w402_f1117",
                        "test_open_w402_f1118",
                        "test_open_w402_f1119"}
        ok = set(real) == expect_break
        return (ok,
                "green(w402_attack): %d BREAK (expect exactly %s: %s)"
                % (len(real), sorted(expect_break),
                   "ok" if ok else "got=" + ",".join(sorted(real))))
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
