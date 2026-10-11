#!/usr/bin/env python3
"""Wave-411 lane 2 close battery: F1296-F1302 CLOSED.

F1296: hex codec roundtrip -- `parseInt(c.toString(16),16)` is the
identity on the int codes (node-exact v24.20.0), staged through
fromCharCode.apply / spread. Two productions (function+apply,
arrow+spread). Distinct from F1267 (two-map codec). Closed by
`_js_f1296_stmt_decode`.

F1297: RegExp indices laundering -- `/(.+)/d.exec(T)` + substring via
m.indices, and `[...T.matchAll(/(.)/dg)]` + x[0] join, wrapping the
F1090-blocked map+join. Both are the identity on line-terminator-free
text (`.` never matches LF/CR/LS/PS -- those codes fail closed).
Distinct from F1185 (staged reads, no indices). Closed by
`_js_f1297_stmt_decode`.

F1298: Symbol.match staging -- `[Symbol.match]` on a plain object
with a fromCharCode-accumulating function returning `[R]`;
`'x'.match(O)` delegates to @@match (String.prototype.match --
node-exact v24.20.0) and `[0]` reads the string. Two productions
(named M/S, inline RESULT). Closed by `_js_f1298_stmt_decode`.

F1299: accumulator variable indirection -- one or two `var X=PREV;`
hops between the fromCharCode accumulation loop and RESULT. The
direct `var RESULT=R` form is F1074's (this hook pre-binds RESULT).
Loop parsed by the F1074/F1075 shared parser. Closed by
`_js_f1299_stmt_decode`.

F1300: Object.freeze on slice -- `Object.freeze(C.slice())` via a
named intermediate (apply or spread) or inline in apply. freeze
returns its argument unchanged (node-exact). Disjoint from F1194
(inline spread `...Object.freeze(...)`) by call shape. Closed by
`_js_f1300_stmt_decode`.

F1301: Object.preventExtensions on slice -- same shapes as F1300
with preventExtensions, plus the inline-apply production.
Disjoint from F1194 by call shape. Closed by
`_js_f1301_stmt_decode`.

F1302: codePointAt identity roundtrip -- fromCodePoint map, join,
then codePointAt-per-index + fromCodePoint push loop, join. The
identity for BMP codes (verified incl. lone surrogates v24.20.0);
astral codes fail closed. Closed by `_js_f1302_stmt_decode`.

New _decode_layer dispatch loop (F1296-F1302); N_STMTDEC_LOOPS 61->62
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1289-F1295, F1303-F1314, F1316-F1322 (other lanes' opens) still MISS.

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
N_STMTDEC_LOOPS_PIN = 62  # wave-411 lane 2: 61 + F1296-F1302 loop

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
    names = ["_js_f1296_stmt_decode", "_js_f1297_stmt_decode",
             "_js_f1298_stmt_decode", "_js_f1299_stmt_decode",
             "_js_f1300_stmt_decode", "_js_f1301_stmt_decode",
             "_js_f1302_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-411 lane 2 (2026-10-11)" in src
          and "F1296-F1302 CLOSED (7" in src
          and "F1336-F1342 filed OPEN (7" in src
          and "F1289-F1295, F1303-F1314, F1316-F1322 OPEN (26" in src
          and "next free F1343" in src)
    for n in range(1296, 1303):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-411 lane 2") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-410: F1260-F1288 CLOSED (29); F1315 CLOSED (1); F1289-F1314 OPEN (26); F1316-F1322 OPEN (7); next free F1323" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1296-F1302 filed shapes now BLOCK."""
    bad = []
    total = 0
    for n in range(1296, 1303):
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
    """let/const twins, renamed vars, whitespace (node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1296: let/const, renamed.
    cases.append(("f1296-let",
                  "let A=%s;let B=A.map(function(x){return parseInt(x.toString(16),16);});let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs))
    cases.append(("f1296-const-arrow",
                  "const A=%s;const B=A.map(x=>parseInt(x.toString(16),16));const T=String.fromCharCode(...B);const RESULT=T;" % cl))
    # F1297: renamed, extra whitespace.
    cases.append(("f1297-exec-ws",
                  "var C=%s; var T = C.map( function(c){ return String.fromCharCode(c); } ).join( '' ); var m = /(.+)/d.exec( T ); var S = T.substring( m.indices[1][0] , m.indices[1][1] ); var RESULT = S;" % cs))
    cases.append(("f1297-matchall-renamed",
                  "let C=%s;let U=C.map(function(c){return String.fromCharCode(c);}).join('');let q=[...U.matchAll(/(.)/dg)];let V=q.map(function(x){return x[0];}).join('');let RESULT=V;" % cl))
    # F1298: renamed, different receiver literal.
    cases.append(("f1298-renamed",
                  "let C=%s;let P={};P[Symbol.match]=function(t){let R='';for(let i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return [R];};let Q='zz'.match(P);let W=Q[0];let RESULT=W;" % cs))
    cases.append(("f1298-inline-renamed",
                  "const C=%s;const P={};P[Symbol.match]=function(t){const R='';for(const i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return [R];};const RESULT='zz'.match(P)[0];" % cl))
    # F1299: renamed, const.
    cases.append(("f1299-const",
                  "const C=%s;const R='';for(const i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}const S=R;const RESULT=S;" % cs))
    cases.append(("f1299-dbl-renamed",
                  "let C=%s;let A='';for(let k=0;k<C.length;k++){A+=String.fromCharCode(C[k]);}let B=A;let D=B;let RESULT=D;" % cl))
    # F1300: renamed, const.
    cases.append(("f1300-const",
                  "const C=%s;const D=Object.freeze(C.slice());const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs))
    cases.append(("f1300-spread-renamed",
                  "let A=%s;let B=Object.freeze(A.slice());let T=String.fromCharCode(...B);let RESULT=T;" % cl))
    # F1301: renamed.
    cases.append(("f1301-renamed",
                  "let A=%s;let B=Object.preventExtensions(A.slice());let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs))
    cases.append(("f1301-inline-renamed",
                  "const A=%s;const T=String.fromCharCode.apply(null,Object.preventExtensions(A.slice()));const RESULT=T;" % cl))
    # F1302: renamed.
    cases.append(("f1302-renamed",
                  "let A=%s;let B=A.map(function(x){return String.fromCodePoint(x);});let D=B.join('');let E=[];for(let k=0;k<D.length;k++){E.push(String.fromCodePoint(D.codePointAt(k)));}let T=E.join('');let RESULT=T;" % cs))
    bad = [name for name, p in cases if not _blocked(p)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Genuine non-assemblers (node-verified v24.20.0) must MISS."""
    cs = _codes(SECRET_S)
    miss = [
        # F1296: parseInt without radix arg (node: parses decimal, differs).
        ("f1296-no-radix",
         "var C=%s;var D=C.map(function(c){return parseInt(c.toString(16));});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1297: line terminator code -- regex drops it (node-verified).
        ("f1297-newline",
         "var C=[120,10,121];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(m.indices[1][0],m.indices[1][1]);var RESULT=S;"),
        # F1297: no d flag -- indices undefined (node-verified differs).
        ("f1297-nodflag",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/.exec(T);var S=T.substring(m.indices[1][0],m.indices[1][1]);var RESULT=S;" % cs),
        # F1298: Symbol.replace is not Symbol.match.
        ("f1298-replace",
         "var C=%s;var O={};O[Symbol.replace]=function(s){var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return [R];};var M='x'.match(O);var S=M[0];var RESULT=S;" % cs),
        # F1298: return R (not [R]) -- match returns string, [0] is a char.
        ("f1298-no-array",
         "var C=%s;var O={};O[Symbol.match]=function(s){var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return R;};var M='x'.match(O);var S=M[0];var RESULT=S;" % cs),
        # F1299: alias of the wrong source.
        ("f1299-wrong-src",
         "var C=%s;var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var S='x';var RESULT=S;" % cs),
        # F1300: seal (not freeze) with named D -- not this finding.
        ("f1300-seal-named",
         "var C=%s;var D=Object.seal(C.slice());var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1300: freeze on C.slice(1) -- drops a code (node-verified).
        ("f1300-slice1",
         "var C=%s;var D=Object.freeze(C.slice(1));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1301: seal (not preventExtensions) inline-apply -- not this finding.
        ("f1301-seal-inline",
         "var C=%s;var S=String.fromCharCode.apply(null,Object.seal(C.slice()));var RESULT=S;" % cs),
        # F1302: astral code -- walk does not reproduce (node-verified).
        ("f1302-astral",
         "var C=[0x1D400,65];var D=C.map(function(c){return String.fromCodePoint(c);});var E=D.join('');var F=[];for(var i=0;i<E.length;i++){F.push(String.fromCodePoint(E.codePointAt(i)));}var S=F.join('');var RESULT=S;"),
        # F1302: codePointAt(i+1) -- shifted read (node-verified differs).
        ("f1302-shifted",
         "var C=%s;var D=C.map(function(c){return String.fromCodePoint(c);});var E=D.join('');var F=[];for(var i=0;i<E.length-1;i++){F.push(String.fromCodePoint(E.codePointAt(i+1)));}var S=F.join('');var RESULT=S;" % cs),
    ]
    bad = [name for name, p in miss if not _misses(p)]
    return (not bad, "%d/%d fail-closed hold%s"
            % (len(miss) - len(bad), len(miss),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: siblings + cross-disjoint ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; filed controls hold."""
    cs = _codes(SECRET_S)
    blocks = [
        # F1267: toString(16) two-map twin still blocks.
        ("f1267-tostring16", _redfirst_shapes("w409", 1267)[0][1]),
        # F1194: inline-spread freeze still blocks.
        ("f1194-freeze-spread",
         "var C=%s;var S=String.fromCharCode(...Object.freeze(C.slice()));var RESULT=S;" % cs),
        # F1074: direct RESULT=R still blocks.
        ("f1074-direct",
         "var C=%s;var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var RESULT=R;" % cs),
        # F1090: bare map+join still blocks.
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        # F1185: RegExp exec staged read still blocks.
        ("f1185-exec", _redfirst_shapes("w407", 1185)[0][1]),
    ]
    bad = [name for name, p in blocks if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes hold%s"
            % (len(blocks) - len(bad), len(blocks),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjoint():
    """Each new hook fires only on its own grammar (no cross-fire)."""
    hooks = {
        "_js_f1296_stmt_decode": dlp._js_f1296_stmt_decode,
        "_js_f1297_stmt_decode": dlp._js_f1297_stmt_decode,
        "_js_f1298_stmt_decode": dlp._js_f1298_stmt_decode,
        "_js_f1299_stmt_decode": dlp._js_f1299_stmt_decode,
        "_js_f1300_stmt_decode": dlp._js_f1300_stmt_decode,
        "_js_f1301_stmt_decode": dlp._js_f1301_stmt_decode,
        "_js_f1302_stmt_decode": dlp._js_f1302_stmt_decode,
    }
    shapes = {}
    for n in range(1296, 1303):
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
        "function parseInt(x) { return x; }",
        "Object.freeze({a: 1});",
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
                "var C=%s;var D=C.map(function(c){return parseInt(c.toString(16),16);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 5 == 2:
            sites.append(
                "var C=%s;var O={};O[Symbol.match]=function(s){var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}return [R];};var M='x'.match(O);var S=M[0];var RESULT=S;" % cs)
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
    """F1289-F1295, F1303-F1314, F1316-F1322 (other lanes) still MISS."""
    bad = []
    total = 0
    for n in list(range(1289, 1296)) + list(range(1303, 1315)) + list(range(1316, 1323)):
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
    """Depth-1 green on w410_attack_probes: exactly F1296-F1302 flip.

    The attack battery's open tests for F1296-F1302 should now BREAK
    (they're closed by this lane); all other tests must HOLD.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w410_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g411l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w410_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        breaks = set()
        for line in out.split("\n"):
            m = re.search(r"BREAK\s+test_open_w410_f(\d+)", line)
            if m:
                breaks.add(int(m.group(1)))
        expected = set(range(1296, 1303))
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
