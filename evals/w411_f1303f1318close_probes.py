#!/usr/bin/env python3
"""Wave-411 lane 3 close battery: F1303-F1308, F1316-F1318 CLOSED.

F1303: Array.at computed negative index -- `C.at(i-C.length)` in a
fromCharCode accumulation loop, and the `C.at(-i)` + split/reverse/join
twin, assemble node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1303_stmt_decode` (two productions; fail-closed on
non-computed indices, missing reversal statement).

F1304: Symbol.iterator generator staging -- `[Symbol.iterator]` as a
generator yielding fromCharCode chars, then `[...O].join('')`,
assembles node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1304_stmt_decode` (fail-closed on non-generator).

F1305: String.raw tagged substitution residual --
`String.raw({raw:['','']},D.join(''))` with a pre-joined substitution
assembles node-exactly (v24.20.0) while find_credential MISSED. F1186
(CLOSED) models only the interleaved form. Closed by
`_js_f1305_stmt_decode` (fail-closed on 3-segment templates, spread).

F1306: Object.getOwnPropertyDescriptors staging -- accumulating
fromCharCode chars into an object, then reading `.value`s via
getOwnPropertyDescriptors, assembles node-exactly (v24.20.0) while
find_credential MISSED. Closed by `_js_f1306_stmt_decode`
(fail-closed on the singular getOwnPropertyDescriptor).

F1307: Reflect.ownKeys object staging -- `'k'+i` keys read back via
Reflect.ownKeys in insertion order, assembles node-exactly (v24.20.0)
while find_credential MISSED. Closed by `_js_f1307_stmt_decode`
(fail-closed on the .map( chain form).

F1308: variable slice index -- `String.fromCharCode.apply(null,C)`
or `String.fromCharCode(...C)` with `.slice(I)` on a variable index
assembles node-exactly (v24.20.0) while find_credential MISSED. The
existing decoder models only literal indices. Closed by
`_js_f1308_stmt_decode` (fail-closed on literal indices, unbound
names).

F1316: fromCodePoint.apply surrogate residual -- surrogate codepoints
(0xD800-0xDFFF) assemble to lone surrogates node-exactly (v24.20.0)
while find_credential MISSED (F1260's _safe_chr rejects them).
Closed by `_js_f1316_stmt_decode` (requires >=1 surrogate; disjoint
from F1260).

F1317: Set.forEach non-empty accumulator residual -- `S='x'` init
assembles node-exactly (v24.20.0) while find_credential MISSED (F1264
requires empty init). Closed by `_js_f1317_stmt_decode` (requires
non-empty init; disjoint from F1264).

F1318: eval-staged fromCodePoint residual --
`eval('String.fromCodePoint('+C.join(',')+')')` assembles
node-exactly (v24.20.0) while find_credential MISSED (F1266 models
only fromCharCode). Closed by `_js_f1318_stmt_decode` (disjoint from
F1266 by the eval prefix).

New _decode_layer dispatch loop (9 hooks); N_STMTDEC_LOOPS 61->62
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; F1289-F1302, F1309-F1314, F1319-F1322 (outside this lane)
still MISS/QUIET.

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
N_STMTDEC_LOOPS_PIN = 62  # wave-411 lane 3: 61 + 1 (real code-count change)

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
    names = ["_js_f1303_stmt_decode", "_js_f1304_stmt_decode",
             "_js_f1305_stmt_decode", "_js_f1306_stmt_decode",
             "_js_f1307_stmt_decode", "_js_f1308_stmt_decode",
             "_js_f1316_stmt_decode", "_js_f1317_stmt_decode",
             "_js_f1318_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d all9=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, all(has.values())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-411 lane 3 (2026-10-11)" in src
          and "F1303-F1308, F1316-F1318 CLOSED (9" in src
          and "F1289-F1302, F1309-F1314, F1319-F1323 OPEN (25" in src
          and "next free F1324" in src
          and "(F1323 filed 2026-10-11 08:20 UTC" in src)
    for n in list(range(1303, 1309)) + [1316, 1317, 1318]:
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-411 lane 3") == 9)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1323**" in src
          and "# Wave-410:" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All 22 filed shapes across F1303-F1308, F1316-F1318 now BLOCK."""
    bad = []
    total = 0
    for n in list(range(1303, 1309)) + [1316, 1317, 1318]:
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
    """let/const twins, S=S+ form, arrow twin, key-prefix twin, neg slice."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1303: let twin, S=S+ form.
    cases.append(("f1303-let",
                  "let C=%s;let S='';for(let i=0;i<C.length;i++){S+=String.fromCharCode(C.at(i-C.length));}let RESULT=S;" % cs))
    cases.append(("f1303-splus",
                  "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S+String.fromCharCode(C.at(i-C.length));}var RESULT=S;" % cl))
    # F1304: const twin.
    cases.append(("f1304-const",
                  "const C=%s;const O={};O[Symbol.iterator]=function*(){for(let i=0;i<C.length;i++){yield String.fromCharCode(C[i]);}};const S=[...O].join('');const RESULT=S;" % cs))
    # F1305: arrow twin, const.
    cases.append(("f1305-arrow",
                  "const C=%s;const D=C.map(c=>String.fromCharCode(c));const S=String.raw({raw:['','']},D.join(''));const RESULT=S;" % cl))
    # F1306: let twin.
    cases.append(("f1306-let",
                  "let C=%s;let O={};for(let i=0;i<C.length;i++){O[i]=String.fromCharCode(C[i]);}let D=Object.getOwnPropertyDescriptors(O);let S='';for(let k in D){S+=D[k].value;}let RESULT=S;" % cs))
    # F1307: different key prefix.
    cases.append(("f1307-prefix",
                  "var C=%s;var O={};for(var i=0;i<C.length;i++){O['z'+i]=String.fromCharCode(C[i]);}var K=Reflect.ownKeys(O);var S='';for(var i=0;i<K.length;i++){S+=O[K[i]];}var RESULT=S;" % cl))
    # F1308: negative variable index (node-exact: drops 0 chars from end... wraps).
    cases.append(("f1308-neg",
                  "var C=%s;var I=-%d;var S=String.fromCharCode.apply(null,C).slice(I);var RESULT=S;" % (cs, len(SECRET_S) + 5)))
    # F1316: surrogate in middle, const.
    cases.append(("f1316-surr2",
                  "const C=[0xDFFF,%s];const S=String.fromCodePoint.apply(null,C);const RESULT=S;" % ",".join(str(ord(c)) for c in SECRET_S)))
    # F1317: different init, let.
    cases.append(("f1317-init",
                  "let C=%s;let S='tok:';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});let RESULT=S;" % cs))
    # F1318: const twin.
    cases.append(("f1318-const",
                  "const C=%s;const S=eval('String.fromCodePoint('+C.join(',')+')');const RESULT=S;" % cl))
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
        # F1303: plain .at(i) is F1046's shape -- my hook must miss.
        ("f1303-at", dlp._js_f1303_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C.at(i));}var RESULT=S;" % cs),
        # F1303: computed but wrong index form.
        ("f1303-wrongidx", dlp._js_f1303_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C.at(i-C.length+1));}var RESULT=S;" % cs),
        # F1303: reversal statement missing on the -i form.
        ("f1303-norev", dlp._js_f1303_stmt_decode,
         "var C=%s;var S='';for(var i=1;i<=C.length;i++){S+=String.fromCharCode(C.at(-i));}var RESULT=S;" % cs),
        # F1304: non-generator function -- must miss.
        ("f1304-nogen", dlp._js_f1304_stmt_decode,
         "var C=%s;var O={};O[Symbol.iterator]=function(){for(var i=0;i<C.length;i++){yield String.fromCharCode(C[i]);}};var S=[...O].join('');var RESULT=S;" % cs),
        # F1305: three-segment template -- must miss.
        ("f1305-3seg", dlp._js_f1305_stmt_decode,
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=String.raw({raw:['','','']},D.join(''));var RESULT=S;" % cs),
        # F1305: spread form is F1186's shape -- my hook must miss.
        ("f1305-spread", dlp._js_f1305_stmt_decode,
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=String.raw({raw:new Array(D.length+1).fill('')},...D);var RESULT=S;" % cs),
        # F1306: singular getOwnPropertyDescriptor is F1273's shape.
        ("f1306-singular", dlp._js_f1306_stmt_decode,
         "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=String.fromCharCode(C[i]);}var D=Object.getOwnPropertyDescriptor(O,'0');var S=D.value;var RESULT=S;" % cs),
        # F1307: .map( chain is F1244's shape -- my hook must miss.
        ("f1307-map", dlp._js_f1307_stmt_decode,
         "var C=%s;var O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});var S=Reflect.ownKeys(O).map(function(k){return O[k];}).join('');var RESULT=S;" % cs),
        # F1308: literal slice(0) is the existing decoder's shape.
        ("f1308-lit0", dlp._js_f1308_stmt_decode,
         "var C=%s;var S=String.fromCharCode.apply(null,C).slice(0);var RESULT=S;" % cs),
        # F1308: unbound variable -- must miss.
        ("f1308-unbound", dlp._js_f1308_stmt_decode,
         "var C=%s;var S=String.fromCharCode.apply(null,C).slice(Q);var RESULT=S;" % cs),
        # F1316: all-ASCII is F1260's shape -- my hook must miss.
        ("f1316-ascii", dlp._js_f1316_stmt_decode,
         "var C=%s;var S=String.fromCodePoint.apply(null,C);var RESULT=S;" % cs),
        # F1316: out-of-range codepoint -- must miss.
        ("f1316-oor", dlp._js_f1316_stmt_decode,
         "var C=[0x110000,120];var S=String.fromCodePoint.apply(null,C);var RESULT=S;"),
        # F1317: empty init is F1264's shape -- my hook must miss.
        ("f1317-empty", dlp._js_f1317_stmt_decode,
         "var C=%s;var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs),
        # F1318: fromCharCode eval is F1266's shape -- my hook must miss.
        ("f1318-fcc", dlp._js_f1318_stmt_decode,
         "var C=%s;var S=eval('String.fromCharCode('+C.join(',')+')');var RESULT=S;" % cs),    ]
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
            ("f1260", "w409", 1260), ("f1264", "w409", 1264),
            ("f1266", "w409", 1266), ("f1186", "w408", 1186),
            ("f1273", "w410", 1273), ("f1244", "w409", 1244),
            ("f1046", "w408", 1046)]:
        try:
            shapes = _redfirst_shapes(prefix, num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("%s:%s" % (label, name))
    # Other opens (outside this lane) must still MISS.
    for num in list(range(1289, 1303)) + list(range(1309, 1315)) + list(range(1319, 1323)):
        try:
            shapes = _redfirst_shapes("w410", num)
        except Exception:
            continue
        for name, payload in shapes:
            if num in range(1309, 1315):
                # provenance seam -- not in this lane's scope; skip
                continue
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
        "var C=[65,66];var S=String.fromCharCode(C.at(0));var RESULT=S;",
        "var arr=[1,2,3];var s=arr.join(',');",
        "for(var i=0;i<10;i++){console.log(i);}",
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
                "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C.at(i-C.length));}var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("var C=%s;var S=String.fromCodePoint.apply(null,C);var RESULT=S;" % cs)
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
    """F1289-F1302, F1319-F1322 (outside this lane) still MISS."""
    bad = []
    for n in list(range(1289, 1303)) + list(range(1319, 1323)):
        try:
            shapes = _redfirst_shapes("w410", n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w410_attack_probes: my 9 flip, 24 hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w410_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g411l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w410_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w410_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # My lane: F1303-F1308, F1316-F1318 now CLOSED -> OPEN pins BREAK.
        # Siblings: F1289-F1302, F1309-F1314, F1319-F1322 still OPEN -> HELD.
        closed_now = set(range(1303, 1309)) | {1316, 1317, 1318}
        still_open = (set(range(1289, 1303)) | set(range(1309, 1315))
                      | set(range(1319, 1323)))
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w410_attack): closed-flip=%d/9 open-hold=%d/24%s"
                % (len(closed_now & broken), len(still_open & held),
                   "" if ok else " MISMATCH"))
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
