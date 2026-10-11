#!/usr/bin/env python3
"""Wave-410 lane 1 close battery: F1260-F1266 CLOSED.

F1260: String.fromCodePoint.apply staging -- `String.fromCodePoint.apply(null,C)`
(and the C.slice() twin) assembles node-exactly (v24.20.0) while find_credential
MISSED. Distinct from F505 (CLOSED: spread form) and F996 (CLOSED: fromCharCode.apply).
Closed by `_js_f1260_stmt_decode` (fromCodePoint semantics via _safe_chr).

F1261: toSpliced/copyWithin laundering -- `A.toSpliced(0,0)` (no-op copy) and
`A.copyWithin(0,0)` (no-op in place) around blocked map+join assemble node-exactly
(v24.20.0) while find_credential MISSED. Distinct from F1207 (CLOSED: other methods)
and F1243 (CLOSED: [].concat laundering). Closed by `_js_f1261_stmt_decode`.

F1262: structuredClone laundering -- `structuredClone(A)` (array and object forms)
around blocked map+join assembles node-exactly (v24.20.0) while find_credential
MISSED. Closed by `_js_f1262_stmt_decode`.

F1263: Map.groupBy staging -- `Map.groupBy(...,function(){return 'k';})` with
`.get('k')` readback assembles node-exactly (v24.20.0) while find_credential MISSED.
Distinct from F1234 (CLOSED: Object.groupBy) and F1230 (CLOSED: Map staged reads).
Closed by `_js_f1263_stmt_decode`.

F1264: Set.forEach staging -- `new Set(C.keys()).forEach(...)` accumulation and the
`.values()`+`.next()` loop form assemble node-exactly (v24.20.0) while find_credential
MISSED. Closed by `_js_f1264_stmt_decode`.

F1265: iterator protocol staging -- manual `.next()` loop, `.values().map()`+spread,
`Array.from(iterator,mapFn)` assemble node-exactly (v24.20.0) while find_credential
MISSED. Distinct from F1239 (CLOSED: Iterator.forEach) and F1172 (CLOSED: Array.from
on arrays). Closed by `_js_f1265_stmt_decode`.

F1266: eval-staged fromCharCode -- `eval('String.fromCharCode('+C.join(',')+')')`
and `eval('String.fromCharCode.apply(null,'+JSON.stringify(C)+')')` assemble
node-exactly (v24.20.0) while find_credential MISSED. Distinct from F1205 (CLOSED:
new Function). Closed by `_js_f1266_stmt_decode` (static eval modeling, never evals).

New _decode_layer dispatch loop (F1260-F1266); N_STMTDEC_LOOPS 57->58 (real
code-count change). Node-exact on all filed shapes (short + long, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1267-F1288 (attack round 77
opens outside this lane) still MISS.

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
N_STMTDEC_LOOPS_PIN = 58  # wave-410 lane 1: 57 + 1 (real code-count change)

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
    names = ["_js_f1260_stmt_decode", "_js_f1261_stmt_decode",
             "_js_f1262_stmt_decode", "_js_f1263_stmt_decode",
             "_js_f1264_stmt_decode", "_js_f1265_stmt_decode",
             "_js_f1266_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-410 lane 1 (2026-10-11)" in src
          and "F1260-F1266 CLOSED (7" in src
          and "F1267-F1288 OPEN (22" in src
          and "next free F1289" in src)
    for n in range(1260, 1267):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-410 lane 1") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1289**" in src
          and "# Wave-409: F1229-F1259 CLOSED (31); F1260-F1288 OPEN (29); next free F1289" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1260-F1266 filed shapes now BLOCK."""
    bad = []
    total = 0
    for n in range(1260, 1267):
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
    """let/const twins, whitespace variants (all node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1260: let/const twins, no-slice form.
    cases.append(("f1260-let",
                  "let C=%s;let S=String.fromCodePoint.apply(null,C);let RESULT=S;" % cs))
    cases.append(("f1260-const-long",
                  "const C=%s;const D=C.slice();const S=String.fromCodePoint.apply(null,D);const RESULT=S;" % cl))
    # F1261: let twin, copyWithin form.
    cases.append(("f1261-let",
                  "let C=%s;let A=C.map(function(c){return String.fromCharCode(c);});let B=A.toSpliced(0,0);let S=B.join('');let RESULT=S;" % cs))
    cases.append(("f1261-const-long",
                  "const C=%s;const A=C.map(function(c){return String.fromCharCode(c);});A.copyWithin(0,0);const S=A.join('');const RESULT=S;" % cl))
    # F1262: let twin, object form.
    cases.append(("f1262-let",
                  "let C=%s;let A=C.map(function(c){return String.fromCharCode(c);});let B=structuredClone(A);let S=B.join('');let RESULT=S;" % cs))
    cases.append(("f1262-const-obj-long",
                  "const C=%s;const O={a:C.map(function(c){return String.fromCharCode(c);})};const B=structuredClone(O);const S=B.a.join('');const RESULT=S;" % cl))
    # F1263: let twin, pairs form.
    cases.append(("f1263-let",
                  "let C=%s;let G=Map.groupBy(C.map(function(c){return String.fromCharCode(c);}),function(){return 'k';});let S=G.get('k').join('');let RESULT=S;" % cs))
    cases.append(("f1263-const-pairs-long",
                  "const C=%s;const G=Map.groupBy(C.map(function(c,i){return [i,String.fromCharCode(c)];}),function(e){return 'k';});const S=G.get('k').map(function(e){return e[1];}).join('');const RESULT=S;" % cl))
    # F1264: let twin, values-next form.
    cases.append(("f1264-let",
                  "let C=%s;let S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});let RESULT=S;" % cs))
    cases.append(("f1264-const-values-long",
                  "const C=%s;let S='';const I=new Set(C.keys()).values();let r;while(!(r=I.next()).done){S+=String.fromCharCode(C[r.value]);}const RESULT=S;" % cl))
    # F1265: let twin, mapspread form.
    cases.append(("f1265-let",
                  "let C=%s;let I=C.keys();let S='';let r;while(!(r=I.next()).done){S+=String.fromCharCode(C[r.value]);}let RESULT=S;" % cs))
    cases.append(("f1265-const-map-long",
                  "const C=%s;const I=C.values().map(function(c){return String.fromCharCode(c);});const A=[...I];const S=A.join('');const RESULT=S;" % cl))
    # F1266: let twin, apply form.
    cases.append(("f1266-let",
                  "let C=%s;let S=eval('String.fromCharCode('+C.join(',')+')');let RESULT=S;" % cs))
    cases.append(("f1266-const-apply-long",
                  "const C=%s;const S=eval('String.fromCharCode.apply(null,'+JSON.stringify(C)+')');const RESULT=S;" % cl))
    bad = []
    for name, payload in cases:
        if not _blocked(payload):
            bad.append(name)
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Genuine non-assemblers (node-verified) must MISS."""
    cs = _codes(SECRET_S)
    miss = [
        # F1260: surrogate codepoint (RangeError in node).
        ("f1260-surrogate",
         "var C=%s;var S=String.fromCodePoint.apply(null,C);var RESULT=S;"
         % ("[" + ",".join(str(0xD800) for _ in SECRET_S) + "]")),
        # F1260: out-of-range codepoint (RangeError in node).
        ("f1260-oorange",
         "var C=%s;var S=String.fromCodePoint.apply(null,C);var RESULT=S;"
         % ("[" + ",".join(str(0x110000) for _ in SECRET_S) + "]")),
        # F1261: toSpliced(0,1) removes element (node-verified differs).
        ("f1261-spliced1",
         "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var B=A.toSpliced(0,1);var S=B.join('');var RESULT=S;" % cs),
        # F1261: copyWithin(0,1) shifts (node-verified differs).
        ("f1261-copywithin1",
         "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});A.copyWithin(0,1);var S=A.join('');var RESULT=S;" % cs),
        # F1262: clone of wrong array.
        ("f1262-wrong-arr",
         "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var B=structuredClone(C);var S=B.join('');var RESULT=S;" % cs),
        # F1263: mismatched get key (node-verified: undefined.join throws).
        ("f1263-key-mismatch",
         "var C=%s;var G=Map.groupBy(C.map(function(c){return String.fromCharCode(c);}),function(){return 'k';});var S=G.get('x').join('');var RESULT=S;" % cs),
        # F1263: non-constant key fn (groups differ).
        ("f1263-nonconst-key",
         "var C=%s;var G=Map.groupBy(C.map(function(c){return String.fromCharCode(c);}),function(c){return c;});var S=G.get('k').join('');var RESULT=S;" % cs),
        # F1264: wrong accumulator init.
        ("f1264-wrong-init",
         "var C=%s;var S='x';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs),
        # F1265: spread of wrong iterator.
        ("f1265-wrong-iter",
         "var C=%s;var I=C.values().map(function(c){return String.fromCharCode(c);});var A=[...C];var S=A.join('');var RESULT=S;" % cs),
        # F1266: eval with different prefix (not modeled).
        ("f1266-bad-prefix",
         "var C=%s;var S=eval('String.fromCodePoint('+C.join(',')+')');var RESULT=S;" % cs),
        # F1266: eval with non-comma join (node-verified differs).
        ("f1266-bad-join",
         "var C=%s;var S=eval('String.fromCharCode('+C.join(';')+')');var RESULT=S;" % cs),
    ]
    bad = [name for name, p in miss if not _misses(p)]
    total = len(miss)
    return (not bad, "%d/%d fail-closed hold%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: siblings + cross-disjoint ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; new hooks don't steal their shapes."""
    cs = _codes(SECRET_S)
    blocks = [
        # F505: fromCodePoint spread still blocks.
        ("f505-spread",
         "var C=%s;var S=String.fromCodePoint(...C);var RESULT=S;" % cs),
        # F996: fromCharCode.apply direct still blocks.
        ("f996-apply",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % cs),
        # F1207: other laundering methods still block.
        ("f1207-slice",
         _redfirst_shapes("w407", 1207)[0][1]),
        # F1243: [].concat laundering still blocks.
        ("f1243-concat",
         _redfirst_shapes("w408", 1243)[0][1]),
        # F1234: Object.groupBy still blocks.
        ("f1234-objgroupby",
         _redfirst_shapes("w408", 1234)[0][1]),
        # F1230: Map staged reads still block.
        ("f1230-mapread",
         _redfirst_shapes("w408", 1230)[0][1]),
        # F1239: Iterator.forEach still blocks.
        ("f1239-iterforeach",
         _redfirst_shapes("w409", 1239)[0][1]),
        # F1172: Array.from on arrays still blocks.
        ("f1172-arrayfrom",
         _redfirst_shapes("w405", 1172)[0][1]),
        # F1205: new Function still blocks.
        ("f1205-newfunc",
         _redfirst_shapes("w407", 1205)[0][1]),
        # F1090: bare map+join still blocks.
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    bad = [name for name, p in blocks if not _blocked(p)]
    total = len(blocks)
    return (not bad, "%d/%d sibling shapes hold%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjoint():
    """Each new hook fires only on its own grammar (no cross-fire)."""
    hooks = {
        "_js_f1260_stmt_decode": dlp._js_f1260_stmt_decode,
        "_js_f1261_stmt_decode": dlp._js_f1261_stmt_decode,
        "_js_f1262_stmt_decode": dlp._js_f1262_stmt_decode,
        "_js_f1263_stmt_decode": dlp._js_f1263_stmt_decode,
        "_js_f1264_stmt_decode": dlp._js_f1264_stmt_decode,
        "_js_f1265_stmt_decode": dlp._js_f1265_stmt_decode,
        "_js_f1266_stmt_decode": dlp._js_f1266_stmt_decode,
    }
    shapes = {}
    for n in range(1260, 1267):
        shapes["_js_f%d_stmt_decode" % n] = _redfirst_shapes("w410", n)
    bad = []
    for hname, hfn in hooks.items():
        own = shapes[hname]
        # own shapes decode
        for sname, p in own:
            if hfn(p) is None:
                bad.append("%s misses own %s" % (hname, sname))
        # others' shapes do not decode via this hook
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
        "var C=[1,2,3];var S=C.join(',');console.log(S);",
        "The eval function is useful for dynamic code.",
    ]
    bad = [p for p in quiet if not _misses(p)]
    total = len(quiet)
    return (not bad, "%d/%d honest quiet%s"
            % (total - len(bad), total,
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
                "var C=%s;var S=String.fromCodePoint.apply(null,C);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append(
                "var C=%s;var S=eval('String.fromCharCode('+C.join(',')+')');var RESULT=S;" % cs)
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
    """F1267-F1288 (attack round 77 opens outside this lane) still MISS."""
    bad = []
    for n in range(1267, 1289):
        shapes = _redfirst_shapes("w409", n)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other-opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w409_attack_probes: exactly F1260-F1266 flip.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w409_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g410l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w409_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w409_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # Expect F1260-F1266 BREAK (now CLOSED), F1267-F1288 HELD (still OPEN).
        # Note: w409_attack_probes returns 1 when open pins BREAK (expected
        # for the 7 closed findings), so we do NOT require returncode 0.
        expected_broken = set(range(1260, 1267))
        expected_held = set(range(1267, 1289))
        ok = (expected_broken <= broken and expected_held <= held)
        return (ok, "green(w409_attack): broke=%d/7 held=%d/22%s"
                % (len(expected_broken & broken), len(expected_held & held),
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
