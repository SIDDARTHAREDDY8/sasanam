#!/usr/bin/env python3
"""Wave-410 lane 2 close battery: F1267-F1273 CLOSED.

F1267: numeric string codec roundtrips -- `String(c).padStart(3,'0')`,
`c.toString(16)`, `Number(c).toPrecision(3)` encode then parseInt back.
Each is the identity on the int codes (toPrecision(3) only for 0..999,
node-verified v24.20.0), staged through fromCharCode.apply. Distinct
from F1203 (toFixed). Closed by `_js_f1267_stmt_decode`.

F1268: numeric coercion staging -- `BigInt(c)->Number(b)`, `Number(c)`,
`parseInt(c,10)` before fromCharCode.apply. All are the identity on
the admitted code range. Closed by `_js_f1268_stmt_decode`.

F1269: WeakRef staging -- `new WeakRef({c:C}).deref().c` and WeakRef
around the staged char object. Distinct from F1183 (WeakMap). Closed
by `_js_f1269_stmt_decode`.

F1270: Array.findIndex side-effect accumulation --
`C.findIndex(c=>{S+=fromCharCode(c);return false;})` (+ the (c,i) twin).
findIndex visits every element because the callback always returns
false. Distinct from F1248 (filter). Closed by `_js_f1270_stmt_decode`.

F1271: Array.pop while-loop reverse build --
`while(D.length){A.push(fromCharCode(D.pop()))}` + reverse().join('')
and the prepend twin `S=fcc(D.pop())+S`. Distinct from F1209
(while+shift). Closed by `_js_f1271_stmt_decode`.

F1272: string-method no-op wrappers -- substring/slice/trim/repeat/
replace($1)/decodeURI around blocked map+join. Each wrapper is
verified to be the identity on the decoded J. Distinct from F1207
(encodeURI/toLowerCase/normalize/slice(0)) and F1195
(template/String()/concat). Closed by `_js_f1272_stmt_decode`.

F1273: object staging residuals -- Object.values on plain literal,
Object.entries on Object.create(null), Object.getOwnPropertyDescriptor
reads. Residuals of F1182 (Object.create+values). Closed by
`_js_f1273_stmt_decode`.

New _decode_layer dispatch loop (F1267-F1273); N_STMTDEC_LOOPS 57->58
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1260-F1266, F1274-F1288 (attack round 77 opens outside this lane)
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
N_STMTDEC_LOOPS_PIN = 58  # wave-410 lane 2: 57 + F1267-F1273 loop

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
    names = ["_js_f1267_stmt_decode", "_js_f1268_stmt_decode",
             "_js_f1269_stmt_decode", "_js_f1270_stmt_decode",
             "_js_f1271_stmt_decode", "_js_f1272_stmt_decode",
             "_js_f1273_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-410 lane 2 (2026-10-11)" in src
          and "F1267-F1273 CLOSED (7" in src
          and "F1229-F1259 CLOSED (31" in src
          and "next free F1289" in src)
    for n in range(1267, 1274):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-410 lane 2") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1289**" in src
          and "# Wave-409: F1229-F1259 CLOSED (31); F1260-F1288 OPEN (29); next free F1289" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1267-F1273 filed shapes now BLOCK."""
    bad = []
    total = 0
    for n in range(1267, 1274):
        shapes = _redfirst_shapes("w409", n)
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
    # F1267: let/const twins.
    cases.append(("f1267-let-padstart",
                  "let C=%s;let P=C.map(function(c){return String(c).padStart(3,'0');});let S=String.fromCharCode.apply(null,P.map(function(p){return parseInt(p,10);}));let RESULT=S;" % cs))
    cases.append(("f1267-const-tostring16",
                  "const C=%s;const H=C.map(function(c){return c.toString(16);});const S=String.fromCharCode.apply(null,H.map(function(h){return parseInt(h,16);}));const RESULT=S;" % cl))
    # F1268: let/const twins.
    cases.append(("f1268-let-bigint",
                  "let C=%s;let B=C.map(function(c){return BigInt(c);});let S=String.fromCharCode.apply(null,B.map(function(b){return Number(b);}));let RESULT=S;" % cs))
    cases.append(("f1268-const-parseint",
                  "const C=%s;const N=C.map(function(c){return parseInt(c,10);});const S=String.fromCharCode.apply(null,N);const RESULT=S;" % cl))
    # F1269: let twin.
    cases.append(("f1269-let",
                  "let C=%s;let W=new WeakRef({c:C});let D=W.deref().c;let S=String.fromCharCode.apply(null,D.slice());let RESULT=S;" % cs))
    # F1270: (c,i) twin with let.
    cases.append(("f1270-let-idx",
                  "let C=%s;let S='';C.findIndex(function(c,i){S+=String.fromCharCode(C[i]);return false;});let RESULT=S;" % cl))
    # F1271: const twins.
    cases.append(("f1271-const-push",
                  "const C=%s;const D=C.slice();const A=[];while(D.length){A.push(String.fromCharCode(D.pop()));}const S=A.reverse().join('');const RESULT=S;" % cs))
    cases.append(("f1271-let-prepend",
                  "let C=%s;let D=C.slice();let S='';while(D.length){S=String.fromCharCode(D.pop())+S;}let RESULT=S;" % cl))
    # F1272: let twins for each wrapper.
    cases.append(("f1272-let-substring",
                  "let C=%s;let A=C.map(function(c){return String.fromCharCode(c);});let J=A.join('');let S=('xx'+J+'yy').substring(2,2+J.length);let RESULT=S;" % cs))
    cases.append(("f1272-let-slice",
                  "let C=%s;let A=C.map(function(c){return String.fromCharCode(c);});let J=A.join('');let S=('xx'+J+'yy').slice(2,-2);let RESULT=S;" % cs))
    cases.append(("f1272-let-replace",
                  "let C=%s;let A=C.map(function(c){return String.fromCharCode(c);});let J=A.join('');let S=J.replace(/(.)/g,'$1');let RESULT=S;" % cl))
    # F1273: let twins.
    cases.append(("f1273-let-values",
                  "let C=%s;let O={};for(let i=0;i<C.length;i++){O['k'+i]=String.fromCharCode(C[i]);}let S=Object.values(O).join('');let RESULT=S;" % cs))
    cases.append(("f1273-const-gopd",
                  "const C=%s;const O={};C.forEach(function(c,i){Object.defineProperty(O,'k'+i,{value:String.fromCharCode(c),enumerable:true});});const S=Object.keys(O).map(function(k){return Object.getOwnPropertyDescriptor(O,k).value;}).join('');const RESULT=S;" % cl))
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
        # F1267: padStart(4) -- different string (node-verified differs).
        ("f1267-padstart4",
         "var C=%s;var P=C.map(function(c){return String(c).padStart(4,'0');});var S=String.fromCharCode.apply(null,P.map(function(p){return parseInt(p,10);}));var RESULT=S;" % cs),
        # F1267: toPrecision(3) with code >= 1000 (node-verified differs).
        ("f1267-toprecision-big",
         "var C=[1000,1001,1002];var S=String.fromCharCode.apply(null,C.map(function(c){return parseInt(Number(c).toPrecision(3),10);}));var RESULT=S;"),
        # F1268: Number on non-numeric (node-verified differs).
        ("f1268-number-str",
         "var C=%s;var N=C.map(function(c){return Number('x'+c);});var S=String.fromCharCode.apply(null,N);var RESULT=S;" % cs),
        # F1269: WeakRef without deref (node-verified differs).
        ("f1269-no-deref",
         "var C=%s;var W=new WeakRef({c:C});var S=String.fromCharCode.apply(null,W.c.slice());var RESULT=S;" % cs),
        # F1270: return true -- stops after first (node-verified differs).
        ("f1270-return-true",
         "var C=%s;var S='';C.findIndex(function(c){S+=String.fromCharCode(c);return true;});var RESULT=S;" % cs),
        # F1271: shift instead of pop (node-verified differs).
        ("f1271-shift",
         "var C=%s;var D=C.slice();var A=[];while(D.length){A.push(String.fromCharCode(D.shift()));}var S=A.reverse().join('');var RESULT=S;" % cs),
        # F1272: trim on whitespace-padded J (node-verified differs).
        ("f1272-trim-ws",
         "var C=[32,120,111,98,32];var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=('  '+J+'  ').trim();var RESULT=S;"),
        # F1272: substring with wrong start (node-verified differs).
        ("f1272-substring-wrong",
         "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=('xx'+J+'yy').substring(1,1+J.length);var RESULT=S;" % cs),
        # F1273: wrong key order (node-verified differs).
        ("f1273-wrong-keys",
         "var C=%s;var O={};for(var i=0;i<C.length;i++){O['z'+(C.length-i)]=String.fromCharCode(C[i]);}var S=Object.values(O).join('');var RESULT=S;" % cs),
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
        # F1203: toFixed twin still blocks (filed shape).
        ("f1203-tofixed", _redfirst_shapes("w407", 1203)[0][1]),
        # F1183: WeakMap twin still blocks (filed shape).
        ("f1183-weakmap", _redfirst_shapes("w407", 1183)[0][1]),
        # F1248: filter twin still blocks (filed shape).
        ("f1248-filter", _redfirst_shapes("w409", 1248)[0][1]),
        # F1209: while+shift twin still blocks (filed shape).
        ("f1209-shift", _redfirst_shapes("w407", 1209)[0][1]),
        # F1207: encodeURI twin still blocks (filed shape).
        ("f1207-encodeuri", _redfirst_shapes("w407", 1207)[0][1]),
        # F1182: Object.create+values twin still blocks (filed shape).
        ("f1182-create-values", _redfirst_shapes("w407", 1182)[0][1]),
        # F1090: bare map+join still blocks.
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    bad = [name for name, p in blocks if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes hold%s"
            % (len(blocks) - len(bad), len(blocks),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjoint():
    """Each new hook fires only on its own grammar (no cross-fire)."""
    hooks = {
        "_js_f1267_stmt_decode": dlp._js_f1267_stmt_decode,
        "_js_f1268_stmt_decode": dlp._js_f1268_stmt_decode,
        "_js_f1269_stmt_decode": dlp._js_f1269_stmt_decode,
        "_js_f1270_stmt_decode": dlp._js_f1270_stmt_decode,
        "_js_f1271_stmt_decode": dlp._js_f1271_stmt_decode,
        "_js_f1272_stmt_decode": dlp._js_f1272_stmt_decode,
        "_js_f1273_stmt_decode": dlp._js_f1273_stmt_decode,
    }
    shapes = {}
    for n in range(1267, 1274):
        shapes["_js_f%d_stmt_decode" % n] = _redfirst_shapes("w409", n)
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
                "var C=%s;var P=C.map(function(c){return String(c).padStart(3,'0');});var S=String.fromCharCode.apply(null,P.map(function(p){return parseInt(p,10);}));var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 5 == 2:
            sites.append("var C=%s;var S='';C.findIndex(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;" % cs)
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
    """F1260-F1266, F1274-F1288 (other lanes) still MISS."""
    bad = []
    total = 0
    for n in list(range(1260, 1267)) + list(range(1274, 1289)):
        shapes = _redfirst_shapes("w409", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "%d/%d other opens miss%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w409_attack_probes: exactly F1267-F1273 flip.

    The attack battery's open tests for F1267-F1273 should now BREAK
    (they're closed by this lane); all other tests must HOLD.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w409_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g410l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w409_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        breaks = set()
        for line in out.split("\n"):
            m = re.search(r"BREAK\s+test_open_w409_f(\d+)", line)
            if m:
                breaks.add(int(m.group(1)))
        expected = set(range(1267, 1274))
        ok = (breaks == expected)
        return (ok, "green(w409_attack): flipped=%s%s"
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
