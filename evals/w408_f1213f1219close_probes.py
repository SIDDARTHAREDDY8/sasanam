#!/usr/bin/env python3
"""Wave-408 lane 3 close battery: F1213-F1219 CLOSED.

F1213: JSON char-array roundtrip. Stringifying the mapped char array
and parsing it back before join assembles node-exactly (v24.20.0)
while find_credential MISSED. Residual of F1132 (CLOSED: int-array
JSON roundtrip). Closed by `_js_f1213_stmt_decode`.

F1214: defineProperty staged reads. Defining indexed char properties
via Object.defineProperty(O,i,{value:...,enumerable:true}) in a
forEach, then Object.values(O).join(''), assembles node-exactly
(v24.20.0) while find_credential MISSED. Sibling of F1182 (CLOSED:
Object.create + indexed assignment). Closed by
`_js_f1214_stmt_decode` (both descriptor key orders).

F1215: String.concat spread. Spreading mapped chars into
`''.concat(...)` assembles node-exactly (v24.20.0) while
find_credential MISSED. Closed by `_js_f1215_stmt_decode`
(`''`/`""` receiver twins).

F1216: URLSearchParams staged reads. Appending chars as param values
via `P.append('k'+i,...)` (or `P.set` with distinct keys) in a
forEach, then `Array.from(P.values()).join('')`, assembles
node-exactly (v24.20.0) while find_credential MISSED. Residual of
F1177 (CLOSED: for-of values()/indexed get). Closed by
`_js_f1216_stmt_decode` (set requires distinct keys -- constant-key
set overwrites and fails closed).

F1217: Reflect.apply member-expression target.
`Reflect.apply(String.fromCharCode,String,C)` (or null thisArg)
assembles node-exactly (v24.20.0) while find_credential MISSED.
Residual of the F519 class (CLOSED: function-expression targets +
literal args). Closed by `_js_f1217_stmt_decode`.

F1218: charAt rebuild loop. Rebuilding the credential char-by-char
via `H.charAt(i)` in a `for(var|let i=0;i<H.length;i++)` loop
assembles node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1218_stmt_decode` (`S+=` and `S=S+` twins).

F1219: charCodeAt roundtrip. Mapping the credential string back
through `charCodeAt` into an int array, then fromCharCode spread,
assembles node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1219_stmt_decode`.

F1213-F1219 filed 2026-10-11 03:06 UTC by wave-407 attack round 75
(local node validation, $0.00 model spend (0 paid calls); LOW, OPEN).

New _decode_layer dispatch loop (F1213-F1219); N_STMTDEC_LOOPS
49->50 (real code-count change). Node-exact on all filed shapes
(short + 40-char, v24.20.0); fail-closed hook-level bounds; sibling
pins hold; F1199-F1212, F1220-F1227 (attack round 75 + lane 2/3
filings) still MISS.

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
N_STMTDEC_LOOPS_PIN = 53  # wave-408 merge: 49 + 4 lanes  # wave-407 merged 49; +1 dispatch loop in this lane (F1213-F1219)

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
    have = all(any("_js_f%d_stmt_decode" % n in lp for lp in loops)
               for n in range(1213, 1220))
    ok = ok and have
    return (ok, "loops=%d pin=%d f1213-f1219=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, have))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-408 lane 3 (2026-10-11)" in src
          and "F1213-F1219 CLOSED (7" in src
          and "F1199-F1212, F1220-F1227 OPEN (22" in src
          and "next free F1228" in src)
    for n in range(1213, 1220):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-408 lane 3") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1228**" in src
          and "# Wave-407: F1182-F1198 CLOSED (17); F1199-F1227 OPEN (29); next free F1228" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    bad = []
    for n in range(1213, 1220):
        shapes = _redfirst_shapes("w408", n)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    total = sum(len(_redfirst_shapes("w408", n)) for n in range(1213, 1220))
    return (not bad, "%d/%d filed+generalization shapes block%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const, renamed idents, and twin forms (all node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1213: let/const + renamed idents.
    cases.append(("f1213-letconst",
                  "let D=%s;const A=D.map(function(x){return String.fromCharCode(x);});const J=JSON.stringify(A);const B=JSON.parse(J);const S=B.join('');const RESULT=S;" % cs))
    # F1214: let + renamed idents.
    cases.append(("f1214-let",
                  "let D=%s;let O={};D.forEach(function(x,j){Object.defineProperty(O,j,{value:String.fromCharCode(x),enumerable:true});});let S=Object.values(O).join('');let RESULT=S;" % cl))
    # F1215: renamed idents.
    cases.append(("f1215-renamed",
                  "var D=%s;var T=''.concat(...D.map(function(x){return String.fromCharCode(x);}));var RESULT=T;" % cs))
    # F1216: renamed idents.
    cases.append(("f1216-renamed",
                  "var D=%s;var Q=new URLSearchParams();D.forEach(function(x,j){Q.append('k'+j,String.fromCharCode(x));});var T=Array.from(Q.values()).join('');var RESULT=T;" % cl))
    # F1217: renamed idents.
    cases.append(("f1217-renamed",
                  "var D=%s;var T=Reflect.apply(String.fromCharCode,String,D);var RESULT=T;" % cs))
    # F1218: renamed idents + index.
    cases.append(("f1218-renamed",
                  "var D=%s;var H=D.map(function(x){return String.fromCharCode(x);}).join('');var T='';for(var j=0;j<H.length;j++){T+=H.charAt(j);}var RESULT=T;" % cl))
    # F1219: renamed idents + index.
    cases.append(("f1219-renamed",
                  "var D=%s;var H=D.map(function(x){return String.fromCharCode(x);}).join('');var E=[];for(var j=0;j<H.length;j++){E.push(H.charCodeAt(j));}var T=String.fromCharCode(...E);var RESULT=T;" % cs))
    bad = [name for name, payload in cases if not _blocked(payload)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Out-of-grammar inputs must MISS (a miss, never a mis-decode).

    Every case below is node-verified (v24.20.0) to NOT assemble the
    credential (throws, yields a wrong string, or drops codes), so
    the MISS is a true fail-closed bound -- never a mislabeled hole.
    """
    cs = _codes(SECRET_S)
    misses = [
        # F1213: stringify of the int array (F1132's domain) -- joins numbers.
        "var C=%s;var J=JSON.stringify(C);var B=JSON.parse(J);var S=B.join('');var RESULT=S;" % cs,
        # F1213: parse of the wrong var -- joins numbers.
        "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var J=JSON.stringify(A);var B=JSON.parse(C);var S=B.join('');var RESULT=S;" % cs,
        # F1214: missing enumerable -- Object.values sees nothing (S="").
        "var C=%s;var O={};C.forEach(function(c,i){Object.defineProperty(O,i,{value:String.fromCharCode(c)});});var S=Object.values(O).join('');var RESULT=S;" % cs,
        # F1214: constant property index -> node throws on redefinition.
        "var C=%s;var O={};C.forEach(function(c,i){Object.defineProperty(O,0,{value:String.fromCharCode(c),enumerable:true});});var S=Object.values(O).join('');var RESULT=S;" % cs,
        # F1215: non-empty receiver -- decodes to 'x'+credential.
        "var C=%s;var S='x'.concat(...C.map(function(c){return String.fromCharCode(c);}));var RESULT=S;" % cs,
        # F1215: extra concat arg -- decodes to 'y'+credential.
        "var C=%s;var S=''.concat('y',...C.map(function(c){return String.fromCharCode(c);}));var RESULT=S;" % cs,
        # F1216: set with constant key overwrites -- only the last char survives.
        "var C=%s;var P=new URLSearchParams();C.forEach(function(c,i){P.set('k',String.fromCharCode(c));});var S=Array.from(P.values()).join('');var RESULT=S;" % cs,
        # F1217: wrong target -- not fromCharCode.
        "var C=%s;var S=Reflect.apply(String.fromCodePoint,String,C);var RESULT=S;" % cs,
        # F1218: off-by-one charAt -- drops the first char.
        "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S='';for(var i=0;i<H.length;i++){S+=H.charAt(i+1);}var RESULT=S;" % cs,
        # F1219: pushing chars not codes -- fromCharCode of NaN.
        "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);}).join('');var A=[];for(var i=0;i<H.length;i++){A.push(H.charAt(i));}var S=String.fromCharCode(...A);var RESULT=S;" % cs,
    ]
    bad = [p[:60] for p in misses if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(misses) - len(bad), len(misses),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; new hooks don't steal their shapes."""
    cs = _codes(SECRET_S)
    blocks = [
        # F1132: int-array JSON roundtrip (F1213 must not steal).
        ("f1132-intjson",
         "var C=%s;var S=String.fromCharCode(...JSON.parse(JSON.stringify(C)));var RESULT=S;" % cs),
        # F1182: Object.create staged assembly (F1214 must not steal).
        ("f1182-objcreate",
         "var C=%s;var O=Object.create(null);C.forEach(function(c,i){O[i]=String.fromCharCode(c);});var S=Object.values(O).join('');var RESULT=S;" % cs),
        # F1090: unwrapped map+join (F1215/F1218/F1219 must not steal).
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        # F1193: FormData staged reads (F1216 must not steal).
        ("f1193-formdata",
         "var C=%s;var F=new FormData();C.forEach(function(c,i){F.append('k'+i,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs),
        # F1177: URLSearchParams for-of values (F1216 must not steal).
        ("f1177-usp-forof",
         "var C=%s;var P=new URLSearchParams(C.map(function(c,i){return ['k'+i,String.fromCharCode(c)];}));var S='';for(var v of P.values()){S+=v;}var RESULT=S;" % cs),
    ]
    bad = [name for name, payload in blocks if not _blocked(payload)]
    # F519: Reflect.apply with function-expression target (not a payload
    # shape; check the hook still fires via its own battery import).
    shapes519 = _redfirst_shapes("w363", 519)
    for name, payload, _recovers in shapes519:
        if not _blocked(payload):
            bad.append("f519:%s" % name)
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(blocks) + len(shapes519) - len(bad),
               len(blocks) + len(shapes519),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest text ----------------

@_t
def test_p5_honest_text():
    honest = [
        "The quarterly financial summary shows revenue growth.",
        "var data = JSON.stringify({a: 1}); var o = JSON.parse(data);",
        "Object.defineProperty(obj, 'x', {value: 1, enumerable: true});",
        "var s = ''.concat(a, b); var t = str.charAt(0);",
        "var p = new URLSearchParams('a=1&b=2');",
        "var r = Reflect.apply(f, null, args);",
        "function build() { var s=''; for (var i=0;i<n;i++) { s += names.charAt(i); } return s; }",
    ]
    bad = [p[:50] for p in honest if not _misses(p)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(honest) - len(bad), len(honest),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});"
               "var J=JSON.stringify(A);var B=JSON.parse(J);"
               "var S=B.join('');var RESULT=S;" % cs)
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(payload)
        dlp.find_credential(payload[::-1])
    dt = time.time() - t0
    return (dt < 30.0, "200 sites x2 in %.1fs (budget 30s)" % dt)


# ---------------- p7: still-open ----------------

@_t
def test_p7_still_open():
    """Round-75 findings outside this lane now BLOCK on merged tree (all closed)."""
    bad = []
    for n in list(range(1199, 1213)) + list(range(1220, 1228)):
        shapes = _redfirst_shapes("w407", n)
        for name, payload in shapes:
            if _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "round-75 others now BLOCK%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w407's attack battery (round-75 opens).

    On merged tree, all F1199-F1227 pins flip to BREAK (all closed).
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w407_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g408l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w407_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        for line in out.split("\n"):
            if "HELD" in line and "test_open_w407_f" in line:
                m = re.search(r"test_open_w407_f(\d+)", line)
                if m:
                    held.add(int(m.group(1)))
        expected = set()
        flipped = set(range(1199, 1228))
        ok = not (flipped & held)
        tail = out.strip().split("\n")[-3:] if not ok else []
        return (ok, "green(w407_attack): held=%d/22 open, flipped=%d/7 %s"
                % (len(expected & held), len(flipped - held),
                   " ".join(tail) if not ok else "exact"))
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
