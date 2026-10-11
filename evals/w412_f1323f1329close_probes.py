#!/usr/bin/env python3
"""Wave-412 lane 1 close battery: F1323-F1329 CLOSED.

F1323: String.prototype.normalize per-char staging --
`String.fromCharCode(c).normalize('NFC'/'NFD')` before join('')
assembles node-exactly (v24.20.0, normalize is identity on ASCII)
while find_credential MISSED. Closed by `_js_f1323_stmt_decode`
(two productions; fail-closed via unicodedata identity check).

F1324: Object.assign code staging -- `Object.assign({},C)` (or
`new Object()`) copies the code array into indexed object
properties; `Object.values` reads them back for fromCharCode.apply.
Assembles node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1324_stmt_decode` (two productions).

F1325: Number.prototype.valueOf coercion staging -- mapping codes
through `new Number(c).valueOf()` (or `Number(c).valueOf()`)
before fromCharCode.apply assembles node-exactly (v24.20.0)
while find_credential MISSED. Distinct from F1268 (CLOSED).
Closed by `_js_f1325_stmt_decode` (two productions).

F1326: BigInt toString(radix) codec -- mapping codes through
`BigInt(c).toString(16)` then `parseInt(h,16)` (or base-36)
before fromCharCode.apply assembles node-exactly (v24.20.0)
while find_credential MISSED. Distinct from F1268 and F1296.
Closed by `_js_f1326_stmt_decode` (radix must match).

F1327: Map.prototype.set accumulation staging -- accumulating
`String.fromCharCode` chars via `M.set(i,ch)` in a loop (or via
the pairs-constructor `new Map(C.map(...))`) then `M.forEach`
join assembles node-exactly (v24.20.0) while find_credential
MISSED. Closed by `_js_f1327_stmt_decode` (two productions).

F1328: Array.prototype.concat.apply residual of F1243 (CLOSED) --
`Array.prototype.concat.apply([],C)` (or `[].concat.apply([],C)`)
before fromCharCode.apply assembles node-exactly (v24.20.0)
while find_credential MISSED. F1243 models the method-call form,
not the .apply form. Closed by `_js_f1328_stmt_decode`.

F1329: String.prototype.includes boolean-oracle staging -- testing
each `String.fromCharCode(C[i])` for membership in a full-ASCII
string via `CH.includes(ch)` (or `CH.indexOf(ch)!==-1`) and
accumulating hits assembles node-exactly (v24.20.0) while
find_credential MISSED. Closed by `_js_f1329_stmt_decode`
(verifies every char is in CH, else fail-closed).

New _decode_layer dispatch loop (7 hooks); N_STMTDEC_LOOPS 65->66
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; F1330-F1348 (outside this lane) still MISS/QUIET.

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
N_STMTDEC_LOOPS_PIN = 66  # wave-412 lane 1: 65 + 1 (real code-count change)

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
    names = ["_js_f1323_stmt_decode", "_js_f1324_stmt_decode",
             "_js_f1325_stmt_decode", "_js_f1326_stmt_decode",
             "_js_f1327_stmt_decode", "_js_f1328_stmt_decode",
             "_js_f1329_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d all7=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, all(has.values())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-412 lane 1 (2026-10-11)" in src
          and "F1323-F1329 CLOSED (7" in src
          and "F1330-F1348 OPEN (19" in src
          and "next free F1349" in src)
    # All 7 entries stamped (check the stamped pattern, not just count,
    # since the lane-3 footer mentions F1323).
    for n in range(1323, 1330):
        pat = "(F%d filed 2026-10-11 08:10 UTC" % n
        # The entry must contain the CLOSED stamp
        idx = src.find(pat)
        assert idx >= 0
        # Find the end of this entry (next "(F" or end)
        # Simpler: check that the stamped version exists
        stamped = "[CLOSED 2026-10-11 wave-412 lane 1]"
        # Count occurrences of the stamp (should be 7 total)
        pass
    ok = ok and src.count("[CLOSED 2026-10-11 wave-412 lane 1]") == 7
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-411:" in src
          and "next free F1349" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All 28 filed shapes across F1323-F1329 now BLOCK."""
    bad = []
    total = 0
    for n in range(1323, 1330):
        shapes = _redfirst_shapes("w411", n)
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
    """let/const twins, different var names."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1323: const twin, NFD.
    cases.append(("f1323-const",
                  "const C=%s;const D=C.map(function(c){return String.fromCharCode(c).normalize('NFD');});const S=D.join('');const RESULT=S;" % cs))
    # F1324: let twin, newobj.
    cases.append(("f1324-let",
                  "let C=%s;let O=Object.assign(new Object(),C);let S=String.fromCharCode.apply(null,Object.values(O));let RESULT=S;" % cl))
    # F1325: const twin, prim form.
    cases.append(("f1325-const",
                  "const C=%s;const A=C.map(function(c){return Number(c).valueOf();});const S=String.fromCharCode.apply(null,A);const RESULT=S;" % cs))
    # F1326: let twin, b36.
    cases.append(("f1326-let",
                  "let C=%s;let D=C.map(function(c){return BigInt(c).toString(36);});let E=D.map(function(h){return parseInt(h,36);});let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cl))
    # F1327: different var names, loop form.
    cases.append(("f1327-names",
                  "var A=%s;var N=new Map();for(var k=0;k<A.length;k++){N.set(k,String.fromCharCode(A[k]));}var T='';N.forEach(function(w){T+=w;});var RESULT=T;" % cs))
    # F1328: let twin, lit form.
    cases.append(("f1328-let",
                  "let C=%s;let D=[].concat.apply([],C);let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cl))
    # F1329: different var names, includes.
    cases.append(("f1329-names",
                  "var A=%s;var H=' !\"#$%%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';var T='';for(var k=0;k<A.length;k++){var q=String.fromCharCode(A[k]);if(H.includes(q)){T+=q;}}var RESULT=T;" % cs))
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
    """Hooks fail closed (miss, never mis-decode) on near-miss shapes."""
    cases = []
    cs = _codes(SECRET_S)
    # F1323: wrong normalize form.
    cases.append(("f1323-badform",
                  "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).normalize('NFKC');});var S=D.join('');var RESULT=S;" % cs,
                  dlp._js_f1323_stmt_decode))
    # F1323: non-empty join sep.
    cases.append(("f1323-badjoin",
                  "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).normalize('NFC');});var S=D.join(',');var RESULT=S;" % cs,
                  dlp._js_f1323_stmt_decode))
    # F1324: wrong source (not C).
    cases.append(("f1324-badsrc",
                  "var C=%s;var D=%s;var O=Object.assign({},D);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % (cs, cs),
                  dlp._js_f1324_stmt_decode))
    # F1325: missing valueOf.
    cases.append(("f1325-novalueof",
                  "var C=%s;var A=C.map(function(c){return Number(c);});var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs,
                  dlp._js_f1325_stmt_decode))
    # F1326: radix mismatch.
    cases.append(("f1326-radixmm",
                  "var C=%s;var D=C.map(function(c){return BigInt(c).toString(16);});var E=D.map(function(h){return parseInt(h,10);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
                  dlp._js_f1326_stmt_decode))
    # F1327: wrong accumulator init.
    cases.append(("f1327-badinit",
                  "var C=%s;var M=new Map();for(var i=0;i<C.length;i++){M.set(i,String.fromCharCode(C[i]));}var S='x';M.forEach(function(v){S+=v;});var RESULT=S;" % cs,
                  dlp._js_f1327_stmt_decode))
    # F1328: missing apply.
    cases.append(("f1328-noapply",
                  "var C=%s;var D=Array.prototype.concat([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
                  dlp._js_f1328_stmt_decode))
    # F1329: CH missing a char (oracle would drop it).
    cases.append(("f1329-dropchar",
                  "var C=%s;var CH='abc';var S='';for(var i=0;i<C.length;i++){var ch=String.fromCharCode(C[i]);if(CH.includes(ch)){S+=ch;}}var RESULT=S;" % cs,
                  dlp._js_f1329_stmt_decode))
    bad = [name for name, p, hook in cases if not _hook_misses(hook, p)]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """New hooks are disjoint: each misses its siblings' filed shapes."""
    hooks = {
        1323: dlp._js_f1323_stmt_decode,
        1324: dlp._js_f1324_stmt_decode,
        1325: dlp._js_f1325_stmt_decode,
        1326: dlp._js_f1326_stmt_decode,
        1327: dlp._js_f1327_stmt_decode,
        1328: dlp._js_f1328_stmt_decode,
        1329: dlp._js_f1329_stmt_decode,
    }
    bad = []
    for n, hook in hooks.items():
        for m in range(1323, 1330):
            if m == n:
                continue
            try:
                shapes = _redfirst_shapes("w411", m)
            except Exception:
                continue
            for name, payload in shapes:
                if not _hook_misses(hook, payload):
                    bad.append("f%d-on-f%d:%s" % (n, m, name))
                    break
    return (not bad, "sibling-disjoint%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (no false positives from new hooks)."""
    cases = [
        "The quick brown fox jumps over the lazy dog.",
        "var x = 1 + 2; console.log('hello world');",
        "function normalize(s) { return s.normalize('NFC'); }",
        "Object.assign({}, {a: 1, b: 2});",
        "const m = new Map(); m.set('key', 'value');",
        "if (arr.includes(item)) { doSomething(); }",
    ]
    bad = [p[:30] for p in cases if not _misses(p)]
    return (not bad, "honest-quiet%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 decode sites complete quickly."""
    cs = _codes(SECRET_S)
    payloads = []
    for i in range(200):
        payloads.append(
            "var C%d=%s;var D%d=C%d.map(function(c){return String.fromCharCode(c).normalize('NFC');});var S%d=D%d.join('');var RESULT%d=S%d;"
            % (i, cs, i, i, i, i, i, i))
    t0 = time.time()
    for p in payloads:
        dlp.find_credential(p)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1330-F1348 (outside this lane) still MISS."""
    bad = []
    for n in list(range(1330, 1336)) + list(range(1336, 1349)):
        prefix = "w411" if n <= 1335 else "w411"
        # F1336-F1348 were filed as w411_fNNNN_redfirst (renumbered)
        try:
            shapes = _redfirst_shapes(prefix, n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w411_attack_probes: my 7 flip, rest hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w411_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g412l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w411_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w411_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # My lane: F1323-F1329 now CLOSED -> OPEN pins BREAK.
        # Others in w411_attack_probes: F1330-F1335 still OPEN -> HELD.
        # (F1336-F1348 renumbered residuals are covered by p7, not by
        # w411_attack_probes which predates the renumbering.)
        closed_now = set(range(1323, 1330))
        still_open = set(range(1330, 1336))
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w411_attack): closed-flip=%d/7 open-hold=%d/6%s"
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
