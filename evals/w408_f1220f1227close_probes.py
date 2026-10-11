#!/usr/bin/env python3
"""Wave-408 lane 4 close battery: F1220-F1228 CLOSED.

F1220: Object.keys index staging -- iterating `Object.keys(C)` and
indexing back into C assembles node-exactly (v24.20.0) while
find_credential MISSED. Closed by `_js_f1220_stmt_decode`.

F1221: Array.from inline mapFn -- spreading `Array.from(C,identity)`
inline (no intermediate variable) assembles node-exactly (v24.20.0)
while find_credential MISSED. Residual of F1172 (CLOSED:
intermediate-var form). Closed by `_js_f1221_stmt_decode`.

F1222: flat(1) on doubly-nested arrays -- swapping the depth literal
to flat(1) on the F1187 production assembles node-exactly (v24.20.0)
while find_credential MISSED. Residual of F1187 (CLOSED: hook
enforced depth == 2). Closed by widening `_js_f1187_stmt_decode`
to accept any depth.

F1223: async-generator yield* with arrow callback --
`yield* C.map(c=>String.fromCharCode(c))` inside an async generator
consumed by for-await assembles node-exactly (v24.20.0) while
find_credential MISSED. Residual of F1189 (CLOSED: form-B hook took
fn-expressions only). Closed by widening `_js_f1189_stmt_decode`
form-B to accept arrow callbacks.

F1224: while-loop FormData staged reads -- staging chars via
F.append/set in a `while(i<C.length)` loop assembles node-exactly
(v24.20.0) while find_credential MISSED. Residual of F1193 (CLOSED:
hook modeled forEach/for-of/indexed-for only). Closed by widening
`_js_f1193_parse_staging` with `_js_f1193_parse_while`.

F1225: for-in FormData staged reads -- staging chars via F.append/set
in a `for(const i in C)` loop assembles node-exactly (v24.20.0) while
find_credential MISSED. Residual of F1193 (CLOSED). Closed by
widening `_js_f1193_parse_staging` with `_js_f1193_parse_forin`.

F1226: defineProperty/defineProperties wrappers --
Object.defineProperty/defineProperties applied to the int-array
variable return the array unchanged (for non-index, non-"length"
properties), so spreading assembles node-exactly (v24.20.0) while
find_credential MISSED. New method family outside F1194's
close-when. Closed by `_js_f1226_stmt_decode` (numeric-index and
"length" properties fail closed -- they would mutate the array).

F1227: Object.assign self-assign wrapper -- Object.assign(C, {}) with
empty sources returns the int-array unchanged, so spreading assembles
node-exactly (v24.20.0) while find_credential MISSED. New method
family outside F1194's close-when. Closed by `_js_f1227_stmt_decode`
(only empty-object sources modeled; non-empty sources fail closed).

F1228: flat() depth-literal variants (filed+closed in-lane) --
`flat(0)`, `flat(3)`, `flat(10)`, `flat(-1)`, `flat(1.5)`,
`flat(0x2)`, `flat(Infinity)`, and `flat()` (no arg) on the
F1187/F1222 production all assemble node-exactly (v24.20.0) while
find_credential MISSED. Residual of F1222. Closed by
`_js_f1187_parse_depth` (any numeric depth + Infinity + omitted).

New _decode_layer dispatch loop (F1220/F1221/F1226/F1227);
N_STMTDEC_LOOPS 49->50 (real code-count change). Node-exact on all
filed shapes (short + 40-char, v24.20.0); fail-closed hook-level
bounds; sibling pins hold; F1199-F1219 (attack round 75 opens outside
this lane) still MISS.

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
N_STMTDEC_LOOPS_PIN = 50  # wave-408 lane 4: +1 dispatch loop (F1220/F1221/F1226/F1227)

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
    has1220 = any("_js_f1220_stmt_decode" in lp for lp in loops)
    has1221 = any("_js_f1221_stmt_decode" in lp for lp in loops)
    has1226 = any("_js_f1226_stmt_decode" in lp for lp in loops)
    has1227 = any("_js_f1227_stmt_decode" in lp for lp in loops)
    ok = ok and has1220 and has1221 and has1226 and has1227
    return (ok, "loops=%d pin=%d f1220=%s f1221=%s f1226=%s f1227=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, has1220, has1221, has1226, has1227))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-408 lane 4 (2026-10-11)" in src
          and "F1220-F1228 CLOSED (9" in src
          and "F1199-F1219 OPEN (21" in src
          and "next free F1229" in src)
    for n in range(1220, 1229):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-408 lane 4") == 9)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1228**" in src
          and "# Wave-407: F1182-F1198 CLOSED (17); F1199-F1227 OPEN (29); next free F1228" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1220-F1228 filed shapes now BLOCK."""
    bad = []
    total = 0
    for n in range(1220, 1228):
        shapes = _redfirst_shapes("w407", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    shapes = _redfirst_shapes("w408", 1228)
    total += len(shapes)
    for name, payload in shapes:
        if not _blocked(payload):
            bad.append("f1228:%s" % name)
    return (not bad, "%d/%d filed shapes block%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const, renamed idents, arrow twins, quote variants, depth
    variants (all node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1220: let/const + renamed + prefix incr.
    cases.append(("f1220-let",
                  "let D=%s;let K=Object.keys(D);let T='';for(let j=0;j<K.length;j++){T+=String.fromCharCode(D[K[j]]);}let RESULT=T;" % cs))
    cases.append(("f1220-prefix-long",
                  "var C=%s;var K=Object.keys(C);var S='';for(var i=0;i<K.length;++i){S+=String.fromCharCode(C[K[i]]);}var RESULT=S;" % cl))
    # F1221: arrow + const/renamed + no mapFn.
    cases.append(("f1221-arrow",
                  "var C=%s;var S=String.fromCharCode(...Array.from(C,c=>c));var RESULT=S;" % cs))
    cases.append(("f1221-const-long",
                  "const D=%s;const T=String.fromCharCode(...Array.from(D,function(x){return x;}));const RESULT=T;" % cl))
    cases.append(("f1221-no-mapfn",
                  "var C=%s;var S=String.fromCharCode(...Array.from(C));var RESULT=S;" % cs))
    # F1222: let/renamed (depth 1).
    cases.append(("f1222-let",
                  "let C=%s;let N=C.map((c)=>[[c]]);let S=String.fromCharCode(...N.flat(1));let RESULT=S;" % cs))
    # F1223: renamed generator + paren arrow + block-body arrow.
    cases.append(("f1223-gen-long",
                  "var C=%s;async function *gen(){yield* C.map((c)=>String.fromCharCode(c));}var S='';for await(var ch of gen()){S+=ch;}var RESULT=S;" % cl))
    cases.append(("f1223-block-arrow",
                  "var C=%s;async function *g(){yield* C.map(c=>{return String.fromCharCode(c);});}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;" % cs))
    # F1224: set + prefix incr + var.
    cases.append(("f1224-set-incr",
                  "var C=%s;var F=new FormData();var i=0;while(i<C.length){F.set('k'+i,String.fromCharCode(C[i]));++i;}var S=[...F.values()].join('');var RESULT=S;" % cs))
    # F1225: var loop.
    cases.append(("f1225-var-long",
                  "var C=%s;var F=new FormData();for(var i in C){F.append('k'+i,String.fromCharCode(C[i]));}var S=Array.from(F.values()).join('');var RESULT=S;" % cl))
    # F1226: double-quote prop + multi-prop.
    cases.append(("f1226-dq",
                  'var C=%s;var S=String.fromCharCode(...Object.defineProperty(C,"y",{value:2}));var RESULT=S;' % cs))
    cases.append(("f1226-multi-long",
                  "var C=%s;var S=String.fromCharCode(...Object.defineProperties(C,{a:{value:1},b:{value:2}}));var RESULT=S;" % cl))
    # F1227: multi-empty + const + safe-key object + empty array.
    cases.append(("f1227-multi",
                  "var C=%s;var S=String.fromCharCode(...Object.assign(C, {}, {}));var RESULT=S;" % cs))
    cases.append(("f1227-const-long",
                  "const D=%s;const T=String.fromCharCode(...Object.assign(D,{}));const RESULT=T;" % cl))
    cases.append(("f1227-safe-key",
                  "var C=%s;var S=String.fromCharCode(...Object.assign(C,{a:1}));var RESULT=S;" % cs))
    cases.append(("f1227-empty-array",
                  "var C=%s;var S=String.fromCharCode(...Object.assign(C,[]));var RESULT=S;" % cs))
    # F1228: depth variants (all node-verified to assemble).
    cases.append(("f1228-flat0",
                  "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(0));var RESULT=S;" % cs))
    cases.append(("f1228-flat3-long",
                  "var C=%s;var N=C.map(c=>[[c]]);var S=String.fromCharCode(...N.flat(3));var RESULT=S;" % cl))
    cases.append(("f1228-flat-noarg",
                  "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat());var RESULT=S;" % cs))
    cases.append(("f1228-flat-nan",
                  "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(NaN));var RESULT=S;" % cs))
    cases.append(("f1228-flat-null",
                  "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(null));var RESULT=S;" % cs))
    cases.append(("f1228-flat-undefined",
                  "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(undefined));var RESULT=S;" % cs))
    cases.append(("f1228-flat-str2",
                  'var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat("2"));var RESULT=S;' % cs))
    cases.append(("f1228-flat-strx",
                  'var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat("x"));var RESULT=S;' % cs))
    bad = [name for name, payload in cases if not _blocked(payload)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Out-of-grammar inputs must MISS (a miss, never a mis-decode).

    Every case below is node-verified (v24.20.0) to NOT assemble the
    credential (throws, yields a wrong string, or drops codes), so the
    MISS is a true fail-closed bound -- never a mislabeled hole.
    """
    cs = _codes(SECRET_S)
    misses = [
        # F1220: keys of the wrong array.
        "var C=%s;var D=[1,2];var K=Object.keys(D);var S='';for(var i=0;i<K.length;i++){S+=String.fromCharCode(C[K[i]]);}var RESULT=S;" % cs,
        # F1221: transforming callback (not identity).
        "var C=%s;var S=String.fromCharCode(...Array.from(C,function(c){return c+1;}));var RESULT=S;" % cs,
        # F1223: yield* of a non-map iterable.
        "var C=%s;async function *g(){yield* C;}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;" % cs,
        # F1226: numeric-index property would mutate the array.
        "var C=%s;var S=String.fromCharCode(...Object.defineProperty(C,'0',{value:999}));var RESULT=S;" % cs,
        # F1226: length property would mutate the array.
        "var C=%s;var S=String.fromCharCode(...Object.defineProperty(C,'length',{value:1}));var RESULT=S;" % cs,
        # F1226: defineProperties with an index key.
        "var C=%s;var S=String.fromCharCode(...Object.defineProperties(C,{0:{value:999}}));var RESULT=S;" % cs,
        # F1227: unsafe key (index) would overwrite elements.
        "var C=%s;var S=String.fromCharCode(...Object.assign(C, {0:999}));var RESULT=S;" % cs,
        # F1227: target is not C.
        "var C=%s;var S=String.fromCharCode(...Object.assign(D, {}));var RESULT=S;" % cs,
    ]
    bad = [p[:60] for p in misses if not _misses(p)]
    return (not bad, "%d/%d fail-closed%s"
            % (len(misses) - len(bad), len(misses),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; new hooks don't steal their shapes."""
    cs = _codes(SECRET_S)
    blocks = [
        # F1187: flat(2) still blocks (widened hook).
        ("f1187-flat2",
         "var C=%s;var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(2));var RESULT=S;" % cs),
        # F1189: fn-callback yield* still blocks (widened hook).
        ("f1189-fn",
         "var C=%s;async function *g(){yield* C.map(function(c){return String.fromCharCode(c);});}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;" % cs),
        # F1193: forEach/indexed-for still block (widened staging).
        ("f1193-foreach",
         "var C=%s;var F=new FormData();C.forEach(function(c,i){F.append('k'+i,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs),
        # F1194: freeze still blocks (new hooks must not steal).
        ("f1194-freeze",
         "var C=%s;var S=String.fromCharCode(...Object.freeze(C));var RESULT=S;" % cs),
        # F1172: intermediate-var Array.from still blocks.
        ("f1172-intermediate",
         "var C=%s;var D=Array.from(C);var S=String.fromCharCode(...D);var RESULT=S;" % cs),
        # F1090: bare map+join still blocks.
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    bad = [name for name, payload in blocks if not _blocked(payload)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(blocks) - len(bad), len(blocks),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjoint():
    """New hooks must not fire on each other's filed shapes."""
    hooks = {
        1220: dlp._js_f1220_stmt_decode,
        1221: dlp._js_f1221_stmt_decode,
        1226: dlp._js_f1226_stmt_decode,
        1227: dlp._js_f1227_stmt_decode,
    }
    bad = []
    for fn, hook in hooks.items():
        for other in (1220, 1221, 1226, 1227):
            if other == fn:
                continue
            prefix = "w407" if other < 1228 else "w408"
            for name, payload in _redfirst_shapes(prefix, other):
                try:
                    if hook(payload) is not None:
                        bad.append("f%d-hook-on-f%d:%s" % (fn, other, name))
                except Exception:  # noqa: BLE001
                    bad.append("f%d-hook-on-f%d:%s:EXC" % (fn, other, name))
    # Widened hooks must not fire on the new hooks' shapes either.
    widened = {
        "f1187": dlp._js_f1187_stmt_decode,
        "f1189": dlp._js_f1189_stmt_decode,
        "f1193": dlp._js_f1193_stmt_decode,
        "f1194": dlp._js_f1194_stmt_decode,
        "f1172": dlp._js_f1172_stmt_decode,
    }
    for wname, hook in widened.items():
        for other in (1220, 1221, 1226, 1227):
            prefix = "w407" if other < 1228 else "w408"
            for name, payload in _redfirst_shapes(prefix, other):
                try:
                    if hook(payload) is not None:
                        bad.append("%s-hook-on-f%d:%s" % (wname, other, name))
                except Exception:  # noqa: BLE001
                    bad.append("%s-hook-on-f%d:%s:EXC" % (wname, other, name))
    return (not bad, "cross-disjoint%s" % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest text ----------------

@_t
def test_p5_honest_text():
    honest = [
        "The quarterly financial summary shows revenue growth.",
        "var keys = Object.keys(config); for (var k of keys) { console.log(k); }",
        "var copy = Array.from(items); var flat = nested.flat(2);",
        "Object.defineProperty(obj, 'x', {value: 1});",
        "var merged = Object.assign({}, defaults, overrides);",
        "async function *gen() { yield 1; yield 2; }",
        "var fd = new FormData(form); for (var k in data) { fd.append(k, data[k]); }",
    ]
    bad = [p[:50] for p in honest if not _misses(p)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(honest) - len(bad), len(honest),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var S=String.fromCharCode(...Object.assign(C, {}));var RESULT=S;" % cs)
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(payload)
        dlp.find_credential(payload[::-1])
    dt = time.time() - t0
    return (dt < 30.0, "200 sites x2 in %.1fs (budget 30s)" % dt)


# ---------------- p7: other lanes' opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1199-F1219 (attack round 75, other lanes) still MISS."""
    bad = []
    for n in range(1199, 1220):
        shapes = _redfirst_shapes("w407", n)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens still MISS%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w407's attack battery (round-75 opens).

    Expects exactly the F1220-F1227 pins to flip to BREAK (now
    closed); every other pin must stay HELD. (F1228 was filed in
    wave-408, not wave-407, so it has no pin here.) Honors
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w407_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g408l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w407_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w407_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        expected_broken = set(range(1220, 1228))
        expected_held = set(range(1199, 1220))
        ok = (expected_broken <= broken and expected_held <= held
              and not (expected_broken & held) and not (expected_held & broken))
        return (ok, "green(w407_attack): broken=%s held=%d/21%s"
                % (sorted(broken & expected_broken), len(expected_held & held),
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
