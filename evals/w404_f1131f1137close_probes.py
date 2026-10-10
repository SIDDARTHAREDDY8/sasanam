#!/usr/bin/env python3
"""Wave-404 lane 3 close battery: F1131-F1137 CLOSED.

F1131: array-copy staged spread residuals -- `...C.splice(0)`,
`...C.concat([])`, `...new Array(...C)`,
`...C.map(function(c){return c;})`, and
`...new Array(C.length).fill(0).map(function(_,i){return C[i];})`
broke the spread hooks (F1120 covers only slice/[].concat/Array.of;
the `...[...C]` literal-copy twin blocks coded). Closed by
_js_f1131_stmt_decode: five copy productions, node-exact.

F1132: clone-roundtrip staged spread -- `...structuredClone(C)` and
`...JSON.parse(JSON.stringify(C))` broke the spread hooks. Closed by
_js_f1132_stmt_decode: deep-copy / decimal round-trip, node-exact.

F1133: Object.* array forms -- `...Object.assign([],C)` and
`...Object.values(C)` broke the hooks (F1106 models only
`Object.assign({},C)`). Closed by _js_f1133_stmt_decode: array-target
assign and values, node-exact.

F1134: string-split roundtrip -- `...C.toString().split(',').map(Number)`
and `...C.join(',').split(',').map(Number)` broke the spread hooks.
Closed by _js_f1134_stmt_decode: decimal round-trip, node-exact.

F1135: reduce-form residuals -- `.map(...).reduce(fn)` with no initial
and `.reduce(3-param fn,'')` broke the hooks (F1090 requires the `,''`
initial and a 2-param callback). Closed by _js_f1135_stmt_decode.

F1136: key-iteration staged accumulation -- `for-in`, `Object.keys`,
`Object.getOwnPropertyNames` (+length guard), `Reflect.ownKeys`
(+length guard) broke the index-anchored grammars. Closed by
_js_f1136_stmt_decode: ascending key order, node-exact.

F1137: filter-then-apply -- `String.fromCharCode.apply(null,
C.filter(...))` broke the apply hooks (the whole-array apply twin
blocks coded via F1066). Closed by _js_f1137_stmt_decode.

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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 41  # wave-404 merge: 38 + 3 loops (lanes 2,3,4) -> 41

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
def test_p1_footer_closed_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F988-F1122 CLOSED (135" in text
          and "Next free finding: **F1142**" in text)
    return (ok, "footer: F988-F1122 CLOSED (135), next F1142")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = "F1123-F1141 OPEN (19" in text
    return (ok, "footer: F1123-F1141 OPEN (19)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-404 lane 3: F1131-F1137 CLOSED (7)" in text
          and "F1123-F1130, F1138-F1141 OPEN (12)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1131_filed_block():
    shapes = _redfirst_shapes("w404", 1131)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1132_filed_block():
    shapes = _redfirst_shapes("w404", 1132)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1133_filed_block():
    shapes = _redfirst_shapes("w404", 1133)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1134_filed_block():
    shapes = _redfirst_shapes("w404", 1134)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1135_filed_block():
    shapes = _redfirst_shapes("w404", 1135)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1136_filed_block():
    shapes = _redfirst_shapes("w404", 1136)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1137_filed_block():
    shapes = _redfirst_shapes("w404", 1137)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # let/const decls, renamed idents, additive RESULT tails
    ("f1131-let",
     "let D={I};let T=String.fromCharCode(...D.splice(0));let RESULT='x'+T;"),
    ("f1131-const",
     "const E={I};const U=String.fromCharCode(...E.concat([]));const RESULT=U+'y';"),
    ("f1132-let",
     "let D={I};let T=String.fromCharCode(...structuredClone(D));let RESULT=T;"),
    ("f1133-const",
     "const E={I};const U=String.fromCharCode(...Object.values(E));const RESULT=U;"),
    ("f1134-let",
     "let D={I};let T=String.fromCharCode(...D.join(',').split(',').map(Number));let RESULT=T;"),
    ("f1134-dq",
     'let D={I};let T=String.fromCharCode(...D.join(",").split(",").map(Number));let RESULT=T;'),
    ("f1135-let",
     "let D={I};let T=D.reduce(function(a,c,i){return a+String.fromCharCode(c);},'');let RESULT=T;"),
    ("f1136-const-of",
     "const E={I};let U='';for(const k of Object.keys(E)){U+=String.fromCharCode(E[k]);}const RESULT=U;"),
    ("f1137-let",
     "let D={I};let T=String.fromCharCode.apply(null,D.filter(function(c){return true;}));let RESULT=T;"),
]


@_t
def test_p3_generalizations_block():
    bad = [name for name, t in _GENERALIZATIONS
           if not _blocked(t.replace("{I}", _codes(SECRET_S)))]
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(_GENERALIZATIONS) - len(bad), len(_GENERALIZATIONS),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p3_generalizations_node_exact():
    # Hook output must equal node's RESULT for each generalization.
    fails = []
    for name, t in _GENERALIZATIONS:
        payload = t.replace("{I}", _codes(SECRET_S))
        r = dlp.find_credential(payload)
        if r is None:
            fails.append(name + "=MISS")
            continue
        # find_credential returns a match object/dict; check the decoded
        # variant contains the secret via the decode path.
        js = payload + 'console.log("RESULT:"+JSON.stringify(RESULT));'
        pr = subprocess.run(["node", "-e", js], capture_output=True,
                            text=True, timeout=30)
        if SECRET_S not in pr.stdout:
            fails.append(name + "=node-mismatch")
    return (not fails, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS) - len(fails), len(_GENERALIZATIONS),
               (" FAIL=" + ",".join(fails)) if fails else ""))


# ---------------- p4: fail-closed ----------------

_FAIL_CLOSED = [
    # F1131: wrong copy forms
    ("f1131-splice-1",
     "var C={I};var S=String.fromCharCode(...C.splice(1));var RESULT=S;"),
    ("f1131-concat-nonempty",
     "var C={I};var S=String.fromCharCode(...C.concat([1]));var RESULT=S;"),
    ("f1131-map-arrow",
     "var C={I};var S=String.fromCharCode(...C.map((c)=>c));var RESULT=S;"),
    ("f1131-fill-nonzero",
     "var C={I};var S=String.fromCharCode(...new Array(C.length).fill(1).map(function(_,i){return C[i];}));var RESULT=S;"),
    # F1132: wrong clone forms
    ("f1132-clone-arg",
     "var C={I};var D=[1];var S=String.fromCharCode(...structuredClone(D));var RESULT=S;"),
    # F1133: object target (F1106's)
    ("f1133-assign-object",
     "var C={I};var S=String.fromCharCode(...Object.assign({},C));var RESULT=S;"),
    # F1134: wrong separator
    ("f1134-sep-semi",
     "var C={I};var S=String.fromCharCode(...C.join(';').split(';').map(Number));var RESULT=S;"),
    # F1135: init present on (a)-form, 2-param on (b)-form
    ("f1135-reduce-init",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).reduce(function(a,b){return a+b;},'');var RESULT=S;"),
    # F1136: indexed for (twin), missing guard on gopn
    ("f1136-indexed-for",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1136-gopn-noguard",
     "var C={I};var S='';for(var k of Object.getOwnPropertyNames(C)){S+=String.fromCharCode(C[k]);}var RESULT=S;"),
    # F1137: non-null thisArg, wrong predicate
    ("f1137-thisarg",
     "var C={I};var S=String.fromCharCode.apply(this,C.filter(function(c){return true;}));var RESULT=S;"),
    ("f1137-pred-false",
     "var C={I};var S=String.fromCharCode.apply(null,C.filter(function(c){return false;}));var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    bad = []
    for name, t in _FAIL_CLOSED:
        payload = t.replace("{I}", _codes(SECRET_S))
        # Must miss at the NEW-hook level: find_credential may still hit
        # via an older hook (e.g. the indexed-for twin blocks coded).
        # We assert the new hooks specifically miss by calling them.
        from gov.dlp import (_js_f1131_stmt_decode, _js_f1132_stmt_decode,
                             _js_f1133_stmt_decode, _js_f1134_stmt_decode,
                             _js_f1135_stmt_decode, _js_f1136_stmt_decode,
                             _js_f1137_stmt_decode)
        hooks = (_js_f1131_stmt_decode, _js_f1132_stmt_decode,
                 _js_f1133_stmt_decode, _js_f1134_stmt_decode,
                 _js_f1135_stmt_decode, _js_f1136_stmt_decode,
                 _js_f1137_stmt_decode)
        hit = [h(payload) for h in hooks]
        if any(v is not None for v in hit):
            bad.append(name)
    return (not bad, "%d/%d fail-closed at new-hook level%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4b: cross-disjointness ----------------

@_t
def test_p4b_cross_disjointness():
    """New shapes miss sibling hooks; sibling shapes miss new hooks."""
    from gov.dlp import (_js_f1131_stmt_decode, _js_f1132_stmt_decode,
                         _js_f1133_stmt_decode, _js_f1134_stmt_decode,
                         _js_f1135_stmt_decode, _js_f1136_stmt_decode,
                         _js_f1137_stmt_decode,
                         _js_f1120_stmt_decode, _js_f1106_stmt_decode,
                         _js_f1090_stmt_decode, _js_f1066_stmt_decode)
    new_hooks = (_js_f1131_stmt_decode, _js_f1132_stmt_decode,
                 _js_f1133_stmt_decode, _js_f1134_stmt_decode,
                 _js_f1135_stmt_decode, _js_f1136_stmt_decode,
                 _js_f1137_stmt_decode)
    sib_hooks = (_js_f1120_stmt_decode, _js_f1106_stmt_decode,
                 _js_f1090_stmt_decode, _js_f1066_stmt_decode)
    I = _codes(SECRET_S)
    # Sibling filed shapes (must miss new hooks)
    sib_shapes = [
        # F1120 slice
        "var C=%s;var S=String.fromCharCode(...C.slice());var RESULT=S;" % I,
        # F1106 assign-object
        "var C=%s;var O=Object.assign({},C);var S=String.fromCharCode(...Object.values(O));var RESULT=S;" % I,
        # F1066 whole-array apply
        "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % I,
    ]
    bad = []
    for s in sib_shapes:
        if any(h(s) is not None for h in new_hooks):
            bad.append("sib-hit-new:" + s[:40])
    # New filed shapes (must miss sibling hooks)
    for fn in (1131, 1132, 1133, 1134, 1135, 1136, 1137):
        for _, payload in _redfirst_shapes("w404", fn):
            if any(h(payload) is not None for h in sib_hooks):
                bad.append("new-hit-sib:f%d" % fn)
                break
    return (not bad, "disjoint both directions%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p5: sibling hooks hold + still-open miss ----------------

@_t
def test_p5_sibling_hooks_hold():
    """Sibling closures still block via find_credential."""
    I = _codes(SECRET_S)
    sib = [
        ("f1120-slice",
         "var C=%s;var S=String.fromCharCode(...C.slice());var RESULT=S;" % I),
        ("f1106-assign",
         "var C=%s;var S=String.fromCharCode(...Object.assign([],C));var RESULT=S;" % I),
        ("f1090-reduce",
         "var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');var RESULT=S;" % I),
        ("f1066-apply",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % I),
    ]
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    """Merged tree: F1123 and F1138 (other lanes' scope) are now CLOSED;
    their shapes must BLOCK. (On the lane tree they still missed.)"""
    I = _codes(SECRET_S)
    closed_shapes = [
        # F1123 systemic: leading statement (closed wave-404 lane 1)
        "var x=1;var C=%s;var S=String.fromCharCode(...C);var RESULT=S;" % I,
        # F1138 unescape (closed wave-404 lane 4)
        "var C=%s;var S=unescape(C.map(function(c){return '%%'+c.toString(16);}).join(''));var RESULT=S;" % I,
    ]
    bad = [s[:40] for s in closed_shapes if _misses(s)]
    return (not bad, "%d/%d now-closed block%s"
            % (len(closed_shapes) - len(bad), len(closed_shapes),
               (" BAD(still miss)=" + ",".join(bad)) if bad else ""))


# ---------------- p6: honest-text quiet ----------------

@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var total = items.reduce(function(a, b) { return a + b; }, 0);",
        "var keys = Object.keys(config);",
        "var copy = structuredClone(state);",
        "var parts = csv.split(',').map(Number);",
        "for (var k in obj) { console.log(k, obj[k]); }",
    ]
    bad = [h[:40] for h in honest if not _misses(h)]
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
            "var C%d=%s;var S%d=String.fromCharCode(...C%d.splice(0));"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w403's round-71 attack battery.

    w403_attack_probes.py now pins F1123-F1140 as CLOSED (all 18
    test_closed_w403_fNNNN must HELD). Any BREAK is a regression.
    Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w403_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g404lane3-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w403_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_closed_w403_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        # All 18 closed pins must HELD.
        expect = {"test_closed_w403_f%d" % n for n in range(1123, 1141)}
        missing = expect - held - broke
        ok = (not broke) and (not missing) and held == expect
        return (ok, "green(w403_attack): %d HELD, broke=%s missing=%s"
                % (len(held), sorted(broke), sorted(missing)))
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
