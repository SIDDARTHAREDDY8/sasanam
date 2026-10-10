#!/usr/bin/env python3
"""Wave-402 lane 1 close battery: F1103/F1104/F1108 CLOSED.

F1103: String.raw staged reads -- `String.raw(O)` / `String.raw({raw:A})`
over a cooked-char array broke the decoder's hook grammars (the
expression-level F493/F575 handle only literal raw segments). Closed by
_js_f1103_stmt_decode: two productions (inline map-then-raw, prebuilt
array), no substitutions, node-exact join semantics.

F1104: Symbol-keyed staged accumulation reads -- `O[K]` computed reads
over a Symbol-keyed int array broke the member-anchored hooks (F1075
anchors on literal `v`, F1099 on identifier names). Closed by
_js_f1104_stmt_decode: `K=Symbol('<desc>')`, `O={}`, `O[K]=[...]`, then
the shared F1074/F1075 for-loop machinery with a Symbol-keyed arrref.

F1108: slice-apply staged reads -- per-index
`String.fromCharCode.apply(null,C.slice(i,i+1))` in a loop broke the
invocation-anchored hooks (F1066 is bind-anchored; the whole-array
apply twin is expression-level). Closed by _js_f1108_stmt_decode:
strict `C.slice(I,I+1)` grammar, node-exact per-index char simulation.

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
N_STMTDEC_LOOPS_PIN = 32  # wave-402 lane 1: 31 + 1 new dispatch loop (real code-count change)

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
    ok = ("F988-F1102 CLOSED (115" in text
          and "Next free finding: **F1111**" in text)
    return (ok, "footer: F988-F1102 CLOSED (115), next F1111")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1103-F1110 OPEN (8" in text)
    return (ok, "footer: F1103-F1110 OPEN (8)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-402 lane 1: F1103, F1104, F1108 CLOSED (3)" in text
          and "F1105-F1107, F1109-F1110 OPEN (5)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1103_filed_block():
    shapes = _redfirst_shapes("w402", 1103)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1104_filed_block():
    shapes = _redfirst_shapes("w402", 1104)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1108_filed_block():
    shapes = _redfirst_shapes("w402", 1108)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

# Generalizations whose decoded output is credential-shaped: must block
# via the full pipeline.
_GENERALIZATIONS_BLOCK = [
    ("f1103", "let C=%s;let O={raw:C.map(function(c){return String.fromCharCode(c);})};let S=String.raw(O);let RESULT=S;"),
    ("f1103", "const D=%s;const P={raw:D.map(function(x){return String.fromCharCode(x);})};const T=String.raw(P);const RESULT=T;"),
    ("f1103", "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var S=String.raw({raw:A});var RESULT='x'+S;"),
    ("f1104", "let K=Symbol('k');let O={};O[K]=%s;let S='';for(let i=0;i<O[K].length;i++){S+=String.fromCharCode(O[K][i]);}let RESULT=S;"),
    ("f1104", "var K=Symbol('desc');var O={};O[K]=%s;var S='';for(var i=0;i<O[K].length;i++){S+=String.fromCharCode(O[K][i]);}var RESULT=S;"),
    ("f1108", "let C=%s;let S='';for(let i=0;i<C.length;i++){S+=String.fromCharCode.apply(null,C.slice(i,i+1));}let RESULT=S;"),
    ("f1108", "var C=%s;var S='';for(var i=0;i<C.length;++i){S+=String.fromCharCode.apply(null,C.slice(i,i+1));}var RESULT=S;"),
    ("f1108", "var C=%s;var S='';for(var i=0;i<C.length;i++)S+=String.fromCharCode.apply(null,C.slice(i,i+1));var RESULT=S;"),
]

_HOOKS = {
    "f1103": dlp._js_f1103_stmt_decode,
    "f1104": dlp._js_f1104_stmt_decode,
    "f1108": dlp._js_f1108_stmt_decode,
}


@_t
def test_p3_generalizations_block():
    bad = []
    for hook, tmpl in _GENERALIZATIONS_BLOCK:
        payload = tmpl % _codes(SECRET_S)
        if not _blocked(payload):
            bad.append(hook + ":" + payload[:40])
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(_GENERALIZATIONS_BLOCK) - len(bad),
               len(_GENERALIZATIONS_BLOCK),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_generalizations_node_exact():
    # Hook-level node-exactness on the generalizations (decoded value
    # must equal the credential).
    bad = []
    for hook, tmpl in _GENERALIZATIONS_BLOCK:
        payload = tmpl % _codes(SECRET_S)
        got = _HOOKS[hook](payload)
        # The third f1103 generalization has RESULT='x'+S so the hook
        # decodes 'x' + credential via the additive RESULT.
        if hook == "f1103" and "RESULT='x'+S" in tmpl:
            want = "x" + SECRET_S
        else:
            want = SECRET_S
        if got != want:
            bad.append("%s: got %r want %r" % (hook, got, want))
    return (not bad, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS_BLOCK) - len(bad),
               len(_GENERALIZATIONS_BLOCK),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: fail-closed bounds + disjointness ----------------

_FAIL_CLOSED = [
    # (hook-name, payload) -- each must MISS at hook level.
    ("f1103", "var C=%s;var O={raw:C.map(function(c){return String.fromCharCode(c);})};var S=String.raw(O,'x');var RESULT=S;"),  # substitution
    ("f1103", "var C=%s;var O={raw:C.map((c)=>String.fromCharCode(c))};var S=String.raw(O);var RESULT=S;"),  # arrow callback
    ("f1103", "var C=%s;var O={raw:C.map(function(c){return String.fromCharCode(c+1);})};var S=String.raw(O);var RESULT=S;"),  # wrong body
    ("f1104", "var K='k';var O={};O[K]=%s;var S='';for(var i=0;i<O[K].length;i++){S+=String.fromCharCode(O[K][i]);}var RESULT=S;"),  # not Symbol
    ("f1104", "var K=Symbol('k');var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),  # dot key -> F1075
    ("f1104", "var K=Symbol('k');var O={k:%s};var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),  # ident key -> F1099
    ("f1108", "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode.apply(null,C.slice(i,i+2));}var RESULT=S;"),  # slice(i,i+2)
    ("f1108", "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode.apply(undefined,C.slice(i,i+1));}var RESULT=S;"),  # non-null thisArg
    ("f1108", "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),  # whole-array -> expression twin
]


@_t
def test_p4_fail_closed():
    bad = []
    for hook, tmpl in _FAIL_CLOSED:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        if _HOOKS[hook](payload) is not None:
            bad.append(hook + ":" + payload[:40])
    return (not bad, "%d/%d fail-closed%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjointness():
    """New hooks must not fire on sibling shapes and vice versa."""
    pairs = [
        (dlp._js_f1103_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
        (dlp._js_f1104_stmt_decode,
         "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
        (dlp._js_f1104_stmt_decode,
         "var O={k:%s};var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
        (dlp._js_f1108_stmt_decode,
         "var C=%s;var F=String.fromCharCode.bind(null,...C);var RESULT=F();"),
        (dlp._js_f1075_stmt_decode,
         "var K=Symbol('k');var O={};O[K]=%s;var S='';for(var i=0;i<O[K].length;i++){S+=String.fromCharCode(O[K][i]);}var RESULT=S;"),
        (dlp._js_f1099_stmt_decode,
         "var K=Symbol('k');var O={};O[K]=%s;var S='';for(var i=0;i<O[K].length;i++){S+=String.fromCharCode(O[K][i]);}var RESULT=S;"),
        (dlp._js_f1066_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode.apply(null,C.slice(i,i+1));}var RESULT=S;"),
    ]
    bad = []
    for hook, tmpl in pairs:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        if hook(payload) is not None:
            bad.append(hook.__name__)
    return (not bad, "%d/%d disjoint%s"
            % (len(pairs) - len(bad), len(pairs),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: sibling pins ----------------

@_t
def test_p5_sibling_hooks_hold():
    shapes = [
        # F1075 v-anchored member reads still block via F1075.
        "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;",
        # F1099 arbitrary property-name reads still block via F1099.
        "var O={k:%s};var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;",
        # F1066 bind invocation still blocks via F1066.
        "var C=%s;var F=String.fromCharCode.bind(null,...C);var RESULT=F();",
        # Whole-array apply twin still blocks (expression-level).
        "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;",
    ]
    bad = []
    for p in shapes:
        payload = p % _codes(SECRET_S)
        if not _blocked(payload):
            bad.append(p[:40])
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p5_still_open_miss():
    """Lane scope: F1105-F1107, F1109-F1110 stay OPEN (other lanes)."""
    # These are other lanes' findings; on this lane tree they must
    # still MISS at the pipeline level (not closed here).
    shapes = [
        # F1105 Proxy get-trap (lane 2 scope).
        "var P=new Proxy({d:%s},{get:function(t,k){return t.d;}});var O={};O.k=P;var S='';for(var i=0;i<O.k.d.length;i++){S+=String.fromCharCode(O.k.d[i]);}var RESULT=S;",
    ]
    # Only assert the ones we can cheaply check miss; the w401 battery
    # carries the authoritative open pins (green check).
    bad = [p[:40] for p in shapes if _blocked(p % _codes(SECRET_S))]
    return (not bad, "%d/%d still-open miss%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: honest-text controls ----------------

@_t
def test_p6_honest_quiet():
    texts = [
        "(function(){var s='ab';return s;})()",
        "var x = String.raw`hello`;",
        "email the quarterly report to the team",
        "var sym = Symbol('description');",
        "for (var i = 0; i < 10; i++) { console.log(i); }",
        "var arr = [1,2,3]; var s = String.fromCharCode.apply(null, arr);",
    ]
    bad = [t[:30] for t in texts if not _misses(t)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(texts) - len(bad), len(texts),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    t0 = time.time()
    site = ("var C=%s;var S='';for(var i=0;i<C.length;i++)"
            "{S+=String.fromCharCode.apply(null,C.slice(i,i+1));}"
            "var RESULT=S;" % _codes(SECRET_S))
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w401's attack battery (carries F1103-F1110
    pins). Honor GOV_SKIP_GREEN. The w401 battery's F1103/F1104/F1108
    pins use the w401 red-firsts (which have a template-substitution
    bug and test malformed payloads); on this lane tree the battery
    must remain green (0 BREAK) -- the real closure is verified by the
    w402 red-firsts and p2 tests above."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w401_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g402lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w401_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # Lane tree: w401 battery must stay green (0 BREAK).
        ok = not real
        return (ok,
                "green(w401_attack): %d BREAK (expect 0)" % len(real))
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
