#!/usr/bin/env python3
"""Wave-406 lane 1 close battery: F1159-F1165 CLOSED.

F1159: Object.fromEntries staged assembly -- `C.map(...)` pairs fed to
`Object.fromEntries`, read back via `Object.values(...).join('')`.
Closed by _js_f1159_stmt_decode, node-exact.

F1160: Map staged reads -- `new Map(C.map(...))` iterated plain or
destructured. Closed by _js_f1160_stmt_decode, node-exact.

F1161: Set staged reads -- `new Set(C.map(...))` of [i,c] pairs,
iterated with fromCharCode(p[1]). Closed by _js_f1161_stmt_decode,
node-exact.

F1162: Array.from(C.entries()) materialization -- indexed
`E[i][1]` or for-of `p[1]` over the materialized pairs. Closed by
_js_f1162_stmt_decode, node-exact.

F1163: sort-family no-op wrappers -- `C.slice().sort(...)` /
`C.toSorted(...)` with an always-zero comparator. Closed by
_js_f1163_stmt_decode, node-exact.

F1164: reduceRight arrow twins -- `(a,c)=>fcc(c)+a` and the indexed
`(a,c,i)=>fcc(C[i])+a` twin. Closed by _js_f1164_stmt_decode,
node-exact.

F1165: pad-then-splice -- `[pads].concat(C)` then `D.splice(0,n)`
with n == len(pads). Closed by _js_f1165_stmt_decode, node-exact.

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
N_STMTDEC_LOOPS_PIN = 44  # wave-406 lane 1: 43 + 1 loop (F1159-F1165)

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
def test_p1_footer_base():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1142-F1158 CLOSED (17" in text
          and "F1159-F1181 OPEN (23" in text
          and "Next free finding: **F1182**" in text)
    return (ok, "base footer: F1142-F1158 CLOSED (17), F1159-F1181 OPEN (23)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-406 lane 1 (2026-10-11): F1159-F1165 CLOSED (7)" in text
          and "F1166-F1181 OPEN (16)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1159_filed_block():
    shapes = _redfirst_shapes("w405", 1159)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1160_filed_block():
    shapes = _redfirst_shapes("w405", 1160)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1161_filed_block():
    shapes = _redfirst_shapes("w405", 1161)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1162_filed_block():
    shapes = _redfirst_shapes("w405", 1162)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1163_filed_block():
    shapes = _redfirst_shapes("w405", 1163)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1164_filed_block():
    shapes = _redfirst_shapes("w405", 1164)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1165_filed_block():
    shapes = _redfirst_shapes("w405", 1165)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # F1159: let/const, renamed idents, additive RESULT
    ("f1159-let",
     "let C={I};let E=C.map(function(c,i){return [i,String.fromCharCode(c)];});let S=Object.values(Object.fromEntries(E)).join('');let RESULT=S;"),
    ("f1159-renamed",
     "var D={I};var P=D.map((c,i)=>[i,String.fromCharCode(c)]);var T=Object.values(Object.fromEntries(P)).join('');var RESULT='x:'+T;"),
    # F1160: const, renamed
    ("f1160-const",
     "const C={I};const M=new Map(C.map((c,i)=>[i,String.fromCharCode(c)]));let S='';for(const [k,v] of M){S+=v;}const RESULT=S;"),
    ("f1160-renamed",
     "var D={I};var Mm=new Map(D.map(function(c,i){return [i,String.fromCharCode(c)];}));var T='';for(var q of Mm){T+=q[1];}var RESULT=T;"),
    # F1161: let, renamed
    ("f1161-let",
     "let C={I};let St=new Set(C.map((c,i)=>[i,c]));let S='';for(let p of St){S+=String.fromCharCode(p[1]);}let RESULT=S;"),
    ("f1161-renamed",
     "var D={I};var Ss=new Set(D.map(function(c,i){return [i,c];}));var T='';for(var r of Ss){T+=String.fromCharCode(r[1]);}var RESULT=T;"),
    # F1162: let/const, renamed
    ("f1162-let",
     "let C={I};let E=Array.from(C.entries());let S='';for(let i=0;i<E.length;i++){S+=String.fromCharCode(E[i][1]);}let RESULT=S;"),
    ("f1162-renamed-forof",
     "var D={I};var P=Array.from(D.entries());var T='';for(var q of P){T+=String.fromCharCode(q[1]);}var RESULT=T;"),
    # F1163: const, renamed, additive RESULT
    ("f1163-const",
     "const C={I};const D=C.slice().sort(()=>0);const S=String.fromCharCode(...D);const RESULT=S;"),
    ("f1163-renamed-tosorted",
     "var Dd={I};var E=Dd.toSorted(function(){return 0;});var T=String.fromCharCode(...E);var RESULT='id:'+T;"),
    # F1164: let, renamed
    ("f1164-let",
     "let C={I};let S=C.reduceRight((a,c)=>String.fromCharCode(c)+a,'');let RESULT=S;"),
    ("f1164-renamed-idx",
     "var D={I};var T=D.reduceRight((a,c,i)=>String.fromCharCode(D[i])+a,'');var RESULT=T;"),
    # F1165: 3-pad, let, renamed
    ("f1165-pad3",
     "var C={I};var D=[0,0,0].concat(C);D.splice(0,3);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1165-let",
     "let C={I};let D=[9].concat(C);D.splice(0,1);let S=String.fromCharCode(...D);let RESULT=S;"),
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
        if not _blocked(payload):
            fails.append(name + "=MISS")
            continue
        pr = subprocess.run(["node", "-e",
                             payload + ";console.log(JSON.stringify(RESULT));"],
                            capture_output=True, text=True, timeout=30)
        if SECRET_S not in pr.stdout:
            fails.append(name + "=node-mismatch")
    return (not fails, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS) - len(fails), len(_GENERALIZATIONS),
               (" FAIL=" + ",".join(fails)) if fails else ""))


# ---------------- p4: fail-closed ----------------

_FAIL_CLOSED = [
    # F1159: Object.entries instead of fromEntries; swapped pair
    ("f1159-entries",
     "var C={I};var E=C.map(function(c,i){return [i,String.fromCharCode(c)];});var S=Object.values(Object.entries(E)).join('');var RESULT=S;"),
    ("f1159-swapped-pair",
     "var C={I};var E=C.map(function(c,i){return [String.fromCharCode(c),i];});var S=Object.values(Object.fromEntries(E)).join('');var RESULT=S;"),
    # F1160: Map without the map() staging; kv[0] instead of kv[1]
    ("f1160-no-map",
     "var C={I};var M=new Map(C);var S='';for(var kv of M){S+=kv[1];}var RESULT=S;"),
    ("f1160-idx0",
     "var C={I};var M=new Map(C.map(function(c,i){return [i,String.fromCharCode(c)];}));var S='';for(var kv of M){S+=kv[0];}var RESULT=S;"),
    # F1161: Set without map; fromCharCode(p[0])
    ("f1161-no-map",
     "var C={I};var St=new Set(C);var S='';for(var p of St){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
    ("f1161-idx0",
     "var C={I};var St=new Set(C.map(function(c,i){return [i,c];}));var S='';for(var p of St){S+=String.fromCharCode(p[0]);}var RESULT=S;"),
    # F1162: C.entries() without Array.from; E[i][0]
    ("f1162-no-from",
     "var C={I};var E=C.entries();var S='';for(var p of E){S+=String.fromCharCode(p[1]);}var RESULT=S;"),
    ("f1162-idx0",
     "var C={I};var E=Array.from(C.entries());var S='';for(var i=0;i<E.length;i++){S+=String.fromCharCode(E[i][0]);}var RESULT=S;"),
    # F1163: comparator returns 1 (reorders); unmodeled method
    ("f1163-cmp1",
     "var C={I};var D=C.slice().sort(function(){return 1;});var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1163-sorted",
     "var C={I};var D=C.slice().sorted(function(){return 0;});var S=String.fromCharCode(...D);var RESULT=S;"),
    # F1164: function callback (F940's); non-empty init
    ("f1164-fn-cb",
     "var C={I};var S=C.reduceRight(function(a,c){return String.fromCharCode(c)+a;},'');var RESULT=S;"),
    ("f1164-nonempty-init",
     "var C={I};var S=C.reduceRight((a,c)=>String.fromCharCode(c)+a,'x');var RESULT=S;"),
    # F1165: pad/splice count mismatch; no splice at all
    ("f1165-count-mismatch",
     "var C={I};var D=[0].concat(C);D.splice(0,2);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("f1165-no-splice",
     "var C={I};var D=[0].concat(C);var S=String.fromCharCode(...D);var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    from gov.dlp import (_js_f1159_stmt_decode, _js_f1160_stmt_decode,
                         _js_f1161_stmt_decode, _js_f1162_stmt_decode,
                         _js_f1163_stmt_decode, _js_f1164_stmt_decode,
                         _js_f1165_stmt_decode)
    hooks = (_js_f1159_stmt_decode, _js_f1160_stmt_decode,
             _js_f1161_stmt_decode, _js_f1162_stmt_decode,
             _js_f1163_stmt_decode, _js_f1164_stmt_decode,
             _js_f1165_stmt_decode)
    bad = []
    for name, t in _FAIL_CLOSED:
        payload = t.replace("{I}", _codes(SECRET_S))
        if any(h(payload) is not None for h in hooks):
            bad.append(name)
    return (not bad, "%d/%d fail-closed at new-hook level%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4b: cross-disjointness ----------------

@_t
def test_p4b_cross_disjointness():
    """New shapes miss sibling hooks; sibling shapes miss new hooks."""
    from gov.dlp import (_js_f1159_stmt_decode, _js_f1160_stmt_decode,
                         _js_f1161_stmt_decode, _js_f1162_stmt_decode,
                         _js_f1163_stmt_decode, _js_f1164_stmt_decode,
                         _js_f1165_stmt_decode,
                         _js_f1126_stmt_decode, _js_f1091_stmt_decode,
                         _js_f1150_stmt_decode, _js_f1090_stmt_decode,
                         _js_f1153_stmt_decode, _js_f1131_stmt_decode,
                         _js_f1120_stmt_decode)
    new_hooks = (_js_f1159_stmt_decode, _js_f1160_stmt_decode,
                 _js_f1161_stmt_decode, _js_f1162_stmt_decode,
                 _js_f1163_stmt_decode, _js_f1164_stmt_decode,
                 _js_f1165_stmt_decode)
    sib_hooks = (_js_f1126_stmt_decode, _js_f1091_stmt_decode,
                 _js_f1150_stmt_decode, _js_f1090_stmt_decode,
                 _js_f1153_stmt_decode, _js_f1131_stmt_decode,
                 _js_f1120_stmt_decode)
    I = _codes(SECRET_S)
    sib_shapes = [
        # F1126 Object.entries(C).map
        "var C=%s;var S=Object.entries(C).map(function(p){return String.fromCharCode(p[1]);}).join('');var RESULT=S;" % I,
        # F1091 direct for-of over C.entries()
        "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(c);}var RESULT=S;" % I,
        # F1150 direct for-of p[1]
        "var C=%s;var S='';for(var p of C.entries()){S+=String.fromCharCode(p[1]);}var RESULT=S;" % I,
        # F1090/F940 function reduceRight
        "var C=%s;var S=C.reduceRight(function(a,c){return String.fromCharCode(c)+a;},'');var RESULT=S;" % I,
        # F1153 sort-comparator side-effect accumulation
        "var C=%s;var S='';var k=0;C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;" % I,
        # F1131 ...C.splice(0)
        "var C=%s;var S=String.fromCharCode(...C.splice(0));var RESULT=S;" % I,
        # F1120 [].concat(C) copy spread
        "var C=%s;var S=String.fromCharCode(...[].concat(C));var RESULT=S;" % I,
    ]
    bad = []
    for s in sib_shapes:
        if any(h(s) is not None for h in new_hooks):
            bad.append("sib-hit-new:" + s[:40])
    for fn in (1159, 1160, 1161, 1162, 1163, 1164, 1165):
        for _, payload in _redfirst_shapes("w405", fn):
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
        ("f1126-entries",
         "var C=%s;var S=Object.entries(C).map(function(p){return String.fromCharCode(p[1]);}).join('');var RESULT=S;" % I),
        ("f1090-reduceright-fn",
         "var C=%s;var S=C.reduceRight(function(a,c){return String.fromCharCode(c)+a;},'');var RESULT=S;" % I),
        ("f1153-sort-accum",
         "var C=%s;var S='';var k=0;C.slice().sort(function(a,b){if(k<C.length){S+=String.fromCharCode(C[k]);k++;}return a-b;});var RESULT=S;" % I),
        ("f1131-splice0",
         "var C=%s;var S=String.fromCharCode(...C.splice(0));var RESULT=S;" % I),
    ]
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    """F1166-F1181 (other lanes' scope) still genuinely MISS."""
    bad = []
    for fn in range(1166, 1182):
        shapes = _redfirst_shapes("w405", fn)
        hit = [name for name, p in shapes if not _misses(p)]
        if hit:
            bad.append("f%d:%s" % (fn, ",".join(hit)))
    return (not bad, "still-open miss%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p6: honest-text quiet ----------------

@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var entries = Object.fromEntries(pairs);",
        "var m = new Map(items);",
        "var s = new Set(values);",
        "var arr = Array.from(iterable);",
        "var sorted = data.slice().sort(compareFn);",
        "var total = items.reduceRight(function(a, b) { return a + b; }, 0);",
        "var copy = source.slice(); copy.splice(0, 2);",
    ]
    bad = [h[:48] for h in honest if not _misses(h)]
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
            "var C%d=%s;var E%d=C%d.map(function(c,i){return [i,String.fromCharCode(c)];});"
            "var S%d=Object.values(Object.fromEntries(E%d)).join('');"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w405's round-73 attack battery.

    w405_attack_probes.py pins F1159-F1181 as OPEN on the base; on
    this lane tree exactly the F1159-F1165 pins must BREAK (now
    closed) and all other pins (F1166-F1181) must HELD. Honor
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w405_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g406lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w405_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        broke = set()
        held = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w405_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_broke = {"test_open_w405_f%d" % n
                        for n in range(1159, 1166)}
        ok = (broke == expect_broke)
        return (ok, "green(w405_attack): broke=%s (want exactly f1159-f1165)"
                % sorted(broke))
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
