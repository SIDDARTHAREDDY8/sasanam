#!/usr/bin/env python3
"""Wave-407 lane 1 close battery: F1182-F1186 CLOSED.

F1182: Object.create staged assembly -- chars assigned into a
null-prototype object via indexed assignment, read back with
Object.values(O).join(''). Closed by _js_f1182_stmt_decode,
node-exact.

F1183: WeakMap staged reads -- chars staged through a WeakMap keyed
by fresh objects (set/get roundtrip), then joined. Twins: `(k)=>`
parenthesized arrows, paren-less `new WeakMap`. Closed by
_js_f1183_stmt_decode, node-exact.

F1184: String.match/matchAll staged assembly -- segmenting the
assembled char string with match(/./gs) or matchAll(/./g or /./gs) and
rejoining. Closed by _js_f1184_stmt_decode, node-exact.

F1185: RegExp exec staged reads -- consuming the assembled char
string with a sticky (/y) or global (/g) regex exec loop. Closed by
_js_f1185_stmt_decode, node-exact.

F1186: String.raw staged reads -- interleaving mapped chars as
substitutions into String.raw({raw: empty template}). Closed by
_js_f1186_stmt_decode, node-exact.

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
RECOMPILE_PIN = 29  # wave-407 merged: lane 3 added _JS_WS_COMPACT_RE
N_STMTDEC_LOOPS_PIN = 49  # wave-407 merged: 46 + 3 (lanes 1+2+3)

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
SECRET_NL = "xoxb-01" + "23\n456789abcdef"  # contains \n for dotall tests


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# ---------------- p3b: stretch shapes (spec-review recs) ----------------

# Spec-review stretch shapes, all node-verified (v24.20.0):
# - F1183: parenthesized arrows `(k)=>` on set/get + paren-less `new WeakMap`
# - F1184: matchAll with the `/./gs` twin (s flag => `.` matches LineTerminators)
_STRETCH = [
    ("f1183-paren-arrow-no-paren-new",
     "var C={I};var M=new WeakMap;var K=C.map((c)=>({v:c}));K.forEach((k)=>M.set(k,String.fromCharCode(k.v)));var S=K.map((k)=>M.get(k)).join('');var RESULT=S;"),
    ("f1183-paren-arrow-only",
     "var C={I};var M=new WeakMap();var K=C.map((c)=>({v:c}));K.forEach((k)=>M.set(k,String.fromCharCode(k.v)));var S=K.map((k)=>M.get(k)).join('');var RESULT=S;"),
    ("f1184-matchall-gs",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=Array.from(T.matchAll(/./gs),function(m){return m[0];}).join('');var RESULT=S;"),
]


@_t
def test_p3b_stretch_shapes_block_node_exact():
    bad = []
    for name, t in _STRETCH:
        payload = t.replace("{I}", _codes(SECRET_S))
        if not _blocked(payload):
            bad.append(name + "=MISS")
            continue
        pr = subprocess.run(["node", "-e",
                             payload + ";console.log(JSON.stringify(RESULT));"],
                            capture_output=True, text=True, timeout=30)
        if SECRET_S not in pr.stdout:
            bad.append(name + "=node-mismatch")
    return (not bad, "%d/%d stretch shapes blocked+node-exact%s"
            % (len(_STRETCH) - len(bad), len(_STRETCH),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p4c_dotall_guard():
    # `/./` without the s flag: node SKIPS LineTerminators (\n \r U+2028
    # U+2029), so the F1184 matchAll (/g) and F1185 exec (/g) decoders must
    # fail closed (miss) rather than mis-decode. Node-verified (v24.20.0):
    # node RESULT != SECRET_NL for both forms.
    from gov.dlp import _js_f1184_stmt_decode, _js_f1185_stmt_decode
    nl = _codes(SECRET_NL)
    matchall = ("var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
                "var S=Array.from(T.matchAll(/./g),function(m){return m[0];}).join('');"
                "var RESULT=S;" % nl)
    execg = ("var C=%s;var R=/./g;var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
             "var S='';var M;while((M=R.exec(T))!==null){S+=M[0];}var RESULT=S;" % nl)
    miss_ok = (_js_f1184_stmt_decode(matchall) is None
               and _js_f1185_stmt_decode(execg) is None)
    # node agrees the miss is correct: RESULT skips the \n
    node_ok = True
    for payload in (matchall, execg):
        pr = subprocess.run(["node", "-e",
                             payload + ";console.log(JSON.stringify(RESULT));"],
                            capture_output=True, text=True, timeout=30)
        if SECRET_NL in pr.stdout or pr.returncode != 0:
            node_ok = False
    ok = miss_ok and node_ok
    return (ok, "dotall guard: hooks miss=%s node-agrees=%s" % (miss_ok, node_ok))


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
    ok = ("F1159-F1181 CLOSED (23" in text
          and "F1182-F1198 OPEN (17" in text
          and "Next free finding: **F1199**" in text)
    return (ok, "base footer: F1159-F1181 CLOSED (23), F1182-F1198 OPEN (17)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-407 lane 1 (2026-10-11): F1182-F1186 CLOSED (5)" in text
          and "F1187-F1198 OPEN (12)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1182_filed_block():
    shapes = _redfirst_shapes("w406", 1182)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1183_filed_block():
    shapes = _redfirst_shapes("w406", 1183)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1184_filed_block():
    shapes = _redfirst_shapes("w406", 1184)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1185_filed_block():
    shapes = _redfirst_shapes("w406", 1185)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1186_filed_block():
    shapes = _redfirst_shapes("w406", 1186)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    # F1182: let/const, renamed vars
    ("f1182-letconst",
     "let C={I};const O=Object.create(null);C.forEach(function(c,i){O[i]=String.fromCharCode(c);});let S=Object.values(O).join('');const RESULT=S;"),
    ("f1182-renamed",
     "var A={I};var X=Object.create(null);A.forEach(function(ch,ix){X[ix]=String.fromCharCode(ch);});var T=Object.values(X).join('');var RESULT='id:'+T;"),
    # F1183: let/const, renamed
    ("f1183-letconst",
     "let C={I};const M=new WeakMap();var K=C.map(c=>({v:c}));K.forEach(k=>M.set(k,String.fromCharCode(k.v)));let S=K.map(k=>M.get(k)).join('');const RESULT=S;"),
    ("f1183-renamed",
     "var A={I};var W=new WeakMap();var P=A.map(function(x){return {v:x};});P.forEach(function(y){W.set(y,String.fromCharCode(y.v));});var T=P.map(function(y){return W.get(y);}).join('');var RESULT=T;"),
    # F1184: let/const, matchAll arrow-free variant stays function form
    ("f1184-letconst",
     "const C={I};let T=C.map(c=>String.fromCharCode(c)).join('');var S=T.match(/./gs).join('');let RESULT=S;"),
    ("f1184-renamed",
     "var A={I};var U=A.map(function(x){return String.fromCharCode(x);}).join('');var V=Array.from(U.matchAll(/./g),function(m){return m[0];}).join('');var RESULT=V;"),
    # F1185: let/const, renamed, sticky flag
    ("f1185-letconst",
     "let C={I};const R=/./g;var T=C.map(c=>String.fromCharCode(c)).join('');let S='';var M;while((M=R.exec(T))!==null){S+=M[0];}const RESULT=S;"),
    ("f1185-renamed-sticky",
     "var A={I};var Rx=/./gy;var U=A.map(function(x){return String.fromCharCode(x);}).join('');var V='';var N;while((N=Rx.exec(U))!==null){V+=N[0];}var RESULT=V;"),
    # F1186: let/const, renamed
    ("f1186-letconst",
     "const C={I};let H=C.map(c=>String.fromCharCode(c));var S=String.raw({raw:new Array(H.length+1).fill('')},...H);let RESULT=S;"),
    ("f1186-renamed",
     "var A={I};var B=A.map(function(x){return String.fromCharCode(x);});var T=String.raw({raw:new Array(B.length+1).fill('')},...B);var RESULT='x:'+T;"),
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
    # F1182: non-null proto; wrong fcc arg
    ("f1182-nonnull-proto",
     "var C={I};var O=Object.create({});C.forEach(function(c,i){O[i]=String.fromCharCode(c);});var S=Object.values(O).join('');var RESULT=S;"),
    ("f1182-wrong-fcc",
     "var C={I};var O=Object.create(null);C.forEach(function(c,i){O[i]=String.fromCharCode(c+1);});var S=Object.values(O).join('');var RESULT=S;"),
    # F1183: plain Map instead of WeakMap; get on wrong name
    ("f1183-plain-map",
     "var C={I};var M=new Map();var K=C.map(function(c){return {v:c};});K.forEach(function(k){M.set(k,String.fromCharCode(k.v));});var S=K.map(function(k){return M.get(k);}).join('');var RESULT=S;"),
    ("f1183-wrong-field",
     "var C={I};var M=new WeakMap();var K=C.map(function(c){return {w:c};});K.forEach(function(k){M.set(k,String.fromCharCode(k.v));});var S=K.map(function(k){return M.get(k);}).join('');var RESULT=S;"),
    # F1184: /../ instead of /./; split instead of match
    ("f1184-double-dot",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=T.match(/../gs).join('');var RESULT=S;"),
    ("f1184-split",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=T.split('').join('');var RESULT=S;"),
    # F1185: no flag; wrong loop var
    ("f1185-no-flag",
     "var C={I};var R=/./;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S='';var M;while((M=R.exec(T))!==null){S+=M[0];}var RESULT=S;"),
    ("f1185-wrong-acc",
     "var C={I};var R=/./g;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S='';var M;while((M=R.exec(T))!==null){T+=M[0];}var RESULT=S;"),
    # F1186: wrong raw length; non-empty fill
    ("f1186-wrong-len",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=String.raw({raw:new Array(H.length).fill('')},...H);var RESULT=S;"),
    ("f1186-nonempty-fill",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=String.raw({raw:new Array(H.length+1).fill('x')},...H);var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    from gov.dlp import (_js_f1182_stmt_decode, _js_f1183_stmt_decode,
                         _js_f1184_stmt_decode, _js_f1185_stmt_decode,
                         _js_f1186_stmt_decode)
    hooks = (_js_f1182_stmt_decode, _js_f1183_stmt_decode,
             _js_f1184_stmt_decode, _js_f1185_stmt_decode,
             _js_f1186_stmt_decode)
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
    from gov.dlp import (_js_f1182_stmt_decode, _js_f1183_stmt_decode,
                         _js_f1184_stmt_decode, _js_f1185_stmt_decode,
                         _js_f1186_stmt_decode,
                         _js_f1133_stmt_decode, _js_f1090_stmt_decode,
                         _js_f1126_stmt_decode, _js_f1160_stmt_decode,
                         _js_f1134_stmt_decode)
    new_hooks = (_js_f1182_stmt_decode, _js_f1183_stmt_decode,
                 _js_f1184_stmt_decode, _js_f1185_stmt_decode,
                 _js_f1186_stmt_decode)
    sib_hooks = (_js_f1133_stmt_decode, _js_f1090_stmt_decode,
                 _js_f1126_stmt_decode, _js_f1160_stmt_decode,
                 _js_f1134_stmt_decode)
    I = _codes(SECRET_S)
    sib_shapes = [
        # F1133 Object.values(C) over the array
        "var C=%s;var S=String.fromCharCode(...Object.values(C));var RESULT=S;" % I,
        # F1090 map+join
        "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % I,
        # F1126 Object.entries(C).map
        "var C=%s;var S=Object.entries(C).map(function(p){return String.fromCharCode(p[1]);}).join('');var RESULT=S;" % I,
        # F1160 Map with pairs + for-of
        "var C=%s;var M=new Map(C.map(function(c,i){return [i,String.fromCharCode(c)];}));var S='';for(var kv of M){S+=kv[1];}var RESULT=S;" % I,
        # F1134 delimiter split roundtrip
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=T.split(',').join('');var RESULT=S;" % I,
    ]
    bad = []
    for s in sib_shapes:
        if any(h(s) is not None for h in new_hooks):
            bad.append("sib-hit-new:" + s[:40])
    for fn in (1182, 1183, 1184, 1185, 1186):
        for _, payload in _redfirst_shapes("w406", fn):
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
        ("f1133-values",
         "var C=%s;var S=String.fromCharCode(...Object.values(C));var RESULT=S;" % I),
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % I),
        ("f1126-entries",
         "var C=%s;var S=Object.entries(C).map(function(p){return String.fromCharCode(p[1]);}).join('');var RESULT=S;" % I),
    ]
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_now_closed_block():
    """F1187-F1198 now BLOCK on the merged tree (lanes 2-4 closed at merge)."""
    bad = []
    for fn in range(1187, 1196):
        shapes = _redfirst_shapes("w406", fn)
        miss = [name for name, p in shapes if _misses(p)]
        if miss:
            bad.append("f%d:%s" % (fn, ",".join(miss)))
    from gov.instruction_provenance import instruction_shaped
    for fn in (1196, 1197, 1198):
        shapes = _redfirst_shapes("w406", fn)
        quiet = [name for name, p in shapes if not instruction_shaped(p)]
        if quiet:
            bad.append("f%d:%s" % (fn, ",".join(quiet)))
    return (not bad, "now-closed block%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p6_honest_quiet():
    honest = [
        "function greet(name) { return 'Hello, ' + name; }",
        "var o = Object.create(null); o.x = 1;",
        "var m = new WeakMap(); m.set(key, value);",
        "var parts = text.match(/\\w+/g);",
        "var re = /./g; var m; while ((m = re.exec(s)) !== null) { count++; }",
        "var s = String.raw({raw: ['a', 'b']}, x);",
        "var t = Object.values(obj).join(',');",
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
            "var C%d=%s;var O%d=Object.create(null);"
            "C%d.forEach(function(c,i){O%d[i]=String.fromCharCode(c);});"
            "var S%d=Object.values(O%d).join('');"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w406's round-74 attack battery.

    On the wave-407 lane-1 tree, w406_attack_probes.py pins
    F1182-F1186 show BREAK (now closed); F1187-F1198 stay HELD.
    Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w406_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g407l1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w406_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[1].startswith("test_closed_"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_held = {"test_closed_w406_f%d" % n for n in range(1182, 1196)}
        expect_held |= {"test_closed_prov_w406_f%d" % n for n in range(1196, 1199)}
        ok = (expect_held <= held and not (expect_held & broke))
        return (ok, "green(w406_attack): broke=%d held=%d (want F1182-98 CLOSED/HELD)"
                % (len(broke), len(held)))
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
