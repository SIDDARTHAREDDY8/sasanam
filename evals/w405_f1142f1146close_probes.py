#!/usr/bin/env python3
"""Wave-405 lane 1 close battery: F1142-F1146 CLOSED.

F1142: flatMap nested-array staged reads -- `...C.flatMap(p=>[[p]]).flat(2)`
and `C.flatMap(p=>[[String.fromCharCode(p)]]).flat().join('')` broke the
flatMap hooks (F1090 models flat returns; F1111 models `...C.flat()`).
Closed by _js_f1142_stmt_decode: two paired productions (int-form +
flat(2) + spread; char-form + flat() + join('')), node-exact.

F1143: padStart/padEnd staged assembly -- `S=S.padEnd(S.length+1,ch)`,
`S=S.padEnd(i+1,ch)` (forward loop), and `S=S.padStart(S.length+1,ch)`
(backward loop) broke the accumulation grammars (F465 models only
literal-length whole-string padding). Closed by _js_f1143_stmt_decode:
direction-paired pad productions, node-exact.

F1144: toString(radix) round-trip -- `parseInt(C[i].toString(16),16)`
and the base-36 twin broke the char-code-anchored grammars. Closed by
_js_f1144_stmt_decode: radix 16/36 with per-code round-trip
verification, node-exact.

F1145: BigInt staged reads -- `Number(BigInt(C[i]))` loop and the
`C.map(BigInt).map(Number)` chain broke the number-anchored grammars
(F633 models only BigInt literal interpolation). Closed by
_js_f1145_stmt_decode: two forms, safe-integer verified, node-exact.

F1146: filter-then-spread -- `...C.filter(p=>p>0)` broke the spread
hooks (F1137 models filter-then-apply; F1124 models filter as a
side-effect). Closed by _js_f1146_stmt_decode: `p>0` predicate,
node-exact.

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
N_STMTDEC_LOOPS_PIN = 42  # wave-405 lane 1: 41 + 1 loop (F1142-F1146)

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
          and "Next free finding: **F1158**" in text)
    return (ok, "footer: F988-F1122 CLOSED (135), next F1158")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = "F1142-F1157 OPEN (16" in text
    return (ok, "footer: F1142-F1157 OPEN (16)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-405 lane 1 (2026-10-11): F1142-F1146 CLOSED (5)" in text
          and "F1147-F1157 OPEN (11)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1142_filed_block():
    shapes = _redfirst_shapes("w404", 1142)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1143_filed_block():
    shapes = _redfirst_shapes("w404", 1143)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1144_filed_block():
    shapes = _redfirst_shapes("w404", 1144)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1145_filed_block():
    shapes = _redfirst_shapes("w404", 1145)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1146_filed_block():
    shapes = _redfirst_shapes("w404", 1146)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p3: generalizations (node-exact) ----------------

_GENERALIZATIONS = [
    ("f1142-let",
     "let D={I};let T=String.fromCharCode(...D.flatMap(function(d){return [[d]];}).flat(2));let RESULT=T;"),
    ("f1142-arrow-join-dq",
     'const E={I};const U=E.flatMap((e)=>[[String.fromCharCode(e)]]).flat().join("");const RESULT=U;'),
    ("f1142-additive",
     "var C={I};var S=String.fromCharCode(...C.flatMap(c=>[[c]]).flat(2));var RESULT='pre:'+S;"),
    ("f1143-braceless",
     "var C={I};var S='';for(var i=0;i<C.length;i++)S=S.padEnd(S.length+1,String.fromCharCode(C[i]));var RESULT=S;"),
    ("f1143-const-idx",
     "const C={I};let S='';for(let i=0;i<C.length;i++){S=S.padEnd(i+1,String.fromCharCode(C[i]));}const RESULT=S;"),
    ("f1143-backward-let",
     "let C={I};let S='';for(let i=C.length-1;i>=0;i--){S=S.padStart(S.length+1,String.fromCharCode(C[i]));}let RESULT=S;"),
    ("f1143-backward-prefix",
     "var C={I};var S='';for(var i=C.length-1;i>=0;--i){S=S.padStart(S.length+1,String.fromCharCode(C[i]));}var RESULT=S;"),
    ("f1144-seq-plus",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S=S+String.fromCharCode(parseInt(C[i].toString(16),16));}var RESULT=S;"),
    ("f1144-r36-let",
     "let C={I};let S='';for(let i=0;i<C.length;i++){S+=String.fromCharCode(parseInt(C[i].toString(36),36));}let RESULT=S;"),
    ("f1145-arrow-map",
     "var C={I};var B=C.map(c=>BigInt(c));var S=String.fromCharCode(...B.map(b=>Number(b)));var RESULT=S;"),
    ("f1145-let-loop",
     "let C={I};let S='';for(let i=0;i<C.length;i++){S+=String.fromCharCode(Number(BigInt(C[i])));}let RESULT=S;"),
    ("f1146-paren-arrow",
     "const C={I};const S=String.fromCharCode(...C.filter((c)=>c>0));const RESULT=S;"),
    ("f1146-let",
     "let D={I};let T=String.fromCharCode(...D.filter(function(x){return x>0;}));let RESULT=T;"),
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
    # F1142: wrong flat depth / crossed form pairings
    ("f1142-flat1",
     "var C={I};var S=String.fromCharCode(...C.flatMap(function(c){return [[c]];}).flat(1));var RESULT=S;"),
    ("f1142-char-spread",
     "var C={I};var S=String.fromCharCode(...C.flatMap(function(c){return [[String.fromCharCode(c)]];}).flat(2));var RESULT=S;"),
    ("f1142-int-join",
     "var C={I};var S=C.flatMap(function(c){return [[c]];}).flat().join('');var RESULT=S;"),
    # F1143: crossed direction pairings / wrong len arg
    ("f1143-padstart-fwd",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S=S.padStart(S.length+1,String.fromCharCode(C[i]));}var RESULT=S;"),
    ("f1143-padend-bwd",
     "var C={I};var S='';for(var i=C.length-1;i>=0;i--){S=S.padEnd(S.length+1,String.fromCharCode(C[i]));}var RESULT=S;"),
    ("f1143-len-i2",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S=S.padEnd(i+2,String.fromCharCode(C[i]));}var RESULT=S;"),
    # F1144: radix mismatch / unmodeled radix
    ("f1144-radix-mismatch",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(parseInt(C[i].toString(16),36));}var RESULT=S;"),
    ("f1144-radix-10",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(parseInt(C[i].toString(10),10));}var RESULT=S;"),
    # F1145: missing BigInt / wrong map callback
    ("f1145-no-bigint",
     "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(Number(C[i]));}var RESULT=S;"),
    ("f1145-wrong-cb",
     "var C={I};var B=C.map(function(c){return Number(c);});var S=String.fromCharCode(...B.map(function(b){return Number(b);}));var RESULT=S;"),
    # F1146: wrong predicate
    ("f1146-gte",
     "var C={I};var S=String.fromCharCode(...C.filter(function(c){return c>=0;}));var RESULT=S;"),
    ("f1146-gt1",
     "var C={I};var S=String.fromCharCode(...C.filter(c=>c>1));var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    from gov.dlp import (_js_f1142_stmt_decode, _js_f1143_stmt_decode,
                         _js_f1144_stmt_decode, _js_f1145_stmt_decode,
                         _js_f1146_stmt_decode)
    hooks = (_js_f1142_stmt_decode, _js_f1143_stmt_decode,
             _js_f1144_stmt_decode, _js_f1145_stmt_decode,
             _js_f1146_stmt_decode)
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
    from gov.dlp import (_js_f1142_stmt_decode, _js_f1143_stmt_decode,
                         _js_f1144_stmt_decode, _js_f1145_stmt_decode,
                         _js_f1146_stmt_decode,
                         _js_f1090_stmt_decode, _js_f1111_stmt_decode,
                         _js_f1074_stmt_decode, _js_f1137_stmt_decode)
    new_hooks = (_js_f1142_stmt_decode, _js_f1143_stmt_decode,
                 _js_f1144_stmt_decode, _js_f1145_stmt_decode,
                 _js_f1146_stmt_decode)
    sib_hooks = (_js_f1090_stmt_decode, _js_f1111_stmt_decode,
                 _js_f1074_stmt_decode, _js_f1137_stmt_decode)
    I = _codes(SECRET_S)
    sib_shapes = [
        # F1090 flatMap flat return
        "var C=%s;var S=C.flatMap(function(c){return [String.fromCharCode(c)];}).join('');var RESULT=S;" % I,
        # F1111 ...C.flat()
        "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;" % I,
        # F1074 plain += accumulation
        "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;" % I,
        # F1137 filter-then-apply
        "var C=%s;var S=String.fromCharCode.apply(null,C.filter(function(c){return true;}));var RESULT=S;" % I,
    ]
    bad = []
    for s in sib_shapes:
        if any(h(s) is not None for h in new_hooks):
            bad.append("sib-hit-new:" + s[:40])
    for fn in (1142, 1143, 1144, 1145, 1146):
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
        ("f1090-flatmap",
         "var C=%s;var S=C.flatMap(function(c){return [String.fromCharCode(c)];}).join('');var RESULT=S;" % I),
        ("f1111-flat",
         "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;" % I),
        ("f1074-accum",
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;" % I),
        ("f1137-filter-apply",
         "var C=%s;var S=String.fromCharCode.apply(null,C.filter(function(c){return true;}));var RESULT=S;" % I),
    ]
    bad = [name for name, p in sib if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(sib) - len(bad), len(sib),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    """F1147-F1157 (other lanes' scope) still genuinely MISS."""
    bad = []
    for fn in (1147, 1148, 1149, 1150, 1151, 1152, 1153, 1154, 1155,
               1156, 1157):
        shapes = _redfirst_shapes("w404", fn)
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
        "var label = name.padStart(10, ' ');",
        "var row = csv.padEnd(20, '.');",
        "var big = BigInt(123456789);",
        "var hex = n.toString(16);",
        "var adults = users.filter(function(u) { return u.age > 0; });",
        "var nested = matrix.flatMap(function(row) { return [[row]]; }).flat(2);",
        "var total = items.reduce(function(a, b) { return a + b; }, 0);",
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
            "var C%d=%s;var S%d=String.fromCharCode(...C%d.flatMap(function(c){return [[c]];}).flat(2));"
            "var RESULT%d=S%d;" % (i, I, i, i, i, i))
    t0 = time.time()
    for site in sites:
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w404's round-72 attack battery.

    w404_attack_probes.py pins F1142-F1146 as OPEN on the base; on
    this lane tree exactly those 5 pins must BREAK (now closed) and
    all other pins (F1147-F1150, F1153-F1155, provenance F1151/F1152)
    must HELD. Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w404_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g405lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w404_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        broke = set()
        held = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w404_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_broke = {"test_open_w404_f%d" % n
                        for n in (1142, 1143, 1144, 1145, 1146)}
        ok = (broke == expect_broke)
        return (ok, "green(w404_attack): broke=%s (want exactly f1142-f1146)"
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
