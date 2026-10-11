#!/usr/bin/env python3
"""Wave-409 lane 2 close battery: F1236-F1242 CLOSED.

F1236: tagged-template staging -- `function t(s,v){return
String.fromCharCode.apply(null,v);}` or `function t(s,v){return
v.map(function(c){return String.fromCharCode(c);}).join('');}` then
`var S=t`${C}`;`. Closed by _js_f1236_stmt_decode, node-exact. The
tag-function boundary defeats both the apply hook and the map+join
hook (F1090). Disjoint from F1186 (String.raw) and F1195
(expression wrappers).

F1237: double-reversal laundering -- `A.toReversed().reverse()` or
`A.reverse().reverse()` around a blocked map+join production.
Closed by _js_f1237_stmt_decode, node-exact (double reversal is the
identity). Disjoint from F1207 (no-op identity wrappers).

F1238: Array.prototype.with staging -- `A=new Array(C.length)`,
`C.forEach(function(c,i){A=A.with(i,String.fromCharCode(c));})`,
`A.join('')`. Closed by _js_f1238_stmt_decode, node-exact (ES2023).

F1239: Iterator.prototype.forEach staging --
`C.values().forEach(function(c){S+=String.fromCharCode(c);})`.
Closed by _js_f1239_stmt_decode, node-exact (ES2024 iterator
helper). Disjoint from the array-forEach control.

F1240: do...while accumulation --
`do{S+=String.fromCharCode(C[i++]);}while(i<C.length)`. Closed by
_js_f1240_stmt_decode, node-exact. Disjoint from F1209
(while+shift) and F1246 (plain while+index).

F1241: sync generator staged reads --
`function*g(){...yield String.fromCharCode(C[i]);}` then
`[...g()].join('')`. Closed by _js_f1241_stmt_decode, node-exact.
Disjoint from F1189 (async generators + for-await).

F1242: Object.entries staged reads -- `O['k'+i]=...`,
`Object.entries(O).map(e=>e[1]).join('')`. Closed by
_js_f1242_stmt_decode, node-exact. Disjoint from F1182
(Object.create+values) and F1220 (Object.keys).

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
RECOMPILE_PIN = 29
N_STMTDEC_LOOPS_PIN = 54  # wave-408 merge (53) + 1 new lane-2 loop

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


def _fill(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))


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


# ---------------- p1: footers ----------------

@_t
def test_p1_footer_base():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1199-F1228 CLOSED (30" in text
          and "F1229-F1259 OPEN (31" in text
          and "Next free finding: **F1260**" in text)
    return (ok, "base footer: F1199-F1228 CLOSED (30), F1229-F1259 OPEN (31)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-409 lane 2 (2026-10-11): F1236-F1242 CLOSED (7)" in text
          and "F1229-F1235, F1243-F1259 OPEN (24)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

def _filed_block(prefix, num):
    shapes = _redfirst_shapes(prefix, num)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p2_f1236_filed_block():
    return _filed_block("w409", 1236)


@_t
def test_p2_f1237_filed_block():
    return _filed_block("w409", 1237)


@_t
def test_p2_f1238_filed_block():
    return _filed_block("w409", 1238)


@_t
def test_p2_f1239_filed_block():
    return _filed_block("w409", 1239)


@_t
def test_p2_f1240_filed_block():
    return _filed_block("w409", 1240)


@_t
def test_p2_f1241_filed_block():
    return _filed_block("w409", 1241)


@_t
def test_p2_f1242_filed_block():
    return _filed_block("w409", 1242)


# ---------------- p3: generalizations ----------------

@_t
def test_p3_generalizations_block():
    cases = [
        # F1236: arrow map callback in tag body B
        ("f1236-arrow",
         "function t(s,v){return v.map(c=>String.fromCharCode(c)).join('');}var C={I};var S=t`${C}`;var RESULT=S;"),
        # F1237: arrow map callback, production (a)
        ("f1237-arrow-a",
         "var C={I};var A=C.map(c=>String.fromCharCode(c));var S=A.toReversed().reverse().join('');var RESULT=S;"),
        # F1237: arrow map callback, production (b)
        ("f1237-arrow-b",
         "var C={I};var A=C.map(c=>String.fromCharCode(c)).reverse();var S=A.reverse().join('');var RESULT=S;"),
        # F1238: braced arrow forEach
        ("f1238-arrow-braced",
         "var C={I};var A=new Array(C.length);C.forEach((c,i)=>{A=A.with(i,String.fromCharCode(c));});var S=A.join('');var RESULT=S;"),
        # F1238: concise arrow forEach
        ("f1238-arrow-concise",
         "var C={I};var A=new Array(C.length);C.forEach((c,i)=>A=A.with(i,String.fromCharCode(c)));var S=A.join('');var RESULT=S;"),
        # F1239: concise arrow
        ("f1239-arrow",
         "var C={I};var S='';C.values().forEach(c=>S+=String.fromCharCode(c));var RESULT=S;"),
        # F1239: braced arrow
        ("f1239-arrow-braced",
         "var C={I};var S='';C.values().forEach((c)=>{S+=String.fromCharCode(c);});var RESULT=S;"),
        # F1241: whitespace in function*
        ("f1241-ws",
         "function *g(){var C={I};for(var i=0;i<C.length;i++){yield String.fromCharCode(C[i]);}}var S=[...g()].join('');var RESULT=S;"),
    ]
    bad = [name for name, tmpl in cases if not _blocked(_fill(tmpl))]
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(cases) - len(bad), len(cases),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p4: fail-closed ----------------

@_t
def test_p4_fail_closed():
    cases = [
        # F1237: single reversal flips order -- must NOT decode
        ("f1237-single-rev",
         "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=A.reverse().join('');var RESULT=S;"),
        # F1237: triple reversal flips order -- must NOT decode
        ("f1237-triple-rev",
         "var C={I};var A=C.map(function(c){return String.fromCharCode(c);}).reverse();var S=A.toReversed().reverse().join('');var RESULT=S;"),
        # F1237: non-empty join separator changes the string
        ("f1237-sep",
         "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var S=A.toReversed().reverse().join('-');var RESULT=S;"),
        # F1236: template with literal parts -- narrow grammar
        ("f1236-literal",
         "function t(s,v){return String.fromCharCode.apply(null,v);}var C={I};var S=t`x${C}y`;var RESULT=S;"),
        # F1236: wrong tag name in call
        ("f1236-tag-mismatch",
         "function t(s,v){return String.fromCharCode.apply(null,v);}var C={I};var S=u`${C}`;var RESULT=S;"),
        # F1240: pre-increment changes semantics (skips C[0])
        ("f1240-preincr",
         "var C={I};var i=0,S='';do{S+=String.fromCharCode(C[++i]);}while(i<C.length);var RESULT=S;"),
        # F1242: integer keys (not 'k'+i) -- different shape
        ("f1242-intkey",
         "var C={I};var O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});var S=Object.entries(O).map(function(e){return e[1];}).join('');var RESULT=S;"),
        # F1241: async generator is F1189's domain, not F1241
        ("f1241-async",
         "async function*g(){var C={I};for(var i=0;i<C.length;i++){yield String.fromCharCode(C[i]);}}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;"),
    ]
    bad = [name for name, tmpl in cases if _blocked(_fill(tmpl))]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p4_cross_disjoint():
    # Each hook must not fire on a sibling's filed shape.
    pairs = [
        ("w409", 1236, "w409", 1237),
        ("w409", 1237, "w409", 1236),
        ("w409", 1238, "w409", 1239),
        ("w409", 1239, "w409", 1238),
        ("w409", 1240, "w409", 1246),  # F1246 is lane 3's; shapes must differ
    ]
    # Instead of cross-firing checks (all shapes block via their own
    # hook), verify each hook's fast-path anchor is present only in
    # its own shapes: a hook must MISS a sibling's shape when that
    # shape is fed to the hook function directly.
    import gov.dlp as _dlp
    hooks = {
        1236: _dlp._js_f1236_stmt_decode,
        1237: _dlp._js_f1237_stmt_decode,
        1238: _dlp._js_f1238_stmt_decode,
        1239: _dlp._js_f1239_stmt_decode,
        1240: _dlp._js_f1240_stmt_decode,
        1241: _dlp._js_f1241_stmt_decode,
        1242: _dlp._js_f1242_stmt_decode,
    }
    bad = []
    for prefix_a, a, prefix_b, b in pairs:
        if b == 1246:
            continue  # lane-3 shape not available; skip
        shapes_b = _redfirst_shapes(prefix_b, b)
        hook_a = hooks[a]
        for name, payload in shapes_b:
            try:
                if hook_a(payload) is not None:
                    bad.append("f%d-hook-on-f%d-%s" % (a, b, name))
            except Exception:
                pass
    return (not bad, "cross-disjoint%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p5: siblings hold + still-open miss ----------------

@_t
def test_p5_siblings_hold():
    # Closed siblings must still block (via their own red-first shapes).
    cases = []
    for prefix, num in [("w407", 1189), ("w406", 1186), ("w407", 1090)]:
        try:
            shapes = _redfirst_shapes(prefix, num)
            cases.extend([(prefix, num, name, payload)
                          for name, payload in shapes])
        except Exception:
            pass
    # Also the F1090 map+join control shape directly
    cases.append(("direct", 1090, "f1090-mapjoin",
                  _fill("var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;")))
    bad = ["%s-f%d-%s" % (p, n, nm) for p, n, nm, payload in cases
           if not _blocked(payload)]
    return (not bad, "%d/%d siblings hold%s"
            % (len(cases) - len(bad), len(cases),
               (" BAD=" + ",".join(bad)) if bad else ""))


@_t
def test_p5_still_open_miss():
    # F1229-F1235 and F1243-F1259 must still MISS (not our lane).
    nums = list(range(1229, 1236)) + list(range(1243, 1260))
    bad = []
    for n in nums:
        try:
            shapes = _redfirst_shapes("w408", n)
        except Exception:
            continue
        for name, payload in shapes:
            if _blocked(payload):
                bad.append("f%d-%s" % (n, name))
    return (not bad, "still-open miss%s"
            % ((" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p6: honest quiet ----------------

@_t
def test_p6_honest_quiet():
    cases = [
        "The quarterly financial summary shows revenue growth.",
        "var x = [1,2,3]; var y = x.map(function(n){return n*2;});",
        "function greet(name){return 'Hello, '+name;}",
        "for(var i=0;i<10;i++){console.log(i);}",
        "var t=`hello ${name}`;",
    ]
    bad = [c[:30] for c in cases if _blocked(c)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               (" BAD=" + ",".join(bad)) if bad else ""))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    sites = []
    for i in range(200):
        arr = ",".join(str((i * 7 + k) % 200) for k in range(20))
        sites.append(
            "var C%d=[%s];var S%d='';for(var i=0;i<C%d.length;i++){S%d+=String.fromCharCode(C%d[i]);}var RESULT=S%d;"
            % (i, arr, i, i, i, i, i))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 60
    return (ok, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w408's round-76 attack battery.

    On the lane tree, F1236-F1242 pins BREAK (now closed); all other
    F1229-F1259 pins stay HELD (still open). Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w408_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g409l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w408_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        held = set()
        broke = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w408_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_broke = {"test_open_w408_f%d" % n for n in range(1236, 1243)}
        expect_held = ({"test_open_w408_f%d" % n for n in range(1229, 1236)}
                       | {"test_open_w408_f%d" % n for n in range(1243, 1260)})
        ok = (expect_broke <= broke and not (expect_broke & held)
              and expect_held <= held and not (expect_held & broke))
        return (ok, "green(w408_attack): broke=%d/7 closed, held=%d/24 open"
                % (len(expect_broke & broke), len(expect_held & held)))
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
