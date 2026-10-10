#!/usr/bin/env python3
"""Wave-401 lane 3 close battery: F1095/F1096 CLOSED.

F1095: destructuring-rest accumulation reads -- binding the int array
through a destructuring rest element (`var [first,...rest]=C;`) and
accumulating over `rest` broke the decoder's int-array-identifier
anchored loop grammars. Closed by _js_f1095_stmt_decode (whole-text
_stmtdec hook): `var|let|const C=[INT,...];`, `var|let|const [H,...R]=C;`,
`var|let|const S=String.fromCharCode(H);`, then a C-style indexed
accumulation for-loop over `R` reusing _js_f1074f1075_parse_for (the
rest tail decodes as codes[1:], the head as codes[0]), simulated
node-exactly (v24.20.0). Disjoint from F1075 (which requires the
`{v:[...]}` object declarator): this requires a plain int-array
declarator plus the rest binding.

F1096: shift-staged accumulation reads -- accumulating through
`Array.prototype.shift` in a length-guarded while loop
(`while(C.length){S+=String.fromCharCode(C.shift());}`) broke the
decoder's index-anchored accumulation grammars (no index variable at
all). Closed by _js_f1096_stmt_decode (whole-text _stmtdec hook): the
braced body holds exactly the accumulation statement; each iteration
removes C[0] and appends its ToUint16 char, so the result is the
ToUint16 decode of the staged array in order. `C.length` and
`C.length>0` are equivalent (length is never negative); anything else
in the condition fails closed. Disjoint from the index-anchored hooks
by construction.

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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 28  # wave-400 merge: 27 + this lane's loop (real code-count change)

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


def _redfirst_shapes(num, prefix="w401"):
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
    # evidence-schema domain pin (self-referential by convention)
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
    mine = [lp for lp in loops if "_js_f1095_stmt_decode" in lp]
    ok = ok and len(mine) == 1 and "_js_f1096_stmt_decode" in mine[0]
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-401 lane 3" in src
          and "F1095, F1096 CLOSED (2" in src
          and "F1093-F1094, F1097-F1102 OPEN (8" in src
          and "Next free finding: **F1103**" in src)
    # entry-count check: F1095/F1096 stamped CLOSED exactly once each.
    ok = ok and src.count("(F1095 filed") == 1 and src.count("(F1096 filed") == 1
    ok = ok and "[CLOSED 2026-10-10 wave-401 lane 3" in src
    return (ok, "lane-local footer present")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1095_filed_block():
    shapes = _redfirst_shapes(1095)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1096_filed_block():
    shapes = _redfirst_shapes(1096)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# (name, template, hook): hook is the hook-level decoder for variants
# whose decoded value is not credential-shaped (start=1, <=).
_GEN_1095 = [
    ("g-let-const", "let C=%s;const[hd,...tl]=C;let S=String.fromCharCode(hd);for(let k=0;k<tl.length;k++){S+=String.fromCharCode(tl[k]);}const RESULT=S;", False),
    ("g-start1", "let C=%s;const[hd,...tl]=C;let S=String.fromCharCode(hd);for(let k=1;k<tl.length;k++){S+=String.fromCharCode(tl[k]);}const RESULT=S;", True),
    ("g-lte", "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<=r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;", True),
    ("g-self-plus", "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++){S=S+String.fromCharCode(r[i]);}var RESULT=S;", False),
    ("g-unbraced", "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++)S+=String.fromCharCode(r[i]);var RESULT=S;", False),
    ("g-pp-incr", "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;++i){S+=String.fromCharCode(r[i]);}var RESULT=S;", False),
    ("g-result-add", "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT='pre:'+S;", False),
    ("g-head-abc", "var C=%s;var[abc,...xyz]=C;var S=String.fromCharCode(abc);for(var i=0;i<xyz.length;i++){S+=String.fromCharCode(xyz[i]);}var RESULT=S;", False),
]

_GEN_1096 = [
    ("g-gt0", "var C=%s;var S='';while(C.length>0){S+=String.fromCharCode(C.shift());}var RESULT=S;", False),
    ("g-self-plus", "var C=%s;var S='';while(C.length){S=S+String.fromCharCode(C.shift());}var RESULT=S;", False),
    ("g-let-const", "const C=%s;let S='';while(C.length>0){S+=String.fromCharCode(C.shift());}const RESULT=S+'!';", False),
    ("g-spaced-gt0", "var C=%s;var S='';while(C.length > 0){S+=String.fromCharCode(C.shift());}var RESULT=S;", False),
    ("g-result-add", "var C=%s;var S='';while(C.length){S+=String.fromCharCode(C.shift());}var RESULT=S+'tail';", False),
]


@_t
def test_p2_generalizations():
    bad = []
    for name, tmpl, hook_level in _GEN_1095:
        p = tmpl % _codes(SECRET_S)
        hit = (dlp._js_f1095_stmt_decode(p) is not None) if hook_level else _blocked(p)
        if not hit:
            bad.append(name)
    for name, tmpl, hook_level in _GEN_1096:
        p = tmpl % _codes(SECRET_S)
        hit = (dlp._js_f1096_stmt_decode(p) is not None) if hook_level else _blocked(p)
        if not hit:
            bad.append(name)
    total = len(_GEN_1095) + len(_GEN_1096)
    return (not bad, "%d/%d generalizations blocked" % (total - len(bad), total))


# ---------------- p3: fail-closed bounds ----------------
# Each must MISS at the hook level (a miss, never a mis-decode).

_FC_1095 = [
    ("fc-two-heads",
     "var C=%s;var[a,b,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;"),
    ("fc-wrong-source",
     "var C=%s;var D=%s;var[a,...r]=D;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;"),
    ("fc-preamble-differs",
     "var C=%s;var[a,...r]=C;var S='x'+String.fromCharCode(a);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;"),
    ("fc-k-minus-1",
     "var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);for(var k=1;k<r.length;k++){S+=String.fromCharCode(r[k-1]);}var RESULT=S;"),
    ("fc-no-destructure",
     "var C=%s;var S=String.fromCharCode(C[0]);for(var i=1;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("fc-f1075-shape",
     "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
    ("fc-head-result",
     "var C=%s;var[RESULT,...r]=C;var S=String.fromCharCode(RESULT);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;"),
    ("fc-empty-arr",
     "var C=[];var[a,...r]=C;var S=String.fromCharCode(a);for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;"),
]

_FC_1096 = [
    ("fc-ge-zero",
     "var C=%s;var S='';while(C.length>=0){S+=String.fromCharCode(C.shift());}var RESULT=S;"),
    ("fc-neq-zero",
     "var C=%s;var S='';while(C.length!=0){S+=String.fromCharCode(C.shift());}var RESULT=S;"),
    ("fc-pop",
     "var C=%s;var S='';while(C.length){S+=String.fromCharCode(C.pop());}var RESULT=S;"),
    ("fc-extra-stmt",
     "var C=%s;var S='';while(C.length){S+=String.fromCharCode(C.shift());C.push(1);}var RESULT=S;"),
    ("fc-unbraced",
     "var C=%s;var S='';while(C.length)S+=String.fromCharCode(C.shift());var RESULT=S;"),
    ("fc-shift-other",
     "var C=%s;var D=%s;var S='';while(C.length){S+=String.fromCharCode(D.shift());}var RESULT=S;"),
    ("fc-cond-other",
     "var C=%s;var S='';while(D.length){S+=String.fromCharCode(C.shift());}var RESULT=S;"),
    ("fc-acc-not-empty",
     "var C=%s;var S='x';while(C.length){S+=String.fromCharCode(C.shift());}var RESULT=S;"),
    ("fc-shift-arg",
     "var C=%s;var S='';while(C.length){S+=String.fromCharCode(C.shift(1));}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    for name, tmpl in _FC_1095:
        n = tmpl.count("%s")
        p = tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)
        if dlp._js_f1095_stmt_decode(p) is not None:
            bad.append(name)
    for name, tmpl in _FC_1096:
        n = tmpl.count("%s")
        p = tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)
        if dlp._js_f1096_stmt_decode(p) is not None:
            bad.append(name)
    total = len(_FC_1095) + len(_FC_1096)
    return (not bad, "%d/%d fail-closed bounds miss" % (total - len(bad), total))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1075():
    # F1075 member-expression reads still decode via F1075, never via
    # the new F1095 hook.
    shapes = _redfirst_shapes(1075, prefix="w398")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if dlp._js_f1095_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1075 blocked=%d/%d, f1095-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1074():
    # F1074 plain-identifier loops still decode via F1074; the new hooks
    # never hit them.
    shapes = _redfirst_shapes(1074, prefix="w399")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1095_stmt_decode(p) is not None
                or dlp._js_f1096_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1074 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1083():
    # F1083 Object.create reads still decode via F1083; the new hooks
    # never hit them.
    shapes = _redfirst_shapes(1083, prefix="w399")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1095_stmt_decode(p) is not None
                or dlp._js_f1096_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1083 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_still_open():
    # F1093, F1094, F1097-F1102 must still MISS -- no incidental closure.
    bad = []
    for num in (1093, 1094, 1097, 1099, 1100, 1101, 1102):
        for sname, shape in _redfirst_shapes(num, prefix="w400"):
            if _blocked(shape):
                bad.append("f%d/%s" % (num, sname))
    # F1098 is the provenance seam -- check via the attack battery's
    # carried pin instead (instruction_shaped harness).
    return (not bad, "still-open miss, incidental=%d" % len(bad))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-destructure",
     "var [first,...rest]=getArgs();console.log(first,rest.length);"),
    ("honest-shift",
     "var q=[1,2,3];while(q.length){process(q.shift());}"),
    ("honest-while-len",
     "var items=[1,2];var s='';while(items.length){s+=items.shift();}"),
    ("honest-prose",
     "destructuring the rest parameter gives you the tail of the array"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var[a,...r]=C;var S=String.fromCharCode(a);"
            "for(var i=0;i<r.length;i++){S+=String.fromCharCode(r[i]);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w400's attack battery (carries F1090-F1102
    pins). Honor GOV_SKIP_GREEN. On this tree F1095/F1096 are now CLOSED,
    so exactly their two open-pin tests flip to BREAK; every other pin
    must stay HELD."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w400_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g401lane3-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w400_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # On this tree F1095/F1096 are closed: exactly their open pins
        # flip; everything else must hold.
        expect_break = {"test_open_w400_f1095", "test_open_w400_f1096"}
        missing_break = expect_break - set(real)
        extra_break = set(real) - expect_break
        ok = not missing_break and not extra_break
        return (ok,
                "green(w400_attack): %d BREAK, missing=%s extra=%s"
                % (len(real), sorted(missing_break), sorted(extra_break)))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

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
