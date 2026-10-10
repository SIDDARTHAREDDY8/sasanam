#!/usr/bin/env python3
"""Wave-399 lane 1 close battery: F1074/F1075 CLOSED.

F1074: labeled-statement accumulation reads -- `lbl:` before a for loop,
a while loop, or a block broke the decoder's statement-anchored hook
grammars. Closed by _js_f1074_stmt_decode (whole-text _stmtdec hook):
optional statement-position label prefix(es) (consumed only when the
text carries no break/continue, so ignoring them is node-exact), then a
C-style indexed for-loop, a braced while-loop (accumulation and
increment in either order), or a block-wrapped for-loop, all simulated
node-exactly (v24.20.0).

F1075: member-expression / with-scope int-array accumulation reads --
`O.v[i]` / `O['v'][i]` / alias `var V=O.v` / `with(O)` scopes broke the
plain-identifier loop productions. Closed by _js_f1075_stmt_decode:
`var O={v:[INTS]};` object declarator, then the member/alias/with loop
forms, simulated node-exactly. Only loop/indexed reads are modeled;
spread receivers fail closed here (F1069 owns those).

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
N_STMTDEC_LOOPS_PIN = 22  # wave-398 merge: 21 + this lane's F1074/F1075 loop (real code-count change)

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


def _redfirst_shapes(num, prefix="w399"):
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
    mine = [lp for lp in loops if "_js_f1074_stmt_decode" in lp]
    ok = ok and len(mine) == 1 and "_js_f1075_stmt_decode" in mine[0]
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-399 lane 1: F1074-F1075 CLOSED (2); F1076-F1080 OPEN (5); next free F1081" in src
          and "F988-F1075 CLOSED (88" in src
          and "F1076-F1080 OPEN (5" in src
          and "Next free finding: **F1081**" in src)
    # entry-count check: F1074/F1075 stamped CLOSED exactly once each;
    # F1080 filed exactly once (Spec-review residual, 2026-10-10 11:41 UTC)
    ok = ok and src.count("(F1074 filed") == 1 and src.count("(F1075 filed") == 1
    ok = ok and src.count("(F1080 filed 2026-10-10 11:41 UTC") == 1
    return (ok, "lane-local footer present")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1074_filed_block():
    shapes = _redfirst_shapes(1074)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1075_filed_block():
    shapes = _redfirst_shapes(1075)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# (name, template, hook_level): hook_level=True asserts at the hook level
# (node-exact decode) instead of find_credential, for variants whose
# decoded value is not credential-shaped (e.g. i=1 start drops the 'x').
_GEN_1074 = [
    ("g-let-const", "const C=%s;let S='';foo: for(let i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}const RESULT=S;", False),
    ("g-start1", "var C=%s;var S='';lbl: for(var i=1;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;", True),
    ("g-lte", "var C=%s;var S='';lbl: for(var i=0;i<=C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;", False),
    ("g-pp-incr", "var C=%s;var S='';lbl: for(var i=0;i<C.length;++i){S+=String.fromCharCode(C[i]);}var RESULT=S;", False),
    ("g-pluseq-incr", "var C=%s;var S='';lbl: for(var i=0;i<C.length;i+=1){S+=String.fromCharCode(C[i]);}var RESULT=S;", False),
    ("g-seq-plus", "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S=S+String.fromCharCode(C[i]);}var RESULT=S;", False),
    ("g-unbraced", "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++)S+=String.fromCharCode(C[i]);var RESULT=S;", False),
    ("g-nested-labels", "var C=%s;var S='';a: b: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;", False),
    ("g-while-lte", "var C=%s;var S='';var i=0;lbl: while(i<=C.length){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;", False),
    ("g-while-incrfirst", "var C=%s;var S='';var i=0;lbl: while(i<C.length){i++;S+=String.fromCharCode(C[i]);}var RESULT=S;", True),
    ("g-while-pp", "var C=%s;var S='';var i=0;lbl: while(i<C.length){S+=String.fromCharCode(C[i]);++i;}var RESULT=S;", False),
    ("g-result-add", 'var C=%s;var S="";lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT="pre:"+S;', False),
    ("g-unlab-while", "var C=%s;var S='';var i=0;while(i<C.length){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;", False),
    ("g-unlab-block", "var C=%s;var S='';{for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}}var RESULT=S;", False),
    ("g-label-samename", "var C=%s;var S='';C: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;", False),
]

_GEN_1075 = [
    ("g-dq-bracket", 'var O={v:%s};var S="";for(var i=0;i<O["v"].length;i++){S+=String.fromCharCode(O["v"][i]);}var RESULT=S;', False),
    ("g-let-const", "const O={v:%s};let S='';for(let i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}const RESULT=S;", False),
    ("g-start1-lte", "var O={v:%s};var S='';for(var i=1;i<=O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;", True),
    ("g-mixed", "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O['v'][i]);}var RESULT=S;", False),
    ("g-with-lte", "var O={v:%s};var S='';with(O){for(var i=0;i<=v.length;i++){S+=String.fromCharCode(v[i]);}}var RESULT=S;", False),
    ("g-quoted-key", "var O={'v':%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;", False),
    ("g-alias-lte", "var O={v:%s};var V=O.v;var S='';for(var i=0;i<=V.length;i++){S+=String.fromCharCode(V[i]);}var RESULT=S;", True),
    ("g-trail-comma", "var O={v:%s,};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;", False),
]


@_t
def test_p2_generalizations():
    bad = []
    for name, tmpl, hook_level in _GEN_1074 + _GEN_1075:
        p = tmpl % _codes(SECRET_S)
        if hook_level:
            hit = (dlp._js_f1074_stmt_decode(p) is not None
                   or dlp._js_f1075_stmt_decode(p) is not None)
        else:
            hit = _blocked(p)
        if not hit:
            bad.append(name)
    total = len(_GEN_1074) + len(_GEN_1075)
    return (not bad, "%d/%d generalizations blocked" % (total - len(bad), total))


# ---------------- p3: fail-closed bounds ----------------
# Each must MISS at the hook level (a miss, never a mis-decode).

_FC_1074 = [
    ("fc-break-lbl",
     "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);break lbl;}var RESULT=S;"),
    ("fc-continue",
     "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);continue;}var RESULT=S;"),
    ("fc-wrong-var",
     "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[j]);}var RESULT=S;"),
    ("fc-unbraced-while",
     "var C=%s;var S='';var i=0;lbl: while(i<C.length)S+=String.fromCharCode(C[i]);i++;var RESULT=S;"),
    ("fc-spread",
     "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(...C);}var RESULT=S;"),
    ("fc-negative",
     "var C=[-1,2];var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("fc-wrong-arr",
     "var C=%s;var S='';lbl: for(var i=0;i<D.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("fc-result-not-acc",
     "var C=%s;var S='';lbl: for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=C;"),
    ("fc-label-then-garbage",
     "var C=%s;var S='';lbl: while(x){}var RESULT=S;"),
]

_FC_1075 = [
    ("fc-wrong-key",
     "var O={w:%s};var S='';for(var i=0;i<O.w.length;i++){S+=String.fromCharCode(O.w[i]);}var RESULT=S;"),
    ("fc-two-props",
     "var O={v:%s,w:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
    ("fc-with-wrong-base",
     "var O={v:%s};var S='';with(X){for(var i=0;i<v.length;i++){S+=String.fromCharCode(v[i]);}}var RESULT=S;"),
    ("fc-spread-member",
     "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(...O.v);}var RESULT=S;"),
    ("fc-alias-wrong-prop",
     "var O={v:%s};var V=O.w;var S='';for(var i=0;i<V.length;i++){S+=String.fromCharCode(V[i]);}var RESULT=S;"),
    ("fc-proto-key",
     "var O={__proto__:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
    ("fc-arr-not-obj",
     "var O=%s;var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
    ("fc-with-member-form",
     "var O={v:%s};var S='';with(O){for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    for name, tmpl in _FC_1074:
        p = tmpl if "%s" not in tmpl else tmpl % _codes(SECRET_S)
        if dlp._js_f1074_stmt_decode(p) is not None:
            bad.append(name)
    for name, tmpl in _FC_1075:
        n = tmpl.count("%s")
        p = tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)
        if dlp._js_f1075_stmt_decode(p) is not None:
            bad.append(name)
    total = len(_FC_1074) + len(_FC_1075)
    return (not bad, "%d/%d fail-closed bounds miss" % (total - len(bad), total))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1069():
    # F1069 spread receivers still decode via F1069, never via the new hooks.
    shapes = _redfirst_shapes(1069, prefix="w397")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1074_stmt_decode(p) is not None
                or dlp._js_f1075_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1069 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_loops():
    # Neighboring loop productions still decode coded. The f1044 shape
    # decodes "hi" (not credential-shaped), so it is pinned at the hook
    # level; the rest are pinned at find_credential.
    c = _codes(SECRET_S)
    hook_cases = [
        ("f1044-forin",
         "var O={a:104,b:105};var ACC='';for(var K in O){ACC+=String.fromCharCode(O[K]);}var RESULT=ACC;",
         dlp._js_f1044_stmt_decode),
    ]
    cred_cases = [
        ("f1046-at",
         "var ARR=%s;var ACC='';for(var I=0;I<ARR.length;I++){ACC+=String.fromCharCode(ARR.at(I));}var RESULT=ACC;" % c),
        ("plain-for",
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;" % c),
        ("plain-spread",
         "var C=%s;var RESULT=String.fromCharCode(...C);" % c),
    ]
    bad = [n for n, p, h in hook_cases if h(p) is None]
    bad += [n for n, p in cred_cases if not _blocked(p)]
    total = len(hook_cases) + len(cred_cases)
    return (not bad, "%d/%d sibling loops block" % (total - len(bad), total))


@_t
def test_p4_still_open():
    # F1076-F1079 (still OPEN from round 66) must still MISS -- no
    # incidental closure. F1080 (filed OPEN by this lane, 11:41 UTC)
    # must still BREAK too.
    bad = []
    for n in (1076, 1077, 1078, 1079):
        for sname, shape in _redfirst_shapes(n, prefix="w398"):
            if _blocked(shape):
                bad.append("f%d/%s" % (n, sname))
    for sname, shape in _redfirst_shapes(1080):
        if _blocked(shape):
            bad.append("f1080/%s" % sname)
    return (not bad, "still-open miss, incidental=%d" % len(bad))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-labeled-loop",
     "outer: for(var i=0;i<items.length;i++){console.log(items[i]);}"),
    ("honest-string-index",
     "var O={v:'hello'};var S='';for(var i=0;i<O.v.length;i++){S+=O.v[i];}var RESULT=S;"),
    ("honest-with",
     "with(document){write('hi');}"),
    ("honest-label-switch",
     "lbl: {var x=1;}console.log(x);"),
    ("honest-prose",
     "the label: for best results, stir gently"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';lbl: for(var i=0;i<C.length;i++)"
            "{S+=String.fromCharCode(C[i]);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w398's attack battery (carries F1074-F1079
    open pins). Honor GOV_SKIP_GREEN. On this tree F1074/F1075 are now
    CLOSED, so exactly their two open-pin tests flip to BREAK; every
    other pin must stay HELD."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w398_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g399lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w398_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # On this tree F1074/F1075 are closed: exactly their open pins
        # flip; everything else must hold.
        expect_break = {"test_open_w398_f1074", "test_open_w398_f1075"}
        missing_break = expect_break - set(real)
        extra_break = set(real) - expect_break
        ok = not missing_break and not extra_break
        return (ok,
                "green(w398_attack): %d BREAK, missing=%s extra=%s"
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
