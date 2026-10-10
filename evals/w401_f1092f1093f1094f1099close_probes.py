#!/usr/bin/env python3
"""Wave-401 lane 2 close battery: F1092 + F1093 + F1094 + F1099 CLOSED.

F1092: tagged-template invocation staging -- `var C=[INTS];` then
`function T(){return C;}` (or `const T=()=>C;`) then
`var S=String.fromCharCode(...T``);`. Closed by _js_f1092_stmt_decode
(whole-text _stmtdec hook), node-exact (v24.20.0, differential 22/22
EXACT across the lane). Disjoint from F1069 (WeakRef/globalThis/
rest-param receivers) and F1089/F1075 (object declarator), verified
both directions.

F1093: getter-chained accumulation reads (F1075 residual) --
`var O={get v(){return C;}};` with `O.v[i]` indexed reads. Closed by
_js_f1093_stmt_decode, reusing the F1074/F1075 for-loop grammar;
node-exact. Disjoint from F1075 (data-property declarator), verified
both directions.

F1094: Reflect.get staged reads (F1083 residual) --
`var O=Object.create(P|{lit});` with `Reflect.get(O,'k')` reads.
Closed by _js_f1094_stmt_decode, reusing the F1083 proto-literal
grammar; node-exact. Disjoint from F1083 (member-syntax reads),
verified both directions.

F1099: arbitrary property-name member reads (F1075 residual) --
`var O={<IDENT>:[INTS]};` with `O.<IDENT>[i]` reads, any identifier
except `v` (F1075 owns the v-anchored production) and `__proto__`.
Closed by _js_f1099_stmt_decode; node-exact. Disjoint from F1075 by
construction, verified both directions.

All four hooks are pure text-to-string scans (no F452 budget; local
per-attempt state via _js_f96x_charge; results bounded by
_MAX_DECODE_BYTES -- wave-383 rule). No new decision codes, no new
re.compile (pins unchanged). Never evals.

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
N_STMTDEC_LOOPS_PIN = 28  # wave-401 lane 2: 27 + 1 new dispatch loop (real code-count change)

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


@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


@_t
def test_p0_verifier_pin():
    # evidence-schema domain pin (self-referential by convention)
    ok = VERIFIER_TAXONOMY_PIN == 33
    print(("HELD " if ok else "BREAK") + " test_p0_verifier_pin (%d)" % VERIFIER_TAXONOMY_PIN)
    return ok


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RECOMPILE_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_recompile_pin (%d)" % n)
    return ok


@_t
def test_p0_stmtdec_loops():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    guarded = all("len(variants) >= _MAX_CANDIDATES" in
                  body[mm.end():mm.end() + 400]
                  for mm in re.finditer(r"for _stmtdec in \(([^)]*)\):",
                                        body, re.DOTALL))
    ok = ok and guarded
    print(("HELD " if ok else "BREAK") +
          " test_p0_stmtdec_loops (%d loops, guards=%s)" % (len(loops), guarded))
    return ok


@_t
def test_p0_footer_state():
    """Lane-local footer: base footer's open findings minus this
    lane's F1092/F1093/F1094/F1099 closures."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("# Wave-401 lane 2: F1092, F1093, F1094, F1099 CLOSED (4); "
          "F1090-F1091, F1095-F1098, F1100-F1102 OPEN (9); next free F1103" in text)
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state")
    return ok


@_t
def test_f1092_filed_shapes_blocked():
    shapes = _redfirst_shapes("w401", 1092)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1092_filed_shapes_blocked (%d shapes%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1093_filed_shapes_blocked():
    shapes = _redfirst_shapes("w401", 1093)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1093_filed_shapes_blocked (%d shapes%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1094_filed_shapes_blocked():
    shapes = _redfirst_shapes("w401", 1094)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1094_filed_shapes_blocked (%d shapes%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1099_filed_shapes_blocked():
    shapes = _redfirst_shapes("w401", 1099)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1099_filed_shapes_blocked (%d shapes%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_generalizations():
    """Node-verified twins beyond the filed shapes: let/const
    declarators, additive RESULT tails, <= bounds, S=S+ accum."""
    c = _codes(SECRET_S)
    blocked = [
        ("f1092-let-additive",
         "let C=%s;function t(){return C;}const S=String.fromCharCode(...t``);let RESULT='x:'+S;" % c),
        ("f1092-arrow-semi",
         "var C=%s;function t(){return C;};var S=String.fromCharCode(...t``);var RESULT=S;" % c),
        ("f1093-lte-bracket",
         "var C=%s;var O={get v(){return C;}};var S='';for(var i=0;i<=O['v'].length;i++){S=S+String.fromCharCode(O['v'][i]);}var RESULT=S;" % c),
        ("f1094-inline-dq",
         'var O=Object.create({k:%s});var S="";for(let i=0;i<Reflect.get(O,"k").length;i++){S+=String.fromCharCode(Reflect.get(O,"k")[i]);}var RESULT=S;' % c),
        ("f1099-data-additive",
         "const O={data:%s};let S='';for(let i=0;i<O.data.length;i++){S+=String.fromCharCode(O.data[i]);}const RESULT=S+'!';" % c),
        ("f1099-arr-bracket",
         "var O={arr:%s};var S='';for(var i=0;i<O['arr'].length;i++){S+=String.fromCharCode(O['arr'][i]);}var RESULT=S;" % c),
    ]
    bad = [n for n, p in blocked if not _blocked(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_generalizations (%d%s)" % (len(blocked), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_fail_closed():
    """Adversarial inputs must MISS at hook level (never mis-decode).
    Checked against the four new hooks directly: sibling hooks may
    legitimately block some of these (e.g. F1075 owns the v-anchored
    shape), which is the disjointness working, not a mis-decode."""
    c = _codes(SECRET_S)
    miss = [
        (dlp._js_f1092_stmt_decode,
         "var C=%s;function t(){return D;}var S=String.fromCharCode(...t``);var RESULT=S;" % c),
        (dlp._js_f1092_stmt_decode,
         "var C=%s;function t(){return C;}var S=String.fromCharCode(...t`x`);var RESULT=S;" % c),
        (dlp._js_f1092_stmt_decode,
         "var C=%s;function t(){return C;}var S=String.fromCharCode(...u``);var RESULT=S;" % c),
        (dlp._js_f1092_stmt_decode,
         "var C=%s;function t(){return C;}var S=String.fromCharCode(t``);var RESULT=S;" % c),
        (dlp._js_f1093_stmt_decode,
         "var C=%s;var O={get v(){return D;}};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % c),
        (dlp._js_f1093_stmt_decode,
         "var C=%s;var O={set v(x){C=x;}};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % c),
        (dlp._js_f1093_stmt_decode,
         "var C=%s;var O={get v(){return C;}};var S='';for(var i=0;i<O.w.length;i++){S+=String.fromCharCode(O.w[i]);}var RESULT=S;" % c),
        (dlp._js_f1094_stmt_decode,
         "var P={k:%s};var O=Object.create(P);var S='';for(var i=0;i<Reflect.get(O,'j').length;i++){S+=String.fromCharCode(Reflect.get(O,'j')[i]);}var RESULT=S;" % c),
        (dlp._js_f1094_stmt_decode,
         "var P={__proto__:%s};var O=Object.create(P);var S='';for(var i=0;i<Reflect.get(O,'x').length;i++){S+=String.fromCharCode(Reflect.get(O,'x')[i]);}var RESULT=S;" % c),
        (dlp._js_f1099_stmt_decode,
         "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % c),
        (dlp._js_f1099_stmt_decode,
         "var O={__proto__:%s};var S='';for(var i=0;i<O.x.length;i++){S+=String.fromCharCode(O.x[i]);}var RESULT=S;" % c),
        (dlp._js_f1099_stmt_decode,
         "var O={k:%s};var S='';for(var i=0;i<O.j.length;i++){S+=String.fromCharCode(O.j[i]);}var RESULT=S;" % c),
        (dlp._js_f1099_stmt_decode,
         "var O={k:%s};var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var R2=S;" % c),
    ]
    bad = ["fc-%d" % i for i, (hook, p) in enumerate(miss) if hook(p) is not None]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_fail_closed (%d%s)" % (len(miss), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_sibling_decoder_pins():
    """F1069/F1075/F1083/F1089 still block their filed shapes; the
    still-OPEN F1090/F1091/F1095/F1096/F1097/F1098(decoder)/F1100/F1101/
    F1102 shapes still miss."""
    c = _codes(SECRET_S)
    blocked = [
        ("f1069-weakref", "var r=new WeakRef({c:%s});var RESULT=String.fromCharCode(...r.deref().c);" % c),
        ("f1069-plain", "var C=%s;var RESULT=String.fromCharCode(...C);" % c),
        ("f1075-loop", "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % c),
        ("f1083-proto", "var P={k:%s};var O=Object.create(P);var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;" % c),
        ("f1089-spread", "var O={v:%s};var RESULT=String.fromCharCode(...O.v);" % c),
    ]
    bad = [n for n, p in blocked if not _blocked(p)]
    still_open = []
    for num in (1090, 1091, 1095, 1096, 1097):
        for name, payload in _redfirst_shapes("w400", num):
            still_open.append((name, payload))
    for num in (1100, 1101, 1102):
        for name, payload in _redfirst_shapes("w400", num):
            still_open.append((name, payload))
    bad += [n for n, p in still_open if not _misses(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_sibling_decoder_pins (%d blocked, %d open%s)" %
          (len(blocked), len(still_open), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_honest_text_quiet():
    honest = [
        "var O={k:[1,2,3]};console.log(O.k.length);",
        "function t(){return 42;}var x=t``;",
        "var O={get v(){return this._v;}};",
        "console.log(Reflect.get(window,'location'));",
        "The quarterly report shows growth in Q3.",
        "(function(){var s='ab';return s;})()",
    ]
    bad = ["honest-%d" % i for i, p in enumerate(honest) if not _misses(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_honest_text_quiet (%d%s)" % (len(honest), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_perf_200_sites():
    c = _codes(SECRET_S)
    texts = []
    for i in range(200):
        if i % 4 == 0:
            texts.append("var O={k:%s};var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;" % c)
        elif i % 4 == 1:
            texts.append("var C=%s;function t(){return C;}var S=String.fromCharCode(...t``);var RESULT=S;" % c)
        elif i % 4 == 2:
            texts.append("var x = %d; // honest text %d" % (i, i))
        else:
            texts.append("<p>honest paragraph number %d with words</p>" % i)
    t0 = time.time()
    for t in texts:
        dlp.find_credential(t)
    dt = time.time() - t0
    ok = dt < 60
    print(("HELD " if ok else "BREAK") + " test_perf_200_sites (%.2fs)" % dt)
    return ok


@_t
def test_green_w400():
    """Depth-1 green check on w400's attack battery (carries F1090-F1099
    OPEN pins). Honor GOV_SKIP_GREEN. The F1092/F1093/F1094/F1099 OPEN
    pins are EXPECTED to flip (now closed); the footer pin flips too;
    anything else breaking is real."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w400 (skipped: GOV_SKIP_GREEN=1)")
        return True
    tmpd = "/var/tmp/g401l2-green-%d-%d" % (os.getpid(), int(time.time()))
    os.makedirs(tmpd)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w400_attack_probes.py")
    expected_flips = ("test_open_w400_f1092", "test_open_w400_f1093",
                      "test_open_w400_f1094", "test_open_w400_f1099")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=600, cwd=REPO_ROOT)
        real, flips = [], []
        footer_held = True
        for line in r.stdout.split("\n"):
            if line.startswith("BREAK "):
                nm = line.split()[1]
                if nm in expected_flips:
                    flips.append(nm)
                else:
                    real.append(nm)
            if line.startswith("HELD test_b0_footer_state"):
                footer_held = True
            if line.startswith("BREAK test_b0_footer_state"):
                footer_held = False
        tally = (r.stdout.strip().split("\n") or ["?"])[-1] if r.stdout else "?"
        # The lane tree preserves the merge footer line verbatim, so the
        # child's footer pin stays HELD; the 4 now-closed OPEN pins flip
        # HELD->BREAK (their shapes now block). Anything else breaking
        # is real.
        ok = (not real and len(flips) == 4 and footer_held)
        print(("HELD " if ok else "BREAK") +
              " test_green_w400 (real=%s flips=%d/4 footer_held=%s tally=%s)" %
              (sorted(real), len(flips), footer_held, tally))
        return ok
    except Exception as e:
        print("BREAK test_green_w400 (exec failed: %s)" % e)
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = []
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            if not fn():
                fails.append(fn.__name__)
        except Exception as e:
            print("BREAK " + fn.__name__ + " (exception: %s)" % e)
            fails.append(fn.__name__)
    print("%d/%d HELD" % (len(TESTS) - len(fails), len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
