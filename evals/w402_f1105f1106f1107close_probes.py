#!/usr/bin/env python3
"""Wave-402 lane 2 close battery: F1105/F1106/F1107 CLOSED.

F1105: Proxy get-trap indexed accumulation reads -- `var P={k:[codes]};`
`var O=new Proxy(P,{get:function(t,p){return t[p];}});` then a C-style
accumulation loop over `O.k` broke the hook grammars (F1059 models only
string-literal-valued targets with an additive RESULT, no loop).
Closed by _js_f1105_stmt_decode: requires exactly one int-array
property (`__proto__` fails closed), the identity get-trap (reuses
_js_f1059_parse_get_trap), and the C-style loop over `O.KEY`
(dot/bracket twins), simulated node-exactly via _js_f1074f1075_parse_for.

F1106: Object.assign staged reads -- `var O=Object.assign({},C);` broke
the hook grammars (F1075 requires the `{v:[...]}` object-literal
declarator; F1088 requires a `{...` spread source). Two productions:
(a) indexed accumulation loop (condition over `C.length`, reads over
`O[i]`); (b) `String.fromCharCode(...Object.values(O))` spread.
Closed by _js_f1106_stmt_decode.

F1107: spread-into-object for-in accumulation -- `var O={...C};` then
`for(var k in O){S+=String.fromCharCode(O[k]);}` broke F1044 (which
requires an int-valued object literal). Closed by
_js_f1107_stmt_decode: requires the `{...C}` spread of the bound array;
the for-in body reuses _js_f1044_parse_accum; integer keys enumerate
ascending node-exactly.

All shapes node-verified (v24.20.0). Green checks ON.
$0-spend-by-construction.

NOTE (honest): the round-69 red-first templates used `{{I}}` (literal
`{I}`, vacuous shapes). Fixed to `{I}` in this lane so the shapes are
real; verified BREAK on the open tree via stash before the fix.
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
N_STMTDEC_LOOPS_PIN = 32  # wave-402 lane 2: 31 + 1 new dispatch loop

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


_HOOKS = {
    "f1105": dlp._js_f1105_stmt_decode,
    "f1106": dlp._js_f1106_stmt_decode,
    "f1107": dlp._js_f1107_stmt_decode,
}


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
def test_p1_footer_lane_local():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-402 lane 2: F1105-F1107 CLOSED (3); "
          "F1103-F1104, F1108-F1110 OPEN (5); next free F1111" in text)
    return (ok, "lane-local footer present")


@_t
def test_p1_closed_stamps():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    stamps = sum(1 for n in (1105, 1106, 1107)
                 if re.search(r"\(F%d filed .*\[CLOSED 2026-10-10 wave-402 lane 2"
                              % n, text))
    ok = stamps == 3
    return (ok, "%d/3 CLOSED stamps" % stamps)


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1105_filed_block():
    shapes = _redfirst_shapes("w401", 1105)
    assert all("{I}" not in p for _, p in shapes), "vacuous shape!"
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1106_filed_block():
    shapes = _redfirst_shapes("w401", 1106)
    assert all("{I}" not in p for _, p in shapes), "vacuous shape!"
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1107_filed_block():
    shapes = _redfirst_shapes("w401", 1107)
    assert all("{I}" not in p for _, p in shapes), "vacuous shape!"
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

# Generalizations whose decoded output is credential-shaped: must block
# via the full pipeline.
_GENERALIZATIONS_BLOCK = [
    # F1105: different key, const/let, arrow trap, bracket read, S=S+.
    ("f1105", "const P={data:%s};let O=new Proxy(P,{get:(t,p)=>t[p]});let S='';for(let i=0;i<O.data.length;i++){S+=String.fromCharCode(O['data'][i]);}let RESULT=S;"),
    ("f1105", "var P={'k':%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O[\"k\"].length;i++){S=S+String.fromCharCode(O[\"k\"][i]);}var RESULT=S;"),
    # F1106a: let/const, S=S+, ++i.
    ("f1106", "let C=%s;const O=Object.assign({},C);let S='';for(let j=0;j<C.length;++j){S=S+String.fromCharCode(O[j]);}let RESULT=S;"),
    # F1106b: different S name, const.
    ("f1106", "const C=%s;const O=Object.assign({},C);const T=String.fromCharCode(...Object.values(O));const RESULT=T;"),
    # F1107: let/const, S=S+, bare k.
    ("f1107", "const C=%s;const O={...C};let T='';for(k in O){T+=String.fromCharCode(O[k]);}const RESULT=T;"),
    ("f1107", "let C=%s;let O={...C};let S='';for(let k in O){S=S+String.fromCharCode(O[k]);}let RESULT='pre'+S;"),
]

# Generalizations whose decoded output is NOT credential-shaped: the
# hook must still decode node-exactly (v24.20.0 verified), pipeline
# stays quiet. Expected values are the node-verified outputs.
_GENERALIZATIONS_NODE = [
    # F1105: <= (OOB -> \0).
    ("f1105", "var P={k:%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<=O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;",
     SECRET_S + "\x00"),
    # F1106a: start=1 skips first char (not credential-shaped; hook
    # still node-exact).
    ("f1106", "var C=%s;var O=Object.assign({},C);var S='';for(var i=1;i<C.length;i++){S+=String.fromCharCode(O[i]);}var RESULT=S;",
     SECRET_S[1:]),
    # F1107: short prefix (not credential-shaped).
    ("f1107", "var C=[120,111];var O={...C};var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;",
     "xo"),
]


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
    bad = []
    for hook, tmpl, want in _GENERALIZATIONS_NODE:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        got = _HOOKS[hook](payload)
        if got != want:
            bad.append("%s: got %r want %r" % (hook, got, want))
    return (not bad, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS_NODE) - len(bad),
               len(_GENERALIZATIONS_NODE),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: fail-closed bounds + disjointness ----------------

_FAIL_CLOSED = [
    # F1105 narrow grammar.
    ("f1105", "var P={__proto__:%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
    ("f1105", "var P={k:%s,j:%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
    ("f1105", "var P={k:%s};var O=new Proxy(P,{get:function(t,p){return t['x'];}});var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
    ("f1105", "var P={k:%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O.j.length;i++){S+=String.fromCharCode(O.j[i]);}var RESULT=S;"),
    ("f1105", "var P={k:'ab'};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
    # F1106 narrow grammar.
    ("f1106", "var C=%s;var O=Object.assign(C);var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(O[i]);}var RESULT=S;"),
    ("f1106", "var C=%s;var O=Object.assign({},C);var S='';for(var i=0;i<O.length;i++){S+=String.fromCharCode(O[i]);}var RESULT=S;"),
    ("f1106", "var C=%s;var O=Object.assign({},C);var S=String.fromCharCode(...Object.values(C));var RESULT=S;"),
    ("f1106", "var C=%s;var O=Object.assign({},C,{});var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(O[i]);}var RESULT=S;"),
    # F1107 narrow grammar.
    ("f1107", "var C=%s;var O={...C,x:1};var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;"),
    ("f1107", "var C=%s;var D=%s;var O={...D};var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;"),
    ("f1107", "var C=%s;var O={...C};var S='';for(var k in C){S+=String.fromCharCode(C[k]);}var RESULT=S;"),
]


@_t
def test_p4_fail_closed():
    bad = []
    for hook, tmpl in _FAIL_CLOSED:
        n = tmpl.count("%s")
        payload = tmpl % ((_codes(SECRET_S),) * n) if n else tmpl
        if _HOOKS[hook](payload) is not None:
            bad.append(hook + ":" + payload[:40])
    return (not bad, "%d/%d fail-closed%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjointness():
    """New hooks must not fire on sibling shapes and vice versa."""
    pairs = [
        # My hooks vs sibling shapes.
        (dlp._js_f1105_stmt_decode,
         "var T={a:'x',b:'y'};var P=new Proxy(T,{get:function(o,k){return o[k];}});var RESULT=P.a+P.b;"),
        (dlp._js_f1106_stmt_decode,
         "var Q={0:120,1:111};var P={...Q};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
        (dlp._js_f1106_stmt_decode,
         "var O={v:[120,111]};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;"),
        (dlp._js_f1107_stmt_decode,
         "var O={0:120,1:111};var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;"),
        # Sibling hooks vs my shapes.
        (dlp._js_f1059_stmt_decode,
         "var P={k:%s};var O=new Proxy(P,{get:function(t,p){return t[p];}});var S='';for(var i=0;i<O.k.length;i++){S+=String.fromCharCode(O.k[i]);}var RESULT=S;"),
        (dlp._js_f1088_stmt_decode,
         "var C=%s;var O=Object.assign({},C);var S=String.fromCharCode(...Object.values(O));var RESULT=S;"),
        (dlp._js_f1075_stmt_decode,
         "var C=%s;var O=Object.assign({},C);var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(O[i]);}var RESULT=S;"),
        (dlp._js_f1044_stmt_decode,
         "var C=%s;var O={...C};var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;"),
    ]
    bad = []
    for hook, tmpl in pairs:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        if hook(payload) is not None:
            bad.append(hook.__name__)
    return (not bad, "%d/%d disjoint%s"
            % (len(pairs) - len(bad), len(pairs),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: sibling pins + still-open ----------------

@_t
def test_p5_sibling_hooks_hold():
    lit = "{" + ",".join("%d:%d" % (i, ord(c))
                          for i, c in enumerate(SECRET_S)) + "}"
    shapes = [
        # F1059 named-target get-trap reads still block via F1059.
        "var T={a:'xoxb-01',b:'23456789abcdef'};var P=new Proxy(T,{get:function(o,k){return o[k];}});var RESULT=P.a+P.b;",
        # F1044 for-in over int literal still blocks via F1044.
        "var O=%s;var S='';for(var k in O){S+=String.fromCharCode(O[k]);}var RESULT=S;" % lit,
        # F1088 spread-rest still blocks via F1088.
        "var Q=%s;var P={...Q};var S=String.fromCharCode(...Object.values(P));var RESULT=S;" % lit,
        # F1075 member reads still block via F1075.
        "var O={v:%s};var S='';for(var i=0;i<O.v.length;i++){S+=String.fromCharCode(O.v[i]);}var RESULT=S;" % _codes(SECRET_S),
    ]
    bad = [p[:40] for p in shapes if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p5_still_open_miss():
    """F1103, F1104, F1108, F1109, F1110 are still OPEN on this lane's scope."""
    shapes = [
        # F1103 String.raw staged reads.
        "var R=String.raw({raw:%s});var S=R;var RESULT=S;" % _codes(SECRET_S),
        # F1108 slice-apply staged reads.
        "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode.apply(null,C.slice(i,i+1));}var RESULT=S;" % _codes(SECRET_S),
    ]
    bad = [p[:40] for p in shapes if _blocked(p)]
    return (not bad, "%d/%d still-open shapes miss%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: honest-text controls ----------------

@_t
def test_p6_honest_quiet():
    texts = [
        "(function(){var s='ab';return s;})()",
        "var x = 1; // Object.assign copies properties",
        "email the quarterly report to the team",
        "var proxy = new Proxy({}, {}); // empty proxy",
        "for (var k in obj) { console.log(k); }",
        "var O = Object.assign({}, defaults);",
    ]
    bad = [t[:30] for t in texts if not _misses(t)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(texts) - len(bad), len(texts),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    t0 = time.time()
    site = ("var C=%s;var O=Object.assign({},C);var S='';for(var i=0;i<C.length;i++)"
            "{S+=String.fromCharCode(O[i]);}var RESULT=S;" % _codes(SECRET_S))
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w401's attack battery. Honor GOV_SKIP_GREEN.

    On this lane tree F1105/F1106/F1107 are closed, so exactly those 3
    open pins must BREAK (shapes now blocked); everything else HELD.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w401_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g402lane2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w401_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        broken = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "BREAK":
                broken.append(parts[1])
        want = {"test_open_w401_f1105", "test_open_w401_f1106",
                "test_open_w401_f1107"}
        ok = set(broken) == want
        return (ok, "green(w401_attack): BREAK=%s (expect %s)"
                % (sorted(broken), sorted(want)))
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
            print(("HELD " if ok else "BREAK ") + fn.__name__ + " -- " + note)
        else:
            print(("HELD " if ok else "BREAK ") + fn.__name__)
        if ok:
            held += 1
        else:
            broken += 1
    print("%d tests, %d BREAK" % (held + broken, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
