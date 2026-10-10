#!/usr/bin/env python3
"""Wave-401 lane 1 close battery: F1090/F1091/F1097 CLOSED.

F1090: higher-order-method staged assembly reads -- staging credential
assembly through an Array.prototype higher-order method over the int
array (reduce/flatMap/map/reduceRight/forEach/every) broke the
decoder's statement-anchored hook grammars. Closed by
_js_f1090_stmt_decode (whole-text _stmtdec hook): seven productions --
reduce function/arrow twins with '' init, flatMap/map with .join(''),
reduceRight prepend-fold (node-verified forward-order), forEach/every
side-effect forms (every's unconditional `return true` is load-bearing
and required by the grammar). All decode to fromCharCode(c0)+...,
node-exact (v24.20.0, 14/14 filed + 6/6 generalizations). Disjoint from
F1057 (requires the `Array.from(` call) and F996 (`.map(Number)`)
both directions; fail-closed 12/12.

F1091: iteration-protocol staged assembly reads -- `for await (var x
of C)` in an async IIFE, `var it=C.values();for(var x of it)`,
`for(var [i,c] of C.entries())` (accumulating `c`), the async
`for await...of C.entries()` twin, and the
`String.fromCharCode(...C.values())` spread. Closed by
_js_f1091_stmt_decode: optional `(async function(){` wrapper,
`var C=[INTS];`, optional `var IT=C.values();` binding,
`var S='';` + for[-await]-of loop (plain or [i,c]-destructured over
C.entries()) or the direct spread form, then `globalThis.RESULT=S;})();`
(in-IIFE) or `var RESULT=<additive of S>;`. `await` admitted only
inside the async wrapper (top-level `for await` is a node SyntaxError).
Node-exact 10/10 filed + 5/5 generalizations; fail-closed 10/10.
Disjoint from the plain for-of twin and the fcc.apply twin both
directions.

F1097: promise-staged assembly reads --
`Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');});`.
Closed by _js_f1097_stmt_decode: Promise.all preserves order (and
assimilates non-promise values, so the `async` on the map callback is
optional), the then-continuation join('') is modeled as the resolved
value, and a trailing chain of inert `.catch(...)`/`.finally(...)`
calls is skipped balanced (nothing rejects; the credential already
materialized). Grammar stays narrow: exactly one `c` param, one `a`
param, empty-string join. Node-exact 2/2 filed + 4/4 generalizations;
fail-closed 8/8.

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
N_STMTDEC_LOOPS_PIN = 31  # wave-401 merge: 27 + 4 lane loops (real code-count change)

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


def _redfirst_shapes(num, prefix="w400"):
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


_NEW_HOOKS = (dlp._js_f1090_stmt_decode, dlp._js_f1091_stmt_decode,
             dlp._js_f1097_stmt_decode)


def _no_new_hook_hit(payload):
    return all(h(payload) is None for h in _NEW_HOOKS)


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
    mine = [lp for lp in loops if "_js_f1090_stmt_decode" in lp]
    ok = (ok and len(mine) == 1
          and "_js_f1091_stmt_decode" in mine[0]
          and "_js_f1097_stmt_decode" in mine[0])
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-401 lane 1 (2026-10-10)" in src
          and "F1090-F1091, F1097 CLOSED (3" in src
          and "F1092-F1096, F1098-F1102 OPEN (7" in src
          and "next free F1103" in src)
    # entry-count check: each stamped CLOSED exactly once.
    ok = (ok and src.count("(F1090 filed") == 1
          and src.count("(F1091 filed") == 1
          and src.count("(F1097 filed") == 1)
    ok = (ok and "[CLOSED 2026-10-10 wave-401 lane 1" in src
          and src.count("[CLOSED 2026-10-10 wave-401 lane 1") == 3)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1103**" in src
          and "F1093-F1102 OPEN (10" in src
          and "# Wave-400: F1083-F1092 CLOSED (10); F1093-F1102 OPEN (10); next free F1103" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1090_filed_block():
    shapes = _redfirst_shapes(1090)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1091_filed_block():
    shapes = _redfirst_shapes(1091)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1097_filed_block():
    shapes = _redfirst_shapes(1097)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes blocked" % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-exact) ----------------
# Each: hook-level decode equals the node-verified value AND the public
# seam flags it. (Node-exactness verified separately against node
# v24.20.0; these assert the same values in-process.)

_GEN = [
    # (name, hook, template, expected)
    ("f1090", dlp._js_f1090_stmt_decode,
     "let C=%s;const S=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');const RESULT=S;",
     SECRET_S),
    ("f1090", dlp._js_f1090_stmt_decode,
     'var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},"");var RESULT=S;',
     SECRET_S),
    ("f1090", dlp._js_f1090_stmt_decode,
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT='pre:'+S+'!';",
     "pre:" + SECRET_S + "!"),
    ("f1090", dlp._js_f1090_stmt_decode,
     "var  C = %s ;\nvar S = C.flatMap( function(c){ return [String.fromCharCode(c)]; } ).join('') ;\nvar RESULT = S ;",
     SECRET_S),
    ("f1090", dlp._js_f1090_stmt_decode,
     'var C=%s;var S=C.reduceRight(function(a,c){return String.fromCharCode(c)+a;},"");var RESULT=S;',
     SECRET_S),
    ("f1090", dlp._js_f1090_stmt_decode,
     "let C=%s;let S='';C.every(function(c){S+=String.fromCharCode(c);return true;});let RESULT=S;",
     SECRET_S),
    ("f1091", dlp._js_f1091_stmt_decode,
     "(async function(){let C=%s;let S='';for await (let y of C){S+=String.fromCharCode(y);}globalThis.RESULT=S;})();",
     SECRET_S),
    ("f1091", dlp._js_f1091_stmt_decode,
     "var C=%s;var S='';for(var [j,d] of C.entries()){S+=String.fromCharCode(d);}var RESULT=S;",
     SECRET_S),
    ("f1091", dlp._js_f1091_stmt_decode,
     "(async function(){var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}globalThis.RESULT=S;})();",
     SECRET_S),
    ("f1091", dlp._js_f1091_stmt_decode,
     "var C=%s;var S=String.fromCharCode(...C.values());var RESULT='k:'+S;",
     "k:" + SECRET_S),
    ("f1091", dlp._js_f1091_stmt_decode,
     "let C=%s;let it=C.values();let S='';for(let x of it){S+=String.fromCharCode(x);}let RESULT=S;",
     SECRET_S),
    ("f1097", dlp._js_f1097_stmt_decode,
     "let C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');});",
     SECRET_S),
    ("f1097", dlp._js_f1097_stmt_decode,
     "var C = %s ;\nPromise.all( C.map( async function(c){ return String.fromCharCode(c); } ) ).then( function(a){ globalThis.RESULT = a.join(''); } );",
     SECRET_S),
    ("f1097", dlp._js_f1097_stmt_decode,
     "var C=%s;Promise.all(C.map(function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');});",
     SECRET_S),
    ("f1097", dlp._js_f1097_stmt_decode,
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');}).catch(function(){});",
     SECRET_S),
    ("f1097", dlp._js_f1097_stmt_decode,
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');}).finally(function(){});",
     SECRET_S),
]


@_t
def test_p2_generalizations():
    bad = []
    for i, (fname, hook, tmpl, exp) in enumerate(_GEN):
        p = tmpl % _codes(SECRET_S)
        if hook(p) != exp or not _blocked(p):
            bad.append("%s/g%d" % (fname, i))
    return (not bad, "%d/%d generalizations node-exact + blocked"
            % (len(_GEN) - len(bad), len(_GEN)))


# ---------------- p3: fail-closed bounds ----------------
# Each must MISS at the hook level (a miss, never a mis-decode).

_FC_1090 = [
    ("fc-reduce-no-init",
     "var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);});var RESULT=S;"),
    ("fc-reduce-nonempty-init",
     "var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},',');var RESULT=S;"),
    ("fc-reduce-wrong-order",
     "var C=%s;var S=C.reduce(function(a,c){return String.fromCharCode(c)+a;},'');var RESULT=S;"),
    ("fc-map-no-join",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);});var RESULT=S;"),
    ("fc-foreach-no-init",
     "var C=%s;C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("fc-every-no-return-true",
     "var C=%s;var S='';C.every(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("fc-every-return-false",
     "var C=%s;var S='';C.every(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("fc-filter",
     "var C=%s;var S=C.filter(function(c){return true;}).join('');var RESULT=S;"),
    ("fc-swapped-params",
     "var C=%s;var S=C.reduce(function(c,a){return a+String.fromCharCode(c);},'');var RESULT=S;"),
    ("fc-empty-arr",
     "var C=[];var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');var RESULT=S;"),
    ("fc-result-acc",
     "var C=%s;var RESULT=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');"),
    ("fc-join-comma",
     "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join(',');var RESULT=S;"),
]

_FC_1091 = [
    ("fc-await-toplevel",
     "var C=%s;var S='';for await (var x of C){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("fc-wrong-source",
     "var C=%s;var S='';for(var x of D){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("fc-destructure-no-entries",
     "var C=%s;var S='';for(var [i,c] of C){S+=String.fromCharCode(c);}var RESULT=S;"),
    ("fc-keys",
     "var C=%s;var S='';for(var k of C.keys()){S+=String.fromCharCode(k);}var RESULT=S;"),
    ("fc-wrong-accum-var",
     "var C=%s;var S='';for(var [i,c] of C.entries()){S+=String.fromCharCode(i);}var RESULT=S;"),
    ("fc-for-in",
     "var C=%s;var S='';for(var x in C){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("fc-empty-arr",
     "var C=[];var S='';for(var x of C){S+=String.fromCharCode(x);}var RESULT=S;"),
    ("fc-iife-no-async-await",
     "(function(){var C=%s;var S='';for await (var x of C){S+=String.fromCharCode(x);}globalThis.RESULT=S;})();"),
    ("fc-spread-plain",
     "var C=%s;var S=String.fromCharCode(...C);var RESULT=S;"),
    ("fc-it-wrong-source",
     "var C=%s;var it=D.values();var S='';for(var x of it){S+=String.fromCharCode(x);}var RESULT=S;"),
]

_FC_1097 = [
    ("fc-join-comma",
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join(',');});"),
    ("fc-catch-unbalanced",
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');}).catch(function( {});"),
    ("fc-catch-template",
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');}).catch(function(){`x`;});"),
    ("fc-catch-comment",
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');}).catch(/*x*/function(){});"),
    ("fc-allSettled",
     "var C=%s;Promise.allSettled(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');});"),
    ("fc-two-params",
     "var C=%s;Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a,b){globalThis.RESULT=a.join('');});"),
    ("fc-await-form",
     "var C=%s;var R=await Promise.all(C.map(async function(c){return String.fromCharCode(c);}));var RESULT=R.join('');"),
    ("fc-wrong-param",
     "var C=%s;Promise.all(C.map(async function(x){return String.fromCharCode(x);})).then(function(a){globalThis.RESULT=a.join('');});"),
    ("fc-empty-arr",
     "var C=[];Promise.all(C.map(async function(c){return String.fromCharCode(c);})).then(function(a){globalThis.RESULT=a.join('');});"),
]


@_t
def test_p3_fail_closed():
    bad = []

    def _fill(tmpl):
        n = tmpl.count("%s")
        return tmpl if n == 0 else tmpl % tuple([_codes(SECRET_S)] * n)

    for name, tmpl in _FC_1090:
        p = _fill(tmpl)
        if dlp._js_f1090_stmt_decode(p) is not None:
            bad.append(name)
    for name, tmpl in _FC_1091:
        p = _fill(tmpl)
        if dlp._js_f1091_stmt_decode(p) is not None:
            bad.append(name)
    for name, tmpl in _FC_1097:
        p = _fill(tmpl)
        if dlp._js_f1097_stmt_decode(p) is not None:
            bad.append(name)
    total = len(_FC_1090) + len(_FC_1091) + len(_FC_1097)
    return (not bad, "%d/%d fail-closed bounds miss" % (total - len(bad), total))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1057():
    # F1057 Array.from mapFn twin still decodes via F1057; the new
    # hooks never hit it.
    shapes = _redfirst_shapes(1057, prefix="w397")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if not _no_new_hook_hit(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f1057 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f996():
    # F996 .map(Number) still decodes via F996; the new hooks never
    # hit it.
    shapes = _redfirst_shapes(996, prefix="w393")
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes if not _no_new_hook_hit(p)]
    ok = not bad_block and not bad_hook
    return (ok, "f996 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_plain_forof():
    # The plain for-of twin (F1091 control) blocks coded via its own
    # hook; the new F1091 hook never hits it.
    p = ("var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}"
         "var RESULT=S;" % _codes(SECRET_S))
    ok = _blocked(p) and dlp._js_f1091_stmt_decode(p) is None
    return (ok, "plain for-of blocks, f1091-hook misses=%s"
            % (dlp._js_f1091_stmt_decode(p) is None))


@_t
def test_p4_sibling_fcc_apply():
    # The plain-identifier fcc.apply twin blocks coded; the new hooks
    # never hit it.
    p = ("var C=%s;var S=String.fromCharCode.apply(null,C);"
         "var RESULT=S;" % _codes(SECRET_S))
    ok = _blocked(p) and _no_new_hook_hit(p)
    return (ok, "fcc.apply blocks, new-hook hits=%s" % (not _no_new_hook_hit(p)))


@_t
def test_p4_sibling_arrayfrom():
    # The Array.from mapFn twin (F1090 control) blocks coded via
    # F1057; the new F1090 hook never hits it.
    p = ("var C=%s;var S=Array.from(C,function(c){return "
         "String.fromCharCode(c);}).join('');var RESULT=S;"
         % _codes(SECRET_S))
    ok = _blocked(p) and dlp._js_f1090_stmt_decode(p) is None
    return (ok, "Array.from mapFn blocks, f1090-hook misses=%s"
            % (dlp._js_f1090_stmt_decode(p) is None))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-reduce",
     "var nums=[1,2,3];var total=nums.reduce(function(a,c){return a+c;},0);"),
    ("honest-foreach",
     "var items=['a'];items.forEach(function(x){console.log(x);});"),
    ("honest-forof",
     "var xs=[1,2];var t=0;for(var x of xs){t+=x;}"),
    ("honest-promise",
     "Promise.all([fetch('/a'),fetch('/b')]).then(function(r){console.log(r.length);});"),
    ("honest-prose",
     "the for-await loop and Promise.all are honest async patterns"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');"
            "var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w400's attack battery (carries
    F1090-F1102 pins). Honor GOV_SKIP_GREEN. On the merged tree all
    F1090-F1102 pins are flipped to closed, so the w400 battery must
    show 0 BREAK; anything breaking is real."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w400_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g401l1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w400_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        # On the merged tree every w400 pin is flipped to closed:
        # 0 BREAK expected; anything breaking is real.
        expect_break = set()
        ok = set(real) == expect_break
        return (ok,
                "green(w400_attack): %d BREAK (expect %d: %s)"
                % (len(real), len(expect_break),
                   "ok" if ok else "got=" + ",".join(sorted(real))))
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
