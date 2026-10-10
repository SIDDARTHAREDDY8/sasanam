#!/usr/bin/env python3
"""Wave-402 lane 3 close battery: F1110 CLOSED.

F1110: inline C.values() of-source iteration-protocol staging --
F1091 (CLOSED wave-401 lane 1) models iteration-protocol staged
assembly for `for[-await]...of` over C / C.values() / C.entries(), but
its hook requires the `var IT=C.values();` binding. The inline
of-source `for(var x of C.values()){S+=String.fromCharCode(x);}` (and
the for-await async-IIFE twin, arrow form) assemble node-exactly
(v24.20.0) while find_credential MISSES. Filed 2026-10-10 by the
wave-401 merge Spec-axis review (HARD-1 residual) as its own finding --
F1091 stays CLOSED.

Closed by _js_f1110_stmt_decode (whole-text _stmtdec hook, new
_decode_layer dispatch loop): `[(async function(){ | (async()=>{]`,
`var|let|const C=[INTS];`, `var|let|const S='';`,
`for [await] (var X of C.values()){S+=String.fromCharCode(X);}`,
tail `globalThis.RESULT=S;})();` (async IIFE) or
`var|let|const RESULT=<additive of string literals and S>;`.
`await` is admitted with or without the async wrapper (node v24.20.0
accepts top-level `await` in scripts -- verified); a bare-identifier
loop variable binds as a sloppy-mode global (node v24.20.0 verified).
Node-exact 4/4 filed + 9/9 generalizations (short + 40-char);
fail-closed 16/16. Disjoint from F1091 by construction (F1091's for-of
parser requires `entries` after `C.` or a pre-bound iterator
identifier; this hook requires the literal inline `C.values()` call)
verified both directions: all 5 F1091 filed productions miss here,
all 4 F1110 shapes miss the F1091 hook.

Self-filed OPEN (16:57 UTC): F1121 (top-level for-await over plain C /
bound IT -- F1091 residual), F1122 (undeclared loop var over bound IT /
entries -- F1091 residual). Both node-verified BREAK, red-firsts
evals/w402_f1121_redfirst.py / evals/w402_f1122_redfirst.py
(renumbered F1111->F1121, F1112->F1122 at wave-402 merge per wave-272).

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
N_STMTDEC_LOOPS_PIN = 32  # wave-402 lane 3: 31 + 1 new loop (real code-count change)

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
    mine = [lp for lp in loops if "_js_f1110_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-402 lane 3 (2026-10-10)" in src
          and "F1110 CLOSED (1" in src
          and "F1121-F1122 filed OPEN (2" in src
          and "F1103-F1109, F1121-F1122 OPEN (9" in src
          and "next free F1123" in src)
    # entry-count check: F1110 filed exactly once.
    ok = (ok and src.count("(F1110 filed") == 1)
    ok = (ok and "[CLOSED 2026-10-10 wave-402 lane 3" in src
          and src.count("[CLOSED 2026-10-10 wave-402 lane 3") == 1)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1123**" in src
          and "F1103-F1110 OPEN (8" in src
          and "# Wave-401: F1090-F1102 CLOSED (13); F1103-F1110 OPEN (8); next free F1111" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1110_filed_block():
    shapes = _redfirst_shapes("w402", 1110)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-verified) ----------------

_GEN_1110 = [
    # (name, template with {I} for the int array)
    ("await-fn-form",
     "(async function(){{var C={I};var S='';for await (var x of C.values())"
     "{{S+=String.fromCharCode(x);}}globalThis.RESULT=S;}})();"),
    ("let-const",
     "let C={I};let S='';for(let x of C.values())"
     "{{S+=String.fromCharCode(x);}}const RESULT=S;"),
    ("additive-tail",
     "var C={I};var S='';for(var x of C.values())"
     "{{S+=String.fromCharCode(x);}}var RESULT='pre:'+S+'!';"),
    ("ws-before-dot",
     "var C={I};var S='';for(var x of C .values())"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("loop-let-var",
     "var C={I};var S='';for(let item of C.values())"
     "{{S+=String.fromCharCode(item);}}var RESULT=S;"),
    ("sync-in-iife",
     "(async()=>{{var C={I};var S='';for(var x of C.values())"
     "{{S+=String.fromCharCode(x);}}globalThis.RESULT=S;}})();"),
    ("const-decls",
     "const C={I};var S='';for(const x of C.values())"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("toplevel-await",
     "var C={I};var S='';for await (var x of C.values())"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("undeclared-loopvar",
     "var C={I};var S='';for(x of C.values())"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    # NOTE (narrow grammar, F1091 convention): `values (` with a space
    # before the paren and spaced `String.fromCharCode ( x )` fail
    # closed -- same as the F1091 hook. Not a regression.
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN_1110:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN_1110)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds ----------------

_FC_1110 = [
    # (name, template with %s for the int-array codes)
    ("f1091-forawait-C",
     "(async function(){{var C=%s;var S='';for await (var x of C)"
     "{S+=String.fromCharCode(x);}globalThis.RESULT=S;}})();"),
    ("f1091-bound-it",
     "var C=%s;var it=C.values();var S='';for(var x of it)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1091-entries",
     "var C=%s;var S='';for(var [i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1091-forawait-entries",
     "(async function(){{var C=%s;var S='';for await (var [i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}globalThis.RESULT=S;}})();"),
    ("f1091-spread",
     "var C=%s;var S=String.fromCharCode(...C.values());var RESULT=S;"),
    ("plain-forof-twin",
     "var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}"
     "var RESULT=S;"),
    ("values-no-call",
     "var C=%s;var S='';for(var x of C.values)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("keys-not-values",
     "var C=%s;var S='';for(var x of C.keys())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("destructure-values",
     "var C=%s;var S='';for(var [i,c] of C.values())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("empty-arr",
     "var C=[];var S='';for(var x of C.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("nonempty-S-init",
     "var C=%s;var S='x';for(var x of C.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("while-loop",
     "var C=%s;var S='';var I=0;while(I<C.length)"
     "{S+=String.fromCharCode(C.values[I]);I++;}var RESULT=S;"),
    ("wrong-accum",
     "var C=%s;var S='';for(var x of C.values()){S+=x;}var RESULT=S;"),
    ("other-array",
     "var C=%s;var S='';for(var x of D.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("named-async-fn",
     "(async function foo(){{var C=%s;var S='';for await (var x of C.values())"
     "{S+=String.fromCharCode(x);}globalThis.RESULT=S;}})();"),
    ("junk", "(function(){var s='ab';return s;})()"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, tmpl in _FC_1110:
        p = tmpl % c if "%s" in tmpl else tmpl
        if dlp._js_f1110_stmt_decode(p) is not None:
            bad.append(name)
    total = len(_FC_1110)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1091():
    # F1091's filed shapes still block (via F1091's own hook); the new
    # F1110 hook never hits any of them (disjoint both directions).
    shapes = _redfirst_shapes("w400", 1091)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1110_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1091 blocked=%d/%d, f1110-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_bound_twin():
    # The bound-iterator twin blocks coded via F1091; the F1110 hook
    # misses it (inline requirement).
    p = ("var C=%s;var it=C.values();var S='';for(var x of it)"
         "{S+=String.fromCharCode(x);}var RESULT=S;" % _codes(SECRET_S))
    ok = _blocked(p) and dlp._js_f1110_stmt_decode(p) is None
    return (ok, "bound twin blocks, f1110-hook misses=%s"
            % (dlp._js_f1110_stmt_decode(p) is None))


@_t
def test_p4_sibling_plain_forof():
    # The plain for-of twin blocks coded via its own hook; the F1110
    # hook misses it.
    p = ("var C=%s;var S='';for(var x of C){S+=String.fromCharCode(x);}"
         "var RESULT=S;" % _codes(SECRET_S))
    ok = _blocked(p) and dlp._js_f1110_stmt_decode(p) is None
    return (ok, "plain for-of blocks, f1110-hook misses=%s"
            % (dlp._js_f1110_stmt_decode(p) is None))


@_t
def test_p4_sibling_fcc_spread():
    # The fromCharCode(...C.values()) spread twin blocks coded via
    # F1091; the F1110 hook misses it.
    p = ("var C=%s;var S=String.fromCharCode(...C.values());"
         "var RESULT=S;" % _codes(SECRET_S))
    ok = _blocked(p) and dlp._js_f1110_stmt_decode(p) is None
    return (ok, "spread twin blocks, f1110-hook misses=%s"
            % (dlp._js_f1110_stmt_decode(p) is None))


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-values-sum",
     "var xs=[1,2,3];var t=0;for(var x of xs.values()){t+=x;}"),
    ("honest-forof",
     "var xs=[1,2];var t=0;for(var x of xs){t+=x;}"),
    ("honest-async",
     "(async()=>{var r=await fetch('/a');console.log(r);})();"),
    ("honest-prose",
     "the values() iterator and for-await loop are honest patterns"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';for(var x of C.values())"
            "{S+=String.fromCharCode(x);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: self-filed open pins ----------------

@_t
def test_p7_open_f1121():
    # F1121 (top-level for-await, F1091 residual; renumbered) must still MISS.
    shapes = _redfirst_shapes("w402", 1121)
    bad = [n for n, p in shapes if not _misses(p)]
    return (not bad, "%d/%d F1121 shapes still open"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p7_open_f1122():
    # F1122 (undeclared loop var, F1091 residual; renumbered) must still MISS.
    shapes = _redfirst_shapes("w402", 1122)
    bad = [n for n, p in shapes if not _misses(p)]
    return (not bad, "%d/%d F1122 shapes still open"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w401's attack battery (carries
    F1103-F1110 pins). Honor GOV_SKIP_GREEN. On this lane tree F1110
    is closed, so exactly test_open_w401_f1110 flips; everything else
    must hold."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w401_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g402l3-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w401_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "BREAK":
                real.append(parts[1])
        expect_break = {"test_open_w401_f1110"}
        ok = set(real) == expect_break
        return (ok,
                "green(w401_attack): %d BREAK (expect exactly %s: %s)"
                % (len(real), sorted(expect_break),
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
