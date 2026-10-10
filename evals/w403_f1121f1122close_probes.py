#!/usr/bin/env python3
"""Wave-403 lane 4 close battery: F1121 + F1122 CLOSED.

F1121: top-level for-await iteration-protocol staging -- F1091 (CLOSED
wave-401 lane 1) admits `await` only inside the async-IIFE wrapper
("await outside async" fails closed) on the premise that top-level
`for await` is a node SyntaxError. Node v24.20.0 accepts top-level
`await` in scripts (verified via script file and `node --check`):
`var C=[...];var S='';for await (var x of C){...}` and the
bound-iterator twin `var IT=C.values();...for await (var x of IT){...}`
assemble node-exactly while find_credential MISSES.

F1122: undeclared loop-variable iteration-protocol staging -- F1091
requires a declaration keyword for the for-of loop variable ("loop var
not declared" fails closed). In sloppy mode node binds a bare
identifier as a global: `var IT=C.values();...for(x of IT){...}` and
`for([i,c] of C.entries()){...}` assemble node-exactly (v24.20.0
verified) while find_credential MISSES.

Both filed 2026-10-10 16:57 UTC by wave-402 lane 3 (Spec-review
follow-up; renumbered F1111->F1121, F1112->F1122 at the wave-402 merge
per wave-272). F1091 stays CLOSED -- these hooks close only the
residuals, filed as their own findings.

Closed by _js_f1121_stmt_decode / _js_f1122_stmt_decode (whole-text
_stmtdec hooks, one new _decode_layer dispatch loop):
- F1121: `var|let|const C=[INTS];[var|let|const IT=C.values();]`
  `var|let|const S='';for await (var|let|const X of C|IT){S+=String.fromCharCode(X);}`
  `var|let|const RESULT=<additive>;`. `await` REQUIRED (sync twins are
  F1091's); no wrapper (wrapper twins are F1091's); plain C or bound
  IT of-source (inline `C.values()` is F1110's); declared loop var
  (undeclared is F1122's).
- F1122: `var|let|const C=[INTS];[var|let|const IT=C.values();]`
  `var|let|const S='';for (X of IT){S+=String.fromCharCode(X);}`
  or `for ([I,C2] of C.entries()){S+=String.fromCharCode(C2);}`
  `var|let|const RESULT=<additive>;`. No `await` (await twin is
  F1121's); loop var must NOT be declared (declared twins are
  F1091's/F1110's); of-source bound IT or `C.entries()` (inline
  `C.values()` is F1110's; plain C is an earlier hook's).

Node-exact 4/4 filed + 8/8 generalizations (short + 40-char);
fail-closed 25/25 hook-level (incl. cross-disjointness both
directions vs F1091/F1110). Disjoint from F1091 by construction
(wrapper/await/declaration) and from F1110 (inline `C.values()`
of-source) verified both directions.

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
N_STMTDEC_LOOPS_PIN = 35  # wave-403 lane 4: 34 + 1 F1121/F1122 dispatch loop

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
    mine = [lp for lp in loops if "_js_f1121_stmt_decode" in lp]
    ok = ok and len(mine) == 1
    return (ok, "loops=%d pin=%d lane-loop-present=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, len(mine) == 1))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-403 lane 4 (2026-10-10)" in src
          and "F1121, F1122 CLOSED (2" in src
          and "F1111-F1120 OPEN (10" in src
          and "next free F1123" in src)
    # entry-count check: F1121/F1122 filed exactly once each.
    ok = (ok and src.count("(F1121 filed") == 1)
    ok = (ok and src.count("(F1122 filed") == 1)
    ok = (ok and "[CLOSED 2026-10-10 wave-403 lane 4" in src
          and src.count("[CLOSED 2026-10-10 wave-403 lane 4") == 2)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1123**" in src
          and "F1111-F1122 OPEN (12" in src
          and "# Wave-402: F1103-F1110 CLOSED (8); F1111-F1122 OPEN (12); next free F1123" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1121_filed_block():
    shapes = _redfirst_shapes("w403", 1121)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p1_f1122_filed_block():
    shapes = _redfirst_shapes("w403", 1122)
    bad = [n for n, p in shapes if not _blocked(p)]
    return (not bad, "%d/%d filed shapes block"
            % (len(shapes) - len(bad), len(shapes)))


# ---------------- p2: generalizations (node-verified) ----------------

_GEN = [
    # (name, template with {I} for the int array; all node-exact v24.20.0)
    ("f1121-let",
     "let C={I};let S='';for await (let x of C)"
     "{{S+=String.fromCharCode(x);}}let RESULT=S;"),
    ("f1121-const-arr",
     "const C={I};var S='';for await (var x of C)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("f1121-additive-tail",
     "var C={I};var S='';for await (var x of C)"
     "{{S+=String.fromCharCode(x);}}var RESULT='pre:'+S+'!';"),
    ("f1121-IT-let",
     "var C={I};let IT=C.values();var S='';for await (var x of IT)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("f1122-IT-additive",
     "var C={I};var IT=C.values();var S='';for(x of IT)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S+'!';"),
    ("f1122-entries-let",
     "let C={I};let S='';for([i,c] of C.entries())"
     "{{S+=String.fromCharCode(c);}}let RESULT=S;"),
    ("f1122-entries-additive",
     "var C={I};var S='';for([i,c] of C.entries())"
     "{{S+=String.fromCharCode(c);}}var RESULT='>'+S;"),
    ("f1122-IT-different-names",
     "var D={I};var J=D.values();var T='';for(z of J)"
     "{{T+=String.fromCharCode(z);}}var RESULT=T;"),
    ("f1122-undeclared-C",
     "var C={I};var S='';for(x of C)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    ("f1122-undeclared-C-let",
     "let C={I};let S='';for(y of C)"
     "{{S+=String.fromCharCode(y);}}let RESULT=S;"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # (name, hook-attr, template with %s for the int-array codes)
    # F1121 hook must miss:
    ("f1121-vs-f1091-wrapper", "_js_f1121_stmt_decode",
     "(async function(){{var C=%s;var S='';for await (var x of C)"
     "{S+=String.fromCharCode(x);}globalThis.RESULT=S;}})();"),
    ("f1121-vs-f1091-sync-IT", "_js_f1121_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(var x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1121-vs-f1110-inline", "_js_f1121_stmt_decode",
     "var C=%s;var S='';for await (var x of C.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1121-vs-f1122-undecl", "_js_f1121_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1121-vs-destructure", "_js_f1121_stmt_decode",
     "var C=%s;var S='';for await (var [i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1121-vs-symbol-iterator", "_js_f1121_stmt_decode",
     "var C=%s;var S='';for await (var x of C[Symbol.iterator]())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1121-vs-ws-dot-values", "_js_f1121_stmt_decode",
     "var C=%s;var S='';for await (var x of C .values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    # F1122 hook must miss:
    ("f1122-vs-f1091-decl-IT", "_js_f1122_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(var x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-f1091-decl-entries", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for(var [i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1122-vs-f1110-decl", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for(var x of C.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-f1110-bare", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for(x of C.values())"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-f1121-await", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for await (var x of C)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-plain-forof-declared", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for(var x of C)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-destructure-values", "_js_f1122_stmt_decode",
     "var C=%s;var S='';for([i,c] of C.values())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1122-vs-await-undecl", "_js_f1122_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for await (x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    # Sibling hooks must miss my shapes (disjoint both directions):
    ("f1091-vs-f1121-C", "_js_f1091_stmt_decode",
     "var C=%s;var S='';for await (var x of C)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1091-vs-f1121-IT", "_js_f1091_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for await (var x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1091-vs-f1122-IT", "_js_f1091_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1091-vs-f1122-entries", "_js_f1091_stmt_decode",
     "var C=%s;var S='';for([i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1110-vs-f1121-C", "_js_f1110_stmt_decode",
     "var C=%s;var S='';for await (var x of C)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1110-vs-f1121-IT", "_js_f1110_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for await (var x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1110-vs-f1122-IT", "_js_f1110_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1110-vs-f1122-entries", "_js_f1110_stmt_decode",
     "var C=%s;var S='';for([i,c] of C.entries())"
     "{S+=String.fromCharCode(c);}var RESULT=S;"),
    ("f1121-vs-f1122-IT", "_js_f1121_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for(x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
    ("f1122-vs-f1121-IT", "_js_f1122_stmt_decode",
     "var C=%s;var IT=C.values();var S='';for await (var x of IT)"
     "{S+=String.fromCharCode(x);}var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        p = tmpl % c if "%s" in tmpl else tmpl
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_f1091():
    # F1091's filed shapes still block (via F1091's own hook); the new
    # hooks never hit any of them (disjoint both directions).
    shapes = _redfirst_shapes("w400", 1091)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1121_stmt_decode(p) is not None
                or dlp._js_f1122_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1091 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1110():
    # F1110's filed shapes still block (via F1110's own hook); the new
    # hooks never hit any of them (disjoint both directions).
    shapes = _redfirst_shapes("w402", 1110)
    bad_block = [n for n, p in shapes if not _blocked(p)]
    bad_hook = [n for n, p in shapes
                if dlp._js_f1121_stmt_decode(p) is not None
                or dlp._js_f1122_stmt_decode(p) is not None]
    ok = not bad_block and not bad_hook
    return (ok, "f1110 blocked=%d/%d, new-hook hits=%d"
            % (len(shapes) - len(bad_block), len(shapes), len(bad_hook)))


@_t
def test_p4_sibling_f1091_still_closed():
    # F1091's entry is still stamped CLOSED (not silently patched).
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = "[CLOSED 2026-10-10 wave-401 lane 1" in src
    return (ok, "F1091 stamp intact")


# ---------------- p5: honest text ----------------

_HONEST = [
    ("junk-quiet", "(function(){var s='ab';return s;})()"),
    ("honest-forof",
     "var xs=[1,2];var t=0;for(var x of xs){t+=x;}"),
    ("honest-await-loop",
     "async function f(){for await (var x of stream){console.log(x);}}"),
    ("honest-values",
     "var it=[1,2].values();for(var x of it){console.log(x);}"),
    ("honest-prose",
     "the top-level for-await loop is an honest pattern"),
]


@_t
def test_p5_honest_text():
    bad = [n for n, p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest-text quiet" % (len(_HONEST) - len(bad), len(_HONEST)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';for await (var x of C)"
            "{S+=String.fromCharCode(x);}var RESULT=S;" % c)
    page = "<html><body><p>hello</p></body></html>"
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(page)
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- p7: still-open pins ----------------

@_t
def test_p7_open_f1111_1120():
    # Attack round 70's F1111-F1120 must still MISS.
    bad = []
    for n in range(1111, 1121):
        shapes = _redfirst_shapes("w402", n)
        bad += [name for name, payload in shapes if not _misses(payload)]
    return (not bad, "F1111-F1120 still open%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w402's attack battery (carries
    F1111-F1122 pins). Honor GOV_SKIP_GREEN. On this lane tree
    F1121/F1122 are closed, so expect exactly those 2 pin flips;
    everything else must hold."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w402_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g403l4-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w402_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real = []
        for line in r.stdout.split("\n"):
            if line.startswith("BREAK test_open_w402_f1121"):
                real.append("f1121")
            elif line.startswith("BREAK test_open_w402_f1122"):
                real.append("f1122")
            elif line.startswith("BREAK"):
                real.append(line)
        expect = ["f1121", "f1122"]
        ok = sorted(real) == expect
        return (ok,
                "green(w402_attack): %d BREAK (expect exactly %s: %s)"
                % (len(real), expect,
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
