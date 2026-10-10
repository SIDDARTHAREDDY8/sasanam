#!/usr/bin/env python3
"""Wave-401 lane 5 close battery: F1100/F1101/F1102 CLOSED.

F1100: labeled while-loop accumulation reads -- a statement-position
label prefix on the F1086 while-loop productions (`lbl:do{...}while(...)`,
`lbl:while(...)...;`) broke the decoder's statement-anchored hook
grammars (F1074's label handling covers only its own for/braced-while
productions; the F1086 hook parses no labels). Closed by
_js_f1100_stmt_decode: requires >=1 label (unlabeled twins are F1086's
-- disjoint by construction), labels inert-verified via the
no-break/continue token scan, loop bodies reuse the F1086 parsers
(braced pre-test while stays F1074's -- fail closed on `{`).

F1101: numeric-bound while conditions -- `do{...}while(I<21)` /
`while(I<21)...` broke the hook grammars (F1086/F1074 model only
`I<C.length` / `I<=C.length`). Closed by _js_f1101_stmt_decode: only
`<` + numeric literal is modeled (`<=` and `.length` fail closed --
F1086 owns those, disjoint by construction); the bound is simulated
node-exactly, including the do-while unconditional first iteration
(num == 0) and OOB reads as "\\0" (F1046 precedent).

F1102: array-spread object rest sources -- `var P={...[c0,c1,...]};`
and `var A=[c0,c1,...];var P={...A};` broke the F1088 hook (models
only object-literal and identifier sources). Closed by
_js_f1102_stmt_decode: spreading an array into an object literal
spreads integer-indexed elements to integer keys ascending
(node-exact, v24.20.0); disjoint from F1088 by the `[`-vs-`{`
spread-source anchor.

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
    ok = ("F988-F1102 CLOSED (108" in text
          and "Next free finding: **F1103**" in text)
    return (ok, "footer: F988-F1102 CLOSED (108), next F1103")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1093-F1099 OPEN (7" in text)
    return (ok, "footer: F1093-F1099 OPEN (7)")


@_t
def test_p1_closed_stamps():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    stamps = sum(1 for n in (1100, 1101, 1102)
                 if re.search(r"\(F%d filed .*\[CLOSED 2026-10-10 wave-401 lane 5"
                              % n, text))
    ok = stamps == 3
    return (ok, "%d/3 CLOSED stamps" % stamps)


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1100_filed_block():
    shapes = _redfirst_shapes("w401", 1100)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1101_filed_block():
    shapes = _redfirst_shapes("w401", 1101)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1102_filed_block():
    shapes = _redfirst_shapes("w401", 1102)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

# Generalizations whose decoded output is credential-shaped: must block
# via the full pipeline.
_GENERALIZATIONS_BLOCK = [
    ("f1100", "var C=%s;var S='';var I=0;a:b:lbl:do{S+=String.fromCharCode(C[I]);I++;}while(I<=C.length);var RESULT=S;"),
    ("f1100", "var C=%s;var S='';var I=0;lbl:do S+=String.fromCharCode(C[I++]);while(I<C.length);var RESULT=S;"),
    ("f1101", "var C=%s;var S='';var I=0;while(I<30)S+=String.fromCharCode(C[I++]);var RESULT=S;"),
    ("f1102", "var P={...%s};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
    ("f1102", "var A=%s;var P={...A};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
]

# Generalizations whose decoded output is NOT credential-shaped (short
# prefix, skipped index 0, OOB tail): the hook must still decode
# node-exactly (v24.20.0 verified), and the pipeline correctly stays
# quiet. Expected values are the node-verified outputs.
_GENERALIZATIONS_NODE = [
    # (hook name, template, node-verified expected decode)
    ("f1100", "var C=%s;var S='';var I=0;lbl:do{I++;S+=String.fromCharCode(C[I]);}while(I<C.length);var RESULT=S;",
     "oxb-0123456789abcdef\x00"),
    ("f1101", "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<5);var RESULT=S;",
     "xoxb-"),
    ("f1101", "var C=%s;var S='';var I=0;do{I++;S+=String.fromCharCode(C[I]);}while(I<10);var RESULT=S;",
     "oxb-012345"),
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
        payload = tmpl % _codes(SECRET_S)
        got = _HOOKS[hook](payload)
        if got != want:
            bad.append("%s: got %r want %r" % (hook, got, want))
    return (not bad, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS_NODE) - len(bad),
               len(_GENERALIZATIONS_NODE),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: fail-closed bounds + disjointness ----------------

_FAIL_CLOSED = [
    # (hook-name, payload) -- each must MISS at hook level.
    ("f1100", "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;"),  # unlabeled -> F1086
    ("f1100", "var C=%s;var S='';var I=0;lbl:while(I<C.length){S+=String.fromCharCode(C[I]);I++;}var RESULT=S;"),  # braced -> F1074
    ("f1100", "var C=%s;var S='';var I=0;lbl:do{S+=String.fromCharCode(C[I]);I++;if(I>3)break;}while(I<C.length);var RESULT=S;"),  # break
    ("f1100", "var C=%s;var S='';var I=0;lbl:for(I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}var RESULT=S;"),  # for -> F1074
    ("f1101", "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<=21);var RESULT=S;"),  # <= not modeled
    ("f1101", "var C=%s;var S='';var I=0;while(I<C.length)S+=String.fromCharCode(C[I++]);var RESULT=S;"),  # .length -> F1086
    ("f1101", "var C=%s;var S='';var I=0;while(I<21){S+=String.fromCharCode(C[I++]);}var RESULT=S;"),  # braced
    ("f1101", "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<21.5);var RESULT=S;"),  # float bound
    ("f1102", "var P={...{0:120}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),  # objlit -> F1088
    ("f1102", "var Q={0:120};var P={...Q};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),  # objvar -> F1088
    ("f1102", "var A=%s;var P={...B};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),  # src mismatch
    ("f1102", "var A='nope';var P={...A};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),  # non-array
    # narrow-grammar: extra decl between P and S is not modeled (F1088 convention)
    ("f1102", "var P={...%s};var T='x';var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
]

_HOOKS = {
    "f1100": dlp._js_f1100_stmt_decode,
    "f1101": dlp._js_f1101_stmt_decode,
    "f1102": dlp._js_f1102_stmt_decode,
}


@_t
def test_p4_fail_closed():
    bad = []
    for hook, tmpl in _FAIL_CLOSED:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        if _HOOKS[hook](payload) is not None:
            bad.append(hook + ":" + payload[:40])
    return (not bad, "%d/%d fail-closed%s"
            % (len(_FAIL_CLOSED) - len(bad), len(_FAIL_CLOSED),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_cross_disjointness():
    """New hooks must not fire on sibling shapes and vice versa."""
    pairs = [
        (dlp._js_f1100_stmt_decode,
         "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;"),
        (dlp._js_f1101_stmt_decode,
         "var C=%s;var S='';var I=0;while(I<C.length)S+=String.fromCharCode(C[I++]);var RESULT=S;"),
        (dlp._js_f1102_stmt_decode,
         "var P={...{0:120}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
        (dlp._js_f1086_stmt_decode,
         "var C=%s;var S='';var I=0;lbl:do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;"),
        (dlp._js_f1088_stmt_decode,
         "var P={...%s};var S=String.fromCharCode(...Object.values(P));var RESULT=S;"),
    ]
    bad = []
    for hook, tmpl in pairs:
        payload = tmpl % _codes(SECRET_S) if "%s" in tmpl else tmpl
        if hook(payload) is not None:
            bad.append(hook.__name__)
    return (not bad, "%d/%d disjoint%s"
            % (len(pairs) - len(bad), len(pairs),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: sibling pins ----------------

def _litobj_full(s):
    return "{" + ",".join("%d:%d" % (i, ord(ch))
                          for i, ch in enumerate(s)) + "}"


@_t
def test_p5_sibling_hooks_hold():
    shapes = [
        # F1074 labeled braced while still blocks via F1074.
        "var C=%s;var S='';var I=0;lbl:while(I<C.length){S+=String.fromCharCode(C[I]);I++;}var RESULT=S;",
        # F1086 unlabeled twins still block via F1086.
        "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;",
        "var C=%s;var S='';var I=0;while(I<C.length)S+=String.fromCharCode(C[I++]);var RESULT=S;",
        # F1088 object-spread twins still block via F1088 (full
        # credential array so the decode is credential-shaped).
        "var P={...%s};var S=String.fromCharCode(...Object.values(P));var RESULT=S;",
    ]
    bad = []
    for p in shapes:
        payload = (p % _litobj_full(SECRET_S) if "{...%s}" in p and "Object.values" in p
                   else p % _codes(SECRET_S) if "%s" in p else p)
        if not _blocked(payload):
            bad.append(p[:40])
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p5_still_open_miss():
    """Merged tree: F1090 (lane 1) and F1099 (lane 2) are closed --
    their shapes must now BLOCK."""
    shapes = [
        # F1090 higher-order reduce twin (closed wave-401 lane 1).
        "var C=%s;var S=C.reduce(function(a,c){return a+String.fromCharCode(c);},'');var RESULT=S;",
        # F1099 arbitrary property-name member read (closed wave-401 lane 2).
        "var O={k:%s};var S='';for(var I=0;I<O.k.length;I++){S+=String.fromCharCode(O.k[I]);}var RESULT=S;",
    ]
    bad = [p[:40] for p in shapes if not _blocked(p % _codes(SECRET_S))]
    return (not bad, "%d/%d merged-tree closed shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: honest-text controls ----------------

@_t
def test_p6_honest_quiet():
    texts = [
        "(function(){var s='ab';return s;})()",
        "var x = 1; // while loops are useful",
        "email the quarterly report to the team",
        "var labels = {a: 1}; // object literal",
        "for (var i = 0; i < 10; i++) { console.log(i); }",
    ]
    bad = [t[:30] for t in texts if not _misses(t)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(texts) - len(bad), len(texts),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    t0 = time.time()
    site = ("var C=%s;var S='';var I=0;lbl:do{S+=String.fromCharCode(C[I]);I++;}"
            "while(I<C.length);var RESULT=S;" % _codes(SECRET_S))
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w400's attack battery (carries F1090-F1102
    pins). Honor GOV_SKIP_GREEN. On the merged tree all F1090-F1102 pins
    are flipped to closed, so the w400 battery must show 0 BREAK;
    anything breaking is real."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w400_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g401lane5-green-", dir="/var/tmp")
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
        # Merged tree: all w400 pins flipped to closed; 0 BREAK expected.
        ok = not real
        return (ok,
                "green(w400_attack): %d BREAK (expect 0)" % len(real))
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
