#!/usr/bin/env python3
"""Wave-400 lane 2 close battery: F1086/F1087/F1088 CLOSED.

F1086: while-loop accumulation reads -- post-test `do...while` (braced
and braceless bodies) and braceless pre-test `while` accumulation broke
the decoder's statement-anchored hook grammars (F1028/F1029 model only
`for` loops; F1074's while parser requires a braced body). Closed by
_js_f1086_stmt_decode (whole-text _stmtdec hook): the 2 braced pre-test
while twins stay F1074's -- the hook fails closed on `{` after the
while condition (hook-level disjointness verified empirically).

F1087: switch-case staged accumulation -- staging the accumulation loop
inside a `switch` case broke the statement-anchored hook grammars.
Closed by _js_f1087_stmt_decode: the loop must be the first statement
of the clause selected by the discriminant's literal value (first
matching `case`, else `default`); other clauses break-only.

F1088: object-spread rest staging -- staging the int array through an
object-spread rest object broke the int-array productions. Closed by
_js_f1088_stmt_decode: integer-index keys read back in ascending numeric
order, duplicate keys later-wins, inline-literal and var-source forms.

All shapes node-verified (v24.20.0). Green checks ON. $0-spend-by-construction.
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
N_STMTDEC_LOOPS_PIN = 27  # wave-400 merge: 24 + 3 lane loops (real code-count change)

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


def _litobj(s):
    return "{" + ",".join("%d:%d" % (i, ord(ch))
                          for i, ch in enumerate(s)) + "}"


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


# ---------------- p1: footer pins ----------------

@_t
def test_p1_footer_closed_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F988-F1088 CLOSED (98" in text
          and "Next free finding: **F1093**" in text)
    return (ok, "footer: F988-F1088 CLOSED (98), next F1093")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1083-F1085, F1089-F1092 OPEN (7" in text)
    return (ok, "footer: F1083-F1085, F1089-F1092 OPEN (7)")


@_t
def test_p1_closed_stamps():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    stamps = sum(1 for n in (1086, 1087, 1088)
                 if re.search(r"\(F%d filed .*\[CLOSED 2026-10-10 wave-400 lane 2"
                              % n, text))
    return (stamps == 3, "%d/3 CLOSED stamps" % stamps)


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1086_filed_block():
    shapes = _redfirst_shapes("w400", 1086)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/6 filed shapes block%s"
            % (len(shapes) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1087_filed_block():
    shapes = _redfirst_shapes("w400", 1087)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/4 filed shapes block%s"
            % (len(shapes) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1088_filed_block():
    shapes = _redfirst_shapes("w400", 1088)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/4 filed shapes block%s"
            % (len(shapes) - len(bad), "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

@_t
def test_p3_f1086_generalizations():
    c = _codes(SECRET_S)
    cases = [
        # (name, payload, expected decoded value, expect_block)
        ("lte", "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<=C.length);var RESULT=S;" % c, SECRET_S + "\0", False),
        ("incr-first", "var C=%s;var S='';var I=0;do{I++;S+=String.fromCharCode(C[I]);}while(I<C.length);var RESULT=S;" % c, "oxb-0123456789abcdef\0", False),
        ("let", "let C=%s;let S='';let I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);let RESULT=S;" % c, SECRET_S, True),
        ("self-plus", "var C=%s;var S='';var I=0;do{S=S+String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;" % c, SECRET_S, True),
        ("while-lte", "var C=%s;var S='';var I=0;while(I<=C.length)S+=String.fromCharCode(C[I++]);var RESULT=S;" % c, SECRET_S + "\0", False),
    ]
    bad = []
    for name, payload, want, expect_block in cases:
        got = dlp._js_f1086_stmt_decode(payload)
        if got != want:
            bad.append(name + "-decode")
        elif expect_block and not _blocked(payload):
            bad.append(name + "-miss")
    return (not bad, "%d/5 node-exact%s"
            % (len(cases) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_f1087_generalizations():
    c = _codes(SECRET_S)
    cases = [
        ("three-cases", "var C=%s;var S='';var K=2;switch(K){case 1:break;case 2:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;default:break;}var RESULT=S;" % c, SECRET_S),
        ("default-only", "var C=%s;var S='';var K=9;switch(K){default:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}}var RESULT=S;" % c, SECRET_S),
        ("trailing-break-opt", "var C=%s;var S='';var K=9;switch(K){case 1:break;default:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}}var RESULT=S;" % c, SECRET_S),
    ]
    bad = []
    for name, payload, want in cases:
        got = dlp._js_f1087_stmt_decode(payload)
        if got != want or not _blocked(payload):
            bad.append(name)
    return (not bad, "%d/3 node-exact%s"
            % (len(cases) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_f1088_generalizations():
    cases = [
        ("dup-keys", "var P={...{0:65,1:66,0:67}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;", "CB"),
        ("out-of-order", "var P={...{2:67,0:65,1:66}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;", "ABC"),
        ("trailing-comma", "var P={...{0:65,1:66,}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;", "AB"),
        ("hex-keys", "var P={...{0x0:65,0x1:66}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;", "AB"),
    ]
    bad = []
    for name, payload, want in cases:
        got = dlp._js_f1088_stmt_decode(payload)
        # "AB"/"CB" are not credential-shaped, so block is not expected;
        # node-exactness of the decoder is the assertion here.
        if got != want:
            bad.append(name)
    return (not bad, "%d/4 node-exact%s"
            % (len(cases) - len(bad), "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: fail-closed bounds + disjointness ----------------

@_t
def test_p4_f1086_fail_closed():
    c = _codes(SECRET_S)
    fc = [
        # braced pre-test while is F1074's -- the lane hook must MISS it
        # (disjointness), even though find_credential still blocks.
        "var C=%s;var S='';var I=0;while(I<C.length){S+=String.fromCharCode(C[I]);I++;}var RESULT=S;" % c,
        "var C=%s;var S='';var I=0;while(I<C.length)S+=String.fromCharCode(C[++I]);var RESULT=S;" % c,
        "var C=%s;var S='';var I=0;lbl:do{S+=String.fromCharCode(C[I]);I++;}while(I<C.length);var RESULT=S;" % c,
        "var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}while(I<20);var RESULT=S;" % c,
    ]
    bad = []
    for name, payload in (("braced-while", fc[0]), ("pre-incr", fc[1]),
                          ("labeled", fc[2]), ("num-cond", fc[3])):
        if dlp._js_f1086_stmt_decode(payload) is not None:
            bad.append(name + "-hook-hit")
    return (not bad, "%d/4 hook-miss%s"
            % (len(fc) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_f1087_fail_closed():
    c = _codes(SECRET_S)
    fc = [
        "var C=%s;var S='';var K=9;switch(K){case 1:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;default:break;}var RESULT=S;" % c,
        "var C=%s;var S='';var K=1;switch(K){case 1:break;case 1:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;}var RESULT=S;" % c,
        "var C=%s;var S='';var K=1;switch(K){case 1:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;default:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;}var RESULT=S;" % c,
        "var C=%s;var S='';var K=1;switch(1){case 1:for(var I=0;I<C.length;I++){S+=String.fromCharCode(C[I]);}break;}var RESULT=S;" % c,
        "var C=%s;var S='';var K=1;switch(K){}var RESULT=S;" % c,
    ]
    bad = [str(i) for i, p in enumerate(fc)
           if dlp._js_f1087_stmt_decode(p) is not None]
    return (not bad, "%d/5 hook-miss%s"
            % (len(fc) - len(bad), "" if not bad else ": " + ",".join(bad)))


@_t
def test_p4_f1088_fail_closed():
    fc = [
        "var P={...{a:65}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;",
        'var P={...{"__proto__":65}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;',
        "var P={...[65,66]};var S=String.fromCharCode(...Object.values(P));var RESULT=S;",
        "var Q={0:65,1:66};var P={...Q};var S=String.fromCharCode(...Object.values(Q));var RESULT=S;",
        "var P={...Q};var S=String.fromCharCode(...Object.values(P));var RESULT=S;",
        "var P={...{}};var S=String.fromCharCode(...Object.values(P));var RESULT=S;",
    ]
    bad = [str(i) for i, p in enumerate(fc)
           if dlp._js_f1088_stmt_decode(p) is not None]
    return (not bad, "%d/6 hook-miss%s"
            % (len(fc) - len(bad), "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: sibling pins ----------------

@_t
def test_p5_sibling_hooks_hold():
    bad = []
    for prefix, num in (("w399", 1074), ("w399", 1075), ("w399", 1076),
                       ("w399", 1077), ("w399", 1078)):
        shapes = _redfirst_shapes(prefix, num)
        for item in shapes:
            # Some red-firsts carry (name, payload, secret) triples.
            name, payload = item[0], item[1]
            if not _blocked(payload):
                bad.append("%s_f%d:%s" % (prefix, num, name))
    return (not bad, "siblings block%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p6: honest-text controls ----------------

@_t
def test_p6_honest_quiet():
    honest = [
        "(function(){var s='ab';return s;})()",
        "var x = 1 + 2; console.log(x);",
        "function greet(name){return 'hello '+name;}",
        "var C=[1,2,3];var S='';for(var i=0;i<C.length;i++){S+=C[i];}",
        "var P={a:1,b:2};var vs=Object.values(P);",
        "switch(x){case 1:foo();break;default:bar();}",
        "var i=0;while(i<10){i++;}",
    ]
    bad = [h for h in honest if not _misses(h)]
    return (not bad, "%d/7 quiet%s"
            % (len(honest) - len(bad), "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    c = _codes(SECRET_S)
    site = ("var C=%s;var S='';var I=0;do{S+=String.fromCharCode(C[I]);I++;}"
            "while(I<C.length);var RESULT=S;" % c)
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(site)
        dlp.find_credential("var x=1;")
    dt = time.time() - t0
    return (dt < 30, "200 sites x2 in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w399's attack battery (carries F1083-F1089
    open pins). Honor GOV_SKIP_GREEN. On this tree F1086/F1087/F1088 are
    now CLOSED, so exactly their three open-pin tests flip to BREAK;
    every other pin must stay HELD."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w399_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g400lane2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w399_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        real, held = [], []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (real if parts[0] == "BREAK" else held).append(parts[1])
        expect_break = {"test_open_w399_f1086", "test_open_w399_f1087",
                        "test_open_w399_f1088"}
        missing_break = expect_break - set(real)
        extra_break = set(real) - expect_break
        ok = not missing_break and not extra_break
        return (ok,
                "green(w399_attack): %d BREAK, missing=%s extra=%s"
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
