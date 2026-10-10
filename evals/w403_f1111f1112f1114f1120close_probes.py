#!/usr/bin/env python3
"""Wave-403 lane 1 close battery: F1111/F1112/F1114/F1120 CLOSED.

F1111: Array.prototype.flat staged reads -- `String.fromCharCode(...C.flat())`
over a flat or nested int array broke the decoder's spread/call-anchored hook
grammars (F1030 models only the inline-literal `...[[codes]].flat()`; F1090 is
flatMap-anchored). Closed by _js_f1111_stmt_decode: flat + nested-chunk
productions, optional depth >= 1 (depth 0/negative fail closed), node-exact.

F1112: TypedArray staged reads -- `Uint16Array.from(C)` / `Uint8Array.from(C)`
then `String.fromCharCode(...T)` broke the hooks (the `...new Uint16Array(C)`
twin blocks coded). Closed by _js_f1112_stmt_decode: u16 identity, u8
ToUint8 (mod 256, node-verified), node-exact.

F1114: Object.freeze-wrapped staged reads -- `Object.freeze([codes])` (bound
or inline) broke the literal/identifier-anchored spread hooks (unfrozen twin
blocks coded). Closed by _js_f1114_stmt_decode: freeze returns its argument
node-exactly.

F1120: array-copy staged spread reads -- `...C.slice()`, `...D` with
`D=[].concat(C)`, `...Array.of(...C)` broke the spread hooks (the
`...[...C]` literal-copy twin blocks coded). Closed by
_js_f1120_stmt_decode: three copy-call productions, node-exact identity.

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
N_STMTDEC_LOOPS_PIN = 38  # wave-403 merge: 34 + 4 loops -> 38 (was lane 1-local 35)

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
    ok = ("F988-F1110 CLOSED (123" in text
          and "Next free finding: **F1123**" in text)
    return (ok, "footer: F988-F1110 CLOSED (123), next F1123")


@_t
def test_p1_footer_open_span():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("F1111-F1122 OPEN (12" in text)
    return (ok, "footer: F1111-F1122 OPEN (12)")


@_t
def test_p1_lane_footer():
    # Lane-local footer written at stamp time (before merge).
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ok = ("# Wave-403 lane 1: F1111, F1112, F1114, F1120 CLOSED (4)" in text
          and "F1113, F1115-F1119, F1121-F1122 OPEN (8)" in text)
    return (ok, "lane-local footer present")


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1111_filed_block():
    shapes = _redfirst_shapes("w402", 1111)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1112_filed_block():
    shapes = _redfirst_shapes("w402", 1112)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1114_filed_block():
    shapes = _redfirst_shapes("w402", 1114)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1120_filed_block():
    shapes = _redfirst_shapes("w402", 1120)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

# Generalizations whose decoded output is credential-shaped: must block
# via the full pipeline. Hook-level node-exactness asserted separately.
_GENERALIZATIONS = [
    # (hook-name, template, expected-decoded)
    ("f1111", "let C=%s;let S=String.fromCharCode(...C.flat());let RESULT=S;",
     SECRET_S),
    ("f1111", "const D=%s;const T=String.fromCharCode(...D.flat(2));const RESULT=T;",
     SECRET_S),
    ("f1111", "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT='p'+S;",
     "p" + SECRET_S),
    ("f1112", "let C=%s;let T=Uint16Array.from(C);let S=String.fromCharCode(...T);let RESULT=S;",
     SECRET_S),
    ("f1112", "const C=%s;const T=Uint8Array.from(C);const S=String.fromCharCode(...T);const RESULT=S;",
     SECRET_S),
    ("f1114", "let C=Object.freeze(%s);let S=String.fromCharCode(...C);let RESULT=S;",
     SECRET_S),
    ("f1114", "const S=String.fromCharCode(...Object.freeze(%s));const RESULT=S;",
     SECRET_S),
    ("f1120", "let C=%s;let S=String.fromCharCode(...C.slice());let RESULT=S;",
     SECRET_S),
    ("f1120", "var C=%s;var D=[].concat(C);var S=String.fromCharCode(...D);var RESULT='q'+S;",
     "q" + SECRET_S),
    ("f1120", "const C=%s;const S=String.fromCharCode(...Array.of(...C));const RESULT=S;",
     SECRET_S),
]

_HOOKS = {
    "f1111": dlp._js_f1111_stmt_decode,
    "f1112": dlp._js_f1112_stmt_decode,
    "f1114": dlp._js_f1114_stmt_decode,
    "f1120": dlp._js_f1120_stmt_decode,
}


@_t
def test_p3_generalizations_block():
    bad = []
    for hook, tmpl, want in _GENERALIZATIONS:
        payload = tmpl % _codes(SECRET_S)
        if not _blocked(payload):
            bad.append(hook + ":" + payload[:40])
    return (not bad, "%d/%d generalizations blocked%s"
            % (len(_GENERALIZATIONS) - len(bad), len(_GENERALIZATIONS),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_generalizations_node_exact():
    bad = []
    for hook, tmpl, want in _GENERALIZATIONS:
        payload = tmpl % _codes(SECRET_S)
        got = _HOOKS[hook](payload)
        if got != want:
            bad.append("%s: got %r want %r" % (hook, got, want))
    return (not bad, "%d/%d node-exact%s"
            % (len(_GENERALIZATIONS) - len(bad), len(_GENERALIZATIONS),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_u8_mod256_node_exact():
    # Uint8Array.from applies ToUint8 (mod 256); the hook must model it
    # node-exactly, not just for in-range codes.
    payload = ("var C=[300,511,45];var T=Uint8Array.from(C);"
               "var S=String.fromCharCode(...T);var RESULT=S;")
    got = dlp._js_f1112_stmt_decode(payload)
    want = chr(44) + chr(255) + chr(45)
    ok = got == want
    return (ok, "u8 mod-256: got %r want %r" % (got, want))


# ---------------- p4: fail-closed bounds + disjointness ----------------

_FAIL_CLOSED = [
    # (hook-name, payload) -- each must MISS at hook level.
    ("f1111", "var C=%s;var S=String.fromCharCode(...C.flat(0));var RESULT=S;"),  # depth 0
    ("f1111", "var C=%s;var S=String.fromCharCode(...C.flat(-1));var RESULT=S;"),  # negative depth
    ("f1111", "var C=%s;var S=String.fromCharCode(...C.flatMap(x=>x));var RESULT=S;"),  # flatMap -> F1090
    ("f1111", "var C=[[%s]];var S=String.fromCharCode(...C.flat());var RESULT=S;"),  # deeper nesting
    ("f1111", "var C=%s;var S=String.fromCharCode(...C.flat());"),  # no RESULT
    ("f1112", "var C=%s;var T=Uint16Array.from(D);var S=String.fromCharCode(...T);var RESULT=S;"),  # arg mismatch
    ("f1112", "var C=%s;var T=new Uint16Array(C);var S=String.fromCharCode(...T);var RESULT=S;"),  # new -> twin
    ("f1112", "var C=%s;var T=Uint16Array.of(...C);var S=String.fromCharCode(...T);var RESULT=S;"),  # .of not .from
    ("f1114", "var C=Object.seal(%s);var S=String.fromCharCode(...C);var RESULT=S;"),  # seal not freeze
    ("f1114", "var C=Object.freeze(%s);var S=String.fromCharCode(...D);var RESULT=S;"),  # base mismatch
    ("f1114", "var C=Object.freeze();var S=String.fromCharCode(...C);var RESULT=S;"),  # no array
    ("f1120", "var C=%s;var S=String.fromCharCode(...C.slice(0));var RESULT=S;"),  # slice(0) args
    ("f1120", "var C=%s;var S=String.fromCharCode(...C.sort());var RESULT=S;"),  # sort not a copy
    ("f1120", "var C=%s;var D=[].concat(D);var S=String.fromCharCode(...D);var RESULT=S;"),  # concat arg mismatch
    ("f1120", "var C=%s;var S=String.fromCharCode(...Array.from(C));var RESULT=S;"),  # Array.from not of
]


@_t
def test_p4_fail_closed():
    bad = []
    for hook, tmpl in _FAIL_CLOSED:
        # Every template takes the flat code array; the deeper-nesting
        # template wraps it as [[<codes>]] -> triple-nested input.
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
        # My hooks vs sibling shapes (must MISS).
        (dlp._js_f1111_stmt_decode,
         "var s=String.fromCharCode(...[[%s]].flat());var RESULT=s;"),  # F1030 inline
        (dlp._js_f1111_stmt_decode,
         "var C=%s;var S=C.flatMap(function(c){return [String.fromCharCode(c)];}).join('');var RESULT=S;"),  # F1090
        (dlp._js_f1112_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...new Uint16Array(C));var RESULT=S;"),  # new-twin
        (dlp._js_f1114_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...C);var RESULT=S;"),  # unfrozen twin
        (dlp._js_f1120_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...[...C]);var RESULT=S;"),  # literal-copy twin
        (dlp._js_f1111_stmt_decode,
         "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),  # F1066
        # Sibling hooks vs my shapes (must MISS).
        (dlp._js_f1030_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;"),
        (dlp._js_f1090_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;"),
        (dlp._js_f1066_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...C.slice());var RESULT=S;"),
    ]
    bad = []
    for hook, tmpl in pairs:
        # The F1030 template takes bare codes (no brackets); the rest
        # take the bracketed array.
        arg = ",".join(str(ord(c)) for c in SECRET_S) if "[[%s]]" in tmpl else _codes(SECRET_S)
        payload = tmpl % arg
        if hook(payload) is not None:
            bad.append(hook.__name__)
    return (not bad, "%d/%d disjoint%s"
            % (len(pairs) - len(bad), len(pairs),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: sibling pins ----------------

@_t
def test_p5_sibling_hooks_hold():
    shapes = [
        # F1030 inline-literal flat still blocks via F1030 (filed shapes
        # use lowercase s; %s here is the bare code list).
        "var s=String.fromCharCode(...[[%s]].flat());var RESULT=s;",
        # F1090 flatMap still blocks via F1090.
        "var C=%s;var S=C.flatMap(function(c){return [String.fromCharCode(c)];}).join('');var RESULT=S;",
        # The ...new Uint16Array(C) twin still blocks.
        "var C=%s;var S=String.fromCharCode(...new Uint16Array(C));var RESULT=S;",
        # The unfrozen twin still blocks.
        "var C=%s;var S=String.fromCharCode(...C);var RESULT=S;",
        # The ...[...C] literal-copy twin still blocks.
        "var C=%s;var S=String.fromCharCode(...[...C]);var RESULT=S;",
        # F1066 whole-array apply still blocks.
        "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;",
    ]
    bad = []
    for p in shapes:
        # The F1030 template takes bare codes (no brackets); the rest
        # take the bracketed array.
        arg = ",".join(str(ord(c)) for c in SECRET_S) if "[[%s]]" in p else _codes(SECRET_S)
        payload = p % arg
        if not _blocked(payload):
            bad.append(p[:40])
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p5_still_open_miss():
    """Lane scope: F1113, F1115-F1119, F1121-F1122 stay OPEN (other lanes)."""
    shapes = [
        # F1113 concat loop (lane 2 scope).
        "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S.concat(String.fromCharCode(C[i]));}var RESULT=S;",
        # F1115 fromCodePoint loop (lane 2 scope).
        "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCodePoint(C[i]);}var RESULT=S;",
        # F1121 top-level for-await (lane 4 scope).
        "var C=%s;var S='';for await (var x of C){S+=String.fromCharCode(x);}var RESULT=S;",
    ]
    bad = [p[:40] for p in shapes if _blocked(p % _codes(SECRET_S))]
    return (not bad, "%d/%d still-open miss%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: honest-text controls ----------------

@_t
def test_p6_honest_quiet():
    texts = [
        "(function(){var s='ab';return s;})()",
        "var arr = [1,2,3]; var t = new Uint16Array(arr);",
        "Object.freeze(config);",
        "var copy = original.slice();",
        "email the quarterly report to the team",
        "for (var i = 0; i < 10; i++) { console.log(i); }",
        "var s = String.fromCharCode.apply(null, arr);",
    ]
    bad = [t[:30] for t in texts if not _misses(t)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(texts) - len(bad), len(texts),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    t0 = time.time()
    site = ("var C=%s;var S=String.fromCharCode(...C.flat());"
            "var RESULT=S;" % _codes(SECRET_S))
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w402's attack battery.

    On this lane tree exactly the 4 closed findings' open pins must flip
    (test_open_w402_f1111/f1112/f1114/f1120 -> BREAK = now blocked);
    every other pin must stay HELD. Honor GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w402_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g403lane1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w402_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        # --tally-only prints only the tally; re-run without it for verdicts.
        r = subprocess.run(
            [sys.executable, "evals/w402_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        breaks = set()
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "BREAK":
                breaks.add(parts[1])
        expect = {"test_open_w402_f1111", "test_open_w402_f1112",
                  "test_open_w402_f1114", "test_open_w402_f1120"}
        ok = breaks == expect
        return (ok, "green(w402_attack): BREAK=%s (expect %s)"
                % (sorted(breaks), sorted(expect)))
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
