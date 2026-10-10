#!/usr/bin/env python3
"""Wave-403 lane 2 close battery: F1113/F1115/F1116 CLOSED.

F1113: String.prototype.concat loop accumulation -- `S=S.concat(
String.fromCharCode(C[i]))` in an indexed loop broke the decoder's
`+=`-anchored accumulation grammars (F1074 family). Closed by
_js_f1113_stmt_decode: concat-assignment accum parser, node-exact sim
via _js_f1074f1075_sim. Disjoint from F1074 (owns += / S=S+) by the
.concat( anchor.

F1115: String.fromCodePoint loop accumulation -- `S+=String.fromCodePoint(
C[i])` broke the fromCharCode-anchored grammars. Closed by
_js_f1115_stmt_decode: fromCodePoint accum parser; BMP-only (any code
> 0xFFFF fails closed -- fromCodePoint would emit a surrogate pair
there while ToUint16 emits one code unit). Disjoint from F1074 by the
fromCodePoint anchor.

F1116: reorder-staged accumulation -- `R=C.slice().reverse()` then
`String.fromCharCode(...R.reverse())` (double-reverse spread) or a
backwards `for(i=R.length-1;i>=0;i--)` loop over R broke the
order-anchored hooks. Closed by _js_f1116_stmt_decode: two
productions, both node-exact (v24.20.0). Disjoint from the
`...[...C]` copy-spread hook (no .reverse() call) and F1074
(forward C.length loops) by grammar.

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
N_STMTDEC_LOOPS_PIN = 35  # wave-403 lane 2: 34 + 1 dispatch loop

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
    "f1113": dlp._js_f1113_stmt_decode,
    "f1115": dlp._js_f1115_stmt_decode,
    "f1116": dlp._js_f1116_stmt_decode,
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
    ok = ("# Wave-403 lane 2: F1113, F1115, F1116 CLOSED (3); "
          "F1111-F1112, F1114, F1117-F1122 OPEN (9); next free F1123" in text)
    return (ok, "lane-local footer present")


@_t
def test_p1_closed_stamps():
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    stamps = sum(1 for n in (1113, 1115, 1116)
                 if re.search(r"\(F%d filed .*\[CLOSED 2026-10-10 wave-403 lane 2"
                              % n, text))
    ok = stamps == 3
    return (ok, "%d/3 CLOSED stamps" % stamps)


# ---------------- p2: filed shapes block ----------------

@_t
def test_p2_f1113_filed_block():
    shapes = _redfirst_shapes("w403", 1113)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1115_filed_block():
    shapes = _redfirst_shapes("w403", 1115)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2_f1116_filed_block():
    shapes = _redfirst_shapes("w403", 1116)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed shapes blocked%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: node-exact generalizations ----------------

# Generalizations whose decoded output is credential-shaped: must block
# via the full pipeline (node-verified v24.20.0).
_GENERALIZATIONS_BLOCK = [
    # F1113: let/const, unbraced, lte.
    ("f1113", "let C=%s;let S='';for(let i=0;i<C.length;i++){S=S.concat(String.fromCharCode(C[i]));}let RESULT=S;"),
    ("f1113", "var C=%s;var S='';for(var i=0;i<C.length;i++)S=S.concat(String.fromCharCode(C[i]));var RESULT=S;"),
    # F1115: S=S+, let/const.
    ("f1115", "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S+String.fromCodePoint(C[i]);}var RESULT=S;"),
    ("f1115", "let C=%s;let S='';for(let i=0;i<C.length;i++){S+=String.fromCodePoint(C[i]);}let RESULT=S;"),
    # F1116a: let/const.
    ("f1116", "let C=%s;let R=C.slice().reverse();let S=String.fromCharCode(...R.reverse());let RESULT=S;"),
    # F1116b: pre-decrement, S=S+.
    ("f1116", "var C=%s;var R=C.slice().reverse();var S='';for(var i=R.length-1;i>=0;--i){S+=String.fromCharCode(R[i]);}var RESULT=S;"),
    ("f1116", "var C=%s;var R=C.slice().reverse();var S='';for(var i=R.length-1;i>=0;i--){S=S+String.fromCharCode(R[i]);}var RESULT=S;"),
]

# Generalizations whose decoded output is NOT credential-shaped: the
# hook must still decode node-exactly (v24.20.0 verified), pipeline
# stays quiet. Expected values are the node-verified outputs.
_GENERALIZATIONS_NODE = [
    # F1113: start=1 skips first char (not credential-shaped).
    ("f1113", "var C=%s;var S='';for(var i=1;i<C.length;i++){S=S.concat(String.fromCharCode(C[i]));}var RESULT=S;",
     SECRET_S[1:]),
    # F1115: <= OOB -> \0 (F1046 precedent).
    ("f1115", "var C=%s;var S='';for(var i=0;i<=C.length;i++){S+=String.fromCodePoint(C[i]);}var RESULT=S;",
     SECRET_S + "\x00"),
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
    # F1113 narrow grammar.
    ("f1113", "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1113", "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S.concat(String.fromCharCode(C[i]),'x');}var RESULT=S;"),
    ("f1113", "var C=%s;var S='';for(var i=0;i<C.length;i++){S.concat(String.fromCharCode(C[i]));}var RESULT=S;"),
    ("f1113", "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S.concat(C[i]);}var RESULT=S;"),
    # F1115 narrow grammar.
    ("f1115", "var C=[0x1F600];var S='';for(var i=0;i<C.length;i++){S+=String.fromCodePoint(C[i]);}var RESULT=S;"),
    ("f1115", "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
    ("f1115", "var C=%s;var S=String.fromCodePoint(...C);var RESULT=S;"),
    # F1116 narrow grammar.
    ("f1116", "var C=%s;var R=C.reverse();var S=String.fromCharCode(...R.reverse());var RESULT=S;"),
    ("f1116", "var C=%s;var R=C.slice();var S=String.fromCharCode(...R.reverse());var RESULT=S;"),
    ("f1116", "var C=%s;var R=C.slice().reverse();var S=String.fromCharCode(...R);var RESULT=S;"),
    ("f1116", "var C=%s;var R=C.slice().reverse();var S='';for(var i=R.length-1;i>=0;i--)S+=String.fromCharCode(R[i]);var RESULT=S;"),
    ("f1116", "var C=%s;var R=C.slice().reverse();var S='';for(var i=0;i<R.length;i++){S+=String.fromCharCode(R[i]);}var RESULT=S;"),
    # F1116: empty array fails closed (F1074 convention; '' can't match).
    ("f1116", "var C=[];var R=C.slice().reverse();var S='';for(var i=R.length-1;i>=0;i--){S+=String.fromCharCode(R[i]);}var RESULT=S;"),
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
        # Sibling hooks vs my shapes.
        (dlp._js_f1074_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S=S.concat(String.fromCharCode(C[i]));}var RESULT=S;"),
        (dlp._js_f1074_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCodePoint(C[i]);}var RESULT=S;"),
        (dlp._js_f1074_stmt_decode,
         "var C=%s;var R=C.slice().reverse();var S=String.fromCharCode(...R.reverse());var RESULT=S;"),
        # My hooks vs sibling shapes.
        (dlp._js_f1113_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
        (dlp._js_f1115_stmt_decode,
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;"),
        (dlp._js_f1116_stmt_decode,
         "var C=%s;var S=String.fromCharCode(...C);var RESULT=S;"),
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
    shapes = [
        # F1074 plain accumulation still blocks via F1074.
        "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;" % _codes(SECRET_S),
        # F505 fromCodePoint spread still blocks.
        "var RESULT=String.fromCodePoint(...%s);" % _codes(SECRET_S),
    ]
    bad = [p[:40] for p in shapes if not _blocked(p)]
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p5_still_open_miss():
    """F1111, F1114, F1117 are still OPEN on this lane tree (filed shapes)."""
    shapes = [
        # F1111 Array.prototype.flat staged reads (filed shape).
        "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;" % _codes(SECRET_S),
        # F1114 Object.freeze-wrapped staged reads (filed shapes).
        "var C=Object.freeze(%s);var S=String.fromCharCode(...C);var RESULT=S;" % _codes(SECRET_S),
        "var S=String.fromCharCode(...Object.freeze(%s));var RESULT=S;" % _codes(SECRET_S),
        # F1117 with-scope staged spread reads (filed shapes).
        "var C=%s;var S='';with({}){S=String.fromCharCode(...C);}var RESULT=S;" % _codes(SECRET_S),
        "var C=%s;var S='';with({C:C}){S=String.fromCharCode(...C);}var RESULT=S;" % _codes(SECRET_S),
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
        "var x = [1,2,3].slice().reverse(); // reverse a copy",
        "email the quarterly report to the team",
        "var s = s.concat('suffix'); // string concat",
        "for (var i = arr.length - 1; i >= 0; i--) { sum += arr[i]; }",
        "String.fromCodePoint(65) is 'A'",
    ]
    bad = [t[:30] for t in texts if not _misses(t)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(texts) - len(bad), len(texts),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf_200_sites():
    t0 = time.time()
    site = ("var C=%s;var S='';for(var i=0;i<C.length;i++)"
            "{S+=String.fromCharCode(C[i]);}var RESULT=S;" % _codes(SECRET_S))
    for _ in range(200):
        dlp.find_credential(site)
    dt = time.time() - t0
    return (dt < 30, "200 sites in %.2fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w402's attack battery. Honor GOV_SKIP_GREEN.

    On this lane tree F1113/F1115/F1116 are closed, so exactly those 3
    open pins must BREAK (shapes now blocked); everything else HELD.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w402_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g403lane2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w402_attack_probes.py", "--tally-only"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        broken = []
        for line in r.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "BREAK":
                broken.append(parts[1])
        want = {"test_open_w402_f1113", "test_open_w402_f1115",
                "test_open_w402_f1116"}
        ok = set(broken) == want
        return (ok, "green(w402_attack): BREAK=%s (expect %s)"
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
