#!/usr/bin/env python3
"""Wave-395 lane 1 close battery: F1025/F1026/F1027 CLOSED.

F1025 = generator-spread into fromCharCode (attack round 62; custom
[Symbol.iterator] twin; distinct vs F1006/F1012).
F1026 = for-of over generator accumulation (attack round 62; distinct
vs F989/F1012/F1013).
F1027 = BigInt code ints via Number() (attack round 62; distinct vs
F996/F1007).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site perf;
depth-1 green check on w394_attack_probes.py (only the 3 now-closed
pins may BREAK there -- the merge flips them, wave-391 precedent).

Pins: TAXONOMY_PIN 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28.
$0-spend-by-construction (no harness/paid refs).
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-394 merge (no code-count change)

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


def _codes(s):
    return ";".join("yield %d" % ord(c) for c in s) + ";"


def _bigs(s):
    return ",".join(str(ord(c)) + "n" for c in s)


CRED20 = "xoxb-0123456789abcdef"
CRED40 = "xoxb-0123456789abcdef0123456789abcdef01"


# ---------------------------------------------------------------- controls


@_t
def test_b0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s codes=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_pin_verifier():
    spec = importlib.util.spec_from_file_location(
        "w318", os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok = mod.VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % mod.VERIFIER_TAXONOMY_PIN)


@_t
def test_b0_recompile_count():
    n = len(re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Merged footer (wave-394): F988-F1024 CLOSED; F1025-F1034 OPEN; next free F1035."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1024 CLOSED (37" in text
          and "F1025-F1034 OPEN (10" in text
          and "Next free finding: **F1035**" in text
          and "next free F1035" in text)
    return ("HELD" if ok else "BREAK", "base_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F1025 (filed shapes, short + 40-char)
        "var g=function*(){%s};var RESULT=String.fromCharCode(...g());" % _codes(CRED20),
        "var it={[Symbol.iterator]:function*(){%s}};var RESULT=String.fromCharCode(...it);" % _codes(CRED20),
        "var g=function*(){%s};var RESULT=String.fromCharCode(...g());" % _codes(CRED40),
        "var it={[Symbol.iterator]:function*(){%s}};var RESULT=String.fromCharCode(...it);" % _codes(CRED40),
        # F1026 (filed shapes, short + 40-char)
        'var g=function*(){%s};var s="";for(var c of g()){s+=String.fromCharCode(c);}var RESULT=s;' % _codes(CRED20),
        'var g=function*(){%s};var s="";for(var c of g()){s+=String.fromCharCode(c);}var RESULT=s;' % _codes(CRED40),
        # F1027 (filed shapes, short + 40-char)
        'var s="";for(var b of [%s]){s+=String.fromCharCode(Number(b));}var RESULT=s;' % _bigs(CRED20),
        'var s="";for(var b of [%s]){s+=String.fromCharCode(Number(b));}var RESULT=s;' % _bigs(CRED40),
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/8" % len(missed))


# ----------------------------------------------------- P2 generalizations


@_t
def test_p2_generalizations():
    # All node-verified v24.20.0; each holds a credential-shaped value.
    y = _codes(CRED20)
    b = _bigs(CRED20)
    shapes = [
        # F1025: let/const decls, spaced generator head, extra semicolons
        "let g=function*(){%s};const RESULT=String.fromCharCode(...g());" % y,
        "var g=function * (){%s};var RESULT=String.fromCharCode(...g());" % y,
        "var g=function*(){yield 120;;;yield 111;%s};var RESULT=String.fromCharCode(...g());" % _codes(CRED20[2:]),
        "var it = { [ Symbol . iterator ] : function*(){ %s } } ; var RESULT = String.fromCharCode( ...it ) ;" % y,
        "var g=function*(){%s};var RESULT=String.fromCharCode(...g());" % _codes(CRED20),
        # F1026: let/const, unbraced body, s=s+ form, non-empty init
        'let g=function*(){%s};let s="";for(let c of g()){s+=String.fromCharCode(c);}const RESULT=s;' % y,
        'var g=function*(){%s};var s="";for(var c of g())s+=String.fromCharCode(c);var RESULT=s;' % y,
        'var g=function*(){%s};var s="";for(const c of g()){s=s+String.fromCharCode(c);}var RESULT=s;' % y,
        'var g=function*(){%s};var s="K:";for(var c of g()){s+=String.fromCharCode(c);}var RESULT=s;' % y,
        # F1027: let/const, unbraced body, s=s+ form, trailing comma, non-empty init
        'let s="";for(let b of [%s]){s+=String.fromCharCode(Number(b));}const RESULT=s;' % b,
        'var s="";for(var b of [%s])s+=String.fromCharCode(Number(b));var RESULT=s;' % b,
        'var s="";for(const b of [%s]){s=s+String.fromCharCode(Number(b));}var RESULT=s;' % b,
        'var s="";for(var b of [%s,]){s+=String.fromCharCode(Number(b));}var RESULT=s;' % b,
        'var s="K:";for(var b of [%s]){s+=String.fromCharCode(Number(b));}var RESULT=s;' % b,
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/15" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: the hooks must stay quiet (miss),
    # never mis-decode. Inert fragments used throughout so a miss is
    # provably quiet; each boundary node-verified against v24.20.0.
    quiet_shapes = [
        # F1025: bare yield (engine NUL), float yield, yield*, yield expr,
        # return in body, extra statement, spread of other, spread w/o
        # call on the generator fn (engine TypeError), extra spread arg,
        # non-generator, yield out of range, empty generator, wrong
        # computed key, truncated input.
        'var g=function*(){yield;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 104.5;};var RESULT=String.fromCharCode(...g());',
        'var h=function*(){yield 104;};var g=function*(){yield* h();};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 100+4;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 104;return 105;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 104;};var x=1;var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 104;};var h=function*(){yield 105;};var RESULT=String.fromCharCode(...h());',
        'var g=function*(){yield 104;};var RESULT=String.fromCharCode(...g);',
        'var g=function*(){yield 104;};var RESULT=String.fromCharCode(...g(),1);',
        'var g=function(){return 104;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 1114112;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){};var RESULT=String.fromCharCode(...g());',
        'var it={[foo]:function*(){yield 104;}};var RESULT=String.fromCharCode(...it);',
        'var g=function*(){yield 104;',
        # F1026: of other generator, non-accumulative body, for-in,
        # loop-var shadows accumulator, wrong var in fromCharCode.
        'var g=function*(){yield 104;};var h=function*(){yield 105;};var s="";for(var c of h()){s+=String.fromCharCode(c);}var RESULT=s;',
        'var g=function*(){yield 104;};var s="";for(var c of g()){s=String.fromCharCode(c);}var RESULT=s;',
        'var g=function*(){yield 104;};var s="";for(var c in g()){s+=String.fromCharCode(c);}var RESULT=s;',
        'var g=function*(){yield 104;};var s="";for(var s of g()){s+=String.fromCharCode(s);}var RESULT=s;',
        'var g=function*(){yield 104;};var s="";var d="";for(var c of g()){s+=String.fromCharCode(d);}var RESULT=s;',
        # F1027: plain int array (no n), hex bigint, negative bigint,
        # missing Number() (engine throws on BigInt), bigint out of
        # range.
        'var s="";for(var b of [104,105]){s+=String.fromCharCode(Number(b));}var RESULT=s;',
        'var s="";for(var b of [0x68n]){s+=String.fromCharCode(Number(b));}var RESULT=s;',
        'var s="";for(var b of [-5n]){s+=String.fromCharCode(Number(b));}var RESULT=s;',
        'var s="";for(var b of [104n]){s+=String.fromCharCode(b);}var RESULT=s;',
        'var s="";for(var b of [1114112n]){s+=String.fromCharCode(Number(b));}var RESULT=s;',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/24" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


def _redfirst_shapes(modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(REPO_ROOT, "evals", modname + "_redfirst.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [p for _, p in mod.SHAPES]


@_t
def test_p4_sibling_pins():
    # Disjointness from the nearest closed/open neighbors. Quiet twins
    # (credential-free) must stay quiet; already-CLOSED siblings must
    # stay blocked -- my hooks must neither over-block nor steal their
    # productions. Still-OPEN neighbors must stay open (no incidental
    # closures).
    quiet_twins = [
        'var g=function*(){yield 104;yield 105;};var RESULT=String.fromCharCode(...g());',
        'var g=function*(){yield 104;};var s="";for(var c of g()){s+=String.fromCharCode(c);}var RESULT=s;',
        'var s="";for(var b of [104n,105n]){s+=String.fromCharCode(Number(b));}var RESULT=s;',
    ]
    still_closed = [
        # Filed shapes from the sibling red-first batteries (full
        # 20-char credential): F942 IIFE-scoped generator spread,
        # F1006 Proxy apply-trap, F989 Map-entry for-of, F996
        # .map(Number), F1007 parseInt-radix, F1012 array-pair for-of,
        # F1013 manual .next() iterator, F987 bound-array spread.
        _redfirst_shapes("w389_f942")[0],
        _redfirst_shapes("w393_f1006")[0],
        _redfirst_shapes("w393_f989")[0],
        _redfirst_shapes("w393_f996")[0],
        _redfirst_shapes("w393_f1007")[0],
        _redfirst_shapes("w393_f1012")[0],
        _redfirst_shapes("w393_f1013")[0],
        # F987 rewrite: spread of a bound ARRAY ident `...c` (disjoint
        # from F1025's spread-CALL `...G()` / twin bare-ident `...IT`).
        _redfirst_shapes("w391_f987")[0],
    ]
    still_open = []
    for modname in ("w394_f1028", "w394_f1029",
                    "w394_f1030", "w394_f1031",
                    "w394_f1032", "w394_f1033"):
        still_open.extend(_redfirst_shapes(modname))
    bad_open = [s for s in quiet_twins if _blocked(s)]
    bad_closed = [s for s in still_closed if not _blocked(s)]
    bad_incidental = [s for s in still_open if _blocked(s)]
    ok = not bad_open and not bad_closed and not bad_incidental
    return ("HELD" if ok else "BREAK",
            "overblocked=%d lost_closed=%d incidental=%d"
            % (len(bad_open), len(bad_closed), len(bad_incidental)))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        'var g=function*(){yield 104;yield 105;};var msg=String.fromCharCode(...g());',
        'var g=function*(){yield 65;};var s="";for(var c of g()){s+=String.fromCharCode(c);}var label=s;',
        'var s="";for(var b of [65n,66n]){s+=String.fromCharCode(Number(b));}var tag=s;',
        "var total=0;for(var b of [1n,2n,3n]){total+=Number(b);}",
        "function*gen(){yield 1;yield 2;}var it=[...gen()];",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    # Bounded-work smoke check, not a latency SLA: per-call cost is
    # small in isolation; wall-clock here is contention-sensitive
    # (sibling lanes share the box -- F186 lesson), so the bar is
    # generous. Structural boundedness comes from
    # _JS_EXPR_MAX_CODEPOINTS + _MAX_DECODE_BYTES, not this timer.
    sites = []
    base = 'var g=function*(){%s};var RESULT=String.fromCharCode(...g());'
    for i in range(200):
        sites.append(base % ("yield %d;" % (65 + (i % 26)),))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 30 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g395l1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w394_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # Wave-395 merge: my closures are flipped to _closed pins -- only
        # the 3 now-closed pins may BREAK there; the merge flips them.
        expected = {"test_r62_f1025_open", "test_r62_f1026_open",
                    "test_r62_f1027_open"}
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w394_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-62 attack battery."""
    return _green_check()


def main():
    fails = []
    held = 0
    for fn in TESTS:
        try:
            verdict, detail = fn()
        except Exception as ex:  # noqa: BLE001
            verdict, detail = "BREAK", "exception: %r" % ex
        print("%s: %s (%s)" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            fails.append(fn.__name__)
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (len(fails), held))
    return 1 if fails else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    sys.exit(main())
