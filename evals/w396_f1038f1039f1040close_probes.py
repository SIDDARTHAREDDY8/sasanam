#!/usr/bin/env python3
"""Wave-396 lane 2 close battery: F1038/F1039/F1040 CLOSED.

F1038 = Set-union-staged index-pair reads (attack round 63; distinct
vs F494's Set production (fails closed on nested-array elements) and
F1028's `new WeakMap` anchor).
F1039 = Atomics/SharedArrayBuffer code accumulation (attack round 63;
`new Int32Array(new SharedArrayBuffer(` anchor unique).
F1040 = built-in-iterator spread into fromCharCode (attack round 63;
distinct vs F1025's generator-call/custom-iterable spread --
re-audited still MISS on the merged tree -- vs F1013's for-of/
while-next head, vs F989's `for(` head).

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected; honest text quiet; 200-site
perf; depth-1 green check on w395_attack_probes.py (only the 3
now-closed pins may BREAK there -- the merge flips them, wave-395
precedent).

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

TAXONOMY_PIN = 2143  # wave-395 merge (no code-count change)

from gov import dlp  # noqa: E402
from gov.instruction_provenance import instruction_shaped  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# Credential-shaped code arrays from the filed shapes (21-char and
# 40-char test credentials, ints only -- not secrets).
CODES21 = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56,
           57, 97, 98, 99, 100, 101, 102]
CODES40 = CODES21 + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99,
                     100, 101, 102, 48, 49, 50]


def _arr(codes):
    return "[" + ",".join(str(c) for c in codes) + "]"


def _pairs(codes, start=0):
    return "[" + ",".join("[%d,%d]" % (i, c) for i, c in enumerate(codes, start)) + "]"


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
    """Base footer (wave-395): F988-F1034 CLOSED (47); F1035-F1047 OPEN (13); next free F1048."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1034 CLOSED (47" in text
          and "F1035-F1047 OPEN (13" in text
          and "Next free finding: **F1048**" in text)
    return ("HELD" if ok else "BREAK", "base_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F1038 (filed: 21-char + 40-char)
        'var u=new Set([...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'
        % (_pairs(CODES21[:10]), _pairs(CODES21[10:], 10)),
        # F1038 s1 filed verbatim (40-char split 20/20)
        'var u=new Set([...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'
        % (_pairs(CODES40[:20]), _pairs(CODES40[20:], 20)),
        # F1039 (filed: 21-char + 40-char)
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(160));var c=%s;for(var i=0;i<40;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<40;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES40),
        # F1040 (filed: Map.values 21 + 40-char, Array.values 21-char)
        'var m=new Map();%s.forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());' % _arr(CODES21),
        'var m=new Map();%s.forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());' % _arr(CODES40),
        'var RESULT=String.fromCharCode(...%s.values());' % _arr(CODES21),
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/7" % len(missed))


# ----------------------------------------------------- P2 generalizations


@_t
def test_p2_generalizations():
    # All node-verified v24.20.0; each holds a credential-shaped value.
    p21a, p21b = _pairs(CODES21[:10]), _pairs(CODES21[10:], 10)
    shapes = [
        # F1038: let/const, spaced tokens, unbraced body, s=s+ form,
        # non-empty init, 3 inner sets, duplicate index (stable)
        'let u=new Set([...new Set(%s),...new Set(%s)]);let all=[...u];all.sort(function(a,b){return a[0]-b[0];});let s="";for(let p of all){s+=String.fromCharCode(p[1]);}let RESULT=s;' % (p21a, p21b),
        'var u = new Set( [ ...new Set( %s ) , ...new Set( %s ) ] ) ; var all = [ ...u ] ; all.sort( function( x , y ) { return x[ 0 ] - y[ 0 ] ; } ) ; var s = "" ; for( var p of all ) { s += String.fromCharCode( p[ 1 ] ) ; } var RESULT = s ;' % (p21a, p21b),
        'var u=new Set([...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all)s+=String.fromCharCode(p[1]);var RESULT=s;' % (p21a, p21b),
        'var u=new Set([...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s=s+String.fromCharCode(p[1]);}var RESULT=s;' % (p21a, p21b),
        'var u=new Set([...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="K:";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;' % (p21a, p21b),
        'var u=new Set([...new Set(%s),...new Set(%s),...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'
        % (_pairs(CODES21[:7]), _pairs(CODES21[7:14], 7), _pairs(CODES21[14:], 14)),
        'var u=new Set([...new Set(%s)]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;'
        % _pairs(list(reversed(CODES21))),
        # F1039: ++i, braceless, s=s+ form, let, oversized buffer,
        # non-empty init, distinct loop vars
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;++i){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;i++)Atomics.store(b,i,c[i]);var s="";for(var i=0;i<21;i++)s+=String.fromCharCode(Atomics.load(b,i));var RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<21;i++){s=s+String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES21),
        'let b=new Int32Array(new SharedArrayBuffer(84));let c=%s;for(let i=0;i<21;i++){Atomics.store(b,i,c[i]);}let s="";for(let i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}let RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(400));var c=%s;for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="K:";for(var i=0;i<21;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;' % _arr(CODES21),
        'var b=new Int32Array(new SharedArrayBuffer(84));var c=%s;for(var i=0;i<21;i++){Atomics.store(b,i,c[i]);}var s="";for(var k=0;k<21;k++){s+=String.fromCharCode(Atomics.load(b,k));}var RESULT=s;' % _arr(CODES21),
        # F1040: new Map no parens, let/const, spaced tokens
        'var m=new Map;%s.forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());' % _arr(CODES21),
        'const m=new Map();%s.forEach(function(c,i){m.set(i,c);});const RESULT=String.fromCharCode(...m.values());' % _arr(CODES21),
        'var m = new Map() ; %s . forEach( function( c , i ) { m.set( i , c ) ; } ) ; var RESULT = String.fromCharCode( ...m.values() ) ;' % _arr(CODES21),
        'let RESULT=String.fromCharCode(...%s.values());' % _arr(CODES21),
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/18" % len(missed))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: the hooks must stay quiet (miss),
    # never mis-decode. Each boundary node-verified against v24.20.0.
    quiet_shapes = [
        # F1038: wrong comparator, missing sort, name collision,
        # p[0] read, RESULT as set name, extra statement, WeakMap
        'var u=new Set([...new Set([[0,65]])]);var all=[...u];all.sort(function(x,y){return x[1]-y[1];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;',
        'var u=new Set([...new Set([[0,65]])]);var all=[...u];var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;',
        'var u=new Set([...new Set([[0,65]])]);var u=[...u];u.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of u){s+=String.fromCharCode(p[1]);}var RESULT=s;',
        'var u=new Set([...new Set([[0,65]])]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[0]);}var RESULT=s;',
        'var u=new Set([...new Set([[0,65]])]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var s2=s;var RESULT=s2;',
        # F1039: const counter (engine throws), undersized buffer,
        # bound mismatch, extra store arg, wrong index, no store loop
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];for(const i=0;i<2;i++){Atomics.store(b,i,c[i]);}var s="";for(const i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(4));var c=[65,66];for(var i=0;i<2;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];for(var i=0;i<3;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<3;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];for(var i=0;i<2;i++){Atomics.store(b,i,c[i],0);}var s="";for(var i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];for(var i=0;i<2;i++){Atomics.store(b,i,c[0]);}var s="";for(var i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];var s="";for(var i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        # F1040: entries(), bare spread (F1025 territory -- must not
        # match mine), swapped set args, arrow callback, keys()
        'var m=new Map();[65,66].forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.entries());',
        'var m=new Map();[65,66].forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m);',
        'var m=new Map();[65,66].forEach(function(c,i){m.set(c,i);});var RESULT=String.fromCharCode(...m.values());',
        'var m=new Map();[65,66].forEach((c,i)=>m.set(i,c));var RESULT=String.fromCharCode(...m.values());',
        'var RESULT=String.fromCharCode(...[65,66].keys());',
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/16" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


def _redfirst_shapes(modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(REPO_ROOT, "evals", modname + "_redfirst.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # SHAPES entries are (name, payload) or (name, payload, ...).
    return [entry[1] for entry in mod.SHAPES]


@_t
def test_p4_sibling_pins():
    # Disjointness from the nearest closed neighbors. Quiet twins
    # (credential-free) must stay quiet; already-CLOSED siblings must
    # stay blocked -- my hooks must neither over-block nor steal their
    # productions. Wave-396 merge: the still-OPEN neighbors are now
    # CLOSED -- their filed shapes must block (dlp seam) or route
    # (F1047 provenance seam).
    quiet_twins = [
        'var u=new Set([...new Set([[0,65]])]);var all=[...u];all.sort(function(x,y){return x[0]-y[0];});var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;',
        'var b=new Int32Array(new SharedArrayBuffer(8));var c=[65,66];for(var i=0;i<2;i++){Atomics.store(b,i,c[i]);}var s="";for(var i=0;i<2;i++){s+=String.fromCharCode(Atomics.load(b,i));}var RESULT=s;',
        'var m=new Map();[65,66].forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());',
        'var RESULT=String.fromCharCode(...[65,66].values());',
    ]
    still_closed = [
        # Filed shapes from the sibling red-first batteries (full
        # credential): F1025 generator spread (re-audited distinct),
        # F1028 WeakMap staging, F989 Map for-of, F1013 manual .next(),
        # F494 Set spread (fails closed on pair elements), F1026/F1027
        # generator for-of / BigInt.
        _redfirst_shapes("w395_f1025")[0],
        _redfirst_shapes("w394_f1028")[0],
        _redfirst_shapes("w393_f989")[0],
        _redfirst_shapes("w393_f1013")[0],
        _redfirst_shapes("w359_f494")[0],
        _redfirst_shapes("w395_f1026")[0],
        _redfirst_shapes("w395_f1027")[0],
    ]
    now_closed_dlp = []
    for modname in ("w395_f1035", "w395_f1036", "w395_f1037",
                    "w395_f1041", "w395_f1042", "w395_f1043",
                    "w395_f1044", "w395_f1045", "w395_f1046"):
        now_closed_dlp.extend(_redfirst_shapes(modname))
    now_closed_prov = _redfirst_shapes("w395_f1047")
    bad_open = [s for s in quiet_twins if _blocked(s)]
    bad_closed = [s for s in still_closed if not _blocked(s)]
    bad_now_closed = [s for s in now_closed_dlp if not _blocked(s)]
    bad_prov = [s for s in now_closed_prov
                if not instruction_shaped(s)]
    ok = (not bad_open and not bad_closed and not bad_now_closed
          and not bad_prov)
    return ("HELD" if ok else "BREAK",
            "overblocked=%d lost_closed=%d unblocked=%d unrouted=%d"
            % (len(bad_open), len(bad_closed), len(bad_now_closed),
               len(bad_prov)))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        'var u=new Set([1,2,3]);var total=0;for(var x of u){total+=x;}',
        'var m=new Map();m.set("a",1);var n=m.size;',
        'var b=new Int32Array(new SharedArrayBuffer(16));Atomics.store(b,0,7);var v=Atomics.load(b,0);',
        'var u=new Set([...new Set([[0,65]])]);var label="pairs-staged";',
        'var codes=[65,66];var s=String.fromCharCode(...codes);',
        'var m=new Map([[0,65],[1,66]]);var s=String.fromCharCode(...m.values());',
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/6" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    # Bounded-work smoke check, not a latency SLA: per-call cost is
    # small in isolation; wall-clock here is contention-sensitive
    # (sibling lanes share the box -- F186 lesson), so the bar is
    # generous. Structural boundedness comes from
    # _JS_EXPR_MAX_CODEPOINTS + _MAX_DECODE_BYTES, not this timer.
    sites = []
    base38 = ('var u=new Set([...new Set([[0,120]])]);var all=[...u];'
              'all.sort(function(x,y){return x[0]-y[0];});var s="";'
              'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;')
    base39 = ('var b=new Int32Array(new SharedArrayBuffer(8));var c=[65];'
              'for(var i=0;i<1;i++){Atomics.store(b,i,c[i]);}var s="";'
              'for(var i=0;i<1;i++){s+=String.fromCharCode(Atomics.load(b,i));}'
              'var RESULT=s;')
    base40 = ('var m=new Map();[65].forEach(function(c,i){m.set(i,c);});'
              'var RESULT=String.fromCharCode(...m.values());')
    for i in range(200):
        sites.append((base38, base39, base40)[i % 3])
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 60 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g396l2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w395_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # Wave-396 merge: all 13 round-63 pins are now CLOSED (the
        # merge flipped them all to expect-blocked/routed), so the child
        # battery must show 0 BREAK.
        expected = set()
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w395_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-63 attack battery."""
    return _green_check()


# ---------------------------------------------------------------- runner


def main():
    fails = []
    for fn in TESTS:
        name = fn.__name__
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "BREAK", "raised %r" % e
        print("%s: %s (%s)" % (name, verdict, note))
        if verdict != "HELD":
            fails.append(name)
    print("%d HELD / %d BREAK of %d" % (len(TESTS) - len(fails), len(fails), len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    sys.exit(main())
