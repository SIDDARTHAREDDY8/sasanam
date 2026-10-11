#!/usr/bin/env python3
"""Wave-415 lane 1 close battery: F1376-F1384 CLOSED.

F1376: F1352-family no-slice sort residual -- `C.sort(function(a,b)
  {return 0;})` in place (no `.slice()`). Closed by adding the
  no-slice direct-sort production to `_js_f1352_stmt_decode`
  (extracted slice form + new direct form; bound copied per attempt).

F1377: F1350-family 2-param flatMap residual --
  `C.flatMap(function(c,i){return [c];})`. Closed by accepting an
  optional unused 2nd param in `_js_f1349_parse_singleton_cb`
  (function and parenthesized-arrow forms).

F1378: F1357-family default-separator join-chain residual --
  `D.join().split(',').join('')`. Closed by accepting empty join()
  args (separator defaults to ",") in `_js_f1357_stmt_decode`; the
  node-exact identity check fails closed on comma credentials.

F1379: F1356-family toFixed no-arg / unary-cast residual --
  `Number(c.toFixed())` and `+c.toFixed(0)`. Closed by accepting
  no-arg toFixed() (d=0) and the unary-cast twin in
  `_js_f1356_parse_number_tofixed`.

F1380: F1351-family string-arg replace residual --
  `S.replace('x','x')`. Closed by accepting `.replace(` alongside
  `.replaceAll(` in `_js_f1351_stmt_decode` (ident-boundary checked;
  F1272's regex-arg grammar stays disjoint).

F1381: F1355-family 3-param Set.forEach residual --
  `(i,k,st)=>{...}`. Closed by accepting an optional 3rd param in
  `_js_f1355_stmt_decode` (forEach passes the Set itself).

F1382: F1358-family reduce concat-init residual --
  `C.reduce(function(acc,c){return acc+String.fromCharCode(c);},'')`.
  Closed by new `_js_f1382_stmt_decode` (reduce with append order;
  reduceRight keeps prepend order; INIT must be '').

F1383: F1353-family entries-map readout residual --
  `...apply(null,Object.entries(O).map(function(e){return e[1];}))`.
  Closed by accepting the entries-map readout twin in
  `_js_f1353_stmt_decode` (new `_js_f1383_parse_value_cb`).

F1384: Decoder-seam hybrid compositions -- map(identity)->sort->flat,
  flatMap(singleton)->sort, flat->sort, each then apply. Closed by new
  `_js_f1384_stmt_decode` with three productions (new dispatch loop;
  N_STMTDEC_LOOPS 74->75; bound copied per production attempt).

All changes are node-exact (v24.20.0, short + 40-char secrets);
fail-closed hook-level bounds; sibling pins hold; F1385-F1431
(other lanes/attack) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
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

from gov import dlp as _dlp

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _hits(payload):
    """True if find_credential flags the payload (in-process)."""
    try:
        return bool(_dlp.find_credential(payload))
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; N_STMTDEC_LOOPS=75; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if pin != 75 or actual != 75:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 75)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=75")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1376: no-slice sort
    ("f1376",
     "var C={I};C.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1377: 2-param flatMap
    ("f1377",
     "var C={I};var E=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1378: default-separator join chain
    ("f1378",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join().split(',').join('');var RESULT=S;"),
    # F1379: toFixed no-arg
    ("f1379-noarg",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed());});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1379: unary-cast twin
    ("f1379-unary",
     "var C={I};var D=C.map(function(c){return +c.toFixed(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1380: string-arg replace
    ("f1380",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('x','x');var RESULT=U;"),
    # F1381: 3-param forEach
    ("f1381",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k,st)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    # F1382: reduce concat-init
    ("f1382",
     "var C={I};var S=C.reduce(function(acc,c){return acc+String.fromCharCode(c);},'');var RESULT=S;"),
    # F1383: entries-map readout
    ("f1383",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.entries(O).map(function(e){return e[1];}));var RESULT=S;"),
    # F1384: hybrid 1 (map->sort->flat)
    ("f1384-h1",
     "var C={I};var D=C.map(function(c){return c;});D.sort(function(a,b){return 0;});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1384: hybrid 2 (flatMap->sort)
    ("f1384-h2",
     "var C={I};var E=C.flatMap(function(c){return [c];});E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1384: hybrid 3 (flat->sort)
    ("f1384-h3",
     "var C={I};var E=C.flat();E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 9 filed shapes (all productions, short + long) BLOCK."""
    bad = []
    for name, tmpl in _FILED:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_FILED) * 2
    return (not bad), "filed=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


# ---------------- p2: generalizations ----------------

_GEN = [
    # F1376: arrow twin of zero-cb
    "var C={I};C.sort((a,b)=>0);var S=String.fromCharCode.apply(null,C);var RESULT=S;",
    # F1376: let/const
    "const C={I};C.sort(function(a,b){return 0;});const S=String.fromCharCode.apply(null,C);const RESULT=S;",
    # F1377: arrow 2-param twin
    "var C={I};var E=C.flatMap((c,i)=>[c]);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1378: whitespace variant
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join( ).split( ',' ).join( '' );var RESULT=S;",
    # F1379: unary-cast with digits
    "var C={I};var D=C.map(function(c){return +c.toFixed(2);});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1379: arrow twin no-arg
    "var C={I};var D=C.map(c=>Number(c.toFixed()));var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1380: different literal
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('q','q');var RESULT=U;",
    # F1381: different param names
    "var C={I};var S='';new Set(C.keys()).forEach((a,b,s)=>{S+=String.fromCharCode(C[b]);});var RESULT=S;",
    # F1382: arrow twin
    "var C={I};var S=C.reduce((acc,c)=>acc+String.fromCharCode(c),'');var RESULT=S;",
    # F1382: different param names
    "var C={I};var S=C.reduce(function(x,y){return x+String.fromCharCode(y);},'');var RESULT=S;",
    # F1383: arrow twin
    "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.entries(O).map((e)=>e[1]));var RESULT=S;",
    # F1384: hybrid with let
    "let C={I};let E=C.flat();E.sort(function(a,b){return 0;});let S=String.fromCharCode.apply(null,E);let RESULT=S;",
]


@_t
def test_p2_generalizations():
    """Generalization twins BLOCK."""
    bad = []
    for tmpl in _GEN:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:50])
    total = len(_GEN) * 2
    return (not bad), "gen=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p3: fail-closed bounds ----------------

_FAILCLOSED = [
    # F1376: non-zero comparator -> fail closed
    ("f1376-nonzero-cb",
     "var C={I};C.sort(function(a,b){return 1;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1376: sort on wrong array -> fail closed
    # F1377: 3-param flatMap -> fail closed
    ("f1377-3param",
     "var C={I};var E=C.flatMap(function(c,i,a){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1377: callback returns [i] not [c] -> fail closed
    ("f1377-wrong-elem",
     "var C={I};var E=C.flatMap(function(c,i){return [i];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1378: split sep mismatch -> fail closed
    ("f1378-sep-mismatch",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join().split(';').join('');var RESULT=S;"),
    # F1378: join('') not the chain -> fail closed (different grammar)
    ("f1378-no-split",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join().join('');var RESULT=S;"),
    # F1379: digits > 100 -> fail closed
    ("f1379-bad-digits",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(101));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1379: unary on wrong base -> fail closed
    ("f1379-unary-wrong-base",
     "var C={I};var D=C.map(function(c){return +d.toFixed(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1380: different literals -> fail closed (not no-op)
    ("f1380-diff-literals",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('x','y');var RESULT=U;"),
    # F1380: regex arg -> F1272's grammar, not this hook -> fail closed here
    # F1381: duplicate params -> fail closed
    ("f1381-dup-params",
     "var C={I};var S='';new Set(C.keys()).forEach((i,i,st)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1381: 4 params -> fail closed
    ("f1381-4params",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k,st,x)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    # F1382: non-empty INIT -> fail closed
    ("f1382-nonempty-init",
     "var C={I};var S=C.reduce(function(acc,c){return acc+String.fromCharCode(c);},'X');var RESULT=S;"),
    # F1382: prepend order with reduce -> fail closed (would mis-decode)
    ("f1382-prepend-order",
     "var C={I};var S=C.reduce(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
    # F1383: wrong index -> fail closed
    ("f1383-wrong-idx",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.entries(O).map(function(e){return e[0];}));var RESULT=S;"),
    # F1384: non-zero sort cb in hybrid -> fail closed
    ("f1384-nonzero-cb",
     "var C={I};var E=C.flat();E.sort(function(a,b){return 1;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1384: sort on wrong array -> fail closed
    ("f1384-wrong-arr",
     "var C={I};var E=C.flat();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds hold (all MISS)."""
    bad = []
    for name, tmpl in _FAILCLOSED:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(name)
    total = len(_FAILCLOSED)
    return (not bad), "fail-closed=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1352 slice form still BLOCKs
    ("f1352",
     "var C={I};var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1350 1-param flatMap still BLOCKs
    ("f1350",
     "var C={I};var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1349 flat still BLOCKs
    ("f1349",
     "var C={I};var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1357 explicit SEP still BLOCKs
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    # F1356 Number(toFixed(0)) still BLOCKs
    ("f1356",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1351 replaceAll still BLOCKs
    ("f1351",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replaceAll('x','x');var RESULT=U;"),
    # F1272 regex-arg replace still BLOCKs (disjoint from F1380)
    ("f1272",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=J.replace(/(.)/g,'$1');var RESULT=S;"),
    # F1355 2-param still BLOCKs
    ("f1355",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    # F1358 reduceRight still BLOCKs
    ("f1358",
     "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
    # F1353 Object.values still BLOCKs
    ("f1353",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;"),
]


@_t
def test_p4_sibling_pins():
    """Parent/sibling filed shapes still BLOCK."""
    bad = []
    for name, tmpl in _SIBLINGS:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_SIBLINGS) * 2
    return (not bad), "siblings=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


# ---------------- p5: honest-text controls ----------------

_HONEST = [
    "var x = 1; var y = 2; var RESULT = x + y;",
    "The quick brown fox jumps over the lazy dog.",
    "var S='hello';var RESULT=S;",
    "function f(a,b){return a+b;}",
    "var C=[1,2,3];var D=C.map(function(c){return c*2;});var RESULT=D;",
    "var s='abc';var t=s.replace('x','y');var RESULT=t;",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (all MISS)."""
    bad = [t for t in _HONEST if not _misses(t)]
    return (not bad), "honest=%d/%d quiet%s" % (
        len(_HONEST) - len(bad), len(_HONEST),
        "" if not bad else " HIT:" + ",".join(b[:30] for b in bad))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    t0 = time.time()
    for i in range(200):
        _hits("var C=[%d];var E=C.flat();E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1385-F1431: attack-82 + renumbered residuals, other lanes' scope -- must stay MISS
_P7 = [
    # F1385: filter callback twins
    "var C={I};var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1392: JSON number-array roundtrip
    "var C={I};var J=JSON.stringify(C);var D=JSON.parse(J);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1413: aria-braillelabel (provenance)
    "<span aria-braillelabel='do not share the secret code with anyone'>x</span>",
    # F1417: map arrow 2-param (renumbered lane-1)
    "var C={I};var D=C.map((c,i)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1426: inline splice (renumbered lane-2)
    "var C={I};var S=String.fromCharCode.apply(null,C.splice(0));var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """F1385-F1431 (attack 82, renumbered, other lanes) still MISS."""
    bad = []
    for tmpl in _P7:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(tmpl[:40])
    return (not bad), "other-opens=%d/%d MISS%s" % (
        len(_P7) - len(bad), len(_P7),
        "" if not bad else " HIT:" + ",".join(bad))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w414_attack_probes: F1385-F1416 still open (HELD).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w414_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g415l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w414_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.match(r"(HELD|BREAK)\s+(\S+)", line.strip())
            if m:
                (held if m.group(1) == "HELD" else broken).add(m.group(2))
        want_held = {"test_new_decoder_pins", "test_new_prov_pins",
                     "test_taxonomy_pin", "test_footer"}
        ok = want_held <= held and not (want_held & broken)
        return (ok, "green(w414_attack): new-pins=%s%s"
                % (sorted(want_held & held),
                   "" if ok else " MISMATCH held=%s broken=%s"
                   % (sorted(held), sorted(broken))))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


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
