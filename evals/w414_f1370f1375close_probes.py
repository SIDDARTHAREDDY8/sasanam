#!/usr/bin/env python3
"""Wave-414 lane 3 close battery: F1370-F1375 CLOSED.

F1370: F1357 multi-char SEP residual -- `D.join('ab').split('ab').join('')`
  with a credential holding 'a' but not 'b' is node-identity (v24.20.0)
  while `_js_f1357_stmt_decode` failed closed (SEP-char check sufficient,
  not necessary). Closed by replacing the check with the node-exact
  identity test `"".join(sep.join(dstr).split(sep)) == dstr`
  (fuzz-verified 2000/2000 against node v24.20.0).

F1371: F1358 arrow-twin residual -- `C.reduceRight((acc,c)=>
  String.fromCharCode(c)+acc,'')` is node-identity while
  `_js_f1358_stmt_decode` required the `function` keyword. Closed by
  accepting the `(p0,p1)=>fcc(p1)+p0` expression-body twin.

F1372: F1355 C[i] residual -- `new Set(C.keys()).forEach((i,k)=>
  {S+=String.fromCharCode(C[i]);})`; for a Set forEach passes
  (value,key) with key===value, so both params are the index. Closed
  by accepting either param as the index in `_js_f1355_stmt_decode`.

F1373: F1336 parenthesized 1-param residual -- `new Set(C.keys())
  .forEach((i)=>{S+=String.fromCharCode(C[i]);});`. Closed by accepting
  the parenthesized param and the block-body twin in
  `_js_f1336_stmt_decode` (node-identical to the expression body).

F1374: F1264 two-param function residual -- `new Set(C.keys())
  .forEach(function(i,k){S+=String.fromCharCode(C[k]);});`. Closed by
  accepting `function(i,k)` and either param as the index in
  `_js_f1264_stmt_decode`.

F1375: F1356 parseInt twin -- `C.map(function(c){return
  parseInt(c.toFixed(0),10);})`. Closed by accepting
  `parseInt(p.toFixed(d),10)` (radix exactly 10, d 0..100) alongside
  `Number(p.toFixed(d))` in `_js_f1356_stmt_decode`.

All changes are in-place hook extensions (no new _decode_layer
dispatch loop; N_STMTDEC_LOOPS stays 72). Node-exact on all filed
shapes (short + 40-char, v24.20.0); fail-closed hook-level bounds;
sibling pins hold; F1360-F1369 (other lanes) still MISS.

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

SECRET_S = "xoxb-01" + "23456789acdef"
SECRET_L = "xoxb-" + "0123456789acdef0123456789acdef012"

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=72; re.compile=29."""
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
    if pin != 72 or actual != 72:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 72)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=72")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1370: multi-char SEP, credential has 'a' not 'b'
    ("f1370",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('ab').split('ab').join('');var RESULT=S;"),
    # F1371: reduceRight arrow twin (expression body)
    ("f1371",
     "var C={I};var S=C.reduceRight((acc,c)=>String.fromCharCode(c)+acc,'');var RESULT=S;"),
    # F1371: reduceRight arrow twin (block body) -- spec-review residual
    ("f1371-block",
     "var C={I};var S=C.reduceRight((acc,c)=>{return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
    # F1372: Set.forEach 2-param arrow using C[i]
    ("f1372",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1373: Set.forEach parenthesized 1-param arrow, block body
    ("f1373",
     "var C={I};var S='';new Set(C.keys()).forEach((i)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1374: Set.forEach two-param function using C[k]
    ("f1374",
     "var C={I};var S='';new Set(C.keys()).forEach(function(i,k){S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    # F1375: toFixed map parseInt twin
    ("f1375",
     "var C={I};var D=C.map(function(c){return parseInt(c.toFixed(0),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 6 filed shapes (short + long) BLOCK."""
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
    # F1370: different multi-char SEP
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('xy').split('xy').join('');var RESULT=S;",
    # F1370: let/const
    "const C={I};const D=C.map(function(c){return String.fromCharCode(c);});const S=D.join('ab').split('ab').join('');const RESULT=S;",
    # F1371: different param names
    "var C={I};var S=C.reduceRight((a,b)=>String.fromCharCode(b)+a,'');var RESULT=S;",
    # F1371: whitespace + let
    "let C={I};let S=C.reduceRight((acc, c) => String.fromCharCode(c) + acc, '');let RESULT=S;",
    # F1372: different param names using first param
    "var C={I};var S='';new Set(C.keys()).forEach((x,y)=>{S+=String.fromCharCode(C[x]);});var RESULT=S;",
    # F1373: parenthesized param, expression body
    "var C={I};var S='';new Set(C.keys()).forEach((i)=>S+=String.fromCharCode(C[i]));var RESULT=S;",
    # F1373: different param name, block body
    "var C={I};var S='';new Set(C.keys()).forEach((x)=>{S+=String.fromCharCode(C[x]);});var RESULT=S;",
    # F1374: two-param function using first param
    "var C={I};var S='';new Set(C.keys()).forEach(function(i,k){S+=String.fromCharCode(C[i]);});var RESULT=S;",
    # F1375: arrow twin of parseInt
    "var C={I};var D=C.map(c=>parseInt(c.toFixed(0),10));var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1375: different digits
    "var C={I};var D=C.map(function(c){return parseInt(c.toFixed(2),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
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
    # F1370: SEP genuinely breaks identity -> node mis-decodes -> fail closed
    ("f1370-sep-in-cred",
     "var C=[97,97];var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('a').split('a').join('');var RESULT=S;"),
    # F1370: SEP mismatch -> fail closed
    ("f1370-sep-mismatch",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('ab').split('xy').join('');var RESULT=S;"),
    # F1371: non-empty INIT -> fail closed
    ("f1371-init-nonempty",
     "var C={I};var S=C.reduceRight((acc,c)=>String.fromCharCode(c)+acc,'X');var RESULT=S;"),
    # F1371: swapped params -> fcc arg mismatch -> fail closed
    ("f1371-swapped-params",
     "var C={I};var S=C.reduceRight((c,acc)=>String.fromCharCode(c)+acc,'');var RESULT=S;"),
    # F1372: unknown index ident -> fail closed
    ("f1372-bad-idx",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[j]);});var RESULT=S;"),
    # F1373: wrong array -> fail closed
    ("f1373-bad-arr",
     "var C={I};var S='';new Set(C.keys()).forEach((i)=>{S+=String.fromCharCode(D[i]);});var RESULT=S;"),
    # F1374: duplicate params -> fail closed
    ("f1374-dup-params",
     "var C={I};var S='';new Set(C.keys()).forEach(function(i,i){S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1375: wrong radix -> fail closed
    ("f1375-bad-radix",
     "var C={I};var D=C.map(function(c){return parseInt(c.toFixed(0),8);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1375: digits > 100 -> fail closed
    ("f1375-bad-digits",
     "var C={I};var D=C.map(function(c){return parseInt(c.toFixed(101),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    # F1357 single-char SEP still BLOCKs
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    # F1358 function form still BLOCKs
    ("f1358",
     "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
    # F1355 C[k] form still BLOCKs
    ("f1355",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    # F1336 paren-less expression arrow still BLOCKs
    ("f1336",
     "var C={I};var S='';new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));var RESULT=S;"),
    # F1264 1-param function still BLOCKs
    ("f1264",
     "var C={I};var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;"),
    # F1356 Number() form still BLOCKs
    ("f1356",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    "var C=[1,2,3];var S=C.reduceRight((acc,c)=>acc+c,0);var RESULT=S;",
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
        _hits("var C=[%d];var S=C.reduceRight((acc,c)=>String.fromCharCode(c)+acc,'');var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1360-F1367: attack-81 decoder pins, other lanes' scope -- must stay MISS
_P7 = [
    "var C={I};var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    "var C={I};var D=C.map(function(c,i){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    "var C={I};var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    "var C={I};var D=C.map(function(c){return Number(c.toExponential(2));});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    "var C={I};var D=C.map(function(c){return Math.abs(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """F1360-F1367 (attack 81, other lanes) still MISS."""
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
    """Depth-1 green on w413_attack_probes: F1360-F1369 still open (HELD).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w413_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g414l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w413_attack_probes.py")],
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
        return (ok, "green(w413_attack): new-pins=%s%s"
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
