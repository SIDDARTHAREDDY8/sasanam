#!/usr/bin/env python3
"""Wave-424 lane B close battery: F1695-F1699 CLOSED.

F1695: Object.keys index readout --
  `var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(O[k]);});` +
  fromCharCode.apply readout. New `_js_f1695_stmt_decode`. Node-exact:
  keys are ["0".."n-1"] in order, O[k] reads each code back.
  Disjoint from F1682 (values readout) by grammar.

F1696: Reflect.construct code-array staging --
  `var A=Reflect.construct(Array,C);` + fromCharCode.apply readout.
  New `_js_f1696_stmt_decode`. Node-exact for != 1 elements
  (single-element fails closed: new Array(x) is sparse).
  Disjoint from F468 (fragment form) by grammar.

F1697: Proxy get-trap staging --
  `var P=new Proxy(C,{get:function(t,k){return t[k];}});` +
  fromCharCode.apply readout. New `_js_f1697_stmt_decode`.
  Node-exact: the trap forwards every read. Disjoint from F1456
  (iterator staging) by grammar.

F1698: Uint8Array subarray/slice views --
  `var U=new Uint8Array(C);var V=U.subarray(0);` (or `U.slice()`) +
  fromCharCode.apply readout. New `_js_f1698_stmt_decode`. Node-exact
  for codes < 256 (ToUint8 identity; else fail closed).
  Disjoint from F1680 (constructor forms) by grammar.

F1699: join/tab-split roundtrip --
  `var T=C.join('\\t');var D=T.split('\\t').map(Number);` +
  fromCharCode.apply readout. New `_js_f1699_stmt_decode`. Node-exact:
  tab join/split invert on integer arrays. Disjoint from F1687
  (comma separator) by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 105->106
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1690-F1694,
F1700-F1704 (other opens) still MISS.

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


_FILED = [
    ("f1695",
     "var C={I};var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(O[k]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1696",
     "var C={I};var A=Reflect.construct(Array,C);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1697",
     "var C={I};var P=new Proxy(C,{get:function(t,k){return t[k];}});var S=String.fromCharCode.apply(null,P);var RESULT=S;"),
    ("f1698-subarray",
     "var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var S=String.fromCharCode.apply(null,V);var RESULT=S;"),
    ("f1698-slice",
     "var C={I};var U=new Uint8Array(C);var V=U.slice();var S=String.fromCharCode.apply(null,V);var RESULT=S;"),
    ("f1699",
     "var C={I};var T=C.join('\\t');var D=T.split('\\t').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=106 (105 base + 1 new loop); re.compile=29; pin 2143; wave-423 footer lineage."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 106)
    notes.append("loops=%d (expect 106)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1695_stmt_decode, _js_f1696_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1695-loop=%s" % has_new)
    # re.compile count unchanged
    nrc = len(re.findall(r"re\.compile\(", dsrc))
    ok = ok and (nrc == 29)
    notes.append("re.compile=%d (expect 29)" % nrc)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w423 = "# Wave-423:" in ftxt
    ok = ok and has_w423
    notes.append("w423-footer=%s" % has_w423)
    ok = ok and ("2143" in ftxt)
    notes.append("tax2143=%s" % ("2143" in ftxt))
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

@_t
def test_p1_filed_shapes():
    """All filed shapes now HIT."""
    bad = []
    total = 0
    for name, tmpl in _FILED:
        for s in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(tmpl.replace("{I}", _codes(s))):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """Renamed idents, let/const, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1695-let-renamed",
         "let A=%s;let O2=Object.assign({},A);let K2=Object.keys(O2);let D2=K2.map(function(q){return Number(O2[q]);});let S2=String.fromCharCode.apply(null,D2);let RESULT=S2;" % cs),
        ("f1695-ws",
         "var C = %s ; var O = Object.assign({} , C) ; var K = Object.keys(O) ; var D = K.map(function(k){return Number(O[k]);}) ; var S = String.fromCharCode.apply(null , D) ; var RESULT = S ;" % cs),
        ("f1696-const",
         "const C=%s;const A=Reflect.construct(Array,C);const S=String.fromCharCode.apply(null,A);const RESULT=S;" % cs),
        ("f1696-renamed",
         "var X=%s;var Y=Reflect.construct(Array,X);var Z=String.fromCharCode.apply(null,Y);var RESULT=Z;" % cs),
        ("f1697-let",
         "let C=%s;let P=new Proxy(C,{get:function(t,k){return t[k];}});let S=String.fromCharCode.apply(null,P);let RESULT=S;" % cs),
        ("f1697-renamed-trap",
         "var C=%s;var P=new Proxy(C,{get:function(a,b){return a[b];}});var S=String.fromCharCode.apply(null,P);var RESULT=S;" % cs),
        ("f1698-const-slice",
         "const C=%s;const U=new Uint8Array(C);const V=U.slice();const S=String.fromCharCode.apply(null,V);const RESULT=S;" % cs),
        ("f1699-let",
         "let C=%s;let T=C.join('\\t');let D=T.split('\\t').map(Number);let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1699-renamed",
         "var A=%s;var B=A.join('\\t');var E=B.split('\\t').map(Number);var F=String.fromCharCode.apply(null,E);var RESULT=F;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d generalizations hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level fail-closed bounds: all must MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1695-noNumber",
         "var C=%s;var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return O[k];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1695-noindex",
         "var C=%s;var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(O);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1695-wrongobj",
         "var C=%s;var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(C[k]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1696-noarg",
         "var C=%s;var A=Reflect.construct(Array);var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs),
        ("f1696-apply",
         "var C=%s;var A=Reflect.apply(Array,null,C);var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs),
        ("f1696-single",
         "var C=[120];var A=Reflect.construct(Array,C);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
        ("f1697-consttrap",
         "var C=%s;var P=new Proxy(C,{get:function(t,k){return 0;}});var S=String.fromCharCode.apply(null,P);var RESULT=S;" % cs),
        ("f1697-noget",
         "var C=%s;var P=new Proxy(C,{});var S=String.fromCharCode.apply(null,P);var RESULT=S;" % cs),
        ("f1697-settrap",
         "var C=%s;var P=new Proxy(C,{set:function(t,k,v){return true;}});var S=String.fromCharCode.apply(null,P);var RESULT=S;" % cs),
        ("f1698-sub1",
         "var C=%s;var U=new Uint8Array(C);var V=U.subarray(1);var S=String.fromCharCode.apply(null,V);var RESULT=S;" % cs),
        ("f1698-bigcode",
         "var C=[120,300];var U=new Uint8Array(C);var V=U.subarray(0);var S=String.fromCharCode.apply(null,V);var RESULT=S;"),
        ("f1699-sep-mismatch",
         "var C=%s;var T=C.join('\\t');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1699-space-sep",
         "var C=%s;var T=C.join(' ');var D=T.split(' ').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Neighboring hooks keep their documented behavior."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1682-values",
         "var C=%s;var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1680-u8",
         "var C=%s;var D=new Uint8Array(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1687-comma",
         "var C=%s;var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1690-bindchar",
         "var C=%s;var f=String.fromCharCode.bind(null);var S=f.apply(null,C);var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d sibling hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest prose / junk stays quiet."""
    cases = [
        ("prose", "The proxy server handles requests via the gateway."),
        ("junk-code", "var x = [1,2,3]; console.log(x);"),
        ("uint8-junk", "var U = new Uint8Array(8);"),
        ("proxy-junk", "var P = new Proxy({}, {});"),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1690-F1694, F1700-F1704 (other lanes' scope) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1690",
         "var C=%s;var f=String.fromCharCode.bind(null);var S=f(...C);var RESULT=S;" % cs),
        ("f1691",
         "var C=%s;var f=String.fromCodePoint.bind(null);var S=f.apply(null,C);var RESULT=S;" % cs),
        ("f1692",
         "var C=%s;var D=C.slice().sort((a,b)=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1700",
         "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1703",
         "var C=[0xD800,%s];var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs[1:]),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 sites scan in reasonable time."""
    cs = _codes(SECRET_S)
    sites = []
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(O[k]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var A=Reflect.construct(Array,C);var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs)
        elif i % 5 == 2:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 5 == 3:
            sites.append("var x=%d;var y=x*2;" % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- g0: green check ----------------

@_t
def test_g0_green():
    """Depth-1 green: adjacent batteries' mains with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "skipped (GOV_SKIP_GREEN=1)")
    notes = []
    ok = True
    # Adjacent: the attack-91 red-first batteries for F1695-F1699 must
    # now print NO-BREAK (shapes fixed), controls still pass.
    for n in (1695, 1696, 1697, 1698, 1699):
        p = os.path.join(REPO_ROOT, "evals", "w423_f%d_redfirst.py" % n)
        if not os.path.exists(p):
            notes.append("f%d-missing" % n)
            ok = False
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            r = subprocess.run([sys.executable, p], capture_output=True,
                               text=True, timeout=300, env=env)
            out = (r.stdout or "") + (r.stderr or "")
            good = ("NO-BREAK" in out and "junk-quiet: OK" in out)
            if not good:
                ok = False
            notes.append("f%d=%s" % (n, "NO-BREAK" if good else "BAD"))
        except Exception:
            ok = False
            notes.append("f%d=ERR" % n)
    return (ok, "; ".join(notes))


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    args = ap.parse_args()
    held = 0
    total = 0
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        total += 1
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %r" % e
        held += 1 if ok else 0
        print("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note))
    print("RESULT: %d/%d HELD" % (held, total))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
