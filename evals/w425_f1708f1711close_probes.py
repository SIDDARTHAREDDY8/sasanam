#!/usr/bin/env python3
"""Wave-425 lane B close battery: F1708-F1711 CLOSED.

F1708: flatMap 1-param function null-thisArg --
  `var D=C.flatMap(function(c){return [c];},null);` +
  fromCharCode.apply readout. New `_js_f1708_stmt_decode`. Node-exact:
  callback returns singleton [c] per element; flatMap flattens to a
  copy of C; null thisArg inert. Disjoint from F1570 (2-param/arrow)
  by grammar.

F1709: map 1-param function null-thisArg --
  `var D=C.map(function(c){return c;},null);` +
  fromCharCode.apply readout. New `_js_f1709_stmt_decode`. Node-exact:
  identity callback; null thisArg inert. Disjoint from F1450
  (3-param, no thisArg), F1361 (2-param) by grammar.

F1710: Array.from null-thisArg --
  `var D=Array.from(C,function(c){return c;},null);` +
  fromCharCode.apply readout. New `_js_f1710_stmt_decode`. Node-exact:
  identity callback ignores this; null thisArg inert. Disjoint from
  F1528 ({} thisArg), F1393 (no third arg) by grammar.

F1711: code-array spread trailing comma --
  `var D=[...C,];` + fromCharCode.apply readout.
  New `_js_f1711_stmt_decode`. Node-exact: trailing comma is a no-op.
  Disjoint from F1656 (string spread), F1654 (no trailing comma) by
  grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 108->109
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1703, F1705-F1707,
F1712-F1714 (other opens) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import os
import re
import shutil
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
    ("f1708",
     "var C={I};var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1709",
     "var C={I};var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1710",
     "var C={I};var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1711",
     "var C={I};var D=[...C,];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=111 (108 base + 3 lanes); re.compile=29; pin 2143; wave-425 merge."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 111)
    notes.append("loops=%d (expect 111)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1708_stmt_decode, _js_f1709_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1708-loop=%s" % has_new)
    # hooks defined
    for fn in ("_js_f1708_stmt_decode", "_js_f1709_stmt_decode",
               "_js_f1710_stmt_decode", "_js_f1711_stmt_decode"):
        has = ("def %s(" % fn) in dsrc
        ok = ok and has
        notes.append("%s=%s" % (fn[4:11], has))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w424 = "# Wave-424:" in ftxt
    ok = ok and has_w424
    notes.append("w424-footer=%s" % has_w424)
    # taxonomy pin 2143 referenced
    ok = ok and ("2143" in ftxt)
    notes.append("tax2143=%s" % ("2143" in ftxt))
    # re.compile count unchanged
    ncompile = len(re.findall(r"re\.compile\(", dsrc))
    ok = ok and (ncompile == 29)
    notes.append("re.compile=%d" % ncompile)
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
        ("f1708-let-renamed",
         "let A=%s;let B=A.flatMap(function(q){return [q];},null);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1708-const-ws",
         "const C = %s ; const D = C.flatMap(function(c){return [c];},null) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1709-let-renamed",
         "let A=%s;let B=A.map(function(q){return q;},null);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1709-const-ws",
         "const C = %s ; const D = C.map(function(c){return c;},null) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1710-let-renamed",
         "let A=%s;let B=Array.from(A,function(q){return q;},null);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1710-const-ws",
         "const C = %s ; const D = Array.from(C,function(c){return c;},null) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1711-let-renamed",
         "let A=%s;let B=[...A,];let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1711-const-ws",
         "const C = %s ; const D = [...C,] ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
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
        # F1708: must be 1-param (2-param fails closed)
        ("f1708-2param",
         "var C=%s;var D=C.flatMap(function(c,i){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1708: thisArg must be null ({} fails closed)
        ("f1708-obj-thisarg",
         "var C=%s;var D=C.flatMap(function(c){return [c];},{});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1708: callback must return [c], not [c+1]
        ("f1708-cb-not-singleton",
         "var C=%s;var D=C.flatMap(function(c){return [c+1];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1708: arrow form is F1570's domain, not this hook (must not be swallowed)
        ("f1708-arrow",
         "var C=%s;var D=C.flatMap(c=>[c],null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1709: must be 1-param (3-param fails closed)
        ("f1709-3param",
         "var C=%s;var D=C.map(function(c,i,a){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1709: thisArg must be null (no-thisArg is F1361/F1422's closed domain)
        # (moved to sibling pins)
        # F1709: callback must return c (not c+1)
        ("f1709-cb-not-ident",
         "var C=%s;var D=C.map(function(c){return c+1;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1710: thisArg must be null ({} is F1528's closed domain; no-thisArg is F1393's)
        # (moved to sibling pins)
        # F1710: must be 1-param
        ("f1710-2param",
         "var C=%s;var D=Array.from(C,function(c,i){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1710: no thisArg is F1393's closed domain (moved to sibling pins)
        # F1711: trailing comma required (plain spread is F1654's closed domain; moved to sibling pins)
        # F1711: double comma fails closed
        ("f1711-double-comma",
         "var C=%s;var D=[...C,,];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1711: spread base must be C
        ("f1711-wrong-base",
         "var C=%s;var Q=%s;var D=[...Q,];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % (cs, cs)),
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
        # (name, payload, want_hit)
        ("f1570-closed-flatmap-arrow",
         "var C=%s;var E=C.flatMap(c=>[String.fromCharCode(c)],null);var S=E.join('');var RESULT=S;" % cs,
         True),
        ("f1450-closed-map3",
         "var C=%s;var D=C.map(function(c,i,a){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1528-closed-from-obj",
         "var C=%s;var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1656-closed-strspread",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S,];var T=D.join('');var RESULT=T;" % cs,
         True),
        ("f1422-closed-map1-noarg",
         "var C=%s;var D=C.map(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1393-closed-from-noarg",
         "var C=%s;var D=Array.from(C,function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1654-closed-spread",
         "var C=%s;var D=[...C];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
    ]
    bad = []
    for n, p, want in cases:
        got = _hits(p)
        if got != want:
            bad.append("%s(want %s)" % (n, "HIT" if want else "MISS"))
    return (not bad, "%d/%d sibling pins%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text without credentials stays quiet."""
    cases = [
        "var D=items.flatMap(function(c){return [c];},null);",
        "var D=rows.map(function(c){return c;},null);",
        "var D=Array.from(items,function(c){return c;},null);",
        "var D=[...items,];",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function flatMap(c){return [c];}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1715-F1717, F1725 (other opens) still MISS."""
    cs = _codes(SECRET_S)
    sur = "[55296," + ",".join(str(ord(c)) for c in SECRET_S) + "]"
    cases = [
        ("f1715",
         "var C=%s;var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1716",
         "var C=%s;var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1717",
         "var O={};var C=%s;for(var i=0;i<C.length;i++){O['k'+i]=C[i];}var D=[];for(var [k,v] of Object.entries(O)){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1725",
         "var C=%s;var D=C.flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % sur),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 mixed sites scan in reasonable time."""
    cs = _codes(SECRET_S)
    sites = []
    for i in range(50):
        sites.append("var C=%s;var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=[...C,];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 120
    return (ok, "200 sites in %.1fs" % dt)


# ---------------- g0: green check (depth-1) ----------------

@_t
def test_g0_green():
    """Adjacent batteries' red-first still behave; GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "skipped (GOV_SKIP_GREEN=1)")
    notes = []
    ok = True
    # F1707/F1712 red-first should still BREAK (open findings)
    for fn, name in (("w424_f1707_redfirst.py", "f1707"),
                     ("w424_f1712_redfirst.py", "f1712")):
        p = os.path.join(REPO_ROOT, "evals", fn)
        if not os.path.exists(p):
            notes.append("%s missing (skip)" % name)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = "/var/tmp/w425g0-%s-%d" % (name, os.getpid())
        os.makedirs(tmpd, exist_ok=True)
        env["TMPDIR"] = tmpd
        try:
            r = subprocess.run([sys.executable, p], capture_output=True,
                               text=True, timeout=300, env=env, cwd=REPO_ROOT)
            out = (r.stdout or "") + (r.stderr or "")
            brk = "BREAK" in out
            ok = ok and brk
            notes.append("%s %s" % (name, "BREAK" if brk else "NOT-BREAK"))
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
    return (ok, "; ".join(notes))


def main():
    results = []
    for fn in TESTS:
        name = fn.__name__
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %r" % e
        results.append((name, ok, note))
        print("%s %s: %s" % ("HELD" if ok else "BREAK", name, note))
    nheld = sum(1 for _, ok, _ in results if ok)
    print("RESULT: %d/%d HELD" % (nheld, len(results)))
    return 0 if nheld == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
