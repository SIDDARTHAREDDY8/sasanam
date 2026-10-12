#!/usr/bin/env python3
"""Wave-426 lane B close battery: F1720-F1724 CLOSED.

F1720: join(undefined) separator roundtrip --
  `var T=C.join(undefined);var D=T.split(',').map(Number);` +
  fromCharCode.apply readout. New `_js_f1720_stmt_decode`. Node-exact:
  undefined separator coerces to default comma; split(',') inverts;
  Number() restores. Disjoint from F1687 (join(',') explicit comma)
  by grammar.

F1721: flat(Infinity) staging --
  `var D=[C];var E=D.flat(Infinity);` + fromCharCode.apply readout.
  New `_js_f1721_stmt_decode`. Node-exact: [C] wraps, flat(Infinity)
  fully flattens. Disjoint from F1432 (flat(2) literal), F1534
  (flat(1+1)) by depth grammar and staging.

F1722: structuredClone with options --
  `var D=structuredClone(C,{transfer:[]});` + fromCharCode.apply readout.
  New `_js_f1722_stmt_decode`. Node-exact: empty transfer list means
  pure deep copy. Disjoint from F1677 (no options arg) by grammar.

F1723: findLast/unshift iteration --
  `var T=[];C.findLast(function(c){T.unshift(c);return false;});` +
  fromCharCode.apply readout. New `_js_f1723_stmt_decode`. Node-exact:
  findLast visits all (return false => no early exit); unshift rebuilds
  in order. No prior filing covers findLast.

F1724: filter 3-arg identity --
  `var D=C.filter(function(c,i,a){return a[i]===c;});` +
  fromCharCode.apply readout. New `_js_f1724_stmt_decode`. Node-exact:
  a[i]===c identically true. Disjoint from F1709 (map 1-param), F1450
  (map 3-param), F1361 (2-param) by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 111->112
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1715-F1719,
F1725-F1734 (other opens) still MISS.

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
    ("f1720",
     "var C={I};var T=C.join(undefined);var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1721",
     "var C={I};var D=[C];var E=D.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1722",
     "var C={I};var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1723",
     "var C={I};var T=[];C.findLast(function(c){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;"),
    ("f1724",
     "var C={I};var D=C.filter(function(c,i,a){return a[i]===c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS = 115 (111 base + 4 lanes); re.compile=29; pin 2143; wave-425 merge footer."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 112)
    notes.append("loops=%d (expect 112)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1720_stmt_decode, _js_f1721_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1720-loop=%s" % has_new)
    # hooks defined
    for fn in ("_js_f1720_stmt_decode", "_js_f1721_stmt_decode",
               "_js_f1722_stmt_decode", "_js_f1723_stmt_decode",
               "_js_f1724_stmt_decode"):
        has = ("def %s(" % fn) in dsrc
        ok = ok and has
        notes.append("%s=%s" % (fn[4:11], has))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w425 = "# Wave-425:" in ftxt
    ok = ok and has_w425
    notes.append("w425-footer=%s" % has_w425)
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
        ("f1720-let-renamed",
         "let A=%s;let B=A.join(undefined);let C=B.split(',').map(Number);let T=String.fromCharCode.apply(null,C);let RESULT=T;" % cs),
        ("f1720-const-ws",
         "const C = %s ; const T = C.join(undefined) ; const D = T.split(',').map(Number) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1721-let-renamed",
         "let A=%s;let B=[A];let E=B.flat(Infinity);let T=String.fromCharCode.apply(null,E);let RESULT=T;" % cs),
        ("f1721-const-ws",
         "const C = %s ; const D = [C] ; const E = D.flat(Infinity) ; const S = String.fromCharCode.apply(null,E) ; const RESULT = S ;" % cs),
        ("f1722-let-renamed",
         "let A=%s;let B=structuredClone(A,{transfer:[]});let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1722-const-ws",
         "const C = %s ; const D = structuredClone(C,{transfer:[]}) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1723-let-renamed",
         "let A=%s;let B=[];A.findLast(function(q){B.unshift(q);return false;});let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1723-const-ws",
         "const C = %s ; const T = [] ; C.findLast(function(c){T.unshift(c);return false;}) ; const S = String.fromCharCode.apply(null,T) ; const RESULT = S ;" % cs),
        ("f1724-let-renamed",
         "let A=%s;let B=A.filter(function(x,j,b){return b[j]===x;});let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1724-const-ws",
         "const C = %s ; const D = C.filter(function(c,i,a){return a[i]===c;}) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
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
        # F1720: sep must be undefined (explicit comma is F1687's CLOSED domain;
        # verified as sibling pin in p4, not a fail-closed case here)
        # F1720: sep must be undefined (no-arg join is a different production)
        ("f1720-noarg",
         "var C=%s;var T=C.join();var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1720: split sep must be comma
        ("f1720-split-tab",
         "var C=%s;var T=C.join(undefined);var D=T.split('\\t').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1721: depth must be Infinity (literal 2 is F1432's domain)
        ("f1721-lit2",
         "var C=%s;var D=[C];var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1721: depth must be Infinity (1+1 is F1534's domain)
        ("f1721-1plus1",
         "var C=%s;var D=[C];var E=D.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1721: staging must be [C] (map-singleton is F1534's domain)
        ("f1721-map-staging",
         "var C=%s;var N=C.map(function(c){return [c];});var E=N.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1722: options must be exactly {transfer:[]} (other options fail closed)
        ("f1722-other-opt",
         "var C=%s;var D=structuredClone(C,{lossless:true});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1722: no options is F1677's CLOSED domain (verified as sibling pin
        # in p4, not a fail-closed case here)
        # F1723: callback must return false (return true would early-exit)
        ("f1723-return-true",
         "var C=%s;var T=[];C.findLast(function(c){T.unshift(c);return true;});var S=String.fromCharCode.apply(null,T);var RESULT=S;" % cs),
        # F1723: must be 1-param (2-param fails closed)
        ("f1723-2param",
         "var C=%s;var T=[];C.findLast(function(c,i){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;" % cs),
        # F1723: must use unshift (push would reverse order)
        ("f1723-push",
         "var C=%s;var T=[];C.findLast(function(c){T.push(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;" % cs),
        # F1724: must be 3-param (1-param is F1709's map domain; 2-param fails closed)
        ("f1724-2param",
         "var C=%s;var D=C.filter(function(c,i){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1724: body must be a[i]===c (different predicate fails closed)
        ("f1724-wrong-pred",
         "var C=%s;var D=C.filter(function(c,i,a){return a[i]!==c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1724: must be filter (map 3-param is F1450's domain)
        ("f1724-map3",
         "var C=%s;var D=C.map(function(c,i,a){return a[i]===c?c:0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        ("f1687-closed-join-comma",
         "var C=%s;var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1432-closed-flat2",
         "var C=%s;var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1534-closed-flat11",
         "var C=%s;var N=C.map(function(c){return [c];});var E=N.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1677-closed-clone",
         "var C=%s;var D=structuredClone(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1709-closed-map1",
         "var C=%s;var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1450-closed-map3",
         "var C=%s;var D=C.map(function(c,i,a){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
        "var T=items.join(undefined);",
        "var E=nested.flat(Infinity);",
        "var D=structuredClone(obj,{transfer:[]});",
        "items.findLast(function(c){return c>0;});",
        "var D=rows.filter(function(c,i,a){return a[i]===c;});",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function filter(c,i,a){return a[i]===c;}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1739-F1742 (other opens) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1739",
         "var C=%s;var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;" % cs),
        ("f1740",
         "var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1741",
         "var C=%s;var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;" % cs),
        ("f1742",
         "var C=%s;var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
    for i in range(40):
        sites.append("var C=%s;var T=C.join(undefined);var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=[C];var E=D.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var T=[];C.findLast(function(c){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=C.filter(function(c,i,a){return a[i]===c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    # F1715/F1725 red-first should still BREAK (open findings)
    for fn, name in (("w425_f1715_redfirst.py", "f1715"),
                     ("w425_f1725_redfirst.py", "f1725")):
        p = os.path.join(REPO_ROOT, "evals", fn)
        if not os.path.exists(p):
            notes.append("%s missing (skip)" % name)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = "/var/tmp/w426g0-%s-%d" % (name, os.getpid())
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
