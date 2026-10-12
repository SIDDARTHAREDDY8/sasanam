#!/usr/bin/env python3
"""Wave-426 lane A close battery: F1715-F1719 CLOSED.

F1715: reduceRight array-building --
  `var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);` +
  fromCharCode.apply readout. New `_js_f1715_stmt_decode`. Node-exact:
  reduceRight iterates from the end; [c].concat(a) prepends each
  element, rebuilding C in original order. Disjoint from F1713
  (reduce left-to-right with a.concat([c])) by grammar.

F1716: entries-destructuring for-of --
  `var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}` +
  fromCharCode.apply readout. New `_js_f1716_stmt_decode`. Node-exact:
  entries() yields [index,value] pairs; destructuring binds [i,c];
  pushes c. Disjoint from F1701 (for(var e of E){D.push(e[1]);})
  by grammar.

F1717: Object.entries destructuring readout --
  `var O=Object.assign({},C);var D=[];`
  `for(var [k,v] of Object.entries(O)){D.push(Number(v));}` +
  fromCharCode.apply readout. New `_js_f1717_stmt_decode`. Node-exact:
  assign copies C to object; entries yields [k,v]; pushes Number(v).
  Disjoint from F1694 (entries map) by grammar.

F1718: push.apply staging --
  `var D=[];D.push.apply(D,C);` + fromCharCode.apply readout.
  New `_js_f1718_stmt_decode`. Node-exact: push.apply spreads C as
  push args with D as receiver; D becomes a copy of C. No prior
  filed finding covers this production.

F1719: Array.from explicit-undefined thisArg --
  `var D=Array.from(C,function(c){return c;},undefined);` +
  fromCharCode.apply readout. New `_js_f1719_stmt_decode`. Node-exact:
  identity callback ignores this; undefined thisArg inert.
  Disjoint from F1710 (null thisArg), F1528 ({} thisArg) by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 111->112
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1720-F1734
(other opens) still MISS.

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
    ("f1715",
     "var C={I};var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1716",
     "var C={I};var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1717",
     "var C={I};var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(O)){D.push(Number(v));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1718",
     "var C={I};var D=[];D.push.apply(D,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1719",
     "var C={I};var D=Array.from(C,function(c){return c;},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=112 (111 base + 1 lane); re.compile=29; pin 2143; wave-425 merge footer."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 112)
    notes.append("loops=%d (expect 112)" % len(loops))
    has_new = "_js_f1715_stmt_decode, _js_f1716_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1715-loop=%s" % has_new)
    # tail guard on the new loop
    new_loop_idx = body.find("_js_f1715_stmt_decode, _js_f1716_stmt_decode,")
    tail = body[new_loop_idx:new_loop_idx + 800]
    has_guard = "_MAX_CANDIDATES" in tail
    ok = ok and has_guard
    notes.append("tail-guard=%s" % has_guard)
    for fn in ("_js_f1715_stmt_decode", "_js_f1716_stmt_decode",
               "_js_f1717_stmt_decode", "_js_f1718_stmt_decode",
               "_js_f1719_stmt_decode"):
        has = ("def %s(" % fn) in dsrc
        ok = ok and has
        notes.append("%s=%s" % (fn[4:11], has))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w425 = "# Wave-425:" in ftxt
    ok = ok and has_w425
    notes.append("w425-footer=%s" % has_w425)
    ok = ok and ("2143" in ftxt)
    notes.append("tax2143=%s" % ("2143" in ftxt))
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
        ("f1715-let-renamed",
         "let A=%s;let B=A.reduceRight(function(x,y){return [y].concat(x);},[]);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1715-const-ws",
         "const C = %s ; const D = C.reduceRight(function(a,c){return [c].concat(a);},[]) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1716-let-renamed",
         "let A=%s;let E=A.entries();let B=[];for(let [j,d] of E){B.push(d);}let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1716-let-ws",
         "let C = %s ; let E = C.entries() ; let D = [] ; for(let [i,c] of E){D.push(c);} let S = String.fromCharCode.apply(null,D) ; let RESULT = S ;" % cs),
        ("f1717-let-renamed",
         "let A=%s;let O=Object.assign({},A);let B=[];for(let [m,n] of Object.entries(O)){B.push(Number(n));}let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1718-let-renamed",
         "let A=%s;let B=[];B.push.apply(B,A);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1718-const-ws",
         "const C = %s ; const D = [] ; D.push.apply(D,C) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
        ("f1719-let-renamed",
         "let A=%s;let B=Array.from(A,function(q){return q;},undefined);let T=String.fromCharCode.apply(null,B);let RESULT=T;" % cs),
        ("f1719-const-ws",
         "const C = %s ; const D = Array.from(C,function(c){return c;},undefined) ; const S = String.fromCharCode.apply(null,D) ; const RESULT = S ;" % cs),
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
        # F1715: must be reduceRight (reduce is F1713's closed domain)
        ("f1715-reduce",
         "var C=%s;var D=C.reduce(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1715: callback must be [c].concat(a), not a.concat([c])
        ("f1715-cb-flipped",
         "var C=%s;var D=C.reduceRight(function(a,c){return a.concat([c]);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1715: init must be [] (non-empty init fails closed)
        ("f1715-nonempty-init",
         "var C=%s;var D=C.reduceRight(function(a,c){return [c].concat(a);},[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1716: indexed e[1] readout is F1701's CLOSED domain (sibling pin, not fail-closed here)
        # F1716: must push the value var, not the index var
        ("f1716-push-idx",
         "var C=%s;var E=C.entries();var D=[];for(var [i,c] of E){D.push(i);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1717: must wrap in Number() (bare v fails closed)
        ("f1717-no-number",
         "var C=%s;var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(O)){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1717: entries base must be O
        ("f1717-wrong-base",
         "var C=%s;var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(C)){D.push(Number(v));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1718: receiver must be D (wrong receiver fails closed)
        ("f1718-wrong-recv",
         "var C=%s;var D=[];D.push.apply(C,D);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1718: method must be push (pop.apply fails closed)
        ("f1718-pop-apply",
         "var C=%s;var D=[];D.pop.apply(D,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1719: null/{} thisArgs are F1710's/F1528's CLOSED domains (sibling pins, not fail-closed here)
        # F1719: must be 1-param callback
        ("f1719-2param",
         "var C=%s;var D=Array.from(C,function(c,i){return c;},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        ("f1713-closed-reduce",
         "var C=%s;var D=C.reduce(function(a,c){return a.concat([c]);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1701-closed-entries-idx",
         "var C=%s;var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1694-closed-objentries-map",
         "var C=%s;var O=Object.assign({},C);var E=Object.entries(O);var D=E.map(function(e){return Number(e[1]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1710-closed-from-null",
         "var C=%s;var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1528-closed-from-obj",
         "var C=%s;var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1393-closed-from-noarg",
         "var C=%s;var D=Array.from(C,function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
        "var D=items.reduceRight(function(a,c){return [c].concat(a);},[]);",
        "for(var [i,c] of rows.entries()){out.push(c);}",
        "for(var [k,v] of Object.entries(cfg)){out.push(Number(v));}",
        "var D=[];D.push.apply(D,items);",
        "var D=Array.from(items,function(c){return c;},undefined);",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function reduceRight(a,c){return [c].concat(a);}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1720-F1734 (other opens) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1720",
         "var C=%s;var T=C.join(undefined);var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1721",
         "var C=%s;var D=[C];var E=D.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1722",
         "var C=%s;var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1723",
         "var C=%s;var T=[];C.findLast(function(c){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;" % cs),
        ("f1724",
         "var C=%s;var D=C.filter(function(c,i,a){return a[i]===c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1725",
         "var C=%s;var D=C.flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % ("[55296," + ",".join(str(ord(c)) for c in SECRET_S) + "]")),
        ("f1726",
         "var C=%s;var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1734",
         "var C=[%s,0xD800];var S=String.fromCharCode.apply(null,C);var RESULT=S;" % ",".join(str(ord(c)) for c in SECRET_S)),
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
        sites.append("var C=%s;var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(O)){D.push(Number(v));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=[];D.push.apply(D,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        sites.append("var C=%s;var D=Array.from(C,function(c){return c;},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    # F1720/F1721 red-first should still BREAK (open findings)
    for fn, name in (("w425_f1720_redfirst.py", "f1720"),
                     ("w425_f1721_redfirst.py", "f1721")):
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
