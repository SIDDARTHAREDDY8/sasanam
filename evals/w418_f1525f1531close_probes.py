#!/usr/bin/env python3
"""Wave-418 lane 2 close battery: F1525-F1531 CLOSED.

F1525: String.prototype.match / split-with-limit readout --
  `var S=C.map(function(c){return String.fromCharCode(c);}).join('');`
  `var E=S.match(/./g);` or `var E=S.split('',S.length);`
  `var RESULT=E.join('');`.
  Closed by `_js_f1525_stmt_decode`. Node-exact: match(/./g) yields each
  UTF-16 code unit (`.` never matches the 4 line terminators -- those
  fail closed); split('',S.length) is exact for every code.
  Disjoint from F1408 (no map/match) and F1512 (comma readout) by grammar.

F1526: entries() body-destructure for-of --
  `for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_v);}`.
  Closed by `_js_f1526_stmt_decode`. Node-exact: entries() yields
  [index,value] pairs; the body pushes each value in order.
  Disjoint from F1396 (keys-iterator / header-destructure) by grammar.

F1527: JSON.stringify identity-replacer --
  `var J=JSON.stringify(C,function(k,v){return v;});var E=JSON.parse(J);`.
  Closed by `_js_f1527_stmt_decode`. Node-exact: the replacer is the
  identity, so the roundtrip deep-copies C.
  Disjoint from F1392 (no replacer) by grammar.

F1528: Array.from mapping + thisArg --
  `var E=Array.from(C,function(c){return c;},{});`.
  Closed by `_js_f1528_stmt_decode`. Node-exact: the identity callback
  ignores `this`, so the `{}` thisArg is inert.
  Disjoint from F1393 (no third argument) by grammar.

F1529: apply arguments-object staging --
  `function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}`
  `var E=g.apply(null,C);`.
  Closed by `_js_f1529_stmt_decode`. Node-exact: g() collects its
  arguments in order. The body is parsed rigidly.

F1530: generator yield* staging --
  `function* g(){yield* C;}` `var E=[...g()];`.
  Closed by `_js_f1530_stmt_decode`. Node-exact: the generator yields
  every element of C in order.
  Disjoint from F1304 (yielding mapped chars) by grammar.

F1531: do...while index-push staging --
  `var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);`.
  Closed by `_js_f1531_stmt_decode`. Node-exact: pushes C[0..length-1]
  in order (C non-empty, body runs at least once).
  Disjoint from the while-shift form and F1464 (for-loop) by grammar.

New _decode_layer dispatch loop (F1525-F1531); N_STMTDEC_LOOPS 84->85
(real code-count change). All filed shapes node-exact (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1518-F1524 + F1532-F1545 (outside this lane) still MISS.

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
    ("f1525-match",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');"),
    ("f1525-split",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.split('',S.length);var RESULT=E.join('');"),
    ("f1526",
     "var C={I};var E=[];for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_v);}var S=String.fromCharCode.apply(null,E);"),
    ("f1526-resultalias",
     "var C={I};var E=[];for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_v);}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1527",
     "var C={I};var J=JSON.stringify(C,function(k,v){return v;});var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);"),
    ("f1527-resultalias",
     "var C={I};var J=JSON.stringify(C,function(k,v){return v;});var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1528",
     "var C={I};var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);"),
    ("f1528-resultalias",
     "var C={I};var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1529",
     "var C={I};function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,C);var S=String.fromCharCode.apply(null,E);"),
    ("f1529-resultalias",
     "var C={I};function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1530",
     "var C={I};function* g(){yield* C;}var E=[...g()];var S=String.fromCharCode.apply(null,E);"),
    ("f1530-resultalias",
     "var C={I};function* g(){yield* C;}var E=[...g()];var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1531",
     "var C={I};var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);var S=String.fromCharCode.apply(null,E);"),
    ("f1531-resultalias",
     "var C={I};var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-417 lineage; N_STMTDEC_LOOPS=85."""
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (pin == 85 and len(loops) == 85)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w417 = "# Wave-417:" in ftxt
    ok = ok and has_w417
    notes.append("w417-footer=%s" % has_w417)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w417_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

@_t
def test_p1_filed_shapes():
    """All filed shapes (+ RESULT-alias pin twins) now HIT."""
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
    """let/const, renamed idents, ws-tolerance, arrow map still HIT."""
    tmpls = [
        # F1525 arrow map twin + let
        "let C={I};let S=C.map(c=>String.fromCharCode(c)).join('');let E=S.match(/./g);let RESULT=E.join('');",
        # F1525 ws-tolerant split shape
        "var C={I} ; var S = C.map(function(c){return String.fromCharCode(c);}).join('') ; var E = S.split('',S.length) ; var RESULT = E.join('') ;",
        # F1526 const + renamed
        "const CC={I};const EE=[];for(const _p of CC.entries()){const _i=_p[0],_v=_p[1];EE.push(_v);}const SS=String.fromCharCode.apply(null,EE);",
        # F1527 renamed idents
        "var C={I};var Q=JSON.stringify(C,function(a,b){return b;});var W=JSON.parse(Q);var S=String.fromCharCode.apply(null,W);",
        # F1528 renamed
        "var C={I};var Z=Array.from(C,function(x){return x;},{});var S=String.fromCharCode.apply(null,Z);",
        # F1529 renamed fn
        "var C={I};function h(){var b=[];for(var j=0;j<arguments.length;j++){b.push(arguments[j]);}return b;}var E=h.apply(null,C);var S=String.fromCharCode.apply(null,E);",
        # F1530 ws-tolerant
        "var C={I};function* g(){yield* C;}var E=[ ...g() ];var S=String.fromCharCode.apply(null,E);",
        # F1531 let + renamed
        "let C={I};let E=[];let i=0;do{E.push(C[i]);i++;}while(i<C.length);let S=String.fromCharCode.apply(null,E);",
    ]
    bad = []
    for i, t in enumerate(tmpls):
        if not _hits(t.replace("{I}", _codes(SECRET_S))):
            bad.append("g%d" % i)
    return (not bad, "%d/%d generalizations hit%s"
            % (len(tmpls) - len(bad), len(tmpls),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Wrong forms are NOT claimed by the new hooks (miss at hook level)."""
    cs = _codes(SECRET_S)
    # LF code (10): match(/./g) would drop it -> hook must miss
    cs_lf = "[" + ",".join(
        ["10"] + [str(ord(c)) for c in SECRET_S[1:]]) + "]"
    cases = [
        ("f1525-match-lf",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');"
         % cs_lf, _dlp._js_f1525_stmt_decode),
        ("f1525-match-gi",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./gi);var RESULT=E.join('');"
         % cs, _dlp._js_f1525_stmt_decode),
        ("f1525-split-wronglimit",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.split('',1);var RESULT=E.join('');"
         % cs, _dlp._js_f1525_stmt_decode),
        ("f1525-split-nonempty-sep",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.split(',',S.length);var RESULT=E.join('');"
         % cs, _dlp._js_f1525_stmt_decode),
        ("f1526-swapped-idx",
         "var C=%s;var E=[];for(var _p of C.entries()){var _i=_p[1],_v=_p[0];E.push(_v);}var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1526_stmt_decode),
        ("f1526-push-idx",
         "var C=%s;var E=[];for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_i);}var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1526_stmt_decode),
        ("f1526-keys",
         "var C=%s;var E=[];for(var _p of C.keys()){var _i=_p[0],_v=_p[1];E.push(_v);}var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1526_stmt_decode),
        ("f1527-nonidentity-replacer",
         "var C=%s;var J=JSON.stringify(C,function(k,v){return k;});var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1527_stmt_decode),
        ("f1527-no-replacer",
         "var C=%s;var J=JSON.stringify(C);var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1527_stmt_decode),
        ("f1528-nonempty-thisarg",
         "var C=%s;var E=Array.from(C,function(c){return c;},{x:1});var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1528_stmt_decode),
        ("f1528-nonidentity-cb",
         "var C=%s;var E=Array.from(C,function(c){return c+1;},{});var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1528_stmt_decode),
        ("f1529-extra-stmt",
         "var C=%s;function g(){var a=[];a.push(0);for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,C);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1529_stmt_decode),
        ("f1529-wrong-apply-arg",
         "var C=%s;function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,[]);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1529_stmt_decode),
        ("f1530-yield-nonstar",
         "var C=%s;function* g(){yield C;}var E=[...g()];var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1530_stmt_decode),
        ("f1531-cond-lte",
         "var C=%s;var E=[];var k=0;do{E.push(C[k]);k++;}while(k<=C.length);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1531_stmt_decode),
        ("f1531-incr-before-push",
         "var C=%s;var E=[];var k=0;do{k++;E.push(C[k]);}while(k<C.length);var S=String.fromCharCode.apply(null,E);"
         % cs, _dlp._js_f1531_stmt_decode),
    ]
    bad = [n for n, p, fn in cases if fn(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1392/F1393/F1396/F1304/F1408/F1512 still HIT (disjoint by grammar)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1392-json-roundtrip",
         "var C=%s;var D=JSON.parse(JSON.stringify(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1393-arrayfrom",
         "var C=%s;var E=Array.from(C,function(c){return c;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1396-keys",
         "var C=%s;var D=[];for(var k of C.keys()){D.push(C[k]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1512-comma-readout",
         "var C=%s;var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;" % cs),
        ("f1408-joinsplit",
         "var C=%s;var D=C.join(';').split(';');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1509-trim",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    quiet = [
        "The quarterly financial summary shows revenue growth.",
        "var x=1;var y=x*2;console.log(y);",
        "function add(a,b){return a+b;}",
        "var s='hello world';console.log(s.match(/o/g));",
        "var a=[1,2,3];var b=Array.from(a,function(x){return x;},{});",
        "var o={};var j=JSON.stringify(o,function(k,v){return v;});",
        "function* gen(){yield* [1,2,3];}",
        "var i=0;do{i++;}while(i<10);",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);var S=String.fromCharCode.apply(null,E);" % cs)
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


# ---------------- p7: other opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1518-F1524 + F1532-F1545 (other lanes) still MISS.

    Runs the w417 red-first batteries as subprocesses; each must exit
    0 (all payloads BREAK on the open tree). F1525-F1531 are excluded --
    they are CLOSED by this lane.
    """
    bad = []
    skip = set(range(1525, 1532))
    for n in list(range(1518, 1525)) + list(range(1532, 1546)):
        if n in skip:
            continue
        p = os.path.join(REPO_ROOT, "evals",
                         "w417_f%d_redfirst.py" % n)
        if not os.path.exists(p):
            bad.append("f%d(missing)" % n)
            continue
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            if n == 1518:
                # F1518 partial closure (wave-417 merge): the 5-param
                # arrow shape (f1518-0) was incidentally closed by
                # lane-1's F1504 hook; the filed 4-param null-thisArg
                # shape (f1518-1) must still BREAK.
                if "BREAK f1518-1" not in out:
                    bad.append("f1518-1(closed?)")
                continue
            if r.returncode != 0:
                bad.append("f%d(closed?)" % n)
        except Exception:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    return (not bad, "other opens still miss%s"
            % ("" if not bad else ": " + ",".join(bad[:8])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w417_attack_probes.

    F1525-F1531 are now closed by this lane (their pins must break);
    F1518-F1524 and F1532-F1545 remain open (their pins must hold).
    Taxonomy (2143) and footer pins must hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w417_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g418l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w417_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            if line.startswith("pin-ok "):
                parts = line.split()
                if len(parts) >= 2:
                    held.add(parts[1])
            elif line.startswith("PIN-FAIL "):
                parts = line.split()
                if len(parts) >= 2:
                    broken.add(parts[1])
        expect_held = {"F%d" % n for n in
                       list(range(1518, 1525)) + list(range(1532, 1544))}
        # NOTE: w417_attack_probes has no F1544/F1545 pins (they are
        # covered by their w417 red-first batteries, checked in p7).
        expect_broken = {"F%d" % n for n in range(1525, 1532)}
        ok = (expect_held <= held and expect_broken <= broken)
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = ok and tax and footer
        return (ok, "green(w417_attack): held=%s broken=%s tax=%s footer=%s"
                % (sorted(held & expect_held) == sorted(expect_held),
                   sorted(broken & expect_broken) == sorted(expect_broken),
                   tax, footer))
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
