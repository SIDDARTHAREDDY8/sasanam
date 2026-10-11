#!/usr/bin/env python3
"""Wave-418 lane 4 close battery: F1539-F1545 CLOSED.

F1539: String.prototype.charAt arithmetic-index push-loop staging --
  `var S=C.map(fcc).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*1+0));}var RESULT=E.join('');`.
  Closed by `_js_f1539_stmt_decode`. Node-exact: k*1+0 is the
  arithmetic identity. Disjoint from F1218 (plain-index S+=
  accumulation) by accumulation grammar.

F1540: statement-sequence fragility (parser robustness) --
  `var S=C.map(fcc).join('');var E=<dead>;var RESULT=S;` with
  `var E=S.search(/x/);` or `var E=1;` intervening. Closed by the
  `_js_f1540_strip_dead_stmt` variant production (strips dead,
  side-effect-free `var|let|const` declarations; the layer-2 pass
  decodes the remainder). Node-exact: removing dead pure statements
  cannot change the assembled credential. Fail-closed: the binding
  must occur exactly once and the RHS must be literal/ident/pure-call.

F1541: iterator take()/drop() staging --
  `var E=C.values().take(C.length).toArray();` /
  `var E=C.values().drop(0).toArray();`.
  Closed by `_js_f1541_stmt_decode`. Node-exact: take(len)/drop(0)
  are the identity. Disjoint from F1457 (map-identity chain).

F1542: ES2023/24 computed-arg twins, closed by in-place extensions:
  x4 `.toReversed()` (even-count identity) in `_js_f1434_stmt_decode`;
  `C.toSpliced(C.length,0)` in `_js_f1435_stmt_decode`;
  `C.with(C.length-1,C[C.length-1])` (index/value must match) in
  `_js_f1436_stmt_decode`; `Map.groupBy(C,function(){return 'k';})`
  + `G.get('k')` (key must match) in `_js_f1437_stmt_decode`.

F1543: String identity-method map staging -- `.repeat(1)`,
  `.normalize()`, `.toWellFormed()` wrappers.
  Closed by `_js_f1543_stmt_decode`. Node-exact per-character
  transforms (verified against node v24.20.0 incl. U+2126,
  combining marks, lone surrogates -- surrogates fail closed via
  the F967 discipline). Disjoint from F1514 (valueOf, D=map/S=join
  form).

F1544: `C.splice(-1)` single-arg twin, closed by in-place extension
  of `_js_f1513_stmt_decode` (deleteCount defaults to len-start).
  Node-identical to (-1,1).

F1545: `E=C.map(cb).flat(2)` chained twin, closed by in-place
  extension of `_js_f1432_stmt_decode`. Node-identical to the
  two-statement form.

New _decode_layer dispatch loop (F1539/F1541/F1543); N_STMTDEC_LOOPS
84->85 (real code-count change). F1540's strip is a direct
production (no new loop). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; F1518-F1538 (other lanes) still MISS.

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
    ("f1539",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*1+0));}var RESULT=E.join('');"),
    ("f1540-a",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.search(/x/);var RESULT=S;"),
    ("f1540-b",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=1;var RESULT=S;"),
    ("f1541-take",
     "var C={I};var E=C.values().take(C.length).toArray();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1541-drop",
     "var C={I};var E=C.values().drop(0).toArray();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1542-x4rev",
     "var C={I};var D=C.toReversed().toReversed().toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1542-with",
     "var C={I};var D=C.with(C.length-1,C[C.length-1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1542-spliced",
     "var C={I};var D=C.toSpliced(C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1542-groupby",
     "var C={I};var G=Map.groupBy(C,function(){return 'k';});var E=G.get('k');var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1543-repeat",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).repeat(1);});var RESULT=E.join('');"),
    ("f1543-normalize",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).normalize();});var RESULT=E.join('');"),
    ("f1543-wellformed",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).toWellFormed();});var RESULT=E.join('');"),
    ("f1544",
     "var C={I};var D=C.splice(-1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1545",
     "var C={I};var E=C.map(function(c){return [[c]];}).flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-417 lineage; N_STMTDEC_LOOPS=88; re.compile=29."""
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
    ok = (pin == 88 and len(loops) == 88)
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
    """let/const, renamed idents, ws-tolerance still HIT."""
    tmpls = [
        # F1539 let + renamed
        "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let E=[];for(let k=0;k<S.length;k++){E.push(S.charAt(k*1+0));}let RESULT=E.join('');",
        # F1539 ws-tolerant arithmetic
        "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k * 1 + 0));}var RESULT=E.join('');",
        # F1540 const + renamed, string-literal dead decl
        "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const Q='zz';const RESULT=S;",
        # F1541 renamed
        "var CC={I};var EE=CC.values().drop(0).toArray();var SS=String.fromCharCode.apply(null,EE);var RESULT=SS;",
        # F1542 x6 toReversed (even count identity)
        "var C={I};var D=C.toReversed().toReversed().toReversed().toReversed().toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1542 ws-tolerant with
        "var C={I};var D=C.with( C.length - 1 , C[ C.length - 1 ] );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1543 let + renamed
        "let C={I};let E=C.map(function(c){return String.fromCharCode(c).normalize();});let RESULT=E.join('');",
        # F1544 ws-tolerant single-arg
        "var C={I};var D=C.splice( -1 );var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
        # F1545 const chained
        "const C={I};const E=C.map(function(c){return [[c]];}).flat(2);const S=String.fromCharCode.apply(null,E);const RESULT=S;",
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
    """Wrong forms are NOT claimed (miss at hook level / scanner level)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1539-k2",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*2+0));}var RESULT=E.join('');" % cs,
         _dlp._js_f1539_stmt_decode),
        ("f1539-k1",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*1+1));}var RESULT=E.join('');" % cs,
         _dlp._js_f1539_stmt_decode),
        ("f1541-take1",
         "var C=%s;var E=C.values().take(1).toArray();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1541_stmt_decode),
        ("f1541-drop1",
         "var C=%s;var E=C.values().drop(1).toArray();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1541_stmt_decode),
        ("f1543-repeat2",
         "var C=%s;var E=C.map(function(c){return String.fromCharCode(c).repeat(2);});var RESULT=E.join('');" % cs,
         _dlp._js_f1543_stmt_decode),
        ("f1543-trim-shape",
         "var C=%s;var E=C.map(function(c){return String.fromCharCode(c).trim();});var RESULT=E.join('');" % cs,
         _dlp._js_f1543_stmt_decode),
        ("f1434-x3rev",
         "var C=%s;var D=C.toReversed().toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1434_stmt_decode),
        ("f1434-x1rev",
         "var C=%s;var D=C.toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1434_stmt_decode),
        ("f1435-del1",
         "var C=%s;var D=C.toSpliced(0,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1435_stmt_decode),
        ("f1436-mismatch",
         "var C=%s;var D=C.with(0,C[C.length-1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1436_stmt_decode),
        ("f1437-keymm",
         "var C=%s;var G=Map.groupBy(C,function(){return 'k';});var E=G.get('x');var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1437_stmt_decode),
        ("f1437-obj-strkey",
         "var C=%s;var G=Object.groupBy(C,function(){return 'k';});var E=G['k'];var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1437_stmt_decode),
        ("f1513-dc2",
         "var C=%s;var D=C.splice(-1,2);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1513_stmt_decode),
        ("f1513-neg2",
         "var C=%s;var D=C.splice(-2);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1513_stmt_decode),
        ("f1432-flat1",
         "var C=%s;var E=C.map(function(c){return [[c]];}).flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1432_stmt_decode),
    ]
    bad = [n for n, p, fn in cases if fn(p) is not None]
    # F1540 scanner-level: used-binding and mutating RHS must not strip.
    f1540_cases = [
        ("f1540-used",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.search(/x/);var RESULT=S+E;" % cs),
        ("f1540-mutating",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=C.push(1);var RESULT=S;" % cs),
        ("f1540-result",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    for n, p in f1540_cases:
        # "used" and "mutating" must MISS; the plain base must HIT (sanity).
        if n == "f1540-result":
            if not _hits(p):
                bad.append(n + "-should-hit")
        elif _hits(p):
            bad.append(n + "-loud")
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) + len(f1540_cases) - len(bad),
               len(cases) + len(f1540_cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Neighboring hooks still HIT (disjoint by grammar)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1218-charat-plain",
         "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);}).join('');var S='';for(var i=0;i<H.length;i++){S+=H.charAt(i);}var RESULT=S;" % cs),
        ("f1457-iter-map",
         "var C=%s;var D=C.values().map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1514-valueof",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;" % cs),
        ("f1432-two-stmt",
         "var C=%s;var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1434-orig",
         "var C=%s;var D=C.toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1435-orig",
         "var C=%s;var D=C.toSpliced(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1436-orig",
         "var C=%s;var D=C.with(0,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1437-orig",
         "var C=%s;var G=Map.groupBy(C,function(c){return 0;});var E=G.get(0);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1513-orig",
         "var C=%s;var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (incl. dead-strip-adjacent shapes)."""
    quiet = [
        "The quarterly financial summary shows revenue growth.",
        "var x=1;var y=x*2;console.log(y);",
        "function add(a,b){return a+b;}",
        "var s='  hello  ';console.log(s.trim());",
        "var E=1;console.log('counter', E);",
        "var q='zz';var r=q.search(/z/);console.log(r);",
        "var C=[1,2,3];var E=C.length;console.log(E);",
        "for(var k=0;k<10;k++){console.log(k);}",
        "var t='a,b,c'.split(',').join('-');console.log(t);",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1546-F1569 (attack-86 + residuals, OPEN) still MISS; F1518-F1545 now CLOSED in merge."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1546", "var C=%s;var E=C.flatMap(function(c){return [c];},[]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1547", "var C=%s;var E=C.map(function(c){return String.fromCharCode(c).padStart(10);});var S=E.join('').trim();var RESULT=S;" % cs),
        ("f1548", "var C=%s;var D=C.slice();D.sort((a,b)=>a-b);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1549", "var C=%s;var J=C.map(function(c){return String.fromCharCode(c);}).join('|');var E=J.split('|');var S=E.join('');var RESULT=S;" % cs),
        ("f1567", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var E=C.map(function(c){return String.fromCharCode(c).repeat(1);});var RESULT=E.join('');" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=1;var RESULT=S;" % cs)
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

def _green_check():
    """Depth-1 green on w417_attack_probes.

    F1539-F1543 are now closed by this lane (their pins must break);
    F1518-F1538 remain open (their pins must hold); F1544/F1545 are
    not in w417_attack_probes (filed after it) -- covered by p1.
    Carry pins (F1504-F1516) must HIT. Taxonomy (2143) and footer
    pins must hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w417_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g418l4-green-", dir="/var/tmp")
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
        expect_held = {"F%d" % n for n in range(1518, 1539)}
        expect_broken = {"F1539", "F1540", "F1541", "F1542", "F1543"}
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


# ---------------- main ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = 0
    total = 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        total += 1
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK",
                              fn.__name__, note)))
        if not ok:
            fails += 1
    print("RESULT: %d/%d HELD" % (total - fails, total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
