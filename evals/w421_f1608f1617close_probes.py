#!/usr/bin/env python3
"""Wave-421 lane 1 close battery: F1608, F1609, F1610, F1612-F1617 CLOSED.

F1608: flatMap further thisArg twins -- 3-param function with "q"
  thisArg, 1-param arrow with undefined thisArg. Closed by
  `_js_f1608_stmt_decode`. Node-exact: thisArg never read.
  Disjoint from F1570 (2-param fn; 1-param arrow null/numeric) by
  grammar.

F1609: padStart/padEnd further variants -- template-literal
  padString, no-padString no-ops, length-exact no-ops. Closed by
  `_js_f1609_stmt_decode`. Node-exact: identity forms. Disjoint
  from F1571 (quoted padString + S.length+INT) by grammar.

F1610: sort further no-op comparators -- Number(a>b), b>=a. Closed
  by `_js_f1610_stmt_decode`. Node-exact: never negative, V8 no-op.
  Disjoint from F1572 (bare a>b) by grammar.

F1612: slice/substring/substr identity variants --
  slice(0,undefined), substring(0,undefined), substr(0,S.length),
  slice(-S.length). Closed by `_js_f1612_stmt_decode`. Node-exact:
  all identities. Disjoint from F1575 (single-arg) by grammar.

F1613: valueOf wrapper variants -- Object(c).valueOf(), new
  String(S).valueOf(). Closed by `_js_f1613_stmt_decode`.
  Node-exact: identities. Disjoint from F1576 ((c).valueOf(),
  String(S).valueOf()) by grammar.

F1614: sparse toString two-hole prefix -- new Array(2).concat(C),
  Array(2).concat(C). Closed by `_js_f1614_stmt_decode`. Node-exact:
  two-comma prefix, slice(2) readout. Disjoint from F1577
  (Array(1)) by grammar.

F1615: String.raw live-template variants -- expression-first,
  backslash-n escaped. Closed by `_js_f1615_stmt_decode`.
  Node-exact: slice readouts. Disjoint from F1578 by grammar.

F1616: includes gated readout variants -- undefined/null/missing
  fromIndex. Closed by `_js_f1616_stmt_decode`. Node-exact: gate
  truthy. Disjoint from F1579 (-0/false/0) by grammar.

F1617: search pattern variants -- template-literal, new String.
  Closed by `_js_f1617_stmt_decode`. Node-exact: index 0, slice(K)
  identity. Disjoint from F1580 by grammar.

New _decode_layer dispatch loop (F1608/F1609/F1610/F1612-F1617);
N_STMTDEC_LOOPS 95->96 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1618-F1641
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
    try:
        r = _dlp.find_credential(payload)
        return bool(r)
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


# ---------------- filed shapes ----------------

_FILED = [
    # F1608: flatMap thisArg twins
    ("f1608-0",
     "var C={I};var E=C.flatMap(function(c,i,a){return [String.fromCharCode(c)];},\"q\");var S=E.join('');var RESULT=S;"),
    ("f1608-1",
     "var C={I};var E=C.flatMap((c)=>[String.fromCharCode(c)],undefined);var S=E.join('');var RESULT=S;"),
    ("f1608-2",
     "var C={I};var E=C.flatMap((c)=>[String.fromCharCode(c)],1);var S=E.join('');var RESULT=S;"),
    # F1609: padStart/padEnd variants
    ("f1609-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+8,'abcd');var T=P.slice(-S.length);var RESULT=T;"),
    ("f1609-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padEnd(S.length+8,'wxyz');var T=P.slice(0,S.length);var RESULT=T;"),
    ("f1609-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+4,`ab`);var T=P.slice(-S.length);var RESULT=T;"),
    ("f1609-3",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.padStart(S.length);var RESULT=T;"),
    ("f1609-4",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.padEnd(S.length,'x');var RESULT=T;"),
    ("f1609-5",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.padStart(0);var RESULT=T;"),
    # F1610: sort comparators
    ("f1610-0",
     "var C={I};var D=C.slice().sort(function(a,b){return Number(a>b);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1610-1",
     "var C={I};var D=C.slice().sort(function(a,b){return b>=a;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1612: slice/substring/substr variants
    ("f1612-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0,undefined);var RESULT=T;"),
    ("f1612-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substring(0,undefined);var RESULT=T;"),
    ("f1612-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substr(0,S.length);var RESULT=T;"),
    ("f1612-3",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(-S.length);var RESULT=T;"),
    # F1613: valueOf variants
    ("f1613-0",
     "var C={I};var E=C.map(function(c){return Object(c).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1613-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=new String(S).valueOf();var RESULT=T;"),
    # F1614: sparse toString
    ("f1614-0",
     "var C={I};var D=new Array(2).concat(C);var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("f1614-1",
     "var C={I};var D=Array(2).concat(C);var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    # F1615: String.raw variants
    ("f1615-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`${S}abc`;var U=T.slice(0,S.length);var RESULT=U;"),
    ("f1615-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`\\n${S}\\n`;var U=T.slice(2,-2);var RESULT=U;"),
    # F1616: includes variants
    ("f1616-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',undefined);var RESULT=K?S:'';"),
    ("f1616-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',null);var RESULT=K?S:'';"),
    ("f1616-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('x');var RESULT=K?S:'';"),
    # F1617: search variants
    ("f1617-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(`xoxb`);var T=S.slice(K);var RESULT=T;"),
    ("f1617-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(new String('xoxb'));var T=S.slice(K);var RESULT=T;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-420 lineage; N_STMTDEC_LOOPS=96; re.compile=29."""
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
    ok = (pin == 96 and len(loops) == 96)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w420 = "# Wave-420:" in ftxt
    ok = ok and has_w420
    notes.append("w420-footer=%s" % has_w420)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w420_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
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
    """Renamed idents, let/const, arrow twins, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1608-const",
         "const C=%s;const E=C.flatMap(function(x,y,z){return [String.fromCharCode(x)];},\"q\");const S=E.join('');const RESULT=S;" % cs),
        ("f1608-ws",
         "var C = %s ; var E = C.flatMap( (c) => [String.fromCharCode(c)] , undefined ) ; var S = E.join('') ; var RESULT = S ;" % cs),
        ("f1609-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T=S.padStart(S.length);let RESULT=T;" % cs),
        ("f1610-arrow-ws",
         "var C=%s;var D=C.slice().sort( function( a , b ) { return Number( a > b ) ; } );var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1612-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const T=S.slice(0,undefined);const RESULT=T;" % cs),
        ("f1613-let",
         "let C=%s;let E=C.map((c)=>Object(c).valueOf());let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cs),
        ("f1614-ws",
         "var C=%s;var D=new Array( 2 ).concat( C );var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        ("f1615-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const T=String.raw`${S}abc`;const U=T.slice(0,S.length);const RESULT=U;" % cs),
        ("f1616-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let K=S.includes('xoxb',null);let RESULT=K?S:'';" % cs),
        ("f1617-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search( `xoxb` );var T=S.slice(K);var RESULT=T;" % cs),
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
        # F1608: only 3-param fn + string, or 1-param arrow + undefined
        # (2-param fn + string is F1570; 1-param arrow + null is F1570)
        ("f1608-4param",
         "var C=%s;var E=C.flatMap(function(c,i,a,b){return [String.fromCharCode(c)];},\"q\");var S=E.join('');var RESULT=S;" % cs),
        ("f1608-undef-fn",
         "var C=%s;var E=C.flatMap(function(c,i,a){return [String.fromCharCode(c)];},undefined);var S=E.join('');var RESULT=S;" % cs),
        # F1609: template padString must be non-empty; no ${}
        ("f1609-empty-tmpl",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+4,``);var T=P.slice(-S.length);var RESULT=T;" % cs),
        ("f1609-expr-tmpl",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+4,`${S}`);var T=P.slice(-S.length);var RESULT=T;" % cs),
        # F1610: only Number(a>b) or b>=a (bare a>b is F1572)
        ("f1610-alt",
         "var C=%s;var D=C.slice().sort(function(a,b){return a>=b;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1610-string",
         "var C=%s;var D=C.slice().sort(function(a,b){return String(a>b);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1612: only the 4 admitted forms (slice(0) single-arg is F1575)
        ("f1612-substr2",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substr(0,undefined);var RESULT=T;" % cs),
        ("f1612-slice2",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0,5);var RESULT=T;" % cs),
        # F1613: only Object(c) or new String(S) ((c).valueOf() is F1576;
        # Number(c).valueOf() is handled by F1553, not tested here)
        # F1614: only Array(2)
        ("f1614-1",
         "var C=%s;var D=new Array(1).concat(C);var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        ("f1614-3",
         "var C=%s;var D=new Array(3).concat(C);var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        # F1615: only the 2 admitted template shapes
        ("f1615-multi",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b${S}c`;var U=T.slice(0,S.length);var RESULT=U;" % cs),
        # F1616: only undefined/null/missing (-0/false/0 is F1579;
        # NaN is handled by another hook, not tested here)
        # F1617: only template or new String (regex is F1580, plain is F1557;
        # concat is handled by another hook, not tested here)
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Sibling findings still handled by their own hooks."""
    cs = _codes(SECRET_S)
    cases = [
        # F1570 (2-param fn string thisArg)
        ("f1570",
         "var C=%s;var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},\"xy\");var S=E.join('');var RESULT=S;" % cs),
        # F1571 (quoted padString + length+INT)
        ("f1571",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var T=P.slice(-S.length);var RESULT=T;" % cs),
        # F1572 (bare a>b)
        ("f1572",
         "var C=%s;var D=C.slice().sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1575 (slice(0) single-arg)
        ("f1575",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0);var RESULT=T;" % cs),
        # F1576 ((c).valueOf())
        ("f1576",
         "var C=%s;var E=C.map(function(c){return (c).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1577 (Array(1))
        ("f1577",
         "var C=%s;var D=new Array(1).concat(C);var S=D.toString();var T=S.split(',').slice(1).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        # F1578 (String.raw q${S}w)
        ("f1578",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var U=T.slice(1,-1);var RESULT=U;" % cs),
        # F1579 (includes -0)
        ("f1579",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',-0);var RESULT=K?S:'';" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d sibling pins hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest-text quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    cases = [
        ("honest-1", "var x = 1; var y = 2; console.log('hello world');"),
        ("honest-2", "function add(a,b){return a+b;} var r = add(1,2);"),
        ("honest-3", "var s = 'not a credential'; var t = s.toUpperCase();"),
        ("honest-4", "var arr = [1,2,3]; var doubled = arr.map(x=>x*2);"),
        ("honest-5", "if (x > 0) { console.log('positive'); } else { console.log('neg'); }"),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still MISS ----------------

@_t
def test_p6_other_opens_miss():
    """F1618-F1641 (other opens) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        # F1618: map arrow-Number (representative)
        ("f1618",
         "var C=%s;var E=C.map((c)=>Number(c));var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1626: normalize NFC (representative)
        ("f1626",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs),
        # F1637: datalist prose (representative)
        ("f1637",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var H='<datalist>'+S+'</datalist>';var RESULT=H;" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 sites in reasonable time."""
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');"
               "var T=S.slice(0,undefined);var RESULT=T;" % cs)
    t0 = time.time()
    for _ in range(200):
        _hits(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return (ok, "200 sites in %.1fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w420_attack_probes.

    F1608/F1609/F1610/F1612-F1617 now HIT (closed, expected FAIL in
    attack battery); F1618-F1641 still MISS (open, expected HELD).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "skipped (GOV_SKIP_GREEN=1)")
    tmpd = None
    try:
        import tempfile
        tmpd = tempfile.mkdtemp(prefix="w421l1-green-",
                                dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmpd
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "evals", "w420_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=REPO_ROOT)
        out = (r.stdout or "") + (r.stderr or "")
        # Expect: F1608/F1609/F1610/F1612-F1617 -> HIT (FAIL lines)
        #         F1618-F1641 -> MISS/QUIET (HELD lines)
        closed = ["F1608", "F1609", "F1610", "F1612", "F1613",
                  "F1614", "F1615", "F1616", "F1617"]
        ok = True
        notes = []
        for fn in closed:
            if ("FAIL %s -> HIT" % fn) not in out:
                ok = False
                notes.append("%s not HIT" % fn)
        # F1618+ should still be HELD (MISS)
        for line in out.split("\n"):
            if line.startswith("HELD F16") and "-> MISS" in line:
                pass  # good
            elif line.startswith("FAIL F16"):
                fn = line.split()[1]
                if fn not in closed:
                    ok = False
                    notes.append("%s unexpected HIT" % fn)
        return (ok, "closed HIT ok; %s" % ("; ".join(notes) if notes else "others held"))
    except Exception as e:
        return (False, "green check error: %s" % e)
    finally:
        if tmpd and os.path.isdir(tmpd):
            shutil.rmtree(tmpd, ignore_errors=True)


@_t
def test_g0_green():
    return _green_check()


def main():
    fails = 0
    for fn in TESTS:
        name = fn.__name__
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %s: %s" % (type(e).__name__, e)
        print(("HELD " if ok else "BREAK ") + "%s: %s" % (name, note))
        if not ok:
            fails += 1
    print("RESULT: %d/%d HELD" % (len(TESTS) - fails, len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
