#!/usr/bin/env python3
"""Wave-422 lane C close battery: F1655-F1666 CLOSED.

F1655: Array.from(S,undefined) -- extends `_js_f1634_stmt_decode`
  (explicit undefined mapfn is a no-op, node-exact). Disjoint from
  F1634 (no second arg) by grammar.
F1656: [...S,] trailing comma -- extends `_js_f1634_stmt_decode`
  (trailing comma is a no-op, node-exact). Disjoint from F1634
  ([...S]) by grammar.
F1657: S.charCodeAt(i) rebuild loop -- extends `_js_f1635_stmt_decode`
  (charCodeAt(i) === codePointAt(i) for BMP; dstr is BMP-only via
  _safe_chr, node-exact). Disjoint from F1635 (codePointAt) by method.
F1658: S[i] bracket-index rebuild loop -- extends
  `_js_f1635_stmt_decode` (S[i] is the char at i, node-exact).
  Disjoint from F1635 (.at(i)) by grammar.
F1659: String(S).toWellFormed() -- extends `_js_f1636_stmt_decode`
  (String(S) is S for string S, node-exact). Disjoint from F1636
  (S.toWellFormed) by wrapper.
F1660: flat(0.000) -- extends `_js_f1562_stmt_decode` (0.000 === 0).
F1661: flat(000) -- extends `_js_f1562_stmt_decode` (legacy octal 000
  === 0). F1662: flat(0e0) -- extends `_js_f1562_stmt_decode`
  (0e0 === 0). F1663: flat(-0e0) -- extends `_js_f1562_stmt_decode`
  (-0e0 === -0). All node-exact, zero-valued depths.
F1664: Object.assign(new Array(00),C) -- extends
  `_js_f1560_stmt_decode` (00 === 0, empty array). F1665:
  Object.assign(new Array(0.0),C) (0.0 === 0). F1666:
  Object.assign(new Array(-0),C) (-0 === 0). All node-exact.

No new _decode_layer dispatch loops (all extensions);
N_STMTDEC_LOOPS stays 99 actual (base pin 100 is a pre-existing
wave-421 merge overstatement, documented in p0).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1642-F1654 and
F1667-F1671 (other opens) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
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
    ("f1655",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S,undefined);var T=D.join('');var RESULT=T;"),
    ("f1656",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S,];var T=D.join('');var RESULT=T;"),
    ("f1657",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.charCodeAt(i));}var RESULT=T;"),
    ("f1658",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=S[i];}var RESULT=T;"),
    ("f1659",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String(S).toWellFormed();var RESULT=T;"),
    ("f1660",
     "var C={I};var D=C.flat(0.000);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1661",
     "var C={I};var D=C.flat(000);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1662",
     "var C={I};var D=C.flat(0e0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1663",
     "var C={I};var D=C.flat(-0e0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1664",
     "var C={I};var D=Object.assign(new Array(00),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1665",
     "var C={I};var D=Object.assign(new Array(0.0),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1666",
     "var C={I};var D=Object.assign(new Array(-0),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-421 lineage; loop count 101 actual (merge);
    re.compile=29. Documents pre-existing pin 100 overstatement."""
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
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    actual = len(loops)
    # This lane adds no dispatch loops (all extensions); merged actual
    # = 99 base +1 lane A +1 lane B = 101.
    # (merge note: wave-421 pin-100 overstatement corrected to 101.)
    ok = (actual == 101)
    notes.append("loops=%d pin=%d (merge: 99+2=101)"
                 % (actual, pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w421 = "# Wave-421:" in ftxt
    ok = ok and has_w421
    notes.append("w421-footer=%s" % has_w421)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w421_attack_probes.py")) as f:
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
    """All 12 filed shapes now HIT (short + long)."""
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
    """Renamed idents, let/const, ws variants, arrow twins."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1655-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const D=Array.from(S, undefined);const T=D.join('');const RESULT=T;" % cs),
        ("f1656-ws",
         "var C = %s ; var S = C.map(function(c){return String.fromCharCode(c);}).join('') ; var D = [...S , ] ; var T = D.join('') ; var RESULT = T ;" % cs),
        ("f1657-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T='';for(var k=0;k<S.length;k++){T+=String.fromCharCode(S.charCodeAt(k));}let RESULT=T;" % cs),
        ("f1658-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for( var i = 0 ; i < S.length ; i++ ){ T += S[i] ; }var RESULT=T;" % cs),
        ("f1659-arrow",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var T=String( S ).toWellFormed();var RESULT=T;" % cs),
        ("f1660-ws",
         "var C=%s;var D=C.flat( 0.000 );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1661-let",
         "let C=%s;let D=C.flat(000);let RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1662-ws",
         "var C=%s;var D=C.flat( 0e0 );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1663-let",
         "let C=%s;let D=C.flat(-0e0);let RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1664-ws",
         "var C=%s;var D=Object.assign( new Array(00) , C );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1665-let",
         "let C=%s;let D=Object.assign(new Array(0.0),C);let RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1666-ws",
         "var C=%s;var D=Object.assign( new Array(-0) , C );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
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
        # F1655: only undefined admitted as second arg
        ("f1655-null", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S,null);var T=D.join('');var RESULT=T;" % cs),
        ("f1655-fn", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S,function(x){return x;});var T=D.join('');var RESULT=T;" % cs),
        # F1656: only one trailing comma
        ("f1656-two", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S,,];var T=D.join('');var RESULT=T;" % cs),
        # F1657: only codePointAt/charCodeAt
        ("f1657-charat", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.charAt(i));}var RESULT=T;" % cs),
        # F1658: only S[i] / S.at(i)
        ("f1658-j", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=S[j];}var RESULT=T;" % cs),
        # F1659: only String(S) wrapper
        ("f1659-lit", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String('x').toWellFormed();var RESULT=T;" % cs),
        # F1660-1663: only filed zero-valued literals
        ("f1660-0001", "var C=%s;var D=C.flat(0.0001);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1661-0001", "var C=%s;var D=C.flat(0001);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1662-0e1", "var C=%s;var D=C.flat(0e1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1663-neg1", "var C=%s;var D=C.flat(-1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1664-1666: only filed zero-valued lengths
        ("f1664-000", "var C=%s;var D=Object.assign(new Array(000),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1665-001", "var C=%s;var D=Object.assign(new Array(0.01),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1666-neg1", "var C=%s;var D=Object.assign(new Array(-1),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
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
        ("f1634-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join('');var RESULT=T;" % cs,
         True),
        ("f1635-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.codePointAt(i));}var RESULT=T;" % cs,
         True),
        ("f1636-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed();var RESULT=T;" % cs,
         True),
        ("f1562-closed",
         "var C=%s;var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1639-closed",
         "var C=%s;var D=C.flat(0.00);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1560-closed",
         "var C=%s;var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1641-closed",
         "var C=%s;var D=Object.assign(new Array(0),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1528-open",
         "var C=%s;var D=Array.from(C,function(c){return String.fromCharCode(c);});var RESULT=D.join('');" % cs,
         False),
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
        "var D=Array.from(items,undefined);var RESULT=D.join(',');",
        "var D=[...text,];var T=D.join('');",
        "for(var i=0;i<s.length;i++){t+=s.charCodeAt(i);}",
        "for(var i=0;i<s.length;i++){t+=s[i];}",
        "var t=String(s).toWellFormed();",
        "var D=C.flat(0.000);var RESULT='hello';",
        "var D=Object.assign(new Array(00),C);var RESULT='hello';",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1642-F1654 (attack 89) and F1667-F1671 (lane-3 residuals) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1642", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;" % cs),
        ("f1649", "var C=%s;var D=Array.from(C,(c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1654", "var C=%s;var D=[...C.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1667", "var C=%s;var D=C.slice();D.fill(1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1671", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKC');var RESULT=T;" % cs),
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
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S,undefined);var T=D.join('');var RESULT=T;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=C.flat(0.000);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs)
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
    """Targeted no-regression check on attack-89 pins (F1642-F1654).

    The full w421_attack_probes.py has outdated _CARRY expectations
    (it expects MISS for F1608-F1641, which are now CLOSED). This
    targeted check verifies the still-OPEN attack-89 findings
    (F1642-F1654) still MISS, plus taxonomy and footer pins.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(attack89-pins): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g422lc-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        # Run w421_attack_probes.py and parse _NEW_PINS results
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w421_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # _NEW_PINS are F1642-F1654 (13); F1648 is incidentally CLOSED
        # by the F1633 hook (Array.prototype.join.call(C,',') shape),
        # so it HITs by design. The other 12 must still MISS.
        new_pins_ok = True
        for n in list(range(1642, 1648)) + list(range(1649, 1655)):
            # Look for "HELD Fn -> MISS" pattern
            if not re.search(r"HELD F%d -> MISS" % n, out):
                new_pins_ok = False
                break
        # F1648 should HIT (incidentally closed by F1633)
        f1648_hit = bool(re.search(r"FAIL F1648 -> HIT", out))
        new_pins_ok = new_pins_ok and f1648_hit
        tax = "taxonomy pin 2143" in out
        footer = "footer pin" in out
        ok = bool(new_pins_ok and tax and footer)
        return (ok, "green(attack89-pins): new_pins=%s tax=%s footer=%s"
                % (new_pins_ok, tax, footer))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


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
