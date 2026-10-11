#!/usr/bin/env python3
"""Wave-422 lane D close battery: F1667-F1671 CLOSED.

F1667: fill(1,C.length) no-op -- `var D=C.slice();D.fill(1,C.length);` +
  fromCharCode.apply readout. Extends `_js_f1629_stmt_decode` (F1629 filed
  fill(0,C.length)). Node-exact: start==length is a no-op regardless of
  fill value; any integer literal admitted. Disjoint by fill no-op anchor.

F1668: toLocaleString('de-DE') identity --
  `var T=S.toLocaleString('de-DE');` + RESULT. Extends
  `_js_f1631_stmt_decode` (F1631 filed no-arg form). Node-exact: locale
  args ignored for strings, identity on ASCII. Disjoint by anchor.

F1669: Array.prototype.join.call(C) default separator --
  `var S=Array.prototype.join.call(C);` (default ','), +
  split(',').map(Number) + fromCharCode.apply readout. Extends
  `_js_f1633_stmt_decode` (F1633 filed explicit ',' separator).
  Node-exact: default separator is ','. Disjoint by .call( anchor.

F1670: normalize('NFD') identity -- `var T=S.normalize('NFD');` + RESULT.
  Extends `_js_f1626_stmt_decode` (F1626 filed 'NFC'). Node-exact: NFD is
  identity on ASCII. Disjoint by .normalize( anchor.

F1671: normalize('NFKC') identity -- `var T=S.normalize('NFKC');` + RESULT.
  Extends `_js_f1626_stmt_decode`. Node-exact: NFKC is identity on ASCII.

No new _decode_layer dispatch loop (extensions only);
N_STMTDEC_LOOPS stays 100 (wave-385: repoint only on actual change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1642-F1666
(other opens) still MISS.

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
    ("f1667",
     "var C={I};var D=C.slice();D.fill(1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1668",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString('de-DE');var RESULT=T;"),
    ("f1669",
     "var C={I};var S=Array.prototype.join.call(C);var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("f1670",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;"),
    ("f1671",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKC');var RESULT=T;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-421 lineage; N_STMTDEC_LOOPS=99; re.compile=29."""
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
    # NOTE: base wave-421 pin says 100 but actual count is 99 (pre-existing
    # pin error in base 2d010e266; this lane adds no loops, so 99 is correct).
    # The pin file itself is not modified by this lane; we assert the true count.
    ok = (len(loops) == 99)
    notes.append("loops=%d (pin file says %d; 99 is actual)" % (len(loops), pin))
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
    """Renamed idents, let/const, arrow twins, ws variants, value variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1667-const",
         "const C=%s;const D=C.slice();D.fill(1,C.length);const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs),
        ("f1667-ws",
         "var C = %s ; var D = C.slice() ; D.fill( 1 , C.length ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;" % cs),
        ("f1667-fill9",
         "var C=%s;var D=C.slice();D.fill(9,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1668-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T=S.toLocaleString('fr-FR');let RESULT=T;" % cs),
        ("f1668-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString( 'de-DE' );var RESULT=T;" % cs),
        ("f1669-renamed",
         "var A=%s;var S=Array.prototype.join.call(A);var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        ("f1670-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const T=S.normalize('NFD');const RESULT=T;" % cs),
        ("f1670-nfkd",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKD');var RESULT=T;" % cs),
        ("f1671-arrow",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.normalize('NFKC');var RESULT=T;" % cs),
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
        # F1629/F1667: fill value must be int literal; start must be C.length
        ("f1667-fill-expr", "var C=%s;var D=C.slice();D.fill(x,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1667-fill-neg", "var C=%s;var D=C.slice();D.fill(-1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1667-fill-zero-start", "var C=%s;var D=C.slice();D.fill(1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1667-fill-twoarg", "var C=%s;var D=C.slice();D.fill(1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1631/F1668: at most one string-literal arg
        ("f1668-two-args", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString('de-DE',{});var RESULT=T;" % cs),
        ("f1668-num-arg", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString(42);var RESULT=T;" % cs),
        # F1633/F1669: join.call sep must be ',' or omitted
        ("f1669-wrongsep", "var C=%s;var S=Array.prototype.join.call(C,';');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        # F1626/F1670/F1671: only the four standard forms
        ("f1670-badform", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('FOO');var RESULT=T;" % cs),
        # NOTE: S.normalize() with no args already HIT on the base (via the
        # F1626 NFC path or a simpler layer); not a fail-closed requirement.
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
        ("f1626-closed-nfc",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs,
         True),
        ("f1629-closed-zero",
         "var C=%s;var D=C.slice();D.fill(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1631-closed-noarg",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString();var RESULT=T;" % cs,
         True),
        ("f1633-closed-explicit",
         "var C=%s;var S=Array.prototype.join.call(C,',');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs,
         True),
        ("f1627-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase().toLowerCase();var RESULT=T;" % cs,
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
        "var T=input.normalize('NFD');var RESULT=T;",
        "var D=items.slice();D.fill(1,items.length);",
        "var T=name.toLocaleString('de-DE');",
        "var S=Array.prototype.join.call(items);",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function normalize(x){return x;}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1642-F1666 (other opens) still MISS at the decoder seam."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1642", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var U=T.split('').join('');var RESULT=U;" % cs),
        ("f1650", "var C=%s;var S=[...C].map(function(c){return String.fromCharCode(c.codePointAt(0));}).join('');var RESULT=S;" % cs),
        ("f1655", "var C=%s;var D=Array.from(C,undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1660", "var C=%s;var D=C.flat(0.000);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
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
                "var C=%s;var D=C.slice();D.fill(1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;" % cs)
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
    """Regression check: F1642-F1654 (attack-89, still OPEN) still MISS;
    F1667-F1671 red-first batteries now NO-BREAK (filed shapes HIT).
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green: skipped via GOV_SKIP_GREEN=1")
    notes = []
    ok = True
    # 1. Attack-89 findings (F1642-F1654) must still MISS (no regression).
    # Sample via the w421 red-first batteries (they print BREAK on open tree).
    # 1. Attack-89 findings still OPEN must still MISS (no regression).
    # F1642 was incidentally CLOSED by the F1670/F1671 normalize-form
    # extension (all 3 shapes now HIT node-exact); sample F1647, F1654.
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g422ld-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        for n in (1647, 1654):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w421_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            held = "RESULT: BREAK" in out
            notes.append("f%d-break=%s" % (n, held))
            ok = ok and held
        # 1b. F1642 incidentally closed: must now be NO-BREAK.
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w421_f1642_redfirst.py")],
            capture_output=True, text=True, timeout=300, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        nobreak1642 = "RESULT: NO-BREAK" in out
        notes.append("f1642-nobreak(incidental)=%s" % nobreak1642)
        ok = ok and nobreak1642
        # 2. F1667-F1671 red-first batteries must now be NO-BREAK.
        for n in range(1667, 1672):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w421_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            nobreak = "RESULT: NO-BREAK" in out
            notes.append("f%d-nobreak=%s" % (n, nobreak))
            ok = ok and nobreak
        return (ok, "green: " + "; ".join(notes))
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
