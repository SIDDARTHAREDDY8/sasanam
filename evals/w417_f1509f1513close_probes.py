#!/usr/bin/env python3
"""Wave-417 lane 2 close battery: F1509-F1513 CLOSED.

F1509: String.prototype.trim map staging --
  `var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');`.
  Closed by `_js_f1509_stmt_decode`. Node-exact: for a single UTF-16 code
  unit trim is the identity iff the unit is outside _JS_TRIM_WS (25 code
  points, enumerated 0x0000-0xFFFF on node v24.20.0); the hook fails closed
  on any trimmable code. Disjoint from F1090 (no trim) and F1510/F1511
  (trimStart/trimEnd) by grammar.

F1510: String.prototype.trimStart map staging -- same shape with
  `.trimStart()`. Closed by `_js_f1510_stmt_decode`. Disjoint from
  F1509/F1511 by ident-boundary keyword match.

F1511: String.prototype.trimEnd map staging -- same shape with
  `.trimEnd()`. Closed by `_js_f1511_stmt_decode`.

F1512: map-then-join comma readout --
  `var D=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=D.split(',').join('');`.
  Closed by `_js_f1512_stmt_decode`. Node-exact: the split recovers the
  per-char strings iff no code unit is ',' (44); the hook fails closed on
  any comma code. Disjoint from F1357 (two-statement D=map form) and F1408
  (join/split apply readout, no map) by grammar.

F1513: splice single-element negative drain --
  `var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);`.
  Closed by `_js_f1513_stmt_decode`. Node-exact: splice(-1,1) removes exactly
  the last element; concat reassembles the original order. Only the exact
  two-arg (-1,1) form admitted. Disjoint from F1443 (splice(-C.length)) and
  F1365 (splice(0)) by grammar.

New _decode_layer dispatch loop (F1509-F1513); N_STMTDEC_LOOPS 81->82
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1504-F1508 + F1514-F1516 (outside this lane) still MISS.

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
    ("f1509",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"),
    ("f1510",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimStart();});var S=D.join('');var RESULT=S;"),
    ("f1511",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimEnd();});var S=D.join('');var RESULT=S;"),
    ("f1512",
     "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;"),
    ("f1513",
     "var C={I};var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-416 lineage; N_STMTDEC_LOOPS=82."""
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
    ok = (pin == 82 and len(loops) == 82)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w416 = "# Wave-416:" in ftxt
    ok = ok and has_w416
    notes.append("w416-footer=%s" % has_w416)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w416_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
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
        # F1509 let + renamed
        "let C={I};let D=C.map(function(c){return String.fromCharCode(c).trim();});let S=D.join('');let RESULT=S;",
        # F1510 const + renamed arr
        "const CC={I};const DD=CC.map(function(c){return String.fromCharCode(c).trimStart();});const SS=DD.join('');const RESULT=SS;",
        # F1511 ws-tolerant
        "var C={I} ; var D = C.map( function(c){ return String.fromCharCode(c).trimEnd(); } ) ; var S = D.join('') ; var RESULT = S ;",
        # F1512 renamed
        "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;",
        # F1513 let
        "let C={I};let D=C.splice(-1,1);let E=C.concat(D);let S=String.fromCharCode.apply(null,E);let RESULT=S;",
        # F1513 ws-tolerant splice args
        "var C={I};var D=C.splice( -1 , 1 );var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
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
    # whitespace code (32): trim would empty the position -> hook must miss
    cs_ws = "[" + ",".join(
        ["32"] + [str(ord(c)) for c in SECRET_S[1:]]) + "]"
    # comma code (44): split(',') would mis-decode -> hook must miss
    cs_comma = "[" + ",".join(
        ["44"] + [str(ord(c)) for c in SECRET_S[1:]]) + "]"
    cases = [
        ("f1509-ws-code",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"
         % cs_ws, _dlp._js_f1509_stmt_decode),
        ("f1509-trimstart-shape",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trimStart();});var S=D.join('');var RESULT=S;"
         % cs, _dlp._js_f1509_stmt_decode),
        ("f1510-trim-shape",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"
         % cs, _dlp._js_f1510_stmt_decode),
        ("f1511-trim-shape",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"
         % cs, _dlp._js_f1511_stmt_decode),
        ("f1512-comma-code",
         "var C=%s;var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;"
         % cs_comma, _dlp._js_f1512_stmt_decode),
        ("f1512-wrong-sep",
         "var C=%s;var J=C.map(function(c){return String.fromCharCode(c);}).join(';');var S=J.split(';').join('');var RESULT=S;"
         % cs, _dlp._js_f1512_stmt_decode),
        ("f1512-two-stmt",
         "var C=%s;var J=C.map(function(c){return String.fromCharCode(c);});var S=J.join(',').split(',').join('');var RESULT=S;"
         % cs, _dlp._js_f1512_stmt_decode),
        ("f1513-splice-neg2",
         "var C=%s;var D=C.splice(-2,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % cs, _dlp._js_f1513_stmt_decode),
        ("f1513-splice-neg1-nodefault",
         "var C=%s;var D=C.splice(-1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % cs, _dlp._js_f1513_stmt_decode),
        ("f1513-splice-0",
         "var C=%s;var D=C.splice(0,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % cs, _dlp._js_f1513_stmt_decode),
        ("f1513-splice-len",
         "var C=%s;var D=C.splice(-C.length,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % cs, _dlp._js_f1513_stmt_decode),
        ("f1513-concat-wrong-arg",
         "var C=%s;var D=C.splice(-1,1);var E=C.concat(C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % cs, _dlp._js_f1513_stmt_decode),
    ]
    bad = [n for n, p, fn in cases if fn(p) is not None]
    # find_credential level: the ws/comma variants must also miss overall
    for n, p, _fn in (cases[0], cases[4]):
        if _hits(p):
            bad.append(n + "-loud")
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1090/F1357/F1408/F1443/F1365 still HIT (disjoint by grammar)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1357-twostmt",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;" % cs),
        ("f1408-joinsplit",
         "var C=%s;var D=C.join(';').split(';');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1443-splice-len",
         "var C=%s;var D=C.splice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1365-splice0",
         "var C=%s;var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        "var s='  hello  ';console.log(s.trim());",
        "var a=[1,2,3];var j=a.join(',');console.log(j);",
        "var b=[1,2,3];var c=b.splice(0,1);console.log(c);",
        "var t='a,b,c'.split(',').join('-');console.log(t);",
        "var u='pad me'.padStart(10);console.log(u);",
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
                "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
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
    """F1504-F1508 + F1514-F1516 (outside this lane's closures) still MISS.

    Runs the w416 red-first batteries as subprocesses; each must exit
    0 (all shapes BREAK = still open). F1509-F1513 are excluded --
    they are CLOSED by this lane. F1517 is excluded: incidentally
    CLOSED at the wave-416 merge (verified HIT); the merge footer
    documents it.
    """
    bad = []
    skip = set(range(1509, 1514)) | {1517}
    for n in range(1504, 1517):
        if n in skip:
            continue
        p = os.path.join(REPO_ROOT, "evals",
                         "w416_f%d_redfirst.py" % n)
        if not os.path.exists(p):
            bad.append("f%d(missing)" % n)
            continue
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:8])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w416_attack_probes.

    F1509-F1513 are now closed by this lane (their pins must break);
    F1504-F1508 and F1514-F1516 remain open (their pins must hold);
    F1517's pin breaks (incidentally closed at the wave-416 merge).
    Taxonomy (2143) and footer pins must hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w416_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g417l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w416_attack_probes.py")],
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
        expect_held = {"F1504", "F1505", "F1506", "F1507", "F1508",
                       "F1514", "F1515", "F1516"}
        expect_broken = {"F1509", "F1510", "F1511", "F1512", "F1513",
                         "F1517"}
        ok = (expect_held <= held and expect_broken <= broken)
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = ok and tax and footer
        return (ok, "green(w416_attack): held=%s broken=%s tax=%s footer=%s"
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
