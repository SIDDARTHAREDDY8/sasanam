#!/usr/bin/env python3
"""Wave-413 lane 1 close battery: F1349-F1352 CLOSED.

F1349: Array.prototype.flat staged reads -- `var D=C.map(function(c){return [c];});var E=D.flat();`
  + fromCharCode.apply assembles node-exactly (v24.20.0) while find_credential MISSED.
  Closed by `_js_f1349_stmt_decode` (map-singleton + flat + apply parser; fail-closed on flat(2),
  non-singleton callbacks). Disjoint from F1030/F1111/F1142 by grammar.

F1350: Array.prototype.flatMap bare staging -- `var E=C.flatMap(function(c){return [c];});`
  + fromCharCode.apply assembles node-exactly (v24.20.0) while find_credential MISSED.
  Closed by `_js_f1350_stmt_decode` (bare flatMap parser; fail-closed if .flat( follows --
  that's F1142's grammar). Disjoint from F1142 by grammar.

F1351: String.prototype.replaceAll no-op wrapper -- map+join then `.replaceAll('x','x')`
  assembles node-exactly (v24.20.0) while find_credential MISSED. Closed by
  `_js_f1351_stmt_decode` (no-op replaceAll parser; fail-closed on differing args).
  Disjoint from F1272 (no replaceAll) by grammar.

F1352: Array.prototype.sort stable no-op staging -- `C.slice(); D.sort((a,b)=>0);`
  + fromCharCode.apply assembles node-exactly (v24.20.0, V8 stable sort) while
  find_credential MISSED. Closed by `_js_f1352_stmt_decode` (slice + zero-comparator
  sort parser; fail-closed on non-zero comparators). Disjoint from F1153 by grammar.

New _decode_layer dispatch loop (F1349-F1352); N_STMTDEC_LOOPS 69->70
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1353-F1359 (outside this lane) still MISS.

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


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-412 lineage; N_STMTDEC_LOOPS=70."""
    ok = True
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
    ok = (pin == 70 and len(loops) == 70)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w412 = "# Wave-412:" in ftxt
    ok = ok and has_w412
    notes.append("w412-footer=%s" % has_w412)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w412_attack_probes.py")) as f:
        asrc = f.read()
    m2 = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", asrc)
    tax_pin = int(m2.group(1)) if m2 else -1
    ok = ok and (tax_pin == 2143)
    notes.append("taxonomy-pin=%d" % tax_pin)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

_FILED = [
    ("f1349",
     "var C={I};var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1350",
     "var C={I};var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1351",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replaceAll('x','x');var RESULT=U;"),
    ("f1352",
     "var C={I};var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


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
    """Arrow forms, let/const, renamed idents, flat(1), slice(0) still HIT."""
    tmpls = [
        # F1349 arrow + flat(1) + let
        "let C={I};let D=C.map(c=>[c]);let E=D.flat(1);let S=String.fromCharCode.apply(null,E);let RESULT=S;",
        # F1349 renamed identifiers
        "var CC={I};var DD=CC.map(function(x){return [x];});var EE=DD.flat();var SS=String.fromCharCode.apply(null,EE);var RESULT=SS;",
        # F1350 arrow
        "var C={I};var E=C.flatMap((c)=>[c]);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
        # F1350 const
        "const C={I};const E=C.flatMap(function(c){return [c];});const S=String.fromCharCode.apply(null,E);const RESULT=S;",
        # F1351 arrow char callback
        "var C={I};var D=C.map(c=>String.fromCharCode(c));var S=D.join('');var U=S.replaceAll('ab','ab');var RESULT=U;",
        # F1352 arrow zero-cb + slice(0)
        "var C={I};var D=C.slice(0);D.sort((a,b)=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1352 renamed
        "var CC={I};var DD=CC.slice();DD.sort(function(x,y){return 0;});var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
    ]
    bad = [t for t in tmpls
           if not _hits(t.replace("{I}", _codes(SECRET_S)))]
    return (not bad, "%d/%d general hit%s"
            % (len(tmpls) - len(bad), len(tmpls),
               "" if not bad else ": %d miss" % len(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Wrong forms are NOT claimed by the new hooks (miss at hook level)."""
    cases = [
        ("f1349-flat2",
         "var C=%s;var D=C.map(function(c){return [c];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1349_stmt_decode),
        ("f1349-nonsingleton",
         "var C=%s;var D=C.map(function(c){return [c,c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1349_stmt_decode),
        ("f1350-with-flat",
         "var C=%s;var E=C.flatMap(function(c){return [c];}).flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1350_stmt_decode),
        ("f1351-diff-args",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replaceAll('x','y');var RESULT=U;"
         % _codes(SECRET_S), _dlp._js_f1351_stmt_decode),
        ("f1351-join-comma",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join(',');var U=S.replaceAll('x','x');var RESULT=U;"
         % _codes(SECRET_S), _dlp._js_f1351_stmt_decode),
        ("f1352-nonzero",
         "var C=%s;var D=C.slice();D.sort(function(a,b){return 1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1352_stmt_decode),
        ("f1352-no-slice",
         "var C=%s;D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1352_stmt_decode),
    ]
    bad = [n for n, p, hook in cases if hook(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1030/F1111/F1142/F1272/F1153 still decode their own shapes."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1111-flat-spread",
         "var C=%s;var S=String.fromCharCode(...C.flat());var RESULT=S;" % cs),
        ("f1142-nested",
         "var C=%s;var S=String.fromCharCode(...C.flatMap(function(c){return [[c]];}).flat(2));var RESULT=S;" % cs),
        ("f1272-replace",
         "var C=%s;var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=J.replace(/(.)/g,'$1');var RESULT=S;" % cs),
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
        "var arr=[1,2,3];var flat=arr.flat();console.log(flat);",
        "var s='hello';var t=s.replaceAll('l','L');",
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
        if i % 4 == 0:
            sites.append(
                "var C=%s;var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("var x=%d;var y=x*2;" % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens still miss ----------------

_OTHER_OPENS = [
    ("f1353",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;"),
    ("f1354",
     "var C={I};var E=[];for(var i=0;i<C.length;i++){E.push([i,C[i]]);}var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;"),
    ("f1355",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    ("f1356",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    ("f1358",
     "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
]


@_t
def test_p7_other_opens_miss():
    """F1353-F1358 (outside this lane) still MISS."""
    bad = []
    for name, tmpl in _OTHER_OPENS:
        p = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(p):
            bad.append(name)
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w412_attack_probes: F1349-F1359 still open (HELD).

    F1349-F1352 are now closed by this lane; the green check verifies
    F1353-F1359 remain open. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w412_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g413l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w412_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # F1353-F1359 still OPEN -> HELD; F1349-F1352 now CLOSED -> may BREAK
        still_open = set(range(1353, 1360))
        ok = (still_open <= held and not (still_open & broken))
        return (ok, "green(w412_attack): open-hold=%d/7%s"
                % (len(still_open & held), "" if ok else " MISMATCH"))
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
