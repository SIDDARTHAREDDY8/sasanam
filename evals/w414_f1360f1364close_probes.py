#!/usr/bin/env python3
"""Wave-414 lane 1 close battery: F1360-F1364 CLOSED.

F1360: Array.prototype.filter Boolean-callback staging --
  `var D=C.filter(Boolean);` + fromCharCode.apply assembles node-exactly
  (v24.20.0) while find_credential MISSED. Closed by
  `_js_f1360_stmt_decode` (filter(Boolean) parser; fail-closed when any
  code is 0 -- Boolean(0) is falsy so the filter would drop it).
  Disjoint from F1248 (filter side-effect accumulation) by grammar.

F1361: Array.prototype.map index-param staging --
  `var D=C.map(function(c,i){return c;});` and the `a[i]` twin +
  fromCharCode.apply assemble node-exactly (v24.20.0) while
  find_credential MISSED. Closed by `_js_f1361_stmt_decode`
  (identity-callback parser: 2-param `return p1` / 3-param
  `return p3[p2]`). Disjoint from F1350 (flatMap) and F1349
  (map+flat) by grammar.

F1362: Object.keys forEach-built staging (F1220/F979 residual) --
  `C.forEach(function(c,i){O['k'+i]=c;});` then
  `Object.keys(O).map(function(k){return O[k];})` + fromCharCode.apply
  assembles node-exactly (v24.20.0; 'k'-prefixed keys keep insertion
  order) while find_credential MISSED. Closed by
  `_js_f1362_stmt_decode`. Disjoint from F1220/F979 by grammar.

F1363: Object.values forEach-built staging (F1324 residual) --
  same forEach build, `Object.values(O)` readout. Closed by
  `_js_f1363_stmt_decode`. Disjoint from F1324 by grammar.

F1364: Object.entries forEach-built staging (F1242 residual) --
  same forEach build, `for(var e of Object.entries(O)){A.push(e[1]);}`
  readout. Closed by `_js_f1364_stmt_decode`. Disjoint from
  F1242/F1273 by grammar.

New _decode_layer dispatch loop (F1360-F1364); N_STMTDEC_LOOPS 72->73
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1365-F1375 (outside this lane) still MISS.

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
    """Pin 2143 holds; footer has wave-413 lineage; N_STMTDEC_LOOPS=74 (merge: 72+2)."""
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
    ok = (pin == 74 and len(loops) == 74)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w413 = "# Wave-413:" in ftxt
    ok = ok and has_w413
    notes.append("w413-footer=%s" % has_w413)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w413_attack_probes.py")) as f:
        asrc = f.read()
    m2 = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", asrc)
    tax_pin = int(m2.group(1)) if m2 else -1
    ok = ok and (tax_pin == 2143)
    notes.append("taxonomy-pin=%d" % tax_pin)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

_FILED = [
    ("f1360",
     "var C={I};var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1361a",
     "var C={I};var D=C.map(function(c,i){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1361b",
     "var C={I};var D=C.map(function(c,i,a){return a[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1362",
     "var O={};var C={I};C.forEach(function(c,i){O['k'+i]=c;});var A=Object.keys(O).map(function(k){return O[k];});var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1363",
     "var O={};var C={I};C.forEach(function(c,i){O['k'+i]=c;});var A=Object.values(O);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1364",
     "var O={};var C={I};C.forEach(function(c,i){O['k'+i]=c;});var A=[];for(var e of Object.entries(O)){A.push(e[1]);}var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
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
    """let/const, renamed idents, renamed params still HIT."""
    tmpls = [
        # F1360 let + renamed
        "let C={I};let D=C.filter(Boolean);let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1361 renamed params, 2-param
        "var CC={I};var DD=CC.map(function(x,y){return x;});var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
        # F1361 renamed params, 3-param twin
        "var C={I};var D=C.map(function(a,b,c){return c[b];});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1361 const
        "const C={I};const D=C.map(function(c,i){return c;});const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1362 const + renamed
        "const O={};const C={I};C.forEach(function(x,y){O['k'+y]=x;});const A=Object.keys(O).map(function(k){return O[k];});const S=String.fromCharCode.apply(null,A);const RESULT=S;",
        # F1363 renamed
        "var OO={};var CC={I};CC.forEach(function(a,b){OO['k'+b]=a;});var AA=Object.values(OO);var SS=String.fromCharCode.apply(null,AA);var RESULT=SS;",
        # F1364 let-e for-of + renamed
        "var O={};var C={I};C.forEach(function(c,i){O['k'+i]=c;});var A=[];for(let e of Object.entries(O)){A.push(e[1]);}var S=String.fromCharCode.apply(null,A);var RESULT=S;",
        # F1364 double-quote key
        'var O={};var C={I};C.forEach(function(c,i){O["k"+i]=c;});var A=Object.values(O);var S=String.fromCharCode.apply(null,A);var RESULT=S;',
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
    cs = _codes(SECRET_S)
    cs0 = _codes("xoxb-01" + "23456789abcde" + chr(0) + "f")
    cases = [
        ("f1360-zero",
         "var C=%s;var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs0, _dlp._js_f1360_stmt_decode),
        ("f1360-fn-cb",
         "var C=%s;var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1360_stmt_decode),
        ("f1361-1param",
         "var C=%s;var D=C.map(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1361_stmt_decode),
        ("f1361-not-ident",
         "var C=%s;var D=C.map(function(c,i){return i;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1361_stmt_decode),
        ("f1361-arr-idx-wrong",
         "var C=%s;var D=C.map(function(c,i,a){return a[c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1361_stmt_decode),
        ("f1362-key-x",
         "var O={};var C=%s;C.forEach(function(c,i){O['x'+i]=c;});var A=Object.keys(O).map(function(k){return O[k];});var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1362_stmt_decode),
        ("f1362-val-mismatch",
         "var O={};var C=%s;C.forEach(function(c,i){O['k'+i]=i;});var A=Object.keys(O).map(function(k){return O[k];});var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1362_stmt_decode),
        ("f1363-wrong-obj",
         "var O={};var P={};var C=%s;C.forEach(function(c,i){O['k'+i]=c;});var A=Object.values(P);var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1363_stmt_decode),
        ("f1364-e0",
         "var O={};var C=%s;C.forEach(function(c,i){O['k'+i]=c;});var A=[];for(var e of Object.entries(O)){A.push(e[0]);}var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1364_stmt_decode),
        ("f1364-bare-e",
         "var O={};var C=%s;C.forEach(function(c,i){O['k'+i]=c;});var A=[];for(e of Object.entries(O)){A.push(e[1]);}var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1364_stmt_decode),
        ("f1364-e10",
         "var O={};var C=%s;C.forEach(function(c,i){O['k'+i]=c;});var A=[];for(var e of Object.entries(O)){A.push(e[10]);}var S=String.fromCharCode.apply(null,A);var RESULT=S;"
         % cs, _dlp._js_f1364_stmt_decode),
    ]
    bad = [n for n, p, hook in cases if hook(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1349/F1350/F1355/F1356 (wave-413 closed) still HIT."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1349-flat",
         "var C=%s;var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1350-flatmap",
         "var C=%s;var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1355-set-foreach",
         "var C=%s;var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;" % cs),
        ("f1356-tofixed",
         "var C=%s;var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        "var arr=[1,2,3];var f=arr.filter(Boolean);console.log(f);",
        "var o={};var ks=Object.keys(o);console.log(ks);",
        "var m=[1,2,3].map(function(x,i){return x;});",
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
                "var C=%s;var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var O={};var C=%s;C.forEach(function(c,i){O['k'+i]=c;});var A=Object.values(O);var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs)
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
    """F1365-F1375 + F1417-F1425 (outside this lane's closures) still MISS.

    Runs the w413/w414 red-first batteries for F1365-F1375/F1417-F1425 as
    subprocesses; each must exit 0 (all shapes BREAK = still open).
    """
    bad = []
    for n in (1365, 1366, 1367, 1368, 1369,
              1370, 1371, 1372, 1373, 1374, 1375):
        p = os.path.join(REPO_ROOT, "evals",
                         "w413_f%d_redfirst.py" % n)
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception as e:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    for n in (1417, 1418, 1419, 1420):
        p = os.path.join(REPO_ROOT, "evals",
                         "w414_f%d_redfirst.py" % n)
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception as e:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    for n in (1421, 1422, 1423, 1424, 1425):
        p = os.path.join(REPO_ROOT, "evals",
                         "w414_f%d_redfirst.py" % n)
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception as e:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w413_attack_probes: F1365-F1369 still open.

    F1360-F1364 are now closed by this lane; the green check verifies
    F1365-F1369 remain open (their pins HELD) and the taxonomy/footer
    pins hold. Honors GOV_SKIP_GREEN. The w412 carry tests in
    w413_attack_probes are stale on the merged base (F1349-F1359 are
    CLOSED there) and are excluded from this check.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w413_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g414l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w413_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # Parse test_new_decoder_pins: the notes list broken pins
        # (truncated to 5, so check f1365-f1367 are NOT broken).
        decoder_break_line = ""
        prov_held = False
        tax_held = False
        footer_held = False
        for line in out.split("\n"):
            if "test_new_decoder_pins" in line:
                decoder_break_line = line
            elif "test_new_prov_pins" in line:
                prov_held = line.startswith("HELD")
            elif "test_taxonomy_pin" in line:
                tax_held = line.startswith("HELD")
            elif "test_footer" in line:
                footer_held = line.startswith("HELD")
        # F1360-F1364 closed -> their pins break; F1365-F1367 open -> hold.
        # The notes truncate, so assert no f1365/f1366/f1367 in the break
        # line, and that f1360-f1364 appear (at least the untruncated ones).
        no_open_broken = not any("f%d" % n in decoder_break_line
                                 for n in (1365, 1366, 1367))
        closed_broken = all("f%d" % n in decoder_break_line
                            for n in (1360, 1361, 1362))
        ok = (decoder_break_line.startswith("BREAK") and no_open_broken
              and closed_broken and prov_held and tax_held
              and footer_held)
        return (ok, "green(w413_attack): no-open-broken=%s closed-broken=%s prov=%s tax=%s footer=%s"
                % (no_open_broken, closed_broken, prov_held, tax_held,
                   footer_held))
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
