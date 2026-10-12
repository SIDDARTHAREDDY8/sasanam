#!/usr/bin/env python3
"""Wave-422 lane B close battery: F1650-F1654 CLOSED.

F1650: codePointAt spread rebuild -- `var D=[...S].map(function(ch)
  {return ch.codePointAt(0);});` + apply readout. Closed by
  `_js_f1650_stmt_decode`. Node-exact: BMP credential alphabet, so
  codePointAt(0) of each spread char is the original code. Disjoint
  from F1634 ([...S]+join) and F1635 (codePointAt for-loop) by
  grammar.

F1651: toWellFormed chained / isWellFormed gated readout --
  `var T=S.toWellFormed().toWellFormed();` or
  `var T=S.isWellFormed()?S:'';`. Closed by
  `_js_f1651_stmt_decode`. Node-exact: S from int codes is
  well-formed (same discipline as F1636). Disjoint from F1636
  (single toWellFormed) by grammar.

F1652: pop-rebuild staging --
  `var T='';var D=C.slice();var x;`
  `while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}`.
  Closed by `_js_f1652_stmt_decode`. Node-exact: pops prepend in
  order; empty pop ends the loop. Disjoint by the
  `while((x=D.pop())!==undefined` grammar.

F1653: groupBy staging -- `var G=Object.groupBy(C,function(c)
  {return 'k';});var D=G.k;` (or Map.groupBy + G.get('k')) + apply
  readout. Closed by `_js_f1653_stmt_decode`. Node-exact: constant
  key groups the full array in order. Disjoint by the `.groupBy(`
  anchor.

F1654: values()/keys() iterator rebuild --
  `var D=[...C.values()];` or `var D=C.keys();` +
  `var E=[...D].map(function(i){return C[i];});` + apply readout.
  Closed by `_js_f1654_stmt_decode`. Node-exact: iterators yield in
  index order. Disjoint from F1401 (for-of values push) and F1634
  ([...S]+join) by grammar.

New _decode_layer dispatch loop (F1650-F1654); N_STMTDEC_LOOPS
99->100 actual (the wave-421 pin of 100 was overstated by 1 at base;
this lane's +1 makes the actual count match the pin -- wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1642-F1649
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
    ("f1650-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;"),
    ("f1651-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed().toWellFormed();var RESULT=T;"),
    ("f1651-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.isWellFormed()?S:'';var RESULT=T;"),
    ("f1652-0",
     "var C={I};var T='';var D=C.slice();var x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;"),
    ("f1653-0",
     "var C={I};var G=Object.groupBy(C,function(c){return 'k';});var D=G.k;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1653-1",
     "var C={I};var G=Map.groupBy(C,function(c){return 'k';});var D=G.get('k');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1654-0",
     "var C={I};var D=[...C.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1654-1",
     "var C={I};var D=C.keys();var E=[...D].map(function(i){return C[i];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-421 lineage; N_STMTDEC_LOOPS=101 actual (merge); re.compile=29."""
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
    ok = (pin == 101 and len(loops) == 101)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w421 = "# Wave-421:" in ftxt
    ok = ok and has_w421
    notes.append("w421-footer=%s" % has_w421)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w421_attack_probes.py")) as f:
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
    """Renamed idents, let/const, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1650-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const D=[...S].map(function(ch){return ch.codePointAt(0);});const T=String.fromCharCode.apply(null,D);const RESULT=T;" % cs),
        ("f1650-ws",
         "var C = %s ; var S = C.map(function(c){return String.fromCharCode(c);}).join('') ; var D = [...S].map(function(ch){return ch.codePointAt(0);}) ; var T = String.fromCharCode.apply(null,D) ; var RESULT = T ;" % cs),
        ("f1651-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T=S.toWellFormed().toWellFormed();let RESULT=T;" % cs),
        ("f1651-gate-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T = S.isWellFormed() ? S : '' ;var RESULT=T;" % cs),
        ("f1652-let",
         "let C=%s;let T='';let D=C.slice();let x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}let RESULT=T;" % cs),
        ("f1653-map-ws",
         "var C=%s;var G = Map.groupBy( C , function(c){return 'k';} ) ;var D=G.get('k');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1654-const",
         "const C=%s;const D=[...C.values()];const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs),
        ("f1654-keys-ws",
         "var C=%s;var D = C.keys() ;var E=[...D].map(function(i){return C[i];});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1650-arrow",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(ch=>ch.codePointAt(0));var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs),
        ("f1650-arrow-paren",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map((ch)=>ch.codePointAt(0));var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs),
        ("f1653-arrow0",
         "var C=%s;var G=Object.groupBy(C,()=>'k');var D=G.k;var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1653-arrow1",
         "var C=%s;var G=Map.groupBy(C,c=>'k');var D=G.get('k');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1654-arrow",
         "var C=%s;var D=C.keys();var E=[...D].map(i=>C[i]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
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
        # F1650: only [...S].map(function(ch){return ch.codePointAt(0);})
        ("f1650-spreadlit", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...'lit'].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs),
        ("f1650-charcodeat", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs),
        ("f1650-cpa1", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(1);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs),
        ("f1650-noapply", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=D.join('');var RESULT=T;" % cs),
        # F1651: only chained twf or gated iwf (single twf is F1636's closed shape)
        ("f1651-triple", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed().toWellFormed().toWellFormed();var RESULT=T;" % cs),
        ("f1651-gate-nonempty", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.isWellFormed()?S:'x';var RESULT=T;" % cs),
        ("f1651-gate-flip", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.isWellFormed()?'':S;var RESULT=T;" % cs),
        # F1652: strict while grammar only
        ("f1652-shift", "var C=%s;var T='';var D=C.slice();var x;while((x=D.shift())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs),
        ("f1652-append", "var C=%s;var T='';var D=C.slice();var x;while((x=D.pop())!==undefined){T=T+String.fromCharCode(x);}var RESULT=T;" % cs),
        ("f1652-null", "var C=%s;var T='';var D=C.slice();var x;while((x=D.pop())!==null){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs),
        ("f1652-noxdecl", "var C=%s;var T='';var D=C.slice();while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs),
        # F1653: only constant ident-like key, matching accessor
        ("f1653-nonconst", "var C=%s;var G=Object.groupBy(C,function(c){return c;});var D=G.k;var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1653-keymismatch", "var C=%s;var G=Object.groupBy(C,function(c){return 'k';});var D=G.j;var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1653-getmismatch", "var C=%s;var G=Map.groupBy(C,function(c){return 'k';});var D=G.get('j');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1653-objget", "var C=%s;var G=Object.groupBy(C,function(c){return 'k';});var D=G.get('k');var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1654: only [...C.values()] / C.keys()+[...D].map
        ("f1654-entries", "var C=%s;var D=[...C.entries()];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1654-valuesidx", "var C=%s;var D=C.values();var E=[...D].map(function(i){return C[i];});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1654-keysapply", "var C=%s;var D=[...C.keys()];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # H1: surrogate-pair codes fail closed (would mis-decode under codePointAt)
        ("f1650-surrpair", "var C=[0x1D83D,0x1DE00,65];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;"),
        # H2: lone-surrogate codes fail closed (gated form would false-positive)
        ("f1651-surrgate", "var C=[0x1D800,120,111,120,98];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.isWellFormed()?S:'';var RESULT=T;"),
        ("f1651-surrchain", "var C=[0x1D800,120,111,120,98];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed().toWellFormed();var RESULT=T;"),
        # H3: const decls fail closed (node TypeError/SyntaxError)
        ("f1652-constT", "var C=%s;const T='';var D=C.slice();var x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs),
        ("f1652-constx", "var C=%s;var T='';var D=C.slice();const x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs),
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
        ("f1401-closed",
         "var C=%s;var D=[];for(var v of C.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1644-open",
         "var C=%s;var D=C.filter((c)=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         False),
        ("f1642-open",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;" % cs,
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
        "var D=[...text].map(function(ch){return ch.codePointAt(0);});",
        "var t=s.toWellFormed().toWellFormed();",
        "var t=s.isWellFormed()?s:'';",
        "while((x=d.pop())!==undefined){t+=x;}",
        "var g=Object.groupBy(items,function(x){return x.k;});",
        "var d=[...c.values()];",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1642-F1647, F1649 (other opens) still MISS at the decoder seam.

    Note: F1648 (Array.prototype.join.call) is HIT on the base --
    a pre-existing incidental closure, not caused by this lane.
    Documented for the merge coordinator's red-first audit.
    """
    cs = _codes(SECRET_S)
    cases = [
        ("f1642", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;" % cs),
        ("f1643", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleUpperCase();var U=T.toLocaleLowerCase();var RESULT=U;" % cs),
        ("f1644", "var C=%s;var D=C.filter((c)=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1645", "var C=%s;var D=C.map(function(c,i){return C.at(i-C.length);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1646", "var C=%s;var S=C.toLocaleString();var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
        ("f1647", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var M=[...S.matchAll(/(?<ch>.)/g)];var T=M.map(function(m){return m[1];}).join('');var RESULT=T;" % cs),
        ("f1649", "var C=%s;var D=Array.from(C,(c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var T='';var D=C.slice();var x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;" % cs)
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
    """No-regression check on w421_attack_probes pins.

    F1650-F1654 flip MISS->HIT by design (closed by this lane).
    F1642-F1647, F1649 must stay MISS. (F1648 is HIT on the base --
    a pre-existing incidental closure, excluded from the hold set.)
    Taxonomy 2143, footer, and no-paid-machinery pins must hold.
    The _CARRY section is stale (expects MISS for wave-421-closed
    findings; FAILs on base too) and is excluded from the assertion.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w421_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g422lb-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w421_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # F1642-F1647, F1649 must stay HELD (MISS); F1648 excluded (pre-existing HIT)
        hold_ok = True
        hold_notes = []
        for fn in ("F1642", "F1643", "F1644", "F1645", "F1646",
                   "F1647", "F1649"):
            m = re.search(r"^(HELD|FAIL) %s -> (\w+)" % fn, out,
                          re.MULTILINE)
            ok = bool(m and m.group(1) == "HELD" and m.group(2) == "MISS")
            hold_ok = hold_ok and ok
            if not ok:
                hold_notes.append(fn)
        # F1650-F1654 must flip to HIT (closed by this lane)
        flip_ok = True
        flip_notes = []
        for fn in ("F1650", "F1651", "F1652", "F1653", "F1654"):
            m = re.search(r"^(HELD|FAIL) %s -> (\w+)" % fn, out,
                          re.MULTILINE)
            ok = bool(m and m.group(1) == "FAIL" and m.group(2) == "HIT")
            flip_ok = flip_ok and ok
            if not ok:
                flip_notes.append(fn)
        tax = "taxonomy pin 2143" in out and "HELD taxonomy pin 2143" in out
        footer = "HELD footer pin" in out
        ok = bool(hold_ok and flip_ok and tax and footer)
        return (ok, "green(w421_attack): hold7=%s flip5=%s tax=%s footer=%s"
                % (hold_ok, flip_ok, tax, footer))
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
