#!/usr/bin/env python3
"""Wave-420 lane 4 close battery: F1600-F1607 CLOSED.

F1600: flat(false) shallow copy -- `var D=C.flat(false);` + map/join
  readout. Closed by `_js_f1600_stmt_decode`. Node-exact: `false`
  coerces to 0, so flat(false) is a shallow copy. Disjoint from F1562
  (flat(0) literal), F1432, F1349, F1534 by grammar.

F1601: spread-literal copy staging -- `var D=[...C];` + map/join
  readout. Closed by `_js_f1601_stmt_decode`. Node-exact: [...C] is a
  shallow copy. Disjoint from F1563 ([].concat(...C)), F1387, F1538
  by grammar.

F1602: concat-with-spread trailing comma -- `var D=[].concat(...C,);`
  + map/join readout. Closed by `_js_f1602_stmt_decode`. Node-exact:
  the trailing comma is a no-op in the argument list. Disjoint from
  F1563 (no trailing comma) by grammar.

F1603: one-statement EM-SPACE trim readout --
  `var RESULT=('\\u2003'+S+'\\u2003').trim();` (direct-RESULT,
  parenthesized). Closed by `_js_f1603_stmt_decode`. Node-exact: pads
  are all-whitespace and S's edge codes are not trimmable
  (fail-closed per _js_f1272_check_trim_safe). Disjoint from F1272
  and F1549 (two-statement T+RESULT) by grammar.

F1604: flatMap 1-param null-thisArg staging --
  `C.flatMap(function(c){return [String.fromCharCode(c)];},null)` +
  join('') readout. Closed by `_js_f1604_stmt_decode`. Node-exact:
  the null thisArg is never read by a 1-param callback. Disjoint from
  F1546 (1-param []/"x" thisArg), F1350 (no thisArg), F1518 (4-param
  null) by grammar.

F1605: padStart default-padString staging --
  `var P=S.padStart(S.length+10);` (no padString) +
  `var RESULT=P.slice(-S.length);`. Closed by
  `_js_f1605_stmt_decode`. Node-exact: default pad is a single space.
  Disjoint from F1547 (explicit padString) by grammar.

F1606: sort reversed-boolean comparator without .slice() --
  `var D=C.sort(function(a,b){return b<a;});` + map/join readout.
  Closed by `_js_f1606_stmt_decode`. Node-exact: b<a never returns
  negative, so the sort is an in-place no-op. Disjoint from F1548
  (.slice().sort), F1508 (a>b, no slice), F1520 by grammar.

F1607: non-swapped substring identity readout --
  `var RESULT=S.substring(0,S.length);`. Closed by
  `_js_f1607_stmt_decode`. Node-exact: substring(0,len) is S.
  Disjoint from F1551 (substring(S.length,0) arg-swap) by grammar.

New _decode_layer dispatch loop (F1600-F1607);
N_STMTDEC_LOOPS 92->93 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1570-F1599
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
    ("f1600",
     "var C={I};var D=C.flat(false);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1601",
     "var C={I};var D=[...C];var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1602",
     "var C={I};var D=[].concat(...C,);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1603",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('\u2003'+S+'\u2003').trim();"),
    ("f1604",
     "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},null);var S=E.join('');var RESULT=S;"),
    ("f1605",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10);var RESULT=P.slice(-S.length);"),
    ("f1606",
     "var C={I};var D=C.sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1607",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(0,S.length);"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-419 lineage; N_STMTDEC_LOOPS=93; re.compile=29."""
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
    ok = (pin == 93 and len(loops) == 93)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w419 = "# Wave-419:" in ftxt
    ok = ok and has_w419
    notes.append("w419-footer=%s" % has_w419)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w419_attack_probes.py")) as f:
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
    """Renamed idents, let/const, arrow twins, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1600-const",
         "const C=%s;const D=C.flat(false);const RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1600-ws",
         "var C = %s ; var D = C.flat( false ) ; var RESULT = D.map(function(c){return String.fromCharCode(c);}).join('') ;" % cs),
        ("f1601-let",
         "let C=%s;let D=[...C];let RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1602-ws",
         "var C=%s;var D=[].concat( ...C , );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1603-nbsp",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('\\u00A0'+S+'\\u00A0').trim();" % cs),
        ("f1603-mixed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' \\t\\u2003'+S+'\\u2003\\t ').trim();" % cs),
        ("f1604-arrow",
         "var C=%s;var E=C.flatMap((c)=>[String.fromCharCode(c)],null);var S=E.join('');var RESULT='x'+S;" % cs),
        ("f1604-parenarrow",
         "var C=%s;var E=C.flatMap(c=>[String.fromCharCode(c)],null);var S=E.join('');var RESULT=S;" % cs),
        ("f1605-bareint",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(40);var RESULT=P.slice(-S.length);" % cs),
        ("f1605-minus",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length-0);var RESULT=P.slice(-S.length);" % cs),
        ("f1606-renamed",
         "let D=%s;let E=D.sort(function(x,y){return y<x;});let S=E.map((c)=>String.fromCharCode(c)).join('');let RESULT=S;" % cs),
        ("f1607-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const RESULT=S.substring(0,S.length);" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d generalizations hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level fail-closed bounds: all must MISS.

    (Closed sibling shapes like flat(0), [].concat(...C), etc. are
    covered by p4 sibling pins, not here.)
    """
    cs = _codes(SECRET_S)
    cases = [
        # F1600: only `false` admitted (not 0/1/true)
        ("f1600-one", "var C=%s;var D=C.flat(1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1600-true", "var C=%s;var D=C.flat(true);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1600-null", "var C=%s;var D=C.flat(null);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1601: only [...C] admitted
        ("f1601-two", "var C=%s;var D=[...C,...C];var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1601-lit", "var C=%s;var D=[...[1,2,3]];var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1601-nospread", "var C=%s;var D=[C];var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1602: trailing comma required; single spread arg only
        ("f1602-twoarg", "var C=%s;var D=[].concat(...C,...C,);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1602-litarg", "var C=%s;var D=[].concat(...[1,2,3],);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1603: ws-only affixes, trim-safe S
        ("f1603-nonws", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('a'+S+'a').trim();" % cs),
        ("f1603-empty", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(''+S+'').trim();" % cs),
        ("f1603-edge", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trim();" % _codes(" " + SECRET_S)),
        ("f1603-notrim", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ');" % cs),
        # F1604: only null thisArg, 1-param only
        ("f1604-undef", "var C=%s;var E=C.flatMap(function(c){return [String.fromCharCode(c)];},undefined);var S=E.join('');var RESULT=S;" % cs),
        ("f1604-2param", "var C=%s;var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},null);var S=E.join('');var RESULT=S;" % cs),
        ("f1604-zero", "var C=%s;var E=C.flatMap(function(c){return [String.fromCharCode(c)];},0);var S=E.join('');var RESULT=S;" % cs),
        # F1605: no padString; padStart only
        ("f1605-padend", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padEnd(S.length+10);var RESULT=P.slice(-S.length);" % cs),
        ("f1605-slice0", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10);var RESULT=P.slice(0,S.length);" % cs),
        # F1606: b<a without .slice(); function form only
        ("f1606-gt", "var C=%s;var D=C.sort(function(a,b){return a>b;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1606-arrow", "var C=%s;var D=C.sort((a,b)=>b<a);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1606-nosemi", "var C=%s;var D=C.sort(function(a,b){return b<a});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        # F1607: only (0,S.length)
        ("f1607-one", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(1,S.length);" % cs),
        ("f1607-slice", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0,S.length);" % cs),
        ("f1607-nolength", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(0,20);" % cs),
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
        ("f1562-closed",
         "var C=%s;var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1563-closed",
         "var C=%s;var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1549-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\u2003'+S+'\u2003';var RESULT=T.trim();" % cs,
         True),
        ("f1546-closed",
         "var C=%s;var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;" % cs,
         True),
        ("f1547-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);" % cs,
         True),
        ("f1548-closed",
         "var C=%s;var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         True),
        ("f1551-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(S.length,0);" % cs,
         True),
        ("f1518-closed",
         "var C=%s;var E=C.flatMap(function(c,i,a,t){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
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
        "var D=C.flat(false);var RESULT='hello world';",
        "var D=[...items];var RESULT=D.join(',');",
        "var RESULT=(' '+name+' ').trim();",
        "function sortCopy(a){return a.sort(function(x,y){return y<x;});}",
        "var s=text.substring(0,text.length);",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1570-F1599 (attack-87, OPEN) still MISS at the decoder seam.

    (F1590 is a provenance-seam finding, tested at the grant_check
    seam, not here.)
    """
    cs = _codes(SECRET_S)
    cases = [
        ("f1570", "var C=%s;var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},'xy');var S=E.join('');var RESULT=S;" % cs),
        ("f1575-substring", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substring(0);var RESULT=T;" % cs),
        ("f1575-substr", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substr(0);var RESULT=T;" % cs),
        ("f1580", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var R=S.search('ab'+'cd');var RESULT=S;" % cs),
        ("f1585", "var C=%s;var D=C.flat(-1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1595", "var C=%s;var D=Object.assign(new Array(),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
                "var C=%s;var D=C.flat(false);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(0,S.length);" % cs)
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
    """Depth-1 green on w419_attack_probes (no-regression check).

    F1600-F1607 are lane residuals, not in the attack-87 battery, so
    this is purely a no-regression check: all 48 pins must hold as
    before (F1570-F1590 open pins MISS, F1546-F1569+F1574 carry HIT,
    taxonomy 2143, footer). Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w419_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g420l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w419_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"HELD:(\d+)/(\d+)", out)
        held_ok = m and m.group(1) == "48" and m.group(2) == "48"
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = bool(held_ok and tax and footer)
        return (ok, "green(w419_attack): held=%s tax=%s footer=%s"
                % (m.group(0) if m else "?", tax, footer))
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
