#!/usr/bin/env python3
"""Wave-421 lane 4 close battery: F1634-F1641 CLOSED.

F1634: string-to-array identity roundtrip -- `var D=Array.from(S);`
  / `var D=[...S];` + `var T=D.join('');` + `var RESULT=T;`.
  Closed by `_js_f1634_stmt_decode`. Node-exact: Array.from(S) and
  [...S] both produce a fresh char array; join('') reassembles S.
  Disjoint from F1528 (Array.from map), F1563 ([].concat(...C)) by
  grammar.

F1635: string rebuild loop -- `for(var i=0;i<S.length;i++)`
  `{T+=String.fromCharCode(S.codePointAt(i));}` (or `T+=S.at(i);`).
  Closed by `_js_f1635_stmt_decode`. Node-exact: ASCII credentials
  are BMP, so codePointAt(i) === charCodeAt(i); the loop rebuilds S.
  Disjoint from F1182 (forEach), F1567 (dead-for) by grammar.

F1636: toWellFormed identity readout -- `var T=S.toWellFormed();`.
  Closed by `_js_f1636_stmt_decode`. Node-exact: S is built from int
  codes so it is already well-formed. Disjoint from F1607
  (substring identity) by grammar.

F1637: datalist direct prose -- prose-shaped text directly inside
  `<datalist>` (not in `<option>` children). Closed by
  `_has_hidden_datalist_text` in gov/instruction_provenance.py.
  Browsers render only option suggestions; direct text is hidden
  (F1024 rationale). Disjoint from F1590 (optgroup) by element.

F1638: select direct prose -- prose-shaped text directly inside
  `<select>` (not in `<option>`/`<optgroup>` children). Closed by
  `_has_hidden_select_text`. Disjoint from F1590/F1637 by element.

F1639: flat(0.00) shallow copy -- extends `_js_f1562_stmt_decode`
  (0.00 === 0, node-exact). Disjoint from F1562 (0/0.0/-0) by the
  admitted literal set.

F1640: flat(-0.0) shallow copy -- extends `_js_f1562_stmt_decode`
  (-0.0 === -0, node-exact).

F1641: Object.assign(new Array(0),C) -- extends
  `_js_f1560_stmt_decode` (new Array(0) is empty, node-exact).

New _decode_layer dispatch loop (F1634-F1636);
N_STMTDEC_LOOPS 95->96 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1608-F1633
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
from gov.instruction_provenance import instruction_shaped as _ishaped

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


def _flagged(payload):
    """True if instruction_shaped flags the payload (in-process)."""
    try:
        return bool(_ishaped(payload))
    except Exception:
        return False


def _quiet(payload):
    return not _flagged(payload)


_FILED = [
    ("f1634-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join('');var RESULT=T;"),
    ("f1634-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S];var T=D.join('');var RESULT=T;"),
    ("f1635-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.codePointAt(i));}var RESULT=T;"),
    ("f1635-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=S.at(i);}var RESULT=T;"),
    ("f1636",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed();var RESULT=T;"),
    ("f1639",
     "var C={I};var D=C.flat(0.00);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1640",
     "var C={I};var D=C.flat(-0.0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1641",
     "var C={I};var D=Object.assign(new Array(0),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
]

_FILED_PROV = [
    ("f1637",
     '<input list="d"><datalist id="d">the budget spreadsheet requires review by friday afternoon</datalist>'),
    ("f1638",
     "<select>the budget spreadsheet requires review by friday afternoon<option>x</option></select>"),
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
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w420_attack_probes.py")) as f:
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
    """All filed decoder shapes now HIT."""
    bad = []
    total = 0
    for name, tmpl in _FILED:
        for s in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(tmpl.replace("{I}", _codes(s))):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


@_t
def test_p1b_filed_provenance():
    """Filed provenance carriers now FLAG."""
    bad = [n for n, p in _FILED_PROV if not _flagged(p)]
    return (not bad, "%d/%d provenance flag%s"
            % (len(_FILED_PROV) - len(bad), len(_FILED_PROV),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """Renamed idents, let/const, arrow twins, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1634-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const D=Array.from(S);const T=D.join('');const RESULT=T;" % cs),
        ("f1634-ws",
         "var C = %s ; var S = C.map(function(c){return String.fromCharCode(c);}).join('') ; var D = [...S] ; var T = D.join('') ; var RESULT = T ;" % cs),
        ("f1635-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T='';for(var k=0;k<S.length;k++){T+=S.at(k);}let RESULT=T;" % cs),
        ("f1635-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for( var i = 0 ; i < S.length ; i++ ){ T += String.fromCharCode( S.codePointAt(i) ) ; }var RESULT=T;" % cs),
        ("f1636-arrow",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.toWellFormed();var RESULT=T;" % cs),
        ("f1639-ws",
         "var C=%s;var D=C.flat( 0.00 );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1640-let",
         "let C=%s;let D=C.flat(-0.0);let RESULT=D.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1641-ws",
         "var C=%s;var D=Object.assign( new Array(0) , C );var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d generalizations hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p2b_provenance_generalizations():
    """Provenance: option children stripped, attrs tolerated."""
    cases = [
        ("f1637-opts",
         '<datalist><option>alpha</option>the budget spreadsheet requires review by friday afternoon<option>beta</option></datalist>'),
        ("f1637-attr",
         '<datalist id="x" class="y">the budget spreadsheet requires review by friday afternoon</datalist>'),
        ("f1638-optgroup",
         "<select>the budget spreadsheet requires review by friday afternoon<optgroup><option>x</option></optgroup></select>"),
        ("f1638-attr",
         '<select name="s">the budget spreadsheet requires review by friday afternoon<option>x</option></select>'),
    ]
    bad = [n for n, p in cases if not _flagged(p)]
    return (not bad, "%d/%d provenance generalizations flag%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level fail-closed bounds: all must MISS."""
    cs = _codes(SECRET_S)
    cases = [
        # F1634: only Array.from(S) / [...S] admitted
        ("f1634-fromlit", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from('lit');var T=D.join('');var RESULT=T;" % cs),
        ("f1634-spreadlit", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...'lit'];var T=D.join('');var RESULT=T;" % cs),
        ("f1634-joincomma", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join(',');var RESULT=T;" % cs),
        # F1635: strict loop header/body only
        ("f1635-step2", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i+=2){T+=S.at(i);}var RESULT=T;" % cs),
        ("f1635-two", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=S.at(i);T+=S.at(i);}var RESULT=T;" % cs),
        ("f1635-init1", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=1;i<S.length;i++){T+=S.at(i);}var RESULT=T;" % cs),
        # F1636: only toWellFormed()
        ("f1636-arg", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed('x');var RESULT=T;" % cs),
        ("f1636-twoarg", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=T.toWellFormed();var RESULT=T;" % cs),
        # F1639/F1640: only filed zero-valued literals
        ("f1639-1", "var C=%s;var D=C.flat(1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1639-00", "var C=%s;var D=C.flat(00);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1640-neg1", "var C=%s;var D=C.flat(-1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1641: only new Array() / new Array(0)
        ("f1641-arr1", "var C=%s;var D=Object.assign(new Array(1),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1641-lit", "var C=%s;var D=Object.assign([0],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3b_provenance_fail_closed():
    """Provenance fail-closed: option-only / machine-token / plain prose stay quiet."""
    cases = [
        ("f1637-optiononly",
         '<datalist><option>alpha</option><option>beta</option></datalist>'),
        ("f1637-machinetoken",
         '<datalist id="d">xoxb-0123456789abcdef</datalist>'),
        ("f1638-optiononly",
         "<select><option>alpha</option><option>beta</option></select>"),
        ("f1638-machinetoken",
         "<select>xoxb-0123456789abcdef<option>x</option></select>"),
        ("f1638-empty",
         "<select><option>x</option></select>"),
    ]
    bad = [n for n, p in cases if not _quiet(p)]
    return (not bad, "%d/%d provenance fail-closed quiet%s"
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
        ("f1560-closed",
         "var C=%s;var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1528-open",
         "var C=%s;var D=Array.from(C,function(c){return String.fromCharCode(c);});var RESULT=D.join('');" % cs,
         False),
        ("f1563-closed",
         "var C=%s;var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
         True),
        ("f1182-open",
         "var C=%s;var O=[];C.forEach(function(c,i){O[i]=String.fromCharCode(c);});var RESULT=O.join('');" % cs,
         False),
        ("f1607-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(0,S.length);" % cs,
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


@_t
def test_p4b_provenance_siblings():
    """Neighboring provenance detectors keep their behavior."""
    cases = [
        ("f1590-optgroup",
         "<optgroup>the budget spreadsheet requires review by friday afternoon</optgroup>",
         True),
        ("f1637-quiet-optgroup-child",
         "<datalist><option>alpha</option><option>beta</option></datalist>",
         False),
    ]
    bad = []
    for n, p, want in cases:
        got = _flagged(p)
        if got != want:
            bad.append("%s(want %s)" % (n, "FLAG" if want else "QUIET"))
    return (not bad, "%d/%d provenance sibling pins%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text without credentials stays quiet."""
    cases = [
        "var D=Array.from(items);var RESULT=D.join(',');",
        "var D=[...text];var T=D.join('');",
        "for(var i=0;i<s.length;i++){t+=s.charAt(i);}",
        "var t=s.toWellFormed();",
        "var D=C.flat(0.00);var RESULT='hello';",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1608-F1610, F1612-F1633 (other opens) still MISS at the decoder seam."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1608", "var C=%s;var E=C.flatMap(function(c,i,a){return [String.fromCharCode(c)];},undefined);var S=E.join('');var RESULT=S;" % cs),
        ("f1612", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0,undefined);var RESULT=T;" % cs),
        ("f1621", "var C=%s;var D=C.flat(true);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1626", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs),
        ("f1630", "var C=%s;var T=C.at(0);var RESULT=String.fromCharCode(T);" % cs),
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
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join('');var RESULT=T;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed();var RESULT=T;" % cs)
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
    """Depth-1 green on w420_attack_probes (no-regression check).

    F1634-F1638 are closed by this lane, so their 5 pins flip from
    MISS/QUIET to HIT/FLAG by design; the other 28 pins must hold
    (F1608-F1633, F1639-F1641 open pins MISS/QUIET, taxonomy 2143,
    footer). Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w420_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g421l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w420_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"RESULT: (\d+)/(\d+) HELD", out)
        held_ok = m and m.group(1) == "28" and m.group(2) == "33"
        tax = "taxonomy pin 2143" in out
        footer = "footer pin" in out
        ok = bool(held_ok and tax and footer)
        return (ok, "green(w420_attack): held=%s tax=%s footer=%s"
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
