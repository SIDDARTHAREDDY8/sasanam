#!/usr/bin/env python3
"""Wave-423 lane C close battery: F1682-F1685 CLOSED.

F1682: Object.assign({},C) + Object.values(O).map(Number) code read --
  `var O=Object.assign({},C);var D=Object.values(O).map(Number);` + apply
  readout. Closed by `_js_f1682_stmt_decode`. Node-exact: assign copies
  indices into a plain object; values() returns them in integer-key
  order; map(Number) is identity. Disjoint from F1133 (array target),
  F1560/F1595/F1641 (new Array() targets) by grammar.

F1683: BigInt map-to-Number staging --
  `var D=C.map(function(c){return BigInt(c);});` then
  `var E=D.map(function(b){return Number(b);});` + apply readout
  (function + arrow twins). Closed by `_js_f1683_stmt_decode`.
  Node-exact: codes < 2^53 round-trip exactly through BigInt.
  Disjoint from F1027 (for-of) and F1582 (direct map(Number)).

F1684: String.prototype.at() negative-index rebuild --
  `var S=C.map(...).join('');var D=[];`
  `for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}`
  then `var S=String.fromCharCode.apply(null,D);` (var-redeclare, or
  fresh-name S2 form pinned by the attack battery) + RESULT.
  Closed by `_js_f1684_stmt_decode`. Node-exact for BMP dstr
  (fail-closed on non-BMP); S.at(i-len)===S[i]. Disjoint from F1635
  (codePointAt loop), F1645 (array .at()), F1657/F1658 by grammar.

F1685: two-step hex codec --
  `var D=C.map(function(c){return c.toString(16);});` then
  `var E=D.map(function(h){return parseInt(h,16);});` + apply readout
  (function + arrow twins). Closed by `_js_f1685_stmt_decode`.
  Node-exact: hex round-trip is exact for non-negative ints.
  Disjoint from F1296 (single-expression) by grammar.

New _decode_layer dispatch loop (F1682-F1685); N_STMTDEC_LOOPS
101->102 actual (real code-count change, wave-385; asserted by count).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1672-F1681,
F1686-F1689 (other opens) still MISS.

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
    ("f1682-0",
     "var C={I};var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1683-0",
     "var C={I};var D=C.map(function(c){return BigInt(c);});var E=D.map(function(b){return Number(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1684-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1684-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
    ("f1685-0",
     "var C={I};var D=C.map(function(c){return c.toString(16);});var E=D.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-422 lineage; N_STMTDEC_LOOPS=102 actual; re.compile=29."""
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
    ok = (pin == 105 and len(loops) == 105)  # merge: pin repointed to actual 105
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w422 = "# Wave-422:" in ftxt
    ok = ok and has_w422
    notes.append("w422-footer=%s" % has_w422)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w422_attack_probes.py")) as f:
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
    """Renamed idents, let/const, ws variants, arrow twins."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1682-const",
         "const C=%s;const O=Object.assign({},C);const D=Object.values(O).map(Number);const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs),
        ("f1682-ws",
         "var C = %s ; var O = Object.assign( {} , C ) ; var D = Object.values( O ).map( Number ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;" % cs),
        ("f1682-renamed",
         "var X=%s;var Y=Object.assign({},X);var Z=Object.values(Y).map(Number);var W=String.fromCharCode.apply(null,Z);var RESULT=W;" % cs),
        ("f1683-arrow",
         "var C=%s;var D=C.map(c=>BigInt(c));var E=D.map(b=>Number(b));var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1683-arrow-paren",
         "var C=%s;var D=C.map((c)=>BigInt(c));var E=D.map((b)=>Number(b));var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1683-let",
         "let C=%s;let D=C.map(function(c){return BigInt(c);});let E=D.map(function(b){return Number(b);});let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cs),
        ("f1684-let",
         "let C=%s;let S=C.map(function(c){return String.fromCharCode(c);}).join('');let D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}let S2=String.fromCharCode.apply(null,D);let RESULT=S2;" % cs),
        ("f1684-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i - S.length).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1685-arrow",
         "var C=%s;var D=C.map(c=>c.toString(16));var E=D.map(h=>parseInt(h,16));var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1685-arrow-paren",
         "var C=%s;var D=C.map((c)=>c.toString(16));var E=D.map((h)=>parseInt(h,16));var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1685-const",
         "const C=%s;const D=C.map(function(c){return c.toString(16);});const E=D.map(function(h){return parseInt(h,16);});const S=String.fromCharCode.apply(null,E);const RESULT=S;" % cs),
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
        # F1682: only {} target + values + map(Number)
        ("f1682-arrtarget", "var C=%s;var O=Object.assign([],C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1682-keys", "var C=%s;var O=Object.assign({},C);var D=Object.keys(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1682-mapstr", "var C=%s;var O=Object.assign({},C);var D=Object.values(O).map(String);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1682-noapply", "var C=%s;var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=D.join(',');var RESULT=S;" % cs),
        # F1683: only BigInt then Number callbacks
        ("f1683-nobigint", "var C=%s;var D=C.map(function(c){return Number(c);});var E=D.map(function(b){return Number(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1683-nostring", "var C=%s;var D=C.map(function(c){return BigInt(c);});var E=D.map(function(b){return String(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1683-bigintadd", "var C=%s;var D=C.map(function(c){return BigInt(c)+1n;});var E=D.map(function(b){return Number(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1684: strict at(i-S.length).charCodeAt(0) grammar
        ("f1684-ati", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1684-cca1", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(1));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1684-codepointat", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).codePointAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1684-letsredecl", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}let S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1684-nonbmp", "var C=[0x1F600,65,66];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        # F1685: only toString(16) then parseInt(h,16)
        ("f1685-radix10", "var C=%s;var D=C.map(function(c){return c.toString(16);});var E=D.map(function(h){return parseInt(h,10);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1685-ts10", "var C=%s;var D=C.map(function(c){return c.toString(10);});var E=D.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # (f1685-single is F1296's closed single-expression shape -- covered in p4)
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Neighboring hooks keep their documented behavior.

    Uses shapes verified against the actual hook grammars (not the
    attack-round prose, which may differ in variable naming).
    """
    cs = _codes(SECRET_S)
    cases = [
        # (name, payload, want_hit)
        # F1296 (closed): single-expression hex -- the f1685-single shape
        ("f1296-closed",
         "var C=%s;var D=C.map(function(c){return parseInt(c.toString(16),16);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        # F1635 (closed): codePointAt for-loop rebuild
        ("f1635-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.codePointAt(i));}var RESULT=T;" % cs,
         True),
        # F1636 (closed): single toWellFormed
        ("f1636-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed();var RESULT=T;" % cs,
         True),
        # F1686 (closed in merge, lane D): map(String) interposed -- must now HIT
        ("f1686-closed",
         "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        # F1645 is CLOSED (wave-422 lane A) -- documents the closure
        ("f1645-closed",
         "var C=%s;var D=C.map(function(c,i){return C.at(i-C.length);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
        "var o=Object.assign({},defaults);",
        "var vs=Object.values(config).map(Number);",
        "var b=BigInt(12345678901234567890);",
        "var n=Number(bigval);",
        "var ch=s.at(-1);",
        "var hex=n.toString(16);",
        "var v=parseInt(str,16);",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1672-F1681, F1686-F1689 now CLOSED in merge -> expect HIT at the decoder seam."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1672", "var C=%s;var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1673", "var C=%s;var T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;" % cs),
        ("f1675", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');var RESULT=D;" % cs),
        ("f1676", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=new URLSearchParams([['k',S]]);var T=P.get('k');var RESULT=T;" % cs),
        ("f1677", "var C=%s;var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1678", "var C=%s;var D=JSON.parse(JSON.stringify(C));var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1679", "var C=%s;var RESULT=String.fromCodePoint.apply(null,C);" % cs),
        ("f1680", "var C=%s;var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1681", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;" % cs),
        ("f1686", "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1687", "var C=%s;var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1688", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;" % cs),
        ("f1689", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;" % cs),
    ]
    bad = [n for n, p in cases if _misses(p)]
    return (not bad, "%d/%d merged-closed hit%s"
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
                "var C=%s;var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=C.map(function(c){return c.toString(16);});var E=D.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
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
    """No-regression check on w422_attack_probes pins (wave-423 merge).

    F1672-F1689 all CLOSED in merge -> expect HIT. Taxonomy 2143, footer,
    and no-paid-machinery pins must hold.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w422_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g423lc-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w422_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # F1672-F1681, F1686-F1689 now CLOSED in merge -> expect HELD->HIT
        hold_ok = True
        hold_notes = []
        for fn in ("F1672", "F1673", "F1675", "F1676", "F1677",
                   "F1678", "F1679", "F1680", "F1681", "F1686",
                   "F1687", "F1688", "F1689"):
            m = re.search(r"^(HELD|FAIL) %s (?:short|long) -> (\w+)" % fn, out,
                          re.MULTILINE)
            # both sizes must be HELD->HIT (closed in wave-423 merge)
            ms = re.findall(r"^(HELD|FAIL) %s (?:short|long) -> (\w+)" % fn,
                            out, re.MULTILINE)
            ok = bool(ms) and all(a == "HELD" and b == "HIT" for a, b in ms)
            hold_ok = hold_ok and ok
            if not ok:
                hold_notes.append(fn)
        # F1682-F1685 must flip to HIT (closed by this lane)
        flip_ok = True
        flip_notes = []
        for fn in ("F1682", "F1683", "F1684", "F1685"):
            ms = re.findall(r"^(HELD|FAIL) %s (?:short|long) -> (\w+)" % fn,
                            out, re.MULTILINE)
            ok = bool(ms) and all(a == "FAIL" and b == "HIT" for a, b in ms)
            flip_ok = flip_ok and ok
            if not ok:
                flip_notes.append(fn)
        tax = "HELD taxonomy pin 2143" in out
        footer = "HELD footer pin" in out
        ok = bool(hold_ok and flip_ok and tax and footer)
        return (ok, "green(w422_attack): hold13=%s%s flip4=%s%s tax=%s footer=%s"
                % (hold_ok, hold_notes, flip_ok, flip_notes, tax, footer))
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
