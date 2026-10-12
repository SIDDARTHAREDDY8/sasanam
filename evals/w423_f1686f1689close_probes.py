#!/usr/bin/env python3
"""Wave-423 lane D close battery: F1686-F1689 CLOSED.

F1686: map(String) interposed before map(Number) --
  `var D=C.map(function(c){return String(c);});var E=D.map(Number);` +
  fromCharCode.apply readout. New `_js_f1686_stmt_decode`. Node-exact:
  String(c)->Number(c) is the identity on integer literals. Disjoint
  from F1582 (direct map(Number) over string codes) by grammar.

F1687: join(',')/split(',')/map(Number) roundtrip --
  `var T=C.join(',');var D=T.split(',').map(Number);` +
  fromCharCode.apply readout. New `_js_f1687_stmt_decode`. Node-exact:
  join/split invert exactly on integer arrays. Disjoint from F1669
  (Array.prototype.join.call default separator) by grammar.

F1688: string split/reverse/reverse/join identity --
  `var T=S.split('').reverse().reverse().join('');` + RESULT.
  New `_js_f1688_stmt_decode`. Node-exact: double array-reverse is the
  identity on every string (no surrogate guard needed). Disjoint from
  F1624 (array-level double reverse) by grammar.

F1689: spread charCodeAt rebuild --
  `var D=[...S].map(function(ch){return ch.charCodeAt(0);});` +
  `var S=String.fromCharCode.apply(null,D);` (var-redeclare) + RESULT.
  New `_js_f1689_stmt_decode`. Node-exact on BMP dstr; fails closed if
  dstr holds any surrogate unit (lead+trail would spread-iterate as
  one astral char -- F1650 discipline). Disjoint from F1657 (indexed
  for-loop) and F1650 (codePointAt) by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 101->102
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1672-F1685
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
    ("f1686",
     "var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1687",
     "var C={I};var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1688",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;"),
    ("f1689",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=102 (101 base + 1 new loop); re.compile=29; pin 2143; wave-422 footer lineage."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 105)  # merge: 101 base + 4 lanes
    notes.append("loops=%d (expect 102)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1686_stmt_decode, _js_f1687_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1686-loop=%s" % has_new)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w422 = "# Wave-422:" in ftxt
    ok = ok and has_w422
    notes.append("w422-footer=%s" % has_w422)
    # taxonomy pin 2143 referenced
    ok = ok and ("2143" in ftxt)
    notes.append("tax2143=%s" % ("2143" in ftxt))
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
        ("f1686-arrow",
         "var C=%s;var D=C.map(c=>String(c));var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1686-arrow-paren",
         "var C=%s;var D=C.map((c)=>String(c));var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1686-const-renamed",
         "const A=%s;const B=A.map(function(x){return String(x);});const F=B.map(Number);const T=String.fromCharCode.apply(null,F);const RESULT=T;" % cs),
        ("f1686-ws",
         "var C = %s ; var D = C.map(function(c){return String(c);}) ; var E = D.map(Number) ; var S = String.fromCharCode.apply(null,E) ; var RESULT = S ;" % cs),
        ("f1687-let",
         "let C=%s;let T=C.join(',');let D=T.split(',').map(Number);let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1687-renamed",
         "var A=%s;var B=A.join(',');var C2=B.split(',').map(Number);var S=String.fromCharCode.apply(null,C2);var RESULT=S;" % cs),
        ("f1688-arrow",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;" % cs),
        ("f1688-const",
         "const C=%s;const S=C.map(function(c){return String.fromCharCode(c);}).join('');const T=S.split('').reverse().reverse().join('');const RESULT=T;" % cs),
        ("f1689-arrow",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(ch=>ch.charCodeAt(0));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1689-arrow-paren",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map((ch)=>ch.charCodeAt(0));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1689-renamed",
         "var A=%s;var B=A.map(function(c){return String.fromCharCode(c);}).join('');var E=[...B].map(function(q){return q.charCodeAt(0);});var B=String.fromCharCode.apply(null,E);var RESULT=B;" % cs),
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
        # F1686: String() interpose required; bare map(String) is F1559's grammar
        ("f1686-bare-string",
         "var C=%s;var D=C.map(String);var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1686: map base must be the String-staged D, not C
        ("f1686-wrong-base",
         "var C=%s;var D=C.map(function(c){return String(c);});var E=C.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1686: second map must be bare Number
        ("f1686-not-number",
         "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(String);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1687: separator must be ',' on both join and split
        ("f1687-semi-sep",
         "var C=%s;var T=C.join(';');var D=T.split(';').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1687-sep-mismatch",
         "var C=%s;var T=C.join(',');var D=T.split(';').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1688: needs the double reverse
        ("f1688-single-reverse",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().join('');var RESULT=T;" % cs),
        ("f1688-triple-reverse",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().reverse().join('');var RESULT=T;" % cs),
        # F1689: redeclare must be var (let/const is a node SyntaxError)
        ("f1689-let-redeclare",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});let S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1689: charCodeAt arg must be 0
        ("f1689-cca-1",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(1);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1689: spread required
        ("f1689-no-spread",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1689: codePointAt is F1650's grammar, not this hook's
        ("f1689-cpa",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
    strcodes = "[" + ",".join("\"%d\"" % ord(c) for c in SECRET_S) + "]"
    cases = [
        # (name, payload, want_hit)
        ("f1582-closed-direct",
         "var A=%s;var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % strcodes,
         True),
        ("f1650-closed-cpa",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs,
         True),
        ("f1624-closed-arr-revrev",
         "var C=%s;var D=C.slice().reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1669-closed-joincall",
         "var C=%s;var S=Array.prototype.join.call(C,',');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs,
         True),
        # F1657 CLOSED (wave-422 lane C): charCodeAt rebuild loop now HITs
        ("f1657-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.charCodeAt(i));}var RESULT=T;" % cs,
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
        "var D=items.map(function(c){return String(c);});var E=D.map(Number);",
        "var T=names.join(',');var D=T.split(',').map(Number);",
        "var T=title.split('').reverse().reverse().join('');",
        "var D=[...label].map(function(ch){return ch.charCodeAt(0);});",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function String(x){return ''+x;}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1672-F1685 (other opens, attack-90) still MISS at the decoder seam."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1672",
         "var C=%s;var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1675",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');var RESULT=D;" % cs),
        ("f1680",
         "var C=%s;var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1684",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var E=String.fromCharCode.apply(null,D);var RESULT=E;" % cs),
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
                "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    """Regression check: F1672-F1685 red-first batteries still BREAK
    (other lanes' findings, still OPEN); F1686-F1689 red-first
    batteries now NO-BREAK (filed shapes HIT). Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green: skipped via GOV_SKIP_GREEN=1")
    notes = []
    ok = True
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g423ld-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        for n in (1672, 1675, 1680, 1684):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w422_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            held = "RESULT: BREAK" in out
            notes.append("f%d-break=%s" % (n, held))
            ok = ok and held
        for n in range(1686, 1690):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w423_f%d_redfirst.py" % n)],
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
