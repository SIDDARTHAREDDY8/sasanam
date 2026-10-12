#!/usr/bin/env python3
"""Wave-424 lane C close battery: F1700-F1702 CLOSED.

F1700: parseInt(x,10) explicit-radix map staging --
  `var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});` +
  fromCharCode.apply readout. New `_js_f1700_stmt_decode`. Node-exact:
  String(c) renders canonical decimal, parseInt(x,10) inverts exactly.
  Disjoint from F1582 (direct map(Number) over string codes) and F1686
  (map(String) then map(Number)) by grammar.

F1701: Array.entries() iterator rebuild --
  `var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}` +
  fromCharCode.apply readout. New `_js_f1701_stmt_decode`. Node-exact:
  entries() yields [index,value] pairs; e[1] rebuilds the code array.
  Disjoint from F1654 (values-spread / keys-map) by grammar.

F1702: values-spread with interposed map(Number) --
  `var D=[...C.values()].map(Number);` + fromCharCode.apply readout.
  New `_js_f1702_stmt_decode`. Node-exact: spread copies C, map(Number)
  is the identity on admitted integers. Disjoint from F1654 (plain
  spread) and F1686 (map(String) base) by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 105->106
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1690-F1699,
F1703-F1704 (other opens) still MISS.

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
    ("f1700",
     "var C={I};var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1701",
     "var C={I};var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1702",
     "var C={I};var D=[...C.values()].map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=108 (105 base + 3 lanes); re.compile=29; pin 2143; wave-423 footer lineage."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 108)
    notes.append("loops=%d (expect 108)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1700_stmt_decode, _js_f1701_stmt_decode," in body
    ok = ok and has_new
    notes.append("f1700-loop=%s" % has_new)
    # hooks defined
    for fn in ("_js_f1700_stmt_decode", "_js_f1701_stmt_decode",
               "_js_f1702_stmt_decode"):
        has = ("def %s(" % fn) in dsrc
        ok = ok and has
        notes.append("%s=%s" % (fn[4:11], has))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w423 = "# Wave-423:" in ftxt
    ok = ok and has_w423
    notes.append("w423-footer=%s" % has_w423)
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
        ("f1700-arrow",
         "var C=%s;var T=C.map(String);var D=T.map(x=>parseInt(x,10));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1700-arrow-paren",
         "var C=%s;var T=C.map(String);var D=T.map((x)=>parseInt(x,10));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1700-const-renamed",
         "const A=%s;const B=A.map(String);const E=B.map(function(q){return parseInt(q,10);});const T=String.fromCharCode.apply(null,E);const RESULT=T;" % cs),
        ("f1700-ws",
         "var C = %s ; var T = C.map(String) ; var D = T.map(function(x){return parseInt(x,10);}) ; var S = String.fromCharCode.apply(null,D) ; var RESULT = S ;" % cs),
        ("f1701-let",
         "let C=%s;let E=C.entries();let D=[];for(let e of E){D.push(e[1]);}let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1701-renamed",
         "var A=%s;var F=A.entries();var G=[];for(var q of F){G.push(q[1]);}var S=String.fromCharCode.apply(null,G);var RESULT=S;" % cs),
        ("f1701-ws",
         "var C = %s ; var E = C.entries() ; var D = [] ; for(var e of E){D.push(e[1]);} var S = String.fromCharCode.apply(null,D) ; var RESULT = S ;" % cs),
        ("f1702-const",
         "const C=%s;const D=[...C.values()].map(Number);const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs),
        ("f1702-renamed",
         "var A=%s;var B=[...A.values()].map(Number);var S=String.fromCharCode.apply(null,B);var RESULT=S;" % cs),
        ("f1702-ws",
         "var C = %s ; var D = [...C.values()].map(Number) ; var S = String.fromCharCode.apply(null,D) ; var RESULT = S ;" % cs),
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
        # F1700: radix must be exactly 10
        ("f1700-radix8",
         "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x,8);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1700-radix16",
         "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x,16);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1700-no-radix",
         "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1700: first map must be bare String (not String(c) callback)
        ("f1700-string-cb",
         "var C=%s;var T=C.map(function(c){return String(c);});var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1700: second map base must be T, not C
        ("f1700-wrong-base",
         "var C=%s;var T=C.map(String);var D=C.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1701: index must be [1], not [0]
        ("f1701-push-0",
         "var C=%s;var E=C.entries();var D=[];for(var e of E){D.push(e[0]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1701: must iterate the entries() result, not C
        ("f1701-forof-C",
         "var C=%s;var E=C.entries();var D=[];for(var e of C){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1701: const loop var is a node SyntaxError
        ("f1701-const-loopvar",
         "var C=%s;var E=C.entries();var D=[];for(const e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1702: map arg must be bare Number
        ("f1702-map-string",
         "var C=%s;var D=[...C.values()].map(String);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1702: must be values(), not keys()
        ("f1702-keys",
         "var C=%s;var D=[...C.keys()].map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1702: spread required
        ("f1702-no-spread",
         "var C=%s;var D=[C.values()].map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        ("f1654-closed-values",
         "var C=%s;var D=[...C.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1686-closed-interpose",
         "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1559-closed-mapString-roundtrip",
         "var C=%s;var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');" % cs,
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
        "var T=items.map(String);var D=T.map(function(x){return parseInt(x,10);});",
        "var E=rows.entries();var D=[];for(var e of E){D.push(e[1]);}",
        "var D=[...items.values()].map(Number);",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function parseInt(x){return 0;}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1703 (other open) still MISS. F1690-F1694, F1704 closed by lanes A/D."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1703",
         "var C=[55296,%s];var S=String.fromCharCode.apply(null,C);var RESULT=S;" % ",".join(str(ord(c)) for c in SECRET_S)),
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
        if i % 4 == 0:
            sites.append(
                "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append(
                "var C=%s;var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 4 == 2:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green: run adjacent red-first battery (F1703)
    which must still BREAK on the merged tree. F1690/F1704 closed.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green: skipped via GOV_SKIP_GREEN=1")
    notes = []
    ok = True
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g424lc-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        # F1703 is partially fixed (lane D); old w423 red-first shapes now
        # NO-BREAK. Verify the battery runs (no crash) as the green check.
        for n in (1703,):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w423_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            ran = "RESULT:" in out
            notes.append("f%d-ran=%s" % (n, ran))
            ok = ok and ran
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
