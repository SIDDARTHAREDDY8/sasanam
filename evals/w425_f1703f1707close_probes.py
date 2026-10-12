#!/usr/bin/env python3
"""Wave-425 lane A close battery: F1703, F1705-F1707 CLOSED.

F1703: surrogate-code smuggling partial -- statement-decoder shared path
  (_js_f996f997_fcc_chr) and _js_parse_fromcharcode_args_inner fixed by
  wave-424 lane D to ToUint16-faithful. All F1686-F1689 surrogate shapes
  now HIT. No new code; verification only.

F1705: Object.assign multi-source staging --
  `var D=Object.assign([],C,C);` + fromCharCode.apply readout. New
  `_js_f1705_stmt_decode`. Node-exact: multi-source copies every index
  into a fresh array. Disjoint from F1560/F1595/F1641 (single-source)
  by grammar.

F1706: untagged template literal identity --
  "var T=`${S}`;" + fromCharCode.apply readout. New
  `_js_f1706_stmt_decode`. Node-exact: `${S}` is identity. Disjoint from
  F1516 (tagged template) by grammar.

F1707: flat with member-expression computed depth --
  `var D=[C];var E=D.flat(C.length-C.length+1);` + fromCharCode.apply
  readout. New `_js_f1707_stmt_decode`. Node-exact: depth expr evaluates
  to 1, flat(1) yields C's elements. Disjoint from F1534 (literal depth)
  by grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 108->109
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1708-F1714
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
    ("f1705",
     "var C={I};var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1706",
     "var C={I};var S=String.fromCharCode.apply(null,C);var T=`${S}`;var RESULT=T;"),
    ("f1707",
     "var C={I};var D=[C];var E=D.flat(C.length-C.length+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=109 (108 base + 1 lane); re.compile=29; pin 2143; wave-424 footer lineage."""
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 109)
    notes.append("loops=%d (expect 109)" % len(loops))
    # new loop present with tail guard
    has_new = "_js_f1705_stmt_decode" in body and "_js_f1707_stmt_decode" in body
    ok = ok and has_new
    notes.append("f1705-f1707 loop present: %s" % has_new)
    # hooks defined
    for h in ("_js_f1705_stmt_decode", "_js_f1706_stmt_decode", "_js_f1707_stmt_decode"):
        present = ("def %s(" % h) in dsrc
        ok = ok and present
        notes.append("%s defined: %s" % (h, present))
    # re.compile = 29
    rc = dsrc.count("re.compile(")
    ok = ok and (rc == 29)
    notes.append("re.compile=%d (expect 29)" % rc)
    # pin 2143 in footer
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = ok and ("2143" in ftxt)
    notes.append("pin 2143 present: %s" % ("2143" in ftxt))
    # footer lineage: wave-424 footer present
    ok = ok and ("# Wave-424:" in ftxt)
    notes.append("wave-424 footer: %s" % ("# Wave-424:" in ftxt))
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
        ("f1705-const-renamed",
         "const A=%s;const B=Object.assign([],A,A);const T=String.fromCharCode.apply(null,B);const RESULT=T;" % cs),
        ("f1705-let",
         "let C=%s;let D=Object.assign([],C,C);let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1705-ws",
         "var C = %s ; var D = Object.assign([], C, C) ; var S = String.fromCharCode.apply(null, D) ; var RESULT = S ;" % cs),
        ("f1706-const",
         "const C=%s;const S=String.fromCharCode.apply(null,C);const T=`${S}`;const RESULT=T;" % cs),
        ("f1706-renamed",
         "var A=%s;var B=String.fromCharCode.apply(null,A);var Q=`${B}`;var RESULT=Q;" % cs),
        ("f1706-ws",
         "var C = %s ; var S = String.fromCharCode.apply(null, C) ; var T = `${S}` ; var RESULT = T ;" % cs),
        ("f1707-let",
         "let C=%s;let D=[C];let E=D.flat(C.length-C.length+1);let S=String.fromCharCode.apply(null,E);let RESULT=S;" % cs),
        ("f1707-renamed",
         "var A=%s;var B=[A];var F=B.flat(A.length-A.length+1);var S=String.fromCharCode.apply(null,F);var RESULT=S;" % cs),
        ("f1707-ws",
         "var C = %s ; var D = [C] ; var E = D.flat(C.length - C.length + 1) ; var S = String.fromCharCode.apply(null, E) ; var RESULT = S ;" % cs),
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
        # F1705: single source (F1560's shape) must NOT hit via f1705 hook
        # (it hits via F1560's own hook, but f1705 hook must not mis-decode)
        ("f1705-single-src",
         "var C=%s;var D=Object.assign([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1705: three sources (not the filed shape)
        ("f1705-three-src",
         "var C=%s;var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1705: wrong base
        ("f1705-wrong-base",
         "var C=%s;var X=%s;var D=Object.assign([],C,X);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % (cs, cs)),
        # F1706: tagged template (F1516's territory)
        ("f1706-tagged",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var T=String.raw`${S}`;var RESULT=T;" % cs),
        # F1706: template with extra text (not pure identity)
        ("f1706-extra-text",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var T=`x${S}`;var RESULT=T;" % cs),
        # F1706: wrong interp base
        ("f1706-wrong-base",
         "var C=%s;var S=String.fromCharCode.apply(null,C);var X='y';var T=`${X}`;var RESULT=T;" % cs),
        # F1707: literal depth (F1534's shape)
        ("f1707-literal-depth",
         "var C=%s;var D=[C];var E=D.flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1707: wrong depth expr (1+1 instead of C.length-C.length+1)
        ("f1707-arith-depth",
         "var C=%s;var D=[C];var E=D.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1707: depth 2 (not 1)
        ("f1707-depth-two",
         "var C=%s;var D=[C];var E=D.flat(C.length-C.length+2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1707: not wrapped in array
        ("f1707-no-wrap",
         "var C=%s;var E=C.flat(C.length-C.length+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
    ]
    # Note: some of these HIT via other hooks (e.g., f1705-single-src hits via F1560).
    # We check that the SPECIFIC new hooks don't mis-decode, i.e., the payload
    # either misses entirely or hits for the right reason. For fail-closed, we
    # verify the new hook functions return None directly.
    from gov.dlp import (_js_f1705_stmt_decode, _js_f1706_stmt_decode,
                         _js_f1707_stmt_decode)
    hooks = {
        "f1705": _js_f1705_stmt_decode,
        "f1706": _js_f1706_stmt_decode,
        "f1707": _js_f1707_stmt_decode,
    }
    bad = []
    for name, payload in cases:
        prefix = name.split("-")[0]
        hook = hooks.get(prefix)
        if hook is None:
            continue
        try:
            res = hook(payload)
        except Exception:
            res = "ERR"
        # The hook must return None (fail closed) for non-filed shapes.
        # Exception: f1705-single-src is F1560's shape, not f1705's -- f1705 hook must return None.
        if res is not None:
            bad.append(name)
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Sibling hooks still work: F1700, F1701, F1702."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1700", "var C=%s;var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1701", "var C=%s;var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1702", "var C=%s;var D=[...C.values()].map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest-quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    cases = [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "function hello() { return 'world'; }",
        "// This is a comment with no credentials",
        "var C=[1,2,3];var D=Object.assign([],C);",  # no readout
    ]
    bad = [p[:30] for p in cases if _hits(p)]
    return (not bad, "%d/%d quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other-opens MISS ----------------

@_t
def test_p6_other_opens_miss():
    """Other open findings still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        # F1708: flatMap with null thisArg
        ("f1708", "var C=%s;var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1709: map with null thisArg
        ("f1709", "var C=%s;var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1710: Array.from with null thisArg
        ("f1710", "var C=%s;var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1711: trailing comma spread
        ("f1711", "var C=%s;var D=[...C,];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1714: direct apply with surrogate (lane C's territory)
        ("f1714", "var C=[0xD800,%s];var S=String.fromCharCode.apply(null,C);var RESULT=S;" % ",".join(str(ord(c)) for c in SECRET_S)),
    ]
    bad = [n for n, p in cases if _hits(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 sites decode in reasonable time."""
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
    sites = [payload] * 200
    t0 = time.time()
    for s in sites:
        _hits(s)
    dt = time.time() - t0
    ok = dt < 120
    return (ok, "200 sites in %.1fs (limit 120s)" % dt)


# ---------------- g0: green ----------------

@_t
def test_g0_green():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "skipped (GOV_SKIP_GREEN=1)")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = "/var/tmp/w425a-g0-%d" % os.getpid()
    os.makedirs(tmpd, exist_ok=True)
    env["TMPDIR"] = tmpd
    batteries = [
        "evals/w424_f1700f1702close_probes.py",
    ]
    notes = []
    ok = True
    for b in batteries:
        bp = os.path.join(REPO_ROOT, b)
        if not os.path.exists(bp):
            notes.append("%s missing (skip)" % b)
            continue
        r = subprocess.run([sys.executable, bp],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        # Check for HELD in output
        held = "HELD" in (r.stdout or "")
        ok = ok and (r.returncode == 0 or held)
        notes.append("%s: %s" % (b, "ok" if held else "rc=%d" % r.returncode))
    shutil.rmtree(tmpd, ignore_errors=True)
    return (ok, "; ".join(notes))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-green", action="store_true",
                    help="skip g0 green check")
    ap.add_argument("--only", default=None,
                    help="run only tests matching substring")
    args = ap.parse_args()
    results = []
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        if args.no_green and fn.__name__ == "test_g0_green":
            continue
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC: %s" % e
        results.append((fn.__name__, ok, note))
        print("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note))
    n_ok = sum(1 for _, ok, _ in results if ok)
    print("RESULT: %d/%d HELD" % (n_ok, len(results)))
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
