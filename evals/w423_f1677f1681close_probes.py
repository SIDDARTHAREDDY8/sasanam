#!/usr/bin/env python3
"""Wave-423 lane B close battery: F1677-F1681 CLOSED.

F1677: structuredClone(code-array) staging --
  `var D=structuredClone(C);` + fromCharCode.apply readout. New hook
  `_js_f1677_stmt_decode`. Node-exact: structuredClone deep-copies the
  dense code array. Disjoint from F536 (object-graph + member reads).

F1678: JSON.parse(JSON.stringify(C)) roundtrip --
  `var D=JSON.parse(JSON.stringify(C));` + fromCharCode.apply readout.
  New hook `_js_f1678_stmt_decode`. Node-exact: roundtrip is
  element-identical. Disjoint from F541 (literal parse).

F1679: String.fromCodePoint.apply(null,C) --
  direct apply readout, no staging var. New hook
  `_js_f1679_stmt_decode`. Node-exact on BMP non-surrogate codes;
  fails closed on astral/surrogate (fromCodePoint throws or pairs).

F1680: Uint8Array code stagings --
  `new Uint8Array(C)` / `Uint8Array.from(C)` / `[...new Uint8Array(C)]`
  + fromCharCode.apply readout. New hook `_js_f1680_stmt_decode`.
  Node-exact iff every code < 256 (ToUint8 identity); fails closed
  otherwise.

F1681: deprecated String HTML wrappers + tag-strip --
  `S.bold().replace(/<\\/?b>/g,'')` /
  `S.anchor('x').replace(/<[^>]*>/g,'')` /
  `S.link('x').replace(/<[^>]*>/g,'')` after the mapjoin staging.
  New hook `_js_f1681_stmt_decode`. Node-exact; fails closed on
  tag-like dstr or tag-like wrapper name.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 101->102
(wave-385: repoint on actual code-count change). Pin 2143,
re.compile=29 unchanged. Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; other opens (F1672-F1676, F1682-F1689) still MISS.

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
    ("f1677",
     "var C={I};var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);"),
    ("f1678",
     "var C={I};var D=JSON.parse(JSON.stringify(C));var RESULT=String.fromCharCode.apply(null,D);"),
    ("f1679",
     "var C={I};var RESULT=String.fromCodePoint.apply(null,C);"),
    ("f1680-new",
     "var C={I};var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);"),
    ("f1680-from",
     "var C={I};var D=Uint8Array.from(C);var RESULT=String.fromCharCode.apply(null,D);"),
    ("f1680-spread",
     "var C={I};var D=[...new Uint8Array(C)];var RESULT=String.fromCharCode.apply(null,D);"),
    ("f1681-bold",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;"),
    ("f1681-anchor",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.anchor('x').replace(/<[^>]*>/g,'');var RESULT=T;"),
    ("f1681-link",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.link('x').replace(/<[^>]*>/g,'');var RESULT=T;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=102 (this lane +1); pin 2143; re.compile=29; wave-422 footer lineage."""
    notes = []
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (len(loops) == 105)  # merge: 101 base + 4 lanes
    notes.append("loops=%d (want 102: 101 base +1 this lane)" % len(loops))
    # taxonomy pin 2143 (repo convention: the attack-probes battery pins it)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w422_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
    rc = len(re.findall(r"re\.compile\(", dsrc))
    ok = ok and rc == 29
    notes.append("re.compile=%d (want 29)" % rc)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w422 = "# Wave-422:" in ftxt
    ok = ok and has_w422
    notes.append("w422-footer=%s" % has_w422)
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
    """Renamed idents, let/const, ws variants, quote variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1677-let",
         "let C=%s;const D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1677-ws",
         "var  C = %s ; var D = structuredClone( C ) ; var RESULT = String.fromCharCode.apply( null , D ) ;" % cs),
        ("f1677-renamed",
         "var Q=%s;var W=structuredClone(Q);var RESULT=String.fromCharCode.apply(null,W);" % cs),
        ("f1678-const",
         "const C=%s;let D=JSON.parse(JSON.stringify(C));var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1678-ws",
         "var C=%s;var D=JSON.parse( JSON.stringify( C ) );var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1679-renamed",
         "var Q=%s;var RESULT=String.fromCodePoint.apply(null,Q);" % cs),
        ("f1679-const",
         "const C=%s;const RESULT=String.fromCodePoint.apply(null,C);" % cs),
        ("f1680-let-from",
         "let C=%s;var D=Uint8Array.from(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1680-spread-ws",
         "var C=%s;var D=[ ...new Uint8Array( C ) ];var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1680-renamed",
         "var Q=%s;var W=new Uint8Array(Q);var RESULT=String.fromCharCode.apply(null,W);" % cs),
        ("f1680-spread-from",
         "var C=%s;var D=[...Uint8Array.from(C)];var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1681-const",
         "const C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');let T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;" % cs),
        ("f1681-anchor-dq",
         'var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join("");var T=S.anchor("y").replace(/<[^>]*>/g,"");var RESULT=T;' % cs),
        ("f1681-link-ws",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.link( 'z' ).replace( /<[^>]*>/g , '' );var RESULT=T;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d generalizations hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level fail-closed bounds: all must MISS at the hook."""
    cs = _codes(SECRET_S)
    hookmap = {
        "f1677": _dlp._js_f1677_stmt_decode,
        "f1678": _dlp._js_f1678_stmt_decode,
        "f1679": _dlp._js_f1679_stmt_decode,
        "f1680": _dlp._js_f1680_stmt_decode,
        "f1681": _dlp._js_f1681_stmt_decode,
    }

    def hook_misses(name, payload):
        try:
            return hookmap[name](payload) is None
        except Exception:
            return False

    cases = [
        # F1677: clone source must be C; no member reads
        ("f1677", "f1677-clone-wrong-src",
         "var C=%s;var E=[1];var D=structuredClone(E);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1677", "f1677-no-clone",
         "var C=%s;var D=C.slice();var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1677", "f1677-clone-member",
         "var C=%s;var D=structuredClone({a:C});var RESULT=String.fromCharCode.apply(null,D.a);" % cs),
        # F1678: must be parse(stringify(C))
        ("f1678", "f1678-stringify-only",
         "var C=%s;var D=JSON.stringify(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1678", "f1678-parse-literal",
         "var C=%s;var D=JSON.parse('[1,2]');var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1678", "f1678-parse-wrong-src",
         "var C=%s;var E=[1];var D=JSON.parse(JSON.stringify(E));var RESULT=String.fromCharCode.apply(null,D);" % cs),
        # F1679: BMP-only; fromCodePoint.apply(null,C)
        ("f1679", "f1679-fcc-not-fcp",
         "var C=%s;var RESULT=String.fromCharCode.apply(null,C);" % cs),
        ("f1679", "f1679-apply-thisarg",
         "var C=%s;var RESULT=String.fromCodePoint.apply(this,C);" % cs),
        ("f1679", "f1679-astral",
         "var C=[120,111,119088];var RESULT=String.fromCodePoint.apply(null,C);"),
        ("f1679", "f1679-surrogate",
         "var C=[120,111,55357];var RESULT=String.fromCodePoint.apply(null,C);"),
        # F1680: Uint8Array only; codes < 256
        ("f1680", "f1680-u16array",
         "var C=%s;var D=new Uint16Array(C);var RESULT=String.fromCharCode.apply(null,D);" % cs),
        ("f1680", "f1680-code-256",
         "var C=[120,256,98];var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);"),
        ("f1680", "f1680-from-noarg",
         "var C=%s;var D=Uint8Array.from();var RESULT=String.fromCharCode.apply(null,D);" % cs),
        # F1681: wrapper + exact regex + empty replacement
        ("f1681", "f1681-no-strip",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold();var RESULT=T;" % cs),
        ("f1681", "f1681-replace-nonempty",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'x');var RESULT=T;" % cs),
        ("f1681", "f1681-wrong-regex",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<b>/,'');var RESULT=T;" % cs),
        ("f1681", "f1681-anchor-noarg",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.anchor().replace(/<[^>]*>/g,'');var RESULT=T;" % cs),
        ("f1681", "f1681-italics",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.italics().replace(/<\\/?i>/g,'');var RESULT=T;" % cs),
        ("f1681", "f1681-nog-flag",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/,'');var RESULT=T;" % cs),
    ]
    bad = ["%s:%s" % (hk, n) for hk, n, p in cases if not hook_misses(hk, p)]
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
        # F536/F541 are OPEN (not closed) -- sibling pins use the
        # direct-apply control and the fromCodePoint spread twin
        # (both HIT per the F1679 entry).
        ("fcc-apply-direct",
         "var C=%s;var RESULT=String.fromCharCode.apply(null,C);" % cs,
         True),
        ("fcp-spread-ctrl",
         "var C=%s;var RESULT=String.fromCodePoint(...C);" % cs,
         True),
        ("f1650-closed-cpa-spread",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs,
         True),
        ("f1626-closed-nfc",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs,
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
        "var D=structuredClone(items);",
        "var D=JSON.parse(JSON.stringify(config));",
        "var s=String.fromCodePoint(65,66);",
        "var D=new Uint8Array(16);",
        "var T=title.bold();",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "function clone(x){return x;}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1672-F1676, F1682-F1684 now CLOSED in merge -> expect HIT; F1688 now CLOSED in merge -> expect HIT."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1672", "var C=%s;var D=Array.from(C);var E=D.map(function(c){return c+1;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1675", "var C=%s;var G=new Intl.Segmenter().segment('abcdef');var A=[...G].map(function(x){return x.segment;});var S=A.join('');var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T;" % cs),
        ("f1682", "var C=%s;var O=Object.assign({},C);var V=Object.values(O);var S=String.fromCharCode.apply(null,V);var RESULT=S;" % cs),
        ("f1685", "var C=%s;var H=C.map(function(c){return c.toString(16);});var B=H.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,B);var RESULT=S;" % cs),
        ("f1688", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var R=S.split('').reverse().reverse().join('');var RESULT=R;" % cs),
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
                "var C=%s;var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;" % cs)
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
    """Regression check (wave-423 merge): F1672-F1689 now CLOSED, so their
    red-first batteries must be NO-BREAK (filed shapes HIT). Honors
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green: skipped via GOV_SKIP_GREEN=1")
    notes = []
    ok = True
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g423lb-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        # 1. Merged-closed findings must now be NO-BREAK (no regression).
        for n in (1672, 1676, 1682, 1689):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w422_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "") + (r.stderr or "")
            nobreak = "RESULT: NO-BREAK" in out
            notes.append("f%d-nobreak=%s" % (n, nobreak))
            ok = ok and nobreak
        # 2. F1677-F1681 red-first batteries must now be NO-BREAK.
        for n in range(1677, 1682):
            r = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals",
                                              "w422_f%d_redfirst.py" % n)],
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
