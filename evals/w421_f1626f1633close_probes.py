#!/usr/bin/env python3
"""Wave-421 lane 3 close battery: F1626-F1633 CLOSED.

F1626: normalize('NFC') identity -- `var T=S.normalize('NFC');` + RESULT.
  Closed by `_js_f1626_stmt_decode`. Node-exact: NFC is identity on ASCII.
  Only 'NFC' admitted; other forms fail closed. Disjoint by .normalize( anchor.

F1627: toUpperCase().toLowerCase() roundtrip --
  `var T=S.toUpperCase().toLowerCase();` + RESULT. Closed by
  `_js_f1627_stmt_decode`. Node-exact: identity on lowercase ASCII.
  Chained form required; bare toLowerCase already HIT. Disjoint by chained anchor.

F1628: filter always-true identity --
  `var D=C.filter(function(c){return true;});` +
  fromCharCode.apply readout. Closed by `_js_f1628_stmt_decode`.
  Node-exact: always-true filter is a shallow copy. Distinct from F1568
  (filter includes(c,1)) by predicate grammar.

F1629: fill(0,C.length) no-op --
  `var D=C.slice();D.fill(0,C.length);` + fromCharCode.apply readout.
  Closed by `_js_f1629_stmt_decode`. Node-exact: start==length is a no-op.
  Only the exact fill(0,C.length) form admitted.

F1630: C.at(i) identity copy --
  `var D=C.map(function(c,i){return C.at(i);});` + fromCharCode.apply.
  Closed by `_js_f1630_stmt_decode`. Node-exact: at(i) rebuilds the array.
  Distinct from F1524 (at() computed-negative) by callback grammar.

F1631: toLocaleString() identity --
  `var T=S.toLocaleString();` + RESULT. Closed by `_js_f1631_stmt_decode`.
  Node-exact: toLocaleString is identity on strings. Disjoint by anchor.

F1632: split/match identity roundtrips (3 shapes) --
  `S.split('').join('')`, `S.match(/./g).join('')`,
  `[...S.matchAll(/./g)].join('')`. Closed by `_js_f1632_stmt_decode`.
  Node-exact: all three are identity on strings.

F1633: Array.prototype .call variants (3 shapes) --
  `Array.prototype.join.call(C,',')` + split/map/apply readout;
  `Array.prototype.slice.call(C)` + apply readout;
  `Array.prototype.map.call(C,identity)` + apply readout. Closed by
  `_js_f1633_stmt_decode`. Node-exact: join.call joins, slice.call copies,
  map.call with identity copies.

New _decode_layer dispatch loop (F1626-F1633);
N_STMTDEC_LOOPS 95->96 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1608-F1625, F1634-F1641
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
    ("f1626",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;"),
    ("f1627",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase().toLowerCase();var RESULT=T;"),
    ("f1628",
     "var C={I};var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1629",
     "var C={I};var D=C.slice();D.fill(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1630",
     "var C={I};var D=C.map(function(c,i){return C.at(i);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1631",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString();var RESULT=T;"),
    ("f1632-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').join('');var RESULT=T;"),
    ("f1632-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.match(/./g).join('');var RESULT=T;"),
    ("f1632-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=[...S.matchAll(/./g)].join('');var RESULT=T;"),
    ("f1633-0",
     "var C={I};var S=Array.prototype.join.call(C,',');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("f1633-1",
     "var C={I};var D=Array.prototype.slice.call(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1633-2",
     "var C={I};var D=Array.prototype.map.call(C,function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
        ("f1626-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const T=S.normalize('NFC');const RESULT=T;" % cs),
        ("f1626-ws",
         "var C = %s ; var S = C.map(function(c){return String.fromCharCode(c);}).join('') ; var T = S.normalize( 'NFC' ) ; var RESULT = T ;" % cs),
        ("f1627-let",
         "let C=%s;let S=C.map((c)=>String.fromCharCode(c)).join('');let T=S.toUpperCase().toLowerCase();let RESULT=T;" % cs),
        ("f1628-renamed",
         "var A=%s;var B=A.filter(function(x){return true;});var S=String.fromCharCode.apply(null,B);var RESULT=S;" % cs),
        ("f1629-let",
         "let C=%s;let D=C.slice();D.fill(0,C.length);let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1630-renamed",
         "var A=%s;var B=A.map(function(x,j){return A.at(j);});var S=String.fromCharCode.apply(null,B);var RESULT=S;" % cs),
        ("f1631-const",
         "const C=%s;const S=C.map((c)=>String.fromCharCode(c)).join('');const T=S.toLocaleString();const RESULT=T;" % cs),
        ("f1632-arrow",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.split('').join('');var RESULT=T;" % cs),
        ("f1633-ws",
         "var C = %s ; var D = Array.prototype.slice.call( C ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;" % cs),
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
        # F1626: only 'NFC' admitted
        ("f1626-nfd", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;" % cs),
        ("f1626-nfkc", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKC');var RESULT=T;" % cs),
        # F1627: chained form required
        ("f1627-upper-only", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase();var RESULT=T;" % cs),
        ("f1627-reversed", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLowerCase().toUpperCase();var RESULT=T;" % cs),
        # F1628: only `return true;` admitted
        ("f1628-false", "var C=%s;var D=C.filter(function(c){return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1628-expr", "var C=%s;var D=C.filter(function(c){return c>0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1628-arrow", "var C=%s;var D=C.filter((c)=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1629: only fill(0,C.length)
        ("f1629-one", "var C=%s;var D=C.slice();D.fill(1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1629-zero-len", "var C=%s;var D=C.slice();D.fill(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1629-twoarg", "var C=%s;var D=C.slice();D.fill(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1630: only C.at(i) with 2-param function
        ("f1630-1param", "var C=%s;var D=C.map(function(c){return C.at(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1630-wrongbase", "var C=%s;var D=C.map(function(c,i){return D.at(i);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1631: no args only
        ("f1631-arg", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString('en');var RESULT=T;" % cs),
        # F1632: only the three shapes
        ("f1632-split-comma", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split(',').join('');var RESULT=T;" % cs),
        ("f1632-match-star", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.match(/.*/g).join('');var RESULT=T;" % cs),
        # F1633: only join/slice/map .call
        ("f1633-wrongsep", "var C=%s;var S=Array.prototype.join.call(C,';');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;" % cs),
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
        ("f1626-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs,
         True),
        ("f1627-closed",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase().toLowerCase();var RESULT=T;" % cs,
         True),
        ("f1568-closed-filter",
         "var C=%s;var D=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         True),
        ("f1611-closed-trim",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\\u2000'+S+'\\u2000';var RESULT=T.trim();" % cs,
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
        "var T=input.normalize('NFC');var RESULT=T;",
        "var T=name.toUpperCase().toLowerCase();",
        "var D=items.filter(function(x){return true;});",
        "var T=text.toLocaleString();",
        "var T=s.split('').join('');",
        "The quarterly financial summary shows revenue growth of 12 percent.",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1608-F1625, F1634-F1641 (other opens) still MISS at the decoder seam."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1608", "var C=%s;var E=C.flatMap(function(c,i,a){return [String.fromCharCode(c)];},undefined);var S=E.join('');var RESULT=S;" % cs),
        ("f1612", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0,undefined);var RESULT=T;" % cs),
        ("f1620", "var C=%s;function g(){var A=Array.from(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);" % cs),
        ("f1634", "var C=%s;var S=Array.from(C,String.fromCharCode).join('');var RESULT=S;" % cs),
        ("f1639", "var C=%s;var D=C.flat(0.00);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
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
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    """Depth-1 green on w420_attack_probes (closure-aware check).

    F1626-F1633 are now CLOSED by this lane, so their 8 pins flip from
    MISS to HIT (expected). All other pins must hold: F1608-F1625,
    F1634-F1638 still MISS (25 pins), taxonomy 2143, footer.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w420_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g421l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w420_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # Expect 25/33 HELD: the 8 F1626-F1633 pins now HIT (closed),
        # all others hold.
        m = re.search(r"RESULT: (\d+)/(\d+) HELD", out)
        held_ok = m and m.group(1) == "25" and m.group(2) == "33"
        # Verify the 8 flipped pins are exactly F1626-F1633
        flipped = []
        for n in range(1626, 1634):
            if re.search(r"FAIL F%d -> HIT" % n, out):
                flipped.append(n)
        flip_ok = (sorted(flipped) == list(range(1626, 1634)))
        tax = "taxonomy pin 2143" in out
        footer = "footer pin" in out
        ok = bool(held_ok and flip_ok and tax and footer)
        return (ok, "green(w420_attack): held=%s flipped=%s tax=%s footer=%s"
                % (m.group(0) if m else "?", flipped, tax, footer))
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
