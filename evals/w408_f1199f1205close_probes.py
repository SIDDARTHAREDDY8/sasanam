#!/usr/bin/env python3
"""Wave-408 lane 1 close battery: F1199-F1205 CLOSED.

F1199: join/split char-array roundtrip -- mapping codes to chars,
joining with a custom separator (or Array toString's comma join),
then splitting and re-joining. Closed by _js_f1199_stmt_decode:
the split separator must equal the join separator, and no character
of the separator may occur in the credential (else the split is not
the inverse of the join -- fail closed). Distinct from F1134
(int-array roundtrip, no char map) and F1090 (bare map+join, no
split step).

F1200: globalThis member-expression staging -- reading
String.fromCharCode off globalThis (dot form via a G alias, or
bracket form directly off globalThis) into a variable, then calling
it in an accumulation loop. Closed by _js_f1200_stmt_decode.

F1201: with-scope fromCharCode accumulation -- accumulating via the
bare fromCharCode inside with(String) (sloppy mode). Closed by
_js_f1201_stmt_decode. Distinct from F1117 (with-scope staged
spread).

F1202: switch-statement accumulation -- accumulating inside a
switch(N){case N:} within the loop. Closed by
_js_f1202_stmt_decode (discriminant and case label must be the same
integer literal).

F1203: Number.toFixed(d) roundtrip -- per-code toFixed(d)+parseInt
roundtrip (0<=d<=100; d>100 is a RangeError in the engine).
Closed by _js_f1203_stmt_decode.

F1204: Date setMilliseconds staging -- round-tripping codes through
a Date's milliseconds (codes must be 0..999; larger values roll
into seconds). Closed by _js_f1204_stmt_decode.

F1205: new-Function staged calls -- new Function('c','return
String.fromCharCode(c)') called per-code in a for loop or a forEach
(function or arrow twin). Closed by _js_f1205_stmt_decode.
Distinct from F893 (literal Function bodies).

All hooks are whole-text, narrow-grammar, fail-closed, F452-charged
per attempt, and results are bounded by _MAX_DECODE_BYTES. Never
evals. Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
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

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 29
STMTDEC_PIN = 50  # wave-408 lane 1: +1 F1199-F1205 dispatch loop

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _hits(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"
# 21-char gate-passing secrets carrying separator characters (for
# fail-closed guard tests; the direct forms HIT, verified).
SECRET_PIPE = "xoxb-0123456789abcde|"
SECRET_COMMA = "xoxb-0123456789abcde,"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _p(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))


FILED = [
    # F1199 (2 productions)
    ("f1199-join-sep",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;"),
    ("f1199-tostring",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var T=A.toString();var S=T.split(',').join('');var RESULT=S;"),
    # F1200 (2 productions)
    ("f1200-dot",
     "var C={I};var G=globalThis;var F=G.String.fromCharCode;var S='';"
     "for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;"),
    ("f1200-bracket",
     "var C={I};var F=globalThis['String']['fromCharCode'];var S='';"
     "for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;"),
    # F1201
    ("f1201-with",
     "var C={I};var S='';with(String){for(var i=0;i<C.length;i++)"
     "{S+=fromCharCode(C[i]);}}var RESULT=S;"),
    # F1202
    ("f1202-switch",
     "var C={I};var S='';for(var i=0;i<C.length;i++){switch(1){case 1:"
     "S+=String.fromCharCode(C[i]);break;}}var RESULT=S;"),
    # F1203
    ("f1203-tofixed",
     "var C={I};var S='';for(var i=0;i<C.length;i++)"
     "{S+=String.fromCharCode(parseInt(C[i].toFixed(0),10));}var RESULT=S;"),
    # F1204
    ("f1204-date",
     "var C={I};var D=new Date(0);var S='';for(var i=0;i<C.length;i++)"
     "{D.setMilliseconds(C[i]);S+=String.fromCharCode(D.getMilliseconds());}"
     "var RESULT=S;"),
    # F1205 (2 productions)
    ("f1205-newfn",
     "var C={I};var F=new Function('c','return String.fromCharCode(c)');"
     "var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;"),
    ("f1205-foreach",
     "var C={I};var F=new Function('c','return String.fromCharCode(c)');"
     "var S='';C.forEach(function(c){S+=F(c);});var RESULT=S;"),
]

# Generalizations: node-verified (v24.20.0) to assemble the credential.
GENERALIZATIONS = [
    ("f1199-arrow",
     "var C={I};var A=C.map(c=>String.fromCharCode(c));"
     "var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;"),
    ("f1199-let-sep",
     "let C={I};let A=C.map(function(ch){return String.fromCharCode(ch);});"
     "let J=A.join('##');let S=J.split('##').join('');var RESULT=S+'!';"),
    ("f1199-empty-sep",
     "const C={I};const A=C.map(c=>String.fromCharCode(c));"
     "const J=A.join('');const S=J.split('').join('');var RESULT=S;"),
    ("f1200-direct",
     "var C={I};var F=globalThis.String.fromCharCode;var S='';"
     "for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;"),
    ("f1200-alias-bracket",
     "var C={I};var G=globalThis;var F=G['String']['fromCharCode'];var S='';"
     "for(let k=0;k<C.length;k+=1){S+=F(C[k]);}var RESULT=S;"),
    ("f1201-let",
     "var C={I};let S='';with(String){for(let i=0;i<C.length;i++)"
     "{S+=fromCharCode(C[i]);}}var RESULT=S;"),
    ("f1202-switch2",
     "var C={I};var S='';for(var i=0;i<C.length;i++){switch(2){case 2:"
     "S+=String.fromCharCode(C[i]);break;}}var RESULT='pre'+S;"),
    ("f1203-tofixed1",
     "var C={I};var S='';for(var i=0;i<C.length;i++)"
     "{S+=String.fromCharCode(parseInt(C[i].toFixed(1),10));}var RESULT=S;"),
    ("f1203-tofixed100",
     "var C={I};var S='';for(var i=0;i<C.length;i++)"
     "{S+=String.fromCharCode(parseInt(C[i].toFixed(100),10));}var RESULT=S;"),
    ("f1204-rename",
     "var C={I};var DT=new Date(0);var S='';for(var i=0;i<C.length;i++)"
     "{DT.setMilliseconds(C[i]);S+=String.fromCharCode(DT.getMilliseconds());}"
     "var RESULT=S;"),
    ("f1205-dq",
     'var C={I};var F=new Function("c","return String.fromCharCode(c)");'
     "var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;"),
    ("f1205-arrow-foreach",
     "var C={I};var F=new Function('c','return String.fromCharCode(c)');"
     "var S='';C.forEach((c)=>{S+=F(c);});var RESULT=S;"),
    ("f1205-unbraced-arrow",
     "var C={I};var F=new Function('c','return String.fromCharCode(c)');"
     "var S='';C.forEach(c=>S+=F(c));var RESULT=S;"),
]

# Fail-closed: scanner must MISS. Entries marked (node) assemble the
# credential in node but must still MISS (guard fires); the rest do
# not assemble (miss is trivially correct).
FAIL_CLOSED = [
    # F1199: separator character occurs in the credential (node joins
    # then splits wrong) -- guard must fire. (node)
    ("f1199-sep-in-cred",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var J=A.join('|');var S=J.split('|').join('');var RESULT=S;",
     SECRET_PIPE),
    # F1199 toString twin: comma in the credential. (node)
    ("f1199-comma-in-cred",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var T=A.toString();var S=T.split(',').join('');var RESULT=S;",
     SECRET_COMMA),
    # F1199: split separator != join separator.
    ("f1199-sep-mismatch",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var J=A.join('|');var S=J.split(':').join('');var RESULT=S;",
     SECRET_S),
    # F1200: wrong base object (window is undefined in node).
    ("f1200-window",
     "var C={I};var F=window.String.fromCharCode;var S='';"
     "for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;",
     SECRET_S),
    # F1201: with(Math) -- fromCharCode does not resolve.
    ("f1201-math",
     "var C={I};var S='';with(Math){for(var i=0;i<C.length;i++)"
     "{S+=fromCharCode(C[i]);}}var RESULT=S;",
     SECRET_S),
    # F1202: case label != discriminant (no case taken).
    ("f1202-case-mismatch",
     "var C={I};var S='';for(var i=0;i<C.length;i++){switch(1){case 2:"
     "S+=String.fromCharCode(C[i]);break;}}var RESULT=S;",
     SECRET_S),
    # F1203: toFixed(101) is a RangeError in the engine.
    ("f1203-tofixed101",
     "var C={I};var S='';for(var i=0;i<C.length;i++)"
     "{S+=String.fromCharCode(parseInt(C[i].toFixed(101),10));}var RESULT=S;",
     SECRET_S),
    # F1204: code 1000 rolls into the seconds field.
    ("f1204-ms-overflow",
     "var C=[1000,{I}];var D=new Date(0);var S='';for(var i=0;i<C.length;i++)"
     "{D.setMilliseconds(C[i]);S+=String.fromCharCode(D.getMilliseconds());}"
     "var RESULT=S;",
     SECRET_S, True),
    # F1205: wrong factory body literal.
    ("f1205-wrong-body",
     "var C={I};var F=new Function('c','return String.fromCharCode(c)+\"!\"');"
     "var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;",
     SECRET_S),
    # F1205: factory param/body mismatch (c undefined -> NaN -> NUL).
    ("f1205-param-mismatch",
     "var C={I};var F=new Function('x','return String.fromCharCode(c)');"
     "var S='';for(var i=0;i<C.length;i++){S+=F(C[i]);}var RESULT=S;",
     SECRET_S),
]

POLITE = ("the quarterly financial summary shows revenue growth across "
          "all regional divisions and market segments")


@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


@_t
def test_p0_verifier_pin():
    ok = VERIFIER_TAXONOMY_PIN == 33
    print(("HELD " if ok else "BREAK") + " test_p0_verifier_pin (%d)" % VERIFIER_TAXONOMY_PIN)
    return ok


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RECOMPILE_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_recompile_pin (%d)" % n)
    return ok


@_t
def test_p0_stmtdec_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \([^)]*\):", body, re.DOTALL)
    ok = len(loops) == STMTDEC_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_stmtdec_pin (%d)" % len(loops))
    return ok


@_t
def test_p0_footer_state():
    """Lane-local footer: F1199-F1205 stamped CLOSED by this lane;
    F1206-F1227 remain OPEN."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    bad = []
    for num in range(1199, 1206):
        if not re.search(r"\(F%d filed .*?\[CLOSED 2026-10-11 wave-408 lane 1\]" % num,
                         text, re.DOTALL):
            bad.append("F%d-not-closed" % num)
    for num in range(1206, 1228):
        m = re.search(r"\(F%d filed .*?; LOW, (OPEN|\[CLOSED)" % num, text)
        if not m or m.group(1) != "OPEN":
            bad.append("F%d-not-open" % num)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state%s"
          % ("" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_filed_shapes():
    """All 11 filed productions (7 findings x sizes) now BLOCK."""
    bad = []
    total = 0
    for name, tmpl in FILED:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(_p(tmpl, secret)):
                bad.append("%s/%s" % (name, "L" if secret == SECRET_L else "S"))
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_filed_shapes (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_generalizations():
    """Node-verified twins and spellings also BLOCK."""
    bad = []
    for name, tmpl in GENERALIZATIONS:
        if not _hits(_p(tmpl)):
            bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_generalizations (%d%s)"
          % (len(GENERALIZATIONS), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_fail_closed():
    """Guard and narrowness cases must MISS (never mis-decode)."""
    bad = []
    # non-vacuity: the separator-carrying secrets pass the gate direct
    for secret in (SECRET_PIPE, SECRET_COMMA):
        if not _hits("var RESULT='%s';" % secret):
            bad.append("gate-vacuous")
    for entry in FAIL_CLOSED:
        name, tmpl, secret = entry[0], entry[1], entry[2]
        prepend_1000 = len(entry) > 3 and entry[3]
        codes = _codes(secret)[1:-1]
        if prepend_1000:
            codes = "1000," + codes
        payload = tmpl.replace("{I}", codes)
        if not _misses(payload):
            bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_fail_closed (%d%s)"
          % (len(FAIL_CLOSED) + 2, "" if ok else ": " + ",".join(bad)))
    return ok


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


@_t
def test_sibling_closed_still_hit():
    """Sibling closed shapes still BLOCK via their own hooks."""
    bad = []
    total = 0
    # F1090 direct map+join twin (the control every filed shape cites)
    total += 1
    if not _hits(_p("var C={I};var S=C.map(function(c)"
                    "{return String.fromCharCode(c);}).join('');var RESULT=S;")):
        bad.append("f1090")
    # F1182 Object.create staged assembly (spot check)
    for name, payload in _redfirst_shapes("w406", 1182)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1182")
            break
    # F1193 FormData staged reads (spot check)
    for name, payload in _redfirst_shapes("w407", 1193)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1193")
            break
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_sibling_closed_still_hit (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_still_open():
    """F1206-F1227 (other lanes' scope) still MISS."""
    bad = []
    total = 0
    for num in (1206, 1210, 1217, 1222, 1224):
        for name, payload in _redfirst_shapes("w407", num):
            total += 1
            if not _misses(payload):
                bad.append("f%d" % num)
                break
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_still_open (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_honest_quiet():
    """Honest text and near-miss shapes stay quiet."""
    cases = [
        ("polite", POLITE),
        ("honest-loop",
         "var C=[1,2,3];var S='';for(var i=0;i<C.length;i++){S+=i;}var R=S;"),
        ("with-nofcc", "with(Math){var x=1;}"),
        ("globalthis-alone", "var G=globalThis;var F=G.String.fromCharCode;"),
        ("switch-honest", "switch(1){case 1:var x=2;break;}"),
        ("date-honest", "var D=new Date(0);D.setMilliseconds(5);var m=D.getMilliseconds();"),
        ("newfn-honest", "var F=new Function('a','b','return a+b');var r=F(1,2);"),
        ("join-honest",
         "var A=['a','b'];var J=A.join(',');var S=J.split(',').join('');var R=S;"),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_honest_quiet (%d%s)"
          % (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_perf_200_sites():
    texts = []
    for i in range(200):
        if i % 5 == 0:
            texts.append(_p(FILED[i % len(FILED)][1]))
        elif i % 5 == 1:
            texts.append(POLITE + " site %d" % i)
        elif i % 5 == 2:
            texts.append("var x = %d; // honest text %d" % (i, i))
        elif i % 5 == 3:
            texts.append(_p(GENERALIZATIONS[i % len(GENERALIZATIONS)][1]))
        else:
            texts.append("<p>honest paragraph number %d with words</p>" % i)
    t0 = time.time()
    for t in texts:
        dlp.find_credential(t)
    dt = time.time() - t0
    ok = dt < 120
    print(("HELD " if ok else "BREAK") + " test_perf_200_sites (%.2fs)" % dt)
    return ok


@_t
def test_green_w407():
    """Depth-1 green check on w407's attack battery. On this lane's
    tree, F1199-F1205 are CLOSED (their open pins must BREAK); all
    other pins (F1206-F1227) must HELD. Honor GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w407 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g408l1-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w407_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=900, cwd=os.path.join(REPO_ROOT, "evals"))
        held, broke = set(), set()
        for line in (r.stdout or "").split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("test_open_w407_f"):
                (held if parts[0] == "HELD" else broke).add(parts[1])
        expect_broke = {"test_open_w407_f%d" % n for n in range(1199, 1206)}
        expect_held = {"test_open_w407_f%d" % n for n in range(1206, 1228)}
        ok = (expect_broke <= broke and expect_held <= held
              and not (expect_held & broke) and not (expect_broke & held))
        print(("HELD " if ok else "BREAK") +
              " test_green_w407 (broke=%d held=%d)" % (len(broke), len(held)))
        if not ok:
            print("  broke: %s" % sorted(broke))
            print("  held: %s" % sorted(held))
        return ok
    except Exception as e:
        print("BREAK test_green_w407 (exec failed: %s)" % e)
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = []
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            if not fn():
                fails.append(fn.__name__)
        except Exception as e:
            print("BREAK " + fn.__name__ + " (exception: %s)" % e)
            fails.append(fn.__name__)
    print("%d/%d HELD" % (len(TESTS) - len(fails), len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
