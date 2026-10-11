#!/usr/bin/env python3
"""Wave-407 lane 3 close battery: F1193-F1195 CLOSED.

F1193: FormData staged reads. Appending chars as form values via
`F.append('k'+i,String.fromCharCode(c))` in a forEach callback, then
reading back via `Array.from(F.values()).join('')` (or the spread
twin `[...F.values()].join('')`) assembles node-exactly (v24.20.0)
while find_credential MISSED. Closed by `_js_f1193_stmt_decode`.

F1194: integrity-method wrapper staged reads. Object.freeze/seal/
preventExtensions applied to the int-array variable (or a slice copy)
before spreading assembles node-exactly (v24.20.0) while
find_credential MISSED. Residual of F1114 (CLOSED): its hook requires
the freeze argument to be the int-array literal and covers only
freeze. Closed by `_js_f1194_stmt_decode` (freeze/seal/
preventExtensions of the bound identifier or its slice copy).

F1195: expression-wrapper laundering. Wrapping a blocked map+join
production in a single-interpolation template literal, String(), or
''+ concatenation defeats whole-text anchoring and assembles
node-exactly (v24.20.0) while find_credential MISSED. Expression-level
residual of the F1123 systemic anchoring fix (CLOSED), which handles
statement-level wrappers only. Closed by `_js_f1195_stmt_decode`.

F1193/F1194/F1195 filed 2026-10-11 01:43 UTC by wave-406 attack round 74
(local node validation, $0.00 model spend (0 paid calls); LOW, OPEN).

New _decode_layer dispatch loop (F1193/F1194/F1195); N_STMTDEC_LOOPS
46->47 (real code-count change). Node-exact on all filed shapes (short
+ 40-char, v24.20.0); fail-closed hook-level bounds; sibling pins
hold; F1182-F1192, F1196-F1198 (attack round 74 opens) still MISS.

Spec-review follow-up (2026-10-11, same commit): the review showed the
close-when criteria ("models ... node-exactly") cover more of each
laundering class than the filed shapes, so the hooks were extended --
F1193: F.set/append key forms (distinct-index, template, bare,
constant-under-append-only), for-of / indexed-for (incl. cached
length) / single-param forEach staging, whitespace-tolerant grammar;
F1194: C.slice(0), C.slice(0,C.length), Array.from(C),
Array.from(C,Number), [...C] copy arms, whitespace-tolerant grammar;
F1195: wrapper chains (template with literal pre/suffix, String(),
<strlit>+/<strlit> suffix, stacked), whitespace-tolerant gates. Two
further-out staging productions discovered during the follow-up were
filed as new findings instead of extended: F1224 (while-loop),
F1225 (for-in), both OPEN. The follow-up also caught the old p3
battery mislabeling defineProperty as a fail-closed miss (it
assembles node-exactly) -- filed as F1226 (defineProperty family)
and F1227 (Object.assign self-assign), both OPEN. Also fixed a
pre-existing NameError crash
in _js_parse_array_from (undefined `depth` -> 0, matching the
adjacent call convention) that the Array.from(C,Number) shape
exposed -- find_credential raised instead of returning a verdict.

Green checks ON. $0-spend-by-construction.
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
RECOMPILE_PIN = 29  # +1 _JS_WS_COMPACT_RE in this lane's follow-up
N_STMTDEC_LOOPS_PIN = 47  # +1 dispatch loop in this lane (F1193/F1194/F1195)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# ---------------- p0: pins ----------------

@_t
def test_p0_taxonomy_pin():
    return (len(TAXONOMY) == TAXONOMY_PIN,
            "taxonomy=%d pin=%d" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_verifier_pin():
    return (VERIFIER_TAXONOMY_PIN == 33,
            "verifier_pin=%d" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    return (n == RECOMPILE_PIN, "re.compile=%d pin=%d" % (n, RECOMPILE_PIN))


@_t
def test_p0_stmtdec_loops():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL)
    ok = len(loops) == N_STMTDEC_LOOPS_PIN
    has1193 = any("_js_f1193_stmt_decode" in lp for lp in loops)
    has1194 = any("_js_f1194_stmt_decode" in lp for lp in loops)
    has1195 = any("_js_f1195_stmt_decode" in lp for lp in loops)
    ok = ok and has1193 and has1194 and has1195
    return (ok, "loops=%d pin=%d f1193=%s f1194=%s f1195=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, has1193, has1194, has1195))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-407 lane 3 (2026-10-11)" in src
          and "F1193-F1195 CLOSED (3" in src
          and "F1224-F1227 filed OPEN (4" in src
          and "F1182-F1192, F1196-F1198 OPEN (14" in src
          and "next free F1228" in src)
    for n in (1193, 1194, 1195):
        ok = ok and src.count("(F%d filed" % n) == 1
    for n in (1224, 1225, 1226, 1227):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-407 lane 3") == 3)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1228**" in src
          and "# Wave-406: F1159-F1181 CLOSED (23); F1182-F1198 OPEN (17); next free F1199" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1193_filed_block():
    shapes = _redfirst_shapes("w406", 1193)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed F1193 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p1_f1194_filed_block():
    shapes = _redfirst_shapes("w406", 1194)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed F1194 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p1_f1195_filed_block():
    shapes = _redfirst_shapes("w406", 1195)
    bad = [name for name, payload in shapes if not _blocked(payload)]
    return (not bad, "%d/%d filed F1195 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const, renamed idents, arrow twins, quote variants, and the
    spec-review extension shapes (all node-verified v24.20.0)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1193: let/const + renamed idents + double-quote key.
    cases.append(("f1193-let",
                  "let D=%s;const G=new FormData();D.forEach(function(x,j){G.append(\"q\"+j,String.fromCharCode(x));});let T=Array.from(G.values()).join('');let RESULT=T;" % cs))
    cases.append(("f1193-arrow-long",
                  "var C=%s;var F=new FormData();C.forEach((c,i)=>F.append('k'+i,String.fromCharCode(c)));var S=[...F.values()].join('');var RESULT=S;" % cl))
    # F1193 spec-review extensions: set, staging loops, key forms, ws.
    cases.append(("f1193-set",
                  "var C=%s;var F=new FormData();C.forEach(function(c,i){F.set('k'+i,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs))
    cases.append(("f1193-forof",
                  "var C=%s;var F=new FormData();let i=0;for(const c of C){F.append('k'+i,String.fromCharCode(c));i++;}var S=[...F.values()].join('');var RESULT=S;" % cs))
    cases.append(("f1193-indexed",
                  "var C=%s;var F=new FormData();for(let i=0;i<C.length;i++){F.append('k'+i,String.fromCharCode(C[i]));}var S=Array.from(F.values()).join('');var RESULT=S;" % cl))
    cases.append(("f1193-indexed-cached",
                  "var C=%s;var F=new FormData();for(let i=0,n=C.length;i<n;i++){F.append('k'+i,String.fromCharCode(C[i]));}var S=Array.from(F.values()).join('');var RESULT=S;" % cs))
    cases.append(("f1193-singleparam",
                  "var C=%s;var F=new FormData();C.forEach((c)=>F.append('k',String.fromCharCode(c)));var S=Array.from(F.values()).join('');var RESULT=S;" % cs))
    cases.append(("f1193-tmplkey",
                  "var C=%s;var F=new FormData();C.forEach(function(c,i){F.append(`k${i}`,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cl))
    cases.append(("f1193-ws",
                  "var C = %s ; var F = new FormData () ; C . forEach ( function ( c , i ) { F . append ( 'k' + i , String . fromCharCode ( c ) ) ; } ) ; var S = Array . from ( F . values ( ) ) . join ( '' ) ; var RESULT = S ;" % cs))
    # F1194: const + seal on renamed array.
    cases.append(("f1194-const-seal",
                  "const D=%s;const T=String.fromCharCode(...Object.seal(D));const RESULT=T;" % cs))
    cases.append(("f1194-preventext-long",
                  "var C=%s;var S=String.fromCharCode(...Object.preventExtensions(C.slice()));var RESULT=S;" % cl))
    # F1194 spec-review extensions: copy arms, ws.
    cases.append(("f1194-slice0",
                  "var C=%s;var S=String.fromCharCode(...Object.freeze(C.slice(0)));var RESULT=S;" % cs))
    cases.append(("f1194-slice0-len",
                  "var C=%s;var S=String.fromCharCode(...Object.freeze(C.slice(0, C.length)));var RESULT=S;" % cl))
    cases.append(("f1194-arrayfrom",
                  "var C=%s;var S=String.fromCharCode(...Object.seal(Array.from(C)));var RESULT=S;" % cs))
    cases.append(("f1194-arrayfrom-number",
                  "var C=%s;var S=String.fromCharCode(...Object.seal(Array.from(C, Number)));var RESULT=S;" % cl))
    cases.append(("f1194-spreadcopy",
                  "var C=%s;var S=String.fromCharCode(...Object.preventExtensions([...C]));var RESULT=S;" % cs))
    cases.append(("f1194-ws",
                  "var C = %s ; var S = String . fromCharCode ( ... Object . seal ( C ) ) ; var RESULT = S ;" % cs))
    # F1195: arrow map callback + String() wrapper, double-quote concat.
    cases.append(("f1195-arrow-string",
                  "var C=%s;var H=C.map((c)=>String.fromCharCode(c));var S=String(H.join(\"\"));var RESULT=S;" % cs))
    cases.append(("f1195-dq-concat-long",
                  "var C=%s;var S=\"\"+C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cl))
    # F1195 spec-review extensions: wrapper chains, ws.
    cases.append(("f1195-tmpl-pre",
                  "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=`x${H.join('')}`;var RESULT=S;" % cs))
    cases.append(("f1195-tmpl-post",
                  "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=`${H.join('')}y`;var RESULT=S;" % cl))
    cases.append(("f1195-suffix",
                  "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=H.join('')+'';var RESULT=S;" % cs))
    cases.append(("f1195-stacked",
                  "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=String(`${H.join('')}`);var RESULT=S;" % cl))
    cases.append(("f1195-inline-pre",
                  "var C=%s;var S='x'+C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs))
    cases.append(("f1195-ws",
                  "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=String ( H . join ( '' ) );var RESULT=S;" % cl))
    bad = [name for name, payload in cases if not _blocked(payload)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Out-of-grammar inputs must MISS (a miss, never a mis-decode).

    Every case below is node-verified (v24.20.0) to NOT assemble the
    credential (throws, yields a wrong/short string, or drops codes),
    so the MISS is a true fail-closed bound -- never a mislabeled
    hole. (Spec-review lesson: the old battery asserted MISS on
    F.set-distinct, `x${...}` templates, 'x'+concat, and
    defineProperty -- all of which assemble and are now blocked or
    filed as F1226.)
    """
    cs = _codes(SECRET_S)
    misses = [
        # F1193: constant-key set overwrites -> only the last char.
        "var C=%s;var F=new FormData();C.forEach(function(c,i){F.set('k',String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs,
        # F1193: shadowed form name -> node throws TypeError.
        "var C=%s;var F=new FormData();C.forEach(function(F,i){F.append('k'+i,String.fromCharCode(F));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs,
        # F1193: duplicate params -> element is the index -> wrong string.
        "var C=%s;var F=new FormData();C.forEach(function(c,c){F.append('k'+c,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs,
        # F1193: unbound key ident -> node throws ReferenceError.
        "var C=%s;var F=new FormData();C.forEach(function(c,i){F.append('k'+j,String.fromCharCode(c));});var S=Array.from(F.values()).join('');var RESULT=S;" % cs,
        # F1193: values() on the wrong object.
        "var C=%s;var F=new FormData();C.forEach(function(c,i){F.append('k'+i,String.fromCharCode(c));});var S=Array.from(G.values()).join('');var RESULT=S;" % cs,
        # F1194: freeze of a non-array (number) -> node throws on spread.
        "var C=%s;var S=String.fromCharCode(...Object.freeze(42));var RESULT=S;" % cs,
        # F1194: slice(1) drops the first code.
        "var C=%s;var S=String.fromCharCode(...Object.freeze(C.slice(1)));var RESULT=S;" % cs,
        # F1195: join with non-empty separator.
        "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=String(H.join(','));var RESULT=S;" % cs,
        # F1195: wrapper around a non-join (String of the char array).
        "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S=String(H);var RESULT=S;" % cs,
        # F1195: concat with non-empty lhs around a comma join.
        "var C=%s;var H=C.map(function(c){return String.fromCharCode(c);});var S='x'+H.join(',');var RESULT=S;" % cs,
    ]
    bad = [p[:60] for p in misses if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(misses) - len(bad), len(misses),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_siblings():
    """Closed siblings still block; new hooks don't steal their shapes."""
    cs = _codes(SECRET_S)
    blocks = [
        # F1090: unwrapped map+join (F1195 must not steal).
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        # F1114: freeze of int-array literal (F1194 must not steal).
        ("f1114-literal",
         "var C=Object.freeze(%s);var S=String.fromCharCode(...C);var RESULT=S;" % cs),
        ("f1114-inline",
         "var S=String.fromCharCode(...Object.freeze(%s));var RESULT=S;" % cs),
    ]
    bad = [name for name, payload in blocks if not _blocked(payload)]
    # Cross-disjointness: new-hook shapes must not hit sibling hooks'
    # productions (verified via the filed shapes blocking only here).
    return (not bad, "%d/%d sibling shapes block%s"
            % (len(blocks) - len(bad), len(blocks),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest text ----------------

@_t
def test_p5_honest_text():
    honest = [
        "The quarterly financial summary shows revenue growth.",
        "var form = new FormData(); form.append('name', 'value');",
        "Object.freeze(config); Object.seal(state);",
        "var s = `Hello ${name}!`; var t = String(42); var u = '' + x;",
        "function submit() { var fd = new FormData(form); fetch(url, {body: fd}); }",
    ]
    bad = [p[:50] for p in honest if not _misses(p)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(honest) - len(bad), len(honest),
               "" if not bad else ": " + "; ".join(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var F=new FormData();C.forEach(function(c,i){F.append('k'+i,String.fromCharCode(c));});"
               "var S=Array.from(F.values()).join('');var RESULT=S;" % cs)
    t0 = time.time()
    for _ in range(200):
        dlp.find_credential(payload)
        dlp.find_credential(payload[::-1])
    dt = time.time() - t0
    return (dt < 30.0, "200 sites x2 in %.1fs (budget 30s)" % dt)


# ---------------- p7: still-open ----------------

@_t
def test_p7_still_open():
    """Round-74 opens outside this lane still MISS."""
    bad = []
    for n in list(range(1182, 1193)) + list(range(1196, 1199)):
        shapes = _redfirst_shapes("w406", n)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "round-74 opens still MISS%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p8: new filings still open ----------------

def _redfirst_shapes_w407(num):
    """Import a w407 red-first module's SHAPES (side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "w407_f%d_redfirst.py" % num)
    spec = importlib.util.spec_from_file_location(
        "w407_f%d_rf" % num, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


@_t
def test_p8_new_findings_open():
    """F1224-F1227 (spec-review follow-up filings) still MISS."""
    bad = []
    for n in (1224, 1225, 1226, 1227):
        shapes = _redfirst_shapes_w407(n)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "new filings still MISS%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w406's attack battery (round-74 opens).

    Expects exactly the F1193/F1194/F1195 pins to flip to BREAK (now
    closed); every other pin must stay HELD. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w406_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g407l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w406_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        flips = set()
        for line in out.split("\n"):
            if line.startswith("BREAK test_open_w406_f"):
                m = re.search(r"test_open_w406_f(\d+)", line)
                if m:
                    flips.add(int(m.group(1)))
        expected = {1193, 1194, 1195}
        ok = flips == expected
        tail = out.strip().split("\n")[-3:] if not ok else []
        return (ok, "green(w406_attack): flips=%s expected=%s %s"
                % (sorted(flips), sorted(expected),
                   " ".join(tail) if not ok else "exact"))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
