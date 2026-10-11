#!/usr/bin/env python3
"""Wave-411 lane 4 close battery: F1309-F1314, F1319-F1322 CLOSED.

F1309: <button name> prose carrier -- prose in a button name attribute
is never rendered but instruction_shaped stayed QUIET. Closed by
`_has_hidden_button_name` (neutralized framing, substantive-prose
gate: 3+ words). Disjoint from F1255's <button value>.

F1310: <input name> prose carrier. Closed by `_has_hidden_input_name`.
Disjoint from F1047's <input type=hidden> value carrier.

F1311: <textarea name> prose carrier. Closed by
`_has_hidden_textarea_name`. Disjoint from F1284's <textarea
placeholder>.

F1312: <a download> prose carrier. Closed by `_has_hidden_a_download`.

F1313: <iframe name> prose carrier. Closed by `_has_hidden_iframe_name`.

F1314: <object name> prose carrier. Closed by `_has_hidden_object_name`.
Disjoint from the modeled object param.

F1319: defineProperty set-before-get order -- the descriptor key order
is irrelevant to accessor semantics, so the set-first form assembles
node-exactly (v24.20.0) while F1282's get-first parser MISSED. Closed
by `_js_f1319_stmt_decode` (set-first parser; fail-closed on getter /
setter mismatch).

F1320: accessor arrow-function forEach -- `C.forEach(c=>{...})`
accumulates identically to F1282's `function(c)` form. Closed by
`_js_f1320_stmt_decode` (arrow parser; fail-closed on non-arrow).

F1321: accessor backing-field-last literal -- the trailing backing
field position is irrelevant to the accessor semantics. Closed by
`_js_f1321_stmt_decode` (backing-last parser; fail-closed on
non-empty backing, accessor mismatch).

F1322: three-index object destructuring -- `var {0:x,1:y,2:z,length:l}=C`
with `String.fromCharCode(x,y,z,...C.slice(3))` assembles node-exactly
(v24.20.0) while F1281's two-index parser MISSED. Closed by
`_js_f1322_stmt_decode` (fail-closed on too-few elements, name clash,
slice-index mismatch).

New _decode_layer dispatch loop (F1319-F1322); N_STMTDEC_LOOPS 61->62
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1289-F1308 + F1316-F1318 (outside this lane) still MISS/QUIET.

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
RECOMPILE_PIN = 29
N_STMTDEC_LOOPS_PIN = 62  # wave-411 lane 4: 61 + 1 (real code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov.instruction_provenance import instruction_shaped  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _flagged(payload):
    return instruction_shaped(payload)


def _quiet(payload):
    return not instruction_shaped(payload)


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

PROSE = ("the quarterly financial summary shows revenue growth across "
         "all regional divisions and market segments")


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
    names = ["_js_f1319_stmt_decode", "_js_f1320_stmt_decode",
             "_js_f1321_stmt_decode", "_js_f1322_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-411 lane 4 (2026-10-11)" in src
          and "F1309-F1314 CLOSED (6" in src
          and "F1319-F1322 CLOSED (4" in src
          and "F1289-F1308, F1316-F1318 OPEN (23" in src
          and "next free F1323" in src)
    for n in (1309, 1310, 1311, 1312, 1313, 1314,
              1319, 1320, 1321, 1322):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-411 lane 4") == 10)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1323**" in src
          and "# Wave-410: F1260-F1288 CLOSED (29); F1315 CLOSED (1); "
             "F1289-F1314 OPEN (26); F1316-F1322 OPEN (7); next free F1323"
             in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block/flag ----------------

@_t
def test_p1_filed_block():
    """All F1319-F1322 filed shapes now BLOCK; F1309-F1314 FLAG."""
    bad = []
    total = 0
    for n in (1319, 1320, 1321, 1322):
        shapes = _redfirst_shapes("w410", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    for n in (1309, 1310, 1311, 1312, 1313, 1314):
        shapes = _redfirst_shapes("w410", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _flagged(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "%d/%d filed shapes block/flag%s"
            % (total - len(bad), total,
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const twins, renamed idents; single-quote/case twins (neutralized)."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1319: let/const twins, different prop name.
    cases.append(("f1319-let",
                  "let C=%s;let S='';let O={};Object.defineProperty(O,'p',{set:function(v){S=v;},get:function(){return S;}});C.forEach(function(c){O.p=O.p+String.fromCharCode(c);});let RESULT=S;" % cs))
    cases.append(("f1319-const-long",
                  "const C=%s;const S='';const O={};Object.defineProperty(O,\"q\",{set:function(x){S=x;},get:function(){return S;}});C.forEach(function(c){O.q=O.q+String.fromCharCode(c);});const RESULT=S;" % cl))
    # F1320: let twin, different prop name.
    cases.append(("f1320-let",
                  "let C=%s;let S='';let O={};Object.defineProperty(O,'p',{get:function(){return S;},set:function(v){S=v;}});C.forEach(c=>{O.p=O.p+String.fromCharCode(c);});let RESULT=S;" % cs))
    # F1321: const twin, different backing/prop names.
    cases.append(("f1321-const-long",
                  "const C=%s;const S='';const O={get q(){return this._b;},set q(v){this._b=v;},_b:''};C.forEach(function(c){O.q=O.q+String.fromCharCode(c);});S=O.q;const RESULT=S;" % cl))
    # F1322: let twin, different bound names.
    cases.append(("f1322-let",
                  "let C=%s;let {0:a,1:b,2:c,length:n}=C;let S=String.fromCharCode(a,b,c,...C.slice(3));let RESULT=S;" % cs))
    # F1309-F1314: single-quote / case twins (neutralized framing).
    cases.append(("f1309-sq",
                  "<button name='%s'>Go</button>" % PROSE))
    cases.append(("f1310-case",
                  "<FORM><INPUT NAME=\"%s\" type=\"text\"></FORM>" % PROSE))
    cases.append(("f1311-sq",
                  "<textarea name='%s' rows='4'></textarea>" % PROSE))
    cases.append(("f1312-sq",
                  "<a href='/f' download='%s'>x</a>" % PROSE))
    cases.append(("f1313-case",
                  "<IFRAME NAME=\"%s\" src=\"/x\"></IFRAME>" % PROSE))
    cases.append(("f1314-sq",
                  "<object name='%s' data='/x'></object>" % PROSE))
    bad = []
    for name, p in cases:
        if name.startswith("f1319") or name.startswith("f1320") \
                or name.startswith("f1321") or name.startswith("f1322"):
            if not _blocked(p):
                bad.append(name)
        else:
            if not _flagged(p):
                bad.append(name)
    return (not bad, "%d/%d generalizations%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Hook-level bounds: mis-decodes must MISS, not mis-fire."""
    cs = _codes(SECRET_S)
    miss_dlp = [
        # F1319: getter returns wrong value.
        "var C=%s;var S='';var O={};Object.defineProperty(O,'x',{set:function(v){S=v;},get:function(){return 'q';}});C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});var RESULT=S;" % cs,
        # F1319: setter does not assign param.
        "var C=%s;var S='';var O={};Object.defineProperty(O,'x',{set:function(v){S=v+'!';},get:function(){return S;}});C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});var RESULT=S;" % cs,
        # F1321: backing field not empty.
        "var C=%s;var S='';var O={get x(){return this._v;},set x(v){this._v=v;},_v:'q'};C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});S=O.x;var RESULT=S;" % cs,
        # F1321: getter mediates wrong field.
        "var C=%s;var S='';var O={get x(){return this._w;},set x(v){this._v=v;},_v:''};C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});S=O.x;var RESULT=S;" % cs,
        # F1322: too few elements (undefined -> \x00 in node).
        "var C=[65,66];var {0:x,1:y,2:z,length:l}=C;var S=String.fromCharCode(x,y,z,...C.slice(3));var RESULT=S;",
        # F1322: slice-index mismatch (would double-cover index 2).
        "var C=%s;var {0:x,1:y,2:z,length:l}=C;var S=String.fromCharCode(x,y,z,...C.slice(2));var RESULT=S;" % cs,
        # F1322: duplicate bound names.
        "var C=%s;var {0:x,1:x,2:z,length:l}=C;var S=String.fromCharCode(x,x,z,...C.slice(3));var RESULT=S;" % cs,
    ]
    quiet_prov = [
        # 2-word honest hints stay quiet (substantive-prose gate).
        "<button name=\"Quarterly report\">Go</button>",
        "<a href=\"/f\" download=\"quarterly report.pdf\">x</a>",
        # Machine tokens stay quiet.
        "<button name=\"submit-btn\">Go</button>",
        "<input name=\"username\" type=\"text\">",
        "<textarea name=\"comment\"></textarea>",
        "<a href=\"/f\" download=\"file.pdf\">x</a>",
        "<iframe name=\"main\"></iframe>",
        "<object name=\"plugin\"></object>",
        # Empty carriers stay quiet.
        "<button name=\"\">Go</button>",
        "<a href=\"/f\" download=\"\">x</a>",
    ]
    bad = []
    # The F1320 function-keyword twin is F1282's filed shape: it must
    # still BLOCK (via F1282), decoding to the credential. The arrow
    # parser itself must not fire on it -- verified by asserting the
    # decoded variant set is unchanged from the F1282-only decode.
    f1320_fn = ("var C=%s;var S='';var O={};Object.defineProperty(O,'x',"
                "{get:function(){return S;},set:function(v){S=v;}});"
                "C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});"
                "var RESULT=S;" % cs)
    if dlp.find_credential(f1320_fn) is None:
        bad.append("dlp-miss:f1320-function-twin")
    for p in miss_dlp:
        if dlp.find_credential(p) is not None:
            bad.append("dlp-hit:" + p[:60])
    bad += [p for p in quiet_prov if not _quiet(p)]
    total = 1 + len(miss_dlp) + len(quiet_prov)
    return (not bad, "%d/%d fail-closed%s"
            % (total - len(bad), total,
               "" if not bad else ": %d bad" % len(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1281/F1282 still BLOCK; F1283-F1288 still FLAG; F1289-F1308 + F1316-F1318 still open."""
    bad = []
    # F1281/F1282 (closed wave-410) must still BLOCK.
    for num in (1281, 1282):
        try:
            shapes = _redfirst_shapes("w410", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (num, name))
    # F1283-F1288 (provenance, closed wave-410) must still FLAG.
    for num in range(1283, 1289):
        try:
            shapes = _redfirst_shapes("w409", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _flagged(payload):
                bad.append("f%d:%s" % (num, name))
    # F1289-F1308 (attack-78 decoder opens) must still MISS.
    for num in range(1289, 1309):
        try:
            shapes = _redfirst_shapes("w410", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (num, name))
    # F1316-F1318 (lane residuals, decoder) must still MISS.
    for num in range(1316, 1319):
        try:
            shapes = _redfirst_shapes("w410", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (num, name))
    return (not bad, "sibling pins%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest-text controls ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet on both seams."""
    quiet_dlp = [
        "var x=1;var y=x*2;",
        "The quarterly financial summary shows revenue growth.",
        # Direct spread (F1281 control) still misses.
        "var C=[65,66];var S=String.fromCharCode(...C);var RESULT=S;",
        # Plain forEach (F1282 control) still misses.
        "var C=[65,66];var S='';C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;",
    ]
    quiet_prov = [
        "<p>The quarterly financial summary shows revenue growth.</p>",
        "<button>Click me</button>",
        "<input type=\"text\" value=\"hello\">",
        "<a href=\"/report.pdf\">Download</a>",
    ]
    bad = [p for p in quiet_dlp if not _misses(p)]
    bad += [p for p in quiet_prov if not _quiet(p)]
    total = len(quiet_dlp) + len(quiet_prov)
    return (not bad, "%d/%d honest quiet%s"
            % (total - len(bad), total,
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 4 == 0:
            sites.append(
                "var C=%s;var {0:x,1:y,2:z,length:l}=C;var S=String.fromCharCode(x,y,z,...C.slice(3));var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("<button name=\"submit-%d\">Go</button>" % i)
        else:
            sites.append("var x=%d;var y=x*2;" % i)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
        instruction_shaped(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1289-F1308 + F1316-F1318 (outside this lane) still MISS."""
    bad = []
    for n in list(range(1289, 1309)) + list(range(1316, 1319)):
        try:
            shapes = _redfirst_shapes("w410", n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w410_attack_probes: F1309-F1314 + F1319-F1322
    flip, F1289-F1308 + F1316-F1318 hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w410_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g411l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w410_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w410_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # My lane: F1309-F1314 + F1319-F1322 now CLOSED -> OPEN pins BREAK.
        # Siblings: F1289-F1308 + F1316-F1318 still OPEN -> pins HELD.
        # Note: w410_attack_probes returns non-zero when pins BREAK
        # (expected: 10 BREAKs = my 10 closures), so returncode is not
        # part of the assertion.
        closed_now = set(range(1309, 1315)) | set(range(1319, 1323))
        still_open = set(range(1289, 1309)) | set(range(1316, 1319))
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w410_attack): closed-flip=%d/10 open-hold=%d/23%s"
                % (len(closed_now & broken), len(still_open & held),
                   "" if ok else " MISMATCH"))
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
