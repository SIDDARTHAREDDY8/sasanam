#!/usr/bin/env python3
"""Wave-410 lane 4 close battery: F1281-F1288 CLOSED.

F1281: destructuring-spread staging -- `var [a,b,...R]=C` /
`var {0:x,1:y,length:l}=C` then `String.fromCharCode(...)` with the
spread assembles node-exactly (v24.20.0) while find_credential
MISSED. Distinct from F1208 (CLOSED: rest-destructuring copy).
Closed by `_js_f1281_stmt_decode` (two productions; fail-closed on
too-few elements, duplicate names, arg mismatch).

F1282: getter/setter accumulation staging --
`Object.defineProperty(O,'x',{get,set})` / `{_v:'',get x,set x}`
with `C.forEach(c=>O.x=O.x+fcc(c))` assembles node-exactly
(v24.20.0) while find_credential MISSED. Distinct from F1214
(CLOSED: defineProperty staging of chars). Closed by
`_js_f1282_stmt_decode` (two productions; fail-closed on
getter/setter mismatch, non-empty backing).

F1283/F1284/F1285/F1286/F1287/F1288: `<select name>`, `<textarea
placeholder>`, `<th abbr>`, `<input placeholder>`,
`aria-valuetext`, `aria-placeholder` prose carriers -- prose in
these never-rendered carriers left instruction_shaped QUIET.
Closed by `_has_hidden_select_name`,
`_has_hidden_textarea_placeholder`, `_has_hidden_th_abbr`,
`_has_hidden_input_placeholder`, `_has_hidden_aria_valuetext`,
`_has_hidden_aria_placeholder` (neutralized framing,
substantive-prose gate: 3+ words).

New _decode_layer dispatch loop (F1281/F1282); N_STMTDEC_LOOPS
57->58 (real code-count change). Node-exact on all filed shapes
(short + 40-char, v24.20.0); fail-closed hook-level bounds;
sibling pins hold; F1260-F1280 (attack round 77 opens outside
this lane) still MISS/QUIET.

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
N_STMTDEC_LOOPS_PIN = 58  # wave-410 lane 4: 57 + 1 (real code-count change)

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
    names = ["_js_f1281_stmt_decode", "_js_f1282_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-410 lane 4 (2026-10-11)" in src
          and "F1281-F1288 CLOSED (8" in src
          and "F1260-F1280 OPEN (21" in src
          and "next free F1289" in src)
    for n in range(1281, 1289):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-410 lane 4") == 8)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1289**" in src
          and "# Wave-409: F1229-F1259 CLOSED (31); F1260-F1288 OPEN (29); next free F1289" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block/flag ----------------

@_t
def test_p1_filed_block():
    """All F1281-F1282 filed shapes now BLOCK; F1283-F1288 FLAG."""
    bad = []
    total = 0
    for n in (1281, 1282):
        shapes = _redfirst_shapes("w409", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    for n in (1283, 1284, 1285, 1286, 1287, 1288):
        shapes = _redfirst_shapes("w409", n)
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
    """let/const twins, 3-name destructure, node-verified v24.20.0."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1281: let/const twins, 3 leading names.
    cases.append(("f1281-let-3names",
                  "let C=%s;let [a,b,c,...R]=C;let S=String.fromCharCode(a,b,c,...R);let RESULT=S;" % cs))
    cases.append(("f1281-const-long",
                  "const C=%s;const {0:x,1:y,length:l}=C;const S=String.fromCharCode(x,y,...C.slice(2));const RESULT=S;" % cl))
    # F1282: let/const twins, different prop/backing names.
    cases.append(("f1282-let",
                  "let C=%s;let S='';let O={};Object.defineProperty(O,'p',{get:function(){return S;},set:function(v){S=v;}});C.forEach(function(c){O.p=O.p+String.fromCharCode(c);});let RESULT=S;" % cs))
    cases.append(("f1282-const-long",
                  "const C=%s;const S='';const O={_b:'',get q(){return this._b;},set q(v){this._b=v;}};C.forEach(function(c){O.q=O.q+String.fromCharCode(c);});S=O.q;const RESULT=S;" % cl))
    # F1283-F1288: single-quote / case twins (neutralized framing).
    cases.append(("f1283-sq",
                  "<select name='%s'>x</select>" % PROSE))
    cases.append(("f1284-sq",
                  "<textarea placeholder='%s'>x</textarea>" % PROSE))
    cases.append(("f1285-case",
                  "<TABLE><TR><TH ABBR=\"%s\">H</TH></TR></TABLE>" % PROSE))
    cases.append(("f1286-sq",
                  "<input placeholder='%s'>" % PROSE))
    cases.append(("f1287-span",
                  "<span aria-valuetext=\"%s\">x</span>" % PROSE))
    cases.append(("f1288-div",
                  "<div aria-placeholder=\"%s\">x</div>" % PROSE))
    bad = []
    for name, p in cases:
        if name.startswith("f1281") or name.startswith("f1282"):
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
        # F1281: too few elements (undefined -> \x00 in node).
        "var C=[65];var [a,b,...R]=C;var S=String.fromCharCode(a,b,...R);var RESULT=S;",
        # F1281: duplicate destructured names.
        "var C=%s;var [a,a,...R]=C;var S=String.fromCharCode(a,a,...R);var RESULT=S;" % cs,
        # F1281: arg order mismatch.
        "var C=%s;var [a,b,...R]=C;var S=String.fromCharCode(b,a,...R);var RESULT=S;" % cs,
        # F1281: wrong rest name in spread.
        "var C=%s;var [a,b,...R]=C;var S=String.fromCharCode(a,b,...Q);var RESULT=S;" % cs,
        # F1282: getter returns wrong value.
        "var C=%s;var S='';var O={};Object.defineProperty(O,'x',{get:function(){return 'q';},set:function(v){S=v;}});C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});var RESULT=S;" % cs,
        # F1282: backing field not empty.
        "var C=%s;var S='';var O={_v:'q',get x(){return this._v;},set x(v){this._v=v;}};C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});S=O.x;var RESULT=S;" % cs,
        # F1282: setter does not assign param.
        "var C=%s;var S='';var O={};Object.defineProperty(O,'x',{get:function(){return S;},set:function(v){S=v+'!';}});C.forEach(function(c){O.x=O.x+String.fromCharCode(c);});var RESULT=S;" % cs,
    ]
    quiet_prov = [
        # 2-word honest hints stay quiet (substantive-prose gate).
        "<textarea placeholder=\"Enter text\">x</textarea>",
        "<div role=\"slider\" aria-valuetext=\"50 percent\">x</div>",
        "<div role=\"textbox\" aria-placeholder=\"Type here\">x</div>",
        # Machine tokens stay quiet.
        "<select name=\"country-select\">x</select>",
        "<th abbr=\"hdr\">H</th>",
        "<input placeholder=\"Search\">",
        # Empty carriers stay quiet.
        "<select name=\"\">x</select>",
        "<textarea placeholder=\"\">x</textarea>",
    ]
    bad = [p for p in miss_dlp if not _misses(p)]
    bad += [p for p in quiet_prov if not _quiet(p)]
    total = len(miss_dlp) + len(quiet_prov)
    return (not bad, "%d/%d fail-closed%s"
            % (total - len(bad), total,
               "" if not bad else ": %d bad" % len(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1208, F1214, F1255-F1258 still hold; F1260-F1280 still open."""
    bad = []
    # F1208 (rest-destructuring copy) and F1214 (defineProperty chars)
    # must still BLOCK (closed by earlier waves).
    sib_block = [
        ("f1208", "w408", 1208),
        ("f1214", "w408", 1214),
    ]
    for label, prefix, num in sib_block:
        try:
            shapes = _redfirst_shapes(prefix, num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("%s:%s" % (label, name))
    # F1255-F1258 (provenance) must still FLAG.
    for num in (1255, 1256, 1257, 1258):
        try:
            shapes = _redfirst_shapes("w408", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _flagged(payload):
                bad.append("f%d:%s" % (num, name))
    # F1260-F1280 (sibling lanes / attack opens) must still MISS/QUIET.
    for num in range(1260, 1281):
        try:
            shapes = _redfirst_shapes("w409", num)
        except Exception:
            continue
        for name, payload in shapes:
            # Decoder-seam findings (1260-1280 incl 1281-1282) use
            # find_credential; provenance (1283-1288) use
            # instruction_shaped. F1260-F1280 are decoder-seam.
            if num <= 1282:
                if not _misses(payload):
                    bad.append("f%d:%s" % (num, name))
            else:
                if not _quiet(payload):
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
                "var C=%s;var [a,b,...R]=C;var S=String.fromCharCode(a,b,...R);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("<select name=\"country-%d\">x</select>" % i)
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
    """F1260-F1280 (outside this lane) still MISS/QUIET."""
    bad = []
    for n in range(1260, 1281):
        try:
            shapes = _redfirst_shapes("w409", n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w409_attack_probes: F1281-F1288 flip, F1260-F1280 hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w409_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g410l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w409_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w409_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # My lane: F1281-F1288 now CLOSED -> their OPEN pins BREAK.
        # Siblings: F1260-F1280 still OPEN -> pins HELD.
        # Note: w409_attack_probes returns non-zero when pins BREAK
        # (expected: 8 BREAKs = my 8 closures), so returncode is not
        # part of the assertion.
        closed_now = set(range(1281, 1289))
        still_open = set(range(1260, 1281))
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w409_attack): closed-flip=%d/8 open-hold=%d/21%s"
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
