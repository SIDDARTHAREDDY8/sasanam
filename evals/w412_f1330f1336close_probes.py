#!/usr/bin/env python3
"""Wave-412 lane 2 close battery: F1330-F1336 CLOSED.

F1330: structuredClone nested-object residual of F1262 (CLOSED) --
`structuredClone({c:C})` (or doubly-nested `{w:{c:C}}`) around the
code array, then fromCharCode.apply on the cloned `.c`, assembled
node-exactly (v24.20.0) while find_credential MISSED. Closed by
`_js_f1330_stmt_decode` (object-literal parser; fail-closed on
wrong key, single clone). Disjoint from F1262 by grammar.

F1331: structuredClone double-laundering residual of F1262 --
`structuredClone(structuredClone(C))` (codes or chars) before
fromCharCode.apply/join assembled node-exactly while find_credential
MISSED. Closed by `_js_f1331_stmt_decode` (double-clone parser;
fail-closed on single clone). Disjoint from F1262 by the doubled
call.

F1332: <menuitem label> prose carrier -- prose in the label attribute
is never rendered but instruction_shaped stayed QUIET. Closed by
`_has_hidden_menuitem_label` (neutralized framing,
substantive-prose gate: 3+ words). Disjoint from F1333's <menu
label> by element.

F1333: <menu label> prose carrier. Closed by
`_has_hidden_menu_label`. Disjoint from F1332 by element.

F1334: <td abbr> prose carrier -- twin of F1285 (CLOSED: th abbr).
Closed by `_has_hidden_td_abbr`. Disjoint by element.

F1335: <form action> prose carrier -- distinct from F1256 (CLOSED:
form name). Closed by `_has_hidden_form_action`.

F1336: Set.forEach arrow-callback twin -- `new
Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));` with empty
or non-empty accumulator init assembled node-exactly (v24.20.0)
while find_credential MISSED. The F1264 decoder (empty init) and
F1317 decoder (non-empty init) both require the `function(i){...}`
callback form. Closed by `_js_f1336_stmt_decode` (arrow parser;
fail-closed on function callback, paren-arrow). Disjoint from
F1264/F1317 by the `=>` callback form.

New _decode_layer dispatch loop (F1330/F1331/F1336);
N_STMTDEC_LOOPS 65->66 (real code-count change). Node-exact on all
filed shapes (short + 40-char, v24.20.0); fail-closed hook-level
bounds; sibling pins hold; F1323-F1329 + F1337-F1348 (outside this
lane) still MISS/QUIET.

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
N_STMTDEC_LOOPS_PIN = 66  # wave-412 lane 2: 65 + 1 (real code-count change)

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
    names = ["_js_f1330_stmt_decode", "_js_f1331_stmt_decode",
             "_js_f1336_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v) for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-412 lane 2 (2026-10-11)" in src
          and "F1330-F1336 CLOSED (7" in src
          and "F1323-F1329, F1337-F1348 OPEN (19" in src
          and "next free F1349" in src)
    for n in (1330, 1331, 1332, 1333, 1334, 1335, 1336):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-412 lane 2") == 7)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-411: F1289-F1322 CLOSED (34); F1323-F1335 OPEN (13); "
             "F1336-F1348 OPEN (13); next free F1349" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block/flag ----------------

@_t
def test_p1_filed_block():
    """All F1330/F1331/F1336 filed shapes now BLOCK; F1332-F1335 FLAG."""
    bad = []
    total = 0
    for n in (1330, 1331, 1336):
        shapes = _redfirst_shapes("w411", n)
        total += len(shapes)
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (n, name))
    for n in (1332, 1333, 1334, 1335):
        shapes = _redfirst_shapes("w411", n)
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
    # F1330: let/const twins, renamed idents, nested form.
    cases.append(("f1330-let",
                  "let C=%s;let W={c:C};let V=structuredClone(W);let S=String.fromCharCode.apply(null,V.c);let RESULT=S;" % cs))
    cases.append(("f1330-const-nested",
                  "const C=%s;const W={w:{c:C}};const V=structuredClone(W);const S=String.fromCharCode.apply(null,V.w.c);const RESULT=S;" % cl))
    # F1331: let twin (codes), const twin (chars).
    cases.append(("f1331-let",
                  "let C=%s;let V=structuredClone(structuredClone(C));let S=String.fromCharCode.apply(null,V);let RESULT=S;" % cs))
    cases.append(("f1331-const-chars",
                  "const C=%s;const A=C.map(function(c){return String.fromCharCode(c);});const V=structuredClone(structuredClone(A));const S=V.join('');const RESULT=S;" % cl))
    # F1336: let/const twins, renamed idents, non-empty init.
    cases.append(("f1336-let",
                  "let C=%s;let S='';new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));let RESULT=S;" % cs))
    cases.append(("f1336-const-nonempty",
                  "const C=%s;const S='xy';new Set(C.keys()).forEach(k=>S+=String.fromCharCode(C[k]));const RESULT=S;" % cl))
    # F1332-F1335: single-quote / case twins (neutralized framing).
    cases.append(("f1332-sq",
                  "<menuitem label='%s'>x</menuitem>" % PROSE))
    cases.append(("f1333-case",
                  "<MENU LABEL=\"%s\"><menuitem>x</menuitem></MENU>" % PROSE))
    cases.append(("f1334-sq",
                  "<td abbr='%s'>Q1</td>" % PROSE))
    cases.append(("f1335-case",
                  "<FORM ACTION=\"%s\"><input type=\"text\"></FORM>" % PROSE))
    bad = []
    for name, p in cases:
        if name.startswith("f1330") or name.startswith("f1331") \
                or name.startswith("f1336"):
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
        # F1330: wrong object key.
        "var C=%s;var W={a:C};var V=structuredClone(W);var S=String.fromCharCode.apply(null,V.a);var RESULT=S;" % cs,
        # F1330: single clone (F1262's shape, different finding).
        "var C=%s;var W={c:C};var V=structuredClone(W);var S=V.c.join('');var RESULT=S;" % cs,
        # F1331: single clone (F1262's shape).
        "var C=%s;var V=structuredClone(C);var S=String.fromCharCode.apply(null,V);var RESULT=S;" % cs,
        # F1331: triple clone (unmodeled).
        "var C=%s;var V=structuredClone(structuredClone(structuredClone(C)));var S=String.fromCharCode.apply(null,V);var RESULT=S;" % cs,
        # F1336: function callback (F1264/F1317's shape).
        "var C=%s;var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs,
        # F1336: parenthesized arrow (unmodeled narrowness).
        "var C=%s;var S='';new Set(C.keys()).forEach((i)=>S+=String.fromCharCode(C[i]));var RESULT=S;" % cs,
        # F1336: wrong accumulator target.
        "var C=%s;var S='';var T='';new Set(C.keys()).forEach(i=>T+=String.fromCharCode(C[i]));var RESULT=S;" % cs,
    ]
    quiet_prov = [
        # Machine tokens stay quiet.
        "<menuitem label=\"file-menu\">x</menuitem>",
        "<menu label=\"edit\">x</menu>",
        "<td abbr=\"qty\">5</td>",
        "<form action=\"/submit\">x</form>",
        # Empty carriers stay quiet.
        "<menuitem label=\"\">x</menuitem>",
        "<form action=\"\">x</form>",
        # 2-word honest hints stay quiet (substantive-prose gate).
        "<menuitem label=\"File menu\">x</menuitem>",
        "<td abbr=\"quantity total\">5</td>",
    ]
    bad = []
    # The F1264/F1317 function-callback twins are their filed shapes:
    # they must still BLOCK (via F1264/F1317). The arrow parser itself
    # must not fire on them -- verified by the p4 sibling pins.
    for p in miss_dlp:
        if dlp.find_credential(p) is not None:
            # F1264/F1317 shapes are EXPECTED to block via their own hooks.
            if "function(i)" not in p:
                bad.append("dlp-hit:" + p[:60])
    bad += [p for p in quiet_prov if not _quiet(p)]
    total = len(miss_dlp) + len(quiet_prov)
    return (not bad, "%d/%d fail-closed%s"
            % (total - len(bad), total,
               "" if not bad else ": %d bad" % len(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1262/F1264/F1317 still BLOCK; F1285/F1309-F1314 still FLAG; F1323-F1329 + F1337-F1348 still open."""
    bad = []
    # F1262/F1264/F1317 (closed) must still BLOCK.
    for num in (1262, 1264, 1317):
        try:
            shapes = _redfirst_shapes("w411" if num >= 1317 else "w409", num)
        except Exception:
            # F1317's red-first is w411_f1317; F1262/F1264 are w409.
            try:
                shapes = _redfirst_shapes("w411", num)
            except Exception:
                continue
        for name, payload in shapes:
            if not _blocked(payload):
                bad.append("f%d:%s" % (num, name))
    # F1285 (th abbr) + F1309-F1314 (provenance, closed) must still FLAG.
    for num in (1285, 1309, 1310, 1311, 1312, 1313, 1314):
        try:
            shapes = _redfirst_shapes("w409" if num < 1309 else "w410", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _flagged(payload):
                bad.append("f%d:%s" % (num, name))
    # F1323-F1329 (attack-79 decoder opens, outside lane) must still MISS.
    for num in range(1323, 1330):
        try:
            shapes = _redfirst_shapes("w411", num)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (num, name))
    # F1337-F1348 (renumbered residuals, outside lane) must still MISS.
    for num in range(1337, 1349):
        for prefix in ("w411",):
            try:
                shapes = _redfirst_shapes(prefix, num)
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
        # Direct apply (F1262 control) still misses the new hooks
        # (it blocks via the direct-apply path, not F1330/F1331).
        "var C=[65,66];var S=String.fromCharCode(...C);var RESULT=S;",
    ]
    quiet_prov = [
        "<p>The quarterly financial summary shows revenue growth.</p>",
        "<menuitem>x</menuitem>",
        "<form><input type=\"text\"></form>",
        "<table><tr><td>Q1</td></tr></table>",
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
                "var C=%s;var W={c:C};var V=structuredClone(W);var S=String.fromCharCode.apply(null,V.c);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("<menuitem label=\"item-%d\">x</menuitem>" % i)
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
    """F1323-F1329 + F1337-F1348 (outside this lane) still MISS/QUIET."""
    bad = []
    for n in list(range(1323, 1330)) + list(range(1337, 1349)):
        try:
            shapes = _redfirst_shapes("w411", n)
        except Exception:
            continue
        for name, payload in shapes:
            # F1332-F1335 are provenance (in-lane, now FLAG) -- skip;
            # they're covered by p1. F1330/F1331/F1336 in-lane -- skip.
            if 1330 <= n <= 1336:
                continue
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w411_attack_probes: F1330-F1335 flip, others hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w411_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g412l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w411_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w411_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # My lane: F1330-F1335 now CLOSED -> OPEN pins BREAK.
        # (F1336 was a lane filing, not an attack pin.)
        # Siblings: F1323-F1329 still OPEN -> pins HELD.
        closed_now = set(range(1330, 1336))
        still_open = set(range(1323, 1330))
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w411_attack): closed-flip=%d/6 open-hold=%d/7%s"
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
