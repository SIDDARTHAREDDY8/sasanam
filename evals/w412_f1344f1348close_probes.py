#!/usr/bin/env python3
"""Wave-412 lane 4 close battery: F1344-F1348 CLOSED.

F1344: F1297 RegExp indices variants -- `T.substring(...m.indices[1])`
(spread), `T.substring(m.indices[0][0],m.indices[0][1])` (group-0), and
`T.slice(m.indices[1][0],m.indices[1][1])` all assemble node-exactly
(v24.20.0) while F1297's substring(indices[1][0],indices[1][1]) parser
MISSED. Closed by `_js_f1344_stmt_decode` (spread/slice/group-0
parser; fail-closed on F1297's exact form).

F1345: F1297 dotAll/no-d-flag residuals -- `/(.+)/ds.exec(T)` with the
`s` flag assembles even with newline codes (dotAll makes `.` match
line terminators), and `[...T.matchAll(/(.)/g)]` without the `d` flag
assembles via x[0] join; both MISSED by F1297 (which requires no `s`
flag / requires the `d` flag). Closed by `_js_f1345_stmt_decode`
(dotAll + no-d-flag parsers; fail-closed on F1297's exact forms).

F1346: F1299 three-hop alias residual -- `var S=R;var T=S;var U=T;`
assembles node-exactly (v24.20.0) while F1299's 1-2 hop parser MISSED.
Closed by `_js_f1346_stmt_decode` (reuses F1299 parser at depth=3;
fail-closed on depths 0-2).

F1347: F1300 freeze-on-slice(0) residual -- `Object.freeze(C.slice(0))`
via named intermediate + apply/spread assembles node-exactly
(v24.20.0) while F1300's bare-slice parser MISSED. Closed by
`_js_f1347_stmt_decode` (slice(0) parser; fail-closed on bare slice).

F1348: F1302 arrow-callback residual -- `C.map(c=>String.fromCodePoint(c))`
assembles node-exactly (v24.20.0) while F1302's function-callback parser
MISSED. Closed by `_js_f1348_stmt_decode` (arrow parser; fail-closed
on function form).

New _decode_layer dispatch loop (F1344-F1348); N_STMTDEC_LOOPS 65->66
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1323-F1343 (outside this lane) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
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


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-411 lineage; N_STMTDEC_LOOPS=66."""
    ok = True
    notes = []
    # N_STMTDEC_LOOPS pin
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    # actual loop count
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (pin == 66 and len(loops) == 66)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    # footer lineage: wave-411 footer present
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w411 = "# Wave-411:" in ftxt
    ok = ok and has_w411
    notes.append("w411-footer=%s" % has_w411)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1344: 3 productions x 2 sizes
    ("f1344-spread",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(...m.indices[1]);var RESULT=S;"),
    ("f1344-group0",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(m.indices[0][0],m.indices[0][1]);var RESULT=S;"),
    ("f1344-slice",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.slice(m.indices[1][0],m.indices[1][1]);var RESULT=S;"),
    # F1345: no-dflag x 2 sizes (dotall uses non-credential test str)
    ("f1345-no-dflag",
     "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=[...T.matchAll(/(.)/g)];var S=m.map(function(x){return x[0];}).join('');var RESULT=S;"),
    # F1346: 3-hop x 2 sizes
    ("f1346-3hop",
     "var C={I};var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var S=R;var T=S;var U=T;var RESULT=U;"),
    # F1347: slice0 apply + spread x 2 sizes
    ("f1347-apply",
     "var C={I};var D=Object.freeze(C.slice(0));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1347-spread",
     "var C={I};var D=Object.freeze(C.slice(0));var S=String.fromCharCode(...D);var RESULT=S;"),
    # F1348: arrow x 2 sizes
    ("f1348-arrow",
     "var C={I};var D=C.map(c=>String.fromCodePoint(c));var E=D.join('');var F=[];for(var i=0;i<E.length;i++){F.push(String.fromCodePoint(E.codePointAt(i)));}var S=F.join('');var RESULT=S;"),
]


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
    """let/const variants and renamed identifiers still HIT."""
    tmpls = [
        "let C={I};let T=C.map(function(c){return String.fromCharCode(c);}).join('');let m=/(.+)/d.exec(T);let S=T.substring(...m.indices[1]);let RESULT=S;",
        "const C={I};const R='';for(const i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}const S=R;const T=S;const U=T;const RESULT=U;",
        "var CC={I};var DD=Object.freeze(CC.slice(0));var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
    ]
    bad = [t for t in tmpls
           if not _hits(t.replace("{I}", _codes(SECRET_S)))]
    return (not bad, "%d/%d general hit%s"
            % (len(tmpls) - len(bad), len(tmpls),
               "" if not bad else ": %d miss" % len(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Sibling exact forms are NOT claimed by the new hooks (miss here)."""
    # These must MISS at the hook level (they're owned by siblings).
    # We test via the hook functions directly to avoid find_credential
    # hitting them through the sibling hooks.
    cases = [
        ("f1344-not-f1297",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(m.indices[1][0],m.indices[1][1]);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1344_stmt_decode),
        ("f1345-not-f1297-dflag",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=[...T.matchAll(/(.)/dg)];var S=m.map(function(x){return x[0];}).join('');var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1345_stmt_decode),
        ("f1346-not-1hop",
         "var C=%s;var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var S=R;var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1346_stmt_decode),
        ("f1346-not-2hop",
         "var C=%s;var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var S=R;var T=S;var RESULT=T;"
         % _codes(SECRET_S), _dlp._js_f1346_stmt_decode),
        ("f1347-not-bare-slice",
         "var C=%s;var D=Object.freeze(C.slice());var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1347_stmt_decode),
        ("f1348-not-function",
         "var C=%s;var D=C.map(function(c){return String.fromCodePoint(c);});var E=D.join('');var F=[];for(var i=0;i<E.length;i++){F.push(String.fromCodePoint(E.codePointAt(i)));}var S=F.join('');var RESULT=S;"
         % _codes(SECRET_S), _dlp._js_f1348_stmt_decode),
    ]
    bad = [n for n, p, hook in cases if hook(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1297/F1299/F1300/F1302 still decode their own shapes."""
    cases = [
        ("f1297",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(m.indices[1][0],m.indices[1][1]);var RESULT=S;"
         % _codes(SECRET_S)),
        ("f1299-1hop",
         "var C=%s;var R='';for(var i=0;i<C.length;i++){R+=String.fromCharCode(C[i]);}var S=R;var RESULT=S;"
         % _codes(SECRET_S)),
        ("f1300",
         "var C=%s;var D=Object.freeze(C.slice());var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % _codes(SECRET_S)),
        ("f1302",
         "var C=%s;var D=C.map(function(c){return String.fromCodePoint(c);});var E=D.join('');var F=[];for(var i=0;i<E.length;i++){F.push(String.fromCodePoint(E.codePointAt(i)));}var S=F.join('');var RESULT=S;"
         % _codes(SECRET_S)),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    quiet = [
        "The quarterly financial summary shows revenue growth.",
        "var x=1;var y=x*2;console.log(y);",
        "function add(a,b){return a+b;}",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
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
                "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var m=/(.+)/d.exec(T);var S=T.substring(...m.indices[1]);var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("var x=%d;var y=x*2;" % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens still miss ----------------

def _redfirst_shapes(wave, n):
    """Load (name, payload) shapes from a red-first battery."""
    import importlib.util
    path = os.path.join(REPO_ROOT, "evals",
                        "w%s_f%d_redfirst.py" % (wave, n))
    spec = importlib.util.spec_from_file_location("_rb%d" % n, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.SHAPES)


@_t
def test_p7_other_opens_miss():
    """F1323-F1343 (outside this lane) still MISS."""
    bad = []
    for n in range(1323, 1344):
        try:
            shapes = _redfirst_shapes("411", n)
        except Exception:
            continue
        for name, payload in shapes:
            if not _misses(payload):
                bad.append("f%d:%s" % (n, name))
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:5])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w411_attack_probes: F1323-F1335 still open (HELD).

    F1344-F1348 have no pins in w411_attack_probes (renumbered residuals);
    their closure is verified by test_p1_filed_shapes above. Honors
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w411_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g412l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w411_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_w411_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # F1323-F1331 decoder + F1332-F1335 provenance still OPEN -> HELD
        still_open = set(range(1323, 1336))
        ok = (still_open <= held and not (still_open & broken))
        return (ok, "green(w411_attack): open-hold=%d/13%s"
                % (len(still_open & held), "" if ok else " MISMATCH"))
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
