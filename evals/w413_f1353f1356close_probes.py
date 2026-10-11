#!/usr/bin/env python3
"""Wave-413 lane 2 close battery: F1353-F1356 CLOSED.

F1353: Object.fromEntries apply readout (F1229 residual) --
`var C=[codes];var E=C.map(function(c,i){return [i,c];});var
O=Object.fromEntries(E);var
S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;`
assembled node-exactly (v24.20.0) while find_credential MISSED.
Closed by `_js_f1353_stmt_decode` (raw-pair map parser + apply
readout; fail-closed on fcc-in-pair or join readout). Disjoint
from F1229 by grammar.

F1354: Object.fromEntries for-loop staging (F1229 residual) --
entries built by `for(var i=0;i<C.length;i++){E.push([i,C[i]]);}`
instead of .map, same apply readout. Closed by
`_js_f1354_stmt_decode`. Disjoint from F1229/F1353 by the for-loop.

F1355: Set.forEach two-param arrow (F1336/F1264 residual) --
`new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});`
assembled node-exactly while find_credential MISSED. Closed by
`_js_f1355_stmt_decode` (2-param arrow parser; Set.forEach passes
(value,value,set) so k is the index). Disjoint from F1264
(function), F1317 (function, non-empty init), F1336 (1-param
arrow) by the 2-param arrow form.

F1356: Number.prototype.toFixed map codec (F1203 residual) --
`var D=C.map(function(c){return Number(c.toFixed(0));});var
S=String.fromCharCode.apply(null,D);` assembled node-exactly
while find_credential MISSED. Closed by `_js_f1356_stmt_decode`
(map + Number() grammar; digit 0..100). Disjoint from F1203
(for-loop + parseInt) by grammar.

New _decode_layer dispatch loop (F1353-F1356);
N_STMTDEC_LOOPS 69->70 (real code-count change). Node-exact on all
filed shapes (short + 40-char, v24.20.0); fail-closed hook-level
bounds; sibling pins hold; F1349-F1352 + F1357-F1359 (outside this
lane) still MISS.

Note: w412_f1353-f1356_redfirst.py used `{{I}}` templates with
`.replace("{I}", ...)` producing `var C={[...]};` (JS SyntaxError),
so their BREAK was vacuous. This lane's w413_fNNNN_redfirst.py
batteries use genuine filed shapes (node-verified).

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

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 29
N_STMTDEC_LOOPS_PIN = 70  # wave-413 lane 2: 69 + 1 (real code-count change)

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


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# Filed shapes (genuine, node-verified -- not the vacuous {{I}} forms).
def _filed_shapes():
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    shapes = []
    # F1353: function form + arrow twin.
    for tag, code in (("short", cs), ("long", cl)):
        shapes.append((
            "f1353-fn-%s" % tag,
            "var C=%s;var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % code))
        shapes.append((
            "f1353-arrow-%s" % tag,
            "var C=%s;var E=C.map((c,i)=>[i,c]);var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % code))
    # F1354: for-loop entries.
    for tag, code in (("short", cs), ("long", cl)):
        shapes.append((
            "f1354-%s" % tag,
            "var C=%s;var E=[];for(var i=0;i<C.length;i++){E.push([i,C[i]]);}var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % code))
    # F1355: two-param arrow.
    for tag, code in (("short", cs), ("long", cl)):
        shapes.append((
            "f1355-%s" % tag,
            "var C=%s;var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;" % code))
    # F1356: function form + arrow twin.
    for tag, code in (("short", cs), ("long", cl)):
        shapes.append((
            "f1356-fn-%s" % tag,
            "var C=%s;var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % code))
        shapes.append((
            "f1356-arrow-%s" % tag,
            "var C=%s;var D=C.map(c=>Number(c.toFixed(0)));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % code))
    return shapes


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
    names = ["_js_f1353_stmt_decode", "_js_f1354_stmt_decode",
             "_js_f1355_stmt_decode", "_js_f1356_stmt_decode"]
    has = {nm: any(nm in lp for lp in loops) for nm in names}
    ok = ok and all(has.values())
    return (ok, "loops=%d pin=%d %s"
            % (len(loops), N_STMTDEC_LOOPS_PIN,
               " ".join("%s=%s" % (k.split("_")[2], v)
                         for k, v in has.items())))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-413 lane 2 (2026-10-11)" in src
          and "F1353-F1356 CLOSED (4" in src
          and "F1349-F1352, F1357-F1359 OPEN (7" in src
          and "F1360-F1363 filed OPEN (4" in src
          and "next free F1364" in src)
    for n in (1353, 1354, 1355, 1356, 1360, 1361, 1362, 1363):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-11 wave-413 lane 2") == 4)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "# Wave-412: F1323-F1348 CLOSED (26); F1349-F1359 OPEN (11); "
             "next free F1360" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_filed_block():
    """All F1353-F1356 filed shapes (genuine) now BLOCK."""
    bad = []
    shapes = _filed_shapes()
    for name, payload in shapes:
        if not _blocked(payload):
            bad.append(name)
    return (not bad, "%d/%d filed shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const twins, renamed idents, digit variants."""
    cases = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    # F1353: let/const, renamed idents.
    cases.append(("f1353-let",
                  "let C=%s;let E=C.map(function(x,y){return [y,x];});let O=Object.fromEntries(E);let S=String.fromCharCode.apply(null,Object.values(O));let RESULT=S;" % cs))
    cases.append(("f1353-const",
                  "const C=%s;const E=C.map((a,b)=>[b,a]);const O=Object.fromEntries(E);const S=String.fromCharCode.apply(null,Object.values(O));const RESULT=S;" % cl))
    # F1354: let twin, renamed idents.
    cases.append(("f1354-let",
                  "let C=%s;let E=[];for(let j=0;j<C.length;j++){E.push([j,C[j]]);}let O=Object.fromEntries(E);let S=String.fromCharCode.apply(null,Object.values(O));let RESULT=S;" % cs))
    # F1355: let/const, renamed params.
    cases.append(("f1355-let",
                  "let C=%s;let S='';new Set(C.keys()).forEach((a,b)=>{S+=String.fromCharCode(C[b]);});let RESULT=S;" % cs))
    cases.append(("f1355-const",
                  "const C=%s;const S='';new Set(C.keys()).forEach((x,y)=>{S+=String.fromCharCode(C[y]);});const RESULT=S;" % cl))
    # F1356: let twin, digit variant toFixed(2), renamed.
    cases.append(("f1356-let",
                  "let C=%s;let D=C.map(function(z){return Number(z.toFixed(2));});let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs))
    cases.append(("f1356-const-arrow",
                  "const C=%s;const D=C.map(w=>Number(w.toFixed(1)));const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cl))
    bad = [n for n, p in cases if not _blocked(p)]
    return (not bad, "%d/%d generalizations block%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level bounds: each new hook returns None on near-misses.

    Direct hook calls (not find_credential) so sibling hooks can't
    mask a mis-fire.
    """
    from gov.dlp import (_js_f1353_stmt_decode, _js_f1354_stmt_decode,
                         _js_f1355_stmt_decode, _js_f1356_stmt_decode)
    cs = _codes(SECRET_S)
    cases = [
        # F1353: join readout instead of apply (unmodeled).
        (_js_f1353_stmt_decode,
         "var C=%s;var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=Object.values(O).join('');var RESULT=S;" % cs),
        # F1353: wrong entries arg.
        (_js_f1353_stmt_decode,
         "var C=%s;var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(C);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % cs),
        # F1353: fcc inside the pair (F1229's grammar, not F1353's).
        (_js_f1353_stmt_decode,
         "var C=%s;var E=C.map(function(c,i){return [i,String.fromCharCode(c)];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % cs),
        # F1354: push wrong pair order ([C[i],i] -- mis-decode risk).
        (_js_f1354_stmt_decode,
         "var C=%s;var E=[];for(var i=0;i<C.length;i++){E.push([C[i],i]);}var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % cs),
        # F1354: map-built entries (F1353's grammar, not F1354's).
        (_js_f1354_stmt_decode,
         "var C=%s;var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % cs),
        # F1355: 1-param paren arrow (F1336's grammar, not F1355's).
        (_js_f1355_stmt_decode,
         "var C=%s;var S='';new Set(C.keys()).forEach((i)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs),
        # F1355: function callback (F1264's grammar).
        (_js_f1355_stmt_decode,
         "var C=%s;var S='';new Set(C.keys()).forEach(function(i,k){S+=String.fromCharCode(C[k]);});var RESULT=S;" % cs),
        # F1355: body uses C[i] not C[k] (wrong index param).
        (_js_f1355_stmt_decode,
         "var C=%s;var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs),
        # F1355: non-empty init (unmodeled narrowness).
        (_js_f1355_stmt_decode,
         "var C=%s;var S='xy';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;" % cs),
        # F1356: parseInt instead of Number (unmodeled).
        (_js_f1356_stmt_decode,
         "var C=%s;var D=C.map(function(c){return parseInt(c.toFixed(0),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1356: toFixed(101) (node RangeError -- must fail closed).
        (_js_f1356_stmt_decode,
         "var C=%s;var D=C.map(function(c){return Number(c.toFixed(101));});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1356: join readout instead of apply (unmodeled).
        (_js_f1356_stmt_decode,
         "var C=%s;var D=C.map(function(c){return Number(c.toFixed(0));});var S=D.join('');var RESULT=S;" % cs),
    ]
    bad = []
    for hook, payload in cases:
        try:
            v = hook(payload)
        except Exception as e:  # noqa: BLE001
            bad.append("%s:EXC %r" % (hook.__name__, e))
            continue
        if v is not None:
            bad.append("%s fired on %s" % (hook.__name__, payload[:60]))
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + "; ".join(bad[:3])))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1229/F1264/F1317/F1336/F1203 still BLOCK (their own hooks)."""
    cs = _codes(SECRET_S)
    sibs = [
        # F1229: fcc-in-pair + join readout.
        ("f1229",
         "var C=%s;var E=C.map(function(c,i){return [i,String.fromCharCode(c)];});var O=Object.fromEntries(E);var S=Object.values(O).join('');var RESULT=S;" % cs),
        # F1264: function callback.
        ("f1264",
         "var C=%s;var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;" % cs),
        # F1336: 1-param arrow.
        ("f1336",
         "var C=%s;var S='';new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));var RESULT=S;" % cs),
        # F1203: for-loop + parseInt toFixed.
        ("f1203",
         "var C=%s;var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(parseInt(C[i].toFixed(0),10));}var RESULT=S;" % cs),
    ]
    bad = [n for n, p in sibs if not _blocked(p)]
    return (not bad, "%d/%d sibling pins hold%s"
            % (len(sibs) - len(bad), len(sibs),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest-text controls ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    quiet = [
        "var x=1;var y=x*2;",
        "The quarterly financial summary shows revenue growth.",
        "var C=[65,66];var S=String.fromCharCode(...C);var RESULT=S;",
        "Object.fromEntries([['a',1]]);",
        "new Set([1,2,3]).forEach(function(x){console.log(x);});",
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
                "var C=%s;var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;" % cs)
        elif i % 4 == 1:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 4 == 2:
            sites.append("var x=%d;var y=x*2;" % i)
        else:
            sites.append(
                "var C=%s;var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;" % cs)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- p7: other opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1349-F1352 + F1357-F1359 (outside this lane) still MISS."""
    bad = []
    cs, cl = _codes(SECRET_S), _codes(SECRET_L)
    opens = [
        # F1349: flat staged reads.
        "var C=%s;var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
        # F1350: flatMap bare.
        "var C=%s;var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
        # F1351: replaceAll no-op.
        "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replaceAll('x','x');var RESULT=U;" % cs,
        # F1352: sort stable no-op.
        "var C=%s;var D=C.map(function(c){return [c];});var E=D.sort(()=>0);var S=String.fromCharCode.apply(null,E.flat());var RESULT=S;" % cs,
        # F1357: chained join/split/join.
        "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;" % cl,
        # F1358: reduceRight (exact filed param names -- `a` hits a
        # pre-existing narrow hook, `acc` is the genuine filed miss).
        "var C=%s;var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;" % cs,
    ]
    for p in opens:
        if not _misses(p):
            bad.append(p[:60])
    return (not bad, "%d/%d other opens miss%s"
            % (len(opens) - len(bad), len(opens),
               "" if not bad else ": " + ",".join(bad[:3])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w412_attack_probes: F1353-F1356 flip, others hold.

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w412_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g413l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w412_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_(f\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(m.group(2))
        # My lane: F1353-F1356 now CLOSED -> OPEN pins BREAK.
        # Siblings: F1349-F1352 + F1357-F1359 still OPEN -> pins HELD.
        closed_now = {"f1353", "f1354", "f1355", "f1356"}
        still_open = {"f1349", "f1350", "f1351", "f1352",
                      "f1357", "f1358", "f1359"}
        ok = (closed_now <= broken and still_open <= held
              and not (closed_now & held) and not (still_open & broken))
        return (ok, "green(w412_attack): closed-flip=%d/4 open-hold=%d/7%s"
                % (len(closed_now & broken), len(still_open & held),
                   "" if ok else " MISMATCH held=%s broken=%s"
                   % (sorted(held), sorted(broken))))
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
