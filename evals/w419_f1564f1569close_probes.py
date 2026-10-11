#!/usr/bin/env python3
"""Wave-419 lane 4 close battery: F1564-F1569 CLOSED.

F1564: Map.set loop staging -- `var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];`
  + map/join readout. Closed by `_js_f1564_stmt_decode`. Node-exact:
  keys 0..len-1 in insertion order, so [...M.values()] is a copy of C.
  Disjoint from F1446 (Map for-of drain), F1536 (Map-constructor +
  values()) by grammar.

F1565: trimStart/trimEnd chained readout --
  `var RESULT=(' '+S+' ').trimStart().trimEnd();` (either trim order,
  any all-whitespace pads). Closed by `_js_f1565_stmt_decode`.
  Node-exact: pads are all-whitespace and S's edge codes are not
  trimmable (fail-closed per _JS_TRIM_WS, F1509 discipline).
  Disjoint from F1509-F1511 (trim on the mapped string directly).

F1566: replace string-arg chained readout --
  `var S=C.map(fcc).join('');var U=S.replace(A,A);` (identical args =
  identity). Closed by `_js_f1566_stmt_decode`. Disjoint from F1380
  (two-statement map/join form) by grammar.

F1567: dead effect-free `for` statement (parser robustness, F1540
  class) -- `for(var k=0;k<1;k++){var Z=k;}` between the staging
  statements. Closed by the `_js_f1567_strip_dead_for` variant
  production (generalizes the F1540 dead-strip class to bounded
  numeric loops with dead bodies; termination direction proven,
  loop var dead, body binds only dead idents with pure RHS).
  Node-exact: removing it cannot change the assembled credential.

F1568: filter includes(c,K>=1) -- `C.filter(function(c,i){return
  C.includes(c,1);})`. Closed by `_js_f1568_stmt_decode`. Node-exact:
  E=[x for x in C if x in C[K:]] computed exactly (no fail-closed
  bound needed). Disjoint from F1524 (fromIndex 0), F1556 (NaN),
  F1517 (no fromIndex) by grammar.

F1569: flatMap 4-param arrow null-thisArg --
  `C.flatMap((c,i,a,t)=>[c],null)`. Closed by
  `_js_f1569_stmt_decode`. Disjoint from F1518 (function-form null),
  F1504 ({} thisArg), F1546 ([]/"x" thisArg) by grammar.

New _decode_layer dispatch loop (F1564/F1565/F1566/F1568/F1569);
N_STMTDEC_LOOPS 88->89 (real code-count change, wave-385).
F1567's strip is a direct production (no new loop). Node-exact on
all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1546-F1563 (other opens)
still MISS.

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
# F1568 needs the first code to repeat later (includes(c,1) keeps it).
SECRET_S68 = "x" + SECRET_S
SECRET_L68 = "x" + SECRET_L
# F1568 generalization with fromIndex=2: every char must occur at index>=2.
SECRET_S682 = "xo" + SECRET_S

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
    ("f1564",
     "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1565",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();"),
    ("f1566",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','x');var RESULT=U;"),
    ("f1567",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;"),
    ("f1569",
     "var C={I};var E=C.flatMap((c,i,a,t)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]
_FILED68 = [
    ("f1568",
     "var C={I};var E=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-418 lineage; N_STMTDEC_LOOPS=92; re.compile=29."""
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
    ok = (pin == 92 and len(loops) == 92)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w418 = "# Wave-418:" in ftxt
    ok = ok and has_w418
    notes.append("w418-footer=%s" % has_w418)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w418_attack_probes.py")) as f:
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
    for name, tmpl in _FILED68:
        for s in (SECRET_S68, SECRET_L68):
            total += 1
            if not _hits(tmpl.replace("{I}", _codes(s))):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S68 else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """Renamed idents, let/const, trim-order/pad twins, loop-form twins."""
    cs = _codes(SECRET_S)
    cs68 = _codes(SECRET_S68)
    cs682 = _codes(SECRET_S682)
    cases = [
        ("f1564-renamed",
         "let D=%s;let N=new Map();for(let j=0;j<D.length;j++){N.set(j,D[j]);}let W=[...N.values()];let RESULT=W.map((c)=>String.fromCharCode(c)).join('');" % cs),
        ("f1565-revorder",
         "var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join('');var RESULT=('\\t'+S+'\\t').trimEnd().trimStart();" % cs),
        ("f1565-dqpad",
         'var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join("");var RESULT=(" "+S+" ").trimStart().trimEnd();' % cs),
        ("f1566-dq",
         'var C=%s;var S=C.map((c)=>String.fromCharCode(c)).join("");var U=S.replace("ab","ab");var RESULT="x"+U;' % cs),
        ("f1567-le",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(let k=0;k<=0;k++){let Z=k;}var RESULT=S;" % cs),
        ("f1567-plus",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<2;k+=1){var Z=k;}var RESULT=S;" % cs),
        ("f1567-two",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}for(var j=5;j>0;j--){var W=j;}var RESULT=S;" % cs),
        ("f1568-k2",
         "var C=%s;var E=C.filter(function(c,i){return C.includes(c,2);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs682),
        ("f1569-5param",
         "var C=%s;var E=C.flatMap((c,i,a,t,u)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1569-const",
         "const C=%s;const E=C.flatMap((c,i,a,t)=>[c],null);const S=String.fromCharCode.apply(null,E);const RESULT=S;" % cs),
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
        ("f1564-swap", "var C=%s;var M=new Map();for(var i=0;i<C.length;i++){M.set(C[i],i);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1564-arg", "var C=%s;var M=new Map([[0,0]]);for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1565-edge", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();" % _codes(" " + SECRET_S)),
        ("f1565-nonws", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('a'+S+'a').trimStart().trimEnd();" % cs),
        ("f1565-single", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart();" % cs),
        ("f1566-differ", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','y');var RESULT=U;" % cs),
        ("f1566-regex", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace(/x/,'x');var RESULT=U;" % cs),
        ("f1566-dollar", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('$`','$`');var RESULT=U;" % cs),
        ("f1567-infinite", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k--){var Z=k;}var RESULT=S;" % cs),
        ("f1567-live", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S+k;" % cs),
        ("f1567-call", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=String(k);}var RESULT=S;" % cs),
        ("f1568-nonlit", "var C=%s;var E=C.filter(function(c,i){return C.includes(c,i);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1568-argmm", "var C=%s;var E=C.filter(function(c,i){return C.includes(d,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1569-undef", "var C=%s;var E=C.flatMap((c,i,a,t)=>[c],undefined);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1569-x", "var C=%s;var E=C.flatMap((c,i,a,t)=>[c],'x');var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1569-3param", "var C=%s;var E=C.flatMap((c,i,a)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
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
        ("f1518-closed",
         "var C=%s;var E=C.flatMap(function(c,i,a,t){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1524-closed",
         "var C=%s;var E=C.filter(function(c,i){return C.includes(c,0);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1509-closed",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;" % cs,
         True),
        ("f1380-closed",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('x','x');var RESULT=U;" % cs,
         True),
        ("f1517-closed",
         "var C=%s;var E=C.filter(function(c){return C.includes(c);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         True),
        ("f1546-open",
         "var C=%s;var E=C.flatMap(function(c){return [c];},[]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         False),
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
        "var M=new Map();M.set(0,1);var V=[...M.values()];var RESULT='hello world';",
        "var S='  padded  ';var RESULT=S.trimStart().trimEnd();",
        "The quarterly financial summary shows revenue growth of 12 percent.",
        "var C=[1,2,3];var E=C.filter(function(c,i){return C.includes(c,1);});var RESULT='done';",
        "function flatMapExample(a){return a.flatMap((x)=>[x],null);}",
    ]
    bad = [p[:40] for p in cases if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1546-F1563 (attack-86, OPEN) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1546", "var C=%s;var E=C.flatMap(function(c){return [c];},[]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1547", "var C=%s;var E=C.map(function(c){return String.fromCharCode(c).padStart(10);});var S=E.join('').trim();var RESULT=S;" % cs),
        ("f1548", "var C=%s;var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1553", "var C=%s;var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1560", "var C=%s;var D=Object.assign([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1562", "var C=%s;var E=C.flat(0);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
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
                "var C=%s;var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;" % cs)
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
    """Depth-1 green on w418_attack_probes.

    F1564-F1569 are now closed by this lane (their pins must break);
    F1546-F1563 remain open (their pins must hold). Carry pins must
    hold. Taxonomy (2143) and footer pins must hold. Honors
    GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w418_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g419l4-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w418_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            if line.startswith("pin-ok "):
                parts = line.split()
                if len(parts) >= 2:
                    held.add(parts[1])
            elif line.startswith("PIN-FAIL "):
                parts = line.split()
                if len(parts) >= 2:
                    broken.add(parts[1])
        expect_held = {"F%d" % n for n in range(1546, 1564)}
        expect_broken = {"F%d" % n for n in range(1564, 1570)}
        ok = (expect_held <= held and expect_broken <= broken)
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = ok and tax and footer
        return (ok, "green(w418_attack): held=%s broken=%s tax=%s footer=%s"
                % (sorted(held & expect_held) == sorted(expect_held),
                   sorted(broken & expect_broken) == sorted(expect_broken),
                   tax, footer))
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
