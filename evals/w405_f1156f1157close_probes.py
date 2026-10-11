#!/usr/bin/env python3
"""Wave-405 lane 4 close battery: F1156-F1158 CLOSED.

F1156: F1124 residual -- no-return side-effect callbacks. The wave-404
lane-2 F1124 hook modeled side-effect accumulation callbacks with an
explicit never-satisfied predicate (`return false` for find/some), but
a callback with NO return statement is effectively never-satisfied
(returns undefined) and assembles node-exactly while find_credential
MISSED. Closed by extending `_js_f1124_parse_cb` to accept the
no-return form for find/some (F1156 branch).

F1157: F1127 residual -- direct-RESULT push-then-join. The wave-404
lane-2 F1127 hook modeled push-then-join via an intermediate
(`var S=A.join('');var RESULT=S;`), but assigning the join directly
(`var RESULT=A.join('');`) assembles node-exactly while
find_credential MISSED. Closed by a direct-RESULT branch in
`_js_f1127_stmt_decode` that decodes `A.join('')` as the credential
dstr with no intermediate.

F1158: bare-`return;` side-effect callbacks (filed 2026-10-11 00:28 UTC
by this lane). F1156's own definitional language ("a callback with NO
return statement") excludes the bare `return;` form, which also returns
undefined -- never-satisfied -- and assembles node-exactly while
find_credential MISSED. Closed by extending the F1156 branch to accept
bare `return;` for find/some. The `return undefined` twin still misses
(fail-closed, out of scope).

F1156/F1157 filed 2026-10-10 23:28 UTC by the wave-404 merge red-first
audit (local node validation, $0.00 model spend (0 paid calls); LOW, OPEN).

Closed inside the existing `_js_f1124_stmt_decode` /
`_js_f1127_stmt_decode` whole-text hooks -- no new _decode_layer
dispatch loop, N_STMTDEC_LOOPS stays 41. Node-exact 8/8 filed +
11/11 generalizations (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1142-F1155 (attack round 72
opens) still MISS.

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
RECOMPILE_PIN = 28
N_STMTDEC_LOOPS_PIN = 41  # no new dispatch loop in this lane

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


def _codes_nb(s):
    """Bracket-less codes for the w404_f1156/f1157 red-first templates,
    whose [%s] already carries the brackets."""
    return ",".join(str(ord(c)) for c in s)


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
    has1124 = any("_js_f1124_stmt_decode" in lp for lp in loops)
    has1127 = any("_js_f1127_stmt_decode" in lp for lp in loops)
    ok = ok and has1124 and has1127
    return (ok, "loops=%d pin=%d f1124=%s f1127=%s"
            % (len(loops), N_STMTDEC_LOOPS_PIN, has1124, has1127))


@_t
def test_p0_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        src = f.read()
    ok = ("# Wave-405 lane 4 (2026-10-10/11)" in src
          and "F1156-F1158 CLOSED (3" in src
          and "F1142-F1155 OPEN (14" in src
          and "next free F1159" in src)
    for n in (1156, 1157, 1158):
        ok = ok and src.count("(F%d filed" % n) == 1
    ok = (ok and src.count("[CLOSED 2026-10-10 wave-405 lane 4") == 2
          and src.count("[CLOSED 2026-10-11 wave-405 lane 4") == 1)
    # base footer lineage preserved (wave-393 lesson).
    ok = (ok and "Next free finding: **F1159**" in src
          and "# Wave-404: F1123-F1141 CLOSED (19); F1142-F1157 OPEN (16); next free F1158" in src)
    return (ok, "lane-local footer present, base lineage preserved")


# ---------------- p1: filed shapes block ----------------

@_t
def test_p1_f1156_filed_block():
    shapes = _redfirst_shapes("w404", 1156)
    bad = []
    for name, tmpl in shapes:
        secret = SECRET_L if name.startswith("f1156-l") else SECRET_S
        if not _blocked(tmpl % _codes_nb(secret)):
            bad.append(name)
    return (not bad, "%d/%d filed F1156 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p1_f1157_filed_block():
    shapes = _redfirst_shapes("w404", 1157)
    bad = []
    for name, tmpl in shapes:
        secret = SECRET_L if name.startswith("f1157-l") else SECRET_S
        if not _blocked(tmpl % _codes_nb(secret)):
            bad.append(name)
    return (not bad, "%d/%d filed F1157 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


@_t
def test_p1_f1158_filed_block():
    shapes = _redfirst_shapes("w405", 1158)
    bad = []
    for name, tmpl in shapes:
        secret = SECRET_L if name.startswith("f1158-l") else SECRET_S
        if not _blocked(tmpl % _codes_nb(secret)):
            bad.append(name)
    return (not bad, "%d/%d filed F1158 shapes block%s"
            % (len(shapes) - len(bad), len(shapes),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p2: generalizations (node-exact v24.20.0) ----------------

_GEN = [
    # (name, template with {I} for the int array; all node-exact v24.20.0)
    ("f1156-find-2p-noreturn",
     "var C={I};var S='';C.find(function(c,i){{S+=String.fromCharCode(c);}});var RESULT=S;"),
    ("f1156-let-renamed",
     "let D={I};let S='';D.some(function(c){{S+=String.fromCharCode(c);}});let RESULT=S;"),
    ("f1156-const-decl",
     "const C={I};let S='';C.find(function(c){{S+=String.fromCharCode(c);}});const RESULT=S;"),
    ("f1156-some-additive",
     "var C={I};var S='';C.some(function(c){{S+=String.fromCharCode(c);}});var RESULT='k:'+S;"),
    ("f1157-let-renamed",
     "const C={I};let B=[];for(let k=0;k<C.length;k++){{B.push(String.fromCharCode(C[k]));}}const RESULT=B.join('');"),
    ("f1157-foreach-let",
     "let C={I};let A=[];C.forEach(function(c){{A.push(String.fromCharCode(c));}});let RESULT=A.join('');"),
    ("f1157-names",
     "var D={I};var E=[];for(var j=0;j<D.length;j++){{E.push(String.fromCharCode(D[j]));}}var RESULT=E.join('');"),
    ("f1158-find-bare-let",
     "let D={I};let S='';D.find(function(c){{S+=String.fromCharCode(c);return;}});let RESULT=S;"),
    ("f1158-find-bare-2p",
     "var C={I};var S='';C.find(function(c,i){{S+=String.fromCharCode(c);return;}});var RESULT=S;"),
]


@_t
def test_p2_generalizations():
    bad = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        for name, tmpl in _GEN:
            p = tmpl.format(I=c)
            if not _blocked(p):
                bad.append("%s-%s" % (tag, name))
    total = 2 * len(_GEN)
    return (not bad, "%d/%d generalizations block%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed bounds (hook-level) ----------------

_FC = [
    # (name, hook-attr, template with %s for the int-array codes)
    # F1156: only find/some no-return is modeled; other no-return
    # methods still miss.
    ("f1156-filter-noreturn", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.filter(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1156-flatmap-noreturn", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.flatMap(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    ("f1156-find-return-undefined", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return undefined;});var RESULT=S;"),
    ("f1156-find-return-true", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.find(function(c){S+=String.fromCharCode(c);return true;});var RESULT=S;"),
    ("f1156-some-return-true", "_js_f1124_stmt_decode",
     "var C=%s;var S='';C.some(function(c){S+=String.fromCharCode(c);return true;});var RESULT=S;"),
    ("f1156-nonempty-acc", "_js_f1124_stmt_decode",
     "var C=%s;var S='x';C.find(function(c){S+=String.fromCharCode(c);});var RESULT=S;"),
    # F1157: only the exact '' join to RESULT is modeled.
    ("f1157-join-comma", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join(',');"),
    ("f1157-join-noarg", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join();"),
    ("f1157-trailing", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join('');var X=1;"),
    ("f1157-join-target-mismatch", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=C.join('');"),
    ("f1157-double-join", "_js_f1127_stmt_decode",
     "var C=%s;var A=[];for(var i=0;i<C.length;i++){A.push(String.fromCharCode(C[i]));}var RESULT=A.join('').toString();"),
]


@_t
def test_p3_fail_closed():
    bad = []
    c = _codes(SECRET_S)
    for name, hook_attr, tmpl in _FC:
        p = tmpl % c
        hook = getattr(dlp, hook_attr)
        if hook(p) is not None:
            bad.append(name)
    total = len(_FC)
    return (not bad, "%d/%d fail-closed bounds miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad)))


@_t
def test_p3_cross_disjoint():
    # The extended hooks must not hit each other's shapes (both
    # directions) nor the sibling new-hook shapes.
    bad = []
    f1156 = _redfirst_shapes("w404", 1156)
    f1157 = _redfirst_shapes("w404", 1157)
    for name, tmpl in f1156:
        p = tmpl % _codes_nb(SECRET_S)
        if dlp._js_f1127_stmt_decode(p) is not None:
            bad.append("f1127-hits-%s" % name)
    for name, tmpl in f1157:
        p = tmpl % _codes_nb(SECRET_S)
        if dlp._js_f1124_stmt_decode(p) is not None:
            bad.append("f1124-hits-%s" % name)
    # F1124's no-return extension must not swallow F1125-F1130 shapes
    # (w403 red-first SHAPES are fully-formed payloads).
    for n in (1125, 1126, 1128, 1129, 1130):
        for name, p in _redfirst_shapes("w403", n):
            if dlp._js_f1124_stmt_decode(p) is not None:
                bad.append("f1124-hits-w403-%d-%s" % (n, name))
    # F1127's direct-RESULT extension must not swallow F1124-F1126/F1128-F1130.
    for n in (1124, 1125, 1126, 1128, 1129, 1130):
        for name, p in _redfirst_shapes("w403", n):
            if dlp._js_f1127_stmt_decode(p) is not None:
                bad.append("f1127-hits-w403-%d-%s" % (n, name))
    return (not bad, "cross-disjoint%s" % ("" if not bad else ": " + ",".join(bad)))


# ---------------- p4: siblings still hold ----------------

@_t
def test_p4_siblings():
    bad = []
    # F1124's original return-false forms still block (w403 SHAPES are
    # fully-formed payloads).
    for name, p in _redfirst_shapes("w403", 1124):
        if not _blocked(p):
            bad.append("w403-1124-%s" % name)
    # F1127's original intermediate-S form still blocks.
    for name, p in _redfirst_shapes("w403", 1127):
        if not _blocked(p):
            bad.append("w403-1127-%s" % name)
    # F1090/F1091/F1123 sibling shapes still block.
    for n, prefix in ((1090, "w400"), (1091, "w400"), (1123, "w403")):
        for name, p in _redfirst_shapes(prefix, n):
            if not _blocked(p):
                bad.append("%s-%d-%s" % (prefix, n, name))
    # Attack round 72 opens (F1142-F1155) must STILL miss
    # (w404 SHAPES are fully-formed payloads).
    for n in list(range(1142, 1151)) + [1153, 1154, 1155]:
        for name, p in _redfirst_shapes("w404", n):
            if not _misses(p):
                bad.append("round72-open-f%d-now-blocks-%s" % (n, name))
    return (not bad, "siblings%s" % ("" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest text stays quiet ----------------

_HONEST = [
    "var C=[1,2,3];var S='';C.find(function(c){return c>1;});console.log(C);",
    "var data=[10,20];var out=data.find(function(x){return x>5;});",
    "var C=[65,66];var A=[];for(var i=0;i<C.length;i++){A.push(C[i]);}var RESULT=A.join(',');",
    "function f(c){S+=c;} var arr=[1,2]; arr.some(f);",
    "var C=[1,2,3];var t=C.filter(function(c){return c>0;});var RESULT=t.length;",
    "const xs=[3,1,2];const r=xs.find(function(x){return x===4;});",
]


@_t
def test_p5_honest_text():
    bad = [p for p in _HONEST if not _misses(p)]
    return (not bad, "%d/%d honest texts quiet%s"
            % (len(_HONEST) - len(bad), len(_HONEST),
               "" if not bad else ": " + ";".join(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    c = _codes_nb(SECRET_S)
    shapes = ([t % c for _, t in _redfirst_shapes("w404", 1156)] +
              [t % c for _, t in _redfirst_shapes("w404", 1157)])
    t0 = time.time()
    for _ in range(50):
        for p in shapes:
            dlp.find_credential(p)
    dt = time.time() - t0
    ok = dt < 30.0
    return (ok, "200 sites in %.2fs (budget 30s)" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check on w404's attack battery (round-72 opens
    F1142-F1155 must still MISS; footer/taxonomy controls hold). Honor
    GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w404_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g405l4-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpd
    try:
        r = subprocess.run(
            [sys.executable, "evals/w404_attack_probes.py"],
            capture_output=True, text=True, env=env,
            timeout=600, cwd=REPO_ROOT)
        ok = r.returncode == 0
        tail = (r.stdout or "")[-300:]
        return (ok, "green(w404_attack): rc=%d %s" % (r.returncode, tail if not ok else "all HELD"))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


# ---------------- runner ----------------

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
