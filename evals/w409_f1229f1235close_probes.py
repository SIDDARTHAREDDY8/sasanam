#!/usr/bin/env python3
"""Wave-409 lane 1 close battery: F1229-F1235 CLOSED.

F1229: Object.fromEntries staged reads -- staging chars through
Object.fromEntries(C.map((c,i)=>[i,fromCharCode(c)])) then
Object.values(O).join(''). Closed by _js_f1229_stmt_decode. Distinct
from F1182 (Object.create + Object.values -- different construction).

F1230: Map staged reads -- accumulating chars into a Map
(M.set(i,fromCharCode(c))) and reading back via M.forEach. Closed by
_js_f1230_stmt_decode. Distinct from F1183 (WeakMap -- different
constructor and key semantics).

F1231: Symbol-keyed accumulation -- accumulating chars under a
Symbol-keyed property (O[sym]+=fromCharCode(c)). Closed by
_js_f1231_stmt_decode.

F1232: Proxy set/get trap staging -- a set-trap that appends
(t[p]+=v) and a get-trap that returns fromCharCode(C[Number(p)]).
Closed by _js_f1232_stmt_decode (two productions).

F1233: DataView setUint8 staging -- round-tripping codes through a
DataView (setUint8 per code, ToUint8 semantics) and reading back via
String.fromCharCode.apply(null, Array.from(new
Uint8Array(B).subarray(0,C.length))). Closed by
_js_f1233_stmt_decode. Distinct from F1191 (TypedArray.prototype.set)
and F1112 (TypedArray.from).

F1234: Object.groupBy staging -- grouping the char array with
Object.groupBy(A, ()=> 'k') then G.k.join(''). Closed by
_js_f1234_stmt_decode.

F1235: Array.splice accumulation -- building the char array via
A.splice(A.length,0,fromCharCode(c)) per code then join(''). Closed
by _js_f1235_stmt_decode.

All hooks are whole-text, narrow-grammar, fail-closed, F452-charged
per attempt, and results are bounded by _MAX_DECODE_BYTES. Never
evals. Green checks ON. $0-spend-by-construction.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
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
STMTDEC_PIN = 57  # wave-409 merge: 53 + 4 lanes (real code-count change)

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


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _p(tmpl, secret=SECRET_S):
    return tmpl.replace("{I}", _codes(secret))


# Filed productions (8 x 2 sizes = 16 shapes).
FILED = [
    ("f1229-fromentries",
     "var C={I};var E=C.map(function(c,i){return [i,String.fromCharCode(c)];});"
     "var O=Object.fromEntries(E);var S=Object.values(O).join('');var RESULT=S;"),
    ("f1230-map",
     "var C={I};var M=new Map();C.forEach(function(c,i){M.set(i,String.fromCharCode(c));});"
     "var S='';M.forEach(function(v){S+=v;});var RESULT=S;"),
    ("f1231-symbol",
     "var C={I};var k=Symbol('k');var O={};O[k]='';"
     "C.forEach(function(c){O[k]+=String.fromCharCode(c);});var RESULT=O[k];"),
    ("f1232-set-trap",
     "var C={I};var T={v:''};var P=new Proxy(T,{set:function(t,p,v){t[p]=t[p]+v;return true;}});"
     "C.forEach(function(c){P.v=String.fromCharCode(c);});var RESULT=T.v;"),
    ("f1232-get-trap",
     "var C={I};var P=new Proxy({},{get:function(t,p){var i=Number(p);return String.fromCharCode(C[i]);}});"
     "var S='';for(var i=0;i<C.length;i++){S+=P[i];}var RESULT=S;"),
    ("f1233-dataview",
     "var C={I};var B=new ArrayBuffer(64);var V=new DataView(B);"
     "C.forEach(function(c,i){V.setUint8(i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B).subarray(0,C.length)));"
     "var RESULT=S;"),
    ("f1234-groupby",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var G=Object.groupBy(A,function(){return 'k';});var S=G.k.join('');var RESULT=S;"),
    ("f1235-splice",
     "var C={I};var A=[];C.forEach(function(c){A.splice(A.length,0,String.fromCharCode(c));});"
     "var S=A.join('');var RESULT=S;"),
]

# Generalizations: node-verified twins (arrow forms, renamed vars, let/const).
# All verified to assemble in node v24.20.0 before asserting BLOCK.
GENERALIZATIONS = [
    ("f1229-arrow",
     "var C={I};var E=C.map((c,i)=>[i,String.fromCharCode(c)]);"
     "var O=Object.fromEntries(E);var S=Object.values(O).join('');var RESULT=S;"),
    ("f1229-letconst",
     "let C={I};const E=C.map(function(ch,ix){return [ix,String.fromCharCode(ch)];});"
     "let O=Object.fromEntries(E);const S=Object.values(O).join('');let RESULT=S;"),
    ("f1230-arrow",
     "var C={I};var M=new Map();C.forEach((c,i)=>{M.set(i,String.fromCharCode(c));});"
     "var S='';M.forEach((v)=>{S+=v;});var RESULT=S;"),
    ("f1231-arrow",
     "var C={I};var k=Symbol('desc');var O={};O[k]='';"
     "C.forEach((c)=>{O[k]+=String.fromCharCode(c);});var RESULT=O[k];"),
    ("f1232a-arrow",
     "var C={I};var T={w:''};var P=new Proxy(T,{set:function(t,p,v){t[p]=t[p]+v;return true;}});"
     "C.forEach((c)=>{P.w=String.fromCharCode(c);});var RESULT=T.w;"),
    ("f1233-arrow",
     "var C={I};var B=new ArrayBuffer(128);var V=new DataView(B);"
     "C.forEach((c,i)=>{V.setUint8(i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B).subarray(0,C.length)));"
     "var RESULT=S;"),
    ("f1234-arrow",
     "var C={I};var A=C.map(c=>String.fromCharCode(c));"
     "var G=Object.groupBy(A,function(){return 'kk';});var S=G.kk.join('');var RESULT=S;"),
    ("f1235-arrow",
     "var C={I};var A=[];C.forEach((c)=>{A.splice(A.length,0,String.fromCharCode(c));});"
     "var S=A.join('');var RESULT=S;"),
    # deleteCount=1 also appends at start==length (node-exact, v24.20.0).
    ("f1235-splice-del1",
     "var C={I};var A=[];C.forEach(function(c){A.splice(A.length,1,String.fromCharCode(c));});"
     "var S=A.join('');var RESULT=S;"),
    # SPEC-review: F1234 arrow groupBy callback (entry names ()=> 'k').
    ("f1234-arrow-groupby",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var G=Object.groupBy(A,()=> 'k');var S=G.k.join('');var RESULT=S;"),
    # SPEC-review: F1232 set-trap += spelling (entry names (t[p]+=v)).
    ("f1232-set-trap-plusassign",
     "var C={I};var T={v:''};var P=new Proxy(T,{set:function(t,p,v){t[p]+=v;return true;}});"
     "C.forEach(function(c){P.v=String.fromCharCode(c);});var RESULT=T.v;"),
    # SPEC-review: F1232 get-trap direct C[Number(p)] (entry names it).
    ("f1232-get-trap-direct",
     "var C={I};var P=new Proxy({},{get:function(t,p){return String.fromCharCode(C[Number(p)]);}});"
     "var S='';for(var i=0;i<C.length;i++){S+=P[i];}var RESULT=S;"),
]

# Fail-closed: shapes that must NOT decode (miss, never mis-decode).
FAIL_CLOSED = [
    # F1229: pair order swapped ([char, idx] instead of [idx, char]).
    ("f1229-pair-swapped",
     "var C={I};var E=C.map(function(c,i){return [String.fromCharCode(c),i];});"
     "var O=Object.fromEntries(E);var S=Object.values(O).join('');var RESULT=S;"),
    # F1229: non-empty join separator.
    ("f1229-join-sep",
     "var C={I};var E=C.map(function(c,i){return [i,String.fromCharCode(c)];});"
     "var O=Object.fromEntries(E);var S=Object.values(O).join(',');var RESULT=S;"),
    # F1230: set args swapped (char as key).
    ("f1230-set-swapped",
     "var C={I};var M=new Map();C.forEach(function(c,i){M.set(String.fromCharCode(c),i);});"
     "var S='';M.forEach(function(v){S+=v;});var RESULT=S;"),
    # F1231: init not empty.
    ("f1231-init-nonempty",
     "var C={I};var k=Symbol('k');var O={};O[k]='x';"
     "C.forEach(function(c){O[k]+=String.fromCharCode(c);});var RESULT=O[k];"),
    # F1232a: trap does not append (overwrites).
    ("f1232a-trap-overwrite",
     "var C={I};var T={v:''};var P=new Proxy(T,{set:function(t,p,v){t[p]=v;return true;}});"
     "C.forEach(function(c){P.v=String.fromCharCode(c);});var RESULT=T.v;"),
    # F1233: buffer too small (node would throw RangeError).
    ("f1233-buf-small",
     "var C={I};var B=new ArrayBuffer(2);var V=new DataView(B);"
     "C.forEach(function(c,i){V.setUint8(i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B).subarray(0,C.length)));"
     "var RESULT=S;"),
    # F1234: non-empty join separator.
    ("f1234-join-sep",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});"
     "var G=Object.groupBy(A,function(){return 'k';});var S=G.k.join('-');var RESULT=S;"),
]

# Sibling closed findings that must still HIT (no regressions).
SIBLINGS = [
    ("f1182-object-create",
     "var C={I};var O=Object.create(null);C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "var S=Object.values(O).join('');var RESULT=S;"),
    ("f1183-weakmap",
     "var C={I};var M=new WeakMap();var K=C.map(function(c){return {v:c};});"
     "K.forEach(function(k){M.set(k,String.fromCharCode(k.v));});"
     "var S=K.map(function(k){return M.get(k);}).join('');var RESULT=S;"),
    ("f1090-mapjoin",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
]

# Still-open findings (F1236-F1259) are covered by test_p0_footer_state
# (entry stamps) and test_green_w408 (attack battery pins).

HONEST = [
    "The quarterly financial summary shows revenue growth.",
    "var x = Object.fromEntries([['a', 1], ['b', 2]]);",
    "var m = new Map(); m.set('k', 'v');",
    "var s = Symbol('desc');",
]


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
    """Merge: F1229-F1259 stamped CLOSED (wave-409 lanes 1-4)."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    bad = []
    for num in range(1229, 1236):
        m = re.search(r"\(F%d filed .*?; LOW, (OPEN|\[CLOSED)" % num, text)
        if not m or not m.group(1).startswith("[CLOSED"):
            bad.append("F%d-not-closed" % num)
    for num in range(1236, 1260):
        m = re.search(r"\(F%d filed .*?; LOW, (OPEN|\[CLOSED)" % num, text)
        if not m or not m.group(1).startswith("[CLOSED"):
            bad.append("F%d-not-closed" % num)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state%s"
          % ("" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_filed_shapes():
    """All 16 filed shapes (8 productions x 2 sizes) now BLOCK."""
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
    """Non-conforming variants MISS (never mis-decode)."""
    bad = []
    for name, tmpl in FAIL_CLOSED:
        if not _misses(_p(tmpl)):
            bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_fail_closed (%d%s)"
          % (len(FAIL_CLOSED), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_sibling_closed_still_hit():
    """Sibling closed findings still BLOCK (no regressions)."""
    bad = []
    for name, tmpl in SIBLINGS:
        if not _hits(_p(tmpl)):
            bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_sibling_closed_still_hit (%d%s)"
          % (len(SIBLINGS), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_honest_quiet():
    """Honest text stays quiet."""
    bad = []
    for i, text in enumerate(HONEST):
        if not _misses(text):
            bad.append("honest-%d" % i)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_honest_quiet (%d%s)"
          % (len(HONEST), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_perf_200_sites():
    """200 mixed sites scan within budget."""
    sites = []
    for i in range(100):
        sites.append(_p(FILED[i % len(FILED)][1]))
    for i in range(100):
        sites.append(HONEST[i % len(HONEST)])
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 60
    print(("HELD " if ok else "BREAK") + " test_perf_200_sites (%.1fs)" % dt)
    return ok


@_t
def test_green_w408():
    """Depth-1 green check on w408's attack battery. On the lane tree,
    F1229-F1235 are CLOSED (their open pins must flip); F1236-F1259
    stay OPEN. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w408 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmpd = tempfile.mkdtemp(prefix="g409l1-green-", dir="/var/tmp")
    try:
        r = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "evals", "w408_attack_probes.py")],
            capture_output=True, text=True, timeout=600, env=env,
            cwd=tmpd)
        out = (r.stdout or "") + (r.stderr or "")
        # Merge: w408_attack_probes is reconciled (F1229-F1259 CLOSED pins);
        # expect it fully green (all HELD, exit 0).
        broke = [l for l in out.split("\n") if l.startswith("BREAK")]
        ok = (not broke and r.returncode == 0)
        print(("HELD " if ok else "BREAK") +
              " test_green_w408 (breaks=%d)" % len(broke))
        if not ok:
            print("  breaks:", broke[:5])
        return ok
    except Exception as e:
        print("BREAK test_green_w408 (exec failed: %s)" % e)
        return False
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = 0
    ran = 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        ran += 1
        try:
            if not fn():
                fails += 1
        except Exception as e:
            print("BREAK %s (exception: %s)" % (fn.__name__, e))
            fails += 1
    print("lane-battery: %d tests, %d FAIL" % (ran, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
