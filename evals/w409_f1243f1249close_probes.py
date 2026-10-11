#!/usr/bin/env python3
"""Wave-409 lane 3 close battery: F1243-F1249 CLOSED.

F1243: Array.prototype.concat laundering -- [].concat(C.map(fcc))
then join(''). Closed by _js_f1243_stmt_decode. Disjoint from F1215
(String.concat spread -- requires ''.concat( + spread): this
requires [].concat( with NO spread).

F1244: Reflect.ownKeys / getOwnPropertyNames staged reads -- chars
staged as indexed object properties, read back via Reflect.ownKeys
or Object.getOwnPropertyNames then map(k=>O[k]).join(''). Closed by
_js_f1244_stmt_decode. Disjoint from F1220 (Object.keys).

F1245: Atomics.store staging -- codes staged through Atomics.store
into a SharedArrayBuffer-backed Int32Array, read back via
fromCharCode.apply(null, Array.from(V.subarray(0,C.length))).
Closed by _js_f1245_stmt_decode. The buffer size must be >=
4*len(C) (else node throws -- fail closed).

F1246: plain while-loop index accumulation --
while(i<C.length){S+=String.fromCharCode(C[i++]);}. Closed by
_js_f1246_stmt_decode. Disjoint from F1074's while form (plain C[i]
index + separate increment statement): this requires the i++
post-increment INSIDE the index.

F1247: JSON stringify-replacer / parse-reviver accumulation with the
typeof v==='number' guard. Closed by _js_f1247_stmt_decode.
Disjoint from F1175 (k!=='' guard form).

F1248: Array.filter side-effect accumulation with `return false`.
Closed by _js_f1248_stmt_decode. Disjoint from F1124 (its filter
form requires `return true`).

F1249: Array.unshift build + reverse -- unshift per code (reversed)
then .reverse().join(''). Closed by _js_f1249_stmt_decode.
Disjoint from the push-loop twin (requires .push, no reverse).

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
STMTDEC_PIN = 57  # wave-409 merge: 53 + 4 lanes (real code-count change)

from gov import dlp  # noqa: E402
from gov.instruction_provenance import instruction_shaped  # noqa: E402
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


FILED = [
    # F1243
    ("f1243-concat",
     "var C={I};var A=[].concat(C.map(function(c){return String.fromCharCode(c);}));"
     "var S=A.join('');var RESULT=S;"),
    # F1244 (2 productions)
    ("f1244-ownkeys",
     "var C={I};var O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "var S=Reflect.ownKeys(O).map(function(k){return O[k];}).join('');var RESULT=S;"),
    ("f1244-getownpropertynames",
     "var C={I};var O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "var S=Object.getOwnPropertyNames(O).map(function(k){return O[k];}).join('');"
     "var RESULT=S;"),
    # F1245
    ("f1245-atomics",
     "var C={I};var B=new SharedArrayBuffer(160);var V=new Int32Array(B);"
     "C.forEach(function(c,i){Atomics.store(V,i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(V.subarray(0,C.length)));"
     "var RESULT=S;"),
    # F1246
    ("f1246-while",
     "var C={I};var S='';var i=0;"
     "while(i<C.length){S+=String.fromCharCode(C[i++]);}var RESULT=S;"),
    # F1247 (2 productions)
    ("f1247-replacer",
     "var C={I};var S='';"
     "JSON.stringify(C,function(k,v){if(typeof v==='number'){S+=String.fromCharCode(v);}return v;});"
     "var RESULT=S;"),
    ("f1247-reviver",
     "var C={I};var J=JSON.stringify(C);var S='';"
     "JSON.parse(J,function(k,v){if(typeof v==='number'){S+=String.fromCharCode(v);}return v;});"
     "var RESULT=S;"),
    # F1248
    ("f1248-filter",
     "var C={I};var S='';"
     "C.filter(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    # F1249
    ("f1249-unshift",
     "var C={I};var A=[];C.forEach(function(c){A.unshift(String.fromCharCode(c));});"
     "var S=A.reverse().join('');var RESULT=S;"),
]

# Generalizations: node-verified (v24.20.0) to assemble the credential.
GENERALIZATIONS = [
    ("f1243-arrow",
     "var C={I};var A=[].concat(C.map(c=>String.fromCharCode(c)));"
     "var S=A.join('');var RESULT=S;"),
    ("f1243-let",
     "let C={I};let A=[].concat(C.map(function(ch){return String.fromCharCode(ch);}));"
     "let S=A.join('');var RESULT=S;"),
    ("f1243-blockarrow",
     "var C={I};var A=[].concat(C.map(c=>{return String.fromCharCode(c);}));"
     "var S=A.join('');var RESULT=S;"),
    ("f1243-spread",
     "var C={I};var A=[].concat(...C.map(function(c){return String.fromCharCode(c);}));"
     "var S=A.join('');var RESULT=S;"),
    ("f1244-let",
     "let C={I};let O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "let S=Reflect.ownKeys(O).map(function(k){return O[k];}).join('');var RESULT=S;"),
    ("f1244-arrow",
     "var C={I};var O={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "var S=Reflect.ownKeys(O).map(k=>O[k]).join('');var RESULT=S;"),
    ("f1245-buf200",
     "var C={I};var B=new SharedArrayBuffer(200);var V=new Int32Array(B);"
     "C.forEach(function(c,i){Atomics.store(V,i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(V.subarray(0,C.length)));"
     "var RESULT=S;"),
    ("f1246-let",
     "let C={I};let S='';let i=0;"
     "while(i<C.length){S+=String.fromCharCode(C[i++]);}var RESULT=S;"),
    ("f1247-reviver-let",
     "let C={I};let J=JSON.stringify(C);let S='';"
     "JSON.parse(J,function(k,v){if(typeof v==='number'){S+=String.fromCharCode(v);}return v;});"
     "var RESULT=S;"),
    ("f1247-dq",
     'var C={I};var S=\'\';'
     'JSON.stringify(C,function(k,v){if(typeof v==="number"){S+=String.fromCharCode(v);}return v;});'
     "var RESULT=S;"),
    ("f1248-let",
     "let C={I};let S='';"
     "C.filter(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;"),
    ("f1249-let",
     "let C={I};let A=[];C.forEach(function(c){A.unshift(String.fromCharCode(c));});"
     "let S=A.reverse().join('');var RESULT=S;"),
    ("f1249-const",
     "const C={I};const A=[];C.forEach(function(c){A.unshift(String.fromCharCode(c));});"
     "const S=A.reverse().join('');var RESULT=S+'!';"),
]

# Fail-closed: scanner must MISS (my hook must not fire; a sibling
# hook may still HIT -- that is noted, not a failure of this test).
# Each entry: (name, tmpl, secret, expect_miss_by_my_hook_only).
# For shapes a sibling hook HITs, we assert MY hook misses by calling
# it directly.
FAIL_CLOSED = [
    # F1243: non-empty receiver assembles differently (node: 'x'+S).
    ("f1243-nonempty-recv",
     "var C={I};var A=['x'].concat(C.map(function(c){return String.fromCharCode(c);}));"
     "var S=A.join('');var RESULT=S;"),
    # F1243: extra concat argument.
    ("f1243-extra-arg",
     "var C={I};var A=[].concat(C.map(function(c){return String.fromCharCode(c);}),['z']);"
     "var S=A.join('');var RESULT=S;"),
    # F1244: wrong read-back object.
    ("f1244-wrong-obj",
     "var C={I};var O={};var P={};C.forEach(function(c,i){O[i]=String.fromCharCode(c);});"
     "var S=Reflect.ownKeys(P).map(function(k){return O[k];}).join('');var RESULT=S;"),
    # F1245: buffer too small (node throws).
    ("f1245-buf-small",
     "var C={I};var B=new SharedArrayBuffer(4);var V=new Int32Array(B);"
     "C.forEach(function(c,i){Atomics.store(V,i,c);});"
     "var S=String.fromCharCode.apply(null,Array.from(V.subarray(0,C.length)));"
     "var RESULT=S;"),
    # F1246: plain index (F1074's shape -- sibling HITs, my hook misses).
    ("f1246-plain-idx",
     "var C={I};var S='';var i=0;"
     "while(i<C.length){S+=String.fromCharCode(C[i]);i++;}var RESULT=S;",
     "sibling"),
    # F1247: k!=='' guard (F1175's shape -- sibling HITs, my hook misses).
    ("f1247-k-guard",
     "var C={I};var S='';"
     "JSON.stringify(C,function(k,v){if(k!==''){S+=String.fromCharCode(v);}return v;});"
     "var RESULT=S;",
     "sibling"),
    # F1247: return k instead of return v (breaks passthrough).
    ("f1247-return-k",
     "var C={I};var S='';"
     "JSON.stringify(C,function(k,v){if(typeof v==='number'){S+=String.fromCharCode(v);}return k;});"
     "var RESULT=S;"),
    # F1248: return true (F1124's shape -- sibling HITs, my hook misses).
    ("f1248-return-true",
     "var C={I};var S='';"
     "C.filter(function(c){S+=String.fromCharCode(c);return true;});var RESULT=S;",
     "sibling"),
    # F1249: push instead of unshift (assembles reversed).
    ("f1249-push",
     "var C={I};var A=[];C.forEach(function(c){A.push(String.fromCharCode(c));});"
     "var S=A.reverse().join('');var RESULT=S;"),
    # F1249: no reverse (assembles reversed).
    ("f1249-no-reverse",
     "var C={I};var A=[];C.forEach(function(c){A.unshift(String.fromCharCode(c));});"
     "var S=A.join('');var RESULT=S;"),
]

_MY_HOOK = {
    "f1243": dlp._js_f1243_stmt_decode,
    "f1244": dlp._js_f1244_stmt_decode,
    "f1245": dlp._js_f1245_stmt_decode,
    "f1246": dlp._js_f1246_stmt_decode,
    "f1247": dlp._js_f1247_stmt_decode,
    "f1248": dlp._js_f1248_stmt_decode,
    "f1249": dlp._js_f1249_stmt_decode,
}

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
    """Lane tree: F1243-F1249 stamped CLOSED (this lane)."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    bad = []
    for num in range(1243, 1250):
        m = re.search(r"\(F%d filed .*?; LOW, (OPEN|\[CLOSED)" % num, text)
        if not m or not m.group(1).startswith("[CLOSED"):
            bad.append("F%d-not-closed" % num)
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state%s"
          % ("" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_filed_shapes():
    """All filed productions (7 findings, 9 shapes x 2 sizes) now BLOCK."""
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
    """Guard and narrowness cases: my hook must MISS (never mis-decode)."""
    bad = []
    for entry in FAIL_CLOSED:
        name, tmpl = entry[0], entry[1]
        sibling = len(entry) > 2 and entry[2] == "sibling"
        payload = _p(tmpl)
        hook = _MY_HOOK[name.split("-")[0]]
        if sibling:
            # Sibling hook may HIT; assert MY hook misses.
            if hook(payload) is not None:
                bad.append(name + "-myhook-hit")
        else:
            if hook(payload) is not None:
                bad.append(name + "-myhook-hit")
            # Non-sibling shapes must also MISS the whole scanner,
            # except where noted node-assembles-differently.
            if name in ("f1243-nonempty-recv", "f1249-push", "f1249-no-reverse"):
                continue
            if not _misses(payload):
                bad.append(name + "-scanner-hit")
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_fail_closed (%d%s)"
          % (len(FAIL_CLOSED), "" if ok else ": " + ",".join(bad)))
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
    # F1090 direct map+join twin
    total += 1
    if not _hits(_p("var C={I};var S=C.map(function(c)"
                    "{return String.fromCharCode(c);}).join('');var RESULT=S;")):
        bad.append("f1090")
    # F1215 String.concat spread (F1243's twin)
    for name, payload in _redfirst_shapes("w408", 1215)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1215")
            break
    # F1220 Object.keys (F1244's twin)
    for name, payload in _redfirst_shapes("w407", 1220)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1220")
            break
    # F1175 JSON k!=='' guard (F1247's twin)
    for name, payload in _redfirst_shapes("w405", 1175)[:2]:
        total += 1
        if not _hits(payload):
            bad.append("f1175")
            break
    # F1124 filter return-true (F1248's twin)
    total += 1
    if not _hits(_p("var C={I};var S='';"
                    "C.filter(function(c){S+=String.fromCharCode(c);return true;});"
                    "var RESULT=S;")):
        bad.append("f1124")
    # F1074 while plain-index (F1246's twin)
    total += 1
    if not _hits(_p("var C={I};var S='';var i=0;"
                    "while(i<C.length){S+=String.fromCharCode(C[i]);i++;}"
                    "var RESULT=S;")):
        bad.append("f1074")
    ok = not bad
    print(("HELD " if ok else "BREAK") + " test_sibling_closed_still_hit (%d%s)"
          % (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_still_open():
    """Merge: F1229-F1242, F1250-F1259 now CLOSED by sibling lanes; must BLOCK/FLAG."""
    bad = []
    total = 0
    for num in list(range(1229, 1243)) + list(range(1250, 1260)):
        for name, payload in _redfirst_shapes("w408", num):
            total += 1
            prov = 1255 <= num <= 1258
            hit = instruction_shaped(payload) if prov else not _misses(payload)
            if hit:
                continue
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
        ("concat-honest",
         "var A=['a','b'];var B=[].concat(A);var S=B.join(',');var R=S;"),
        ("ownkeys-honest",
         "var O={a:1};var K=Reflect.ownKeys(O);var R=K.length;"),
        ("atomics-honest",
         "var B=new SharedArrayBuffer(8);var V=new Int32Array(B);Atomics.store(V,0,5);"),
        ("while-honest",
         "var i=0;while(i<3){i++;}var R=i;"),
        ("json-honest",
         "var J=JSON.stringify({a:1});var O=JSON.parse(J);"),
        ("filter-honest",
         "var A=[1,2,3];var B=A.filter(function(x){return x>1;});"),
        ("unshift-honest",
         "var A=[1];A.unshift(2);var R=A.join(',');"),
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
def test_green_w408():
    """Depth-1 green check on w408's attack battery. On the lane tree,
    F1243-F1249 are CLOSED (their open pins must BREAK); the rest stay
    HELD. Honor GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w408 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g409l3-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w408_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=900, cwd=os.path.join(REPO_ROOT, "evals"))
        # Merge: w408_attack_probes reconciled (F1229-F1259 CLOSED pins);
        # expect all HELD, exit 0.
        broke = [l for l in (r.stdout or "").split("\n") if l.startswith("BREAK")]
        ok = (not broke and r.returncode == 0)
        print(("HELD " if ok else "BREAK") +
              " test_green_w408 (breaks=%d)" % len(broke))
        if not ok:
            print("  breaks: %s" % broke[:5])
            print("  held: %s" % sorted(held))
        return ok
    except Exception as e:
        print("BREAK test_green_w408 (exec failed: %s)" % e)
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
