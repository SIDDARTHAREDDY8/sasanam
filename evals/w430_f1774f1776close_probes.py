#!/usr/bin/env python3
"""Wave-430 Lane C close probes for F1774/F1775/F1776.

Pin/footer pins, filed shapes, generalizations, fail-closed bounds,
sibling pins, honest-text controls, perf (200 sites), depth-1 green
check honoring GOV_SKIP_GREEN=1.

GOV_DEPLOYMENT_MODE=staging at module level. Unique-suffixed /var/tmp
TMPDIRs. No in-repo git in self-pins.
"""
import os
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

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


# Filed shapes (exact from FINDINGS.md)
_FILED = [
    ('f1774-filed',
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('')"),
    ('f1775-filed',
     "var C={I};var it=C.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D)"),
    ('f1776-filed',
     "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D)"),
]

# Generalizations (whitespace, let/const, chunk sizes, trailing ;)
_GENERAL = [
    ('f1774-let-ws',
     "let C = {I} ; let D = C.map(function(c){return String.fromCharCode(c);}) ; let RESULT = D.join('') ;"),
    ('f1774-const',
     "const C={I};const D=C.map(function(c){return String.fromCharCode(c);});const RESULT=D.join('')"),
    ('f1774-dq',
     'var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join("")'),
    ('f1775-let',
     "let C={I};let it=C.values();let D=[];let r;while(!(r=it.next()).done){D.push(r.value);}let S=String.fromCharCode.apply(null,D);"),
    ('f1775-const-it',
     "const C={I};const it=C.values();const D=[];let r;while(!(r=it.next()).done){D.push(r.value);}const S=String.fromCharCode.apply(null,D)"),
    ('f1776-k8',
     "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/8);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D)"),
    ('f1776-k1',
     "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/1);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);"),
    ('f1776-let',
     "let C={I};let G=Map.groupBy(C,function(c,i){return Math.floor(i/16);});let D=[];for(let k=0;G.has(k);k++){D=D.concat(G.get(k));}let S=String.fromCharCode.apply(null,D)"),
]

# Fail-closed bounds (must MISS — non-identity or out-of-grammar)
# NOTE (wave-430 lane C spec review H1/H2): three shapes originally listed
# here assemble node-exactly and were filed as new findings instead:
# - f1774-2param -> F1782 (2-param callback, identity, assembles)
# - f1776-k2048 -> F1783 (K=2048, single chunk, identity, assembles)
# - f1776-const-key -> F1784 (const key + loop, identity, assembles)
# A fail-closed bound must be a NON-assembling input; the _GENERAL section's
# node_ok guard is the pattern (S2).
_FAILCLOSED = [
    # F1774: non-empty join separator is not identity
    ('f1774-join-comma',
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join(',')"),
    # F1774: identity callback belongs to F1709, not F1774 (disjoint)
    # (verified non-assembling for F1774's grammar: F1709's hook requires
    #  the ,null thisArg which this shape lacks)
    ('f1774-identity-cb',
     "var C={I};var D=C.map(function(c){return c;},null);var RESULT=D.join('')"),
    # F1775: .values() on non-C base (D undefined -> throws, non-identity)
    ('f1775-wrong-base',
     "var C={I};var it=D.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D)"),
    # F1775: missing .done check (infinite loop guard: node throws, non-identity)
    ('f1775-no-done',
     "var C={I};var it=C.values();var D=[];var r;while(!(r=it.next())){D.push(r.value);}var S=String.fromCharCode.apply(null,D)"),
    # F1776: chunk divisor 0 (Math.floor(i/0)=NaN/Infinity keys, non-identity)
    ('f1776-k0',
     "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/0);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D)"),
    # F1776: Object.groupBy belongs to F1757, not F1776 (disjoint)
    # (G.has is not a function on plain objects -> throws, non-identity)
    ('f1776-object-groupby',
     "var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D)"),
]

# Sibling pins (must still HIT via their own hooks, not mine)
_SIBLINGS = [
    ('f1709-pin',
     "var C={I};var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ('f1757-pin',
     "var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);};var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ('f1339-pin',
     "var C={I};var O={};O[Symbol.replace]=function(s){return C.map(function(c){return String.fromCharCode(c);}).join('');};var S='x'.replace(O);var RESULT=S;"),
]

# Honest-text controls (must MISS — no credential)
_CONTROLS = [
    ('honest-nocred',
     "var C=[72,101,108,108,111];var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('')"),
    ('honest-text',
     "The quick brown fox jumps over the lazy dog."),
    ('honest-join',
     "var parts=['a','b','c'];var RESULT=parts.join('');"),
]


def _node_assembles(payload, secret, result_var):
    """Verify node assembles the credential (node-exactness)."""
    js = payload + f";console.log('OUT:'+((typeof {result_var}!=='undefined')?{result_var}:''));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=30)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def main():
    fails = 0
    total = 0

    print("=== Pin/footer pins ===")
    # N_STMTDEC_LOOPS pin (126 base + 1 new = 127)
    import re
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dlp_src = f.read()
    # Count dispatch loops in _decode_layer
    m = re.search(r"def _decode_layer\(text\):(.*?)\n\n\ndef ", dlp_src, re.S)
    if m:
        body = m.group(1)
        loops = len(re.findall(r"for _stmtdec in \(([^)]*)\):", body))
        ok = (loops == 127)
        print(("PIN-OK " if ok else "PIN-FAIL ") + f"N_STMTDEC_LOOPS={loops} (expect 127)")
        if not ok:
            fails += 1
        total += 1
    # re.compile count pin (29)
    recompiles = dlp_src.count("re.compile(")
    ok = (recompiles == 29)
    print(("PIN-OK " if ok else "PIN-FAIL ") + f"re.compile={recompiles} (expect 29)")
    if not ok:
        fails += 1
    total += 1

    print("\n=== Filed shapes (must HIT, node-exact) ===")
    for name, tmpl in _FILED:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            # Determine result var for node check
            if "RESULT=D.join" in tmpl:
                rvar = "RESULT"
            else:
                rvar = "S"
            node_ok = _node_assembles(payload, secret, rvar)
            verdict = _scan(payload)
            ok = node_ok and verdict == "HIT"
            print(("PASS " if ok else "FAIL ") + f"{name} {label} node={node_ok} scanner={verdict}")
            if not ok:
                fails += 1

    print("\n=== Generalizations (must HIT) ===")
    for name, tmpl in _GENERAL:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if "RESULT=D.join" in tmpl or "RESULT = D.join" in tmpl:
                rvar = "RESULT"
            else:
                rvar = "S"
            node_ok = _node_assembles(payload, secret, rvar)
            verdict = _scan(payload)
            # For generalizations, we require HIT if node assembles
            # (if node doesn't assemble, it's not a valid generalization)
            if not node_ok:
                print(f"SKIP {name} {label} (node does not assemble)")
                total -= 1
                continue
            ok = (verdict == "HIT")
            print(("PASS " if ok else "FAIL ") + f"{name} {label} scanner={verdict}")
            if not ok:
                fails += 1

    print("\n=== Fail-closed bounds (must MISS) ===")
    for name, tmpl in _FAILCLOSED:
        total += 1
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        verdict = _scan(payload)
        ok = (verdict == "MISS")
        print(("PASS " if ok else "FAIL ") + f"{name} scanner={verdict}")
        if not ok:
            fails += 1

    print("\n=== Sibling pins (must HIT via own hooks) ===")
    for name, tmpl in _SIBLINGS:
        total += 1
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        verdict = _scan(payload)
        ok = (verdict == "HIT")
        print(("PASS " if ok else "FAIL ") + f"{name} scanner={verdict}")
        if not ok:
            fails += 1

    print("\n=== Honest-text controls (must MISS) ===")
    for name, payload in _CONTROLS:
        total += 1
        verdict = _scan(payload)
        ok = (verdict == "MISS")
        print(("PASS " if ok else "FAIL ") + f"{name} scanner={verdict}")
        if not ok:
            fails += 1

    print("\n=== Perf (200 sites) ===")
    # 200 synthetic sites with map/join/values/groupBy keywords (no credential)
    sites = []
    for i in range(200):
        sites.append(f"var x{i}=[{i}];var y{i}=x{i}.map(function(c){{return c;}});var z{i}=y{i}.join(',');")
    big_text = "".join(sites)
    start = time.time()
    verdict = _scan(big_text)
    elapsed = time.time() - start
    total += 1
    # 30s budget for 200 sites on full scanner (hooks are ~0s; baseline dominates)
    ok = (verdict == "MISS" and elapsed < 30.0)
    print(("PASS " if ok else "FAIL ") + f"200 sites: {elapsed:.2f}s scanner={verdict}")
    if not ok:
        fails += 1

    print("\n=== Depth-1 green check ===")
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP green check (GOV_SKIP_GREEN=1)")
    else:
        # Run adjacent battery mains with GOV_SKIP_GREEN=1 (depth-1)
        tmpdir = tempfile.mkdtemp(prefix="w430_laneC_green_", dir="/var/tmp")
        os.makedirs(tmpdir, exist_ok=True)
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmpdir
        # Run the w395 perfharden pin battery (adjacent)
        green_batteries = [
            "evals/w395_perfharden_probes.py",
        ]
        for batt in green_batteries:
            total += 1
            batt_path = os.path.join(REPO_ROOT, batt)
            if not os.path.exists(batt_path):
                print(f"SKIP {batt} (not found)")
                total -= 1
                continue
            r = subprocess.run([sys.executable, batt_path],
                               capture_output=True, text=True, timeout=300,
                               env=env, cwd=REPO_ROOT)
            ok = (r.returncode == 0)
            print(("PASS " if ok else "FAIL ") + f"green:{batt} rc={r.returncode}")
            if not ok:
                print(r.stdout[-500:] if r.stdout else "")
                print(r.stderr[-500:] if r.stderr else "")
                fails += 1

    print(f"\nRESULT: {'PASS' if fails == 0 else 'FAIL'} ({total - fails}/{total} pass, {fails} fails)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
