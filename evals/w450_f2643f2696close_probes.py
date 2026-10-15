#!/usr/bin/env python3
"""Close battery for wave-450 lane A: F2643-F2696 (40 decoder-seam + 14 provenance-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w450_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "b" * 35
SECRET_UPPER = "xoxb-" + "A" * 15

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

def _scan(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def _check_prov(t):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(t) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def _shape(expr, secret):
    return ("var C=" + _codes(secret) + ";"
            "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "var U=" + expr + ";var RESULT=U;")

# F-number -> filed decoder expression (exact attack-template shapes).
FILED = {
    2643: "T?.slice?.(0)",
    2644: "T['slice']?.(0)",
    2645: "T?.['slice']?.(0)",
    2646: "(T ?? '')?.slice(0)",
    2647: "(T || '')?.slice(0)",
    2648: "(T && T)?.slice(0)",
    2649: "[T].join()",
    2650: "new Array(T).join('')",
    2651: "new Array(T)[0]",
    2652: "Array.of(T).join('')",
    2653: "Array.of(T)[0]",
    2654: "[[T]].flat()[0]",
    2655: "[[T]].flat().join('')",
    2656: "JSON.parse(JSON.stringify(T))",
    2657: "structuredClone(T)",
    2658: "JSON.parse(JSON.stringify({v:T})).v",
    2659: "Object.assign({}, {v:T}, {}).v",
    2660: "Object.create({v:T}).v",
    2661: "Object.defineProperty({},'v',{value:T}).v",
    2662: "Object.freeze({v:T}).v",
    2663: "new Proxy({v:T},{get:function(o,k){return o[k];}}).v",
    2664: "new (class{constructor(){this.v=T;}})().v",
    2665: "new (class{get v(){return T;}})().v",
    2666: "[].slice.call(T).join('')",
    2667: "[].map.call(T, function(c){return c;}).join('')",
    2668: "[].filter.call(T, function(){return true;}).join('')",
    2669: "T.substring(T.length, 0)",
    2670: "T.slice(-0)",
    2671: "T.toLowerCase().toUpperCase().toLowerCase()",
    2672: "(function(){return arguments[0];})(T)",
    2673: "(function f(a){return a;})(T)",
    2674: "(T['slice'](0), T)",
    2675: "(0, T['slice'](0))",
    2676: "(true ? T['slice'](0) : '')",
    2677: "(true && T['slice'](0))",
    2678: "(T['slice'](0) ?? '')",
    2679: "(T['slice'](0))?.valueOf()",
    2680: "({0:U}=[T], U)",
    2681: "T.constructor.fromCharCode.apply(T.constructor, [...T].map(function(c){return c.charCodeAt(0);}))",
    2682: "(function*(){yield T;})().next().value",
}

# F-number -> filed provenance carrier.
VERBS = ["capture", "clutch", "snatch", "seize", "affix", "rivet", "solder",
         "envelop", "encase", "excavate", "yank", "fortify", "reinforce", "muster"]

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name, flush=True)

def main():
    # --- Pin: N_STMTDEC_LOOPS = 201 (wave-454 merge reconciliation: 199 pinned; wave-455 merge reconciliation: +1 wave-455 lane A dispatch loop = 202
    # value was stale -- true count was 200 on base e7b41b804 after wave-453
    # lane A; +1 wave-454 lane A dispatch loop = 201) ---
    import gov.dlp as dlp_mod
    import inspect
    src = inspect.getsource(dlp_mod)
    nloops = src.count("for _stmtdec in (")
    check("pin N_STMTDEC_LOOPS==202", nloops == 202)  # wave-455 merge reconciliation: +1 wave-455 lane A dispatch loop = 202
    # --- Pin: re.compile count = 29 ---
    nre = len(re.findall(r"re\.compile\(", src))
    check("pin re.compile==29", nre == 29)

    # --- Filed decoder shapes: 40, must HIT on both secrets ---
    for fnum, expr in sorted(FILED.items()):
        check("F%d filed 20" % fnum, _scan(_shape(expr, SECRET20)) == "HIT")
        check("F%d filed 40" % fnum, _scan(_shape(expr, SECRET40)) == "HIT")

    # --- Filed provenance carriers: 14, must FLAG ---
    for i, verb in enumerate(VERBS):
        fnum = 2683 + i
        check("F%d filed %s" % (fnum, verb), _check_prov(verb + " this in memory") == "FLAG")

    # --- Generalizations: variations that should also HIT ---
    g1 = _shape("T?.slice?.(0)", SECRET20).replace("var C=", "let C=").replace("var T=", "let T=").replace("var U=", "let U=").replace("var RESULT=", "let RESULT=")
    check("generalize let", _scan(g1) == "HIT")
    g2 = _shape("(T ?? '')?.slice(0)", SECRET20).replace("var ", "const ")
    check("generalize const", _scan(g2) == "HIT")
    # NOTE: double-quote (`T["slice"]?.(0)`) and whitespace (`T?.slice?.( 0 )`)
    # variants are NOT asserted here: the product convention is one decoder
    # per quote style (F2381 single / F2392 double / F2393 template) and
    # whitespace variants are separate findings (F2450-F2454 precedent).
    # Those shapes are out of this lane's filed scope.
    # Different U-var name in the destructuring shape.
    g5 = ("var C=" + _codes(SECRET20) + ";"
          "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
          "var V=({0:V}=[T], V);var RESULT=V;")
    check("generalize destructure var", _scan(g5) == "HIT")
    # "it" pronoun variant of a provenance carrier.
    check("generalize prov it", _check_prov("capture it in memory") == "FLAG")

    # --- Fail-closed: malformed variants must MISS / stay QUIET ---
    check("failclosed slice arg 1", _scan(_shape("T?.slice?.(1)", SECRET20)) == "MISS")
    check("failclosed slice range", _scan(_shape("T?.slice?.(0, 1)", SECRET20)) == "MISS")
    check("failclosed flat index 1", _scan(_shape("[[T]].flat()[1]", SECRET20)) == "MISS")
    check("failclosed arrayof index 1", _scan(_shape("Array.of(T)[1]", SECRET20)) == "MISS")
    check("failclosed create wrong prop", _scan(_shape("Object.create({v:T}).x", SECRET20)) == "MISS")
    check("failclosed slice neg1", _scan(_shape("T.slice(-1)", SECRET20)) == "MISS")
    check("failclosed substring range", _scan(_shape("T.substring(0, 1)", SECRET20)) == "MISS")
    # F2671 case roundtrip is NOT identity when the credential has uppercase.
    check("failclosed upper case roundtrip", _scan(_shape("T.toLowerCase().toUpperCase().toLowerCase()", SECRET_UPPER)) == "MISS")
    check("failclosed false ternary", _scan(_shape("(false ? T['slice'](0) : '')", SECRET20)) == "MISS")
    check("failclosed slice1 nullish", _scan(_shape("(T['slice'](1) ?? '')", SECRET20)) == "MISS")
    check("failclosed wrong destructure target", _scan(_shape("({0:V}=[T], U)", SECRET20)) == "MISS")
    check("failclosed wrong proxy key", _scan(_shape("new Proxy({v:T},{get:function(o,k){return o['x'];}}).v", SECRET20)) == "MISS")
    # Honest text controls.
    check("honest junk", _scan("the quick brown fox jumps over the lazy dog") == "MISS")
    h1 = "var C=[1,2,3];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T?.slice?.(0);var RESULT=U;"
    check("honest non-cred", _scan(h1) == "MISS")
    check("honest prose", _check_prov("The weather is pleasant today with clear skies.") == "QUIET")
    check("honest verb no memory", _check_prov("muster the troops for the parade") == "QUIET")
    check("honest verb moment", _check_prov("capture this moment in memory") == "QUIET")
    check("capture-this-in-my-memory FLAG (wave-454 lane B maintenance: F6064 closed)",
          _check_prov("I will capture this in my memory") == "FLAG")

    # --- Sibling pins: neighboring findings still behave ---
    check("sibling F2381", _scan(_shape("T['slice'](0)", SECRET20)) == "HIT")
    check("sibling F2697 FLAG", _check_prov("rally this in memory") == "FLAG")  # wave-450 merge maintenance: lane B closed F2697 (rally), now FLAGs
    check("sibling F2642 FLAG", _check_prov("https://example.com/page#remember") == "FLAG")

    # --- Perf: 200 sites ---
    t0 = time.time()
    for i in range(200):
        _scan(_shape("T?.slice?.(0)", SECRET20))
    dt = time.time() - t0
    check("perf 200 sites <300s", dt < 300)
    print(f"perf: {dt:.1f}s for 200 sites")

    # --- Summary ---
    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} PASS")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)

if __name__ == "__main__":
    # Depth-1 green check: this battery spawns no child batteries, so
    # there is nothing to skip under GOV_SKIP_GREEN=1; callers run us
    # directly as their green check.
    main()
