#!/usr/bin/env python3
"""Close battery for wave-449 lane B: F2538-F2585 (48 decoder-seam).

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
_TMPD = tempfile.mkdtemp(prefix="w449_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "b" * 35

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

def _shape(expr, secret):
    return ("var C=" + _codes(secret) + ";"
            "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "var U=" + expr + ";var RESULT=U;")

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name, flush=True)

def main():
    # --- Pin: N_STMTDEC_LOOPS = 195 ---
    import gov.dlp as dlp_mod
    import inspect
    src = inspect.getsource(dlp_mod)
    nloops = src.count("for _stmtdec in (")
    check("pin N_STMTDEC_LOOPS==195", nloops == 195)
    # --- Pin: re.compile count = 29 ---
    nre = len(re.findall(r"re\.compile\(", src))
    check("pin re.compile==29", nre == 29)

    # --- Filed shapes: 48, must HIT on both secrets ---
    check("F2538 filed 20", _scan(_shape("T?.slice(0)", SECRET20)) == "HIT")
    check("F2538 filed 40", _scan(_shape("T?.slice(0)", SECRET40)) == "HIT")
    check("F2539 filed 20", _scan(_shape("T?.['slice'](0)", SECRET20)) == "HIT")
    check("F2539 filed 40", _scan(_shape("T?.['slice'](0)", SECRET40)) == "HIT")
    check("F2540 filed 20", _scan(_shape("T?.['substring'](0)", SECRET20)) == "HIT")
    check("F2540 filed 40", _scan(_shape("T?.['substring'](0)", SECRET40)) == "HIT")
    check("F2541 filed 20", _scan(_shape("T?.['concat']('')", SECRET20)) == "HIT")
    check("F2541 filed 40", _scan(_shape("T?.['concat']('')", SECRET40)) == "HIT")
    check("F2542 filed 20", _scan(_shape("(T ?? '')", SECRET20)) == "HIT")
    check("F2542 filed 40", _scan(_shape("(T ?? '')", SECRET40)) == "HIT")
    check("F2543 filed 20", _scan(_shape("(T ?? '')['slice'](0)", SECRET20)) == "HIT")
    check("F2543 filed 40", _scan(_shape("(T ?? '')['slice'](0)", SECRET40)) == "HIT")
    check("F2544 filed 20", _scan(_shape("(T || '')", SECRET20)) == "HIT")
    check("F2544 filed 40", _scan(_shape("(T || '')", SECRET40)) == "HIT")
    check("F2545 filed 20", _scan(_shape("(T || '')['slice'](0)", SECRET20)) == "HIT")
    check("F2545 filed 40", _scan(_shape("(T || '')['slice'](0)", SECRET40)) == "HIT")
    check("F2546 filed 20", _scan(_shape("(T && T)", SECRET20)) == "HIT")
    check("F2546 filed 40", _scan(_shape("(T && T)", SECRET40)) == "HIT")
    check("F2547 filed 20", _scan(_shape("(T ? T : '')", SECRET20)) == "HIT")
    check("F2547 filed 40", _scan(_shape("(T ? T : '')", SECRET40)) == "HIT")
    check("F2548 filed 20", _scan(_shape("(0, T)", SECRET20)) == "HIT")
    check("F2548 filed 40", _scan(_shape("(0, T)", SECRET40)) == "HIT")
    check("F2549 filed 20", _scan(_shape("(0, T)['slice'](0)", SECRET20)) == "HIT")
    check("F2549 filed 40", _scan(_shape("(0, T)['slice'](0)", SECRET40)) == "HIT")
    check("F2550 filed 20", _scan(_shape("(void 0, T)", SECRET20)) == "HIT")
    check("F2550 filed 40", _scan(_shape("(void 0, T)", SECRET40)) == "HIT")
    check("F2551 filed 20", _scan(_shape("(typeof T === 'string' ? T : '')", SECRET20)) == "HIT")
    check("F2551 filed 40", _scan(_shape("(typeof T === 'string' ? T : '')", SECRET40)) == "HIT")
    check("F2552 filed 20", _scan(_shape("(T instanceof String ? T : T)", SECRET20)) == "HIT")
    check("F2552 filed 40", _scan(_shape("(T instanceof String ? T : T)", SECRET40)) == "HIT")
    check("F2553 filed 20", _scan(_shape("(function(){return T;})()", SECRET20)) == "HIT")
    check("F2553 filed 40", _scan(_shape("(function(){return T;})()", SECRET40)) == "HIT")
    check("F2554 filed 20", _scan(_shape("(function(){var x=T;return x;})()", SECRET20)) == "HIT")
    check("F2554 filed 40", _scan(_shape("(function(){var x=T;return x;})()", SECRET40)) == "HIT")
    check("F2555 filed 20", _scan(_shape("(function(x=T){return x;})()", SECRET20)) == "HIT")
    check("F2555 filed 40", _scan(_shape("(function(x=T){return x;})()", SECRET40)) == "HIT")
    check("F2556 filed 20", _scan(_shape("(function(){return this.v;}).call({v:T})", SECRET20)) == "HIT")
    check("F2556 filed 40", _scan(_shape("(function(){return this.v;}).call({v:T})", SECRET40)) == "HIT")
    check("F2557 filed 20", _scan(_shape("({get v(){return T;}}).v", SECRET20)) == "HIT")
    check("F2557 filed 40", _scan(_shape("({get v(){return T;}}).v", SECRET40)) == "HIT")
    check("F2558 filed 20", _scan(_shape("({get v(){return T;}})['v']", SECRET20)) == "HIT")
    check("F2558 filed 40", _scan(_shape("({get v(){return T;}})['v']", SECRET40)) == "HIT")
    check("F2559 filed 20", _scan(_shape("({...{v:T}}).v", SECRET20)) == "HIT")
    check("F2559 filed 40", _scan(_shape("({...{v:T}}).v", SECRET40)) == "HIT")
    check("F2560 filed 20", _scan(_shape("([U] = [T], U)", SECRET20)) == "HIT")
    check("F2560 filed 40", _scan(_shape("([U] = [T], U)", SECRET40)) == "HIT")
    check("F2561 filed 20", _scan(_shape("(({v:U} = {v:T}), U)", SECRET20)) == "HIT")
    check("F2561 filed 40", _scan(_shape("(({v:U} = {v:T}), U)", SECRET40)) == "HIT")
    check("F2562 filed 20", _scan(_shape("([...a] = [T], a[0])", SECRET20)) == "HIT")
    check("F2562 filed 40", _scan(_shape("([...a] = [T], a[0])", SECRET40)) == "HIT")
    check("F2563 filed 20", _scan(_shape("T['sl'+'ice'](0)", SECRET20)) == "HIT")
    check("F2563 filed 40", _scan(_shape("T['sl'+'ice'](0)", SECRET40)) == "HIT")
    check("F2564 filed 20", _scan(_shape("T[ 'slice' ]( 0 )", SECRET20)) == "HIT")
    check("F2564 filed 40", _scan(_shape("T[ 'slice' ]( 0 )", SECRET40)) == "HIT")
    check("F2565 filed 20", _scan(_shape("( T )['slice']( 0 )", SECRET20)) == "HIT")
    check("F2565 filed 40", _scan(_shape("( T )['slice']( 0 )", SECRET40)) == "HIT")
    check("F2566 filed 20", _scan(_shape("String['prototype']['slice']['apply'](T,[0])", SECRET20)) == "HIT")
    check("F2566 filed 40", _scan(_shape("String['prototype']['slice']['apply'](T,[0])", SECRET40)) == "HIT")
    check("F2567 filed 20", _scan(_shape("Array['prototype']['join']['call'](T['split'](''),'')", SECRET20)) == "HIT")
    check("F2567 filed 40", _scan(_shape("Array['prototype']['join']['call'](T['split'](''),'')", SECRET40)) == "HIT")
    check("F2568 filed 20", _scan(_shape("Reflect['get']({v:T},'v')", SECRET20)) == "HIT")
    check("F2568 filed 40", _scan(_shape("Reflect['get']({v:T},'v')", SECRET40)) == "HIT")
    check("F2569 filed 20", _scan(_shape("Object['getOwnPropertyDescriptor']({v:T},'v')['value']", SECRET20)) == "HIT")
    check("F2569 filed 40", _scan(_shape("Object['getOwnPropertyDescriptor']({v:T},'v')['value']", SECRET40)) == "HIT")
    check("F2570 filed 20", _scan(_shape("String.prototype.concat.apply('',[T])", SECRET20)) == "HIT")
    check("F2570 filed 40", _scan(_shape("String.prototype.concat.apply('',[T])", SECRET40)) == "HIT")
    check("F2571 filed 20", _scan(_shape("T.split('').reduce(function(a,c){return a+c;},'')", SECRET20)) == "HIT")
    check("F2571 filed 40", _scan(_shape("T.split('').reduce(function(a,c){return a+c;},'')", SECRET40)) == "HIT")
    check("F2572 filed 20", _scan(_shape("T.split('').filter(function(){return true;}).join('')", SECRET20)) == "HIT")
    check("F2572 filed 40", _scan(_shape("T.split('').filter(function(){return true;}).join('')", SECRET40)) == "HIT")
    check("F2573 filed 20", _scan(_shape("T['split']('')['map'](function(c,i,a){return a[i];})['join']('')", SECRET20)) == "HIT")
    check("F2573 filed 40", _scan(_shape("T['split']('')['map'](function(c,i,a){return a[i];})['join']('')", SECRET40)) == "HIT")
    check("F2574 filed 20", _scan(_shape("T['toLowerCase']()['toUpperCase']()['toLowerCase']()", SECRET20)) == "HIT")
    check("F2574 filed 40", _scan(_shape("T['toLowerCase']()['toUpperCase']()['toLowerCase']()", SECRET40)) == "HIT")
    check("F2575 filed 20", _scan(_shape("T['split']('', T['length'])['join']('')", SECRET20)) == "HIT")
    check("F2575 filed 40", _scan(_shape("T['split']('', T['length'])['join']('')", SECRET40)) == "HIT")
    check("F2576 filed 20", _scan(_shape("T['match'](/[^]/g)['join']('')", SECRET20)) == "HIT")
    check("F2576 filed 40", _scan(_shape("T['match'](/[^]/g)['join']('')", SECRET40)) == "HIT")
    check("F2577 filed 20", _scan(_shape("T['replace'](/(?:)/, function(){return '';})", SECRET20)) == "HIT")
    check("F2577 filed 40", _scan(_shape("T['replace'](/(?:)/, function(){return '';})", SECRET40)) == "HIT")
    check("F2578 filed 20", _scan(_shape("T['substring'](undefined)", SECRET20)) == "HIT")
    check("F2578 filed 40", _scan(_shape("T['substring'](undefined)", SECRET40)) == "HIT")
    check("F2579 filed 20", _scan(_shape("T['substr'](null)", SECRET20)) == "HIT")
    check("F2579 filed 40", _scan(_shape("T['substr'](null)", SECRET40)) == "HIT")
    check("F2580 filed 20", _scan(_shape("T['slice'](undefined,undefined)", SECRET20)) == "HIT")
    check("F2580 filed 40", _scan(_shape("T['slice'](undefined,undefined)", SECRET40)) == "HIT")
    check("F2581 filed 20", _scan(_shape("T['slice'](-0)", SECRET20)) == "HIT")
    check("F2581 filed 40", _scan(_shape("T['slice'](-0)", SECRET40)) == "HIT")
    check("F2582 filed 20", _scan(_shape("T['slice'](0, T['length'])", SECRET20)) == "HIT")
    check("F2582 filed 40", _scan(_shape("T['slice'](0, T['length'])", SECRET40)) == "HIT")
    check("F2583 filed 20", _scan(_shape("T['substring'](0, T['length'])", SECRET20)) == "HIT")
    check("F2583 filed 40", _scan(_shape("T['substring'](0, T['length'])", SECRET40)) == "HIT")
    check("F2584 filed 20", _scan(_shape("T['substr'](0, T['length'])", SECRET20)) == "HIT")
    check("F2584 filed 40", _scan(_shape("T['substr'](0, T['length'])", SECRET40)) == "HIT")
    check("F2585 filed 20", _scan(_shape("T['toString'](undefined)", SECRET20)) == "HIT")
    check("F2585 filed 40", _scan(_shape("T['toString'](undefined)", SECRET40)) == "HIT")

    # --- Generalizations: variations that should also HIT ---
    # let/const instead of var
    g1 = _shape("T?.slice(0)", SECRET20).replace("var C=", "let C=").replace("var T=", "let T=").replace("var U=", "let U=").replace("var RESULT=", "let RESULT=")
    check("generalize let", _scan(g1) == "HIT")
    # const
    g2 = _shape("(T ?? '')", SECRET20).replace("var ", "const ")
    check("generalize const", _scan(g2) == "HIT")

    # --- Fail-closed: malformed variants must MISS ---
    # Wrong method name
    f1 = _shape("T?.slice(0)", SECRET20).replace("T?.slice(0)", "T?.slice(1)")
    check("failclosed wrong arg", _scan(f1) == "MISS")
    # Non-credential (junk) should not hit
    check("honest junk", _scan("the quick brown fox jumps over the lazy dog") == "MISS")
    # Honest text with similar shape but no credential
    h1 = "var C=[1,2,3];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T?.slice(0);var RESULT=U;"
    check("honest non-cred", _scan(h1) == "MISS")

    # --- Sibling pins: neighboring findings still HIT ---
    # F2537 (previous wave) shape should still work
    sib = _shape("T['slice'](0)", SECRET20)  # F2381 shape
    check("sibling F2381", _scan(sib) == "HIT")

    # --- Perf: 200 sites ---
    t0 = time.time()
    for i in range(200):
        _scan(_shape("T?.slice(0)", SECRET20))
    dt = time.time() - t0
    check("perf 200 sites <300s", dt < 300)
    print(f"perf: {dt:.1f}s for 200 sites")

    # --- Summary ---
    print(f"\n{PASS.__len__()}/{PASS.__len__() + FAIL.__len__()} PASS")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)

if __name__ == "__main__":
    # Depth-1 green check: if GOV_SKIP_GREEN=1, skip (we are the green check)
    # Actually we ARE the battery; the green check is for our callers.
    # We honor it by not spawning child batteries.
    main()
