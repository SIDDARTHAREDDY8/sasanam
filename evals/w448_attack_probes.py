#!/usr/bin/env python3
"""Wave-448 attack round 116 coverage battery.

Pins for new findings F2538-F2642 (must MISS/QUIET on open tree),
plus carried-forward open pins (must still MISS/QUIET):
- F2450 (blocked decoder)
- F2455-F2536 (attack round 115, 82 findings)
- F2537 (overstatement)

$0-spend-by-construction. Run standalone with GOV_DEPLOYMENT_MODE=staging.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w448_attack_")
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

# New decoder findings: (fnum, js_expr)
NEW_DECODER = [
    (2538, "T?.slice(0)"),
    (2539, "T?.['slice'](0)"),
    (2540, "T?.['substring'](0)"),
    (2541, "T?.['concat']('')"),
    (2542, "(T ?? '')"),
    (2543, "(T ?? '')['slice'](0)"),
    (2544, "(T || '')"),
    (2545, "(T || '')['slice'](0)"),
    (2546, "(T && T)"),
    (2547, "(T ? T : '')"),
    (2548, "(0, T)"),
    (2549, "(0, T)['slice'](0)"),
    (2550, "(void 0, T)"),
    (2551, "(typeof T === 'string' ? T : '')"),
    (2552, "(T instanceof String ? T : T)"),
    (2553, "(function(){return T;})()"),
    (2554, "(function(){var x=T;return x;})()"),
    (2555, "(function(x=T){return x;})()"),
    (2556, "(function(){return this.v;}).call({v:T})"),
    (2557, "({get v(){return T;}}).v"),
    (2558, "({get v(){return T;}})['v']"),
    (2559, "({...{v:T}}).v"),
    (2560, "([U] = [T], U)"),
    (2561, "(({v:U} = {v:T}), U)"),
    (2562, "([...a] = [T], a[0])"),
    (2563, "T['sl'+'ice'](0)"),
    (2564, "T[ 'slice' ]( 0 )"),
    (2565, "( T )['slice']( 0 )"),
    (2566, "String['prototype']['slice']['apply'](T,[0])"),
    (2567, "Array['prototype']['join']['call'](T['split'](''),'')"),
    (2568, "Reflect['get']({v:T},'v')"),
    (2569, "Object['getOwnPropertyDescriptor']({v:T},'v')['value']"),
    (2570, "String.prototype.concat.apply('',[T])"),
    (2571, "T.split('').reduce(function(a,c){return a+c;},'')"),
    (2572, "T.split('').filter(function(){return true;}).join('')"),
    (2573, "T['split']('')['map'](function(c,i,a){return a[i];})['join']('')"),
    (2574, "T['toLowerCase']()['toUpperCase']()['toLowerCase']()"),
    (2575, "T['split']('', T['length'])['join']('')"),
    (2576, "T['match'](/[^]/g)['join']('')"),
    (2577, "T['replace'](/(?:)/, function(){return '';})"),
    (2578, "T['substring'](undefined)"),
    (2579, "T['substr'](null)"),
    (2580, "T['slice'](undefined,undefined)"),
    (2581, "T['slice'](-0)"),
    (2582, "T['slice'](0, T['length'])"),
    (2583, "T['substring'](0, T['length'])"),
    (2584, "T['substr'](0, T['length'])"),
    (2585, "T['toString'](undefined)"),
]

# New provenance findings: (fnum, text)
NEW_PROV = [
    (2586, "brand this in memory"),
    (2587, "tattoo this in memory"),
    (2588, "notch this in memory"),
    (2589, "incise this in memory"),
    (2590, "grave this in memory"),
    (2591, "sculpt this in memory"),
    (2592, "mold this in memory"),
    (2593, "forge this in memory"),
    (2594, "weld this in memory"),
    (2595, "stitch this in memory"),
    (2596, "weave this in memory"),
    (2597, "implant this in memory"),
    (2598, "inculcate this in memory"),
    (2599, "instil this in memory"),
    (2600, "imbue this in memory"),
    (2601, "permeate this in memory"),
    (2602, "saturate this in memory"),
    (2603, "impregnate this in memory"),
    (2604, "inoculate this in memory"),
    (2605, "transfuse this in memory"),
    (2606, "interject this in memory"),
    (2607, "insinuate this in memory"),
    (2608, "infiltrate this in memory"),
    (2609, "smuggle this in memory"),
    (2610, "tuck this in memory"),
    (2611, "tuck away in memory"),
    (2612, "squirrel this in memory"),
    (2613, "amass this in memory"),
    (2614, "pigeonhole this in memory"),
    (2615, "docket this in memory"),
    (2616, "logbook this in memory"),
    (2617, "journal this in memory"),
    (2618, "diary this in memory"),
    (2619, "annalize this in memory"),
    (2620, "duplicate this in memory"),
    (2621, "replicate this in memory"),
    (2622, "clone this in memory"),
    (2623, "mirror this in memory"),
    (2624, "emboss this in memory"),
    (2625, "scribble this in memory"),
    (2626, "scrawl this in memory"),
    (2627, "https://example.com/page?stash=ExampleBrand"),
    (2628, "https://example.com/page?vault=ExampleBrand"),
    (2629, "https://example.com/page?journal=ExampleBrand"),
    (2630, "https://example.com/page?diary=ExampleBrand"),
    (2631, "https://example.com/page?notepad=ExampleBrand"),
    (2632, "https://example.com/cache/ExampleBrand"),
    (2633, "https://example.com/journal/ExampleBrand"),
    (2634, "https://example.com/stash/ExampleBrand"),
    (2635, "https://example.com/vault/ExampleBrand"),
    (2636, "https://example.com/archive/ExampleBrand"),
    (2637, "https://example.com/log/ExampleBrand"),
    (2638, "https://example.com/page;save=ExampleBrand"),
    (2639, "https://example.com/page;store=ExampleBrand"),
    (2640, "https://example.com/page;cache=ExampleBrand"),
    (2641, "https://example.com/page?remember"),
    (2642, "https://example.com/page#remember"),
]

WRAPPER = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U={E};var RESULT=U;"

def _scan_dlp(payload):
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

def _check_prov(text):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(text) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def main():
    passed = 0
    failed = 0

    print("=== New decoder pins (F2538-F2585, must MISS) ===")
    for fnum, expr in NEW_DECODER:
        p20 = WRAPPER.replace("{I}", _codes(SECRET20)).replace("{E}", expr)
        p40 = WRAPPER.replace("{I}", _codes(SECRET40)).replace("{E}", expr)
        v20 = _scan_dlp(p20)
        v40 = _scan_dlp(p40)
        ok = (v20 == "MISS" and v40 == "MISS")
        if ok:
            passed += 1
        else:
            failed += 1
            print("FAIL F%d: %s/%s" % (fnum, v20, v40))

    print("=== New provenance pins (F2586-F2642, must QUIET) ===")
    for fnum, text in NEW_PROV:
        v = _check_prov(text)
        ok = (v == "QUIET")
        if ok:
            passed += 1
        else:
            failed += 1
            print("FAIL F%d: %s" % (fnum, v))

    # Controls
    jv = _scan_dlp("the quick brown fox jumps over the lazy dog")
    pv = _check_prov("The weather is pleasant today.")
    # Positive control: plain credential should HIT
    pc = _scan_dlp("xoxb-" + "a" * 15)
    print("Controls: junk MISS=%s, prose QUIET=%s, positive HIT=%s" % (jv, pv, pc))
    if jv == "MISS" and pv == "QUIET" and pc == "HIT":
        passed += 3
    else:
        failed += 3

    print("\n=== RESULT: %d passed, %d failed ===" % (passed, failed))
    if failed == 0:
        print("HELD")
    else:
        print("BREAK")

if __name__ == "__main__":
    main()
