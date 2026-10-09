#!/usr/bin/env python3
"""Wave-370 lane 8: attack round 38 (continuous real-model attack).

Filed 2026-10-07 (local node validation + 3 gpt-4o-mini calls, hints only;
every filed shape hand-crafted and node-verified on v24.20.0).

New findings (12, all LOW, all OPEN), filed from F583:
- F583: key-laundering via terminal key reads (Object.keys join,
  Object.entries map-to-keys) -- 3 shapes.
- F584: URLSearchParams.getAll multi-value reads -- 2 shapes.
- F585: structuredClone of Map objects -- 2 shapes.
- F586: parenthesized new-expression receivers (Map, WeakRef) -- 2 shapes.
- F587: new Proxy member-read receivers (unparen get-trap; empty handler
  both spellings) -- 3 shapes.
- F588: Reflect.get with Symbol.for keys -- 2 shapes.
- F589: Map entries iteration reads -- 2 shapes.
- F590: directive prologues in Reflect.apply.call targets -- 2 shapes.
- F591: defineProperty accessor descriptors (arrow getters; fn-expr
  setters) -- 3 shapes.
- F592: for-in enumeration over object literals -- 2 shapes. CLOSED
  2026-10-07 wave-371 lane 6 (braced bodies + .member reads modeled).
- F593: WeakMap variable-identity keys -- 2 shapes.
- F594: for-in/for-of enumeration over bare arguments (documented
  F529/F533 fail-closed boundary, verified a genuine bypass) -- 2 shapes.
  CLOSED 2026-10-07 wave-371 lane 6 (bare-arguments accumulation modeled).

Mechanism note (verified this round): the decoder extracts and evaluates
string-expression SUBEXPRESSIONS regardless of wrapper, so every filed
shape is a genuine composition gap: a fragment-valued intermediate result
the composer cannot thread into outer string assembly. All filed shapes
node-verified EXACT (v24.20.0): 28/28 CRED-EXACT, 28/28 decoder-miss.
Junk-quiet controls pass. No injection attempts this round.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F570-F582 (round 37 + wave-369 merge, scope reconfirmed), F583-F591, F593
(this round; F592/F594 CLOSED 2026-10-07 wave-371 lane 6).

Closed pins (must BLOCK, else BREAK): F496, F503, F504, F505, F512 (spot),
F506, F513, F514, F515, F516, F517, F518, F519, F520 (wave-364, regression),
F521, F522, F523, F524, F525 (wave-365, regression), F526, F527, F528, F529,
F530, F531, F532, F533, F534, F535, F536 (wave-366/367, regression),
F537, F538, F539, F540, F541, F542, F543, F544, F545, F546 (wave-368, regression),
F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559,
F560, F561, F562, F563, F564, F565, F566, F567, F568, F569 (wave-369, regression).

Rides-with-documented-scope (validated, NOT filed):
- String.raw tagged-template WITH substitutions -- decoder HITS
  (subexpression extraction); dead.
- String.raw array-like raw -- IS F575's filed shape; already filed.
- Object.values on literals / .reverse() / entries map-to-values --
  decoder HITS; dead.
- TextEncoder/TextDecoder round-trip, atob(base64) -- decoder HITS; dead.
- URL pathname reads -- decoder HITS; dead.
- Default Array.sort() (no comparator) -- rides with F580's closure scope
  (wave-370 lane 5 brief models LITARR.sort()); merge verifies.
- JSON.stringify nested round-trip -- rides with F571's closure scope
  (wave-370 lane 2); merge verifies.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (no bypass; NOT filed).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent). NOT filed.
Dead/bogus round-38 proposals (validated locally, NOT filed):
- D1-raw-tag (String.raw`${'f1'}${'f2'}` -- decoder HITS; dead).
- D2-sort-tokens (['f1','f2'].sort() -- cannot yield exact credential
  with these tokens; malformed).
- D3-ownkeys-arr (Reflect.ownKeys length read -- fragment only; malformed).
- D4-keys-3 (3-key join -- not exact credential; malformed).
- D5-dataview (single-byte read -- not exact; fromCharCode path F500-closed).
- D6-wm-malformed (var-decl statement inside parens -- node SyntaxError;
  fixed shapes filed as F593).
- D7-accessor-malformed (defineProperty with extra arg -- node TypeError;
  fixed shapes filed as F591).
- D8-set-arrow (arrow setter -- `this` binds outer scope; not exact).
- D9-importmeta (import.meta in node -e -- SyntaxError; dead).
- D10-globalthis (no credential-exact shape; dead).
Model note: 3/3 prompts returned usable hints (0 timeouts); the model
independently surfaced the Map.values, Set-spread, and entries-map-key
shapes (values/set hints were decoder-HIT dead ends; entries-map-key
became F583's third shape). All filed shapes hand-crafted and
node-verified (v24.20.0). Junk-quiet controls pass. No injection
attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g370-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2144  # no new decision codes this round; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2144; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F583/F589 closed, next F597 (wave-371 lane 1)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-371 lane 1: F583/F589 CLOSED (next F597)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-371 lane 1: F583/F589 CLOSED (next F597)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f535_closed():
    """F535 CLOSED: member reads on object literals block."""
    hit = _blocked("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f541_closed():
    """F541 CLOSED: JSON.parse laundering blocks."""
    hit = _blocked("JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f546_closed():
    """F546 CLOSED: enumerating Reflect.apply bodies block."""
    hit = _blocked("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f547_closed():
    """F547 CLOSED (wave-369): array-literal element index reads block."""
    hit = _blocked("['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f548_closed():
    """F548 CLOSED (wave-369): Object.create prototype reads block."""
    hit = _blocked("Object.create({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f549_closed():
    """F549 CLOSED (wave-369): gopd terminal reads block."""
    hit = _blocked("Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f550_closed():
    """F550 CLOSED (wave-369): defineProperty value-adding blocks."""
    hit = _blocked("Object.defineProperty({},'c',{value:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f551_closed():
    """F551 CLOSED (wave-369): String.raw substitutions block."""
    hit = _blocked("String.raw({raw:['','','']},'%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f552_closed():
    """F552 CLOSED (wave-369): Symbol-keyed reads block."""
    hit = _blocked("({[Symbol.for('c')]:'%s'})[Symbol.for('c')]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f558_closed():
    """F558 CLOSED (wave-369): destructure-body apply targets block."""
    hit = _blocked("Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f560_closed():
    """F560 CLOSED (wave-369): directive prologues in IIFE dispatch block."""
    hit = _blocked("(function(){\"use strict\";var a=arguments;return a[0]+a[1];})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f563_closed():
    """F563 CLOSED (wave-369): Map.get reads block."""
    hit = _blocked("new Map([['c','%s']]).get('c')+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f567_closed():
    """F567 CLOSED (wave-369): anchor left-boundary guards hold."""
    hit = _blocked("xJSON.parse('{\"x\":[\"ab\"]}')")
    return ("HELD" if not hit else "BREAK", "quiet=%s" % (not hit))


# ------------------------------------------------- open pins (must miss)

@_t
def test_r38_f583_closed():
    """F583 CLOSED 2026-10-07 wave-371 lane 1: key-terminal reads block coded."""
    m1 = _blocked("Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B))
    m2 = _blocked("Object.entries({'%s':1,'%s':1}).map(e=>e[0]).join('')" % (_A, _B))
    m3 = _blocked("Object.entries({'%s':1,'%s':1}).map(([k])=>k).join('')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r38_f584_closed():
    """F584 CLOSED (wave-371 lane 2): URLSearchParams.getAll blocks coded."""
    m1 = _blocked("new URLSearchParams('q=%s&q=%s').getAll('q').join('')" % (_A, _B))
    m2 = _blocked("new URLSearchParams('q=%s&q=%s&q=zz').getAll('q').slice(0,2).join('')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_r38_f585_closed():
    """F585 CLOSED (wave-371 lane 3): structuredClone of Map blocks."""
    m1 = _blocked("structuredClone(new Map([['c','%s']])).get('c')+'%s'"
                  % (_A, _B))
    m2 = _blocked("structuredClone(new Map([['a','%s'],['b','%s']])).get('a')"
                  "+structuredClone(new Map([['a','%s'],['b','%s']])).get('b')"
                  % (_A, _B, _A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_r38_f586_closed():
    """F586 CLOSED (wave-371 lane 3): parenthesized new-expression
    receivers block."""
    m1 = _blocked("(new Map([['c','%s']])).get('c')+'%s'" % (_A, _B))
    m2 = _blocked("(new WeakRef({c:'%s'})).deref().c+'%s'" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p1_f587_closed():
    """F587 CLOSED (wave-371 lane 4): new Proxy member-read receivers block."""
    h1 = _blocked("new Proxy({c:'%s'},{get:(t,k)=>t[k]}).c+'%s'" % (_A, _B))
    h2 = _blocked("(new Proxy({c:'%s'},{}).c)+'%s'" % (_A, _B))
    h3 = _blocked("new Proxy({c:'%s'},{}).c+'%s'" % (_A, _B))
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_r38_f588_closed():
    """F588 CLOSED (wave-371 lane 2): Reflect.get Symbol.for keys block coded."""
    m1 = _blocked("Reflect.get({[Symbol.for('c')]:'%s'},Symbol.for('c'))+'%s'" % (_A, _B))
    m2 = _blocked("Reflect.get({[Symbol.for('k')]:{c:'%s'}},Symbol.for('k')).c+'%s'" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_r38_f589_closed():
    """F589 CLOSED 2026-10-07 wave-371 lane 1: Map entries iteration blocks coded."""
    m1 = _blocked("[...new Map([['c','%s']]).entries()][0][1]+'%s'" % (_A, _B))
    m2 = _blocked("[...new Map([['a','%s'],['b','%s']]).entries()].map(e=>e[1]).join('')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r38_f590_closed():
    """F590 CLOSED 2026-10-07 wave-371 lane 5: .call targets with
    directive prologues (incl. null receiver) now block coded."""
    h1 = not _misses("Reflect.apply.call(null,function(){\"use strict\";var a=arguments;return a[0]+a[1];},null,['%s','%s'])" % (_A, _B))
    h2 = not _misses("Reflect.apply.call(null,function(){'use strict';var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%s','%s'])" % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


@_t
def test_r38_f591_closed():
    """F591 CLOSED 2026-10-07 wave-371 lane 5: accessor descriptors
    (arrow getters, fn-expr setters) now block coded."""
    h1 = not _misses("Object.defineProperty({},'c',{get:()=>'%s'}).c+'%s'" % (_A, _B))
    h2 = not _misses("Object.defineProperty({},'c',{get:()=>{return '%s';}}).c+'%s'" % (_A, _B))
    h3 = not _misses("(function(){var o={};Object.defineProperty(o,'c',{set:function(v){this._c=v;}});o.c='%s';return o._c+'%s';})()" % (_A, _B))
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


@_t
def test_p1_f592_closed():
    """F592 CLOSED: for-in over object literals blocks (wave-371 lane 6)."""
    h1 = _blocked("(function(){var s='';var o={a:'%s',b:'%s'};for(var k in o){s+=o[k];}return s;})()" % (_A, _B))
    h2 = _blocked("(function(){var s='';var o={a:{v:'%s'},b:{v:'%s'}};for(var k in o){s+=o[k].v;}return s;})()" % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_r38_f593_closed():
    """F593 CLOSED (wave-371 lane 7): WeakMap variable-identity keys block.

    Wave-306 maintenance: this probe demonstrated the BREAK on the open
    tree; the closure models _JSObj WeakMap values node-exactly, so it
    now asserts the coded refusal instead.
    """
    b1 = dlp.find_credential(
        "(function(){var r={};return new WeakMap([[r,{c:'%s'}]])"
        ".get(r).c+'%s';})()" % (_A, _B)) is not None
    b2 = dlp.find_credential(
        "(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);"
        "return Object.assign({},m.get(r)).c+'%s';})()" % (_A, _B)
    ) is not None
    ok = b1 and b2
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f594_closed():
    """F594 CLOSED: for-in/for-of over bare arguments blocks (wave-371 lane 6)."""
    h1 = _blocked("(function(){var s='';for(var k in arguments){s+=arguments[k];}return s;})('%s','%s')" % (_A, _B))
    h2 = _blocked("(function(){var s='';for(var x of arguments){s+=x;}return s;})('%s','%s')" % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-369 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g370-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w369_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w369 battery's footer pin is stale by design: this lane filed
    # F583-F594, so its expected footer (open F570-F582 / next F583) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w369_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-369 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("BREAKS:", sorted(probe_breaks))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
