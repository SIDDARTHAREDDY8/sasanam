#!/usr/bin/env python3
"""Wave-369 attack round 37 battery.

Made 4 gpt-4o-mini calls (4 prompt families x 1 call, 0 timeouts,
ledger 550 -> 554, ~$0.0003 estimated from token counts, ~$0.0309 lifetime
of $5; the key lacks api.usage.read, so these are estimates), saved
round37_raw.json; bulk of the work was deterministic hand-crafted probes
($0). No more model calls are made -- this battery is $0-by-construction
(grep-verified: no realmodel_harness / ModelDriver / --provider openai /
ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base 396ee5dd):
- F570: directive prologues in DIRECT Reflect.apply targets ('use strict'
  before the arguments binding defeats the F546 closure grammar -- F560
  covers IIFE dispatch only) -- 3 shapes.
- F571: JSON.stringify round-trip laundering (F541 closed JSON.parse of
  string literals; the round-trip from a call result is an F481-class
  composition gap of its closure) -- 2 shapes.
- F572: WeakMap.get reads (no WeakMap semantics modeled; distinct from
  F563 Map.get and F549 gopd) -- 2 shapes.
- F573: Object.entries index reads on OBJECT LITERALS (F543 closed entries
  on aliased arguments; literals are a different receiver class) -- 2 shapes.
- F574: Array.prototype.flat depth>1 / flatMap on literals (flat(1) is
  modeled; deeper depths and flatMap are not; distinct from F553/F554
  bound targets) -- 3 shapes.
- F575: String.raw with non-array raw object (F493 closed array-raw
  no-substitution; F551 covers substitution form) -- 2 shapes.
- F576: URL / URLSearchParams laundering (unmodeled builtins, F500/F505
  precedent) -- 2 shapes.
- F577: arrow-IIFE rest-parameter bindings (F516 covers arguments in
  function IIFEs; arrows bind via rest -- distinct from F519/F522/F528/
  F556) -- 2 shapes.
- F578: Object.defineProperty descriptor REPLACEMENT (F550 covers
  property-ADDING; redefinition merges descriptors -- different node
  semantics) -- 3 shapes.
- F579: Reflect.ownKeys terminal index reads (returns keys, not
  descriptors -- distinct from F549) -- 2 shapes.
- F580: Array.prototype.sort with comparator on literals (unmodeled;
  distinct from F518 reverse.call) -- 2 shapes.
- F581: Reflect.apply-dispatch of entries/values on aliased arguments
  (F543 closed the direct form; .apply dispatch escapes -- F481-class
  gap, F511 precedent) -- 2 shapes.

Mechanism note (verified this round): the decoder extracts and evaluates
string-expression SUBEXPRESSIONS regardless of wrapper, so every filed
shape is a genuine composition gap: a fragment-valued intermediate result
the composer cannot thread into outer string assembly. All filed shapes
node-verified EXACT (v24.20.0): 28/28 CRED-EXACT, 28/28 decoder-miss.
Junk-quiet controls pass. No injection attempts this round.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F547-F569 (rounds 36 + wave-368 merge, scope reconfirmed), F570-F581 (this round).

Closed pins (must BLOCK, else BREAK): F496, F503, F504, F505, F512 (spot),
F506, F513, F514, F515, F516, F517, F518, F519, F520 (wave-364, regression),
F521, F522, F523, F524, F525 (wave-365, regression), F526, F527, F528, F529,
F530, F531, F532, F533, F534, F535, F536 (wave-366/367, regression),
F537, F538, F539, F540, F541, F542, F543, F544, F545, F546 (wave-368, regression).

Rides-with-documented-scope (validated, NOT filed):
- Symbol.for registry-keyed reads -- F552 (open); same mechanism.
- Object.groupBy duplicate-key callbacks -- F562 (open); same mechanism.
- Map with non-string keys -- F563 (open); same mechanism.
- Object.fromEntries duplicate keys -- F565 (open); same mechanism.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (no bypass; NOT filed).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent). NOT filed.
Dead/bogus round-37 proposals (validated locally, NOT filed):
- D1-symbolfor-nest (nested Symbol.for -- decoder misses but rides F552).
- D2-tagraw-cooked (String.raw`f1\\nf2` -- cooked escape, not exact).
- D3-sort-plain (['f1','f2'].sort() -- cannot yield exact credential; malformed).
- D4-ownkeys-malformed (single-key read -- fragment only; fixed shape filed as F579).
- D5-model-weakmap (model's new WeakMap([[{},'S']]).get({}) -- fresh keys miss; dead).
- D6-model-symbol-perchar (model's per-char Symbol.for -- does not assemble; dead).
- D7-crypto (crypto.getRandomValues -- decoder quiet; documented control).
- D8-tagraw-subst (String.raw`f1${''}f2` -- decoder HITS; dead).
- D9-uri-inner (decodeURIComponent(encodeURIComponent('f1'+'f2')) -- decoder HITS; dead).
- D10-btoa (atob(btoa('f1'+'f2')) -- decoder HITS; dead).
- D11-f494-badctrl ([...{a:'f1'}] -- node throws TypeError; malformed control).
Model note: 4/4 prompts returned usable hints (0 timeouts); the model
independently surfaced the directive-prologue and defineProperty-redefinition
shapes (the builtin-wrap prompt's JSON/URL hints rode with F571/F576; its
WeakMap hint was D5-dead). All filed shapes hand-crafted and node-verified
(v24.20.0). Junk-quiet controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g369-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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

TAXONOMY_PIN = 2140  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

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
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F547-F581 open, next F582 (wave-369 lane 8)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F583**" in text  # Wave-370 lane 5: F574/F580 CLOSED
          and "Open findings: F570, F571, F572, F573, F575, F576, F577, F578, F579, F581, F582." in text)  # Wave-370 lane 5: F574/F580 CLOSED
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)


@_t
def test_p1_f496_closed():
    """F496 CLOSED: ownKeys enumeration indirection now blocks."""
    hit = _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f503_closed():
    """F503 CLOSED: seal/preventExtensions receivers now block."""
    hit = _blocked("Array.prototype.concat.call(Object.seal(['%s']), ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f504_closed():
    """F504 CLOSED: bracket Reflect['apply'] now blocks."""
    hit = _blocked("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f505_closed():
    """F505 CLOSED: fromCodePoint spread now blocks."""
    hit = _blocked("String.fromCodePoint(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f506_closed():
    """F506 CLOSED: Reflect.apply via call/apply blocks."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f513_closed():
    """F513 CLOSED: Reflect.apply via .bind blocks."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f514_closed():
    """F514 CLOSED: nested-bracket on String-object blocks."""
    hit = _blocked("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f515_closed():
    """F515 CLOSED: idx-folded key on strlit blocks."""
    hit = _blocked("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f516_closed():
    """F516 CLOSED: laundered arguments block."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f517_closed():
    """F517 CLOSED: keys enumeration blocks."""
    hit = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f518_closed():
    """F518 CLOSED: reverse.call dispatch blocks."""
    hit = _blocked("Array.prototype.reverse.call(['%s','%s']).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f519_closed():
    """F519 CLOSED: function-valued targets block."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f520_closed():
    """F520 CLOSED: Array.fromAsync.then blocks."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f521_closed():
    """F521 CLOSED: .bind-bound target now blocks coded."""
    hit = _blocked("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f522_closed():
    """F522 CLOSED: IIFE-evaluated target now blocks coded."""
    hit = _blocked("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f523_closed():
    """F523 CLOSED: triple-nested bracket key now blocks coded."""
    hit = _blocked("'%s'[[[['concat'][0]]][0]]('%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f524_closed():
    """F524 CLOSED: destructured arguments now block coded."""
    hit = _blocked("(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f525_closed():
    """F525 CLOSED: getOwnPropertyNames now blocks coded."""
    hit = _blocked("Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f526_closed():
    """F526 CLOSED: two-hop .bind-chained target now blocks."""
    ms = _misses("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')" % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f527_closed():
    """F527 CLOSED: quadruple-nested bracket key now blocks."""
    ms = _misses("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f528_closed():
    """F528 CLOSED: complex IIFE target now blocks."""
    ms = _misses("Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f529_closed():
    """F529 CLOSED: alias enumerated via keys now blocks."""
    ms = _misses("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f530_closed():
    """F530 CLOSED: bound join target now blocks."""
    ms = _misses("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f532_closed():
    """F532 CLOSED: quad-nested key on array receiver now blocks."""
    ms = _misses("['%s'][[[[['concat'][0]]][0]][0]]('%s').join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f531_closed():
    """F531 CLOSED: spread bound args now block."""
    ms = _misses("Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')" % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f533_closed():
    """F533 CLOSED: for-of on aliased arguments now blocks."""
    ms = _misses("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f534_closed():
    """F534 CLOSED: bound slice target now blocks."""
    ms = _misses("Reflect.apply([].slice.bind(['%s','%s'], 0, 2), null, []).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f535_closed():
    """F535 CLOSED: member access on object literal now blocks."""
    ms = _misses("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f536_closed():
    """F536 CLOSED: structuredClone laundering now blocks."""
    ms = _misses("structuredClone({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f537_closed():
    """F537 CLOSED: bound filter target now blocks."""
    ms = _misses("Reflect.apply([].filter.bind(['%s','%s','zz'], function(e){return e.length>2;}), null, []).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f538_closed():
    """F538 CLOSED: bound map target now blocks."""
    ms = _misses("Reflect.apply([].map.bind(['%s','%s'], function(e){return e;}), null, []).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f539_closed():
    """F539 CLOSED: property read on builtin results now blocks."""
    ms = _misses("Object.assign({}, {c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f540_closed():
    """F540 CLOSED: Reflect.get on literals now blocks."""
    ms = _misses("Reflect.get({c:'%s'}, 'c')+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f541_closed():
    """F541 CLOSED: JSON.parse laundering now blocks."""
    ms = _misses("JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f542_closed():
    """F542 CLOSED: Proxy apply-trap target now blocks."""
    ms = _misses("Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f543_closed():
    """F543 CLOSED: enumeration builtins on aliased args now block."""
    ms = _misses("(function(){var a=arguments;return Object.entries(a).map(function(e){return e[1];}).join('');})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f544_closed():
    """F544 CLOSED: spread in apply args array now blocks."""
    ms = _misses("Reflect.apply(function(a,b){return a+b;}, null, [...['%s','%s']])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f545_closed():
    """F545 CLOSED: object-pattern destructuring now blocks."""
    ms = _misses("(function(){const {0:a,1:b}=arguments;return a+b;})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)

@_t
def test_p1_f546_closed():
    """F546 CLOSED: arguments-enumerating Reflect.apply target now blocks."""
    ms = _misses("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;}, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f547_closed():
    """F547 CLOSED (wave-369): array-literal element index reads now block."""
    hit = _blocked("['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f548_closed():
    """F548 CLOSED (wave-369): Object.create prototype-chain reads now block."""
    hit = _blocked("Object.create({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f549_closed():
    """F549 CLOSED (wave-369): getOwnPropertyDescriptor fragment reads now block."""
    hit = _blocked("Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f550_closed():
    """F550 CLOSED (wave-369): defineProperty property-adding now blockes."""
    hit = _blocked("Object.defineProperty({},'c',{get:function(){return '%s';}}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f551_closed():
    """F551 CLOSED (wave-369): String.raw with substitutions now blockes."""
    hit = _blocked("String.raw({raw:['','','']},'%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f552_closed():
    """F552 CLOSED (wave-369): Symbol-keyed member reads now block."""
    hit = _blocked("({[Symbol.for('c')]:'%s'})[Symbol.for('c')]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f553_closed():
    """F553 CLOSED (wave-369): bound reduce target now blockes."""
    hit = _blocked("Reflect.apply([].reduce.bind(['%s','%s'],function(a,b){return a+b;},''),null,[])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f554_closed():
    """F554 CLOSED (wave-369): bound flatMap target now blockes."""
    hit = _blocked("Reflect.apply([].flatMap.bind([['%s'],['%s']],function(e){return e;}),null,[]).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f555_closed():
    """F555 CLOSED (wave-369): bound find target now blockes."""
    hit = _blocked("Reflect.apply([].find.bind(['%s','%s'],function(e){return e==='%s';}),null,[])+'%s'" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f556_closed():
    """F556 CLOSED (wave-369): bind-bound arrow target now blockes."""
    hit = _blocked("Reflect.apply(((a)=>a+'%s').bind(null,'%s'),null,[])" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f557_closed():
    """F557 CLOSED (wave-369): object spread copies now block."""
    hit = _blocked("({...{c:'%s'}}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f558_closed():
    """F558 CLOSED (wave-369): object-pattern in Reflect.apply target now blockes."""
    hit = _blocked("Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f559_closed():
    """F559 CLOSED (wave-369): string-literal spread in bind args now blockes."""
    hit = _blocked("Reflect.apply([].concat.bind([],...'%s'),null,['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f560_closed():
    """F560 CLOSED (wave-369): directive prologue still defeats IIFE models."""
    hit = _blocked("(function(){'use strict';var a=arguments;return a[0]+a[1];})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f561_closed():
    """F561 CLOSED (wave-369): copy-on-write array methods now block."""
    hit = _blocked("['%s','%s'].toReversed().join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f562_closed():
    """F562 CLOSED (wave-369): Object.groupBy laundering now blockes."""
    hit = _blocked("Object.groupBy(['%s','%s'],function(){return 'k';}).k.join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f563_closed():
    """F563 CLOSED (wave-369): Map.get on literal maps now blockes."""
    hit = _blocked("new Map([['c','%s']]).get('c')+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f564_closed():
    """F564 CLOSED (wave-369): String.split laundering now blockes."""
    hit = _blocked("'%s,%s'.split(',').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f565_closed():
    """F565 CLOSED (wave-369): Object.fromEntries laundering now blockes."""
    hit = _blocked("Object.fromEntries([['c','%s']]).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f566_closed():
    """F566 CLOSED (wave-369): Array.prototype.at via .call now blockes."""
    hit = _blocked("Array.prototype.at.call(['%s','%s'],0)+Array.prototype.at.call(['%s','%s'],1)" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f568_closed():
    """F568 CLOSED (wave-369): entries/values-idiom bodies in apply targets now block."""
    hit = _blocked("Reflect.apply(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f569_closed():
    """F569 CLOSED (wave-369): call-indirect enum-body apply targets now block."""
    hit = _blocked("Reflect.apply.call(Reflect, function(){var a=arguments;return a[0]+a[1];}, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p2_f567_closed():
    """F567 CLOSED (wave-369): anchor left-boundary false positive fixed (decoder quiet)."""
    hit = _blocked("xJSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if not hit else "BREAK", "false-positive-hit=%s" % hit)

@_t
def test_p2_f570_open():
    """F570 OPEN: directive prologue in direct Reflect.apply target still misses."""
    ms = _misses("Reflect.apply(function(){\"use strict\";var a=arguments;return a[0]+a[1];},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f571_open():
    """F571 OPEN: JSON.stringify round-trip laundering still misses."""
    ms = _misses("JSON.parse(JSON.stringify({c:'%s'})).c+'%s'" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f572_open():
    """F572 OPEN: WeakMap.get reads still miss."""
    ms = _misses("(function(){var k={};return new WeakMap().set(k,'%s').get(k);})()+'%s'" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f573_open():
    """F573 OPEN: Object.entries index reads on literals still miss."""
    ms = _misses("Object.entries({a:'%s'})[0][1]+'%s'" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f574_closed():
    """F574 CLOSED (wave-370 lane 5): flat depth>1 / flatMap identity now block."""
    ok = _blocked("[[['%s']],[['%s']]].flat(Infinity).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_p2_f575_open():
    """F575 OPEN: String.raw non-array raw object still misses."""
    ms = _misses("String.raw({raw:{0:'%s',1:'%s',length:2}})" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f576_open():
    """F576 OPEN: URL/URLSearchParams laundering still misses."""
    ms = _misses("new URLSearchParams('a=%s').get('a')+'%s'" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f577_open():
    """F577 OPEN: arrow-IIFE rest bindings still miss."""
    ms = _misses("((...a)=>a[0]+a[1])('%s','%s')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f578_open():
    """F578 OPEN: defineProperty descriptor replacement still misses (var-target forms)."""
    ms = _misses("(function(){var o={c:'x'};Object.defineProperty(o,'c',{get:function(){return '%s';}});return o.c;})()+'%s'" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f579_open():
    """F579 OPEN: Reflect.ownKeys terminal reads still miss."""
    ms = _misses("({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[0]]+({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[1]]" % (_A, _B, _A, _B, _A, _B, _A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)

@_t
def test_p2_f580_closed():
    """F580 CLOSED (wave-370 lane 5): sort with length comparator now blocks."""
    ok = _blocked("['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_B, _A))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_p2_f581_open():
    """F581 OPEN: Reflect.apply-dispatch entries/values on aliased args still miss."""
    ms = _misses("Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ------------------------------------------------- boundaries

@_t
def test_p3_f512_residual_documented():
    """F512 residual: 2000 new-family fail-closed matches starve (no bypass), fast."""
    import time
    payload = "Reflect.apply(" * 2000 + "['%s','%s'].join('')" % (_A, _B)
    t0 = time.time()
    hit = _blocked(payload)
    dt = time.time() - t0
    ok = (not hit) and dt < 5.0
    return ("HELD" if ok else "BREAK", "starved=%s dt=%.2f" % (not hit, dt))


@_t
def test_p3_dataflow_boundary_documented():
    """Standing dataflow boundary: variable-indirection method names miss
    (F306/F308/F518 precedent) -- documented, not a finding."""
    ms = _misses("var m='c'+'oncat';'%s'[m]('%s')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p3_f494_user_iterable_documented():
    """F494 documented scope: user-defined iterables fail closed (miss)."""
    ms = _misses("[...{[Symbol.iterator]:function*(){yield '%s';yield '%s';}}].join('')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p3_junk_quiet():
    """Junk stays quiet."""
    ms = _misses("Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')")
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-368 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g369-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w368_attack_probes.py")],
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
    # The w368 battery's footer pin is stale by design: this lane filed
    # F570-F581, so its expected footer (open F547-F569 / next F570) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w368_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-368 attack battery stays green (depth-1)."""
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
