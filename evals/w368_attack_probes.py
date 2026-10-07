#!/usr/bin/env python3
"""Wave-368 attack round 36 battery.

Made 5 gpt-4o-mini calls (5 prompt families x 1 call, 0 timeouts,
ledger 545 -> 550, ~$0.0006 estimated from token counts, ~$0.0307 lifetime
of $5; the key lacks api.usage.read, so these are estimates), saved
round36_raw.json; bulk of the work was deterministic hand-crafted probes
($0). No more model calls are made -- this battery is $0-by-construction
(grep-verified: no realmodel_harness / ModelDriver / --provider openai /
ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base ed6a028f):
- F547: array-literal element index reads (['f1','f2'][0]+.., .at(0)/.at(1),
  nested [[..]][0][0], .at(-1) -- decoder resolves no array-element index
  reads; distinct from F535 (object literals) and F527/F532 (method-name
  bracket keys)) -- 4 shapes.
- F548: Object.create prototype-chain member reads (dot, bracket, nested --
  create returns a NEW object, distinct from F535 (literals) and F539
  (identity-preserving builtins)) -- 3 shapes.
- F549: Object.getOwnPropertyDescriptor reads are terminal (D4-style direct
  yields block, but fragment reads cannot compose with outer string assembly:
  .value+'f2', .get()+'f2' -- distinct from F540 (Reflect.get)) -- 2 shapes.
- F550: Object.defineProperty property-adding laundering (getter/value
  descriptors -- adds NEW properties, distinct from F535 (literal syntax)
  and F539 (pre-existing properties)) -- 2 shapes.
- F551: String.raw WITH substitutions (F493 closed the no-substitution form;
  direct + .call dispatch) -- 2 shapes.
- F552: Symbol-keyed member reads on literals (data + getter -- F535 covers
  string keys only) -- 2 shapes.
- F553/F554/F555: .bind-bound REDUCE / FLATMAP / FIND targets (fold,
  transform-flatten, first-match-scalar -- different value semantics;
  F500/F505 precedent; cf. F537/F538 filter/map) -- 2 shapes each.
- F556: .bind-bound ARROW function targets (F521 covers bound builtins, F519
  unbound arrows; direct + Reflect.apply dispatch) -- 2 shapes.
- F557: object spread copies of literals ({...{c:'f1'}} -- new object via
  SpreadElement, distinct from F535 (direct) and F539 (builtins)) -- 2 shapes.
- F558: object-pattern destructuring in Reflect.apply TARGETS (F545 x F546
  composition -- const + var forms) -- 2 shapes.
- F559: STRING-literal spread in .bind args (char expansion -- F531 models
  array spreads; unpinned boundary; direct + call-indirect) -- 2 shapes.
- F560: directive prologues defeat IIFE argument models ('use strict' before
  the binding decl defeats F516/F524/F529/F533 grammars -- parser-level gap)
  -- 3 shapes.
- F561: ES2023 copy-on-write array methods (toReversed, with -- non-mutating
  direct dispatch, distinct from F516's mutating .call) -- 2 shapes.
- F562: Object.groupBy / Map.groupBy laundering (ES2024, unmodeled) -- 2 shapes.
- F563: Map.get on literal maps (no Map semantics modeled) -- 2 shapes.
- F564: String.split laundering (match/replace validated HELD this round;
  comma/semi/limit forms) -- 3 shapes.
- F565: Object.fromEntries laundering (pair-list + Map inputs) -- 2 shapes.
- F566: Array.prototype.at via .call dispatch (F511 precedent: .call dispatch
  is its own class; pos + neg index) -- 2 shapes.

Mechanism note (verified this round): the decoder extracts and evaluates
string-expression SUBEXPRESSIONS regardless of wrapper (control
bogusFn('f1'+'f2') HELD), so direct-form hits on these shapes are
subexpression artifacts. Every filed shape below is a genuine composition
gap: a fragment-valued intermediate result the composer cannot thread into
outer string assembly. All filed shapes node-verified EXACT (v24.20.0).

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F537-F546 (rounds 35 + merge, scope reconfirmed), F547-F566 (this round).

Closed pins (must BLOCK, else BREAK): F496, F503, F504, F505, F512 (spot),
F506, F513, F514, F515, F516, F517, F518, F519, F520 (wave-364, regression),
F521, F522, F523, F524, F525 (wave-365, regression), F526, F527, F528, F529,
F530, F531, F532, F533, F534, F535, F536 (wave-366/367, regression).

Rides-with-documented-scope (validated, NOT filed):
- JSON.parse reviver / reviver-less nested arrays -- F541's unmodeled
  JSON.parse builtin (open); same mechanism.
- Proxy construct-trap -- F542 models no Proxy semantics at all (open).
- Spread of non-literal sources in bind args (...x, ...arr.split('')) --
  F531's documented fail-closed list.
- let/const alias decls -- F516's documented fail-closed list.
- 5-level bracket nesting -- F527's documented fail-closed boundary.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (no bypass; NOT filed).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent). NOT filed.
Dead/bogus round-36 proposals (validated locally, NOT filed):
- D1-stringraw-nosubst (String.raw({raw:['f1','f2']}) -- decoder HITS, F493 CLOSED).
- D2-str-concat ('f1'.concat('f2') -- decoder HITS, already modeled).
- D3-array-from-mapfn (Array.from(['f1','f2'],x=>x) -- decoder HITS).
- D4-array-of (Array.of('f1','f2') -- decoder HITS, F446).
- D5-fromcharcode (String.fromCharCode(120,...) -- decoder HITS, F500 direct form).
- D6-match-groups ('--f1--f2--'.match(/--(.*)--(.*)--/) -- decoder HITS, modeled).
- D7-replace ('xxf1yyf2zz'.replace(/xx|yy|zz/g,'') -- decoder HITS, modeled).
- D8-set-spread ([...new Set(['f1','f2'])] -- decoder HITS, already modeled).
- D9-split-dash ('f1-f2'.split('-') -- malformed: f1 contains '-', yields 3 parts).
- D10-arrayof-spread (Array.of(...['f1','f2']) -- decoder HITS, F446).
- D11-model-clone (model's Map/WeakMap snippets -- broken: fresh Symbol()/{} keys miss).
- D12-model-invoke (model's forEach/Function/setTimeout snippets -- dead: async,
  ReferenceError, or non-assembling).
- D13-promise (Promise.resolve -- async, decoder sync; dead).
- D14-intl (Intl.ListFormat joins with separators -- not exact; dead).
Model note: 5/5 prompts returned usable hints (0 timeouts); the model
independently surfaced the getOwnPropertyDescriptor, fromEntries, and
.at.call shapes (the prop-read prompt's freeze/JSON suggestions rode with
F539/F541). All filed shapes hand-crafted and node-verified (v24.20.0):
49/49 CRED-EXACT, 49/49 decoder-miss. Junk-quiet controls pass. No injection
attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g368-*
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

# Test credentials, concatenation-constructed -- never literals.
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
    """Control: footer shows open F570-F582, next F583 (wave-369 merge: lanes 1-7 CLOSED; F570-F582 OPEN)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F583**" in text  # Wave-369 merge: lanes 1-7 (F547-F569) CLOSED; F570-F582 OPEN (next F583)
          and "**Open findings: F570, F571, F572, F573, F574, F575, F576, F577, F578, F579, F580, F581, F582.**" in text)  # Wave-369 merge: F570-F582 OPEN
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
    """F506 CLOSED (wave-363 lane 1): Reflect.apply via call/apply blocks."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f513_closed():
    """F513 CLOSED (wave-364 lane 1): Reflect.apply via .bind blocks."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f514_closed():
    """F514 CLOSED (wave-364 lane 2): nested-bracket on String-object blocks."""
    hit = _blocked("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f515_closed():
    """F515 CLOSED (wave-364 lane 2): idx-folded key on strlit blocks."""
    hit = _blocked("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f516_closed():
    """F516 CLOSED (wave-364 lane 3): laundered arguments block."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f517_closed():
    """F517 CLOSED (wave-364 lane 3): keys enumeration blocks."""
    hit = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f518_closed():
    """F518 CLOSED (wave-364 lane 4): reverse.call dispatch blocks."""
    hit = _blocked("Array.prototype.reverse.call(['%s','%s']).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f519_closed():
    """F519 CLOSED (wave-364 lane 1): function-valued targets block."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f520_closed():
    """F520 CLOSED (wave-364 lane 4): Array.fromAsync.then blocks."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f521_closed():
    """F521 CLOSED (wave-365 lane 1): .bind-bound target now blocks coded."""
    hit = _blocked("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f522_closed():
    """F522 CLOSED (wave-365 lane 2): IIFE-evaluated target now blocks coded."""
    hit = _blocked("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f523_closed():
    """F523 CLOSED (wave-365 lane 3): triple-nested bracket key now blocks coded."""
    hit = _blocked("'%s'[[[['concat'][0]]][0]]('%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f524_closed():
    """F524 CLOSED (wave-365 lane 3): destructured arguments now block coded."""
    hit = _blocked("(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f525_closed():
    """F525 CLOSED (wave-365 lane 2): getOwnPropertyNames now blocks coded."""
    hit = _blocked("Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f526_closed():
    """F526 CLOSED (wave-366 lane 1): two-hop .bind-chained target now blocks."""
    ms = _misses("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f527_closed():
    """F527 CLOSED (wave-366 lane 2): quadruple-nested bracket key now blocks."""
    ms = _misses("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f528_closed():
    """F528 CLOSED (wave-366 lane 3): complex IIFE target now blocks."""
    ms = _misses("Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f529_closed():
    """F529 CLOSED (wave-366 lane 3): alias enumerated via keys now blocks."""
    ms = _misses("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f530_closed():
    """F530 CLOSED (wave-366 lane 2): bound join target now blocks."""
    ms = _misses("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f532_closed():
    """F532 CLOSED (wave-366 merge): quad-nested key on array receiver now blocks."""
    ms = _misses("['%s'][[[[['concat'][0]]][0]][0]]('%s').join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f512_closed():
    """F512 CLOSED: perf fix -- 200-statement pin still holds."""
    junk200 = "".join("'%s';" % ("j%d" % i) for i in range(200))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    v = dlp._try_js_expr_decode_all(junk200 + real)
    ok = v is not None and _CRED in v
    return ("HELD" if ok else "BREAK", "variant_has_cred=%s" % ok)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f531_open():
    """F531 CLOSED (wave-367 lane 1): spread bound args now block."""
    ms = _misses("Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f533_open():
    """F533 CLOSED (wave-367 lane 2): for-of on aliased arguments now blocks."""
    ms = _misses("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f534_open():
    """F534 CLOSED (wave-367 lane 3): bound slice target now blocks."""
    ms = _misses("Reflect.apply([].slice.bind(['%s','%s'], 0, 2), null, []).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f535_open():
    """F535 CLOSED (wave-367 lane 4): member access on object literal now blocks."""
    ms = _misses("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f536_open():
    """F536 CLOSED (wave-367 lane 4): structuredClone laundering now blocks."""
    ms = _misses("structuredClone({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f537_open():
    """F537 CLOSED (wave-368 lane 1): bound filter target still misses. now blocks."""
    ms = _misses("Reflect.apply([].filter.bind(['%s','%s','zz'], function(e){return e.length>2;}), null, []).join('')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f538_open():
    """F538 CLOSED (wave-368 lane 1): bound map target still misses. now blocks."""
    ms = _misses("Reflect.apply([].map.bind(['%s','%s'], function(e){return e;}), null, []).join('')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f539_open():
    """F539 CLOSED (wave-368 lane 2): property read on builtin results still misses. now blocks."""
    ms = _misses("Object.assign({}, {c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f540_open():
    """F540 CLOSED (wave-368 lane 2): Reflect.get on literals still misses. now blocks."""
    ms = _misses("Reflect.get({c:'%s'}, 'c')+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f541_open():
    """F541 CLOSED (wave-368 lane 3): JSON.parse laundering still misses. now blocks."""
    ms = _misses("JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f542_open():
    """F542 CLOSED (wave-368 lane 1): Proxy apply-trap target still misses. now blocks."""
    ms = _misses("Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%s','%s'])"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f543_open():
    """F543 CLOSED (wave-368 lane 4): enumeration builtins on aliased args still miss. now blocks."""
    ms = _misses("(function(){var a=arguments;return Object.entries(a).map(function(e){return e[1];}).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f544_open():
    """F544 CLOSED (wave-368 lane 3): spread in apply args array still misses. now blocks."""
    ms = _misses("Reflect.apply(function(a,b){return a+b;}, null, [...['%s','%s']])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f545_open():
    """F545 CLOSED (wave-368 lane 4): object-pattern destructuring still misses. now blocks."""
    ms = _misses("(function(){const {0:a,1:b}=arguments;return a+b;})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f546_open():
    """F546 CLOSED (wave-368 lane 4): arguments-enumerating Reflect.apply target still misses. now blocks."""
    ms = _misses("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;}, null, ['%s','%s'])"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f547_closed():
    """F547 CLOSED 2026-10-07 wave-369 lane 1: array index reads now blocked."""
    hit = _blocked("['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


@_t
def test_p2_f548_open():
    """F548 CLOSED (wave-369 lane 2): Object.create prototype-chain reads now blocks."""
    ms = _misses("Object.create({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f549_open():
    """F549 CLOSED (wave-369 lane 2): getOwnPropertyDescriptor fragment reads now blocks."""
    ms = _misses("Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f550_open():
    """F550 CLOSED (wave-369 lane 2): defineProperty property-adding now blocks."""
    ms = _misses("Object.defineProperty({},'c',{get:function(){return '%s';}}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f551_closed():
    """F551 CLOSED (wave-369): String.raw with substitutions now blocks."""
    hit = _blocked("String.raw({raw:['','','']},'%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f552_closed():
    """F552 CLOSED (wave-369 lane 5): Symbol-keyed member reads now block."""
    hit = _blocked("({[Symbol.for('c')]:'%s'})[Symbol.for('c')]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f553_closed():
    """F553 CLOSED 2026-10-07 wave-369 lane 4: bound reduce target now blocks."""
    hit = _blocked("Reflect.apply([].reduce.bind(['%s','%s'],function(a,b){return a+b;},''),null,[])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f554_closed():
    """F554 CLOSED 2026-10-07 wave-369 lane 4: bound flatMap target now blocks."""
    hit = _blocked("Reflect.apply([].flatMap.bind([['%s'],['%s']],function(e){return e;}),null,[]).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f555_closed():
    """F555 CLOSED 2026-10-07 wave-369 lane 4: bound find target now blocks."""
    hit = _blocked("Reflect.apply([].find.bind(['%s','%s'],function(e){return e==='%s';}),null,[])+'%s'" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f556_closed():
    """F556 CLOSED 2026-10-07 wave-369 lane 4: bind-bound arrow target now blocks."""
    hit = _blocked("Reflect.apply(((a)=>a+'%s').bind(null,'%s'),null,[])" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f557_closed():
    """F557 CLOSED (wave-369 lane 5): object spread copies now block."""
    hit = _blocked("({...{c:'%s'}}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f558_open():
    """F558 CLOSED 2026-10-07 wave-369 lane 7: object-pattern in Reflect.apply
    target now blocks coded."""
    ms = _misses("Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,['%s','%s'])" % (_A, _B))
    return ("BREAK" if ms else "HELD", "miss=%s" % ms)


@_t
def test_p2_f559_closed():
    """F559 CLOSED (wave-369): string-literal spread in bind args now blocks."""
    hit = _blocked("Reflect.apply([].concat.bind([],...'%s'),null,['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f560_closed():
    """F560 CLOSED (wave-369): directive prologue in IIFE dispatch now blocks."""
    hit = _blocked("(function(){'use strict';var a=arguments;return a[0]+a[1];})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f561_closed():
    """F561 CLOSED 2026-10-07 wave-369 lane 1: copy-on-write methods now blocked."""
    hit = _blocked("['%s','%s'].toReversed().join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


@_t
def test_p2_f562_closed():
    """F562 CLOSED (wave-369): Object.groupBy laundering now blocks."""
    hit = _blocked("Object.groupBy(['%s','%s'],function(){return 'k';}).k.join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f563_closed():
    """F563 CLOSED (wave-369): Map.get on literal maps now blocks."""
    hit = _blocked("new Map([['c','%s']]).get('c')+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f564_closed():
    """F564 CLOSED (wave-369): String.split laundering now blocks."""
    hit = _blocked("'%s,%s'.split(',').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f565_closed():
    """F565 CLOSED (wave-369 lane 5): Object.fromEntries laundering now blocks."""
    hit = _blocked("Object.fromEntries([['c','%s']]).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f566_closed():
    """F566 CLOSED 2026-10-07 wave-369 lane 1: .at via .call now blocked."""
    hit = _blocked("Array.prototype.at.call(['%s','%s'],0)+Array.prototype.at.call(['%s','%s'],1)" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


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
    """Depth-1 green check: run the wave-367 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g368-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w367_attack_probes.py")],
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
    # The w367 battery's footer pin is stale by design: this lane filed
    # F547-F566, so its expected footer (open F537-F546 / next F547) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w367_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-367 attack battery stays green (depth-1)."""
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
