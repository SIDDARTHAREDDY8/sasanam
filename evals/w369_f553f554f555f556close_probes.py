#!/usr/bin/env python3
"""Wave-369 F553/F554/F555/F556 closure battery (lane 4).

Four LOW findings from wave-368 attack round 36 (node v24.20.0 ->
credential, decoder missed on the wave-368-merged base) -- the
bound-builtin family, F500/F505 per-builtin precedent:

F553: Reflect.apply with a .bind-bound REDUCE target.
  F521 models .bind-bound CONCAT targets, F530 JOIN, F534 SLICE, F537
  FILTER, F538 MAP -- but reduce FOLDS with different value semantics:
    Reflect.apply([].reduce.bind(['f1','f2'],function(a,b){return a+b;},''),null,[])
    Reflect.apply.call(Reflect,[].reduce.bind(['f1','f2'],function(a,b){return a+b;},''),null,[])
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct per the F500/F505 precedent.

F554: Reflect.apply with a .bind-bound FLATMAP target.
  flatMap transforms AND flattens (1:N), distinct from map's 1:1
  transform (F538) and filter's selection (F537):
    Reflect.apply([].flatMap.bind([['f1'],['f2']],function(e){return e;}),null,[]).join('')
    Reflect.apply.call(Reflect,[].flatMap.bind([['f1'],['f2']],function(e){return e;}),null,[]).join('')

F555: Reflect.apply with a .bind-bound FIND target.
  find selects the FIRST match and returns a SCALAR, distinct from
  filter's array result (F537) and map's transform (F538):
    Reflect.apply([].find.bind(['f1','f2'],function(e){return e==='f1';}),null,[])+'f2'
    Reflect.apply.call(Reflect,[].find.bind(['f1','f2'],function(e){return e==='f1';}),null,[])+'f2'

F556: .bind-bound arrow/function targets.
  F521 models bound CONCAT (builtin) targets and F519 models UNBOUND
  arrow targets, but a .bind-bound arrow is unmodeled:
    ((a)=>a+'f2').bind(null,'f1')()
    Reflect.apply(((a)=>a+'f2').bind(null,'f1'),null,[])

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f553f554f555_bound_head` -- the shared `[].NAME` /
    `Array.prototype.NAME` receiver+member head (ws-tolerant,
    ident-boundary-checked; inner member dot-only, F506 precedent).
  * `_js_parse_f553_bound_reduce_target` -- `[].reduce.bind(BINDTHIS,
    CB[, INIT])`; CB parsed by `_js_parse_fn_target` (F519 additive
    body); INIT a string literal or absent (acc starts at elements[0];
    empty BINDTHIS with no INIT fails closed -- node throws). When
    INIT is unbound and the call supplies args, the first call arg
    becomes INIT (node v24.20.0: `B.reduce(CB, C[0])`); a bound INIT
    wins and the call args are ignored. The fold is node-exact: body operands index the declared params (slot 0 =
    accumulator, slot 1 = element); a third-or-later param reference
    (index/array -- undecidable) fails closed. Returns the scalar.
  * `_js_parse_f554_bound_flatmap_target` -- `[].flatMap.bind(BINDTHIS,
    CB)`; BINDTHIS elements are arrays-of-plain-strings or plain
    strings (deeper nesting fails closed); CB the shared identity
    grammar (`_js_parse_map_callback`) -- the bare String form fails
    closed here (String(['f1','f2']) === 'f1,f2', not identity over
    array elements). Identity + one-level flatten, node-exact.
    Returns a _JSArr (flatMap yields an array).
  * `_js_parse_f555_eq_predicate` -- `(p)=>p==='lit'` / `p=>p=='lit'` /
    `function(p){return p==='lit';}` (loose == over strings is
    engine-identical to ===, node-verified); find returns the first
    equal element; no match fails closed (node: undefined).
  * `_js_parse_f556_additive_body` / `_js_parse_f556_fn_target` --
    F519's target grammar with string-literal operands admitted
    (`a+'f2'`); `_js_parse_f556_bound_arrow_target` parses
    `(FN).bind(BT, lit, ...)` (BT parsed-and-discarded -- arrows
    ignore the receiver; modeled bodies never reference `this`).
    Invocation args = bound args then call args; extras beyond the
    declared params are dropped (the engine ignores them, node
    v24.20.0); fewer args than params fail closed. Three call sites: the
    direct `(FN).bind(...)()` invocation
    (`_js_parse_f556_bound_arrow_call`, hooked in `_js_parse_primary`),
    `Reflect.apply(BOUNDARROW, thisArg, argsList)` (new "boundarrow"
    peek in `_js_peek_reflect_apply_target` -- string-aware
    close-paren scan via `_js_scan_close_paren`), and the F521
    call-dispatch / F513 bind-indirect fallbacks.
  * New peeks "boundreduce" / "boundflatmap" / "boundfind" (both
    receiver classes, bind-lookahead only). F513
    (`Reflect.apply.bind(Reflect)(...)`) and F521
    (`Reflect.apply.call(Reflect, ...)`) gain F553/F554/F555
    fallbacks nested after F538 and F556 after F544; every raise
    commits nothing on the next parser's input (member/receiver
    check first), so the fallbacks are clean. The F521
    call-dispatch chain was additionally flattened into a loop --
    the nesting hit Python's static block limit; the loop is
    verdict-identical to the nested chain.

Fail closed (documented, never mis-decoded): non-literal BINDTHIS,
non-plain-string elements, zero/extra bound args, non-modeled
callbacks (e.g. `function(a,b){return a-b;}` for reduce,
`e=>e+'x'` for flatMap, `e!=='f1'` for find), non-literal INIT,
reduce bodies referencing the index/array params, bare-String
flatMap callbacks, find with no match, non-literal/spread bound
args on arrows, arrow arity mismatches, second `.bind` hops on
arrows, `.bind` on non-reduce/flatMap/find builtins (other
findings' scopes).

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"
_CRED = _A1 + _A2

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: F553 filed
def p1_f553_filed_shapes():
    shapes = [
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect,[].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F553 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f553_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.reduce receiver (node-identical)
        "Reflect.apply(Array.prototype.reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # arrow callback
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],(a,b)=>a+b,''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # no INIT: accumulator starts at elements[0]
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;}),null,[])"
        % {"A1": _A1, "A2": _A2},
        # non-empty INIT is the fold seed
        "Reflect.apply([].reduce.bind(['%(A2)s'],function(a,b){return a+b;},'%(A1)s'),null,[])"
        % {"A1": _A1, "A2": _A2},
        # swapped param names: slot 0 is still the accumulator
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(y,x){return y+x;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # ?.-bind member form (F490)
        "Reflect.apply([].reduce?.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # bracket-string bind member (F482)
        "Reflect.apply([].reduce['bind'](['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "Reflect.apply( [].reduce.bind( ['%(A1)s' , '%(A2)s'] , function( a , b ){ return a + b ; } , '' ) , null , [] )"
        % {"A1": _A1, "A2": _A2},
        # non-empty call argsArray is parsed and discarded (engine ignores it)
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,['junk'])"
        % {"A1": _A1, "A2": _A2},
        # INIT from the CALL args: no bound INIT, so C[0] becomes INIT
        # (node v24.20.0: B.reduce(CB, C[0]))
        "Reflect.apply([].reduce.bind(['%(A2)s'],function(a,b){return a+b;}),null,['%(A1)s'])"
        % {"A1": _A1, "A2": _A2},
        # same via the call-indirect path
        "Reflect.apply.call(Reflect,[].reduce.bind(['%(A2)s'],function(a,b){return a+b;}),null,['%(A1)s'])"
        % {"A1": _A1, "A2": _A2},
        # same via the bind-indirect (F513) path
        "Reflect.apply.bind(Reflect)([].reduce.bind(['%(A2)s'],function(a,b){return a+b;}),null,['%(A1)s'])"
        % {"A1": _A1, "A2": _A2},
        # bound INIT wins over call args (engine ignores the rest)
        "Reflect.apply([].reduce.bind(['%(A2)s'],function(a,b){return a+b;},'%(A1)s'),null,['junk','junk2'])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F553 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P2: F553 bounds
def p2_f553_bounds():
    # Every shape here must NOT decode to the credential: either it
    # fails closed (miss) or it decodes to something != credential.
    # want_block=False pins "decoder does not claim the credential".
    shapes = [
        # INIT from call args, junk values -> 'zzyy' (node-exact, stays quiet)
        "Reflect.apply([].reduce.bind(['yy'],function(a,b){return a+b;}),null,['zz'])",
        # junk BINDTHIS -> 'zzyy' (node-exact, stays quiet)
        "Reflect.apply([].reduce.bind(['zz','yy'],function(a,b){return a+b;},''),null,[])",
        # non-literal BINDTHIS element
        "Reflect.apply([].reduce.bind(['%(A1)s',x],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1},
        # non-modeled callback: subtraction
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a-b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # non-modeled callback: literal in body
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+'x';},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # body referencing the index param (undecidable)
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b,i){return a+b+i;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # non-literal INIT
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},x),null,[])"
        % {"A1": _A1, "A2": _A2},
        # numeric INIT
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},0),null,[])"
        % {"A1": _A1, "A2": _A2},
        # extra bound args
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},'',null),null,[])"
        % {"A1": _A1, "A2": _A2},
        # zero bound args: reduce() with no callback -> engine throws; fail closed
        "Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s']),null,[])"
        % {"A1": _A1, "A2": _A2},
        # empty BINDTHIS with no INIT -> node throws TypeError; fail closed
        "Reflect.apply([].reduce.bind([],function(a,b){return a+b;}),null,[])",
        # .bind on a non-reduce builtin here (concat is F521's scope)
        "Reflect.apply([].concat.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # non-array BINDTHIS
        "Reflect.apply([].reduce.bind('ab',function(a,b){return a+b;},''),null,[])",
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F553 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P3: F554 filed
def p3_f554_filed_shapes():
    shapes = [
        "Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect,[].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F554 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p3_f554_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.flatMap receiver
        "Reflect.apply(Array.prototype.flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # arrow identity
        "Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],e=>e),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # block-body arrow identity (F448)
        "Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],e=>{return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # mixed array/plain-string BINDTHIS elements (node flattens one level)
        "Reflect.apply([].flatMap.bind([['%(A1)s'],'%(A2)s'],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # multi-element inner arrays
        "Reflect.apply([].flatMap.bind([['%(A1)s','%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "Reflect.apply( [].flatMap.bind( [ ['%(A1)s'] , ['%(A2)s'] ] , function( e ){ return e ; } ) , null , [] ).join( '' )"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F554 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P4: F554 bounds
def p4_f554_bounds():
    shapes = [
        # junk BINDTHIS -> 'zzyy' (node-exact, stays quiet)
        "Reflect.apply([].flatMap.bind([['zz'],['yy']],function(e){return e;}),null,[]).join('')",
        # bare String callback: String(['f1','f2']) === 'f1,f2', not identity
        "Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],String),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-identity callback
        "Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return [e];}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # numeric element inside inner array
        "Reflect.apply([].flatMap.bind([['%(A1)s',1]],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1},
        # deeper nesting (decoder's join model is exact one level down)
        "Reflect.apply([].flatMap.bind([[['%(A1)s']]],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1},
        # extra bound args
        "Reflect.apply([].flatMap.bind([['%(A1)s']],function(e){return e;},null),null,[]).join('')"
        % {"A1": _A1},
        # zero bound args
        "Reflect.apply([].flatMap.bind([['%(A1)s']]),null,[]).join('')"
        % {"A1": _A1},
        # .bind on map here (F538's scope, not flatMap)
        "Reflect.apply([].map.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F554 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P5: F555 filed
def p5_f555_filed_shapes():
    shapes = [
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect,[].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F555 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p5_f555_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.find receiver
        "Reflect.apply(Array.prototype.find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # arrow predicate, bare param
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],e=>e==='%(A1)s'),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # arrow predicate, parenthesized param
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],(e)=>e==='%(A1)s'),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # loose == over strings is engine-identical to ===
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e=='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # match on the second element
        "Reflect.apply([].find.bind(['zz','%(A1)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "Reflect.apply( [].find.bind( ['%(A1)s' , '%(A2)s'] , function( e ){ return e === '%(A1)s' ; } ) , null , [] ) + '%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F555 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P6: F555 bounds
def p6_f555_bounds():
    shapes = [
        # no match -> node undefined; decoder fails closed (quiet)
        "Reflect.apply([].find.bind(['zz','yy'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # !== is not an equality match
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e!=='zz';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # non-literal RHS
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e===x;}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # two-param callback (index param undecidable here)
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e,i){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # block-body arrow
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],e=>{return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # extra bound args
        "Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';},null),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # .bind on filter here (F537's scope, not find)
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F555 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P7: F556 filed
def p7_f556_filed_shapes():
    shapes = [
        "((a)=>a+'%(A2)s').bind(null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply(((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,[])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F556 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p7_f556_variants():
    shapes = [
        # call-indirect dispatch (F521 fallback path)
        "Reflect.apply.call(Reflect,((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,[])"
        % {"A1": _A1, "A2": _A2},
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)(((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,[])"
        % {"A1": _A1, "A2": _A2},
        # function-expression target
        "(function(a){return a+'%(A2)s';}).bind(null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply((function(a){return a+'%(A2)s';}).bind(null,'%(A1)s'),null,[])"
        % {"A1": _A1, "A2": _A2},
        # params-only body (F519-shaped arrow, bound)
        "((a,b)=>a+b).bind(null,'%(A1)s','%(A2)s')()"
        % {"A1": _A1, "A2": _A2},
        # bound args + call args fill params in order
        "((a,b)=>a+b).bind(null,'%(A1)s')('%(A2)s')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply(((a,b)=>a+b).bind(null,'%(A1)s'),null,['%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # literal-only body
        "(()=> '%(A1)s'+'%(A2)s').bind(null)()"
        % {"A1": _A1, "A2": _A2},
        # ?.-bind and bracket-string bind members
        "((a)=>a+'%(A2)s')?.bind(null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
        "((a)=>a+'%(A2)s')['bind'](null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "( ( a ) => a + '%(A2)s' ).bind( null , '%(A1)s' )( )"
        % {"A1": _A1, "A2": _A2},
        # extra call args beyond arity: the engine ignores them
        # (node v24.20.0) -- still the credential
        "Reflect.apply(((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,['junk'])"
        % {"A1": _A1, "A2": _A2},
        "((a)=>a+'%(A2)s').bind(null,'%(A1)s')('junk')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect,((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,['junk'])"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.bind(Reflect)(((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,['junk'])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F556 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P8: F556 bounds
def p8_f556_bounds():
    shapes = [
        # junk literals -> 'zzyy' (node-exact, stays quiet)
        "((a)=>a+'yy').bind(null,'zz')()",
        # non-literal bound arg
        "((a)=>a+'%(A2)s').bind(null,x)()"
        % {"A2": _A2},
        # spread bound arg (F531's spread is concat-family only)
        "((a)=>a+'%(A2)s').bind(null,...['%(A1)s'])()"
        % {"A1": _A1, "A2": _A2},
        # arity mismatch: two params, one arg
        "((a,b)=>a+b).bind(null,'%(A1)s')()"
        % {"A1": _A1},
        # arity mismatch: one param, two args
        "((a)=>a).bind(null,'%(A1)s','%(A2)s')()"
        % {"A1": _A1, "A2": _A2},
        # non-additive body: member access
        "((a)=>a.length).bind(null,'%(A1)s')()"
        % {"A1": _A1},
        # non-additive body: undeclared name
        "((a)=>a+b).bind(null,'%(A1)s')()"
        % {"A1": _A1},
        # template literal operand
        "((a)=>a+`%(A2)s`).bind(null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
        # second .bind hop (documented residual)
        "((a)=>a+'%(A2)s').bind(null,'%(A1)s').bind(null)()"
        % {"A1": _A1, "A2": _A2},
        # bound function with no immediate call: not a decodable value
        "var f=((a)=>a+'%(A2)s').bind(null,'%(A1)s');"
        % {"A1": _A1, "A2": _A2},
        # generator arrow target
        "((function*(a){yield a;}).bind(null,'%(A1)s')())"
        % {"A1": _A1},
        # object-literal thisArg: the F521 family's thisArg grammar is
        # array/marker/null only -- arrows ignore the receiver in the
        # engine, but the decoder fails closed here (family-consistent,
        # documented; the filed shapes use null)
        "((a)=>a+'%(A2)s').bind({},'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F556 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P9: compositions
def p9_compositions():
    # Neighbors must stay HELD (no regression); the four closures must
    # not swallow each other's or siblings' shapes.
    held = [
        # F521 bound concat
        "Reflect.apply([].concat.bind([],'%(A1)s'),null,['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # F530 bound join (filed shape: no postfix -- join yields a string)
        "Reflect.apply([].join.bind(['%(A1)s','%(A2)s'],''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # F534 bound slice
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'],0,2),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # F537 bound filter
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'],function(e){return e.length>2;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # F538 bound map
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'],function(e){return e;}),null,[]).join('')"
        % {"A1": _A1, "A2": _A2},
        # F519 literal fn target (unbound arrow still the F519 path)
        "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # F544 spread argsArray on a plain fn target
        "Reflect.apply((a,b)=>a+b,null,[...['%(A1)s','%(A2)s']])"
        % {"A1": _A1, "A2": _A2},
        # F553 via the F513 bind-indirect path (fallback nesting)
        "Reflect.apply.bind(Reflect)([].reduce.bind(['%(A1)s','%(A2)s'],(a,b)=>a+b,''),null,[])"
        % {"A1": _A1, "A2": _A2},
        # F555 via the F521 call-indirect path (fallback nesting)
        "Reflect.apply.call(Reflect,[].find.bind(['%(A1)s','%(A2)s'],e=>e==='%(A1)s'),null,[])+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # F556 direct call through the primary chain
        "((a)=>a+'%(A2)s').bind(null,'%(A1)s')()"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in held if _verdict(s, True)[0] == "BREAK"]
    # Siblings' OPEN findings must still MISS (no accidental closes):
    # F574 flat depth>1 / flatMap (attack round 37) -- pin the ones
    # adjacent to this lane's machinery.
    open_quiet = [
        # F574: flat at depth>1 still misses
        "[[['%(A1)s']],[['%(A2)s']]].flat(2).join('')"
        % {"A1": _A1, "A2": _A2},
        # F574: flatMap identity still misses
        "['%(A1)s','%(A2)s'].flatMap(x=>[x]).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad += [s for s in open_quiet if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions honest" % (len(held) + len(open_quiet) - len(bad),
                                           len(held) + len(open_quiet)))


# ------------------------------------------------------------- P10: node differential
_NODE_EXPRS = [
    # (js inner-expr template, node result equals credential?)
    ("Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])", True),
    ("Reflect.apply.call(Reflect,[].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])", True),
    ("Reflect.apply.bind(Reflect)([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])", True),
    ("Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],(a,b)=>a+b,''),null,[])", True),
    ("Reflect.apply([].reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;}),null,[])", True),
    ("Reflect.apply([].reduce.bind(['%(A2)s'],function(a,b){return a+b;},'%(A1)s'),null,[])", True),
    ("Reflect.apply([].reduce.bind(['zz','yy'],function(a,b){return a+b;},''),null,[])", False),
    ("Reflect.apply(Array.prototype.reduce.bind(['%(A1)s','%(A2)s'],function(a,b){return a+b;},''),null,[])", True),
    ("Reflect.apply([].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')", True),
    ("Reflect.apply.call(Reflect,[].flatMap.bind([['%(A1)s'],['%(A2)s']],function(e){return e;}),null,[]).join('')", True),
    ("Reflect.apply([].flatMap.bind([['%(A1)s'],'%(A2)s'],function(e){return e;}),null,[]).join('')", True),
    ("Reflect.apply([].flatMap.bind([['zz'],['yy']],function(e){return e;}),null,[]).join('')", False),
    ("Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'", True),
    ("Reflect.apply.call(Reflect,[].find.bind(['%(A1)s','%(A2)s'],function(e){return e==='%(A1)s';}),null,[])+'%(A2)s'", True),
    ("Reflect.apply([].find.bind(['%(A1)s','%(A2)s'],e=>e==='%(A1)s'),null,[])+'%(A2)s'", True),
    ("Reflect.apply([].find.bind(['zz','yy'],function(e){return e==='%(A1)s';}),null,[])", False),
    ("((a)=>a+'%(A2)s').bind(null,'%(A1)s')()", True),
    ("Reflect.apply(((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,[])", True),
    ("Reflect.apply.call(Reflect,((a)=>a+'%(A2)s').bind(null,'%(A1)s'),null,[])", True),
    ("(function(a){return a+'%(A2)s';}).bind(null,'%(A1)s')()", True),
    ("((a,b)=>a+b).bind(null,'%(A1)s')('%(A2)s')", True),
    ("((a)=>a+'yy').bind(null,'zz')()", False),
]


def p10_node_differential():
    mismatches = []
    for template, node_has_cred in _NODE_EXPRS:
        js = template % {"A1": _A1, "A2": _A2}
        try:
            r = subprocess.run(["node", "-e", "console.log(JSON.stringify(%s))" % js],
                               capture_output=True, text=True, timeout=30)
            # node prints an empty line for undefined (e.g. find with
            # no match) -- treat as the undefined sentinel.
            out = r.stdout.strip()
            # node prints "undefined" (or nothing) for undefined --
            # treat both as the undefined sentinel.
            node_val = json.loads(out) if (out and out != "undefined") else None
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "node failed on %s: %r" % (js[:60], e))
        node_cred = (node_val == _CRED)
        if node_cred != node_has_cred:
            return ("ERROR",
                    "node disagrees with expected on %s: node=%r" % (js[:60], node_val))
        decoder_blocks = _blocked(js)
        if decoder_blocks != node_cred:
            mismatches.append(js[:72])
    if mismatches:
        return ("BREAK", "%d decoder/node mismatches: %s"
                % (len(mismatches), "; ".join(mismatches)))
    return ("HELD", "%d/%d decoder agrees with node v24.20.0"
            % (len(_NODE_EXPRS), len(_NODE_EXPRS)))


# ------------------------------------------------------------- P11: pin/footer
def p11_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F583**" in text  # Wave-370 merge: F570-F573/F576-F579 CLOSED
          and "**Open findings: F574, F575, F580, F581, F582.**" in text  # Wave-370 merge: F574/F575/F580/F581/F582 OPEN
          and "**Status: CLOSED 2026-10-07 wave-369 lane 4.**" in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P12: perf bound
def p12_perf_bound():
    # Hostile input: many bound-reduce/flatMap/find/arrow anchors --
    # must starve fast (F452 lesson: fail-closed matches must consume
    # scan budget; the _MAX_WHOLETEXT_ATTEMPTS cap applies).
    junk = ("Reflect.apply([].reduce.bind(['ab','cd'],function(a,b){return a+b;},''),null,[])"
            "Reflect.apply([].flatMap.bind([['ab'],['cd']],function(e){return e;}),null,[]).join('')"
            "Reflect.apply([].find.bind(['ab','cd'],function(e){return e==='ab';}),null,[])"
            "((a)=>a+'cd').bind(null,'ab')()") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2800-anchor reduce/flatMap/find/arrow corpus: hit=%s %.2fs" % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w368_f553_redfirst.py",
    "evals/w368_f554_redfirst.py",
    "evals/w368_f555_redfirst.py",
    "evals/w368_f556_redfirst.py",
    "evals/w368_f537f538f542close_probes.py",
    "evals/w368_f539f540close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g369lane4-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" %
                  (rel, line[-1] if line else "rc=%d" % r.returncode,
                   time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f553-filed", p1_f553_filed_shapes),
    ("p1-f553-variants", p1_f553_variants),
    ("p2-f553-bounds", p2_f553_bounds),
    ("p3-f554-filed", p3_f554_filed_shapes),
    ("p3-f554-variants", p3_f554_variants),
    ("p4-f554-bounds", p4_f554_bounds),
    ("p5-f555-filed", p5_f555_filed_shapes),
    ("p5-f555-variants", p5_f555_variants),
    ("p6-f555-bounds", p6_f555_bounds),
    ("p7-f556-filed", p7_f556_filed_shapes),
    ("p7-f556-variants", p7_f556_variants),
    ("p8-f556-bounds", p8_f556_bounds),
    ("p9-compositions", p9_compositions),
    ("p10-node-differential", p10_node_differential),
    ("p11-pin-footer", p11_pin_footer),
    ("p12-perf-bound", p12_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    rows = []
    for name, fn in PROBES:
        try:
            v, msg = fn()
        except Exception as e:  # noqa: BLE001
            v, msg = "ERROR", "%s: %s" % (type(e).__name__, e)
        rows.append((name, v, msg))
        if v == "HELD":
            held += 1
        else:
            brk += 1
        print("%-22s %s -- %s" % (name, v, msg))
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (brk, held))
    g = green_check()
    print("green-check: %s" % ("PASS" if g else "FAIL"))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": g,
                          "probes": rows}))
    return 1 if (brk or not g) else 0


if __name__ == "__main__":
    sys.exit(main())
