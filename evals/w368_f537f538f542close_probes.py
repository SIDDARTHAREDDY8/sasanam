#!/usr/bin/env python3
"""Wave-368 F537/F538/F542 closure battery (lane 1).

Three LOW findings from wave-367 attack round 35 (node v24.20.0 ->
credential, decoder missed on the wave-367-merged base):

F537: Reflect.apply with a .bind-bound FILTER target.
  F521 models .bind-bound CONCAT targets, F530 JOIN targets, F534
  SLICE targets -- but the bound function can be any builtin
  (F500/F505 precedent: different builtins are separate findings):
    Reflect.apply([].filter.bind(['f1','f2','zz'], function(e){return e.length>2;}), null, []).join('')
    Reflect.apply.call(Reflect, [].filter.bind(['f1','f2','zz'], function(e){return e.length>2;}), null, []).join('')
  Both node-evaluate to the exact credential when the kept tokens have
  length > 2 (the battery uses 9/12-length tokens; 'zz' with length 2 is
  dropped -- note 'f1'.length === 2 in node, so the literal 'f1'/'f2'
  tokens would not demonstrate the leak as written; the FINDINGS.md
  entry uses 'f1a'/'f2b'). Distinct from F521/F530/F534
  (different builtins) and F482 (filter under .call dispatch, not
  .bind-bound Reflect.apply targets).

F538: Reflect.apply with a .bind-bound MAP target.
  Same family as F537: `[].map.bind(['f1','f2'], function(e){return e;})`
  -- the identity-mapped array postfix-joins to the credential.
  Distinct from F537 (map transforms, filter selects; F500/F505
  precedent).

F542: Proxy apply-trap as a Reflect.apply target.
  F519 models literal function targets and F522/F528 IIFE-evaluated
  targets, but the target can be a Proxy whose apply trap interposes
  the call:
    Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['f1','f2'])
    Reflect.apply.call(Reflect, new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['f1','f2'])
  Both node-evaluate to the exact credential (the delegating trap is
  engine-identical to a direct call). Distinct from F519 (literal
  targets), F522/F528 (IIFE targets), F535 (get-traps).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f537_filter_predicate` parses the bound filter
    callback: function-form `function(p){return p.length OP K;}` and
    expression-arrow forms `(p)=>p.length OP K` / `p=>p.length OP K`,
    OP in <,<=,>,>=, K a non-negative int literal (the
    _js_parse_number grammar admits no sign). Spec ("plencmp", op,
    k); applied by `_js_plencmp_apply` over all-plain-str arrays with
    UTF-16 code-unit length (node: '𐀀'.length === 2, v24.20.0) --
    _JSNumStr elements fail closed (F475: (1).length is undefined in
    the engine). Any other callback body fails closed (documented).
  * `_js_parse_f537_bound_filter_target` parses
    `[].filter.bind(BINDTHIS, CB)` / `Array.prototype.filter.bind(...)`
    (node-identical: [].filter === Array.prototype.filter) with the
    F506 thisArg classes (array literal / Array-constructor,
    all-string elements) and exactly ONE bound arg (the predicate).
  * `_js_parse_f538_bound_map_target` is the map twin, reusing the
    existing `_js_parse_map_callback` (identity / bare String --
    F437/F448/F460 grammar, engine-exact over strings).
  * The bound-filter/map triples parse `BOUND, thisArg, argsList`
    (thisArg parsed-and-discarded per the F483 precedent; argsList
    string-literal-only and discarded -- the engine ignores
    post-bound filter/map args, node v24.20.0 verified). Results are
    _JSArr (filter/map yield arrays); the postfix chain applies
    (.join('') assembles the credential).
  * `_js_parse_f542_apply_trap` verifies a delegating apply-trap:
    function-form, expression-arrow, or single-return block-arrow
    with exactly `(P1,P2,P3)` params and body exactly
    `return Reflect.apply(P1,P2,P3);` (dot form, own params in
    order) -- engine-identical to a direct call. Anything else
    (non-delegating bodies, extra handler keys, wrong arg order)
    fails closed (documented).
  * `_js_parse_f542_proxy_apply_triple` parses
    `new Proxy(FN, {apply: TRAP}), thisArg, argsList` where FN uses
    the F519/F522 target grammar (literal fn-expr/arrow or
    IIFE-evaluated); the delegated result is the F519 additive-body
    evaluation over the argsList. Returns a plain str like F519.
  * New peeks in `_js_peek_reflect_apply_target`: "boundfilter" /
    "boundmap" (both receiver classes, bind-lookahead only) and
    "proxyapply" (`new Proxy(` head). F513
    (`Reflect.apply.bind(Reflect)(...)`) and F521
    (`Reflect.apply.call(Reflect, ...)`) gain F537/F538/F542
    fallbacks nested after the F534 fallback; the F534 raise commits
    nothing on filter/map/proxy input (it rejects at the non-slice
    member check before any value parse), so the fallback is clean.

Fail closed (documented, never mis-decoded): non-literal BINDTHIS,
non-string elements, zero/extra bound args, non-modeled callbacks
(e.g. `function(e){return e.length;}`, `e=>e+'x'`, length bound
`>x`/`>2.5`), `.bind` on non-filter/map builtins (F521/F530/F534
scopes), non-delegating traps, extra handler keys, get-traps here
(F535's scope), non-function proxy targets, `?.`/`['bind']` on the
inner filter/map member (F506 precedent: inner member dot-only --
wait, F534 allows F490/F482 on the .bind member but dot-only on the
inner slice member; same here).

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

TAXONOMY_PIN = 2140  # Wave-368 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: F537 filed
def p1_f537_filed_shapes():
    shapes = [
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, [].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F537 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f537_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.filter receiver (node-identical)
        "Reflect.apply(Array.prototype.filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # arrow predicate, bare param
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], e=>e.length>2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # arrow predicate, parenthesized param
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], (e)=>e.length>2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # other comparison ops: >= keeps all three (zz length 2 >= 2)
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length>=9;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # <= drops both (9/12 <= 8 false)
        # NOTE: want_block True only when the result IS the credential;
        # this shape yields '' -- decode must not hallucinate the credential.
        # Covered in p2 as a junk-boundary instead.
        # constant-true predicate keeps the pair
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(){return true;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "Reflect.apply( [].filter.bind( ['%(A1)s' , '%(A2)s' , 'zz'] , function( e ){ return e.length > 2 ; } ) , null , [] ).join( '' )"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F537 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P2: F537 bounds
def p2_f537_bounds():
    # Every shape here must NOT decode to the credential: either it
    # fails closed (miss) or it decodes to something != credential.
    # want_block=False pins "decoder does not claim the credential".
    shapes = [
        # length<=2 keeps only 'zz' -> 'zz' (node-exact, stays quiet)
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length<=2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # <= bound that drops everything -> '' (must not hallucinate)
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length<=8;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal BINDTHIS element
        "Reflect.apply([].filter.bind(['%(A1)s',x], function(e){return e.length>2;}), null, []).join('')"
        % {"A1": _A1},
        # non-modeled callback: length as value (number truthiness)
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-modeled callback: extra statement
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){var q=1;return e.length>2;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal length bound
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length>x;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # fractional length bound
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length>2.5;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # zero bound args: filter() with no callback -> engine throws; fail closed
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # extra bound args
        "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length>2;}, null), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-array BINDTHIS
        "Reflect.apply([].filter.bind('ab', function(e){return e.length>0;}), null, []).join('')"
        % {"A1": _A1},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F537 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P3: F538 filed
def p3_f538_filed_shapes():
    shapes = [
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, [].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F538 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p3_f538_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.map receiver
        "Reflect.apply(Array.prototype.map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # arrow identity
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], e=>e), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # block-body arrow identity (F448)
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], e=>{return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # bare String callback (F460 -- identity over strings)
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], String), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # bracket-string bind member (F482 form)
        "Reflect.apply([].map['bind'](['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F538 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P4: F538 bounds
def p4_f538_bounds():
    shapes = [
        # non-identity callback: literal-producing but not modeled
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], function(e){return e+'x';}), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # zero bound args
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # extra bound args
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}, null), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal BINDTHIS element
        "Reflect.apply([].map.bind(['%(A1)s',y], function(e){return e;}), null, []).join('')"
        % {"A1": _A1},
        # Number callback: NaN-producing, never identity
        "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], Number), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F538 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P5: F542 filed
def p5_f542_filed_shapes():
    shapes = [
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F542 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p5_f542_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # expression-arrow trap
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:(t,th,args)=>Reflect.apply(t,th,args)}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # block-body arrow trap
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:(t,th,args)=>{return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # named trap function
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function deleg(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # arrow target (F519 form) under the proxy
        "Reflect.apply(new Proxy((a,b)=>a+b,{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # IIFE-evaluated target (F522 x F542 composition)
        "Reflect.apply(new Proxy((function(){return function(a,b){return a+b;};})(),{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance
        "Reflect.apply( new Proxy( function( a , b ){ return a + b ; } , { apply : function( t , th , args ){ return Reflect.apply( t , th , args ) ; } } ) , null , [ '%(A1)s' , '%(A2)s' ] )"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F542 variants block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P6: F542 bounds
def p6_f542_bounds():
    shapes = [
        # non-delegating trap: returns a constant (engine yields 'x')
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return 'x';}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # trap calls Reflect.apply with shuffled args (not a passthrough)
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(args,t,th);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # extra handler key
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);},get:function(t,k){return t[k];}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # get-trap where apply belongs (F535's scope, not F542's)
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{get:function(t,k){return t[k];}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # non-function proxy target
        "Reflect.apply(new Proxy({c:'%(A1)s'},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # trap with wrong arity (two params)
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,args){return Reflect.apply(t,null,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # trap body references a free variable
        "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(q,th,args);}}), null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F542 boundaries stay quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P7: compositions
def p7_compositions():
    # Neighbors must stay HELD (no regression); F546 (filed at the
    # wave-367 merge, CLOSED 2026-10-07 wave-368 lane 4) must now HIT.
    held = [
        # F521 bound concat
        "Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # F530 bound join (filed shape: no postfix -- join yields a string)
        "Reflect.apply([].join.bind(['%(A1)s','%(A2)s'], ''), null, [])"
        % {"A1": _A1, "A2": _A2},
        # F534 bound slice
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # F519 literal fn target
        "Reflect.apply(function(a,b){return a+b;}, null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # F535 literal member read (filed shape: member read + concat)
        "({c:'%(A1)s'}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in held if _verdict(s, True)[0] == "BREAK"]
    # F546 CLOSED 2026-10-07 wave-368 lane 4 (merge maintenance):
    # arguments-exotic body under Reflect.apply must now HIT.
    f546 = "Reflect.apply(function(){var a=arguments;return a[0]+a[1];}, null, ['%(A1)s','%(A2)s'])" % {"A1": _A1, "A2": _A2}
    if _verdict(f546, True)[0] == "BREAK":
        bad.append(f546)
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions honest" % (len(held) + 1 - len(bad), len(held) + 1))


# ------------------------------------------------------------- P8: node differential
_NODE_EXPRS = [
    # (js inner-expr template, node result equals credential?)
    ("Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')", True),
    ("Reflect.apply.call(Reflect, [].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')", True),
    ("Reflect.apply.bind(Reflect)([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')", True),
    ("Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], e=>e.length>2), null, []).join('')", True),
    ("Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length>=9;}), null, []).join('')", True),
    ("Reflect.apply([].filter.bind(['%(A1)s','%(A2)s'], function(e){return e.length<=8;}), null, []).join('')", False),
    ("Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, ['junk']).join('')", True),
    ("Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')", True),
    ("Reflect.apply.call(Reflect, [].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')", True),
    ("Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], e=>e), null, []).join('')", True),
    ("Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], String), null, []).join('')", True),
    ("Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])", True),
    ("Reflect.apply.call(Reflect, new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])", True),
    ("Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:(t,th,args)=>Reflect.apply(t,th,args)}), null, ['%(A1)s','%(A2)s'])", True),
    ("Reflect.apply(new Proxy((a,b)=>a+b,{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%(A1)s','%(A2)s'])", True),
]


def p8_node_differential():
    mismatches = []
    for template, node_has_cred in _NODE_EXPRS:
        js = template % {"A1": _A1, "A2": _A2}
        try:
            r = subprocess.run(["node", "-e", "console.log(JSON.stringify(%s))" % js],
                               capture_output=True, text=True, timeout=30)
            node_val = json.loads(r.stdout.strip())
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


# ------------------------------------------------------------- P9: pin/footer
def p9_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F583**" in text  # Wave-369 merge: lanes 1-6 (F547-F557,F560,F562,F563,F565) CLOSED; next F570
          and "**Open findings: F570, F571, F572, F573, F574, F575, F576, F577, F578, F579, F580, F581, F582.**" in text  # Wave-369 merge: lanes 1-6 CLOSED
          and "**Status: CLOSED 2026-10-07 wave-368 lane 1**" in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # Hostile input: many bound-filter/map/proxy anchors -- must
    # starve fast (F452 lesson: fail-closed matches must consume scan
    # budget; the _MAX_WHOLETEXT_ATTEMPTS cap applies).
    junk = ("Reflect.apply([].filter.bind(['ab','cd'], function(e){return e.length>1;}), null, []).join('')"
            "Reflect.apply([].map.bind(['ab','cd'], function(e){return e;}), null, []).join('')"
            "Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['ab','cd'])") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor filter/map/proxy corpus: hit=%s %.2fs" % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w367_f537_redfirst.py",
    "evals/w367_f538_redfirst.py",
    "evals/w367_f542_redfirst.py",
    "evals/w367_f534close_probes.py",
    "evals/w367_f531close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g368lane1-green-%d" % abs(hash(rel))
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
    ("p1-f537-filed", p1_f537_filed_shapes),
    ("p1-f537-variants", p1_f537_variants),
    ("p2-f537-bounds", p2_f537_bounds),
    ("p3-f538-filed", p3_f538_filed_shapes),
    ("p3-f538-variants", p3_f538_variants),
    ("p4-f538-bounds", p4_f538_bounds),
    ("p5-f542-filed", p5_f542_filed_shapes),
    ("p5-f542-variants", p5_f542_variants),
    ("p6-f542-bounds", p6_f542_bounds),
    ("p7-compositions", p7_compositions),
    ("p8-node-differential", p8_node_differential),
    ("p9-pin-footer", p9_pin_footer),
    ("p10-perf-bound", p10_perf_bound),
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
