#!/usr/bin/env python3
"""Wave-361 F496 + F497 closure battery (lane 1).

F496 (LOW, filed 2026-10-06 wave-360 attack round 28): Reflect.ownKeys
key-enumeration indirection at dispatch targets bypasses the bounded
static JS-expression decoder -- F491 covers Reflect.get /
property-descriptor reads of a NAMED property, but enumerating all keys
with Reflect.ownKeys and selecting by predicate bypasses every anchor:

  Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], 'f1','f2').join('')
  Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')].call([], 'f1','f2').join('')
  [].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('f1','f2').join('')
  Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['f1','f2'], '')

All node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants. Distinct from F491 (named-property reads).
Close-when: the decoder resolves Reflect.ownKeys enumeration with a
statically decidable predicate equivalently to direct member access
(or refuses obfuscation-shaped runs coded) such that find_credential
flags them, red-first verified, honest text unaffected. This lane
resolves the filed predicate class engine-exactly (the flagging half)
and fails closed outside it.

F497 (LOW, filed 2026-10-06 wave-360 attack round 28):
constructor-property factory with a non-empty array receiver bypasses
the bounded static JS-expression decoder -- F476 closed the
[].constructor.of / Array['of'] path but documents "['x'].constructor.of
is a documented residual": the receiver rule requires an empty array
literal, so any non-empty receiver bypasses the factory desugar:

  ['x'].constructor.of('f1','f2').join('')
  ['x','y'].constructor.of('f1','f2').join('')
  ['x'].constructor['of']('f1','f2').join('')

All node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants. Distinct from F476 (empty-receiver factory).
Close-when: the decoder models the constructor-property factory for
non-empty array receivers (or refuses obfuscation-shaped runs coded)
such that find_credential flags them, red-first verified, honest text
unaffected. This lane normalizes ['lit',...].constructor to Array
node-exactly (the flagging half) and fails closed outside the modeled
receiver class.

Closure design (gov/dlp.py):
  F496:
  * New node-verified own-key lists `_F496_ARRAY_PROTO_KEYS`,
    `_F496_STRING_PROTO_KEYS`, `_F496_ARRAY_CTOR_KEYS`
    (Reflect.ownKeys string keys, node v24.20.0).
  * New `_js_parse_ownkeys_bracket_key`: parses
    `[Reflect.ownKeys(SRC).filter(k=>k==='NAME')[0]]` (plus the
    no-index filter form -- the 1-element result coerces via
    ToPropertyKey, node-verified -- and `.find(...)`) to the
    engine-exact key NAME. The predicate class is exactly one arrow
    (`k` or `(k)`) with body `k === 'NAME'` / `k == 'NAME'` (operand
    order either way, string literal only). SRC is one of
    Array.prototype / String.prototype / Array / [].constructor (via
    _js_parse_reflect_get_target); NAME must be a genuine own key of
    SRC (membership check -- without it, `Reflect.ownKeys(Math)` would
    mis-decode, node throws TypeError there). Anything else fails
    closed: non-literal comparators, !==, non-filter/find selects,
    extra select arguments, non-zero indices, unmodeled SRC,
    Object.getOwnPropertyNames.
  * Hooked as a third fallback in `_js_parse_prototype_dispatch`'s
    `[` branch (after literal and F492 folded keys) and in
    `_js_parse_ctor_factory`'s `[` branch -- the resolved key reuses
    the existing method-table validation (faithful by construction,
    no F481-class composition gap).
  * No new regexes (re.compile stays 28); F430 part budget charged
    via state["ops"].
  F497:
  * New `_js_is_nonempty_ctor_recv`: quote-aware peek for
    '[<array-literal>].constructor' (nested brackets tracked,
    string/template literals skipped).
  * `_js_parse_ctor_factory` receiver generalized: `[]` (F476) or a
    string-literal-only array literal (F497, via
    _js_parse_string_literal_list -- part-budget charged); any array
    literal's .constructor is engine-identical to Array (node
    v24.20.0). Numeric/nested/template/spread receivers fail closed
    (documented).
  * New dispatch branch in `_js_parse_primary` routing the non-empty
    receiver to the factory (disjoint from array literals and the
    F471 spread-copy).
  * `_js_parse_dispatch_thisarg` accepts the non-empty ctor ref
    (F486 factory dispatch / fromCharCode dispatch thisArg; the value
    is discarded -- the engine ignores it). F480's
    `_js_parse_array_ctor_ref` is untouched (its documented
    `[1].constructor` boundary stands).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 4 F496 + 3 F497 filed shapes block (node-exact
      decode checked); generalizations (no-index filter, ws
      tolerance, ==, reversed equality, paren param, String SRC,
      multi-element receivers, bracket member, direct call,
      of.call/of.apply dispatch) block node-exactly; F496xF491 /
      F497xF476 / F496xF492 / F497xF488 compositions hold.
  P2  fail-closed boundaries: F496 unmodeled SRC, non-own-key,
      !==, non-filter/find selects, non-zero index, non-literal
      comparator, getOwnPropertyNames, wrong param name, extra args,
      non-method keys; F497 numeric/trailing-comma/nested/template/
      non-literal receivers, from/ofx members; junk quiet; neighbors
      intact (F476/F478/F480/F482/F483/F486/F487/F488/F491/F492/F493/
      F494/F495 still decode; F498-F502 still miss).
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored; F441 ordering untouched.
  P4  pin + footer (F496, F497 CLOSED locally; open F498-F502 / next
      F503).
"""

import os
import sys
import subprocess
import argparse
import json

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-361 lane 1: F496, F497 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F662, F663, F664, F665, F666, F667, F668, F669, F670, F671"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-361 lane 1: F496, F497 CLOSED locally (merge finalizes tree-wide)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 lane 3: F528, F529 CLOSED locally (merge finalizes)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
FOOTER_NEXT = "F672"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)

# Constructed via concatenation: the write path redacts credential literals.
# Split to match the red-first batteries: neither fragment alone is
# credential-shaped (a fragment like 'xoxb-0123456789' would trip the
# strict rule on the raw text and invalidate miss expectations).
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try{ out.push(JSON.stringify(eval(cases[k]))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=120)
    return json.loads(r.stdout)


# ---------------------------------------------------------------- P1: closure
def p1_f496_filed_shapes_block():
    shapes = [
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        "Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')].call([], '%s','%s').join('')" % (_A, _B),
        "[].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('%s','%s').join('')" % (_A, _B),
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['%s','%s'], '')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "4/4 F496 filed shapes blocked")


def p1_f496_node_exact():
    decode_cases = [
        # no-index filter: 1-element result coerces via ToPropertyKey.
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')].call([], 'ab','cd').join('')", "abcd"),
        # ws tolerance.
        ("Array.prototype[ Reflect.ownKeys( Array.prototype ).filter( k => k === 'concat' )[ 0 ] ].call( [], 'ab', 'cd' ).join('')", "abcd"),
        # == and reversed operand order.
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k=='concat')[0]].call([], 'ab','cd').join('')", "abcd"),
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>'concat'===k)[0]].call([], 'ab','cd').join('')", "abcd"),
        # parenthesized param.
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter((k)=>k==='concat')[0]].call([], 'ab','cd').join('')", "abcd"),
        # String SRC + String dispatch target.
        ("String.prototype[Reflect.ownKeys(String.prototype).filter(k=>k==='concat')[0]].call('S', 'ab','cd')", "Sabcd"),
        # join target.
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['ab','cd'], '')", "abcd"),
        # ctor SRC key 'of'.
        ("[].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('ab','cd').join('')", "abcd"),
        # innocent decodes stay quiet (decode checked, not blocking).
        ("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], 'ab','cd').join('')", "abcd"),
    ]
    for payload, want in decode_cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    cred_cases = [
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        "Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')].call([], '%s','%s').join('')" % (_A, _B),
        "[].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('%s','%s').join('')" % (_A, _B),
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['%s','%s'], '')" % (_A, _B),
    ]
    for payload in cred_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:50])
    return ("HELD", "9/9 F496 decodes node-exact; 4/4 credential variants block")


def p1_f497_filed_shapes_block():
    shapes = [
        "['x'].constructor.of('%s','%s').join('')" % (_A, _B),
        "['x','y'].constructor.of('%s','%s').join('')" % (_A, _B),
        "['x'].constructor['of']('%s','%s').join('')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "3/3 F497 filed shapes blocked")


def p1_f497_node_exact():
    decode_cases = [
        # multi-element receiver.
        ("['x','y','z'].constructor.of('ab','cd').join('')", "abcd"),
        # ws tolerance.
        ("[ 'x' ].constructor.of( 'ab', 'cd' ).join('')", "abcd"),
        ("['x' ].constructor[ 'of' ]( 'ab','cd' ).join('')", "abcd"),
        # F488 direct call with non-empty receiver.
        ("['x'].constructor('ab','cd').join('')", "abcd"),
        # F486 factory dispatch with non-empty receiver + thisArg.
        ("['x'].constructor.of.call(['x'].constructor, 'ab','cd').join('')", "abcd"),
        ("['x'].constructor.of.apply(['x'].constructor, ['ab','cd']).join('')", "abcd"),
        # empty receiver still decodes (F476 composition).
        ("[].constructor.of('ab','cd').join('')", "abcd"),
        # innocent decodes stay quiet (decode checked, not blocking).
        ("['x'].constructor.of('ab','cd').join('')", "abcd"),
    ]
    for payload, want in decode_cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    cred_cases = [
        "['x'].constructor.of('%s','%s').join('')" % (_A, _B),
        "['x','y'].constructor.of('%s','%s').join('')" % (_A, _B),
        "['x'].constructor['of']('%s','%s').join('')" % (_A, _B),
    ]
    for payload in cred_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:50])
    return ("HELD", "8/8 F497 decodes node-exact; 3/3 credential variants block")


def p1_compositions():
    # F496 x F491: named-property reads still decode via their own path.
    if not _blocked("Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F491 named-read composition missed")
    # F497 x F476: the empty-receiver factory still decodes.
    if not _blocked("[].constructor.of('%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F476 empty-receiver composition missed")
    # F496 x F492: folded predicate keys fail closed (documented).
    if _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='con'+'cat')[0]].call([], '%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F496xF492 folded predicate decoded (must fail closed)")
    # F497 x F488: parenthesized empty-ctor callee still decodes.
    if not _blocked("([].constructor)('%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F488 paren-callee composition missed")
    # F497 x F480: bracket-apply with non-empty thisArg still fails closed
    # (F480's documented boundary -- _js_parse_array_ctor_ref untouched).
    if _blocked("[].constructor['apply'](['x'].constructor, ['%s','%s']).join('')" % (_A, _B)):
        return ("BREAK", "F480 thisArg boundary widened")
    return ("HELD", "F496xF491, F497xF476, F496xF492, F497xF488, F497xF480 compositions hold")


# ------------------------------------------------------- P2: boundaries
def p2_f496_boundaries():
    miss_cases = [
        # unmodeled enumeration source: node throws TypeError.
        "Array.prototype[Reflect.ownKeys(Math).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # name not an own key of SRC: selection is undefined.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='nosuch')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # !== predicate.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k!=='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # not filter/find.
        "Array.prototype[Reflect.ownKeys(Array.prototype).map(k=>k)[0]].call([], '%s','%s').join('')" % (_A, _B),
        # non-zero index.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[1]].call([], '%s','%s').join('')" % (_A, _B),
        # non-literal comparator.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='con'+'cat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # non-arrow predicate.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter('concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # getOwnPropertyNames not modeled.
        "Array.prototype[Object.getOwnPropertyNames(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # predicate compares the wrong name.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(j=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # extra select argument.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat',null)[0]].call([], '%s','%s').join('')" % (_A, _B),
        # own key but not a modeled dispatch method: node throws.
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='length')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # find with trailing [0]: ('concat')[0] is 'c', not the method.
        "Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
    ]
    for payload in miss_cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "boundary decoded: %s" % payload[:60])
    return ("HELD", "12/12 F496 boundaries fail closed")


def p2_f497_boundaries():
    miss_cases = [
        # numeric receiver elements.
        "[1].constructor.of('%s','%s').join('')" % (_A, _B),
        # trailing comma receiver.
        "['x',].constructor.of('%s','%s').join('')" % (_A, _B),
        # nested receiver.
        "[['x']].constructor.of('%s','%s').join('')" % (_A, _B),
        # non-literal receiver.
        "[x].constructor.of('%s','%s').join('')" % (_A, _B),
        # from member: throws in node with string args.
        "['x'].constructor.from('%s','%s').join('')" % (_A, _B),
        # ident boundary.
        "['x'].constructor.ofx('%s','%s').join('')" % (_A, _B),
        # non-array source.
        "'x'.constructor.of('%s','%s').join('')" % (_A, _B),
        # spread receiver.
        "[...['x']].constructor.of('%s','%s').join('')" % (_A, _B),
    ]
    for payload in miss_cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "boundary decoded: %s" % payload[:60])
    return ("HELD", "8/8 F497 boundaries fail closed")


def p2_junk_quiet():
    junk = [
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], 'ab','cd').join('')",
        "['x'].constructor.of('ab','cd').join('')",
        "var q = Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]];",
    ]
    for payload in junk:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "junk flagged: %s" % payload[:60])
    return ("HELD", "junk quiet")


def p2_neighbors_intact():
    # Closed neighbors must still decode.
    closed = [
        "[].constructor.of('%s','%s').join('')" % (_A, _B),  # F476
        "Array.prototype.concat.call([], '%s','%s').join('')" % (_A, _B),  # F478
        "Array.prototype['concat'].call([], '%s','%s').join('')" % (_A, _B),  # F482
        "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')" % (_A, _B),  # F491
        "Array.prototype['con'+'cat'].call([], '%s','%s').join('')" % (_A, _B),  # F492
        "String.raw({raw:['%s','%s']})" % (_A, _B),  # F493
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),  # F494
        "Reflect['construct'](Array, ['%s','%s']).join('')" % (_A, _B),  # F498 CLOSED (wave-361 lane 2; merge maintenance)
        "[...'%s',...'%s'].join('')" % (_A, _B),  # F499 CLOSED (wave-361 lane 2; merge maintenance)
        "Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A, _B),  # F502 CLOSED (wave-361 lane 3; merge maintenance)
        "const a='%s'; const b='%s'; a+b" % (_A, _B),  # F501 CLOSED (wave-361 lane 3; merge maintenance)
        "Array.prototype.concat.call(Object.seal([]), '%s','%s').join('')" % (_A, _B),  # F503 CLOSED (wave-362 lane 1; merge maintenance)
    ]
    for payload in closed:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "closed neighbor missed: %s" % payload[:60])
    # Open findings must still miss.
    open_shapes = [
        "String.fromCharCode(...['%s','%s'].map(c=>c.charCodeAt(0)))" % (_A, _B),  # F500-adjacent (must miss: non-literal map)
    ]
    for payload in open_shapes:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "open finding decoded: %s" % payload[:60])
    return ("HELD", "closed neighbors decode; F500-adjacent/F503 still miss")


# ------------------------------------------------------- P3: decoder pins
def p3_node_differential():
    decode_cases = [
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], 'ab','cd').join('')",
        "Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')].call([], 'ab','cd').join('')",
        "[].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('ab','cd').join('')",
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['ab','cd'], '')",
        "['x'].constructor.of('ab','cd').join('')",
        "['x','y'].constructor.of('ab','cd').join('')",
        "['x'].constructor['of']('ab','cd').join('')",
        "['x'].constructor.of.call(['x'].constructor, 'ab','cd').join('')",
    ]
    node = _node_eval(decode_cases)
    for payload, n in zip(decode_cases, node):
        d = _decoded(payload)
        if n == "THROWS" or d != json.loads(n):
            return ("BREAK", "not node-exact: %s -> %r node %s" % (payload[:50], d, n))
    return ("HELD", "8/8 node byte-identical (subprocess)")


def p3_no_new_regexes():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(__import__("re").findall(r"re\.compile", src))
    if n != 28:
        return ("BREAK", "re.compile count %d want 28" % n)
    return ("HELD", "re.compile count 28 (no new regexes)")


def p3_f430_bounds():
    # A 200-element receiver trips the part budget -> fail closed.
    recv = "[" + ",".join("'x%d'" % i for i in range(200)) + "]"
    if _blocked("%s.constructor.of('ab','cd').join('')" % recv):
        return ("BREAK", "part budget not tripped (receiver)")
    # The indirection itself is ops-counted; deep nesting is bounded.
    deep = "Array.prototype" + "[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]]" * 3
    if _blocked(deep + ".call([], 'ab','cd').join('')"):
        return ("BREAK", "chained ownKeys selections decoded (must fail closed)")
    return ("HELD", "F430 budgets honored")


def p3_f441_ordering_untouched():
    # _try_bslash_unescape_all still precedes the _ESC_RUN layers.
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return ("HELD", "F441 ordering untouched")


# ------------------------------------------------------- P4: pin + footer
def p4_pin_and_footer():
    assert len(TAXONOMY) == TAXONOMY_PIN, (len(TAXONOMY), TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Lane-local footer expectation: F496, F497 closed here; the merge
    # finalizes tree-wide.
    assert ("Open findings: %s." % FOOTER_OPEN) in text, "footer open"
    assert ("Next free finding: **%s**" % FOOTER_NEXT) in text, "footer next"
    assert "F496" in text and "F497" in text and "CLOSED" in text
    return ("HELD", "pin=%d footer open %s next %s (lane-local)" %
            (TAXONOMY_PIN, FOOTER_OPEN, FOOTER_NEXT))


_PROBES = [
    ("p1-f496-filed-shapes-block", p1_f496_filed_shapes_block),
    ("p1-f496-node-exact", p1_f496_node_exact),
    ("p1-f497-filed-shapes-block", p1_f497_filed_shapes_block),
    ("p1-f497-node-exact", p1_f497_node_exact),
    ("p1-compositions", p1_compositions),
    ("p2-f496-boundaries", p2_f496_boundaries),
    ("p2-f497-boundaries", p2_f497_boundaries),
    ("p2-junk-quiet", p2_junk_quiet),
    ("p2-neighbors-intact", p2_neighbors_intact),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f430-bounds", p3_f430_bounds),
    ("p3-f441-ordering-untouched", p3_f441_ordering_untouched),
    ("p4-pin-and-footer", p4_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        return pid, fn()
    except Exception as e:  # noqa: BLE001 -- loud, never silent
        return pid, ("ERROR", "%s: %s" % (type(e).__name__, e))


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Parses both verdict formats
    (wave-320 class: a parse matching neither format passes vacuously)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    notes = []
    scripts = ("w360_attack_probes.py",
               "w360_f496_redfirst.py",
               "w360_f497_redfirst.py",
               "w360_f491f492f493close_probes.py",
               "w360_f494f495close_probes.py",
               "w359_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g361-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        breaks = set()
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "BREAK" and len(parts) >= 2:
                breaks.add(parts[1].rstrip(":"))
            elif len(parts) >= 2 and parts[1] == "BREAK":
                breaks.add(parts[0])
        if not breaks and r.returncode != 0:
            raise AssertionError("green check failed: could not parse any "
                                 "probe verdicts from child output: %s"
                                 % notes[-1])
        if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
            raise AssertionError("green check failed: %s" % notes[-1])
        if breaks:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe")
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                print(pid, verdict)
                return 0 if verdict[0] == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v[0] == "BREAK")
    held = sum(1 for _, v in results if v[0] == "HELD")
    err = sum(1 for _, v in results if v[0] == "ERROR")
    for pid, v in results:
        print(pid, v[0], v[1] if len(v) > 1 else "")
    print("w361_f496f497close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v[0] == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v[0] == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    main()
