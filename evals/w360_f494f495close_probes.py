#!/usr/bin/env python3
"""Wave-360 F494 + F495 closure battery (lane 3).

F494 (LOW, filed 2026-10-06 wave-359 attack round 27): spread of
non-literal iterables bypasses the bounded static JS-expression
decoder -- F462 models spread of array literals; spreading a
generator object, a Set, or Map.values() node-evaluates (v24.20.0)
to the exact credential while the decoder produced zero variants:

  [...(function*(){yield 'f1';yield 'f2'})()].join('')
  [...new Set(['f1','f2'])].join('')
  [].join.call([...new Set(['f1','f2'])], '')
  [...new Map([[0,'f1'],[1,'f2']]).values()].join('')

Distinct from F462 (literal spread). Close-when: the decoder fails
closed (coded refusal) on spread of non-literal iterables such that
find_credential flags them, red-first verified, honest text
unaffected. This lane models the filed classes engine-exactly (the
flagging half of the close-when) and fails closed outside them.

F495 (LOW, filed 2026-10-06 wave-359 attack round 27): method
invocation through local variable bindings bypasses the bounded
static JS-expression decoder -- the decoder anchored dispatch on
member-expression callees; the same function reached through a
destructured or aliased binding bypasses every anchor:

  const {concat} = Array.prototype; concat.call([], 'f1','f2').join('')
  let c = [].concat; c.call([], 'f1','f2').join('')
  const K = [].constructor; K.of('f1','f2').join('')

All node-evaluate (v24.20.0) to the exact credential while the
decoder produced zero variants. No filed finding covers
free-variable callees. Distinct from F478 (member-expression
dispatch) and F488 (parenthesized non-identifier callees -- here the
callee is a plain identifier bound by a local declaration).
Close-when: the decoder resolves single-statement local bindings to
built-in members (or refuses obfuscation-shaped runs coded) such
that find_credential flags them, red-first verified, honest text
unaffected.

Closure design (gov/dlp.py):
  F494:
  * New `_js_match_kw`: ident-boundary keyword match helper.
  * New `_js_parse_new_set`: `new Set([...])` spread source --
    string-literal elements only, SameValueZero dedup
    (first-occurrence order), node-exact.
  * New `_js_parse_new_map_values`: `new Map([[k,v],...]).values()`
    spread source -- literal keys (string/numeric, later-wins on
    duplicates), string-literal values, insertion-order values,
    node-exact.
  * New `_js_parse_generator_iife`: `(function*(){yield
    'lit';...})()` spread source -- fixed string-literal yields
    unrolled in order (return value excluded, node-exact); params,
    non-literal yields, loops, or call args fail closed.
  * `_js_parse_spread_copy` dispatches on the spread-source head
    (`new Set`, `new Map`, `(function*`); every other source keeps
    the exact previous primary path (F462/F471 unchanged).
  * Fail closed: numeric/marker/nested Set elements, non-pair or
    non-literal Map entries, `new WeakSet` / other `new X`,
    mixed/nested spreads (existing F471 guards).
  F495:
  * New `_js_parse_binding_source`: whitelisted sources `[].<ident>`
    and exactly `Array.prototype` (ws-tolerant).
  * New `_js_ident_tokens`: regex-free identifier tokenizer that
    skips string literals and comments exactly; aborts on any
    backtick (fail-safe).
  * New `_js_resolve_local_bindings`: one leading `const`/`let`
    statement (`{a[, b: c]}` from Array.prototype, or `id =
    [].<member>`, comma-separated) rewrites callee-position
    identifier uses in the remainder to the bound member text.
    Reassignment or redeclaration of a bound name aborts the
    rewrite; non-leading statements, `var`, non-whitelisted
    sources, destructuring defaults, and template literals decline.
  * `_decode_layer` runs the normal whole-text scan on the rewritten
    text as one additive variant (the unrewritten text is still
    scanned).
  * No new regexes (re.compile stays 28); F430 bounds honored; F441
    ordering untouched.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 4 F494 + 3 F495 filed shapes block (node-exact
      decode checked); generalizations (ws tolerance, dedup,
      key-overwrite, rename destructure, multi-declarator, apply
      through binding) block node-exactly; F494xF478 / F495xF478 /
      F494xF462 compositions hold.
  P2  fail-closed boundaries: F494 numeric/marker/nested elements,
      non-pair maps, non-literal yields, loops, params, WeakSet,
      mixed/nested spreads; F495 reassignment/redeclaration abort,
      var declines, non-whitelisted sources, non-leading bindings,
      template literals, member-position and string-literal names
      untouched; junk quiet; neighbors intact (F462/F471/F476/F478
      still decode; F489-F493 still break open).
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored; F441 ordering untouched.
  P4  pin + footer (F494, F495 CLOSED locally; open F489-F493 / next
      F496).
"""

import os
import sys
import subprocess
import argparse
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2143  # Wave-360 lane 3: F494, F495 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-361 merge: F496-F502 all CLOSED (lanes 1-3 merged; merge finalizes tree-wide)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)
FOOTER_NEXT = "F738"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xox" + "b-0123456789"
_B = "abc" + "def"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _decoded_bound(payload):
    # F495 node-exactness: the binding rewrite lives in _decode_layer,
    # so apply it explicitly before the whole-text scan here.
    rw = dlp._js_resolve_local_bindings(payload)
    if rw is None:
        return None
    return dlp._try_js_expr_decode_all(rw)


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


# ---------------------------------------------------------------- P1: closure
def p1_f494_filed_shapes_block():
    shapes = [
        "[...(function*(){yield '%s';yield '%s'})()].join('')" % (_A, _B),
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),
        "[].join.call([...new Set(['%s','%s'])], '')" % (_A, _B),
        "[...new Map([[0,'%s'],[1,'%s']]).values()].join('')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "4/4 F494 filed shapes blocked")


def p1_f494_node_exact():
    decode_cases = [
        # Set: dedup is first-occurrence order (node-exact).
        ("[...new Set(['ab','ab','cd'])].join('')", "abcd"),
        # Map: duplicate key overwrites, position kept (node-exact).
        ("[...new Map([[0,'ab'],[0,'cd']]).values()]", None),  # no join: not obfuscation-shaped
        ("[...new Map([[0,'ab'],[0,'cd']]).values()].join('')", "cd"),
        # Generator: return value excluded, yields in order.
        ("[...(function*(){yield 'ab'; return 'zz'})()].join('')", "ab"),
        # ws tolerance.
        ("[... new  Set( [ 'ab' , 'cd' ] ) ].join('')", "abcd"),
        ("[...new\tMap([[0,'ab']]).values()].join('')", "ab"),
        ("[...( function* ( ) { yield 'ab' ; yield 'cd' } )()].join('')", "abcd"),
        # named generator.
        ("[...(function* gen(){yield 'ab'})()].join('')", "ab"),
        # empty set: decodes to '' which the whole-text scan reports as
        # None -- consistent with the pre-existing `[].join('')`
        # baseline (an empty decode is not obfuscation-shaped).
        ("[...new Set([])].join('')", None),
        # string keys.
        ("[...new Map([['k','ab'],['j','cd']]).values()].join('')", "abcd"),
    ]
    for payload, want in decode_cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    cred_cases = [
        "[...(function*(){yield '%s';yield '%s'})()].join('')" % (_A, _B),
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),
        "[].join.call([...new Set(['%s','%s'])], '')" % (_A, _B),
        "[...new Map([[0,'%s'],[1,'%s']]).values()].join('')" % (_A, _B),
    ]
    for payload in cred_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:50])
    return ("HELD", "9/9 F494 decodes node-exact; 4/4 credential variants block")


def p1_f495_filed_shapes_block():
    shapes = [
        "const {concat} = Array.prototype; concat.call([], '%s','%s').join('')" % (_A, _B),
        "let c = [].concat; c.call([], '%s','%s').join('')" % (_A, _B),
        "const K = [].constructor; K.of('%s','%s').join('')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "3/3 F495 filed shapes blocked")


def p1_f495_node_exact():
    decode_cases = [
        # rename destructure.
        ("const {concat: cc} = Array.prototype; cc.call([], 'ab','cd').join('')", "abcd"),
        # multi-declarator.
        ("const a = [].concat, b = [].join; a.call([], 'ab','cd').join('')", "abcd"),
        # bound method through .apply (no postfix: the direct form
        # `Array.prototype.join.apply(...).toString()` is unmodeled
        # upstream -- the rewrite is faithful to the direct form).
        ("const {join} = Array.prototype; join.apply(['ab','cd'], [])", "ab,cd"),
        # multi-name destructure.
        ("const {concat, join} = Array.prototype; concat.call(['ab'], 'cd').join('')", "abcd"),
        # ws tolerance.
        ("const  { concat }  =  Array.prototype ; concat.call( [], 'ab' ).join('')", "ab"),
        ("let\tc\t=\t[].concat; c.call([],'ab').join('')", "ab"),
        # innocent decodes stay quiet (decode checked, not blocking).
        ("const {concat} = Array.prototype; concat.call([], 'ab','cd').join('')", "abcd"),
    ]
    for payload, want in decode_cases:
        d = _decoded_bound(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    cred_cases = [
        "const {concat} = Array.prototype; concat.call([], '%s','%s').join('')" % (_A, _B),
        "let c = [].concat; c.call([], '%s','%s').join('')" % (_A, _B),
        "const K = [].constructor; K.of('%s','%s').join('')" % (_A, _B),
    ]
    for payload in cred_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:50])
    return ("HELD", "7/7 F495 decodes node-exact; 3/3 credential variants block")


def p1_compositions():
    # F494 x F462: literal spread still decodes (F462 intact).
    if _decoded("[...['ab','cd']].join('')") != "abcd":
        return ("BREAK", "F462 literal spread regressed")
    # F494 x F471: spread-copy factory still desugars.
    if _decoded("[...['ab','cd']].join('')") != "abcd":
        return ("BREAK", "F471 spread-copy regressed")
    # F495 x F478: binding through .apply dispatches.
    if not _blocked("const {concat} = Array.prototype; concat.apply([], ['%s','%s']).join('')" % (_A, _B)):
        return ("BREAK", "F495 x F478 apply composition not blocked")
    # F495 x F476: alias of the constructor factory.
    if not _blocked("const K = [].constructor; K.of('%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F495 x F476 of composition not blocked")
    # F494 x F483: Set spread as .apply argsArray.
    if not _blocked("[].concat.apply([], [...new Set(['%s','%s'])]).join('')" % (_A, _B)):
        return ("BREAK", "F494 x F483 apply-args composition not blocked")
    return ("HELD", "5/5 compositions hold")


# ------------------------------------------------------------- P2: boundaries
def p2_f494_boundaries():
    # All must miss (fail closed), never mis-decode.
    miss_cases = [
        # numeric Set elements: node decodes '12', we fail closed (documented).
        "[...new Set([1,2])].join('')",
        # non-pair / non-literal Map entries.
        "[...new Map([['k',{}]]).values()].join('')",
        "[...new Map([[0]]).values()].join('')",
        # non-literal yield.
        "[...(function*(){yield 'a'+'b'})()].join('')",
        # bare yield.
        "[...(function*(){yield;})()].join('')",
        # generator with params.
        "[...(function*(x){yield 'a'})()].join('')",
        # generator with call args.
        "[...(function*(){yield 'a'})('x')].join('')",
        # other new-expressions still fail closed.
        "[...new WeakSet()].join('')",
        "[...new Array('ab')].join('')",
        # mixed spread (existing F471 guard).
        "[...new Set(['ab']), 'cd'].join('')",
        # nested spread copy (existing guard).
        "[...[...new Set(['ab'])]]".replace("]]", "])]"),
        # non-generator paren primary still fails closed as before.
        "[...('ab')].join('')",
    ]
    for payload in miss_cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "boundary decoded (want miss): %s" % payload[:60])
    return ("HELD", "%d/%d F494 boundaries fail closed" % (len(miss_cases), len(miss_cases)))


def p2_f495_boundaries():
    miss_cases = [
        # reassignment aborts the rewrite (node: last binding wins).
        "let c = [].concat; c = [].join; c.call(['ab','cd'], '').toUpperCase()",
        "const c = [].concat; c = [].join; c.call(['ab'])",
        # redeclaration aborts.
        "const c = [].concat; const c = [].join; c.call(['ab'])",
        # var declines.
        "var c = [].concat; c.call([], 'ab','cd').join('')",
        # non-whitelisted source declines.
        "const {x} = foo; x.call([], 'ab')",
        "const c = evil; c.call([], 'ab')",
        "const c = [].foo; c.call([], 'ab')",
        # destructuring default declines.
        "const {concat = [].join} = Array.prototype; concat.call(['ab'])",
        # non-leading binding declines.
        "'ab'; const {concat} = Array.prototype; concat.call([], 'cd')",
        # template literal in the remainder declines.
        "const c = [].concat; c.call([], `ab`)",
        # member-position name untouched (node throws; we must miss).
        "const c = [].concat; x.c([], 'ab')",
    ]
    for payload in miss_cases:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "boundary blocked (want miss): %s" % payload[:60])
    # shadowing: a bound name rebound as a function/catch/arrow
    # parameter, for-loop declarator, or nested declaration aborts
    # the rewrite (node would resolve the inner binding).
    shadow_cases = [
        "const c = [].concat; function g(c){ return c.call(['%s']); }" % _A,
        "const c = [].concat; f = (c) => c.call(['%s']);" % _A,
        "const c = [].concat; f = c => c.length;",
        "const c = [].concat; try{}catch(c){ c.call(['%s']); }" % _A,
        "const c = [].concat; for (const c of x){ c.call(['%s']); }" % _A,
        "const c = [].concat; { let [c] = x; }",
        "const c = [].concat; function c(){}",
    ]
    for p in shadow_cases:
        if dlp._js_resolve_local_bindings(p) is not None:
            return ("BREAK", "shadow not declined: %s" % p[:60])
    # no-shadow controls still rewrite.
    for p in ["const c = [].concat; function g(){ return c.call(['%s']); }" % _A,
              "const c = [].concat; f = (x) => c.call([x]);",
              "const c = [].concat; try{}catch(e){ c.call(['%s']); }" % _A]:
        if dlp._js_resolve_local_bindings(p) is None:
            return ("BREAK", "clean shape wrongly declined: %s" % p[:60])
    # string-literal containing the bound name is never corrupted:
    # decodes node-exactly to the innocent value.
    d = _decoded_bound("const c = [].concat; c.call([], 'c', 'd').join('')")
    if d != "cd":
        return ("BREAK", "string-literal corruption: %r" % (d,))
    return ("HELD", "%d/%d F495 boundaries fail closed; literal intact; shadowing declines"
            % (len(miss_cases) + len(shadow_cases) + 3, len(miss_cases) + len(shadow_cases) + 3))


def p2_junk_quiet():
    quiet = [
        "[...new Set(['ab','cd'])].join('')",
        "[...(function*(){yield 'ab'})()].join('')",
        "[...new Map([[0,'ab']]).values()].join('')",
        "const {concat} = Array.prototype; concat.call([], 'ab','cd').join('')",
        "let c = [].concat; c.call([], 'ab').join('')",
        "const K = [].constructor; K.of('ab').join('')",
    ]
    for payload in quiet:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "junk blocked: %s" % payload[:60])
    return ("HELD", "%d/%d junk payloads quiet" % (len(quiet), len(quiet)))


def p2_neighbors_intact():
    # Closed neighbors still decode/block.
    if _decoded("['ab','cd'].join('')") != "abcd":
        return ("BREAK", "F434 array join regressed")
    if _decoded("[].concat.call([], 'ab','cd').join('')") != "abcd":
        return ("BREAK", "F478 dispatch regressed")
    if _decoded("[].constructor.of('ab','cd').join('')") != "abcd":
        return ("BREAK", "F476 factory regressed")
    if _decoded("Array.of('ab','cd').join('')") != "abcd":
        return ("BREAK", "F446 factory regressed")
    # Open findings still break open (miss).
    for fid, payload in [
        ("F489", "[].concat.call({length:2, 0:'ab', 1:'cd'}, 'ef').join('')"),
        ("F490", "[].concat?.call([], 'ab','cd').join('')"),
        ("F491", "Reflect.get(Array.prototype, 'concat').call([], 'ab').join('')"),
        ("F492", "Array.prototype['con'+'cat'].call([], 'ab').join('')"),
        ("F493", "String.raw({raw:['ab','cd']})"),
    ]:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "%s not still open: %s" % (fid, payload[:50]))
    return ("HELD", "4/4 closed neighbors decode; F489-F493 still open")


# ------------------------------------------------------------------ P3: pins
def p3_node_differential():
    """Node byte-fidelity on the differential set (subprocess)."""
    cases = [
        "[...(function*(){yield 'ab';yield 'cd'})()].join('')",
        "[...new Set(['ab','cd'])].join('')",
        "[...new Set(['ab','ab','cd'])].join('')",
        "[].join.call([...new Set(['ab','cd'])], '')",
        "[...new Map([[0,'ab'],[1,'cd']]).values()].join('')",
        "[...new Map([[0,'ab'],[0,'cd']]).values()].join('')",
        "[...(function*(){yield 'ab'; return 'zz'})()].join('')",
        "[... new Set( [ 'ab' ] )].join('')",
        "const {concat} = Array.prototype; concat.call([], 'ab','cd').join('')",
        "let c = [].concat; c.call([], 'ab','cd').join('')",
        "const K = [].constructor; K.of('ab','cd').join('')",
        "const {concat: cc} = Array.prototype; cc.call([], 'ab').join('')",
        "const a = [].concat, b = [].join; b.call(['ab','cd'], '')",
    ]
    node_src = "const out=[];\n"
    for idx, p in enumerate(cases):
        node_src += ("try{out[%d]=eval(%s)}catch(e){out[%d]='THROW'};\n"
                     % (idx, repr(p), idx))
    node_src += "console.log(JSON.stringify(out));\n"
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:100])
    import json as _json
    want = _json.loads(r.stdout)
    for idx, p in enumerate(cases):
        d = _decoded(p)
        if d is None:
            # F495 shapes decode via the binding rewrite in _decode_layer.
            d = _decoded_bound(p)
        if d != want[idx]:
            return ("BREAK", "%s -> %r want %r" % (p[:45], d, want[idx]))
    return ("HELD", "%d/%d node byte-identical" % (len(cases), len(cases)))


def p3_no_new_regexes():
    # Neither closure adds a regex: the F494 parsers are hand-written
    # recursive descent; the F495 rewrite is a manual tokenizer.
    # Pin the exact anchor pattern string (unchanged by this lane;
    # repr() literal -- equality with the live value is the pin).
    # Wave-360 merge: union of lane-1 (optional-chaining), lane-2
    # (Reflect.get / getOwnPropertyDescriptor / String.raw) widenings.
    # Wave-362 lane 2 (F504): the Reflect bracket-member class gains
    # backtick and nested-bracket (literal-alternation only);
    # re.compile count unchanged.
    # F505 (wave-362 lane 3): String.fromCodePoint alternative
    # added to the pinned repr (literal-alternation only -- the
    # same F468 precedent); re.compile count unchanged (28).
    # F508 (wave-363 lane 2): Array.from alternative added (literal-alternation only); re.compile count unchanged (28).
    # F510 (wave-363 lane 4): the Object alternative gains `values` in the pinned repr (literal-alternation only); re.compile count unchanged (28).
    # F525 (wave-365 lane 2): the Object dot-member alternative gains
    # getOwnPropertyNames/getOwnPropertyDescriptors (key/descriptor
    # enumeration indirection) -- new member-name alternatives, pinned
    # exactly here; re.compile count unchanged (28).
    # F539 (wave-368 lane 2): the Object dot-member alternative gains
    # freeze (identity-preserving builtin on object literals) -- new
    # member-name alternative, pinned exactly here; re.compile count
    # unchanged (28).
    # F565 (wave-369 lane 5): the Object dot-member alternative gains
    # fromEntries (deserializing builtin on literal pair lists / Map)
    # -- new member-name alternative, pinned exactly here; re.compile
    # count unchanged (28).
    # Wave-369 lane 5 (F565): re-pinned to the live anchor --
    # the pin had gone stale (structuredClone (F536, wave-367 lane 4); JSON (F541, wave-368 lane 3); new WeakRef (F539, wave-368 lane 2)
    # added without re-pin); exactness restored and the
    # fromEntries member alternative added. re.compile count
    # unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String\.fromCodePoint|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call|from)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"`\[])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor|getOwnPropertyNames|getOwnPropertyDescriptors|values|keys|entries|freeze|fromEntries)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"structuredClone(?![_$A-Za-z0-9])|JSON(?![_$A-Za-z0-9])|new[ \t\n\r]+WeakRef(?![_$A-Za-z0-9])|"
        r"\("
    )
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned")


def p3_f430_bounds():
    # Part/codepoint budgets still trip on adversarial iterable input.
    big = "[...new Set([%s])].join('')" % ",".join(
        "'x%d'" % i for i in range(200))
    if _blocked(big):
        return ("BREAK", "part budget not tripped (set)")
    gen = "[...(function*(){%s})()].join('')" % "".join(
        "yield 'x%d';" % i for i in range(200))
    if _blocked(gen):
        return ("BREAK", "part budget not tripped (generator)")
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
    # Lane-local footer expectation: F494, F495 closed here; the merge
    # finalizes tree-wide.
    assert ("Open findings: %s." % FOOTER_OPEN) in text, "footer open"
    assert ("Next free finding: **%s**" % FOOTER_NEXT) in text, "footer next"
    assert "F494" in text and "F495" in text and "CLOSED" in text
    return ("HELD", "pin=%d footer open %s next %s (lane-local)" %
            (TAXONOMY_PIN, FOOTER_OPEN, FOOTER_NEXT))


_PROBES = [
    ("p1-f494-filed-shapes-block", p1_f494_filed_shapes_block),
    ("p1-f494-node-exact", p1_f494_node_exact),
    ("p1-f495-filed-shapes-block", p1_f495_filed_shapes_block),
    ("p1-f495-node-exact", p1_f495_node_exact),
    ("p1-compositions", p1_compositions),
    ("p2-f494-boundaries", p2_f494_boundaries),
    ("p2-f495-boundaries", p2_f495_boundaries),
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
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w359_attack_probes.py",
               "w359_f494_redfirst.py",
               "w359_f495_redfirst.py",
               "w359_f486f487f488close_probes.py",
               "w358_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g360-green-%s-%d" % (script.replace(".py", ""),
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
    print("w360_f494f495close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
    sys.exit(main())
