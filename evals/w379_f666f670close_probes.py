#!/usr/bin/env python3
"""Wave-379 lane 4: close F666 + F670 (Proxy trap family).

F666 (LOW, filed 2026-10-08 by wave-378 lane 7, attack round 46): Proxy
traps beyond get bypass the bounded static JS-expression decoder --
F642 (CLOSED) models get traps with var-bound operands, but apply
traps (callable proxy: p() invokes the trap) and has traps
(in-operator guards: 'k' in p invokes the trap with the key) had no
modeled path.

F670 (LOW, filed 2026-10-08 by wave-378 lane 7, found while pinning the
F642 control): the F642 closure modeled only the concise-arrow get-trap
form; the arrow block-body twin, the function-expression twin, and the
method-shorthand twin all node-evaluated to the exact credential while
the decoder missed.

Fix (gov/dlp.py, zero new re.compile):
- F670: _js_parse_f642_proxy_trap generalized to four node-exact
  function forms (concise arrow, block-body arrow, function
  expression, method shorthand) sharing _js_parse_f6xx_additive_fn
  (F642 bound-operand additive discipline). Strictly additive: no
  previously-decoded input changes behavior (verified by the F642
  red-first + close battery).
- F666 apply: _js_parse_f666_apply_trap_iife --
  (function(){[DECL X='LIT';]*var|let|const p=new
  Proxy(function(){},{apply:TRAP});return p()(+'LIT')*;})() --
  the call p() evaluates the trap body (four function forms, params
  ignored); the terminal tail allows literals, bound idents, and
  +p() re-invocations (the trap body is deterministic, so each call
  yields the same value -- node-exact v24.20.0).
- F666 has: _js_parse_f666_has_trap_iife --
  (function(){var|let|const p=new Proxy({},{has:TRAP});
  [var|let|const o={...};]*return
  ('GL' in p?THEN:JUNK)(+'LIT')*;})() -- the in-operator invokes
  has(target, GL); the modeled trap body is exactly
  `return IDENT==='LIT';` with IDENT the trap's second param (the
  key), so the guard is true iff GL===LIT (node-exact); on true the
  ternary picks THEN (a member read on an object-literal binding via
  _js_parse_f535_object, or a string literal); on false the engine
  yields JUNK+tail (no credential) so the decoder fails closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


# ------------------------------------------------ p1: filed shapes (must block)

@_t
def test_p1_f666_apply_filed():
    """F666 filed shape 1: apply trap via p() blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function(){return '"
         + _A + "';}});return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f666_has_filed():
    """F666 filed shape 2: has trap in-operator guard blocks."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f670_arrow_block():
    """F670 filed shape 1: get trap arrow block body blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B
         + "';var p=new Proxy({},{get:(t,k)=>{return a+b;}});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f670_function_expr():
    """F670 filed shape 2: get trap function expression blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B
         + "';var p=new Proxy({},{get:function(t,k){return a+b;}});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f670_method_shorthand():
    """F670 filed shape 3: get trap method shorthand blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B
         + "';var p=new Proxy({},{get(t,k){return a+b;}});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)

@_t
def test_p2_apply_concise_arrow():
    """Apply concise-arrow twin blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply:()=>'" + _A + "'});"
         "return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_method_shorthand():
    """Apply method-shorthand twin blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply(){return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_block_arrow():
    """Apply block-body arrow twin blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply:()=>{return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_bound_operand():
    """Apply trap body over a bound ident blocks."""
    s = ("(function(){var a='" + _A + "';var p=new Proxy(function(){},"
         "{apply:function(){return a;}});return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_named_function():
    """Apply named function-expression twin blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function tr(){return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_reinvoke_tail():
    """Apply +p() re-invocation tail decodes node-exact (deterministic trap)."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function(){return '" + _A + "';}});"
         "return p()+'" + _B + "'+p();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_apply_let_twin():
    """Apply let/const decl twins block."""
    shapes = [
        "(function(){let p=new Proxy(function(){},{apply:function(){return '" + _A + "';}});return p()+'" + _B + "';})()",
        "(function(){const p=new Proxy(function(){},{apply:function(){return '" + _A + "';}});return p()+'" + _B + "';})()",
    ]
    got = [_blocked(s) and _decodes_exact(s, _A + _B) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "twins=%s" % got)


@_t
def test_p2_has_method_shorthand():
    """Has method-shorthand twin blocks."""
    s = ("(function(){var p=new Proxy({},{has(t,k){return k==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_block_arrow():
    """Has block-body arrow twin blocks."""
    s = ("(function(){var p=new Proxy({},{has:(t,k)=>{return k==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_concise_arrow():
    """Has concise-arrow twin blocks."""
    s = ("(function(){var p=new Proxy({},{has:(t,k)=>k==='x'});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_literal_then():
    """Has literal THEN branch blocks (benign generalization)."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "return ('x' in p?'" + _A + "':'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_bracket_then():
    """Has bracket-member THEN read blocks."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o['x']:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_multi_prop_object():
    """Has multi-property object binding: right member picked."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={w:'jx',x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_has_bound_tail():
    """Has bound tail operand decodes node-exact (binding section)."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var b='" + _B + "';var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f670_named_function_expr():
    """F670 named function-expression twin blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:function gt(t,k){return a+b;}});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f670_bare_ident_param():
    """F670 bare-ident param concise arrow still blocks (F642 discipline)."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:t=>a+b});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f670_async_named_param():
    """A param literally named async is a SYNC arrow (node-verified) -- blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:async=>a+b});return p.anything;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

@_t
def test_p3_has_guard_false():
    """Has guard key mismatch: engine yields junk+tail, no credential -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={x:'" + _A + "'};return ('y' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_compare_on_target():
    """Has trap comparing the TARGET param (not the key): guard false -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return t==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_single_param():
    """Has trap with one param: no key binding -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t){return t==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_loose_equality():
    """Has trap with == (not ===): tight scope -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k=='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_nonempty_target():
    """Has trap on a non-{} target: tight scope -- miss."""
    s = ("(function(){var p=new Proxy([],{has:function(t,k){return k==='x';}});"
         "var o={x:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_missing_member():
    """Has THEN member missing from the object: engine yields undefined -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={y:'" + _A + "'};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_has_nonstring_member():
    """Has THEN member not a string: engine yields '5...' -- miss."""
    s = ("(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});"
         "var o={x:5};return ('x' in p?o.x:'junk')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_async_arrow():
    """Apply async arrow trap: engine yields a Promise -- miss, never mis-decoded."""
    s = ("(function(){var p=new Proxy(function(){},{apply:async()=>{return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_async_function():
    """Apply async function-expression trap: engine yields a Promise -- miss."""
    s = ("(function(){var p=new Proxy(function(){},{apply:async function(){return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_with_args():
    """Apply trap invoked with args: tight scope (filed shape is p()) -- miss."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function(){return '" + _A + "';}});"
         "return p('z')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_nonempty_target():
    """Apply trap on a non-empty function target: tight scope -- miss."""
    s = ("(function(){var p=new Proxy(function(){var z=1;},{apply:function(){return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_wrong_trap_key():
    """Proxy with a get trap invoked as a call: get trap never fires -- miss."""
    s = ("(function(){var p=new Proxy(function(){},{get:function(){return '" + _A + "';}});"
         "return p()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_extra_handler_prop():
    """Apply handler with an extra property: tight scope -- miss."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function(){return '" + _A + "';},"
         "get:function(){return 'jx';}});return p()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_apply_trap_not_invoked():
    """Apply trap present but proxy never called: no laundering -- miss."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function(){return '" + _A + "';}});"
         "return '" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f670_async_arrow():
    """F670 async-arrow get trap: engine yields a Promise -- miss, never mis-decoded."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:async(t,k)=>a+b});return p.anything;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f670_generator_trap():
    """F670 generator get trap: tight scope -- miss."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:function*(t,k){return a+b;}});return p.anything;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f670_nonreturn_block():
    """F670 block-body arrow without return: engine yields undefined -- miss."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:(t,k)=>{a+b;}});return p.anything;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f670_unbound_ident():
    """F670 trap body with an unbound ident: engine ReferenceError -- miss."""
    s = ("(function(){var a='" + _A + "';var p=new Proxy({},{get(t,k){return a+z;}});"
         "return p.anything;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: open neighbors still miss

@_t
def test_p4_open_neighbors_still_miss():
    """F662-F665, F667-F669, F671 now CLOSED (wave-379 merge): they block."""
    shapes = [
        # F662 class static field
        "(function(){class C{static x='" + _A + "';}return C.x+'" + _B + "';})()",
        # F663 fromEntries member reads
        "(function(){var o=Object.fromEntries([['a','" + _A + "'],['b','" + _B + "']]);return o.a+o.b;})()",
        # F664 descriptor .get() in additive position
        "(function(){var o={get x(){return '" + _A + "';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()",
        # F665 bare ?. read
        "({x:'" + _A + "'})?.x+'" + _B + "'",
        # F667 with-scope
        "(function(){var o={x:'" + _A + "',y:'" + _B + "'};with(o){return x+y;}})()",
        # F668 custom tag
        "(function(){function tag(s){return s[0]+'" + _B + "';}return tag" + chr(96) + _A + chr(96) + ";})()",
        # F669 Set spread
        "(function(){var st=new Set(['" + _A + "','" + _B + "']);return [...st].join('');})()",
        # F671 var-bound dot read in IIFE-return additive
        "(function(){var o={x:'" + _A + "'};return o.x+'" + _B + "';})()",
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "miss=%s" % got)


# ------------------------------------------------ p5: composition (closed neighbors held)

@_t
def test_p5_f642_still_held():
    """F642's own shapes still block (concise arrow, getter, WeakRef)."""
    shapes = [
        "(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()",
        "(function(){var a='" + _A + "',b='" + _B + "';var o={get s(){return a+b;}};return o.s;})()",
        "(function(){var a='" + _A + "',b='" + _B + "';var w=new WeakRef({get s(){return a+b;}});return w.deref().s;})()",
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


@_t
def test_p5_junk_quiet():
    """No-credential trap shapes stay quiet."""
    shapes = [
        "(function(){var p=new Proxy(function(){},{apply:function(){return 'jx';}});return p()+'jy';})()",
        "(function(){var p=new Proxy({},{has:function(t,k){return k==='x';}});var o={x:'jx'};return ('x' in p?o.x:'junk')+'jy';})()",
        "(function(){var a='jx',b='jy';var p=new Proxy({},{get(t,k){return a+b;}});return p.anything;})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: pin, footer, no new regexes

@_t
def test_p6_pin_footer():
    """Pin 2143; lane-local footer (open F662-F665, F667-F669, F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F713**" in text)  # Wave-379 lane 4: F666, F670 CLOSED; open F662-F665, F667-F669, F671 / next F672
    ok = ok and ("Open findings: F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712." in text)  # Wave-379 lane 4: F666, F670 CLOSED; open F662-F665, F667-F669, F671 / next F672
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf

@_t
def test_p7_perf():
    """200 mixed trap sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var p=new Proxy(function(){},{apply:function(){return 'a%d';}});return p()+'b';})()" % k)
        corpus.append("(function(){var a='a%d',b='b';var p=new Proxy({},{get(t,k){return a+b;}});return p.x;})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w378_f666_redfirst.py", 0),
                               ("evals/w378_f670_redfirst.py", 0),
                               ("evals/w378_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p8_green_check():
    """Depth-1 green check: F666/F670 red-firsts + wave-378 attack battery green."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
