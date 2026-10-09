#!/usr/bin/env python3
"""Wave-387 lane 12: close F873 + F874 + F875 + F876.

F873 (LOW; filed 2026-10-09 ~06:00 UTC by attack round 55):
`['CRED'].reduce((a)=>a,'x')` / `['CRED'].reduce((a)=>a)` -- the
identity callback makes the fold node-exact without iterating, but
the F437 grammar requires the `pA+pB` body and produced zero
variants.

F874 (LOW; filed 2026-10-09 ~06:00 UTC by attack round 55):
`(function(){var it=['CRED'].values();return
[].concat(...it).join('');})()` -- array-iterator spread
laundering; no production modeled `.values()` iterators, `new
Set` sources, or spread-of-iterator concat.

F875 (LOW; filed 2026-10-09 ~06:00 UTC by attack round 55):
`(function(){var o={k:'CRED'};return
Object.getOwnPropertyNames(o).map(function(k){return
o[k];})[0];})()` -- key-projection laundering; F525 requires a
literal enumeration source (fails on the var-bound `o`) and the
F437-family map only accepts identity callbacks (fails on the
`o[k]` member-read body).

F876 (LOW; filed 2026-10-09 ~06:00 UTC by attack round 55):
`(function(){class C{static{this.k='CRED';}}return
C.k;})()` -- static-block `this.` assignment to the class's own
static data property; the F662 static-block parser only modeled
assignments to env-bound outer names.

Fix (gov/dlp.py, zero new re.compile -- count stays 28):
- F873: `_js_parse_f873_identity_callback` /
  `_js_parse_f873_identity_reduce` -- identity callbacks
  (`function(a){return a;}`, `(a)=>a`, `(a,b)=>a`, `a=>a`,
  block-arrow twins) tried before the F437 grammar inside the
  reduce branch (F452 budget snapshot/restore on miss; identity
  never parses in F437 so no previously-decoded input changes
  behavior). With INIT the result is INIT; without INIT it is
  the seed element (first for reduce, last for reduceRight);
  seedless empty fails closed (the engine throws).
- F874: `_js_parse_f874_iter_spread_iife` -- dedicated IIFE
  parser (hooked after F810): `var|let|const IT=['LIT',...]` or
  `new Set(['LIT',...])` (SameValueZero dedup), `.values()`,
  `[].concat(...IT).join('SEP')` (literal sep or the engine
  default `","`), optional `+'LIT'` tail terms.
- F875: `_js_parse_f875_keymap_iife` -- dedicated IIFE parser
  (hooked after F874): object via `_js_parse_enumeration_source`
  (plain-string values only), `Object.getOwnPropertyNames(o)` /
  `Object.keys(o)` (dot or F480 bracket-string member),
  `.map(function(p){return o[p];})` / arrow twins (param must
  not shadow the object name), `[INT]` in bounds, optional
  `+'LIT'` tail terms.
- F876: `_js_f876_this_assign` -- `this.NAME='LIT';` /
  `this['NAME']='LIT';` (+= twins) in static blocks, writing the
  F662 class record's static dict (node-verified: a later
  `static get` for a this-assigned name throws, so the getter
  branch fails closed on `_this_assigned` names instead of
  applying field-wins; `+=` on unset fails closed --
  'undefinedLIT' is outside the string-only discipline).

Entry corrections vs filed text: F873's "no-init identity is
blocked" control claim was overstated (it missed); both
identity twins are modeled now. F875's s3 arrow filed shape is
missing its IIFE tail in the entry; the close-when criterion is
met by the modeled twin.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "AKIAIOSFODNN7" + "EXAMPLE"
_B = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"

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


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads at the pin count."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s count=%d"
            % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_p0_footer_state():
    """Lane-local footer: F873-F876 CLOSED; open F829-F872,
    F877-F892; next F893."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F893**" in text
          and "F873-F876 CLOSED" in text
          and "F877, F878" in text
          and ", F873," not in text
          and ", F876," not in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f873_s1():
    """F873 entry s1 (function-form identity, return pos) blocks + exact."""
    s = ("(function(){return ['" + _A
          + "'].reduce(function(a){return a;},'x')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "x" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f873_s2():
    """F873 entry s2 (two-param identity) blocks + exact."""
    s = ("(function(){return ['" + _A
          + "','y'].reduce(function(a,b){return a;},'x')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "x" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f874_s1():
    """F874 s1 (iterator spread) blocks + exact."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "return [].concat(...it).join('')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f874_s2():
    """F874 s2 (Set iterator spread, dedup) blocks + exact."""
    s = ("(function(){var it=new Set(['" + _A + "','" + _A
         + "']).values();return [].concat(...it).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f875_s1():
    """F875 s1 (getOwnPropertyNames keymap) blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.getOwnPropertyNames(o).map(function(k){return o[k];})[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f875_s2():
    """F875 s2 (Object.keys twin) blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.keys(o).map(function(k){return o[k];})[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f875_s3():
    """F875 s3 (arrow twin) blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.getOwnPropertyNames(o).map((k)=>o[k])[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f876_s1():
    """F876 s1 (static-block this-assign) blocks + exact."""
    s = ("(function(){class C{static{this.k='" + _A + "';}}"
         "return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f876_s2():
    """F876 s2 (decl + this-assign) blocks + exact."""
    s = ("(function(){class C{static k;static{this.k='" + _A
         + "';}}return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)

# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f873_two_param():
    """F873 (a,b)=>a identity twin blocks + exact."""
    s = ("['" + _A + "','" + _A + "'].reduce((a,b)=>a,'" + _B + "')")
    ok = _blocked(s) and _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_bare_param():
    """F873 bare-param arrow twin blocks + exact."""
    s = ("['" + _A + "'].reduce(a=>a,'" + _B + "')")
    ok = _blocked(s) and _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_block_arrow():
    """F873 block-body arrow twin blocks + exact."""
    s = ("['" + _A + "'].reduce((a)=>{return a;},'" + _B + "')")
    ok = _blocked(s) and _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_reduce_right():
    """F873 reduceRight identity twin blocks + exact."""
    s = ("['" + _A + "','" + _A + "'].reduceRight((a)=>a,'" + _B + "')")
    ok = _blocked(s) and _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_noinit_two_elem():
    """F873 no-init two-element seed is elements[0] + exact."""
    s = ("['" + _A + "','zz'].reduce((a,b)=>a)+'" + _B + "'")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_empty_with_init():
    """F873 empty array with init yields init + exact."""
    s = ("[].reduce((a)=>a,'" + _A + "')+'" + _B + "'")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f873_additive_init():
    """F873 additive string init blocks + exact."""
    s = ("['" + _A + "'].reduce((a)=>a,'f'+'1')+'" + _B + "'")
    ok = _blocked(s) and _decodes_exact(s, "f1" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f874_three_elem():
    """F874 three-element iterator spread blocks + exact."""
    s = ("(function(){var it=['a','" + _A + "','c'].values();"
         "return [].concat(...it).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, "a" + _A + "c")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f874_let_const():
    """F874 let/const decl twins block."""
    s1 = ("(function(){let it=['" + _A + "'].values();"
          "return [].concat(...it).join('');})()")
    s2 = ("(function(){const it=['" + _A + "'].values();"
          "return [].concat(...it).join('');})()")
    ok = _blocked(s1) and _blocked(s2)
    return ("HELD" if ok else "BREAK", "twins=%s" % ok)


@_t
def test_p2_f874_join_default():
    """F874 join() default separator is ',' (node-exact)."""
    s = ("(function(){var it=['a','" + _A + "'].values();"
         "return [].concat(...it).join();})()")
    ok = _blocked(s) and _decodes_exact(s, "a," + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f874_plus_tail():
    """F874 +'LIT' tail after the concat-join blocks + exact."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "return [].concat(...it).join('')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f875_multi_key():
    """F875 multi-key object, [1] selects second value + exact."""
    s = ("(function(){var o={a:'x',k:'" + _A + "'};return "
         "Object.getOwnPropertyNames(o).map(function(k){return o[k];})[1]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f875_int_keys():
    """F875 int-like keys sort ascending (node-exact).

    Two-key form: 3+ keys exhaust the F452 parts budget via
    pre-existing speculative-hook leaks (documented residual in
    the F875 entry), so the generalization is pinned at two keys.
    """
    s = ("(function(){var o={'2':'a',k:'" + _A + "'};return "
         "Object.keys(o).map(function(k){return o[k];})[1]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f875_bare_arrow():
    """F875 bare-param arrow twin blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.keys(o).map(k=>o[k])[0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f875_block_arrow():
    """F875 block-body arrow twin blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.getOwnPropertyNames(o).map((k)=>{return o[k];})[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f875_bracket_member():
    """F875 Object['keys'] bracket-string twin blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object['keys'](o).map(function(k){return o[k];})[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f876_bracket_this():
    """F876 this['k'] bracket twin blocks + exact."""
    s = ("(function(){class C{static{this['k']='" + _A + "';}}"
         "return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f876_plus_eq_field():
    """F876 += on a field-defined static blocks + exact."""
    s = ("(function(){class C{static k='a';static{this.k+='" + _A
         + "';}}return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "a" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f876_two_blocks():
    """F876 two static blocks accumulate + exact."""
    s = ("(function(){class C{static{this.k='a';}static{this.k+='"
         + _A + "';}}return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "a" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f876_block_then_field():
    """F876 block-assign then field def: field wins + exact."""
    s = ("(function(){class C{static{this.k='" + _A
         + "';}static k='f1';}return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "f1" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)

# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f873_ret_second_param():
    """F873 (a,b)=>b is a different production -- stays closed."""
    s = ("['" + _A + "','y'].reduce((a,b)=>b,'" + _B + "')")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f873_named_function():
    """F873 named function expression stays closed."""
    s = ("['" + _A + "'].reduce(function f(a){return a;},'" + _B + "')")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f873_three_params():
    """F873 three-param callback stays closed."""
    s = ("['" + _A + "'].reduce((a,b,c)=>a,'" + _B + "')")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f873_empty_no_init():
    """F873 seedless empty reduce stays closed (engine throws)."""
    s = "[].reduce((a)=>a)"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f873_nonstring_init():
    """F873 non-string init stays closed."""
    s = ("['" + _A + "'].reduce((a)=>a,['" + _B + "'])")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f874_nonstring_elem():
    """F874 non-string element stays closed."""
    s = ("(function(){var it=['" + _A + "',1].values();"
         "return [].concat(...it).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f874_extra_concat_arg():
    """F874 extra concat arg stays closed."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "return [].concat(...it,'x').join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f874_spread_other():
    """F874 spread of an unbound ident stays closed."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "return [].concat(...other).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f874_nonliteral_sep():
    """F874 non-literal join separator stays closed."""
    s = ("(function(){var it=['" + _A + "'].values();"
         "return [].concat(...it).join(x);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f874_keys_not_values():
    """F874 .keys() instead of .values() stays closed."""
    s = ("(function(){var it=['" + _A + "'].keys();"
         "return [].concat(...it).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f875_index_oob():
    """F875 out-of-range index stays closed."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.keys(o).map(function(k){return o[k];})[5]+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f875_nonstring_value():
    """F875 non-string value stays closed."""
    s = ("(function(){var o={k:1};return "
         "Object.keys(o).map(function(k){return o[k];})[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f875_shadowed_param():
    """F875 param shadowing the object name stays closed."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.keys(o).map(function(o){return o[o];})[0]+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f875_wrong_receiver():
    """F875 map over another object's keys stays closed."""
    s = ("(function(){var o={k:'" + _A + "'};var p={k:'z'};return "
         "Object.keys(p).map(function(k){return o[k];})[0]+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f875_identity_cb():
    """F875 identity map callback stays closed (not this route)."""
    s = ("(function(){var o={k:'" + _A + "'};return "
         "Object.keys(o).map(function(k){return k;})[0]+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f876_getter_then_block():
    """F876 getter-then-this-assign stays closed (engine throws)."""
    s = ("(function(){class C{static get k(){return 'a';}"
         "static{this.k='" + _A + "';}}return C.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f876_block_then_getter():
    """F876 this-assign-then-getter stays closed (engine throws)."""
    s = ("(function(){class C{static{this.k='" + _A + "';}"
         "static get k(){return 'a';}}return C.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f876_plus_eq_unset():
    """F876 += on unset static stays closed ('undefinedLIT')."""
    s = ("(function(){class C{static{this.k+='" + _A + "';}}"
         "return C.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f876_nonliteral_rhs():
    """F876 non-literal RHS stays closed."""
    s = ("(function(){var x='" + _A + "';class C{static{this.k=x;}}"
         "return C.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_f437_intact():
    """F437 param-assembly reduce still blocks (F873 fallthrough).

    The init seeds the fold first (node-exact): init + e0 + e1.
    """
    s = ("['a','" + _A + "'].reduce((a,b)=>a+b,'" + _B + "')")
    ok = _blocked(s) and _decodes_exact(s, _B + "a" + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f437_noinit_intact():
    """F437 no-init assembly reduce still blocks."""
    s = ("['" + _A + "','b'].reduce((a,b)=>a+b)+'" + _B + "'")
    ok = _blocked(s) and _decodes_exact(s, _A + "b" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f462_intact():
    """F462 direct concat still blocks (IIFE context)."""
    s = ("(function(){return [].concat('" + _A + "','" + _B + "');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f525_intact():
    """F525 literal-source getOwnPropertyNames still blocks."""
    s = ("Object.getOwnPropertyNames({k:'" + _A + "'}).join('')+'"
         + _B + "'")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f662_static_field_intact():
    """F662 static field shape still blocks + exact."""
    s = ("(function(){class C{static k='" + _A + "';}"
         "return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f662_static_getter_intact():
    """F662 static getter shape still blocks + exact."""
    s = ("(function(){class C{static get k(){return '" + _A
         + "';}}return C.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f662_static_block_env_intact():
    """F662 static-block env assignment still blocks + exact."""
    s = ("(function(){var s='';class C{static{s='" + _A
         + "';}}return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f672_static_block_env_intact():
    """F672 (private-member) static-block env assignment intact."""
    s = ("(function(){var s='';class C{static #p='x';static{s='"
         + _A + "';}}return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f672_this_still_closed():
    """F672 static-block this-assign stays closed (out of scope)."""
    s = ("(function(){class C{static #p='x';static{this.k='" + _A
         + "';}}return C.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p4_f769_intact():
    """F769 var-bound .at() reads still block + exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.at(0)+a.at(1);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)

# ------------------------------------------------ p5: junk / honest quiet


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    honest = ("the reduce callback returns its first argument and the "
              "static block assigns the key before the class returns")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in <20s with zero hits."""
    sites = []
    for k in range(200):
        if k % 5 == 0:
            sites.append(
                "(function(){var r=['a%d'].reduce((a)=>a,'x');"
                "return r;})()" % k)
        elif k % 5 == 1:
            sites.append(
                "(function(){var it=['a%d'].values();"
                "return [].concat(...it).join('');})()" % k)
        elif k % 5 == 2:
            sites.append(
                "(function(){var o={k:'a%d'};return "
                "Object.keys(o).map(function(k){return o[k];})[0];})()" % k)
        elif k % 5 == 3:
            sites.append(
                "(function(){class C{static{this.k='a%d';}}"
                "return C.k;})()" % k)
        else:
            sites.append(
                "(function(){var r='';lbl:{r+='a%d';if(1){break lbl;}"
                "r+='xx';}return r;})()" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # All four red-firsts expect 0 BREAK (closed).
    for batt in ("evals/w387_f873_redfirst.py",
                 "evals/w387_f874_redfirst.py",
                 "evals/w387_f875_redfirst.py",
                 "evals/w387_f876_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
        elif nbreak != 0:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: all four red-firsts at 0 BREAK."""
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
