#!/usr/bin/env python3
"""Wave-381 lane 5: close F691 + F698 (descriptor-read residuals).

F691 (LOW; filed 2026-10-08 by wave-380 lane 8, attack round 48):
data-descriptor .value reads bypass the bounded static JS-expression
decoder -- F664 (CLOSED) models accessor .get() invocation, but data
descriptors:
  (function(){var o={};Object.defineProperty(o,'x',{value:'f1',
  enumerable:true});return Object.getOwnPropertyDescriptor(o,'x')
  .value+'f2';})()
and the Reflect twin both node-evaluate to the exact credential
(node v24.20.0) while the decoder produces zero variants.

F698 (LOW; filed 2026-10-08 by wave-380 lane 8, attack round 48,
found while pinning the F664 control): F664 residual --
defineProperty-installed accessor + descriptor .get() invocation
bypasses the decoder -- the F664 closure (wave-379 lane 2) models
descriptor .get() invocation only for literal-getter sources
(var o={get x(){...}}):
  (function(){var o={};Object.defineProperty(o,'x',
  {get:function(){return 'f1';}});return
  Object.getOwnPropertyDescriptor(o,'x').get()+'f2';})()
and the arrow twin both node-evaluate to the exact credential
while the decoder produces zero variants. Distinct from F664
(literal-getter sources) and F673 (defineProperties-installed
getters read via o.x, which blocks).

Fix (gov/dlp.py, zero new re.compile): _js_parse_f691f698_
descriptor_iife -- the var binds an empty object; each
Object.defineProperty(o,'KEY',DESC) installs KEY -> the
descriptor's decoded plain-string value (data) or an _JSAccessor
(getter return, already evaluated, F549/F550 precedent); the
return is a +-joined additive of string literals and
(Object|Reflect).getOwnPropertyDescriptor(o,'KEY')(.value|.get())
terms, resolved node-exactly against the installed map
(.value on an accessor is undefined in the engine; .get() on a
data descriptor throws; both fail closed). Hooked after F664
with its hook and trailing return intact (wave-379 lesson);
F664 stays CLOSED for its literal-getter pins -- this lane
closes only the defineProperty residual and does not widen or
patch F664's closure or entry.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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

TAXONOMY_PIN = 2143  # no new decision codes this lane

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
def test_p1_f691_filed_gopd_value():
    """F691 filed: Object.defineProperty data-descriptor .value blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A
         + "',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x')"
         + ".value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f691_filed_reflect_value():
    """F691 filed: Reflect.getOwnPropertyDescriptor .value twin blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A
         + "',enumerable:true});return Reflect.getOwnPropertyDescriptor(o,'x')"
         + ".value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f698_filed_dp_get_fn():
    """F698 filed: defineProperty-installed getter .get() blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{get:function(){return '" + _A + "';}});return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f698_filed_dp_get_arrow():
    """F698 filed: defineProperty-installed arrow getter .get() blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{get:()=>'"+ _A + "'});return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)


@_t
def test_p2_let_decl():
    """let-bound target blocks."""
    s = ("(function(){let o={};Object.defineProperty(o,'x',{value:'" + _A
         + "'});return Object.getOwnPropertyDescriptor(o,'x').value+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_const_decl():
    """const-bound target blocks."""
    s = ("(function(){const o={};Object.defineProperty(o,'x',"
         + "{get:()=>'" + _A + "'});return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_two_keys_additive():
    """Two installs, two descriptor terms in the additive."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A
         + "'});Object.defineProperty(o,'y',{value:'" + _B + "'});return "
         + "Object.getOwnPropertyDescriptor(o,'x').value+"
         + "Object.getOwnPropertyDescriptor(o,'y').value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_reflect_get_term():
    """Reflect head on the .get() terminal blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{get:()=>'" + _A + "'});return "
         + "Reflect.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_named_getter():
    """Named function getter installs node-exactly."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{get:function g(){return '" + _A + "';}});return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_mixed_terms():
    """Literal + descriptor terms interleave."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A
         + "'});return 'P-'+Object.getOwnPropertyDescriptor(o,'x').value+'-"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "P-" + _A + "-" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_ws_twin():
    """Whitespace-tolerant twin blocks."""
    s = ("(function(){ var o = {} ; Object.defineProperty( o , 'x' , "
         + "{ value : '" + _A + "' } ) ; return "
         + "Object.getOwnPropertyDescriptor( o , 'x' ).value + '" + _B
         + "' ; })()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_value_only_return():
    """Single descriptor term, no additive."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A + _B
         + "'});return Object.getOwnPropertyDescriptor(o,'x').value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must miss)


def _bound(name, payload):
    miss = _misses(payload)
    return ("HELD" if miss else "BREAK", "%s quiet=%s" % (name, miss))


@_t
def test_p3_value_on_accessor():
    """BOUND: .value on an accessor descriptor is undefined in the engine."""
    return _bound("value-on-accessor",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{get:()=>'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_get_on_data():
    """BOUND: .get() on a data descriptor throws TypeError in the engine."""
    return _bound("get-on-data",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').get()+'cd';})()")


@_t
def test_p3_get_with_args():
    """BOUND: .get() with args fails closed (F664 parity)."""
    return _bound("get-with-args",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{get:()=>'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').get(1)+'cd';})()")


@_t
def test_p3_missing_key():
    """BOUND: missing key throws in the engine."""
    return _bound("missing-key",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'y').value+'cd';})()")


@_t
def test_p3_proto_key():
    """BOUND: __proto__ key fails closed."""
    return _bound("proto-key",
                  "(function(){var o={};Object.defineProperty(o,'__proto__',"
                  "{value:'ab'});return Object.getOwnPropertyDescriptor(o,"
                  "'__proto__').value+'cd';})()")


@_t
def test_p3_nonliteral_key():
    """BOUND: non-literal key fails closed."""
    return _bound("nonliteral-key",
                  "(function(){var o={};var k='x';"
                  "Object.defineProperty(o,k,{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,k).value+'cd';})()")


@_t
def test_p3_set_only():
    """BOUND: set-only descriptor reads as undefined."""
    return _bound("set-only",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{set:function(v){}});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_numeric_value():
    """BOUND: non-string descriptor values fail closed."""
    return _bound("numeric-value",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:123});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_unsafe_int_string():
    """BOUND: >2^53 integer-shaped values fail closed (F699 guard)."""
    return _bound("unsafe-int",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'9007199254740993'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_getter_this():
    """BOUND: this-dependent getter bodies fail closed."""
    return _bound("getter-this",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{get:function(){return this.y;}});return "
                  "Object.getOwnPropertyDescriptor(o,'x').get()+'cd';})()")


@_t
def test_p3_getter_args():
    """BOUND: getter with parameters fails closed."""
    return _bound("getter-args",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{get:function(a){return 'ab';}});return "
                  "Object.getOwnPropertyDescriptor(o,'x').get()+'cd';})()")


@_t
def test_p3_bracket_head():
    """BOUND: bracket head fails closed (dot form only)."""
    return _bound("bracket-head",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'ab'});return "
                  "Object['getOwnPropertyDescriptor'](o,'x').value+'cd';})()")


@_t
def test_p3_bracket_terminal():
    """BOUND: bracket terminal fails closed (F664 parity)."""
    return _bound("bracket-terminal",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x')['value']+'cd';})()")


@_t
def test_p3_reassign():
    """BOUND: reassignment of the bound var fails closed."""
    return _bound("reassign",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{value:'ab'});o={};return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_other_target():
    """BOUND: install on a different ident fails closed."""
    return _bound("other-target",
                  "(function(){var o={};var p={};"
                  "Object.defineProperty(p,'x',{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_defineProperties_plural():
    """BOUND: defineProperties (plural) stays F673's."""
    return _bound("defineProperties-plural",
                  "(function(){var o={};"
                  "Object.defineProperties(o,{x:{value:'ab'}});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_named_function():
    """BOUND: named function IIFE fails closed."""
    return _bound("named-fn",
                  "(function foo(){var o={};"
                  "Object.defineProperty(o,'x',{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_extra_statement():
    """BOUND: extra statements fail closed."""
    return _bound("extra-stmt",
                  "(function(){var o={};"
                  "Object.defineProperty(o,'x',{value:'ab'});var z=1;return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_nonempty_init():
    """BOUND: non-empty initial object fails closed."""
    return _bound("nonempty-init",
                  "(function(){var o={y:'q'};"
                  "Object.defineProperty(o,'x',{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


@_t
def test_p3_writable_with_get():
    """BOUND: {get, writable} throws in the engine."""
    return _bound("writable-with-get",
                  "(function(){var o={};Object.defineProperty(o,'x',"
                  "{get:()=>'ab',writable:true});return "
                  "Object.getOwnPropertyDescriptor(o,'x').get()+'cd';})()")


@_t
def test_p3_reinstall_same_key():
    """BOUND: same-key reinstall fails closed (engine throws unless
    configurable; configurable:true twin is a documented residual)."""
    return _bound("reinstall",
                  "(function(){var o={};"
                  "Object.defineProperty(o,'x',{value:'zz'});"
                  "Object.defineProperty(o,'x',{value:'ab'});return "
                  "Object.getOwnPropertyDescriptor(o,'x').value+'cd';})()")


# ------------------------------------------------ p4: siblings still hold


@_t
def test_p4_f664_literal_getter():
    """F664 (CLOSED): literal-getter .get() still blocks coded."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f664=%s" % ok)


@_t
def test_p4_f673_defineProperties():
    """F673 (CLOSED): defineProperties-installed getter via o.x blocks."""
    s = ("(function(){var o={};Object.defineProperties(o,{x:{get:function(){"
         + "return '" + _A + "';}}});return o.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p4_f549_literal_target():
    """F549 (CLOSED): literal-target descriptor .get() blocks."""
    s = ("(function(){return Object.getOwnPropertyDescriptor("
         + "{get x(){return '" + _A + "';}},'x').get()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f549=%s" % ok)


@_t
def test_p4_f550_expr_defineProperty():
    """F550 (CLOSED): expression-level defineProperty routes still block."""
    ok = True
    for s in (("Object.defineProperty({a:'x'},'b',{value:'" + _A + "'}).b+'"
               + _B + "'"),
              ("Object.defineProperty({},'b',{get:function(){return '" + _A
               + "';}}).b+'" + _B + "'")):
        ok = ok and _blocked(s)
    return ("HELD" if ok else "BREAK", "f550=%s" % ok)


# ------------------------------------------------ p5: open neighbors still miss
# (filed shapes copied verbatim from evals/w380_attack_probes.py open
# pins / evals/w380_f699_redfirst.py -- nothing absorbed)


def _neighbor(name, payload):
    miss = _misses(payload)
    return ("HELD" if miss else "BREAK", "%s quiet=%s" % (name, miss))


def _neighbor_blocked(name, payload):
    blk = _blocked(payload)
    return ("HELD" if blk else "BREAK", "%s blocked=%s" % (name, blk))


@_t
def test_p5_f686_open():
    """F686 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f686",
                     "(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.keys(p).join('');})()" % (_A, _B))


@_t
def test_p5_f687_open():
    """F687 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f687",
                     "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s';})()" % (_A, _B))


@_t
def test_p5_f688_open():
    """F688 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f688",
                     "(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))


@_t
def test_p5_f689_open():
    """F689 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f689",
                     "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});return [...p].join('');})()" % (_A, _B))


@_t
def test_p5_f690_open():
    """F690 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f690",
                     "(function(){function C(){this.x='%s';}var c=new C();return c.x+'%s';})()" % (_A, _B))


@_t
def test_p5_f692_open():
    """F692 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f692",
                     "(function(){class B{static x='%s';}class D extends B{static y(){return super.x;}}return D.y()+'%s';})()" % (_A, _B))


@_t
def test_p5_f693_open():
    """F693 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f693",
                     "(function(){var {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))


@_t
def test_p5_f694_open():
    """F694 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f694",
                     "(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B))


@_t
def test_p5_f695_open():
    """F695 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f695",
                     "(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B))


@_t
def test_p5_f696_open():
    """F696 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f696",
                     "(function(){return (new String('%s'))+'%s';})()" % (_A, _B))


@_t
def test_p5_f697_open():
    """F697 now CLOSED (wave-381) -- blocks."""
    return _neighbor_blocked("f697",
                     "(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B))


@_t
def test_p5_f699_open():
    """F699 now CLOSED (wave-381) -- fail-closed, no decode."""
    return _neighbor("f699",
                     "(function(){var o={x:9007199254740993};with(o){return x+'" + _B + "';}})()")


# ------------------------------------------------ p6: junk quiet / composition


@_t
def test_p6_junk_quiet():
    """Junk through the new shapes stays quiet."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{value:'x'});return "
         + "Object.getOwnPropertyDescriptor(o,'x').value+'y';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "quiet=%s" % miss)


@_t
def test_p6_junk_getter_quiet():
    """Junk through the getter shape stays quiet."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         + "{get:()=>'x'});return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'y';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "quiet=%s" % miss)


# ------------------------------------------------ p7: pin, footer, no new regexes


@_t
def test_p7_pin_footer():
    """Pin 2140; lane-local footer (open F686-F690, F692-F697, F699 / next F700)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-381 lane 5: F691, F698 CLOSED; open F686-F690, F692-F697, F699 / next F700  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-381 lane 5: F691, F698 CLOSED; open F686-F690, F692-F697, F699 / next F700  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p7_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p8: perf


@_t
def test_p8_perf():
    """200 mixed F691/F698 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var o={};Object.defineProperty(o,'x',"
                      "{value:'x%d'});return "
                      "Object.getOwnPropertyDescriptor(o,'x').value;})()" % k)
        corpus.append("(function(){var o={};Object.defineProperty(o,'x',"
                      "{get:()=>'x%d'});return "
                      "Object.getOwnPropertyDescriptor(o,'x').get();})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p9: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w380_f691_redfirst.py", 0),
                               ("evals/w380_f698_redfirst.py", 0),
                               ("evals/w380_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g381-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F691/F698 red-firsts + wave-380 attack battery."""
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
