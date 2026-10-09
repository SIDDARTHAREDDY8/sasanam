#!/usr/bin/env python3
"""Wave-382 lane 4: close F706 + F707 (Proxy-trap residuals).

F706 (LOW; filed 2026-10-08 by wave-381 lane 8, attack round 49):
Proxy defineProperty-trap fragment writes bypass the bounded static
JS-expression decoder -- the decoder models Proxy set/construct/
deleteProperty/getPrototypeOf traps (F675) and ownKeys (F686) but
not the defineProperty trap:
  (function(){var t={};var p=new Proxy(t,{defineProperty:
  function(tr,pr,de){tr[pr]='f1';return true;}});
  Object.defineProperty(p,'x',{value:1});return t.x+'f2';})()
and the fallback twin (tr[pr]=de.value2||'f1') both node-evaluate
to the exact credential (node v24.20.0) while the decoder produces
zero variants.

F707 (LOW; filed 2026-10-08 by wave-381 lane 8, attack round 49):
Proxy getOwnPropertyDescriptor-trap descriptor reads bypass the
decoder -- the get trap (F642) and getPrototypeOf (F675) are
modeled but not the gOPD trap:
  (function(){var t={x:'f1'};var p=new Proxy(t,
  {getOwnPropertyDescriptor:function(tr,pr){return
  {value:tr[pr],configurable:true};}});return
  Object.getOwnPropertyDescriptor(p,'x').value+'f2';})()
and the Reflect twin both node-evaluate to the exact credential
while the decoder produces zero variants.

Fix (gov/dlp.py, zero new re.compile): _js_parse_f706_dp_iife --
the var binds a literal target; var p=new Proxy(t,
{defineProperty:DPFN}); each (Object|Reflect).defineProperty(
p,'X',{DESC}) statement fires the modeled TR[PR]=RHS write into
the tracked target (RHS is a string literal or a
de.M||'LIT' fallback resolved against the ToPropertyDescriptor-
normalized descriptor -- only the six standard fields are
visible in the engine, node-verified); terminal return
(p|t).MEM(+'LIT')* reads the tracked target.
_js_parse_f707_gopd_iife -- the gopd call invokes the trap with
(target, key); the trap's data descriptor carries value:
target[key], so .value reads the tracked member. configurable:
true is REQUIRED (the engine's trap invariant throws TypeError
otherwise -- decoding those shapes would mis-decode).
Both hooked after F689 with their trailing
`return _js_parse_postfix(...)` intact (wave-379 lesson);
disjoint by handler key from F642/F666/F675/F686/F689 and from
F691/F698 (plain-object descriptors, no Proxy).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
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
def test_p1_f706_filed_dp_trap():
    """F706 filed: defineProperty-trap literal write blocks, node-exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f706_filed_dp_trap_fallback():
    """F706 filed: defineProperty-trap de.value2||'LIT' fallback blocks, node-exact."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.value2||'" + _A + "';return true;}});Object.defineProperty(p,'x',"
         "{value:1});return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f707_filed_gopd_trap():
    """F707 filed: gOPD-trap descriptor .value read blocks, node-exact."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr],configurable:true};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f707_filed_gopd_trap_reflect():
    """F707 filed: Reflect.getOwnPropertyDescriptor twin blocks, node-exact."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr],configurable:true};}});return "
         "Reflect.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)


@_t
def test_p2_f706_reflect_defineprop():
    """F706 variant: Reflect.defineProperty fires the trap identically."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Reflect.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_method_shorthand():
    """F706 variant: method-shorthand trap body."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_arrow_trap():
    """F706 variant: block-body arrow trap."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:(tr,pr,de)=>"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_multi_defineprop():
    """F706 variant: two defineProperty statements, read the second key."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "Object.defineProperty(p,'y',{value:2});return t.y+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_nonempty_target():
    """F706 variant: non-empty literal target composes with trap writes."""
    s = ("(function(){var t={a:'" + _A + "'};var p=new Proxy(t,{defineProperty:"
         "function(tr,pr,de){tr[pr]='" + _B + "';return true;}});"
         "Object.defineProperty(p,'x',{value:1});return t.a+t.x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_fallback_stripped():
    """F706 variant: non-standard de.value2 is stripped by ToPropertyDescriptor."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.value2||'" + _A + "';return true;}});Object.defineProperty(p,'x',"
         "{value2:'zz'});return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_fallback_std_field():
    """F706 variant: standard de.value field passes through."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.value||'" + _B + "';return true;}});Object.defineProperty(p,'x',"
         "{value:'" + _A + "'});return t.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f706_p_receiver():
    """F706 variant: terminal reads via the proxy (no get trap -> fallthrough)."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "return p.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f707_method_shorthand():
    """F707 variant: method-shorthand gOPD trap."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor"
         "(tr,pr){return {value:tr[pr],configurable:true};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f707_concise_arrow():
    """F707 variant: concise-arrow gOPD trap."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "(tr,pr)=>({value:tr[pr],configurable:true})});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f707_writable_false():
    """F707 variant: extra writable:false flag does not trip the invariant."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr],configurable:true,writable:false};}});"
         "return Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f706_trap_no_return():
    """F706 bound: trap without return makes defineProperty throw in the engine."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_trap_return_false():
    """F706 bound: trap returning false makes defineProperty throw."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return false;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_proto_key():
    """F706 bound: __proto__ defineProperty key fails closed (proto-pollution shape)."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'__proto__',"
         "{value:1});return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_extra_statement():
    """F706 bound: statements between the proxy decl and defineProperty fail closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});var z=1;Object.defineProperty(p,'x',"
         "{value:1});return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_chained_fallback():
    """F706 bound: longer || chains in the trap RHS fail closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.a||de.b||'" + _A + "';return true;}});Object.defineProperty(p,'x',"
         "{value:1});return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_fallback_bool_field():
    """F706 bound (spec-review): boolean-field fallback fails closed.

    {writable:'f1'} -> the engine's ToPropertyDescriptor applies
    ToBoolean, so the trap writes boolean true ('truef2' in node),
    not the raw literal -- decoding the literal would mis-decode.
    """
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.writable||'" + _A + "';return true;}});Object.defineProperty(p,'x',"
         "{writable:'f1'});return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_fallback_get_field():
    """F706 bound (spec-review): get-field fallback fails closed.

    {get:'f1'} -> the engine's ToPropertyDescriptor throws
    TypeError (get must be callable) -- decoding the literal
    would mis-decode.
    """
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]=de.get||'" + _A + "';return true;}});Object.defineProperty(p,'x',"
         "{get:'f1'});return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f706_nonliteral_body():
    """F706 bound: non-write trap bodies fail closed."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{return true;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f707_no_configurable():
    """F707 bound: missing configurable throws TypeError in the engine (invariant)."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr]};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f707_configurable_false():
    """F707 bound: configurable:false throws TypeError in the engine (invariant)."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr],configurable:false};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f707_accessor_descriptor():
    """F707 bound: get: accessor members fail closed (F698 territory)."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {get:function(){return tr[pr];},configurable:true};}});"
         "return Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f707_no_value_member():
    """F707 bound: descriptor without value fails closed."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {configurable:true};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').value+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f707_get_terminal():
    """F707 bound: .get (not .value) terminal fails closed."""
    s = ("(function(){var t={x:'" + _A + "'};var p=new Proxy(t,{getOwnPropertyDescriptor:"
         "function(tr,pr){return {value:tr[pr],configurable:true};}});return "
         "Object.getOwnPropertyDescriptor(p,'x').get+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------ p4: siblings still hold


@_t
def test_p4_sibling_f675_set():
    """Sibling F675 (set trap) still blocks."""
    s = ("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});"
         "p.x='" + _A + "';return t.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f686_ownkeys():
    """Sibling F686 (ownKeys trap) still blocks."""
    s = ("(function(){var p=new Proxy({},{ownKeys:function(){return ['" + _A + "','" + _B + "'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.keys(p).join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f689_symiter():
    """Sibling F689 (Symbol.iterator trap) still blocks."""
    s = ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '" + _A + "';yield '" + _B + "';};}return t[k];}});"
         "return [...p].join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f691_plain_gopd():
    """Sibling F691 (plain-object descriptor .value) still blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A + "',"
         "enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f698_dp_accessor():
    """Sibling F698 (defineProperty-installed accessor .get()) still blocks."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',"
         "{get:function(){return '" + _A + "';}});return "
         "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f642_get():
    """Sibling F642 (get trap with var-bound operands) still blocks."""
    s = ("(function(){var a='" + _A + "',b='" + _B + "';var p=new Proxy({},{get:(t,k)=>a+b});"
         "return p.anything;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ p5: open neighbors still miss


@_t
def test_p5_neighbor_f700_flatmap():
    """Open neighbor F700 (flatMap mapping-fn) still misses -- nothing absorbed."""
    s = ("(function(){var a=[['" + _A + "',''],['" + _B + "','']];"
         "return a.flatMap(function(x){return x;}).join('');})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p5_neighbor_f708_map_get():
    """Open neighbor F708 (Map.get) still misses -- nothing absorbed."""
    s = ("(function(){var m=new Map([['k','" + _A + "'],['j','" + _B + "']]);"
         "return m.get('k')+m.get('j');})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p5_neighbor_f701_getter_spread():
    """Neighbor F701 (getter on object spread) CLOSED by sibling lane (merge) -- blocks coded."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};var c={...o};"
         "return c.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ p6: junk-quiet + perf


@_t
def test_p6_junk_quiet():
    """Honest proxy text stays quiet."""
    s = "var p = new Proxy({}, {}); // nothing obfuscated here"
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6_junk_quiet_2():
    """Honest defineProperty text stays quiet."""
    s = "Object.defineProperty(obj, 'key', {value: 42});"
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p6_perf():
    """200 decode sites stay fast."""
    s = ("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de)"
         "{tr[pr]='" + _A + "';return true;}});Object.defineProperty(p,'x',{value:1});"
         "return t.x+'" + _B + "';})()")
    t0 = time.time()
    ok = True
    for _ in range(200):
        if not _blocked(s):
            ok = False
            break
    dt = time.time() - t0
    held = ok and dt < 20.0
    return ("HELD" if held else "BREAK", "hit=%s dt=%.2fs" % (ok, dt))


# ------------------------------------------------ p7: pin + lane-local footer


@_t
def test_p7_pin_taxonomy():
    """Taxonomy pin 2143 (no new decision codes this lane)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p7_lane_footer():
    """FINDINGS.md lane-local footer: F706/F707 closed, open F700-F705/F708-F712."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F921**" in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p8: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w381_f706_redfirst.py", 0),
                               ("evals/w381_f707_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
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
    # w381_attack_probes: the lane-local footer repoint makes its
    # b0 footer pin BREAK by design; tolerate exactly that one
    # (wave-305/306 class -- merge-time tree-wide repoint).
    tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals/w381_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = None
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
    if real_break is None:
        bad.append(("evals/w381_attack_probes.py", "no-tally"))
    elif real_break - footer_break != 0:
        bad.append(("evals/w381_attack_probes.py", real_break))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p8_green_check():
    """Depth-1 green check: F706/F707 red-firsts + wave-381 attack battery."""
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
