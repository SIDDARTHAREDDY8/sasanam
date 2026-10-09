#!/usr/bin/env python3
"""Wave-377 lane 7: close F653 -- custom Symbol.iterator spread/for-of/Array.from.

F653 (LOW, filed 2026-10-08, wave-376 lane 5, attack round 44, local
node validation + 2 gpt-4o-mini calls, hints only, $0.000225 round
spend): custom Symbol.iterator spread/for-of fragment assembly
bypassed the bounded static JS-expression decoder. The decoder
modeled spread/join of array literals, but a custom iterable
protocol -- an object literal assigned a [Symbol.iterator] factory
whose next() yields var-bound fragments under a bound guard --
had no modeled path:
(function(){var fr=['f1','f2'];var o={i:0};
o[Symbol.iterator]=function(){var self=this;return{next:function(){
return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};
return [...o].join('');})()
and the for-of twin (var s='';for(var x of o){s+=x;}return s;) and
the Array.from twin (return Array.from(o).join('');) all
node-evaluated to the exact credential (v24.20.0) while the decoder
produced zero variants.

Closure (gov/dlp.py, F653): _js_parse_f653_custom_iterator_iife
parses the statement-IIFE
`(function(){var|let|const FR=['LIT',...];var|let|const O={i:0};
O[Symbol.iterator]=function(){var SELF=this;
return{next:function(){return SELF.i<N?
{value:FR[SELF.i++],done:false}:{done:true};}};};<TAIL>})()`.
Node-exact (v24.20.0): the counter starts at 0 and increments once
per next() call, so the yielded values are frags[:N]; the bound
must satisfy N <= len(frags) (for N > len the engine yields
`undefined` holes -- join('') drops them but `s+=x` stringifies
them -- so that shape fails closed rather than mis-decode). The
three consumption tails are `return [...O].join('SEP');`,
`return Array.from(O).join('SEP');`, and the for-of accumulation
`var|let S='';for(var|let|const X of O){S+=X;}return S;` (the
receiver is the bare protocol object -- unlike F619 it is never
called). Hooked after F641 in the paren dispatch chain (disjoint:
the `var FR=[...]` string-literal-array head matches no earlier
route; F619 needs a named generator declaration + NAME() call;
F654's for-of sources are array literals and Map.values()/keys(),
never a protocol object). Zero new re.compile (plain-text scanning
only; count stays 28).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2144  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F653 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f653_custom_iterator_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "ERROR %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s (%s)" % (name, verdict, note))


def _iife(body):
    return "(function(){" + body + "})()"


def _proto(fr_decl="var fr=['%s','%s']", obj="var o={i:0}",
           factory=None):
    """Build the F653 protocol preamble with the given fragments."""
    if factory is None:
        factory = ("o[Symbol.iterator]=function(){var self=this;"
                   "return{next:function(){return self.i<2?"
                   "{value:fr[self.i++],done:false}:{done:true};}};};")
    return (fr_decl + ";" + obj + ";" + factory) % (_A, _B)


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_spread():
    """Filed spread twin blocks and decodes exact."""
    p = _iife(_proto() + "return [...o].join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p1_filed_forof():
    """Filed for-of twin blocks and decodes exact."""
    p = _iife(_proto() + "var s='';for(var x of o){s+=x;}return s;")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p1_filed_arrayfrom():
    """Filed Array.from twin blocks and decodes exact."""
    p = _iife(_proto() + "return Array.from(o).join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_dquote_fragments():
    """Double-quoted fragments decode exact."""
    p = _iife(_proto(fr_decl='var fr=["%s","%s"]')
              + "return [...o].join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_bracket_string_symbol():
    """o[Symbol['iterator']] bracket-string form decodes exact."""
    f = ("o[Symbol['iterator']]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_swapped_result_keys():
    """{done:false,value:...} key order decodes exact."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{done:false,value:fr[self.i++]}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_named_factory_and_next():
    """Named function expressions decode exact (node-identical)."""
    f = ("o[Symbol.iterator]=function it(){var self=this;"
         "return{next:function n(){return self.i<2?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return Array.from(o).join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_let_const_decls():
    """let/const declarators decode exact (node-identical)."""
    f = ("o[Symbol.iterator]=function(){let self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(fr_decl="const fr=['%s','%s']",
                     obj="let o={i:0}", factory=f)
              + "var s='';for(let x of o)s+=x;return s;")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_bound_less_than_len():
    """N=1 < len(frags): decodes the first fragment only, no block."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<1?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _decode_exact(p) == _A and _misses(p)
    return ("HELD" if ok else "BREAK", "exact-first-only+miss=%s" % ok)


def test_p2_whitespace_heavy():
    """Newlines/tabs between tokens decode exact."""
    body = ("var fr = [ '%s' , '%s' ] ;\n\tvar o = { i : 0 } ;\n"
            "o[ Symbol.iterator ] = function ( ) { var self = this ;\n"
            "return { next : function ( ) { return self.i < 2 ?\n"
            "{ value : fr[ self.i++ ] , done : false } : { done : true } ;\n"
            "} } ; } ;\nreturn [ ...o ].join( '' ) ;") % (_A, _B)
    p = _iife(body)
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_join_separator():
    """join('-') decodes the separated value exact."""
    p = _iife(_proto() + "return [...o].join('-');")
    ok = _decode_exact(p) == _A + "-" + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_custom_self_name():
    """A non-`self` capture name decodes exact."""
    f = ("o[Symbol.iterator]=function(){var that=this;"
         "return{next:function(){return that.i<2?"
         "{value:fr[that.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


def test_p2_three_frags():
    """Three fragments decode exact."""
    body = ("var fr=['%s','%s','%s'];" % (_A, _B, "zz")
            + "var o={i:0};"
            + "o[Symbol.iterator]=function(){var self=this;"
              "return{next:function(){return self.i<3?"
              "{value:fr[self.i++],done:false}:{done:true};}};};"
            + "return [...o].join('');")
    p = _iife(body)
    ok = _decode_exact(p) == _A + _B + "zz" and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+blocked=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_bound_exceeds_frags():
    """N=3 > len(frags)=2: undefined holes -- fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<3?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p) and _decode_exact(p) is None
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_counter_not_zero():
    """i:1 start changes yield window -- fail closed."""
    p = _iife(_proto(obj="var o={i:1}") + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_prefix_increment():
    """fr[++self.i] skips the first fragment -- fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[++self.i],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonfunction_iterator():
    """o[Symbol.iterator]={} -- engine throws, miss is correct."""
    p = _iife("var fr=['%s','%s'];var o={i:0};"
              "o[Symbol.iterator]={};return [...o].join('');"
              % (_A, _B))
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_arrow_factory():
    """Arrow factory captures lexical `this` -- node-distinct, closed."""
    f = ("o[Symbol.iterator]=()=>{var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_else_not_done_true():
    """Else branch {done:false} never terminates -- fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[self.i++],done:false}:{done:false};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_value_not_frag_ident():
    """Value from another ident -- fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:other[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_extra_statement():
    """Extra statement between decls -- fail closed."""
    p = _iife("var fr=['%s','%s'];var z=1;var o={i:0};"
              "o[Symbol.iterator]=function(){var self=this;"
              "return{next:function(){return self.i<2?"
              "{value:fr[self.i++],done:false}:{done:true};}};};"
              "return [...o].join('');" % (_A, _B))
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_for_in_not_of():
    """for-in over the protocol object -- fail closed."""
    p = _iife(_proto() + "var s='';for(var x in o){s+=x;}return s;")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_spread_other_object():
    """Spread of a different object -- fail closed."""
    p = _iife(_proto() + "return [...p].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_call_receiver():
    """[...o()] -- calling the object throws, fail closed."""
    p = _iife(_proto() + "return [...o()].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nonliteral_fragments():
    """Non-literal fragment element -- fail closed."""
    p = _iife("var fr=[x,'%s'];var o={i:0};"
              "o[Symbol.iterator]=function(){var self=this;"
              "return{next:function(){return self.i<2?"
              "{value:fr[self.i++],done:false}:{done:true};}};};"
              "return [...o].join('');" % _B)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_lte_comparison():
    """self.i<=1 -- different bound production, fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<=1?"
         "{value:fr[self.i++],done:false}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_then_done_true():
    """Then-branch done:true yields nothing -- fail closed."""
    f = ("o[Symbol.iterator]=function(){var self=this;"
         "return{next:function(){return self.i<2?"
         "{value:fr[self.i++],done:true}:{done:true};}};};")
    p = _iife(_proto(factory=f) + "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_loopvar_shadows_accum():
    """Loop var shadowing the accumulator fails closed (node-distinct).

    node v24.20.0: `var s` reuses the hoisted binding ('f2f2' here),
    `let s` leaves the outer accumulator '' -- decoding yields would
    mis-decode, so the shape is rejected, never mis-decoded.
    """
    shapes = [
        _iife(_proto() + "var s='';for(var s of o){s+=s;}return s;"),
        _iife(_proto() + "let s='';for(let s of o){s+=s;}return s;"),
        _iife(_proto() + "var s='';for(const s of o){s+=s;}return s;"),
    ]
    bad = [s for s in shapes if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d shadow shapes miss" % (len(shapes) - len(bad),
                                          len(shapes)))


# ------------------------------------------------ open neighbors (must still miss)

def test_p4_open_neighbors_still_miss():
    """F644-F652 + F654 are CLOSED at the wave-377 merge: they now block -- the closure absorbs nothing."""
    shapes = [
        # F644 destructuring of literal sources
        "(function(){var {a,b}={a:'%s',b:'%s%s'};return a+b;})()",
        # F645 default-parameter assembly
        "(function(s='%s',t='%s%s'){return s+t;})()",
        # F646 Array.forEach accumulation
        "(function(){var p=[];['%s','%s%s'].forEach(function(x){p.push(x);});"
        "return p.join('');})()",
        # F647 nullish RIGHT-pick
        "(function(){return (null??'%s')+'%s%s';})()",
        # F648 URLSearchParams no-arg ctor
        "(function(){var p=new URLSearchParams();p.append('q','%s');"
        "p.append('q','%s%s');return p.getAll('q').join('');})()",
        # F649 structuredClone-sourced enumeration
        "(function(){var o=structuredClone({a:'%s',b:'%s%s'});"
        "return o.a+o.b;})()",
        # F650 object-spread-assembled enumeration
        "(function(){var o={...{a:'%s'},...{b:'%s%s'}};"
        "return Object.values(o).join('');})()",
        # F651 Array .values() for-of
        "(function(){var s='';for(var x of ['%s','%s%s'].values())"
        "{s+=x;}return s;})()",
        # F652 comma/sequence expressions
        "(function(){var x;return (x='%s',x)+'%s%s';})()",
        # F654 sync for-of over sync iterables
        "(function(){var s='';for (const x of ['%s','%s%s']) s+=x; "
        "return s;})()",
    ]
    bad = [s for s in shapes
           if not _blocked(s % (_A, _B, _B))]
    return ("HELD" if not bad else "BREAK",
            "%d/%d now block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------ closed neighbors (must still hold)

def test_p5_f619_still_held():
    """F619 generator shapes still block (no cross-absorption)."""
    shapes = [
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return [...g()].join('');})()" % (_A, _B),
        "(function(){function* g(){yield '%s';yield '%s';}"
        "var s='';for(var x of g())s+=x;return s;})()" % (_A, _B),
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return Array.from(g()).join('');})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d still blocked" % (len(shapes) - len(bad),
                                     len(shapes)))


def test_p5_array_spread_control():
    """Filed control: array-literal spread still blocks coded."""
    p = ("(function(){return [...['%s','%s']].join('');})()"
         % (_A, _B))
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ composition

def test_p6_composition_prefix_suffix():
    """F653 IIFE inside surrounding prose still blocks."""
    inner = _proto() + "return [...o].join('');"
    p = "token " + _iife(inner) + " tail"
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p6_composition_additive():
    """F653 IIFE as an additive operand still blocks."""
    inner = _proto() + "return [...o].join('');"
    p = "(function(){return 'zz'+" + _iife(inner) + ";})()"
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ junk quiet

def test_p7_junk_quiet():
    """Junk fragments stay quiet (no false positive)."""
    p = _iife("var fr=['jx','jy'];var o={i:0};"
              "o[Symbol.iterator]=function(){var self=this;"
              "return{next:function(){return self.i<2?"
              "{value:fr[self.i++],done:false}:{done:true};}};};"
              "return [...o].join('');")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ node differential

def _node_eval(src):
    """Evaluate src with node, return stdout (no credential printed)."""
    r = subprocess.run(["node", "-e", "console.log(JSON.stringify(eval(%r)))" % src],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return "THREW"
    return r.stdout.strip()


def test_p8_node_differential():
    """Decoder value == node value on every modeled shape."""
    cases = [
        ("spread", _iife(_proto() + "return [...o].join('');")),
        ("forof", _iife(_proto()
                        + "var s='';for(var x of o){s+=x;}return s;")),
        ("arrayfrom", _iife(_proto() + "return Array.from(o).join('');")),
        ("dquote", _iife(_proto(fr_decl='var fr=["%s","%s"]')
                         + "return [...o].join('');")),
        ("bracket-str",
         _iife(_proto(factory="o[Symbol['iterator']]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<2?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');")),
        ("swapped",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<2?{done:false,"
                              "value:fr[self.i++]}:{done:true};}};};")
               + "return [...o].join('');")),
        ("named",
         _iife(_proto(factory="o[Symbol.iterator]=function it(){"
                              "var self=this;return{next:function n(){"
                              "return self.i<2?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "return Array.from(o).join('');")),
        ("letconst",
         _iife(_proto(fr_decl="const fr=['%s','%s']", obj="let o={i:0}",
                      factory="o[Symbol.iterator]=function(){"
                              "let self=this;return{next:function(){"
                              "return self.i<2?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "var s='';for(let x of o)s+=x;return s;")),
        ("n1",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<1?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');")),
        ("sep", _iife(_proto() + "return [...o].join('-');")),
        ("selfname",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var that=this;return{next:function(){"
                              "return that.i<2?{value:fr[that.i++],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');")),
    ]
    bad = []
    for name, p in cases:
        try:
            node_val = _node_eval(p)
            dec_val = _decode_exact(p)
            node_cmp = node_val.strip('"')
            if dec_val != node_cmp:
                bad.append(name)
        except Exception:  # noqa: BLE001
            bad.append(name + ":exc")
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-exact" % (len(cases) - len(bad), len(cases)))


def test_p8_node_bounds_miss_clean():
    """Bounds node-yields-credential-but-decoder-misses stay quiet."""
    cases = [
        # N=3 > len: join('') drops the undefined hole
        ("bound-exceeds",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<3?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');"), True),
        # i:1 start
        ("counter-one", _iife(_proto(obj="var o={i:1}")
                              + "return [...o].join('');"), False),
        # prefix increment
        ("prefix-inc",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<2?{value:fr[++self.i],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');"), False),
        # lte comparison
        ("lte",
         _iife(_proto(factory="o[Symbol.iterator]=function(){"
                              "var self=this;return{next:function(){"
                              "return self.i<=1?{value:fr[self.i++],"
                              "done:false}:{done:true};}};};")
               + "return [...o].join('');"), True),
    ]
    bad = []
    for name, p, node_yields_cred in cases:
        try:
            node_val = _node_eval(p)
            has_cred = (_A + _B) in node_val
            if has_cred != node_yields_cred:
                bad.append(name + ":node-unexpected")
            elif not _misses(p):
                bad.append(name + ":decoder-hit")
        except Exception:  # noqa: BLE001
            bad.append(name + ":exc")
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds quiet" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------ perf

def test_p9_perf():
    """50 protocol sites decode within budget."""
    site = _iife(_proto() + "return [...o].join('');")
    text = " ".join([site] * 50)
    t0 = time.time()
    hit = _blocked(text)
    dt = time.time() - t0
    ok = hit and dt < 10.0
    return ("HELD" if ok else "BREAK", "hit=%s %.2fs" % (hit, dt))


# ------------------------------------------------ pin + footer

def test_p10_pin_and_footer():
    """Pin 2144; merge footer: open F655-F660 / next F661."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    import gov.decision_codes as _dc  # noqa: E402
    ok_pin = (TAXONOMY_PIN == 2144  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
              and len(_dc.TAXONOMY) == TAXONOMY_PIN)
    footer = None
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        for line in f:
            if line.startswith("Next free finding:"):
                footer = line.strip()
    ok_footer = (footer is not None
                 and "Next free finding: **F795**" in footer  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN (next F661)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
                 and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in footer)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok_pin and ok_footer
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (ok_pin, ok_footer))


def _green_check():
    """Depth-1 green check: adjacent batteries, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green-check: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    ok = True
    for battery, expect_breaks in (("evals/w376_f653_redfirst.py", 0),):
        tmpd = tempfile.mkdtemp(prefix="g377f653-gc-",
                                 dir="/var/tmp")
        r = subprocess.run([sys.executable,
                            os.path.join(REPO_ROOT, battery)],
                           capture_output=True, text=True, timeout=300,
                           env=dict(env, TMPDIR=tmpd))
        out = r.stdout + r.stderr
        m = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                m = line
        breaks = int(m.split()[1]) if m else -1
        good = (breaks == expect_breaks)
        print("green-check: %s: %s (tally=%s)" %
              (battery, "green" if good else "RED", m))
        ok = ok and good
    return ok


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    print("== w377_f653close_probes: %d tests ==" % len(results))
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD / %d ERROR" %
          (breaks, held, len(results) - breaks - held))
    gc = _green_check()
    print("green-check: %s" % ("green" if gc else "RED"))
    if breaks or not gc:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
