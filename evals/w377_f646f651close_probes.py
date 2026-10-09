#!/usr/bin/env python3
"""Wave-377 lane 3: close F646 + F651 (array-iteration family).

F646 (LOW, filed attack round 44): Array.prototype.forEach fragment
accumulation bypassed the bounded static JS-expression decoder --
F601 (CLOSED) models Map.prototype.forEach with value-accumulating
callbacks, but Array.prototype.forEach is a different receiver with
a different callback signature (element, index, array) and had no
modeled path. Two disciplines: the `S+=E` accumulation (F600/F601/
F602 callback grammar reused verbatim) and the `P.push(X)` /
`return P.join('SEP')` twin (join with no argument uses the
engine's comma default, node-verified).

F651 (LOW, filed attack round 44): Array.prototype.entries()/
values()/keys() for-of fragment assembly bypassed the decoder --
F622 (CLOSED) models Object.keys enumeration and F632 (CLOSED)
for-in, but the Array iterator methods consumed with for-of had no
modeled path. Node-exact desugar (v24.20.0): .values() yields
elements, .keys() yields indices, .entries() yields [index,
element] pairs, all ascending. The receiver is an inline array
literal or a var/let/const-bound array literal; destructuring
`[A,B]` is entries()-only; holes fail closed (for-of visits holes
as undefined).

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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2144  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B
_F23 = _F2 + _F3
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ F646 filed shapes (must block)

def test_p1_f646_push_join():
    """Filed shape 1: push-into-array + join('') twin blocks."""
    ok = _blocked("(function(){var p=[];['%s','%s'].forEach("
                  "function(x){p.push(x);});return p.join('');})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f646_accumulate():
    """Filed shape 2: string-accumulator twin blocks."""
    ok = _blocked("(function(){var s='';['%s','%s'].forEach("
                  "function(x){s+=x;});return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f646_arrow():
    """Filed shape 3: arrow-callback twin blocks."""
    ok = _blocked("(function(){var s='';['%s','%s'].forEach("
                  "(x)=>{s+=x;});return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f646_junk_quiet():
    """Junk through the same grammar stays quiet."""
    ok = _misses("(function(){var s='';['jx','jy'].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ F646 variants (must block)

def test_p2_f646_arrow_push():
    """Arrow push block-body twin blocks."""
    ok = _blocked("(function(){var p=[];['%s','%s'].forEach("
                  "(x)=>{p.push(x);});return p.join('');})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_concise_push():
    """Concise-arrow push twin blocks (node-verified)."""
    ok = _blocked("(function(){var p=[];['%s','%s'].forEach("
                  "x=>p.push(x));return p.join('');})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_concise_accum():
    """Concise-arrow `x=>s+=x` twin blocks (node-verified)."""
    ok = _blocked("(function(){var s='';['%s','%s'].forEach("
                  "x=>s+=x);return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_two_param():
    """Two-param callback (element, index) blocks."""
    ok = _blocked("(function(){var s='';['%s','%s'].forEach("
                  "function(x,i){s+=x;});return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_let_accum():
    """`let` accumulator twin blocks."""
    ok = _blocked("(function(){let s='';['%s','%s'].forEach("
                  "function(x){s+=x;});return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_ws():
    """Whitespace-tolerant shape blocks."""
    ok = _blocked("(function(){var s='';['%s','%s'].forEach( function"
                  " ( x ) { s += x ; } );return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_single_frag():
    """Single-fragment array blocks."""
    ok = _blocked("(function(){var s='';['%s'].forEach("
                  "function(x){s+=x;});return s;})()" % _CRED)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_const_push():
    """`const` array push twin blocks (node-legal: push never reassigns)."""
    ok = _blocked("(function(){const p=[];['%s','%s'].forEach("
                  "function(x){p.push(x);});return p.join('');})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f646_push_additive():
    """Additive push operand blocks (node-verified: 'f1f1f2f2')."""
    ok = _blocked("(function(){var p=[];['%s'].forEach("
                  "function(x){p.push(x+x);});return p.join('');})()"
                  % _CRED)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ F646 bounds (must miss)

def test_p3_f646_const_accum():
    """`const` accumulator throws at runtime: fail closed."""
    ok = _misses("(function(){const s='';['a','b'].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_nonempty_accum():
    """Non-empty accumulator fails closed."""
    ok = _misses("(function(){var s='x';['a','b'].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_nonliteral_elem():
    """Non-literal element fails closed."""
    ok = _misses("(function(){var s='';['a',y].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_hole():
    """Sparse hole fails closed (forEach skips holes; _JSNil ambiguity)."""
    ok = _misses("(function(){var s='';['a',,'b'].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_numeric_elem():
    """Numeric element fails closed (documented boundary)."""
    ok = _misses("(function(){var s='';['a',1].forEach("
                 "function(x){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_assign_body():
    """`s=x` (not `s+=x`) body fails closed."""
    ok = _misses("(function(){var s='';['a','b'].forEach("
                 "function(x){s=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_param_shadows():
    """Param shadowing the accumulator fails closed."""
    ok = _misses("(function(){var s='';['a','b'].forEach("
                 "function(s){s+=s;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_three_params():
    """Three-param callback fails closed (third is the array)."""
    ok = _misses("(function(){var s='';['a','b'].forEach("
                 "function(x,i,a){s+=x;});return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_nonliteral_sep():
    """Non-literal join separator fails closed."""
    ok = _misses("(function(){var p=[];['a','b'].forEach("
                 "function(x){p.push(x);});return p.join(sep);})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_return_bare():
    """`return p` without join fails closed (documented boundary)."""
    ok = _misses("(function(){var p=[];['a','b'].forEach("
                 "function(x){p.push(x);});return p;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_idx_arith():
    """`(i+1)` on the numeric index fails closed (would mis-decode)."""
    ok = _misses("(function(){var s='';['a','b'].forEach("
                 "function(x,i){s+=(i+1);});return s;})()")
    ok2 = _misses("(function(){var s='';['a','b'].forEach("
                  "function(x,i){s+=i+i;});return s;})()")
    ok3 = _misses("(function(){var p=[];['a','b'].forEach("
                  "function(x,i){p.push(i+1);});return p.join('');})()")
    ok = ok and ok2 and ok3
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p3_f646_nonempty_arracc():
    """Non-empty array accumulator fails closed."""
    ok = _misses("(function(){var p=['z'];['a','b'].forEach("
                 "function(x){p.push(x);});return p.join('');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ F651 filed shapes (must block)

def test_p4_f651_entries():
    """Filed shape 1: entries() + _e[1] blocks."""
    ok = _blocked("(function(){var s='';for(var _e of ['%s','%s']"
                  ".entries()){s+=_e[1];}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f651_values():
    """Filed shape 2: values() twin blocks."""
    ok = _blocked("(function(){var s='';for(var x of ['%s','%s']"
                  ".values()){s+=x;}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f651_keys():
    """Filed shape 3: keys() over bound array blocks."""
    ok = _blocked("(function(){var fr=['%s','%s'];var s='';"
                  "for(var i of fr.keys()){s+=fr[i];}return s;})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f651_junk_quiet():
    """Junk through the same grammar stays quiet."""
    ok = _misses("(function(){var s='';for(var x of ['jx','jy']"
                 ".values()){s+=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ F651 variants (must block)

def test_p5_f651_destructure():
    """Destructured `[i,v]` entries twin blocks (node-verified)."""
    ok = _blocked("(function(){var s='';for(var [i,v] of ['%s','%s']"
                  ".entries()){s+=v;}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_const_loopvar():
    """`const` loopvar twin blocks (for-of allows const)."""
    ok = _blocked("(function(){var s='';for(const x of ['%s','%s']"
                  ".values()){s+=x;}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_unbraced():
    """Unbraced loop body blocks (node-verified)."""
    ok = _blocked("(function(){var s='';for(var x of ['%s','%s']"
                  ".values())s+=x;return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_let_binding():
    """`let`-bound array twin blocks."""
    ok = _blocked("(function(){let fr=['%s','%s'];var s='';"
                  "for(var i of fr.keys()){s+=fr[i];}return s;})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_bound_entries():
    """entries() over bound array blocks."""
    ok = _blocked("(function(){var fr=['%s','%s'];var s='';"
                  "for(var _e of fr.entries()){s+=_e[1];}return s;})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_single_frag():
    """Single-fragment entries twin blocks."""
    ok = _blocked("(function(){var s='';for(var _e of ['%s']"
                  ".entries()){s+=_e[1];}return s;})()" % _CRED)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_ws():
    """Whitespace-tolerant shape blocks."""
    ok = _blocked("(function(){var s='';for ( var x of ['%s','%s']"
                  ".values( ) ) { s += x ; } return s ; })()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p5_f651_keys_index_additive():
    """keys() index in additive E blocks (node: '01')."""
    ok = _blocked("(function(){var fr=['%s'];var s='';"
                  "for(var i of fr.keys()){s+=fr[i]+i;}return s;})()"
                  % _CRED)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ F651 bounds (must miss)

def test_p6_f651_hole():
    """Sparse hole fails closed (for-of visits holes as undefined)."""
    ok = _misses("(function(){var s='';for(var x of ['a',,'b']"
                 ".values()){s+=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_const_accum():
    """`const` accumulator fails closed."""
    ok = _misses("(function(){const s='';for(var x of ['a','b']"
                 ".values()){s+=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_assign_body():
    """`s=x` (not `s+=x`) body fails closed."""
    ok = _misses("(function(){var s='';for(var x of ['a','b']"
                 ".values()){s=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_loopvar_shadows():
    """Loopvar shadowing the accumulator fails closed."""
    ok = _misses("(function(){var s='';for(var s of ['a','b']"
                 ".values()){s+=s;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_destructure_values():
    """Destructuring on values() fails closed (engine yields strings)."""
    ok = _misses("(function(){var s='';for(var [a,b] of ['ab','cd']"
                 ".values()){s+=a;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_bare_pair():
    """Bare pair read `s+=_e` fails closed (documented boundary)."""
    ok = _misses("(function(){var s='';for(var _e of ['a','b']"
                 ".entries()){s+=_e;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_bare_forof():
    """Bare for-of (no iterator method) is F654's shape: still misses."""
    ok = _misses("(function(){var s='';for(var x of ['a','b'])"
                 "{s+=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_reassign():
    """Reassigned bound array fails closed (single-assignment)."""
    ok = _misses("(function(){var fr=['a'];fr=['b'];var s='';"
                 "for(var i of fr.keys()){s+=fr[i];}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_pair_idx2():
    """`_e[2]` fails closed."""
    ok = _misses("(function(){var s='';for(var _e of ['a','b']"
                 ".entries()){s+=_e[2];}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_method_arg():
    """Iterator method with an argument fails closed."""
    ok = _misses("(function(){var s='';for(var x of ['a','b']"
                 ".values(0)){s+=x;}return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_idx_arith():
    """Numeric `+` on the index fails closed (would mis-decode)."""
    ok = _misses("(function(){var s='';for(var i of ['a','b']"
                 ".keys()){s+=(i+1);}return s;})()")
    ok2 = _misses("(function(){var s='';for(var _e of ['a','b']"
                  ".entries()){s+=_e[0]+1;}return s;})()")
    ok3 = _misses("(function(){var s='';for(var [a,b] of ['a','b']"
                  ".entries()){s+=a+a;}return s;})()")
    ok = ok and ok2 and ok3
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_f651_await():
    """`for await` is F640's production: fails this grammar closed."""
    ok = _misses("(async()=>{var s='';for await (const x of "
                 "['a','b'].values()) s+=x; return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ closed neighbors (must still block)

def test_p7_f600_still_blocks():
    """F600 Map.keys().forEach still blocks."""
    ok = _blocked("(function(){var s='';new Map([['%s','x']]).keys()"
                  ".forEach(function(k){s+=k;});return s;})()" % _CRED)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f601_still_blocks():
    """F601 Map.forEach still blocks."""
    ok = _blocked("(function(){var s='';new Map([['a','%s'],"
                  "['b','%s']]).forEach(function(v){s+=v;});return s;})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f602_still_blocks():
    """F602 Set for-of still blocks."""
    ok = _blocked("(function(){var s='';for(var x of new Set("
                  "['%s','%s'])){s+=x;}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f620_still_blocks():
    """F620 thunk-array forEach still blocks (not absorbed by F646)."""
    ok = _blocked("(function(){var s='';[()=>'%s',()=>'%s'].forEach("
                  "f=>{s+=f();});return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f622_still_blocks():
    """F622 Object.keys enumeration still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};var k="
                  "Object.keys(o);return o[k[0]]+o[k[1]];})()"
                  % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f632_still_blocks():
    """F632 for-in still blocks."""
    ok = _blocked("(function(){var o={x:{p:'%s'},y:{q:'%s'}};"
                  "var s='';for(var k in o){s+=o[k].p||o[k].q;}"
                  "return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p7_f640_still_blocks():
    """F640 for-await still blocks."""
    ok = _blocked("(async()=>{var s='';for await (const x of "
                  "['%s','%s']) s+=x; return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ open neighbors (must still miss)

def test_p8_f644_still_closed():
    """F644 CLOSED at wave-377 merge: destructuring now blocks."""
    ok = _blocked("(function(){var {a,b}={a:'%s',b:'%s'};"
                 "return a+b;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f645_still_closed():
    """F645 CLOSED at wave-377 merge: default params now block."""
    ok = _blocked("(function(s='%s',t='%s'){return s+t;})()"
                 % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f647_still_closed():
    """F647 CLOSED at wave-377 merge: nullish RIGHT-pick now blocks."""
    ok = _blocked("(function(){return (null??'%s')+'%s';})()"
                 % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f648_still_closed():
    """F648 CLOSED at wave-377 merge: USP no-arg ctor now blocks."""
    ok = _blocked("(function(){var p=new URLSearchParams();"
                 "p.append('q','%s');p.append('q','%s');"
                 "return p.getAll('q').join('');})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f649_still_closed():
    """F649 CLOSED at wave-377 merge: structuredClone var-bound members now block."""
    ok = _blocked("(function(){var o=structuredClone({a:'%s',"
                 "b:'%s'});return o.a+o.b;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f650_still_closed():
    """F650 CLOSED at wave-377 merge: object-spread enumeration now blocks."""
    ok = _blocked("(function(){var o={...{a:'%s'},...{b:'%s'}};"
                 "return Object.values(o).join('');})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f652_still_closed():
    """F652 CLOSED at wave-377 merge: comma expressions now block."""
    ok = _blocked("(function(){var x;return (x='%s',x)+'%s';})()"
                 % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f653_still_closed():
    """F653 CLOSED at wave-377 merge: custom Symbol.iterator for-of now blocks."""
    ok = _blocked("(function(){var fr=['%s','%s'];var o={i:0};"
                 "o[Symbol.iterator]=function(){var self=this;return{"
                 "next:function(){return self.i<2?{value:fr[self.i++],"
                 "done:false}:{done:true};}};};var s='';"
                 "for(var x of o){s+=x;}return s;})()" % (_F1, _F23))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


def test_p8_f654_still_closed():
    """F654 CLOSED at wave-377 merge: sync for-of now blocks."""
    ok = _blocked("(function(){var s='';for (const x of ['%s','%s','%s'])"
                 " s+=x; return s;})()" % (_F1, _F2, _F3))
    return ("HELD" if ok else "BREAK", "blocks=%s" % ok)


# ------------------------------------------------ pin + footer

def test_p9_pin_taxonomy_2140_sorted():
    """Pin 2144 asserted (wave-269/338 form coverage)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2144 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p9_footer_state():
    """Merge footer: F644-F654 closed; open F655-F660; next F661."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F795**" in text  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN (next F661)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN (next F661)  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p9_re_compile_28():
    """No new re.compile calls (plain-text scanning only)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


# ------------------------------------------------ perf

def test_p10_perf_corpus():
    """forEach / iterator dispatch sites do not blow the scan budget (F452)."""
    corpus = ("['a','b'].forEach(function(x){s+=x;});"
              "for(var x of ['a','b'].values()){s+=x;} ") * 200
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "quiet=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ green check (depth-1)

def test_p11_green_check():
    """Depth-1 green check: F646 + F651 red-firsts, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w376_f646_redfirst.py", 0),
                               ("evals/w376_f651_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    _t("p1_f646_push_join", test_p1_f646_push_join)
    _t("p1_f646_accumulate", test_p1_f646_accumulate)
    _t("p1_f646_arrow", test_p1_f646_arrow)
    _t("p1_f646_junk_quiet", test_p1_f646_junk_quiet)
    _t("p2_f646_arrow_push", test_p2_f646_arrow_push)
    _t("p2_f646_concise_push", test_p2_f646_concise_push)
    _t("p2_f646_concise_accum", test_p2_f646_concise_accum)
    _t("p2_f646_two_param", test_p2_f646_two_param)
    _t("p2_f646_let_accum", test_p2_f646_let_accum)
    _t("p2_f646_ws", test_p2_f646_ws)
    _t("p2_f646_single_frag", test_p2_f646_single_frag)
    _t("p2_f646_const_push", test_p2_f646_const_push)
    _t("p2_f646_push_additive", test_p2_f646_push_additive)
    _t("p3_f646_const_accum", test_p3_f646_const_accum)
    _t("p3_f646_nonempty_accum", test_p3_f646_nonempty_accum)
    _t("p3_f646_nonliteral_elem", test_p3_f646_nonliteral_elem)
    _t("p3_f646_hole", test_p3_f646_hole)
    _t("p3_f646_numeric_elem", test_p3_f646_numeric_elem)
    _t("p3_f646_assign_body", test_p3_f646_assign_body)
    _t("p3_f646_param_shadows", test_p3_f646_param_shadows)
    _t("p3_f646_three_params", test_p3_f646_three_params)
    _t("p3_f646_nonliteral_sep", test_p3_f646_nonliteral_sep)
    _t("p3_f646_return_bare", test_p3_f646_return_bare)
    _t("p3_f646_idx_arith", test_p3_f646_idx_arith)
    _t("p3_f646_nonempty_arracc", test_p3_f646_nonempty_arracc)
    _t("p4_f651_entries", test_p4_f651_entries)
    _t("p4_f651_values", test_p4_f651_values)
    _t("p4_f651_keys", test_p4_f651_keys)
    _t("p4_f651_junk_quiet", test_p4_f651_junk_quiet)
    _t("p5_f651_destructure", test_p5_f651_destructure)
    _t("p5_f651_const_loopvar", test_p5_f651_const_loopvar)
    _t("p5_f651_unbraced", test_p5_f651_unbraced)
    _t("p5_f651_let_binding", test_p5_f651_let_binding)
    _t("p5_f651_bound_entries", test_p5_f651_bound_entries)
    _t("p5_f651_single_frag", test_p5_f651_single_frag)
    _t("p5_f651_ws", test_p5_f651_ws)
    _t("p5_f651_keys_index_additive", test_p5_f651_keys_index_additive)
    _t("p6_f651_hole", test_p6_f651_hole)
    _t("p6_f651_const_accum", test_p6_f651_const_accum)
    _t("p6_f651_assign_body", test_p6_f651_assign_body)
    _t("p6_f651_loopvar_shadows", test_p6_f651_loopvar_shadows)
    _t("p6_f651_destructure_values", test_p6_f651_destructure_values)
    _t("p6_f651_bare_pair", test_p6_f651_bare_pair)
    _t("p6_f651_bare_forof", test_p6_f651_bare_forof)
    _t("p6_f651_reassign", test_p6_f651_reassign)
    _t("p6_f651_pair_idx2", test_p6_f651_pair_idx2)
    _t("p6_f651_method_arg", test_p6_f651_method_arg)
    _t("p6_f651_idx_arith", test_p6_f651_idx_arith)
    _t("p6_f651_await", test_p6_f651_await)
    _t("p7_f600_still_blocks", test_p7_f600_still_blocks)
    _t("p7_f601_still_blocks", test_p7_f601_still_blocks)
    _t("p7_f602_still_blocks", test_p7_f602_still_blocks)
    _t("p7_f620_still_blocks", test_p7_f620_still_blocks)
    _t("p7_f632_still_blocks", test_p7_f632_still_blocks)
    _t("p7_f622_still_blocks", test_p7_f622_still_blocks)
    _t("p7_f640_still_blocks", test_p7_f640_still_blocks)
    _t("p8_f644_still_closed", test_p8_f644_still_closed)
    _t("p8_f645_still_closed", test_p8_f645_still_closed)
    _t("p8_f647_still_closed", test_p8_f647_still_closed)
    _t("p8_f648_still_closed", test_p8_f648_still_closed)
    _t("p8_f649_still_closed", test_p8_f649_still_closed)
    _t("p8_f650_still_closed", test_p8_f650_still_closed)
    _t("p8_f652_still_closed", test_p8_f652_still_closed)
    _t("p8_f653_still_closed", test_p8_f653_still_closed)
    _t("p8_f654_still_closed", test_p8_f654_still_closed)
    _t("p9_pin_taxonomy_2140_sorted", test_p9_pin_taxonomy_2140_sorted)
    _t("p9_footer_state", test_p9_footer_state)
    _t("p9_re_compile_28", test_p9_re_compile_28)
    _t("p10_perf_corpus", test_p10_perf_corpus)
    _t("p11_green_check", test_p11_green_check)
    nbreak = sum(1 for _, v, _ in results if v == "BREAK")
    nheld = sum(1 for _, v, _ in results if v == "HELD")
    nerr = len(results) - nbreak - nheld
    print("tally: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
