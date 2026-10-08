#!/usr/bin/env python3
"""Wave-375 lane 5 close probes: F626 + F627 + F635 (URLSearchParams family).

F626 (LOW, filed attack round 42): URLSearchParams iteration protocols.
F599 (CLOSED) models append/set statement-form mutations with getAll/get
terminal reads on the constructor receiver, but the ITERATION read path
has no modeled path on the same receiver:
  (function(){var p=new URLSearchParams('a=f1&b=f2');var s='';for(var kv of p){s+=kv[1];}return s;})()
  (function(){var p=new URLSearchParams('a=f1&b=f2');var s='';p.forEach(function(v){s+=v;});return s;})()
  (function(){var p=new URLSearchParams('a=f1&b=f2');var s='';for(var k of p.keys()){s+=p.get(k);}return s;})()
all node-evaluate to the exact credential (v24.20.0) while the decoder
produces zero variants. Closed by _js_parse_f626_params_iteration_iife:
for-of over p / p.entries() (KV[0|1]), p.keys() (p.get(K) first-value
semantics, or the name-accumulating twin), p.values(), and forEach with
a single-param accumulator callback (function or arrow form); `var|let`
accumulator seed (`const` throws in the engine -- fails closed).

F627 (LOW, filed attack round 42): variable-bound (non-literal) VALUES
in URLSearchParams statement-form mutations on the constructor receiver.
F599 (CLOSED) models literal names+values and F616 (CLOSED) the
name-binding axis, but the value axis escaped:
  (function(){var p=new URLSearchParams('');var v='f1';p.append('q',v);p.append('q','f2');return p.getAll('q').join('');})()
  (function(){var p=new URLSearchParams('q=xx');var v='f1';p.set('q',v);return p.get('q')+'f2';})()
Closed by folding the value axis into _js_parse_f616_varname_mutation_iife:
bindings are role-agnostic string constants (the same bound ident may
serve as a name in one statement and a value in another, engine-exact).

F635 (LOW, filed wave-374 lane 5 as F621, renumbered F621->F635 at the
wave-374 merge per the wave-272 rule): the F616 x F617 hybrid --
variable-bound parameter NAMES on the `new URL(...).searchParams`
receiver:
  (function(){var u=new URL('http://x/');var q='q';u.searchParams.append(q,'f1');u.searchParams.append(q,'f2');return u.searchParams.getAll(q).join('');})()
  (function(){var u=new URL('http://x/?q=xx');var k='q';u.searchParams.set(k,'f1');return u.searchParams.get(k)+'f2';})()
  (function(){var u=new URL('http://x/?q=xx');var k='q';u.searchParams.delete(k);u.searchParams.set(k,'f1');return u.searchParams.get(k)+'f2';})()
Closed by adding the F616-style name-binding section to
_js_parse_f617_url_searchparams_iife (names only; a var-bound VALUE on
the searchParams receiver stays a documented residual).

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential (subprocess) for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json as _json
import re as _re
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

TAXONOMY_PIN = 2140  # Wave-374 merge: pin 2140 (F612-F620 closed)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------- P1: F626 filed
def p1_f626_filed_shapes():
    """The three filed F626 shapes must decode (HELD after closure)."""
    shapes = [
        ("params-forof",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(var kv of p){s+=kv[1];}return s;})()" % (_A1, _A2)),
        ("params-foreach",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "p.forEach(function(v){s+=v;});return s;})()" % (_A1, _A2)),
        ("params-keys-get",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(var k of p.keys()){s+=p.get(k);}return s;})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in shapes if not _blocked(s)]
    return (("HELD", "%d/%d F626 filed shapes decode" % (len(shapes), len(shapes)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P2: F626 variants
def p2_f626_variants():
    """Engine-identical F626 generalizations must decode (node-verified)."""
    variants = [
        # KV[0] -- the name twin of the filed for-of shape
        ("forof-idx0",
         "(function(){var p=new URLSearchParams('%s=x&%s=y');var s='';"
         "for(var kv of p){s+=kv[0];}return s;})()" % (_A1, _A2)),
        # of p.entries() -- engine-identical to of p
        ("forof-entries",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(var e of p.entries()){s+=e[1];}return s;})()" % (_A1, _A2)),
        # let/const loop vars
        ("forof-let",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(let kv of p){s+=kv[1];}return s;})()" % (_A1, _A2)),
        ("forof-const",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(const kv of p){s+=kv[1];}return s;})()" % (_A1, _A2)),
        # arrow callback twin of the filed forEach shape
        ("foreach-arrow",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "p.forEach((v)=>{s+=v;});return s;})()" % (_A1, _A2)),
        # keys()+get with duplicate names -- get() is first-value
        ("keys-get-dup",
         "(function(){var p=new URLSearchParams('a=%s&a=zz&b=%s');var s='';"
         "for(var k of p.keys()){s+=p.get(k);}return s;})()" % (_A1, _A2)),
        # the name-accumulating twin of the keys loop
        ("keys-name",
         "(function(){var p=new URLSearchParams('%s=x&%s=y');var s='';"
         "for(var k of p.keys()){s+=k;}return s;})()" % (_A1, _A2)),
        # of p.values()
        ("values",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';"
         "for(var v of p.values()){s+=v;}return s;})()" % (_A1, _A2)),
        # non-empty accumulator seed
        ("seed",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');var s='Q';"
         "for(var kv of p){s+=kv[1];}return s;})()" % (_A1, _A2)),
        # let accumulator
        ("let-acc",
         "(function(){var p=new URLSearchParams('a=%s&b=%s');let s='';"
         "for(var kv of p){s+=kv[1];}return s;})()" % (_A1, _A2)),
        # ws-tolerant
        ("ws",
         "(function(){var p = new URLSearchParams( 'a=%s&b=%s' ) ; var s = '' ; "
         "for( var kv of p ){ s += kv[1] ; } return s ; })()" % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d F626 variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))

# ---------------------------------------------------------- P3: F626 bounds
def p3_f626_bounds():
    """F626 boundaries must stay fail-closed (quiet)."""
    bounds = [
        # mutations before the loop: documented residual
        ("mut-before-loop",
         "(function(){var p=new URLSearchParams('');var s='';"
         "p.append('a','%s');for(var kv of p){s+=kv[1];}return s;})()" % _A1),
        # destructuring loop var: not modeled
        ("destructure",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(var [k,v] of p){s+=v;}return s;})()" % _A1),
        # undeclared loop var
        ("undeclared-lv",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(kv of p){s+=kv[1];}return s;})()" % _A1),
        # const accumulator: engine throws TypeError -- fail closed
        ("const-acc",
         "(function(){var p=new URLSearchParams('a=%s');const s='';"
         "for(var kv of p){s+=kv[1];}return s;})()" % _A1),
        # extra loop-body statement
        ("extra-body-stmt",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(var kv of p){s+=kv[1];s+=kv[0];}return s;})()" % _A1),
        # forEach callback with two params
        ("foreach-2params",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "p.forEach(function(v,k){s+=v;});return s;})()" % _A1),
        # concise arrow body
        ("concise-arrow",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "p.forEach(v=>s+=v);return s;})()" % _A1),
        # mutation inside the loop body: live-iteration semantics
        ("mut-in-loop",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(var kv of p){s+=kv[1];p.append('b','x');}return s;})()" % _A1),
        # pair index other than 0/1
        ("idx2",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(var kv of p){s+=kv[2];}return s;})()" % _A1),
        # loop var shadowing the accumulator
        ("shadow-s",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "for(var s of p){s+=s[1];}return s;})()" % _A1),
        # callback param shadowing the accumulator
        ("cb-shadow-s",
         "(function(){var p=new URLSearchParams('a=%s');var s='';"
         "p.forEach(function(s){s+=s;});return s;})()" % _A1),
        # accumulator name other than the seeded one
        ("other-accum",
         "(function(){var p=new URLSearchParams('a=%s');var s='';var t='';"
         "for(var kv of p){t+=kv[1];}return s;})()" % _A1),
    ]
    bad = [n for n, s in bounds if not _quiet(s)]
    return (("HELD", "%d/%d F626 bounds quiet" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "fired: %r" % (bad,)))


# ---------------------------------------------------------- P4: F627 filed
def p4_f627_filed_shapes():
    """The two filed F627 shapes must decode (HELD after closure)."""
    shapes = [
        ("append-varbound-value",
         "(function(){var p=new URLSearchParams('');var v='%s';"
         "p.append('q',v);p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        ("set-varbound-value",
         "(function(){var p=new URLSearchParams('q=xx');var v='%s';"
         "p.set('q',v);return p.get('q')+'%s';})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in shapes if not _blocked(s)]
    return (("HELD", "%d/%d F627 filed shapes decode" % (len(shapes), len(shapes)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P5: F627 variants
def p5_f627_variants():
    """F627 value-axis generalizations must decode (node-verified)."""
    variants = [
        # the same binding as name in one statement, value in another
        ("both-axes",
         "(function(){var p=new URLSearchParams('');var k='q';var v='%s';"
         "p.append(k,v);p.append(k,'%s');"
         "return p.getAll(k).join('');})()" % (_A1, _A2)),
        # duplicate var value rebinds (last wins, engine-exact)
        ("val-rebind",
         "(function(){var p=new URLSearchParams('');var v='zz';var v='%s';"
         "p.append('q',v);p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # var-bound value with set/delete + var-bound names
        ("set-del-value",
         "(function(){var p=new URLSearchParams('z=zz');var k='q';var v='%s';"
         "p.delete('z');p.set(k,v);return p.get(k)+'%s';})()" % (_A1, _A2)),
        # var-bound value with sort (F606's union, value axis)
        ("sort-value",
         "(function(){var p=new URLSearchParams('z=zz');var v='%s';"
         "p.append('q',v);p.append('q','%s');p.sort();"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # value binding unused by name positions still decodes
        ("value-only-decl",
         "(function(){var p=new URLSearchParams('');var v='%s';"
         "p.append('q',v);p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d F627 variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P6: F627 bounds
def p6_f627_bounds():
    """F627 value-axis boundaries must stay fail-closed (quiet)."""
    bounds = [
        # unbound value ident: engine throws ReferenceError
        ("unbound-value",
         "(function(){var p=new URLSearchParams('');"
         "p.append('q',v);return p.getAll('q').join('');})()"),
        # non-string binding RHS
        ("nonstring-rhs",
         "(function(){var p=new URLSearchParams('');var v=1;"
         "p.append('q',v);return p.getAll('q').join('');})()"),
        # value decl after the first mutation
        ("decl-after-mut",
         "(function(){var p=new URLSearchParams('');p.append('q','%s');"
         "var v='x';p.append('q',v);return p.getAll('q').join('');})()" % _A1),
        # duplicate let value decl: SyntaxError in the engine
        ("dup-let",
         "(function(){var p=new URLSearchParams('');let v='z';let v='%s';"
         "p.append('q',v);return p.getAll('q').join('');})()" % _A1),
        # value binding colliding with the params ident
        ("value-is-pname",
         "(function(){var p=new URLSearchParams('');var p='%s';"
         "p.append('q',p);return p.getAll('q').join('');})()" % _A1),
    ]
    bad = [n for n, s in bounds if not _quiet(s)]
    return (("HELD", "%d/%d F627 bounds quiet" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "fired: %r" % (bad,)))

# ---------------------------------------------------------- P7: F635 filed
def p7_f635_filed_shapes():
    """The three filed F635 shapes must decode (HELD after closure)."""
    shapes = [
        ("append-varbound-name",
         "(function(){var u=new URL('http://x/');var q='q';"
         "u.searchParams.append(q,'%s');u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll(q).join('');})()" % (_A1, _A2)),
        ("set-get-varbound-name",
         "(function(){var u=new URL('http://x/?q=xx');var k='q';"
         "u.searchParams.set(k,'%s');return u.searchParams.get(k)+'%s';})()"
         % (_A1, _A2)),
        ("del-set-get-varbound-name",
         "(function(){var u=new URL('http://x/?q=xx');var k='q';"
         "u.searchParams.delete(k);u.searchParams.set(k,'%s');"
         "return u.searchParams.get(k)+'%s';})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in shapes if not _blocked(s)]
    return (("HELD", "%d/%d F635 filed shapes decode" % (len(shapes), len(shapes)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P8: F635 variants
def p8_f635_variants():
    """F635 name-axis generalizations must decode (node-verified)."""
    variants = [
        # duplicate var name rebinds (last wins, engine-exact)
        ("rebind",
         "(function(){var u=new URL('http://x/');var q='z';var q='q';"
         "u.searchParams.append(q,'%s');u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll(q).join('');})()" % (_A1, _A2)),
        # bracket-string member reads
        ("bracket",
         "(function(){var u=new URL('http://x/?q=xx');var k='q';"
         "u['searchParams']['set'](k,'%s');"
         "return u['searchParams']['get'](k)+'%s';})()" % (_A1, _A2)),
        # two distinct name bindings
        ("two-names",
         "(function(){var u=new URL('http://x/');var a='q';var b='q';"
         "u.searchParams.append(a,'%s');u.searchParams.append(b,'%s');"
         "return u.searchParams.getAll(a).join('');})()" % (_A1, _A2)),
        # ws-tolerant
        ("ws",
         "(function(){var u = new URL( 'http://x/' ) ; var q = 'q' ; "
         "u.searchParams.append( q , '%s' ) ; u.searchParams.append( q , '%s' ) ; "
         "return u.searchParams.getAll( q ).join( '' ) ; })()" % (_A1, _A2)),
        # delete with a bound name, query-seeded pairs
        ("delete-bound",
         "(function(){var u=new URL('http://x/?z=zz');var k='z';"
         "u.searchParams.delete(k);u.searchParams.append('q','%s');"
         "u.searchParams.append('q','%s');"
         "return u.searchParams.getAll('q').join('');})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d F635 variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P9: F635 bounds
def p9_f635_bounds():
    """F635 boundaries must stay fail-closed (quiet)."""
    bounds = [
        # unbound name ident: engine throws ReferenceError
        ("unbound-name",
         "(function(){var u=new URL('http://x/');"
         "u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll('q').join('');})()" % _A1),
        # var-bound VALUE on the searchParams receiver: documented
        # residual (F635 closes the name axis only)
        ("var-value",
         "(function(){var u=new URL('http://x/');var v='%s';"
         "u.searchParams.append('q',v);"
         "return u.searchParams.getAll('q').join('');})()" % _A1),
        # duplicate let name decl: SyntaxError in the engine
        ("dup-let",
         "(function(){var u=new URL('http://x/');let q='z';let q='q';"
         "u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll(q).join('');})()" % _A1),
        # name decl after the first mutation
        ("decl-after-mut",
         "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q','%s');var q='q';"
         "return u.searchParams.getAll(q).join('');})()" % _A1),
        # name decl colliding with the URL ident
        ("name-is-uname",
         "(function(){var u=new URL('http://x/');var u='q';"
         "u.searchParams.append('q','%s');"
         "return u.searchParams.getAll('q').join('');})()" % _A1),
    ]
    bad = [n for n, s in bounds if not _quiet(s)]
    return (("HELD", "%d/%d F635 bounds quiet" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "fired: %r" % (bad,)))

# ---------------------------------------------------------- P10: compositions
def p10_compositions():
    """Neighbor findings stay HELD; sibling wave-375 findings still BREAK (not absorbed)."""
    held = [
        # F599: literal-name append/getAll statement form
        ("f599-append",
         "(function(){var p=new URLSearchParams('');"
         "p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # F616: var-bound name, literal values
        ("f616-name",
         "(function(){var p=new URLSearchParams('');var q='q';"
         "p.append(q,'%s');p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % (_A1, _A2)),
        # F617: literal names on the searchParams receiver
        ("f617-literal",
         "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q','%s');u.searchParams.append('q','%s');"
         "return u.searchParams.getAll('q').join('');})()" % (_A1, _A2)),
        # F576: .get on constructor strings
        ("f576-get",
         "new URLSearchParams('q=%s').get('q')+'%s'" % (_A1, _A2)),
    ]
    miss = [
        # F621, F622, F628, F636 are CLOSED on the merged tree (wave-375
        # merge, lanes 1/2/4/7) -- their shapes now block via their own
        # closures, not absorbed by this lane. Only truly-open findings
        # (F640-F643) belong in the miss list.
    ]
    bad_held = [n for n, s in held if not _blocked(s)]
    bad_miss = [n for n, s in miss if _blocked(s)]
    bad = bad_held + ["absorbed:" + n for n in bad_miss]
    return (("HELD", "%d/%d compositions hold" % (len(held) + len(miss), len(held) + len(miss)))
            if not bad else ("BREAK", "bad: %r" % (bad,)))


# ---------------------------------------------------------- P11: node differential
_DIFF_CASES = [
    # F626
    ("f626-forof", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var kv of p){s+=kv[1];}return s;})()"),
    ("f626-forof-idx0", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var kv of p){s+=kv[0];}return s;})()"),
    ("f626-forof-entries", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var e of p.entries()){s+=e[1];}return s;})()"),
    ("f626-forof-let", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(let kv of p){s+=kv[1];}return s;})()"),
    ("f626-forof-const", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(const kv of p){s+=kv[1];}return s;})()"),
    ("f626-foreach", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';p.forEach(function(v){s+=v;});return s;})()"),
    ("f626-foreach-arrow", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';p.forEach((v)=>{s+=v;});return s;})()"),
    ("f626-keys-get", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var k of p.keys()){s+=p.get(k);}return s;})()"),
    ("f626-keys-get-dup", "(function(){var p=new URLSearchParams('a=AAA&a=zz&b=BBB');var s='';for(var k of p.keys()){s+=p.get(k);}return s;})()"),
    ("f626-keys-name", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var k of p.keys()){s+=k;}return s;})()"),
    ("f626-values", "(function(){var p=new URLSearchParams('a=AAA&b=BBB');var s='';for(var v of p.values()){s+=v;}return s;})()"),
    ("f626-seed", "(function(){var p=new URLSearchParams('a=AAA');var s='Q';for(var kv of p){s+=kv[1];}return s;})()"),
    ("f626-let-acc", "(function(){var p=new URLSearchParams('a=AAA');let s='';for(var kv of p){s+=kv[1];}return s;})()"),
    # F627
    ("f627-append-val", "(function(){var p=new URLSearchParams('');var v='AAA';p.append('q',v);p.append('q','BBB');return p.getAll('q').join('');})()"),
    ("f627-set-val", "(function(){var p=new URLSearchParams('q=xx');var v='AAA';p.set('q',v);return p.get('q')+'BBB';})()"),
    ("f627-both-axes", "(function(){var p=new URLSearchParams('');var k='q';var v='AAA';p.append(k,v);return p.getAll(k).join('');})()"),
    ("f627-val-rebind", "(function(){var p=new URLSearchParams('');var v='zz';var v='AAA';p.append('q',v);return p.getAll('q').join('');})()"),
    # F635
    ("f635-append", "(function(){var u=new URL('http://x/');var q='q';u.searchParams.append(q,'AAA');u.searchParams.append(q,'BBB');return u.searchParams.getAll(q).join('');})()"),
    ("f635-setget", "(function(){var u=new URL('http://x/?q=xx');var k='q';u.searchParams.set(k,'AAA');return u.searchParams.get(k)+'BBB';})()"),
    ("f635-delsetget", "(function(){var u=new URL('http://x/?q=xx');var k='q';u.searchParams.delete(k);u.searchParams.set(k,'AAA');return u.searchParams.get(k)+'BBB';})()"),
    ("f635-rebind", "(function(){var u=new URL('http://x/');var q='z';var q='q';u.searchParams.append(q,'AAA');return u.searchParams.getAll(q).join('');})()"),
]


def p11_node_differential():
    """Every decode above must be value-exact against node v24.20.0."""
    cases = [t.replace("AAA", _A1).replace("BBB", _A2) for _, t in _DIFF_CASES]
    script = ("const cases=" + _json.dumps(cases) + ";"
              "for(const s of cases){let v;try{v=(0,eval)(s)}catch(e)"
              "{console.log('THROW:'+e.constructor.name);continue}"
              "console.log(JSON.stringify(v));}")
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                       timeout=120)
    lines = [l for l in (r.stdout or "").splitlines() if l]
    if r.returncode != 0 or len(lines) != len(cases):
        return "BREAK", "node run failed rc=%d lines=%d" % (r.returncode, len(lines))
    bad = []
    for (name, _), line, src in zip(_DIFF_CASES, lines, cases):
        try:
            node_val = _json.loads(line)
        except Exception:
            bad.append(name + ":node-" + line[:40])
            continue
        fam = name.split("-")[0]
        parser = {"f626": dlp._js_parse_f626_params_iteration_iife,
                  "f627": dlp._js_parse_f616_varname_mutation_iife,
                  "f635": dlp._js_parse_f617_url_searchparams_iife}[fam]
        rr = parser(src, 0, 0, {"parts": 0, "ops": 0})
        dec_val = rr[0] if rr else None
        if dec_val != node_val:
            bad.append(name)
    return (("HELD", "%d/%d node-exact" % (len(_DIFF_CASES), len(_DIFF_CASES)))
            if not bad else ("BREAK", "diffs: %r" % (bad,)))


# ---------------------------------------------------------- P12: pin + footer
def p12_pin_footer():
    """Pin stays 2140; footer shows the lane-local open set."""
    from gov import guac_graph  # noqa: E402
    pin_ok = TAXONOMY_PIN == 2140 and guac_graph.TAXONOMY_PIN == 2140
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    footer_ok = ("Next free finding: **F672**" in text  # Wave-375 lane 5: footer repoint open F621-F625, F628-F634, F636-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
                 and "Open findings: F662, F663, F664, F665, F666, F667, F668, F669, F670, F671."  # Wave-375 lane 5: footer repoint open F621-F625, F628-F634, F636-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
                 in text)
    ok = pin_ok and footer_ok
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (pin_ok, footer_ok))


# ---------------------------------------------------------- P13: perf bound
def p13_perf_bound():
    # The F626/F616/F617 branches add bounded decode attempts per IIFE
    # anchor; the hostile corpus must stay under the 5s pin (F452).
    corpus = ("\"(function(){var p=new URLSearchParams('');var s='';"
              "for(var kv of p){s+=kv[1];}return s;})()\";" * 60 +
              "\"(function(){var p=new URLSearchParams('');var v='x';"
              "p.append('q',v);return p.getAll('q').join('');})()\";" * 60 +
              "\"(function(){var u=new URL('http://x/');var q='q';"
              "u.searchParams.append(q,'x');"
              "return u.searchParams.getAll(q).join('');})()\";" * 60)
    t0 = time.time()
    dlp.find_credential(corpus)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "corpus %.2fs" % dt)


GREEN_ADJACENT = [
    "evals/w374_f626_redfirst.py",
    "evals/w374_f627_redfirst.py",
    "evals/w374_f616f617close_probes.py",
    "evals/w374_attack_probes.py",
    "evals/w373_f616_redfirst.py",
    "evals/w373_f617_redfirst.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        p = os.path.join(REPO_ROOT, rel)
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = "/var/tmp/g375-l5-green"
        os.makedirs(env["TMPDIR"], exist_ok=True)
        r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                           timeout=600, env=env, cwd=REPO_ROOT)
        tail = (r.stdout or "").strip().splitlines()
        tally = tail[-1] if tail else ""
        m = _re.search(r"(\d+) BREAK", tally)
        good = r.returncode == 0 and m is not None and int(m.group(1)) == 0
        print("green %s: %s (%s)" % (rel, "OK" if good else "FAIL", tally))
        ok = ok and good
    return ok


PROBES = [
    ("p1-f626-filed", p1_f626_filed_shapes),
    ("p2-f626-variants", p2_f626_variants),
    ("p3-f626-bounds", p3_f626_bounds),
    ("p4-f627-filed", p4_f627_filed_shapes),
    ("p5-f627-variants", p5_f627_variants),
    ("p6-f627-bounds", p6_f627_bounds),
    ("p7-f635-filed", p7_f635_filed_shapes),
    ("p8-f635-variants", p8_f635_variants),
    ("p9-f635-bounds", p9_f635_bounds),
    ("p10-compositions", p10_compositions),
    ("p11-node-differential", p11_node_differential),
    ("p12-pin-footer", p12_pin_footer),
    ("p13-perf-bound", p13_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks = 0
    for name, fn in PROBES:
        if args.probe and args.probe != name:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never silent
            verdict, detail = "BREAK", "EXC %s: %s" % (type(e).__name__, str(e)[:120])
        print("%s: %s (%s)" % (name, verdict, detail))
        if verdict != "HELD":
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, len(PROBES) - breaks))
    if args.probe:
        return 1 if breaks else 0
    print("--- green check ---")
    gok = green_check()
    print("OVERALL: %s" % ("HELD" if breaks == 0 and gok else "BREAK"))
    return 0 if breaks == 0 and gok else 1


if __name__ == "__main__":
    sys.exit(main())
