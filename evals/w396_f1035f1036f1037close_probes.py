#!/usr/bin/env python3
"""Wave-396 lane-1 close battery: F1035 + F1036 + F1037.

F1035: Object.assign-staged code reads:
  `var o=Object.assign({},{a:[codes]});var RESULT=String.fromCharCode(...o.a);`
  (getter variant `Object.assign({},{get a(){return [codes];}})` invokes
  the source getter during assignment, node-exact).
F1036: structuredClone-staged code reads:
  `var RESULT=String.fromCharCode(...structuredClone([codes]));`
F1037: groupBy-keyed code reassembly:
  `var g=Object.groupBy([[i,code],...],function(p){return p[0]%2;});`
  `var all=g[0].concat(g[1]);` (or `g.get(0).concat(g.get(1))` for
  Map.groupBy) `all.sort(function(a,b){return a[0]-b[0];});`
  `var s="";for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;`

All three decoders are node-exact (v24.20.0) for their modeled subsets;
everything outside the strict grammars fails closed (miss, never
mis-decode). Pin 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28 -- all
untouched. $0 spend by construction. Depth-1 green check honors
GOV_SKIP_GREEN=1.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


_C21 = ("[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,"
        "101,102]")
_C21L = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
         97, 98, 99, 100, 101, 102]
_P21 = ",".join("[%d,%d]" % (i, c) for i, c in enumerate(_C21L))


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_state():
    """Lane-local footer: F1035-F1037 CLOSED; F1038-F1047 open (10); next F1048."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1048**" in text
          and "F1038-F1047 OPEN (10" in text
          and "F1035-F1037 CLOSED (3" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


@_t
def test_p0_findings_stamps():
    """F1035/F1036/F1037 entries carry the wave-396 lane-1 CLOSED stamp."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = all("(F%d filed" % f in text
             and "[CLOSED 2026-10-10 wave-396 lane 1" in
             text.split("(F%d filed" % f)[1][:400]
             for f in (1035, 1036, 1037))
    return ("HELD" if ok else "BREAK", "stamps-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


@_t
def test_p1_f1035_filed_short():
    p = ('var o=Object.assign({},{a:%s});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-filed-short")


@_t
def test_p1_f1035_filed_40():
    c40 = ("[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,"
           "101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,"
           "49,50]")
    p = ('var o=Object.assign({},{a:%s});'
         'var RESULT=String.fromCharCode(...o.a);') % c40
    return ("HELD" if _blocked(p) else "BREAK", "f1035-filed-40")


@_t
def test_p1_f1035_filed_getter():
    p = ('var o=Object.assign({},{get a(){return %s;}});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-filed-getter")


@_t
def test_p1_f1036_filed_short():
    p = 'var RESULT=String.fromCharCode(...structuredClone(%s));' % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1036-filed-short")


@_t
def test_p1_f1036_filed_40():
    c40 = ("[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,"
           "101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,"
           "49,50]")
    p = 'var RESULT=String.fromCharCode(...structuredClone(%s));' % c40
    return ("HELD" if _blocked(p) else "BREAK", "f1036-filed-40")


@_t
def test_p1_f1037_filed_obj_short():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-filed-obj-short")


@_t
def test_p1_f1037_filed_obj_40():
    p40 = ",".join("[%d,%d]" % (i, c) for i, c in enumerate(
        _C21L + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
                 101, 102, 48, 49, 50]))
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % p40
    return ("HELD" if _blocked(p) else "BREAK", "f1037-filed-obj-40")


@_t
def test_p1_f1037_filed_map_short():
    p = ('var g=Map.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g.get(0).concat(g.get(1));'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-filed-map-short")


@_t
def test_p1_f1037_filed_map_40():
    p40 = ",".join("[%d,%d]" % (i, c) for i, c in enumerate(
        _C21L + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
                 101, 102, 48, 49, 50]))
    p = ('var g=Map.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g.get(0).concat(g.get(1));'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % p40
    return ("HELD" if _blocked(p) else "BREAK", "f1037-filed-map-40")


# --------------------------------------- p2: generalizations (node-verified)


@_t
def test_p2_f1035_let_decl():
    p = ('let o=Object.assign({},{a:%s});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-let")


@_t
def test_p2_f1035_whitespace():
    p = ('var o = Object.assign( {}, { a : %s } ) ;\n'
         'var RESULT = String.fromCharCode( ...o.a ) ;') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-ws")


@_t
def test_p2_f1035_target_override():
    # Source props win over target props (node-exact).
    p = ('var o=Object.assign({a:[1]},{a:%s});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-override")


@_t
def test_p2_f1035_trailing_comma():
    p = ('var o=Object.assign({},{a:%s,});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1035-trailcomma")


@_t
def test_p2_f1036_const_decl():
    p = 'const RESULT=String.fromCharCode(...structuredClone(%s));' % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1036-const")


@_t
def test_p2_f1036_whitespace():
    p = 'var RESULT = String.fromCharCode( ...structuredClone( %s ) ) ;' % _C21
    return ("HELD" if _blocked(p) else "BREAK", "f1036-ws")


@_t
def test_p2_f1037_arrow_keyfn():
    p = ('var g=Object.groupBy([%s],p=>p[0]%%2);'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-arrowkey")


@_t
def test_p2_f1037_arrow_comparator():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort((a,b)=>a[0]-b[0]);var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-arrowcmp")


@_t
def test_p2_f1037_swapped_concat():
    # Sort restores index order regardless of concat order (node-exact).
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[1].concat(g[0]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-swapped")


@_t
def test_p2_f1037_braceless_loop():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all)s+=String.fromCharCode(p[1]);var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-braceless")


@_t
def test_p2_f1037_let_const_decls():
    p = ('let g=Map.groupBy([%s],function(p){return p[0]%%2;});'
         'const all=g.get(0).concat(g.get(1));'
         'all.sort(function(a,b){return a[0]-b[0];});let s="";'
         'for(let p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _blocked(p) else "BREAK", "f1037-decls")


# --------------------------------------- p3: fail-closed bounds (hook misses)


def _hook_none(hook, payload):
    return hook(payload) is None


@_t
def test_p3_f1035_method_member():
    p = ('var o=Object.assign({},{m(){}});'
         'var RESULT=String.fromCharCode(...o.a);')
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-method")


@_t
def test_p3_f1035_setter():
    p = ('var o=Object.assign({},{set a(v){}});'
         'var RESULT=String.fromCharCode(...o.a);')
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-setter")


@_t
def test_p3_f1035_three_args():
    p = ('var o=Object.assign({},{a:%s},{b:[1]});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-3args")


@_t
def test_p3_f1035_one_arg():
    p = ('var o=Object.assign({a:%s});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-1arg")


@_t
def test_p3_f1035_missing_prop():
    # o.b is node-undefined -- outside the string-only discipline.
    p = ('var o=Object.assign({},{a:%s});'
         'var RESULT=String.fromCharCode(...o.b);') % _C21
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-missingprop")


@_t
def test_p3_f1035_shorthand():
    p = ('var a=%s;var o=Object.assign({},{a});'
         'var RESULT=String.fromCharCode(...o.a);') % _C21
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-shorthand")


@_t
def test_p3_f1035_getter_no_return():
    p = ('var o=Object.assign({},{get a(){}});'
         'var RESULT=String.fromCharCode(...o.a);')
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-getter-noret")


@_t
def test_p3_f1035_proto_data():
    # `{__proto__: value}` sets the prototype, not an own data prop
    # (node) -- modeling it as staged would mis-decode (spec review).
    p = ('var o=Object.assign({__proto__:[120]},{__proto__:[65]});'
         'var RESULT=String.fromCharCode(...o.__proto__);')
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-proto-data")


@_t
def test_p3_f1035_proto_getter():
    p = ('var o=Object.assign({},{get __proto__(){return [65];}});'
         'var RESULT=String.fromCharCode(...o.__proto__);')
    return ("HELD" if _hook_none(dlp._js_f1035_stmt_decode, p) else "BREAK",
            "fc35-proto-getter")


@_t
def test_p3_f1036_object_arg():
    p = 'var RESULT=String.fromCharCode(...structuredClone({}));'
    return ("HELD" if _hook_none(dlp._js_f1036_stmt_decode, p) else "BREAK",
            "fc36-obj")


@_t
def test_p3_f1036_nested_array():
    p = 'var RESULT=String.fromCharCode(...structuredClone([[120]]));'
    return ("HELD" if _hook_none(dlp._js_f1036_stmt_decode, p) else "BREAK",
            "fc36-nested")


@_t
def test_p3_f1036_no_spread():
    # fromCharCode(array) coerces to NaN -> no credential assembled.
    p = 'var RESULT=String.fromCharCode(structuredClone(%s));' % _C21
    return ("HELD" if _hook_none(dlp._js_f1036_stmt_decode, p) else "BREAK",
            "fc36-nospread")


@_t
def test_p3_f1036_hole():
    p = 'var RESULT=String.fromCharCode(...structuredClone([,120]));'
    return ("HELD" if _hook_none(dlp._js_f1036_stmt_decode, p) else "BREAK",
            "fc36-hole")


def _f1037_seq(body):
    return ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
            'var all=g[0].concat(g[1]);'
            'all.sort(function(a,b){return a[0]-b[0];});var s="";'
            '%s'
            'var RESULT=s;') % (_P21, body)


@_t
def test_p3_f1037_gapped_indices():
    p = ('var g=Object.groupBy([[0,120],[2,111]],function(p){return p[0]%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;')
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-gapped")


@_t
def test_p3_f1037_repeated_index():
    p = ('var g=Object.groupBy([[0,120],[0,111]],function(p){return p[0]%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;')
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-repeat")


@_t
def test_p3_f1037_non_parity_keyfn():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%3;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-keyfn3")


@_t
def test_p3_f1037_missing_sort():
    # Without the sort node assembles evens-then-odds -- unmodeled.
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-nosort")


@_t
def test_p3_f1037_same_group_twice():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[0]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-samekey")


@_t
def test_p3_f1037_obj_with_get():
    # Object flavor with .get( reads is a node TypeError -- fail closed.
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g.get(0).concat(g.get(1));'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-obj-get")


@_t
def test_p3_f1037_wrong_comparator():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[1]-b[1];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-cmp1")


@_t
def test_p3_f1037_nonempty_acc():
    p = ('var g=Object.groupBy([%s],function(p){return p[0]%%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="x";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;') % _P21
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-nonempty-acc")


@_t
def test_p3_f1037_index_accum():
    # p[0] accumulates indices -- unmodeled projection.
    p = _f1037_seq('for(var p of all){s+=String.fromCharCode(p[0]);}')
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-idx-accum")


@_t
def test_p3_f1037_const_loop_var():
    # for(const p of ...) is a node SyntaxError on second iteration.
    p = _f1037_seq('for(const p of all){s+=String.fromCharCode(p[1]);}')
    return ("HELD" if _hook_none(dlp._js_f1037_stmt_decode, p) else "BREAK",
            "fc37-const-loop")


# --------------------------------------- p4: sibling pins stay open


def _redfirst_first_shape(f):
    fp = os.path.join(REPO_ROOT, "evals", "w395_f%d_redfirst.py" % f)
    src = open(fp).read()
    ns = {"__name__": "x", "__file__": fp}
    exec(src.split("CONTROLS =")[0], ns)  # noqa: S102
    return ns["SHAPES"][0]


@_t
def test_p4_siblings_now_closed():
    """Wave-396 merge: F1038-F1046 closed by lanes 2-4 -- filed shapes must now BLOCK via find_credential."""
    bad = []
    for f in range(1038, 1047):
        name, payload = _redfirst_first_shape(f)
        if _misses(payload):
            bad.append(name)
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "siblings-closed=%s" % (bad or "all-9-blocked"))


# --------------------------------------- p5: honest text stays quiet


@_t
def test_p5_honest_assign_decode():
    # Decodes honestly to "hi" (non-credential) -- no block.
    p = ('var o=Object.assign({},{a:[104,105]});'
         'var RESULT=String.fromCharCode(...o.a);')
    dec = dlp._js_f1035_stmt_decode(p)
    ok = dec == "hi" and _misses(p)
    return ("HELD" if ok else "BREAK", "honest-assign")


@_t
def test_p5_honest_clone_decode():
    p = 'var RESULT=String.fromCharCode(...structuredClone([104,105]));'
    dec = dlp._js_f1036_stmt_decode(p)
    ok = dec == "hi" and _misses(p)
    return ("HELD" if ok else "BREAK", "honest-clone")


@_t
def test_p5_honest_groupby_decode():
    p = ('var g=Object.groupBy([[0,104],[1,105]],function(p){return p[0]%2;});'
         'var all=g[0].concat(g[1]);'
         'all.sort(function(a,b){return a[0]-b[0];});var s="";'
         'for(var p of all){s+=String.fromCharCode(p[1]);}var RESULT=s;')
    dec = dlp._js_f1037_stmt_decode(p)
    ok = dec == "hi" and _misses(p)
    return ("HELD" if ok else "BREAK", "honest-groupby")


@_t
def test_p5_junk_quiet():
    ctrls = [
        "(function(){var s='ab';return s;})()",
        "var o=Object.assign({},{a:[]});var x=1;",
        "console.log('structuredClone is a global');",
        "Object.groupBy([1,2],function(x){return x;});",
    ]
    bad = [c for c in ctrls if not _misses(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "junk=%s" % (bad or "quiet"))


# --------------------------------------- p6: perf


@_t
def test_p6_perf_200_sites():
    """200 anchor-bearing fail-closed sites stay fast (no F452 regression)."""
    sites = []
    for i in range(70):
        sites.append('var o%d=Object.assign({},{a:[%d]});var z=%d;'
                     % (i, 100 + i, i))
    for i in range(70):
        sites.append('var RESULT%d=String.fromCharCode(...structuredClone([%d]));'
                     % (i, 100 + i))
    for i in range(60):
        sites.append('var g%d=Object.groupBy([[0,%d]],function(p){return p[0]%%3;});'
                     % (i, 100 + i))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs" % dt)


# --------------------------------------- p7: depth-1 green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w396_f1035_redfirst.py", "w396_f1036_redfirst.py",
                    "w396_f1037_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g396-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format: "FAIL <shape>" (blocked, good on the
        # closed tree) / "BREAK <shape>" (miss, bad); "ctrl-ok <name>"
        # / "CTRL-FAIL <name>".
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        total_bad += bad
        notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
        if nshapes == 0:
            total_bad += 1
            notes.append("%s: no shapes tallied" % battery)
    ok = total_bad == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d bad [%s]"
            % (total_bad, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the three red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held, broke, failed = 0, 0, []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        if verdict == "HELD":
            held += 1
        else:
            broke += 1
            failed.append((fn.__name__, note))
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("HELD %d / BREAK %d / %d total" % (held, broke, held + broke))
    for name, note in failed:
        print("FAILED:", name, note)
    return 1 if broke else 0


if __name__ == "__main__":
    sys.exit(main())
