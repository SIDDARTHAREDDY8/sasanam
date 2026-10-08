#!/usr/bin/env python3
"""Wave-379 lane 2: close F663 + F664 (Object member-source family).

F663 (LOW; filed 2026-10-08 by wave-378 lane 7, attack round 46):
Object.fromEntries-assembled member reads bypass the bounded static
JS-expression decoder. F565 models fromEntries as an enumeration
source (the Object.values twin blocks coded), but member reads on a
var-bound fromEntries result escape the receiver model:
  (function(){var o=Object.fromEntries([['a','f1'],['b','f2']]);
  return o.a+o.b;})()  -> node "f1f2" (v24.20.0)

Fix (gov/dlp.py, zero new re.compile): _js_parse_f663_fromentries_
members_iife -- the F649 var-bound-member-reads idiom with the F565
_from_entries source parser: the var binds the F565 _JSObj, each
o.M / o['M'] term resolves via _jsobj_lookup, the +-joined sum is
the decoded value. The inline expression-level twin already blocks
through F565's postfix member-read branch -- this closes only the
var-bound statement twin.

F664 (LOW; filed 2026-10-08 by wave-378 lane 7, attack round 46):
getter invocation through Object.getOwnPropertyDescriptor in
additive position bypasses the decoder. F549 models descriptor-get
on an object LITERAL target, but a var-bound target escapes it:
  (function(){var o={get x(){return 'f1';}};
  return Object.getOwnPropertyDescriptor(o,'x').get()+'f2';})()
  -> node "f1f2" (v24.20.0)

Fix (gov/dlp.py, zero new re.compile): _js_parse_f664_gopd_
varbound_iife -- the var binds the accessor-aware _js_parse_f535_
object props; each Object.getOwnPropertyDescriptor(o,'KEY').get()
term resolves to the accessor's already-evaluated string value
(F549's terminal discipline: .get() on data props / .value on
accessors / missing keys / call args all fail closed); string
literals join in the additive. Note the finding's "bare-call twin
blocks" control is a raw-literal subexpression artifact -- the
split bare-call form misses on the base tree too, and this parser
closes it as the one-term additive.

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
def test_p1_f663_filed_member_reads():
    """F663 filed: var-bound fromEntries member reads block."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f664_filed_descriptor_get():
    """F664 filed: var-bound descriptor .get() in additive position blocks."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)


@_t
def test_p2_f663_bracket_twin():
    """F663 bracket twin: o['a']+o['b'] blocks."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o['a']+o['b'];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_let_twin():
    """F663 let twin blocks."""
    s = ("(function(){let o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_const_twin():
    """F663 const twin blocks."""
    s = ("(function(){const o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_new_map_twin():
    """F663 new-Map pair list twin blocks."""
    s = ("(function(){var o=Object.fromEntries(new Map([['a','" + _A
         + "'],['b','" + _B + "']]));return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_dupe_keys_later_wins():
    """F663 duplicate keys: later wins (node-exact)."""
    s = ("(function(){var o=Object.fromEntries([['a','jx'],['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_integer_keys():
    """F663 integer keys ToPropertyKey to decimal repr (node-exact)."""
    s = ("(function(){var o=Object.fromEntries([[1,'" + _A
         + "'],[2,'" + _B + "']]);return o['1']+o['2'];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_three_terms():
    """F663 three-term additive blocks."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b+'zz';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f663_ws_twin():
    """F663 whitespace-tolerant twin blocks."""
    s = ("(function(){var o = Object.fromEntries( [ ['a','" + _A
         + "'] , ['b','" + _B + "'] ] );return o.a + o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f664_two_getters():
    """F664 two-descriptor additive blocks."""
    s = ("(function(){var o={get x(){return '" + _A
         + "';},get y(){return '" + _B + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+"
         + "Object.getOwnPropertyDescriptor(o,'y').get();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f664_single_term_return():
    """F664 one-term additive (split bare-call): blocks, not an artifact."""
    s = ("(function(){var o={get x(){return '" + _A + _B + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f664_ws_twin():
    """F664 whitespace-tolerant twin blocks."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor( o , 'x' ).get() + '" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f664_getter_additive_body():
    """F664 getter with an additive return body blocks."""
    s = ("(function(){var o={get x(){return 'xox'+'b-0123';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f664_const_twin():
    """F664 const twin blocks."""
    s = ("(function(){const o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f663_missing_key():
    """F663 missing key: o.z is undefined -- fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "']]);return o.a+o.z;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_numeric_index():
    """F663 numeric index member: fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o[0]+o[1];})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_reassignment():
    """F663 reassignment of the var: trailing statements fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "']]);o={};return o.a;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_multi_decl():
    """F663 multi-decl: fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "']]),p=1;return o.a;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_named_function():
    """F663 named function head: fail closed."""
    s = ("(function f(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_call_args():
    """F663 non-empty call args: fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "'],['b','" + _B + "']]);return o.a+o.b;})(1)")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_extra_statement():
    """F663 extra statement before return: fail closed."""
    s = ("(function(){var o=Object.fromEntries([['a','" + _A
         + "']]);var q=1;return o.a;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f663_plain_object_stays_open():
    """F663 source must be fromEntries: plain object is F671's shape (now CLOSED, wave-379 merge)."""
    s = ("(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};return o.a+o.b;})()")
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p3_f664_get_on_data():
    """F664 .get() on a data property: engine TypeError -- fail closed."""
    s = ("(function(){var o={x:'" + _A + "'};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_value_on_accessor():
    """F664 .value on an accessor: engine undefined -- fail closed."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').value+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_missing_key():
    """F664 missing key: engine TypeError -- fail closed."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'y').get()+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_get_with_args():
    """F664 .get('a') with args: fail closed (F549 parity)."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get('a')+'" + _B
         + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_bracket_terminal():
    """F664 ['get']() bracket terminal: fail closed (F549 parity)."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x')['get']()+'" + _B
         + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_computed_key():
    """F664 computed key: fail closed."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};var k='x';"
         + "return Object.getOwnPropertyDescriptor(o,k).get()+'" + _B
         + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_this_getter():
    """F664 this-dependent getter body: fail closed."""
    s = ("(function(){var o={get x(){return this.y;}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_nonstring_getter():
    """F664 non-string getter value: fail closed, never mis-decoded."""
    s = ("(function(){var o={get x(){return {a:1};}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'" + _B + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_wrong_target():
    """F664 descriptor target other than the bound ident: fail closed."""
    s = ("(function(){var o={get x(){return '" + _A + "';}};var p={};"
         + "return Object.getOwnPropertyDescriptor(p,'x').get()+'" + _B
         + "';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f664_member_read_term():
    """F664 o.y member-read term is not in the term grammar: fail closed."""
    s = ("(function(){var o={get x(){return '" + _A
         + "';},y:'" + _B + "'};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+o.y;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------ p4: open neighbors still miss


@_t
def test_p4_f662_still_open():
    """F662 now CLOSED (wave-379 merge): class static field blocks."""
    s = "(function(){class C{static x='%s';}return C.x+'%s';})()" % (_A, _B)
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f665_still_open():
    """F665 now CLOSED (wave-379 merge): ?. member read blocks."""
    s = "({x:'%s'})?.x+'%s'" % (_A, _B)
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f666_still_open():
    """F666 now CLOSED (wave-379 merge): Proxy apply trap blocks."""
    s = ("(function(){var p=new Proxy(function(){},{apply:function()"
         + "{return '%s';}});return p()+'%s';})()") % (_A, _B)
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f667_still_open():
    """F667 now CLOSED (wave-379 merge): with-scope reads block."""
    s = ("(function(){var o={x:'%s',y:'%s'};with(o){return x+y;}})()"
         % (_A, _B))
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f668_still_open():
    """F668 now CLOSED (wave-379 merge): tag-function template blocks."""
    s = ("(function(){function tag(s){return s[0]+'%s';}return tag`%s`;})()"
         % (_B, _A))
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f669_still_open():
    """F669 now CLOSED (wave-379 merge): iterable spread blocks."""
    s = ("(function(){var st=new Set(['%s','%s']);return [...st].join('');})()"
         % (_A, _B))
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f670_still_open():
    """F670 now CLOSED (wave-379 merge): get-trap block-body blocks."""
    s = ("(function(){var a='%s',b='%s';var p=new Proxy({},"
         + "{get:(t,k)=>{return a+b;}});return p.anything;})()") % (_A, _B)
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_p4_f671_still_open():
    """F671 now CLOSED (wave-379 merge): return-position reads block."""
    s = ("(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B))
    blocked = _blocked(s)
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


# ------------------------------------------------ p5: closed neighbors still held


@_t
def test_p5_f565_still_held():
    """F565 (CLOSED): Object.values of fromEntries still blocks."""
    s = ("(function(){return Object.values(Object.fromEntries([['a','%s'],"
         + "['b','%s']])).join('');})()") % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


@_t
def test_p5_f549_still_held():
    """F549 (CLOSED): literal-target descriptor .get() still blocks."""
    s = ("Object.getOwnPropertyDescriptor({get x(){return '%s';}},'x')"
         + ".get()+'%s'") % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


@_t
def test_p5_f649_still_held():
    """F649 (CLOSED): structuredClone var-bound member reads still block."""
    s = ("(function(){var o=structuredClone({a:'%s',b:'%s'});"
         + "return o.a+o.b;})()") % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


@_t
def test_p5_f535_still_held():
    """F535 (CLOSED): direct member reads still block."""
    s = "({a:'%s'}).a+'%s'" % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


@_t
def test_p5_f510_still_held():
    """F510 (CLOSED): Object.values on plain objects still blocks."""
    s = "Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


@_t
def test_p5_f664_value_on_data_route():
    """Existing route: var-bound .value on data prop still blocks."""
    s = ("(function(){var o={x:'%s%s'};return "
         + "Object.getOwnPropertyDescriptor(o,'x').value;})()") % (_A, _B)
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


# ------------------------------------------------ p6: junk quiet, composition


@_t
def test_p6_junk_f663_quiet():
    """Junk through the F663 shape stays quiet."""
    s = ("(function(){var o=Object.fromEntries([['a','x'],['b','y']]);"
         + "return o.a+o.b;})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "quiet=%s" % miss)


@_t
def test_p6_junk_f664_quiet():
    """Junk through the F664 shape stays quiet."""
    s = ("(function(){var o={get x(){return 'x';}};return "
         + "Object.getOwnPropertyDescriptor(o,'x').get()+'y';})()")
    miss = _misses(s)
    return ("HELD" if miss else "BREAK", "quiet=%s" % miss)


# ------------------------------------------------ p7: pin, footer, no new regexes


@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (open F662, F665-F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F738**" in text)  # Wave-379 lane 2: F663, F664 CLOSED; open F662, F665-F671 / next F672
    ok = ok and ("Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." in text)  # Wave-379 lane 2: F663, F664 CLOSED; open F662, F665-F671 / next F672
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
    """200 mixed F663/F664 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var o=Object.fromEntries([['a','x%d']]);"
                      "return o.a;})()" % k)
        corpus.append("(function(){var o={get x(){return 'x%d';}};return "
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
    for batt, expect_break in (("evals/w378_f663_redfirst.py", 0),
                               ("evals/w378_f664_redfirst.py", 0),
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
def test_p9_green_check():
    """Depth-1 green check: F663/F664 red-firsts + wave-378 attack battery."""
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
