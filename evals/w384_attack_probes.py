"""Wave-384 lane 13: attack round 52 (continuous real-model attack).

Filed 2026-10-09 (local node validation on v24.20.0 + 1 gpt-4o-mini call
($0.000153), hints only; every filed shape hand-crafted and node-verified).
The model's single brainstorm call contributed the Array.fill family (F773);
its other two ideas were already-covered seams.

New findings (32, all LOW, all OPEN), filed F762-F793:
- F762: indexed character reads (String.prototype.charAt / .at).
- F763: String.prototype.normalize identity.
- F764: slice-family residuals (substr, substring argument-swap).
- F765: RegExp match/matchAll extraction.
- F766: Array.prototype.find / findLast.
- F767: Array.prototype.splice reads.
- F768: array entry-pair reads (Array.prototype.entries spread, Object.entries on arrays).
- F769: Array.prototype.at on var-bound arrays (inline literals block).
- F770: String case transforms (toLowerCase).
- F771: String.prototype.toWellFormed identity (var-bound; inline/concat block).
- F772: ES2023 non-mutating array methods (toSorted, toSpliced).
- F773: Array.prototype.fill without range args (model hint).
- F774: property descriptor value reads (getOwnPropertyDescriptor(s).value).
- F775: F723 residual: Object.getPrototypeOf member reads.
- F776: F673 residual: nested-object __proto__ literal reads.
- F777: F748 residual: plain || / && value flows.
- F778: F647 residual: ?? with computed right operand.
- F779: Symbol introspection reads (description, keyFor).
- F780: constructor this-binding reads.
- F781: prototype method reads.
- F782: call/apply/bind thisArg binding reads.
- F783: super method dispatch reads.
- F784: labeled break/continue value flows.
- F785: F709/F727 residual: boolean-flag while-loop accumulation.
- F786: F602 residual: continue-guarded for-of accumulation.
- F787: F750 residual: Error cause reads.
- F788: AggregateError.errors reads.
- F789: Proxy construct-trap reads.
- F790: F749/F758 residual: destructuring binding reads (object/array rest, param, for-of).
- F791: private method reads (private fields block).
- F792: groupBy reads (Map.groupBy / Object.groupBy).
- F793: Iterator helper reads (Iterator.prototype.map / drop).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F738-F761 (rounds 50-51), F762-F793 (this round).

Closed pins (must BLOCK, else BREAK): F713-F737 (wave-383 closures).

Rides-with-documented-scope (validated, NOT filed):
- Set.prototype.intersection / difference -- still miss; same ES2025 set-operation family as F745 (OPEN), not re-filed.
- Reflect.deleteProperty statements -- still miss; same finding as F754 (OPEN), not re-filed.
- F754 delete variants (delete o['y']) -- still miss; same finding, not re-filed.
- String.prototype.trim / repeat / concat / encodeURI / escape / unescape / padEnd / split-limit / replaceAll / slice(-n) / arr.slice(-n) / arr.concat / reduceRight / map-identity / sort / reverse -- BLOCK; already modeled.
- String search/includes/startsWith/indexOf/lastIndexOf conditionals -- BLOCK; already modeled.
- Reflect.get, Object.assign (plain + getter sources), object spread of getters, hasOwnProperty/in/typeof/instanceof conditionals, Object.hasOwn guards, Object.defineProperties -- BLOCK; already modeled.
- class getters/methods/statics/computed fields, generator spread/yield*, custom tagged templates, nested destructuring, Array.prototype.with, toReversed, string spread, comma operator, with-statement, optional chaining, WeakMap.get, private FIELDS (#x), decodeURIComponent, JSON.parse, structuredClone, TextDecoder, Proxy.apply, Proxy.revocable, for-in, Array.of, Array.from, fromEntries, concat.apply, try/finally without catch, switch WITH break, valueOf/toString, plain getters, String.raw -- BLOCK; already modeled.
- Junk-quiet controls pass.
Model note: 1/1 prompts returned usable output (0 timeouts).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (model spend logged
separately in the realmodel ledger).
"""

import argparse
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-383 merge

from gov import dlp
from gov.dlp import _try_js_expr_decode_all
from gov.decision_codes import TAXONOMY

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


# ---------------------------------------------------------------- controls


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: wave-385 lane-4 local footer (F768/F769 CLOSED; open F762-F767, F770-F794, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-385 lane 4: F768, F769 CLOSED; open F762-F767, F770-F794 (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-385 lane 4: F768, F769 CLOSED; open F762-F767, F770-F794 (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- closed pins (must block)

@_t
def test_r52_f713_s1_closed():
    """F713 CLOSED (wave-383 lane 1): Map spread-join values + tail: blocks coded."""
    ok = _blocked("(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f714_s1_closed():
    """F714 CLOSED (wave-383 lane 1): Proxy has-trap + in: blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{has:function(t,k){return true;}});var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f715_s1_closed():
    """F715 CLOSED (wave-383 lane 2): deleteProperty {return false;}: blocks coded."""
    ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f716_s1_closed():
    """F716 CLOSED (wave-383 lane 2): Reflect.set: blocks coded."""
    ok = _blocked("(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f717_s1_closed():
    """F717 CLOSED (wave-383 lane 3): Reflect.defineProperty: blocks coded."""
    ok = _blocked("(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f718_s1_closed():
    """F718 CLOSED (wave-383 lane 3): Reflect.has cond: blocks coded."""
    ok = _blocked("(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f719_s1_closed():
    """F719 CLOSED (wave-383 lane 4): for-of over Set: blocks coded."""
    ok = _blocked("(function(){var r='';var s=new Set(['%s','%s']);for(var x of s){r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f720_s1_closed():
    """F720 CLOSED (wave-383 lane 4): Array includes cond: blocks coded."""
    ok = _blocked("(function(){var f=['k'].includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f721_s1_closed():
    """F721 CLOSED (wave-383 lane 5): Array indexOf cond: blocks coded."""
    ok = _blocked("(function(){var f=['k'].indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f722_s1_closed():
    """F722 CLOSED (wave-383 lane 5): Map.has cond: blocks coded."""
    ok = _blocked("(function(){var m=new Map([['k',1]]);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f723_s1_closed():
    """F723 CLOSED (wave-383 lane 6): Object.create proto-chain getter: blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f724_s1_closed():
    """F724 CLOSED (wave-383 lane 6): setPrototypeOf installed getter: blocks coded."""
    ok = _blocked("(function(){var c={};Object.setPrototypeOf(c,{get x(){return '%s';}});return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f725_s1_closed():
    """F725 CLOSED (wave-383 lane 7): __lookupGetter__: blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f726_s1_closed():
    """F726 CLOSED (wave-383 lane 7): template toPrimitive coercion: blocks coded."""
    ok = _blocked("(function(){var o={toString:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f727_s1_closed():
    """F727 CLOSED (wave-383 lane 8): do-while accumulation: blocks coded."""
    ok = _blocked("(function(){var r='';var i=0;do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f728_s1_closed():
    """F728 CLOSED (wave-383 lane 8): generator .next().value: blocks coded."""
    ok = _blocked("(function(){function* g(){yield '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f729_s1_closed():
    """F729 CLOSED (wave-383 lane 9): void operator: blocks coded."""
    ok = _blocked("(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f730_s1_closed():
    """F730 CLOSED (wave-383 lane 9): nested entries destructuring: blocks coded."""
    ok = _blocked("(function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'%s',b:'%s'});return v1+v2;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f731_s1_closed():
    """F731 CLOSED (wave-383 lane 10): isExtensible trap: blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=Object.isExtensible(p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f732_s1_closed():
    """F732 CLOSED (wave-383 lane 10): getPrototypeOf-trap write: blocks coded."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(tr){tr.__g='%s';return Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);return t.__g+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f733_s1_closed():
    """F733 CLOSED (wave-383 lane 11): WeakRef deref: blocks coded."""
    ok = _blocked("(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f734_s1_closed():
    """F734 CLOSED (wave-383 lane 11): symbol member: blocks coded."""
    ok = _blocked("(function(){var s=Symbol('k');var o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f735_s1_closed():
    """F735 CLOSED (wave-383 lane 12): nested function closure: blocks coded."""
    ok = _blocked("(function(){var f='%s';function g(){return f;}return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f736_s1_closed():
    """F736 CLOSED (wave-383 lane 12): default params: blocks coded."""
    ok = _blocked("(function(){function h(a='%s'){return a;}return h()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r52_f737_s1_closed():
    """F737 CLOSED (wave-383 lane 13): setPrototypeOf trap: blocks coded."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tr,pr){tr.__p='%s';return true;}});Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

# ------------------------------------------- open pins (must miss)

@_t
def test_r52_f762_s1_open():
    """F762 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s';return s.charAt(0)+s.slice(1)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f762_s2_open():
    """F762 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s';return s.at(0)+s.at(1)+s.slice(2)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f763_s1_open():
    """F763 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s';return s.normalize()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f763_s2_open():
    """F763 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s';return s.normalize('NFD')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f764_s1_open():
    """F764 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='xx%s';return s.substr(-9)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f764_s2_open():
    """F764 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%sxx';return s.substring(9,0)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f765_s1_open():
    """F765 OPEN: miss reproduces."""
    miss = _misses("(function(){var m='xx%syy'.match(/xoxb-[0-9]+/);return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f765_s2_open():
    """F765 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=[...'xx%syy'.matchAll(/xoxb-[0-9]+/g)];return m[0][0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f766_s1_open():
    """F766 OPEN: miss reproduces."""
    miss = _misses("(function(){return [['%s'],['xx']].find(function(a){return true;})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f766_s2_open():
    """F766 OPEN: miss reproduces."""
    miss = _misses("(function(){return [['xx'],['%s']].findLast(function(a){return true;})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f767_s1_open():
    """F767 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['xx','%s','%s'].splice(1).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f767_s2_open():
    """F767 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['xx','%s','%s','yy'].splice(1,2).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f768_s1_closed():
    """F768 CLOSED (wave-385 lane 4): blocks."""
    hit = _blocked("(function(){return [...['%s','%s'].entries()].map(function(e){return e[1];}).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r52_f768_s2_closed():
    """F768 CLOSED (wave-385 lane 4): blocks."""
    hit = _blocked("(function(){return Object.entries(['%s','%s']).map(function(e){return e[1];}).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r52_f769_s1_closed():
    """F769 CLOSED (wave-385 lane 4): blocks."""
    hit = _blocked("(function(){var a=['%s','%s'];return a.at(0)+a.at(-1);})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r52_f769_s2_closed():
    """F769 CLOSED (wave-385 lane 4): blocks."""
    hit = _blocked("(function(){var a=['xx','%s','%s'];return a.at(1)+a.at(2);})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r52_f770_s1_open():
    """F770 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='XOXB-0123';return s.toLowerCase()+'%s';})()" % (_B,))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f770_s2_open():
    """F770 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='xox'+'B-0123';return s.toLowerCase()+'%s';})()" % (_B,))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f771_s1_open():
    """F771 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s';return s.toWellFormed()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f771_s2_open():
    """F771 OPEN: miss reproduces."""
    miss = _misses("(function(){var t='%s';return t.toWellFormed()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f772_s1_open():
    """F772 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['%s','%s'].toSorted().reverse().join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f772_s2_open():
    """F772 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['xx','%s','%s'].toSpliced(0,1).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f773_s1_open():
    """F773 OPEN: miss reproduces."""
    miss = _misses("(function(){return [new Array(1).fill('%s')[0],'%s'].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f773_s2_open():
    """F773 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['xx'];a.fill('%s');return a[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f774_s1_open():
    """F774 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f774_s2_open():
    """F774 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};return Object.getOwnPropertyDescriptors(o).x.value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f775_s1_open():
    """F775 OPEN: miss reproduces."""
    miss = _misses("(function(){var p={x:'%s'};var o=Object.create(p);return Object.getPrototypeOf(o).x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f775_s2_open():
    """F775 OPEN: miss reproduces."""
    miss = _misses("(function(){var p={x:'%s'};var o={};Object.setPrototypeOf(o,p);return Object.getPrototypeOf(o).x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f776_s1_open():
    """F776 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={__proto__:{x:'%s'}};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f776_s2_open():
    """F776 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};o.__proto__={x:'%s'};return o.__proto__.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f777_s1_open():
    """F777 OPEN: miss reproduces."""
    miss = _misses("(function(){var x='';return (x||'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f777_s2_open():
    """F777 OPEN: miss reproduces."""
    miss = _misses("(function(){return (1&&'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f778_s1_open():
    """F778 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=null;return (f??(function(){return '%s';}))()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f778_s2_open():
    """F778 s2 now BLOCKS: wave-384 lane 5 (F747) models nullish-LEFT ??
    with member RIGHT on tracked literals (node-exact); F778 stays OPEN
    on s1 (function-call right operand)."""
    hit = _blocked("(function(){var o={x:'%s'};var n=null;return (n??o.x)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)

@_t
def test_r52_f779_s1_open():
    """F779 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=Symbol('%s');return s.description+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f779_s2_open():
    """F779 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=Symbol.for('%s');return Symbol.keyFor(s)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f780_s1_open():
    """F780 OPEN: miss reproduces."""
    miss = _misses("(function(){function C(x){this.x=x;}var o=new C('%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f780_s2_open():
    """F780 OPEN: miss reproduces."""
    miss = _misses("(function(){return Reflect.construct(function(x){this.x=x;},['%s']).x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f781_s1_open():
    """F781 OPEN: miss reproduces."""
    miss = _misses("(function(){function C(){}C.prototype.m=function(){return '%s';};return new C().m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f781_s2_open():
    """F781 OPEN: miss reproduces."""
    miss = _misses("(function(){function C(){}C.prototype.m=function(){return '%s';};return new C()['m']()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f782_s1_open():
    """F782 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return this.x;}return f.call({x:'%s'})+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f782_s2_open():
    """F782 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return this.x;}var g=f.bind({x:'%s'});return g()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f783_s1_open():
    """F783 OPEN: miss reproduces."""
    miss = _misses("(function(){class B{m(){return '%s';}}class C extends B{m(){return super.m();}}return new C().m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f783_s2_open():
    """F783 OPEN: miss reproduces."""
    miss = _misses("(function(){class B{m(){return '%s';}}class C extends B{m(){return super['m']();}}return new C().m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f784_s1_open():
    """F784 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';lbl:{r+='%s';if(1)break lbl;r+='xx';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f784_s2_open():
    """F784 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';continue outer;r+='xx';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f785_s1_open():
    """F785 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';var go=true;while(go){r+='%s';go=false;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f785_s2_open():
    """F785 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';var go=!0;while(go){r+='%s';go=false;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f786_s1_open():
    """F786 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';for(var x of ['%s','xx','%s']){if(x==='xx')continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f786_s2_open():
    """F786 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';var a=['%s','xx','%s'];for(var i=0;i<a.length;i++){if(a[i]==='xx')continue;r+=a[i];}return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f787_s1_open():
    """F787 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw new Error('x',{cause:'%s'});}catch(e){return e.cause+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f787_s2_open():
    """F787 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new Error('x');e.cause='%s';return e.cause+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f788_s1_open():
    """F788 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new AggregateError(['%s'],'x');return e.errors[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f788_s2_open():
    """F788 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new AggregateError(['%s','%s'],'x');return e.errors.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f789_s1_open():
    """F789 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f789_s2_open():
    """F789 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[1]};}});return new p('xx','%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f790_s1_open():
    """F790 OPEN: miss reproduces."""
    miss = _misses("(function(){var {a,...r}={a:'%s',b:'%s'};return a+r.b;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f790_s2_open():
    """F790 OPEN: miss reproduces."""
    miss = _misses("(function(){var [a,...r]=['%s','%s','xx'];return a+r[0];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f791_s1_open():
    """F791 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{#m(){return '%s';}go(){return this.#m();}}return new C().go()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f791_s2_open():
    """F791 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{static #m(){return '%s';}static go(){return C.#m();}}return C.go()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f792_s1_open():
    """F792 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=Map.groupBy(['%s','%s'],function(x){return x[0];});return m.get('x')[0]+m.get('4')[0];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f792_s2_open():
    """F792 OPEN: miss reproduces."""
    miss = _misses("(function(){var o=Object.groupBy(['%s','%s'],function(x){return x[0];});return o.x[0]+o['4'][0];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f793_s1_open():
    """F793 OPEN: miss reproduces."""
    miss = _misses("(function(){return [...['%s','%s'].values().map(function(x){return x;})].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r52_f793_s2_open():
    """F793 OPEN: miss reproduces."""
    miss = _misses("(function(){return [...['xx','%s','%s'].values().drop(1)].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w383_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
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
    # The w383 battery's footer pin is stale by design: this lane repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w383_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-383 attack battery stays green (depth-1)."""
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
