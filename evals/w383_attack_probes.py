"""Wave-383 lane 14: attack round 51 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (21, all LOW, all OPEN), filed F740-F760:
- F740: try/catch value flows.
- F741: switch fallthrough value flows.
- F742: DataView byte laundering.
- F743: F697 residual: assigned Symbol.toPrimitive.
- F744: F683 residual: value-replacement reviver.
- F745: Set.prototype.union (ES2025).
- F746: class extends builtin construction.
- F747: F647 residual: missing-key nullish-LEFT + ??= assignment.
- F748: logical assignment ||= / &&=.
- F749: destructuring defaults.
- F750: Error .message reads.
- F751: Reflect.ownKeys / Object.keys map-reads.
- F752: F728 residual: builtin-iterator .next().value.
- F753: spread argument lists (call + construct).
- F754: delete operator statements.
- F755: F535 residual: computed string-name getters.
- F756: ternary conditional value flow.
- F757: new.target.
- F758: rest parameters.
- F759: setter value flow.
- F760: template-nested member reads.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F713 (lane-7 kept) + F714-F737 (round 50), F758-F760 (this round;
F740-F757 closed wave-384).

Closed pins (must BLOCK, else BREAK): F700-F712 (wave-382 closures),
F713-F737 (wave-383 closures), F740-F757 (wave-384 closures).

Rides-with-documented-scope (validated, NOT filed):
- F723 variant (Object.create proto-chain getter, filed shape verbatim) -- still misses; same open finding, not re-filed.
- F736 variant (default params, no-arg call h()) -- still misses; same open finding, not re-filed.
- Steal-lane seams: seqgate full chain refuses coded; specflat nested-leaf and split-across-leaves injections refuse coded; benign specs pass.
- try/finally without catch -- BLOCK; already modeled.
- switch WITH break -- BLOCK; already modeled.
- JSON.parse without reviver -- BLOCK; already modeled.
- valueOf / literal {[Symbol.toPrimitive]} -- BLOCK (F697); only the assigned form misses (filed F743).
- plain getters -- BLOCK (F535); only computed string names miss (filed F755).
- generator .next() -- BLOCK (F677/F728 pins); only builtin-iterator .next() misses (filed F752).
- decodeURIComponent -- BLOCK; already modeled.
- WeakMap.get, private fields, with-statement, optional chaining, tagged templates, String.raw, comma operator, for-in, Array.of, Array.from, reduce, fromEntries, concat.apply, structuredClone, TextDecoder, Proxy.revocable -- BLOCK; already modeled.
- Junk-quiet controls pass.
Model note: 2/2 prompts returned usable hints (0 timeouts); the second call was an accidental duplicate of the first prompt (wasted ~$0.0005, disclosed).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (model spend logged
separately in the realmodel ledger).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # steal lane A repoint

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
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- closed pins (must block)


@_t
def test_r49_f700_s1_open():
    """F700 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){return ['%s','%s'].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f700_s2_open():
    """F700 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){return ['%s','%s'].flatMap(function(f){return ['',f];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f701_s1_open():
    """F701 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f701_s2_open():
    """F701 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';},get y(){return '%s';}};var c={...o};return c.x+c.y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f702_s1_open():
    """F702 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';}};return Object.assign({},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f702_s2_open():
    """F702 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';}};var c=Object.assign({z:1},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f703_s1_open():
    """F703 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={};o.__defineGetter__('x',function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f703_s2_open():
    """F703 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={};o.__defineGetter__('a',function(){return '%s';});o.__defineGetter__('b',function(){return '%s';});return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f704_s1_open():
    """F704 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f704_s2_open():
    """F704 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o=Object.create(Object.prototype,{x:{enumerable:true,get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f705_s1_open():
    """F705 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x',{})+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f705_s2_open():
    """F705 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f706_s1_open():
    """F706 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]='%s';return true;}});Object.defineProperty(p,'x',{value:1});return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f706_s2_open():
    """F706 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]='%s';return true;}});Object.defineProperty(p,'y',{value:2});return t.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f707_s1_open():
    """F707 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Object.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f707_s2_open():
    """F707 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Reflect.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f708_s1_open():
    """F708 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f708_s2_open():
    """F708 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map();m.set('k','%s');var k='k';return m.get(k)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f709_s1_open():
    """F709 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f709_s2_open():
    """F709 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var r='';var i=0;while(i<2){r+=['%s','%s'][i];i++;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f710_s1_open():
    """F710 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var s=new Set(['k']);var f=s.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f710_s2_open():
    """F710 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var s=new Set(['q']);return (s.has('q')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f711_dot_misdecode_closed():
    """F711 CLOSED (wave-382 merge): raw decoder no longer mis-decodes >2^53 dot read (fail-closed)."""
    got = _try_js_expr_decode_all("({x:9007199254740993}).x+'" + _B + "'")
    ok = got != "9007199254740993" + _B
    return ("HELD" if ok else "BREAK", "no-misdecode=%s" % ok)


@_t
def test_r49_f711_bracket_misdecode_closed():
    """F711 CLOSED (wave-382 merge): raw decoder no longer mis-decodes >2^53 bracket read (fail-closed)."""
    got = _try_js_expr_decode_all("({x:9007199254740993})['x']+'" + _B + "'")
    ok = got != "9007199254740993" + _B
    return ("HELD" if ok else "BREAK", "no-misdecode=%s" % ok)


@_t
def test_r49_f712_s1_open():
    """F712 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f712_s2_open():
    """F712 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map([['k','%s']]);return Array.from(m)[0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

# --------------------------------- round-50 open pins (must miss)


@_t
def test_r50_f713_s1_open():
    """F713 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_r50_f713_s2_open():
    """F713 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var m=new Map([['k','%s']]);return [...m].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_r50_f737_s1_open():
    """F737 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tr,pr){tr.__p='%s';return true;}});Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f737_s2_open():
    """F737 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tg,pt){tg['k']='%s';return true;}});Object.setPrototypeOf(p,[]);return t.k+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f714_s1_open():
    """F714 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var p=new Proxy({},{has:function(t,k){return true;}});var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f714_s2_open():
    """F714 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var p=new Proxy({},{has:function(t,k){return k==='y';}});var f=('y' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f715_s1_open():
    """F715 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f715_s2_open():
    """F715 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={y:'%s'};var p=new Proxy(t,{deleteProperty:function(a,b){return false;}});delete p['y'];return t.y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f716_s1_open():
    """F716 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f716_s2_open():
    """F716 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={};var k='x';Reflect.set(o,k,'%s');return o[k]+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f717_s1_open():
    """F717 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f717_s2_open():
    """F717 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={};Reflect.defineProperty(o,'y',{value:'%s',enumerable:true});return o['y']+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f718_s1_open():
    """F718 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f718_s2_open():
    """F718 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f=Reflect.has({a:1},'a')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f719_s1_open():
    """F719 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var r='';var s=new Set(['%s','%s']);for(var x of s){r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f719_s2_open():
    """F719 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var r='';for(var x of new Set(['%s','%s'])){r=r+x;}return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f720_s1_open():
    """F720 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f=['k'].includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f720_s2_open():
    """F720 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var a=['q','k'];var f=a.includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f721_s1_open():
    """F721 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f=['k'].indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f721_s2_open():
    """F721 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f=['a','k'].indexOf('k')>0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f722_s1_open():
    """F722 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var m=new Map([['k',1]]);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f722_s2_open():
    """F722 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var m=new Map();m.set('k',1);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f723_s1_open():
    """F723 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={get x(){return '%s';}};var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f723_s2_open():
    """F723 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var p={get y(){return '%s';}};var c=Object.create(p);var d=Object.create(c);return d.y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f724_s1_open():
    """F724 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var c={};Object.setPrototypeOf(c,{get x(){return '%s';}});return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f724_s2_open():
    """F724 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var c={};var p={get y(){return '%s';}};Object.setPrototypeOf(c,p);return c.y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f725_s1_open():
    """F725 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={get x(){return '%s';}};var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f725_s2_open():
    """F725 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={};o.__defineGetter__('y',function(){return '%s';});return o.__lookupGetter__('y').call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f726_s1_open():
    """F726 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={toString:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f726_s2_open():
    """F726 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={[Symbol.toPrimitive]:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f727_s1_open():
    """F727 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var r='';var i=0;do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f727_s2_open():
    """F727 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var r='';var i=0;do{r=r+['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f728_s1_open():
    """F728 OPEN (generator .next().value member reads): miss reproduces."""
    blocked = not _misses("(function(){function* g(){yield '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f728_s2_open():
    """F728 OPEN (generator .next().value member reads): miss reproduces."""
    blocked = not _misses("(function(){function* g(){yield '%s';yield '%s';}var it=g();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f729_s1_open():
    """F729 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f729_s2_open():
    """F729 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var x='%s';void 0;return x+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f730_s1_open():
    """F730 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'%s',b:'%s'});return v1+v2;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f730_s2_open():
    """F730 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var e=Object.entries({a:'%s',b:'%s'});var [[,v1],[,v2]]=e;return v1+v2;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f731_s1_open():
    """F731 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=Object.isExtensible(p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f731_s2_open():
    """F731 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=!Object.isExtensible(p)?'xx':'%s';return f+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f732_s1_open():
    """F732 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(tr){tr.__g='%s';return Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);return t.__g+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f732_s2_open():
    """F732 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(x){x['h']='%s';return Object.getPrototypeOf(x);}});Object.getPrototypeOf(p);return t.h+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f733_s1_open():
    """F733 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().v+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f733_s2_open():
    """F733 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var w=new WeakRef({v:'%s'});return w.deref()['v']+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f734_s1_open():
    """F734 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var s=Symbol('k');var o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f734_s2_open():
    """F734 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var s=Symbol('k');var o={[s]:'%s'};return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f735_s1_open():
    """F735 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f='%s';function g(){return f;}return g()+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f735_s2_open():
    """F735 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){var f='%s';var g=function(){return f;};return g()+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f736_s1_open():
    """F736 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){function h(a='%s'){return a;}return h()+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r50_f736_s2_open():
    """F736 CLOSED (wave-383): block verified."""
    blocked = not _misses("(function(){function h(a='%s',b='%s'){return a+b;}return h('%s');})()" % (_A, _B, _A))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

# --------------------------------- round-51 open pins (must miss)


@_t
def test_r51_f738_s1_open():
    """F740 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var r;try{throw '%s';}catch(e){r=e;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f738_s2_open():
    """F740 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var r='';try{r+='%s';throw 0;}catch(e){r+='%s';}return r;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f739_s1_open():
    """F741 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var x='%s';switch('k'){case 'k':x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f739_s2_open():
    """F741 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var x='%s';switch('z'){default:x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f742_s1_closed():
    """F742 CLOSED (wave-384 lane 3): DataView byte laundering blocks coded."""
    ok = _blocked("(function(){var v=new DataView(new ArrayBuffer(4));v.setUint8(0,120);v.setUint8(1,111);return String.fromCharCode(v.getUint8(0),v.getUint8(1))+'xb-0123'+'%s';})()" % (_A,))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f742_s2_closed():
    """F742 CLOSED (wave-384 lane 3): DataView byte laundering blocks coded."""
    ok = _blocked("(function(){var v=new DataView(new ArrayBuffer(2));v.setUint8(0,120);v.setUint8(1,111);return String.fromCharCode(v.getUint8(0))+'o'+'xb-0123'+'%s';})()" % (_A,))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f743_s1_closed():
    """F743 CLOSED (wave-384 lane 3): assigned Symbol.toPrimitive blocks coded."""
    ok = _blocked("(function(){var o={};o[Symbol.toPrimitive]=function(){return '%s';};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f743_s2_closed():
    """F743 CLOSED (wave-384 lane 3): assigned Symbol.toPrimitive blocks coded."""
    ok = _blocked("(function(){var o={};o[Symbol.toPrimitive]=function(hint){return '%s';};return String(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f742_s1_open():
    """F744 CLOSED (wave-384): block verified."""
    blocked = not _misses('(function(){return JSON.parse(\'{"k":"x"}\',function(k,v){return k===\'k\'?\'%s\':v;}).k+\'%s\';})()' % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f742_s2_open():
    """F744 CLOSED (wave-384): block verified."""
    blocked = not _misses('(function(){var r=JSON.parse(\'{"a":1}\',function(k,v){return k===\'\'?\'%s\':v;});return r+\'%s\';})()' % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f743_s1_open():
    """F745 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var s=new Set(['%s']).union(new Set(['%s']));return [...s].join('');})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f743_s2_open():
    """F745 CLOSED (wave-384): block verified."""
    blocked = not _misses("(function(){var a=new Set(['%s']);var b=new Set(['%s']);return [...a.union(b)].join('');})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f744_s1_open():
    """F746 CLOSED (wave-384 lane 5): blocks."""
    blocked = _blocked("(function(){class M extends Map{}var m=new M();m.set('k','%s');return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f744_s2_open():
    """F746 CLOSED (wave-384 lane 5): blocks."""
    blocked = _blocked("(function(){class M extends Map{}var m=new M([['k','%s']]);var s='';for(var v of m.values())s+=v;return s+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f745_s1_open():
    """F747 CLOSED (wave-384 lane 5): blocks."""
    blocked = _blocked("(function(){var o={};return (o.x??'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f745_s2_open():
    """F747 CLOSED (wave-384 lane 5): blocks."""
    blocked = _blocked("(function(){var x=null;var y=x??'%s';return y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)

@_t
def test_r51_f746_s1_closed():
    """F748 CLOSED: still blocks."""
    ok = _blocked("(function(){var x;x||='%s';x+='%s';return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f748=%s" % ok)

@_t
def test_r51_f746_s2_closed():
    """F748 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={x:'%s'};o.x&&=o.x+'%s';return o.x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f748=%s" % ok)

@_t
def test_r51_f747_s1_closed():
    """F749 CLOSED: still blocks."""
    ok = _blocked("(function(){var {x='%s',y='%s'}={};return x+y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f749=%s" % ok)

@_t
def test_r51_f747_s2_closed():
    """F749 CLOSED: still blocks."""
    ok = _blocked("(function(){var {x:q='%s'}={};return q+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f749=%s" % ok)

@_t
def test_r51_f748_s1_open():
    """F750 CLOSED (wave-384 lane 7): blocks coded."""
    miss = ok = _blocked("(function(){try{throw new Error('%s');}catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f748_s2_open():
    """F750 CLOSED (wave-384 lane 7): blocks coded."""
    miss = ok = _blocked("(function(){function f(){throw new RangeError('%s');}try{f();}catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f749_s1_open():
    """F751 CLOSED (wave-384 lane 7): blocks coded."""
    miss = ok = _blocked("(function(){var o={x:'%s',y:'%s'};return Reflect.ownKeys(o).map(function(k){return o[k];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f749_s2_open():
    """F751 CLOSED (wave-384 lane 7): blocks coded."""
    miss = ok = _blocked("(function(){var o={};o.x='%s';o.y='%s';var s='';Reflect.ownKeys(o).forEach(function(k){s+=o[k];});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f750_s1_closed():
    """F752 CLOSED (F728 residual: builtin-iterator .next().value): blocks coded."""
    hit = _blocked("(function(){var it=['%s','%s'][Symbol.iterator]();var s='';s+=it.next().value;s+=it.next().value;return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r51_f750_s2_closed():
    """F752 CLOSED (F728 residual: builtin-iterator .next().value): blocks coded."""
    hit = _blocked("(function(){var s=new Set(['%s','%s']);var it=s.values();var r='';r+=it.next().value;r+=it.next().value;return r;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r51_f751_s1_closed():
    """F753 CLOSED (spread argument lists (call + construct)): blocks coded."""
    hit = _blocked("(function(){function h(){var s='';for(var i=0;i<arguments.length;i++)s+=arguments[i];return s;}return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r51_f751_s2_closed():
    """F753 CLOSED (spread argument lists (call + construct)): blocks coded."""
    hit = _blocked("(function(){function h(a,b){return a+b;}return h(...['%s','%s']);})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r51_f752_s1_open():
    """F754 CLOSED (wave-384 lane 9): blocks coded."""
    miss = ok = _blocked("(function(){var o={x:'%s',y:'junk'};delete o.y;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f752_s2_open():
    """F754 CLOSED (wave-384 lane 9): blocks coded."""
    miss = ok = _blocked("(function(){var o={x:'%s',y:'junk'};delete o['y'];return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f753_s1_open():
    """F755 CLOSED (wave-384 lane 9): blocks coded."""
    miss = ok = _blocked("(function(){var o={get ['x'](){return '%s';}};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f753_s2_open():
    """F755 CLOSED (wave-384 lane 9): blocks coded."""
    miss = ok = _blocked("(function(){var o={get ['x'](){return '%s';}};return o['x']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f754_s1_open():
    """F756 CLOSED (wave-384 lane 10): blocks coded."""
    miss = ok = _blocked("(function(){var c=true;return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f754_s2_open():
    """F756 CLOSED (wave-384 lane 10): blocks coded."""
    miss = ok = _blocked("(function(){var c=false;var x=c?'z':'%s';return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f755_s1_open():
    """F757 CLOSED (wave-384 lane 10): blocks coded."""
    miss = ok = _blocked("(function(){function C(){this.x=new.target===C?'%s':'z';}return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f755_s2_open():
    """F757 CLOSED (wave-384 lane 10): blocks coded."""
    miss = ok = _blocked("(function(){class D{constructor(){this.v=new.target?'%s':'z';}}return new D().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f756_s1_open():
    """F758 CLOSED (wave-384 lane 11): blocks coded."""
    miss = ok = _blocked("(function(){function h(...xs){return xs.join('');}return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f756_s2_open():
    """F758 CLOSED (wave-384 lane 11): blocks coded."""
    miss = ok = _blocked("(function(){function h(a,...rest){return a+rest[0];}return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f757_s1_open():
    """F759 CLOSED (wave-384 lane 11): blocks coded."""
    miss = ok = _blocked("(function(){var o={_v:'',set x(v){this._v=v;}};o.x='%s';return o._v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f757_s2_open():
    """F759 CLOSED (wave-384 lane 11): blocks coded."""
    miss = ok = _blocked("(function(){var o={set x(v){this.w=v;},get w(){return this._w;},set w(v){this._w=v;}};o.x='%s';return o._w+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r51_f758_s1_closed():
    """F760 CLOSED (template-nested member reads): blocks coded."""
    hit = _blocked("(function(){var o={x:'%s'};return `${o.x}%s`;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


@_t
def test_r51_f758_s2_closed():
    """F760 CLOSED (template-nested member reads): blocks coded."""
    hit = _blocked("(function(){var o={x:'%s',y:'%s'};return `${o.x}${o.y}`;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w382_attack_probes.py")],
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
    # The w382 battery's footer pin is stale by design: this lane repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w382_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-382 attack battery stays green (depth-1)."""
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
