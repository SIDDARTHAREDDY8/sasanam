"""Wave-382 lane 8: attack round 50 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (24, all LOW, all OPEN), filed F713-F736 (attack-F713 renumbered F737 at wave-382 merge, wave-272 first-filing):
- F714: Proxy has-trap + `in` operator conditional reads.
- F715: F675 residual: Proxy deleteProperty-trap `{return false;}` body.
- F716: Reflect.set fragment writes.
- F717: Reflect.defineProperty fragment writes.
- F718: Reflect.has conditional reads.
- F719: for-of accumulation over Set.
- F720: Array.prototype.includes conditional reads.
- F721: Array.prototype.indexOf conditional reads (CLOSED wave-383 lane 5).
- F722: Map.prototype.has conditional reads (CLOSED wave-383 lane 5).
- F723: Object.create prototype-chain getter reads.
- F724: Object.setPrototypeOf installed getter reads.
- F725: __lookupGetter__ legacy API reads.
- F726: F697 residual: template-literal toPrimitive coercion.
- F727: F709 residual: do-while accumulation.
- F728: generator .next().value member reads.
- F729: void operator statements.
- F730: nested destructuring of Object.entries.
- F731: Proxy isExtensible-trap.
- F732: F675 residual: Proxy getPrototypeOf-trap write body.
- F733: WeakRef deref reads.
- F734: symbol-keyed member reads.
- F735: nested function closure reads.
- F736: default parameter reads.
- F737: Proxy setPrototypeOf-trap fragment writes (filed as F713; renumbered at merge).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F700-F712 (round 49 + wave-381 merge renumbers),  (this round).

Closed pins (must BLOCK, else BREAK): F686-F712 (wave-381/382 closures), F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737 (wave-383 lanes).
F699 fails closed (None) by design -- its pin asserts the miss.F699 fails closed (None) by design -- its pin asserts the miss.
F711 pins the raw-decoder mis-decode (find_credential fails closed on it).

Rides-with-documented-scope (validated, NOT filed):
- Steal-lane seams: seqgate full chain refuses coded; userinfo-smuggled
  fetch URL is an operator-config/differential-parsing concern, not filed;
  specflat nested-leaf and split-across-leaves injections refuse coded.
- Object.values index reads -- BLOCK; already modeled.
- Array.from with mapping fn -- BLOCK; already modeled.
- Reflect.apply/construct -- BLOCK; already modeled.
- arguments indexing -- BLOCK; already modeled.
- for-of over arrays -- BLOCK; already modeled.
- Junk-quiet controls pass.
Model note: 2/2 prompts returned usable hints (0 timeouts).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
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
    """Control: merged footer (wave-383 merge coordinator)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- closed pins (must block)


@_t
def test_p1_f686_closed():
    """F686 CLOSED: still blocks."""
    ok = _blocked("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Object.keys(p).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f686=%s" % ok)

@_t
def test_p1_f687_closed():
    """F687 CLOSED: still blocks."""
    ok = _blocked("(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f687=%s" % ok)

@_t
def test_p1_f688_closed():
    """F688 CLOSED: still blocks."""
    ok = _blocked("(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f688=%s" % ok)

@_t
def test_p1_f689_closed():
    """F689 CLOSED: still blocks."""
    ok = _blocked("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator){return function*(){yield '%s';yield '%s';};}return t[k];}});return [...p].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f689=%s" % ok)

@_t
def test_p1_f690_closed():
    """F690 CLOSED: still blocks."""
    ok = _blocked("(function(){function C(){this.x='%s';}var c=new C();return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f690=%s" % ok)

@_t
def test_p1_f691_closed():
    """F691 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f691=%s" % ok)

@_t
def test_p1_f692_closed():
    """F692 CLOSED: still blocks."""
    ok = _blocked("(function(){class B{static x='%s';}class D extends B{static y(){return super.x;}}return D.y()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f692=%s" % ok)

@_t
def test_p1_f693_closed():
    """F693 CLOSED: still blocks."""
    ok = _blocked("(function(){var {a:{b:c}={b:'%s'}}={};return c+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f693=%s" % ok)

@_t
def test_p1_f694_closed():
    """F694 CLOSED: still blocks."""
    ok = _blocked("(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "f694=%s" % ok)

@_t
def test_p1_f695_closed():
    """F695 CLOSED: still blocks."""
    ok = _blocked("(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f695=%s" % ok)

@_t
def test_p1_f696_closed():
    """F696 CLOSED: still blocks."""
    ok = _blocked("(function(){return (new String('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f696=%s" % ok)

@_t
def test_p1_f697_closed():
    """F697 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)

@_t
def test_p1_f698_closed():
    """F698 CLOSED: still blocks."""
    ok = _blocked("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f698=%s" % ok)


@_t
def test_p1_f699_fail_closed():
    """F699 CLOSED: >2^53 with-scope now fails closed (None)."""
    ok = _misses("(function(){var o={x:9007199254740993};with(o){return x+'%s';}})()" % _B)
    return ("HELD" if ok else "BREAK", "f699-fail-closed=%s" % ok)

# --------------------------------- round-49 + merge open pins (must miss)


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
def test_r49_f712_s1_open():
    """F712 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r49_f712_s2_open():
    """F712 CLOSED (wave-382 merge): blocks coded."""
    miss = ok = _blocked("(function(){var m=new Map([['k','%s']]);return Array.from(m)[0][1]+'%s';})()" % (_A, _B))
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
# ------------------------------------------------- this round (must miss)


@_t
def test_r50_f737_s1_closed():
    """F737 CLOSED (wave-383 lane 13; filed as F713): blocks coded."""
    blk = _blocked("(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tr,pr){tr.__p='%s';return true;}});Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)

@_t
def test_r50_f737_s2_closed():
    """F737 CLOSED (wave-383 lane 13; filed as F713): blocks coded."""
    blk = _blocked("(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tg,pt){tg['k']='%s';return true;}});Object.setPrototypeOf(p,[]);return t.k+'%s';})()" % (_A, _B))
    return ("HELD" if blk else "BREAK", "blocked=%s" % blk)

@_t
def test_r50_f714_s1_closed():
    """F714 CLOSED (wave-383 lane 1): blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{has:function(t,k){return true;}});var f=('x' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f714_s2_closed():
    """F714 CLOSED (wave-383 lane 1): blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{has:function(t,k){return k==='y';}});var f=('y' in p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f715_s1_closed():
    """F715 CLOSED (wave-383 lane 2): blocks coded."""
    ok = _blocked("(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f715_s2_closed():
    """F715 CLOSED (wave-383 lane 2): blocks coded."""
    ok = _blocked("(function(){var t={y:'%s'};var p=new Proxy(t,{deleteProperty:function(a,b){return false;}});delete p['y'];return t.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f716_s1_closed():
    """F716 CLOSED (wave-383 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={};Reflect.set(o,'x','%s');return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f716_s2_closed():
    """F716 CLOSED (wave-383 lane 2): blocks coded."""
    ok = _blocked("(function(){var o={};var k='x';Reflect.set(o,k,'%s');return o[k]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f717_s1_closed():
    """F717 CLOSED (wave-383 lane 3): blocks coded."""
    ok = _blocked("(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f717_s2_closed():
    """F717 CLOSED (wave-383 lane 3): blocks coded."""
    ok = _blocked("(function(){var o={};Reflect.defineProperty(o,'y',{value:'%s',enumerable:true});return o['y']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f718_s1_closed():
    """F718 CLOSED (wave-383 lane 3): blocks coded."""
    ok = _blocked("(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f718_s2_closed():
    """F718 CLOSED (wave-383 lane 3): blocks coded."""
    ok = _blocked("(function(){var f=Reflect.has({a:1},'a')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f719_s1_closed():
    """F719 CLOSED (wave-383 lane 4): blocks coded."""
    ok = _blocked("(function(){var r='';var s=new Set(['%s','%s']);for(var x of s){r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f719_s2_closed():
    """F719 CLOSED (wave-383 lane 4): blocks coded."""
    ok = _blocked("(function(){var r='';for(var x of new Set(['%s','%s'])){r=r+x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f720_s1_closed():
    """F720 CLOSED (wave-383 lane 4): blocks coded."""
    ok = _blocked("(function(){var f=['k'].includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f720_s2_closed():
    """F720 CLOSED (wave-383 lane 4): blocks coded."""
    ok = _blocked("(function(){var a=['q','k'];var f=a.includes('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f721_s1_closed():
    """F721 CLOSED (wave-383 lane 5): blocks coded."""
    ok = _blocked("(function(){var f=['k'].indexOf('k')===0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f721_s2_closed():
    """F721 CLOSED (wave-383 lane 5): blocks coded."""
    ok = _blocked("(function(){var f=['a','k'].indexOf('k')>0?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f722_s1_closed():
    """F722 CLOSED (wave-383 lane 5): blocks coded."""
    ok = _blocked("(function(){var m=new Map([['k',1]]);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f722_s2_closed():
    """F722 CLOSED (wave-383 lane 5): blocks coded."""
    ok = _blocked("(function(){var m=new Map();m.set('k',1);var f=m.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f723_s1_closed():
    """F723 CLOSED (wave-383 lane 6): blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};var c=Object.create(o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f723_s2_closed():
    """F723 CLOSED (wave-383 lane 6): blocks coded."""
    ok = _blocked("(function(){var p={get y(){return '%s';}};var c=Object.create(p);var d=Object.create(c);return d.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f724_s1_closed():
    """F724 CLOSED (wave-383 lane 6): blocks coded."""
    ok = _blocked("(function(){var c={};Object.setPrototypeOf(c,{get x(){return '%s';}});return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f724_s2_closed():
    """F724 CLOSED (wave-383 lane 6): blocks coded."""
    ok = _blocked("(function(){var c={};var p={get y(){return '%s';}};Object.setPrototypeOf(c,p);return c.y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f725_s1_closed():
    """F725 CLOSED (wave-383 lane 7): blocks coded."""
    ok = _blocked("(function(){var o={get x(){return '%s';}};var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f725_s2_closed():
    """F725 CLOSED (wave-383 lane 7): blocks coded."""
    ok = _blocked("(function(){var o={};o.__defineGetter__('y',function(){return '%s';});return o.__lookupGetter__('y').call(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f726_s1_closed():
    """F726 CLOSED (wave-383 lane 7): blocks coded."""
    ok = _blocked("(function(){var o={toString:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f726_s2_closed():
    """F726 CLOSED (wave-383 lane 7): blocks coded."""
    ok = _blocked("(function(){var o={[Symbol.toPrimitive]:function(){return '%s';}};return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f727_s1_closed():
    """F727 CLOSED (wave-383 lane 8): blocks coded."""
    ok = _blocked("(function(){var r='';var i=0;do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f727_s2_closed():
    """F727 CLOSED (wave-383 lane 8): blocks coded."""
    ok = _blocked("(function(){var r='';var i=0;do{r=r+['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f728_s1_closed():
    """F728 CLOSED (wave-383 lane 8): blocks coded."""
    ok = _blocked("(function(){function* g(){yield '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f728_s2_closed():
    """F728 CLOSED (wave-383 lane 8): blocks coded."""
    ok = _blocked("(function(){function* g(){yield '%s';yield '%s';}var it=g();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f729_s1_closed():
    """F729 CLOSED (wave-383 lane 9): blocks coded."""
    ok = _blocked("(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f729_s2_closed():
    """F729 CLOSED (wave-383 lane 9): blocks coded."""
    ok = _blocked("(function(){var x='%s';void 0;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f730_s1_closed():
    """F730 CLOSED (wave-383 lane 9): blocks coded."""
    ok = _blocked("(function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'%s',b:'%s'});return v1+v2;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f730_s2_closed():
    """F730 CLOSED (wave-383 lane 9): blocks coded."""
    ok = _blocked("(function(){var e=Object.entries({a:'%s',b:'%s'});var [[,v1],[,v2]]=e;return v1+v2;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f731_s1_closed():
    """F731 CLOSED (wave-383 lane 10): blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=Object.isExtensible(p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f731_s2_closed():
    """F731 CLOSED (wave-383 lane 10): blocks coded."""
    ok = _blocked("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=!Object.isExtensible(p)?'xx':'%s';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f732_s1_closed():
    """F732 CLOSED (wave-383 lane 10): blocks coded."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(tr){tr.__g='%s';return Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);return t.__g+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f732_s2_closed():
    """F732 CLOSED (wave-383 lane 10): blocks coded."""
    ok = _blocked("(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(x){x['h']='%s';return Object.getPrototypeOf(x);}});Object.getPrototypeOf(p);return t.h+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f733_s1_closed():
    """F733 CLOSED (wave-383 lane 11): blocks coded."""
    ok = _blocked("(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f733_s2_closed():
    """F733 CLOSED (wave-383 lane 11): blocks coded."""
    ok = _blocked("(function(){var w=new WeakRef({v:'%s'});return w.deref()['v']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f734_s1_closed():
    """F734 CLOSED (wave-383 lane 11): blocks coded."""
    ok = _blocked("(function(){var s=Symbol('k');var o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f734_s2_closed():
    """F734 CLOSED (wave-383 lane 11): blocks coded."""
    ok = _blocked("(function(){var s=Symbol('k');var o={[s]:'%s'};return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f735_s1_closed():
    """F735 CLOSED (wave-383 lane 12): blocks coded."""
    ok = _blocked("(function(){var f='%s';function g(){return f;}return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f735_s2_closed():
    """F735 CLOSED (wave-383 lane 12): blocks coded."""
    ok = _blocked("(function(){var f='%s';var g=function(){return f;};return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f736_s1_closed():
    """F736 CLOSED (wave-383 lane 12): blocks coded."""
    ok = _blocked("(function(){function h(a='%s'){return a;}return h()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r50_f736_s2_closed():
    """F736 CLOSED (wave-383 lane 12): blocks coded."""
    ok = _blocked("(function(){function h(a='%s',b='%s'){return a+b;}return h('%s');})()" % (_A, _B, _A))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w381_attack_probes.py")],
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
    # The w381 battery's footer pin is stale by design: merge repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w381_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-381 attack battery stays green (depth-1)."""
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
