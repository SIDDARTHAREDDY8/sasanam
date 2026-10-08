"""Wave-379 lane 8: attack round 47 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (14, all LOW, all OPEN), filed from F672:
- F672: class fragment sources beyond F662 (CLOSED 2026-10-08 wave-380
  lane 1) -- private static
  fields, private instance fields, extends/super reads, class
  expressions, computed method names, static inheritance, mixins
  (7 shapes, one mechanism).
- F673: object-construction member reads beyond F663/F664/F671 --
  defineProperties getters, Object.entries/Object.values destructuring,
  computed-key literals, Object.create proto reads, hasOwn-guarded reads
  (6 shapes). F671 files plain-literal member reads in IIFE-return
  position; these are distinct source productions.
- F674: this-bound member reads -- method this.x, getter this.y
  (2 shapes).
- F675: Proxy traps beyond F642 (get), F666 (apply/has), F670
  (non-concise get forms) -- set, construct, deleteProperty,
  getPrototypeOf, revocable (5 shapes).
- F676: optional-chaining beyond F665 -- ?.() calls, ?.[] brackets,
  nullish combos, chained ?. reads (4 shapes).
- F677: iterator protocols beyond F653/F656/F659/F669 -- manual
  iterator objects, custom Symbol.asyncIterator, generator return
  delegation, multi-.next() sequencing, yield* over generators,
  for-await over promise arrays (6 shapes).
- F678: with-statement beyond F667 -- nested with, with-then-tail-read
  (2 shapes).
- F679: statement-body accumulation beyond F655 -- C-style for, while,
  for-in guards, try-catch, if-else chains, for(;;)+break,
  do-while+break (7 shapes).
- F680: symbol-mediated fragment reads -- Symbol.keyFor,
  Symbol.for().description, symbol-keyed member reads (3 shapes).
- F681: array mutator fragment assembly beyond F658 -- splice, fill
  (2 shapes).
- F682: whitespace-trimmed literal reads -- trim/trimStart/trimEnd
  (3 shapes).
- F683: JSON reviver fragment assembly -- object, key-guarded, array
  (3 shapes).
- F684: destructuring documented residuals beyond F644/F645 -- defaults
  referencing earlier params (F645 residual), nested patterns (F644
  residual) (2 shapes).
- F685: arrow-lexical arguments reads beyond F545 -- arguments[0]/[1]
  captured by an arrow in a call-arg IIFE (2 shapes).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F662-F671 (round 46), F673-F685 (this round; F672 CLOSED wave-380 lane 1).

Closed pins (must BLOCK, else BREAK): F463, F510, F535, F601, F612,
F619, F642, F653, F655, F657, F658, F661, F672.

Rides-with-documented-scope (validated, NOT filed):
- Tag-function substitutions and String.raw twins -- BLOCK; already
  modeled (F463/F668).
- Arrow arguments with a method receiver -- BLOCK; already modeled.
- Array flat/concat/slice/reverse/toReversed/with, replace/replaceAll/
  match-groups/padEnd/substring/split, JSON.parse member reads,
  Object.groupBy, Number toString -- all BLOCK; already modeled.
- Single-statement if/switch early returns -- BLOCK (F611/F655 bodies).
- `delete o?.x` -- malformed (delete yields a boolean); discarded.
- Array toSorted on the fragments -- malformed (sort order); discarded.
- Generator .return(v).value -- assembles only one fragment
  (malformed); discarded, not a decoder signal.
Model note: 2/2 prompts returned usable hints (0 timeouts). The class
hints (private fields, inheritance) and statement hints (C-style for,
while, if-else chains) guided hand-crafted extensions validated
node-exact (v24.20.0). Junk-quiet controls pass.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g379-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000234
logged separately in the realmodel ledger).
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

TAXONOMY_PIN = 2140  # no new decision codes this round

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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
def test_b0_footer_state():
    """Control: footer shows F675-F685 open, next F686 (F672-F674 CLOSED wave-380 lanes 1-2)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F686**" in text
          and "Open findings: F675, F676, F677, F678, F679, F680, F681, F682, F683, F684, F685." in text)  # Wave-380 merge: F672 (lane 1), F673, F674 (lane 2) CLOSED; footer repoint open F675-F685 / next F686
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f463_closed():
    """String.raw tag form CLOSED: still blocks."""
    ok = _blocked("String.raw`%s%s`" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f463=%s" % ok)


@_t
def test_p1_f510_closed():
    """inline Object.values CLOSED: still blocks."""
    ok = _blocked("Object.values({a:'%s',b:'%s'}).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f510=%s" % ok)


@_t
def test_p1_f535_closed():
    """literal getter member read CLOSED: still blocks."""
    ok = _blocked("({get x(){return '%s%s';}}).x" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)


@_t
def test_p1_f601_closed():
    """inline Map forEach CLOSED: still blocks."""
    ok = _blocked("(function(){var s='';new Map([['k','%s%s']]).forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f601=%s" % ok)


@_t
def test_p1_f612_closed():
    """var-bound values CLOSED: still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f612=%s" % ok)


@_t
def test_p1_f619_closed():
    """generator spread CLOSED: still blocks."""
    ok = _blocked("[...(function*(){yield '%s';yield '%s';})()].join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f619=%s" % ok)


@_t
def test_p1_f642_closed():
    """Proxy get trap var-bound CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f642=%s" % ok)


@_t
def test_p1_f653_closed():
    """custom-iterator Array.from CLOSED: still blocks."""
    ok = _blocked("Array.from(new Set(['%s','%s'])).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f653=%s" % ok)


@_t
def test_p1_f655_closed():
    """two-decl statement IIFE CLOSED: still blocks."""
    ok = _blocked("(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f655=%s" % ok)


@_t
def test_p1_f657_closed():
    """var-bound Map forEach CLOSED: still blocks."""
    ok = _blocked("(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f657=%s" % ok)


@_t
def test_p1_f658_closed():
    """flatMap literal-array CLOSED: still blocks."""
    ok = _blocked("(function(){return ['%s','%s'].flatMap(function(x){return [x];}).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f658=%s" % ok)


@_t
def test_p1_f661_closed():
    """declaration-position sequence CLOSED: still blocks."""
    ok = _blocked("(function(){var s=('jx','%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f661=%s" % ok)


# ------------------------------------------------- F672 CLOSED pins (must block; wave-380 lane 1)

@_t
def test_r47_f672_s1_closed():
    """F672 CLOSED (priv-static): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){class C{static #x='%s';static y(){return C.#x;}}return C.y()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s2_closed():
    """F672 CLOSED (priv-inst): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){class C{#x='%s';get(){return this.#x;}}return new C().get()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s3_closed():
    """F672 CLOSED (extends-super): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){class C{get x(){return '%s';}}class D extends C{}return new D().x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s4_closed():
    """F672 CLOSED (class-expr): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){var C=class{static x='%s';};return C.x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s5_closed():
    """F672 CLOSED (computed-method): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){class C{['g'+''](){return '%s';}}return new C()['g'+'']()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s6_closed():
    """F672 CLOSED (static-inherit): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){class C{static x='%s';}class D extends C{}return D.x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r47_f672_s7_closed():
    """F672 CLOSED (mixin): coded refusal (wave-380 lane 1)."""
    hit = _blocked("(function(){var M=function(S){return class extends S{get x(){return '%s';}};};class B{}return new (M(B))().x+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F673 closed pins (must block)

@_t
def test_r47_f673_s1_closed():
    """F673 CLOSED (defineprop-getter): now blocks."""
    ok = _blocked("(function(){var o={};Object.defineProperties(o,{x:{get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f673_s2_closed():
    """F673 CLOSED (entries-destr): now blocks."""
    ok = _blocked("(function(){var [[k,v]]=Object.entries({x:'%s'});return v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f673_s3_closed():
    """F673 CLOSED (values-destr): now blocks."""
    ok = _blocked("(function(){var [v]=Object.values({x:'%s'});return v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f673_s4_closed():
    """F673 CLOSED (computed-key): now blocks."""
    ok = _blocked("(function(){var k='x';var o={[k]:'%s'};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f673_s5_closed():
    """F673 CLOSED (create): now blocks."""
    ok = _blocked("(function(){var o=Object.create({x:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f673_s6_closed():
    """F673 CLOSED (hasown): now blocks."""
    ok = _blocked("(function(){var o={x:'%s'};return (Object.hasOwn(o,'x')?o.x:'junk')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F674 closed pins (must block)

@_t
def test_r47_f674_s1_closed():
    """F674 CLOSED (this-method): now blocks."""
    ok = _blocked("(function(){var o={x:'%s',get:function(){return this.x;}};return o.get()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r47_f674_s2_closed():
    """F674 CLOSED (this-getter): now blocks."""
    ok = _blocked("(function(){var o={get x(){return this.y;},y:'%s'};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- F675 open pins (must miss)

@_t
def test_r47_f675_s1_open():
    """F675 OPEN (set-trap): miss reproduces."""
    miss = _misses("(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});p.x='%s';return p.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f675_s2_open():
    """F675 OPEN (construct): miss reproduces."""
    miss = _misses("(function(){var P=new Proxy(function(){},{construct:function(){return {x:'%s'};}});return new P().x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f675_s3_open():
    """F675 OPEN (delete): miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};var p=new Proxy(o,{deleteProperty:function(t,k){return true;}});delete p.x;return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f675_s4_open():
    """F675 OPEN (getproto): miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{getPrototypeOf:function(){return {x:'%s'};}});return Object.getPrototypeOf(p).x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f675_s5_open():
    """F675 OPEN (revocable): miss reproduces."""
    miss = _misses("(function(){var r=Proxy.revocable({},{get:function(){return '%s';}});return r.proxy.x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F676 open pins (must miss)

@_t
def test_r47_f676_s1_open():
    """F676 OPEN (opt-call): miss reproduces."""
    miss = _misses("(function(){var o={f:function(){return '%s';}};return o?.f()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f676_s2_open():
    """F676 (opt-bracket): now BLOCKED via F665 closure (wave-379 merge partial absorption)."""
    blocked = _blocked("(function(){var o={x:'%s'};return o?.['x']+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


@_t
def test_r47_f676_s3_open():
    """F676 OPEN (opt-nullish): miss reproduces."""
    miss = _misses("(function(){var o=null;return (o?.x ?? '%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f676_s4_open():
    """F676 (opt-chain): now BLOCKED via F665 closure (wave-379 merge partial absorption)."""
    blocked = _blocked("(function(){var o={x:{y:'%s'}};return o?.x?.y+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "blocked=%s" % blocked)


# ------------------------------------------------- F677 open pins (must miss)

@_t
def test_r47_f677_s1_open():
    """F677 OPEN (manual-obj): miss reproduces."""
    miss = _misses("(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'%s':'%s',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f677_s2_open():
    """F677 OPEN (async-custom): miss reproduces."""
    miss = _misses("(async function(){var o={vals:['%s','%s'],[Symbol.asyncIterator]:async function*(){yield this.vals[0];yield this.vals[1];}};var s='';for await(var x of o){s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f677_s3_open():
    """F677 OPEN (gen-return): miss reproduces."""
    miss = _misses("(function(){function* g(){yield '%s';return '%s';}var it=g();var a=it.next();var b=it.next();return a.value+b.value;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f677_s4_open():
    """F677 OPEN (next-seq): miss reproduces."""
    miss = _misses("(function(){var g=(function*(){yield '%s';yield '%s';})();var a=g.next();var b=g.next();return a.value+b.value;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f677_s5_open():
    """F677 OPEN (yieldstar-gen): miss reproduces."""
    miss = _misses("(function(){function* h(){yield '%s';}function* g(){yield* h();yield '%s';}return [...g()].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f677_s6_open():
    """F677 OPEN (forawait-promises): miss reproduces."""
    miss = _misses("(async function(){var s='';for await(var x of [Promise.resolve('%s'),Promise.resolve('%s')]){s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F678 open pins (must miss)

@_t
def test_r47_f678_s1_open():
    """F678 OPEN (nested): miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};var p={y:'%s'};with(o){with(p){return x+y;}}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f678_s2_open():
    """F678 OPEN (tail-read): miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};var s;with(o){s=x;}return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F679 open pins (must miss)

@_t
def test_r47_f679_s1_open():
    """F679 OPEN (cfor): miss reproduces."""
    miss = _misses("(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'%s':'%s';}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s2_open():
    """F679 OPEN (while): miss reproduces."""
    miss = _misses("(function(){var s='';var i=0;while(i<2){s+=i===0?'%s':'%s';i++;}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s3_open():
    """F679 OPEN (forin-guard): miss reproduces."""
    miss = _misses("(function(){var o={x:'%s'};var s='';for(var k in o){if(k==='x'){s+=o[k];}}return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s4_open():
    """F679 OPEN (trycatch): miss reproduces."""
    miss = _misses("(function(){var s='';try{throw '%s';}catch(e){s+=e;}s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s5_open():
    """F679 OPEN (ifelse-chain): miss reproduces."""
    miss = _misses("(function(){var s='';if(false){s+='junk';}else if(true){s+='%s';}s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s6_open():
    """F679 OPEN (forbreak): miss reproduces."""
    miss = _misses("(function(){var s='';for(;;){s+='%s';break;}s+='%s';return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f679_s7_open():
    """F679 OPEN (dowhile-break): miss reproduces."""
    miss = _misses("(function(){var s='';var i=0;do{s+=i===0?'%s':'%s';i++;if(i>=2){break;}}while(true);return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F680 open pins (must miss)

@_t
def test_r47_f680_s1_open():
    """F680 OPEN (keyfor): miss reproduces."""
    miss = _misses("(function(){return Symbol.keyFor(Symbol.for('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f680_s2_open():
    """F680 OPEN (desc): miss reproduces."""
    miss = _misses("(function(){return Symbol.for('%s').description+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f680_s3_open():
    """F680 OPEN (sym-keyed): miss reproduces."""
    miss = _misses("(function(){var o={[Symbol.for('k')]:'%s'};return o[Symbol.for('k')]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F681 open pins (must miss)

@_t
def test_r47_f681_s1_open():
    """F681 OPEN (splice): miss reproduces."""
    miss = _misses("(function(){var a=['junk','%s','%s'];a.splice(0,1);return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f681_s2_open():
    """F681 OPEN (fill): miss reproduces."""
    miss = _misses("(function(){var a=['x','y'];a.fill('%s',0,1);a.fill('%s',1,2);return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F682 open pins (must miss)

@_t
def test_r47_f682_s1_open():
    """F682 OPEN (trim): miss reproduces."""
    miss = _misses("(function(){return ' %s '.trim()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f682_s2_open():
    """F682 OPEN (trimstart): miss reproduces."""
    miss = _misses("(function(){return ' %s'.trimStart()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f682_s3_open():
    """F682 OPEN (trimend): miss reproduces."""
    miss = _misses("(function(){return '%s '.trimEnd()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F683 open pins (must miss)

@_t
def test_r47_f683_s1_open():
    """F683 OPEN (reviver): miss reproduces."""
    miss = _misses("(function(){return JSON.parse('{\"x\":\"%s\"}',function(k,v){return typeof v==='string'?v+'%s':v;}).x;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f683_s2_open():
    """F683 OPEN (reviver-key): miss reproduces."""
    miss = _misses("(function(){return JSON.parse('{\"x\":\"%s\",\"y\":\"z\"}',function(k,v){return k==='x'?v+'%s':v;}).x;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f683_s3_open():
    """F683 OPEN (reviver-arr): miss reproduces."""
    miss = _misses("(function(){return JSON.parse('[\"%s\"]',function(k,v){return k==='0'?v+'%s':v;})[0];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F684 open pins (must miss)

@_t
def test_r47_f684_s1_open():
    """F684 OPEN (default-ref): miss reproduces."""
    miss = _misses("(function({a='%s',b=a+'%s'}={}){return b;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f684_s2_open():
    """F684 OPEN (nested): miss reproduces."""
    miss = _misses("(function(){var {x:{y}}={x:{y:'%s'}};return y+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F685 open pins (must miss)

@_t
def test_r47_f685_s1_open():
    """F685 OPEN (arrow-args): miss reproduces."""
    miss = _misses("(function(){var f=()=>arguments[0];return f()+'%s';})('%s')" % (_B, _A))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r47_f685_s2_open():
    """F685 OPEN (arrow-args-idx1): miss reproduces."""
    miss = _misses("(function(){var f=()=>arguments[1];return f()+'%s';})('junk','%s')" % (_B, _A))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)



# ------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g379-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w378_attack_probes.py")],
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
    # The w378 battery's footer pin is stale by design: this lane filed
    # F672-F685, so its expected footer (open F662-F671 / next F672)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w378_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-378 attack battery stays green (depth-1)."""
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
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
            errors += 1
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
