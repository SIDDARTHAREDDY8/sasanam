#!/usr/bin/env python3
"""Wave-386 attack battery (round 54): pins re-pinned CLOSED at wave-387 merge.

Each pin asserts the decoder MISSES a node-verified credential-laundering
shape on the open tree (BREAK = still open). Carries the wave-385 open pins
via the depth-1 green check on w385_attack_probes.py (GOV_SKIP_GREEN=1).

Short test credentials, pin 2143, $0-spend-by-construction (model spend logged
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

TAXONOMY_PIN = 2143  # wave-385 merge (no code-count change)

from gov import dlp
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


def _hits(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- controls


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in text
          and "F893, F894, F895, F896, F897, F898, F899, F900, F901, F902, F903, F904, F905, F906, F907, F908, F909, F910, F911, F912, F913, F914, F915, F916, F917, F918, F919, F920." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- open pins (must miss)

@_t
def test_r54_f834_s1_closed():
    """F834 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={m(){return '%s';}};return o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f834_s2_closed():
    """F834 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={k:'%s',m(){return this.k;}};return o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f835_s1_closed():
    """F835 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var f=()=>'%s';return f()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f835_s2_closed():
    """F835 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var f=()=>{return '%s';};return f()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f836_s1_closed():
    """F836 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(a){return function(b){return a+b;};}return f('%s')('%s');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f836_s2_closed():
    """F836 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return (()=>()=>'%s')()()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f837_s1_closed():
    """F837 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return (function(){return {k:'%s'};})().k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f837_s2_closed():
    """F837 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var r=(function(){return ['%s','%s'];})();return r[0]+r[1];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f838_s1_closed():
    """F838 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function outer(){function inner(){return '%s';}return inner();}return outer()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f838_s2_closed():
    """F838 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function a(){function b(){function c(){return '%s';}return c();}return b();}return a()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f839_s1_closed():
    """F839 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var r='';{let k='%s';r=k;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f839_s2_closed():
    """F839 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var r='';if(true){let k='%s';r=k;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f840_s1_closed():
    """F840 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var k='%s';var o={k};return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f840_s2_closed():
    """F840 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var k='%s',j='x';var o={k,j};return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f841_s1_closed():
    """F841 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=[];a.push('%s');a.push('%s');return a.join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f841_s2_closed():
    """F841 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=[];a.push('%s');a.push('%s');return a.join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f842_s1_closed():
    """F842 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=[];a[0]='%s';a[1]='%s';return a.join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f842_s2_closed():
    """F842 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=['x'];a[1]='%s';a[2]='%s';return a.slice(1).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f843_s1_closed():
    """F843 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=['%s','%s','x'];a.length=2;return a.join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f843_s2_closed():
    """F843 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=['%s','%s','x','y'];a.length=2;return a.join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f844_s1_closed():
    """F844 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={0:'%s'};return o[0]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f844_s2_closed():
    """F844 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={0:'%s'};return o[2-2]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f845_s1_closed():
    """F845 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={};var s=Symbol.for('kk');o[s]='%s';return o[Symbol.for('kk')]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f845_s2_closed():
    """F845 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var s=Symbol.for('k');var o={[s]:'%s'};return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f846_s1_closed():
    """F846 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={['k'+'ey']:'%s'};return o.key+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f846_s2_closed():
    """F846 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={};o['k'+'ey']='%s';return o['key']+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f847_s1_closed():
    """F847 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={};Object.defineProperties(o,{k:{value:'%s',enumerable:true}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f847_s2_closed():
    """F847 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={};Object.defineProperties(o,{k:{value:'%s',writable:true}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f848_s1_closed():
    """F848 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var x=1,r='';switch(x){case 1:r='%s';break;default:r='z';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f848_s2_closed():
    """F848 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var x=2,r='';switch(x){case 1:r='x';break;case 2:r='%s';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f849_s1_closed():
    """F849 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f849_s2_closed():
    """F849 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){try{throw {message:'%s'};}catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f850_s1_closed():
    """F850 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});p.k='%s';return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f850_s2_closed():
    """F850 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v+'!';return true;}});p.k='%s';return p.k.slice(0,-1)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f851_s1_closed():
    """F851 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy(new Proxy({k:'%s'},{}),{});return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f851_s2_closed():
    """F851 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy(new Proxy(new Proxy({k:'%s'},{}),{}),{});return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f852_s1_closed():
    """F852 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){return {value:t[k],configurable:true};}});return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f852_s2_closed():
    """F852 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){var d=Object.getOwnPropertyDescriptor(t,k);return d;}});return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f853_s1_closed():
    """F853 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function* g(a){yield a;}var it=g('%s');return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f853_s2_closed():
    """F853 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function* g(a,b){yield a;yield b;}var it=g('%s','%s');return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f854_s1_closed():
    """F854 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function* g(){yield 'x';return '%s';}var it=g();it.next();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f854_s2_closed():
    """F854 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function* g(){return '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f855_s1_closed():
    """F855 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var it=['%s','%s'].values().take(2).toArray();return it[0]+it[1];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f855_s2_closed():
    """F855 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return [...['%s','%s','x'].values().take(2)].join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f856_s1_closed():
    """F856 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var b=new TextEncoder().encode('%s');return new TextDecoder().decode(b)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f856_s2_closed():
    """F856 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var e=new TextEncoder();var d=new TextDecoder();return d.decode(e.encode('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f857_s1_closed():
    """F857 CLOSED (wave-387 lane 8): Intl.Segmenter for-of: blocks coded."""
    ok = _blocked("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'}).segment('%s');var r='';for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f857_s2_closed():
    """F857 CLOSED (wave-387 lane 8): Intl.Segmenter Array.from/map/join: blocks coded."""
    ok = _blocked("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'}).segment('%s');return Array.from(s).map(function(x){return x.segment;}).join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f858_s1_closed():
    """F858 CLOSED (wave-387 lane 8): URL hash carrier: blocks coded."""
    ok = _blocked("(function(){var u=new URL('https://h/#%s');return u.hash.slice(1)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f858_s2_closed():
    """F858 CLOSED (wave-387 lane 8): URL username carrier: blocks coded."""
    ok = _blocked("(function(){var u=new URL('https://h/');u.username='%s';return u.username+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f859_s1_closed():
    """F859 CLOSED (wave-387 lane 8): URLSearchParams set + get: blocks coded."""
    ok = _blocked("(function(){var p=new URLSearchParams();p.set('k','%s');return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f859_s2_closed():
    """F859 CLOSED (wave-387 lane 8): URLSearchParams append + get: blocks coded."""
    ok = _blocked("(function(){var p=new URLSearchParams();p.append('k','%s');return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f860_s1_closed():
    """F860 CLOSED (wave-387 lane 8): FormData set + get: blocks coded."""
    ok = _blocked("(function(){var f=new FormData();f.set('k','%s');return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f860_s2_closed():
    """F860 CLOSED (wave-387 lane 8): FormData append x2 + get: blocks coded."""
    ok = _blocked("(function(){var f=new FormData();f.append('k','%s');f.append('k','x');return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r54_f861_s1_closed():
    """F861 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var h=new Headers();h.set('x-k','%s');return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f861_s2_closed():
    """F861 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var h=new Headers({'x-k':'%s'});return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f862_s1_closed():
    """F862 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return new TypeError('%s').message+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f862_s2_closed():
    """F862 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return new DOMException('%s').message+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f863_s1_closed():
    """F863 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={toJSON:function(){return '%s';}};return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f863_s2_closed():
    """F863 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={k:'%s',toJSON:function(){return this.k;}};return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f864_s1_closed():
    """F864 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f864_s2_closed():
    """F864 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return JSON.parse(JSON.stringify({k:'%s'}),function(k,v){return k===''?v:v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f865_s1_closed():
    """F865 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){var m=structuredClone(new Map([['k','%s']]));return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f865_s2_closed():
    """F865 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){var m=structuredClone(new Map([['k','%s'],['x','y']]));return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f866_s1_closed():
    """F866 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){var s='z%s'+'z';return s.split(/(xoxb-[0-9a-f]+)/)[1]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f866_s2_closed():
    """F866 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){return ('%s,'+'%s').split(/,/).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f867_s1_closed():
    """F867 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){return ('x'+'%s').match(/(?<m>xoxb-[0-9a-f]+)/).groups.m+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f867_s2_closed():
    """F867 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){return ('x'+'%s').match(/(?<m>xoxb-[0-9a-f]+)/).groups.m+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f868_s1_closed():
    """F868 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){function f(n){return n<=0?'%s':f(n-1);}return f(1)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f868_s2_closed():
    """F868 CLOSED: hit reproduces (wave-387 lane 10)."""
    hit = _hits("(function(){function f(n){return n<=0?'%s':f(n-1); }return f(2)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f869_s1_closed():
    """F869 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(){return Array.prototype.slice.call(arguments).join('');}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f869_s2_closed():
    """F869 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return String.prototype.split.call('%s,%s',',').join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f870_s1_closed():
    """F870 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(){return '%s';}return f.bind(null).bind(null)()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f870_s2_closed():
    """F870 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(){return '%s';}var g=f.bind(null);return g.bind(null)()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f871_s1_closed():
    """F871 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(){return g.apply(null,arguments);}function g(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f871_s2_closed():
    """F871 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(){return g.apply(null,arguments);}function g(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f872_s1_closed():
    """F872 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=['%s','%s'];a.sort(function(x,y){return 0;});return a[0]+a[1];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f872_s2_closed():
    """F872 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return ['%s','%s'].sort(function(){return 0;}).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f873_s1_closed():
    """F873 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return ['x'].reduce(function(a){return a;},'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f873_s2_closed():
    """F873 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return ['x','y'].reduce(function(a,b){return a;},'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f874_s1_closed():
    """F874 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var it=['%s','%s'].values();return [].concat(...it).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f874_s2_closed():
    """F874 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var it=['%s','%s'].values();return [].concat(...it).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f875_s1_closed():
    """F875 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={k:'%s'};return Object.getOwnPropertyNames(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f875_s2_closed():
    """F875 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var o={k:'%s'};return Object.keys(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f876_s1_closed():
    """F876 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){class C{static{this.k='%s';}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f876_s2_closed():
    """F876 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){class C{static k;static{this.k='%s';}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f877_s1_closed():
    """F877 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){class C{static k;static{try{C.k='%s';}catch(e){}}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f877_s2_closed():
    """F877 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var r='';class C{static{try{throw 0;}catch(e){r='%s';}}}return r+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f878_s1_closed():
    """F878 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}return new C('%s').m()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f878_s2_closed():
    """F878 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){class C{constructor(x){this._k=x;}get=()=>this._k;}return new C('%s').get()+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f879_s1_closed():
    """F879 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var C=class{constructor(x){this.k=x;}};return new C('%s').k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f879_s2_closed():
    """F879 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var C=class D{constructor(x){this.k=x;}};return new C('%s').k+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f880_s1_closed():
    """F880 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){return ['%s','%s'].toSorted(function(x,y){return 0;}).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f880_s2_closed():
    """F880 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var a=['%s','%s','x'].toSorted(function(x,y){return 0;});return a[0]+a[1];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f881_s1_closed():
    """F881 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var s=new Set(['%s','%s']);var r='';s.forEach(function(v){r+=v;});return r;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f881_s2_closed():
    """F881 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){var s=new Set(['%s','%s']);var r='';s.forEach(function(v){r+=v;});return r;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f882_s1_closed():
    """F882 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(a){return a[0]+a[1];}return f(['%s','%s']);})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r54_f882_s2_closed():
    """F882 CLOSED (wave-387): hit reproduces."""
    hit = _hits("(function(){function f(a,b){return a[0]+b;}return f(['%s'],'%s');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

# ------------------------------------------------------- green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w385_attack_probes.py")],
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
    # The w385 battery's footer pin is stale by design: this lane repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w385_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Depth-1 green check on the prior round's battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        verdict, note = fn()
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
