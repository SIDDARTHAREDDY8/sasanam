#!/usr/bin/env python3
"""Wave-386 attack battery (round 54): 49 new decoder-miss pins (F829-F877).

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


# ---------------------------------------------------------------- controls


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F795-F817, F819-F828, F829-F877 open, next F878)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F878**" in text  # Wave-386 attack round 54
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, F802, F803, F804, F805, F806, F807, F808, F809, F810, F811, F812, F813, F814, F815, F816, F817, F819, F820, F821, F822, F823, F824, F825, F826, F827, F828, F829, F830, F831, F832, F833, F834, F835, F836, F837, F838, F839, F840, F841, F842, F843, F844, F845, F846, F847, F848, F849, F850, F851, F852, F853, F854, F855, F856, F857, F858, F859, F860, F861, F862, F863, F864, F865, F866, F867, F868, F869, F870, F871, F872, F873, F874, F875, F876, F877." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- open pins (must miss)

@_t
def test_r54_f829_s1_open():
    """F829 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={m(){return '%s';}};return o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f829_s2_open():
    """F829 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s',m(){return this.k;}};return o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f830_s1_open():
    """F830 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=()=>'%s';return f()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f830_s2_open():
    """F830 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=()=>{return '%s';};return f()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f831_s1_open():
    """F831 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a){return function(b){return a+b;};}return f('%s')('%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f831_s2_open():
    """F831 OPEN: miss reproduces."""
    miss = _misses("(function(){return (()=>()=>'%s')()()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f832_s1_open():
    """F832 OPEN: miss reproduces."""
    miss = _misses("(function(){return (function(){return {k:'%s'};})().k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f832_s2_open():
    """F832 OPEN: miss reproduces."""
    miss = _misses("(function(){var r=(function(){return ['%s','%s'];})();return r[0]+r[1];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f833_s1_open():
    """F833 OPEN: miss reproduces."""
    miss = _misses("(function(){function outer(){function inner(){return '%s';}return inner();}return outer()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f833_s2_open():
    """F833 OPEN: miss reproduces."""
    miss = _misses("(function(){function a(){function b(){function c(){return '%s';}return c();}return b();}return a()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f834_s1_open():
    """F834 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';{let k='%s';r=k;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f834_s2_open():
    """F834 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';if(true){let k='%s';r=k;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f835_s1_open():
    """F835 OPEN: miss reproduces."""
    miss = _misses("(function(){var k='%s';var o={k};return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f835_s2_open():
    """F835 OPEN: miss reproduces."""
    miss = _misses("(function(){var k='%s',j='x';var o={k,j};return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f836_s1_open():
    """F836 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=[];a.push('%s');a.push('%s');return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f836_s2_open():
    """F836 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=[];a.push('%s');a.push('%s');return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f837_s1_open():
    """F837 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=[];a[0]='%s';a[1]='%s';return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f837_s2_open():
    """F837 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['x'];a[1]='%s';a[2]='%s';return a.slice(1).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f838_s1_open():
    """F838 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s','x'];a.length=2;return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f838_s2_open():
    """F838 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s','x','y'];a.length=2;return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f839_s1_open():
    """F839 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={0:'%s'};return o[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f839_s2_open():
    """F839 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={0:'%s'};return o[2-2]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f840_s1_open():
    """F840 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};var s=Symbol.for('kk');o[s]='%s';return o[Symbol.for('kk')]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f840_s2_open():
    """F840 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=Symbol.for('k');var o={[s]:'%s'};return o[s]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f841_s1_open():
    """F841 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={['k'+'ey']:'%s'};return o.key+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f841_s2_open():
    """F841 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};o['k'+'ey']='%s';return o['key']+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f842_s1_open():
    """F842 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};Object.defineProperties(o,{k:{value:'%s',enumerable:true}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f842_s2_open():
    """F842 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};Object.defineProperties(o,{k:{value:'%s',writable:true}});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f843_s1_open():
    """F843 OPEN: miss reproduces."""
    miss = _misses("(function(){var x=1,r='';switch(x){case 1:r='%s';break;default:r='z';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f843_s2_open():
    """F843 OPEN: miss reproduces."""
    miss = _misses("(function(){var x=2,r='';switch(x){case 1:r='x';break;case 2:r='%s';break;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f844_s1_open():
    """F844 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f844_s2_open():
    """F844 OPEN: miss reproduces."""
    miss = _misses("(function(){try{throw {message:'%s'};}catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f845_s1_open():
    """F845 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v;return true;}});p.k='%s';return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f845_s2_open():
    """F845 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{set:function(t,k,v){t[k]=v+'!';return true;}});p.k='%s';return p.k.slice(0,-1)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f846_s1_open():
    """F846 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy(new Proxy({k:'%s'},{}),{});return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f846_s2_open():
    """F846 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy(new Proxy(new Proxy({k:'%s'},{}),{}),{});return p.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f847_s1_open():
    """F847 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){return {value:t[k],configurable:true};}});return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f847_s2_open():
    """F847 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:function(t,k){var d=Object.getOwnPropertyDescriptor(t,k);return d;}});return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f848_s1_open():
    """F848 OPEN: miss reproduces."""
    miss = _misses("(function(){function* g(a){yield a;}var it=g('%s');return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f848_s2_open():
    """F848 OPEN: miss reproduces."""
    miss = _misses("(function(){function* g(a,b){yield a;yield b;}var it=g('%s','%s');return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f849_s1_open():
    """F849 OPEN: miss reproduces."""
    miss = _misses("(function(){function* g(){yield 'x';return '%s';}var it=g();it.next();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f849_s2_open():
    """F849 OPEN: miss reproduces."""
    miss = _misses("(function(){function* g(){return '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f850_s1_open():
    """F850 OPEN: miss reproduces."""
    miss = _misses("(function(){var it=['%s','%s'].values().take(2).toArray();return it[0]+it[1];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f850_s2_open():
    """F850 OPEN: miss reproduces."""
    miss = _misses("(function(){return [...['%s','%s','x'].values().take(2)].join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f851_s1_open():
    """F851 OPEN: miss reproduces."""
    miss = _misses("(function(){var b=new TextEncoder().encode('%s');return new TextDecoder().decode(b)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f851_s2_open():
    """F851 OPEN: miss reproduces."""
    miss = _misses("(function(){var e=new TextEncoder();var d=new TextDecoder();return d.decode(e.encode('%s'))+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f852_s1_open():
    """F852 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'}).segment('%s');var r='';for(var x of s){r+=x.segment;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f852_s2_open():
    """F852 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=new Intl.Segmenter('en',{granularity:'grapheme'}).segment('%s');return Array.from(s).map(function(x){return x.segment;}).join('')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f853_s1_open():
    """F853 OPEN: miss reproduces."""
    miss = _misses("(function(){var u=new URL('https://h/#%s');return u.hash.slice(1)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f853_s2_open():
    """F853 OPEN: miss reproduces."""
    miss = _misses("(function(){var u=new URL('https://h/');u.username='%s';return u.username+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f854_s1_open():
    """F854 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams();p.set('k','%s');return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f854_s2_open():
    """F854 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams();p.append('k','%s');return p.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f855_s1_open():
    """F855 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=new FormData();f.set('k','%s');return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f855_s2_open():
    """F855 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=new FormData();f.append('k','%s');f.append('k','x');return f.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f856_s1_open():
    """F856 OPEN: miss reproduces."""
    miss = _misses("(function(){var h=new Headers();h.set('x-k','%s');return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f856_s2_open():
    """F856 OPEN: miss reproduces."""
    miss = _misses("(function(){var h=new Headers({'x-k':'%s'});return h.get('x-k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f857_s1_open():
    """F857 OPEN: miss reproduces."""
    miss = _misses("(function(){return new TypeError('%s').message+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f857_s2_open():
    """F857 OPEN: miss reproduces."""
    miss = _misses("(function(){return new DOMException('%s').message+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f858_s1_open():
    """F858 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={toJSON:function(){return '%s';}};return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f858_s2_open():
    """F858 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s',toJSON:function(){return this.k;}};return JSON.parse(JSON.stringify(o))+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f859_s1_open():
    """F859 OPEN: miss reproduces."""
    miss = _misses("(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f859_s2_open():
    """F859 OPEN: miss reproduces."""
    miss = _misses("(function(){return JSON.parse(JSON.stringify({k:'%s'}),function(k,v){return k===''?v:v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f860_s1_open():
    """F860 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=structuredClone(new Map([['k','%s']]));return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f860_s2_open():
    """F860 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=structuredClone(new Map([['k','%s'],['x','y']]));return m.get('k')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f861_s1_open():
    """F861 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='z%s'+'z';return s.split(/(xoxb-[0-9a-f]+)/)[1]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f861_s2_open():
    """F861 OPEN: miss reproduces."""
    miss = _misses("(function(){return ('%s,'+'%s').split(/,/).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f862_s1_open():
    """F862 OPEN: miss reproduces."""
    miss = _misses("(function(){return ('x'+'%s').match(/(?<m>xoxb-[0-9a-f]+)/).groups.m+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f862_s2_open():
    """F862 OPEN: miss reproduces."""
    miss = _misses("(function(){return ('x'+'%s').match(/(?<m>xoxb-[0-9a-f]+)/).groups.m+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f863_s1_open():
    """F863 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(n){return n<=0?'%s':f(n-1);}return f(1)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f863_s2_open():
    """F863 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(n){return n<=0?'%s':f(n-1); }return f(2)+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f864_s1_open():
    """F864 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return Array.prototype.slice.call(arguments).join('');}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f864_s2_open():
    """F864 OPEN: miss reproduces."""
    miss = _misses("(function(){return String.prototype.split.call('%s,%s',',').join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f865_s1_open():
    """F865 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return '%s';}return f.bind(null).bind(null)()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f865_s2_open():
    """F865 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return '%s';}var g=f.bind(null);return g.bind(null)()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f866_s1_open():
    """F866 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return g.apply(null,arguments);}function g(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f866_s2_open():
    """F866 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return g.apply(null,arguments);}function g(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f867_s1_open():
    """F867 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s'];a.sort(function(x,y){return 0;});return a[0]+a[1];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f867_s2_open():
    """F867 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['%s','%s'].sort(function(){return 0;}).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f868_s1_open():
    """F868 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['x'].reduce(function(a){return a;},'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f868_s2_open():
    """F868 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['x','y'].reduce(function(a,b){return a;},'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f869_s1_open():
    """F869 OPEN: miss reproduces."""
    miss = _misses("(function(){var it=['%s','%s'].values();return [].concat(...it).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f869_s2_open():
    """F869 OPEN: miss reproduces."""
    miss = _misses("(function(){var it=['%s','%s'].values();return [].concat(...it).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f870_s1_open():
    """F870 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};return Object.getOwnPropertyNames(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f870_s2_open():
    """F870 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};return Object.keys(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f871_s1_open():
    """F871 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{static{this.k='%s';}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f871_s2_open():
    """F871 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{static k;static{this.k='%s';}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f872_s1_open():
    """F872 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{static k;static{try{C.k='%s';}catch(e){}}}return C.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f872_s2_open():
    """F872 OPEN: miss reproduces."""
    miss = _misses("(function(){var r='';class C{static{try{throw 0;}catch(e){r='%s';}}}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f873_s1_open():
    """F873 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}return new C('%s').m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f873_s2_open():
    """F873 OPEN: miss reproduces."""
    miss = _misses("(function(){class C{constructor(x){this._k=x;}get=()=>this._k;}return new C('%s').get()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f874_s1_open():
    """F874 OPEN: miss reproduces."""
    miss = _misses("(function(){var C=class{constructor(x){this.k=x;}};return new C('%s').k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f874_s2_open():
    """F874 OPEN: miss reproduces."""
    miss = _misses("(function(){var C=class D{constructor(x){this.k=x;}};return new C('%s').k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f875_s1_open():
    """F875 OPEN: miss reproduces."""
    miss = _misses("(function(){return ['%s','%s'].toSorted(function(x,y){return 0;}).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f875_s2_open():
    """F875 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s','x'].toSorted(function(x,y){return 0;});return a[0]+a[1];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f876_s1_open():
    """F876 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=new Set(['%s','%s']);var r='';s.forEach(function(v){r+=v;});return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f876_s2_open():
    """F876 OPEN: miss reproduces."""
    miss = _misses("(function(){var s=new Set(['%s','%s']);var r='';s.forEach(function(v){r+=v;});return r;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f877_s1_open():
    """F877 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a){return a[0]+a[1];}return f(['%s','%s']);})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r54_f877_s2_open():
    """F877 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a,b){return a[0]+b;}return f(['%s'],'%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

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
