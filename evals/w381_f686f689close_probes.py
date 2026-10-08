#!/usr/bin/env python3
"""Wave-381 lane 1: close F686 + F689 (Proxy-trap residuals).

F686 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
Proxy ownKeys-trap key-name laundering -- Object.keys / for-in /
Object.getOwnPropertyNames / Reflect.ownKeys over a proxy whose
ownKeys trap returns fragment key names (4 filed shapes).

F689 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
Proxy Symbol.iterator-trap iterable spread/for-of -- the get trap
returns a fixed-yield generator as Symbol.iterator; `[...p]` /
for-of iterate it (2 filed shapes).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f686_ownkeys_iife (+ 8 helpers): the ownKeys trap body
  must be exactly `return ['L1',...];` (string literals only,
  duplicate keys fail closed -- node v24.20.0 throws on
  duplicates); the getOwnPropertyDescriptor twin must return
  exactly `{enumerable:true,configurable:true}` (either prop
  order) so all four terminals enumerate exactly the trap's list;
  the proxy target is exactly `{}` (trap invariants then hold
  trivially). Four function/arrow forms + method shorthand per
  trap, handler keys in either order. Terminals: Object.keys(p) /
  Object.getOwnPropertyNames(p) / Reflect.ownKeys(p) joined with
  '' (non-empty separators fail closed), or
  `var s='';for(var k in p){s+=k;}return s;`.
- _js_parse_f689_symiter_iife (+ 6 helpers): the get trap body
  must be exactly `if(k===Symbol.iterator){return
  function*(){<fixed-yield body>};}return t[k];` (2 params, block
  forms + method shorthand; `==` fails closed); the generator
  yields come from _js_parse_f6xx_fixed_yield_body (paren yields,
  ASI, yield* delegation, trailing return skipped; empty body
  yields nothing -- node-exact). Proxy target `[]` or `{}` (both
  node-verified: the iteration path never consults the target).
  Terminals: `return [...p].join('');` or
  `var s='';for(var x of p){s+=x;}return s;`.
Both hooked after F675 in _js_parse_primary (disjoint by trap
key / handler shape; F642 requires a literal binding section +
additive trap body, F666 requires apply/has, F675 requires
set/construct/deleteProperty/getPrototypeOf keys or the revocable
head).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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

TAXONOMY_PIN = 2143  # no new decision codes this lane

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


# ------------------------------------------------ p1: filed shapes (must block, node-exact)

@_t
def test_p1_f686_filed():
    """F686's 4 filed shapes block and decode node-exactly."""
    shapes = [
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.keys(p).join('');})()"),
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "var s='';for(var k in p){s+=k;}return s;})()"),
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.getOwnPropertyNames(p).join('');})()"),
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Reflect.ownKeys(p).join('');})()"),
    ]
    want = _A + _B
    got = [(_blocked(s % (_A, _B)) and _decodes_exact(s % (_A, _B), want))
           for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "filed=%s" % got)


@_t
def test_p1_f689_filed():
    """F689's 2 filed shapes block and decode node-exactly."""
    shapes = [
        ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "return [...p].join('');})()"),
        ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "var s='';for(var x of p){s+=x;}return s;})()"),
    ]
    want = _A + _B
    got = [(_blocked(s % (_A, _B)) and _decodes_exact(s % (_A, _B), want))
           for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "filed=%s" % got)


# ------------------------------------------------ p2: variants (must block, node-exact)

@_t
def test_p2_f686_variants():
    """F686 form variants: arrows, method shorthand, key/prop order."""
    shapes = [
        # concise arrows
        ("(function(){const p=new Proxy({},{ownKeys:()=>['%s','%s'],"
         "getOwnPropertyDescriptor:()=>({enumerable:true,configurable:true})});"
         "return Object.keys(p).join('');})()"),
        # block arrow ownKeys + function gOPD
        ("(function(){let p=new Proxy({},{ownKeys:()=>{return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.getOwnPropertyNames(p).join('');})()"),
        # method shorthand, swapped prop order
        ("(function(){var p=new Proxy({},{ownKeys(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor(){return {configurable:true,enumerable:true};}});"
         "return Reflect.ownKeys(p).join('');})()"),
        # handler keys in reverse order
        ("(function(){var p=new Proxy({},{getOwnPropertyDescriptor:function()"
         "{return {enumerable:true,configurable:true};},"
         "ownKeys:function(){return ['%s','%s'];}});"
         "return Object.keys(p).join('');})()"),
        # single key
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object.keys(p).join('');})()"),
        # whitespace around dots (node-identical member access)
        ("(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},"
         "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
         "return Object. keys(p). join('');})()"),
    ]
    wants = [_A + _B, _A + _B, _A + _B, _A + _B, _A + _B, _A + _B]
    argss = [(_A, _B), (_A, _B), (_A, _B), (_A, _B), (_A + _B,), (_A, _B)]
    got = [(_blocked(s % a) and _decodes_exact(s % a, w))
           for s, w, a in zip(shapes, wants, argss)]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "variants=%s" % got)


@_t
def test_p2_f689_variants():
    """F689 form variants: target/get forms, yield grammars."""
    shapes = [
        # object target
        ("(function(){var p=new Proxy({},{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "return [...p].join('');})()"),
        # method-shorthand get
        ("(function(){var p=new Proxy([],{get(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "return [...p].join('');})()"),
        # block-arrow get
        ("(function(){var p=new Proxy([],{get:(t,k)=>{if(k===Symbol.iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "var s='';for(var x of p){s+=x;}return s;})()"),
        # paren yields + yield* delegation
        ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield ('%s');yield* ['%s'];};}return t[k];}});"
         "return [...p].join('');})()"),
        # trailing return in generator
        ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
         "{return function*(){yield '%s';return;};}return t[k];}});"
         "return [...p].join('');})()"),
        # whitespace around dots (node-identical member access)
        ("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol. iterator)"
         "{return function*(){yield '%s';yield '%s';};}return t[k];}});"
         "return [...p]. join('');})()"),
    ]
    wants = [_A + _B, _A + _B, _A + _B, _A + _B, _A + _B, _A + _B]
    argss = [(_A, _B), (_A, _B), (_A, _B), (_A, _B), (_A + _B,), (_A, _B)]
    got = [(_blocked(s % a) and _decodes_exact(s % a, w))
           for s, w, a in zip(shapes, wants, argss)]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "variants=%s" % got)


# ------------------------------------------------ p3: fail-closed bounds

@_t
def test_p3_f686_bounds():
    """F686 shapes the decoder must refuse (node throws / wrong value)."""
    shapes = [
        # duplicate keys: node throws TypeError
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a','a'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()",
        # non-string element: node throws TypeError
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a',1];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()",
        # missing gOPD twin: Object.keys sees nothing in the engine
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a'];}});"
        "return Reflect.ownKeys(p).join('');})()",
        # non-empty target: trap invariants unmodeled
        "(function(){var p=new Proxy({x:1},{ownKeys:function(){return ['a'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()",
        # non-empty join separator would mis-decode
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a','b'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join(',');})()",
        # extra statements
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "var z=1;return Object.keys(p).join('');})()",
        # gOPD not enumerable: Object.keys excludes the key in the engine
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['a'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:false,configurable:true};}});"
        "return Object.keys(p).join('');})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "bounds=%s" % got)


@_t
def test_p3_f689_bounds():
    """F689 shapes the decoder must refuse."""
    shapes = [
        # loose ==: outside the modeled grammar
        "(function(){var p=new Proxy([],{get:function(t,k){if(k==Symbol.iterator)"
        "{return function*(){yield 'a';};}return t[k];}});return [...p].join('');})()",
        # missing fall-through: grammar requires it
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield 'a';};}}});return [...p].join('');})()",
        # non-generator iterator value
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return ['a'];}return t[k];}});return [...p].join('');})()",
        # spread of a different ident
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield 'a';};}return t[k];}});var q=p;return [...q].join('');})()",
        # for-in over the proxy is the ownKeys path, not the iterator path
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield 'a';};}return t[k];}});"
        "var s='';for(var k in p){s+=k;}return s;})()",
        # generator with params
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(a){yield 'a';};}return t[k];}});return [...p].join('');})()",
        # non-literal yield
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield x;};}return t[k];}});return [...p].join('');})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "bounds=%s" % got)


# ------------------------------------------------ p4: neighbors

@_t
def test_p4_open_neighbors_still_miss():
    """Round-48 findings F687/F688/F690-F699 now CLOSED (wave-381 lanes 2-7); they block (nothing absorbed)."""
    shapes = [
        # F687 WeakSet membership
        ("(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'jx')+'%s';})()" % (_A, _B)),
        # F688 functional replacer
        ("(function(){return 'ab'.replace(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B)),
        # F690 constructor-this
        ("(function(){function C(){this.x='%s';}var c=new C();return c.x+'%s';})()" % (_A, _B)),
        # F691 data-descriptor .value (filed pin)
        ("(function(){var o={};Object.defineProperty(o,'x',{value:'%s',enumerable:true});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B)),
        # F694 match-group reassembly (filed pin)
        ("(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B)),
        # F696 boxed String (filed pin)
        ("(function(){return (new String('%s'))+'%s';})()" % (_A, _B)),
        # F698 defineProperty accessor (filed pin)
        ("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B)),
    ]
    got = [_blocked(s) for s in shapes]
    # F699 >2^53 with-scope: fail-closed (no decode), not a coded block
    got_f699 = _misses("(function(){var o={x:9007199254740993};with(o){return x+'%s';}})()" % _B)
    ok = all(got) and got_f699
    return ("HELD" if ok else "BREAK", "closed-neighbors=%s f699-miss=%s" % (got, got_f699))


@_t
def test_p4_closed_neighbors_still_block():
    """Closed proxy-trap neighbors (F642/F666/F670/F675) still block."""
    shapes = [
        # F642 get trap (filed pin)
        "(function(){var a='%s',b='%s';var p=new Proxy({},{get:(t,k)=>a+b});return p.anything;})()" % (_A, _B),
        # F666 apply trap (filed pin)
        "(function(){var p=new Proxy(function(){},{apply:function(){return '%s%s';}});return p();})()" % (_A, _B),
        # F675 set trap (filed red-first)
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});p.x='%s';return p.x+'%s';})()" % (_A, _B),
        # F675 revocable (filed red-first)
        "(function(){var r=Proxy.revocable({},{get:function(){return '%s';}});return r.proxy.x+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "closed-neighbors=%s" % got)


# ------------------------------------------------ p5: junk quiet

@_t
def test_p5_junk_quiet():
    """No-credential trap shapes stay quiet."""
    shapes = [
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['jx','jy'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "return Object.keys(p).join('');})()",
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['jx'];},"
        "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
        "var s='';for(var k in p){s+=k;}return s;})()",
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield 'jx';yield 'jy';};}return t[k];}});"
        "return [...p].join('');})()",
        "(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
        "{return function*(){yield 'jx';};}return t[k];}});"
        "var s='';for(var x of p){s+=x;}return s;})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: pin, footer, no new regexes

@_t
def test_p6_pin_footer():
    """Pin 2140; lane-local footer (open F687, F688, F690-F699 / next F700)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-381 lane 1: F686+F689 CLOSED; open F687, F688, F690-F699 / next F700  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-381 lane 1: F686+F689 CLOSED; open F687, F688, F690-F699 / next F700  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf

@_t
def test_p7_perf():
    """200 mixed trap sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var p=new Proxy({},{ownKeys:function(){return ['a%d'];},"
                      "getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});"
                      "return Object.keys(p).join('');})()" % k)
        corpus.append("(function(){var p=new Proxy([],{get:function(t,k){if(k===Symbol.iterator)"
                      "{return function*(){yield 'a%d';};}return t[k];}});"
                      "return [...p].join('');})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w380_f686_redfirst.py", 0),
                               ("evals/w380_f689_redfirst.py", 0),
                               ("evals/w380_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g381-green-", dir="/var/tmp")
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
def test_p8_green_check():
    """Depth-1 green check: F686/F689 red-firsts + wave-380 attack battery green."""
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
