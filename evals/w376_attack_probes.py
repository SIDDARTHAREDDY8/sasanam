#!/usr/bin/env python3
"""Wave-376 lane 5: attack round 44 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 2 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (10, all LOW, all OPEN), filed from F644:
- F644: object/array-pattern destructuring of literal sources -- 3 shapes.
- F645: function default-parameter fragment assembly -- 3 shapes.
- F646: Array.prototype.forEach accumulation -- 3 shapes.
- F647: nullish-coalescing RIGHT-pick fragment assembly -- 3 shapes.
- F648: URLSearchParams no-arg constructor + append + getAll().join() -- 3 shapes.
- F649: structuredClone-sourced enumeration / var-bound member reads -- 3 shapes.
- F650: object-spread-assembled enumeration sources -- 3 shapes.
- F651: Array .entries()/.values()/.keys() for-of assembly -- 3 shapes.
- F652: comma/sequence expressions in additive position -- 3 shapes.
- F653: custom Symbol.iterator spread/for-of/Array.from -- 3 shapes.

Mechanism notes (verified this round):
- F545 (CLOSED) models object-pattern destructuring of `arguments` and F524
  array-pattern destructuring of `arguments`; destructuring a LITERAL source
  ({a,b}={...}, [a,b]=[...]) is a new source class (F644). Distinct.
- F612 (CLOSED) documents 'named functions/params' as a fail-closed residual
  of its var-binding production; default parameter values in a no-arg IIFE
  are a distinct binding production (F645). The with-args twin is a
  documented F612 boundary ('non-empty call args'), not filed.
- F601 (CLOSED) models Map.prototype.forEach; Array.prototype.forEach is a
  different receiver/callback signature (F646). Distinct.
- F490 (CLOSED) models (LEFT ?? RIGHT) only for method-reference LEFT
  (picks LEFT); the nullish-LEFT branch picking RIGHT is unmodeled (F647).
  A whole credential in RIGHT still blocks via the literal scan -- the gap
  is specifically the split across ??.
- F599 (CLOSED) requires `new URLSearchParams('LIT')`; the no-argument
  constructor with the same appends + getAll('k').join('') escapes (F648).
  set/get terminals on the no-arg form already block.
- F536 (CLOSED) models INLINE direct member reads on structuredClone;
  var-bound intermediates (var o=structuredClone(...); o.a+o.b) and
  Object.values()/entries() over structuredClone sources escape (F649).
- F510/F612 model plain-literal enumeration sources (inline/var-bound);
  spread-assembled literals ({...{a:'f1'},...{b:'f2'}}) are a new source
  production (F650). Distinct.
- F622 (Object.keys) / F632 (for-in) model enumeration; the Array iterator
  methods .entries()/.values()/.keys() with for-of are unmodeled (F651).
All filed shapes node-verified EXACT (v24.20.0): 30/30 CRED-EXACT,
30/30 decoder-miss. Junk-quiet controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F640-F643 (round 43), F644-F653 (this round).

Closed pins (must BLOCK, else BREAK): F510, F536, F545, F599, F601, F612.

Rides-with-documented-scope (validated, NOT filed):
- Ternary `(true?'f1':'x')+'f2'` -- BREAK, but general conditional
  expressions are a deliberate scope boundary (the decoder is a bounded
  expression decoder; F597 covers ternary only inside flatMap callbacks).
  Not filed.
- while-loop / switch-statement / with-statement fragment assembly --
  all BREAK, but statement-level control flow is outside the bounded
  expression-decoder seam. Not filed.
- class private-field reads (`this.#x`) -- BREAK, but class semantics are
  outside the seam. Not filed.
- F639 residual: 3-level literal paths Object.values(o.x.y) -- BREAK but
  DOCUMENTED RESIDUAL of F639 ('two-level paths (o.x.y)' fail closed);
  not filed.
- F619 residual: `.next().value` chained reads -- BREAK but DOCUMENTED
  RESIDUAL of F619; not filed.
- F630 residual: JSON.parse with reviver -- BREAK but DOCUMENTED RESIDUAL
  of F630 ('revivers fail closed'); not filed.
- F612 residuals: multi-decl `var a='f1',b='f2'` ('multi-decl'), default
  params with non-empty call args ('non-empty call args') -- verified
  fail-closed/miss as documented; not filed.
- BigInt atom (`String(123n)`, `(123n).toString()`, bigint+bigint) -- all
  HELD now (F633 CLOSED, wave-375 lane 4); atom closure verified.
- String.raw with substitutions, `new Function`, `.substr()`/`.substring()`,
  `.trim()`, `decodeURI`, `unescape`, `atob`, rest-spread `(...a)=>a.join('')`,
  `(x='f1'+'f2',x)` comma-first-operand -- all HELD; correctly modeled.
- USP no-arg set/get terminals, `(null??'FULLCRED')` whole-credential RIGHT,
  `['f1','f2'].reduce((a,x)=>a+x,'')`, `Array.from(arr,x=>x).join('')`,
  `[[..]].flat().join('')`, class getters/statics, `.match()` groups,
  `.padStart()`, `?.` optional chaining -- all HELD; correctly modeled.
Dead probes -- "Not filed (validated)":
- `String.raw` backtick-with-substitution probe -- malformed template
  (extra literal chars); discarded, not a decoder signal.
- Uint8-fromCharCode probe with wrong code units -- malformed; discarded.
- Destructuring-with-default probe `{a=' f1'}` -- malformed (stray space
  broke the key); discarded.
Model note: 2/2 prompts returned usable hints (0 timeouts). The
default-params and forEach hints confirmed locally-probed gaps; the
String.raw/reduce/map/flat/Object.values hints validated as already-held.
All filed shapes hand-crafted and node-verified (v24.20.0). Junk-quiet
controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g376-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (model spend $0.000225
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

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
    """Control: footer shows F644-F646/F648-F651/F653-F655 open, next F656 (this lane)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F656**" in text  # Wave-377 lane 4: F655 FILED OPEN
          and "Open findings: F644, F645, F646, F648, F649, F650, F651, F653, F654, F655." in text)  # Wave-377 lane 4: F655 FILED OPEN
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f510_closed():
    """F510 CLOSED: inline plain-literal values() blocks."""
    hit = _blocked("(function(){return Object.values({a:'%s',b:'%s%s'}).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f536_closed():
    """F536 CLOSED: inline structuredClone member read blocks."""
    hit = _blocked("(function(){return structuredClone({c:'%s'}).c+'%s%s';})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f545_closed():
    """F545 CLOSED: object-pattern destructuring of arguments blocks."""
    hit = _blocked("(function(){const {0:a,1:b}=arguments;return a+b;})('%s','%s%s')"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f599_closed():
    """F599 CLOSED: append mutations on literal-ctor params block."""
    hit = _blocked("(function(){var p=new URLSearchParams('');p.append('q','%s');p.append('q','%s%s');return p.getAll('q').join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f601_closed():
    """F601 CLOSED: Map.prototype.forEach accumulation blocks."""
    hit = _blocked("(function(){var s='';new Map([['a','%s'],['b','%s%s']]).forEach(function(v){s+=v;});return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f612_closed():
    """F612 CLOSED: var-bound values() blocks."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s',c:'%s'};return Object.values(o).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F640 open pins (must miss)

@_t
def test_r43_f640_s1_closed():
    """F640 CLOSED (wave-376 lane 1) (shape forawait-accumulate): now blocked."""
    hit = _blocked("(async()=>{var s='';for await (const x of ['%s','%s','%s']) s+=x; return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f640_s2_closed():
    """F640 CLOSED (wave-376 lane 1) (shape forawait-push-join): now blocked."""
    hit = _blocked("(async()=>{var p=[];for await (const x of ['%s','%s','%s']) p.push(x); return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f640_s3_closed():
    """F640 CLOSED (wave-376 lane 1) (shape forawait-map-values): now blocked."""
    hit = _blocked("(async()=>{var s='';for await (const x of new Map([['a','%s'],['b','%s'],['c','%s']]).values()) s+=x; return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F641 open pins (must miss)

@_t
def test_r43_f641_s1_closed():
    """F641 CLOSED (wave-376 lane 2) (shape microtask-assembly): now blocked."""
    hit = _blocked("(async()=>{var p=[];queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));await null;return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s2_closed():
    """F641 CLOSED (wave-376 lane 2) (shape microtask-nested): now blocked."""
    hit = _blocked("(async()=>{var p=[];queueMicrotask(()=>{p.push('%s');queueMicrotask(()=>p.push('%s'+'%s'));});await null;await null;return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s3_closed():
    """F641 CLOSED (wave-376 lane 2) (shape microtask-promise-flush): now blocked."""
    hit = _blocked("(async()=>{var s='';queueMicrotask(()=>{s+='%s';});queueMicrotask(()=>{s+='%s'+'%s';});await Promise.resolve();return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f641_s4_closed():
    """F641 CLOSED (wave-376 lane 2) (shape timeout-assembly): now blocked."""
    hit = _blocked("(async()=>{var p=[];setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);await new Promise(r=>setTimeout(r,20));return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F642 open pins (must miss)

@_t
def test_r43_f642_s1_closed():
    """F642 CLOSED (wave-376 lane 3) (shape getter-varfrags): now blocked."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var o={get s(){return a+b+c;}};return o.s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f642_s2_closed():
    """F642 CLOSED (wave-376 lane 3) (shape proxy-get-trap-varfrags): now blocked."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var p=new Proxy({},{get:(t,k)=>a+b+c});return p.anything;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f642_s3_closed():
    """F642 CLOSED (wave-376 lane 3) (shape weakref-deref-getter-varfrags): now blocked."""
    hit = _blocked("(function(){var a='%s',b='%s',c='%s';var w=new WeakRef({get s(){return a+b+c;}});return w.deref().s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F643 open pins (must miss)

@_t
def test_r43_f643_s1_closed():
    """F643 CLOSED (wave-376 lane 4) (shape fromcharcode-u8-spread): now blocked."""
    hit = _blocked("String.fromCharCode(...new Uint8Array([%s]))+'%s'"
                   % (",".join(str(b) for b in (_F1 + _F2).encode("latin-1")), _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f643_s2_closed():
    """F643 CLOSED (wave-376 lane 4) (shape fromcharcode-u8-apply): now blocked."""
    hit = _blocked("String.fromCharCode.apply(null,new Uint8Array([%s]))+'%s'"
                   % (",".join(str(b) for b in (_F1 + _F2).encode("latin-1")), _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r43_f643_s3_closed():
    """F643 CLOSED (wave-376 lane 4) (shape fromcodepoint-u8-spread): now blocked."""
    hit = _blocked("String.fromCodePoint(...new Uint8Array([%s]))+'%s'"
                   % (",".join(str(b) for b in (_F1 + _F2).encode("latin-1")), _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

# ------------------------------------------------- F644 open pins (must miss)

@_t
def test_r44_f644_s1_open():
    """F644 OPEN (shape destructure-object-shorthand): miss reproduces."""
    miss = _misses("(function(){var {a,b}={a:'%s',b:'%s%s'};return a+b;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f644_s2_open():
    """F644 OPEN (shape destructure-object-rename): miss reproduces."""
    miss = _misses("(function(){var {a:x,b:y}={a:'%s',b:'%s%s'};return x+y;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f644_s3_open():
    """F644 OPEN (shape destructure-array-literal): miss reproduces."""
    miss = _misses("(function(){var [a,b]=['%s','%s%s'];return a+b;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F645 open pins (must miss)

@_t
def test_r44_f645_s1_open():
    """F645 OPEN (shape default-params-noarg): miss reproduces."""
    miss = _misses("(function(s='%s',t='%s%s'){return s+t;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f645_s2_open():
    """F645 OPEN (shape default-params-undefined): miss reproduces."""
    miss = _misses("(function(s='%s',t='%s%s'){return s+t;})(undefined,undefined)"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f645_s3_open():
    """F645 OPEN (shape default-params-destructured): miss reproduces."""
    miss = _misses("(function({a,b}={a:'%s',b:'%s%s'}){return a+b;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F646 open pins (must miss)

@_t
def test_r44_f646_s1_open():
    """F646 OPEN (shape foreach-push-join): miss reproduces."""
    miss = _misses("(function(){var p=[];['%s','%s%s'].forEach(function(x){p.push(x);});return p.join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f646_s2_open():
    """F646 OPEN (shape foreach-accumulate): miss reproduces."""
    miss = _misses("(function(){var s='';['%s','%s%s'].forEach(function(x){s+=x;});return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f646_s3_open():
    """F646 OPEN (shape foreach-arrow): miss reproduces."""
    miss = _misses("(function(){var s='';['%s','%s%s'].forEach((x)=>{s+=x;});return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F647 closed pins (must block; wave-377 lane 4)

@_t
def test_r44_f647_s1_closed():
    """F647 CLOSED (shape nullish-null-left): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){return (null??'%s')+'%s%s';})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r44_f647_s2_closed():
    """F647 CLOSED (shape nullish-void-left): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){return (void 0??'%s')+'%s%s';})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r44_f647_s3_closed():
    """F647 CLOSED (shape nullish-undef-var): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){var z;return (z??'%s')+'%s%s';})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F648 open pins (must miss)

@_t
def test_r44_f648_s1_open():
    """F648 OPEN (shape usp-noarg-getall-join): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s%s');return p.getAll('q').join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f648_s2_open():
    """F648 OPEN (shape usp-noarg-three-appends): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s');p.append('q','%s');return p.getAll('q').join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f648_s3_open():
    """F648 OPEN (shape usp-noarg-getall-map): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s%s');return p.getAll('q').map(function(x){return x;}).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F649 open pins (must miss)

@_t
def test_r44_f649_s1_open():
    """F649 OPEN (shape sclone-varbound-members): miss reproduces."""
    miss = _misses("(function(){var o=structuredClone({a:'%s',b:'%s%s'});return o.a+o.b;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f649_s2_open():
    """F649 OPEN (shape sclone-inline-values): miss reproduces."""
    miss = _misses("(function(){return Object.values(structuredClone({a:'%s',b:'%s%s'})).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f649_s3_open():
    """F649 OPEN (shape sclone-varbound-values): miss reproduces."""
    miss = _misses("(function(){var o=structuredClone({a:'%s',b:'%s%s'});return Object.values(o).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F650 open pins (must miss)

@_t
def test_r44_f650_s1_open():
    """F650 OPEN (shape spread-varbound-values): miss reproduces."""
    miss = _misses("(function(){var o={...{a:'%s'},...{b:'%s%s'}};return Object.values(o).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f650_s2_open():
    """F650 OPEN (shape spread-inline-values): miss reproduces."""
    miss = _misses("(function(){return Object.values({...{a:'%s'},...{b:'%s%s'}}).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f650_s3_open():
    """F650 OPEN (shape spread-varbound-entries): miss reproduces."""
    miss = _misses("(function(){var o={...{a:'%s'},...{b:'%s%s'}};return Object.entries(o).map(function(e){return e[1];}).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F651 open pins (must miss)

@_t
def test_r44_f651_s1_open():
    """F651 OPEN (shape array-entries-forof): miss reproduces."""
    miss = _misses("(function(){var s='';for(var _e of ['%s','%s%s'].entries()){s+=_e[1];}return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f651_s2_open():
    """F651 OPEN (shape array-values-forof): miss reproduces."""
    miss = _misses("(function(){var s='';for(var x of ['%s','%s%s'].values()){s+=x;}return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f651_s3_open():
    """F651 OPEN (shape array-keys-index): miss reproduces."""
    miss = _misses("(function(){var fr=['%s','%s%s'];var s='';for(var i of fr.keys()){s+=fr[i];}return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- F652 closed pins (must block; wave-377 lane 4)

@_t
def test_r44_f652_s1_closed():
    """F652 CLOSED (shape comma-assign-read): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){var x;return (x='%s',x)+'%s%s';})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r44_f652_s2_closed():
    """F652 CLOSED (shape comma-multi): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){var x,y;return (x='%s',y='%s%s',x+y);})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_r44_f652_s3_closed():
    """F652 CLOSED (shape comma-nested-additive): blocks (wave-377 lane 4)."""
    hit = _blocked("(function(){var x,y;return ((x='%s',x)+(y='%s%s',y));})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F653 open pins (must miss)

@_t
def test_r44_f653_s1_open():
    """F653 OPEN (shape symbol-iterator-spread): miss reproduces."""
    miss = _misses("(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};return [...o].join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f653_s2_open():
    """F653 OPEN (shape symbol-iterator-forof): miss reproduces."""
    miss = _misses("(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};var s='';for(var x of o){s+=x;}return s;})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r44_f653_s3_open():
    """F653 OPEN (shape symbol-iterator-arrayfrom): miss reproduces."""
    miss = _misses("(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};return Array.from(o).join('');})()"
                   % (_F1, _F2, _F3))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-375 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g376-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w375_attack_probes.py")],
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
    # The w375 battery's footer pin is stale by design: this lane filed
    # F644-F653, so its expected footer (open F640-F643 / next F644)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w375_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-375 attack battery stays green (depth-1)."""
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
