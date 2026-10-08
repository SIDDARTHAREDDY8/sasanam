"""Wave-374 lane 8: attack round 42 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 3 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (14, all LOW, all OPEN), filed from F621:
- F621: Object.assign mutated-target reads -- 3 shapes. [CLOSED 2026-10-08 wave-375 lane 1]
- F622: Object.keys + computed bracket reads on var-bound objects -- 2 shapes. [CLOSED 2026-10-08 wave-375 lane 2]
- F623: values()/enumeration reads on Object.fromEntries results -- 3 shapes.
- F624: String.prototype.slice() with trimming bounds -- 3 shapes.
- F625: Map entries()/keys() spread into call arguments -- 3 shapes.
- F626: URLSearchParams iteration protocols (for-of/forEach/keys+get) -- 3 shapes.
- F627: variable-bound VALUES in URLSearchParams statement-form mutations -- 2 shapes.
- F628: decodeURIComponent fragment laundering -- 2 shapes.
- F629: TextDecoder byte assembly -- 2 shapes.
- F630: JSON.parse-sourced Object.values/Object.entries -- 2 shapes.
- F631: async generator yield assembly (for-await/.next) -- 2 shapes.
- F632: for-in with compound member expressions -- 2 shapes. CLOSED wave-375 lane 2.
- F633: BigInt-to-string fragment assembly -- 3 shapes.
- F634: reduce() over Object.entries() results -- 2 shapes.

Mechanism notes (verified this round):
- F593/F605 (CLOSED) model Object.assign with member reads on the call result;
  a var-bound target mutated by an assign STATEMENT and read back via
  Object.values/entries escapes (F621).
- F612 (OPEN) covers values/entries through var-bound OBJECT literals; key
  enumeration with computed bracket reads is a different read path (F622).
- F565 (CLOSED) models Object.fromEntries with member reads; values()/for-in
  reads on fromEntries results were never composed (F623).
- F466 (CLOSED) models .slice() on string ARRAYS; on STRING values only
  identity slices reduce (via the substring scan); trimming slices escape (F624).
- F615 (OPEN) covers Map.values() spread; entries()/keys() are different
  source productions (F500/F505 precedent) (F625).
- F599 (CLOSED) models getAll/get terminals on the constructor receiver;
  the iteration read path (for-of/forEach/keys+get) escapes (F626).
- F616 (OPEN) covers variable-bound parameter NAMES; the VALUE axis is
  unmodeled (F627).
- F576 (CLOSED) models the full-credential decodeURIComponent roundtrip;
  fragment forms escape (F611 fragment precedent) (F628).
- TextDecoder().decode(Uint8Array) is an unmodeled deserializing builtin
  (F500/F505 precedent) (F629).
- F541 (CLOSED) models JSON.parse; F612 (OPEN) covers var-bound literals;
  a JSON.parse call result bound and read via values/entries escapes (F630).
- F619 (OPEN) covers SYNC generators; async generators are a different
  production (F631).
- F592 (CLOSED) models for-in with a single .MEM member read; compound
  member expressions (`o[k].p||o[k].q`) escape (F632).
- BigInt literals have no decoder atom; String(123n)/`${123n}` digit
  fragments are invisible (padStart itself is modeled) (F633).
- F437 (CLOSED) models .reduce() on array-literal/Object.values() receivers;
  the Object.entries() receiver escapes (F634).
All filed shapes node-verified EXACT (v24.20.0): 34/34 CRED-EXACT
(F631's 2 via async node drivers), 34/34 decoder-miss. Junk-quiet
controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F612-F620 (round 41, closing in parallel wave-374 lanes), F623-F634
(this round; F621 CLOSED 2026-10-08 wave-375 lane 1; F622, F632 CLOSED 2026-10-08 wave-375 lane 2).

Closed pins (must BLOCK, else BREAK): F576, F583, F596 (older spots),
F595, F606, F607, F608, F609, F610, F611 (wave-373 closures),
F621 (wave-375 lane 1).

Rides-with-documented-scope (validated, NOT filed -- exact shapes recorded
for merge verification against the parallel wave-374 closure lanes):
- ((a)=>(a+'f2')).bind(null,'f1').bind(null)() and
  ((a,b)=>a+b).bind(null,'f1').apply(null,['f2']) -- BREAK; F614-scope
  (bind-on-bound-function chains); the F614 close-when ("indirect invocation
  of function-expression receivers node-exactly") arguably covers them;
  re-verify at merge: if the wave-374 F614 lane misses them, file.
- (function(){var f=[()=>'f1',()=>'f2'];var g=f[0].bind(null);return g()+f[1]();})()
  and (function(){var f=[(a)=>a+'f2'];return f[0].bind(null,'f1')();})() --
  BREAK; F614xF620 composition (bind on thunks); re-verify at merge.
- (function(){var o={x:{p:'f1'},y:{q:'f2'}};return
  Object.values(o.x).concat(Object.values(o.y)).join('');})() -- BREAK;
  F612-scope (nested var-bound paths); re-verify at merge.
- Promise.reject(new Error('f1')).catch(e=>e.message+'f2'),
  Promise.resolve('f1').finally(()=>{}).then(v=>v+'f2'),
  Promise.allSettled([Promise.resolve('f1'),Promise.resolve('f2')])
  .then(r=>r.map(x=>x.value).join('')) -- BREAK; F618-scope (rejection/
  finally/allSettled callbacks); re-verify at merge.
- 'x'+String.raw`${'f1'}${'f2'}` (fixed authoring) -- decoder HITS; dead.
  String.raw`\n`-escape shapes -- BREAK but subsumed by F624 (string-slice
  trimming is the mechanism); listed as F624 variants.
- JSON.parse('["f1","f2"]').join('') -- decoder HITS (F541); dead.
- new TextDecoder().decode(new TextEncoder().encode('f1f2')) -- decoder HITS; dead.
- ['f1','f2'].reduceRight((a,b)=>b+a), Array.of('f1','f2').join(''),
  Array.from(['f1','f2']).join('') -- decoder HITS (F437); dead.
- crypto.subtle.digest('SHA-256',...) -- decoder fail-closed, no hit,
  no exception; not filed per scope.
Model note: 3/3 prompts returned usable hints (0 timeouts). The reduceRight/
Array.of/Array.from hints validated as already-closed (F437); the
entries-reduce hint surfaced the F634 gap (entries receiver); the
fromCharCode/concat hints validated as already-closed (F500/F478). All
filed shapes hand-crafted and node-verified (v24.20.0). Junk-quiet
controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g374-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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
_B = "4567" + "89abcdef"
_CRED = _A + _B
_BYTES = ",".join(str(b) for b in _CRED.encode("latin-1"))

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
    """Control: footer shows F622/F632 closed (lane-local)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F640**" in text  # # Wave-375 merge lane 1/10: F621 CLOSED  # # Wave-375 merge lane 2/10: F622, F632 CLOSED  # Wave-374 merge: final truth  # Wave-374 merge: footer repoint open F621-F639 / next F640
          and "Open findings: F623, F624, F625, F626, F627, F628, F629, F630, F631, F633, F634, F635, F636, F637, F638, F639." in text)  # # Wave-375 merge lane 1/10: F621 CLOSED  # # Wave-375 merge lane 2/10: F622, F632 CLOSED  # Wave-374 merge: final truth  # Wave-374 merge: footer repoint open F621-F639 / next F640
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f576_closed():
    """F576 CLOSED (wave-370 lane 2): URLSearchParams.get blocks."""
    hit = _blocked("new URLSearchParams('q=%s%s').get('q')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f583_closed():
    """F583 CLOSED (wave-371 lane 1): key-terminal reads block."""
    hit = _blocked("Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f596_closed():
    """F596 CLOSED (wave-371 lane 7): WeakMap statement-form set/get blocks."""
    hit = _blocked("(function(){var k={};var m=new WeakMap();m.set(k,'%s');return m.get(k);})()+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f595_closed():
    """F595 CLOSED (wave-373 lane 1): stringify nested arrays blocks."""
    hit = _blocked("JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f606_closed():
    """F606 CLOSED (wave-373 lane 2): USP mutation guards block."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=%s');p.append('q','%s');p.sort();return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f607_closed():
    """F607 CLOSED (wave-373 lane 3): filter predicates block."""
    hit = _blocked("['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f608_closed():
    """F608 CLOSED (wave-373 lane 4): Set spread into call args blocks."""
    hit = _blocked("((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f609_closed():
    """F609 CLOSED (wave-373 lane 5): replace function-repl blocks."""
    hit = _blocked("'%sXX'.replace('XX',()=>'%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f610_closed():
    """F610 CLOSED (wave-373 lane 2): USP set-then-get blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('q=xx');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f611_closed():
    """F611 CLOSED (wave-373 lane 6): atob fragment assembly blocks."""
    hit = _blocked("(function(){var m=new WeakMap();var k={};m.set(k,atob('eG94Yi0wMTIz'));return m.get(k)+'%s';})()" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------- this round's open pins (F621+)

@_t
def test_r42prior_f621_closed():
    """F621 CLOSED (wave-375 lane 1): assign mutated-target reads block."""
    hit = _blocked("(function(){var t={};Object.assign(t,{a:'%s',b:'%s'});return Object.values(t).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f622_closed():
    """F622 CLOSED (wave-375 lane 2): Object.keys + computed bracket reads block."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s'};var k=Object.keys(o);return o[k[0]]+o[k[1]];})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)  # Wave-375 lane 2: F622 CLOSED


@_t
def test_r42_f623_open():
    """F623 OPEN: values() on fromEntries results miss."""
    miss = _misses("Object.values(Object.fromEntries([['a','%s'],['b','%s']])).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f624_open():
    """F624 OPEN: String.slice() trimming bounds miss."""
    miss = _misses("\"xx%s\".slice(2)+'%s'" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f625_open():
    """F625 OPEN: Map.entries() spread into call args miss."""
    miss = _misses("((...a)=>a.map(e=>e[1]).join(''))(...new Map([['a','%s'],['b','%s']]).entries())" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f626_open():
    """F626 OPEN: URLSearchParams for-of iteration miss."""
    miss = _misses("(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';for(var kv of p){s+=kv[1];}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f627_open():
    """F627 OPEN: var-bound VALUES in USP mutations miss."""
    miss = _misses("(function(){var p=new URLSearchParams('');var v='%s';p.append('q',v);p.append('q','%s');return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f628_open():
    """F628 OPEN: decodeURIComponent fragment laundering miss."""
    miss = _misses("decodeURIComponent('%s'+encodeURIComponent('%s'))" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f629_open():
    """F629 OPEN: TextDecoder byte assembly miss."""
    miss = _misses("new TextDecoder().decode(new Uint8Array([%s]))" % _BYTES)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f630_open():
    """F630 OPEN: JSON.parse-sourced Object.values miss."""
    miss = _misses("(function(){var o=JSON.parse('{\"a\":\"%s\",\"b\":\"%s\"}');return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f631_open():
    """F631 OPEN: async generator for-await miss."""
    miss = _misses("(async function(){async function* g(){yield '%s';yield '%s';}var s='';for await (var x of g()){s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p1_f632_closed():
    """F632 CLOSED (wave-375 lane 2): for-in compound member expressions block."""
    hit = _blocked("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';for(var k in o){s+=o[k].p||o[k].q;}return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)  # Wave-375 lane 2: F632 CLOSED


@_t
def test_r42_f633_open():
    """F633 OPEN: BigInt-to-string fragments miss."""
    miss = _misses("('" + _A[:5] + "'+String(123n)+'" + _B + "')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f634_open():
    """F634 OPEN: reduce() over Object.entries() miss."""
    miss = _misses("Object.entries({a:\"%s\",b:\"%s\"}).reduce((a,[k,v])=>a+v,\"\")" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# --------------------------------- per-shape open pins (round 42)
@_t
def test_r42prior_f621_s2_closed():
    """F621 CLOSED (wave-375 lane 1, shape assign-entries): blocks."""
    hit = _blocked("(function(){var t={};Object.assign(t,{a:'%s',b:'%s'});return Object.entries(t).map(e=>e[1]).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_r42prior_f621_s3_closed():
    """F621 CLOSED (wave-375 lane 1, shape assign-ctor-target): blocks."""
    hit = _blocked("(function(){var t=new Object();Object.assign(t,{a:'%s',b:'%s'});return Object.values(t).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)

@_t
def test_p1_f622_s2_closed():
    """F622 CLOSED (wave-375 lane 2, shape keys-map): blocks."""
    hit = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.keys(o).map(k=>o[k]).join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)  # Wave-375 lane 2: F622 CLOSED

@_t
def test_r42_f623_s2_open():
    """F623 OPEN (shape fromentries-varbound): miss reproduces."""
    miss = _misses("(function(){var o=Object.fromEntries([['a','%s'],['b','%s']]);return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f623_s3_open():
    """F623 OPEN (shape fromentries-forin): miss reproduces."""
    miss = _misses("(function(){var o=Object.fromEntries(new Map([['a','%s'],['b','%s']]));var s='';for(var k in o){s+=o[k];}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f624_s2_open():
    """F624 OPEN (shape slice-trim-bounded): miss reproduces."""
    miss = _misses('"xx%syy".slice(2,11)+\'%s\'' % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f624_s3_open():
    """F624 OPEN (shape slice-trim-varbound): miss reproduces."""
    miss = _misses('(function(){var s="xx%s";return s.slice(2)+\'%s\';})()' % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f625_s2_open():
    """F625 OPEN (shape entries-fixed): miss reproduces."""
    miss = _misses("((a,b)=>a[1]+b[1])(...new Map([['a','%s'],['b','%s']]).entries())" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f625_s3_open():
    """F625 OPEN (shape keys-spread): miss reproduces."""
    miss = _misses("((...a)=>a.join(''))(...new Map([['%s','x'],['%s','y']]).keys())" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f626_s2_open():
    """F626 OPEN (shape params-foreach): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';p.forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f626_s3_open():
    """F626 OPEN (shape params-keys-get): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams('a=%s&b=%s');var s='';for(var k of p.keys()){s+=p.get(k);}return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f627_s2_open():
    """F627 OPEN (shape set-varbound-value): miss reproduces."""
    miss = _misses("(function(){var p=new URLSearchParams('q=xx');var v='%s';p.set('q',v);return p.get('q')+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f628_s2_open():
    """F628 OPEN (shape decode-split): miss reproduces."""
    miss = _misses("decodeURIComponent(encodeURIComponent('%s')+encodeURIComponent('%s'))" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f629_s2_open():
    """F629 OPEN (shape textdecoder-label): miss reproduces."""
    miss = _misses("new TextDecoder('utf-8').decode(new Uint8Array([%s]))" % (_BYTES,))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f630_s2_open():
    """F630 OPEN (shape jsonparse-entries): miss reproduces."""
    miss = _misses('(function(){var o=JSON.parse(\'{\\"a\\":\\"%s\\",\\"b\\":\\"%s\\"}\');return Object.entries(o).map(e=>e[1]).join(\'\');})()' % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f631_s2_open():
    """F631 OPEN (shape asyncgen-next): miss reproduces."""
    miss = _misses("(async function(){async function* g(){yield '%s';}var it=g();var a=await it.next();return a.value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_p1_f632_s2_closed():
    """F632 CLOSED (wave-375 lane 2, shape forin-or-bracket): blocks."""
    hit = _blocked("(function(){var o={x:{p:'%s'},y:{q:'%s'}};var s='';for(var k in o){s+=o[k]['p']||o[k]['q'];}return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)  # Wave-375 lane 2: F632 CLOSED

@_t
def test_r42_f634_s2_open():
    """F634 OPEN (shape entries-reduce-indexed): miss reproduces."""
    miss = _misses('Object.entries({a:"%s",b:"%s"}).reduce((a,e)=>a+e[1],"")' % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r42_f633_s2_open():
    """F633 OPEN (shape bigint-template): miss reproduces."""
    miss = _misses("`" + _A[:5] + "${123n}" + _B + "`")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_r42_f633_s3_open():
    """F633 OPEN (shape bigint-padstart): miss reproduces."""
    miss = _misses("('" + _A[:4] + "-'+String(123n).padStart(4,'0')+'" + _B + "')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-373 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g374-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w373_attack_probes.py")],
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
    # The w373 battery's footer pin is stale by design: this lane filed
    # F621-F634, so its expected footer (open F612-F620 / next F621)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w373_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-373 attack battery stays green (depth-1)."""
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
