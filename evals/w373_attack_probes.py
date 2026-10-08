"""Wave-373 lane 7: attack round 41 (continuous real-model attack).

Filed 2026-10-08 (local node validation on v24.20.0 + 3 gpt-4o-mini calls,
hints only; every filed shape hand-crafted and node-verified).

New findings (9, all LOW, all OPEN), filed from F612:
- F612: var-bound Object.values/Object.entries indirection -- 3 shapes.
- F613: String.raw tag template in non-leading positions -- 3 shapes.
- F614: Function.prototype.call/.apply/.bind on function expressions -- 3 shapes.
- F615: Map.values() spread into call arguments -- 3 shapes.
- F616: variable-bound (non-literal) parameter names in URLSearchParams
  statement-form mutations -- 3 shapes.
- F617: URL.searchParams set/append/delete + get/getAll laundering -- 3 shapes.
- F618: Promise resolution callbacks assemble fragments -- 3 shapes.
- F619: generator yield/spread assembly -- 3 shapes.
- F620: indexed/thunk function invocation assembles fragments -- 3 shapes.

Mechanism notes (verified this round):
- F510 (CLOSED) models Object.values/Object.entries on INLINE literals;
  a var-bound intermediate (`var o=<src>; Object.values(o)`) escapes (F612).
- F463 (CLOSED) models the String.raw tag only in the leading-primary
  position; RHS-of-+, parenthesized, array-element, and template-interp
  positions escape (F613). Leading and substitution forms block coded.
- F478/F482 (OPEN) cover .call/.apply/.bind on prototype-method (dot and
  bracket) receivers; function-expression receivers escape (F614).
- F608 (OPEN) covers Set spread into call args; Map.values() is a
  different source production (F500/F505 precedent) and escapes (F615).
- F599 (CLOSED) models literal-name mutations; variable-bound names
  (`var q='q'`) escape the statement-form model (F616). Non-literal .get
  on constructor strings still fails closed (control).
- F599's residual claimed `new URL(...)` bindings fail closed; the
  `new URL(...).searchParams` receiver production misses entirely (F617).
- Promise.all/.race .then callbacks and async-IIFE awaits assemble
  fragments invisibly (F618); sync generators via spread/for-of/Array.from
  likewise (F619); thunks invoked by index/.map/.forEach likewise (F620).
All filed shapes node-verified EXACT (v24.20.0): 27/27 CRED-EXACT
(F618's 3 via async node drivers), 27/27 decoder-miss. Junk-quiet
controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F595, F606-F611 (prior rounds), F613-F620 (this round; F612 closed
wave-374 lane 1).

Closed pins (must BLOCK, else BREAK): F576, F583, F596 (older spots),
F597, F598, F599, F600, F602, F603, F604, F605 (wave-372 closures),
F612 (wave-374 lane 1).

Rides-with-documented-scope (validated, NOT filed):
- JSON.parse(JSON.stringify([[,'f1'],['f2']])).flat().join('') and the
  flat(2) deeper-nesting twin -- BREAK, but within F595's filed mechanism
  (nested array values); left for wave-373 lane 1's F595 closure; re-verify
  at merge.
- ['f1','f2',''].filter(Boolean).join('') and
  ['f1','f2','xx'].filter((x,i)=>i<2).join('') -- decoder HITS; dead
  (filter identity/index forms modeled; F607's scope is value predicates).
- 'f1XX'.replace('XX',(()=> 'f2').bind(null)) -- BREAK, but within F609's
  close-when ("function-valued replace callbacks"); left for wave-373 lane
  5's F609 closure; re-verify at merge.
- (function(){var p=new URLSearchParams('a=1&q=xx');p.delete('a');
  p.set('q','f1');return p.get('q')+'f2';})() -- BREAK, but an F606xF610
  composition covered by the union of their close-whens; re-verify at merge.
- atob(atob('<double-b64>')) -- decoder HITS; dead (F439 fixpoint pass).
- /(...)(...)/.exec groups, ['f1','f2'].at(0), structuredClone([...]),
  JSON.parse(JSON.stringify(m.get(k))) (F595xF596), weakmap-set-chain --
  decoder HITS or engine-dead; validated.
- new Intl.ListFormat('en',{style:'narrow'}).format(['f1','f2']) -- node
  yields 'f1, f2' (not the credential); dead.
Model note: 3/3 prompts returned usable hints (0 timeouts). The model's
generator/async-iterator/dispatch families independently surfaced the
generator-spread, thunk-index, and bind-arrow shapes filed as
F619/F620/F614; the String.raw-call and filter-identity hints validated as
already-closed scope. All filed shapes hand-crafted and node-verified
(v24.20.0). Junk-quiet controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g373-*
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
    """Control: footer shows F613-F620 open, next F621 (lane-local)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F621**" in text  # Wave-373 merge: attack round 41 filed F612-F620
          and "Open findings: F613, F614, F615, F616, F617, F618, F619, F620." in text)  # Wave-374 lane 1: F612 CLOSED
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
def test_p1_f597_closed():
    """F597 CLOSED (wave-372 lane 1): flatMap scalar callbacks block."""
    hit = _blocked("['%s','%s'].flatMap((x)=>x).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f598_closed():
    """F598 CLOSED (wave-372 lane 2): stringify of derived arrays blocks."""
    hit = _blocked("JSON.parse(JSON.stringify(Array.from(new Set(['%s','%s'])))).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f599_closed():
    """F599 CLOSED (wave-372 lane 3): USP append/set then getAll blocks."""
    hit = _blocked("(function(){var p=new URLSearchParams('');p.append('q','%s');p.append('q','%s');return p.getAll('q').join('');})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f600_closed():
    """F600 CLOSED (wave-372 lane 4): Map keys iteration blocks."""
    hit = _blocked("Array.from(new Map([['%s',1],['%s',2]]).keys()).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f602_closed():
    """F602 CLOSED (wave-372 lane 4): Set iteration blocks."""
    hit = _blocked("(function(){var s='';for(var x of new Set(['%s','%s'])){s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f603_closed():
    """F603 CLOSED (wave-372 lane 5): String.replace literal patterns block."""
    hit = _blocked("'%sX'.replace('X','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f604_closed():
    """F604 CLOSED (wave-372 lane 6): localeCompare sort blocks."""
    hit = _blocked("['%s','%s'].sort((a,b)=>b.localeCompare(a)).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f605_closed():
    """F605 CLOSED (wave-372 lane 6): Object.assign neighbor variants block."""
    hit = _blocked("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);return Object.assign({x:1},m.get(r)).c+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------- closed pins, prior rounds (must block)

@_t
def test_r41prior_f595_closed():
    """F595 CLOSED 2026-10-08 wave-373 lane 1: stringify nested arrays block."""
    m1 = _blocked("JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')" % (_A, _B))
    m2 = _blocked("JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f606_closed():
    """F606 CLOSED 2026-10-08 wave-373 lane 2: USP mutation guards block."""
    m1 = _blocked("(function(){var p=new URLSearchParams('q=%s');p.append('q','%s');p.sort();return p.getAll('q').join('');})()" % (_A, _B))
    m2 = _blocked("(function(){var p=new URLSearchParams('a=1&q=%s');p.append('q','%s');p.delete('a');return p.getAll('q').join('');})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f607_closed():
    """F607 CLOSED 2026-10-08 wave-373 lane 3: filter predicates block."""
    m1 = _blocked("['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A, _B))
    m2 = _blocked("['%s','%s',''].filter(x=>x.length>2).join('')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f608_closed():
    """F608 CLOSED 2026-10-08 wave-373 lane 4: Set spread args block."""
    m1 = _blocked("((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B))
    m2 = _blocked("((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f609_closed():
    """F609 CLOSED 2026-10-08 wave-373 lane 5: replace function block."""
    m1 = _blocked("'%sXX'.replace('XX',()=>'%s')" % (_A, _B))
    m2 = _blocked("'%sXX'.replace(/XX/,()=>'%s')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f610_closed():
    """F610 CLOSED 2026-10-08 wave-373 lane 2: USP set-then-get block."""
    m1 = _blocked("(function(){var p=new URLSearchParams('q=xx');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    m2 = _blocked("(function(){var p=new URLSearchParams('');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)


@_t
def test_r41prior_f611_closed():
    """F611 CLOSED 2026-10-08 wave-373 lane 6: atob fragments block."""
    m1 = _blocked("atob('eG94Yi0wMTIz')+'%s'" % _B)
    m2 = _blocked("(function(){var b=atob('eG94Yi0wMTIz');return b+'%s';})()" % _B)
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "block=%s" % ok)

# ----------------------------------------- prior-open pins now closed

@_t
def test_p1_f612_closed():
    """F612 CLOSED (wave-374 lane 1): var-bound values/entries blocks."""
    h1 = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    h2 = _blocked("(function(){var o=Object.freeze({a:'%s',b:'%s'});return Object.values(o).join('');})()" % (_A, _B))
    h3 = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.entries(o).map(e=>e[1]).join('');})()" % (_A, _B))
    ok = h1 and h2 and h3
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ----------------------------------------- open pins, round 41 (must miss)


@_t
def test_r41_f613_open():
    """F613 OPEN: String.raw tag in non-leading positions misses."""
    m1 = _misses("'" + _A + "'+String.raw`" + _B + "`")
    m2 = _misses("(String.raw`" + _A + "`)+'" + _B + "'")
    m3 = _misses("[String.raw`" + _A + "`,String.raw`" + _B + "`].join('')")
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f614_open():
    """F614 OPEN: .call/.apply/.bind on function expressions misses."""
    m1 = _misses("((a,b)=>a+b).apply(null,['%s','%s'])" % (_A, _B))
    m2 = _misses("((a,b)=>a+b).call(null,'%s','%s')" % (_A, _B))
    m3 = _misses("((a)=>(a+'%s')).bind(null,'%s')()" % (_B, _A))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f615_open():
    """F615 OPEN: Map.values() spread into call arguments misses."""
    src = "new Map([['a','%s'],['b','%s']]).values()" % (_A, _B)
    m1 = _misses("((...a)=>a.join(''))(..." + src + ")")
    m2 = _misses("((a,b)=>a+b)(..." + src + ")")
    m3 = _misses("((a,b)=>a+b).call(null,..." + src + ")")
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f616_open():
    """F616 OPEN: non-literal param names in USP mutations miss."""
    m1 = _misses("(function(){var p=new URLSearchParams('');var q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()" % (_A, _B))
    m2 = _misses("(function(){var p=new URLSearchParams('');var q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll('q').join('');})()" % (_A, _B))
    m3 = _misses("(function(){var p=new URLSearchParams('q=xx');var k='q';p.set(k,'%s');return p.get(k)+'%s';})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f617_open():
    """F617 OPEN: URL.searchParams set/append/delete + get/getAll misses."""
    m1 = _misses("(function(){var u=new URL('http://x/?q=xx');u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()" % (_A, _B))
    m2 = _misses("(function(){var u=new URL('http://x/');u.searchParams.append('q','%s');u.searchParams.append('q','%s');return u.searchParams.getAll('q').join('');})()" % (_A, _B))
    m3 = _misses("(function(){var u=new URL('http://x/?a=1&q=xx');u.searchParams.delete('a');u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f618_open():
    """F618 OPEN: Promise resolution callbacks miss."""
    m1 = _misses("Promise.all([Promise.resolve('%s'),Promise.resolve('%s')]).then(a=>a.join(''))" % (_A, _B))
    m2 = _misses("Promise.all([Promise.resolve('%s'),Promise.resolve('%s')]).then(([a,b])=>a+b)" % (_A, _B))
    m3 = _misses("Promise.race([Promise.resolve('%s')]).then(v=>v+'%s')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f619_open():
    """F619 OPEN: generator yield/spread assembly misses."""
    m1 = _misses("(function(){function* g(){yield '%s';yield '%s';}return [...g()].join('');})()" % (_A, _B))
    m2 = _misses("(function(){function* g(){yield '%s';yield '%s';}var s='';for(var x of g())s+=x;return s;})()" % (_A, _B))
    m3 = _misses("(function(){function* g(){yield '%s';yield '%s';}return Array.from(g()).join('');})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r41_f620_open():
    """F620 OPEN: indexed/thunk function invocation misses."""
    m1 = _misses("(function(){var f=[()=>'%s',()=>'%s'];return f[0]()+f[1]();})()" % (_A, _B))
    m2 = _misses("[()=>'%s',()=>'%s'].map(f=>f()).join('')" % (_A, _B))
    m3 = _misses("(function(){var s='';[()=>'%s',()=>'%s'].forEach(f=>{s+=f();});return s;})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-372 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g373-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w372_attack_probes.py")],
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
    # The w372 battery's footer pin is stale by design: this lane filed
    # F612-F620, so its expected footer (open F595, F606-F611 / next F612)
    # no longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w372_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-372 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("BREAKS:", sorted(probe_breaks))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
