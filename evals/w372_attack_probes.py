"""Wave-372 lane 7: attack round 40 (continuous real-model attack).

Filed 2026-10-07 (takeover lane; local node validation on v24.20.0 + 3
gpt-4o-mini calls, hints only; every filed shape hand-crafted and
node-verified).

New findings (5, all LOW, all OPEN), filed from F607:
- F607: Array.prototype.filter with non-trivial predicates -- 3 shapes.
- F608: Set spread into call arguments -- 3 shapes.
- F609: String.prototype.replace with function replacements -- 3 shapes.
- F610: URLSearchParams.set mutation then .get read -- 3 shapes.
- F611: base64 runs decoding to credential fragments escape the F445
  credential-shape gate -- 3 shapes.

Mechanism notes (verified this round):
- The decoder models filter only with the identity predicate; predicate-shaped
  callbacks that select fragments escape (F607).
- F602's filed entry documents [...new Set(...)] ARRAY spread as modeled, but
  spreading a Set into CALL ARGUMENTS is a different dispatch shape (F608).
- F603's closure (wave-372 lane 5) covers literal patterns and $-patterns in
  the replacement string; function-valued replacements compute at runtime and
  have no modeled path -- verified still missing on the F603-closed lane tree
  (F609).
- F599's closure (wave-372 lane 3) models append/set mutations followed by
  getAll(); set() mutation read back via .get() is a different read path --
  verified still missing on the F599-closed lane tree (F610).
- F445's closure (wave-349) emits base64 variants only when the decoded text
  is credential-shaped; a run decoding to a credential FRAGMENT
  ("eG94Yi0wMTIz" -> "xoxb-0123") never becomes a variant, so
  fragment-then-concatenate assembly is invisible in atob() calls (bare call,
  var-bound, WeakMap-composed). Full-credential base64 blocks coded
  (controls). Correction: the round-39 battery docstring listed
  "atob/base64 ... decoder HITS; dead" -- that note is wrong for fragment
  forms (re-verified on the wave-371 tree); round 39 must have probed
  full-credential base64 only.
All filed shapes node-verified EXACT (v24.20.0): 15/15 CRED-EXACT,
15/15 decoder-miss. Junk-quiet controls pass. No injection attempts.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared): F597-F605
(round 39), F607-F611 (this round). F583-F596 are pinned CLOSED by the
wave-371 spot pins below; earlier waves are pinned by the w371 attack
battery, run as the depth-1 green check below.

Closed pins (must BLOCK, else BREAK): F583, F585, F587, F589, F591, F593,
F594, F596 (wave-371 spot), F576 (regression spot).

Rides-with-documented-scope (validated, NOT filed):
- (function(){var p=new URLSearchParams();p.set('k','f1');p.append('k','f2');return p.getAll('k').join('');})()
  -- IS F599's filed scope (append/set mutation + getAll terminal read);
  already filed.
- [...new Map([['k1','f1'],['k2','f2']]).values()].join('') -- decoder HITS;
  dead (Map values modeled).
- [...new WeakMap().values()].join('') -- engine throws (WeakMap has no
  .values()); dead.
- Array.from(['f1','f2']).join('') -- decoder HITS; dead.
- (previous agent validated, inherited) reduce-* (F553's scope), weakmap
  set-chain (F596 CLOSED), assign-getter (decoder HITS), slice-tail/mid
  (decoder HITS), proxy-computed (HELD), sort-locale-rev (F604's filed
  shape), flatmap-index (F597's family), forin-map-keys (node yields no
  credential; dead), f598-shape (F598's shape).
Model note: 3/3 prompts returned usable hints (0 timeouts). The model's
r40-mutate family independently surfaced params.set/append chains and
Map.set chains, which validated as F599's scope (not new) and HELD
respectively. All filed shapes hand-crafted and node-verified (v24.20.0).
Junk-quiet controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g372-*
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
    """Control: footer shows F597-F611 open, next F612 (wave-372 lane 7)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F612**" in text  # Wave-372 lane 7 (attack round 40): F597-F605 OPEN (base); F607-F611 filed OPEN (next F612)
          and "Open findings: F597, F598, F599, F600, F601, F602, F603, F604, F605, F607, F608, F609, F610, F611." in text)  # Wave-372 lane 7 (attack round 40): F597-F605 OPEN (base); F607-F611 filed OPEN (next F612)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f583_closed():
    """F583 CLOSED (wave-371 lane 1): key-terminal reads block."""
    hit = _blocked("Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f585_closed():
    """F585 CLOSED (wave-371 lane 3): structuredClone of Map blocks."""
    hit = _blocked("structuredClone(new Map([['c','%s']])).get('c')+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_closed():
    """F587 CLOSED (wave-371 lane 4): Proxy member-read receivers block."""
    hit = _blocked("new Proxy({c:'%s'},{get:(t,k)=>t[k]}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f589_closed():
    """F589 CLOSED (wave-371 lane 1): Map entries iteration blocks."""
    hit = _blocked("[...new Map([['c','%s']]).entries()][0][1]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f591_closed():
    """F591 CLOSED (wave-371 lane 5): defineProperty accessor descriptors block."""
    hit = _blocked("Object.defineProperty({},'c',{get:()=>'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f593_closed():
    """F593 CLOSED (wave-371 lane 7): WeakMap variable-identity keys block."""
    hit = _blocked("(function(){var r={};return new WeakMap([[r,{c:'%s'}]]).get(r).c+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f594_closed():
    """F594 CLOSED (wave-371 lane 6): bare-arguments enumeration blocks."""
    hit = _blocked("(function(){var s='';for(var k in arguments){s+=arguments[k];}return s;})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f596_closed():
    """F596 CLOSED (wave-371 lane 7): WeakMap statement-form set/get blocks."""
    hit = _blocked("(function(){var k={};var m=new WeakMap();m.set(k,'%s');return m.get(k);})()+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f576_closed():
    """F576 CLOSED (wave-370 lane 2): URLSearchParams.get blocks."""
    hit = _blocked("new URLSearchParams('q=%s%s').get('q')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ----------------------------------------- open pins, round 39 (must miss)

@_t
def test_r39_f597_open():
    """F597 OPEN: flatMap with non-array-returning callbacks misses."""
    m1 = _misses("[['%s'],['%s']].flatMap((x)=>x).join('')" % (_A, _B))
    m2 = _misses("['%s','%s'].flatMap((x)=>x).join('')" % (_A, _B))
    m3 = _misses("['%s','%s'].flatMap((c)=>c==='x'?'x':c).join('')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f598_open():
    """F598 OPEN: JSON.stringify of derived arrays misses."""
    m1 = _misses("JSON.parse(JSON.stringify(Array.from(new Set(['%s','%s'])))).join('')" % (_A, _B))
    m2 = _misses("JSON.parse(JSON.stringify([...new Set(['%s','%s'])]))).join('')" % (_A, _B))
    m3 = _misses("JSON.parse(JSON.stringify(Array.from(new Map([['a','%s'],['b','%s']]).values()))).join('')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f599_open():
    """F599 OPEN: URLSearchParams.append then getAll misses."""
    m1 = _misses("(function(){var p=new URLSearchParams('q=%s');p.append('q','%s');return p.getAll('q').join('');})()" % (_A, _B))
    m2 = _misses("(function(){var p=new URLSearchParams('');p.append('q','%s');p.append('q','%s');return p.getAll('q').join('');})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f600_open():
    """F600 OPEN: Map keys iteration reads miss."""
    m1 = _misses("Array.from(new Map([['%s',1],['%s',2]]).keys()).join('')" % (_A, _B))
    m2 = _misses("[...new Map([['%s',1],['%s',2]]).keys()].join('')" % (_A, _B))
    m3 = _misses("(function(){var s='';new Map([['%s',1],['%s',2]]).keys().forEach(function(k){s+=k;});return s;})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f601_open():
    """F601 OPEN: Map.prototype.forEach reads miss."""
    m1 = _misses("(function(){var s='';new Map([['a','%s'],['b','%s']]).forEach(function(v){s+=v;});return s;})()" % (_A, _B))
    m2 = _misses("(function(){var s='';new Map([['a','%s'],['b','%s']]).forEach((v)=>{s+=v;});return s;})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f602_open():
    """F602 OPEN: Set iteration reads miss."""
    m1 = _misses("(function(){var s='';for(var x of new Set(['%s','%s'])){s+=x;}return s;})()" % (_A, _B))
    m2 = _misses("(function(){var s='';var st=new Set(['%s','%s']);st.forEach(function(x){s+=x;});return s;})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f603_open():
    """F603 OPEN: String.prototype.replace laundering misses."""
    m1 = _misses("'%sX'.replace('X','%s')" % (_A, _B))
    m2 = _misses("'%sXX'.replace('XX','%s')" % (_A, _B))
    m3 = _misses("'X%s'.replace('X','%s')" % (_B, _A))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f604_open():
    """F604 OPEN: sort with localeCompare comparators misses."""
    m1 = _misses("['%s','%s'].sort((a,b)=>b.localeCompare(a)).join('')" % (_B, _A))
    m2 = _misses("['%s','%s'].sort((x,y)=>y.localeCompare(x)).join('')" % (_B, _A))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f605_open():
    """F605 OPEN (wave-371 lane 7): Object.assign neighbor variants miss."""
    m1 = _misses("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);return Object.assign({x:1},m.get(r)).c+'%s';})()" % (_A, _B))
    m2 = _misses("(function(){var r={};var m=new WeakMap([[r,{c:'%s'}]]);return Object.assign({},m.get(r),{d:1}).c+'%s';})()" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ----------------------------------------- open pins, round 40 (must miss)

@_t
def test_r40_f606_open():
    """F607 OPEN: filter with non-trivial predicates misses."""
    m1 = _misses("['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A, _B))
    m2 = _misses("['%s','xx','%s'].filter(function(x){return x!=='xx';}).join('')" % (_A, _B))
    m3 = _misses("['%s','%s',''].filter(x=>x.length>2).join('')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r40_f607_open():
    """F608 OPEN: Set spread into call arguments misses."""
    m1 = _misses("((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B))
    m2 = _misses("((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B))
    m3 = _misses("((a,b)=>a+b).call(null,...new Set(['%s','%s']))" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r40_f608_open():
    """F609 OPEN: String.replace with function replacements misses."""
    m1 = _misses("'%sXX'.replace('XX',()=>'%s')" % (_A, _B))
    m2 = _misses("'%sXX'.replace(/XX/,()=>'%s')" % (_A, _B))
    m3 = _misses("'%sXX'.replace('XX',(m,off)=>off===5?'%s':'')" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r40_f609_open():
    """F610 OPEN: URLSearchParams.set then .get misses."""
    m1 = _misses("(function(){var p=new URLSearchParams('q=xx');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    m2 = _misses("(function(){var p=new URLSearchParams('');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    m3 = _misses("(function(){const p=new URLSearchParams('q=zz');p.set('q','%s');return p.get('q')+'%s';})()" % (_A, _B))
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r40_f610_open():
    """F611 OPEN: base64 runs decoding to credential fragments miss."""
    m1 = _misses("atob('eG94Yi0wMTIz')+'%s'" % _B)
    m2 = _misses("(function(){var b=atob('eG94Yi0wMTIz');return b+'%s';})()" % _B)
    m3 = _misses("(function(){var m=new WeakMap();var k={};m.set(k,atob('eG94Yi0wMTIz'));return m.get(k)+'%s';})()" % _B)
    ok = m1 and m2 and m3
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-371 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g372-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w371_attack_probes.py")],
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
    # The w371 battery's footer pin is stale by design: this lane filed
    # F607-F611, so its expected footer (open F597-F605 / next F607) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w371_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-371 attack battery stays green (depth-1)."""
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
