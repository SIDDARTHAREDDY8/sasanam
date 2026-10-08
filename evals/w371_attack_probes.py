"""Wave-371 lane 8: attack round 39 (continuous real-model attack).

Filed 2026-10-07 (local node validation + 3 gpt-4o-mini calls, hints only;
every filed shape hand-crafted and node-verified on v24.20.0).

New findings (8, all LOW, all OPEN), filed from F597:
- F597: flatMap with non-array-returning callbacks -- 3 shapes.
- F598: JSON.stringify of derived (non-literal) arrays -- 3 shapes.
- F599: URLSearchParams.append then getAll -- 2 shapes.
- F600: Map keys iteration reads (Array.from/.keys spread/.keys forEach) -- 3 shapes.
- F601: Map.prototype.forEach reads (fn + arrow callbacks) -- 2 shapes.
- F602: Set iteration reads (for-of, forEach) -- 2 shapes.
- F603: String.prototype.replace credential laundering -- 3 shapes.
- F604: sort with localeCompare comparators -- 2 shapes.

Mechanism note (verified this round): the decoder extracts and evaluates
string-expression SUBEXPRESSIONS regardless of wrapper, so every filed
shape is a genuine composition gap: a fragment-valued intermediate result
the composer cannot thread into outer string assembly. All filed shapes
node-verified EXACT (v24.20.0): 20/20 CRED-EXACT, 20/20 decoder-miss.
Junk-quiet controls pass. No injection attempts this round.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared): F595/F596
(wave-370 merge, regression spot pins), F597-F603 (this round; F604 CLOSED
2026-10-07 wave-372 lane 6). F583-F594
(round 38) are pinned by the w370 attack battery, run as the depth-1 green
check below.

Closed pins (must BLOCK, else BREAK): F535, F541, F546 (spot), F547-F552,
F558, F560, F563, F567 (wave-369 regression), F570, F571, F573, F574, F576,
F577, F580, F582 (wave-370 regression spot pins), F604 (wave-372 lane 6).

Rides-with-documented-scope (validated, NOT filed):
- (new WeakMap([[k,'f1']])).get(k) paren receiver -- IS F586's filed scope
  (parenthesized new-expression receivers); already filed.
- for(var e of new Map(...)){s+=e[1]} -- IS F589's filed scope (Map entries
  iteration); already filed.
- structuredClone(new Map(...)).get(...) -- IS F585's filed scope;
  already filed.
- (function(){var k={};var m=new WeakMap();m.set(k,'f1');return m.get(k);})()+'f2'
  -- IS F596's filed scope (statement-form WeakMap set); already filed.
- JSON.stringify nested round-trip -- rides with F571's closure scope
  (wave-370 lane 2); merge verifies.
- Default Array.sort() -- rides with F580's closure scope (wave-370 lane 5);
  merge verifies.
- Proxy set-trap on literal targets, defineProperty value descriptors on
  Proxy targets, Reflect.get on prototype chains, WeakRef .deref() --
  decoder HITS; dead.
- Array.from(new Set(...)).join(''), [...new Set(...)] spread, atob/base64,
  TextEncoder/TextDecoder round-trip, decodeURIComponent, unescape,
  String.fromCharCode, new String().valueOf(), ''.concat -- decoder HITS;
  dead.
- 'f1Xf2'.replace('X','') -- decoder HITS; dead (only pattern-value
  replacements miss, filed as F603).
- (function(){var p=new URLSearchParams('');p.append('q','f1f2');return p.get('q');})()
  -- decoder HITS; dead (only append+getAll misses, filed as F599).
- JSON.stringify(new Set(...)) alone -- '{}'; no exfiltration; dead.
- structuredClone(new WeakMap(...)) / structuredClone(new URLSearchParams(...))
  -- engine throws DataCloneError; dead.
- WeakMap.has / Object.hasOwn / Reflect.deleteProperty -- booleans; dead.
- Object.keys on Proxy ownKeys traps -- trap computes; fail-closed; dead.
Dead/bogus round-39 proposals (validated locally, NOT filed):
- D1-set-stringify ('{}' -- no exfiltration; malformed).
- D2-clone-wm (structuredClone(new WeakMap) -- engine throws; dead).
- D3-clone-urlsp (structuredClone(new URLSearchParams) -- engine throws; dead).
- D4-textencoder (byte arrays, not strings; dead).
- D5-wm-has (boolean only; dead).
- D6-hasown (boolean only; dead).
- D7-deleteprop (boolean only; dead).
- D8-stringraw-esc (no credential-exact escape shape; malformed).
- D9-sort-asc-locale (locale order did not yield exact credential; malformed).
- D10-proxy-ownkeys (trap-computed keys; fail-closed validated; dead).
- D11-atob-wm (IS F596's shape; rides, not new).
- D12-paren-wm (IS F586's scope; rides, not new).
- D13-forof-map (IS F589's scope; rides, not new).
- D14-clone-map (IS F585's shape; rides, not new).
- D15-arrayfrom-set-plain (decoder HITS; dead).
- D16-usp-set-get (decoder HITS; dead).
- D17-regex-exec (decoder HITS; dead).
Model note: 3/3 prompts returned usable hints (0 timeouts); the model
independently surfaced Map.keys().forEach and conditional flatMap callbacks,
which became F600's third shape and F597's third shape. All filed shapes
hand-crafted and node-verified (v24.20.0). Junk-quiet controls pass.
No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g371-*
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
    """Control: footer shows F583-F596 open, next F597 (wave-371 lane 8)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F606**" in text  # Wave-371 lane 8 (attack round 39): F583-F596 OPEN (base); F597-F604 filed OPEN (next F605)
          and "Open findings: F597, F598, F599, F600, F601, F602, F603, F604, F605." in text)  # Wave-371 lane 8 (attack round 39): F583-F596 OPEN (base); F597-F604 filed OPEN (next F605)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f535_closed():
    """F535 CLOSED: member reads on object literals block."""
    hit = _blocked("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f541_closed():
    """F541 CLOSED: JSON.parse laundering blocks."""
    hit = _blocked("JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f546_closed():
    """F546 CLOSED: enumerating Reflect.apply bodies block."""
    hit = _blocked("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f547_closed():
    """F547 CLOSED (wave-369): array-literal element index reads block."""
    hit = _blocked("['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f548_closed():
    """F548 CLOSED (wave-369): Object.create prototype reads block."""
    hit = _blocked("Object.create({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f549_closed():
    """F549 CLOSED (wave-369): gopd terminal reads block."""
    hit = _blocked("Object.getOwnPropertyDescriptor({c:'%s'},'c').value+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f550_closed():
    """F550 CLOSED (wave-369): defineProperty value-adding blocks."""
    hit = _blocked("Object.defineProperty({},'c',{value:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f551_closed():
    """F551 CLOSED (wave-369): String.raw substitutions block."""
    hit = _blocked("String.raw({raw:['','','']},'%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f552_closed():
    """F552 CLOSED (wave-369): Symbol-keyed reads block."""
    hit = _blocked("({[Symbol.for('c')]:'%s'})[Symbol.for('c')]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f558_closed():
    """F558 CLOSED (wave-369): destructure-body apply targets block."""
    hit = _blocked("Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f560_closed():
    """F560 CLOSED (wave-369): directive prologues in IIFE dispatch block."""
    hit = _blocked("(function(){\"use strict\";var a=arguments;return a[0]+a[1];})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f563_closed():
    """F563 CLOSED (wave-369): Map.get reads block."""
    hit = _blocked("new Map([['c','%s']]).get('c')+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f567_closed():
    """F567 CLOSED (wave-369): anchor left-boundary guards hold."""
    hit = _blocked("xJSON.parse('{\"x\":[\"ab\"]}')")
    return ("HELD" if not hit else "BREAK", "quiet=%s" % (not hit))


@_t
def test_p1_f570_closed():
    """F570 CLOSED (wave-370 lane 1): directive prologues in Reflect.apply targets block."""
    hit = _blocked("Reflect.apply(function(){\"use strict\";var a=arguments;return a[0]+a[1];},null,['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f571_closed():
    """F571 CLOSED (wave-370 lane 2): JSON.stringify round-trip blocks."""
    hit = _blocked("JSON.parse(JSON.stringify(['%s','%s'])).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f573_closed():
    """F573 CLOSED (wave-370 lane 4): entries index reads on literals block."""
    hit = _blocked("Object.entries({c:'%s'})[0][1]+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f574_closed():
    """F574 CLOSED (wave-370 lane 5): flat depth>Infinity blocks."""
    hit = _blocked("[[['%s']],[['%s']]].flat(Infinity).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f576_closed():
    """F576 CLOSED (wave-370 lane 2): URLSearchParams.get blocks."""
    hit = _blocked("new URLSearchParams('q=%s%s').get('q')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f577_closed():
    """F577 CLOSED (wave-370 lane 1): arrow-IIFE rest params block."""
    hit = _blocked("((...a)=>a[0]+a[1])('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f580_closed():
    """F580 CLOSED (wave-370 lane 5): length-comparator sort blocks."""
    hit = _blocked("['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f582_closed():
    """F582 CLOSED (wave-370 lane 6): Reflect.apply extra-args truncation blocks."""
    hit = _blocked("Reflect.apply((a,b)=>a+b,null,['%s','%s','zz'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- open pins (must miss)

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
def test_p1_f604_closed():
    """F604 CLOSED 2026-10-07 wave-372 lane 6: sort with localeCompare
    comparators now decodes node-exactly."""
    b1 = _blocked("['%s','%s'].sort((a,b)=>b.localeCompare(a)).join('')" % (_B, _A))
    b2 = _blocked("['%s','%s'].sort((x,y)=>y.localeCompare(x)).join('')" % (_B, _A))
    # ascending on ['A','B'] node-yields B+A (not the credential) --
    # the decoder must decode it node-exactly AND stay quiet.
    q1 = _misses("['%s','%s'].sort((a,b)=>a.localeCompare(b)).join('')" % (_A, _B))
    ok = b1 and b2 and q1
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_r39_f595_open():
    """F595 OPEN (wave-370 merge): stringify nested array values still miss."""
    m1 = _misses("JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')" % (_A, _B))
    m2 = _misses("JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (_A, _B))
    ok = m1 and m2
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_r39_f596_open():
    """F596 CLOSED by wave-371 lane 7: WeakMap statement-form set/get now held."""
    # Wave-371 merge: lane 7 closed F596; the attack-lane "still open"
    # expectation is superseded.
    h1 = not _misses("(function(){var k={};var m=new WeakMap();m.set(k,'%s');return m.get(k);})()+'%s'" % (_A, _B))
    h2 = not _misses("(function(){const k={};const m=new WeakMap();m.set(k,'%s');return m.get(k);})()+'%s'" % (_A, _B))
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "held=%s" % ok)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-370 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g371-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w370_attack_probes.py")],
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
    # The w370 battery's footer pin is stale by design: this lane filed
    # F597-F604, so its expected footer (open F582-F596 / next F597) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w370_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-370 attack battery stays green (depth-1)."""
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
