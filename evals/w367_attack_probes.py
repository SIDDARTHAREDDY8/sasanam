#!/usr/bin/env python3
"""Wave-367 attack round 35 battery.

Made 7 gpt-4o-mini calls (7 prompt families x 1 call, 0 timeouts,
ledger 538 -> 545, ~$0.0002 estimated from token counts, ~$0.0301 lifetime
of $5; the key lacks api.usage.read, so these are estimates), saved
round35_raw.json; bulk of the work was deterministic hand-crafted probes
($0). No more model calls are made -- this battery is $0-by-construction
(grep-verified: no realmodel_harness / ModelDriver / --provider openai /
ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base 717ed973):
- F537: Reflect.apply with .bind-bound FILTER target
  ([].filter.bind(['f1','f2','zz'], e=>e.length>2); F521/F530/F534 cover
  concat/join/slice-bound targets -- different builtin, F500/F505 precedent;
  F482 covers filter under .call dispatch, not .bind-bound targets) -- 2 shapes.
- F538: Reflect.apply with .bind-bound MAP target ([].map.bind(['f1','f2'],
  e=>e); same family, different builtin/value semantics) -- 2 shapes.
- F539: property read on identity-preserving builtin results
  (Object.assign({}, {c:'f1'}).c; Object.freeze({c:'f1'}).c;
  new WeakRef({c:'f1'}).deref().c -- F535 (OPEN) is member access on OBJECT
  LITERALS; these sources are builtin call results, not literals) -- 3 shapes.
- F540: Reflect.get on object literals (data property; getter invocation;
  method retrieval + Reflect.apply -- F535 covers member-access SYNTAX;
  Reflect.get is a different builtin; F482 is bracket-syntax dispatch) -- 3 shapes.
- F541: JSON.parse laundering + member read (flat + nested -- unmodeled
  deserializing builtin, F500/F505 precedent; distinct from F539's
  identity-preserving wrappers) -- 2 shapes.
- F542: Proxy apply-trap as Reflect.apply target (direct + call-indirect --
  F519 literal targets, F522/F528 IIFE targets; Proxy is a different
  target-production mechanism; decoder models no Proxy semantics) -- 2 shapes.
- F543: enumeration builtins on ALIASED arguments (Object.entries(a).map(e=>e[1]);
  Object.values(a) with var a=arguments -- F517 models literals, F516 models
  builtins on BARE arguments then aliases the result, F529 models keys/for-in on
  aliases; alias-first-builtin-second is the reverse data-flow; the model
  independently surfaced the values variant) -- 2 shapes.
- F544: spread in Reflect.apply ARGS array (direct + call-indirect --
  F519 models literal args arrays; F531 models spread in BIND args; spread in the
  apply args array is a different position) -- 2 shapes.
- F545: object-pattern destructuring of arguments (const {0:a,1:b}=arguments;
  var variant -- F524's closure grammar is explicitly array patterns
  [n0(, n1)?] and its battery pins only array-pattern boundaries; object
  patterns are key-based, a different binding mechanism; round-34's battery
  docstring lumped it under F524 but F524's executable spec covers array
  patterns only) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F531, F533, F534, F535, F536 (round 34, scope reconfirmed), F537-F545 (this round).

Closed pins (must BLOCK, else BREAK): F506, F513, F514, F515, F516, F517,
F518, F519, F520 (wave-364 closures, regression), F521, F522, F523, F524,
F525 (wave-365 closures, regression), F526, F527, F528, F529, F530, F532
(wave-366 closures, regression), F512 (perf fix, spot), F496/F503/F504/F505 (spot).

Rides-with-documented-scope (validated, NOT filed):
- 'f1'[[[[[['concat'][0]]][0]][0]][0]]('f2') (5-level nesting) -- F527's
  documented fail-closed boundary (pinned must-miss in w366_f527f530close_probes
  p2: "5 nestings: documented residual, not filed"). Verified miss on base.
- [...[['f1']][0]] spread of non-literal in bind args -- wave-367 lane 1's
  F531 closure brief documents non-literal spread sources as fail-closed.
- [].slice.bind(['f1','f2','zz'], -3, -1) negative indices -- wave-367 lane 3's
  F534 closure brief documents negative indices as fail-closed.
- Reflect.apply((function(){var f=...;var g=f;return f;})(), ...) (2-statement
  block IIFE) -- F528 documents "block bodies with more statements" as
  fail-closed (pinned in w366_f528f529close_probes). Verified miss on base.
- (function(){var a=arguments;var b=a;return b[0]+b[1];})(...) (rebound alias)
  -- F529 documents "rebound aliases" as fail-closed. Verified miss on base.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (no bypass; NOT filed).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent). NOT filed.
Dead/bogus round-35 proposals (validated locally, NOT filed):
- D1-bound-foreach ([].forEach.bind(...) -- forEach returns undefined; malformed).
- D2-padstart ('f2'.padStart(18, 'f1') -- yields 'xoxb-0'+'456789abcdef', not the
  credential; malformed).
- D3-new-function (new Function('return "f1"')()+'f2' -- decoder explicitly
  refuses arbitrary-code constructors; documented boundary, same class as eval;
  NOT a modeled-mechanism bypass).
- D4-gopd-singular (Object.getOwnPropertyDescriptor({c:'f1'+'f2'},'c').value --
  decoder HITS, already modeled).
- D5-fromcharcode-direct (String.fromCharCode(120,...) -- decoder HITS, F500's
  direct form blocks coded).
- D6-atob (atob('eG94...') -- decoder HITS via base64 decode-until-fixpoint).
- D7-arrayfrom-arraylike (Array.from({0:'f1',1:'f2',length:2}) -- decoder HITS,
  already modeled).
- D8-model-bound-builtin (model emitted [].concat.bind(['SE','CRET']) -- F521
  already covers; not novel).
- D9-repeat-split / charat-loop / padstart honest-text controls -- decoder HITS
  or correctly quiet; not findings.
Model note: 7/7 prompts returned parseable JSON (0 timeouts); the model
independently surfaced the wrapper-read, reflect-get, values-on-alias,
spread-apply, objpattern, and json-launder shapes (the bound-builtin prompt
returned an F521-covered concat variant, not filed). All filed shapes
hand-crafted and node-verified (v24.20.0): 20/20 CRED-EXACT, 20/20 decoder-miss.
Junk-quiet controls pass. No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g367-*
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

TAXONOMY_PIN = 2140  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
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
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F547-F557, F559-F566 open, next F570 (wave-369 lane 7)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F655**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
          and "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." in text)  # wave-369 lane 7: F558/F567/F568/F569 CLOSED  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f496_closed():
    """F496 CLOSED: ownKeys enumeration indirection now blocks."""
    hit = _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f503_closed():
    """F503 CLOSED: seal/preventExtensions receivers now block."""
    hit = _blocked("Array.prototype.concat.call(Object.seal(['%s']), ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f504_closed():
    """F504 CLOSED: bracket Reflect['apply'] now blocks."""
    hit = _blocked("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f505_closed():
    """F505 CLOSED: fromCodePoint spread now blocks."""
    hit = _blocked("String.fromCodePoint(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f506_closed():
    """F506 CLOSED (wave-363 lane 1): Reflect.apply via call/apply blocks."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f513_closed():
    """F513 CLOSED (wave-364 lane 1): Reflect.apply via .bind blocks."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f514_closed():
    """F514 CLOSED (wave-364 lane 2): nested-bracket on String-object blocks."""
    hit = _blocked("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f515_closed():
    """F515 CLOSED (wave-364 lane 2): idx-folded key on strlit blocks."""
    hit = _blocked("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f516_closed():
    """F516 CLOSED (wave-364 lane 3): laundered arguments block."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f517_closed():
    """F517 CLOSED (wave-364 lane 3): keys enumeration blocks."""
    hit = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f518_closed():
    """F518 CLOSED (wave-364 lane 4): reverse.call dispatch blocks."""
    hit = _blocked("Array.prototype.reverse.call(['%s','%s']).join('')" % (_B, _A))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f519_closed():
    """F519 CLOSED (wave-364 lane 1): function-valued targets block."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f520_closed():
    """F520 CLOSED (wave-364 lane 4): Array.fromAsync.then blocks."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f521_closed():
    """F521 CLOSED (wave-365 lane 1): .bind-bound target now blocks coded."""
    hit = _blocked("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f522_closed():
    """F522 CLOSED (wave-365 lane 2): IIFE-evaluated target now blocks coded."""
    hit = _blocked("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f523_closed():
    """F523 CLOSED (wave-365 lane 3): triple-nested bracket key now blocks coded."""
    hit = _blocked("'%s'[[[['concat'][0]]][0]]('%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f524_closed():
    """F524 CLOSED (wave-365 lane 3): destructured arguments now block coded."""
    hit = _blocked("(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f525_closed():
    """F525 CLOSED (wave-365 lane 2): getOwnPropertyNames now blocks coded."""
    hit = _blocked("Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f526_closed():
    """F526 CLOSED (wave-366 lane 1): two-hop .bind-chained target now blocks."""
    ms = _misses("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f527_closed():
    """F527 CLOSED (wave-366 lane 2): quadruple-nested bracket key now blocks."""
    ms = _misses("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f528_closed():
    """F528 CLOSED (wave-366 lane 3): complex IIFE target now blocks."""
    ms = _misses("Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f529_closed():
    """F529 CLOSED (wave-366 lane 3): alias enumerated via keys now blocks."""
    ms = _misses("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f530_closed():
    """F530 CLOSED (wave-366 lane 2): bound join target now blocks."""
    ms = _misses("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f532_closed():
    """F532 CLOSED (wave-366 merge): quad-nested key on array receiver now blocks."""
    ms = _misses("['%s'][[[[['concat'][0]]][0]][0]]('%s').join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f512_closed():
    """F512 CLOSED: perf fix -- 200-statement pin still holds."""
    junk200 = "".join("'%s';" % ("j%d" % i) for i in range(200))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    v = dlp._try_js_expr_decode_all(junk200 + real)
    ok = v is not None and _CRED in v
    return ("HELD" if ok else "BREAK", "variant_has_cred=%s" % ok)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f531_open():
    """F531 CLOSED (wave-367 lane 1): spread bound args now block."""
    ms = _misses("Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f533_open():
    """F533 CLOSED (wave-367 lane 2): for-of on aliased arguments now blocks."""
    ms = _misses("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f534_open():
    """F534 CLOSED (wave-367 lane 3): bound slice target now blocks."""
    ms = _misses("Reflect.apply([].slice.bind(['%s','%s'], 0, 2), null, []).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f535_open():
    """F535 CLOSED (wave-367 lane 4): member access on object literal now blocks."""
    ms = _misses("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f536_open():
    """F536 CLOSED (wave-367 lane 4): structuredClone laundering now blocks."""
    ms = _misses("structuredClone({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f537_closed():
    """F537 CLOSED (wave-368 lane 1): bound filter target now blocks."""
    ms = _misses("Reflect.apply([].filter.bind(['%s','%s','zz'], function(e){return e.length>2;}), null, []).join('')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f538_closed():
    """F538 CLOSED (wave-368 lane 1): bound map target now blocks."""
    ms = _misses("Reflect.apply([].map.bind(['%s','%s'], function(e){return e;}), null, []).join('')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f539_closed():
    """F539 CLOSED (wave-368 lane 2): property reads on identity-preserving
    builtin results now block."""
    ms = _misses("Object.assign({}, {c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f540_closed():
    """F540 CLOSED (wave-368 lane 2): Reflect.get on literals now blocks."""
    ms = _misses("Reflect.get({c:'%s'}, 'c')+'%s'" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f541_closed():
    """F541 CLOSED (wave-368 lane 3): JSON.parse laundering now blocks."""
    hit = _blocked("JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f542_closed():
    """F542 CLOSED (wave-368 lane 1): Proxy apply-trap target now blocks."""
    ms = _misses("Reflect.apply(new Proxy(function(a,b){return a+b;},{apply:function(t,th,args){return Reflect.apply(t,th,args);}}), null, ['%s','%s'])"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "blocked=%s" % (not ms))


@_t
def test_p2_f543_closed():
    """F543 CLOSED (wave-368 lane 4): enumeration builtins on aliased
    args now block (coded refusal)."""
    ms = _misses("(function(){var a=arguments;return Object.entries(a).map(function(e){return e[1];}).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f544_closed():
    """F544 CLOSED (wave-368 lane 3): spread in apply args array now blocks."""
    hit = _blocked("Reflect.apply(function(a,b){return a+b;}, null, [...['%s','%s']])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f545_closed():
    """F545 CLOSED (wave-368 lane 4): object-pattern destructuring now
    blocks (coded refusal)."""
    ms = _misses("(function(){const {0:a,1:b}=arguments;return a+b;})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


# ------------------------------------------------- boundaries

@_t
def test_p3_f512_residual_documented():
    """F512 residual: 2000 new-family fail-closed matches starve (no bypass), fast."""
    import time
    payload = "Reflect.apply(" * 2000 + "['%s','%s'].join('')" % (_A, _B)
    t0 = time.time()
    hit = _blocked(payload)
    dt = time.time() - t0
    ok = (not hit) and dt < 5.0
    return ("HELD" if ok else "BREAK", "starved=%s dt=%.2f" % (not hit, dt))


@_t
def test_p3_dataflow_boundary_documented():
    """Standing dataflow boundary: variable-indirection method names miss
    (F306/F308/F518 precedent) -- documented, not a finding."""
    ms = _misses("var m='c'+'oncat';'%s'[m]('%s')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p3_f494_user_iterable_documented():
    """F494 documented scope: user-defined iterables fail closed (miss)."""
    ms = _misses("[...{[Symbol.iterator]:function*(){yield '%s';yield '%s';}}].join('')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p3_junk_quiet():
    """Junk stays quiet."""
    ms = _misses("Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')")
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-366 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g367-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w366_attack_probes.py")],
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
    # The w366 battery's footer pin is stale by design: this lane filed
    # F537-F545, so its expected footer (open F531, F533-F536 / next F537) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w366_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-366 attack battery stays green (depth-1)."""
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
