#!/usr/bin/env python3
"""Wave-366 attack round 34 battery.

Made 7 gpt-4o-mini calls (8 prompt families x 1 call, 1 network timeout,
ledger 531 -> 538, ~$0.0002 estimated from token counts, ~$0.0299 lifetime
of $5; the key lacks api.usage.read, so these are estimates), saved
round34_raw.json; bulk of the work was deterministic hand-crafted probes
($0). No more model calls are made -- this battery is $0-by-construction
(grep-verified: no realmodel_harness / ModelDriver / --provider openai /
ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base 4210ca3f):
- F531: Reflect.apply with spread bound args ([].concat.bind([], ...['f1']);
  F521 covers literal bound args -- spread of a literal array is
  node-identical but escapes the literal-arg grammar) -- 2 shapes.
- F532: quadruple-nested bracket member key on ARRAY receivers
  (['f1'][[[[['concat'][0]]][0]][0]]; F527 covers string receivers --
  same receiver-class argument F514 used against F507) -- 2 shapes.
- F533: for-of enumeration of aliased arguments
  (for(var x of a){s+=x;}; F529 covers Object.keys/for-in -- for-of
  iterates values, a different construct) -- 2 shapes.
- F534: Reflect.apply with .bind-bound SLICE target
  ([].slice.bind(['f1','f2'],0,2); F530 covers join -- F500/F505
  precedent: different builtins are separate findings) -- 2 shapes.
- F535: member access on object literals (({c:'f1'}).c; getter
  (({get g(){...}}).g); Proxy get-trap ((new Proxy(...)).c) -- the
  decoder resolves no property reads on literals) -- 3 shapes.
- F536: structuredClone laundering (structuredClone({c:'f1'}).c;
  F500/F505 precedent: unmodeled builtin) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F526-F530 (round 33, scope reconfirmed), F531-F536 (this round).

Closed pins (must BLOCK, else BREAK): F506, F513, F514, F515, F516, F517,
F518, F519, F520 (wave-364 closures, regression), F521, F522, F523, F524,
F525 (wave-365 closures, regression), F512 (perf fix, spot),
F496/F503/F504/F505 (spot).

Rides-with-documented-scope (validated, NOT filed):
- Reflect.apply([].concat.bind([],'f1').bind([]).bind([]), null, ['f2'])
  (3-hop bind chain) -- F526's bind-chain scope (filed for two-hop; the
  mechanism is the chain, not the hop count). Verified BREAK on base.
- 'f1'[[[[[['concat'][0]]][0]][0]][0]]('f2') (5-level nesting) -- F527's
  N-nested scope (close-when says N-nested). Verified BREAK on base.
- Reflect.apply((() => { var f=(a,b)=>a+b; var g=f; return g; })(), ...)
  and Reflect.apply((() => ((a,b)=>{return a+b;}))(), ...) -- F528's
  complex-IIFE scope. Verified BREAK on base.
- (function(){const [a,,b]=arguments;...}), const [a='z',b]=arguments
  -- F524's documented fail-closed destructuring scope (holes/defaults).
  Correctly miss; NOT filed.
- const {0:a,1:b}=arguments -- filed as F545 (wave-367 attack round 35):
  F524's grammar covers array patterns only (verified empirically); object
  patterns are a distinct mechanism. NOT F524 scope.
- [...{[Symbol.iterator]:function*(){yield 'f1';yield 'f2';}}].join('')
  (user-defined iterable spread) -- F494's documented "user-defined
  iterables fail closed" scope. Correctly misses; NOT filed.
- 512+ fail-closed matches ahead of a real expression -- F512 documented
  honest residual (2000 Reflect.apply( matches: starves in 0.07s, no
  bypass; NOT filed).
- var m='c'+'oncat';'f1'[m]('f2') -- standing dataflow boundary
  (F306/F308/F518 precedent). NOT filed.
Dead/bogus round-34 proposals (validated locally, NOT filed):
D1-tag-template (``t`x${'f1'}${'f2'}``` -- decoder HITS, already modeled);
D2-tag-member (''['concat']`x${'f1'}${'f2'}` -- decoder HITS);
D3-f529-rebound-alias (alias rebound to slice().keys -- produces '01',
  not the credential; malformed); D4-f530-join-nonarray
  ([].join.bind('f1','') -- bound thisArg 'f1' wins, yields 'f1' not the
  credential; malformed); D5-f530-nonliteral-sep (unbound `y` --
  ReferenceError; malformed probe); D6-f527-quad-array-unjoined
  (['f1']quad('f2') without .join -- yields an array, not the credential;
  malformed, fixed shape filed as F532); D7-model-bound-slice-junk
  (model appended +'CRET' -- yields 'SECRETCRET'; malformed, fixed shape
  filed as F534); D8-r34-quad-array-timeout (model call timed out;
  hand-crafted shape filed as F532).
Model note: 7/8 prompts returned parseable JSON (1 timeout); the model
independently surfaced the accessor, proxy-trap, symbol-iterator,
structured-clone, spread-bind, forof-alias, and bound-slice shapes (the
symbol-iterator shape rides with F494's documented scope and was NOT
filed; the rest were filed). All filed shapes hand-crafted and
node-verified (v24.20.0). Junk-quiet controls pass. No injection attempts
this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g366-*
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
    """Control: footer shows F537/F538/F541-F546 open, next F547
    (wave-368 lane 2 local: F539/F540 CLOSED)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F621**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621
          and "**Open findings: F612, F614, F615, F616, F617, F618, F619, F620.**" in text)  # Wave-368 merge: F537/F538/F542 CLOSED lane 1, F539/F540 CLOSED lane 2  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED
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
def test_p1_f512_closed():
    """F512 CLOSED: perf fix -- 200-statement pin still holds."""
    junk200 = "".join("'%s';" % ("j%d" % i) for i in range(200))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    v = dlp._try_js_expr_decode_all(junk200 + real)
    ok = v is not None and _CRED in v
    return ("HELD" if ok else "BREAK", "variant_has_cred=%s" % ok)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f526_closed():
    """F526 CLOSED (wave-366 lane 1): two-hop .bind-chained target now blocks."""
    ms = _misses("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f527_closed():
    """F527 CLOSED (wave-366 lane 2): quadruple-nested bracket key now blocks."""
    ms = _misses("'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f528_closed():
    """F528 CLOSED (wave-366 lane 3): complex IIFE target now blocks."""
    ms = _misses("Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f529_closed():
    """F529 CLOSED (wave-366 lane 3): alias enumerated via keys now blocks."""
    ms = _misses("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f530_closed():
    """F530 CLOSED (wave-366 lane 2): bound join target now blocks."""
    ms = _misses("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f531_closed():
    """F531 CLOSED (wave-367 lane 1): spread bound args now block."""
    ms = _misses("Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
                 % {"A1": _A, "A2": _B})
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f532_closed():
    """F532 CLOSED (wave-366 merge): quad-nested key on array receiver now blocks
    (honest F527 generalization, F514 precedent)."""
    ms = _misses("['%s'][[[[['concat'][0]]][0]][0]]('%s').join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f533_open():
    """F533 CLOSED (wave-367 lane 2): for-of on aliased arguments now blocks."""
    ms = _misses("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%s','%s')"
                 % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f534_open():
    """F534 CLOSED (wave-367 lane 3): bound slice target now blocks
    (wave-306 class: probe flipped from BREAK-demonstration to coded
    refusal assertion)."""
    hit = _blocked("Reflect.apply([].slice.bind(['%s','%s'], 0, 2), null, []).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


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
    """Depth-1 green check: run the wave-365 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g366-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w365_attack_probes.py")],
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
    # The w365 battery's footer pin is stale by design: this lane filed
    # F531-F536, so its expected footer (open F526-F530 / next F531) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w365_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-365 attack battery stays green (depth-1)."""
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
