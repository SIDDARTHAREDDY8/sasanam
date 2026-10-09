#!/usr/bin/env python3
"""Wave-364 attack round 32 battery.

Made 8 gpt-4o-mini calls (8 prompt families x 1 call, ledger 515 -> 523,
~$0.000841 estimated from token counts, ~$0.029353 lifetime of $5; the key
lacks api.usage.read, so these are estimates), saved round32_raw.json; bulk
of the work was deterministic hand-crafted probes ($0). No more model calls
are made -- this battery is $0-by-construction (grep-verified: no
realmodel_harness / ModelDriver / --provider openai / ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base ead27c2b):
- F521: Reflect.apply with .bind-bound function targets ([].concat.bind([], 'f1')
  as target; F506 models concat targets, F513 models bind indirection with
  plain targets, F519 models arrow/fn-expr targets) -- 3 shapes.
- F522: Reflect.apply with an IIFE-evaluated function target
  ((() => (a,b)=>a+b)(); F519 covers literal arrow/fn-expr targets) -- 2 shapes.
- F523: triple-nested bracket member keys on string receivers
  ('f1'[[[['concat'][0]]][0]]; F515 covers double-nested, F514 covers nested
  on String-objects) -- 2 shapes.
- F524: destructured arguments laundering (const [a,b]=arguments; F516 covers
  simple alias/rest/Array.from/values -- destructuring is pattern binding,
  a different mechanism) -- 2 shapes.
- F525: Object.getOwnPropertyNames / getOwnPropertyDescriptors enumeration
  indirection (F517 covers entries/keys/for-in; per F500/F505 precedent,
  different builtins are separate findings) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F513-F520 (round 31, scope reconfirmed), F521-F525 (this round).

Closed pins (must BLOCK, else BREAK): F496, F497, F498, F499, F500, F501,
F502, F503, F504, F505 (spot), F506, F507, F508, F509, F510, F511 (wave-363
closures, regression), F512 (perf fix, spot).

Rides-with-documented-scope (validated, NOT filed):
- Reflect.apply.bind(Reflect, [].concat, [], [...])() (prebound args) and
  Reflect.apply.bind(Reflect).call(null, ...) -- F513's bind-indirection
  family (filed shapes cover the unbound form).
- Reflect.apply([].concat.bind([], 'f1'), ...) rides inside F521 (bound
  target is the filed mechanism; direct/call/bind dispatches are 3 shapes
  of one finding).
- String('f1')[['concat'][0]](String('f2')) (single-nested on boxed string)
  -- F514's nested-bracket member-key scope.
- (function(){const args=arguments;...}) and reassigned-alias
  (var args=arguments; args=Array.from(args)) -- F516's alias-laundering
  family (one identifier; destructuring is F524).
- (function(){var r='';var o={...};for(var k in o)r+=o[k];return r})()
  (for-in accumulating VALUES) -- F517's for-in statement scope (keys
  variant is the filed shape).
- Array.fromAsync / for-await shapes -- async boundary, no synchronous
  credential (documented, NOT filed).
- 512+ fail-closed matches ahead of a real expression -- the F512
  documented honest residual (600 matches: 0.51s, fail-closed starvation,
  no bypass; NOT filed).
Dead/bogus round-32 proposals (validated locally, NOT filed):
D1-bind-no-invoke (Reflect.apply.bind(...) without invocation -- returns a
  bound function, never evaluated; malformed probe, my error); D2-array-join
  ('f1'[['concat'][0]]('f2') without .join -- node returns an array, not the
  credential; probe artifact); D3-fill (Array.prototype.fill.call cannot
  produce two distinct fragments from one fill value -- mechanism dead);
D4-iife-string-target (IIFE returning a string is not callable -- TypeError,
  probe error); D5-sort-call (sort.call blocks coded -- HELD); D6-descriptors
  -direct (Object.getOwnPropertyDescriptors({b:'f1f2'}).b.value blocks
  coded -- HELD); D7-spread-direct ([...arguments].join('') blocks coded --
  HELD); D8-concat/join-call (Array.prototype.concat.call / join.call block
  coded -- HELD, F511-family scope).
Model note: 8/8 prompts returned parseable JSON (truncated at 150 tokens as
usual); salvaged: bind-target-in-bind/call shapes (F521), IIFE-arrow target
(F522), descriptors-direct-prop (dead, HELD), const-alias (F516 scope),
sort-call (dead, HELD), for-in-values (F517 scope). All filed shapes were
hand-crafted and node-verified (v24.20.0). Junk-quiet controls pass.
No injection attempts this round.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g364-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

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
    """Pin stays 2144; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F526/F528/F529 open, next F531 (wave-366
    lane 2: F527/F530 CLOSED)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-366 lane 2: F527/F530 CLOSED; F526/F528/F529 OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in text)  # Wave-366 lane 2: F527/F530 CLOSED; F526/F528/F529 OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
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
    """F506 CLOSED (wave-363 lane 1, merge): Reflect.apply via call/apply
    indirection now blocks (regression pin)."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f507_closed():
    """F507 CLOSED (wave-363 lane 2, merge): bracket on string literals
    now blocks (regression pin)."""
    ms = _misses("''['concat']('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f508_closed():
    """F508 CLOSED (wave-363 lane 2, merge): Array.from with mapper
    now blocks (regression pin)."""
    ms = _misses("Array.from(['%s','%s'], x=>x).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f509_closed():
    """F509 CLOSED (wave-363 lane 3, merge): bare arguments receiver
    now blocks (regression pin)."""
    ms = _misses("(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f510_closed():
    """F510 CLOSED (wave-363 lane 4, merge): Object.values indirection
    now blocks (regression pin)."""
    ms = _misses("Object.values({0:'%s',1:'%s'}).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f511_closed():
    """F511 CLOSED (wave-363 lane 4, merge): splice.call dispatch
    now blocks (regression pin)."""
    ms = _misses("Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p1_f512_closed():
    """F512 CLOSED: perf fix -- the F452 200-statement pin still holds
    (battery-exact: fail-closed junk statements + real expression)."""
    junk200 = "".join("'%s';" % ("j%d" % i) for i in range(200))
    real = "['%s','%s'].reduce((a,b)=>a+b)" % (_A, _B)
    v = dlp._try_js_expr_decode_all(junk200 + real)
    ok = v is not None and _CRED in v
    return ("HELD" if ok else "BREAK", "variant_has_cred=%s" % ok)


# ------------------------------------------------- open pins (must miss)

@_t
def test_p2_f513_closed():
    """F513 CLOSED (wave-364 lane 1): Reflect.apply via .bind now blocks
    (coded refusal -- wave-306 class)."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    hit2 = _blocked("Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f514_closed():
    """F514 CLOSED (wave-364 lane 2): nested-bracket key on a String-object
    receiver now blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f515_closed():
    """F515 CLOSED (wave-364 lane 2): idx-folded key on strlit now blocks
    (coded refusal -- wave-306 class)."""
    hit = _blocked("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f516_closed():
    """F516 CLOSED (wave-364 lane 3): laundered arguments now block
    (coded refusal -- wave-306 class)."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    hit2 = _blocked("(function(...args){return args.join('');})('%s','%s')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f517_open():
    """F517 CLOSED (wave-364 lane 3): entries/keys/for-in now block
    (coded refusal -- wave-306 class)."""
    hit = _blocked("Object.entries({0:'%s',1:'%s'}).map(p=>p[1]).join('')" % (_A, _B))
    hit2 = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f518_open():
    """F518 OPEN (round 31): mutating-method .call still misses."""
    ms = _misses("var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f519_closed():
    """F519 CLOSED (wave-364 lane 1): function-valued-target Reflect.apply
    now blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    hit2 = _blocked("Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f520_closed():
    """F520 CLOSED (wave-364 lane 4): Array.fromAsync.then now blocks
    (coded refusal -- wave-306 class)."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f521_closed():
    """F521 CLOSED (wave-365 lane 1): .bind-bound Reflect.apply target now
    blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f522_closed():
    """F522 CLOSED (wave-365 lane 2): IIFE-evaluated Reflect.apply target
    now blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A, _B))
    hit2 = _blocked("Reflect.apply((function(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f523_closed():
    """F523 CLOSED (wave-365 lane 3): triple-nested bracket key now
    blocks (coded refusal -- wave-306 class: the probe that
    demonstrated the BREAK now asserts the refusal)."""
    ms = _misses("'%s'[[[['concat'][0]]][0]]('%s')" % (_A, _B))
    ms2 = _misses("String('%s')[[[['concat'][0]]][0]](String('%s'))"
                  % (_A, _B))
    return ("HELD" if not ms and not ms2 else "BREAK",
            "miss=%s miss2=%s" % (ms, ms2))


@_t
def test_p2_f524_closed():
    """F524 CLOSED (wave-365 lane 3): destructured arguments now
    block (coded refusal -- wave-306 class: the probe that
    demonstrated the BREAK now asserts the refusal)."""
    ms = _misses("(function(){const [a,b]=arguments;return a+b})('%s','%s')"
                 % (_A, _B))
    ms2 = _misses("(function(){var [x,y]=arguments;return x+y})('%s','%s')"
                  % (_A, _B))
    return ("HELD" if not ms and not ms2 else "BREAK",
            "miss=%s miss2=%s" % (ms, ms2))


@_t
def test_p2_f525_closed():
    """F525 CLOSED (wave-365 lane 2): getOwnPropertyNames/Descriptors
    enumeration now blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    hit2 = _blocked("Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f530_closed():
    """F530 CLOSED (wave-366 lane 2; filed as F526 by wave-365 lane 1,
    renumbered at wave-365 merge per wave-272 rule): .bind-bound JOIN
    target now blocks."""
    hit = _blocked("Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- boundaries

@_t
def test_p3_f512_residual_documented():
    """F512 residual: 600 fail-closed matches starve (no bypass), fast."""
    import time
    payload = '"a".concat(' * 600 + "['%s','%s'].join('')" % (_A, _B)
    t0 = time.time()
    hit = _blocked(payload)
    dt = time.time() - t0
    ok = (not hit) and dt < 5.0
    return ("HELD" if ok else "BREAK", "starved=%s dt=%.2f" % (not hit, dt))


@_t
def test_p3_junk_quiet():
    """Junk stays quiet."""
    ms = _misses("Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')")
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-363 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g364-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w363_attack_probes.py")],
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
    # The w363 battery's footer pin is stale by design: this lane filed
    # F521-F525, so its expected footer (open F513-F520 / next F521) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w363_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-363 attack battery stays green (depth-1)."""
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
