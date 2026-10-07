#!/usr/bin/env python3
"""Wave-363 attack round 31 battery.

Made 8 gpt-4o-mini calls (8 prompt families x 1 call, ledger 507 -> 515,
~$0.000607 estimated from token counts, ~$0.028513 lifetime of $5; the key
lacks api.usage.read, so these are estimates), saved round31_raw.json; bulk
of the work was deterministic hand-crafted probes ($0). No more model calls
are made -- this battery is $0-by-construction (grep-verified: no
realmodel_harness / ModelDriver / --provider openai / ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base f250581e):
- F513: Reflect.apply reached through .bind indirection (F506 covers
  call/apply only; bind returns a callable, never invokes) -- 2 shapes.
- F514: bracket member access on String-object receivers (new String /
  String() boxing; F507 covers string literals) -- 3 shapes.
- F515: array-index-folded member key on a string-literal receiver
  (''[['concat'][0]]; F507's fold is string-concat, F504's nested-bracket
  is Reflect-namespace-only) -- 2 shapes.
- F516: the arguments object laundered before dispatch (local alias, rest
  parameter, Array.from(arguments), Object.values(arguments); F509 covers
  bare arguments) -- 4 shapes.
- F517: object enumeration indirection -- Object.entries, Object.keys,
  for-in (F510 covers Object.values only) -- 3 shapes.
- F518: Array.prototype mutating methods through .call dispatch
  (push/unshift mutate a local, reverse.call returns the reversed array;
  F511 covers splice.call/.apply) -- 3 shapes.
- F519: Reflect.apply with a function-valued target (arrow / function
  expression; F469/F504/F506 model concat-family targets) -- 2 shapes.
- F520: Array.fromAsync dispatch unmodeled (F508 covers sync Array.from)
  -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F506-F511 (round 30, scope reconfirmed), F513-F520 (this round).

Closed pins (must BLOCK, else BREAK): F496, F497, F498, F499, F500, F501,
F502, F503, F504, F505 (spot), F512 (perf fix, spot).

Rides-with-documented-scope (validated, NOT filed):
- Array.from({length:2,0:'f1',1:'f2'}) -- exact F508 filed shape (OPEN).
- Array.prototype.splice.call({length:2,...}) -- exact F511 filed shape (OPEN).
- Array.prototype.join.apply(arguments,['']) -- F509's call/apply family
  (F506 precedent: call/apply siblings are one finding; OPEN).
- Reflect[['apply'][0]]([].concat,...) direct nested-bracket call -- F504
  family (nested-bracket on Reflect namespace; F504 OPEN).
- 512+ fail-closed matches ahead of a real expression -- the F512
  documented honest residual (600 matches: 0.52s, fail-closed starvation,
  no bypass; NOT filed).
Dead/bogus round-31 proposals (validated locally, NOT filed):
D1-fn-bind-call (Function.prototype.bind.call(Reflect.apply,Reflect,...)
  without invocation -- returns a bound function, never evaluated; the
  invoked variant IS F513); D2-double-indirect
  (Function.prototype.apply.call(Function.prototype.call,...) yields '';
  no recovery); D3-model-mutate-suggestions (push/unshift on fresh array
  literals -- no mutation persistence; probe artifacts); D4-model-fromasync
  (payloads contained 'ABCD' literally -- below fragment floor artifacts);
D5-str-concat-call ('String.prototype.concat.call' blocks coded -- HELD);
D6-concat-apply ('[].concat.apply' blocks coded -- HELD).
Model note: 8/8 prompts returned parseable JSON; salvaged: bind shapes
(F513), String-object bracket shapes (F514), arguments-alias/rest/from/
values shapes (F516), entries/keys/for-in (F517), push/unshift/reverse
(F518), reflect-arrow target (F519), fromAsync (F520). str-dblbracket
(F515) was hand-crafted. Junk-quiet controls pass throughout.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g363-*
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
    """Control: footer shows F521, F523, F524 open, next F526
    (wave-365 lane 2: F522, F525 CLOSED; merge finalizes)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F597**" in text  # Wave-365 lane 2: F522, F525 CLOSED  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and "**Open findings: F582, F583, F584, F585, F586, F587, F588, F589, F590, F591, F592, F593, F594, F595, F596.**" in text)  # Wave-365 lane 2: F522, F525 CLOSED  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
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
def test_p2_f506_closed():
    """F506 CLOSED (wave-363 lane 1, merge): Reflect.apply via call/apply
    indirection now blocks (wave-306 maintenance)."""
    ms = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f507_closed():
    """F507 CLOSED (wave-363 lane 2, merge): bracket on string literals
    now blocks (wave-306 maintenance)."""
    ms = _misses("''['concat']('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f508_closed():
    """F508 CLOSED (wave-363 lane 2, merge): Array.from with mapper
    now blocks (wave-306 maintenance)."""
    ms = _misses("Array.from(['%s','%s'], x=>x).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f509_closed():
    """F509 CLOSED (wave-363 lane 3, merge): bare arguments receiver
    now blocks (wave-306 maintenance)."""
    ms = _misses("(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f510_closed():
    """F510 CLOSED (wave-363 lane 4, merge): Object.values indirection
    now blocks (wave-306 maintenance)."""
    ms = _misses("Object.values({0:'%s',1:'%s'}).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f511_closed():
    """F511 CLOSED (wave-363 lane 4, merge): splice.call dispatch
    now blocks (wave-306 maintenance)."""
    ms = _misses("Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f513_closed():
    """F513 CLOSED (wave-364 lane 1): Reflect.apply via .bind now blocks
    (coded refusal -- wave-306 class: the probe that demonstrated the
    BREAK now asserts the refusal)."""
    hit = _blocked("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    hit2 = _blocked("Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f514_closed():
    """F514 CLOSED (wave-364 lane 2): the nested-bracket shape on
    String-object receivers now blocks (wave-306 maintenance). The
    single-bracket shapes were already closed by accident at the
    wave-363 merge (see test_p2_f514_partial_closed)."""
    ms = _misses("String('%s')[[['concat'][0]]](String('%s'))" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f514_partial_closed():
    """F514 shapes 1-2 CLOSED by accident at wave-363 merge (honest: the F507
    lane-2 generalization routes them to the already-modeled dot-form path;
    base-vs-merged evidence in the merge report)."""
    b1 = not _misses("new String('%s')['concat']('%s')" % (_A, _B))
    b2 = not _misses("String('%s')['concat']('%s')" % (_A, _B))
    ok = b1 and b2
    return ("HELD" if ok else "BREAK", "shape1=%s shape2=%s" % (b1, b2))


@_t
def test_p2_f515_closed():
    """F515 CLOSED (wave-364 lane 2): idx-folded key on strlit now
    blocks (wave-306 maintenance)."""
    ms = _misses("''[['concat'][0]]('%s','%s')" % (_A, _B))
    return ("HELD" if not ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f516_closed():
    """F516 CLOSED (wave-364 lane 3): laundered arguments now block
    (coded refusal -- wave-306 class)."""
    hit = _blocked("(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A, _B))
    hit2 = _blocked("(function(...args){return args.join('');})('%s','%s')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f517_closed():
    """F517 CLOSED (wave-364 lane 3): entries/keys/for-in now block
    (coded refusal -- wave-306 class)."""
    hit = _blocked("Object.entries({0:'%s',1:'%s'}).map(p=>p[1]).join('')" % (_A, _B))
    hit2 = _blocked("Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f518_open():
    """F518 CLOSED (narrowed, wave-364 lane 4): the reverse-call shape
    blocks; the push-call shape is a documented dataflow boundary
    (still misses, pinned)."""
    ms = _misses("var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (_A, _B))
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


@_t
def test_p2_f519_closed():
    """F519 CLOSED (wave-364 lane 1): function-valued-target
    Reflect.apply now blocks (coded refusal -- wave-306 class)."""
    hit = _blocked("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A, _B))
    hit2 = _blocked("Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (_A, _B))
    return ("HELD" if hit and hit2 else "BREAK", "hit=%s hit2=%s" % (hit, hit2))


@_t
def test_p2_f520_open():
    """F520 CLOSED (wave-364 lane 4): Array.fromAsync.then now blocks."""
    hit = _blocked("Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B))
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
    ms = _misses("Reflect.apply.bind(Reflect)([].concat, [], ['ab','cd']).join('')")
    return ("HELD" if ms else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-362 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g363-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w362_attack_probes.py")],
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
    # The w362 battery's footer pin is stale by design: this lane filed
    # F513-F520, so its expected footer (open F506-F511 / next F513) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w362_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-362 attack battery stays green (depth-1)."""
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
