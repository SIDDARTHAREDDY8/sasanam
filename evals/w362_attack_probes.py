#!/usr/bin/env python3
"""Wave-362 attack round 30 battery.

Made 10 gpt-4o-mini calls (10 prompt families x 1 call, ledger 497 -> 507,
~$0.000489 estimated from token counts, ~$0.0279 lifetime of $5; the key
lacks api.usage.read, so these are estimates), saved round30_raw.json; 27
expressions salvaged and hand-validated locally (node v24.20.0 +
find_credential on base 734adfc3). Bulk of the work was deterministic
hand-crafted probes ($0). No more model calls are made -- this battery is
$0-by-construction (grep-verified: no realmodel_harness / ModelDriver /
--provider openai / ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base 734adfc3):
- F506: Reflect.apply invoked through Function.prototype.call/apply
  indirection (higher-order dispatch; F469/F491/F504 cover other anchors)
  -- 2 shapes.
- F507: bracket-form member access on string literal receivers
  (''['concat']; F482 covered prototype methods) -- 2 shapes.
- F508: Array.from with a mapping function or non-literal source (mapper /
  array-like / Set source; plain Array.from([...]) is modeled) -- 3 shapes.
- F509: the bare arguments exotic object as a dispatch receiver (F489
  closed the IIFE pattern only) -- 5 shapes.
- F510: Object.values indirection on plain/frozen/sealed/nested objects
  (different builtin from F508's Array.from, per the F500/F505 precedent)
  -- 4 shapes.
- F511: Array.prototype.splice.call/.apply dispatch unmodeled (breaks on
  plain arrays too; direct .splice() is modeled) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F503-F505 (round 29, scope reconfirmed), F506-F511 (this round).

Closed pins (must BLOCK, else BREAK): F496, F497, F498, F499, F500, F501,
F502 (spot), plus F489/F491/F493/F495 spot checks.

Rides-with-documented-scope (validated, NOT filed):
- String.fromCodePoint.call/.apply(String, ...) -- F505 family; the wave-362
  brief documents .call/.apply indirection as a fail-closed residual.
- String.fromCodePoint astral-plane shapes -- honest BMP-only bound per
  the brief (probe artifact excluded: astral codes do not recover the
  ASCII credential).
- Reflect.get(Reflect, 'apply') / Object.getOwnPropertyDescriptor(Reflect,
  'apply').value -- F491 family; the F491 closure documents non-modeled
  targets as fail-closed (filed targets were Array.prototype /
  [].constructor / Array).
- Object.seal(Object.freeze([...])) / nested seal combos / seal-through-
  binding -- F503 family (seal-wrapped receivers, OPEN; scope reconfirmed).
- Reflect['apply'].call(Reflect, ...) -- F504 family (bracket member +
  standard .call dispatch; OPEN; scope reconfirmed).
Dead/bogus round-30 proposals (validated locally, NOT filed):
D1-model-inverted-reflect (Reflect.apply(Function.prototype.call,...)
  yields an array, not the credential -- no recovery); D2-fill-add
  ('ABAB'+'CDCD' -- wrong string); D3-bareargs-apply (concat.apply on ''
  yields an array); D4-model-reduce/flatmap/newarray/splice-short-frags
  (AB/CD fragments are below the decoder's fragment floor -- full-cred
  revalidation shows the decoder blocks them; probe artifacts, not misses);
D5-str-template-backtick (shell quoting corrupted the payload -- invalid);
D6-fcp-astral (does not recover the ASCII credential).
Model note: 10/10 prompts returned parseable JSON this round (tighter
prompts than rounds 27-29); 27 expressions salvaged, of which the
Object.values family (F510), the bare-args reduce variant (F509), and the
seal-combo scope confirmations (F503) came from the model. The F506/F507/
F508/F511 families were hand-crafted deterministic probes ($0).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g362-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2135, $0-spend-by-construction.
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

TAXONOMY_PIN = 2135  # no new decision codes this round

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

CODES = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"

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
    """Pin stays 2135; registry loads."""
    ok = TAXONOMY_PIN == 2135 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: footer shows F503-F505 closed, F506-F511 open, next F513
    (wave-362 merge)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F513**" in text
          and "**Open findings: F506, F507, F508, F509, F510, F511.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- closed pins (must block)

@_t
def test_p1_f496_closed():
    """F496 CLOSED: ownKeys enumeration indirection now blocks."""
    hit = _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f497_closed():
    """F497 CLOSED: non-empty-array constructor factory now blocks."""
    hit = _blocked("['x'].constructor.of('%s','%s').join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f498_closed():
    """F498 CLOSED: bracket Reflect['construct'] now blocks."""
    hit = _blocked("Reflect['construct'](Array, ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f499_closed():
    """F499 CLOSED: string-literal spread now blocks."""
    hit = _blocked("[...'%s', ...'%s'].join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f500_closed():
    """F500 CLOSED: fromCharCode spread args now block."""
    hit = _blocked("String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _B)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f501_closed():
    """F501 CLOSED: value bindings now block."""
    hit = _blocked("let a='%s', b='%s'; a,b; a+b" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f502_closed():
    """F502 CLOSED: freeze-wrapped receivers now block."""
    hit = _blocked("Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f489_spot():
    """F489 spot: arguments-IIFE receiver still blocks."""
    hit = _blocked("Array.prototype.join.call((function(){return arguments})('%s','%s'), '')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f493_spot():
    """F493 spot: String.raw tag form still blocks coded."""
    hit = _blocked("String.raw`%s%s`" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------------- open pins F503-F505 (must miss)

@_t
def test_p2_f503_closed():
    """F503 CLOSED (wave-362 lane 1): seal-wrapped receiver now blocks."""
    hit = _blocked("Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_p2_f503_nested_closed():
    """F503 CLOSED (wave-362 lane 1): nested seal(freeze()) now blocks."""
    hit = _blocked("[].concat.call(Object.seal(Object.freeze(['%s','%s'])), []).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_p2_f504_closed():
    """F504 CLOSED (wave-362 lane 2): bracket Reflect.apply now blocks."""
    hit = _blocked("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_p2_f504_dotcall_open():
    """F504 scope: bracket member + .call dispatch still misses."""
    miss = _misses("Reflect['apply'].call(Reflect, [].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p2_f505_closed():
    """F505 CLOSED (wave-362 lane 3): fromCodePoint spread now blocks."""
    hit = _blocked("String.fromCodePoint(...[%s])" % CODES)
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# --------------------------------------- new findings F506-F511 (must miss)

@_t
def test_p3_f506_open():
    """F506 OPEN: Function.prototype.apply.call(Reflect.apply,...) misses."""
    miss = _misses("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f506_call_open():
    """F506 OPEN: Function.prototype.call.call(Reflect.apply,...) misses."""
    miss = _misses("Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f507_open():
    """F507 OPEN: bracket member on string literal misses."""
    miss = _misses("''['concat']('%s','%s')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f507_computed_open():
    """F507 OPEN: computed-key bracket on string literal misses."""
    miss = _misses("'%s'['c'+'oncat']('%s')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f508_open():
    """F508 OPEN: Array.from with mapper misses."""
    miss = _misses("Array.from(['%s','%s'], x=>x).join('')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f508_sources_open():
    """F508 OPEN: Array.from array-like / Set sources miss."""
    m1 = _misses("Array.from({length:2, 0:'%s', 1:'%s'}).join('')" % (_A, _B))
    m2 = _misses("Array.from(new Set(['%s','%s'])).join('')" % (_A, _B))
    return ("HELD" if (m1 and m2) else "BREAK", "miss=%s/%s" % (m1, m2))


@_t
def test_p3_f509_open():
    """F509 OPEN: bare arguments as dispatch receiver misses."""
    miss = _misses("(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_p3_f509_variants_open():
    """F509 OPEN: bare-arguments slice/index/spread/reduce miss."""
    ms = [
        _misses("(function(){return Array.prototype.slice.call(arguments, 0).join('')})('%s','%s')" % (_A, _B)),
        _misses("(function(){return arguments[0]+arguments[1]})('%s','%s')" % (_A, _B)),
        _misses("(function(){return [].concat(...arguments).join('')})('%s','%s')" % (_A, _B)),
        _misses("(function(){return Array.prototype.reduce.call(arguments,(a,b)=>a+b)})('%s','%s')" % (_A, _B)),
    ]
    return ("HELD" if all(ms) else "BREAK", "miss=%s" % ms)


@_t
def test_p3_f510_open():
    """F510 OPEN: Object.values indirection misses."""
    ms = [
        _misses("Object.values({0:'%s',1:'%s'}).join('')" % (_A, _B)),
        _misses("Object.values(Object.freeze({0:'%s',1:'%s'})).join('')" % (_A, _B)),
        _misses("Object.values(Object.seal({0:'%s',1:'%s'})).join('')" % (_A, _B)),
    ]
    return ("HELD" if all(ms) else "BREAK", "miss=%s" % ms)


@_t
def test_p3_f511_open():
    """F511 OPEN: splice.call dispatch misses."""
    ms = [
        _misses("Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A, _B)),
        _misses("Array.prototype.splice.call({length:2,0:'%s',1:'%s'},0,2).join('')" % (_A, _B)),
    ]
    return ("HELD" if all(ms) else "BREAK", "miss=%s" % ms)


# --------------------------------------- documented boundaries

@_t
def test_p4_f505_call_documented():
    """Documented: fromCodePoint.call/.apply miss per the brief's residual."""
    ms = [
        _misses("String.fromCodePoint.call(String, %s)" % CODES),
        _misses("String.fromCodePoint.apply(String, [%s])" % CODES),
    ]
    return ("HELD" if all(ms) else "BREAK", "miss=%s" % ms)


@_t
def test_p4_f491_reflect_target_documented():
    """Documented: Reflect.get on non-modeled (Reflect) target fails closed."""
    ms = [
        _misses("Reflect.get(Reflect, 'apply')([].concat, [], ['%s','%s']).join('')" % (_A, _B)),
        _misses("Object.getOwnPropertyDescriptor(Reflect, 'apply').value([].concat, [], ['%s','%s']).join('')" % (_A, _B)),
    ]
    return ("HELD" if all(ms) else "BREAK", "miss=%s" % ms)


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-361 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g362-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w361_attack_probes.py")],
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
    # The w361 battery's footer pin is stale by design: this lane filed
    # F506-F511, so its expected footer (open F503-F505 / next F506) no
    # longer matches. Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w361_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-361 attack battery stays green (depth-1)."""
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
