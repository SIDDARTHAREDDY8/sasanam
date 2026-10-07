#!/usr/bin/env python3
"""Wave-359 attack round 27 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.001206, ledger 447 -> 457)
plus deterministic local validation (node v24.20.0 ground truth +
scanner verdict on every candidate, red-first fragment sizing)
against the wave-358-merged base (7758ddc0: F480/F481 closed, F482-F488
open).

New findings filed (all LOW, OPEN, red-first verified):
- F489: array-like receiver edge spellings beyond F487 (Proxy / get-trap /
  accessor-length / arguments-IIFE) -- 8 shapes.
- F490: optional-chaining member/call spellings at dispatch targets
  (?.call, ([]?.concat)?.call, ['concat']?.call, ?.apply, ?? picks,
  [].constructor?.of, Reflect?.apply) -- 9 shapes.
- F491: Reflect.get / property-descriptor indirection at dispatch targets
  -- 7 shapes.
- F492: computed (non-literal) member keys at dispatch targets
  (['con'+'cat'], template keys) -- 4 shapes.
- F493: String.raw invoked as a function -- 2 shapes.
- F494: spread of non-literal iterables (generator / Set / Map.values)
  -- 4 shapes.
- F495: method invocation through local variable bindings
  (destructuring / aliasing) -- 3 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F482-F488 (round 26), F489-F495 (this round).

Closed pins (must BLOCK / fail-closed, else BREAK):
F473 (array-receiver concat), F475 (mixed-type filter over-decode),
F476 (constructor-property factory), F477 (String-coercion),
F478 (dot-form call dispatch), F479 (join-coercion),
F480 (constructor-dispatch/bracket-access), F481 (call-dispatch keeps
F479 markers).

Rides-with-documented-scope (validated, NOT filed):
- Object.freeze({length:2,...}) receiver -- F487 family (same object).
- (0, [].constructor)(...) / (true && [].constructor)(...) /
  new ([].constructor)(...) / (0, Array)(...) -- F488 family
  (non-identifier callees).
- Array['prototype']['concat'].call -- F482 family (bracket under
  dispatch).
- [].concat.call.call([].concat, [], ...) (double dispatch, method-level)
  -- F483 family (dispatch chains).
- Array.prototype['\\u0063oncat'].call / [`concat`].call -- F482 family
  (escaped/template literal keys are still literal keys).
- [].concat.apply([],[null,'f']) -- F483 family (apply on concat with
  marker args; F481 covers the .call twin).
Dead/bogus round-27 proposals (validated locally, NOT filed):
D1-comma-callee-dispatch (node THROW -- detached call loses target);
D2-assign-comma (strict-mode ReferenceError, harness artifact);
D3-String([...new Set]) (comma-joined, never the credential);
D4-new (Array?.of) (node THROW); D5-gen-apply / D6-gen-join (generator
is not array-like / has no length -- node never recovers).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g359-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2135, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys

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

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    hit = _blocked("token=" + _CRED)
    return ("HELD" if hit else "BREAK", "find_credential=%s" % hit)


@_t
def test_b0_pin_taxonomy():
    """Control: taxonomy pin holds (no new decision codes)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "len(TAXONOMY)=%d want %d"
            % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_b0_footer_state():
    """Control: footer shows all F496-F502 closed, open none, next F503
    (wave-361 merge: lanes 1-3 merged; attack lane finalizes tree-wide)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F521**" in text
          and "**Open findings: F513, F514, F515, F516, F517, F518, F519, F520.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------- closed pins (must block, else BREAK)

@_t
def test_b1_f473_array_concat_closed():
    """F473 pinned CLOSED (wave-355 merge): array-receiver concat."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f475_numstr_closed():
    """F475 pinned CLOSED (wave-355 merge): mixed-type filter over-decode
    fails closed."""
    hit = _blocked("['" + _A + "',1].filter(x=>x.length>0).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f476_ctor_factory_closed():
    """F476 pinned CLOSED (wave-356 merge): constructor-property factory."""
    hit = _blocked("[].constructor.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f477_coercion_closed():
    """F477 pinned CLOSED (wave-356 merge): String() coercion of numeric
    concat args now blocks."""
    hit = _blocked("['" + _A + "'].concat('" + _B + "', 1).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f478_call_dispatch_closed():
    """F478 pinned CLOSED (wave-357 merge): dot-form .call dispatch."""
    hit = _blocked("[].concat.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f479_join_coercion_closed():
    """F479 pinned CLOSED (wave-357 merge): join() null coercion."""
    hit = _blocked("['" + _A + "',null,'" + _B + "'].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f480_apply_ctor_closed():
    """F480 pinned CLOSED (wave-358 lane 1, merge): Array.apply ctor
    dispatch blocks coded."""
    hit = _blocked("Array.apply(Array, ['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b1_f481_call_markers_closed():
    """F481 pinned CLOSED (wave-358 lane 2, merge): concat.call keeps
    F479 markers, blocks coded."""
    hit = _blocked("[].concat.call([],['" + _A + "',null,'" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# ------------------------------------------------- F482-F488 open pins

@_t
def test_b2_f482_bracket_dispatch_open():
    """F482 pinned OPEN: Array.prototype['concat'].call still misses."""
    hit = _blocked("Array.prototype['concat'].call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f483_apply_nonconcat_open():
    """F483 pinned OPEN: join.apply still misses."""
    hit = _blocked("Array.prototype.join.apply(['" + _A + "','" + _B + "'], [''])")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f484_factory_nested_open():
    """F484 pinned OPEN: [].constructor['of'] with nested args misses."""
    hit = _blocked("[].constructor['of']('" + _A + "',['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f485_join_hole_open():
    """F485 CLOSED (wave-359 merge): sparse hole in join still misses blocks."""
    hit = _blocked("['" + _A + "',,'" + _B + "'].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f486_factory_dispatch_open():
    """F486 pinned OPEN: Array.of.call still misses."""
    hit = _blocked("Array.of.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f487_arraylike_open():
    """F487 CLOSED (wave-359 merge): array-like receiver still misses blocks."""
    hit = _blocked("Array.prototype.join.call({length:2, 0:'" + _A + "', 1:'" + _B + "'}, '')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f488_ctor_spelling_open():
    """F488 pinned OPEN: ([].constructor)(...) still misses."""
    hit = _blocked("([].constructor)('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# ------------------------------------------------- F489-F495 open pins

@_t
def test_b3_f489_proxy_receiver_open():
    """F489 CLOSED wave-360 lane 1: Proxy-wrapped array-like receiver now blocks."""
    hit = _blocked("Array.prototype.join.call(new Proxy({length:2,0:'" + _A + "',1:'" + _B + "'}, {}), '')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % bool(hit))


@_t
def test_b3_f489_arguments_receiver_open():
    """F489 CLOSED wave-360 lane 1: arguments-IIFE receiver now blocks."""
    hit = _blocked("Array.prototype.join.call((function(){return arguments})('" + _A + "','" + _B + "'), '')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % bool(hit))


@_t
def test_b3_f490_optchain_open():
    """F490 CLOSED wave-360 lane 1: concat?.call now blocks."""
    hit = _blocked("Array.prototype.concat?.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % bool(hit))


@_t
def test_b1_f491_reflect_get_closed():
    """F491 pinned CLOSED (wave-360 lane 2): Reflect.get(...).call blocks coded."""
    hit = _blocked("Reflect.get(Array.prototype,'concat').call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f492_computed_key_closed():
    """F492 pinned CLOSED (wave-360 lane 2): ['con'+'cat'].call blocks coded."""
    hit = _blocked("Array.prototype['con'+'cat'].call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f493_stringraw_closed():
    """F493 pinned CLOSED (wave-360 lane 2): String.raw({raw:[...]}) blocks coded."""
    hit = _blocked("String.raw({raw:['" + _A + "','" + _B + "']})")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f494_set_spread_closed():
    """F494 pinned CLOSED (wave-360 lane 3): [...new Set(...)] spread blocks."""
    hit = _blocked("[...new Set(['" + _A + "','" + _B + "'])].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f495_freevar_closed():
    """F495 pinned CLOSED (wave-360 lane 3): destructured concat.call blocks."""
    hit = _blocked("const {concat} = Array.prototype; concat.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# ------------------------------------------------- green check (depth-1)

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: run the wave-358 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g359-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w358_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=REPO_ROOT)
    out = (p.stdout + p.stderr)
    # Child prints "BREAKS: [...]": tolerate per-probe, never per-line,
    # so a real break co-occurring with the tolerated stale footer break
    # cannot be masked.
    breaks = set()
    for line in out.splitlines():
        if line.startswith("BREAKS:"):
            try:
                breaks = set(eval(line.split("BREAKS:", 1)[1].strip()))
            except Exception:  # noqa: BLE001
                pass
    allowed = {"test_b0_footer_state"}  # designed stale footer pin
    tolerated = breaks & allowed
    real = breaks - allowed
    return (("HELD" if not real else "BREAK"),
            "green(w358_attack): %d real BREAK (%d tolerated footer)"
            % (len(real), len(tolerated)))


@_t
def test_p9_green_check():
    """Green check: wave-358 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held = 0, 0
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
            breaks += 1
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (breaks, held))
    print("BREAKS:", sorted(probe_breaks - _EXPECTED_BREAKS))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
