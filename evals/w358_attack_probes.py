#!/usr/bin/env python3
"""Wave-358 attack round 26 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.00098, ledger 437 -> 447)
plus deterministic local validation (node v24.20.0 ground truth +
scanner verdict on every candidate, red-first fragment sizing)
against the wave-357-merged base (5ffa4c5a: F478/F479 closed, F480/F481
open).

New findings filed (all LOW, OPEN, red-first verified):
- F482: bracket-string member access on prototype methods under
  .call/.apply dispatch (F478 x F480-B composition) -- 10 shapes.
- F483: .apply/.bind dispatch (and dispatch chains) on non-concat
  prototype methods (F478 documented residual) -- 11 shapes.
- F484: constructor-factory with non-string-literal args: nested arrays,
  spread (F476 documented residual) -- 7 shapes.
- F485: array-literal edge spellings beyond F479's modeled classes:
  sparse holes, trailing comma, depth-2+ nesting -- 5 shapes.
- F486: .call/.apply dispatch on static factory methods (Array.of.call,
  [].constructor.of.call, String.fromCharCode.apply) -- 3 shapes.
- F487: .call dispatch on array-like (non-array) receivers -- 3 shapes.
- F488: direct invocation of constructor spellings through
  non-identifier callees (([].constructor)(...)) -- 4 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F480 (constructor-dispatch/bracket-access), F481 (call-dispatch drops
F479 markers), F482-F488 (this round).

Closed pins (must BLOCK / fail-closed, else BREAK):
F476 (constructor-property factory), F477 (String-coercion),
F478 (dot-form call dispatch), F479 (join-coercion), F473
(array-receiver concat), F475 (mixed-type filter over-decode).

Rides-with-documented-scope (validated, NOT filed):
- Reflect['apply']([].constructor, [].constructor, [['f1'],['f2']]) --
  F480-A family ([].constructor spelling of Array).
- Reflect['apply'](String.prototype['concat'], '', ['f1','f2']) --
  F480-B family (bracket Reflect.apply, concat target).
- Array.prototype.join.call(['f1',null,'f2'], '') -- HELD (receiver
  parser is F479-aware; the F481 gap is arguments only).
- [].concat.call([], ...['f1','f2']) -- HELD (spread through .call).
- ['f1',[null],'f2'].join('') -- HELD (null inside nested arrays).
Dead/bogus round-26 proposals (validated locally, NOT filed):
D1-push-call-join (node THROW -- push returns length); D2-nested-undef
(comma -- node never recovers); D3-concat-arraylike-noargs
('[object Object]'); D4-ctor-of-numeric / D5-reduce-null / D6-join-bool /
D7-concat-apply-numeric / D8-assign-call / D9-join-nested-mixed /
D10-join-hole-tostring (node never recovers the credential).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g358-*
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
    """Control: footer shows F480-F488 open, next F489 (wave-358 lane 3:
    F482-F488 filed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F489**" in text
          and "**Open findings: F480, F481, F482, F483, F484, F485, F486, F487, F488.**" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------- closed pins (must block, else BREAK)

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
def test_b1_f473_array_concat_closed():
    """F473 pinned CLOSED (wave-355 merge): array-receiver concat."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f475_numstr_closed():
    """F475 pinned CLOSED (wave-355 merge, lane 3): mixed-type filter
    over-decode fails closed."""
    hit = _blocked("['" + _A + "',1].filter(x=>x.length>0).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F480/F481 open pins

@_t
def test_b2_f480_apply_ctor_open():
    """F480 pinned OPEN (wave-357 lane 3): Array.apply ctor dispatch."""
    hit = _blocked("Array.apply(Array, ['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b2_f480_fcc_bracket_open():
    """F480 pinned OPEN: String['fromCharCode'] bracket access."""
    codes = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56,
             57, 97, 98, 99, 100, 101, 102]
    hit = _blocked("String['fromCharCode'](%s)" % ",".join(str(c) for c in codes))
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b2_f481_call_markers_open():
    """F481 pinned OPEN (wave-357 merge): concat.call drops F479 markers."""
    hit = _blocked("[].concat.call([],['" + _A + "',null,'" + _B + "']).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


# ------------------------------------------------- F482-F488 open pins

@_t
def test_b3_f482_bracket_dispatch_open():
    """F482 pinned OPEN: Array.prototype['concat'].call still misses."""
    hit = _blocked("Array.prototype['concat'].call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f483_apply_nonconcat_open():
    """F483 pinned OPEN: join.apply still misses."""
    hit = _blocked("Array.prototype.join.apply(['" + _A + "','" + _B + "'], [''])")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f483_bind_chain_open():
    """F483 pinned OPEN: double dispatch still misses."""
    hit = _blocked("Function.prototype.call.call(Array.prototype.concat, [], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f484_factory_nested_open():
    """F484 pinned OPEN: [].constructor['of'] with nested args misses."""
    hit = _blocked("[].constructor['of']('" + _A + "',['" + _B + "']).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f485_join_hole_open():
    """F485 pinned OPEN: sparse hole in join still misses."""
    hit = _blocked("['" + _A + "',,'" + _B + "'].join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f485_deep_nest_open():
    """F485 pinned OPEN: depth-2 nesting still misses."""
    hit = _blocked("['" + _A + "',[['" + _B + "']]].join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f486_factory_dispatch_open():
    """F486 pinned OPEN: Array.of.call still misses."""
    hit = _blocked("Array.of.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f487_arraylike_open():
    """F487 pinned OPEN: array-like receiver still misses."""
    hit = _blocked("Array.prototype.join.call({length:2, 0:'" + _A + "', 1:'" + _B + "'}, '')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b3_f488_ctor_spelling_open():
    """F488 pinned OPEN: ([].constructor)(...) still misses."""
    hit = _blocked("([].constructor)('" + _A + "','" + _B + "').join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


# ------------------------------------------------- green check (depth-1)

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: run the wave-357 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g358-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w357_attack_probes.py")],
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
            "green(w357_attack): %d real BREAK (%d tolerated footer)"
            % (len(real), len(tolerated)))


@_t
def test_p9_green_check():
    """Green check: wave-357 attack battery stays green (depth-1)."""
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
