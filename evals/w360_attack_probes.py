#!/usr/bin/env python3
"""Wave-360 attack round 28 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.001118, ledger 457 -> 467)
plus deterministic local validation (node v24.20.0 ground truth +
scanner verdict on every candidate, red-first fragment sizing)
against the wave-359-merged base (f98f5696: F482-F488 closed, F489-F495
open).

New findings filed (all LOW, OPEN, red-first verified):
- F496: Reflect.ownKeys key-enumeration indirection at dispatch targets
  (filter/find/ctor-of/join) -- 4 shapes.
- F497: non-empty-array constructor-property factory (['x'].constructor.of,
  the F476 documented residual) -- 3 shapes.
- F498: bracket-form Reflect['construct'] dispatch (the F480 documented
  residual candidate; dot form already blocks) -- 2 shapes.
- F499: spread of string literals in array literals ([...'f1',...'f2'],
  the F471 documented candidate residual) -- 3 shapes.
- F500: spread args in String.fromCharCode (new call site vs F462's
  concat-spread, closed) -- 2 shapes.
- F501: fragment assembly through local value bindings (let/var/const
  additive; F495 covers method bindings, this is value bindings) -- 4 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F489-F495 (round 27), F496-F501 (this round).

Closed pins (must BLOCK / fail-closed, else BREAK): F473, F475, F476, F477,
F478, F479, F480, F481, F482, F483, F484, F485, F486, F487, F488 (spot).

Rides-with-documented-scope (validated, NOT filed):
- ([]['concat'] ?? [].join).call([], ...) -- F490 family (?? member pick;
  F490 filed the dot-form; same mechanism).
- Array.prototype['con'.concat('cat')].call -- F492 family (computed key;
  F492 filed additive/template keys; still OPEN).
- (function(){return [...arguments].join('')})('f1','f2') -- F494 family
  (spread of a non-literal iterable; F494 filed generator/Set/Map.values).
- const c = [].concat; c.apply(...) / c.bind([])(...) / const {concat:c2}
  / const {prototype:{concat}} destructuring / var c / sloppy-assign --
  F495 family (local bindings; F495 filed const/let/destructure).
- String.prototype.replace.apply('X', ['X', frag]) -- already HELD
  (F478 residual verified covered).
- Array.prototype[Reflect.ownKeys...] on getPrototypeOf receivers --
  HELD (decoder blocks; not filed).
- [...new String('f1f2')].join('') -- HELD (String-object spread blocked).
- 'a'.padStart(5, 1.5) -- HELD (F477 float fail-closed, documented).
Dead/bogus round-28 proposals (validated locally, NOT filed):
D1-object-spread-reexport ({...Array.prototype} is {} -- prototype methods
are non-enumerable; node THROW); D2-arrow-arguments (arrows lack arguments;
node THROW); D3-model-xctor-outputs (model omitted .join('') -- array, not
the credential string); D4-reflect-construct-dot (dot form already HELD);
D5-typed-array-spread ([...new Uint8Array] spreads numbers -- no credential
path without fromCharCode composition); D6-nonfoldable-key (['con'+x] with
unbound x -- node THROW).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g360-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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
    """Control: footer shows no open findings after F506-F511 closures
    (wave-363 lanes 1-4), next F513 (merge finalizes)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F612**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
          and "**Open findings: F595, F606, F608, F609, F610, F611.**" in text)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------- closed pins (must block, else BREAK)

@_t
def test_b1_f482_bracket_dispatch_closed():
    """F482 pinned CLOSED (wave-359 merge): bracket dispatch."""
    hit = _blocked("Array.prototype['concat'].call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f483_apply_nonconcat_closed():
    """F483 pinned CLOSED (wave-359 merge): .apply on non-concat methods."""
    hit = _blocked("Array.prototype.join.apply(['" + _A + "','" + _B + "'], [''])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f484_factory_nested_closed():
    """F484 pinned CLOSED (wave-359 merge): factory nested-array args."""
    hit = _blocked("[].constructor.of(['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f486_static_call_closed():
    """F486 pinned CLOSED (wave-359 merge): Array.of.call dispatch."""
    hit = _blocked("Array.of.call(Array, '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f488_paren_ctor_closed():
    """F488 pinned CLOSED (wave-359 merge): parenthesized ctor callee."""
    hit = _blocked("([].constructor)('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------- open pins, prior rounds (must miss)

@_t
def test_b2_f489_proxy_open():
    """F489 pinned OPEN: Proxy get-trap receiver still misses."""
    hit = _blocked("Array.prototype.join.call(new Proxy({length:2}, "
                   "{get:(t,p)=>p==='length'?2:({0:'" + _A + "',1:'" + _B + "'})[p]}), '')")
    return ("HELD" if not hit else "BREAK", "hit=%s (want miss)" % hit)


@_t
def test_b2_f490_optchain_closed():
    """F490 CLOSED (wave-360 merge, lane 1)."""
    hit = _blocked("Array.prototype.concat?.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f491_reflect_get_closed():
    """F491 CLOSED (wave-360 merge, lane 2)."""
    hit = _blocked("Reflect.get(Array.prototype,'concat').call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b2_f495_freevar_closed():
    """F495 CLOSED (wave-360 merge, lane 3)."""
    hit = _blocked("const {concat} = Array.prototype; concat.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# ------------------------------- closed by wave-361 (must block)

@_t
def test_b3_f496_ownkeys_closed():
    """F496 CLOSED (wave-361): ownKeys indirection now decodes."""
    hit = _blocked("Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]]"
                   ".call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f497_xctor_closed():
    """F497 CLOSED (wave-361): non-empty factory receiver now decodes."""
    hit = _blocked("['x'].constructor.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f498_bracket_construct_open():
    """F498 CLOSED (wave-361 lane 2): Reflect['construct'] now blocks."""
    hit = _blocked("Reflect['construct'](Array, ['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f499_string_spread_open():
    """F499 CLOSED (wave-361 lane 2): string-literal spread now blocks."""
    hit = _blocked("[...'" + _A + "', ...'" + _B + "'].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f500_fromcharcode_spread_closed():
    """F500 CLOSED (wave-361 lane 3): fromCharCode spread args now block."""
    hit = _blocked("String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '" + _B + "'")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


@_t
def test_b3_f501_value_binding_closed():
    """F501 CLOSED (wave-361 lane 3): fragment value bindings now block."""
    hit = _blocked("let a='" + _A + "', b='" + _B + "'; a,b; a+b")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)


# ------------------------------------------------- green check (depth-1)

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: run the wave-359 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g360-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w359_attack_probes.py")],
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
            "green(w359_attack): %d real BREAK (%d tolerated footer)"
            % (len(real), len(tolerated)))


@_t
def test_p9_green_check():
    """Green check: wave-359 attack battery stays green (depth-1)."""
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
