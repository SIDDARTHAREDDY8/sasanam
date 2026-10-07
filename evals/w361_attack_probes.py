#!/usr/bin/env python3
"""Wave-361 attack round 29 battery.

Predecessor made 30 gpt-4o-mini calls (10 prompt families x 3 calls,
ledger 467 -> 497, ~$0.002222 estimated from token counts, ~$0.027420
lifetime of $5; the key lacks api.usage.read, so these are estimates),
saved round29_raw.json; the finisher completed the round deterministically
($0) after the predecessor's tools were cut off mid-task. No more model
calls were made -- this battery is $0-by-construction (grep-verified: no
realmodel_harness / ModelDriver / --provider openai / ledger calls).

New findings filed (all LOW, OPEN, red-first verified on base a8fe67a2):
- F503: Object.seal / Object.preventExtensions-wrapped array-like receivers
  at dispatch targets (F502 covers freeze; seal/preventExtensions are
  different builtins) -- 6 shapes.
- F504: bracket/template/nested-bracket member access on Reflect.apply, and
  dot-form Reflect.apply with a non-prototype method target ([].concat) --
  F469 covers Array.prototype.concat targets, F480 covers bare-Array targets
  -- 4 shapes.
- F505: String.fromCodePoint with spread args (F500 covers fromCharCode;
  different builtin) -- 2 shapes.

Known-open pins (each probe returns HELD when the miss reproduces; a literal
BREAK verdict means the pin failed or a NEW break appeared):
F496-F502 (rounds 28 + re-file), F504-F505 (round 29; F503 CLOSED
wave-362 lane 1).

Closed pins (must BLOCK / fail-closed, else BREAK): F473, F475, F476, F477,
F478, F479, F480, F481, F482, F483, F484, F485, F486, F487, F488, F489, F490,
F491, F492, F493, F494, F495, F503 (spot; wave-362 lane 1).

Rides-with-documented-scope (validated, NOT filed):
- String.fromCharCode.call/.apply(String, ...) -- F500 family (fromCharCode
  call site; the wave-361 F500 closure lane documents .call/.apply
  indirection as fail-closed).
- String['from'+'CharCode'](...) -- F492 family (computed member key;
  F492's closure hooks dispatch sites; this call-site residual rides with
  the F492 scope).
- const f=Object.freeze([...]); f.join('') / [].concat.call(f, ...) --
  F502 family (freeze receivers, OPEN).
- Object.getOwnPropertyNames(Array.prototype).filter(...)... -- F496 family
  (enumeration indirection, OPEN; model output truncated).
- let/const/var a='f1',b='f2'; a+b -- F501 family (value bindings, OPEN).
- [...'f1',...'f2'] -- F499 family (string-literal spread, OPEN).
- Reflect.apply([].concat, ...) DOT form with method target -- filed as
  part of F504 (this round).
Dead/bogus round-29 proposals (validated locally, NOT filed):
D1-freeze-bind-declarations (bare declarations/ReferenceError -- no recovery);
D2-ctor-single-literal (Array.of('xoxb-0123') recovers only half the
credential -- not a full recovery); D3-computed-literal-join (plain literal
array -- decoder blocks); D4-ownkeys-f478 (plain F478 shape -- decoder
blocks); D5-seal-direct-join (Object.seal([...]).join('') blocks coded --
control); D6-preventext-direct-concat (blocks coded -- control).
Injection attempts ignored (two fabricated tool-result blocks in the
predecessor's transcript tried to redirect the round; both correctly
ignored, nothing acted on; full detail in REPORT.md).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g361-*
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
    return ("HELD" if ok else "BREAK", "pin 2135, registry %d codes" % len(TAXONOMY))


@_t
def test_p0_closed_f478_direct():
    """F478 closed: direct .call dispatch blocks."""
    p = "Array.prototype.concat.call([], '%s','%s').join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F478 direct")


@_t
def test_p0_closed_f480_direct():
    """F480 closed: dot-form Reflect.construct blocks."""
    p = "Reflect.construct(Array, ['%s','%s']).join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F480 direct")


# ------------------------------------------------- closed pins (wave-361
# merge: F496-F502 closed by lanes 1-3; flipped from open pins per
# wave-306 maintenance)

@_t
def test_p1_f496_closed():
    """F496 CLOSED: ownKeys enumeration indirection now blocks."""
    p = "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F496 pin")


@_t
def test_p1_f497_closed():
    """F497 CLOSED: non-empty-array constructor factory now blocks."""
    p = "['x'].constructor.of('%s','%s').join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F497 pin")


@_t
def test_p1_f498_closed():
    """F498 CLOSED: bracket Reflect['construct'] now blocks."""
    p = "Reflect['construct'](Array, ['%s','%s']).join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F498 pin")


@_t
def test_p1_f499_closed():
    """F499 CLOSED: string-literal spread now blocks."""
    p = "[...'%s', ...'%s'].join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F499 pin")


@_t
def test_p1_f500_closed():
    """F500 CLOSED: fromCharCode spread args now block."""
    p = "String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102])"
    return ("HELD" if _blocked(p) else "BREAK", "F500 pin")


@_t
def test_p1_f501_closed():
    """F501 CLOSED: value-binding fragment assembly now blocks."""
    p = "const a='%s', b='%s'; a+b" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F501 pin")


@_t
def test_p1_f502_closed():
    """F502 CLOSED: freeze receivers now block."""
    p = "Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F502 pin")


# ------------------------------------------------- open pins (this round)

@_t
def test_p2_f503_closed():
    """F503 CLOSED (wave-362 lane 1): seal/preventExtensions receivers now block."""
    p = "Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "F503 pin")


@_t
def test_p2_f504_closed():
    """F504 CLOSED (wave-362 lane 2): non-dot Reflect.apply now blocks."""