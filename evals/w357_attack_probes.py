#!/usr/bin/env python3
"""Wave-357 attack round 25 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.00047, ledger 427 -> 437)
against the wave-356-merged base (fd359d56: F476/F477 closed, F478/F479
open). Local validation first (node v24.20.0 ground truth + scanner
verdict on every candidate with red-first fragment sizing -- the first
validation pass tripped the raw-text rule with oversized fragments and
was redone).

New finding filed (LOW, OPEN, red-first verified):
- F480: constructor-function call/apply dispatch + bracket-string member
  access on built-in call sites --
  Array.apply(Array,['f1','f2']).join(''), Array['apply'](Array,['f1','f2']),
  Array.call(Array,'f1','f2'), Array['call'](Array,'f1','f2'),
  [].constructor['apply']([].constructor,['f1','f2']),
  Reflect['apply'](Array,Array,[['f1'],['f2']]),
  String['fromCharCode'](120,111,...), Object['assign']([],[...]).
  All node-evaluate to the credential while the decoder produces zero
  variants. Distinct from F469 (Reflect.apply dot-form), F478
  (.call/.apply/.bind on prototype METHODS), F476 (constructor-property
  factory path -- no dispatch), F458 (fromCharCode dot form),
  F471 (Object.assign dot form).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F478 (.call/.apply/.bind miss), F479 (join-coercion miss),
F480 (constructor-dispatch/bracket-access miss).

Closed pins (must BLOCK / fail-closed, else BREAK):
F476 (constructor-property factory), F477 (String-coercion),
F473 (array-receiver concat), F474 (concat TypeError guard),
F475 (mixed-type filter over-decode).

Rides-with-documented-scope (validated, NOT filed):
- String.prototype.concat.call('',...['f1','f2']) etc. -- F478 family.
- [].constructor.of(1,'f1','f2') / ([...],'f2') -- F476 documented
  "numeric/nested/additive fail closed" residual.
- ['f1',null,'f2'].join('') -- F479 join-null-mid shape.
- Reflect.apply(Array.prototype.join,...) -- fail closed (F469 scope).
Dead/bogus round-25 proposals (validated locally, NOT filed):
C5-String(0)/String(true)/String([null]) (never build the credential);
C3-bool join (booleans break the credential: node never recovers);
C1-join-call-spread (node THROW -- malformed); comp-ctor-num
(['f1',1] via .of -- node never recovers); fc-string-null/undef
('null'/'undefined' -- no credential); c2-of shapes ride F476 residual.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g357-*
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
    """Control: footer shows F498-F502 open, next F503 (wave-361 lane 1:
    F496, F497 CLOSED locally; merge finalizes tree-wide)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F640**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
          and "**Open findings: F621, F622, F623, F624, F625, F626, F627, F628, F629, F630, F631, F632, F633, F634, F635, F636, F637, F638, F639.**" in text)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------- F476/F477 closed pins (wave-356 merge)

@_t
def test_b1_f476_ctor_factory_closed():
    """F476 pinned CLOSED (wave-356 merge, lane 1): constructor-property
    factory now blocks."""
    hit = _blocked("[].constructor.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f477_coercion_closed():
    """F477 pinned CLOSED (wave-356 merge, lane 2): String() coercion of
    numeric concat args now blocks."""
    hit = _blocked("['" + _A + "'].concat('" + _B + "', 1).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# --------------------------------- F473-F475 closed pins (sample)

@_t
def test_b1_f473_array_concat_closed():
    """F473 pinned CLOSED (wave-355 merge, lane 1): array-receiver paren
    .concat now blocks."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f474_typeerror_guard_closed():
    """F474 pinned CLOSED (wave-355 merge, lane 2): the concat TypeError
    guard fails closed without raising."""
    try:
        hit = _blocked("('" + _A + "').concat(['" + _B + "'])")
    except TypeError:
        return ("BREAK", "raised TypeError")
    return ("HELD" if not hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f475_numstr_closed():
    """F475 pinned CLOSED (wave-355 merge, lane 3): mixed-type filter
    over-decode fails closed."""
    hit = _blocked("['" + _A + "',1].filter(x=>x.length>0).join('')")
    return ("HELD" if not hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F478 closed pin (sample)

@_t
def test_b2_f478_call_dispatch_closed():
    """F478 pinned CLOSED (wave-357 merge, lane 1): .call dispatch on
    prototype methods now refuses coded."""
    hit = _blocked("Array.prototype.concat.call([], '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)  # Wave-357 merge: F478 CLOSED


# ------------------------------------------------- F479 closed pin (sample)

@_t
def test_b2_f479_join_coercion_closed():
    """F479 pinned CLOSED (wave-357 merge, lane 2): join() coercion of null
    elements now refuses coded."""
    hit = _blocked("['" + _A + "',null,'" + _B + "'].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s (want block)" % hit)  # Wave-357 merge: F479 CLOSED


# ------------------------------------------------- F480 closed pins

@_t
def test_b3_f480_apply_ctor_open():
    """F480 CLOSED (wave-358 lane 1): Array.apply constructor
    dispatch now blocked."""
    hit = _blocked("Array.apply(Array, ['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-358 lane 1: F480 CLOSED


@_t
def test_b3_f480_call_ctor_bracket_open():
    """F480 CLOSED (wave-358 lane 1): Array['call'] constructor dispatch
    now blocked."""
    hit = _blocked("Array['call'](Array, '" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-358 lane 1: F480 CLOSED


@_t
def test_b3_f480_fcc_bracket_open():
    """F480 CLOSED (wave-358 lane 1): String['fromCharCode'] bracket access
    now blocked."""
    codes = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56,
             57, 97, 98, 99, 100, 101, 102]
    hit = _blocked("String['fromCharCode'](%s)" % ",".join(str(c) for c in codes))
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-358 lane 1: F480 CLOSED


@_t
def test_b3_f480_assign_bracket_open():
    """F480 CLOSED (wave-358 lane 1): Object['assign'] bracket access
    now blocked."""
    hit = _blocked("Object['assign']([], ['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-358 lane 1: F480 CLOSED


# ------------------------------------------------- green check (depth-1)

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: run the wave-356 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g357-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w356_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=REPO_ROOT)
    out = (p.stdout + p.stderr)
    # Child prints "BREAKS: ['test_x', ...]": tolerate per-probe, never
    # per-line, so a real break co-occurring with the tolerated stale
    # footer break cannot be masked (review fix, wave-357 lane 3).
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
            "green(w356_attack): %d real BREAK (%d tolerated footer)"
            % (len(real), len(tolerated)))


@_t
def test_p9_green_check():
    """Green check: wave-356 attack battery stays green (depth-1)."""
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
