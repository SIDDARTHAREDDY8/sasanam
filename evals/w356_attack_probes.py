#!/usr/bin/env python3
"""Wave-356 attack round 24 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.00045, ledger 417 -> 427)
against the wave-355-merged base (0c2ed594: F473-F475 closed, F476/F477
open). Local validation first (node v24.20.0 ground truth + scanner
verdict on every candidate); the model round then confirmed the .call
family and contributed .bind/reduce.call/filter.call/splice-replace
variants. Only node-exact + scanner-miss shapes were filed.

New findings filed (LOW, OPEN, red-first verified):
- F478: .call/.apply/.bind dispatch on prototype methods --
  Array.prototype.concat.call([],'f1','f2').join(''),
  String.prototype.concat.call('f1','f2'),
  [].concat.call([],'f1','f2').join(''),
  Array.prototype.join.call(['f1','f2'],''),
  Array.prototype.slice.call(['f1','f2'],0,2).join(''),
  Array.prototype.concat.apply([ ],['f1','f2']).join(''),
  Array.prototype.reduce.call(['f1','f2'],(acc,curr)=>acc+curr,''),
  Array.prototype.filter.call(['f1','f2',''], x=>x!=='').join(''),
  String.prototype.concat.bind('f1')('f2'),
  [].map.call(['f1','f2'], String).join(''),
  String.prototype.replace.call('f1,f2', /,/g, '').
  All node-evaluate to the credential while the decoder produces zero
  variants. Distinct from F469 (Reflect.apply -- the Reflect API dispatch
  path, a different mechanism).
- F479: join() coercion of non-string array elements --
  ['f1','f2',null].join(''), ['f1','f2',undefined].join(''),
  ['f1',['f2']].join('') node-evaluate to the credential (engine coerces:
  null/undefined -> "", nested arrays stringify) while the decoder's
  array parser fails closed on the whole literal. Distinct from F477
  (String() coercion of method ARGUMENTS -- a different parser path)
  and F475 (filter over-decode -- the opposite direction).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F476 (constructor-of miss), F477 (String-coercion miss),
F478 (.call/.apply/.bind miss), F479 (join-coercion miss).

Closed pins (must BLOCK / fail-closed, else BREAK):
F473 (array-receiver concat), F474 (concat TypeError guard),
F475 (mixed-type filter over-decode).

Confirmed fixed on the closed tree: the round-23 F473-class mis-decodes
([...['a']].concat(['b']), ['a','b'].map(String).concat(['c'])) now BLOCK.

Dead/bogus round-24 proposals (validated locally, NOT filed):
C2-ctorprop (all already decoded); C3 fragmentary shapes (never build the
credential); C5 typeof-map (fail-closed); C6 trim/includes predicates
(F470 documented scope); C9 fill+splice/map/reduce (node never recovers
the credential); C10 empty-element joins (already decoded);
String['fromCharCode'] (4 chars only); concat float/bool args and
join_bool (node never recovers the exact credential); f475_additive
(documented F475 residual); m_bind_join/m_splice_repl (node never
recovers); m_substr_call (BLOCKS -- control); f476_arr_from /
f476_ctor_from (BLOCKS -- already covered); 'C'.padStart(29,String(98))
(BLOCKS via raw-text rule); String([C,'']).split filter (BLOCKS via
raw-text rule).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g356-*
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
    """Control: footer shows F480 open, next F481 (wave-357 merge:
    F478, F479 CLOSED; merge finalized tree-wide)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F481**" in text  # Wave-357 merge: F480 filed
          and "**Open findings: F480.**" in text)  # Wave-357 merge: F478, F479 CLOSED
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------- F473-F475 closed pins (sample)

@_t
def test_b1_f473_array_concat_closed():
    """F473 pinned CLOSED (wave-355 merge, lane 1): array-receiver paren
    .concat now blocks."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f474_concat_typeerror_closed():
    """F474 pinned CLOSED (wave-355 merge, lane 2): the paren-concat
    non-spread arg path fails closed without raising."""
    try:
        hit = _blocked("('" + _A + "').concat(['" + _B + "'])")
    except Exception as e:  # noqa: BLE001 -- must never raise
        return ("BREAK", "raised %s" % type(e).__name__)
    return ("HELD" if not hit else "BREAK", "fail-closed=%s" % (not hit))


@_t
def test_b1_f475_filter_overdecode_closed():
    """F475 pinned CLOSED (wave-355 merge, lane 3): mixed-type filter no
    longer over-decodes."""
    hit = _blocked("['" + _A + "',1].filter(x=>x.length>0).join('')")
    return ("HELD" if not hit else "BREAK", "no-overdecode=%s" % (not hit))


@_t
def test_b1_f473_misdecode_fixed():
    """Round-23 F473-class mis-decodes now BLOCK on the closed tree
    (were corrupt variants pre-F473)."""
    h1 = _blocked("[...['" + _A + "']].concat(['" + _B + "']).join('')")
    h2 = _blocked("['" + _A + "','" + _B + "'].map(String).concat(['c']).join('')")
    ok = h1 and h2
    return ("HELD" if ok else "BREAK", "h1=%s h2=%s" % (h1, h2))


# ------------------------------------------------- F476/F477 open pins

@_t
def test_b2_f476_constructor_of_open():
    """F476 CLOSED (wave-356 merge): [].constructor.of now blocked."""
    hit = _blocked("[].constructor.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-356 merge: F476 CLOSED


@_t
def test_b2_f477_string_coercion_open():
    """F477 CLOSED (wave-356 merge): numeric concat-arg coercion now blocked."""
    hit = _blocked("['" + _A + "'].concat(123456789,'" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-356 merge: F477 CLOSED


@_t
def test_b2_f476_ctor_from_blocked():
    """Scope: [].constructor.from stays BLOCKED (not filed)."""
    hit = _blocked("[].constructor.from(['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F478/F479 open pins

@_t
def test_b2_f478_call_concat_open():
    """F478 CLOSED (wave-357 lane 1): Array.prototype.concat.call now blocked."""
    hit = _blocked("Array.prototype.concat.call([], '" + _A + "', '" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-357 lane 1: F478 CLOSED


@_t
def test_b2_f478_bind_concat_open():
    """F478 CLOSED (wave-357 lane 1): String.prototype.concat.bind now blocked."""
    hit = _blocked("String.prototype.concat.bind('" + _A + "')('" + _B + "')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-357 lane 1: F478 CLOSED


@_t
def test_b2_f478_call_filter_open():
    """F478 CLOSED (wave-357 lane 1): Array.prototype.filter.call now blocked."""
    hit = _blocked("Array.prototype.filter.call(['" + _A + "','" + _B + "',''], x=>x!=='').join('')")
    return ("HELD" if hit else "BREAK", "blocked=%s" % hit)  # Wave-357 lane 1: F478 CLOSED


@_t
def test_b2_f479_join_null_still_closed():
    """F479 CLOSED (wave-357 lane 2): join() null-element coercion now
    blocks -- the decoder models null -> "" engine-exactly."""
    hit = _blocked("['" + _A + "','" + _B + "',null].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f479_join_nested_still_closed():
    """F479 CLOSED (wave-357 lane 2): join() nested-array coercion now
    blocks -- the decoder models single-level nesting engine-exactly."""
    hit = _blocked("['" + _A + "',['" + _B + "']].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- scope notes

@_t
def test_b3_f469_reflect_apply_still_closed():
    """Scope: Reflect.apply concat (F469) still blocks -- .call is the
    distinct new shape, not a Reflect regression."""
    hit = _blocked("Reflect.apply(Array.prototype.concat,[],[['" + _A + "'],['" + _B + "']]).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_join_undefined_still_closed():
    """F479 CLOSED (wave-357 lane 2): join() undefined-element coercion
    now blocks -- the decoder models undefined -> "" engine-exactly."""
    hit = _blocked("['" + _A + "','" + _B + "',undefined].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f470_trim_filter_scope_quiet():
    """Scope: .filter(x=>x.trim()!=='') stays fail-closed (F470 scope)."""
    hit = _blocked("['" + _A + "','" + _B + "'].filter(x=>x.trim()!=='').join('')")
    return ("HELD" if not hit else "BREAK", "quiet=%s" % (not hit))


_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# open-finding probes pin the CURRENT miss behavior, so any BREAK is a
# real change (fix or regression), never an expected break.


def _green_check():
    """Depth-1 green check on the previous attack battery (wave-355).

    Honors GOV_SKIP_GREEN: when set, record a skipped note and return
    without spawning. A standalone run (var unset) runs the child with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).
    Wave-305-class note: w355_attack_probes.py's test_b0_footer_state
    pins the pre-filing footer (next F478, open F476/F477); this lane
    filed F478/F479 and moved the footer to next F480, so exactly that
    one stale probe is tolerated -- the merge's tree-wide footer sweep
    repoints it. Any OTHER break is a real regression and fails.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    child = os.path.join(REPO_ROOT, "evals", "w355_attack_probes.py")
    tmpdir = "/var/tmp/g356-attack-gc-%d" % os.getpid()
    os.makedirs(tmpdir, exist_ok=True)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpdir
    try:
        p = subprocess.run(
            [sys.executable, child], capture_output=True, text=True,
            env=env, timeout=600, cwd=REPO_ROOT)
    except Exception as e:  # noqa: BLE001
        return "ERROR spawning child: %s" % e
    out = (p.stdout or "") + (p.stderr or "")
    # Child prints "tally: H HELD / B BREAK / E ERROR" and "BREAKS: [...]".
    breaks = set()
    for line in out.splitlines():
        if line.startswith("BREAKS:"):
            try:
                breaks = set(eval(line.split("BREAKS:", 1)[1].strip()))
            except Exception:  # noqa: BLE001
                pass
    notes = []
    allowed = {"test_b0_footer_state"}
    tolerated = breaks & allowed
    real = breaks - allowed
    if tolerated:
        notes.append("tolerated stale footer probe: %s" % sorted(tolerated))
    if real:
        return "BREAK: unexpected child breaks %s %s" % (sorted(real), notes)
    # Child rc: 0 == all green (modulo tolerated), 1 == breaks incl.
    # tolerated-only is fine.
    if p.returncode not in (0, 1):
        return "BREAK: child rc=%d %s" % (p.returncode, notes)
    return "green (%s)" % ("; ".join(notes) if notes else "no breaks")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    held, probe_breaks, errors = 0, set(), 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 - probe must never abort
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
        print("%-42s %s %s" % (fn.__name__, verdict, note))
    print("tally: %d HELD / %d BREAK / %d ERROR" % (held, len(probe_breaks),
                                                   errors))
    if probe_breaks:
        print("BREAKS:", sorted(probe_breaks))
    if errors:
        return 2
    return 0 if not (probe_breaks - _EXPECTED_BREAKS) else 1


if __name__ == "__main__":
    sys.exit(main())
