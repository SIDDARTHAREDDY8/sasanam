#!/usr/bin/env python3
"""Wave-354 attack round 22 regression battery.

Model-driven composition probes (gpt-4o-mini, 10 calls, ~$0.0006, ledger
397 -> 407) against the wave-353-merged base (f5e332ca: F461-F468 closed,
F469-F472 open). Every proposal validated locally (node v24.20.0 ground
truth + scanner verdict); only node-exact + scanner-miss shapes were
filed.

New findings filed (all LOW, OPEN, red-first verified):
- F473: array-receiver paren .concat bypass -- ['a'].concat(['b']).join(''),
  [].concat(...['a'],...['b']).join(''), ['a','b'].concat([]).join(''),
  Array(1).fill('a').concat('b').join(''),
  Array(1).fill('a').concat(...['b']).join('') all node-recover the
  credential while the decoder fails closed at "method on unjoined
  array". Distinct from F462 (string-receiver spread concat, closed
  wave-353): this is the ARRAY-receiver class. Correction to the
  round-21 scope note: [].concat(...Array(1).fill('a'),...) was
  attributed to F462's spread mechanism; the miss is the array
  receiver, i.e. F473's mechanism.
- F474: uncaught TypeError -- ('a').concat(['b']).join('') (string
  receiver, _JSArr argument) raises "TypeError: sequence item 0:
  expected str instance, _JSArr found" from "".join(parts), escaping
  find_credential. The spread path checks isinstance(e, str); the
  non-spread path has no argument type guard. Distinct from F473
  (receiver fail-closed miss): this is the missing ARGUMENT guard.
  Honest note (two-axis review correction): the full shape throws in a
  real engine too (.join is not a function), so F474 is a robustness
  defect (fail-UNDEFINED on adversarial input), not a recovery bypass.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F469-F472 (wave-353, still open), F473 (array-receiver concat miss),
F474 (concat TypeError escape).

Round-22 scope notes (validated, NOT new findings -- each rides with
the cited close-when):
- F471 x C6: Reflect.construct(Array, Object.assign([], ['a','b'])),
  Reflect.construct(Array, [...['a','b']]),
  Reflect.construct(Array, Array.from(['a','b'])) -- copy factories as
  Reflect args; same array-copy-factory mechanism as F471; rides with
  F471's close-when (for the F471 closure lane).
- F473 x C10: Object.assign([], ['a','b']).concat().join('') -- array-
  receiver concat on a copy-produced array; composition of two opens
  (F471 x F473); rides with F473's close-when once F471's factories
  decode.
- F464 x C7 / F467 x C7: ['a','b',''].filter(x=>x!=null).toString()
  .replace(/,/g,'') and the !==undefined variant now BLOCK -- the
  F464+F467 closures compose; scope confirmed closed.
- F469 x C8: the exact F469 shape re-validated still misses; the
  nested-Reflect proposals node-yield arrays, not the credential --
  dead as stated.

Documented residuals (not findings):
- F472 x C4: 'c'.slice`1`, 'abc'.substring`1,3`, 'abc'.substr`1,2` --
  node yields '' or 'abc', not the credential; dead as stated.
- F470 x C5: slice+method-call filter without .join node-yields an
  array, not the credential string; dead as stated (with .join they
  would be F470-class).

Dead/bogus round-22 proposals (validated locally, NOT filed): C2
fill().map((_,i)=>'ab'[i]) and fill().reduce (free-variable/index
callbacks, fail-closed per F459/F447 -- node 'ab' is the unsubstituted
demo literal); C3 revpad (model embedded the literal credential and
reversed it -- node yields reversed text, scanner blocks the literal);
C7 third shape (toString without replace node-yields comma-joined text,
not the credential); C9 matchpad (node yields 'xoxb-xpad...', not
credential-shaped); C4 tagcall, C5 slicefilt, C8 nested-Reflect (above).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g354-*
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
    """Control: footer shows no open findings, next F478 (wave-356 merge:
    F476, F477 CLOSED)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F612**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
          and "**Open findings: F595, F606, F608, F609, F610, F611.**" in text)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 OPEN  # Wave-356 lane 1: F476 CLOSED  # Wave-356 lane 2: F477 CLOSED  # Wave-356 merge: F476, F477 CLOSED  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------- F461-F468 closed pins (sample)

@_t
def test_b1_f461_reverse_closed():
    """F461 pinned CLOSED: ['b','a'].reverse().join('') blocks."""
    hit = _blocked("['" + _B + "','" + _A + "'].reverse().join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f462_spread_concat_closed():
    """F462 pinned CLOSED: ''.concat(...['a','b']) blocks."""
    hit = _blocked("''.concat(...['" + _A + "','" + _B + "'])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f463_tagjoin_closed():
    """F463 pinned CLOSED: ['a','b'].join`` blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].join``")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f464_tostring_replace_closed():
    """F464 pinned CLOSED: ['a','b'].toString().replace(/,/g,'') blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].toString().replace(/,/g,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f467_nullfilter_closed():
    """F467 pinned CLOSED: ['a','b',''].filter(x=>x!==null) blocks."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f468_reflect_construct_closed():
    """F468 pinned CLOSED: Reflect.construct(Array,['a','b']) blocks."""
    hit = _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F469-F472 closed pins (wave-354 merge)

@_t
def test_b2_f469_reflect_apply_closed():
    """F469 pinned CLOSED (wave-354 merge, lane 1): Reflect.apply concat
    now blocks via the F462 desugar."""
    hit = _blocked("Reflect.apply(Array.prototype.concat,[],[['"
                   + _A + "'],['" + _B + "']]).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f470_match_predicate_closed():
    """F470 pinned CLOSED (wave-354 merge, lane 2): match-truthiness
    filter predicates now block."""
    hit = _blocked("['" + _A + "','" + _B + "','']"
                   ".filter(x=>x.match(/[a-z]/)).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f471_object_assign_closed():
    """F471 pinned CLOSED (wave-354 merge, lane 3): array-copy factories
    now block."""
    hit = _blocked("Object.assign([],['" + _A + "','" + _B + "'])"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f472_repeat_tagged_closed():
    """F472 pinned CLOSED (wave-354 merge, lane 4): tagged-template
    repeat now blocks."""
    hit = _blocked("'" + _A + "'.repeat`" + "2`")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F473/F474 open pins

@_t
def test_b2_f473_litarr_concat_closed():
    """F473 CLOSED 2026-10-06 wave-355 lane 1: ['a'].concat(['b']).join('')
    blocks -- array-receiver paren .concat modeled."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f473_empty_concat_spread_closed():
    """F473 CLOSED 2026-10-06 wave-355 lane 1: [].concat(...['a'],...['b'])
    .join('') blocks -- array-receiver concat with spread args."""
    hit = _blocked("[].concat(...['" + _A + "'],...['" + _B + "'])"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f473_fill_concat_closed():
    """F473 CLOSED 2026-10-06 wave-355 lane 1: Array(1).fill('a').concat
    ('b').join('') blocks -- array-receiver concat on fill array."""
    hit = _blocked("Array(1).fill('" + _A + "').concat('" + _B + "')"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f474_concat_typeerror_closed():
    """F474 CLOSED 2026-10-06 wave-355 lane 2: ('a').concat(['b']).join('')
    no longer raises -- the paren-concat branch type-guards its args and
    fails closed (the engine's implicit Array-to-String coercion is not
    modeled; fail closed is the honest direction)."""
    try:
        hit = _blocked("('" + _A + "').concat(['" + _B + "']).join('')")
        raised = False
    except TypeError:
        hit, raised = False, True
    ok = (not raised) and (not hit)
    return ("HELD" if ok else "BREAK",
            "raised=%s blocked=%s" % (raised, hit))


# ------------------------------------------------- round-22 scope notes

@_t
def test_b3_f471_reflect_copy_scope_open():
    """F471 scope (round 22, model C6): Reflect.construct(Array,
    Object.assign([], ['a','b'])).join('') -- copy factories as Reflect
    args; same array-copy-factory mechanism; rides with F471's
    close-when."""
    miss = not _blocked("Reflect.construct(Array,Object.assign([],['"
                        + _A + "','" + _B + "'])).join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b3_f464_f467_compose_scope_closed():
    """F464 x F467 scope (round 22, model C7):
    ['a','b',''].filter(x=>x!=null).toString().replace(/,/g,'') now
    blocks -- the two closures compose; scope confirmed closed."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!=null)"
                   ".toString().replace(/,/g,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f472_tagcall_scope_dead():
    """F472 scope (round 22, model C4): 'c'.slice`1` -- node yields '',
    not the credential; dead as stated, pinned quiet."""
    quiet = not _blocked("'c'.slice`1`")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F469-F473 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); F474's pin is now a closed-assertion (HELD = no
# raise + fail-closed, wave-355 lane 2); a literal BREAK verdict means
# the pin failed or a NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).

    Wave-305-class note: w353_attack_probes.py's test_b0_footer_state
    pins the pre-filing footer (next F473); this lane moved the footer to
    next F476, so exactly that one probe is expected to BREAK here. The
    merge coordinator's tree-wide footer sweep repoints it. Any OTHER
    break is a real regression and fails this check."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w353_attack_probes.py",):
        tmp = "/var/tmp/g354-green-%s-%d" % (script.replace(".py", ""),
                                             os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        # Extract the BREAK set. Probe lines are test-name-first
        # ("test_b0_footer_state   BREAK footer=False"); older batteries
        # print verdict-first ("BREAK test_name: note"). Parse both --
        # a parse that matches neither format passes vacuously and is a
        # silent green (wave-320 class).
        breaks = set()
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "BREAK" and len(parts) >= 2:
                breaks.add(parts[1].rstrip(":"))
            elif len(parts) >= 2 and parts[1] == "BREAK":
                breaks.add(parts[0])
        if not breaks and r.returncode != 0:
            raise AssertionError("green check failed: could not parse any "
                                 "probe verdicts from child output: %s"
                                 % notes[-1])
        allowed = {"test_b0_footer_state"}
        if not breaks <= allowed:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
        notes.append("tolerated stale footer probe: %s" % sorted(breaks))
    return "; ".join(notes)


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
