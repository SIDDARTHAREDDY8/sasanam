#!/usr/bin/env python3
"""Wave-355 attack round 23 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.00045, ledger 407 -> 417)
against the wave-354-merged base (0cd94265: F469-F472 closed, F473/F474
open). Every proposal validated locally (node v24.20.0 ground truth +
scanner verdict); only node-exact + scanner-miss shapes were filed.

New finding filed (LOW, OPEN, red-first verified):
- F477: implicit String() coercion of non-string arguments --
  ['x'].concat(123456789,'y') (numeric args stringified),
  'x'.padStart(21,['z']) (array padString coerced),
  'a,b'.replace(/,/g,['']) (array replacement coerced),
  String(['a','b']).replace(/,/g,'') (String() ctor unmodeled).
  All four node-evaluate to the credential while the decoder produces
  zero variants. Distinct from F473 (array RECEIVER) and F474 (TypeError
  on _JSArr args -- these shapes fail closed silently, no raise).
  Filed by the attack lane; committed first (e7d867cf, 2026-10-06
  ~10:35 UTC) per the wave-272 reconciliation rule. Lane 3's parallel
  filter-over-decode candidate must renumber (F477+) at merge.
- F476: constructor-property Array.of factory path --
  [].constructor.of('a','b').join('') and Array['of']('a','b').join('')
  node-evaluate to the credential while the decoder produces zero
  variants. F446's entry explicitly documents these as "out of F446
  scope, documented not filed" (distinct scan shape from the Array.of
  identifier anchor); this files that residual. [].constructor.from is
  BLOCKED (not filed). [CLOSED 2026-10-06 wave-356 lane 1: gov/dlp.py
  _js_parse_ctor_factory desugars the constructor-property factory to
  the F446 path; probes flipped to closed assertions.]

Validated but NOT filed:
- F470-adjacent: .filter(x=>x.trim()!=='') / .filter(x=>x.includes('a'))
  miss -- F470 closure's documented fail-closed scope (.test/.includes/
  .search family); rides with F470's close-when.
- F473-class mis-decodes: [...['a']].concat(['b']),
  ['a','b'].map(String).concat(['c']) -- corrupt variants, ride with
  F473's close-when.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F473 (array-receiver concat miss), F474 (concat TypeError escape),
F477 (String-coercion miss). F476 (constructor-of miss) CLOSED wave-356
lane 1 -- pinned closed above.

Confirmed fail-closed (pinned quiet): Reflect.apply(Array.prototype.join)
non-concat target; nested Reflect.construct.

Dead/bogus round-23 proposals (validated locally, NOT filed): C1 nested
Reflect (node-yields arrays); C2/C3 (not credential-shaped); C4 repeat
string-count with verbatim receiver (raw-text rule); C5 String().split
(non-exact); C6 trim-filter (F470 scope); C7 comma-joined (non-exact);
C8 Reflect slice/join/reverse (fail-closed); C9 constructor.from
(mis-decode, rides with F446 residual).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g355-*
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
    """Control: footer shows F482-F488 open, next F489 (wave-358 merge:
    F480, F481 CLOSED; F482-F488 filed OPEN)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F583**" in text  # Wave-357 merge: F480 filed; Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and "**Open findings: F570, F571, F572, F573, F574, F575, F576, F577, F578, F579, F580, F581, F582.**" in text)  # Wave-357 merge: F478, F479 CLOSED; Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------- F469-F472 closed pins (sample)

@_t
def test_b1_f469_reflect_apply_closed():
    """F469 pinned CLOSED (wave-354 merge, lane 1): Reflect.apply concat
    now blocks via the F462 desugar."""
    hit = _blocked("Reflect.apply(Array.prototype.concat,[],[['"
                   + _A + "'],['" + _B + "']]).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f470_match_predicate_closed():
    """F470 pinned CLOSED (wave-354 merge, lane 2): match-truthiness
    filter predicates now block."""
    hit = _blocked("['" + _A + "','" + _B + "','']"
                   ".filter(x=>x.match(/[a-z]/)).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f471_object_assign_closed():
    """F471 pinned CLOSED (wave-354 merge, lane 3): array-copy factories
    now block."""
    hit = _blocked("Object.assign([],['" + _A + "','" + _B + "'])"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f472_repeat_tagged_closed():
    """F472 pinned CLOSED (wave-354 merge, lane 4): tagged-template
    repeat now blocks."""
    hit = _blocked("'" + _A + "'.repeat`" + "2`")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F473/F474 open pins

@_t
def test_b2_f473_litarr_concat_closed():
    """F473 CLOSED (wave-355 lane 1, merged): ['a'].concat(['b']).join('')
    now blocks via _js_apply_array_concat."""
    hit = _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f473_fill_concat_closed():
    """F473 CLOSED (wave-355 lane 1, merged): Array(1).fill('a').concat('b')
    now blocks via _js_apply_array_concat on the fill-produced array."""
    hit = _blocked("Array(1).fill('" + _A + "').concat('" + _B + "')"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f474_concat_typeerror_closed():
    """F474 CLOSED (wave-355 lane 2, merged): ('a').concat(['b']) no longer
    raises -- the isinstance guard fails closed instead of escaping TypeError."""
    try:
        dlp.find_credential("('" + _A + "').concat(['" + _B + "']).join('')")
        raised = False
    except TypeError:
        raised = True
    return ("HELD" if not raised else "BREAK", "raised=%s" % raised)


# ------------------------------------------------- F477 closed pins

@_t
def test_b2_f477_concat_numeric_closed():
    """F477 pinned CLOSED (wave-356 lane 2): ['x'].concat(123456789,'y') now blocks --
    numeric concat args are stringified by the engine (String()
    coercion), but the decoder accepts only string/spread args."""
    hit = _blocked("['" + "xoxb-" + "0" + "'].concat(123456789,'"
                   + "abcdef" + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f477_padstart_array_closed():
    """F477 pinned CLOSED (wave-356 lane 2): 'x'.padStart(21,['z']) now blocks -- array padString
    is coerced via String(['z'])='z', but the decoder accepts only
    literal pad strings (F465)."""
    hit = _blocked("'" + "123456789abcdef" + "'.padStart(21,['"
                   + "xoxb-" + "0" + "'])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f477_replace_array_closed():
    """F477 pinned CLOSED (wave-356 lane 2): 'a,b'.replace(/,/g,['']) now blocks -- array
    replacement is coerced via String([''])='', but the decoder
    accepts only literal-string replacements (F464)."""
    hit = _blocked("'" + "xoxb-" + "0" + "," + "123456789abcdef"
                   + "'.replace(/,/g,[''])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f477_string_ctor_closed():
    """F477 pinned CLOSED (wave-356 lane 2): String(['a','b']) now blocks --
    the String() constructor call is unmodeled (F464 covers only
    .toString())."""
    hit = _blocked("String(['" + "xoxb-" + "01234" + "','"
                   + "56789abcdef" + "']).replace(/,/g,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- round-23 scope notes

@_t
def test_b2_f476_constructor_of_closed():
    """F476 pinned CLOSED (wave-356 lane 1): [].constructor.of('a','b').join('')
    now blocks via the constructor-property factory desugar (was open on the
    wave-355 tree; F446's entry explicitly excluded this shape)."""
    hit = _blocked("[].constructor.of('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f476_array_bracket_of_closed():
    """F476 pinned CLOSED (wave-356 lane 1): Array['of']('a','b').join('')
    now blocks -- same property-lookup factory mechanism as
    [].constructor.of."""
    hit = _blocked("Array['of']('" + _A + "','" + _B + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f470_trim_filter_scope_open():
    """F470 scope (round 23): ['a','b'].filter(x=>x.trim()!=='') misses
    -- F470 closure's documented fail-closed scope (.test/.includes/
    .search family); rides with F470's close-when, not a new finding."""
    miss = not _blocked("['" + _A + "','" + _B + "']"
                        ".filter(x=>x.trim()!=='').join('')")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


@_t
def test_b3_reflect_apply_join_scope_quiet():
    """Round-23 confirmed fail-closed: Reflect.apply(Array.prototype.join)
    non-concat target stays quiet."""
    quiet = not _blocked("Reflect.apply(Array.prototype.join,['"
                         + _A + "','" + _B + "'],[])")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_b3_nested_reflect_scope_quiet():
    """Round-23 confirmed fail-closed: nested Reflect stays quiet."""
    quiet = not _blocked("Reflect.apply(Reflect.construct,null,[Array,[["
                         + "'" + _A + "'],['" + _B + "']]])")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F473-F477 misses are pinned as known-open (each probe returns HELD when
# the miss reproduces); a literal BREAK verdict means the pin failed or a
# NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).

    Wave-305-class note: w354_attack_probes.py's test_b0_footer_state
    pins the pre-filing footer (next F477, open F473/F474); this lane
    filed F477 and moved the footer to next F476, so exactly that one
    probe is expected to BREAK here. The merge coordinator's tree-wide
    footer sweep repoints it. Any OTHER break is a real regression and
    fails this check.

    Wave-356 lane 2 note: w354's test_b0_footer_state was repointed
    (open F476, next F478) in this tree, so it HELDs here; the
    tolerance below still passes (breaks subset of allowed)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w354_attack_probes.py",):
        tmp = "/var/tmp/g355-green-%s-%d" % (script.replace(".py", ""),
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
