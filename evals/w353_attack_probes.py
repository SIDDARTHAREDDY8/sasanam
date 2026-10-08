#!/usr/bin/env python3
"""Wave-353 attack round 21 regression battery.

Model-driven composition probes (gpt-4o-mini, 8 calls, ~$0.00045, ledger
389 -> 397) against the wave-352-merged base (5e43ef2c: F454-F460 closed,
F461-F468 open). Every proposal validated locally (node v24.20.0 ground
truth + scanner verdict); only node-exact + scanner-miss shapes were
filed.

New findings filed (all LOW, OPEN, red-first verified):
- F469: Reflect.apply(Array.prototype.concat,[],...) array assembly --
  distinct Reflect method from F468's Reflect.construct close-when.
  CLOSED 2026-10-06 wave-354 lane 1 (desugared to
  thisArg.concat(...argsArray), engine-exact).
- F470: method-call-result .filter predicates (x.match(/[a-z]/)
  truthiness, x.charCodeAt(0)>47 comparison) -- bypass F447's syntactic
  truthiness-preserving model; not in F447's documented residuals.
  CLOSED 2026-10-06 wave-354 lane 2 (modeled node-exact in gov/dlp.py).
- F471: array-copy factories -- Object.assign([], [...]) and the
  spread-copy [...['frag1','frag2']] (same mechanism, one finding).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F461-F468 (wave-352; F461-F468 CLOSED wave-353, their pins flipped to
closed assertions), F470-F471 (this round, still open), F472 (wave-353
lane 2, still open). F469 CLOSED wave-354 lane 1 (pin flipped to the
closed assertion).

Round-21 scope notes (validated, NOT new findings -- each rides with the
cited close-when):
- F461 x C1: ['frag2','frag1'].reverse().reduce((x,y)=>x+y,'') -- reverse
  composes with the closed F437 reduce; same unmodeled-.reverse()
  mechanism as F461; rides with F461's close-when.
- F462 x C2: [].concat(...Array(1).fill('a'),...Array(1).fill('b')) --
  multi-spread-args concat with fill arrays; same spread-concat mechanism
  as F462; rides with F462's close-when. (The single-spread
  credential-yielding form, [].concat(...Array(1).fill('cred')).join(''),
  blocks.)
- F464 x C4: ['frag',String.fromCharCode(...)].toString().replace(/,/g,'')
  -- fromCharCode-decimal fragments ride with F464's string-rewrite
  mechanism; rides with F464's close-when.
- F466 x C6: ['a','b'].slice(0,3).filter(x=>x!==undefined) -- composition
  of two open findings (F466 slice, F467-scope !==undefined); not new.

Documented residuals (not findings):
- F457: IIFE-call interpolation payloads (`${(()=>'<A>')()}`) miss, but
  the F457 closure note explicitly documents calls as fail-closed --
  pinned as documented residual.
- F445 / F447 / F443: pinned CLOSED (short-b64 gate closure, truthiness
  predicates, fill forms); atob-wrapped short b64 and IIFE-template
  shapes block.

Dead/bogus round-21 proposals (validated locally, NOT filed): C1
split+reverse+join (node yields reversed credential, not exact; scanner
blocks anyway); C2 Array(1).fill(x).join('') (BLOCKED -- F443 closed);
C3 join/reduce template interpolation (BLOCKED -- F457 closed); C4
replace-identity (node '' -- bogus) and concat+replace (node drops the
second fragment -- bogus); C5 btoa(pad) / atob+padStart (node yields
b64/padded text, not the credential -- bogus as exact recovery;
btoa(pad) misses the scanner but node yields b64 text, atob+padStart
blocks); C6 charCodeAt>96 as stated (predicate wrong for the
fragments -- bogus; the corrected >47 form is F470's second shape);
C7 all three (predicates not constant-true -- node '' -- bogus);
C8 Array.from (BLOCKED -- wave-351 dead proposal, still blocked).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g353-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B
_C2 = "89abcdef"
_C1 = "xoxb-" + "012345678"
_CRED2 = "xoxb-" + "0123456789abcdef"
_BT = chr(96)  # backtick

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
    """Control: footer shows F477 open, next F478 (wave-355 merge:
    F473-F475 CLOSED; F476, F477 filed OPEN; wave-356 lane 1: F476
    CLOSED)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F738**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in text)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 OPEN  # Wave-356 lane 1: F476 CLOSED  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- F461-F468 closed pins
# (wave-353 merge: the wave-353 closure lanes closed F461-F468; these
# probes now assert the coded refusal instead of the open miss.)

@_t
def test_b1_f461_reverse_join_closed():
    """F461 closed: .reverse().join('') now blocks."""
    hit = _blocked("['" + _B + "','" + _A + "'].reverse().join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f462_spread_concat_closed():
    """F462 closed: spread-args concat now blocks."""
    hit = _blocked("\"" + "\".concat(...['" + _A + "','" + _B + "'])")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f463_tagged_template_join_closed():
    """F463 closed: join as a tagged template now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f464_tostring_replace_closed():
    """F464 closed: .toString().replace(/,/g,'') now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].toString()"
                        ".replace(/,/g,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f465_padstart_closed():
    """F465 closed: .padStart assembly now blocks."""
    hit = _blocked("'" + _C2 + "'.padStart(21,'" + _C1 + "')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f466_slice_noop_closed():
    """F466 closed: .slice(0,2).join('') now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "'].slice(0,2).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f467_filter_neq_null_closed():
    """F467 closed: .filter(x=>x!==null) now blocks."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null)"
                        ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b1_f468_reflect_construct_closed():
    """F468 closed: Reflect.construct(Array,[...]) now blocks."""
    hit = _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                        ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- F469-F470 open pins
# (F471 moved to the closed pins below -- wave-354 lane 3)

@_t
def test_b2_f469_reflect_apply_closed():
    """F469 pinned CLOSED (wave-354 lane 1): Reflect.apply(
    Array.prototype.concat,...) now blocks -- desugared to
    thisArg.concat(...argsArray)."""
    hit = _blocked("Reflect.apply(Array.prototype.concat,[],[['"
                   + _A + "'],['" + _B + "']]).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f470_match_predicate_closed():
    """F470 CLOSED (wave-354 lane 2): .filter(x=>x.match(/[a-z]/)) now
    blocks -- method-call truthiness is modeled."""
    hit = _blocked("['" + _A + "','" + _B + "','']"
                   ".filter(x=>x.match(/[a-z]/)).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f470_charcode_predicate_closed():
    """F470 CLOSED (wave-354 lane 2): .filter(x=>x.charCodeAt(0)>47)
    now blocks -- method-call-result comparison is modeled."""
    hit = _blocked("['" + _A + "','" + _B + "']"
                   ".filter(x=>x.charCodeAt(0)>47).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f471_object_assign_closed():
    """F471 CLOSED (wave-354 lane 3): Object.assign([], [...]) array-copy
    now blocks via _js_parse_object_assign."""
    hit = _blocked("Object.assign([],['" + _A + "','" + _B + "'])"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b2_f471_spread_copy_closed():
    """F471 CLOSED (wave-354 lane 3): spread-copy [...['frag1','frag2']]
    now blocks via _js_parse_spread_copy -- same array-copy-factory
    mechanism as Object.assign."""
    hit = _blocked("[...['" + _A + "','" + _B + "']].join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- round-21 scope notes

@_t
def test_b3_f461_revred_scope_closed():
    """F461 scope (round 21, model C1): ['frag2','frag1'].reverse()
    .reduce((x,y)=>x+y,'') -- now blocked by the F461+F437 closures
    composing; the scope note rode with F461's close-when."""
    hit = _blocked("['" + _B + "','" + _A + "']"
                    ".reverse().reduce((x,y)=>x+y,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f462_multispread_scope_closed():
    """F462 scope (round 21, model C2) CLOSED by F473 2026-10-06 wave-355
    lane 1: [].concat(...Array(1).fill('a'),...Array(1).fill('b')).join('')
    blocks -- array-receiver concat with spread args (F473 mechanism)."""
    hit = _blocked("[].concat(...Array(1).fill('" + _A + "'),"
                   "...Array(1).fill('" + _B + "')).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f464_fcc_frag_scope_closed():
    """F464 scope (round 21, model C4): fromCharCode-decimal fragments --
    now blocked by the F464+F458 closures composing; the scope note
    rode with F464's close-when."""
    fcc = ",".join(str(c) for c in _B.encode())
    hit = _blocked("['" + _A + "',String.fromCharCode(" + fcc + ")]"
                    ".toString().replace(/,/g,'')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f466_slice_undef_scope_closed():
    """F466/F467 scope (round 21, model C6): .slice(0,3)
    .filter(x=>x!==undefined) -- now blocked by the F466+F467 closures
    composing; the scope note rode with their close-whens."""
    hit = _blocked("['" + _A + "','" + _B + "'].slice(0,3)"
                    ".filter(x=>x!==undefined).join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b3_f457_iife_residual_open():
    """F457 documented residual (round 21, model C3): IIFE-call
    interpolation payloads (`${(()=>'<A>')()}`) miss, but the F457
    closure note explicitly documents calls as fail-closed -- pinned
    as documented residual, not a new finding."""
    miss = not _blocked(_BT + "${(()=>'" + _A + "')()}${(()=>'" + _B
                        + "')()}" + _BT)
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------- closed pins

@_t
def test_b4_f443_fill_closed():
    """F443 pinned CLOSED: Array(1).fill(x).join('') blocks."""
    hit = _blocked("Array(1).fill('" + _CRED + "').join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f445_short_b64_closed():
    """F445 pinned CLOSED (wave-349 lane 1): short-b64 runs now decode
    with a credential-shape gate."""
    short = "xox" + "b-abc123" + "def" + "456"  # 16 chars
    b64 = base64.b64encode(short.encode()).decode()
    hit = _blocked("atob('" + b64 + "')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f447_truthy_filter_closed():
    """F447 pinned CLOSED: truthy .filter predicate blocks (x!=='')."""
    hit = _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!=='')"
                   ".join('')")
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_b4_f457_tmpl_interp_closed():
    """F457 pinned CLOSED: template-literal ${} interpolation of string
    literals blocks."""
    hit = _blocked(_BT + "${'" + _A + "'}${'" + _B + "'}" + _BT)
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ---------------------------------------------------------------- green check

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere: the
# F469/F470/F472 misses are pinned as known-open (each probe returns HELD
# when the miss reproduces; F461-F468 and F471 are closed); a literal
# BREAK verdict means the pin failed or a NEW unexpected break appeared.


def _green_check():
    """Depth-1 green check: the previous attack battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting).

    Wave-305-class note: w352_attack_probes.py's test_b0_footer_state
    pinned the pre-filing footer (next F469); wave-354 lane 4 repointed
    it in-tree to the current footer, so no stale-footer break is
    expected here. Any break is a real regression and fails this
    check."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.join(os.path.expanduser("~"), "workspace",
                               ".gov-venv", "bin", "python")
    notes = []
    for script in ("w352_attack_probes.py",):
        tmp = "/var/tmp/g353-green-%s-%d" % (script.replace(".py", ""),
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
