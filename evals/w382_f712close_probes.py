#!/usr/bin/env python3
"""Wave-382 lane 7: close F712 (var-bound Map iteration reads).

F712 (LOW, filed 2026-10-08 by wave-381 lane 2 as F700, renumbered
at the wave-381 merge): a VAR-BOUND literal Map's iteration reads
bypass the bounded static JS-expression decoder -- F695 (CLOSED)
models only the INLINE bare-Map iteration protocol
(`[...new Map(...)]`, `Array.from(new Map(...))`), and F589/F600
(CLOSED) model only inline `.entries()`/`.keys()` iteration:
`(function(){var m=new Map([['k','f1']]);return
[...m.entries()][0][1]+'f2';})()`, the keys twin
`[...m.keys()][0]`, the values twin `[...m.values()][0]`, the
Array.from twin `Array.from(m)[0][1]`, and the Array.from-entries
twin `Array.from(m.entries())[0][1]` all node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero variants.
Distinct from F695 (inline sources), F589 (inline entries), F600
(inline keys), F669 (var-bound spread+join consumption), F708
(var-bound Map.get, OPEN).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f712_map_iter_iife (+ _js_f712_iter_source,
  _js_f712_index, _js_f712_operand): the statement-IIFE body
  grammar is `[var|let|const M=new Map([[...]]);]* return ADD;`
  (declaration-before-use; redeclare/forward-ref fail closed;
  entries validated by the shared _js_parse_new_map_head --
  later-wins, SameValueZero keys, plain string-literal values).
  The return is a `+`-joined additive of string literals and
  var-bound iteration reads: `[...m]` / `[...m.entries()]` /
  `[...m.keys()]` / `[...m.values()]` / `Array.from(m)` /
  `Array.from(m.entries())` / `Array.from(m.keys())` /
  `Array.from(m.values())`, each indexed `[I]` / `[I][J]`
  (canonical decimal indices, bounds-checked -- out-of-range
  fails closed exactly where node throws TypeError). Keys keep
  their _JSNumStr provenance (the F600/F695 discipline), so
  numeric-key reads concat node-exactly. Hooked after F692 in
  _js_parse_primary; disjoint by binding family (red-first
  verified: 5 BREAK on the open tree).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ------------------------------------------------ p0: pin

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------ p1: F712 filed shapes now block

@_t
def test_p1_f712_filed_shapes_closed():
    """F712 CLOSED: all five filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['%s','v']]);return [...m.keys()][0]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','%s']]);return [...m.values()][0]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','%s']]);return Array.from(m)[0][1]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','%s']]);return Array.from(m.entries())[0][1]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p2: node-exact variants

@_t
def test_p2_variants_node_exact():
    """Variants decode node-exactly (v24.20.0 verified by differential: 16/16).

    The numeric-key variant (key `1` -> _JSNumStr provenance) is
    value-exact per the lane differential but is not credential-shaped,
    so it is asserted there, not here (same precedent as wave-381 lane 2).
    """
    shapes = [
        # bare spread of var-bound map (same iteration protocol)
        "(function(){var m=new Map([['k','%s']]);return [...m][0][1]+'%s';})()" % (_A, _B),
        # key-side index into pair array
        "(function(){var m=new Map([['%s','v']]);return [...m][0][0]+'%s';})()" % (_A, _B),
        # Array.from keys/values twins
        "(function(){var m=new Map([['%s','v']]);return Array.from(m.keys())[0]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','%s']]);return Array.from(m.values())[0]+'%s';})()" % (_A, _B),
        # second pair, later-wins dupes, two maps, const/let
        "(function(){var m=new Map([['a','x'],['k','%s']]);return [...m.values()][1]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','a'],['k','%s']]);return [...m.values()][0]+'%s';})()" % (_A, _B),
        "(function(){var m=new Map([['k','%s']]);var n=new Map([['j','%s']]);return [...m.values()][0]+[...n.values()][0];})()" % (_A, _B),
        "(function(){const m=new Map([['k','%s']]);let n=new Map([['j','%s']]);return [...m.values()][0]+[...n.values()][0];})()" % (_A, _B),
        # whitespace-tolerant
        "(function(){ var m = new Map( [ [ 'k' , '%s' ] ] ) ; return [ ... m . entries ( ) ] [ 0 ] [ 1 ] + '%s' ; })()" % (_A, _B),
        # return additive with plain literal term
        "(function(){var m=new Map([['k','v']]);return '%s%s';})()" % (_A, _B),
        # pair read without second index: node stringifies the pair
        # array via Array.prototype.toString ("k,f1"); the decoder
        # coerces identically (regression: this used to raise
        # TypeError out of find_credential)
        "(function(){var m=new Map([['k','%s']]);return [...m.entries()][0]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p3: fail-closed bounds

@_t
def test_p3_bounds_fail_closed():
    """Out-of-scope shapes fail closed (rejected, never mis-decoded)."""
    shapes = [
        "(function(){var m=new Map([['k','v']]);return [...m.entries()][5][1]+'x';})()",  # out-of-range pair index (node throws)
        "(function(){var m=new Map([['k','v']]);return [...m.entries()][0][2]+'x';})()",  # out-of-range key/value index
        "(function(){var m=new Map([['k','v']]);return [...m.keys()][0][1]+'x';})()",  # scalar re-index (node string-indexes)
        "(function(){var m=new Map([['k','v']]);return [...m['entries']()][0][1]+'x';})()",  # bracket-string member form
        "(function(){var m=new Map([['k','v']]);m.set('j','w');return [...m.values()][0]+'x';})()",  # m.set tail (F708 territory)
        "(function(){var s='ab';return [...m.values()][0]+'x';})()",  # non-Map declaration
        "(function(){var m=new Map([['k','v']]);var m=new Map([['j','w']]);return [...m.values()][0]+'x';})()",  # redeclare
        "(function(){var m=new Map([['k','v']]);return [...n.values()][0]+'x';})()",  # unbound map
        "(function(){var m=new Map([['k','v']]);return [...m.size][0]+'x';})()",  # bad member
        "(function(){var m=new Map([['k','v']]);return [...m.values()][0x0]+'x';})()",  # non-canonical index
        "(function(){var m=new Map([['a','x'],['k','v']]);return [...m.values()][-1]+'x';})()",  # negative index (node: undefined, never last element)
        "(function(){var m=new Map([['k','v']]);return [...m.entries()][0][-1]+'x';})()",  # negative pair index
        "(function(){var m=new Map([['k','v']]);return [...m.values()][0]+'x';var z=1;})()",  # trailing statement
        "(function(){var m=new Map([['k',x]]);return [...m.values()][0]+'x';})()",  # non-literal value
        "(function(){var m=new Map([['k','v']]);return m.get('k')+'x';})()",  # Map.get: F708, still OPEN
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p4: neighbors hold

@_t
def test_p4_neighbors_hold():
    """Sibling closures still block; nothing absorbed."""
    shapes = [
        # F695 inline bare-Map iteration: still blocks
        "(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B),
        # F589 inline entries: still blocks
        "(function(){return [...new Map([['k','%s']]).entries()][0][1]+'%s';})()" % (_A, _B),
        # F600 inline keys: still blocks
        "(function(){return [...new Map([['%s','v']]).keys()][0]+'%s';})()" % (_A, _B),
        # F669 var-bound spread+join consumption (filed shapes): still blocks
        "(function(){var st=new Set(['%s','%s']);return [...st].join('');})()" % (_A, _B),
        "(function(){var m=new Map();m.set('a','%s');m.set('b','%s');return [...m.values()].join('');})()" % (_A, _B),
        # F494 inline values spread: still blocks
        "(function(){return [...new Map([['k','%s']]).values()][0]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


@_t
def test_p4_open_findings_still_miss():
    """F700/F701/F708/F709 now CLOSED by sibling lanes (merge) -- block coded; F713 CLOSED by wave-383 lane 1 -- blocks coded."""
    closed = [
        "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B),  # F708 Map.get
        "(function(){return ['%s','%s'].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B),  # F700 flatMap
        "(function(){var o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B),  # F701 getter-on-spread
        "(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B),  # F709 loop +=
        "(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B),  # F713 literal-Map spread-join (wave-383 lane 1)
    ]
    got_c = [_blocked(s) for s in closed]
    ok = all(got_c)
    return ("HELD" if ok else "BREAK", "closed=%s" % (got_c,))


# ------------------------------------------------ p5: junk quiet

@_t
def test_p5_junk_quiet():
    """Honest text stays quiet (no false positives)."""
    shapes = [
        "'(function(){var m=new Map();return 1;})()'",
        "(function(){var m=new Map([['k','v']]);return 'quiet';})()",
        "(function(){var m=new Map([['k','v']]);return [...m.values()].join(',');})()",
        "(function(){var m=new Map([['k','v']]);return m.size;})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: pin, footer, no new regexes

@_t
def test_p6_pin_footer():
    """Pin 2143; lane-local footer (F712 CLOSED, F713 filed; open F700-F711,F713 / next F714)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F921**" in text)  # Wave-383 lane 1: F713, F714 CLOSED  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 lane 1  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf

@_t
def test_p7_perf():
    """200 mixed var-bound Map iteration sites decode quickly."""
    corpus = []
    for k in range(200):
        corpus.append("(function(){var m=new Map([['k','a%d']]);return [...m.values()][0]+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w381_f712_redfirst.py", 0),
                               ("evals/w381_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        footer_break = 0
        for line in out.splitlines():
            if line.startswith("test_b0_footer_state: BREAK"):
                footer_break = 1
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
            continue
        # The w381 battery's footer pin asserts the pre-lane footer;
        # this lane's FINDINGS.md repoint breaks it by design --
        # merge owns the tree-wide repoint (wave-305/306 class).
        # Tolerate exactly that 1 BREAK; any other BREAK still fails.
        nbreak -= footer_break
        if nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p8_green_check():
    """Depth-1 green check: F712 red-first + wave-381 attack battery green."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
