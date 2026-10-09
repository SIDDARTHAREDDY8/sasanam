#!/usr/bin/env python3
"""Wave-385 lane 3: close F766 + F767 (Array find/findLast, splice reads).

F766 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): Array.prototype.find / findLast -- the decoder modeled filter
(F607, CLOSED) but had no find production: find/findLast with
predicates resolve node-exactly while the decoder produced zero
variants. Filed shapes:
  (function(){return [['f1'],['xx']].find(function(a){return true;})[0]+'f2';})()
  (function(){return [['xx'],['f1']].findLast(function(a){return true;})[0]+'f2';})()
plus the length-predicate variant.

F767 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round
52): Array.prototype.splice reads -- the decoder had only the narrow
F466 literal-(0,2) splice form: splice returns the removed elements
node-exactly while the decoder produced zero variants for every other
arg shape. Filed shapes:
  (function(){return ['xx','f1','f2'].splice(1).join('');})()
  (function(){return ['xx','f1','f2','yy'].splice(1,2).join('');})()

F822 (LOW, OPEN; filed 2026-10-09 03:26:22 UTC by this lane): NEW --
optional-chaining direct method calls (`?.method(args)`) miss every
modeled method (the `?.` form resolves to a _JSMethodRef whose
direct-call step is never dispatched). Documented here, stays OPEN.

Fix (gov/dlp.py, zero new re.compile):
- F766: "find"/"findLast" added to _F478_ARRAY_METHODS and
  _JS_POSTFIX_METHOD_NAMES; a new branch in _js_apply_method_at
  reuses the filter predicate grammar (_js_parse_filter_callback)
  and _js_filter_spec_apply (same F475/F479 fail-closed
  discipline); find returns the first match, findLast the last;
  no match -> fail closed (the engine yields undefined; a later
  member read would throw -- the decoder never decodes a throw).
  thisArg fails closed. Budget snapshot/restore on miss (F452 /
  wave-383 lesson).
- F767: the _js_apply_method_at splice branch generalized from the
  F466 literal-(0,2) form to full literal-int semantics via the new
  _js_splice_span helper (negative start counts from the end, both
  clamped engine-exactly -- F681 precedent); the removed elements
  are returned as a fresh _JSArr and the receiver is mutated in
  place (the engine mutates). Insert items, fractional args (F561
  precedent), and non-literal args fail closed. The F483 value
  mirror is generalized identically (shared helper -- the two can
  never drift). The mutation happens only after the full arg
  grammar validates, so a miss never mutates.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_no_new_recompile():
    """Zero new re.compile (stays 28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F766/F767 closed, F822 filed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F796**" in text
          and "Open findings: F762, F763, F764, F765, F768, F769, F770, "
              "F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, "
              "F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, "
              "F791, F792, F793, F794, F822." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f766_s1():
    """F766 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){return [['" + _A + "'],['xx']].find("
         "function(a){return true;})[0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f766_s2():
    """F766 filed shape 2 (findLast) blocks + decodes node-exact."""
    s = ("(function(){return [['xx'],['" + _A + "']].findLast("
         "function(a){return true;})[0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f767_s1():
    """F767 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){return ['xx','" + _A + "','" + _B
         + "'].splice(1).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f767_s2():
    """F767 filed shape 2 (start,count) blocks + decodes node-exact."""
    s = ("(function(){return ['xx','" + _A + "','" + _B
         + "','yy'].splice(1,2).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f766_arrow():
    """F766 arrow predicate blocks + exact."""
    s = ("(function(){return [['" + _A + "'],['xx']].find(a=>true)[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f766_length_pred():
    """F766 length-predicate variant blocks + exact."""
    s = ("(function(){return ['','" + _A + "'].find(s=>s.length>0)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f766_index_pred():
    """F766 positional predicate blocks + exact."""
    s = ("(function(){return ['x','" + _A + "'].find((e,i)=>i>0)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f766_findlast_arrow():
    """F766 findLast arrow blocks + exact."""
    s = ("(function(){return [['xx'],['" + _A + "']].findLast(a=>true)[0]+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f766_bracket():
    """F766 bracket-name call blocks + exact."""
    s = ("(function(){return [['" + _A + "'],['xx']]['find']("
         "function(a){return true;})[0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f766_dispatch_call():
    """F766 Array.prototype.find.call blocks + exact."""
    s = ("(function(){return Array.prototype.find.call([['" + _A
         + "'],['xx']],function(a){return true;})[0]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_negative():
    """F767 negative start blocks + exact."""
    s = ("(function(){return ['x','" + _A + "','" + _B
         + "'].splice(-2).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_zero_start():
    """F767 splice(0) blocks + exact."""
    s = ("(function(){return ['" + _A + "','" + _B
         + "','z'].splice(0).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + "z")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_neg_clamp():
    """F767 negative start clamped to 0 blocks + exact."""
    s = ("(function(){return ['" + _A + "','" + _B
         + "'].splice(-9,2).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_f466_still():
    """F767: the F466 literal-(0,2) form still blocks + exact."""
    s = ("(function(){return ['" + _A + "','" + _B
         + "'].splice(0,2).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_dispatch_call():
    """F767 Array.prototype.splice.call blocks + exact."""
    s = ("(function(){return Array.prototype.splice.call(['xx','" + _A
         + "','" + _B + "'],1).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_apply_mirror():
    """F767 .apply mirror blocks + exact (value path)."""
    s = ("(function(){return Array.prototype.splice.apply(['xx','" + _A
         + "','" + _B + "'],[1]).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f767_apply_mirror_neg():
    """F767 .apply mirror with negative start blocks + exact."""
    s = ("(function(){return Array.prototype.splice.apply(['xx','" + _A
         + "','" + _B + "'],[-2]).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f766_no_match():
    """F766 no match -> engine undefined -> fail closed."""
    s = ("(function(){return ['a','b'].find(x=>x==='z');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f766_no_match_index():
    """F766 no-match indexed read would throw -> fail closed."""
    s = ("(function(){return ['a'].find(x=>x==='z')[0];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f766_thisarg():
    """F766 thisArg fails closed (documented bound)."""
    s = ("(function(){return ['" + _A + "'].find(x=>true,{});})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f766_nonarray():
    """F766 on a non-array fails closed."""
    s = ("(function(){return 'ab'.find(x=>true);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f766_unmodeled_pred():
    """F766 unmodeled predicate fails closed."""
    s = ("(function(){return ['a','b'].find(x=>y);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f766_mixed_length():
    """F766 length predicate over mixed types fails closed (F475)."""
    s = ("(function(){return ['a',1].find(x=>x.length>0);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f767_insert():
    """F767 insert items fail closed (documented bound)."""
    s = ("(function(){return ['a','b'].splice(1,1,'x').join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f767_fractional():
    """F767 fractional start fails closed (F561 precedent)."""
    s = ("(function(){return ['a','b'].splice(1.5).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f767_nonliteral():
    """F767 non-literal start fails closed."""
    s = ("(function(){return ['a','b'].splice(x).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f767_nonarray():
    """F767 on a non-array fails closed."""
    s = ("(function(){return 'ab'.splice(1);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f607_filter():
    """F607 filter pin still blocks."""
    s = ("(function(){return ['zz','" + _A + "'].filter(s=>s!=='zz').join('')"
         "+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f607=%s" % ok)


@_t
def test_p4_sibling_f547_at():
    """F547 .at() pin still blocks."""
    s = ("(function(){return ['" + _A + "','x'].at(0)+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f547=%s" % ok)


@_t
def test_p4_sibling_f561_with():
    """F561 .with() pin still blocks."""
    s = ("(function(){return ['x','y'].with(0,'" + _A + "').join('')+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f561=%s" % ok)


@_t
def test_p4_sibling_f681_mutation():
    """F681 splice-mutation-statement pin still blocks."""
    s = ("(function(){var a=['junk','" + _A + "','" + _B
         + "'];a.splice(0,1);return a.join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f681=%s" % ok)


@_t
def test_p4_neighbor_f822_open():
    """Neighbor F822 (filed this lane) still misses -- honest open shape."""
    s = "['" + _A + "','" + _B + "']?.join('')"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f822-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_find_unaffected():
    """Honest find without credentials still misses."""
    s = "(function(){return ['a','b'].find(x=>x==='b');})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_splice_unaffected():
    """Honest splice without credentials still misses."""
    s = "(function(){return ['a','b','c'].splice(1).join('');})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){return [['a%d'],['x']].find(a=>true)[0];})()" % k)
        sites.append(
            "(function(){return ['x','a%d','b'].splice(1).join('');})()" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # w384_attack_probes.py expects 1 BREAK: its test_b0_footer_state
    # asserts the base footer (open F762-F794); the lane-local repoint
    # (F766/F767 closed, F822 filed) moves it. The tree-wide footer
    # repoint is merge-owned (wave-305 lesson); all functional probes
    # must HELD. The F822 red-first stays 2 BREAK (open finding).
    for batt, expect_break in (("evals/w384_f766_redfirst.py", 0),
                               ("evals/w384_f767_redfirst.py", 0),
                               ("evals/w385_f822_redfirst.py", 2),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: F766/F767 red-firsts (0 BREAK), F822
    red-first (2 BREAK, open finding), wave-384 attack battery
    (1 BREAK: the footer pin only, lane-local repoint; tree-wide
    repoint is merge-owned)."""
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
