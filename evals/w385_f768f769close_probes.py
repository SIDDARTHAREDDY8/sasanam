#!/usr/bin/env python3
"""Wave-385 lane 4: close F768 + F769.

F768 (LOW, filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack
round 52): array entry-pair reads -- Array.prototype.entries spread
into an array and Object.entries applied to arrays have no
production. F612 (CLOSED) covers var-bound Object.entries on
objects, but `[...['f1','f2'].entries()].map(function(e){return
e[1];}).join('')` and `Object.entries(['f1','f2']).map(function(e)
{return e[1];}).join('')` node-evaluate to the exact credential
(node v24.20.0) while the decoder produced zero variants.

F769 (LOW, filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack
round 52): Array.prototype.at on var-bound arrays -- .at() on an
inline array literal blocks (F547), but on a var-bound array it
misses: `(function(){var a=['f1','f2'];return
a.at(0)+a.at(-1);})()` node-evaluates to the exact credential
while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F768: `_js_parse_f768_spread_entries` (twin A:
  `[...ARRLIT.entries()].map(PROJ)`, hooked in the `[` branch
  before the ordinary array literal) and
  `_js_parse_f768_object_entries_array` (twin B:
  `Object.entries(ARRLIT).map(PROJ)`, hooked in the Object
  branch before F517). Both require the mandatory `.map`
  projection (F517 discipline, via `_js_parse_entries_projection`
  which already recognizes `function(e){return e[1];}`) and
  thread the projected array through `_js_parse_postfix`.
  Node-exact: the array-iterator twin yields numeric indices
  (modeled as _JSNumStr), the Object.entries twin yields string
  indices. Dense plain-string arrays only; holes, non-string
  elements, `.entries()` args, and missing/unrecognized
  projections fail closed.
- F769: `_js_parse_f769_at_varbound_iife`, hooked after F757
  with parts/ops snapshot/restore on miss (wave-383 lesson).
  `(function(){DECL a=ARRLIT;return ADD;})()` where ADD is a
  `+`-joined additive of string literals and `a.at(INT)` /
  `a['at'](INT)` reads with F547's node-exact element-read
  semantics (negative counts from the end; out-of-bounds fails
  closed). At least one `.at()` term is required (disjoint from
  literal-only returns).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed /var/tmp TMPDIRs), fresh
/var/tmp/g385-* TMPDIRs, no in-repo git in self-pins,
concatenation-constructed credentials, pin 2143, $0-spend-by-construction.
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
def test_b0_footer_state():
    """Control: lane-local footer (F768/F769 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f768_s1():
    """F768 filed shape 1 (entries spread) blocks + decodes node-exact."""
    s = ("(function(){return [...['" + _A + "','" + _B + "'].entries()]"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f768_s2():
    """F768 filed shape 2 (Object.entries on array) blocks + exact."""
    s = ("(function(){return Object.entries(['" + _A + "','" + _B + "'])"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f769_s1():
    """F769 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a.at(0)+a.at(-1);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f769_s2():
    """F769 filed shape 2 blocks + decodes node-exact."""
    s = ("(function(){var a=['xx','" + _A + "','" + _B + "'];"
         "return a.at(1)+a.at(2);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f768_arrow():
    """F768 arrow projection blocks + exact."""
    s = ("(function(){return [...['" + _A + "','" + _B + "'].entries()]"
         ".map(e=>e[1]).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f768_keys_spread():
    """F768 keys projection on the spread twin: numeric indices join."""
    s = ("(function(){return [...['a','b','c'].entries()]"
         ".map(function(e){return e[0];}).join('');})()")
    ok = _decodes_exact(s, "012")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f768_keys_object():
    """F768 keys projection on the Object.entries twin: string indices."""
    s = ("(function(){return Object.entries(['a','b','c'])"
         ".map(e=>e[0]).join('');})()")
    ok = _decodes_exact(s, "012")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f768_bracket_entries():
    """F768 bracket-string ['entries']() twin blocks + exact."""
    s = ("(function(){return [...['" + _A + "','" + _B + "']['entries']()]"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f768_bracket_object():
    """F768 Object['entries'] bracket twin blocks + exact."""
    s = ("(function(){return Object['entries'](['" + _A + "','" + _B + "'])"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f768_destructure():
    """F768 destructured pair param projection blocks + exact."""
    s = ("(function(){return Object.entries(['" + _A + "','" + _B + "'])"
         ".map(function([k,v]){return v;}).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f769_bracket_at():
    """F769 a['at']() bracket twin blocks + exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return a['at'](0)+a['at'](-1);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f769_let_const():
    """F769 let/const binding twins decode node-exact (const also blocks:
    the xoxb- prefix lands at the start so the Slack rule fires)."""
    s1 = ("(function(){let a=['" + _A + "','" + _B + "'];"
          "return a.at(1)+a.at(0);})()")
    s2 = ("(function(){const a=['" + _A + "','" + _B + "'];"
          "return a.at(-2)+a.at(-1);})()")
    ok = (_decodes_exact(s1, _B + _A)
          and _decodes_exact(s2, _A + _B) and _blocked(s2))
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f769_lit_mix():
    """F769 literal + at-read mixed additive decodes node-exact."""
    s = ("(function(){var a=['" + _A + "','" + _B + "'];"
         "return 'x'+a.at(0)+'y';})()")
    ok = _decodes_exact(s, "x" + _A + "y")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f768_no_map():
    """F768 spread-entries without .map projection fails closed."""
    s = "(function(){return [...['a','b'].entries()].join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f768_entries_args():
    """F768 .entries() with arguments fails closed."""
    s = ("(function(){return [...['a','b'].entries(0)]"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f768_hole():
    """F768 spread twin over a holey array fails closed."""
    s = ("(function(){return [...['a',,'b'].entries()]"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f768_obj_hole():
    """F768 Object.entries twin over a holey array fails closed."""
    s = ("(function(){return Object.entries(['a',,'b'])"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f768_nonstr():
    """F768 non-string array element fails closed."""
    s = ("(function(){return Object.entries(['a',1])"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f768_bad_projection():
    """F768 unrecognized projection: my parser fails closed (returns
    None). Note: a DIFFERENT pre-existing route mis-decodes this
    shape as 'Object.entriesab' on the base too (verified
    base-identical) -- out of scope, flagged for a future wave."""
    s = ("(function(){return Object.entries(['a','b'])"
         ".map(function(e){return e;}).join('');})()")
    # My F768 parsers must not claim it: the decode must not be the
    # node-exact "0,a1,b".
    got = dlp._try_js_expr_decode_all(s)
    ok = got is None or "0,a1,b" not in got
    return ("HELD" if ok else "BREAK", "not-claimed=%s" % ok)


@_t
def test_p3_f768_extra_arg():
    """F768 Object.entries with extra args fails closed."""
    s = ("(function(){return Object.entries(['a','b'],'x')"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_oob():
    """F769 out-of-bounds .at() fails closed (engine undefined)."""
    s = "(function(){var a=['a','b'];return a.at(5);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_oob_neg():
    """F769 negative out-of-bounds .at() fails closed."""
    s = "(function(){var a=['a','b'];return a.at(-3);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_bracket_read():
    """F769 plain bracket index read (not .at) stays unclaimed."""
    s = "(function(){var a=['a','b'];return a[0]+a[1];})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_wrong_receiver():
    """F769 .at() on a different array fails closed."""
    s = "(function(){var a=['a','b'];var b=['c'];return b.at(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_nonlit_index():
    """F769 non-literal .at() index fails closed."""
    s = "(function(){var a=['a','b'];var i=0;return a.at(i);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_extra_arg():
    """F769 .at() with extra args fails closed."""
    s = "(function(){var a=['a','b'];return a.at(0,1);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_nonstr_elem():
    """F769 non-string array element fails closed."""
    s = "(function(){var a=['a',1];return a.at(1);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_hole():
    """F769 holey array fails closed."""
    s = "(function(){var a=['a',,'b'];return a.at(1);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_reassign():
    """F769 reassigned binding fails closed."""
    s = "(function(){var a=['a','b'];a=['c'];return a.at(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_multi_decl():
    """F769 multi-declaration fails closed."""
    s = "(function(){var a=['a','b'],b=['c'];return a.at(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f769_extra_stmt():
    """F769 extra statement fails closed."""
    s = ("(function(){var a=['a','b'];var z=1;"
         "return a.at(0);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still work


@_t
def test_p4_sibling_f612():
    """F612 var-bound Object.entries on objects still blocks."""
    s = ("(function(){var o={x:'" + _A + "',y:'" + _B + "'};"
         "return Object.entries(o).map(function(e){return e[1];})"
         ".join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f612=%s" % ok)


@_t
def test_p4_sibling_f517():
    """F517 inline Object.entries on objects still blocks."""
    s = ("(function(){return Object.entries({x:'" + _A + "',y:'" + _B + "'})"
         ".map(function(e){return e[1];}).join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f517=%s" % ok)


@_t
def test_p4_sibling_f547():
    """F547 inline .at() still blocks."""
    s = ("(function(){return ['" + _A + "','" + _B + "'].at(0)"
         "+['" + _A + "','" + _B + "'].at(-1);})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f547=%s" % ok)


@_t
def test_p4_sibling_f573():
    """F573 bare Object.entries on object literals still decodes."""
    s = ("(function(){return Object.entries({x:'a',y:'b'})"
         "[0][1]+'cd';})()")
    ok = _decodes_exact(s, "acd")
    return ("HELD" if ok else "BREAK", "f573=%s" % ok)


@_t
def test_p4_neighbor_f767_open():
    """Neighbor F767 stays OPEN in the footer (my change doesn't touch it)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = "F767," in text and "F767 filed" in text
    return ("HELD" if ok else "BREAK", "f767-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_entries_unaffected():
    """Honest Object.entries on objects without credentials stays quiet."""
    s = "Object.entries({a:1}).length"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_at_unaffected():
    """Honest .at() on non-arrays stays quiet."""
    s = "'hello'.at(0)"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){return [...['a%d','b'].entries()]"
            ".map(function(e){return e[1];}).join('');})()" % k)
        sites.append(
            "(function(){var a=['x','y'];return a.at(0);})()")
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
    # (battery, expected BREAKs): all green -- the w384 attack
    # battery's F768/F769 pins were flipped to closed by this lane
    # and its footer pin repointed to the lane-local footer.
    for batt, expect_break in (("evals/w384_f768_redfirst.py", 0),
                               ("evals/w384_f769_redfirst.py", 0),
                               ("evals/w385_f768_redfirst.py", 0),
                               ("evals/w385_f769_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 0)):
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
    """Depth-1 green check: red-firsts + w384 attack battery all green."""
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
