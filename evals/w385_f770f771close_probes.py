#!/usr/bin/env python3
"""Wave-385 lane 5: close F770 + F771 (String case transforms / toWellFormed).

F770 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round 52):
String case transforms (toLowerCase) -- the decoder had no case-transform
production: toLowerCase on an uppercase fragment resolved node-exactly
while the decoder produced zero variants.

F771 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack round 52):
String.prototype.toWellFormed identity -- toWellFormed is the identity on
well-formed text, but the decoder had no production for it: on a
var-bound string it passed the fragment through node-exactly while the
decoder produced zero variants (inline/concat forms blocked).

Fix (gov/dlp.py, zero new re.compile):
- F770: "toLowerCase"/"toUpperCase" added to _JS_POSTFIX_METHOD_NAMES with
  branches in _js_apply_method_at (ASCII-only discipline: plain-str
  receiver, non-ASCII fails closed -- Python's Unicode case tables
  diverge from the engine's on exotic code points; _JSNumStr/_JSBigInt
  fail closed like the engine's TypeError; strict no-arg), plus
  _js_parse_f770_case_iife for concat-initialized bindings
  (F611 owns literal initializers and is tried first; F652/F661 own
  paren/sequence initializers).
- F771: "toWellFormed" added to _JS_POSTFIX_METHOD_NAMES with a branch
  in _js_apply_method_at (identity on well-formed text; lone
  surrogates -> U+FFFD exactly as the engine, node-verified).

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
def test_b0_footer_state():
    """Control: lane-local footer (F770/F771 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f770_s1():
    """F770 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var s='XOXB-0123';return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f770_s2():
    """F770 filed shape 2 (concat init) blocks + decodes node-exact."""
    s = ("(function(){var s='xox'+'B-0123';return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f771_s1():
    """F771 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var s='" + _A + "';return s.toWellFormed()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f771_s2():
    """F771 filed shape 2 (twin) blocks + decodes node-exact."""
    s = ("(function(){var t='" + _A + "';return t.toWellFormed()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_toupper_literal():
    """toUpperCase twin on literal-bound var decodes node-exact.

    (Decode-exactness only: the DLP credential pattern is
    lowercase, so an uppercased variant does not block -- the
    production's value is modeling the transform node-exactly,
    closing the case-transform gap symmetrically.)
    """
    s = ("(function(){var s='" + _A + "';return s.toUpperCase()+'" + _B
         + "';})()")
    ok = _decodes_exact(s, _A.upper() + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_toupper_concat():
    """toUpperCase on concat-bound var (F770 hook) decodes node-exact."""
    s = ("(function(){var s='xoxb-'+'0123';return s.toUpperCase()+'" + _B
         + "';})()")
    ok = _decodes_exact(s, _A.upper() + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_let_const():
    """let/const declarators work like var."""
    s1 = ("(function(){let s='X'+'OXB-0123';return s.toLowerCase()+'" + _B
          + "';})()")
    s2 = ("(function(){const s='X'+'OXB-0123';return s.toLowerCase()+'" + _B
          + "';})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_multi_tail():
    """Multiple +'LIT' tail pieces assemble."""
    s = ("(function(){var s='X'+'OXB-0123';return s.toLowerCase()+'456789'+'abcdef';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_bracket_form():
    """Bracket-string method call s['toLowerCase']() blocks + exact."""
    s = ("(function(){var s='XOXB-0123';return s['toLowerCase']()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_ws_before_paren():
    """Whitespace between method name and paren is fine (postfix discipline)."""
    s = ("(function(){var s='XOXB-0123';return s.toLowerCase ()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_chained_trim():
    """Chained .toLowerCase().trim() blocks + exact."""
    s = ("(function(){var s='XOXB-0123 ';return s.toLowerCase().trim()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_twf_paren_concat():
    """toWellFormed on a parenthesized concat blocks + exact."""
    s = ("(function(){return ('" + _A + "'+'').toWellFormed()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_twf_bracket():
    """toWellFormed bracket form blocks + exact."""
    s = ("(function(){var s='" + _A + "';return s['toWellFormed']()+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_nonascii_concat_init():
    """Non-ASCII concat init fails closed (case tables may diverge)."""
    s = ("(function(){var s='\u00c4BC'+'def';return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_nonascii_literal():
    """Non-ASCII literal receiver fails closed."""
    s = ("(function(){var s='\u00c4BC';return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_extra_arg():
    """Extra call argument fails closed (strict no-arg)."""
    s = ("(function(){var s='ABC';return s.toLowerCase('tr')+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_twf_extra_arg():
    """toWellFormed with an argument fails closed."""
    s = ("(function(){var s='ABC';return s.toWellFormed('x')+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_wrong_case_name():
    """Wrong-case method name fails closed."""
    s = ("(function(){var s='ABC';return s.tolowercase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_numeric_receiver():
    """Numeric receiver fails closed (engine throws TypeError)."""
    s = "(function(){return (123).toLowerCase()+'" + _B + "';})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_optchain():
    """Optional-chaining call fails closed (tight scope)."""
    s = ("(function(){var s='A'+'B';return s?.toLowerCase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_dispatch_call():
    """String.prototype.toLowerCase.call dispatch fails closed."""
    s = ("(function(){var s='A'+'B';return String.prototype.toLowerCase.call(s)+'"
         + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_reassignment():
    """Reassignment between decl and return fails closed."""
    s = ("(function(){var s='A'+'B';s='C';return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_nonliteral_tail():
    """Non-literal tail term fails closed."""
    s = ("(function(){var s='A'+'B';return s.toLowerCase()+x;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_seq_init():
    """Sequence initializer fails closed (F652/F661 own it)."""
    s = ("(function(){var s=('A','B');return s.toLowerCase()+'" + _B
         + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_unbound_name():
    """toLowerCase on an unbound name fails closed."""
    s = "(function(){return q.toLowerCase()+'" + _B + "';})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block; neighbors open


@_t
def test_p4_sibling_trim():
    """Pre-existing trim production still blocks."""
    s = ("(function(){var s='" + _A + " ';return s.trim()+'" + _B
         + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "trim=%s" % ok)


@_t
def test_p4_sibling_f611():
    """F611 literal-init path intact (F770 hook does not steal it)."""
    s = ("(function(){var s='" + _A + "';return s+'"+ _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


@_t
def test_p4_neighbor_f769_open():
    """Neighbor F769 (OPEN) still misses."""
    s = ("(function(){var a=['" + _A + "','" + _B
         + "'];return a.at(0)+a.at(-1);})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f769-open=%s" % ok)


@_t
def test_p4_neighbor_f772_open():
    """Neighbor F772 (OPEN) still misses."""
    s = ("(function(){return ['" + _A + "','" + _B
         + "'].toSorted().reverse().join('');})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f772-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_lowercase_word():
    """Honest prose mentioning toLowerCase stays quiet."""
    ok = _misses("call s.toLowerCase() on the input string")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var s='AB%d';return s.toLowerCase()+'x';})()" % k)
        sites.append(
            "(function(){var s='a%d'+'b';return s.toWellFormed()+'x';})()" % k)
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
    # w385 red-firsts: 0 BREAK each on the closed tree.
    # w384_attack_probes: exactly 1 BREAK = its test_b0_footer_state on
    # the lane-local footer (wave-305 class; tree-wide repoint is
    # merge-owned).
    for batt, expect_break in (("evals/w385_f770_redfirst.py", 0),
                               ("evals/w385_f771_redfirst.py", 0),
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
    """Depth-1 green check: w385 red-firsts (0 BREAK) + w384 attack
    battery (1 BREAK: the footer pin only, lane-local repoint;
    tree-wide repoint is merge-owned)."""
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
