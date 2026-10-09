#!/usr/bin/env python3
"""Wave-384 lane 6: close F748 + F749 (logical assignment; destructuring defaults).

F748 (LOW; filed 2026-10-08 by wave-383 lane 14, attack round 51,
renumbered at the wave-383 merge): logical assignment ||= / &&= --
the decoder had no logical-assignment production:
  (function(){var x;x||='f1';x+='f2';return x;})()
  (function(){var o={x:'f1'};o.x&&=o.x+'f2';return o.x;})()
both node-evaluate to the exact credential (v24.20.0) while the
decoder produced zero variants.

F749 (LOW; same provenance): destructuring defaults -- the decoder
modeled plain destructuring (F545, CLOSED) but not default
initializers:
  (function(){var {x='f1',y='f2'}={};return x+y;})()
  (function(){var {x:q='f1'}={};return q+'f2';})()
both node-evaluate to the exact credential (v24.20.0) while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F748: _js_parse_f748_logassign_iife (+ _js_f748_subst_expr,
  _js_f748_scan_expr, _js_f748_truthy, _js_f748_eval_additive,
  _js_f748_guard_assign), hooked after F671 with the
  snapshot/restore idiom (wave-383 merge lesson) and the
  wave-379 tail return intact. Node-exact statement semantics:
  ||= assigns when falsy, &&= when truthy, ??= when undefined,
  += concatenates (ToString(undefined) === "undefined").
- F749: _js_parse_f749_destructure_default_iife, hooked after
  F748; object-pattern defaults over a string-literal source
  (source wins when the key is present, else the default).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
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


def _decodes_only(payload, want):
    return dlp._try_js_expr_decode_all(payload) == want


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
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f748_s1():
    """F748 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var x;x||='" + _A + "';x+='" + _B
         + "';return x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f748_s2():
    """F748 filed shape 2 blocks + decodes node-exact."""
    s = ("(function(){var o={x:'" + _A + "'};o.x&&=o.x+'" + _B
         + "';return o.x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f749_s1():
    """F749 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var {x='" + _A + "',y='" + _B
         + "'}={};return x+y;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f749_s2():
    """F749 filed shape 2 (renamed) blocks + decodes node-exact."""
    s = ("(function(){var {x:q='" + _A + "'}={};return q+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f748_or_on_empty():
    """F748 ||= on '' assigns: blocks + exact."""
    s = ("(function(){var x='';x||='" + _A + "';return x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f748_or_noassign_truthy():
    """F748 ||= on truthy is a no-op: node-exact honest decode."""
    s = "(function(){var x='a';x||='zz';return x;})()"
    ok = _decodes_only(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f748_nullish_assign():
    """F748 ??= on undefined assigns: blocks + exact."""
    s = ("(function(){var x;x??='" + _A + "';return x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f748_nullish_keep():
    """F748 ??= on a string keeps it: node-exact honest decode."""
    s = "(function(){var x='a';x??='zz';return x;})()"
    ok = _decodes_only(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f748_plus_undef():
    """F748 += on undefined: ToString is 'undefined', node-exact."""
    s = "(function(){var x;x+='zz';return x;})()"
    ok = _decodes_only(s, "undefinedzz")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f748_let():
    """F748 let-bound ||= : blocks + exact."""
    s = ("(function(){let x;x||='" + _A + "';return x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f748_member_or():
    """F748 member ||= on falsy member: blocks + exact."""
    s = ("(function(){var o={x:''};o.x||='" + _A + "';return o.x+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f748_const_member():
    """F748 member write on a const-bound object is legal: exact."""
    s = ("(function(){const o={x:'" + _A + "'};o.x+='" + _B
         + "';return o.x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f748_chain():
    """F748 chained ||= : second is a no-op, node-exact."""
    s = ("(function(){var x;x||='" + _A + "';x||='zz';return x;})()")
    ok = _decodes_only(s, _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f748_rhs_additive():
    """F748 RHS may itself be additive: node-exact."""
    s = ("(function(){var x='a';x+='" + _A + "';return x+'" + _B
         + "';})()")
    ok = _decodes_only(s, "a" + _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f749_source_wins():
    """F749 present source value beats the default: blocks + exact."""
    s = ("(function(){var {x='zz'}={x:'" + _A + "'};return x+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f749_mixed():
    """F749 one default + one source value: node-exact."""
    s = ("(function(){var {x='" + _A + "',y='" + _B
         + "'}={x:'a'};return x+y;})()")
    ok = _decodes_only(s, "a" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f749_string_key():
    """F749 string-literal key: blocks + exact."""
    s = ("(function(){var {'x':q='" + _A + "'}={};return q+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f749_const_let():
    """F749 const/let heads: blocks + exact."""
    s1 = ("(function(){const {x='" + _A + "'}={};return x+'" + _B
          + "';})()")
    s2 = ("(function(){let {x='" + _A + "'}={};return x+'" + _B
          + "';})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B))
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f748_const_plain():
    """F748 const plain-name rebinding: engine throws -> fail closed."""
    s = "(function(){const x='a';x+='zz';return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_bitwise():
    """F748 bitwise |= is not modeled -> fail closed."""
    s = "(function(){var x;x|='zz';return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_undeclared():
    """F748 undeclared target -> fail closed."""
    s = "(function(){y||='zz';return y;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_bare_rhs():
    """F748 bare-ident RHS -> fail closed."""
    s = "(function(){var x;x||=y;return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_member_on_string():
    """F748 member step on a string binding -> fail closed."""
    s = "(function(){var o='s';o.x||='zz';return o;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_missing_member():
    """F748 missing member -> fail closed."""
    s = ("(function(){var o={x:'" + _A + "'};o.y||='" + _B
         + "';return o.y;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_template_rhs():
    """F748 template RHS -> fail closed."""
    s = "(function(){var x;x||=`zz`;return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_no_return():
    """F748 without return -> fail closed."""
    s = "(function(){var x;x||='zz';})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_bare_dict_return():
    """F748 bare dict read in return ("[object Object]") -> closed."""
    s = ("(function(){var o={x:'" + _A + "'};o.x||='" + _B
         + "';return o;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_reassign_return():
    """F748 reassignment inside return -> fail closed."""
    s = "(function(){var x='a';x||='zz';return x='b';})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_multi_decl():
    """F748 multi-declarator -> fail closed (F661's shape)."""
    s = "(function(){var x='a',y='b';x||='zz';return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f748_call_args():
    """F748 with call args -> fail closed."""
    s = "(function(){var x;x||='zz';return x;})('a')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_array():
    """F749 array pattern (documented residual) -> fail closed."""
    s = "(function(){var [a='zz']=['x'];return a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_nonstr_source():
    """F749 non-string source value -> fail closed."""
    s = "(function(){var {x='zz'}={x:1};return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_nonstr_default():
    """F749 non-string default -> fail closed."""
    s = "(function(){var {x=y}={};return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_dup_names():
    """F749 duplicate bound names -> fail closed."""
    s = "(function(){var {x='a',x='b'}={};return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_nonobject_source():
    """F749 non-object source -> fail closed."""
    s = "(function(){var {x='zz'}='s';return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_reassign_return():
    """F749 reassignment inside return -> fail closed."""
    s = "(function(){var {x='zz'}={};return x='b';})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_arity3():
    """F749 three bindings -> fail closed (documented arity)."""
    s = "(function(){var {x='a',y='b',z='c'}={};return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f749_rest():
    """F749 rest element -> fail closed."""
    s = "(function(){var {...r}={x:'zz'};return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_sibling_f611():
    """F611 single-binding pin still blocks."""
    s = ("(function(){var x='" + _A + "';return x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


@_t
def test_p4_sibling_f661():
    """F661 decl-sequence pin still blocks."""
    s = ("(function(){var s=('jx','" + _A + "');return s+'" + _B
         + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f661=%s" % ok)


@_t
def test_p4_sibling_f671():
    """F671 member-read pin still blocks."""
    s = ("(function(){var o={x:'" + _A + "'};return o.x+'" + _B
         + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


@_t
def test_p4_neighbor_f740_now_closed():
    """Neighbor F740 (try/catch) now blocks (closed wave-384 lane 2)."""
    s = ("(function(){var r;try{throw '" + _A + "';}catch(e){r=e;}"
         "return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f740-closed=%s" % ok)


@_t
def test_p4_neighbor_f752_now_closed():
    """Neighbor F752 (builtin-iterator .next().value) now blocks (closed wave-384 lane 8)."""
    s = ("(function(){var it=['" + _A + "','" + _B
         + "'][Symbol.iterator]();var s='';s+=it.next().value;"
         "s+=it.next().value;return s;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f752-closed=%s" % ok)


@_t
def test_p4_plain_destructure_pin():
    """Pre-existing pin: plain object destructuring from a literal
    (no defaults) already blocks on the base tree -- unaffected."""
    s = ("(function(){var {a,b}={a:'" + _A + "',b:'" + _B
         + "'};return a+b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_logassign_no_fp():
    """Honest ||= / += text decodes but never flags (no false positive)."""
    s = "(function(){var x='ab';x+='cd';return x;})()"
    ok = _misses(s) and _decodes_only(s, "abcd")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_destructure_no_fp():
    """Honest destructuring-defaults text never flags."""
    s = "(function(){var {x='ab',y='cd'}={};return x+y;})()"
    ok = _misses(s) and _decodes_only(s, "abcd")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var x;x||='a%d';x+='b%d';return x;})()" % (k, k))
        sites.append(
            "(function(){var {x='a%d',y='b%d'}={};return x+y;})()"
            % (k, k))
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
    # w383_attack_probes.py expects 0 BREAKs after the wave-384 merge
    # footer repoint (test_b0_footer_state now asserts the merged
    # footer); all functional probes must HELD.
    for batt, expect_break in (("evals/w383_f748_redfirst.py", 0),
                               ("evals/w383_f749_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
    """Depth-1 green check: F748/F749 red-firsts (0 BREAK) + wave-383
    attack battery (1 BREAK: the footer pin only, lane-local repoint;
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
