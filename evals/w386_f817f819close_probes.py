#!/usr/bin/env python3
"""Wave-386 lane 12: close F817 + F819 (swap destructuring, fill ranges).

F817 (LOW; filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
F790 residual -- rest/swap destructuring. F790 (CLOSED, wave-385)
covers declaration-pattern rest, but the bare swap/copy assignment
`[a,b]=[b,a]` had no production: it resolves node-exactly while the
decoder produced zero variants. Filed shapes:
  (function(){var [a,...r]=['f1','f2'];return a+r[0];})()   [s1: HELD on
   the merged base via F790's var-form rest -- asserted, not re-closed]
  (function(){var a='f1',b='f2';[a,b]=[b,a];return b+a;})()  [s2: the miss]

F819 (LOW; filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
F773 residual -- fill with range args. F773 (CLOSED, wave-385) covers
1-arg fill with an indexed-read return and F681 covers 3-arg fill on
array-literal decls, but `new Array(N)` decls and 2-arg fills had no
production. Filed shapes:
  (function(){var a=new Array(3);a.fill('f1',0,1);a.fill('f2',1,2);
   return a.join('');})()
  (function(){var a=['z','z'];a.fill('f1',-2,-1);a.fill('f2',-1);
   return a.join('');})()

Fix (gov/dlp.py, zero new re.compile):
- F817: `_js_parse_f817_swap_iife` -- `(function(){DECL; [P]=[E];
  return ADD;})()` with var/let string-literal declarators, a flat
  equal-length swap/copy assignment (RHS read before LHS assign,
  engine order), and the F790 additive return. `const` fails closed
  (engine throws TypeError); literal binding names (null/true/false)
  fail closed (engine SyntaxError); unbound names, length mismatch,
  holes, defaults, rest, reassignment all fail closed. Hooked after
  F790 with parts/ops snapshot-restore on miss.
- F819: `_js_parse_f819_fill_range_iife` -- `(function(){DECL;
  FILL+; return NAME.join(SEP);})()` with `new Array(N)` or
  array-literal decls and 1/2/3-arg fills (engine fill semantics:
  negative counts back, clamped, start>=end no-op). Disjoint from
  F681 (requires the new-Array decl or a 1/2-arg fill -- F681 fails
  closed on both) and F773 (indexed-read return). Hooked after F773
  with parts/ops snapshot-restore on miss.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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
    """Control: lane-local footer (F817/F819 closed)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, "
              "F801, F802, F803, F804, F805, F806, F807, F808, F809, "
              "F810, F811, F812, F813, F814, F815, F816, F820, F821, "
              "F822, F823, F824, F825, F826, F827, F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f817_s1():
    """F817 filed shape 1 (var rest) blocks + decodes node-exact."""
    s = ("(function(){var [a,...r]=['" + _A + "','" + _B
         + "'];return a+r[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f817_s2():
    """F817 filed shape 2 (swap) blocks + decodes node-exact."""
    s = ("(function(){var a='" + _A + "',b='" + _B
         + "';[a,b]=[b,a];return b+a;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f819_s1():
    """F819 filed shape 1 (new Array + range fills) blocks + exact."""
    s = ("(function(){var a=new Array(3);a.fill('" + _A + "',0,1);"
         "a.fill('" + _B + "',1,2);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f819_s2():
    """F819 filed shape 2 (negative ranges) blocks + exact."""
    s = ("(function(){var a=['z','z'];a.fill('" + _A + "',-2,-1);"
         "a.fill('" + _B + "',-1);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f817_swap3():
    """F817 3-way rotation blocks + exact."""
    s = ("(function(){var a='" + _A + "',b='x',c='" + _B
         + "';[a,c,b]=[a,b,c];return a+b+c;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + "x")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f817_copy():
    """F817 single copy decodes node-exact (fragment: exact only)."""
    s = ("(function(){var a='x';[a]=['" + _A + "'];return a;})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f817_lit_rhs():
    """F817 literal RHS blocks + exact."""
    s = ("(function(){var a='x',b='y';[a,b]=['" + _A + "','" + _B
         + "'];return a+b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f817_let():
    """F817 let decl blocks + exact."""
    s = ("(function(){let a='" + _A + "',b='" + _B
         + "';[a,b]=[b,a];return b+a;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f819_neg_start():
    """F819 negative start blocks + exact."""
    s = ("(function(){var a=['a','b','c'];a.fill('" + _A
         + "',-2);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, "a" + _A + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f819_one_arg_join():
    """F819 1-arg fill + join return blocks + exact."""
    s = ("(function(){var a=['z','z'];a.fill('" + _A
         + "');return a.join('-');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "-" + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f819_noop():
    """F819 out-of-range fill (no-op) decodes node-exact."""
    s = ("(function(){var a=['a','b'];a.fill('" + _A
         + "',5);return a.join('');})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f819_default_sep():
    """F819 default join separator decodes node-exact."""
    s = ("(function(){var a=new Array(2);a.fill('" + _A
         + "');return a.join();})()")
    ok = _decodes_exact(s, _A + "," + _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f817_const():
    """F817 const decl throws in the engine -- fail closed."""
    s = "(function(){const a='x';[a]=['y'];return a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_unbound_lhs():
    """F817 unbound LHS (sloppy global) -- fail closed."""
    s = "(function(){var a='x';[a,b]=[a,'y'];return a+b;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_len_mismatch():
    """F817 pattern length mismatch -- fail closed."""
    s = "(function(){var a='x',b='y';[a]=[a,b];return a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_hole():
    """F817 hole in pattern -- fail closed."""
    s = "(function(){var a='x',b='y';[,b]=[a,b];return b;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_default():
    """F817 default in pattern -- fail closed."""
    s = "(function(){var a='x';[a='d']=['y'];return a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_rest():
    """F817 rest element -- unclaimed by any hook, fail closed."""
    s = "(function(){var a='x',b='y';[a,...r]=[b,a];return a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_literal_name():
    """F817 `null` binding (engine SyntaxError) -- fail closed."""
    s = "(function(){var null='x',b='y';[null,b]=[b,null];return b;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f817_reassign():
    """F817 reassignment between decl and swap -- fail closed."""
    s = "(function(){var a='x',b='y';a='z';[a,b]=[b,a];return b+a;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f819_frac_len():
    """F819 fractional new Array (engine RangeError) -- fail closed."""
    s = "(function(){var a=new Array(2.5);a.fill('X');return a.join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f819_neg_len():
    """F819 negative new Array (engine RangeError) -- fail closed."""
    s = "(function(){var a=new Array(-1);return a.join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f819_str_len():
    """F819 string new Array arg (single element, not length) -- closed."""
    s = "(function(){var a=new Array('3');a.fill('X');return a.join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f819_frac_fill():
    """F819 fractional fill index (engine truncates; F681 parity) -- closed."""
    s = "(function(){var a=['a','b'];a.fill('X',0.5,1);return a.join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f819_splice():
    """F819 splice statement is F767's domain -- still blocks there."""
    s = ("(function(){var a=['a','" + _A + _B
         + "'];a.splice(0,1);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f819_nonlit_fill():
    """F819 non-literal fill value -- fail closed."""
    s = "(function(){var a=['a','b'];var v='X';a.fill(v);return a.join('');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f681_domain():
    """F819 defers array-literal + all-3-arg fills to F681 (direct)."""
    fn = getattr(dlp, "_js_parse_f819_fill_range_iife", None)
    if fn is None:
        return ("HELD", "skipped (function absent on base tree)")
    s = "(function(){var a=['a','b'];a.fill('X',0,1);return a.join('');})()"
    r = fn(s, 0, 0, {"parts": 0, "ops": 0})
    ok = r is None
    return ("HELD" if ok else "BREAK", "defers=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must still block)


@_t
def test_p4_f790_rest():
    """Sibling: F790 var rest still blocks."""
    s = ("(function(){var [a,...r]=['" + _A + "','" + _B
         + "','x'];return a+r[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f749_plain():
    """Sibling: F749 plain destructuring still blocks."""
    s = ("(function(){var [a,b]=['" + _A + "','" + _B
         + "'];return a+b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f681_fill3():
    """Sibling: F681 3-arg fill still blocks."""
    s = ("(function(){var a=['x','y'];a.fill('" + _A + _B
         + "',0,1);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + "y")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f773_fill1_idx():
    """Sibling: F773 1-arg fill + indexed read still blocks."""
    s = ("(function(){var a=['x','y'];a.fill('" + _A + _B
         + "');return a[0];})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f767_splice():
    """Sibling: F767 splice still blocks."""
    s = ("(function(){return ['x','" + _A + _B + "'].splice(1).join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p5: honest text (must stay quiet)


@_t
def test_p5_honest_1():
    """Honest text stays quiet."""
    ok = _misses("hello world, this is honest text with no code")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_2():
    """Honest array join stays quiet."""
    ok = _misses("(function(){var a=['x','y'];return a.join('-');})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_3():
    """Honest swap of non-credentials stays quiet."""
    ok = _misses("(function(){var a='x',b='y';[a,b]=[b,a];return a+b;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_4():
    """Honest new Array stays quiet."""
    ok = _misses("(function(){var a=new Array(2);return a.length;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in reasonable time."""
    sites = []
    for k in range(50):
        sites.append("(function(){var a='x',b='y';[a,b]=[b,a];return a+b;})()")
        sites.append("(function(){var a=new Array(3);a.fill('X',0,1);"
                     "a.fill('Y',1,2);return a.join('');})()")
        sites.append("(function(){var [a,...r]=['x','y'];return a+r[0];})()")
        sites.append("(function(){var a=['x','y'];a.fill('X',0,1);"
                     "return a.join('');})()")
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # w385_f817/f819_redfirst.py expect 0 BREAK (closed); the
    # w385_attack battery expects 4 BREAKs: its test_b0_footer_state
    # asserts the base footer (open F795-F828) while this lane's
    # footer closes F817/F819, and its F817-s2 / F819-s1 / F819-s2
    # open pins now HELD -- all four are the expected consequences
    # of this closure. The tree-wide footer repoint is merge-owned
    # (wave-305 lesson); all functional probes HELD.
    for batt, expect_break in (("evals/w385_f817_redfirst.py", 0),
                               ("evals/w385_f819_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 4)):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
    """Depth-1 green check: F817/F819 red-firsts (0 BREAK), w385
    attack battery (4 BREAK = footer pin + 3 closure pins)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
        if not args.tally_only:
            print("%s %-28s %s" % (verdict, fn.__name__, note))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
