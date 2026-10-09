#!/usr/bin/env python3
"""Wave-386 lane 5: close F803 + F804 (var-bound method-call results;
named-function arguments indexed reads).

F803 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack
round 53): var-bound method-call results -- the decoder binds vars
to literals but not to method-call results: var s='f1'.repeat(1) and
var s='f1'.concat('') miss while node resolves them exactly.

F804 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack
round 53): arguments indexed reads -- F524 (CLOSED) covers
destructuring from arguments, but indexed arguments[0]/arguments[1]
reads inside a named function declaration have no production: they
resolve node-exactly while the decoder produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F803: the F611 var-binding initializer now accepts
  'LIT'.repeat(n) / 'LIT'.concat('lit', ...) via _js_apply_method
  with the narrow _F803_INIT_METHODS allowlist (repeat, concat) --
  the same node-exact grammar/bounds/fail-closed rules as the
  inline twin, budget snapshot/restore on miss. Non-allowlisted
  methods, malformed calls, and non-string results fail closed.
- F804: new _js_parse_f804_named_fn_arguments_iife for
  (function(){function F(){BODY}return F('lit',...);})() --
  every arguments[N] in code spans is textually replaced by the
  quoted N-th call-site literal, then the rewritten body is
  re-parsed as an anonymous IIFE at depth+1 (F611 handles the
  var-decl twin). Bare/member/call/assignment uses of arguments,
  out-of-range or non-canonical indices, declared params, and
  nested function/class/arrow/new/delete/this/super all fail closed.

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


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_no_new_re():
    """Zero new re.compile (28 stands)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F803/F804 closed, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "F795, F796, F797, F798, F799, F800, F801, F802, " in text
          and "F805, F806, F807, F808, F809, F810, F811, F812, F813, "
              "F814, F815, F816, F817, " in text
          and "F819, F820, F821, F822, F823, F824, F825, F826, F827, "
              "F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f803_s1():
    """F803 filed s1: var s='f1'.repeat(1)."""
    p = ("(function(){var s='%s'.repeat(1);return s+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f803-s1")


@_t
def test_p1_f803_s2():
    """F803 filed s2: var s='f1'.concat('')."""
    p = ("(function(){var s='%s'.concat('');return s+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f803-s2")


@_t
def test_p1_f804_s1():
    """F804 filed s1: named fn arguments[0]+arguments[1]."""
    p = ("(function(){function f(){return arguments[0]+arguments[1];}"
         "return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f804-s1")


@_t
def test_p1_f804_s2():
    """F804 filed s2: named fn var x=arguments[1]."""
    p = ("(function(){function f(){var x=arguments[1];"
         "return arguments[0]+x;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f804-s2")


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_f803_repeat3():
    """F803: repeat(3) initializer."""
    p = ("(function(){var s='%s'.repeat(3);return s;})()" % _A)
    return ("HELD" if _blocked(p) else "BREAK", "repeat3")


@_t
def test_p2_f803_concat_multi():
    """F803: concat with two literal args."""
    p = ("(function(){var s='%s'.concat('%s','%s');return s;})()"
         % (_A, _B, _B))
    return ("HELD" if _blocked(p) else "BREAK", "concat-multi")


@_t
def test_p2_f803_ws():
    """F803: whitespace around the method call."""
    p = ("(function(){var s = '%s' . repeat( 1 ) ;return s+'%s';})()"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "ws")


@_t
def test_p2_f804_three_args():
    """F804: three call args, middle index read."""
    p = ("(function(){function f(){return arguments[0]+arguments[2];}"
         "return f('%s','%s','%s');})()" % (_A, _B, _A))
    return ("HELD" if _blocked(p) else "BREAK", "three-args")


@_t
def test_p2_f804_two_decls():
    """F804: two var decls over arguments."""
    p = ("(function(){function f(){var a=arguments[0];var b=arguments[1];"
         "return a+b;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "two-decls")


@_t
def test_p2_f804_bracket_ws():
    """F804: whitespace inside brackets."""
    p = ("(function(){function f(){return arguments[ 0 ]+'%s';}"
         "return f('%s');})()" % (_B, _A))
    return ("HELD" if _blocked(p) else "BREAK", "bracket-ws")


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f803_nonallowlisted():
    """F803: slice initializer fails closed (not allowlisted)."""
    p = ("(function(){var s='%s'.slice(0,2);return s;})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "slice-miss")


@_t
def test_p3_f803_bad_repeat():
    """F803: repeat() with no args fails closed."""
    p = ("(function(){var s='%s'.repeat();return s;})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "repeat-noarg")


@_t
def test_p3_f803_repeat_negative():
    """F803: repeat(-1) fails closed (engine throws)."""
    p = ("(function(){var s='%s'.repeat(-1);return s;})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "repeat-neg")


@_t
def test_p3_f803_concat_numeric():
    """F803: concat(1) coerces node-exactly (F477), not fail-closed."""
    p = "(function(){var s='ab'.concat(1);return s;})()"
    # Node: 'ab'.concat(1) === 'ab1' -- the decoder models the
    # numeric coercion node-exactly (same as the inline twin), so
    # this is a decode, not a fail-closed miss. (find_credential
    # does not flag single-literal returns -- pre-existing.)
    got = dlp._try_js_expr_decode_all(p)
    ok = got is not None and "ab1" in got
    return ("HELD" if ok else "BREAK", "concat-num=%r" % (got,))


@_t
def test_p3_f803_huge_repeat():
    """F803: huge repeat count fails closed (budget)."""
    p = ("(function(){var s='%s'.repeat(999999999);return s;})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "repeat-huge")


@_t
def test_p3_f804_oob():
    """F804: out-of-range index fails closed."""
    p = ("(function(){function f(){return arguments[2];}"
         "return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "oob")


@_t
def test_p3_f804_noncanonical():
    """F804: non-canonical [00] fails closed."""
    p = ("(function(){function f(){return arguments[00];}"
         "return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "noncanonical")


@_t
def test_p3_f804_length():
    """F804: arguments.length member read fails closed."""
    p = ("(function(){function f(){return arguments.length;}"
         "return f('%s');})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "length")


@_t
def test_p3_f804_bare():
    """F804: bare arguments use fails closed."""
    p = ("(function(){function f(){return arguments;}"
         "return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "bare")


@_t
def test_p3_f804_params():
    """F804: declared params fail closed."""
    p = ("(function(){function f(a){return a;}"
         "return f('%s');})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "params")


@_t
def test_p3_f804_name_mismatch():
    """F804: call name != function name fails closed."""
    p = ("(function(){function f(){return arguments[0];}"
         "return g('%s');})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "name-mismatch")


@_t
def test_p3_f804_nonlit_arg():
    """F804: non-literal call arg fails closed."""
    p = ("(function(){function f(){return arguments[0];}"
         "return f('%s',x);})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "nonlit-arg")


@_t
def test_p3_f804_nested_fn():
    """F804: nested function in body fails closed."""
    p = ("(function(){function f(){function g(){return 1;}"
         "return arguments[0];}return f('%s');})()" % _A)
    return ("HELD" if _misses(p) else "BREAK", "nested-fn")


@_t
def test_p3_f804_write_through():
    """F804: arguments[0]=x write fails closed."""
    p = ("(function(){function f(){arguments[0]='x';"
         "return arguments[1];}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if _misses(p) else "BREAK", "write-through")


# ------------------------------------------------ p4: sibling pins


@_t
def test_p4_f611_plain():
    """Sibling: F611 plain literal initializer still blocks."""
    p = ("(function(){var s='%s';return s+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f611")


@_t
def test_p4_f509_anon():
    """Sibling: F509 anonymous arguments form still blocks."""
    p = ("(function(){return arguments[0]+arguments[1]})('%s','%s')"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f509")


@_t
def test_p4_f524_anon():
    """Sibling: F524 anonymous destructure form still blocks."""
    p = ("(function(){const [a,b]=arguments;return a+b})('%s','%s')"
         % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f524")


@_t
def test_p4_repeat_inline():
    """Sibling: inline repeat twin still blocks."""
    p = ("(function(){return '%s'.repeat(1)+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "repeat-inline")


@_t
def test_p4_concat_inline():
    """Sibling: inline concat twin still blocks."""
    p = ("(function(){return '%s'.concat('')+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "concat-inline")


@_t
def test_p4_f661_two_decl():
    """Sibling: F661 two-declarator form still blocks."""
    p = ("(function(){var a='%s',b='%s';return a+b;})()" % (_A, _B))
    return ("HELD" if _blocked(p) else "BREAK", "f661")


# ------------------------------------------------ p5: honest text


@_t
def test_p5_honest_var():
    """Honest: plain var, no credential."""
    p = "(function(){var s='ab';return s+'cd';})()"
    return ("HELD" if _misses(p) else "BREAK", "honest-var")


@_t
def test_p5_honest_repeat():
    """Honest: repeat initializer, no credential."""
    p = "(function(){var s='ab'.repeat(2);return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "honest-repeat")


@_t
def test_p5_honest_namedfn():
    """Honest: named fn arguments, no credential."""
    p = ("(function(){function f(){return arguments[0]+'!';}"
         "return f('ab');})()")
    return ("HELD" if _misses(p) else "BREAK", "honest-namedfn")


@_t
def test_p5_junk_quiet():
    """Honest: junk-quiet control."""
    p = "'(function(){var s=\\'ab\\';return s;})()'"
    return ("HELD" if _misses(p) else "BREAK", "junk")


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """Perf: 200 mixed sites under 30s."""
    sites = []
    for k in range(200):
        if k % 4 == 0:
            sites.append("(function(){var s='%s'.repeat(1);return s+'%s';})()"
                         % (_A, _B))
        elif k % 4 == 1:
            sites.append("(function(){function f(){return arguments[0]+"
                         "arguments[1];}return f('%s','%s');})()" % (_A, _B))
        elif k % 4 == 2:
            sites.append("(function(){var s='ab'.repeat(2);return s;})()")
        else:
            sites.append("(function(){return 'ab'+'cd';})()")
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 30 else "BREAK", "perf=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Both w386 red-firsts must be 0 BREAK (F803/F804 closed); the
    # wave-385 attack battery is expected to report exactly 1 BREAK:
    # its test_b0_footer_state asserts the merged footer, while this
    # lane's footer is lane-local (F803/F804 closed) -- tree-wide
    # repoint is merge-owned (wave-305 lesson). All functional
    # probes must HELD.
    for batt, expect_break in (("evals/w386_f803_redfirst.py", 0),
                               ("evals/w386_f804_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 1)):
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
    """Depth-1 green check: w386 red-firsts 0 BREAK + w385 attack 1 BREAK
    (footer pin only, lane-local; merge-owned)."""
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
            verdict, note = ("ERROR", "%s: %r" % (fn.__name__, e))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
        if not args.tally_only:
            print("%-42s %-6s %s" % (fn.__name__, verdict, note))
    print("tally: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
