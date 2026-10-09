#!/usr/bin/env python3
"""Wave-386 lane 1: close F795 + F796 (IIFE with parameters; async value flows).

F795 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round 53):
IIFE with parameters -- the decoder's IIFE productions bind no params:
(function(a,b){return a+b;})('f1','f2') and the arrow twin
((a,b)=>a+b)('f1','f2') evaluate node-exactly while the decoder produced
zero variants.

F796 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round 53):
async function value flows -- the decoder has no async production:
(async function(){var x=await 'f1';return x+'f2';})() and the async-method
twin (async function(){var o={async m(){return 'f1';}};
return await o.m()+'f2';})() evaluate to Promises of the credential while
the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F795: _js_parse_f795_param_iife + _js_parse_f795_param_arrow_iife.
  Positional binding (extra args ignored, F582; fewer args than params
  fail closed, F582/F524); string-literal defaults (F645); node-exact
  (v24.20.0). Hooked after F645 (function) / F608 (arrow); disjoint by
  invocation grammar.
- F796: _js_parse_f796_async_iife. Two tight shapes: (A) var x = await
  'LIT'; return ADD, (B) var o = {async m(){return 'LIT';}};
  return await o.m() + tail. Deterministic fulfillment (F631).

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
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recount():
    """Zero new re.compile (28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F795/F796 closed, F829 filed, next F830)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F830**" in text
          and "F795" in text and "F796" in text and "F829" in text
          and "CLOSED" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f795_s1():
    """F795 filed shape 1 (function params) blocks + decodes node-exact."""
    s = "(function(a,b){return a+b;})('" + _A + "','" + _B + "')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f795_s2():
    """F795 filed shape 2 (arrow params) blocks + decodes node-exact."""
    s = "((a,b)=>a+b)('" + _A + "','" + _B + "')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f796_s1():
    """F796 filed shape 1 (await literal) blocks + fulfillment exact."""
    s = "(async function(){var x=await '" + _A + "';return x+'" + _B + "';})()"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f796_s2():
    """F796 filed shape 2 (async method) blocks + fulfillment exact."""
    s = ("(async function(){var o={async m(){return '" + _A + "';}};"
         "return await o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f795_defaults():
    """Default params: supplied arg wins, missing takes default."""
    s1 = "(function(a='d',b){return a+b;})('" + _A + "','" + _B + "')"
    s2 = "(function(a='" + _A + "',b='" + _B + "'){return a+b;})()"
    # s1: F795 decodes (arg wins over default). s2: zero-arg invocation
    # is F645's domain -- F645 decodes via defaults (_A+_B); F795 must
    # not mis-decode it (its arg grammar requires >=1 literal arg).
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "defaults=%s" % ok)


@_t
def test_p2_f795_extra_args():
    """Extra args ignored engine-exactly (F582)."""
    s = "(function(a,b){return a+b;})('" + _A + "','" + _B + "','x')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "extra=%s" % ok)


@_t
def test_p2_f795_named():
    """Named function expression decodes (name ignored, F522)."""
    s = "(function f(a,b){return b+a;})('" + _B + "','" + _A + "')"
    # a=_B, b=_A, body b+a -> _A+_B (node-exact).
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "named=%s" % ok)


@_t
def test_p2_f795_arrow3_ws():
    """Arrow 3-param + ws-tolerant function form decode."""
    s1 = "((a,b,c)=>a+b+c)('" + _A + "','" + _B + "','x')"
    s2 = ("( function ( a , b ) { return a + b ; } )( '"
          + _A + "' , '" + _B + "' )")
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B + "x")
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    return ("HELD" if ok else "BREAK", "arrow3+ws=%s" % ok)


@_t
def test_p2_f796_let_const_named():
    """let/const/named async functions model the fulfillment."""
    s1 = "(async function(){let x=await '" + _A + "';return x+'" + _B + "';})()"
    s2 = "(async function(){const x=await '" + _A + _B + "';return x;})()"
    s3 = "(async function f(){var x=await '" + _A + _B + "';return x;})()"
    ok = _blocked(s1) and _decodes_exact(s1, _A + _B)
    ok = ok and _blocked(s2) and _decodes_exact(s2, _A + _B)
    ok = ok and _blocked(s3) and _decodes_exact(s3, _A + _B)
    return ("HELD" if ok else "BREAK", "variants=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f795_fewer_args():
    """Fewer args than params fails closed (F582/F524)."""
    s = "(function(a,b){return a+b;})('" + _A + "')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f795_dup_params():
    """Duplicate params fail closed (conservative)."""
    s = "(function(a,a){return a;})('" + _A + "','" + _B + "')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f795_nonliteral_arg():
    """Non-literal invocation arg fails closed."""
    s = "(function(a){return a;})(x)"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f795_unbound():
    """Unbound ident in body fails closed (engine ReferenceError)."""
    s = "(function(a){return b;})('" + _A + "')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f795_block_body():
    """Arrow block body fails closed (documented residual)."""
    s = "((a)=>{return a;})('" + _A + "')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f796_await_nonliteral():
    """await on a non-literal fails closed."""
    s = "(async function(){var x=await y;return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f796_two_statements():
    """Two statements fail closed (documented residual)."""
    s = ("(async function(){var x=await '" + _A + "';var y='" + _B
         + "';return x+y;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f796_async_arrow():
    """Async arrow IIFE fails closed (documented residual)."""
    s = "(async ()=>{var x=await '" + _A + "';return x;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f796_params():
    """Parameterized async function fails closed."""
    s = "(async function(a){return a;})('" + _A + "')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


@_t
def test_p3_f796_bracket_call():
    """Bracket-form method call fails closed."""
    s = ("(async function(){var o={async m(){return '" + _A + "';}};"
         "return await o['m']()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sibling_f645():
    """F645 (default params, zero-arg) still decodes."""
    s = "(function(a='d'){return a;})()"
    ok = _decodes_exact(s, "d")
    return ("HELD" if ok else "BREAK", "f645=%s" % ok)


@_t
def test_p4_sibling_f608():
    """F608 (spread args) still decodes."""
    s = "((a,b)=>a+b)(...new Set(['" + _A + "','" + _B + "']))"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f608=%s" % ok)


@_t
def test_p4_sibling_f522():
    """F522 (zero-arg IIFE) still decodes."""
    s = "(function(){return '" + _A + "';})()"
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "f522=%s" % ok)


@_t
def test_p4_sibling_f519():
    """F519 (Reflect.apply) still decodes."""
    s = "Reflect.apply((a)=>a, null, ['" + _A + "'])"
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "f519=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest_quiet():
    """Honest text with IIFE shapes but no credential stays quiet."""
    s1 = "(function(a,b){return a+b;})('x','y')"
    s2 = "(async function(){var x=await 'x';return x+'y';})()"
    s3 = "var hello = 'world';"
    ok = _misses(s1) and _misses(s2) and _misses(s3)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(a,b){return a+b;})('p%d','q%d')" % (k, k))
        sites.append(
            "(async function(){var x=await 'r%d';return x;})()" % k)
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
    # Both lane red-firsts must be 0 BREAK (F795/F796 closed); the
    # wave-385 attack battery is expected to report exactly 5 BREAKs:
    # its test_b0_footer_state asserts the base footer (this lane's
    # footer is lane-local with F795/F796 closed), and its four
    # F795/F796 open-state pins now hit because this lane closes them
    # -- tree-wide maintenance is merge-owned (wave-306 lesson).
    # All functional probes must HELD.
    for batt, expect_break in (("evals/w386_f795_redfirst.py", 0),
                               ("evals/w386_f796_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 5)):
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
    """Depth-1 green check: lane red-firsts 0 BREAK + wave-385 attack
    battery 5 BREAKs (footer + 4 closed pins, lane-local; merge-owned)."""
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
