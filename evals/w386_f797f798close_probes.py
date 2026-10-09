#!/usr/bin/env python3
"""Wave-386 lane 2: close F797 + F798 (yield* delegation / generator methods;
WeakMap/WeakSet multi-binding reads).

F797 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round 53):
F728 residual -- yield* delegation across generators and object-literal
generator methods have no decoder production: both resolve node-exactly
while the decoder produced zero variants.

F798 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round 53):
WeakMap/WeakSet multi-binding reads -- the decoder modeled only
single-set/single-get WeakMap reads: WeakMap.get across multiple keys and
WeakSet.has-guarded ternaries resolve node-exactly while the decoder
produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F797: _js_f797_parse_gen_body parses generator bodies with yield/yield*
  statements and a trailing return; _js_f797_flat_yields resolves
  delegation to a flat yield sequence (fresh iterator per delegation,
  cycles fail closed = engine RangeError, unknown callees fail closed);
  _js_parse_f797_yieldstar_iife requires >=1 delegation (disjoint from
  F728) and models the F728 additive against the flat sequence (16-call
  bound, trailing return at exhaustion); _js_parse_f797_genmethod_iife
  models object-literal generator methods where each O.m() call is a
  fresh iterator delivering the first flat yield (node v24.20.0
  verified), with optional leading generator decls for method-body
  yield* delegation.
- F798: _js_parse_f572_weakmap_iife's decl loop accepts comma-separated
  declarators (each binding mints its own uid, engine-exact rebinding);
  _js_parse_f572_return_expr's additive tail accepts a weakmap get-chain
  term after '+'. New _js_parse_f798_weakset_ternary_iife handles
  WeakSet membership-ternary assignments (X = ws.has(k)?'a':'b') feeding
  an additive return (disjoint from F687's parenthesized-ternary head).

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
def test_b0_footer_state():
    """Control: lane-local footer (F797/F798 stamped CLOSED, F829 filed
    OPEN, next F830)."""
    import re
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    stamped797 = ("(F797 filed 2026-10-09 03:25 UTC" in text
                  and "LOW, CLOSED 2026-10-09 wave-386 lane 2: F728 residual"
                  in text)
    stamped798 = ("(F798 filed 2026-10-09 03:25 UTC" in text
                  and "LOW, CLOSED 2026-10-09 wave-386 lane 2: WeakMap/WeakSet"
                  in text)
    filed829 = "(F829 filed 2026-10-09 05:41 UTC, wave-386 lane 2" in text
    footers = [l for l in text.splitlines()
               if "Next free finding: **F830**" in l]
    last = footers[-1] if footers else ""
    m = re.search(r"Open findings: ([^*]*)", last)
    open_list = m.group(1) if m else ""
    open_ok = (", F797," not in open_list and ", F798," not in open_list
               and "F795," in open_list and "F799," in open_list
               and "F829." in open_list)
    ok = stamped797 and stamped798 and filed829 and open_ok
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f797_s1():
    """F797 filed shape 1 (yield* delegation) blocks + decodes node-exact."""
    s = ("(function(){function* a(){yield '" + _A + "';}function* b(){"
         "yield* a();yield '" + _B + "';}var it=b();"
         "return it.next().value+it.next().value;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f797_s2():
    """F797 filed shape 2 (generator method) blocks + decodes node-exact."""
    s = ("(function(){var o={*m(){yield '" + _A + "';}};"
         "return o.m().next().value+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f798_s1():
    """F798 filed shape 1 (multi-binding WeakMap) blocks + exact."""
    s = ("(function(){var wm=new WeakMap();var k1={},k2={};"
         "wm.set(k1,'" + _A + "');wm.set(k2,'" + _B + "');"
         "return wm.get(k1)+wm.get(k2);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f798_s2():
    """F798 filed shape 2 (WeakSet ternary assign) blocks + exact."""
    s = ("(function(){var ws=new WeakSet();var k={};ws.add(k);"
         "var x=ws.has(k)?'" + _A + "':'zz';return x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f797_chain3():
    """Three-generator delegation chain resolves node-exactly."""
    s = ("(function(){function* a(){yield 'A';}function* b(){yield* a();"
         "yield 'B';}function* c(){yield* b();yield 'C';}var it=c();"
         "return it.next().value+it.next().value+it.next().value;})()")
    ok = _decodes_exact(s, "ABC")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f797_double_deleg():
    """Two sibling delegations inline the callee sequence twice."""
    s = ("(function(){function* a(){yield 'A';}function* b(){yield* a();"
         "yield* a();}var it=b();"
         "return it.next().value+it.next().value;})()")
    ok = _decodes_exact(s, "AA")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f797_trailing_return():
    """Trailing return surfaces at exhaustion, node-exact."""
    s = ("(function(){function* a(){yield 'A';return 'RA';}function* b(){"
         "yield* a();return 'RB';}var it=b();"
         "return it.next().value+it.next().value;})()")
    ok = _decodes_exact(s, "ARB")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f797_two_methods():
    """Two generator methods each read fresh, node-exact."""
    s = ("(function(){var o={*m(){yield 'A';},*n(){yield 'B';}};"
         "return o.m().next().value+o.n().next().value;})()")
    ok = _decodes_exact(s, "AB")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f797_method_twice():
    """Repeated method call re-reads the first yield (fresh iterator)."""
    s = ("(function(){var o={*m(){yield 'A';}};"
         "return o.m().next().value+o.m().next().value;})()")
    ok = _decodes_exact(s, "AA")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f797_method_delegates():
    """Method body delegating to a declared generator resolves."""
    s = ("(function(){function* a(){yield 'A';}var o={*m(){yield* a();}};"
         "return o.m().next().value;})()")
    ok = _decodes_exact(s, "A")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_3bind():
    """Three WeakMap bindings read back node-exactly."""
    s = ("(function(){var wm=new WeakMap();var k1={},k2={},k3={};"
         "wm.set(k1,'a');wm.set(k2,'b');wm.set(k3,'c');"
         "return wm.get(k1)+wm.get(k2)+wm.get(k3);})()")
    ok = _decodes_exact(s, "abc")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_mixed_tail():
    """WeakMap chain term after '+' with a literal separator."""
    s = ("(function(){var wm=new WeakMap();var k1={},k2={};"
         "wm.set(k1,'a');wm.set(k2,'b');"
         "return wm.get(k1)+'-'+wm.get(k2);})()")
    ok = _decodes_exact(s, "a-b")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_single_still():
    """Single-binding WeakMap shape (F572) still decodes."""
    s = ("(function(){var wm=new WeakMap();var k={};wm.set(k,'a');"
         "return wm.get(k);})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_negated():
    """Negated has() ternary selects the else branch, node-exact."""
    s = ("(function(){var ws=new WeakSet();var k={};ws.add(k);"
         "var x=!ws.has(k)?'zz':'a';return x+'b';})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_two_ternaries():
    """Two ternary assignments in one body."""
    s = ("(function(){var ws=new WeakSet();var k={};ws.add(k);"
         "var x=ws.has(k)?'a':'zz';var y=ws.has(k)?'b':'yy';"
         "return x+y;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f798_else_branch():
    """has() on a non-member takes the else branch, node-exact."""
    s = ("(function(){var ws=new WeakSet();var k={};"
         "var x=ws.has(k)?'a':'zz';return x;})()")
    ok = _decodes_exact(s, "zz")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must NOT decode)


@_t
def test_p3_f797_cycle():
    """Mutual delegation cycle fails closed (engine RangeError)."""
    s = ("(function(){function* a(){yield* b();}function* b(){yield* a();}"
         "var it=a();return it.next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_self_deleg():
    """Self-delegation fails closed (engine RangeError)."""
    s = ("(function(){function* a(){yield* a();}var it=a();"
         "return it.next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_unknown_deleg():
    """Delegation to an undeclared name fails closed."""
    s = ("(function(){function* b(){yield* zz();}var it=b();"
         "return it.next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_noniter_deleg():
    """Delegation to a non-iterable fails closed (engine TypeError)."""
    s = ("(function(){function* b(){yield* 42;}var it=b();"
         "return it.next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_empty_method():
    """Method with no yields fails closed (engine undefined)."""
    s = ("(function(){var o={*m(){}};return o.m().next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_past_exhaustion():
    """next() past exhaustion fails closed (engine undefined)."""
    s = ("(function(){function* a(){yield 'A';}function* b(){yield* a();}"
         "var it=b();return it.next().value+it.next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_sibling_deleg():
    """Method delegating to a sibling method fails closed (engine
    ReferenceError -- bare method names are not in scope)."""
    s = ("(function(){var o={*m(){yield* n();},*n(){yield 'A';}};"
         "return o.m().next().value;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f797_too_many_next():
    """17 next() calls exceed the 16-call bound (fail closed)."""
    s = ("(function(){function* a(){yield 'A';}function* b(){yield* a();}"
         "var it=b();return " + "+".join(["it.next().value"] * 17)
         + ";})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f798_missing_key():
    """WeakMap.get on an unset key fails closed (engine undefined)."""
    s = ("(function(){var wm=new WeakMap();var k1={},k2={};"
         "wm.set(k1,'a');return wm.get(k2);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f798_trailing_comma():
    """Trailing comma in declarator list fails closed (engine SyntaxError)."""
    s = ("(function(){var wm=new WeakMap();var k1={},;"
         "wm.set(k1,'a');return wm.get(k1);})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f798_ctor_arg():
    """WeakSet constructor with an iterable arg fails closed."""
    s = ("(function(){var ws=new WeakSet([{}]);var k={};"
         "ws.add(k);var x=ws.has(k)?'a':'zz';return x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must not regress)


@_t
def test_p4_f728_plain():
    """F728 plain single-generator shape still decodes (no delegation)."""
    s = ("(function(){function* g(){yield 'A';yield 'B';}var it=g();"
         "return it.next().value+it.next().value;})()")
    ok = _decodes_exact(s, "AB")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_f656_firstnext():
    """F656 plain generator twin still decodes."""
    s = ("(function(){function* g(){yield 'A';}var it=g();"
         "return it.next().value;})()")
    ok = _decodes_exact(s, "A")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_f687_weakset_paren():
    """F687 parenthesized WeakSet ternary still decodes (disjoint)."""
    s = ("(function(){var ws=new WeakSet();var k={};ws.add(k);"
         "return (ws.has(k)?'A':'zz');})()")
    ok = _decodes_exact(s, "A")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_f572_rebind():
    """F572 rebinding discipline still holds (second set wins)."""
    s = ("(function(){var wm=new WeakMap();var k={};"
         "wm.set(k,'a');wm.set(k,'b');return wm.get(k);})()")
    ok = _decodes_exact(s, "b")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_f677_nextseq():
    """F677 next-sequence shape still decodes."""
    s = ("(function(){function* g(){yield 'A';yield 'B';}var it=g();"
         "return it.next().value+it.next().value;})()")
    ok = _decodes_exact(s, "AB")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p5: honest-text controls (must NOT block)


@_t
def test_p5_honest_generator():
    """Honest generator prose does not block."""
    ok = _misses("the generator yields results lazily via yield* delegation")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p5_honest_weakmap():
    """Honest WeakMap prose does not block."""
    ok = _misses("store per-key state in a WeakMap with multiple bindings")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p5_honest_weakset():
    """Honest WeakSet prose does not block."""
    ok = _misses("membership is tracked with a WeakSet and has() checks")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){function* a(){yield 'x%d';}function* b(){"
            "yield* a();}var it=b();return it.next().value;})()" % k)
        sites.append(
            "(function(){var o={*m(){yield 'y%d';}};"
            "return o.m().next().value;})()" % k)
        sites.append(
            "(function(){var wm=new WeakMap();var k1={},k2={};"
            "wm.set(k1,'p%d');wm.set(k2,'q%d');"
            "return wm.get(k1)+wm.get(k2);})()" % (k, k))
        sites.append(
            "(function(){var ws=new WeakSet();var k={};ws.add(k);"
            "var x=ws.has(k)?'r%d':'zz';return x;})()" % k)
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
    # Both red-firsts must be 0 BREAK (F797/F798 closed); the
    # wave-385 attack battery is expected to report exactly 5 BREAK:
    # - its b0 footer pin asserts the base footer (F795-F828 open),
    #   while this lane's footer is lane-local (F797/F798 closed) --
    #   tree-wide repoint is merge-owned (wave-305 lesson);
    # - its four r53_f797/f798_*_open pins assert the filed shapes
    #   MISS; they now BREAK (miss=False) because the shapes are
    #   closed -- the expected red-first-audit inversion proving
    #   the closure;
    # - the F829 red-first reports 1 RAISED (the open NameError bug,
    #   filed this lane).
    # All functional probes must HELD.
    for batt, expect_break in (("evals/w386_f797_redfirst.py", 0),
                               ("evals/w386_f798_redfirst.py", 0),
                               ("evals/w386_f829_redfirst.py", 1),
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
    """Depth-1 green check: both F797/F798 red-firsts 0 BREAK, F829
    red-first 1 RAISED (open bug, filed this lane), wave-385 attack
    battery 5 BREAK (1 footer pin, lane-local merge-owned; 4
    r53_f797/f798 open-pins inverted by the closure -- the expected
    red-first-audit signal)."""
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
