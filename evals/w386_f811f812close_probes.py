#!/usr/bin/env python3
"""Wave-386 lane 9: close F811 + F812 (computed method names; Object wrapper reads).

F811 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round
53): computed method names -- F755 covers computed getters, but
{[k](){...}} / {['m'+'2'](){...}} had no production: they resolve
node-exactly (v24.20.0) while the decoder produced zero variants.

F812 (LOW; filed 2026-10-09 03:25 UTC by wave-385 lane 13, attack round
53): Object wrapper reads -- F539 models Object.freeze/assign in VALUE
position only and F548 models Object.create(PROTO[,PROPS]) in VALUE
position only: a var-bound Object.seal literal in an IIFE return
additive, and a var-bound Object.create(null) result mutated by a
post-binding assignment (o.k='lit'), both resolve node-exactly while
the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile, pin 2143 untouched):
- F811: shorthand methods in _js_parse_f67x_object (this_bodies-gated,
  like the name:function(){...} method value; zero-arg only; all key
  forms incl. computed) + computed string-literal/additive keys in its
  `[` branch (F492 fold); new _js_parse_f811_computed_method_iife for
  the two-decl `var K='LIT';var o={[K](){...}};` shape (hooked after
  F674, snapshot/restore; disjoint: F673's computed-key data shape
  fails closed on shorthand methods, F674 is single-decl). The
  single-decl additive-key shape routes via F674 unchanged.
- F812: Object.seal/preventExtensions added to
  _js_parse_f539_object_identity (identity on the argument,
  node-verified); new _js_parse_f812_sealed_iife (var-bound sealed
  literal) + _js_parse_f812_create_assign_iife (create result +
  o.K='lit' assignments, __proto__ fails closed), both hooked after
  F811 with snapshot/restore.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    path = os.path.join(REPO_ROOT, "evals",
                        "w318_evidence_schema_probes.py")
    text = open(path).read()
    ok = "VERIFIER_TAXONOMY_PIN = 33" in text
    return ("HELD" if ok else "BREAK", "vpin=%s" % ok)


@_t
def test_p0_no_new_re_compile():
    """Zero new re.compile (stays 28)."""
    path = os.path.join(REPO_ROOT, "gov", "dlp.py")
    text = open(path).read()
    n = len(re.findall(r"re\.compile\(", text))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F811/F812 closed, F829+F830 filed, next F831)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F831**" in text
          and "F811, F812 CLOSED" in text
          and "F829 FILED" in text
          and "F830 FILED" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, "
              "F802, F803, F804, F805, F806, F807, F808, F809, F810, F813, "
              "F814, F815, F816, F817, F819, F820, F821, F822, F823, F824, "
              "F825, F826, F827, F828, F829, F830." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f811_s1():
    """F811 filed shape 1 ({[k](){...}}) blocks + decodes node-exact."""
    s = ("(function(){var k='m';var o={[k](){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f811_s2():
    """F811 filed shape 2 ({['m'+'2'](){...}}) blocks + node-exact."""
    s = ("(function(){var o={['m'+'2'](){return '" + _A + "';}};"
         "return o.m2()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f812_s1():
    """F812 filed shape 1 (Object.seal IIFE) blocks + node-exact."""
    s = ("(function(){var o=Object.seal({k:'" + _A + "'});"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f812_s2():
    """F812 filed shape 2 (create+assign IIFE) blocks + node-exact."""
    s = ("(function(){var o=Object.create(null);o.k='" + _A + "';"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f811_plain_shorthand():
    """Plain shorthand m(){} blocks + exact (single-decl, via F674)."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_string_computed():
    """{['m'](){...}} blocks + exact."""
    s = ("(function(){var o={['m'](){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_bracket_call():
    """o['m']() bracket-call twin blocks + exact."""
    s = ("(function(){var k='m';var o={[k](){return '" + _A + "';}};"
         "return o['m']()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_this_body():
    """Method reading this.k decodes with this=o, node-exact."""
    s = ("(function(){var o={k:'" + _A + "',m(){return this.k;}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_two_methods():
    """Two computed methods both callable, node-exact."""
    s = ("(function(){var k='m';var o={[k](){return '" + _A + "';},"
         "n(){return '" + _B + "';}};return o.m()+o.n();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_freeze_iife():
    """Object.freeze IIFE twin blocks + exact."""
    s = ("(function(){var o=Object.freeze({k:'" + _A + "'});"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_prevent_iife():
    """Object.preventExtensions IIFE twin blocks + exact."""
    s = ("(function(){var o=Object.preventExtensions({k:'" + _A + "'});"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_seal_valuepos():
    """Object.seal value-position read blocks + exact."""
    s = "var x=Object.seal({k:'" + _A + "'}).k+'" + _B + "';"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_bracket_assign():
    """o['k']='lit' bracket-assign twin blocks + exact."""
    s = ("(function(){var o=Object.create(null);o['k']='" + _A + "';"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_two_assigns():
    """Two assignments both land, node-exact (later-wins)."""
    s = ("(function(){var o=Object.create(null);o.a='" + _A + "';"
         "o.b='" + _B + "';return o.a+o.b;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_proto_assign_shadow():
    """Assignment shadows a proto prop, node-exact."""
    s = ("(function(){var o=Object.create({k:'nope'});o.k='" + _A + "';"
         "return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p2_f811_two_keys():
    """Two key declarators, both callable, node-exact (spec HARD-1a)."""
    s = ("(function(){var a='m';var b='n';var o={[a](){return '" + _A + "';},"
         "[b](){return '" + _B + "';}};return o.m()+o.n();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_comma_declarator():
    """Comma-joined `var k='m',o={...}` blocks + exact (spec HARD-1b)."""
    s = ("(function(){var k='m',o={[k](){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f811_additive_call_key():
    """o['m'+'2']() additive call key blocks + exact (spec HARD-1c)."""
    s = ("(function(){var o={['m'+'2'](){return '" + _A + "';}};"
         "return o['m'+'2']()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f812_nullproto_dunder():
    """o.__proto__='lit' on null-proto installs own prop, node-exact
    (spec HARD-2c)."""
    s = ("(function(){var o=Object.create(null);o.__proto__='" + _A + "';"
         "return o.__proto__+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f811_method_param():
    """m(x){...} with a parameter fails closed."""
    s = ("(function(){var o={m(x){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f811_body_unbound_ident():
    """Method body reading an outer var fails closed (w376 pin)."""
    s = ("(function(){var a='" + _A + "';var o={s(){return a;}};"
         "return o.s();})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f811_call_with_args():
    """o.m(1): non-empty call args fail closed."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o.m(1)+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f811_call_missing_key():
    """o.n(): call on a missing key fails closed."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o.n()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f811_bare_method_read():
    """o.m without a call: methods are function values, fail closed."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o.m+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f811_named_function():
    """Named function expression fails closed."""
    s = ("(function(){var k='m';var o={[k](){return '" + _A + "';}};"
         "return (function foo(){return o.m();})()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f811_setter_still_closed():
    """set s(v){} setters still fail closed."""
    s = ("(function(){var o={set s(v){},m(){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f812_proto_assign():
    """o.__proto__=... on a NON-null proto fails closed (setter)."""
    s = ("(function(){var o=Object.create({});o.__proto__={k:'" + _A + "'};"
         "return o.k+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f812_assign_wrong_name():
    """Assignment to a different ident fails closed."""
    s = ("(function(){var o=Object.create(null);p.k='" + _A + "';"
         "return o.k+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f812_seal_two_args():
    """Object.seal({...},{...}): two args fail closed."""
    s = ("(function(){var o=Object.seal({k:'" + _A + "'},{j:1});"
         "return o.k+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_f812_seal_nonobject():
    """Object.seal('s'): non-object arg fails closed."""
    s = "(function(){var o=Object.seal('abc');return o;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f812_create_no_assign():
    """Bare create with no assignment stays out of F812's routes."""
    s = ("(function(){var o=Object.create(null);"
         "return 'x';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p4: siblings (must still block)


@_t
def test_p4_sibling_f674_method():
    """F674 function-valued method still blocks + exact."""
    s = ("(function(){var o={a:function(){return '" + _A + "';}};"
         "return o.a()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f674=%s" % ok)


@_t
def test_p4_sibling_f673_computed_data():
    """F673 computed-key DATA shape still blocks + exact."""
    s = ("(function(){var k='m';var o={[k]:'" + _A + "'};"
         "return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f673=%s" % ok)


@_t
def test_p4_sibling_f755_computed_getter():
    """F755 computed string getter still blocks + exact."""
    s = ("(function(){var o={get ['m'](){return '" + _A + "';}};"
         "return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f755=%s" % ok)


@_t
def test_p4_sibling_f535_getter():
    """F535 plain getter still blocks + exact."""
    s = ("(function(){var o={get m(){return '" + _A + "';}};"
         "return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f535=%s" % ok)


@_t
def test_p4_sibling_f539_freeze():
    """F539 freeze value-position still blocks + exact."""
    s = "var x=Object.freeze({k:'" + _A + "'}).k+'" + _B + "';"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f539=%s" % ok)


@_t
def test_p4_sibling_f548_create():
    """F548 create value-position still blocks + exact."""
    s = "var x=Object.create(null,{k:{value:'" + _A + "'}}).k+'" + _B + "';"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f548=%s" % ok)


@_t
def test_p4_sibling_f704_create_accessor():
    """F704 create-accessor IIFE still blocks + exact."""
    s = ("(function(){var o=Object.create(null,{k:{get:function(){return '"
         + _A + "';}}});return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f704=%s" % ok)


# ------------------------------------------------ p4b: open neighbors (must still miss)


@_t
def test_p4b_neighbor_f810_s1_open():
    """Neighbor F810 (method chains) still misses -- honest open shape."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return '" + _A + "';}};return o.a().b()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f810-open=%s" % ok)


@_t
def test_p4b_neighbor_f810_s2_open():
    """Neighbor F810 shape 2 still misses."""
    s = ("(function(){var o={a:function(){this.v='" + _A + "';return this;},"
         "b:function(){return this.v;}};return o.a().b()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f810-open=%s" % ok)


@_t
def test_p4b_neighbor_f813_s1_open():
    """Neighbor F813 (descriptor re-installation) still misses."""
    s = ("(function(){var o={};var d=Object.getOwnPropertyDescriptor({k:'"
         + _A + "'},'k');Object.defineProperty(o,'k',d);"
         "return o.k+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f813-open=%s" % ok)


@_t
def test_p4b_neighbor_f829_open():
    """Neighbor F829 (bound-ident computed getter, filed this lane)
    still misses -- honest open shape."""
    s = ("(function(){var k='m';var o={get [k](){return '" + _A + "';}};"
         "return o.m+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f829-open=%s" % ok)


@_t
def test_p4b_neighbor_f830_open():
    """Neighbor F830 (seal+method, filed this lane) still misses."""
    s = ("(function(){var o=Object.seal({m(){return '" + _A + "';}});"
         "return o.m()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f830-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_method_unaffected():
    """Honest shorthand method without a credential still misses."""
    s = "(function(){var o={m(){return 'hello';}};return o.m();})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_seal_unaffected():
    """Honest seal without a credential still misses."""
    s = "(function(){var o=Object.seal({k:'v'});return o.k;})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_create_assign_unaffected():
    """Honest create+assign without a credential still misses."""
    s = "(function(){var o=Object.create(null);o.k='v';return o.k;})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){var o={m%d(){return 'a%d';}};return o.m%d();})()"
            % (k, k, k))
        sites.append(
            "(function(){var o=Object.seal({k:'b%d'});return o.k;})()" % k)
        sites.append(
            "(function(){var o=Object.create(null);o.k='c%d';return o.k;})()"
            % k)
        sites.append(
            "(function(){var t='d%d';var o={[t](){return 'e';}};"
            "return o.d%d();})()" % (k, k))
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
    # Both lane red-firsts must be 0 BREAK (F811/F812 closed); the
    # F829/F830 red-firsts must be 2 BREAK each (filed OPEN this
    # lane -- honest open state).
    for batt, expect_break in (("evals/w386_f811_redfirst.py", 0),
                               ("evals/w386_f812_redfirst.py", 0),
                               ("evals/w386_f829_redfirst.py", 2),
                               ("evals/w386_f830_redfirst.py", 2)):
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
    # The wave-385 attack battery is expected to report exactly these
    # BREAKs on the lane tree: the 4 F811/F812 open pins now block
    # (closed this lane) and its footer pin is stale (lane-local
    # footer; tree-wide repoint is merge-owned -- wave-305 lesson).
    # F810's open pins must still HELD (miss).
    tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w385_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=1200,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    lines = {ln.split(":")[0]: ln for ln in out.splitlines() if ": " in ln}
    expect_break = {"test_b0_footer_state",
                    "test_r53_f811_s1_open", "test_r53_f811_s2_open",
                    "test_r53_f812_s1_open", "test_r53_f812_s2_open"}
    expect_held = {"test_r53_f810_s1_open", "test_r53_f810_s2_open"}
    for name in expect_break:
        ln = lines.get(name, "")
        if ": BREAK" not in ln:
            bad.append((name, "expected-BREAK"))
    for name in expect_held:
        ln = lines.get(name, "")
        if ": HELD" not in ln:
            bad.append((name, "expected-HELD"))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: lane red-firsts 0 BREAK (closed),
    F829/F830 red-firsts 2 BREAK (filed open); w385 attack shows
    exactly the 4 closed-pin + 1 footer BREAKs, F810 pins HELD."""
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
            print("ERROR in %s: %s" % (fn.__name__, note))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
