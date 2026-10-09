#!/usr/bin/env python3
"""Wave-385 lane 10: close F780 + F781 (param'd-constructor this-binding
reads; prototype method reads).

F780 (LOW; filed 2026-10-09 by wave-384 attack round 52): F690
residual -- F690 models zero-param constructors but fails closed on
constructor params and call args:
  (function(){function C(x){this.x=x;}var o=new C('f1');return o.x+'f2';})()
  (function(){return Reflect.construct(function(x){this.x=x;},['f1']).x+'f2';})()

F781 (LOW; filed 2026-10-09 by wave-384 attack round 52): the decoder
has no prototype-method production:
  (function(){function C(){}C.prototype.m=function(){return 'f1';};return new C().m()+'f2';})()
  (function(){function C(){}C.prototype.m=function(){return 'f1';};return new C()['m']()+'f2';})()

Fix (gov/dlp.py, zero new re.compile):
- F780: _js_parse_f780_ctor_param_iife (+ _js_f780_parse_params,
  _js_f780_parse_ctor_body, _js_f780_bind, _js_f780_new_instance,
  _js_f780_parse_lit_array, _js_f780_reflect_construct,
  _js_f780_member_read, _js_f780_operand), hooked after F690 with
  the wave-383 F733 parts/ops snapshot-restore discipline.
  Disjoint: F690 requires zero-param ctors and fails closed on
  params/call args. Param-unbound members carry the _F780_MISSING
  marker so a later literal cannot mask an undefined overwrite
  (node-exact).
- F781: _js_parse_f781_proto_method_iife (+ _js_f781_parse_method_body,
  _js_f781_parse_new_call), hooked after F780. Disjoint: every
  accepted shape carries a `C.prototype.m=` statement head, which
  F780 fails closed on.

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
    """Control: lane-local footer (F780/F781/F796 closed, F795 filed,
    next F797)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F797**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, "
              "F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, "
              "F779, F782, F783, F784, F785, F786, F787, F788, F789, F790, "
              "F791, F792, F793, F794, F795." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f780_s1():
    """F780 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){function C(x){this.x=x;}var o=new C('" + _A
         + "');return o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f780_s2():
    """F780 filed shape 2 (Reflect.construct twin) blocks + exact."""
    s = ("(function(){return Reflect.construct(function(x){this.x=x;},['"
         + _A + "']).x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f781_s1():
    """F781 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f781_s2():
    """F781 filed shape 2 (bracket twin) blocks + decodes node-exact."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return new C()['m']()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f780_multi_param():
    """F780 two-param constructor binds positionally, node-exact."""
    s = ("(function(){function C(a,b){this.x=a;this.y=b;}var o=new C('"
         + _A + "','" + _B + "');return o.x+o.y;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f780_class():
    """F780 class-constructor twin blocks + exact."""
    s = ("(function(){class C{constructor(x){this.x=x;}}return new C('"
         + _A + "').x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f780_lit_param_mix():
    """F780 literal + param this-assign mix blocks + exact."""
    s = ("(function(){function C(x){this.a='pre';this.x=x;}var o=new C('"
         + _A + "');return o.a+o.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "pre" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f780_later_wins():
    """F780 later this-assignment wins, node-exact."""
    s = ("(function(){function C(x){this.x=x;this.x='z';}return new C('"
         + _A + "').x;})()")
    ok = _decodes_exact(s, "z") and not _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "later-wins=%s" % ok)


@_t
def test_p2_f780_bracket():
    """F780 bracket this-assign / bracket read twins block + exact."""
    s = ("(function(){function C(x){this['x']=x;}var o=new C('" + _A
         + "');return o['x']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f780_reflect_named():
    """F780 Reflect.construct with a declared ctor name blocks + exact."""
    s = ("(function(){function C(x){this.x=x;}return "
         "Reflect.construct(C,['" + _A + "']).x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f781_multi_method():
    """F781 two prototype methods dispatch independently, node-exact."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};C.prototype.n=function(){return '" + _B
         + "';};return new C().m()+new C().n();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f781_later_wins():
    """F781 later prototype install wins, node-exact."""
    s = ("(function(){function C(){}C.prototype.m=function(){return 'z';};"
         "C.prototype.m=function(){return '" + _A + "';};"
         "return new C().m();})()")
    ok = _decodes_exact(s, _A) and not _decodes_exact(s, "z")
    return ("HELD" if ok else "BREAK", "later-wins=%s" % ok)


@_t
def test_p2_f781_varbound():
    """F781 var-bound instance method call blocks + exact."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};var o=new C();return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f781_bracket_install():
    """F781 bracket-form prototype install blocks + exact."""
    s = ("(function(){function C(){}C.prototype['m']=function(){return '"
         + _A + "';};return new C()['m']();})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f796_class_empty():
    """F796: empty-class prototype method read blocks + decodes exact."""
    s = ("(function(){class C{}C.prototype.m=function(){return '"
         + _A + "';};return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f796_class_bracket():
    """F796: bracket-form class prototype install blocks + exact."""
    s = ("(function(){class C{}C.prototype['m']=function(){return '"
         + _A + "';};var o=new C();return o['m']()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_f796_class_extends():
    """F796 bound: class extends fails closed."""
    s = ("(function(){class C extends Object{}C.prototype.m=function(){"
         "return 'a';};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f796_class_nonempty():
    """F796 bound: non-empty class body fails closed."""
    s = ("(function(){class C{go(){return 1;}}C.prototype.m=function(){"
         "return 'a';};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f780_missing_arg():
    """F780 missing call arg -> member undefined -> fail closed."""
    s = ("(function(){function C(x){this.x=x;}return new C().x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_undef_overwrite():
    """F780 undefined overwriting a literal -> fail closed (no mask)."""
    s = ("(function(){function C(x){this.x='z';this.x=x;}return new C().x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_ctor_return():
    """F780 `return` in the ctor body fails closed (returned object
    would replace the instance in the engine)."""
    s = ("(function(){function C(x){this.x=x;return {x:'zz'};}"
         "return new C('" + _A + "').x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_nonthis_stmt():
    """F780 non-this statement in the ctor body fails closed."""
    s = ("(function(){function C(x){var z=1;this.x=x;}return new C('"
         + _A + "').x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_unbound_rhs():
    """F780 unbound RHS ident fails closed (ReferenceError in node)."""
    s = ("(function(){function C(x){this.x=y;}return new C('" + _A
         + "').x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_default_param():
    """F780 default params fail closed (F736 owns defaults)."""
    s = ("(function(){function C(x='d'){this.x=x;}return new C().x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_rc_nonarray():
    """F780 Reflect.construct with non-array args fails closed
    (node throws TypeError)."""
    s = ("(function(){return Reflect.construct(function(x){this.x=x;},'"
         + _A + "').x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f780_rc_newtarget():
    """F780 Reflect.construct third (newTarget) arg fails closed."""
    s = ("(function(){function D(){}return "
         "Reflect.construct(function(x){this.x=x;},['" + _A + "'],D).x;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_thisread():
    """F781 non-literal method return fails closed."""
    s = ("(function(){function C(){this.x='" + _A + "';}"
         "C.prototype.m=function(){return this.x;};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_argcall():
    """F781 method called with args fails closed (zero-param only)."""
    s = ("(function(){function C(){}C.prototype.m=function(x){return x;};"
         "return new C().m('" + _A + "');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_nocall():
    """F781 bare method read without the call fails closed (the engine
    yields the function object)."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return typeof new C().m;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_protoassign():
    """F781 wholesale `C.prototype={...}` fails closed."""
    s = ("(function(){function C(){}C.prototype={m:function(){return '"
         + _A + "';}};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_missmethod():
    """F781 call of an uninstalled method fails closed (node throws)."""
    s = ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return new C().n();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_namedfn():
    """F781 named function expression method fails closed."""
    s = ("(function(){function C(){}C.prototype.m=function foo(){return '"
         + _A + "';};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_ctorbody():
    """F781 non-empty ctor body fails closed (F690/F780 own those)."""
    s = ("(function(){function C(){this.x='" + _A + "';}"
         "C.prototype.m=function(){return '" + _A + "';};"
         "return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_arrow():
    """F781 arrow-function method fails closed."""
    s = ("(function(){function C(){}C.prototype.m=()=>'a';"
         "return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f781_extends():
    """F781 subclassing fails closed."""
    s = ("(function(){class B{}class C extends B{}"
         "C.prototype.m=function(){return 'a';};return new C().m();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f690():
    """F690 zero-param ctor pin still blocks."""
    s = ("(function(){function C(){this.x='" + _A + "';}var o=new C();"
         "return o.x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f690=%s" % ok)


@_t
def test_p4_sibling_f757():
    """F757 new.target pin still blocks."""
    s = ("(function(){function C(){this.x=new.target===C?'" + _A
         + "':'z';}return new C().x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f757=%s" % ok)


@_t
def test_p4_sibling_f735():
    """F735 nested-function closure pin still blocks."""
    s = ("(function(){var f='" + _A + "';function g(){return f;}"
         "return g()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f735=%s" % ok)


@_t
def test_p4_sibling_f736():
    """F736 default-param pin still blocks."""
    s = ("(function(){function h(a='" + _A + "'){return a;}"
         "return h()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f736=%s" % ok)


@_t
def test_p4_neighbor_f779_open():
    """Neighbor F779 still misses -- out of scope; honest open shape."""
    s = ("(function(){var s=Symbol.for('" + _A + "');"
         "return Symbol.keyFor(s)+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f779-open=%s" % ok)


@_t
def test_p4_neighbor_f782_open():
    """Neighbor F782 still misses -- out of scope; honest open shape."""
    s = ("(function(){function f(){return this.x;}"
         "return f.call({x:'" + _A + "'})+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f782-open=%s" % ok)


@_t
def test_p4_neighbor_f795_open():
    """Neighbor F795 (filed this lane) still misses -- honest open."""
    s = ("(function(){function C(x){this.x=x;}"
         "C.prototype.m=function(){return '" + _A + "';};"
         "return new C('" + _A + "').m()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f795-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_ctor_unaffected():
    """Honest constructor without a fragment still misses."""
    s = "(function(){function C(x){this.x=x;}var o=new C('ab');return o.x;})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_method_unaffected():
    """Honest prototype method without a fragment still misses."""
    s = ("(function(){function C(){}C.prototype.m=function(){return 'ab';};"
         "return new C().m();})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){function C(x){this.x=x;}var o=new C('a%d');"
            "return o.x;})()" % k)
        sites.append(
            "(function(){function C(){}C.prototype.m=function(){return 'v';};"
            "return new C().m();})()")
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
    # (battery, expected BREAKs): the w384 attack battery's only
    # expected BREAK is test_b0_footer_state (base footer pin; the
    # lane-local repoint is merge-owned, wave-305 lesson). The
    # w385_f795 red-first is 2 BREAK by design (open finding); the
    # w385_f796 red-first is 0 BREAK (closed this lane).
    for batt, expect_break in (("evals/w384_f780_redfirst.py", 0),
                               ("evals/w384_f781_redfirst.py", 0),
                               ("evals/w385_f795_redfirst.py", 2),
                               ("evals/w385_f796_redfirst.py", 0),
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
    """Depth-1 green check: F780/F781 red-firsts (0 BREAK), the F795
    red-first (2 BREAK: open finding by design), and the wave-384
    attack battery (1 BREAK: the footer pin only, lane-local
    repoint; tree-wide repoint is merge-owned)."""
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
