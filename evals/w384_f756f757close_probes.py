#!/usr/bin/env python3
"""Wave-384 lane 10: close F756 (ternary conditional value flow) + F757 (new.target).

F756 (LOW, filed 2026-10-08 by wave-383 attack round 51): the decoder
has no conditional-expression production, so a fragment selected by a
provably-constant ternary leaves the credential readable while the
decoder produces zero variants:
  (function(){var c=true;return (c?'f1':'z')+'f2';})()
  (function(){var c=false;var x=c?'z':'f1';return x+'f2';})()

F757 (LOW, filed 2026-10-08 by wave-383 attack round 51): the decoder
has no new.target production, so new.target===C guards and
new.target truthiness tests select the fragment while the decoder
produces zero variants:
  (function(){function C(){this.x=new.target===C?'f1':'z';}
   return new C().x+'f2';})()
  (function(){class D{constructor(){this.v=new.target?'f1':'z';}}
   return new D().v+'f2';})()

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f756_ternary_iife (+ _js_f756_eval_cond,
  _js_f756_branch, _js_f756_ternary_at): `(function(){DECL;*
  return ADD;})()` where decls bind booleans (`true`/`false`),
  strings, or ternary results, and the return additive's terms
  are string literals, bound string names, or parenthesized
  ternaries with constant boolean conditions (literals, bound
  bools, `!` of those -- ToBoolean is the identity there,
  node-exact v24.20.0). Hooked after F734 with parts/ops
  snapshot/restore on miss (wave-383 merge lesson).
- _js_parse_f757_newtarget_iife (+ _js_f757_expect_new_target,
  _js_f757_this_assign): `(function(){function C(){
  this.M=new.target[===|!== NAME]?'A':'B';}return new
  C().M(+'LIT')*;})()` and the `class C{constructor(){
  this.M=...;}}` twin. The condition is provably decidable:
  new.target inside a constructor invoked via `new C()` is C
  itself (truthy). Comparisons against any other name throw
  ReferenceError in the engine (node v24.20.0 verified) and
  fail closed. Hooked after F756 with snapshot/restore.

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


def _decodes_to(payload, value):
    """The whole-text JS-expression decode yields exactly *value*."""
    variant = dlp._try_js_expr_decode_all(payload)
    return variant is not None and value in variant


# ---------------------------------------------------------------- controls

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


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f756_s1():
    """F756 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var c=true;return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f756-s1=%s" % ok)


@_t
def test_p1_f756_s2():
    """F756 filed shape 2 (ternary binding) blocks."""
    ok = _blocked(
        "(function(){var c=false;var x=c?'z':'%s';return x+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f756-s2=%s" % ok)


@_t
def test_p1_f757_s1():
    """F757 filed shape 1 (function ctor, === guard) blocks."""
    ok = _blocked(
        "(function(){function C(){this.x=new.target===C?'%s':'z';}"
        "return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f757-s1=%s" % ok)


@_t
def test_p1_f757_s2():
    """F757 filed shape 2 (class ctor, truthiness) blocks."""
    ok = _blocked(
        "(function(){class D{constructor(){this.v=new.target?'%s':'z';}}"
        "return new D().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f757-s2=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_f756_negated():
    """Negated bound condition decodes node-exactly."""
    ok = _blocked(
        "(function(){var c=true;var d=false;return (!d?'%s':'z')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "neg=%s" % ok)


@_t
def test_p2_f756_const_let():
    """const/let decls + bound-string branch decode."""
    ok = _blocked(
        "(function(){const c=false;let x='%s';return (c?'z':x)+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "constlet=%s" % ok)


@_t
def test_p2_f756_multi_tail():
    """Three-term additive tail decodes."""
    ok = _blocked(
        "(function(){var c=true;return (c?'%s':'z')+'%s'+'!';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "multitail=%s" % ok)


@_t
def test_p2_f756_paren_binding():
    """Parenthesized ternary in a decl initializer decodes."""
    ok = _blocked(
        "(function(){var c=true;var y=(c?'%s':'z');return y+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "parenbind=%s" % ok)


@_t
def test_p2_f756_ws_after_semi():
    """Whitespace between decls and return decodes."""
    ok = _blocked(
        "(function(){var c=true; return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "wsafter=%s" % ok)


@_t
def test_p2_f756_string_alias():
    """String-alias decl feeding a ternary branch decodes."""
    ok = _blocked(
        "(function(){var s='%s';var t=s;var c=true;return (c?t:'z')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "alias=%s" % ok)


@_t
def test_p2_f756_else_branch():
    """False condition selects the else branch."""
    ok = _decodes_to(
        "(function(){var c=false;return (c?'z':'%s')+'%s';})()" % (_A, _B),
        _A + _B)
    return ("HELD" if ok else "BREAK", "else=%s" % ok)


@_t
def test_p2_f757_neq_self():
    """new.target!==C (same name) selects the else branch."""
    ok = _decodes_to(
        "(function(){function C(){this.x=new.target!==C?'z':'%s';}"
        "return new C().x+'%s';})()" % (_A, _B),
        _A + _B)
    return ("HELD" if ok else "BREAK", "neqself=%s" % ok)


@_t
def test_p2_f757_class_eq():
    """Class ctor with new.target===D guard decodes."""
    ok = _blocked(
        "(function(){class D{constructor(){this.v=new.target===D?'%s':'z';}}"
        "return new D().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "classeq=%s" % ok)


@_t
def test_p2_f757_no_tail():
    """Bare new C().M return (no additive tail) decodes."""
    ok = _decodes_to(
        "(function(){function C(){this.x=new.target?'%s':'z';}"
        "return new C().x;})()" % _A,
        _A)
    return ("HELD" if ok else "BREAK", "notail=%s" % ok)


# --------------------------------------------------------------- bounds p3

@_t
def test_p3_f756_nullish():
    """?? is not a ternary -- fail closed."""
    ok = _misses(
        "(function(){var c=true;return (c??'z')+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nullish=%s" % ok)


@_t
def test_p3_f756_nonbool_cond():
    """Non-boolean condition is not modeled -- fail closed."""
    ok = _misses(
        "(function(){var c=1;return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonbool=%s" % ok)


@_t
def test_p3_f756_string_cond():
    """String condition (truthy, not boolean) -- fail closed."""
    ok = _misses(
        "(function(){var c='x';return (c?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "strcond=%s" % ok)


@_t
def test_p3_f756_bare_ternary_return():
    """Bare ternary in return position would mis-scope over + -- fail closed."""
    ok = _misses(
        "(function(){var c=true;return c?'%s':'z';})()" % _A)
    return ("HELD" if ok else "BREAK", "baretern=%s" % ok)


@_t
def test_p3_f756_rebind():
    """Rebinding a condition name fails closed."""
    ok = _misses(
        "(function(){var c=true;var c=false;return (c?'%s':'z')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "rebind=%s" % ok)


@_t
def test_p3_f756_unbound_cond():
    """Unbound condition name fails closed."""
    ok = _misses(
        "(function(){return (q?'%s':'z')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_f757_unbound_cmp():
    """new.target!==D with unbound D throws in the engine -- fail closed."""
    ok = _misses(
        "(function(){function C(){this.x=new.target!==D?'%s':'z';}"
        "return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unboundcmp=%s" % ok)


@_t
def test_p3_f757_wrong_name():
    """new.target===D (other name) throws in the engine -- fail closed."""
    ok = _misses(
        "(function(){function C(){this.x=new.target===D?'%s':'z';}"
        "return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "wrongname=%s" % ok)


@_t
def test_p3_f757_ctor_args():
    """Constructor call with args is not modeled -- fail closed."""
    ok = _misses(
        "(function(){function C(){this.x=new.target?'%s':'z';}"
        "return new C('a').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "ctorargs=%s" % ok)


@_t
def test_p3_f757_member_mismatch():
    """Reading a different member than assigned -- fail closed."""
    ok = _misses(
        "(function(){function C(){this.x=new.target?'%s':'z';}"
        "return new C().y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "membermismatch=%s" % ok)


@_t
def test_p3_f757_extends():
    """Class extends clause is not modeled -- fail closed."""
    ok = _misses(
        "(function(){class D extends Object{constructor(){this.v=new.target?'%s':'z';}}"
        "return new D().v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "extends=%s" % ok)


@_t
def test_p3_f757_proto_assign():
    """__proto__ assignment changes the prototype, not an own prop -- fail closed."""
    ok = _misses(
        "(function(){function C(){this.__proto__=new.target?'%s':'z';}"
        "return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proto=%s" % ok)


@_t
def test_p3_f757_multi_stmt():
    """Extra constructor statements are not modeled -- fail closed."""
    ok = _misses(
        "(function(){function C(){var q=1;this.x=new.target?'%s':'z';}"
        "return new C().x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multistmt=%s" % ok)


# -------------------------------------------- neighbors and honest text p4

@_t
def test_p4_sibling_f710():
    """F710 Set-has ternary still blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['k']);return (s.has('k')?'%s':'xx')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f710=%s" % ok)


@_t
def test_p4_sibling_f718():
    """F718 Reflect.has ternary still blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s'};var f=Reflect.has(o,'x')?'%s':'z';"
        "return f+'%s';})()" % (_A, _A, _B))
    return ("HELD" if ok else "BREAK", "f718=%s" % ok)


@_t
def test_p4_sibling_f697():
    """F697 toPrimitive coercion still blocks."""
    ok = _blocked(
        "(function(){var o={toString:function(){return '%s';}};return o+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)


@_t
def test_p4_open_f740():
    """F740 (try/catch) still misses -- open finding untouched."""
    ok = _misses(
        "(function(){var r;try{throw '%s';}catch(e){r=e;}return r+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f740=%s" % ok)


@_t
def test_p4_open_f758():
    """F758 (rest params) still misses -- open finding untouched."""
    ok = _misses(
        "(function(){function h(...xs){return xs.join('');}return h('%s','%s');})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f758=%s" % ok)


@_t
def test_p4_open_f761():
    """F761 (over-decode: non-callable @@toPrimitive) still over-decodes -- open finding untouched."""
    ok = _blocked(
        "(function(){var o={[Symbol.toPrimitive]:'x',"
        "toString:function(){return '%s';}};return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f761=%s" % ok)


@_t
def test_p4_honest_ternary():
    """Honest ternary without credentials stays quiet."""
    ok = _misses("(function(){var c=flag;return c?'yes':'no';})()")
    return ("HELD" if ok else "BREAK", "honest-tern=%s" % ok)


@_t
def test_p4_honest_newtarget():
    """Honest new.target use stays quiet."""
    ok = _misses("class Widget{constructor(){this.v=new.target?'y':'n';}}")
    return ("HELD" if ok else "BREAK", "honest-nt=%s" % ok)


@_t
def test_p4_honest_iife():
    """Honest boolean-ternary IIFE stays quiet."""
    ok = _misses("(function(){var c=true;return (c?'a':'b');})()")
    return ("HELD" if ok else "BREAK", "honest-iife=%s" % ok)


# ------------------------------------------------------- node exactness p5

@_t
def test_p5_f756_exact():
    """F756 filed shapes decode to the exact node value."""
    ok = (_decodes_to("(function(){var c=true;return (c?'f1':'z')+'f2';})()", "f1f2")
          and _decodes_to("(function(){var c=false;var x=c?'z':'f1';return x+'f2';})()", "f1f2"))
    return ("HELD" if ok else "BREAK", "exact756=%s" % ok)


@_t
def test_p5_f757_exact():
    """F757 filed shapes decode to the exact node value."""
    ok = (_decodes_to("(function(){function C(){this.x=new.target===C?'f1':'z';}return new C().x+'f2';})()", "f1f2")
          and _decodes_to("(function(){class D{constructor(){this.v=new.target?'f1':'z';}}return new D().v+'f2';})()", "f1f2"))
    return ("HELD" if ok else "BREAK", "exact757=%s" % ok)


# ------------------------------------------------------------- green p6

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree. The attack
    # battery's 4 F756/F757 pins now assert the coded block; its 1
    # tolerated BREAK is test_b0_footer_state, which asserts the
    # base footer -- the lane-local footer repoint is merge-owned
    # tree-wide (wave-305/306 class).
    for batt, expect_break in (("evals/w383_f756_redfirst.py", 0),
                               ("evals/w383_f757_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 1)):
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
    # The single tolerated attack-battery BREAK must be the footer
    # pin, not a real probe.
    if not bad:
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable,
             os.path.join(REPO_ROOT, "evals", "w383_attack_probes.py")],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        if "test_b0_footer_state: BREAK" not in out:
            bad.append(("w383_attack_probes.py", "footer-not-the-break"))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p6_green_check():
    """Depth-1 green check: F756/F757 red-firsts + wave-383 attack battery."""
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
