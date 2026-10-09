#!/usr/bin/env python3
"""Wave-386 lane 6: close F805 + F806 (static-block reads; mixin extends reads).

F805 (LOW; filed 2026-10-09 by wave-385 attack round 53): class static
block reads -- the decoder had no static-block production for
declarations and name-RHS assignments: static initialization blocks
assigning outer vars via block-local bindings resolve node-exactly
while the decoder produced zero variants.

F806 (LOW; filed 2026-10-09 by wave-385 attack round 53): mixin
extends-expression reads -- the decoder had no extends-expression
production: classes extending call-expression mixins resolve
node-exactly while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F805: `_js_f662_static_block` gains a block-local scope.
  Node-verified (v24.20.0): `var`/`let`/`const` inside a static block
  are scoped to the block (the block has its own VarEnvironment;
  `var` does NOT hoist out, and never overwrites an outer binding).
  `var|let|const NAME='LIT';` binds locally (`const` without init and
  non-var+var redeclaration are node SyntaxErrors -- fail closed).
  Assignments target a block-local mutable binding or an env-bound
  mutable name (the F662 discipline). RHS may be a literal or a
  block-local/env string name (undefined RHS fails closed).
- F806: `_js_f672_parse_extends` accepts `extends MNAME(ARGNAME)`
  where MNAME is an ("fn", param, brace) mixin binding and ARGNAME
  is a cenv class or an anonymous `class{...}` expression; the
  mixin's body is parsed with the parameter bound to the argument's
  record (the F672 new-(M(B))() discipline). Plus a bare
  `function NAME(PARAM){return class extends PARAM{BODY};}`
  declaration production in `_js_f672_top_stmt` (mirrors the
  `var NAME=function...` form; no trailing `;`).

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
_FULL = _A + _B

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
def test_p0_pin_re_compile():
    """Zero new re.compile: count stays 28."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_pin_verifier_taxonomy():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    src = open(os.path.join(REPO_ROOT, "evals",
                            "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = 33" in src
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % ok)


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F805/F806 closed, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, "
              "F802, F803, F804, F807, F808, F809, F810, F811, F812, F813, "
              "F814, F815, F816, F817, F819, F820, F821, F822, F823, F824, "
              "F825, F826, F827, F828." in text
          and "# Wave-386 lane 6: F805, F806 CLOSED" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f805_s1():
    """F805 filed shape 1 (var in static block) blocks + decodes."""
    s = ("(function(){var r;class C{static{var x='" + _A
         + "';r=x;}}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "s1")


@_t
def test_p1_f805_s2():
    """F805 filed shape 2 (let in static block) blocks + decodes."""
    s = ("(function(){var r;class C{static{let x='" + _A
         + "';r=x;}}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "s2")


@_t
def test_p1_f806_s1():
    """F806 filed shape 1 (bare function mixin) blocks + decodes."""
    s = ("(function(){function M(Base){return class extends Base{m(){return '"
         + _A + "';}};}class B{}class C extends M(B){}return new C().m()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "s1")


@_t
def test_p1_f806_s2():
    """F806 filed shape 2 (var-function mixin, class{} arg) blocks."""
    s = ("(function(){var M=function(B){return class extends B{v(){return '"
         + _A + "';}};};class C extends M(class{}){}return new C().v()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "s2")


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f805_const_pluseq():
    """F805: const block-local + outer += name decodes."""
    s = ("(function(){var r='" + _A + "';class C{static{const x='"
         + _B + "';r+=x;}}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "const+=")


@_t
def test_p2_f805_let_pluseq_local():
    """F805: block-local let += literal then outer read decodes."""
    s = ("(function(){var r;class C{static{let x='" + _A
         + "';x+='" + _B + "';r=x;}}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "let+=local")


@_t
def test_p2_f805_reassign_local():
    """F805: reassignment of block-local var decodes."""
    s = ("(function(){var r;class C{static{var x='Q';x='" + _A
         + "';r=x;}}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "reassign")


@_t
def test_p2_f805_redeclare_noinit_keeps():
    """F805: bare `var x;` redeclare keeps the value (node) -- decodes."""
    s = ("(function(){var r;class C{static{var x='" + _A
         + "';var x;r=x;}}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "redeclare-noinit")


@_t
def test_p2_f805_two_statics():
    """F805: two static blocks, second appends outer."""
    s = ("(function(){var r;class C{static{var x='" + _A
         + "';r=x;}static{r+='" + _B + "';}}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "two-statics")


@_t
def test_p2_f805_outer_not_clobbered():
    """F805: block var does not overwrite outer binding (node).

    `var x='Q'` outside, `var x=_A` inside the static block: the block
    has its own VarEnvironment, so the outer x stays 'Q' and
    `return r+x` decodes to _A+'Q' (not _A+_A).
    """
    s = ("(function(){var x='Q';var r;class C{static{var x='" + _A
         + "';r=x;}}return r+x;})()")
    ok = _decodes_exact(s, _A + "Q")
    return ("HELD" if ok else "BREAK", "no-clobber")


@_t
def test_p2_f806_named_mixin_class():
    """F806: named class inside mixin body decodes."""
    s = ("(function(){function M(Base){return class K extends Base{m(){return '"
         + _A + "';}};}class B{}class C extends M(B){}return new C().m()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "named-mixin")


@_t
def test_p2_f806_decl_mixin_class_arg():
    """F806: bare function mixin with class{} argument decodes."""
    s = ("(function(){function M(B){return class extends B{v(){return '"
         + _A + "';}};}class C extends M(class{}){}return new C().v()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "decl-mixin-classarg")


@_t
def test_p2_f806_bare_fn_no_semi():
    """F806: bare mixin fn without trailing `;` (node ASI) decodes."""
    s = ("(function(){function M(B){return class extends B{v(){return '"
         + _A + "';}}}class C extends M(class{}){}return new C().v()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "bare-fn-no-semi")


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f805_const_no_init():
    """F805: const without init is a node SyntaxError -> miss."""
    s = "(function(){var r;class C{static{const x;r=x;}}return r;})()"
    return ("HELD" if _misses(s) else "BREAK", "const-noinit")


@_t
def test_p3_f805_redeclare():
    """F805: let+var redeclaration is a node SyntaxError -> miss."""
    s = ("(function(){var r;class C{static{let x='" + _A
         + "';var x='B';r=x;}}return r;})()")
    return ("HELD" if _misses(s) else "BREAK", "redeclare")


@_t
def test_p3_f805_const_target():
    """F805: assignment to block-local const throws -> miss."""
    s = ("(function(){var r;class C{static{const x='" + _A
         + "';x='B';r=x;}}return r;})()")
    return ("HELD" if _misses(s) else "BREAK", "const-target")


@_t
def test_p3_f805_uninit_rhs():
    """F805: name RHS bound to undefined -> miss (not 'undefined...')."""
    s = ("(function(){var r;class C{static{var x;r=x;}}return r+'" + _B
         + "';})()")
    return ("HELD" if _misses(s) else "BREAK", "uninit-rhs")


@_t
def test_p3_f805_unbound_target():
    """F805: assignment to unbound name throws -> miss."""
    s = ("(function(){var r;class C{static{q='" + _A
         + "';r=q;}}return r;})()")
    return ("HELD" if _misses(s) else "BREAK", "unbound")


@_t
def test_p3_f805_cross_block():
    """F805: block-local not visible in sibling static block -> miss."""
    s = ("(function(){var r;class C{static{var x='" + _A
         + "';}static{r=x;}}return r;})()")
    return ("HELD" if _misses(s) else "BREAK", "cross-block")


@_t
def test_p3_f806_non_fn():
    """F806: extends call on non-function throws -> miss."""
    s = "(function(){var M=5;class B{}class C extends M(B){}return 1;})()"
    return ("HELD" if _misses(s) else "BREAK", "non-fn")


@_t
def test_p3_f806_non_class_arg():
    """F806: mixin arg not a class -> miss."""
    s = ("(function(){function M(B){return class extends B{v(){return '"
         + _A + "';}};}class C extends M(Q){}return 1;})()")
    return ("HELD" if _misses(s) else "BREAK", "non-class-arg")


@_t
def test_p3_f806_mixin_not_param():
    """F806: mixin body not extending the param -> miss."""
    s = ("(function(){function M(B){return class extends Q{v(){return '"
         + _A + "';}};}class B{}class C extends M(B){}return 1;})()")
    return ("HELD" if _misses(s) else "BREAK", "not-param")


# ------------------------------------------------ p4: sibling pins (must still hold)


@_t
def test_p4_f662_static_block():
    """Sibling: F662 static-block literal assignment still decodes."""
    s = ("(function(){var r;class C{static{r='" + _A
         + "';}}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "f662")


@_t
def test_p4_f662_static_pluseq():
    """Sibling: F662 static-block += literal still decodes."""
    s = ("(function(){var r='" + _A + "';class C{static{r+='" + _B
         + "';}}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "f662+=")


@_t
def test_p4_f672_extends_ident():
    """Sibling: F672 plain extends-identifier still decodes."""
    s = ("(function(){class B{m(){return '" + _A
         + "';}}class D extends B{}return new D().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "f672-extends")


@_t
def test_p4_f672_mixin_new():
    """Sibling: F672 new (M(B))() mixin still decodes."""
    s = ("(function(){var M=function(S){return class extends S{m(){return '"
         + _A + "';}};};class B{}return new (M(B))().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _FULL)
    return ("HELD" if ok else "BREAK", "f672-mixin-new")


# ------------------------------------------------ p5: honest text (must stay quiet)


@_t
def test_p5_honest():
    """Honest code stays quiet."""
    honest = [
        "(function(){class C{static{var x='ab';}}return x;})()",
        "(function(){class B{}class C extends B{}return 1;})()",
        "(function(){function M(B){return 1;}return M(2);})()",
        "'just a string with class and static words'",
    ]
    bad = [h for h in honest if not _misses(h)]
    return ("HELD" if not bad else "BREAK", "honest=%d/%d" % (
        len(honest) - len(bad), len(honest)))


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in reasonable time."""
    sites = []
    for i in range(100):
        sites.append("(function(){var r;class C{static{var x%d='%s';r=x%d;}}return r+'%s';})()"
                     % (i, _A, i, _B))
    for i in range(100):
        sites.append("(function(){function M%d(B){return class extends B{v(){return '%s';}};}class C%d extends M%d(class{}){}return 1;})()"
                     % (i, _A, i, i))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The lane red-firsts expect 0 BREAK; w385_attack_probes.py expects
    # exactly 5 BREAK = the 4 F805/F806 open pins + its test_b0_footer_state
    # pin on the lane-local footer (wave-305 class; tree-wide repoint is
    # merge-owned). All functional probes must HELD.
    for batt, expect_break in (("evals/w386_f805_redfirst.py", 0),
                               ("evals/w386_f806_redfirst.py", 0),
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
    """Depth-1 green check: lane red-firsts + w385 attack battery."""
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
