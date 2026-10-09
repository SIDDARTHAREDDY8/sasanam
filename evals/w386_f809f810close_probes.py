#!/usr/bin/env python3
"""Wave-386 lane 8: close F809 + F810 (non-IIFE closure value flows; this-returning method chains).

F809 (LOW; filed 2026-10-09 by wave-385 attack round 53): non-IIFE
closure value flows -- the decoder is IIFE-scoped: Promise executor
bodies assigning outer vars and curried nested closures resolve
node-exactly while the decoder produces zero variants.

F810 (LOW; filed 2026-10-09 by wave-385 attack round 53): this-returning
method chains -- the decoder has no method-chain production: o.a().b()
where a returns this resolves node-exactly while the decoder produces
zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F809: `_js_parse_f809_executor_iife` models
  `(function(){DECL*;new Promise(function(P){STMT*;});return ADD;})()`
  -- the Promise constructor invokes its executor synchronously
  (node v24.20.0), so `NAME='LIT'` assignments to outer-declared
  vars take effect before the return; bare `P();` calls on the
  executor's own params are no-ops. `_js_parse_f809_curry_iife`
  models `(function(){function F(P1..Pn){return
  function(Q1..Qm){return ADD;};}return F(L1..Ln)(M1..Mm)[+...];})()`
  -- the inner ADD (F614 additive body over the combined param
  list) evaluates with both bindings via `_js_f556_apply`.
- F810: `_js_parse_f810_chain_iife` models
  `(function(){DECL o={k:function(){BODY},...};return ADD;})()` with
  >=1 >=2-call method-chain term. Each `.m()` step invokes the
  method with `this` bound to the current receiver props
  (updated in place by `this.M='L'` assignments); `return this`
  leaves the receiver unchanged; `return this.M` / `return 'L'`
  produce a string (further chaining throws in the engine --
  fail closed); a chain yielding the object itself fails closed.

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
    """Control: lane-local footer (F809/F810 closed, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, "
              "F802, F803, F804, F805, F806, F807, F808, F811, F812, "
              "F813, F814, F815, F816, F817, F819, F820, F821, F822, "
              "F823, F824, F825, F826, F827, F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f809_s1():
    """F809 filed shape 1 (Promise executor assignment) blocks + exact."""
    s = ("(function(){var r;new Promise(function(res){r='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f809_s2():
    """F809 filed shape 2 (curried nested closure) blocks + exact."""
    s = ("(function(){function f(a){return function(b){return a+b;};}"
         "return f('" + _A + "')('" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f810_s1():
    """F810 filed shape 1 (return-this chain) blocks + exact."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return '" + _A + "';}};return o.a().b()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f810_s2():
    """F810 filed shape 2 (this-assign chain) blocks + exact."""
    s = ("(function(){var o={a:function(){this.v='" + _A
         + "';return this;},b:function(){return this.v;}};"
         "return o.a().b()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_executor_let_multi():
    """let decl + two-param executor + two assignments, node-exact."""
    s = ("(function(){let r;let q;new Promise(function(res,rej){r='"
         + _A + "';q='" + _B + "';res();});return r+q;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_executor_init_overwrite():
    """Initialized decl overwritten by the executor, node-exact."""
    s = ("(function(){var r='zz';new Promise(function(res){r='"
         + _A + "';res();});return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_executor_zero_param():
    """Zero-param executor still runs synchronously, node-exact."""
    s = ("(function(){var r;new Promise(function(){r='" + _A
         + "';});return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_curry_2x2():
    """Two outer + two inner params, node-exact."""
    s = ("(function(){function f(a,c){return function(b,d){return a+b+c+d;};}"
         "return f('" + _A + "','x')('y','" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "yx" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_curry_zero_outer():
    """Zero-param outer function, node-exact."""
    s = ("(function(){function f(){return function(b){return '"
         + _A + "'+b;};}return f()('" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_curry_multi_term():
    """Two curry-call terms in one return additive, node-exact."""
    s = ("(function(){function f(a){return function(b){return a+b;};}"
         "return f('" + _A + "')('x')+f('y')('" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "xy" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_chain_3():
    """Three-method chain, node-exact."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return this;},c:function(){return '" + _A
         + "';}};return o.a().b().c()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_chain_assign_read():
    """Assign-then-read across the chain with a literal tail, node-exact."""
    s = ("(function(){var o={a:function(){this.v='" + _A
         + "';return this;},b:function(){return this.v+'" + _B
         + "';}};return o.a().b();})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_chain_data_prop():
    """Data prop on the receiver read through a chain, node-exact."""
    s = ("(function(){var o={v:'" + _A
         + "',a:function(){return this;},b:function(){return this.v;}};"
         "return o.a().b()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_executor_return():
    """return inside the executor fails closed."""
    s = ("(function(){var r;new Promise(function(res){r='" + _A
         + "';return 1;});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_undeclared_assign():
    """Assignment to an undeclared name fails closed."""
    s = ("(function(){var r;new Promise(function(res){q='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_uninit_read():
    """Reading an uninitialized var fails closed (engine: undefined)."""
    s = ("(function(){var r;var s;new Promise(function(res){r='" + _A
         + "';res();});return s+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_param_shadow():
    """Executor param shadowing a decl fails closed."""
    s = ("(function(){var r;new Promise(function(r){r='" + _A
         + "';});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_named():
    """Named executor fails closed."""
    s = ("(function(){var r;new Promise(function ex(res){r='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_generator():
    """Generator executor fails closed."""
    s = ("(function(){var r;new Promise(function*(res){r='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_curry_arity():
    """Curry arity mismatch fails closed (engine: undefined)."""
    s = ("(function(){function f(a,c){return function(b){return a+b+c;};}"
         "return f('" + _A + "')('" + _B + "');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_curry_shadow():
    """Inner param shadowing an outer param fails closed."""
    s = ("(function(){function f(a){return function(a){return a+'"
         + _A + "';};}return f('" + _B + "')('x');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_curry_extra_stmt():
    """Extra statement in the outer body fails closed."""
    s = ("(function(){function f(a){var x=1;return function(b){return a+b;};}"
         "return f('" + _A + "')('" + _B + "');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_literal_then_call():
    """Chaining after a literal-returning method throws in the engine: fail closed."""
    s = ("(function(){var o={a:function(){return '" + _A
         + "';},b:function(){return '" + _B + "';}};return o.a().b();})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_unknown_method():
    """Unknown method in the chain fails closed (engine throws)."""
    s = ("(function(){var o={a:function(){return this;}};"
         "return o.a().zz()+'" + _A + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_method_params():
    """Method with params fails closed."""
    s = ("(function(){var o={a:function(x){return this;},"
         "b:function(){return '" + _A + "';}};return o.a().b()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_bracket():
    """Bracket-string member form fails closed (narrow: dot form only)."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return '" + _A + "';}};return o['a']().b()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_optional():
    """Optional chaining fails closed (narrow: dot form only)."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return '" + _A + "';}};return o?.a().b()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_obj_yield():
    """Chain yielding the object itself fails closed (engine: [object Object])."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return this;}};return o.a().b()+'" + _A + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_unset_read():
    """Reading a never-set member fails closed (engine: undefined)."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return this.v;}};return o.a().b()+'" + _A + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_const_reassign():
    """Executor reassigning a const fails closed (engine: rejected promise, init kept)."""
    s = ("(function(){const r='init';new Promise(function(res){r='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_executor_const_noinit():
    """const without initializer fails closed (engine: SyntaxError)."""
    s = ("(function(){const r;new Promise(function(res){r='" + _A
         + "';res();});return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p2_executor_const_read():
    """const with initializer and no reassignment decodes node-exactly."""
    s = ("(function(){const r='" + _A
         + "';new Promise(function(res){res();});return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p3_chain_proto_assign():
    """this.__proto__ assignment fails closed (engine silently ignores it)."""
    s = ("(function(){var o={a:function(){this.__proto__='" + _A
         + "';return this;},b:function(){return this.__proto__;}};"
         "return o.a().b()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_chain_getter():
    """Getter property fails closed."""
    s = ("(function(){var o={get a(){return this;},"
         "b:function(){return '" + _A + "';}};return o.a().b()+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must stay HELD)


@_t
def test_p4_sib_f614():
    """F614 (function-expression dispatch) still blocks."""
    s = "((a,b)=>a+b).apply(null,['" + _A + "','" + _B + "'])"
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "sibling=%s" % ok)


@_t
def test_p4_sib_f618():
    """F618 (Promise.all().then()) still blocks."""
    s = ("Promise.all([Promise.resolve('" + _A + "'),Promise.resolve('"
         + _B + "')]).then(a=>a.join(''))")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "sibling=%s" % ok)


@_t
def test_p4_sib_f753():
    """F753 (spread call) still blocks."""
    s = ("(function(){function h(a,b){return a+b;}return h(...['" + _A
         + "','" + _B + "']);})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "sibling=%s" % ok)


@_t
def test_p4_sib_f782():
    """F782 (thisArg dispatch) still blocks."""
    s = ("(function(){function f(){return this.x;}return f.call({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "sibling=%s" % ok)


@_t
def test_p4_sib_single_call():
    """F810 single-call twin still blocks via its existing route."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return '" + _A + "';}};return o.b()+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "sibling=%s" % ok)


# ------------------------------------------------ p5: honest text (must stay quiet)


@_t
def test_p5_honest_plain():
    """Plain text stays quiet."""
    ok = _misses("'just some harmless text with no code at all'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_iife():
    """Benign IIFE stays quiet."""
    ok = _misses("(function(){var s='hello';return s+' world';})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_promise():
    """Benign Promise executor with no credential stays quiet."""
    s = ("(function(){var r='ok';new Promise(function(res){res();});"
         "return r+'!';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_chain():
    """Benign method chain with no credential stays quiet."""
    s = ("(function(){var o={a:function(){return this;},"
         "b:function(){return 'xy';}};return o.a().b()+'!';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in reasonable time."""
    sites = []
    for k in range(50):
        sites.append("(function(){var r;new Promise(function(res){r='a"
                     + str(k) + "';res();});return r+'b';})()")
        sites.append("(function(){function f(a){return function(b){return a+b;};}"
                     "return f('a" + str(k) + "')('b');})()")
        sites.append("(function(){var o={a:function(){return this;},"
                     "b:function(){return 'a" + str(k)
                     + "';}};return o.a().b()+'b';})()")
        sites.append("(function(){var s='plain" + str(k) + "';return s;})()")
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Both red-firsts must be 0 BREAK (F809/F810 closed); the
    # wave-385 attack battery is expected to be fully green: this
    # lane flipped the F809/F810 pins to _closed and repointed its
    # lane-local footer (wave-305/306 class, lane-owned).
    for batt, expect_break in (("evals/w385_f809_redfirst.py", 0),
                               ("evals/w385_f810_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 0)):
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
    """Depth-1 green check: red-firsts 0 BREAK + w385 attack battery green."""
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
