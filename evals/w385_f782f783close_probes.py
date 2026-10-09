#!/usr/bin/env python3
"""Wave-385 lane 11: close F782 + F783.

F782 (LOW, filed 2026-10-09 by wave-384 attack round 52): F614
(CLOSED, wave-374) models call/apply/bind on function-expression
receivers with literal args but discards the thisArg (its bodies
never reference `this`); a named function declaration whose body
reads `this.MEM`, invoked via `NAME.call(TA)` / `NAME.apply(TA)` /
`NAME.bind(TA)()` / a var-bound `g=NAME.bind(TA)` then `g()`,
binds `this` node-exactly while the decoder produced zero
variants.

F783 (LOW, filed 2026-10-09 by wave-384 attack round 52): the
decoder has no super-dispatch production; `class C extends B`
with `super.m()` dispatches to the parent method node-exactly
while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F782: _js_parse_f782_thisarg_iife (+ _js_parse_f782_thisarg_obj,
  _js_parse_f782_dispatch_member, _js_parse_f782_this_return,
  _js_parse_f782_dispatch_value), hooked after F757 with the
  parts/ops snapshot-restore discipline (wave-383 F733 lesson).
  The declared function takes no params and returns
  `this.MEM[+'lit'*]`; the thisArg is an object literal with
  plain-string-literal values carrying MEM (getters, methods,
  __proto__, non-literal values fail closed -- documented
  fail-safe residuals); dispatches are `.call(TA)` (no extra
  args), `.apply(TA[,[]])`, `.bind(TA)()` (immediate invocation
  required), and the var-bound twin `g()`; the return is a
  string-literal/dispatch additive with >=1 dispatch term.
- F783: _js_parse_f783_super_iife (+ _js_parse_f783_str_additive,
  _js_parse_f783_method, _js_parse_f783_class), hooked after
  F782. Classes declare string-additive methods and/or
  `super.m()` / `super['m']()` dispatch methods; constructors,
  getters/setters, statics, fields, and computed members fail
  closed. Super dispatch resolves along the home-object
  prototype chain node-exactly (multi-hop chains walk per call
  site); missing methods fail closed (the engine throws
  TypeError there -- never decode a throw).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

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
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F782/F783 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-385 lane 11: F782, F783 CLOSED
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f782_s1():
    """F782 filed shape 1 (f.call thisArg) blocks + decodes node-exact."""
    s = ("(function(){function f(){return this.x;}return f.call({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f782_s2():
    """F782 filed shape 2 (var-bound f.bind thisArg) blocks + exact."""
    s = ("(function(){function f(){return this.x;}var g=f.bind({x:'"
         + _A + "'});return g()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f783_s1():
    """F783 filed shape 1 (super.m dispatch) blocks + decodes node-exact."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f783_s2():
    """F783 filed shape 2 (super['m'] dispatch) blocks + exact."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{m(){return super['m']();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f782_apply():
    """F782 f.apply(thisArg) twin blocks + exact."""
    s = ("(function(){function f(){return this.x;}return f.apply({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f782_apply_empty():
    """F782 f.apply(thisArg, []) twin blocks + exact."""
    s = ("(function(){function f(){return this.x;}return f.apply({x:'"
         + _A + "'},[])+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f782_bind_direct():
    """F782 f.bind(thisArg)() direct twin blocks + exact."""
    s = ("(function(){function f(){return this.x;}return f.bind({x:'"
         + _A + "'})()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f782_body_additive():
    """F782 additive function body (this.x+'-a') blocks + exact."""
    s = ("(function(){function f(){return this.x+'-a';}return f.call({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "-a" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f782_bracket_twins():
    """F782 this['x'] + f['call'] bracket twins block + exact."""
    s = ("(function(){function f(){return this['x'];}return f['call']({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f782_multi_dispatch():
    """F782 two dispatch terms in one additive block + exact."""
    s = ("(function(){function f(){return this.x;}return f.call({x:'"
         + _A + "'})+f.apply({x:'" + _B + "'});})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f783_plain_method():
    """F783 plain (non-super) class method twin blocks + exact."""
    s = ("(function(){class C{m(){return '" + _A + "';}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f783_additive_body():
    """F783 additive parent method body blocks + exact."""
    s = ("(function(){class B{m(){return '" + _A + "'+'xx';}}"
         "class C extends B{m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "xx" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f783_chain():
    """F783 two-hop super chain (C->B->A) blocks + exact."""
    s = ("(function(){class A{m(){return '" + _A + "';}}"
         "class B extends A{m(){return super.m();}}"
         "class C extends B{m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f783_diff_names():
    """F783 super dispatch to a differently-named parent method."""
    s = ("(function(){class B{p(){return '" + _A + "';}}"
         "class C extends B{m(){return super.p();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f782_arrow_ignores_thisarg():
    """F782 arrow function ignores thisArg (node: undefined) -> closed."""
    s = ("(function(){var f=()=>this.x;return f.call({x:'" + _A
         + "'})+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_null_thisarg():
    """F782 null thisArg (node: globalThis -> undefined) -> closed."""
    s = ("(function(){function f(){return this.x;}return f.call(null)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_missing_key():
    """F782 thisArg missing the read key (node: undefined) -> closed."""
    s = ("(function(){function f(){return this.x;}return f.call({y:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_getter_thisarg():
    """F782 getter thisArg (engine WOULD read it) -> closed (fail-safe residual)."""
    s = ("(function(){function f(){return this.x;}return f.call({get x(){return '"
         + _A + "';}})+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_nonliteral_value():
    """F782 non-literal thisArg value -> closed."""
    s = ("(function(){function f(){return this.x;}return f.call({x:123})+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_params():
    """F782 function with params -> closed (documented boundary)."""
    s = ("(function(){function f(a){return this.x;}return f.call({x:'"
         + _A + "'})+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_proto_key():
    """F782 __proto__ thisArg key -> closed (fail-safe residual)."""
    s = ("(function(){function f(){return this.x;}return f.call({__proto__:{x:'"
         + _A + "'}})+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f782_bind_no_call():
    """F782 bound-but-never-invoked function -> closed."""
    s = ("(function(){function f(){return this.x;}var g=f.bind({x:'"
         + _A + "'});return '" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_constructor():
    """F783 class with a constructor -> closed (documented boundary)."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{constructor(){super();}m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_missing_parent():
    """F783 super dispatch to a missing parent method (node throws) -> closed."""
    s = ("(function(){class B{q(){return '" + _A + "';}}"
         "class C extends B{m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_super_prop():
    """F783 non-call super member read -> closed."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{m(){return super.m;}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_new_args():
    """F783 new C(args) with construction args -> closed (documented)."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{m(){return super.m();}}"
         "return new C('x').m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_getter():
    """F783 getter method (node throws TypeError) -> closed."""
    s = ("(function(){class B{m(){return '" + _A + "';}}"
         "class C extends B{get m(){return super.m();}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f783_fwd_ref():
    """F783 forward-referenced superclass (node throws ReferenceError) -> closed."""
    s = ("(function(){class C extends B{m(){return super.m();}}"
         "class B{m(){return '" + _A + "';}}"
         "return new C().m()+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f757():
    """F757 new.target pin still blocks."""
    s = ("(function(){function C(){this.x=new.target===C?'" + _A
         + "':'z';}return new C().x+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f757=%s" % ok)


@_t
def test_p4_sibling_f668():
    """F668 tag-function pin still blocks (real filed shape)."""
    s = ("(function(){function tag(s){return s[0]+'" + _B + "';}return tag`"
         + _A + "`;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f668=%s" % ok)


@_t
def test_p4_sibling_f619():
    """F619 generator pin still blocks (real filed shape)."""
    s = ("(function(){function* g(){yield '" + _A + "';yield '" + _B
         + "';}return [...g()].join('');})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f619=%s" % ok)


@_t
def test_p4_neighbor_f784_open():
    """Neighbor F784 (still OPEN) still misses -- honest open shape."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1)break lbl;r+='xx';}"
         "return r+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f784-open=%s" % ok)


@_t
def test_p4_preexisting_inherit():
    """Pre-existing: inherited-without-override class read decodes on
    base and lane identically (F662/F672 family, not this lane)."""
    s = ("(function(){class B{m(){return '" + _A + "';}}class C extends B{}"
         "return new C().m()+'" + _B + "';})()")
    got = dlp._try_js_expr_decode_all(s)
    ok = got is not None and (_A + _B) in got
    return ("HELD" if ok else "BREAK", "preexisting=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_call_unaffected():
    """Honest .call with literal args and no this-read still misses."""
    s = "(function(){function f(a){return a;}return f.call(null,'xy');})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_class_unaffected():
    """Honest class without credential still misses."""
    s = "(function(){class C{m(){return 'ab';}}return new C().m();})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){function f(){return this.x;}return f.call({x:'a%d'})+'b';})()" % k)
        sites.append(
            "(function(){class B{m(){return 'a%d';}}class C extends B{m(){return super.m();}}return new C().m()+'b';})()" % k)
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
    # w384_attack_probes.py expects 1 BREAK: its test_b0_footer_state
    # asserts the base footer (open F762-F794); the lane-local repoint
    # (F782/F783 closed) moves it. The tree-wide footer repoint is
    # merge-owned (wave-305 lesson); all functional probes must HELD.
    for batt, expect_break in (("evals/w384_f782_redfirst.py", 0),
                               ("evals/w384_f783_redfirst.py", 0),
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
    """Depth-1 green check: F782/F783 red-firsts (0 BREAK) + wave-384
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
