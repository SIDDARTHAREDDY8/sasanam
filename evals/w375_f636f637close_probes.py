#!/usr/bin/env python3
"""Wave-375 lane 7: close F636, F637 -- bind-chain family.

F636 (LOW, filed wave-374 merge, merge-time re-verification of lane 3's
F614 closure): bind-on-bound-function chains bypassed the bounded static
JS-expression decoder. F614 (CLOSED, wave-374 lane 3) models a single
.call/.apply/.bind on a function-expression receiver, but a second
.dispatch on the already-bound function escaped:
((a)=>(a+'f2')).bind(null,'f1').bind(null)() and
((a,b)=>a+b).bind(null,'f1').apply(null,['f2']) both node-evaluated to
the exact credential (v24.20.0) while the decoder produced zero
variants.

F637 (LOW, filed wave-374 merge, merge-time re-verification of lanes
3/7): .bind on indexed thunks (the F614 x F620 composition) bypassed
the decoder. F614 requires a bare function-expression receiver and
F620 (CLOSED, wave-374 lane 7) models direct f[INT]() invocation of
zero-arg literal thunks, but .bind applied to an indexed thunk
element then invoked escaped both:
(function(){var f=[()=>'f1',()=>'f2'];var g=f[0].bind(null);
return g()+f[1]();})() and
(function(){var f=[(a)=>a+'f2'];return f[0].bind(null,'f1')();})().

Closure (gov/dlp.py):
- F636: _js_parse_f636_bind_chain routes ((FN)) at the
  parenthesized-group seam after F614 (disjoint: F614's bind branch
  requires immediate invocation parens; the chained shapes do not
  have them). Node-exact (v24.20.0): a .bind on a bound function
  concatenates the bound arg lists; the chain terminates in an
  immediate invocation paren, a .call, or an .apply dispatch, whose
  args fill the remaining params in order (F556 arity precedent:
  extras dropped, fewer args than params fail closed). The first
  dispatch must be .bind (.call/.apply invoke immediately, so their
  result cannot start a chain); exactly one second dispatch; 3+
  chains fail closed (documented residual).
- F637: _js_parse_f637_thunk_bind_iife routes
  (function(){var|const|let f=[ELEM,...];
  [var|const|let g=f[INT].bind(BT, lit, ...);]*
  return EXPR;})() after F620 (disjoint: parameterized elements fail
  F620's zero-arg literal thunk array; a second decl or a .bind
  member fails the index-IIFE's exact return shape). Each element is
  an arrow parsed by _js_parse_f614_fn_target (zero-arg literal
  thunks are the params=[] special case). EXPR is a + chain of
  f[INT]() (zero-arg elements only), f[INT].bind(BT, lit,
  ...)(lit, ...) (immediate invocation), or g()/g(lit, ...)
  (bound-thunk binding). Node-exact arity; thisArgs parsed and
  discarded (F614/F483 precedent). Zero new re.compile
  (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g375-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_f636_filed_bind_bind():
    """((a)=>(a+'f2')).bind(null,'f1').bind(null)() blocks."""
    ok = _blocked("((a)=>(a+'" + _B + "')).bind(null,'" + _A
                  + "').bind(null)()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_f636_filed_bind_apply():
    """((a,b)=>a+b).bind(null,'f1').apply(null,['f2']) blocks."""
    ok = _blocked("((a,b)=>a+b).bind(null,'" + _A + "').apply(null,['"
                  + _B + "'])")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _f637_shape1():
    return ("(function(){var f=[()=>'F0',()=>'F1'];"
            "var g=f[0].bind(null);return g()+f[1]();})()").replace(
                "F0", _A).replace("F1", _B)


def _f637_shape2():
    return ("(function(){var f=[(a)=>a+'F1'];"
            "return f[0].bind(null,'F0')();})()").replace(
                "F0", _A).replace("F1", _B)


def test_p1_f637_filed_shapes():
    """Both F637 filed shapes block."""
    ok = _blocked(_f637_shape1()) and _blocked(_f637_shape2())
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_f636_bind_call_twin():
    """((a,b)=>a+b).bind(null,'f1').call(null,'f2') -- engine-identical."""
    ok = _blocked("((a,b)=>a+b).bind(null,'" + _A + "').call(null,'"
                  + _B + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f636_bind_bind_callargs():
    """((a,b)=>a+b).bind(null,'f1').bind(null)('f2') -- callargs fill."""
    ok = _blocked("((a,b)=>a+b).bind(null,'" + _A + "').bind(null)('"
                  + _B + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f636_dispatch_twins():
    """['bind'] bracket form and ?.bind form are engine-identical."""
    ok = _blocked("((a)=>(a+'" + _B + "'))['bind'](null,'" + _A
                  + "')['bind'](null)()")
    ok = ok and _blocked("((a)=>(a+'" + _B + "'))?.bind(null,'" + _A
                         + "')?.bind(null)()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f636_fn_expression():
    """function(a){return a+'f2'} receiver -- fn-expr twin blocks."""
    ok = _blocked("(function(a){return a+'" + _B + "';}).bind(null,'"
                  + _A + "').bind(null)()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f636_ws_forgiving():
    """Whitespace-tolerant chain blocks."""
    ok = _blocked("((a)=>(a+'" + _B + "')) . bind( null , '" + _A
                  + "' ) . bind( null ) ( )")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f637_mixed_elements():
    """Zero-arg + parameterized elements, const/let decls block."""
    p = ("(function(){const f=[()=>'F0',(a)=>a+'F1'];"
         "let g=f[1].bind(null,'F0');return f[0]()+g();})()").replace(
             "F0", _A).replace("F1", _B)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f637_two_bindings():
    """Two bound-thunk bindings in one IIFE block."""
    p = ("(function(){var f=[(a)=>a+'F1'];var g=f[0].bind(null,'F0');"
         "var h=f[0].bind(null);return g()+h('F0');})()").replace(
             "F0", _A).replace("F1", _B)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f637_bind_callargs():
    """f[0].bind(null,'f1')('f2') -- bound-then-call fill blocks."""
    p = ("(function(){var f=[(a,b)=>a+b];"
         "return f[0].bind(null,'F0')('F1');})()").replace(
             "F0", _A).replace("F1", _B)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_f637_extra_args_dropped():
    """Extras beyond the params are dropped engine-exactly."""
    p = ("(function(){var f=[()=>'F0F1'];"
         "return f[0].bind(null,'junk')();})()").replace(
             "F0", _A).replace("F1", _B)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ boundaries (must fail closed)

def test_p3_f636_three_chain_closed():
    """3+ dispatch chains fail closed (documented residual)."""
    ok = _misses("((a)=>(a+'" + _B + "')).bind(null,'" + _A
                 + "').bind(null).bind(null)()")
    ok = ok and _misses("((a,b,c)=>a+b+c).bind(null,'" + _A + "').bind("
                        "null,'" + _A + "').apply(null,['" + _B + "'])")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f636_nonliteral_thisarg_closed():
    """A non-literal thisArg fails closed."""
    ok = _misses("((a)=>(a+'" + _B + "')).bind(x,'" + _A
                 + "').bind(null)()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f636_nonliteral_arg_closed():
    """A non-literal bound arg fails closed."""
    ok = _misses("((a)=>(a+'x')).bind(null,x).bind(null)()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f636_arity_closed():
    """Fewer args than params fails closed (node: undefined slots)."""
    ok = _misses("((a,b)=>a+b).bind(null,'" + _A + "').bind(null)()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_oob_index_closed():
    """Out-of-range index fails closed (engine throws)."""
    p = ("(function(){var f=[()=>'F0'];return f[1]();})()").replace(
        "F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_undeclared_closed():
    """Use of an undeclared binding name fails closed."""
    p = ("(function(){var f=[()=>'F0'];return g();})()").replace(
        "F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_rebind_alias_closed():
    """Rebinding the array alias fails closed."""
    p = ("(function(){var f=[()=>'F0'];var f=f[0].bind(null);"
         "return f();})()").replace("F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_nonliteral_arg_closed():
    """A non-literal bind arg fails closed."""
    ok = _misses("(function(){var f=[(a)=>a+'x'];"
                 "return f[0].bind(null,x)();})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_arity_closed():
    """Bind with fewer args than params fails closed."""
    p = ("(function(){var f=[(a,b)=>a+b];"
         "return f[0].bind(null,'F0')();})()").replace("F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_direct_param_closed():
    """Direct f[INT]() on a parameterized element fails closed."""
    ok = _misses("(function(){var f=[(a)=>a+'x'];return f[0]();})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_noinvoke_closed():
    """A bound element with no invocation is not decodable."""
    p = ("(function(){var f=[(a)=>a+'x'];var g=f[0].bind(null,'F0');"
         "return g;})()").replace("F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_funcexpr_elem_closed():
    """function-expression elements fail closed (arrow-only scope)."""
    p = ("(function(){var f=[function(){return 'F0'}];"
         "return f[0]();})()").replace("F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f637_nonbind_member_closed():
    """.call on an indexed thunk is not the F637 shape."""
    p = ("(function(){var f=[(a)=>a+'x'];"
         "return f[0].call(null,'F0');})()").replace("F0", _A)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ composition (no absorption)

def test_p4_neighbors_stay_held():
    """F614/F620/F478/F482/F556 controls still block; F636/F637 disjoint."""
    ok = _blocked("((a)=>(a+'" + _B + "')).bind(null,'" + _A + "')()")
    ok = ok and _blocked(
        "(function(){var f=[()=>'F0',()=>'F1'];"
        "return f[0]()+f[1]();})()".replace("F0", _A).replace("F1", _B))
    ok = ok and _blocked("Array.prototype.concat.apply([], ['" + _A
                         + "','" + _B + "']).join('')")
    ok = ok and _blocked("((a)=>a+'" + _B + "').bind(null,'" + _A
                         + "')()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _open_shapes():
    """Filed shapes of the currently-OPEN findings (must still miss).

    F640-F643 (attack round 43). F621-F639 are all CLOSED on the merged
    tree (wave-375 merge); their shapes now block.
    """
    import importlib
    shapes = []
    for fnum in (640, 641, 642, 643):
        mod = importlib.import_module("w375_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append((fnum, name, payload))
    return shapes
def test_p4_open_neighbors_still_miss():
    """F621-F635, F638, F639 shapes still miss (not absorbed)."""
    bad = ["F%d/%s" % (fnum, name)
           for fnum, name, payload in _open_shapes()
           if not _misses(payload)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "miss=%s bad=%s" % (ok, bad[:3]))


def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    ok = ok and _misses("((a)=>a).bind(null,'x').bind(null)()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F636, F637 closed; open F621-F635, F638, F639; next F640."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F655**" in text  # Wave-375 lane 7: F636, F637 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
          and "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." in text)  # Wave-375 lane 7: F636, F637 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


def test_p5_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


def test_p5_perf_corpus():
    """Dispatch sites do not blow the scan budget (F452 discipline)."""
    corpus = ("((a)=>(a+'" + _B + "')).bind(null,'" + _A
              + "').bind(null)() " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: F614 + F620 close batteries, GOV_SKIP_GREEN=1.

    The only tolerated BREAK is the footer-state probe: my FINDINGS.md
    update closed F636/F637, so the two batteries' pinned footers are
    stale until the wave-375 merge's tree-wide repoint (wave-305/306
    class, merge-owned). Any other BREAK is a real regression.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    ok_all = True
    notes = []
    for name in ("w374_f614close_probes.py", "w374_f620close_probes.py"):
        tmp = tempfile.mkdtemp(prefix="g375-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", name)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        bad = [ln for ln in out.splitlines()
               if " BREAK " in (" " + ln + " ")
               and not ln.startswith("test_p5_footer_state")
               and not ln.startswith("tally:")]
        good = not bad
        ok_all = ok_all and good
        notes.append("%s=bad%d" % (name, len(bad)))
    return ("HELD" if ok_all else "BREAK", ",".join(notes))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
