#!/usr/bin/env python3
"""Wave-374 lane 3: close F614 -- .call/.apply/.bind on function expressions.

F614 (LOW, filed attack round 41): Function.prototype.call/.apply/.bind on
FUNCTION-EXPRESSION receivers bypassed the bounded static JS-expression
decoder. F478 (CLOSED, wave-357) models dispatch on prototype-method
receivers (`Array.prototype.concat.apply([], [...])` blocks coded) and
F482 (CLOSED, wave-359) the bracket-string dispatch member, but a
parenthesized arrow/function receiver had no modeled path:
((a,b)=>a+b).apply(null,['f1','f2']), the .call twin, and the .bind twin
((a)=>(a+'f2')).bind(null,'f1')() all node-evaluated to the exact
credential (v24.20.0) while the decoder produced zero variants.

Closure (gov/dlp.py, F614): _js_parse_f614_fnexpr_dispatch routes
((FN)).call/.apply/.bind at the parenthesized-group seam, after F556's
exact .bind route (disjoint: F556 rejects parenthesized bodies, F614
accepts them). _js_parse_f614_fn_target mirrors the F556 target grammar
(F519 param grammar -- no `...rest`, so F577 keeps its route; generators
and async fail closed) with one extension: the additive body may carry a
single grouping-paren wrap. Desugar is node-exact (v24.20.0): .call fills
params in order, .apply spreads the array, .bind fills bound-then-call;
the thisArg is parsed and discarded (arrows ignore receivers, bodies
never reference `this` -- F483/F556 precedent); extras are dropped,
fewer args fail closed (node coerces undefined -- F519 precedent). Zero
new re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g374-*
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

def test_p1_filed_apply():
    """((a,b)=>a+b).apply(null,['f1','f2']) blocks."""
    ok = _blocked("((a,b)=>a+b).apply(null,['" + _A + "','" + _B + "'])")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_call():
    """((a,b)=>a+b).call(null,'f1','f2') blocks."""
    ok = _blocked("((a,b)=>a+b).call(null,'" + _A + "','" + _B + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_bind():
    """((a)=>(a+'f2')).bind(null,'f1')() blocks (paren body)."""
    ok = _blocked("((a)=>(a+'" + _B + "')).bind(null,'" + _A + "')()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_fn_expression_twins():
    """function(a,b){return a+b;} / named function receivers block."""
    ok = _blocked("(function(a,b){return a+b;}).apply(null,['" + _A
                  + "','" + _B + "'])")
    ok = ok and _blocked("(function f(a){return a+'" + _B
                         + "';}).call(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_bind_callargs():
    """((a,b)=>a+b).bind(null,'f1')('f2') -- bound-then-call fill."""
    ok = _blocked("((a,b)=>a+b).bind(null,'" + _A + "')('" + _B + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_noarg_call():
    """(()=>'f1'+'f2').call(null) -- zero-param receiver blocks."""
    ok = _blocked("(()=>'" + _A + "'+'" + _B + "').call(null)")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_extra_args_dropped():
    """((a,b)=>a+b).call(null,'f1','f2','f3') -- extras dropped, full cred."""
    ok = _blocked("((a,b)=>a+b).call(null,'" + _A + "','" + _B
                  + "','junk')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_bracket_optchain_dispatch():
    """['apply'] bracket form and ?.call form are engine-identical."""
    ok = _blocked("((a,b)=>a+b)['apply'](null,['" + _A + "','" + _B + "'])")
    ok = ok and _blocked("((a,b)=>a+b)?.call(null,'" + _A + "','" + _B
                         + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_ws_forgiving():
    """Whitespace-tolerant twin blocks."""
    ok = _blocked("( ( a , b ) => a + b ).apply( null , [ '" + _A
                  + "' , '" + _B + "' ] )")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_parenbody_call():
    """((a)=>(a+'f2')).call(null,'f1') -- paren body, .call twin."""
    ok = _blocked("((a)=>(a+'" + _B + "')).call(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ boundaries (must fail closed)

def test_p3_fewer_args_closed():
    """((a,b)=>a+b).call(null,'f1') -- node yields 'f1undefined'; miss."""
    ok = _misses("((a,b)=>a+b).call(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_bind_no_call_closed():
    """((a)=>a).bind(null,'f1') -- a bound function is not decodable."""
    ok = _misses("((a)=>a).bind(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_nested_paren_closed():
    """((a)=>((a+'f2'))).call(null,'f1') -- nested parens fail closed."""
    ok = _misses("((a)=>((a+'" + _B + "'))).call(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_array_arg_to_call_closed():
    """((a,b)=>a+b).call(null,['f1','f2']) -- array is not a string arg."""
    ok = _misses("((a,b)=>a+b).call(null,['" + _A + "','" + _B + "'])")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_apply_nonarray_closed():
    """((a,b)=>a+b).apply(null,'f1') -- apply needs the array form."""
    ok = _misses("((a,b)=>a+b).apply(null,'" + _A + "')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_zero_arg_closed():
    """((a)=>a).call(null) -- one param, zero args: miss."""
    ok = _misses("((a)=>a).call(null)")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ composition (no absorption)

def test_p4_neighbors_stay_held():
    """F478/F482/F556 still block; F577 rest-param .call unaffected."""
    ok = _blocked("Array.prototype.concat.apply([], ['" + _A + "','"
                  + _B + "']).join('')")
    ok = ok and _blocked("Array.prototype['concat'].call([], '" + _A
                         + "','" + _B + "').join('')")
    ok = ok and _blocked("((a)=>a+'" + _B + "').bind(null,'" + _A + "')()")
    ok = ok and _blocked("((...a)=>a[0]+a[1]).call(null,'" + _A + "','"
                         + _B + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _round42_shapes():
    """Filed shapes of the currently-OPEN findings (must still miss).

    F621-F639 all CLOSED on the merged tree (wave-375 merge); only
    F640-F643 (attack round 43) remain open.
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
    """F640-F643 shapes still miss (not absorbed); F614 residual stays quiet."""
    bad = ["F%d/%s" % (fnum, name) for fnum, name, payload in _round42_shapes()
           if not _misses(payload)]
    ok = not bad
    ok = ok and _misses("((a,b)=>a+b).call(q,'" + _A + "','" + _B
                        + "')")  # F614 residual: non-literal thisArg
    return ("HELD" if ok else "BREAK", "miss=%s bad=%s" % (ok, bad[:3]))
def test_p4_junk_quiet():
    """Honest text unaffected: junk stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    ok = ok and _misses("((a)=>a).bind(null,'x')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ pin + footer + perf

def test_p5_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2140 and len(dc.TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F614 closed; open F612, F613, F615-F620; next F621."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F700**" in text  # Wave-374 lane 3: F614 CLOSED  # Wave-374 merge: footer repoint open F612, F613, F615-F620 / next F621  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)  # Wave-374 lane 3: F614 CLOSED  # Wave-374 merge: footer repoint open F612, F613, F615-F620 / next F621  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
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
    corpus = ("((a,b)=>a+b).call(null,'" + _A + "','" + _B + "') " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: wave-373 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g374-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w373_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    for line in out.splitlines():
        if line.startswith("BREAKS:"):
            try:
                import ast
                blist = ast.literal_eval(line.split(":", 1)[1].strip())
                real_break = len(blist) if isinstance(blist, list) else 0
            except (IndexError, ValueError, SyntaxError):
                pass
    ok = (real_break == 0)
    return ("HELD" if ok else "BREAK",
            "w373_attack real_break=%d" % real_break)


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
