#!/usr/bin/env python3
"""Wave-376 lane 3: close F642 -- getter bodies with var-bound fragment operands.

F642 (LOW, filed attack round 43, 2026-10-08, local node validation +
2 gpt-4o-mini calls, hints only): getter bodies with var-bound fragment
operands bypassed the bounded static JS-expression decoder. The decoder
models object-literal getters whose bodies concatenate LITERALS (F535,
expression-level -- control blocks), but when the additive operands are
var-bound identifiers the getter body was invisible:
(function(){var a='f1',b='f2',c='f3';var o={get s(){return a+b+c;}};return o.s;})(),
the Proxy get-trap twin
(function(){var a='f1',b='f2',c='f3';var p=new Proxy({},{get:(t,k)=>a+b+c});return p.anything;})(),
and the WeakRef-deref twin
(function(){var a='f1',b='f2',c='f3';var w=new WeakRef({get s(){return a+b+c;}});return w.deref().s;})()
all node-evaluated to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F542 (Proxy apply-traps) and F550
(defineProperty getters); the minimal mechanism is the getter body,
the Proxy/WeakRef are wrappers.

Closure (gov/dlp.py, F642): _js_parse_f642_getter_varbound_iife parses
`(function(){[DECL X='LIT'(,X='LIT')*;]+WRAPPER;TERM})()` -- a binding
section (F616-style: var|const|let, comma-separated declarators,
string-literal RHS only; duplicate var rebinds last-wins,
duplicate let/const fails closed), one wrapper (object-literal getter
/ Proxy get-trap / WeakRef getter object), and a matching terminal
(`return o.s;` / `return p.M;` / `return w.deref().s;`). The getter/trap
body ADD resolves bound idents against the bindings node-exactly;
unbound idents, `this`, computed heads, setters, method shorthand,
block-body traps, terminal mismatches, and extra statements all fail
closed. Hooked after F639 (disjoint: earlier routes require
URLSearchParams/URL/enumeration/defineProperty bindings; F611 a
single decl + direct return; the all-literal getter keeps the F535
route). Zero new re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g376-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
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
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B
_CRED = _F1 + _F2 + _F3


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F642 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f642_getter_varbound_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001
        verdict, note = "BREAK", "ERROR %r" % e
    results.append((name, verdict, note))
    print("%-42s %s (%s)" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_getter():
    """Filed shape 1: plain getter, var-bound operands (exact + hit)."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o.s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "filed-getter")


def test_p1_filed_proxy():
    """Filed shape 2: Proxy get-trap twin (exact + hit)."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var p=new Proxy({},{get:(t,k)=>a+b+c});return p.anything;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "filed-proxy")


def test_p1_filed_weakref():
    """Filed shape 3: WeakRef-deref twin (exact + hit)."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var w=new WeakRef({get s(){return a+b+c;}});return w.deref().s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "filed-weakref")


# ------------------------------------------------ variants (must block)

def test_p2_dquote():
    """Double-quoted binding literals."""
    p = ('(function(){var a="' + _F1 + '",b="' + _F2 + '",c="' + _F3 + '";'
         'var o={get s(){return a+b+c;}};return o.s;})()')
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "dquote")


def test_p2_bracket_access():
    """o['s'] bracket-string terminal (exact + hit)."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o['s'];})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "bracket-access")


def test_p2_multi_bind_stmts():
    """Separate binding statements."""
    p = ("(function(){var a='" + _F1 + "';var b='" + _F2 + "';var c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o.s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "multi-bind-stmts")


def test_p2_const_let():
    """const/let bindings."""
    p = ("(function(){const a='" + _F1 + "';let b='" + _F2 + "';var c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o.s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "const-let")


def test_p2_mixed_lit_bound():
    """Mixed literal + bound operands (exact + hit)."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a+'" + _F2 + "'+'" + _F3 + "';}};return o.s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "mixed-lit-bound")


def test_p2_var_rebind():
    """Duplicate var rebinds last-wins (node-exact)."""
    p = ("(function(){var a='zz';var a='" + _F1 + "';var b='" + _F2 + "';var c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o.s;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "var-rebind")


def test_p2_proxy_no_params():
    """Proxy trap with zero params."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var p=new Proxy({},{get:()=>a+b+c});return p.anything;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "proxy-no-params")


def test_p2_proxy_bare_param():
    """Proxy trap with a single bare-ident param."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var p=new Proxy({},{get:t=>a+b+c});return p['k'];})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "proxy-bare-param")


def test_p2_getter_name():
    """Non-default getter name, terminal matches."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var o={get cred(){return a+b+c;}};return o.cred;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "getter-name")


def test_p2_ws_heavy():
    """Whitespace-tolerant spacing."""
    p = ("(function(){ var a = '" + _F1 + "' , b = '" + _F2 + "' , c = '" + _F3 + "' ; "
         "var o = { get s(){ return a + b + c ; } } ; return o.s ; })()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "ws-heavy")


def test_p2_weakref_bracket():
    """WeakRef twin with bracket-string terminal."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var w=new WeakRef({get s(){return a+b+c;}});return w.deref()['s'];})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "weakref-bracket")


# ------------------------------------------------ fail-closed bounds

def test_p3_unbound_ident_closed():
    """Unbound ident in the body (engine ReferenceError) misses."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a+z;}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "unbound-ident")


def test_p3_this_closed():
    """`this` operand fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a+this.x;}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "this-operand")


def test_p3_computed_head_closed():
    """Computed getter head fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get ['s'](){return a;}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "computed-head")


def test_p3_setter_closed():
    """Setter present fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a;},set s(v){}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "setter")


def test_p3_method_shorthand_closed():
    """Method shorthand is not a getter."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={s(){return a;}};return o.s();})()")
    return ("HELD" if _misses(p) else "BREAK", "method-shorthand")


def test_p3_block_arrow_trap_closed():
    """Block-body trap arrow fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var p=new Proxy({},{get:(t,k)=>{return a;}});return p.x;})()")
    return ("HELD" if _misses(p) else "BREAK", "block-arrow-trap")


def test_p3_terminal_mismatch_closed():
    """Terminal reads a different member than the getter."""
    p = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
         "var o={get s(){return a+b+c;}};return o.t;})()")
    return ("HELD" if _misses(p) else "BREAK", "terminal-mismatch")


def test_p3_extra_stmt_closed():
    """Extra statement between wrapper and return fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a;}};var z=1;return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "extra-stmt")


def test_p3_wrapper_collision_closed():
    """Wrapper ident bound in the section fails closed."""
    p = ("(function(){var o='x';"
         "var o={get s(){return o;}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "wrapper-collision")


def test_p3_deref_args_closed():
    """w.deref(1) fails closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var w=new WeakRef({get s(){return a;}});return w.deref(1).s;})()")
    return ("HELD" if _misses(p) else "BREAK", "deref-args")


def test_p3_nonempty_call_closed():
    """Non-empty invocation args fail closed."""
    p = ("(function(){var a='" + _F1 + "';"
         "var o={get s(){return a;}};return o.s;})(1)")
    return ("HELD" if _misses(p) else "BREAK", "nonempty-call")


def test_p3_named_fn_closed():
    """Named function IIFE fails closed."""
    p = ("(function f(){var a='" + _F1 + "';"
         "var o={get s(){return a;}};return o.s;})()")
    return ("HELD" if _misses(p) else "BREAK", "named-fn")


def test_p3_no_bindings_old_route():
    """No binding section: the F535 all-literal route still blocks (control)."""
    p = ("(function(){var o={get s(){return '" + _F1 + "'+'" + _F2 + "'+'" + _F3 + "';}};"
         "return o.s;})()")
    ok = _decode_exact(p) is None and _blocked(p)
    return ("HELD" if ok else "BREAK", "no-bindings-old-route")


# ------------------------------------------------ composition

def test_p4_f612_stays_held():
    """F612 (CLOSED) shapes still block after the F642 hook."""
    ok = True
    ok = ok and _blocked("(function(){var o={a:'" + _A + "',b:'" + _B + "'};"
                         "return Object.values(o).join('');})()")
    ok = ok and _blocked("(function(){var o={a:'" + _A + "',b:'" + _B + "'};"
                         "return Object.entries(o).map(e=>e[1]).join('');})()")
    return ("HELD" if ok else "BREAK", "f612-held")


def test_p4_f535_getter_stays_held():
    """F535 literal-getter expression route still blocks."""
    p = "({get s(){return '" + _A + "'+'" + _B + "';}}).s"
    return ("HELD" if _blocked(p) else "BREAK", "f535-getter-held")


def test_p4_open_neighbors_still_miss():
    """Open findings F644-F654 CLOSED at wave-377 merge: now block (nothing absorbed)."""
    import importlib
    shapes = []
    for fnum in (644, 645, 647, 648, 649, 650, 652, 653):  # Wave-377 lane 3: F646, F651 CLOSED (removed from open list)
        mod = importlib.import_module("w376_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append(payload)
    mod654 = importlib.import_module("w376_f654_redfirst")
    for name, payload, recovers in mod654.SHAPES:
        if recovers:
            shapes.append(payload)
    ok = all(_blocked(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "closed-neighbors-block=%s" % ok)


# ------------------------------------------------ pin / footer / perf

def test_p5_pin_taxonomy():
    """Pin stays 2143; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p5_footer_state():
    """Footer: F642 closed; open F640, F641, F643; next F644."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F700**" in text  # Wave-376 lane 3: F642 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)  # Wave-376 lane 3: F642 CLOSED # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
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
    corpus = ("(function(){var a='" + _F1 + "',b='" + _F2 + "',c='" + _F3 + "';"
              "var o={get s(){return a+b+c;}};return o.s;})() " * 200)
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = hit and dt < 20.0
    return ("HELD" if ok else "BREAK", "hit=%s dt=%.2fs" % (hit, dt))


def test_p9_green_check():
    """Depth-1 green check: F642 red-first + attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w375_f642_redfirst.py", 0),
                               ("evals/w375_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g376-green-", dir="/var/tmp")
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
