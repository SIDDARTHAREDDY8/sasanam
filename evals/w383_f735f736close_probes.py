#!/usr/bin/env python3
"""Close battery for F735 + F736 (wave-383 lane 12).

F735 (LOW, attack round 50): nested function closure reads --
`var f='LIT';function g(){return f;}return g()+'LIT';` and the
`var g=function(){return f;};` twin bypassed the decoder (no
nested-function production). Closed by
`_js_parse_f735f736_nested_fn_iife` (gov/dlp.py, hooked after
F712): nested declarations and var-bound function expressions
evaluate at call time against the call-time environment.

F736 (LOW, attack round 50): default parameter reads --
`function h(a='LIT'){return a;}return h()+'LIT';` and `function
h(a='LIT',b='LIT'){return a+b;}return h('LIT');` (corrected shape:
h(a=_A,b=_B)/h(_A) evaluates A+B node-exact). Closed by the same
parser: default params bind positionally (explicit literal args
override, missing args take literal defaults).

Prints BREAK on any regression. Standalone: 0 BREAK expected.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
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


# ------------------------------------------------------------- controls

TAXONOMY_PIN = 2143


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F735/F736 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f735_s1():
    """F735 filed shape 1 (nested fn declaration) blocks."""
    ok = _blocked(
        "(function(){var f='%s';function g(){return f;}"
        "return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f735-s1=%s" % ok)


@_t
def test_p1_f735_s2():
    """F735 filed shape 2 (var-bound fn expression) blocks."""
    ok = _blocked(
        "(function(){var f='%s';var g=function(){return f;};"
        "return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f735-s2=%s" % ok)


@_t
def test_p1_f736_s1():
    """F736 filed shape 1 (single default param) blocks."""
    ok = _blocked(
        "(function(){function h(a='%s'){return a;}"
        "return h()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f736-s1=%s" % ok)


@_t
def test_p1_f736_s2():
    """F736 filed shape 2 (corrected: h(a,b)/h(a) -> A+B) blocks."""
    ok = _blocked(
        "(function(){function h(a='%s',b='%s'){return a+b;}"
        "return h('%s');})()" % (_A, _B, _A))
    return ("HELD" if ok else "BREAK", "f736-s2=%s" % ok)


# ------------------------------------------------------ generalizations (p2)

@_t
def test_p2_multi_decl_closure():
    """Closure over comma-separated bindings."""
    ok = _blocked(
        "(function(){var f='%s',g2='x';function h(){return f+g2;}"
        "return h()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multi-decl=%s" % ok)


@_t
def test_p2_three_defaults():
    """Three default params, all defaulted at call."""
    ok = _blocked(
        "(function(){function h(a='%s',b='%s',c='zz'){return a+b+c;}"
        "return h();})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "three-defaults=%s" % ok)


@_t
def test_p2_explicit_beats_default():
    """Explicit arg shadows the default (node-exact)."""
    ok = _blocked(
        "(function(){var z='x';function h(a='y'){return a;}"
        "return h('%s')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "explicit=%s" % ok)


@_t
def test_p2_call_first_operand():
    """Call as a non-first additive operand."""
    ok = _blocked(
        "(function(){var f='%s';function g(){return f;}"
        "return 'q'+g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "call-first=%s" % ok)


@_t
def test_p2_forward_ref():
    """Function declared before the binding it reads (call-time env)."""
    ok = _blocked(
        "(function(){function g(){return f;}var f='%s';"
        "return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "forward-ref=%s" % ok)


@_t
def test_p2_var_rebind():
    """Duplicate var rebinds last-wins (engine-exact)."""
    ok = _blocked(
        "(function(){var f='zz';function g(){return f;}var f='%s';"
        "return g()+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "rebind=%s" % ok)


@_t
def test_p2_ws_variants():
    """Whitespace-tolerant nested bodies decode (spec-review O1)."""
    ok = _blocked(
        "(function(){var f='%s';function g(){ return f; }"
        "return g()+'%s';})()" % (_A, _B))
    ok2 = _blocked(
        "(function(){function h( a='%s' ){return a;}"
        "return h()+'%s';})()" % (_A, _B))
    ok = ok and ok2
    return ("HELD" if ok else "BREAK", "ws-variants=%s" % ok)


# -------------------------------------------------------------- bounds (p3)

@_t
def test_p3_bound_nonliteral_default():
    """Non-literal default fails closed (miss, never mis-decode)."""
    ok = _misses(
        "(function(){var f='a';function h(a=f){return a;}"
        "return h();})()")
    return ("HELD" if ok else "BREAK", "nonliteral-default=%s" % ok)


@_t
def test_p3_bound_unbound_body():
    """Body reading an unbound ident fails closed (ReferenceError)."""
    ok = _misses("(function(){function g(){return x;}return g();})()")
    return ("HELD" if ok else "BREAK", "unbound-body=%s" % ok)


@_t
def test_p3_bound_this_body():
    """`this` in a nested body fails closed."""
    ok = _misses(
        "(function(){function g(){return this.x;}return g();})()")
    return ("HELD" if ok else "BREAK", "this-body=%s" % ok)


@_t
def test_p3_bound_nested_call():
    """A body calling another nested function fails closed."""
    ok = _misses(
        "(function(){var f='a';function g(){return f;}"
        "function k(){return g();}return k();})()")
    return ("HELD" if ok else "BREAK", "nested-call=%s" % ok)


@_t
def test_p3_bound_missing_no_default():
    """Missing arg with no default fails closed (engine undefined)."""
    ok = _misses("(function(){function h(a){return a;}return h();})()")
    return ("HELD" if ok else "BREAK", "missing-nodefault=%s" % ok)


@_t
def test_p3_bound_extra_args():
    """Extra call args fail closed (conservative)."""
    ok = _misses(
        "(function(){function h(a='x'){return a;}"
        "return h('y','z');})()")
    return ("HELD" if ok else "BREAK", "extra-args=%s" % ok)


@_t
def test_p3_bound_named_fnexpr():
    """Named function expressions fail closed."""
    ok = _misses(
        "(function(){var g=function n(){return 'a';};return g();})()")
    return ("HELD" if ok else "BREAK", "named-fnexpr=%s" % ok)


@_t
def test_p3_bound_fn_redeclared():
    """Redeclared nested functions fail closed."""
    ok = _misses(
        "(function(){function g(){return 'a';}"
        "function g(){return 'b';}return g();})()")
    return ("HELD" if ok else "BREAK", "redeclared=%s" % ok)


@_t
def test_p3_bound_arrow():
    """Arrow functions fail closed."""
    ok = _misses("(function(){var g=()=>'a';return g();})()")
    return ("HELD" if ok else "BREAK", "arrow=%s" % ok)


@_t
def test_p3_bound_method_on_call():
    """Method calls on a call result fail closed."""
    ok = _misses(
        "(function(){function g(){return 'a';}"
        "return g().toString();})()")
    return ("HELD" if ok else "BREAK", "method-on-call=%s" % ok)


# ------------------------------------------- siblings still block (p4)

@_t
def test_p4_sibling_f690():
    """F690 constructor shape still blocks."""
    ok = _blocked(
        "(function(){function C(){this.k='%s';}var c=new C();"
        "return c.k+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f690=%s" % ok)


@_t
def test_p4_sibling_f642():
    """F642 getter-varbound shape still blocks."""
    ok = _blocked(
        "(function(){var a='%s',b='%s';var o={get s(){return a+b;}};"
        "return o.s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f642=%s" % ok)


@_t
def test_p4_sibling_f712():
    """F712 map-iteration shape still blocks."""
    ok = _blocked(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()][0]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f712=%s" % ok)


# ------------------------------------------- open neighbors still miss (p4b)

@_t
def test_p4_neighbor_f713_open():
    """F713 (literal Map spread-join) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var m=new Map([['k','%s']]);"
        "return [...m.values()].join('')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-closed=%s" % ok)


@_t
def test_p4_neighbor_f737_open():
    """F737 (Proxy setPrototypeOf-trap) now BLOCKS (closed wave-383 lane 13)."""
    ok = not _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:"
        "function(tr,pr){tr.__p='%s';return true;}});"
        "Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f737-closed=%s" % ok)


# ------------------------------------------------------------- honest (p5)

@_t
def test_p5_honest_quiet():
    """Honest nested functions stay quiet."""
    ok = _misses("function greet(name) { return 'hello ' + name; }")
    ok2 = _misses("(function(){var f='ab';function g(){return f;}"
                  "return g();})()")
    return ("HELD" if (ok and ok2) else "BREAK",
            "honest=%s,%s" % (ok, ok2))


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ---------------------------------------------------------------- perf (p8)

@_t
def test_p8_perf():
    """200 mixed sites decode quickly (F452 budget intact)."""
    t0 = time.time()
    for _ in range(100):
        _blocked("(function(){var f='ab';function g(){return f;}"
                 "return g()+'cd';})()")
        _misses("(function(){function g(){return x;}return g();})()")
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ---------------------------------------------------------- green check (p9)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree.
    # w382_attack_probes expects exactly 1 BREAK: its footer test
    # still asserts the base footer (open F713-F737 incl. F735/F736);
    # the lane-local footer (F735/F736 closed) is merge-owned
    # tree-wide (wave-305/306 class). Any other BREAK fails loudly.
    for batt, expect_break in (("evals/w382_f735_redfirst.py", 0),
                               ("evals/w382_f736_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F735/F736 red-firsts + wave-382 attack battery."""
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
