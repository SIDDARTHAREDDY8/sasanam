#!/usr/bin/env python3
"""Wave-378 lane 2: close F656 + F659 -- generator .next().value reads and yield* delegation.

F656 (LOW, filed 2026-10-08, wave-377 lane 9, attack round 45, local
node validation + 2 gpt-4o-mini calls, hints only): generator
`.next().value` fragment reads bypassed the bounded static
JS-expression decoder. F619 (CLOSED) modeled sync-generator
yield/spread/for-of/Array.from assembly but documented
`.next().value` reads as a fail-closed residual; the filed shapes
`(function*(){yield 'f1';yield 'junk';})().next().value+'f2'` and
`(function(){var g=(function*(){yield 'f1';})();return
g.next().value+'f2';})()` both node-evaluated to the exact
credential (v24.20.0) while the decoder produced zero variants.

F659 (LOW, filed 2026-10-08, wave-377 lane 9, attack round 45):
`yield*` spread assembly bypassed the decoder. F619 modeled
sync-generator yield/spread assembly but documented `yield*` as a
fail-closed residual; the filed shapes
`[...(function*(){yield* ['f1','f2'];})()].join('')` and
`(function(){var g=function*(){yield* ['f1','f2'];};return
[...g()].join('');})()` both node-evaluated to the exact credential
(v24.20.0) while the decoder produced zero variants.

Closure (gov/dlp.py):
- F656: `_js_parse_f656_next_value_iife` parses
  `(function*(){yield 'LIT';...})().next().value` at expression
  level -- the fixed-yield generator (F494 grammar, now incl. F659
  yield*) is invoked, the FIRST `.next()` yields yields[0]
  (grammar guarantees >=1 yield), `.value` reads it; the result
  flows through the normal postfix chain. `.next('x')`,
  `.next().done`, `.next()` without `.value`, or any other member
  fails closed. `_js_parse_f656_bound_next_value_iife` parses the
  statement twin `(function(){var|let|const
  G=(function*(){...})();return G.next().value+...;})()` -- the
  bound name is read exactly once; the tail is re-parsed
  additively with the first yield substituted (F631 rewrite
  precedent). Hooked after F653 in the paren dispatch chain
  (disjoint: the `(function*` head matches no earlier route).
- F659: `_js_parse_f659_yield_star_array` parses the delegation
  operand `['LIT',...]`; the fixed-yield body grammar is shared as
  `_js_parse_f6xx_fixed_yield_body` (F494 expression form keeps its
  trailing-return skip; F619 statement form keeps return
  fail-closed) and now accepts `yield* ['LIT',...];` statements.
  F619's declaration additionally accepts the var-bound
  generator-expression twin `var|let|const NAME =
  function*(){...};` (grouped or bare; engine-identical for the
  modeled consume tails). Only inputs the old grammars failed
  closed are accepted, so no previously decoded input changes
  behavior. Zero new re.compile (count stays 28).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
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

results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "ERROR %r" % (e,)
    results.append((name, verdict, note))
    print("%-44s %s (%s)" % (name, verdict, note))


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact_f656_expr(js):
    """Exact decoded value via the F656 expression parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f656_next_value_iife(js, 0, 0, state)
    assert r is not None, "F656 expr parser returned None"
    val, _ = r
    return val


def _decode_exact_f656_stmt(js):
    """Exact decoded value via the F656 statement parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f656_bound_next_value_iife(js, 0, 0, state)
    assert r is not None, "F656 stmt parser returned None"
    val, _ = r
    return val


def _decode_exact_f619_iife(js):
    """Exact decoded value via the F619 statement parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f619_generator_iife(js, 0, 0, state)
    assert r is not None, "F619 parser returned None"
    val, _ = r
    return val


# ------------------------------------------------ p1: filed shapes (must block)

def test_p1_f656_filed_expr():
    """F656 filed expression shape blocks; internal seam decodes exact."""
    js = ("(function*(){yield '%s';yield 'junk';})().next().value+'%s'"
          % (_A, _B))
    exact = _decode_exact_f656_expr(
        "(function*(){yield '%s';yield 'junk';})().next().value" % _A)
    ok = _blocked(js) and exact == _A
    return ("HELD" if ok else "BREAK", "exact=%r blocked=%s" % (exact, _blocked(js)))


def test_p1_f656_filed_stmt():
    """F656 filed statement shape blocks; internal seam decodes exact."""
    js = ("(function(){var g=(function*(){yield '%s';})();"
          "return g.next().value+'%s';})()" % (_A, _B))
    exact = _decode_exact_f656_stmt(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r blocked=%s" % (exact, _blocked(js)))


def test_p1_f659_filed_expr():
    """F659 filed expression shape blocks."""
    js = ("[...(function*(){yield* ['%s','%s'];})()].join('')" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p1_f659_filed_stmt():
    """F659 filed statement shape blocks; internal seam decodes exact."""
    js = ("(function(){var g=function*(){yield* ['%s','%s'];};"
          "return [...g()].join('');})()" % (_A, _B))
    exact = _decode_exact_f619_iife(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r blocked=%s" % (exact, _blocked(js)))


# ------------------------------------------------ p2: variants (must block)

def test_p2_f656_ws_heavy():
    """F656 with heavy whitespace still blocks."""
    js = ("( function* ( ) { yield '%s' ; } ) ( ) . next ( ) . value + '%s'"
          % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f656_dquote_yields():
    """F656 with double-quoted yields blocks."""
    js = ('(function*(){yield "%s";yield "junk";})().next().value+"%s"'
          % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f656_named_genexpr():
    """F656 with a named generator expression blocks."""
    js = ("(function* gen(){yield '%s';})().next().value+'%s'" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f656_three_yields_first():
    """F656 reads the FIRST yield of three."""
    js = ("(function*(){yield '%s';yield '%s';yield 'junk';})()"
          ".next().value" % (_A, _B))
    exact = _decode_exact_f656_expr(js)
    ok = exact == _A and _misses(js + "+'jy'")
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f656_yieldstar_first():
    """F656 over a yield* body reads the first delegated element."""
    js = ("(function*(){yield* ['%s','%s'];})().next().value" % (_A, _B))
    exact = _decode_exact_f656_expr(js)
    ok = exact == _A
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f656_trailing_return():
    """F656 with a trailing return still reads the first yield."""
    js = ("(function*(){yield '%s';return 'rx';})().next().value" % _A)
    exact = _decode_exact_f656_expr(js)
    ok = exact == _A
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f656_stmt_let_const():
    """F656 statement twin with let/const bindings blocks."""
    ok = True
    for decl in ("let", "const"):
        js = ("(function(){%s g=(function*(){yield '%s';})();"
              "return g.next().value+'%s';})()" % (decl, _A, _B))
        ok = ok and _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f656_stmt_grouped():
    """F656 statement twin with a grouped generator expression blocks."""
    js = ("(function(){var g=(function*(){yield '%s';})();"
          "return g.next().value+'%s';})()" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f659_three_elems_sep():
    """F659 yield* with three elements and a separator blocks."""
    js = ("[...(function*(){yield* ['%s','%s','%s'];})()].join('-')"
          % (_A, _B, "zz"))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f659_paren_operand():
    """F659 yield* with a parenthesized array operand blocks."""
    js = ("[...(function*(){yield* (['%s','%s']);})()].join('')" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p2_f659_mixed_yields():
    """F659 yield* mixed with plain yields blocks in order."""
    js = ("(function(){function* g(){yield '%s';yield* ['%s'];}"
          "return [...g()].join('');})()" % (_A, _B))
    exact = _decode_exact_f619_iife(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f659_varbound_plain():
    """F619 generalization: var-bound generator, plain yields, spread."""
    js = ("(function(){var g=function*(){yield '%s';yield '%s';};"
          "return [...g()].join('');})()" % (_A, _B))
    exact = _decode_exact_f619_iife(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f659_varbound_forof():
    """F619 generalization: var-bound generator with for-of tail."""
    js = ("(function(){var g=function*(){yield '%s';yield '%s';};"
          "var s='';for(var x of g()){s+=x;}return s;})()" % (_A, _B))
    exact = _decode_exact_f619_iife(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f659_varbound_arrayfrom():
    """F619 generalization: var-bound generator with Array.from tail."""
    js = ("(function(){var g=function*(){yield '%s';yield '%s';};"
          "return Array.from(g()).join('');})()" % (_A, _B))
    exact = _decode_exact_f619_iife(js)
    ok = _blocked(js) and exact == _A + _B
    return ("HELD" if ok else "BREAK", "exact=%r" % (exact,))


def test_p2_f659_dquote_array():
    """F659 yield* with double-quoted array elements blocks."""
    js = ('[...(function*(){yield* ["%s","%s"];})()].join("")' % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

def test_p3_f656_next_with_arg():
    """F656: .next('x') args fail closed (node ignores, decoder refuses)."""
    ok = _misses("(function*(){yield '%s';})().next('x').value+'%s'"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_next_done():
    """F656: .next().done fails closed (not a credential read)."""
    ok = _misses("(function*(){yield '%s';})().next().done+'%s'"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_next_no_value():
    """F656: .next() without .value fails closed (object, not a string)."""
    ok = _misses("(function*(){yield '%s';})().next()+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_next_other_member():
    """F656: .next().xyz fails closed."""
    ok = _misses("(function*(){yield '%s';})().next().xyz+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_nonliteral_yield():
    """F656: non-literal yields fail closed."""
    ok = _misses("(function*(){yield %s;})().next().value+'%s'"
                 % ("_A", _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_stmt_two_reads():
    """F656: two .next() reads on the bound generator fail closed (stateful)."""
    ok = _misses("(function(){var g=(function*(){yield '%s';yield '%s';})();"
                 "return g.next().value+g.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_stmt_extra_statement():
    """F656: extra statements in the IIFE body fail closed."""
    ok = _misses("(function(){var g=(function*(){yield '%s';})();var z=1;"
                 "return g.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_stmt_reassign():
    """F656: reassignment of the bound name fails closed."""
    ok = _misses("(function(){var g=(function*(){yield '%s';})();g=1;"
                 "return g.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_stmt_wrong_name():
    """F656: .next() on a different name fails closed."""
    ok = _misses("(function(){var g=(function*(){yield '%s';})();"
                 "return h.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f656_generator_not_invoked():
    """F656: uninvoked generator expression fails closed."""
    ok = _misses("(function*(){yield '%s';}).next().value+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f659_yieldstar_string():
    """F659: yield* over a string fails closed (internal seam).

    The public seam cannot carry this bound without embedding the
    raw credential (which the text scan correctly flags), so the
    boundary is proven at the internal seam: the generator parser
    raises _JSExprFail on a string operand.
    """
    state = {"ops": 0, "parts": 0, "depth": 0}
    try:
        _dlp._js_parse_generator_iife(
            "(function*(){yield* 'ab';})()", 0, 0, state)
        ok = False
    except _dlp._JSExprFail:
        ok = True
    return ("HELD" if ok else "BREAK", "raises=%s" % ok)


def test_p3_f659_yieldstar_hole():
    """F659: yield* array with a hole fails closed."""
    ok = _misses("[...(function*(){yield* ['%s',,'%s'];})()].join('')"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f659_yieldstar_nonliteral():
    """F659: yield* with a non-literal element fails closed."""
    ok = _misses("[...(function*(){yield* ['%s',_B];})()].join('')" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f659_yieldstar_ident():
    """F659: yield* over an identifier fails closed."""
    ok = _misses("[...(function*(){var a=['%s'];yield* a;})()].join('')"
                 % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f659_yieldstar_nested():
    """F659: yield* with a nested array fails closed."""
    ok = _misses("[...(function*(){yield* [['%s']];})()].join('')" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p3_f659_async_yieldstar():
    """F659: async-generator yield* stays fail-closed (out of scope)."""
    ok = _misses("(async function(){async function* g(){yield* ['%s'];};"
                 "return 1;})()" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: open neighbors still miss

def test_p4_f655_closed_by_sibling():
    """F655 (statement-IIFE multi-decl) CLOSED by sibling lane (wave-378 merge): filed shape now blocks."""
    ok = not _misses("(function(){var s='%s';var t='%s';return s+t;})()"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "block=" + str(ok) + " via-sibling")


def test_p4_f657_closed_by_sibling():
    """F657 (var-bound Map forEach) CLOSED by sibling lane (wave-378 merge): filed shape now blocks."""
    ok = not _misses("(function(){var m=new Map([['k','%s'],['j','%s']]);"
                 "var s='';m.forEach(function(v){s+=v;});return s;})()"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "block=" + str(ok) + " via-sibling")


def test_p4_f658_closed_by_sibling():
    """F658 (flatMap) CLOSED by sibling lane (wave-378 merge): filed shape now blocks."""
    ok = not _misses("['x'].flatMap(()=>['%s','%s']).join('')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "block=" + str(ok) + " via-sibling")


def test_p4_f660_closed_by_sibling():
    """F660 (env-threaded tail reads) CLOSED by sibling lane (wave-378 merge): filed shape now blocks."""
    ok = not _misses("(function(){var x;return (x='%s',x)+'%s'+x;})()"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "block=" + str(ok) + " via-sibling")


def test_p4_f661_closed_by_sibling():
    """F661 (declaration-position sequences) CLOSED by sibling lane (wave-378 merge): filed shape now blocks."""
    ok = not _misses("(function(){var s=('jx','%s');return s+'%s';})()"
                 % (_A, _B))
    return ("HELD" if ok else "BREAK", "block=" + str(ok) + " via-sibling")


# ------------------------------------------------ p5: closed neighbors still held

def test_p5_f619_still_held():
    """F619 named-decl spread still blocks."""
    ok = _blocked("(function(){function* g(){yield '%s';yield '%s';}"
                   "return [...g()].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p5_f619_forof_still_held():
    """F619 for-of tail still blocks."""
    ok = _blocked("(function(){function* g(){yield '%s';yield '%s';}"
                   "var s='';for(var x of g()){s+=x;}return s;})()"
                   % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p5_f494_spread_still_held():
    """F494 anonymous-generator spread still blocks."""
    ok = _blocked("[...(function*(){yield '%s';yield '%s';})()].join('')"
                   % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p5_f653_still_held():
    """F653 custom-iterator spread still blocks."""
    js = ("(function(){var fr=['%s','%s'];var o={i:0};"
          "o[Symbol.iterator]=function(){var self=this;return{next:function(){"
          "return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};"
          "return [...o].join('');})()" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p5_f631_still_held():
    """F631 async-generator next-await still blocks."""
    js = ("(async function(){async function* g(){yield '%s';}"
          "var it=g();var r=await it.next();return r.value+'%s';})()"
          % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ p6: junk quiet

def test_p6_f656_junk_quiet():
    """F656 junk fragments stay quiet."""
    ok = _misses("(function*(){yield 'jx';})().next().value+'jy'")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p6_f659_junk_quiet():
    """F659 junk fragments stay quiet."""
    ok = _misses("[...(function*(){yield* ['jx'];})()].join('')")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


def test_p6_partial_credential_quiet():
    """Partial-credential shapes stay quiet."""
    ok = _misses("(function*(){yield '%s';})().next().value+'jy'" % _A)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p7: composition

def test_p7_f656_in_array_join():
    """F656 read as an array element composes through join."""
    js = ("[(function*(){yield '%s';})().next().value,'%s'].join('')"
          % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


def test_p7_f656_yieldstar_body():
    """F656 over a yield* body reads the first delegated element."""
    js = ("(function*(){yield* ['%s','%s'];})().next().value+'%s'"
          % (_A, _B, "zz"))
    exact = _decode_exact_f656_expr(
        "(function*(){yield* ['%s','%s'];})().next().value" % (_A, _B))
    ok = exact == _A and _misses(js)
    return ("HELD" if ok else "BREAK", "exact=%r quiet=%s" % (exact, _misses(js)))


def test_p7_f659_in_additive():
    """F659 spread composes additively."""
    js = ("[...(function*(){yield* ['%s'];})()].join('')+'%s'" % (_A, _B))
    ok = _blocked(js)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ p8: pin + footer

def test_p8_pin_and_footer():
    """Pin 2143; lane-local footer: open F662-F671 / next F672."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    ok_pin = False
    footer = None
    with open(path) as fh:
        for line in fh:
            if "TAXONOMY_PIN = 2143" in line or "pin 2143" in line:  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
                ok_pin = True
            if line.startswith("Next free finding:"):
                footer = line.strip()
    ok_footer = (footer is not None
                 and "Next free finding: **F921**" in footer  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
                 and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in footer)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok_pin and ok_footer
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (ok_pin, ok_footer))


# ------------------------------------------------ p9: perf

def test_p9_perf():
    """200 mixed sites decode quickly."""
    sites = []
    for k in range(50):
        sites.append("(function*(){yield '%s';})().next().value+'%s'"
                     % (_A, _B))
        sites.append("[...(function*(){yield* ['%s','%s'];})()].join('')"
                     % (_A, _B))
        sites.append("(function(){var g=function*(){yield '%s';};"
                     "return [...g()].join('');})()" % _A)
        sites.append("plain text with no credential %d" % k)
    t0 = time.time()
    for s in sites:
        find_credential(s)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p10: re.compile pin

def test_p10_no_new_re_compile():
    """gov/dlp.py still has exactly 28 re.compile( calls."""
    import re
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as fh:
        src = fh.read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile count=%d" % n)


# ------------------------------------------------ p11: green check (depth-1)

def _green_check():
    """Depth-1 green check: adjacent batteries, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green-check: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    ok = True
    for battery, expect_breaks in (
            ("evals/w377_f656_redfirst.py", 0),
            ("evals/w377_f659_redfirst.py", 0),
            ("evals/w377_attack_probes.py", 0)):
        tmpd = tempfile.mkdtemp(prefix="g378f656f659-gc-", dir="/var/tmp")
        r = subprocess.run([sys.executable,
                            os.path.join(REPO_ROOT, battery)],
                           capture_output=True, text=True, timeout=900,
                           env=dict(env, TMPDIR=tmpd))
        out = r.stdout + r.stderr
        m = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                m = line
        breaks = int(m.split()[1]) if m else -1
        good = (breaks == expect_breaks)
        print("green-check: %s: %s (tally=%s)" %
              (battery, "green" if good else "RED", m))
        ok = ok and good
    return ok


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    print("== w378_f656f659close_probes: %d tests ==" % len(results))
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD / %d ERROR" %
          (breaks, held, len(results) - breaks - held))
    gc = _green_check()
    print("green-check: %s" % ("green" if gc else "RED"))
    if breaks or not gc:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
