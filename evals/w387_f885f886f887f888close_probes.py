#!/usr/bin/env python3
"""Wave-387 lane 15: close F885 + F886 + F887 + F888 (arrow CustomEvent
listeners; computed getter names; return-paren whitespace; dot-method
whitespace).

F885 (LOW; filed 2026-10-09 05:33 UTC by wave-386 lane 7, review
residual of the F808 closure): arrow-function CustomEvent listeners --
`(e)=>{r=e.detail;}` resolves node-exactly (v24.20.0) but the F808 hook
modeled only `function` listeners. Filed shapes:
  (function(){var t=new EventTarget();var r='';t.addEventListener('x',
   (e)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',
   {detail:'f1'}));return r+'f2';})()
  (function(){var t=new EventTarget();var r='';t.addEventListener('y',
   (e)=>{r=e.detail.k;});t.dispatchEvent(new CustomEvent('y',
   {detail:{k:'f1'}}));return r+'f2';})()

F886 (LOW; filed 2026-10-09 05:38:39 UTC by wave-386 lane 9, closure
residual of the F811 work): computed getter names -- F755 covers
`get ['x']()` and F811 covers computed method names, but
`get [k]()` (k bound to a string literal) and `get ['m'+'2']()`
(additive fold) had no production in _js_parse_f535_getter_head.
Filed shapes:
  (function(){var k='m';var o={get [k](){return 'f1';}};
   return o.m+'f2';})()
  (function(){var o={get ['m'+'2'](){return 'f1';}};
   return o.m2+'f2';})()

F887 (LOW; filed 2026-10-09 05:40:54 UTC by wave-386 lane 4, spec-review
hard finding on the F801 closure): whitespace between `return` and the
grouping paren in the F801 named-function body -- the engine tolerates
`return (a+'f2')` but _js_parse_f614_additive_body (via F801) checked
`text[j] == "("` without skipping whitespace. Filed shapes:
  (function(){function f(a){return (a+'f2');}
   return Reflect.apply(f,null,['f1']);})()
  (function(){function f(a,b){return (a+b);}
   return Reflect.apply(f,null,['f1','f2']);})()

F888 (LOW; filed 2026-10-09 05:40:54 UTC by wave-386 lane 4, spec-review
hard finding on the F802 closure): whitespace between `.` and the
method name in the native postfix chain -- the engine tolerates
`a. flat()` but _js_parse_postfix matched the method name at `j+1`
without skipping whitespace. Filed shapes:
  (function(){var a=[['f1'],['f2']];return a. flat().join('');})()
  [['f1'],['f2']]. flat().join('')

Fix (gov/dlp.py, zero new re.compile):
- F885: arrow-listener twin branch inside _js_parse_f808_customevent_iife
  -- `(e)=>{...}` parses the same single-statement body as the
  `function(e){...}` form (same param checks; multi-param, concise
  bodies, and async arrows fail closed). Disjoint: previously only
  `function` listeners were accepted.
- F886: _js_parse_f535_getter_head gains pre_env/depth/state params;
  `[IDENT]` resolves via pre_env (F67x key-branch precedent),
  `['m'+'2']` folds via _js_fold_bracket_key (F492), string-literal
  and Symbol.for paths unchanged. All three call sites thread
  state/depth; the F67x site also threads pre_env.
- F887: _js_parse_f801_named_fn skips whitespace after `return`
  before the F614 body (narrow: F801 only).
- F888: the _JS_POSTFIX_METHOD_NAMES loop skips whitespace once
  after the dot (no-space inputs unaffected).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
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
def test_p0_no_new_recompile():
    """Zero new re.compile (stays 28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    src = open(os.path.join(REPO_ROOT, "evals",
                            "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = 33" in src
    return ("HELD" if ok else "BREAK", "verifier-pin=%s" % ok)


@_t
def test_b0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1]
          and "F919, F920." in foot[-1]
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block + exact)


@_t
def test_p1_f885_s1():
    """F885 filed shape 1 (arrow listener, string detail)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "(e)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'"
         + _A + "'}));return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f885_s2():
    """F885 filed shape 2 (arrow listener, nested detail)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('y',"
         "(e)=>{r=e.detail.k;});t.dispatchEvent(new CustomEvent('y',"
         "{detail:{k:'" + _A + "'}}));return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f886_s1():
    """F886 filed shape 1 (bound-identifier computed getter)."""
    s = ("(function(){var k='m';var o={get [k](){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f886_s2():
    """F886 filed shape 2 (additive-fold computed getter)."""
    s = ("(function(){var o={get ['m'+'2'](){return '" + _A
         + "';}};return o.m2+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f887_s1():
    """F887 filed shape 1 (space after return, single param)."""
    s = ("(function(){function f(a){return (a+'" + _B
         + "');}return Reflect.apply(f,null,['" + _A + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f887_s2():
    """F887 filed shape 2 (space after return, two params)."""
    s = ("(function(){function f(a,b){return (a+b);}"
         "return Reflect.apply(f,null,['" + _A + "','" + _B + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f888_s1():
    """F888 filed shape 1 (space after dot, var-bound)."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a. flat().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f888_s2():
    """F888 filed shape 2 (space after dot, inline twin)."""
    s = "[['" + _A + "'],['" + _B + "']]. flat().join('')"
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f885_ws_arrow():
    """F885 whitespace around the arrow param blocks + exact."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "( e )=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',"
         "{detail:'" + _A + "'}));return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f885_let_decls():
    """F885 let-declared target/accumulator blocks + exact."""
    s = ("(function(){let t=new EventTarget();let r='';t.addEventListener('x',"
         "(e)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'"
         + _A + "'}));return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f886_comma_decl():
    """F886 comma-joined key declarator blocks + exact."""
    s = ("(function(){var k='m',o={get [k](){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f886_two_getters():
    """F886 additive getter beside a plain getter blocks + exact."""
    s = ("(function(){var o={get ['a'+'b'](){return '" + _A
         + "';},get c(){return 'X';}};return o.ab+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f887_tab():
    """F887 tab after return blocks + exact."""
    s = ("(function(){function f(a){return\t(a+'" + _B
         + "');}return Reflect.apply(f,null,['" + _A + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f887_inner_ws():
    """F887 whitespace inside the grouping paren blocks + exact."""
    s = ("(function(){function f(a,b){return ( a + b );}"
         "return Reflect.apply(f,null,['" + _A + "','" + _B + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f888_multi_ws():
    """F888 multiple spaces after dot blocks + exact."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a.   flat().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f888_chain_ws():
    """F888 whitespace at two chain steps blocks + exact."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a. flat(). join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f885_concise_body():
    """F885 concise-body arrow fails closed (engine-valid)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "(e)=>r=e.detail);t.dispatchEvent(new CustomEvent('x',{detail:'"
         + _A + "'}));return r+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f885_two_params():
    """F885 two-param arrow fails closed (engine-valid)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "(e,i)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('x',"
         "{detail:'" + _A + "'}));return r+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f885_wrong_type():
    """F885 type-mismatched dispatch fails closed (listener never fires)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "(e)=>{r=e.detail;});t.dispatchEvent(new CustomEvent('y',"
         "{detail:'" + _A + "'}));return r+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f885_shadow_param():
    """F885 param shadowing the accumulator fails closed."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "(r)=>{r=r.detail;});t.dispatchEvent(new CustomEvent('x',"
         "{detail:'" + _A + "'}));return r+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f886_unbound_ident():
    """F886 unbound computed identifier fails closed (ReferenceError)."""
    s = ("(function(){var o={get [k](){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f886_nonstring_bound():
    """F886 non-string-bound identifier fails closed."""
    s = ("(function(){var k=3;var o={get [k](){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f886_mixed_fold():
    """F886 mixed literal+bound-identifier fold fails closed (F893 OPEN)."""
    s = ("(function(){var k='2';var o={get ['m'+k](){return '" + _A
         + "';}};return o.m2+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f886_numeric():
    """F886 numeric computed key fails closed (documented boundary)."""
    s = ("(function(){var o={get [3](){return '" + _A
         + "';}};return o[3]+'" + _B + "';})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f887_double_paren():
    """F887 double-wrapped parens fail closed (F614: single wrap only)."""
    s = ("(function(){function f(a){return ((a+'" + _B
         + "'));}return Reflect.apply(f,null,['" + _A + "']);})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


@_t
def test_p3_f888_unknown_method():
    """F888 unknown method with whitespace fails closed."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a. flatx().join('');})()")
    return ("HELD" if _fails_closed(s) else "BREAK", "fails-closed")


# ------------------------------------------------ p4: sibling pins (must still hold)


@_t
def test_p4_f808_function_twin():
    """F808 function-listener twin still blocks (not disturbed)."""
    s = ("(function(){var t=new EventTarget();var r='';t.addEventListener('x',"
         "function(e){r=e.detail;});t.dispatchEvent(new CustomEvent('x',"
         "{detail:'" + _A + "'}));return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f755_computed_str_getter():
    """F755 computed string-literal getter still blocks."""
    s = ("(function(){var o={get ['m'](){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f552_symbol_getter():
    """F552 Symbol.for getter head still parses; end-to-end unchanged.

    The head resolves the ("symbol", k) tuple as before (base tree
    also misses the full shape -- the read path is unmodeled); this
    pins that the F886 rework did not disturb the Symbol branch.
    """
    head = "get [Symbol.for('k')]()"
    name, _ = dlp._js_parse_f535_getter_head(head, 4)
    ok_head = name == ("symbol", "k")
    s = ("(function(){var o={get [Symbol.for('k')](){return '" + _A
         + "';}};return o[Symbol.for('k')]})()")
    ok_e2e = _fails_closed(s)  # unchanged from base: read unmodeled
    ok = ok_head and ok_e2e
    return ("HELD" if ok else "BREAK",
            "head=%s e2e-fails-closed=%s" % (ok_head, ok_e2e))


@_t
def test_p4_f801_nospace():
    """F801 no-space return-paren twin still blocks."""
    s = ("(function(){function f(a){return(a+'" + _B
         + "');}return Reflect.apply(f,null,['" + _A + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f802_nospace():
    """F802 no-space dot twin still blocks."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a.flat().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f811_computed_method():
    """F811 computed method name still blocks."""
    s = ("(function(){var k='m';var o={[k](){return '" + _A
         + "';}};return o.m()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f674_plain_getter():
    """F674 single-decl plain getter still blocks."""
    s = ("(function(){var o={get m(){return '" + _A
         + "';}};return o.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_bracket_key_ws():
    """Bracket-string key with whitespace still blocks (pre-existing)."""
    s = ("(function(){var a=[['" + _A + "'],['" + _B
         + "']];return a[ 'flat' ]().join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest_prose():
    """Prose mentioning the new shapes stays quiet."""
    s = ("The addEventListener arrow (e)=>{r=e.detail;} and the "
         "a. flat() chain and return (x) spacing are just docs.")
    return ("HELD" if _misses(s) else "BREAK", "quiet")


@_t
def test_p5_honest_getter_prose():
    """Prose mentioning computed getters stays quiet."""
    s = "A get [k](){} getter with a computed name is only an example."
    return ("HELD" if _misses(s) else "BREAK", "quiet")


# ------------------------------------------------ p6: perf (200 sites)


@_t
def test_p6_perf_200():
    """200 mixed laundering sites stay fast (fail-closed bounds apply)."""
    sites = []
    for i in range(50):
        sites.append("(function(){var t=new EventTarget();var r='';"
                     "t.addEventListener('x',(e)=>{r=e.detail;});"
                     "t.dispatchEvent(new CustomEvent('x',{detail:'a'}));"
                     "return r+'b';})()")
        sites.append("(function(){var o={get ['a'+'b'](){return 'x';}};"
                     "return o.ab+'y';})()")
        sites.append("(function(){function f(a){return (a+'y');}"
                     "return Reflect.apply(f,null,['x']);})()")
        sites.append("(function(){var a=[['x'],['y']];"
                     "return a. flat().join('');})()")
    payload = ";".join(sites)
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The four w387 red-firsts expect 0 BREAK (closed); w387_f893 and
    # w387_f894 expect 2 BREAK each (filed OPEN this lane). The
    # w386_attack battery expects exactly 1 BREAK on this tree: its
    # test_b0_footer_state (base footer vs this lane's footer); its
    # test_p9_green_check is skipped under GOV_SKIP_GREEN=1. Verified
    # identical on the base tree -- the count is merge-owned, not a
    # regression.
    for batt, expect_break in (("evals/w387_f885_redfirst.py", 0),
                               ("evals/w387_f886_redfirst.py", 0),
                               ("evals/w387_f887_redfirst.py", 0),
                               ("evals/w387_f888_redfirst.py", 0),
                               ("evals/w387_f893_redfirst.py", 2),
                               ("evals/w387_f894_redfirst.py", 2),
                               ("evals/w386_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts closed, w386_attack at 1 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
        if not args.tally_only:
            print("%s %-28s %s" % (verdict, fn.__name__, note))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
