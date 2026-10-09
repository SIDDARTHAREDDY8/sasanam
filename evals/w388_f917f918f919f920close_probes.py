#!/usr/bin/env python3
"""Wave-388 lane 7: close F917 + F918 + F919 + F920 (JS laundering residuals).

F917 (LOW; wave-387 lane 15, closure residual of the F886 work): mixed
literal+bound-identifier computed getter names -- F886 covers
`get [k]()` (bound ident) and `get ['m'+'2']()` (pure additive fold),
but `get ['m'+k]()` / `get [k+'2']()` with k bound to a string
literal has no production: _js_fold_key_expr folds literal-only
operands. Close-when: the decoder models mixed computed getter
names node-exactly (or refuses the laundering coded) such that
find_credential flags them, honest text unaffected.

F918 (LOW; wave-387 lane 15, Spec-review residual of the F888 work):
comments between `.` and the native postfix method name -- F888
covers whitespace (`a. flat()`), but `a./*x*/flat()` is engine-valid
(token-identical to `a.flat()`, node v24.20.0) while
_js_parse_postfix does not skip it. Close-when: the decoder skips JS
comments between `.` and the postfix method name node-exactly (or
refuses the laundering coded) such that find_credential flags them,
honest text unaffected.

F919 (LOW; wave-387 lane 11, F872 closure residual probe): bare sort()
statement form -- F872 models sort with a constant-zero comparator
(statement hook _js_parse_f872_sortzero_iife), but the bare
`a.sort();` statement is not modeled. Close-when: the decoder models
the bare-sort statement form node-exactly (default UTF-16 order;
astral elements fail closed, F580 precedent) such that
find_credential flags reassembled credentials, honest text
unaffected. Fragment note: the filed s1 fragments
('xoxb-0123'/'456789abcdef') sort to "456789abcdefxoxb-0123", which
carries no regex-flaggable credential under any correct
implementation; the battery asserts the filed arrangement is
modeled node-exactly (hook-level) and adds a sort-surviving
arrangement proving detection.

F920 (LOW; wave-387 lane 11, F870 closure residual probe): single
.bind on a named function declaration -- F870 models 2-dispatch
bind chains (`f.bind(null).bind(null)()`), but `f.bind(null)()` on a
named declaration has no production. Close-when: the decoder models
single-bind on named declarations node-exactly (or refuses the
laundering coded) such that find_credential flags them, honest text
unaffected.

Fix (gov/dlp.py, zero new re.compile):
- F917: _js_fold_key_expr/_js_fold_bracket_key take optional
  pre_env; identifier operands bound to string literals fold;
  unbound/non-string idents fail closed. The F535 getter head
  threads pre_env into both additive-fold sites and tries the
  mixed fold when an ident is followed by `+`.
- F918: new _js_skip_ws_comments (block + line comments are
  tokenizer-whitespace, node-verified; unterminated block comments
  stop the skip and fail closed); used at the F888 dot-method site
  in _js_parse_postfix and the F802/F832 var-bound IIFE first-step
  sites. _js_span_braced (F509) skips comment spans so braces
  inside comments never affect the block structure; regex/division
  `/` still fails closed (documented boundary).
- F919: _js_parse_f872_sortzero_iife accepts the bare `A.sort();`
  statement: elements sorted by default UTF-16 order (Python
  sorted() on BMP-only strings; astral elements fail closed);
  indexed reads observe the sorted order.
- F920: _js_parse_f870_chain_value takes hops (2/1); the twin-1
  return site tries 2-hop then 1-hop with budget snapshot/restore
  on the first miss (F452). A single direct dispatch must be
  .bind + immediate invocation; .call/.apply single direct stays
  F614's (disjoint).

New findings filed: none.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed /var/tmp TMPDIRs), no in-repo git
in self-pins, concatenation-constructed credentials, pin 2143,
VERIFIER_TAXONOMY_PIN 33, $0-spend-by-construction.
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
_Z = "zzzzzzzzzzzz"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decodes_to(payload, want):
    return dlp._try_js_expr_decode_all(payload) == want


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_verifier_taxonomy_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    import re
    hits = []
    for root, _ds, fs in os.walk(os.path.join(REPO_ROOT, "evals")):
        for fn in fs:
            if fn.endswith(".py"):
                src = open(os.path.join(root, fn)).read()
                hits += re.findall(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src)
    ok = bool(hits) and all(h == "33" for h in hits)
    return ("HELD" if ok else "BREAK", "verifier-pin=%s" % (hits[:3]))


@_t
def test_p0_no_new_re_compile():
    """Zero new re.compile: count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_footer_state():
    """Control: merge footer (F917-F920 closed; open F921-F926, F928-F936; next F937)."""
    import re
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = False
    if foot:
        last = foot[-1]
        m = re.search(r"\*\*Open findings: ([^*]+)\.\*\*", last)
        open_list = m.group(1) if m else ""
        items = [x.strip() for x in open_list.split(",")]
        want = (["F%d" % n for n in range(921, 927)]
                + ["F%d" % n for n in range(928, 937)])
        ok = ("**F937**" in last
              and items == want
              and "# Wave-387 merge: F829-F892 CLOSED (64)" in last
              and "F893-F920 CLOSED (28)" in last)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f917_s1():
    """F917 filed shape: get ['m'+k]() blocks, decodes exact."""
    p = ("(function(){var k='2';var o={get ['m'+k](){return '%s';}};"
         "return o.m2+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f917_s2():
    """F917 filed shape: get [k+'2']() blocks, decodes exact."""
    p = ("(function(){var k='m';var o={get [k+'2'](){return '%s';}};"
         "return o.m2+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f918_s1():
    """F918 filed shape: a./*x*/flat() IIFE blocks, decodes exact."""
    p = ("(function(){var a=[['%s'],['%s']];"
         "return a./*x*/flat().join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f918_s2():
    """F918 filed shape: bare [[..]]./*x*/flat().join blocks exact."""
    p = "[['%s'],['%s']]./*x*/flat().join('')" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f919_s1b():
    """F919 shape: bare sort() statement, credential reassembles post-sort."""
    p = ("(function(){var a=['%s','%s'];a.sort();"
         "return a[0]+a[1];})()" % (_A, _Z))
    ok = _blocked(p) and _decodes_to(p, _A + _Z)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f919_s2():
    """F919 filed shape: bare sort() + reversed indexed reads blocks exact."""
    p = ("(function(){var a=['%s','%s'];a.sort();"
         "return a[1]+a[0];})()" % (_B, _A))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f919_filed_fragments_exact():
    """F919: filed fragment arrangement modeled node-exactly (hook-level)."""
    p = ("(function(){var a=['%s','%s'];a.sort();"
         "return a[0]+a[1];})()" % (_A, _B))
    r = dlp._js_parse_f872_sortzero_iife(p, 0, 0, {"parts": 0, "ops": 0})
    ok = r is not None and r[0] == _B + _A
    return ("HELD" if ok else "BREAK", "model-exact=%s" % ok)


@_t
def test_p1_f920_s1():
    """F920 filed shape: f.bind(null)() blocks, decodes exact."""
    p = ("(function(){function f(){return '%s';}return "
         "f.bind(null)()+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f920_s2():
    """F920 filed shape: f.bind(null,'f1')() blocks, decodes exact."""
    p = ("(function(){function f(a){return a;}return "
         "f.bind(null,'%s')()+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-exact)


@_t
def test_p2_f917_ws_tolerant():
    """F917: whitespace-tolerant mixed fold decodes exact."""
    p = ("(function(){var k='2';var o={get [ 'm' + k ](){return 'f1';}};"
         "return o.m2+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f917_two_idents():
    """F917: two bound identifiers fold, node-exact."""
    p = ("(function(){var k1='m';var k2='2';var o={get [k1+k2]()"
         "{return 'f1';}};return o.m2+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f917_three_operands():
    """F917: three-operand mixed fold, node-exact."""
    p = ("(function(){var k='m';var o={get [k+'2'+'x'](){return 'f1';}};"
         "return o.m2x+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f917_template_leading():
    """F917: template-leading mixed additive folds at the getter head."""
    st = {"parts": 0, "ops": 0}
    name, _j = dlp._js_parse_f535_getter_head(
        "[`m`+k]()", 0, pre_env={"k": "2"}, depth=0, state=st)
    ok = name == "m2"
    return ("HELD" if ok else "BREAK", "name=%s" % name)


@_t
def test_p2_f918_line_comment():
    """F918: line comment between . and method, node-exact."""
    p = ("(function(){var a=[['f1'],['f2']];return a.//x\n"
         "flat().join('');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f918_empty_comment():
    """F918: empty block comment, node-exact."""
    p = "[['f1'],['f2']]./**/flat().join('')"
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f918_comment_brace_span():
    """F918: braces inside comments never corrupt _js_span_braced."""
    p = ("(function(){var a=[['f1'],['f2']];/* } { */return "
         "a.flat().join('');})()")
    brace = p.index("{", p.index("function"))
    inner_start, inner_end, _after = dlp._js_span_braced(p, brace)
    body = p[inner_start:inner_end]
    # The span must cover the whole body: without comment-skipping,
    # the `}` inside the comment would terminate the span early.
    ok = body == ("var a=[['f1'],['f2']];/* } { */return "
                  "a.flat().join('');")
    return ("HELD" if ok else "BREAK", "span=%s" % ok)


@_t
def test_p2_f919_three_elem():
    """F919: 3-element bare sort with reordered reads, node-exact."""
    p = ("(function(){var a=['f2','f3','f1'];a.sort();"
         "return a[0]+a[1]+a[2];})()")
    ok = _decodes_to(p, "f1f2f3")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f919_ws_parens():
    """F919: whitespace inside sort parens, node-exact."""
    p = ("(function(){var a=['f1','f2'];a.sort( );"
         "return a[0]+a[1];})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f919_mixed_literals():
    """F919: return additive mixes literals and indexed reads."""
    p = ("(function(){var a=['b','a'];a.sort();"
         "return 'x'+a[0]+a[1];})()")
    ok = _decodes_to(p, "xab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f920_call_args():
    """F920: bound + invocation args accumulate, node-exact."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null,'f1')('f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f920_two_hops_still():
    """F920: F870 2-hop chain still decodes (no regression)."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null,'f1').bind(null)('f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f920_alias_still():
    """F920: F870 alias twin still decodes (no regression)."""
    p = ("(function(){function f(){return 'f1';}var g=f.bind(null);"
         "return g.bind(null)()+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f917_unbound_ident():
    """F917 bound: unbound identifier operand fails closed."""
    p = ("(function(){var k='2';var o={get ['m'+zz](){return 'f1';}};"
         "return o.m2+'f2';})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f917_unbound_head():
    """F917 bound: unbound computed getter name fails closed."""
    p = ("(function(){var k='2',j='3';var o={get [zz](){return 'f1';}};"
         "return o.m2+'f2';})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f918_unterminated_comment():
    """F918 bound: unterminated block comment fails closed."""
    p = "(function(){var a=[['f1'],['f2']];return a./*x.flat().join('');})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f918_regex_after_dot():
    """F918 bound: /x/ after dot is not a comment -- fails closed."""
    p = "(function(){var a=[['f1'],['f2']];return a./x/.flat().join('');})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f918_regex_in_body():
    """F918 bound: regex literal in IIFE body still fails closed."""
    p = "(function(){var r=/x/;return 'f1';})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f919_oor_index():
    """F919 bound: out-of-range indexed read fails closed."""
    p = "(function(){var a=['f1','f2'];a.sort();return a[5];})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f919_astral():
    """F919 bound: astral element fails closed (UTF-16/code-point diverge)."""
    p = "(function(){var a=['\\U0001F600','b'];a.sort();return a[0];})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f919_nonzero_cmp():
    """F919 bound: non-zero comparator in statement form fails closed."""
    p = "(function(){var a=['f1','f2'];a.sort(()=>1);return a[0]+a[1];})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f919_let_residual():
    """F919 bound: let-bound array is a documented residual (miss)."""
    p = "(function(){let a=['f1','f2'];a.sort();return a[0]+a[1];})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f920_no_invoke():
    """F920 bound: single bind without invocation fails closed."""
    p = ("(function(){function f(){return 'f1';}return "
         "f.bind(null)+'f2';})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f920_three_chain():
    """F920 bound: 3-dispatch chain still fails closed."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null).bind(null).bind(null)('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f920_arity_short():
    """F920 bound: fewer args than params fail closed."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null)('f1');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sib_f886_bound_ident():
    """Sibling: F886 bound-ident getter still blocks."""
    p = ("(function(){var k='m2';var o={get [k](){return '%s';}};"
         "return o.m2+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f886_pure_additive():
    """Sibling: F886 pure-additive getter still blocks."""
    p = ("(function(){var o={get ['m'+'2'](){return '%s';}};"
         "return o.m2+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f888_ws():
    """Sibling: F888 whitespace dot-method still blocks."""
    p = ("(function(){var a=[['%s'],['%s']];"
         "return a. flat().join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f802_flat():
    """Sibling: F802 var-bound flat IIFE still blocks."""
    p = ("(function(){var a=[['%s'],['%s']];"
         "return a.flat().join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f872_zero_stmt():
    """Sibling: F872 zero-comparator statement still blocks."""
    p = ("(function(){var a=['%s','%s'];a.sort(function(x,y){return 0;});"
         "return a[0]+a[1];})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f870_two_hop():
    """Sibling: F870 2-hop bind chain still blocks."""
    p = ("(function(){function f(){return '%s';}return "
         "f.bind(null).bind(null)()+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_bare_sort_expr():
    """Sibling: bare sort() expression still decodes."""
    p = "['f1','f2'].sort().join('')"
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_span_braced_strings():
    """Sibling: braces inside strings still span correctly."""
    p = "(function(){var s='}{';return s+'f1';})()"
    ok = _decodes_to(p, "}{f1")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p5: junk / honest quiet


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    honest = ("the sort comparator returns zero for equal elements and "
              "the bind chain applies arguments in order")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_comment_quiet():
    """Honest code comments stay quiet."""
    honest = "function f(){/* TODO: sort the rows */ return rows.sort();}"
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_getter_quiet():
    """Honest computed getter without credential stays quiet."""
    honest = ("(function(){var k='2';var o={get ['m'+k](){return 'ab';}};"
              "return o.m2+'cd';})()")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in <20s with zero hits."""
    sites = []
    for k in range(200):
        m = k % 4
        if m == 0:
            sites.append(
                "(function(){var k='2';var o={get ['m'+k](){return 'a%d';}};"
                "return o.m2+'b';})()" % k)
        elif m == 1:
            sites.append(
                "(function(){var a=[['a%d'],['b']];"
                "return a./*x*/flat().join('');})()" % k)
        elif m == 2:
            sites.append(
                "(function(){var a=['a%d','b'];a.sort();"
                "return a[0]+a[1];})()" % k)
        else:
            sites.append(
                "(function(){function f(){return 'a%d';}"
                "return f.bind(null)()+'b';})()" % k)
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
    # Red-firsts: this lane's four expect 0 BREAK; the parent
    # findings' red-firsts (F886/F888/F872/F870) expect 0 BREAK
    # (no regressions from the shared-code changes).
    for batt, expect_break in (
            ("evals/w388_f917_redfirst.py", 0),
            ("evals/w388_f918_redfirst.py", 0),
            ("evals/w388_f919_redfirst.py", 0),
            ("evals/w388_f920_redfirst.py", 0),
            ("evals/w387_f886_redfirst.py", 0),
            ("evals/w387_f888_redfirst.py", 0),
            ("evals/w387_f872_redfirst.py", 0),
            ("evals/w387_f870_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts at expected tallies."""
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
