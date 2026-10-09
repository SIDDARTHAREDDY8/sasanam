#!/usr/bin/env python3
"""Wave-387 lane 11: close F869 + F870 + F871 + F872 (call/apply/bind/sort laundering).

F869 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54):
builtin method borrowing -- the decoder models `.call` on user
functions (F614) but not builtin borrowing:
`Array.prototype.slice.call(arguments)` and
`String.prototype.split.call(s,',')` resolve node-exactly while the
decoder produces zero variants.

F870 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54):
bind chains on named function declarations --
`f.bind(null).bind(null)()` resolves node-exactly while the decoder
produces zero variants.

F871 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54):
apply with the arguments object -- `g.apply(null,arguments)`
resolves node-exactly while the decoder produces zero variants.

F872 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54):
sort with comparator -- `['f1','f2'].sort(()=>0)` resolves
node-exactly while the decoder produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F869: (a) "split" joins _F478_STRING_METHODS (F478 desugar +
  node-exact F564 split production, limit-arg included); (b) new
  statement hook _js_parse_f869_slicecall_iife for
  `(function(){function NAME(){return
  Array.prototype.slice.call(arguments).join('SEP');}return ADD;})()`
  (zero declared params, exact dot chain, bare `arguments`, literal
  separator, literal call args).
- F870: new statement hook _js_parse_f870_bindchain_iife --
  `f.bind(BT).bind(BT)(ARGS)` / `.call` / `.apply` chains (exactly 2
  dispatches; first must be .bind) and the `var g=f.bind(BT);`
  alias twin; bound args accumulate, arity enforced (F556
  precedent), thisArgs parsed+discarded (F636 precedent).
- F871: new statement hook _js_parse_f871_applyargs_iife --
  `function F(...){return G.apply(BT,arguments);}` +
  `function G(Qs){return ADD;}` + `return F(LITS);`; arguments
  bound to the call-site literals, applied to G's params.
- F872: (a) the expression-level `sort` production accepts the
  constant-zero comparator (function/arrow/block-arrow) as the
  identity (V8 stable sort + all-equal comparisons provably
  preserve order; every other comparator still fails closed);
  (b) new statement hook _js_parse_f872_sortzero_iife for
  `var A=[LITS];A.sort(ZEROCMP);return ADD;` with in-range
  indexed reads.

New findings filed: F893 (bare sort() statement form:
`var a=['f1','f2'];a.sort();return a[0]+a[1]` misses), F894
(single .bind on a named function declaration:
`f.bind(null)()` misses) -- 2026-10-09 07:21 UTC (exact timestamps
in ~/workspace/teams/wave387-f869f870f871f872close/REPORT.md). Filing erratum: the filed s2 twins of F869/F870/F872
carry a trailing `)` typo and are SyntaxErrors in node v24.20.0;
the lane closes the node-valid (balanced) twins.

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
def test_p0_no_new_re_compile():
    """Zero new re.compile: count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F869-F872 closed; new F893/F894
    open; open F829-F868, F873-F894; next F895)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    open_list = ("F829, F830, F831, F832, F833, F834, F835, F836, F837, "
                 "F838, F839, F840, F841, F842, F843, F844, F845, F846, "
                 "F847, F848, F849, F850, F851, F852, F853, F854, F855, "
                 "F856, F857, F858, F859, F860, F861, F862, F863, F864, "
                 "F865, F866, F867, F868, F873, F874, F875, F876, F877, "
                 "F878, F879, F880, F881, F882, F883, F884, F885, F886, "
                 "F887, F888, F889, F890, F891, F892, F893, F894.")
    footer = text.split("Open findings:")[1].split(".")[0]
    ok = ("Next free finding: **F895**" in text
          and "Open findings: " + open_list in text
          and ", F869," not in footer and ", F870," not in footer
          and ", F871," not in footer and ", F872," not in footer)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f869_s1():
    """F869 filed shape: slice.call(arguments).join('') blocks exact."""
    p = ("(function(){function f(){return Array.prototype.slice.call"
         "(arguments).join('');}return f('%s','%s');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f869_s2():
    """F869 filed shape (balanced twin): split.call(s,',') blocks exact."""
    p = ("(function(){return String.prototype.split.call('%s,%s',',')"
         ".join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f870_s1():
    """F870 filed shape: f.bind(null).bind(null)() blocks exact."""
    p = ("(function(){function f(){return '%s';}return "
         "f.bind(null).bind(null)()+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f870_s2():
    """F870 filed shape (balanced twin): var g=f.bind alias blocks exact."""
    p = ("(function(){function f(){return '%s';}var g=f.bind(null);"
         "return g.bind(null)()+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f871_s1():
    """F871 filed shape: g.apply(null,arguments) blocks exact."""
    p = ("(function(){function f(){return g.apply(null,arguments);}"
         "function g(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f871_s2():
    """F871 twin: reversed params (b+a) with swapped call args blocks exact."""
    p = ("(function(){function f(){return g.apply(null,arguments);}"
         "function g(a,b){return b+a;}return f('%s','%s');})()" % (_B, _A))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f872_s1():
    """F872 filed shape: statement sort(zero-cmp) + indexed reads exact."""
    p = ("(function(){var a=['%s','%s'];a.sort(function(x,y){return 0;});"
         "return a[0]+a[1];})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f872_s2():
    """F872 filed shape (balanced twin): expr sort(zero-cmp).join blocks."""
    p = ("(function(){return ['%s','%s'].sort(function(){return 0;})"
         ".join('');})()" % (_A, _B))
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-exact)


@_t
def test_p2_f869_join_sep():
    """F869: literal join separator decodes node-exactly."""
    p = ("(function(){function f(){return Array.prototype.slice.call"
         "(arguments).join(',');}return f('f1','f2');})()")
    ok = _decodes_to(p, "f1,f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f869_bracket_call():
    """F869: F482 bracket-string ['call'] twin decodes node-exactly."""
    p = ("(function(){function f(){return Array.prototype.slice['call']"
         "(arguments).join('');}return f('f1','f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f869_split_limit():
    """F869: split.call with limit arg decodes node-exactly (F564)."""
    p = ("(function(){return String.prototype.split.call('f1,f2',',',1)"
         ".join('');})()")
    ok = _decodes_to(p, "f1")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f870_bind_args():
    """F870: bound args accumulate across the chain, node-exact."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null,'f1').bind(null)('f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f870_call_terminal():
    """F870: .call terminal after .bind decodes node-exactly."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null).call(null,'f1','f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f870_apply_terminal():
    """F870: .apply terminal after .bind decodes node-exactly."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null).apply(null,['f1','f2']);})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f870_twin2_bindargs():
    """F870 twin 2: alias bind carries args, node-exact."""
    p = ("(function(){function f(a,b){return a+b;}var g=f.bind(null,'f1');"
         "return g.bind(null)('f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f870_optchain_twins():
    """F870: F490 ?.-chain twin decodes node-exactly."""
    p = ("(function(){function f(){return 'f1';}return "
         "f?.bind(null)?.bind(null)()+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f871_extra_callargs():
    """F871: extra call args dropped engine-exactly."""
    p = ("(function(){function f(){return g.apply(null,arguments);}"
         "function g(a,b){return a+b;}return f('f1','f2','f3');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f872_three_elem():
    """F872: 3-element zero-sort with reordered indexed reads, exact."""
    p = ("(function(){var a=['f1','f2','f3'];a.sort(()=>0);"
         "return a[2]+a[0]+a[1];})()")
    ok = _decodes_to(p, "f3f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f872_block_arrow():
    """F872: block-bodied zero arrow comparator, node-exact."""
    p = ("(function(){var a=['f1','f2'];a.sort(()=>{return 0;});"
         "return a[0]+a[1];})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f872_expr_zero_arrow():
    """F872: expression sort(()=>0).join, node-exact."""
    p = "['f1','f2'].sort(()=>0).join('')"
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f872_named_fn_cmp():
    """F872: named function zero comparator, node-exact."""
    p = "['f1','f2'].sort(function cmp(x,y){return 0;}).join('')"
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f869_declared_params():
    """F869 bound: declared params alongside arguments fail closed."""
    p = ("(function(){function f(a){return Array.prototype.slice.call"
         "(arguments).join('');}return f('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f869_extra_slice_arg():
    """F869 bound: extra slice arg fails closed (would decode f2)."""
    p = ("(function(){function f(){return Array.prototype.slice.call"
         "(arguments,1).join('');}return f('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f869_regex_sep():
    """F869 bound: regex split separator fails closed (F564 boundary)."""
    p = ("(function(){return String.prototype.split.call('f1,f2',/,/)"
         ".join('');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f870_three_chain():
    """F870 bound: 3-dispatch chain fails closed (documented residual)."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null).bind(null).bind(null)('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f870_arity_short():
    """F870 bound: fewer args than params fail closed (undefined slot)."""
    p = ("(function(){function f(a,b){return a+b;}return "
         "f.bind(null).bind(null)('f1');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f870_no_invoke():
    """F870 bound: chain without invocation parens fails closed."""
    p = ("(function(){function f(){return 'f1';}return "
         "f.bind(null).bind(null)+'f2';})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f870_call_first():
    """F870 bound: leading .call (immediate invoke) fails closed."""
    p = ("(function(){function f(){return 'f1';}return "
         "f.call(null).bind(null)()+'f2';})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f871_g_first():
    """F871 bound: G declared before F fails closed (filed order only)."""
    p = ("(function(){function g(a,b){return a+b;}"
         "function f(){return g.apply(null,arguments);}"
         "return f('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f871_apply_extra_arg():
    """F871 bound: apply 3rd arg fails closed (engine ignores it)."""
    p = ("(function(){function f(){return g.apply(null,arguments,[]);}"
         "function g(a,b){return a+b;}return f('f1','f2');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f871_indexed_arguments():
    """F871 bound: indexed arguments[i] fails closed (F809 owns it)."""
    p = ("(function(){function f(){return g.apply(null,arguments[0]);}"
         "function g(a){return a;}return f('f1');})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f872_desc_cmp():
    """F872 bound: genuine reordering comparator fails closed."""
    p = ("(function(){var a=['f1','f2'];"
         "a.sort(function(x,y){return y.localeCompare(x);});"
         "return a[0]+a[1];})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f872_nonzero_const():
    """F872 bound: non-zero constant comparator fails closed."""
    p = "['f1','f2'].sort(()=>1).join('')"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f872_oor_index():
    """F872 bound: out-of-range indexed read fails closed."""
    p = ("(function(){var a=['f1','f2'];a.sort(()=>0);return a[5];})()")
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f872_bare_sort_stmt():
    """F872 bound: bare sort() statement form fails closed (F893)."""
    p = "(function(){var a=['f1','f2'];a.sort();return a[0]+a[1];})()"
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sib_f614_call():
    """Sibling: F614 arrow .call still blocks."""
    p = "((a,b)=>a+b).call(null,'%s','%s')" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f636_chain():
    """Sibling: F636 paren-fn bind-bind chain still blocks."""
    p = "((a)=>(a+'%s')).bind(null,'%s').bind(null)()" % (_B, _A)
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f478_concat():
    """Sibling: F478 String.prototype.concat.call still decodes."""
    p = ("(function(){return String.prototype.concat.call('f1','f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f564_split():
    """Sibling: F564 direct 'f1,f2'.split(',') still decodes."""
    p = "(function(){return 'f1,f2'.split(',').join('');})()"
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f580_sort():
    """Sibling: F580 length-comparator sort still decodes."""
    p = "['f2','f1'].sort((a,b)=>a.length-b.length).join('')"
    ok = _decodes_to(p, "f2f1")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f604_sort():
    """Sibling: F604 localeCompare-desc sort still decodes."""
    p = "['f1','f2'].sort((a,b)=>b.localeCompare(a)).join('')"
    ok = _decodes_to(p, "f2f1")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f809_args():
    """Sibling: F809 indexed arguments still decodes."""
    p = ("(function(){function f(){return arguments[0]+arguments[1];}"
         "return f('f1','f2');})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f810_chain():
    """Sibling: F810 method chain still decodes."""
    p = ("(function(){var o={a:function(){return this;},"
         "b:function(){return 'f1';}};return o.a().b()+'f2';})()")
    ok = _decodes_to(p, "f1f2")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_bare_sort_expr():
    """Sibling: bare sort() expression still decodes."""
    p = "['f1','f2'].sort().join('')"
    ok = _decodes_to(p, "f1f2")
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
def test_p5_honest_code_quiet():
    """Honest code with sort/bind stays quiet."""
    honest = "function sortRows(rows){return rows.sort((a,b)=>a-b);}"
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
                "(function(){function f(){return Array.prototype.slice.call"
                "(arguments).join('');}return f('a%d','b');})()" % k)
        elif m == 1:
            sites.append(
                "(function(){function f(){return 'a%d';}"
                "return f.bind(null).bind(null)()+'b';})()" % k)
        elif m == 2:
            sites.append(
                "(function(){var a=['a%d','b'];a.sort(()=>0);"
                "return a[0]+a[1];})()" % k)
        else:
            sites.append(
                "(function(){function f(){return g.apply(null,arguments);}"
                "function g(x,y){return x+y;}return f('a%d','b');})()" % k)
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
    # Red-firsts: the four closed findings expect 0 BREAK; the two
    # newly-filed findings (F893/F894) expect 2 BREAK (open by design).
    for batt, expect_break in (
            ("evals/w387_f869_redfirst.py", 0),
            ("evals/w387_f870_redfirst.py", 0),
            ("evals/w387_f871_redfirst.py", 0),
            ("evals/w387_f872_redfirst.py", 0),
            ("evals/w387_f893_redfirst.py", 2),
            ("evals/w387_f894_redfirst.py", 2)):
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
