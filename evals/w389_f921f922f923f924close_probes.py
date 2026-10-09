#!/usr/bin/env python3
"""Wave-389 lane 1: close F921 + F922 + F923 + F924 (JS laundering residuals).

F921 (LOW; wave-388 attack round 56): Function.prototype.bind partial
application -- F870 twin 2 models `var GNAME=NAME.bind(BT,ARGS);`
followed by a further .bind/.call/.apply dispatch, but a BARE call
`GNAME(...)` (bound args prepend call args) resolves node-exactly
while the decoder produced zero variants. Close-when: the decoder
models bind partial application node-exactly (or refuses the
laundering coded) such that find_credential flags them, honest text
unaffected.

F922 (LOW; wave-388 attack round 56): switch with a bound-identifier
discriminant -- the F655 switch sim parses literal-only
discriminants, so `var x=1;switch(x){...}` (incl. default-into-case
fallthrough) resolves node-exactly while the decoder produced zero
variants. Close-when: the decoder models switch statements with
identifier discriminants node-exactly (or refuses the laundering
coded) such that find_credential flags them, honest text unaffected.

F923 (LOW; wave-388 attack round 56): `??=` on null-initialized
bindings -- F748 models ??= only for declared-but-unassigned
bindings; `var s=null;s??='f1';...` resolves node-exactly while the
decoder produced zero variants. Close-when: the decoder models ??=
(and ||=, &&=) for every initializer form node-exactly (or refuses
the laundering coded) such that find_credential flags them, honest
text unaffected.

F924 (LOW; wave-388 attack round 56): labeled `continue LBL` from a
nested loop -- F784's labeled-for models a single loop, so
`outer:for(...){for(...){if(j===1)continue outer;...}}` resolves
node-exactly while the decoder produced zero variants. Close-when:
the decoder models labeled break/continue node-exactly (or refuses
the laundering coded) such that find_credential flags them, honest
text unaffected.

Fix (gov/dlp.py, zero new re.compile):
- F921: new _js_parse_f921_partial_call -- twin-2 return site
  branches on `(` (bare call, structurally disjoint from every
  dispatch head): prebound + call args fill params (F556 arity
  precedent: short fails closed, extras dropped).
- F922: _js_f655_top_stmt accepts integer-literal initializers
  (stored as int; every other env consumer fails closed on
  non-string values -- guards in _js_f655_sim_accum and
  _js_parse_f645_bound_operand); new _js_f922_switch_disc (literal
  first, then bound int/string ident) and _js_f922_sim_switch
  (F655 literal attempt first with F452 snapshot/restore).
- F923: new _JS_F748_NULL sentinel for `null` initializers --
  ??=/||= assign, &&= does not, += renders "null" (node-exact);
  const-rebinding still refuses coded; a null final value fails
  closed at the return substitution.
- F924: new _js_parse_f924_nested_for_iife (+ _js_f924_for_head,
  the F784 integer-counter discipline) -- decidable
  `if(C===K)/if(C!==K)continue LBL;` guards over nested loops,
  lazy ranges, total inner-body executions capped at
  _JS_F679_MAX_ITERS; hooked after F784 with snapshot/restore.

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
    """Pin stays 2143: the real registry count equals the expected pin."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK",
            "taxonomy=%d pin=%d" % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_p0_verifier_taxonomy_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (read from the real constant)."""
    import re
    src = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    hits = re.findall(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src)
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
    """Merged footer: F921-F936 closed; open F937-F948; next F949."""
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
        want = ["F%d" % n for n in range(937, 949)]
        ok = ("**F949**" in last
              and items == want
              and "F921-F936 CLOSED (15)" in last)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f921_s1():
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return g('%s');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f921-s1")


@_t
def test_p1_f921_s2_long():
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return g('%s');})()") % ("xox", "b-" + "0123456789abcdef0123456789abcdef012")
    return ("HELD" if _blocked(p) else "BREAK", "f921-s2-long")


@_t
def test_p1_f921_s3_3arg():
    p = ("(function(){function f(a,b,c){return a+b+c;}"
         "var g=f.bind(null,'%s','%s');return g('');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f921-s3-3arg")


@_t
def test_p1_f922_s1_fallthrough():
    p = ("(function(){var s='';var x=1;switch(x){case 1:s+='%s';"
         "case 2:s+='%s';break;default:}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f922-s1")


@_t
def test_p1_f922_s2_default_fall():
    p = ("(function(){var s='';var x=9;switch(x){case 1:s+='nope';"
         "break;default:s+='%s';case 2:s+='%s';}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f922-s2")


@_t
def test_p1_f922_s3_long():
    p = ("(function(){var s='';var x=9;switch(x){case 1:s+='nope';"
         "break;default:s+='%s';case 2:s+='%s';}return s;})()") % ("xox", "b-" + "0123456789abcdef0123456789abcdef012")
    return ("HELD" if _blocked(p) else "BREAK", "f922-s3-long")


@_t
def test_p1_f923_s1():
    p = ("(function(){var s=null;s??='%s';s+='%s';return s;})())") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f923-s1")


@_t
def test_p1_f923_s2_long():
    p = ("(function(){var s=null;s??='%s';s+='%s';return s;})())") % ("xox", "b-" + "0123456789abcdef0123456789abcdef012")
    return ("HELD" if _blocked(p) else "BREAK", "f923-s2-long")


@_t
def test_p1_f924_s1():
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f924-s1")


@_t
def test_p1_f924_s2_long():
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j===1)continue outer;s+='%s';}}"
         "return s+'%s';})()") % ("xox", "b-" + "0123456789abcdef0123456789abcdef012")
    return ("HELD" if _blocked(p) else "BREAK", "f924-s2-long")


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_f921_all_at_call():
    """Zero prebound args: var g=f.bind(null);return g('f1','f2')."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null);return g('%s','%s');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f921-all-at-call")


@_t
def test_p2_f921_all_prebound():
    """Empty call args: var g=f.bind(null,'f1','f2');return g()."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s','%s');return g();})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f921-all-prebound")


@_t
def test_p2_f921_extra_call_args_dropped():
    """Extra call args dropped engine-exactly."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return g('%s','junk');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f921-extra-dropped")


@_t
def test_p2_f922_string_discriminant():
    """String binding as discriminant (fallthrough yields full credential)."""
    p = ("(function(){var s='';var x='a';switch(x){case 'a':s+='%s';"
         "case 'b':s+='%s';break;default:s+='nope';}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f922-string-disc")


@_t
def test_p2_f922_large_int():
    """Larger integer discriminant."""
    p = ("(function(){var s='';var x=42;switch(x){case 42:s+='%s';"
         "case 43:s+='%s';break;default:}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f922-large-int")


@_t
def test_p2_f922_no_match_no_default():
    """No match and no default: accumulator untouched (decode-exact)."""
    p = ("(function(){var s='';var x=9;switch(x){case 1:s+='nope';"
         "break;}return s+'%s';})()") % (_B,)
    return ("HELD" if _decodes_to(p, _B) else "BREAK", "f922-no-match")


@_t
def test_p2_f923_or_assign_null():
    """||= assigns on null (falsy)."""
    p = ("(function(){var s=null;s||='%s';s+='%s';return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f923-or-null")


@_t
def test_p2_f923_and_assign_null_miss():
    """&&= does NOT assign on null (falsy) -- stays missed."""
    p = ("(function(){var s=null;s&&='%s';return s;})()") % (_A,)
    return ("HELD" if _misses(p) else "BREAK", "f923-and-null-miss")


@_t
def test_p2_f923_plus_null_exact():
    """+= on null renders 'null' node-exactly (decodes, not a credential)."""
    p = "(function(){var s=null;s+='f1';return s;})()"
    return ("HELD" if _decodes_to(p, "nullf1") else "BREAK",
            "f923-plus-null")


@_t
def test_p2_f924_neq_guard():
    """!== guard variant (two accums for the full credential)."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<2;j++){if(j!==0)continue outer;"
         "s+='%s';s+='%s';}}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f924-neq")


@_t
def test_p2_f924_outer_counter_guard():
    """Guard on the outer counter."""
    p = ("(function(){var s='';outer:for(var i=0;i<2;i++){"
         "for(var j=0;j<2;j++){if(i===0)continue outer;s+='%s';}}"
         "return s;})()") % (_A,)
    return ("HELD" if _blocked(p) else "BREAK", "f924-outer-guard")


@_t
def test_p2_f924_le_bounds():
    """<= bounds on both loops."""
    p = ("(function(){var s='';outer:for(var i=0;i<=1;i++){"
         "for(var j=0;j<=2;j++){if(j===2)continue outer;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f924-le")


@_t
def test_p2_f924_multi_accum():
    """Two accumulations per inner iteration."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<2;j++){if(j===1)continue outer;"
         "s+='%s';s+='%s';}}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "f924-multi-accum")


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f921_arity_short():
    """Fewer total args than params: engine coerces undefined -- miss."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return g();})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f921-arity-short")


@_t
def test_p3_f921_nonliteral_call_arg():
    """Non-literal call arg: miss."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return g(x);})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f921-nonlit")


@_t
def test_p3_f921_no_call():
    """Bound function with no call is not a decodable value: miss."""
    p = ("(function(){function f(a,b){return a+b;}"
         "var g=f.bind(null,'%s');return '%s';})()") % (_A, _B)
    return ("HELD" if _misses(p) else "BREAK", "f921-no-call-quiet")


@_t
def test_p3_f922_negative_label():
    """Negative case label: _js_parse_number is non-negative --
    documented residual, miss."""
    p = ("(function(){var s='';var x=-1;switch(x){case -1:s+='%s';"
         "break;default:}return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-neg-label")


@_t
def test_p3_f922_fractional_init():
    """Fractional initializer: miss."""
    p = ("(function(){var s='';var x=1.5;switch(x){case 1:s+='%s';"
         "}return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-frac")


@_t
def test_p3_f922_unbound_disc():
    """Unbound discriminant ident: miss."""
    p = ("(function(){var s='';switch(x){case 1:s+='%s';"
         "}return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-unbound")


@_t
def test_p3_f922_ident_label():
    """Identifier case label is a node-evaluated expression: miss."""
    p = ("(function(){var s='';var x=1;var y=1;switch(x){case y:s+='%s';"
         "}return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-ident-label")


@_t
def test_p3_f922_dup_default():
    """Duplicate default is a node SyntaxError: miss."""
    p = ("(function(){var s='';var x=9;switch(x){default:s+='a';"
         "default:s+='b';}return s;})()")
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-dup-default")


@_t
def test_p3_f922_accum_into_int():
    """Accumulation into an integer binding: miss (discriminant-only)."""
    p = ("(function(){var s='';var x=1;x+='a';switch(x){case 1:s+='%s';"
         "}return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f922-accum-int")


@_t
def test_p3_f923_int_initializer():
    """Integer initializer still fails closed (documented bound)."""
    p = ("(function(){var s=0;s||='%s';return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f923-int-init")


@_t
def test_p3_f923_const_null():
    """const null + ??= is an engine TypeError: miss."""
    p = ("(function(){const s=null;s??='%s';return s;})()") % (_A,)
    return ("HELD" if _fails_closed(p) else "BREAK", "f923-const")


@_t
def test_p3_f924_break_not_continue():
    """break in the guard position: outside the modeled subset."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j===1)break outer;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _fails_closed(p) else "BREAK", "f924-break")


@_t
def test_p3_f924_unlabeled_continue():
    """Unlabeled continue: outside the modeled subset."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j===1)continue;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _fails_closed(p) else "BREAK", "f924-unlabeled")


@_t
def test_p3_f924_wrong_label():
    """continue for an unknown label is a node SyntaxError: miss."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j===1)continue nope;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _fails_closed(p) else "BREAK", "f924-wrong-label")


@_t
def test_p3_f924_too_many_iters():
    """Iteration cap: 100x100 inner-body executions fail closed."""
    p = ("(function(){var s='';outer:for(var i=0;i<100;i++){"
         "for(var j=0;j<100;j++){if(j===99)continue outer;s+='a';}}"
         "return s;})()")
    return ("HELD" if _fails_closed(p) else "BREAK", "f924-iter-cap")


@_t
def test_p3_f924_loose_eq_guard():
    """== guard (not ===): outside the modeled subset."""
    p = ("(function(){var s='';outer:for(var i=0;i<1;i++){"
         "for(var j=0;j<3;j++){if(j==1)continue outer;s+='%s';}}"
         "return s+'%s';})()") % (_A, _B)
    return ("HELD" if _fails_closed(p) else "BREAK", "f924-loose-eq")


# ------------------------------------------------ p4: sibling pins


@_t
def test_p4_sib_f870_two_hop():
    """F870 two-dispatch chain still blocks."""
    p = ("(function(){function f(a,b){return a+b;}"
         "return f.bind(null).bind(null,'%s')('%s');})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f870")


@_t
def test_p4_sib_f920_single_bind():
    """F920 single direct bind still blocks."""
    p = ("(function(){function f(a){return a;}"
         "return f.bind(null,'%s')()+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f920")


@_t
def test_p4_sib_f748_undef_init():
    """F748 declared-but-unassigned ??= still blocks."""
    p = ("(function(){var s;s??='%s';s+='%s';return s;})())") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f748")


@_t
def test_p4_sib_f655_literal_switch():
    """F655 literal-discriminant switch still blocks."""
    p = ("(function(){var s='';switch(1){case 1:s+='%s';case 2:s+='%s';"
         "break;default:}return s;})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f655")


@_t
def test_p4_sib_f784_labeled_for():
    """F784 single labeled-for still blocks."""
    p = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';"
         "continue outer;r+='xx';}return r+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f784")


@_t
def test_p4_sib_f747_qq_chain():
    """F747 ?? chain still blocks."""
    p = ("(function(){var o={};return (o.x??'%s')+'%s';})()") % (_A, _B)
    return ("HELD" if _blocked(p) else "BREAK", "sib-f747")


# ------------------------------------------------ p5: honest text


@_t
def test_p5_junk_quiet():
    p = "'(function(){var s=\\'ab\\';return s;})()'"
    return ("HELD" if _misses(p) else "BREAK", "junk-quiet")


@_t
def test_p5_honest_quiet():
    p = "the quarterly report is attached for review"
    return ("HELD" if _misses(p) else "BREAK", "honest-quiet")


@_t
def test_p5_honest_switch_quiet():
    p = ("(function(){var s='';var x=2;switch(x){case 1:s+='a';"
         "break;default:s+='b';}return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "honest-switch-quiet")


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 decode sites stay fast."""
    sites = []
    for k in range(200):
        sites.append(
            ("(function(){function f(a,b){return a+b;}"
             "var g=f.bind(null,'x%d');return g('y');})()") % k)
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "perf=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # This lane's red-firsts expect 0 BREAK; the parent findings'
    # red-firsts (F870/F748/F655/F784) expect 0 BREAK (no
    # regressions from the shared-code changes); the new F948
    # red-first expects 2 BREAK (filed open this lane; renumbered
    # F937->F948 at the wave-389 merge, wave-272 rule).
    for batt, expect_break in (
            ("evals/w388_f921_redfirst.py", 0),
            ("evals/w388_f922_redfirst.py", 0),
            ("evals/w388_f923_redfirst.py", 0),
            ("evals/w388_f924_redfirst.py", 0),
            ("evals/w389_f948_redfirst.py", 2),
            ("evals/w387_f870_redfirst.py", 0),
            ("evals/w383_f748_redfirst.py", 0),
            ("evals/w377_f655_redfirst.py", 0),
            ("evals/w384_f784_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g389-green-", dir="/var/tmp")
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
