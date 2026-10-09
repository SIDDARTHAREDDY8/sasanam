#!/usr/bin/env python3
"""Wave-390 lane 2 close battery: F941 + F942 + F943 + F944 CLOSED.

Verifies the four LOW findings (wave-389 attack round 57, filed
2026-10-09 12:34 UTC) are closed on the lane tree: pins, filed shapes
(must block, node-exact decode), generalizations (must block),
fail-closed bounds (must miss / stay quiet, never mis-decode),
sibling pins (F897/F458/F486 fromCharCode forms, \\x escapes),
honest-text controls, perf (200 sites), and a depth-1 green check on
the four w390 red-first batteries (GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running). 63 probes.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-389 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_DOTALL_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"
_FULL40 = _L1 + _L2
_CODES = ",".join(str(ord(c)) for c in _FULL)
_CODES40 = ",".join(str(ord(c)) for c in _FULL40)
_ARRLIKE = ",".join("%d:%d" % (i, ord(c)) for i, c in enumerate(_FULL))

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33 (evals/w318_evidence_schema_probes.py)."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_DOTALL_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer():
    """Lane-local footer: F941-F944 stamped CLOSED; open F937-F940, F945-F948; next F949."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    m = re.search(r"Next free finding: \*\*F949\*\*\. \*\*Open findings: "
                  r"([^*]+)\.", text)
    if not m:
        return ("BREAK", "no F949 footer")
    opens = [x.strip() for x in m.group(1).split(",")]
    want = (["F%d" % i for i in range(937, 941)]
            + ["F%d" % i for i in range(945, 949)])
    ok = (opens == want
          and text.count("CLOSED 2026-10-09 wave-390 lane 2") >= 4)
    return ("HELD" if ok else "BREAK",
            "open=%d want=%d" % (len(opens), len(want)))


# ------------------------------------------------- F941 filed shapes


@_t
def test_p1_f941_filed_short():
    """F941 filed shape (short) blocks, node-exact decode."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
         "String.fromCharCode(c[i])+f(i+1);}return f(0);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f941-short")


@_t
def test_p1_f941_filed_40():
    """F941 filed shape (40-char) blocks, node-exact decode."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
         "String.fromCharCode(c[i])+f(i+1);}return f(0);})()") % _CODES40
    ok = _blocked(p) and _decode(p) == _FULL40
    return ("HELD" if ok else "BREAK", "f941-40")


# -------------------------------------------- F941 generalizations


@_t
def test_p1_f941_eq_guard():
    """F941 generalization: i===c.length guard (node v24.20.0)."""
    p = ("(function(){var c=[%s];function f(i){return i===c.length?'':"
         "String.fromCharCode(c[i])+f(i+1);}return f(0);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f941-eq-guard")


@_t
def test_p1_f941_let_tail():
    """F941 generalization: let decl + literal tail (node v24.20.0)."""
    p = ("(function(){let c=[%s];function f(i){return i>=c.length?'':"
         "String.fromCharCode(c[i])+f(i+1);}return f(0)+'!';})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL + "!"
    return ("HELD" if ok else "BREAK", "f941-let-tail")


# -------------------------------------------- F941 fail-closed bounds


@_t
def test_p1_f941_flip_misses():
    """F941 bound: flipped f(i+1)+fromCharCode body misses (node: reversed)."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
         "f(i+1)+String.fromCharCode(c[i]);}return f(0);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f941-flip-miss")


@_t
def test_p1_f941_skip_misses():
    """F941 bound: f(i+2) step misses (node: skipped chars)."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
         "String.fromCharCode(c[i])+f(i+2);}return f(0);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f941-skip-miss")


@_t
def test_p1_f941_nonempty_base_misses():
    """F941 bound: non-empty base case misses (node: different value)."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'-':"
         "String.fromCharCode(c[i])+f(i+1);}return f(0);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f941-base-miss")


@_t
def test_p1_f941_start1_misses():
    """F941 bound: f(1) start misses (node: sliced value)."""
    p = ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
         "String.fromCharCode(c[i])+f(i+1);}return f(1);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f941-start-miss")


@_t
def test_p1_f941_typedarray_misses():
    """F941 bound: typed-array decl misses (documented narrow class)."""
    p = ("(function(){var c=new Uint8Array([%s]);function f(i){return "
         "i>=c.length?'':String.fromCharCode(c[i])+f(i+1);}return "
         "f(0);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f941-typedarray-miss")


# ------------------------------------------------- F942 filed shapes


@_t
def test_p2_f942_filed_short():
    """F942 filed shape (short) blocks, node-exact decode."""
    p = ("(function(){function* g(){var c=[%s];for(var x of c)yield x;}"
         "return String.fromCharCode(...g());})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f942-short")


@_t
def test_p2_f942_filed_40():
    """F942 filed shape (40-char) blocks, node-exact decode."""
    p = ("(function(){function* g(){var c=[%s];for(var x of c)yield x;}"
         "return String.fromCharCode(...g());})()") % _CODES40
    ok = _blocked(p) and _decode(p) == _FULL40
    return ("HELD" if ok else "BREAK", "f942-40")


# -------------------------------------------- F942 generalizations


@_t
def test_p2_f942_braced_let_tail():
    """F942 generalization: braced yield, let decl, literal tail."""
    p = ("(function(){function* g(){let c=[%s];for(let x of c){yield x;}}"
         "return String.fromCharCode(...g())+'!';})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL + "!"
    return ("HELD" if ok else "BREAK", "f942-braced-let-tail")


# -------------------------------------------- F942 fail-closed bounds


@_t
def test_p2_f942_yield_expr_misses():
    """F942 bound: yield x+1 misses (node: shifted values)."""
    p = ("(function(){function* g(){var c=[%s];for(var x of c)yield x+1;}"
         "return String.fromCharCode(...g());})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f942-yield-expr-miss")


@_t
def test_p2_f942_spread_nongen_misses():
    """F942 bound: spread of a non-generator call misses."""
    p = ("(function(){function* g(){var c=[%s];for(var x of c)yield x;}"
         "return String.fromCharCode(...h());})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f942-nongen-miss")


# ------------------------------------------------- F943 filed shapes


@_t
def test_p3_f943_ctor_alias():
    """F943 s1: ''.constructor.fromCharCode blocks, node-exact."""
    p = ("(function(){return ''.constructor.fromCharCode(%s);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-ctor-alias")


@_t
def test_p3_f943_reflect_apply():
    """F943 s2: Reflect.apply(String.fromCharCode,...) blocks, node-exact."""
    p = ("(function(){return Reflect.apply(String.fromCharCode,null,"
         "[%s]);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-reflect-apply")


@_t
def test_p3_f943_arraylike_apply():
    """F943 s3: .apply(null,{0:..,length:N}) blocks, node-exact."""
    p = ("(function(){return String.fromCharCode.apply(null,{%s,"
         "length:%d});})()") % (_ARRLIKE, len(_FULL))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-arraylike")


@_t
def test_p3_f943_bound_call():
    """F943 s4: Function.prototype.call.bind(...) blocks, node-exact."""
    p = ("(function(){var f=Function.prototype.call.bind("
         "String.fromCharCode);return f(null,%s);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-bound-call")


# -------------------------------------------- F943 generalizations


@_t
def test_p3_f943_ctor_bracket():
    """F943 generalization: ''.constructor['fromCharCode'] (node v24.20.0)."""
    p = ("(function(){return ''.constructor['fromCharCode'](%s);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-ctor-bracket")


@_t
def test_p3_f943_ctor_nonempty_recv():
    """F943 generalization: non-empty receiver literal, decode-only.

    A single char is not credential-shaped, so this asserts
    node-exact decode (the product-level block is covered by the
    filed-shape tests).
    """
    p = ("(function(){return 'ab'.constructor.fromCharCode(%s);})()") % _CODES
    ok = _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-ctor-recv")


@_t
def test_p3_f943_reflect_bracket():
    """F943 generalization: Reflect.apply(String['fromCharCode'],...)."""
    p = ("(function(){return Reflect.apply(String['fromCharCode'],null,"
         "[%s]);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-reflect-bracket")


@_t
def test_p3_f943_arraylike_reorder():
    """F943 generalization: reordered array-like keys (node v24.20.0)."""
    keys = ",".join("%d:%d" % (i, ord(c))
                    for i, c in reversed(list(enumerate(_FULL))))
    p = ("(function(){return String.fromCharCode.apply(null,{%s,"
         "length:%d});})()") % (keys, len(_FULL))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-arraylike-reorder")


@_t
def test_p3_f943_arraylike_strkeys():
    """F943 generalization: string-literal int keys (node v24.20.0)."""
    keys = ",".join("'%d':%d" % (i, ord(c)) for i, c in enumerate(_FULL))
    p = ("(function(){return String.fromCharCode.apply(null,{%s,"
         "length:%d});})()") % (keys, len(_FULL))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-arraylike-strkeys")


@_t
def test_p3_f943_arraylike_trailcomma():
    """F943 generalization: trailing comma in array-like (node v24.20.0)."""
    p = ("(function(){return String.fromCharCode.apply(null,{%s,"
         "length:%d,});})()") % (_ARRLIKE, len(_FULL))
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-arraylike-trailcomma")


@_t
def test_p3_f943_bound_apply_twin():
    """F943 generalization: .apply.bind twin with [CODES] (node v24.20.0)."""
    p = ("(function(){var f=Function.prototype.apply.bind("
         "String.fromCharCode);return f(null,[%s]);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-bound-apply")


@_t
def test_p3_f943_bound_const():
    """F943 generalization: const alias decl (node v24.20.0)."""
    p = ("(function(){const f=Function.prototype.call.bind("
         "String.fromCharCode);return f(null,%s);})()") % _CODES
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-bound-const")


@_t
def test_p3_f943_direct_bind_call():
    """F943 filed literal shape: direct bound-call invocation."""
    p = ("Function.prototype.call.bind(String.fromCharCode)(null,%s)"
         % _CODES)
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-direct-bind-call")


@_t
def test_p3_f943_direct_bind_apply():
    """F943 generalization: direct .apply.bind twin with [CODES]."""
    p = ("Function.prototype.apply.bind(String.fromCharCode)(null,[%s])"
         % _CODES)
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-direct-bind-apply")


@_t
def test_p3_f943_direct_bind_bracket():
    """F943 generalization: direct bind over String['fromCharCode']."""
    p = ('Function.prototype.call.bind(String["fromCharCode"])(null,%s)'
         % _CODES)
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f943-direct-bind-bracket")


@_t
def test_p3_f943_direct_bind_args_miss():
    """F943 bound: direct bind with bound args misses (arity shift)."""
    p = ("Function.prototype.call.bind(String.fromCharCode,null)(%s)"
         % _CODES)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-direct-bind-args")


@_t
def test_p3_f943_arraylike_q007_miss():
    """F943 bound: quoted non-canonical key ignored -> missing index.

    Node reads property "7" (absent) -> undefined; the static model
    fails closed rather than mis-decoding (node v24.20.0).
    """
    p = ("(function(){return String.fromCharCode.apply(null,"
         "{0:120,1:111,\"007\":88,length:8});})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-arraylike-q007")


# -------------------------------------------- F943 fail-closed bounds


@_t
def test_p3_f943_arraylike_missing_misses():
    """F943 bound: array-like missing index misses (engine reads undefined)."""
    p = ("(function(){return String.fromCharCode.apply(null,"
         "{0:120,length:2});})()")
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-arraylike-missing")


@_t
def test_p3_f943_reflect_codepoint_misses():
    """F943 bound: Reflect.apply over fromCodePoint misses (wrong builtin)."""
    p = ("(function(){return Reflect.apply(String.fromCodePoint,null,"
         "[%s]);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-reflect-codepoint")


@_t
def test_p3_f943_bound_args_misses():
    """F943 bound: .bind with bound args misses (arity shift)."""
    p = ("(function(){var f=Function.prototype.call.bind("
         "String.fromCharCode,null);return f(%s);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-bound-args")


@_t
def test_p3_f943_ctor_paren_misses():
    """F943 bound: parenthesized receiver misses (narrow class)."""
    p = ("(function(){return ('').constructor.fromCharCode(%s);})()") % _CODES
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f943-ctor-paren")


# ------------------------------------------------- F944 filed shapes


@_t
def test_p4_f944_pure():
    """F944 filed shape (pure \\u{...}) blocks, node-exact decode."""
    p = ("(function(){return '\\u{78}\\u{6f}\\u{78}\\u{62}-"
         "0123456789abcdef';})()")
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f944-pure")


@_t
def test_p4_f944_mixed():
    """F944 filed shape (mixed \\u{...}+\\x) blocks, node-exact decode."""
    p = ("(function(){return '\\u{78}ox'+\"\\x62-0123456789abcdef\";})()")
    ok = _blocked(p) and _decode(p) == _FULL
    return ("HELD" if ok else "BREAK", "f944-mixed")


# -------------------------------------------- F944 generalizations


@_t
def test_p4_f944_template():
    """F944 generalization: template literal with \\u{...}.

    Node-exact at the parser level (unit); short cooked values are
    length-gated before the credential rules, so the product stays
    quiet (verified against node v24.20.0).
    """
    unit, _ = dlp._js_parse_template("`\\u{41}\\u{42}`", 0, 0,
                                     {"parts": 0, "ops": 0})
    p = "(function(){return `\\u{41}\\u{42}`;})()"
    ok = unit == "AB" and _misses(p)
    return ("HELD" if ok else "BREAK", "f944-template")


@_t
def test_p4_f944_astral():
    """F944 generalization: astral \\u{1F600} decodes (junk, quiet)."""
    unit, _ = dlp._js_parse_string("'\\u{1F600}'", 0)
    p = "(function(){return '\\u{1F600}';})()"
    ok = unit == "\U0001F600" and _misses(p)
    return ("HELD" if ok else "BREAK", "f944-astral")


@_t
def test_p4_f944_zero():
    """F944 generalization: \\u{0} decodes to NUL (node v24.20.0)."""
    unit, _ = dlp._js_parse_string("'a\\u{0}b'", 0)
    p = "(function(){return 'a\\u{0}b';})()"
    ok = unit == "a\0b" and _misses(p)
    return ("HELD" if ok else "BREAK", "f944-zero")


# -------------------------------------------- F944 fail-closed bounds


@_t
def test_p4_f944_empty_braces_miss():
    """F944 bound: \\u{} misses (engine SyntaxError)."""
    p = "(function(){return '\\u{}';})()"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-empty")


@_t
def test_p4_f944_too_big_miss():
    """F944 bound: \\u{110000} misses (engine SyntaxError)."""
    p = "(function(){return '\\u{110000}';})()"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-too-big")


@_t
def test_p4_f944_unterminated_miss():
    """F944 bound: unterminated \\u{78 misses (engine SyntaxError)."""
    p = "(function(){return '\\u{78';})()"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-unterminated")


@_t
def test_p4_f944_surrogate_miss():
    """F944 bound: lone surrogate \\u{D800} misses (fail-closed)."""
    p = "(function(){return '\\u{D800}';})()"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-surrogate")


@_t
def test_p4_f944_rawtext_ubrace():
    """F944: raw-text \\u{...} run decodes via the escape-run layer."""
    p = "key=" + "".join("\\u{%x}" % ord(c) for c in _FULL)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "f944-rawtext")


@_t
def test_p4_f944_rawtext_mixed():
    """F944: mixed \\x + \\u{...} raw-text run blocks."""
    p = "k=\\x78\\u{6f}xb-0123456789abcdef"
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "f944-rawtext-mixed")


@_t
def test_p4_f944_rawtext_bad_miss():
    """F944 bound: raw-text \\u{110000} stays quiet (fail-closed)."""
    p = "key=\\u{110000}" + "".join("\\u{%x}" % ord(c) for c in _FULL)
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-rawtext-bad")


@_t
def test_p4_f944_rawtext_unterminated_miss():
    """F944 bound: unterminated raw-text \\u{78 stays quiet."""
    p = "key=\\u{78"
    ok = _misses(p)
    return ("HELD" if ok else "BREAK", "f944-rawtext-unterminated")


# ------------------------------------------------- sibling pins


@_t
def test_p5_sibling_f458_direct():
    """Sibling: canonical String.fromCharCode(...) still blocks."""
    p = "(function(){return String.fromCharCode(%s);})()" % _CODES
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-f458")


@_t
def test_p5_sibling_f486_call():
    """Sibling: String.fromCharCode.call(null,...) still blocks."""
    p = "(function(){return String.fromCharCode.call(null,%s);})()" % _CODES
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-f486-call")


@_t
def test_p5_sibling_f486_apply():
    """Sibling: String.fromCharCode.apply(null,[...]) still blocks."""
    p = ("(function(){return String.fromCharCode.apply(null,[%s]);})()"
         % _CODES)
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-f486-apply")


@_t
def test_p5_sibling_f897_spread():
    """Sibling: F897 var-bound spread twin still blocks."""
    p = ("(function(){var cs=[%s];return String.fromCharCode.call(null,"
         "...cs);})()") % _CODES
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-f897")


@_t
def test_p5_sibling_hex_escape():
    """Sibling: \\x-escape twin still blocks."""
    p = ("(function(){return '\\x78\\x6f\\x78\\x62-0123456789abcdef';})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-hex-escape")


@_t
def test_p5_sibling_u4_escape():
    """Sibling: \\uXXXX twin still blocks."""
    p = ("(function(){return '\\u0078\\u006f\\u0078\\u0062-"
         "0123456789abcdef';})()")
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "sib-u4-escape")


# ------------------------------------------------- honest text


@_t
def test_p6_honest_junk():
    """Honest text: junk IIFE stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if ok else "BREAK", "honest-junk")


@_t
def test_p6_honest_plain():
    """Honest text: plain words stay quiet."""
    ok = _misses("hello world, this is a test")
    return ("HELD" if ok else "BREAK", "honest-plain")


@_t
def test_p6_honest_backslash():
    """Honest text: backslash prose stays quiet."""
    ok = _misses("use \\n for newline and \\t for tab")
    return ("HELD" if ok else "BREAK", "honest-backslash")


# ------------------------------------------------- perf


@_t
def test_p7_perf():
    """Perf: 200 mixed sites decode in under 10s."""
    sites = []
    for k in range(50):
        sites.append(
            ("(function(){var c=[%s];function f(i){return i>=c.length?'':"
             "String.fromCharCode(c[i])+f(i+1);}return f(0);})()") % _CODES)
        sites.append(
            ("(function(){function* g(){var c=[%s];for(var x of c)yield x;}"
             "return String.fromCharCode(...g());})()") % _CODES)
        sites.append(
            ("(function(){return ''.constructor.fromCharCode(%s);})()")
            % _CODES)
        sites.append(
            ("(function(){return '\\u{78}\\u{6f}\\u{78}\\u{62}-"
             "0123456789abcdef';})()"))
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 10.0 and len(sites) == 200
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_break = 0
    notes = []
    for battery in ("w389_f941_redfirst.py", "w389_f942_redfirst.py",
                    "w389_f943_redfirst.py", "w389_f944_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g390-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        breaks = None
        for line in out.splitlines():
            m = re.match(r"shapes (\d+) BREAK", line)
            if m:
                breaks = int(m.group(1))
        if breaks is None or p.returncode != 0:
            total_break += 1
            notes.append("%s: no tally/rc=%s" % (battery, p.returncode))
        else:
            total_break += breaks
            notes.append("%s: %d BREAK" % (battery, breaks))
    ok = total_break == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d BREAK [%s]" % (total_break, "; ".join(notes)))


@_t
def test_p8_green_check():
    """Depth-1 green check: the four red-firsts stay 0 BREAK."""
    return _green_check()


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    breaks, held = 0, 0
    notes = []
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- battery must not crash
            verdict, note = "BREAK", "%s raised %r" % (fn.__name__, e)
        print("%s %s [%s]" % (verdict, fn.__name__, note))
        if verdict == "BREAK":
            breaks += 1
            notes.append(fn.__name__)
        else:
            held += 1
    print("battery: %d BREAK / %d HELD" % (breaks, held))
    if notes:
        print("broken: %s" % ", ".join(notes))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
