#!/usr/bin/env python3
"""Wave-386 lane 11: close F815 (toString/valueOf overrides on builtin
receivers) + F816 (non-literal ternary conditions on object bindings).

F815 (LOW, filed 2026-10-09 by wave-385 attack round 53): F697
(CLOSED) models toString/valueOf overrides on plain objects, but
overrides installed on builtin instances miss while node coerces
them exactly:
  (function(){var d=new Date(0);d.toString=function(){return
  'f1';};return d+'f2';})()
  (function(){var r=/x/;r.toString=function(){return 'f1';};return
  ''+r+'f2';})()

F816 (LOW, filed 2026-10-09 by wave-385 attack round 53): F756
(CLOSED) covers boolean-literal ternary conditions, but
method-call/operator conditions (hasOwnProperty, in, typeof,
instanceof) have no production:
  (function(){var o={k:'f1'};return
  o.hasOwnProperty('k')?o.k+'f2':'z';})()
  (function(){var o={k:'f1'};return 'k' in
  o?o.k+'f2':'z';})()

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f815_builtin_override_iife (+ _js_f815_parse_receiver,
  _js_f815_parse_override_assign, _js_f815_strict_string_additive,
  _js_f815_toprimitive, _js_f815_skip_balanced_paren):
  `(function(){var NM=RECV;ASSIGN+;return ADD;})()` where RECV is
  `new Date(...)`, `new Number(...)`, `new RegExp('lit'[,'flags'])`,
  a regex literal, or a function expression; ASSIGN installs own
  toString/valueOf/[Symbol.toPrimitive] overrides (later-wins; a
  [Symbol.toPrimitive] assignment on a Date is a silent no-op --
  Date.prototype[@@toPrimitive] is non-writable, node v24.20.0);
  the return is a `+`-additive of string literals, bare receiver
  idents (ToPrimitive hint "default"), and `String(NM)` terms
  (hint "string"). Resolution is node-exact: own callable
  @@toPrimitive wins hint-independently; else toString-first for
  Dates / hint "string", valueOf-first otherwise, with the
  RegExp/Function fall-through (inherited Object.prototype.
  valueOf returns the receiver itself, non-primitive) and the
  Number stop (inherited Number.prototype.valueOf returns a
  primitive). Only an effective own callable override with a pure
  string-literal body decodes; all else fails closed. Hooked
  after F743 with parts/ops snapshot/restore on miss (wave-383
  merge lesson). Disjoint from F697/F743: both require an object
  literal binding; this requires a builtin receiver.
- _js_parse_f816_objcond_iife (+ _js_f816_parse_object_binding,
  _js_f816_eval_cond, _js_f816_typeof_operand, _js_f816_branch,
  _js_f816_ternary_at): `(function(){var o={...};DECL*;return
  ADD;})()` where the binding is a plain-string object (a
  `__proto__` key fails closed); conditions are F756 booleans
  plus `o.hasOwnProperty('lit'|name)` (own keys only; shadowed
  own key fails closed), `'lit' in o` (own keys + the exact
  Object.prototype member set), `typeof T ===|!==|==|!= 'lit'`,
  and `T instanceof R` (8 builtins), with optional `!`; branches
  are `+`-additives of string literals, bound string names, and
  own-key member reads; the return is a whole bare ternary or an
  additive of string literals / bound names / parenthesized
  ternaries. Hooked after F756 with snapshot/restore. Disjoint
  from F756: F756's decl loop rejects a `{` binding.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (each green-check child gets a unique-suffixed
/var/tmp TMPDIR via mkdtemp; the battery process itself inherits
the launcher's TMPDIR, same as sibling batteries), no in-repo git
in self-pins, concatenation-constructed credentials, pin 2143,
$0-spend-by-construction (this battery imports only gov.dlp and
stdlib).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
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


def _verifier_pin():
    """Read VERIFIER_TAXONOMY_PIN from its defining battery (text read;
    the evidence-schema taxonomy is a different domain, value 33)."""
    src = open(os.path.join(REPO_ROOT, "evals",
                            "w318_evidence_schema_probes.py")).read()
    m = re.search(r"^VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src, re.M)
    return int(m.group(1)) if m else None

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


def _decodes_to(payload, value):
    """The whole-text JS-expression decode yields exactly *value*."""
    variant = dlp._try_js_expr_decode_all(payload)
    return variant is not None and value in variant


# ------------------------------------------------------------------ p0 pins

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    vpin = _verifier_pin()
    ok = vpin == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % vpin)


@_t
def test_p0_no_new_regex():
    """Zero new re.compile( -- the 28-pattern pin stands."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F815/F816 CLOSED; open F795-F814,
    F817, F819-F828; next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, "
          "F802, F803, F804, F805, F806, F807, F808, F809, F810, F811, "
          "F812, F813, F814, F817, F819, F820, F821, F822, F823, F824, "
          "F825, F826, F827, F828." in text
          and "# Wave-386 lane 11: F815, F816 CLOSED" in text
          and "F815" in text and "F816" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- F815 filed shapes

@_t
def test_p1_f815_s1():
    """F815 filed shape 1 (Date + own toString) blocks."""
    ok = _blocked(
        "(function(){var d=new Date(0);d.toString=function(){return '%s';};"
        "return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f815-s1=%s" % ok)


@_t
def test_p1_f815_s2():
    """F815 filed shape 2 (regex literal + own toString) blocks."""
    ok = _blocked(
        "(function(){var r=/x/;r.toString=function(){return '%s';};"
        "return ''+r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f815-s2=%s" % ok)


# ------------------------------------------------------- F815 generalizations

@_t
def test_p2_f815_valueof_regex():
    """Own valueOf on a regex receiver blocks."""
    ok = _blocked(
        "(function(){var r=/x/;r.valueOf=function(){return '%s';};"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "valueof=%s" % ok)


@_t
def test_p2_f815_symtoprim():
    """Own [Symbol.toPrimitive] on a regex receiver blocks."""
    ok = _blocked(
        "(function(){var r=/x/;r[Symbol.toPrimitive]=function(){return '%s';};"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "symtoprim=%s" % ok)


@_t
def test_p2_f815_bracket_member():
    """Bracket-member override assignment blocks."""
    ok = _blocked(
        "(function(){var d=new Date(0);d['toString']=function(){return '%s';};"
        "return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_f815_new_regexp():
    """new RegExp('lit') receiver blocks."""
    ok = _blocked(
        "(function(){var r=new RegExp('x');r.toString=function(){return '%s';};"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "newregexp=%s" % ok)


@_t
def test_p2_f815_new_number_valueof():
    """new Number receiver with own valueOf blocks."""
    ok = _blocked(
        "(function(){var n=new Number(1);n.valueOf=function(){return '%s';};"
        "return n+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "newnumber=%s" % ok)


@_t
def test_p2_f815_function_receiver():
    """Function-expression receiver with own toString blocks."""
    ok = _blocked(
        "(function(){var f=function(){};f.toString=function(){return '%s';};"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "fnrecv=%s" % ok)


@_t
def test_p2_f815_later_wins():
    """Later override assignment wins (node-exact)."""
    ok = _blocked(
        "(function(){var d=new Date(0);d.toString=function(){return 'z';};"
        "d.toString=function(){return '%s';};return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "laterwins=%s" % ok)


@_t
def test_p2_f815_string_call():
    """String(d) hint-string term blocks."""
    ok = _blocked(
        "(function(){var d=new Date(0);d.toString=function(){return '%s';};"
        "return String(d)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "stringcall=%s" % ok)


@_t
def test_p2_f815_num_symtoprim_body():
    """Numeric @@toPrimitive body is String()-coerced (F794 parity)."""
    ok = _decodes_to(
        "(function(){var r=/x/;r[Symbol.toPrimitive]=function(){return 65;};"
        "return r+'!';})()", "65!")
    return ("HELD" if ok else "BREAK", "numsym=%s" % ok)


@_t
def test_p2_f815_regex_flags():
    """Regex literal with flags blocks."""
    ok = _blocked(
        "(function(){var r=/x/gi;r.toString=function(){return '%s';};"
        "return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "flags=%s" % ok)


@_t
def test_p2_f815_multi_assign():
    """Two overrides, effective-first (valueOf) wins on regex."""
    ok = _blocked(
        "(function(){var r=/x/;r.toString=function(){return 'z';};"
        "r.valueOf=function(){return '%s';};return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multiassign=%s" % ok)


@_t
def test_p2_f815_exact():
    """F815 filed shapes decode to the exact node value."""
    ok = (_decodes_to(
        "(function(){var d=new Date(0);d.toString=function(){return 'f1';};"
        "return d+'f2';})()", "f1f2")
        and _decodes_to(
        "(function(){var r=/x/;r.toString=function(){return 'f1';};"
        "return ''+r+'f2';})()", "f1f2"))
    return ("HELD" if ok else "BREAK", "exact815=%s" % ok)


# ------------------------------------------------------- F815 fail-closed bounds

@_t
def test_p3_f815_date_valueof_only():
    """Own valueOf on a Date: inherited Date toString (TZ-dependent)
    wins in the engine -- decoder misses (fail closed)."""
    ok = _misses(
        "(function(){var d=new Date(0);d.valueOf=function(){return '%s';};"
        "return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "datevalueof=%s" % ok)


@_t
def test_p3_f815_number_tostring_only():
    """Own toString on a Number: inherited valueOf yields a primitive
    -- decoder misses (fail closed)."""
    ok = _misses(
        "(function(){var n=new Number(1);n.toString=function(){return '%s';};"
        "return n+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "numtostring=%s" % ok)


@_t
def test_p3_f815_noncallable_tostring():
    """Non-callable own toString: engine skips it -- decoder misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=42;return d+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nctostring=%s" % ok)


@_t
def test_p3_f815_noncallable_symtoprim():
    """Non-callable @@toPrimitive: engine throws -- decoder misses."""
    ok = _misses(
        "(function(){var r=/x/;r[Symbol.toPrimitive]=42;return r+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "ncsym=%s" % ok)


@_t
def test_p3_f815_arrow_body():
    """Arrow-function override body: documented residual -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=()=>'%s';"
        "return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "arrow=%s" % ok)


@_t
def test_p3_f815_this_body():
    """this-reading override body: documented residual -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return this.x;};"
        "return d+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "thisbody=%s" % ok)


@_t
def test_p3_f815_numeric_tostring_body():
    """Numeric toString body: documented residual (F697 parity) -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return 65;};"
        "return d+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "numbody=%s" % ok)


@_t
def test_p3_f815_generator_receiver():
    """Generator function receiver: not a modeled receiver -- misses."""
    ok = _misses(
        "(function(){var f=function*(){};f.toString=function(){return '%s';};"
        "return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "generator=%s" % ok)


@_t
def test_p3_f815_new_no_parens():
    """`new Date;` without parens: documented residual -- misses."""
    ok = _misses(
        "(function(){var d=new Date;d.toString=function(){return '%s';};"
        "return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "noparens=%s" % ok)


@_t
def test_p3_f815_extra_statement():
    """Extra statement between override and return -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return '%s';};"
        "var z=1;return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "extrastmt=%s" % ok)


@_t
def test_p3_f815_reassign_receiver():
    """Receiver reassignment -- misses (fail closed)."""
    ok = _misses(
        "(function(){var d=new Date(0);d=new Date(1);"
        "d.toString=function(){return '%s';};return d+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "reassign=%s" % ok)


@_t
def test_p3_f815_unbound_term():
    """Unbound return term -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return '%s';};"
        "return d+q+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_f815_member_term():
    """Member-read return term: other shapes' domain -- misses."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return '%s';};"
        "return d.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "memberterm=%s" % ok)


@_t
def test_p3_f815_no_override():
    """No override assignment: earlier grammars own it -- misses here."""
    ok = _misses(
        "(function(){var d=new Date(0);return d+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "nooverride=%s" % ok)


@_t
def test_p3_f815_literal_only_return():
    """Literal-only return: earlier grammars own it -- misses here."""
    ok = _misses(
        "(function(){var d=new Date(0);d.toString=function(){return 'x';};"
        "return 'a'+'b';})()")
    return ("HELD" if ok else "BREAK", "litonly=%s" % ok)


@_t
def test_p3_f815_bad_regex_flags():
    """Invalid regex flags (node throws): fail closed.
    Spec-review HARD-2."""
    ok = all([
        _misses("(function(){var r=/x/zz;r.toString=function(){return '%s';};"
               "return r+'%s';})()" % (_A, _B)),
        _misses("(function(){var r=/x/gg;r.toString=function(){return '%s';};"
               "return r+'%s';})()" % (_A, _B)),
        _misses("(function(){var r=new RegExp('x','zz');"
               "r.toString=function(){return '%s';};return r+'%s';})()"
               % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "badflags=%s" % ok)


# ------------------------------------------------------- F816 filed shapes

@_t
def test_p1_f816_s1():
    """F816 filed shape 1 (hasOwnProperty condition) blocks."""
    ok = _blocked(
        "(function(){var o={k:'%s'};return o.hasOwnProperty('k')?o.k+'%s':'z';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f816-s1=%s" % ok)


@_t
def test_p1_f816_s2():
    """F816 filed shape 2 (in-operator condition) blocks."""
    ok = _blocked(
        "(function(){var o={k:'%s'};return 'k' in o?o.k+'%s':'z';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f816-s2=%s" % ok)

# ------------------------------------------------------- F816 generalizations

@_t
def test_p2_f816_hop_variants():
    """hasOwnProperty variants: false / proto-member / bracket /
    bound-name arg / negated."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};return o.hasOwnProperty('z')?'q':o.k+'%s';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return o.hasOwnProperty('toString')?'q':o.k+'%s';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return o['hasOwnProperty']('k')?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};var kk='k';return o.hasOwnProperty(kk)?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return !o.hasOwnProperty('z')?o.k+'%s':'z';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "hopvars=%s" % ok)


@_t
def test_p2_f816_in_variants():
    """in-operator variants: proto member / missing / __proto__ /
    bound-name operand."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};return 'toString' in o?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return 'z' in o?'q':o.k+'%s';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return '__proto__' in o?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};var kk='k';return kk in o?o.k+'%s':'z';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "invars=%s" % ok)


@_t
def test_p2_f816_typeof_variants():
    """typeof variants: === / !== / == / != over own key, proto
    member, missing key, and bound string names."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};return typeof o.k==='string'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return typeof o.k!=='number'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return typeof o.k=='string'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return typeof o.z==='undefined'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return typeof o.toString==='function'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return typeof o==='object'?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var s='x';var o={k:'%s'};return typeof s==='string'?o.k+'%s':'z';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "typeofvars=%s" % ok)


@_t
def test_p2_f816_instanceof_variants():
    """instanceof variants: Object true, Array false, primitive false."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};return o instanceof Object?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return o instanceof Array?'q':o.k+'%s';})()" % (_A, _B)),
        _blocked("(function(){var s='x';var o={k:'%s'};return s instanceof String?'q':o.k+'%s';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "instvars=%s" % ok)


@_t
def test_p2_f816_bool_conditions():
    """F756 boolean conditions still work under an object binding."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};var c=true;return c?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};var c=false;return !c?o.k+'%s':'z';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "boolconds=%s" % ok)


@_t
def test_p2_f816_paren_ternary_return():
    """Parenthesized ternary in the return additive blocks."""
    ok = _blocked(
        "(function(){var o={k:'%s'};return (o.hasOwnProperty('k')?o.k:'z')+'%s';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "parentern=%s" % ok)


@_t
def test_p2_f816_decl_ternaries():
    """Bare and parenthesized ternary decl initializers block."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};var y=o.hasOwnProperty('k')?o.k:'z';return y+'%s';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};var y=(o.hasOwnProperty('k')?o.k:'z');return y+'%s';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "decltern=%s" % ok)


@_t
def test_p2_f816_branch_variants():
    """Branch variants: bracket member read, multi-key, duplicate
    keys (later-wins), false-branch additive."""
    ok = all([
        _blocked("(function(){var o={k:'%s'};return o.hasOwnProperty('k')?o['k']+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={a:'x',k:'%s'};return 'k' in o?o.k+'%s':o.a;})()" % (_A, _B)),
        _blocked("(function(){var o={k:'x',k:'%s'};return o.hasOwnProperty('k')?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};return o.hasOwnProperty('z')?'q':o.k+'%s';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "branchvars=%s" % ok)


@_t
def test_p2_f816_exact():
    """F816 filed shapes decode to the exact node value."""
    ok = (_decodes_to(
        "(function(){var o={k:'f1'};return o.hasOwnProperty('k')?o.k+'f2':'z';})()",
        "f1f2")
        and _decodes_to(
        "(function(){var o={k:'f1'};return 'k' in o?o.k+'f2':'z';})()",
        "f1f2"))
    return ("HELD" if ok else "BREAK", "exact816=%s" % ok)


# ------------------------------------------------------- F816 fail-closed bounds

@_t
def test_p3_f816_shadowed_hasownproperty():
    """Shadowed own hasOwnProperty: engine throws -- decoder misses."""
    ok = _misses(
        "(function(){var o={hasOwnProperty:1,k:'%s'};"
        "return o.hasOwnProperty('k')?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "shadowhop=%s" % ok)


@_t
def test_p3_f816_dunder_key():
    """__proto__ key in the object binding -- misses (fail closed)."""
    ok = _misses(
        "(function(){var o={__proto__:'x',k:'%s'};"
        "return 'toString' in o?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "dunderkey=%s" % ok)


@_t
def test_p3_f816_nonlit_hop_arg():
    """Non-literal hasOwnProperty argument -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};return o.hasOwnProperty(0)?o.k+'%s':'z';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlithop=%s" % ok)


@_t
def test_p3_f816_foreign_in():
    """in-operator over a foreign object -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};var p={};return 'k' in p?o.k+'%s':'z';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "foreignin=%s" % ok)


@_t
def test_p3_f816_nonown_branch_key():
    """Branch member read of a non-own key -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};return o.hasOwnProperty('k')?o.z+'%s':'q';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonownbranch=%s" % ok)


@_t
def test_p3_f816_two_objects():
    """Two object bindings -- misses (fail closed)."""
    ok = _misses(
        "(function(){var o={k:'%s'};var p={j:'x'};"
        "return o.hasOwnProperty('k')?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "twoobj=%s" % ok)


@_t
def test_p3_f816_no_ternary():
    """No ternary in the body: F816's own parser declines it
    (disjointness); a pre-existing decoder already blocks the
    shape, so the credential is still caught."""
    p = "(function(){var o={k:'%s'};return o.k+'%s';})()" % (_A, _B)
    mine = dlp._js_parse_f816_objcond_iife(p, 0, 0, {"parts": 0, "ops": 0})
    ok = mine is None and _blocked(p)
    return ("HELD" if ok else "BREAK", "noternary=%s" % ok)


@_t
def test_p3_f816_nested_ternary():
    """Nested ternary in a branch -- misses (fail closed)."""
    ok = _misses(
        "(function(){var o={k:'%s'};var c=true;"
        "return c?o.hasOwnProperty('k')?o.k:'a':'b';})()" % _A)
    return ("HELD" if ok else "BREAK", "nested=%s" % ok)


@_t
def test_p3_f816_nullish():
    """?? after the condition is the nullish operator -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};return o.hasOwnProperty('k')??o.k:'q';})()"
        % _A)
    return ("HELD" if ok else "BREAK", "nullish=%s" % ok)


@_t
def test_p3_f816_unbound_condition():
    """Unbound condition operand -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};return q?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unboundcond=%s" % ok)


@_t
def test_p3_f816_bad_instanceof_rhs():
    """instanceof with an unmodeled rhs -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};return o instanceof Foo?o.k+'%s':'z';})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "badinst=%s" % ok)


@_t
def test_p3_f816_return_bare_object():
    """Bare bound object in the return -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};var c=true;return c?o:'z';})()" % _A)
    return ("HELD" if ok else "BREAK", "bareobj=%s" % ok)


@_t
def test_p3_f816_negated_operators():
    """A leading `!` on `in` / `typeof`-comparison / `instanceof`
    is modeled with JS precedence (`!` binds tighter): `!z in o`
    is `(!z) in o` (boolean key), `!T instanceof R` is always
    false, `!typeof T === 's'` is false / `!==` is true, and
    `==`/`!=` reduce to a ToNumber-zero check. Spec-review
    HARD-1 (the naive whole-result negation mis-decoded and
    laundered); all now block node-exactly."""
    ok = all([
        # `!z in o` = `(!z) in o` = `"false" in o` = False ->
        # false branch carries the credential.
        _blocked("(function(){var o={k:'%s'};var z='q';"
                 "return !z in o?'z':o.k+'%s';})()" % (_A, _B)),
        # `!typeof o.k==='number'` = `false==='number'` = False.
        _blocked("(function(){var o={k:'%s'};"
                 "return !typeof o.k==='number'?'z':o.k+'%s';})()" % (_A, _B)),
        # `!typeof o.k!=='number'` = `false!=='number'` = True.
        _blocked("(function(){var o={k:'%s'};"
                 "return !typeof o.k!=='number'?o.k+'%s':'z';})()" % (_A, _B)),
        # `!s instanceof Object` = `(false) instanceof Object` = False.
        _blocked("(function(){var o={k:'%s'};var s='x';"
                 "return !s instanceof Object?'z':o.k+'%s';})()" % (_A, _B)),
        # `!o instanceof Object` = False.
        _blocked("(function(){var o={k:'%s'};"
                 "return !o instanceof Object?'z':o.k+'%s';})()" % (_A, _B)),
        # `!typeof o.k==''` = `false==''` = True (ToNumber('')==0).
        _blocked("(function(){var o={k:'%s'};"
                 "return !typeof o.k==''?o.k+'%s':'z';})()" % (_A, _B)),
        # `!typeof o.k=='x'` = `false=='x'` = False.
        _blocked("(function(){var o={k:'%s'};"
                 "return !typeof o.k=='x'?'z':o.k+'%s';})()" % (_A, _B)),
        # ...and the exact `!` forms still block:
        _blocked("(function(){var o={k:'%s'};"
                 "return !o.hasOwnProperty('z')?o.k+'%s':'z';})()" % (_A, _B)),
        _blocked("(function(){var o={k:'%s'};var c=false;"
                 "return !c?o.k+'%s':'z';})()" % (_A, _B)),
    ])
    return ("HELD" if ok else "BREAK", "negops=%s" % ok)


@_t
def test_p3_f816_rebind():
    """Rebinding a bound name -- misses."""
    ok = _misses(
        "(function(){var o={k:'%s'};var o={j:'x'};"
        "return o.hasOwnProperty('k')?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "rebind=%s" % ok)


# ------------------------------------------------------- sibling pins (p6)

@_t
def test_p6_sibling_f697():
    """F697 (object toString/valueOf overrides) still blocks."""
    ok = _blocked(
        "(function(){var o={v:'%s',toString:function(){return this.v;}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)


@_t
def test_p6_sibling_f743():
    """F743 (Symbol.toPrimitive on plain object) still blocks."""
    ok = _blocked(
        ("(function(){var o={};o[Symbol.toPrimitive]=function(){return '\u00a7A';};"
         "return o+'\u00a7B';})()").replace("\u00a7A", _A).replace("\u00a7B", _B))
    return ("HELD" if ok else "BREAK", "f743=%s" % ok)


@_t
def test_p6_sibling_f756():
    """F756 (boolean ternary) still blocks."""
    ok = _blocked(
        ("(function(){var c=true;return (c?'\u00a7A':'z')+'\u00a7B';})()"
         ).replace("\u00a7A", _A).replace("\u00a7B", _B))
    return ("HELD" if ok else "BREAK", "f756=%s" % ok)


# ------------------------------------------------------- honest-text (p7)

@_t
def test_p7_honest_junk():
    """Honest control: no credential anywhere -- stays quiet."""
    ok = _misses("(function(){var d=new Date(0);return 'nothing here';})()")
    return ("HELD" if ok else "BREAK", "junk=%s" % ok)


@_t
def test_p7_honest_ternary():
    """Honest control: object ternary without a credential -- quiet."""
    ok = _misses(
        "(function(){var o={k:'x'};return o.hasOwnProperty('k')?o.k:'z';})()")
    return ("HELD" if ok else "BREAK", "honesttern=%s" % ok)


@_t
def test_p7_honest_iife():
    """Honest control: plain builtin IIFE without overrides -- quiet."""
    ok = _misses("(function(){var d=new Date(0);return 'a'+'b';})()")
    return ("HELD" if ok else "BREAK", "honestiife=%s" % ok)


# ------------------------------------------------------- perf (p8)

@_t
def test_p8_perf_200_sites():
    """200 mixed F815/F816 sites decode within the perf budget."""
    sites = []
    for i in range(100):
        sites.append(
            "(function(){var d=new Date(%d);d.toString=function(){return 'p%d';};"
            "return d+'t';})()" % (i, i))
        sites.append(
            "(function(){var o={k:'p%d'};return o.hasOwnProperty('k')?o.k:'z';})()"
            % i)
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------------- green check (p9)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree: the two new
    # w386 red-firsts plus the sibling red-firsts adjacent to the
    # new hooks (F697/F743/F756). Red-firsts carry no footer pins,
    # so the lane-local footer cannot perturb them.
    for batt in ("evals/w386_f815_redfirst.py",
                 "evals/w386_f816_redfirst.py",
                 "evals/w380_f697_redfirst.py",
                 "evals/w383_f743_redfirst.py",
                 "evals/w383_f756_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
        elif nbreak != 0:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p9_green_check():
    """Depth-1 green check: new + sibling red-firsts, 0 BREAK."""
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
