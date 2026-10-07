#!/usr/bin/env python3
"""Closure probes for F470 (wave-354 lane 2).

F470 (LOW): method-call-result .filter predicates bypassed the bounded
static JS-expression decoder's truthiness-preserving predicate model.
F447 (closed, wave-350 lane 2) models truthiness-preserving predicates
only as syntactic falsiness tests over parsed strings (x=>x!=='' ,
x=>!!x, x=>x.length>0, bare x, function(x){return x;}), and F467
(closed, wave-353 lane 4) models constant-true null comparisons
(x!==null | x!==undefined | x!=null). A predicate whose truthiness
comes from a METHOD CALL result was unmodeled:

- ['frag1','frag2',''].filter(x=>x.match(/[a-z]/)).join('') --
  match() returns a truthy array for strings containing [a-z], null
  for ''; node-evaluates to the credential while the scanner missed.
- ['frag1','frag2'].filter(x=>x.charCodeAt(0)>47).join('') --
  method-call-result comparison; node-evaluates to the credential
  while the scanner missed.

Now modeled (gov/dlp.py, node v24.20.0 byte-identical):
- p.match(/[a-z]/) -- also /[A-Z]/, /[0-9]/ only (hand-scanned
  single-range classes, no new regexes, no flags): keep elements
  containing a char in the class (match() is truthy iff non-null).
- p.charCodeAt(IDX) OP K -- OP in <,<=,>,>=; IDX a literal
  non-negative int; K a literal int (optional leading '-'): keep
  elements whose UTF-16 code unit at IDX satisfies the comparison.
  Empty strings and out-of-range indices are NaN in node, and every
  relational comparison against NaN is false, so those elements are
  always dropped (node-verified). Astral characters expose UTF-16
  surrogates, hence the utf-16-le decode rather than ord() -- though
  the decoder's string parser is ASCII-only, so astral elements
  cannot arise from literals (pre-existing boundary, not F470's).
- Both arrow and function(x){return ...;} forms; the F467 shadow
  guard applies (a param named `undefined` fails the method-call
  forms closed, conservative).

Unifying the function-form filter body with the arrow grammar also
decodes function(x){return x!=='';} / return x.length>0; / return
!!x; -- all node-exact truthiness forms the arrow grammar already
modeled (the w350 documented residual is updated, not silently
dropped).

Neighbor dispositions (node-verified, documented here and in the
FINDINGS.md closure note):
- x.match(/[a-z]/) / /[A-Z]/ / /[0-9]/ -- modeled (keep-on-class-hit).
- x.charCodeAt(0)>47 / >=65 / <66 / <=98 / charCodeAt(1)>96 /
  charCodeAt(0)>-5 -- modeled (per-op node-verified).
- function(x){return x.match(/[a-z]/);} /
  function(x){return x.charCodeAt(0)<=98;} -- modeled.
- x.match(/[a-z]/g) (flags), /[a-z0-9]/ (multi-range), /[^a-z]/
  (negation), /[ab]/ (bare chars), /[\\-]/ (escapes), x.match('ab')
  (string arg), x.test/x.includes/x.search, x.match(/[a-z]/,1)
  (extra arg) -- fail closed (documented scope: rejected, never
  mis-decoded).
- x.charCodeAt() (no arg), x.charCodeAt(0,1) (extra arg),
  x.charCodeAt(-1) (negative), x.charCodeAt(0.5) (fractional),
  x.charCodeAt(0)===97 / !== / == (non-relational ops),
  x=>x.charCodeAt(0) (bare, no comparison), x=>!!x.match(...)
  (double-negated method call), x=>x.match(/[a-z]/).length
  (trailing member) -- fail closed.
- undefined=>undefined.match(/[a-z]/) -- fail closed (F467 shadow
  guard, conservative; node would resolve the param fine).
- '' elements under charCodeAt comparisons are NaN-dropped
  (node-verified); the empty join then hits the pre-existing
  empty-gating boundary (no variant), consistent with the paren
  forms.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: match/ccmp arrow/function/paren/ws forms block coded
      dlp-slack-token; empty-element NaN-drop blocks; compositions
      block.
  P2  controls: plain credential blocks; junk variants quiet; neighbor
      closures intact (F443 .filter(Boolean), F447 truthiness incl.
      function form, F467 null-cmp, F459 positional).
  P3  decoder pins: exact decode values; fail-closed neighbors yield
      no variant (flags, multi-range, negation, escapes, string args,
      .test/.includes/.search, bad charCodeAt shapes, shadow guard,
      double negation, trailing members).
  P4  discrimination: prose mentions quiet; filter on non-array
      quiet; map with match body quiet.
  P5  ReDoS: hostile near-miss inputs complete fast with no
      exceptions; F171 module stays 2/2.
  P6  no-regression: adjacent closures still block (F443 fill/Boolean,
      F446 of, F447 truthiness, F454 multi-arg, F459 positional,
      F460 map-String, F461 reverse, F462 spread-concat, F463 tagged,
      F464 toString/replace, F465 pad, F466 slice, F467 null-cmp,
      F468 reflect-construct).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F469, F471, F472 / next F473, F470 CLOSED entry
      present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w354_f470close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-354: F470 closed, no new decision codes; pin unchanged 2135
FOOTER_OPEN = "F521, F522, F523, F524, F525"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-355 lanes 1+2: F473, F474 CLOSED; open none / next F475 (merge intermediate)  # Wave-354: next free finding after F470 closure  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-354 lane 2: F470 CLOSED locally (merge finalizes tree-wide); wave-353 merge: F461-F468 CLOSED, F469-F472 filed OPEN (next F473)  # Wave-355 lane 3: F475 filed + CLOSED  # Wave-355 lane 3: F475 FILED + CLOSED (merge intermediate)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)
FOOTER_NEXT = "F526"  # Wave-355 lanes 1+2: F473, F474 CLOSED; open none / next F475 (merge intermediate)  # Wave-354: next free finding after F470 closure  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-354 lane 2: F470 CLOSED locally (merge finalizes tree-wide); wave-353 merge: F461-F468 CLOSED, F469-F472 filed OPEN (next F473)  # Wave-355 lane 3: F475 filed + CLOSED  # Wave-355 lane 3: F475 FILED + CLOSED (merge intermediate)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credential -- constructed via concatenation, never a literal.
_A = "xoxb-" + "abc123"
_B = "def" + "456"
_CRED = _A + _B
assert len(_CRED) == 17


def _blocked(payload):
    return dlp.find_credential(payload) == "dlp-slack-token"


# ---------------------------------------------------------------- P1: closure

def p1_closure_match_arrow():
    return _blocked("['" + _A + "','" + _B + "',''].filter(x=>x.match(/[a-z]/))"
                    ".join('')")


def p1_closure_match_function():
    return _blocked("['" + _A + "','" + _B + "',''].filter(function(x)"
                    "{return x.match(/[a-z]/);}).join('')")


def p1_closure_match_paren():
    return _blocked("['" + _A + "','" + _B + "'].filter((x)=>x.match(/[a-z]/))"
                    ".join('')")


def p1_closure_match_ws():
    return _blocked("['" + _A + "','" + _B + "'].filter( x => x . match ( /[a-z]/ ) )"
                    ".join('')")


def p1_closure_ccmp_arrow():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x.charCodeAt(0)>47)"
                    ".join('')")


def p1_closure_ccmp_empty_dropped():
    # '' is NaN under charCodeAt -- dropped, credential still assembles.
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x.charCodeAt(0)>47)"
                    ".join('')")


def p1_closure_ccmp_function():
    return _blocked("['" + _A + "','" + _B + "'].filter(function(x)"
                    "{return x.charCodeAt(0)>47;}).join('')")


def p1_closure_ccmp_ops():
    return (_blocked("['" + _A + "','" + _B + "'].filter(x=>x.charCodeAt(0)>=97)"
                     ".join('')")
            and _blocked("['" + _A + "','" + _B + "'].filter(x=>x.charCodeAt(0)<200)"
                         ".join('')")
            and _blocked("['" + _A + "','" + _B + "'].filter(x=>x.charCodeAt(1)<=120)"
                         ".join('')"))


def p1_closure_ccmp_negative_bound():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x.charCodeAt(0)>-5)"
                    ".join('')")


def p1_closure_compose():
    return _blocked("['" + _A + "','" + _B + "','']"
                    ".filter(x=>x.match(/[a-z]/)).filter(x=>x.charCodeAt(0)>47)"
                    ".join('')")


def p1_closure_fn_truthiness_unified():
    # Wave-354 unification: function-form truthiness bodies decode.
    return (_blocked("['" + _A + "','','" + _B + "'].filter(function(x)"
                     "{return x!=='';}).join('')")
            and _blocked("['" + _A + "','','" + _B + "'].filter(function(x)"
                         "{return x.length>0;}).join('')"))


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_quiet():
    return (not _blocked("['ab','cd',''].filter(x=>x.match(/[a-z]/)).join('')")
            and not _blocked("['ab','cd'].filter(x=>x.charCodeAt(0)>47).join('')")
            and not _blocked("['ab','cd'].filter(function(x)"
                             "{return x.match(/[0-9]/);}).join('')"))


def p2_control_f443_intact():
    return _blocked("['" + _A + "','','" + _B + "'].filter(Boolean).join('')")


def p2_control_f447_intact():
    return (_blocked("['" + _A + "','','" + _B + "'].filter(x=>x!=='').join('')")
            and _blocked("['" + _A + "','','" + _B + "'].filter(function(x)"
                         "{return x;}).join('')"))


def p2_control_f467_intact():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x!==null).join('')")


def p2_control_f459_intact():
    return _blocked("['" + _A + "','" + _B + "','x'].filter((x,i)=>i<2).join('')")


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_match_value():
    r = dlp._try_js_expr_decode("['f1','F2',''].filter(x=>x.match(/[a-z]/))"
                                ".join('-')", 0)
    return r is not None and r[0] == "f1"


def p3_pin_match_upper_value():
    r = dlp._try_js_expr_decode("['f1','F2'].filter(x=>x.match(/[A-Z]/))"
                                ".join('')", 0)
    return r is not None and r[0] == "F2"


def p3_pin_match_digit_value():
    r = dlp._try_js_expr_decode("['f1','FG'].filter(x=>x.match(/[0-9]/))"
                                ".join('')", 0)
    return r is not None and r[0] == "f1"


def p3_pin_ccmp_value():
    # '' is NaN (dropped); 'f1'/'F2' kept (102/70 > 47).
    r = dlp._try_js_expr_decode("['f1','F2',''].filter(x=>x.charCodeAt(0)>47)"
                                ".join('')", 0)
    return r is not None and r[0] == "f1F2"


def p3_pin_ccmp_idx1_value():
    # 'ab': 'b'=98>96 keep; 'aB': 'B'=66>96 drop.
    r = dlp._try_js_expr_decode("['ab','aB'].filter(x=>x.charCodeAt(1)>96)"
                                ".join('')", 0)
    return r is not None and r[0] == "ab"


def p3_pin_ccmp_oor_no_variant():
    # Out-of-range index is NaN for every element: all dropped, and the
    # empty join hits the pre-existing empty-gating boundary (no
    # variant) -- node-verified (node yields "").
    r = dlp._try_js_expr_decode("['ab','cd'].filter(x=>x.charCodeAt(5)>0)"
                                ".join('')", 0)
    return r is None


def p3_pin_ccmp_negative_bound():
    r = dlp._try_js_expr_decode("['ab'].filter(x=>x.charCodeAt(0)>-5)"
                                ".join('')", 0)
    return r is not None and r[0] == "ab"


def p3_pin_fn_strict_neq_value():
    # Wave-354 unification: function-form truthiness decodes.
    r = dlp._try_js_expr_decode("['f1',''].filter(function(x){return x!=='';})"
                                ".join('')", 0)
    return r is not None and r[0] == "f1"


def p3_pin_match_scope_fails():
    # Out-of-scope match shapes fail closed: no decode variant at all.
    for body in ("x=>x.match(/[a-z]/g)",     # flags
                 "x=>x.match(/[a-z0-9]/)",   # multi-range class
                 "x=>x.match(/[^a-z]/)",     # negated class
                 "x=>x.match(/[ab]/)",       # bare chars, no range
                 "x=>x.match('ab')",         # string arg
                 "x=>x.test(/[a-z]/)",       # wrong method
                 "x=>x.includes('a')",        # wrong method
                 "x=>x.search(/[a-z]/)",     # wrong method
                 "x=>x.match(/[a-z]/, 1)"):  # extra arg
        r = dlp._try_js_expr_decode("['f1','f2'].filter(" + body
                                    + ").join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_ccmp_scope_fails():
    # Out-of-scope charCodeAt shapes fail closed: no variant.
    for body in ("x=>x.charCodeAt()>47",       # no index arg
                 "x=>x.charCodeAt(0,1)>47",    # extra arg
                 "x=>x.charCodeAt(-1)>47",     # negative index
                 "x=>x.charCodeAt(0.5)>47",    # fractional index
                 "x=>x.charCodeAt(0)===97",    # non-relational ops
                 "x=>x.charCodeAt(0)!==97",
                 "x=>x.charCodeAt(0)==97",
                 "x=>x.charCodeAt(0)",        # bare, no comparison
                 "x=>x.charCodeAt(0)>47.5",    # fractional bound
                 "x=>!!x.match(/[a-z]/)",     # double-negated call
                 "x=>x.match(/[a-z]/).length"):  # trailing member
        r = dlp._try_js_expr_decode("['f1','f2'].filter(" + body
                                    + ").join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_shadow_fails():
    # A param named `undefined` fails the method-call forms closed
    # (F467 shadow guard, conservative).
    r = dlp._try_js_expr_decode("['f1','f2'].filter("
                                "undefined=>undefined.match(/[a-z]/))"
                                ".join('')", 0)
    return r is None


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_prose_quiet():
    return (not _blocked("the x.match(/[a-z]/) predicate keeps lowercase")
            and not _blocked("use x.charCodeAt(0)>47 to test the first char")
            and not _blocked("filter(x=>x.match(/[0-9]/)) drops non-digits"))


def p4_discr_filter_on_string_quiet():
    # The predicate only parses as a .filter callback on an array.
    return not _blocked("'ab'.filter(x=>x.match(/[a-z]/))")


def p4_discr_map_match_quiet():
    # .map with a match body is not the identity: fails closed.
    return not _blocked("['" + _A + "','" + _B + "'].map(x=>x.match(/[a-z]/))"
                        ".join('')")


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile():
    hostile = [
        "['a','b'].filter(x=>x.match(/[" + "a" * 5000,
        "['a','b'].filter(x=>x.match(/[a-" + "z" * 5000 + "]/))",
        "['a','b'].filter(x=>x.charCodeAt(" + "9" * 5000 + ")>47)",
        "['a','b'].filter(x=>x.charCodeAt(0)" + ">" * 5000,
        "['a','b'].filter(x=>x.charCodeAt(0)>-" + "5" * 5000 + ")",
        "['a','b'].filter(" + "x=>x.match(/[a-z]/).filter(" * 200,
        "['a','b'].filter(x=>x" + "." * 5000 + "match(/[a-z]/))",
        "['a','b'].filter(x=>x.charCodeAt(" + "0." * 2000 + ")>47)",
    ]
    t0 = time.perf_counter()
    for h in hostile:
        dlp.find_credential(h)
    dt = time.perf_counter() - t0
    return dt < 5.0


def p5_redos_f171_module():
    # The F171 hostile-input module (tests/test_wave110_f171_dlp_redos.py)
    # must stay 2/2 through the change.
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(REPO_ROOT, "tests"),
                            pattern="test_wave110_f171_dlp_redos.py")
    assert suite.countTestCases() == 2, "F171 module shape changed"
    runner = unittest.TextTestRunner(stream=open(os.devnull, "w"))
    result = runner.run(suite)
    return result.wasSuccessful()


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f443_filter_boolean():
    return _blocked("['" + _A + "','','" + _B + "'].filter(Boolean).join('')")


def p6_noreg_f443_fill():
    return _blocked("Array(2).fill('" + _A + "').join('').concat('" + _B
                    + "')")


def p6_noreg_f446_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f447_truthy():
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x!=='').join('')")


def p6_noreg_f454_multi():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p6_noreg_f459_positional():
    return _blocked("['" + _A + "','" + _B + "','x'].filter((x,i)=>i!==2)"
                    ".join('')")


def p6_noreg_f460_map_string():
    return _blocked("['" + _A + "','" + _B + "'].map(String).join('')")


def p6_noreg_f461_reverse():
    return _blocked("['" + _B + "','" + _A + "'].reverse().join('')")


def p6_noreg_f462_spread_concat():
    return _blocked("''.concat(...['" + _A + "','" + _B + "'])")


def p6_noreg_f463_tagged():
    return _blocked("['" + _A + "','" + _B + "'].join``")


def p6_noreg_f464_tostring_replace():
    return _blocked("['" + _A + "','" + _B + "'].toString().replace(/,/g,'')")


def p6_noreg_f465_pad():
    return _blocked("'" + _B + "'.padStart(21,'xoxb-012345678')")


def p6_noreg_f466_slice():
    return _blocked("['" + _A + "','" + _B + "','x'].slice(0,2).join('')")


def p6_noreg_f467_nullcmp():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x!=null).join('')")


def p6_noreg_f468_reflect():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-354 lane 2" in footer
    return ok


_PROBES = [
    ("p1-closure-match-arrow", p1_closure_match_arrow),
    ("p1-closure-match-function", p1_closure_match_function),
    ("p1-closure-match-paren", p1_closure_match_paren),
    ("p1-closure-match-ws", p1_closure_match_ws),
    ("p1-closure-ccmp-arrow", p1_closure_ccmp_arrow),
    ("p1-closure-ccmp-empty-dropped", p1_closure_ccmp_empty_dropped),
    ("p1-closure-ccmp-function", p1_closure_ccmp_function),
    ("p1-closure-ccmp-ops", p1_closure_ccmp_ops),
    ("p1-closure-ccmp-negative-bound", p1_closure_ccmp_negative_bound),
    ("p1-closure-compose", p1_closure_compose),
    ("p1-closure-fn-truthiness-unified", p1_closure_fn_truthiness_unified),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p2-control-f443-intact", p2_control_f443_intact),
    ("p2-control-f447-intact", p2_control_f447_intact),
    ("p2-control-f467-intact", p2_control_f467_intact),
    ("p2-control-f459-intact", p2_control_f459_intact),
    ("p3-pin-match-value", p3_pin_match_value),
    ("p3-pin-match-upper-value", p3_pin_match_upper_value),
    ("p3-pin-match-digit-value", p3_pin_match_digit_value),
    ("p3-pin-ccmp-value", p3_pin_ccmp_value),
    ("p3-pin-ccmp-idx1-value", p3_pin_ccmp_idx1_value),
    ("p3-pin-ccmp-oor-no-variant", p3_pin_ccmp_oor_no_variant),
    ("p3-pin-ccmp-negative-bound", p3_pin_ccmp_negative_bound),
    ("p3-pin-fn-strict-neq-value", p3_pin_fn_strict_neq_value),
    ("p3-pin-match-scope-fails", p3_pin_match_scope_fails),
    ("p3-pin-ccmp-scope-fails", p3_pin_ccmp_scope_fails),
    ("p3-pin-shadow-fails", p3_pin_shadow_fails),
    ("p4-discr-prose-quiet", p4_discr_prose_quiet),
    ("p4-discr-filter-on-string-quiet", p4_discr_filter_on_string_quiet),
    ("p4-discr-map-match-quiet", p4_discr_map_match_quiet),
    ("p5-redos-hostile", p5_redos_hostile),
    ("p5-redos-f171-module", p5_redos_f171_module),
    ("p6-noreg-f443-filter-boolean", p6_noreg_f443_filter_boolean),
    ("p6-noreg-f443-fill", p6_noreg_f443_fill),
    ("p6-noreg-f446-of", p6_noreg_f446_of),
    ("p6-noreg-f447-truthy", p6_noreg_f447_truthy),
    ("p6-noreg-f454-multi", p6_noreg_f454_multi),
    ("p6-noreg-f459-positional", p6_noreg_f459_positional),
    ("p6-noreg-f460-map-string", p6_noreg_f460_map_string),
    ("p6-noreg-f461-reverse", p6_noreg_f461_reverse),
    ("p6-noreg-f462-spread-concat", p6_noreg_f462_spread_concat),
    ("p6-noreg-f463-tagged", p6_noreg_f463_tagged),
    ("p6-noreg-f464-tostring-replace", p6_noreg_f464_tostring_replace),
    ("p6-noreg-f465-pad", p6_noreg_f465_pad),
    ("p6-noreg-f466-slice", p6_noreg_f466_slice),
    ("p6-noreg-f467-nullcmp", p6_noreg_f467_nullcmp),
    ("p6-noreg-f468-reflect", p6_noreg_f468_reflect),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:
        print("%-36s ERROR %s: %s" % (pid, type(e).__name__, e))
        return (pid, "ERROR")
    print("%-36s %s" % (pid, "HELD" if ok else "BREAK"))
    return (pid, "HELD" if ok else "BREAK")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w353_attack_probes.py",
               "w353_f461f462close_probes.py",
               "w353_f463close_probes.py",
               "w353_f464f465f466close_probes.py",
               "w353_f467f468close_probes.py",
               "w352_attack_probes.py",
               "w350_f447f448close_probes.py",
               "w346_dlp_composition_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g354-green-%s-%d" % (script.replace(".py", ""),
                                             os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
            raise AssertionError("green check failed: %s" % notes[-1])
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w354_f470close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
