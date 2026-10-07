#!/usr/bin/env python3
"""Wave-359 F486+F487+F488 closure battery (lane 3).

Three LOW findings from wave-358 attack round 26 (all node v24.20.0 ->
credential, decoder missed on the wave-358-merged base):

F486: .call/.apply dispatch on STATIC factory methods -- F478 covers
  .call/.apply on PROTOTYPE methods, F476 covers the factories in
  DIRECT form, F458 covers String.fromCharCode direct. Dispatching
  the factories themselves bypasses all three anchors:
    Array.of.call([], 'f1','f2').join('')
    [].constructor.of.call([].constructor, 'f1','f2').join('')
    String.fromCharCode.apply(null, [120,111,...])
  Distinct from F478 (prototype methods), F476 (direct factory),
  F458 (direct fromCharCode), F480-A (dispatch of the CONSTRUCTOR
  itself: Array.apply(Array,['f1','f2']) -- here the dispatch target
  is the factory method).

F487: .call dispatch on ARRAY-LIKE (non-array) receivers -- the F478
  closure validates the receiver as a parsed array or string, but the
  engine accepts any array-like ({length, indexed elements}) for
  join/slice/filter:
    Array.prototype.join.call({length:2, 0:'f1', 1:'f2'}, '')
    Array.prototype.slice.call({length:2, 0:'f1', 1:'f2'}, 0).join('')
    Array.prototype.filter.call({length:2, 0:'f1', 1:'f2'}, x=>true).join('')
  Distinct from F478 (array/string receivers hold) and F473
  (array-receiver modeling).

F488: direct invocation of constructor-function spellings through
  non-identifier callees -- the decoder anchors the Array constructor
  call on the identifier form (Array('f1','f2') blocks coded); the
  same function reached as ([].constructor)('f1','f2'),
  Object.getPrototypeOf([]).constructor('f1','f2'),
  ([]['constructor'])('f1','f2'),
  (Object.getPrototypeOf([])['constructor'])('f1','f2') node-evaluates
  to the credential while the decoder produced zero variants.
  Distinct from F476 (the .of factory) and F480-A (call/apply
  DISPATCH of the constructor -- here there is no dispatch, just a
  differently-spelled direct call).

Closure design (gov/dlp.py):
  F486:
  * `_js_parse_of_args` refactored: inner arg grammar extracted as
    `_js_parse_of_args_inner(text, k, state, closer)` (')' for direct,
    ']' for .apply); the direct form is byte-identical through the
    refactor.
  * `_js_parse_fromcharcode_args` refactored: inner codepoint grammar
    extracted as `_js_parse_fromcharcode_args_inner(text, i, closer)`.
  * New `_js_parse_dispatch_thisarg`: parses the Function.prototype
    dispatch thisArg (constructor ref, null/undefined/true/false
    keyword, or additive value) and DISCARDS it -- Array.of and
    String.fromCharCode ignore `this` per spec (node-verified:
    Array.of.call([],...), Array.of.call(null,...),
    String.fromCharCode.apply(null,...) all engine-identical to the
    direct form).
  * New `_js_parse_of_dispatch` / `_js_parse_fcc_dispatch`: desugar
    FACTORY.call/apply to the direct factory path, reusing the exact
    direct-form arg grammars (faithful by construction -- same
    fail-closed arg classes, no F481-class gap). `.bind` on a factory
    fails closed (bound factory is not a decodable value).
  * Hooks: `_js_parse_array_of` (Array.of.call/apply),
    `_js_parse_ctor_factory` ([].constructor.of.call/apply), and the
    String primary branch (String.fromCharCode.call/apply, dot and
    bracket-string member forms). The dispatch head commits the
    parse: a malformed dispatch fails closed, never falls through.
  F487:
  * New `_js_parse_arraylike_recv`: parses `{length:N, 0:v0, ...}`
    to a _JSArr with engine-exact index semantics. length must be a
    decimal integer literal 0.._JS_EXPR_MAX_PARTS; every index in
    [0, length) must be explicitly present (HOLES fail closed --
    the engine's filter SKIPS holes but visits explicit undefined,
    and the flat _JSArr cannot distinguish them -- rejected, never
    mis-decoded); values are string literals or F479 markers
    (null/undefined/true/false -- explicit null joins as '', exactly
    as the engine coerces); duplicate keys take the later value
    (engine-exact); string keys ('0', 'length') accepted
    (engine-exact); extra non-index properties, getters, spread,
    non-numeric length all fail closed.
  * Hooked into `_js_apply_fn_dispatch` receiver parse: a '{' head
    commits to the array-like parse (the additive grammar cannot
    parse '{' anyway).
  F488:
  * Anchor `_JS_EXPR_START`: the Object alternative gains
    `getPrototypeOf` (a new member-name alternative -- NOT
    character-class-only; pinned exactly in p3). re.compile count
    stays 28.
  * New `_js_parse_ctor_callee`: peeks the constructor-function
    callee reference ([].constructor, []['constructor'],
    Object.getPrototypeOf([]).constructor,
    Object.getPrototypeOf([])['constructor'] -- all engine-identical
    to Array, node-verified).
  * Hooks: the `(` primary branch ((CALLEE)(args)), the `[` primary
    branch ([]['constructor'](args) non-paren), `_js_parse_ctor_factory`
    ([].constructor(args) non-paren), and the Object primary branch
    (Object.getPrototypeOf([]).constructor(args) non-paren). All
    desugar to the F454 multi-arg Array constructor grammar
    (string-literal-only args). `(f)`, `(a||b)`, and chained-paren
    callees fail closed (documented).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 3+3+4 filed shapes block; symmetric variants
      (of.apply, fcc.call, non-paren ctor) block; node-exactness of
      the decoded credential on the filed shapes.
  P2  fail-closed boundaries: factory .bind; holes/len-string/extra
      props in array-like; (f)/(a||b)/chained-paren callees;
      numeric ctor args; F482-F485 OPEN shapes intact; F476/F478/F480
      neighbors intact; junk quiet.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string with the
      F488 getPrototypeOf widening); F430 bounds; F441 ordering.
  P4  pin + footer (F486/F487/F488 CLOSED; open F482-F485 / next F489).
"""

import os
import sys
import subprocess
import argparse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-359 lane 3: F486/F487/F488 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569"  # Wave-361 lane 1: F496, F497 CLOSED locally (merge finalizes tree-wide)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-360 lane 3: F494, F495 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 3: F486/F487/F488 CLOSED locally (merge finalizes tree-wide)  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-359 lane 3: F486/F487/F488 CLOSED locally (merge finalizes tree-wide)  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
FOOTER_NEXT = "F570"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)

# Constructed via concatenation: the write path redacts credential literals.
# Neither fragment matches the credential pattern alone (xoxb- + 10+ chars):
# _A has only 5 chars after the prefix; _B has no prefix. Their
# concatenation CRED is the full credential.
_A = "xox" + "b-01234"
_B = "56789" + "abcdef"
CRED = _A + _B
_FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        97, 98, 99, 100, 101, 102]
_FCC_S = ",".join(str(c) for c in _FCC)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    r = dlp._try_js_expr_decode(payload, 0)
    return r[0] if r else None


def _verdict(payload, want_block):
    try:
        hit = _blocked(payload)
    except Exception as e:  # noqa: BLE001 -- loud is a failure here
        return ("BREAK", "raised %r" % (e,))
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "hit=%s want_block=%s" % (hit, want_block))


# ------------------------------------------------------------- P1: closure
def p1_f486_filed_shapes():
    cases = [
        ("Array.of.call([], '" + _A + "','" + _B + "').join('')", True),
        ("[].constructor.of.call([].constructor, '" + _A + "','" + _B + "').join('')", True),
        ("String.fromCharCode.apply(null, [" + _FCC_S + "])", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed F486 shapes block" % (len(cases) - len(bad), len(cases)))


def p1_f486_variants():
    cases = [
        ("Array.of.apply([], ['" + _A + "','" + _B + "']).join('')", True),
        ("String.fromCharCode.call(null, " + _FCC_S + ")", True),
        ("String['fromCharCode'].apply(null, [" + _FCC_S + "])", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F486 symmetric variants block" % (len(cases) - len(bad), len(cases)))


def p1_f486_node_exact():
    # The decoded credential is byte-identical to the node evaluation.
    got = _decoded("Array.of.call([], '" + _A + "','" + _B + "').join('')")
    if got != CRED:
        return ("BREAK", "of.call decoded %r want %r" % (got, CRED))
    got = _decoded("String.fromCharCode.apply(null, [" + _FCC_S + "])")
    if got != CRED:
        return ("BREAK", "fcc.apply decoded %r want %r" % (got, CRED))
    return ("HELD", "F486 decodes node-exact")


def p1_f487_filed_shapes():
    cases = [
        ("Array.prototype.join.call({length:2, 0:'" + _A + "', 1:'" + _B + "'}, '')", True),
        ("Array.prototype.slice.call({length:2, 0:'" + _A + "', 1:'" + _B + "'}, 0).join('')", True),
        ("Array.prototype.filter.call({length:2, 0:'" + _A + "', 1:'" + _B + "'}, x=>true).join('')", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed F487 shapes block" % (len(cases) - len(bad), len(cases)))


def p1_f487_markers():
    # F487 x F479: explicit null/bool markers in the array-like decode
    # node-exactly (node: null->'', true->'true').
    got = _decoded("Array.prototype.join.call({length:3, 0:'" + _A + "', 1:'" + _B + "', 2:null}, '')")
    if got != CRED:
        return ("BREAK", "array-like null decoded %r want %r" % (got, CRED))
    return ("HELD", "F487 marker coercion node-exact")


def p1_f488_filed_shapes():
    cases = [
        ("([].constructor)('" + _A + "','" + _B + "').join('')", True),
        ("Object.getPrototypeOf([]).constructor('" + _A + "','" + _B + "').join('')", True),
        ("([]['constructor'])('" + _A + "','" + _B + "').join('')", True),
        ("(Object.getPrototypeOf([])['constructor'])('" + _A + "','" + _B + "').join('')", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed F488 shapes block" % (len(cases) - len(bad), len(cases)))


def p1_f488_variants():
    cases = [
        ("[].constructor('" + _A + "','" + _B + "').join('')", True),
        ("[]['constructor']('" + _A + "','" + _B + "').join('')", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F488 non-paren variants block" % (len(cases) - len(bad), len(cases)))


def p1_f488_node_exact():
    got = _decoded("([].constructor)('" + _A + "','" + _B + "').join('')")
    if got != CRED:
        return ("BREAK", "paren-ctor decoded %r want %r" % (got, CRED))
    got = _decoded("Object.getPrototypeOf([]).constructor('" + _A + "','" + _B + "').join('')")
    if got != CRED:
        return ("BREAK", "getproto-ctor decoded %r want %r" % (got, CRED))
    return ("HELD", "F488 decodes node-exact")


# ---------------------------------------------------- P2: fail-closed bounds
def p2_factory_bind_closed():
    # .bind on a static factory is not modeled (bound factory is not a
    # decodable value) -- fails closed.
    cases = [
        "Array.of.bind([], '" + _A + "').join('')",
        "String.fromCharCode.bind(null, 120).join('')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d factory .bind shapes fail closed" % (len(cases) - len(bad), len(cases)))


def p2_arraylike_bounds():
    cases = [
        # hole (missing index) -- engine filter skips holes; fail closed
        "Array.prototype.join.call({length:3, 0:'" + _A + "', 2:'" + _B + "'}, '')",
        # non-numeric length
        "Array.prototype.join.call({length:'2', 0:'" + _A + "', 1:'" + _B + "'}, '')",
        # extra non-index property
        "Array.prototype.join.call({length:2, 0:'" + _A + "', 1:'" + _B + "', foo:'x'}, '')",
        # index beyond length
        "Array.prototype.join.call({length:2, 0:'" + _A + "', 1:'" + _B + "', 5:'x'}, '')",
        # no length
        "Array.prototype.join.call({0:'" + _A + "', 1:'" + _B + "'}, '')",
        # non-constant getter (unmodelable -- the engine evaluates
        # arbitrary getter code; F489 models only `get length()
        # { return N; }` with a constant numeric N)
        "Array.prototype.join.call({get length(){return n}, 0:'" + _A + "', 1:'" + _B + "'}, '')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d array-like bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p2_ctor_callee_bounds():
    cases = [
        # non-constructor callee
        "(f)('" + _A + "','" + _B + "').join('')",
        # logical-or callee
        "(a || b)('" + _A + "','" + _B + "').join('')",
        # chained parens (documented fail-closed)
        "(([].constructor))('" + _A + "','" + _B + "').join('')",
        # numeric ctor arg (F454 arg class)
        "([].constructor)('" + _A + "',123).join('')",
        # junk stays quiet
        "([].constructor)('ab','cd').join('')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d ctor-callee bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p2_open_findings_intact():
    # F482-F485 are now CLOSED (wave-359 lanes 1+2) -- their shapes
    # must now block. (Lane-3 version asserted they stayed open;
    # updated at the wave-359 merge.)
    cases = [
        # F484: nested-array factory arg
        "[].constructor.of('" + _A + "',['" + _B + "']).join('')",
        # F482: bracket member under call dispatch
        "Array.prototype['concat'].call([],['" + _A + "','" + _B + "']).join('')",
    ]
    quiet = [c for c in cases if _verdict(c, True)[0] == "BREAK"]
    return ("HELD" if not quiet else "BREAK",
            "%d/%d closed shapes block" % (len(cases) - len(quiet), len(cases)))


def p2_neighbors_intact():
    cases = [
        ("[].constructor.of('" + _A + "','" + _B + "').join('')", True),   # F476
        ("Array.prototype.concat.call([], '" + _A + "','" + _B + "').join('')", True),  # F478
        ("Array.apply(Array, ['" + _A + "','" + _B + "']).join('')", True),  # F480
        ("Array.of.call([], 'ab','cd').join('')", False),  # junk quiet
        ("Array.prototype.join.call({length:2, 0:'ab', 1:'cd'}, '')", False),  # junk quiet
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d neighbor shapes intact" % (len(cases) - len(bad), len(cases)))


# -------------------------------------------------------- P3: decoder pins
def p3_node_differential():
    # Subprocess node differential: byte-identical on a sample of the
    # new shapes (node v24.20.0).
    payloads = [
        "Array.of.call([], 'ab','cd').join('')",
        "String.fromCharCode.apply(null, [104,105])",
        "Array.prototype.join.call({length:2, 0:'ab', 1:'cd'}, '')",
        "Array.prototype.slice.call({length:2, 0:'ab', 1:'cd'}, 0).join('')",
        "([].constructor)('ab','cd').join('')",
        "Object.getPrototypeOf([]).constructor('ab','cd').join('')",
    ]
    script = "console.log(JSON.stringify([%s].map(s=>eval(s))))" % (
        ",".join("'%s'" % p.replace("'", "\\'") for p in payloads))
    try:
        r = subprocess.run(["node", "-e", script], capture_output=True,
                           text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "node subprocess failed: %r" % (e,))
    import json
    try:
        expected = json.loads(r.stdout.strip())
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "node output unparseable: %r" % (e,))
    bad = []
    for p, want in zip(payloads, expected):
        got = _decoded(p)
        if got != want:
            bad.append((p, got, want))
    if bad:
        return ("BREAK", "differential mismatch: %r" % (bad[:2],))
    return ("HELD", "%d-shape node differential byte-identical" % len(payloads))


def p3_no_new_regexes():
    import re
    # F488: the Object anchor alternative gains getPrototypeOf (a new
    # member-name alternative, pinned exactly) -- re.compile count
    # unchanged. Wave-360 lane 1 (F490): the Reflect alternative gains
    # (\?\.|\.) for Reflect?.apply shapes. Wave-360 lane 2
    # (F491/F493): the Reflect alternative gains `get`, the Object
    # alternative gains `getOwnPropertyDescriptor`, and the String
    # alternative gains `.raw(` / `.raw.call(` -- literal-alternation
    # only, pinned exactly; re.compile count unchanged.
    # Wave-362 lane 2 (F504): the Reflect bracket-member class gains
    # backtick and nested-bracket (literal-alternation only);
    # re.compile count unchanged.
    # F505 (wave-362 lane 3): String.fromCodePoint alternative
    # added (literal-alternation only -- the same F468
    # precedent); re.compile count unchanged (28).
    # F508 (wave-363 lane 2): Array.from alternative added (literal-alternation only); re.compile count unchanged (28).
    # F510 (wave-363 lane 4): the Object alternative gains `values`
    # (literal-alternation only); re.compile count unchanged (28).
    # F525 (wave-365 lane 2): the Object dot-member alternative gains
    # getOwnPropertyNames/getOwnPropertyDescriptors (key/descriptor
    # enumeration indirection) -- new member-name alternatives, pinned
    # exactly here; re.compile count unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String\.fromCodePoint|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|"
        r"[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|"
        r"apply|call|from)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|"
        r"[ \t\n\r]*\[[ \t\n\r]*['\"`\[])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor|getOwnPropertyNames|getOwnPropertyDescriptors|values|keys|entries)|"
        r"[ \t\n\r]*\[[ \t\n\r]*['\"])|\(")
    for s in ["Array.apply(", "Array.of.call", "Array.from(", "[].constructor.of.call",
              "String.fromCharCode.apply", "Object.getPrototypeOf",
              "Array.prototype.concat", "Object.assign"]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned with F488 widening")


def p3_f430_bounds():
    big = "Array.of.call([], %s).join('')" % ",".join(
        "'x%d'" % i for i in range(200))
    if _blocked(big):
        return ("BREAK", "part budget not tripped")
    big2 = "Array.prototype.join.call({length:200, %s}, '')" % ",".join(
        "%d:'x'" % i for i in range(200))
    if _blocked(big2):
        return ("BREAK", "array-like length budget not tripped")
    return ("HELD", "F430 budgets honored")


def p3_f441_ordering_untouched():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return ("HELD", "F441 ordering untouched")


# ------------------------------------------------------------ P4: pin+footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert len(TAXONOMY) == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F570**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    assert "**Open findings: F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569.**" in text  # Wave-361 lane 1: F496, F497 CLOSED locally (merge finalizes tree-wide); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    return ("HELD", "pin=2140 footer open F503, F504, F505 next F506 (wave-361 merge)")


PROBES = [
    ("p1-f486-filed-shapes", p1_f486_filed_shapes),
    ("p1-f486-variants", p1_f486_variants),
    ("p1-f486-node-exact", p1_f486_node_exact),
    ("p1-f487-filed-shapes", p1_f487_filed_shapes),
    ("p1-f487-markers", p1_f487_markers),
    ("p1-f488-filed-shapes", p1_f488_filed_shapes),
    ("p1-f488-variants", p1_f488_variants),
    ("p1-f488-node-exact", p1_f488_node_exact),
    ("p2-factory-bind-closed", p2_factory_bind_closed),
    ("p2-arraylike-bounds", p2_arraylike_bounds),
    ("p2-ctor-callee-bounds", p2_ctor_callee_bounds),
    ("p2-open-findings-intact", p2_open_findings_intact),
    ("p2-neighbors-intact", p2_neighbors_intact),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f430-bounds", p3_f430_bounds),
    ("p3-f441-ordering-untouched", p3_f441_ordering_untouched),
    ("p4-pin-and-footer", p4_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        return fn()
    except AssertionError as e:
        return ("BREAK", "assert: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%r" % (e,))


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Parses both verdict formats
    (wave-320 class: a parse matching neither format passes vacuously)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w358_f480close_probes.py",
               "w358_f481close_probes.py",
               "w357_f478close_probes.py",
               "w357_f479close_probes.py",
               "w358_attack_probes.py",
               "w357_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g359-green-%s-%d" % (script.replace(".py", ""),
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
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w359_f486f487f488close: starting %d probes" % len(PROBES))
    results = []
    for pid, fn in PROBES:
        v, note = _safe(pid, fn)
        results.append((pid, v, note))
        print("%-28s %s | %s" % (pid, v, note))
    green = _green_check()
    print("p9-green-check: %s" % green.split("\n")[0])
    breaks = sorted(pid for pid, v, _ in results
                    if v == "BREAK" and pid not in _EXPECTED_BREAKS)
    errors = sorted(pid for pid, v, _ in results if v == "ERROR")
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v, _ in results if v == "BREAK"))
    print("w359_f486f487f488close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(results) - len(breaks) - len(errors),
             len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    if missing:
        print("missing expected BREAKs: %s" % missing)
    if "FAILED" in green:
        print("GREEN CHECK FAILED")
        return 1
    return 1 if (breaks or errors or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
