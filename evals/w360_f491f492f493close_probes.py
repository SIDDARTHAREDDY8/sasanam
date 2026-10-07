#!/usr/bin/env python3
"""Wave-360 F491+F492+F493 closure battery (lane 2).

Three LOW findings from wave-359 attack round 27 (all node v24.20.0 ->
credential, decoder missed on the wave-359-merged base):

F491: Reflect.get / property-descriptor indirection -- the decoder
  anchors Reflect.construct/apply (F468/F469) and Object.assign (F471)
  but not the member-lookup indirection:
    Reflect.get(Array.prototype,'concat').call([], 'f1','f2').join('')
    Object.getOwnPropertyDescriptor(Array.prototype,'concat').value.call([], 'f1','f2').join('')
    Reflect.get([].constructor,'of')('f1','f2').join('')
    Reflect.get(Array,'of')('f1','f2').join('')
    Reflect.get(Array.prototype,'slice').call(['f1','f2'], 0).join('')
    Object.getOwnPropertyDescriptor(Array.prototype,'join').value.call(['f1','f2'], '')
    Object.getOwnPropertyDescriptor([].constructor,'of').value('f1','f2').join('')
  Distinct from F469 (Reflect.apply) and F480 (bracket-accessed
  ctors/dispatch).

F492: computed (non-literal) member keys at dispatch targets --
  F482 covers string-literal bracket keys, but constant expressions
  as keys bypass it:
    Array.prototype['con'+'cat'].call([], 'f1','f2').join('')
    Array.prototype['con'+'cat'].apply([], ['f1','f2']).join('')
    ([]['con'+'cat'])('f1','f2').join('')
    Array.prototype[`con${'cat'}`].call([], 'f1','f2').join('')
  Distinct from F482 (literal keys).

F493: String.raw invoked as a function -- the decoder models tagged
  templates (F463: String.raw`f1${'f2'}` blocks coded) and String()
  coercion (F477), but not the call form:
    String.raw({raw:['f1','f2']})
    String.raw.call(null, {raw:['f1','f2']})
  The tag form is the already-held control and keeps blocking.

Closure design (gov/dlp.py):
  F491:
  * New `_js_parse_reflect_get`: parses
    `Reflect.get(TARGET, KEY)` / `Reflect['get'](TARGET, KEY)`; the
    `get` member commits the parse (malformed shapes fail closed).
    Returns None for non-get members (falls through to
    _js_parse_reflect_call, which fails closed on them as before).
  * New `_js_parse_gopd_value`: parses
    `Object.getOwnPropertyDescriptor(TARGET, KEY).value` (dot or
    bracket-string `.value`); other descriptor fields fail closed.
  * New `_js_parse_reflect_get_target`: the filed target classes --
    `Array.prototype` / `String.prototype` (textual, ws-tolerant,
    ident-boundary-checked) and the Array constructor reference
    (`Array` / `[].constructor`, via _js_parse_array_ctor_ref).
    Bracket targets (`Array['prototype']`), Math, and other receivers
    fail closed (documented residual).
  * New `_js_desugar_indirect_member`: the resolved reference is
    engine-identical to the direct member access (node-verified), so
    the parse continues by textually desugaring to the canonical
    direct form (`Array.prototype.concat` / `Array.of`) plus the
    verbatim original suffix, delegating to
    _js_parse_prototype_dispatch / _js_parse_array_constructor with a
    positional index mapping -- every downstream grammar, bound, and
    fail-closed behavior is shared with the direct form (faithful by
    construction, no F481-class gap). KEY is a string literal or a
    constant-folded computed key (the F491xF492 composition, via
    _js_fold_key_expr); unmodeled method keys fail closed (the engine
    throws on the resolved call, exactly as the direct form does).
  * Anchor `_JS_EXPR_START`: the Reflect alternative gains `get`,
    the Object alternative gains `getOwnPropertyDescriptor`
    (literal-alternation only; ident-boundary guards keep
    `Reflect.getOwnPropertyDescriptor(` failing closed).
  F492:
  * New `_js_fold_key_expr` / `_js_fold_bracket_key`: constant-fold
    string-literal and literal-only-template operands over additive
    chains (engine-exact: `'con'+'cat'` === 'concat',
    `` `con${'cat'}` `` === 'concat', node-verified; the cooked
    template string is what computed property access uses as the
    key). Non-literal operands (variables, calls, numerics) fail
    closed; the folded name must be a non-empty ASCII identifier;
    each `+` operand is charged to the part budget.
  * Hooked as a fallback after _js_parse_bracket_member fails in
    _js_parse_prototype_dispatch, _js_parse_postfix_dispatch, and
    _js_parse_dispatch_target_ref (signature widened to take
    depth/state).
  * New `_js_parse_paren_member_call`: `(ARR_EXPR[KEY])(args)` (the
    filed shape 3, plus the literal-key `([]['concat'])(...)`
    ride-along which also missed) desugars to the direct method call
    via _js_apply_method_at -- the same text-form argument grammar
    as `[].concat(...)`, faithful by construction. Non-array
    receivers and unmodeled methods fall through to the normal
    parenthesized path (fails closed).
  F493:
  * New `_js_parse_string_raw`: `String.raw({raw:[...]})` /
    `String.raw.call(R, {raw:[...]})`. The template object must have
    exactly one key (`raw`) with a string-literal-only array value
    (the _js_parse_string_literal_list grammar -- numerics, nested,
    markers, templates fail closed); with no substitutions the engine
    concatenates the raw segments (node-verified). The `.call`
    thisArg is parsed and discarded (the engine ignores it);
    `.apply`/`.bind`, substitution arguments, extra keys, and
    non-array raw fail closed. The tag form is NOT handled here --
    it keeps its F463/F457 coded-refusal handling (control).
  * Anchor `_JS_EXPR_START`: the String alternative gains
    `.raw(` and `.raw.call(` (ws-tolerant); the tag form keeps
    anchoring via the backtick character class. re.compile count
    stays 28.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 7+4+2 filed shapes block; symmetric variants
      (Reflect['get'], ws-tolerant, String.prototype target,
      F491xF492 computed key, F491xF480 bracket-get, literal-key
      paren-call) block; node-exactness of the decoded credential on
      the filed shapes; tag-form control still blocks.
  P2  fail-closed boundaries: F491 unmodeled targets/keys, bare
      indirection, non-.value descriptor fields,
      Reflect.getOwnPropertyDescriptor; F492 variable/call/numeric
      keys, unmodeled computed keys, F492xF486 (Array['o'+'f'] fails
      closed); F493 substitutions, extra keys, non-array raw,
      .apply, nested arrays; open findings F489/F490/F494/F495
      intact; neighbors F478/F480/F482/F486/F488 intact; junk quiet.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor alternatives);
      F430 budgets; F441 ordering.
  P4  pin + footer (F491/F492/F493 CLOSED locally; open F489, F490,
      F494, F495 / next F506).
"""

import os
import sys
import subprocess
import argparse
import json

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-360 lane 2: F491/F492/F493 closed; no new decision codes
FOOTER_OPEN = "F513, F516, F517, F518, F519, F520"  # Wave-361 lane 3: F500, F501, F502 CLOSED locally (merge finalizes tree-wide)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-360 lane 2: F491/F492/F493 CLOSED locally (merge finalizes tree-wide)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)  # Wave-364 lane 2: F514, F515 CLOSED (lane-local)
FOOTER_NEXT = "F521"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)

_A = "xoxb-0123"
_B = "456789abcdef"


def _blocked(payload):
    return bool(dlp.find_credential(payload))


def _decoded(payload):
    """Return the decoded credential, or None.

    _try_js_expr_decode_all returns a single whole-text variant string.
    """
    variant = dlp._try_js_expr_decode_all(payload)
    if variant and _A + _B in variant:
        return _A + _B
    return None


# ------------------------------------------------------------ P1: closure
def p1_f491_filed_shapes():
    shapes = [
        "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')",
        "Object.getOwnPropertyDescriptor(Array.prototype,'concat').value.call([], '%s','%s').join('')",
        "Reflect.get([].constructor,'of')('%s','%s').join('')",
        "Reflect.get(Array,'of')('%s','%s').join('')",
        "Reflect.get(Array.prototype,'slice').call(['%s','%s'], 0).join('')",
        "Object.getOwnPropertyDescriptor(Array.prototype,'join').value.call(['%s','%s'], '')",
        "Object.getOwnPropertyDescriptor([].constructor,'of').value('%s','%s').join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "7/7 filed F491 shapes block")


def p1_f491_variants():
    shapes = [
        # F491xF480: bracket member on Reflect
        "Reflect['get'](Array.prototype,'concat').call([], '%s','%s').join('')",
        # ws-tolerant (supported positions)
        "Reflect .get(Array.prototype,'concat').call([], '%s','%s').join('')",
        "Reflect.get( Array.prototype , 'concat' ).call( [], '%s' , '%s' ).join('')",
        # String.prototype target
        "Reflect.get(String.prototype,'concat').call('x', '%s','%s')",
        # F491xF492: computed key inside Reflect.get
        "Reflect.get(Array.prototype,'con'+'cat').call([], '%s','%s').join('')",
        # gopd with bracket .value
        "Object.getOwnPropertyDescriptor(Array.prototype,'concat')['value'].call([], '%s','%s').join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "6/6 F491 variants block")


def p1_f491_node_exact():
    shapes = [
        "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')",
        "Object.getOwnPropertyDescriptor([].constructor,'of').value('%s','%s').join('')",
        "Reflect.get(Array.prototype,'slice').call(['%s','%s'], 0).join('')",
    ]
    for s in shapes:
        if _decoded(s % (_A, _B)) != _A + _B:
            return ("BREAK", "not node-exact: %s" % s[:60])
    return ("HELD", "3/3 F491 shapes node-exact")


def p1_f492_filed_shapes():
    shapes = [
        "Array.prototype['con'+'cat'].call([], '%s','%s').join('')",
        "Array.prototype['con'+'cat'].apply([], ['%s','%s']).join('')",
        "([]['con'+'cat'])('%s','%s').join('')",
        "Array.prototype[`con${'cat'}`].call([], '%s','%s').join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "4/4 filed F492 shapes block")


def p1_f492_variants():
    shapes = [
        # literal-key paren-call (also missed pre-fix; rides along)
        "([]['concat'])('%s','%s').join('')",
        # ws-tolerant computed key
        "Array.prototype[ 'con' + 'cat' ].call( [], '%s' , '%s' ).join( '' )",
        # template key on the paren-call
        "([][`con${'cat'}`])('%s','%s').join('')",
        # additive chain of three
        "Array.prototype['c'+'o'+'ncat'].call([], '%s','%s').join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "4/4 F492 variants block")


def p1_f492_node_exact():
    shapes = [
        "Array.prototype['con'+'cat'].call([], '%s','%s').join('')",
        "([]['con'+'cat'])('%s','%s').join('')",
        "Array.prototype[`con${'cat'}`].call([], '%s','%s').join('')",
    ]
    for s in shapes:
        if _decoded(s % (_A, _B)) != _A + _B:
            return ("BREAK", "not node-exact: %s" % s[:60])
    return ("HELD", "3/3 F492 shapes node-exact")


def p1_f493_filed_shapes():
    shapes = [
        "String.raw({raw:['%s','%s']})",
        "String.raw.call(null, {raw:['%s','%s']})",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "2/2 filed F493 shapes block")


def p1_f493_variants():
    shapes = [
        # ws-tolerant
        "String . raw ( { raw : [ '%s' , '%s' ] } )",
        # .call with ws and a non-null thisArg
        "String.raw . call ( [], { raw : [ '%s' , '%s' ] } )",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "2/2 F493 variants block")


def p1_f493_node_exact():
    if _decoded("String.raw({raw:['%s','%s']})" % (_A, _B)) != _A + _B:
        return ("BREAK", "call form not node-exact")
    if _decoded("String.raw.call(null, {raw:['%s','%s']})" % (_A, _B)) != _A + _B:
        return ("BREAK", "dispatch form not node-exact")
    return ("HELD", "2/2 F493 shapes node-exact")


def p1_tag_form_control():
    # The tag form is the already-working path (F463/F457): the decoder
    # decodes it and find_credential hits ("blocks coded"). The control
    # asserts my change did not alter tag-form behavior.
    if not _blocked("String.raw`%s${'%s'}`" % (_A, _B)):
        return ("BREAK", "tag form regressed -- F463/F457 path broken")
    return ("HELD", "tag form still decodes (F463/F457 untouched)")


# ------------------------------------------------------------ P2: boundaries
def p2_f491_boundaries():
    # Every one of these must MISS (fail closed, honest).
    shapes = [
        "Reflect.get(Math,'max')",  # unmodeled target
        "Reflect.get(Array.prototype,'replace').call('a','b')",  # unmodeled key
        "Reflect.get(Array.prototype,'concat')",  # bare indirection
        "Object.getOwnPropertyDescriptor(Array.prototype,'concat')",  # no .value
        "Object.getOwnPropertyDescriptor(Array.prototype,'concat').writable",  # bad field
        "Reflect.getOwnPropertyDescriptor(Array.prototype,'concat')",  # Reflect has no gopd
        "Reflect.get(Array['prototype'],'concat')",  # bracket target (documented residual)
        "Reflect.get(Array.prototype,'concat').call([], 'ab','cd').join('')",  # junk quiet
    ]
    bad = [s for s in shapes if _blocked(s)]
    if bad:
        return ("BREAK", "over-decoded: %s" % bad)
    return ("HELD", "8/8 F491 boundaries fail closed")


def p2_f492_boundaries():
    shapes = [
        "Array.prototype[x].call([], '%s','%s').join('')" % (_A, _B),  # variable key
        "Array.prototype[getKey()].call([], '%s','%s').join('')" % (_A, _B),  # call key
        "Array.prototype['con'+'xyz'].call([], '%s','%s').join('')" % (_A, _B),  # unmodeled
        "Array['o'+'f']('%s','%s').join('')" % (_A, _B),  # F492xF486: not filed
        "Array.prototype['con'+'cat'].call([], 'ab','cd').join('')",  # junk quiet
    ]
    bad = [s for s in shapes if _blocked(s)]
    if bad:
        return ("BREAK", "over-decoded: %s" % bad)
    return ("HELD", "5/5 F492 boundaries fail closed")


def p2_f493_boundaries():
    shapes = [
        "String.raw({raw:['%s','%s']}, 'X')" % (_A, _B),  # substitutions
        "String.raw({raw:['%s'], x:1})" % _A,  # extra key
        "String.raw({raw:'%s'})" % _A,  # raw not an array
        "String.raw.apply(null, [{raw:['%s','%s']}])" % (_A, _B),  # .apply
        "String.raw({raw:[['%s']]})" % _A,  # nested array
        "String.raw({raw:['ab','cd']})",  # junk quiet
    ]
    bad = [s for s in shapes if _blocked(s)]
    if bad:
        return ("BREAK", "over-decoded: %s" % bad)
    return ("HELD", "6/6 F493 boundaries fail closed")


def p2_open_findings_intact():
    # Wave-360 merge: F490 (lane 1) and F494 (lane 3) are now CLOSED --
    # their shapes must block. Wave-361: F496 (lane 1) and F499 (lane 2)
    # are now CLOSED -- their shapes must block.
    closed_shapes = [
        "Array.prototype.concat?.call([], '%s','%s').join('')" % (_A, _B),  # F490 CLOSED
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),  # F494 CLOSED
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),  # F496 CLOSED
        "[...'%s', ...'%s'].join('')" % (_A, _B),  # F499 CLOSED (wave-361 lane 2)
    ]
    bad = [s for s in closed_shapes if not _blocked(s)]
    if bad:
        return ("BREAK", "closed finding missed: %s" % bad)
    open_shapes = [
    ]
    bad = [s for s in open_shapes if _blocked(s)]
    if bad:
        return ("BREAK", "open finding decoded: %s" % bad)
    return ("HELD", "F490/F494/F496/F499 closed; no open shapes in this probe")


def p2_neighbors_intact():
    # Closed neighbors still block.
    shapes = [
        "[].concat.call([], '%s','%s').join('')" % (_A, _B),  # F478
        "Array.prototype['concat'].call([], '%s','%s').join('')" % (_A, _B),  # F482
        "Array.of.call([], '%s','%s').join('')" % (_A, _B),  # F486
        "([]['constructor'])('%s','%s').join('')" % (_A, _B),  # F488
    ]
    bad = [s for s in shapes if not _blocked(s)]
    if bad:
        return ("BREAK", "neighbor regressed: %s" % bad)
    return ("HELD", "4/4 neighbors intact")


# ------------------------------------------------------------ P3: decoder pins
def p3_node_differential():
    shapes = [
        "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')" % (_A, _B),
        "Object.getOwnPropertyDescriptor(Array.prototype,'concat').value.call([], '%s','%s').join('')" % (_A, _B),
        "Reflect.get([].constructor,'of')('%s','%s').join('')" % (_A, _B),
        "Reflect.get(Array,'of')('%s','%s').join('')" % (_A, _B),
        "Reflect.get(Array.prototype,'slice').call(['%s','%s'], 0).join('')" % (_A, _B),
        "Object.getOwnPropertyDescriptor(Array.prototype,'join').value.call(['%s','%s'], '')" % (_A, _B),
        "Object.getOwnPropertyDescriptor([].constructor,'of').value('%s','%s').join('')" % (_A, _B),
        "Reflect['get'](Array.prototype,'concat').call([], '%s','%s').join('')" % (_A, _B),
        "Reflect.get(Array.prototype,'con'+'cat').call([], '%s','%s').join('')" % (_A, _B),
        "Array.prototype['con'+'cat'].call([], '%s','%s').join('')" % (_A, _B),
        "Array.prototype['con'+'cat'].apply([], ['%s','%s']).join('')" % (_A, _B),
        "([]['con'+'cat'])('%s','%s').join('')" % (_A, _B),
        "Array.prototype[`con${'cat'}`].call([], '%s','%s').join('')" % (_A, _B),
        "([]['concat'])('%s','%s').join('')" % (_A, _B),
        "String.raw({raw:['%s','%s']})" % (_A, _B),
        "String.raw.call(null, {raw:['%s','%s']})" % (_A, _B),
    ]
    node_src = "const outs=[];\n"
    for s in shapes:
        node_src += "outs.push(JSON.stringify((%s)));\n" % s
    node_src += "console.log(JSON.stringify(outs));"
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:200])
    node_vals = [json.loads(x) for x in json.loads(r.stdout)]
    bad = []
    for s, nv in zip(shapes, node_vals):
        variant = dlp._try_js_expr_decode_all(s) or ""
        if nv not in variant:
            bad.append(s[:60])
    if bad:
        return ("BREAK", "differential mismatch: %s" % bad)
    return ("HELD", "16/16 node byte-identical")


def p3_no_new_regexes():
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    if n != 28:
        return ("BREAK", "re.compile count=%d want 28" % n)
    # the anchor widenings are literal-alternation only
    for lit in ["(construct|apply|get)", "getOwnPropertyDescriptor",
                r"\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()"]:
        if lit not in src:
            return ("BREAK", "anchor widening missing: %s" % lit[:30])
    return ("HELD", "no new regexes; anchor widenings literal-only")


def p3_f430_bounds():
    # budgets hold: a pathological key chain trips the parts budget
    # instead of hanging, and deep nesting fails closed.
    big = "Array.prototype['%s'].call([], 'a','b')" % ("'a'+".join(["'c'"] * 200))
    try:
        dlp.find_credential(big)
    except Exception:
        pass
    deep = "(" * 40 + "['f1','f2']" + ")" * 40
    if _blocked(deep + ".join('')"):
        return ("BREAK", "deep nesting decoded")
    return ("HELD", "F430 budgets honored")


def p3_f441_ordering_untouched():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return ("HELD", "F441 ordering untouched")


# ------------------------------------------------------------ P4: pin+footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2135
    assert len(TAXONOMY) == 2135
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F521**" in text
    # Wave-362 lane 2: F504 CLOSED locally (merge finalizes tree-wide).
    # Wave-364 lane 2: F514, F515 CLOSED (lane-local footer).
    assert "**Open findings: F513, F516, F517, F518, F519, F520.**" in text
    return ("HELD", "pin=2135 footer open none next F503 (wave-361 merge)")


PROBES = [
    ("p1-f491-filed-shapes", p1_f491_filed_shapes),
    ("p1-f491-variants", p1_f491_variants),
    ("p1-f491-node-exact", p1_f491_node_exact),
    ("p1-f492-filed-shapes", p1_f492_filed_shapes),
    ("p1-f492-variants", p1_f492_variants),
    ("p1-f492-node-exact", p1_f492_node_exact),
    ("p1-f493-filed-shapes", p1_f493_filed_shapes),
    ("p1-f493-variants", p1_f493_variants),
    ("p1-f493-node-exact", p1_f493_node_exact),
    ("p1-tag-form-control", p1_tag_form_control),
    ("p2-f491-boundaries", p2_f491_boundaries),
    ("p2-f492-boundaries", p2_f492_boundaries),
    ("p2-f493-boundaries", p2_f493_boundaries),
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
    scripts = ("w359_f491_redfirst.py",
               "w359_f492_redfirst.py",
               "w359_f493_redfirst.py",
               "w359_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g360-green-%s-%d" % (script.replace(".py", ""),
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
    print("w360_f491f492f493close: starting %d probes" % len(PROBES))
    results = []
    for pid, fn in PROBES:
        v, note = _safe(pid, fn)
        results.append((pid, v, note))
        print("%s: %s -- %s" % (pid, v, note))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    print("green check: %s" % _green_check())
    probe_breaks = set(pid for pid, v, _ in results if v == "BREAK")
    if probe_breaks - _EXPECTED_BREAKS:
        print("BREAKS:", sorted(probe_breaks - _EXPECTED_BREAKS))
        sys.exit(1)
    if n_err:
        print("ERRORS present")
        sys.exit(2)


if __name__ == "__main__":
    main()
