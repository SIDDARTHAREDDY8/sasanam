#!/usr/bin/env python3
"""Wave-369 F547/F561/F566 closure battery (lane 1: array-read family).

Three LOW findings from wave-368 attack round 36 (node v24.20.0 ->
credential, decoder missed on the wave-368-merged base):

F547: array-literal element index reads. The decoder resolved no
array-element index reads:
  ['f1','f2'][0]+['f1','f2'][1], ['f1','f2'].at(0)+['f1','f2'].at(1),
  [['f1'],['f2']][0][0]+[['f1'],['f2']][1][0],
  ['f1','f2'].at(0)+['f1','f2'].at(-1)
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F535 (object literals) and
F527/F532 (bracket keys resolving to METHOD names, not elements).

F561: ES2023 copy-on-write array methods. F516 covers MUTATING
methods via .call dispatch, but toReversed/with are NON-mutating,
called DIRECTLY, returning new arrays:
  ['f2','f1'].toReversed().join(''), ['zz','f2'].with(0,'f1').join('')
both node-evaluate to the exact credential while the decoder produced
zero variants. Distinct from F516 (mutating, .call dispatch) and F511
(splice dispatch).

F566: Array.prototype.at via .call dispatch. F547 covers DIRECT
.at()/index reads, but the .call dispatch form is a different
dispatch mechanism (F511 precedent: .call dispatch is its own finding
class):
  Array.prototype.at.call(['f1','f2'],0)+Array.prototype.at.call(['f1','f2'],1)
node-evaluates to the exact credential while the decoder produced zero
variants. Distinct from F547 (direct reads) and F511 (splice dispatch).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

* `_js_parse_indexed_array_read` (new): `[INTLIT]` / `['INTLIT']`
  element reads on a parsed _JSArr, hooked FIRST in the
  `_js_parse_postfix` `[` branch (disjoint from the method-name
  folds -- integer-literal vs method-name keys). Non-negative
  literal indices only (decimal or 0x via _js_parse_number,
  engine-exact: [0x1] === [1]; canonical-digit string literals
  ['0'] too). Bracket [-1] is a property read (undefined in the
  engine) and fails closed; out-of-bounds reads are engine-undefined
  and fail closed (the decoder has no undefined value);
  _JSNil/_JSBool elements fail closed; str (incl _JSNumStr) and
  nested _JSArr elements pass through so chained reads resolve.
* `"at"` joins `_F478_ARRAY_METHODS` (F566 -- the dispatch desugar
  shares the direct form's literal-integer rule) and
  `_JS_POSTFIX_METHOD_NAMES` with a new `_js_apply_method_at` branch
  (checked BEFORE the "method on unjoined array" guard, F473
  precedent): negative indices count back from the end (engine .at
  semantics); missing/non-literal index, extra args, and
  out-of-bounds fail closed. A matching `_js_apply_method_values`
  branch mirrors it for .apply/.bind dispatch (F483: every modeled
  prototype method gets the value form).
* `"toReversed"` / `"with"` join `_JS_POSTFIX_METHOD_NAMES` with new
  `_js_apply_method_at` branches (also before the unjoined-array
  guard): toReversed() returns a fresh reversed _JSArr (any args fail
  closed); .with(IDX, VAL) returns a fresh _JSArr with element IDX
  replaced (negative counts from the end, node-exact; out-of-range
  throws RangeError in the engine, so it fails closed; VAL must be
  a string). Dispatch (.call/.apply/.bind) on toReversed/with is
  unmodeled and fails closed -- a documented residual (filed shapes
  are direct-only; a future attack shape would be an honest new
  finding per the F514 precedent).

Fail closed (documented, never mis-decoded): bracket negative or
non-literal indices, non-canonical string keys (['0x1'], [' 0'],
['00'], ['01'] -- leading-zero digit strings are property reads,
undefined in the engine),
unclosed brackets, out-of-bounds reads, _JSNil/_JSBool elements,
.at with missing/non-literal/extra args or out-of-bounds,
.toReversed with any args, .with with non-literal/fractional/wrong-
arity IDX, out-of-range IDX, or non-string VAL, non-_JSArr receivers
for all three methods, and `?.at(...)` / `?.toReversed(...)` direct
methodref calls -- the F490 methodref step models dispatch
(.call/.apply/.bind) on references, never direct `(args)` calls;
verified identical for ?.concat/?.join on the base tree, so this is
pre-existing design, not a regression.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
$0-spend-by-construction (no harness/ModelDriver/socket in this
file -- grep-verified before running).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import json
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); no new decision codes this lane

from gov import dlp  # noqa: E402
from gov import guac_graph  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


# ------------------------------------------------------------- P1: F547 filed
def p1_f547_filed_shapes():
    shapes = [
        "['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B),
        "['%s','%s'].at(0)+['%s','%s'].at(1)" % (_A, _B, _A, _B),
        "[['%s'],['%s']][0][0]+[['%s'],['%s']][1][0]" % (_A, _B, _A, _B),
        "['%s','%s'].at(0)+['%s','%s'].at(-1)" % (_A, _B, _A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ---------------------------------------------------------- P2: F547 variants
def p2_f547_variants():
    variants = [
        # canonical-digit string key (engine: ['f1','f2']['0'] === 'f1')
        "['%s','%s']['0']+'%s'" % (_A, _B, _B),
        # hex literal index (engine: [0x1] === [1])
        "['%s','%s'][0x0]+'%s'" % (_A, _B, _B),
        # ws tolerance inside brackets
        "['%s','%s'][ 0 ]+'%s'" % (_A, _B, _B),
        # ws tolerance in .at call
        "['%s','%s'] .at( 0 )+'%s'" % (_A, _B, _B),
        # bracket-string member-call form (F507 path routes to at)
        "['%s','%s']['at'](0)+'%s'" % (_A, _B, _B),
        # paren-member-call form (F492 path)
        "(['%s','%s']['at'])(0)+'%s'" % (_A, _B, _B),
        # dispatch on array value (F478 table now includes at)
        "['%s','%s'].at.call(['%s','%s'],0)+'%s'" % (_A, _B, _A, _B, _B),
        # triple-nested read chain
        "[[['%s']]][0][0][0]+'%s'" % (_A, _B),
    ]
    bad = [s for s in variants if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(variants) - len(bad),
                                       len(variants)))


# ------------------------------------------------------------ P3: F547 bounds
def p3_f547_bounds():
    # Every one of these must stay quiet: engine-undefined reads,
    # malformed indices, and non-string elements fail closed.
    bounds = [
        "['%s','%s'][-1]" % (_A, _B),          # property read, undefined
        "['%s','%s'][5]" % (_A, _B),            # out of bounds, undefined
        "['%s','%s'].at(5)" % (_A, _B),         # out of bounds, undefined
        "['%s','%s'].at()" % (_A, _B),          # missing index
        "['%s','%s'].at(0,1)" % (_A, _B),       # extra args
        "['%s','%s'].at('0')" % (_A, _B),       # non-literal index
        "['%s','%s'].at(x)" % (_A, _B),         # ident index
        "['%s','%s'][1.5]" % (_A, _B),          # fractional index
        "['%s','%s']['0x1']" % (_A, _B),        # non-canonical string key
        "['%s','%s'][' 0']" % (_A, _B),         # non-canonical string key
        "['%s','%s']['00']" % (_A, _B),         # non-canonical: undefined
        "['%s','%s']['01']" % (_A, _B),         # non-canonical: undefined
        "['%s','%s'][0" % (_A, _B),             # unclosed bracket
        "[null,'%s'][0]+'%s'" % (_B, _A),       # _JSNil element
        "[true,'%s'][0]+'%s'" % (_B, _A),       # _JSBool element
        "'%s'.at(0)" % _A,                     # at on non-array
        "['zz','yy'][0]+['zz','yy'][1]",        # junk stays quiet
    ]
    loud = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d bounds quiet" % (len(bounds) - len(loud), len(bounds)))


# ------------------------------------------------------------- P4: F561 filed
def p4_f561_filed_shapes():
    shapes = [
        "['%s','%s'].toReversed().join('')" % (_B, _A),
        "['zz','%s'].with(0,'%s').join('')" % (_B, _A),
        "['%s','zz'].with(-1,'%s').join('')" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ---------------------------------------------------------- P5: F561 variants
def p5_f561_variants():
    variants = [
        # hex index
        "['zz','%s'].with(0x0,'%s').join('')" % (_B, _A),
        # replace at last index with positive form
        "['%s','zz'].with(1,'%s').join('')" % (_A, _B),
        # chained: with then index read
        "['zz','%s'].with(0,'%s')[0]+'%s'" % (_B, _A, _B),
        # chained: toReversed then at
        "['%s','%s'].toReversed().at(0)+'%s'" % (_B, _A, _B),
        # bracket-string member-call form
        "['%s','%s']['toReversed']().join('')" % (_B, _A),
        "['zz','%s']['with'](0,'%s').join('')" % (_B, _A),
        # ws tolerance
        "['%s','%s'] .toReversed( ) .join('')" % (_B, _A),
        # double reversal is identity
        "['%s','%s'].toReversed().toReversed().join('')" % (_A, _B),
    ]
    bad = [s for s in variants if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(variants) - len(bad),
                                       len(variants)))


# ------------------------------------------------------------ P6: F561 bounds
def p6_f561_bounds():
    bounds = [
        "['%s','%s'].toReversed(1)" % (_A, _B),     # args fail closed
        "['zz','%s'].with(5,'%s')" % (_B, _A),      # RangeError -> closed
        "['zz','%s'].with(-3,'%s')" % (_B, _A),     # RangeError -> closed
        "['%s','%s'].with(0)" % (_A, _B),           # wrong arity
        "['%s','%s'].with(0,'a','b')" % (_A, _B),   # wrong arity
        "['%s','%s'].with(0.5,'x')" % (_A, _B),     # fractional index
        "['%s','%s'].with(x,'y')" % (_A, _B),       # non-literal index
        "['%s','%s'].with(0,[1])" % (_A, _B),       # non-string value
        "['%s','%s'].with(0,null)" % (_A, _B),      # null value
        "'%s'.toReversed()" % _A,                   # non-array receiver
        "'%s'.with(0,'x')" % _A,                    # non-array receiver
        "['zz','yy'].toReversed().join('')",        # junk stays quiet
    ]
    loud = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d bounds quiet" % (len(bounds) - len(loud), len(bounds)))


# ------------------------------------------------------------- P7: F566 filed
def p7_f566_filed_shapes():
    shapes = [
        ("Array.prototype.at.call(['%s','%s'],0)"
         "+Array.prototype.at.call(['%s','%s'],1)") % (_A, _B, _A, _B),
        ("Array.prototype.at.call(['%s','%s'],0)"
         "+Array.prototype.at.call(['%s','%s'],-1)") % (_A, _B, _A, _B),
        # bracket-string target form (F482)
        ("Array.prototype['at'].call(['%s','%s'],0)"
         "+Array.prototype['at'].call(['%s','%s'],1)") % (_A, _B, _A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ---------------------------------------------------------- P8: F566 variants
def p8_f566_variants():
    variants = [
        # .apply dispatch (value-form branch)
        ("Array.prototype.at.apply(['%s','%s'],[0])"
         "+''+Array.prototype.at.apply(['%s','%s'],[1])") % (_A, _B, _A, _B),
        # .bind dispatch with immediate call (value-form branch)
        ("Array.prototype.at.bind(['%s','%s'],0)()"
         "+Array.prototype.at.bind(['%s','%s'],1)()") % (_A, _B, _A, _B),
        # dispatch on array value (F478 value-dispatch path)
        ("['%s','%s'].at.call(['%s','%s'],0)"
         "+['%s','%s'].at.call(['%s','%s'],1)") % (_A, _B, _A, _B, _A, _B,
                                                  _A, _B),
        # hex index through dispatch
        "'%s'+Array.prototype.at.call(['%s','%s'],0x1)" % (_A, _A, _B),
        # negative index through .apply
        "Array.prototype.at.apply(['%s','%s'],[-2])+'%s'" % (_A, _B, _B),
    ]
    bad = [s for s in variants if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(variants) - len(bad),
                                       len(variants)))


# ------------------------------------------------------------ P9: F566 bounds
def p9_f566_bounds():
    bounds = [
        # out of bounds -> undefined -> closed
        "Array.prototype.at.call(['%s','%s'],5)" % (_A, _B),
        "Array.prototype.at.call(['%s','%s'],-3)" % (_A, _B),
        # extra dispatch args -> closed (conservative; engine ignores)
        "Array.prototype.at.call(['%s','%s'],0,1)" % (_A, _B),
        # non-literal index
        "Array.prototype.at.call(['%s','%s'],x)" % (_A, _B),
        # missing index
        "Array.prototype.at.call(['%s','%s'])" % (_A, _B),
        # .apply with non-array argsArray
        "Array.prototype.at.apply(['%s','%s'],0)" % (_A, _B),
        # unmodeled target (engine throws -- not a real method)
        "Array.prototype.atx.call(['%s','%s'],0)" % (_A, _B),
        # toReversed/with dispatch is deliberately unmodeled (F561
        # residual -- direct form only)
        "Array.prototype.toReversed.call(['%s','%s'])" % (_B, _A),
        "Array.prototype.with.call(['zz','%s'],0,'%s')" % (_B, _A),
    ]
    loud = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d bounds quiet" % (len(bounds) - len(loud), len(bounds)))


# ------------------------------------------------------- P10: compositions
def p10_compositions():
    # Closed neighbors stay HELD; mechanism-adjacent OPEN findings
    # from other lanes stay missed (this lane must not accidentally
    # close them -- the merge reconciles).
    held = [
        # F535 literal member access
        "({c:'%s'}).c+'%s'" % (_A, _B),
        # F469 direct join
        "['%s','%s'].join('')" % (_A, _B),
        # F521 bound concat (true filed shape: bound arg + argsList)
        ("Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')"
         % (_A, _B)),
        # F530 bound join
        "Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (_A, _B),
        # F506 higher-order dispatch
        ("Function.prototype.apply.call(Reflect.apply, Reflect, "
         "[[].concat, [], ['%s','%s']]).join('')") % (_A, _B),
        # F527 quad-nested bracket key on strings
        "'%s'[[[[['concat'][0]]][0]][0]]('%s')" % (_A, _B),
        # F532 quad-nested bracket key on arrays (true filed shape)
        "['%s'][[[[['concat'][0]]][0]][0]]('%s').join('')" % (_A, _B),
        # F511 splice dispatch
        ("Array.prototype.splice.call(['%s','%s'],0,2).join('')"
         % (_A, _B)),
        # F518 reverse dispatch
        ("Array.prototype.reverse.call(['%s','%s']).join('')"
         % (_B, _A)),
        # F534 bound slice
        ("Reflect.apply([].slice.bind(['%s','%s'],0,2), null, []).join('')"
         % (_A, _B)),
    ]
    missed_closed = [s for s in held if not _blocked(s)]
    # Wave-370 lane 5 CLOSED F574 (flat depth>1) and the F580
    # length-comparator shape: these now block. The default-sort shape
    # ['_A','_B'].sort() decodes to _B+_A (non-credential order) -- it
    # is modeled but does not block; assert the honest decode below.
    now_closed = [
        "[[['%s']],[['%s']]].flat(Infinity).join('')" % (_A, _B),
        "[[['%s']],[['%s']]].flat(2).join('')" % (_A, _B),
        "['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_B, _A),
    ]
    missed_now_closed = [s for s in now_closed if not _blocked(s)]
    sort_default_decodes = (dlp._try_js_expr_decode_all(
        "['%s','%s'].sort().join('')" % (_A, _B)) == _B + _A)
    ok = not missed_closed and not missed_now_closed and sort_default_decodes
    return ("HELD" if ok else "BREAK",
            "neighbors held %d/%d, f574/f580 closed %d/%d, sort-default decodes=%s"
            % (len(held) - len(missed_closed), len(held),
               len(now_closed) - len(missed_now_closed), len(now_closed),
               sort_default_decodes))


# ---------------------------------------------------- P11: node differential
def p11_node_differential():
    # Decoder-vs-node agreement: for each shape, node must produce
    # the credential exactly when the decoder blocks, and must NOT
    # (undefined / throws / different value) when the decoder is
    # quiet. Byte-exact on v24.20.0.
    import subprocess as _sp
    cases = [
        # (payload, node_must_yield_credential)
        ("['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B), True),
        ("['%s','%s'].at(-1)" % (_A, _B), False),       # single half
        ("['%s','%s'].at(0)+['%s','%s'].at(-1)" % (_A, _B, _A, _B), True),
        ("['%s','%s'][-1]" % (_A, _B), False),          # undefined
        ("['%s','%s'][9]" % (_A, _B), False),           # undefined
        ("['%s','%s'].at(9)" % (_A, _B), False),        # undefined
        ("['%s','%s'].toReversed().join('')" % (_B, _A), True),
        ("['zz','%s'].with(0,'%s').join('')" % (_B, _A), True),
        ("['%s','zz'].with(-1,'%s').join('')" % (_A, _B), True),
        ("['zz','%s'].with(9,'%s').join('')" % (_B, _A), False),  # throws
        (("Array.prototype.at.call(['%s','%s'],0)"
          "+Array.prototype.at.call(['%s','%s'],1)") % (_A, _B, _A, _B),
         True),
        ("Array.prototype.at.call(['%s','%s'],9)" % (_A, _B), False),
    ]
    js_lines = []
    for i, (p, _) in enumerate(cases):
        esc = p.replace("\\", "\\\\").replace("`", "\\`").replace("$", "\\$")
        js_lines.append(
            "try{var _r%d=eval(`%s`);console.log(%d+':'+(_r%d===undefined?'UNDEF':String(_r%d)));}catch(e){console.log(%d+':THROW');}"
            % (i, esc, i, i, i, i))
    try:
        r = _sp.run(["node", "-e", "\n".join(js_lines)],
                    capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node spawn failed: %s" % e)
    node_out = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            node_out[int(k)] = v
    bad = []
    for i, (p, want_cred) in enumerate(cases):
        node_val = node_out.get(i, "MISSING")
        blocked = _blocked(p)
        node_has = (node_val == _CRED)
        if want_cred and not (node_has and blocked):
            bad.append((p, "want-cred", node_val, blocked))
        if not want_cred and blocked:
            # decoder blocked something node does not yield as the
            # credential -- over-decode (undefined/throw shapes must
            # never block)
            bad.append((p, "over-decode", node_val, blocked))
    # Value-exact differential (non-credential values): the decoder's
    # whole-text variant must equal node's value byte-for-byte. This
    # pins engine-exactness where the public seam cannot (numeric
    # .with VAL, negative .at, toReversed element order).
    from gov.dlp import _try_js_expr_decode_all  # noqa: E402
    value_cases = [
        "['a','b'].with(0,1).join('')",          # numeric VAL -> '1b'
        "['a','b'].with(-1,'z').join('')",       # negative IDX -> 'az'
        "['b','a'].toReversed().join('')",       # reversal -> 'ba'
        "['a','b'].at(-1)",                      # negative .at -> 'b'
        "['a','b'][0x1]",                        # hex index -> 'b'
        "[[['x']]][0][0][0]",                    # nested read -> 'x'
    ]
    for p in value_cases:
        want = _sp.run(["node", "-e", "console.log(String(eval(%s)))"
                        % json.dumps(p)],
                       capture_output=True, text=True,
                       timeout=60).stdout.strip()
        got = _try_js_expr_decode_all(p)
        if got != want:
            bad.append((p, "value-exact", want, got))
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-agreement (%s)" % (len(cases) + len(value_cases)
                                           - len(bad),
                                           len(cases) + len(value_cases),
                                           bad[:2] if bad else "exact"))


# ---------------------------------------------------------- P12: pin/footer
def p12_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    import re as _re
    assert _re.compile("").pattern == "", "re sanity"
    assert len(_re.findall(r"re\.compile", open(
        os.path.join(REPO_ROOT, "gov", "dlp.py")).read())) == 28, \
        "re.compile count moved"
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F612**" in text  # Wave-369 lane 1: F547/F561/F566 CLOSED  # Wave-372 merge: footer repoint next F612
          and "**Open findings: F595, F606, F607, F609, F610, F611.**" in text  # Wave-369 lane 1: F547/F561/F566 CLOSED; wave-370 lane 4: F573/F578 CLOSED  # Wave-372 lane 1: F597 CLOSED  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED
          and "Status: CLOSED 2026-10-07 wave-369 lane 1." in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P13: perf
def p13_perf_bound():
    # Hostile input: many at/with/index anchors -- must starve fast
    # (F452 lesson: fail-closed matches must consume scan budget).
    import time
    junk = ("['ab','cd'].at(0)['ab','cd'].toReversed()['ab','cd'].with(0,'x')"
            "Array.prototype.at.call(['ab','cd'],0)") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2800-anchor at/with/index corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w368_f547_redfirst.py",
    "evals/w368_f561_redfirst.py",
    "evals/w368_f566_redfirst.py",
    "evals/w368_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g369lane1-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = __import__("time").time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env,
                               cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" %
                  (rel, line[-1] if line else "rc=%d" % r.returncode,
                   __import__("time").time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f547-filed", p1_f547_filed_shapes),
    ("p2-f547-variants", p2_f547_variants),
    ("p3-f547-bounds", p3_f547_bounds),
    ("p4-f561-filed", p4_f561_filed_shapes),
    ("p5-f561-variants", p5_f561_variants),
    ("p6-f561-bounds", p6_f561_bounds),
    ("p7-f566-filed", p7_f566_filed_shapes),
    ("p8-f566-variants", p8_f566_variants),
    ("p9-f566-bounds", p9_f566_bounds),
    ("p10-compositions", p10_compositions),
    ("p11-node-differential", p11_node_differential),
    ("p12-pin-footer", p12_pin_footer),
    ("p13-perf-bound", p13_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    rows = []
    for name, fn in PROBES:
        try:
            v, msg = fn()
        except Exception as e:  # noqa: BLE001
            v, msg = "ERROR", "%s: %s" % (type(e).__name__, e)
        rows.append((name, v, msg))
        if v == "HELD":
            held += 1
        else:
            brk += 1
        print("%-22s %s -- %s" % (name, v, msg))
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (brk, held))
    g = green_check()
    print("green-check: %s" % ("PASS" if g else "FAIL"))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": g,
                          "probes": rows}))
    return 1 if (brk or not g) else 0


if __name__ == "__main__":
    sys.exit(main())
