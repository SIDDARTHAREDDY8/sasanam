#!/usr/bin/env python3
"""Wave-356 F476 closure battery (lane 1).

F476 (LOW, filed 2026-10-06 wave-355 attack round 23): the bounded static
JS-expression decoder modeled the Array.of('f1','f2') identifier anchor
(F446), but not the constructor-property factory path:

  [].constructor.of('f1','f2').join('')      node: credential, decoder: miss
  Array['of']('f1','f2').join('')             node: credential, decoder: miss

F446's entry explicitly documents `[].constructor.of(...)` /
`Array['of'](...)` as "out of F446 scope, documented not filed".

Closure design (gov/dlp.py, F476):
  * `_js_parse_of_args` -- the F446 argument-list grammar extracted
    verbatim (string-literal-only args; numeric/nested/additive fail
    closed); `_js_parse_array_of` now delegates to it.
  * `_js_parse_ctor_factory` -- parses `[].constructor.of(...)`,
    `[].constructor['of'](...)` / `[].constructor["of"](...)`,
    `Array['of'](...)` / `Array["of"](...)`, desugaring to the
    fragment list via `_js_parse_of_args`. Only the `of` member is
    modeled: `[].constructor.from('a','b')` throws TypeError in the
    engine (from's second arg must be a function), so `from` with
    string args fails closed -- never mis-decoded as `of`;
    `[].constructor.from([...])` needs no factory model: the inner array
    literal splices through the pre-existing array-literal + `.join` path
    (the `from(` wrapper is copied verbatim around it, node agrees on the
    joined text), so find_credential flags it without any
    constructor-property modeling (documented, not filed). Only the exact
    `[]` receiver is modeled;
    `['x'].constructor.of` is engine-valid but a documented residual.
    `of`/`constructor` are ident-boundary-checked; `Array[x]`,
    `Array.prototype.constructor` chains, and `.constructor` on
    non-array receivers fail closed.
  * `_js_is_ctor_recv` -- cheap text peek (`[` ws `]` ws `.`) keeps the
    F476 path disjoint from array literals and the F471 spread-copy.
  * `_js_parse_primary` dispatches the two new shapes; the anchor
    gains the bracket-member alternative (character class only --
    no new regexes, no new re.compile; linear-time preserved).

Documented fail-closed boundaries (NOT bypasses, disclosed here):
  * `['x'].constructor.of('a','b')` -- decoder None, node 'ab'.
    Conservative residual: only the exact `[]` receiver is modeled.
  * `[].constructor.of(1)` -- decoder None, node '1'. Same scope
    boundary as F446's Array.of(1) refusal.
  * ws before the '.' of a following method chain
    (`[].constructor.of('a','b') .join('')`) -- decoder None, node
    'ab'. Pre-existing postfix whitespace rule (base F446 behaves
    identically); the factory call itself is fully ws-tolerant.
  * `[].constructor.from('a','b')` -- decoder None, node THROWS.
    Fail-closed is engine-exact here.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: constructor-property factory shapes decode
      byte-identical (dot, bracket, ctor-bracket, ws-tolerant,
      backtick args, single arg, Array["of"]).
  P2  controls: fail-closed shapes produce no variant (numeric /
      additive / nested args, ofx member, non-literal key,
      prototype chain, non-array receiver, from-with-strings,
      elem-array receiver residual); F446 anchor still decodes;
      `[].constructor.from([...])` still blocked; junk quiet;
      seam-level FP shape quiet.
  P3  decoder pins: node byte-fidelity on the full differential set
      (subprocess); anchor pattern pin (F476 alternative present);
      re.compile count unchanged (28); F441 _decode_layer ordering
      untouched; _js_parse_array_of delegates (behavior preserved).
  P4  discrimination: FP corpus (repo docs) hit-set identical to
      base; innocent constructor text quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F446 Array.of,
      F454 multi-arg Array, F455 ws anchor, F468 Reflect.construct,
      F469 Reflect.apply, F471 spread copy / Object.assign, F475
      _JSNumStr filter, F443 Array fill, F434 array join, F472
      repeat tag).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F477 / next F478, F476 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w356_f476close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import glob
import json
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-356: F476 closed; no new decision codes
FOOTER_OPEN = "F496, F497, F498, F499, F500, F501, F502"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-359 lane 2: F484, F485 CLOSED locally (merge finalizes tree-wide)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 lane 1: F480 CLOSED locally (merge finalizes tree-wide)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN
FOOTER_NEXT = "F503"  # Wave-357 merge: F480 filed OPEN; next free F481  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496
FOOTER_NEXT = "F503"  # Wave-356 lane 1: F476 CLOSED; next free F478  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123456789"
_B = "abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try{ out.push(JSON.stringify(eval(cases[k]))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, "node failed: %s" % r.stderr[-200:]
    return json.loads(r.stdout)


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001
        print("%-45s ERROR %s" % (pid, e))
        return pid, "ERROR"
    print("%-45s %s" % (pid, "HELD" if ok else "BREAK"))
    return pid, ("HELD" if ok else "BREAK")


# ---------------------------------------------------------------- P1: closure

def p1_closure_ctor_dot():
    return _decoded("[].constructor.of('%s','%s').join('')" % (_A, _B)) == _A + _B


def p1_closure_array_bracket_sq():
    return _decoded("Array['of']('%s','%s').join('')" % (_A, _B)) == _A + _B


def p1_closure_array_bracket_dq():
    return _decoded('Array["of"](' + "'%s','%s').join('')" % (_A, _B)) == _A + _B


def p1_closure_ctor_bracket():
    return _decoded("[].constructor['of']('%s','%s').join('')"
                    % (_A, _B)) == _A + _B


def p1_closure_ctor_bracket_dq():
    return _decoded('[].constructor["of"](' + "'%s','%s').join('')"
                    % (_A, _B)) == _A + _B


def p1_closure_ws_tolerant():
    return _decoded("[ ] . constructor . of ( '%s' , '%s' ).join('')"
                    % (_A, _B)) == _A + _B


def p1_closure_ws_bracket():
    return _decoded("Array [ 'of' ] ( '%s' , '%s' ).join('')"
                    % (_A, _B)) == _A + _B


def p1_closure_backtick_args():
    return _decoded("[].constructor.of(`%s`,`%s`).join('')" % (_A, _B)) == _A + _B


def p1_closure_single_arg():
    return _decoded("[].constructor.of('%s').join('')" % _A) == _A


def p1_closure_zero_args():
    # Consistent with F446: Array.of().join('') is not decoded on base.
    return _decoded("[].constructor.of().join('')") is None


def p1_closure_postfix_chain():
    # The factory result composes through the postfix chain.
    return _blocked("[].constructor.of('%s','%s').join('')" % (_A, _B))


# ---------------------------------------------------------------- P2: controls

def p2_control_numeric_arg_none():
    # Same scope boundary as F446's Array.of(1) refusal.
    return _decoded("[].constructor.of(1).join('')") is None


def p2_control_additive_arg_none():
    # Pre-existing whole-text inner decode (base F446 behaves
    # identically: 'Array.of(ab).join('')'); the outer factory fails
    # closed and the credential is never recovered.
    return _decoded("[].constructor.of('a'+'b').join('')") != "ab"


def p2_control_nested_arg_decodes():
    # Wave-359 (F484): nested array-literal args now decode
    # node-exactly -- [].constructor.of(['a']) is [['a']], joined 'a'.
    return _decoded("[].constructor.of(['a']).join('')") == "a"


def p2_control_ofx_none():
    return _decoded("[].constructor.ofx('%s','%s').join('')" % (_A, _B)) is None


def p2_control_bracket_ofx_none():
    return _decoded("Array['ofx']('%s','%s').join('')" % (_A, _B)) is None


def p2_control_nonliteral_key_none():
    return _decoded("Array[x]('%s','%s').join('')" % (_A, _B)) is None


def p2_control_prototype_chain_none():
    return _decoded("Array.prototype.constructor.of('%s').join('')" % _A) is None


def p2_control_nonarray_receiver_none():
    return _decoded("''.constructor.of('%s').join('')" % _A) is None


def p2_control_from_strings_none():
    # Node THROWS (from's second arg must be a function) -- fail-closed
    # is engine-exact.
    return _decoded("[].constructor.from('%s','%s')" % (_A, _B)) is None


def p2_control_from_numeric_none():
    return _decoded("[].constructor.from(1).join('')") is None


def p2_control_ctor_bracket_from_none():
    return _decoded("[].constructor['from']('%s').join('')" % _A) is None


def p2_control_backtick_member_none():
    # Conservative: only quote-form member names are modeled.
    return _decoded("Array[`of`]('%s').join('')" % _A) is None


def p2_control_elem_receiver_residual():
    # Documented residual: engine-valid, conservatively unmodeled.
    return _decoded("['x'].constructor.of('%s','%s').join('')" % (_A, _B)) is None


def p2_control_from_array_inner_splice():
    # No factory model needed: the inner array literal splices through
    # the pre-existing array-literal + .join path (from( copied verbatim
    # around it; node agrees on the joined text) -- flagged without any
    # constructor-property modeling (documented, not filed).
    return _blocked("[].constructor.from(['%s','%s']).join('')" % (_A, _B))


def p2_control_f446_anchor_still_decodes():
    return _blocked("Array.of('%s','%s').join('')" % (_A, _B))


def p2_control_junk_quiet():
    return not _blocked("[].constructor.of('ab','cd').join('')")


def p2_control_seam_fp_quiet():
    c9 = "xoxb-" + "a" * 5
    return not _blocked("[].constructor.of('%s','%s').join('')" % (c9, "zz"))


# ---------------------------------------------------------------- P3: pins

def p3_pin_node_byte_fidelity():
    cases = [
        ("[].constructor.of('a','b').join('')", "ab", "ab"),
        ("Array['of']('a','b').join('')", "ab", "ab"),
        ('Array["of"](' + "'a','b').join('')", "ab", "ab"),
        ("[].constructor['of']('a','b').join('')", "ab", "ab"),
        ("[ ] . constructor . of ( 'a' , 'b' ).join('')", "ab", "ab"),
        ("Array [ 'of' ] ( 'a' , 'b' ).join('')", "ab", "ab"),
        ("[].constructor [ 'of' ] ( 'a' , 'b' ).join('')", "ab", "ab"),
        ("[].constructor.from(['a','b']).join('')",
         "[].constructor.fromab", "ab"),
        ("[].constructor.of(`a`,`b`).join('')", "ab", "ab"),
        ("[].constructor.of('a').join('')", "a", "a"),
        ("[].constructor.of(1).join('')", None, "1"),
        ("[].constructor.ofx('a','b').join('')", None, "THROWS"),
        ("Array[x]('a','b').join('')", None, "THROWS"),
        ("Array.prototype.constructor.of('a').join('')", None, "a"),
        ("''.constructor.of('a').join('')", None, "THROWS"),
        ("[].constructor.from('a','b')", None, "THROWS"),
        ("['x'].constructor.of('a','b').join('')", None, "ab"),
        ("Array[`of`]('a').join('')", None, "a"),
    ]
    node = _node_eval([c[0] for c in cases])
    for (payload, dec_want, node_want), n in zip(cases, node):
        dec = _decoded(payload)
        if node_want == "THROWS":
            if not (n == "THROWS" and dec is None):
                return False
        else:
            if not (n == json.dumps(node_want) and dec == dec_want):
                return False
    return True


def p3_pin_anchor_f476_alternative():
    # The anchor covers the bracket-member factory (char-class only);
    # [].constructor.of starts with '[', already in the class.
    # F480 (wave-358 lane 1): the dot-member alternative widened to
    # (of|apply|call); the bracket alternative is unchanged.
    pat = dlp._JS_EXPR_START.pattern
    assert "(of|apply|call)|\\[[ \\t\\n\\r]*['\\\"]" in pat, pat
    for s in ["Array['of']", 'Array["of"]', "Array [ 'of' ]",
              "Array.of", "[].constructor.of"]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return True


def p3_pin_array_of_delegates():
    # _js_parse_array_of still routes through _js_parse_of_args with
    # identical behavior on the F446 arg classes; wave-359 (F484)
    # additionally models nested array-literal args node-exactly.
    state = {"ops": 0, "parts": 0}
    arr, _ = dlp._js_parse_array_of("Array.of('a','b')", 0, state)
    if list(arr.elements) != ["a", "b"]:
        return False
    arr2, _ = dlp._js_parse_array_of("Array.of(['a'])", 0,
                                    {"ops": 0, "parts": 0})
    if len(arr2.elements) != 1 or \
            list(arr2.elements[0].elements) != ["a"]:
        return False
    for bad in ("Array.of(1)", "Array.of('a'+'b')",
                "Array.ofx('a')"):
        try:
            dlp._js_parse_array_of(bad, 0, {"ops": 0, "parts": 0})
        except dlp._JSExprFail:
            continue
        return False
    return True


def p3_pin_f441_ordering_untouched():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return True


# ---------------------------------------------------------------- P4: discrimination

_FP_BASELINE = {
    "README.md": "dlp-github-token",
    "SITUATION_MATRIX.md": "dlp-aws-access-key",
    "docs/decision-code-coverage.md": "dlp-entropy-tripwire",
    "evals/FINDINGS.md": "dlp-aws-access-key",
    "evals/SITUATION_MATRIX.md": "dlp-aws-access-key",
}


def p4_discr_fp_corpus_identical():
    corpus = sorted(glob.glob("README.md") + glob.glob("docs/*.md")
                    + glob.glob("evals/*.md")
                    + ["BUILD_LOG.md", "THREAT_MODEL.md",
                       "SITUATION_MATRIX.md"])
    hits = {}
    for p in corpus:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                t = f.read()
        except OSError:
            continue
        r = dlp.find_credential(t[:200000])
        if r:
            hits[p] = r
    return hits == _FP_BASELINE


def p4_discr_innocent_ctor_quiet():
    cases = [
        "[].constructor.name",
        "Array['length']",
        "[].constructor.of('id','7').join(',')",
    ]
    return all(not _blocked(c) for c in cases)


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        "[].constructor." + "of" * 500 + "('a').join('')",
        "[].constructor.of(" + "'a'," * 2000 + "'a').join('')",
        "Array[" + "'of'," * 1000 + "]('a').join('')",
        "[" + " " * 5000 + "].constructor.of('a').join('')",
        "[].constructor[" + "'of'" * 500 + "]('a').join('')",
        "[].constructor.of('a','b').join('')" * 60,
    ]
    for h in hostile:
        t0 = time.time()
        try:
            dlp.find_credential(h)
        except Exception:
            return False
        if time.time() - t0 > 5:
            return False
    return True


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f446_array_of():
    return _blocked("Array.of('%s','%s').join('')" % (_A, _B))


def p6_noreg_f454_multi_arg():
    return _blocked("Array('%s','%s').join('')" % (_A, _B))


def p6_noreg_f455_ws_anchor():
    return _blocked("Array . of('%s','%s').join('')" % (_A, _B))


def p6_noreg_f468_reflect_construct():
    return _blocked("Reflect.construct(Array,['%s','%s']).join('')" % (_A, _B))


def p6_noreg_f469_reflect_apply():
    return _blocked(
        "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')"
        % (_A, _B))


def p6_noreg_f471_spread_copy():
    return _blocked("[...['%s','%s']].join('')" % (_A, _B))


def p6_noreg_f471_object_assign():
    return _blocked("Object.assign([],['%s','%s']).join('')" % (_A, _B))


def p6_noreg_f475_numstr_filter():
    # F475: mixed-type array fails closed under x.length>0. Short
    # fragment keeps the decoded text under the seam floor so the probe
    # measures F475's fail-closed, not the seam.
    a = "xoxb-" + "a" * 5
    return not _blocked("['%s',1].filter(x=>x.length>0).join('')" % a)


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('%s').join('')" % (_A + _B))


def p6_noreg_f434_array_join():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


def p6_noreg_f472_repeat_tag():
    bt = chr(96)
    return _blocked("'%s'.repeat%s2%s" % (_A + _B, bt, bt))


def p6_noreg_f473_array_concat():
    return _blocked("['%s'].concat(['%s']).join('')" % (_A, _B))


def p6_noreg_f473_empty_receiver_concat():
    # Wave-356 regression guard: the F476 '[].constructor' peek must not
    # steal the empty-array receiver -- [].concat(...) stays F473's.
    return _blocked("[].concat(...['%s'],...['%s']).join('')" % (_A, _B))


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
    ok = ok and "CLOSED 2026-10-06 wave-356 lane 1" in footer
    ok = ok and "(F476 filed 2026-10-06, wave-355 lane 4" in footer
    return ok


_PROBES = [
    ("p1-closure-ctor-dot", p1_closure_ctor_dot),
    ("p1-closure-array-bracket-sq", p1_closure_array_bracket_sq),
    ("p1-closure-array-bracket-dq", p1_closure_array_bracket_dq),
    ("p1-closure-ctor-bracket", p1_closure_ctor_bracket),
    ("p1-closure-ctor-bracket-dq", p1_closure_ctor_bracket_dq),
    ("p1-closure-ws-tolerant", p1_closure_ws_tolerant),
    ("p1-closure-ws-bracket", p1_closure_ws_bracket),
    ("p1-closure-backtick-args", p1_closure_backtick_args),
    ("p1-closure-single-arg", p1_closure_single_arg),
    ("p1-closure-zero-args", p1_closure_zero_args),
    ("p1-closure-postfix-chain", p1_closure_postfix_chain),
    ("p2-control-numeric-arg-none", p2_control_numeric_arg_none),
    ("p2-control-additive-arg-none", p2_control_additive_arg_none),
    ("p2-control-nested-arg-decodes", p2_control_nested_arg_decodes),
    ("p2-control-ofx-none", p2_control_ofx_none),
    ("p2-control-bracket-ofx-none", p2_control_bracket_ofx_none),
    ("p2-control-nonliteral-key-none", p2_control_nonliteral_key_none),
    ("p2-control-prototype-chain-none", p2_control_prototype_chain_none),
    ("p2-control-nonarray-receiver-none", p2_control_nonarray_receiver_none),
    ("p2-control-from-strings-none", p2_control_from_strings_none),
    ("p2-control-from-numeric-none", p2_control_from_numeric_none),
    ("p2-control-ctor-bracket-from-none", p2_control_ctor_bracket_from_none),
    ("p2-control-backtick-member-none", p2_control_backtick_member_none),
    ("p2-control-elem-receiver-residual", p2_control_elem_receiver_residual),
    ("p2-control-from-array-inner-splice", p2_control_from_array_inner_splice),
    ("p2-control-f446-anchor-still-decodes", p2_control_f446_anchor_still_decodes),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p2-control-seam-fp-quiet", p2_control_seam_fp_quiet),
    ("p3-pin-node-byte-fidelity", p3_pin_node_byte_fidelity),
    ("p3-pin-anchor-f476-alternative", p3_pin_anchor_f476_alternative),
    ("p3-pin-array-of-delegates", p3_pin_array_of_delegates),
    ("p3-pin-f441-ordering-untouched", p3_pin_f441_ordering_untouched),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-innocent-ctor-quiet", p4_discr_innocent_ctor_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f454-multi-arg", p6_noreg_f454_multi_arg),
    ("p6-noreg-f455-ws-anchor", p6_noreg_f455_ws_anchor),
    ("p6-noreg-f468-reflect-construct", p6_noreg_f468_reflect_construct),
    ("p6-noreg-f469-reflect-apply", p6_noreg_f469_reflect_apply),
    ("p6-noreg-f471-spread-copy", p6_noreg_f471_spread_copy),
    ("p6-noreg-f471-object-assign", p6_noreg_f471_object_assign),
    ("p6-noreg-f475-numstr-filter", p6_noreg_f475_numstr_filter),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f434-array-join", p6_noreg_f434_array_join),
    ("p6-noreg-f472-repeat-tag", p6_noreg_f472_repeat_tag),
    ("p6-noreg-f473-array-concat", p6_noreg_f473_array_concat),
    ("p6-noreg-f473-empty-receiver-concat", p6_noreg_f473_empty_receiver_concat),
    ("p7-pin-and-footer", p7_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Parses both verdict formats
    (wave-320 class: a parse matching neither format passes vacuously)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w355_attack_probes.py",
               "w355_f473close_probes.py",
               "w355_f474close_probes.py",
               "w355_f475close_probes.py",
               "w354_attack_probes.py",
               "w354_f472close_probes.py",
               "w354_f471close_probes.py")
    stale_footer_ok = {}
    for script in scripts:
        tmp = "/var/tmp/g356-green-%s-%d" % (script.replace(".py", ""),
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
        breaks = set()
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "BREAK" and len(parts) >= 2:
                breaks.add(parts[1].rstrip(":"))
            elif len(parts) >= 2 and parts[1] == "BREAK":
                breaks.add(parts[0])
        if not breaks and r.returncode != 0:
            raise AssertionError("green check failed: could not parse any "
                                 "probe verdicts from child output: %s"
                                 % notes[-1])
        if "unexpected BREAKs" in out or "expected BREAKs missing" in out:
            raise AssertionError("green check failed: %s" % notes[-1])
        allowed = stale_footer_ok.get(script, set())
        if not breaks <= allowed:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
        if breaks:
            notes.append("tolerated stale footer probe: %s" % sorted(breaks))
        if r.returncode != 0 and not breaks <= allowed:
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
    print("w356_f476close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
