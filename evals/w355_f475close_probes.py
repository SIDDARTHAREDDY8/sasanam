#!/usr/bin/env python3
"""Wave-355 F475 closure battery (lane 3).

F475 (LOW, filed 2026-10-06 wave-355 lane 3 from the wave-354 merge
report's pre-existing mis-decode candidate): the bounded static
JS-expression decoder coerced numeric array-literal elements to strings
at parse time (`str(num)` in `_js_parse_primary`), losing type
provenance, then evaluated type-dependent `.filter` predicates as if
every element were a string:

  ['a',1].filter(x=>x.length>0).join('')         decoder 'a1', node 'a'
  [1,2].filter(x=>x.length>0).join('')          decoder '12', node ''
  Array(2).fill(1).filter(x=>x.length>0).join('') decoder '11', node ''
  ['a',1].filter(x=>x.match(/[a-z]/)).join('')   decoder 'a',  node THROWS
  ['a',1].filter(x=>x.charCodeAt(0)>47).join('') decoder 'a1', node THROWS

(node ground truths verified on node v24.20.0). FP-direction
over-claim: the scanner reported text the engine never produces.

Closure design (gov/dlp.py, F475):
  * `_JSNumStr(str)` marks string values parsed from JS number
    literals. Behavior-identical to str everywhere except explicit
    `isinstance(..., _JSNumStr)` checks; propagates automatically
    through array copies (spread, reverse, slice, Object.assign).
  * `x.length>0` gets its own `("plen",)` spec, split from
    `("truthy",)` (which stays for the type-independent forms
    `x!==''`, `!!x`, bare `x`, `Boolean`).
  * The filter apply site raises `_JSExprFail` on any `_JSNumStr`
    element under the `plen` / `match` / `ccmp` specs: mixed-type
    arrays under type-dependent predicates never decode.
  * `.map(String)` clears provenance (engine-exact: `String(1)` is
    the string `'1'`); identity maps keep it (node keeps 1 a number).
  * `_js_parse_map_callback` now returns `(next_index, stringifies)`.

Documented fail-closed boundaries (NOT bypasses, disclosed here):
  * `['b','a',1].reverse().filter(x=>x.length>0)` -- decoder None,
    node 'ab'. The attacker gains nothing: any credential text must
    live in the string elements, and the pure-string form already
    decodes; the numeric element can never contribute credential
    text under these predicates in the engine.
  * `['a',1+2].join('')` -- decoder 'a12', node 'a3' (numeric
    ADDITIVE coercion: `_js_parse_additive` string-concatenates).
    Separate pre-existing class, not F475's filter-predicate class;
    candidate for a future finding, not silently fixed here.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: mixed-type arrays under x.length>0 / x.match /
      x.charCodeAt predicates fail closed (decoder-level None);
      numeric fill, hex/float literals, function-form callbacks,
      identity-map provenance, reverse composition.
  P2  controls: pure-string arrays still decode under every
      predicate; type-independent predicates still decode over
      MIXED arrays; .map(String) normalizes (node-exact 'a1');
      junk quiet; seam-level FP shape quiet.
  P3  decoder pins: node byte-fidelity on the full differential set
      (subprocess); _JSNumStr provenance pin; ("plen",) spec-split
      pin; map stringifies-flag pin; no new regexes (anchor pattern
      unchanged); F441 _decode_layer ordering untouched.
  P4  discrimination: FP corpus (repo docs) hit-set identical to
      base; innocent mixed arrays quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F469
      Reflect.apply, F470 match/ccmp pure-string, F471 spread copy,
      F472 repeat tag, F467 null-cmp filter, F443 Array fill, F434
      array join, F462 spread concat, F460 map String, F461
      reverse, F466 slice).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F473, F474 / next F476, F475 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w355_f475close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-355: F475 closed; no new decision codes
FOOTER_OPEN = "F480, F481"  # Wave-355 lane 3: F475 filed + CLOSED (merge finalizes tree-wide)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 lane 1: F476 CLOSED  # Wave-356 lane 2: F477 CLOSED  # Wave-356 merge: F476, F477 CLOSED  # Wave-357 merge: F478, F479 CLOSED (next F481)
FOOTER_NEXT = "F482"  # Wave-355 lane 3: F475 filed + CLOSED; next free F476  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: unchanged  # Wave-357 merge: F478, F479 CLOSED (next F481)

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xox" + "b-abc123" + "def" + "456"
_A = "xox" + "b-abc123"
_B = "def" + "456"


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

def p1_closure_plen_mixed_none():
    return _decoded("['a',1].filter(x=>x.length>0).join('')") is None


def p1_closure_plen_allnum_none():
    return _decoded("[1,2].filter(x=>x.length>0).join('')") is None


def p1_closure_plen_fillnum_none():
    return _decoded("Array(2).fill(1).filter(x=>x.length>0).join('')") is None


def p1_closure_plen_hexnum_none():
    # 0x31 == 49: still a number in the engine.
    return _decoded("['a',0x31].filter(x=>x.length>0).join('')") is None


def p1_closure_plen_floatnum_none():
    return _decoded("['a',1.5].filter(x=>x.length>0).join('')") is None


def p1_closure_match_mixed_none():
    return _decoded("['a',1].filter(x=>x.match(/[a-z]/)).join('')") is None


def p1_closure_ccmp_mixed_none():
    return _decoded("['a',1].filter(x=>x.charCodeAt(0)>47).join('')") is None


def p1_closure_plen_function_form_none():
    return _decoded(
        "['a',1].filter(function(x){return x.length>0;}).join('')") is None


def p1_closure_identity_map_keeps_provenance():
    # node: ['a',1].map(x=>x) keeps 1 a number -> filter drops it.
    return _decoded(
        "['a',1].map(x=>x).filter(x=>x.length>0).join('')") is None


def p1_closure_reverse_mixed_none():
    # Documented fail-closed boundary (see module docstring).
    return _decoded(
        "['b','a',1].reverse().filter(x=>x.length>0).join('')") is None


# ---------------------------------------------------------------- P2: controls

def p2_control_pure_string_plen():
    return _decoded("['ab',''].filter(x=>x.length>0).join('')") == "ab"


def p2_control_pure_string_match():
    return _decoded("['ab','c'].filter(x=>x.match(/[a-z]/)).join('')") == "abc"


def p2_control_pure_string_ccmp():
    return _decoded(
        "['ab','c'].filter(x=>x.charCodeAt(0)>47).join('')") == "abc"


def p2_control_mixed_neq():
    return _decoded("['a',1].filter(x=>x!=='').join('')") == "a1"


def p2_control_mixed_boolean():
    return _decoded("['a',1].filter(Boolean).join('')") == "a1"


def p2_control_mixed_identity():
    return _decoded("['a',1].filter(x=>x).join('')") == "a1"


def p2_control_mixed_dneg():
    return _decoded("['a',1].filter(x=>!!x).join('')") == "a1"


def p2_control_mixed_nullcmp():
    return _decoded("['a',1].filter(x=>x!==null).join('')") == "a1"


def p2_control_mixed_positional():
    return _decoded("['a',1].filter((x,i)=>i<2).join('')") == "a1"


def p2_control_map_string_normalizes():
    # Engine-exact: String(1) === '1', a genuine string.
    return _decoded(
        "['a',1].map(String).filter(x=>x.length>0).join('')") == "a1"


def p2_control_mixed_join():
    return _decoded("['a',1].join('')") == "a1"


def p2_control_seam_fp_quiet():
    c9 = "xoxb-" + "a" * 9
    return not _blocked("['%s',1].filter(x=>x.length>0).join('')" % c9)


def p2_control_junk_quiet():
    return not _blocked("['ab',1].filter(x=>x.length>0).join('')")


# ---------------------------------------------------------------- P3: pins

def p3_pin_node_byte_fidelity():
    # Every claimed shape: byte-identical to node, or fail-closed in a
    # documented direction (None vs node '' / node-throws / F434).
    cases = [
        ("['a',1].filter(x=>x.length>0).join('')", None, "a"),
        ("[1,2].filter(x=>x.length>0).join('')", None, ""),
        ("Array(2).fill(1).filter(x=>x.length>0).join('')", None, ""),
        ("['a',1].filter(x=>x.match(/[a-z]/)).join('')", None, "THROWS"),
        ("['a',1].filter(x=>x.charCodeAt(0)>47).join('')", None, "THROWS"),
        ("['a',1].filter(function(x){return x.length>0;}).join('')",
         None, "a"),
        ("['a','b'].filter(x=>x.length>0).join('')", "ab", "ab"),
        ("['a',1].filter(x=>x!=='').join('')", "a1", "a1"),
        ("['a',1].filter(Boolean).join('')", "a1", "a1"),
        ("['a',1].filter(x=>x!==null).join('')", "a1", "a1"),
        ("['a','b'].filter(x=>x.match(/[a-z]/)).join('')", "ab", "ab"),
        ("['a','b'].filter(x=>x.charCodeAt(0)>47).join('')", "ab", "ab"),
        ("['a',1].map(String).filter(x=>x.length>0).join('')", "a1", "a1"),
        ("['a',1].map(x=>x).filter(x=>x.length>0).join('')", None, "a"),
        ("[1,2].join('')", "12", "12"),
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


def p3_pin_numstr_provenance():
    state = {"ops": 0, "parts": 0}
    arr, _ = dlp._js_parse_array("['a',1]", 0, 0, state)
    types = [type(e).__name__ for e in arr.elements]
    if types != ["str", "_JSNumStr"]:
        return False
    # Additive of two plain strings stays plain (node: genuine string).
    state = {"ops": 0, "parts": 0}
    arr2, _ = dlp._js_parse_array("['a'+'b',1]", 0, 0, state)
    if [type(e).__name__ for e in arr2.elements] != ["str", "_JSNumStr"]:
        return False
    # _JSNumStr behaves exactly like str.
    e = dlp._JSNumStr("1")
    return (e + "x" == "1x" and len(e) == 1 and e != ""
            and type(str(e)).__name__ == "str")


def p3_pin_plen_spec_split():
    s1, _ = dlp._js_parse_truthy_body("x.length>0", 0, "x")
    s2, _ = dlp._js_parse_truthy_body("x!==''", 0, "x")
    s3, _ = dlp._js_parse_truthy_body("!!x", 0, "x")
    s4, _ = dlp._js_parse_truthy_body("x", 0, "x")
    return (s1[0] == "plen" and s2[0] == "truthy" and s3[0] == "truthy"
            and s4[0] == "truthy")


def p3_pin_map_stringifies_flag():
    nxt, stringifies = dlp._js_parse_map_callback("String)", 0)
    if not stringifies:
        return False
    _, s2 = dlp._js_parse_map_callback("x=>x", 0)
    _, s3 = dlp._js_parse_map_callback("function(x){return x;}", 0)
    return (not s2) and (not s3)


def p3_pin_no_new_regexes():
    # The F475 closure added no anchor change -- character classes and
    # the _JSNumStr check are not regexes. re.compile count unchanged.
    # Wave-356 lane 1: F476 widened the Array anchor with the ['of']
    # bracket alternative (character-class only, no new re.compile).
    # Wave-356 lane 2: F477 added the String( constructor alternative.
    # Wave-357 lane 1: F478 added the X.prototype dispatch-target
    # alternatives (character class only, no new re.compile).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String[ \t\n\r]*\(|Array(\(|"
        r"[ \t\n\r]*(\.[ \t\n\r]*of|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect[ \t\n\r]*\.[ \t\n\r]*(construct|apply)|Object[ \t\n\r]*\.[ \t\n\r]*assign|\(")
    for s in ["'", '"', "`", "[", "String.fromCharCode",
              "Array(", "Array.of", "Array.prototype.concat",
              "String.prototype.concat", "String(",
              "Reflect.construct", "Reflect.apply",
              "Object.assign", "("]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return True


def p3_pin_f441_ordering_untouched():
    # _try_bslash_unescape_all still precedes the _ESC_RUN layers.
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


def p4_discr_innocent_mixed_quiet():
    cases = [
        "['id',7].filter(x=>x.length>0).join(',')",
        "['a',1].filter(x=>x.match(/[0-9]/)).join('')",
        "[200,404].filter(x=>x>100).join('')",
    ]
    return all(not _blocked(c) for c in cases)


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        "['a'," + "1," * 2000 + "1].filter(x=>x.length>0).join('')",
        "['a',1].filter(x=>" + "x.length>" * 500 + "0).join('')",
        "['a',1].filter(x=>x.match(/[" + "a" * 5000 + "]/)).join('')",
        "[" + "1," * 5000 + "].filter(x=>x.length>0).join('')",
        "['a',1].filter(x=>x.charCodeAt(" + "0" * 2000 + ")>47).join('')",
        "['a',1].map(String).filter(x=>x.length>0).join('')" * 60,
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

def p6_noreg_f469_reflect_apply():
    return _blocked(
        "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')"
        % (_A, _B))


def p6_noreg_f470_match_pure():
    return _blocked(
        "['%s','%s'].filter(x=>x.match(/[a-z]/)).join('')" % (_A, _B))


def p6_noreg_f470_ccmp_pure():
    return _blocked(
        "['%s','%s'].filter(x=>x.charCodeAt(0)>47).join('')" % (_A, _B))


def p6_noreg_f471_spread_copy():
    return _blocked("[...['%s','%s']].join('')" % (_A, _B))


def p6_noreg_f472_repeat_tag():
    bt = chr(96)
    return _blocked("'%s'.repeat%s2%s" % (_A + _B, bt, bt))


def p6_noreg_f467_null_filter():
    return _blocked("['%s','%s',''].filter(x=>x!==null).join('')" % (_A, _B))


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('%s').join('')" % (_A + _B))


def p6_noreg_f434_array_join():
    return _blocked("['%s','%s'].join('')" % (_A, _B))


def p6_noreg_f462_spread_concat():
    return _blocked("''.concat(...['%s','%s'])" % (_A, _B))


def p6_noreg_f460_map_string():
    return _blocked("['%s','%s'].map(String).join('')" % (_A, _B))


def p6_noreg_f461_reverse():
    return _blocked("['%s','%s'].reverse().join('')" % (_B, _A))


def p6_noreg_f466_slice():
    return _blocked("['%s','%s'].slice(0,2).join('')" % (_A, _B))


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
    ok = ok and "CLOSED 2026-10-06 wave-355 lane 3" in footer
    ok = ok and "(F475 filed 2026-10-06, wave-355 lane 3" in footer
    return ok


_PROBES = [
    ("p1-closure-plen-mixed-none", p1_closure_plen_mixed_none),
    ("p1-closure-plen-allnum-none", p1_closure_plen_allnum_none),
    ("p1-closure-plen-fillnum-none", p1_closure_plen_fillnum_none),
    ("p1-closure-plen-hexnum-none", p1_closure_plen_hexnum_none),
    ("p1-closure-plen-floatnum-none", p1_closure_plen_floatnum_none),
    ("p1-closure-match-mixed-none", p1_closure_match_mixed_none),
    ("p1-closure-ccmp-mixed-none", p1_closure_ccmp_mixed_none),
    ("p1-closure-plen-function-form-none", p1_closure_plen_function_form_none),
    ("p1-closure-identity-map-keeps-provenance",
     p1_closure_identity_map_keeps_provenance),
    ("p1-closure-reverse-mixed-none", p1_closure_reverse_mixed_none),
    ("p2-control-pure-string-plen", p2_control_pure_string_plen),
    ("p2-control-pure-string-match", p2_control_pure_string_match),
    ("p2-control-pure-string-ccmp", p2_control_pure_string_ccmp),
    ("p2-control-mixed-neq", p2_control_mixed_neq),
    ("p2-control-mixed-boolean", p2_control_mixed_boolean),
    ("p2-control-mixed-identity", p2_control_mixed_identity),
    ("p2-control-mixed-dneg", p2_control_mixed_dneg),
    ("p2-control-mixed-nullcmp", p2_control_mixed_nullcmp),
    ("p2-control-mixed-positional", p2_control_mixed_positional),
    ("p2-control-map-string-normalizes", p2_control_map_string_normalizes),
    ("p2-control-mixed-join", p2_control_mixed_join),
    ("p2-control-seam-fp-quiet", p2_control_seam_fp_quiet),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p3-pin-node-byte-fidelity", p3_pin_node_byte_fidelity),
    ("p3-pin-numstr-provenance", p3_pin_numstr_provenance),
    ("p3-pin-plen-spec-split", p3_pin_plen_spec_split),
    ("p3-pin-map-stringifies-flag", p3_pin_map_stringifies_flag),
    ("p3-pin-no-new-regexes", p3_pin_no_new_regexes),
    ("p3-pin-f441-ordering-untouched", p3_pin_f441_ordering_untouched),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-innocent-mixed-quiet", p4_discr_innocent_mixed_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f469-reflect-apply", p6_noreg_f469_reflect_apply),
    ("p6-noreg-f470-match-pure", p6_noreg_f470_match_pure),
    ("p6-noreg-f470-ccmp-pure", p6_noreg_f470_ccmp_pure),
    ("p6-noreg-f471-spread-copy", p6_noreg_f471_spread_copy),
    ("p6-noreg-f472-repeat-tag", p6_noreg_f472_repeat_tag),
    ("p6-noreg-f467-null-filter", p6_noreg_f467_null_filter),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f434-array-join", p6_noreg_f434_array_join),
    ("p6-noreg-f462-spread-concat", p6_noreg_f462_spread_concat),
    ("p6-noreg-f460-map-string", p6_noreg_f460_map_string),
    ("p6-noreg-f461-reverse", p6_noreg_f461_reverse),
    ("p6-noreg-f466-slice", p6_noreg_f466_slice),
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
    scripts = ("w354_attack_probes.py",
               "w354_f469close_probes.py",
               "w354_f470close_probes.py",
               "w354_f471close_probes.py",
               "w354_f472close_probes.py",
               "w353_attack_probes.py",
               "w353_f467f468close_probes.py")
    stale_footer_ok = {}
    for script in scripts:
        tmp = "/var/tmp/g355-green-%s-%d" % (script.replace(".py", ""),
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
    print("w355_f475close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
