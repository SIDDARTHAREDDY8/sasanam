#!/usr/bin/env python3
"""Wave-355 F474 closure battery (lane 2).

F474 (LOW, filed 2026-10-06 wave-354 attack round 22): robustness defect,
fail-UNDEFINED -- NOT a bypass. `('a').concat(['b'])` (paren, non-spread
arg path): the arg is appended as a _JSArr with no type check, and
`"".join(parts)` later raises `TypeError: sequence item 0: expected str
instance, _JSArr found`, escaping the public seam `find_credential`.
The spread path guards `isinstance(e, str)`; the non-spread argument
path had none, so the exception escaped instead of failing closed with
_JSExprFail.

Closure design (gov/dlp.py, F474): the non-spread concat-arg branch now
type-guards its argument exactly like the spread path -- a non-str arg
raises _JSExprFail (fail closed). Node-justified direction (v24.20.0):
`('a').concat(['b'])` evaluates to 'ab' via IMPLICIT Array-to-String
coercion (String(['b']) == 'b'), which the static decoder cannot model;
modeling it as string-concat would mis-decode (e.g. ['b','c'] ->
'ab,c' vs a naive 'abc'), so fail closed is the only honest direction.
The full filed shape with trailing .join('') throws in a real engine
too, confirming F474 is robustness-only.

Audit (same defect class): every other string-assembly site in the
JS-expression decoder was audited -- _js_parse_array rejects nested
_JSArr elements at parse; the fill/join-separator/replace/pad/tag
branches all guard receivers/args with isinstance checks; the F469
Reflect.apply desugar guards every element; _collect_strings appends
only str/decoded leaves; escape/entity decoders None-check. The
paren-concat non-spread branch was the only unguarded site.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the filed shape + all node-verified raise-variants now
      fail closed at the decoder level (no variant) AND raise nothing
      at the public seam.
  P2  controls: plain credential blocks; string-args concat still
      decodes; spread concat (F462) still decodes; Reflect.apply concat
      (F469) still decodes; junk quiet.
  P3  decoder pins: node differential on the direction (node coerces,
      decoder fails closed -- pinned deliberately); no new regexes
      (anchor pattern unchanged); F441 _decode_layer ordering untouched.
  P4  discrimination: FP corpus hit-set identical to base; innocent
      concat shapes quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F462 spread, F469
      Reflect.apply, F463 join tagged, F434 array join, F443 Array
      fill, F446 Array.of, F461 reverse, F464 toString-replace, F465
      padStart, F466 slice, F467 null-cmp filter, F468 Reflect.construct,
      F470 match/ccmp filter, F471 spread-copy/Object.assign, F472
      repeat tagged); F473 attack filing pinned open as documented.
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F473 / next F475, F474 CLOSED entry present.
  PZ  fuzz: 24 malformed adversarial inputs at the public seam --
      zero exceptions (the fail-closed scanner never raises).
  PG  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w355_f474close_probes.py
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

TAXONOMY_PIN = 2135  # Wave-355: F474 closed; no new decision codes
FOOTER_OPEN = "F482, F483, F484, F485, F486, F487, F488"  # Wave-357 lane 2: F479 CLOSED locally; Wave-355 lane 2: F474 CLOSED (merge finalizes tree-wide); F473 is the wave-354 attack-lane filing (commit e6db7a26)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 lane 1: F476 CLOSED  # Wave-356 lane 2: F477 CLOSED  # Wave-356 merge: F476, F477 CLOSED  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN
FOOTER_NEXT = "F489"  # Wave-355 lane 2: F474 closed; next free F475  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: unchanged  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xox" + "b-abc123" + "def" + "456"
_A = "xox" + "b-abc123"
_B = "def" + "456"
_FRAG1 = "xoxb-" + "0123"
_FRAG2 = "4567" + "89abcdef"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _no_raise(payload):
    try:
        dlp.find_credential(payload)
        return True
    except Exception:
        return False


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

def p1_closure_filed_shape_no_raise():
    # The filed shape: decoder fails closed, and nothing raises.
    p = "('" + _FRAG1 + "').concat(['" + _FRAG2 + "'])"
    return _no_raise(p) and not _blocked(p)


def p1_closure_filed_shape_decoder_level():
    r = dlp._try_js_expr_decode("('a').concat(['b'])", 0)
    return r is None


def p1_closure_array_of_arg():
    p = "('" + _FRAG1 + "').concat(Array.of('" + _FRAG2 + "'))"
    return _no_raise(p) and not _blocked(p)


def p1_closure_mixed_args():
    # ('a').concat('b', ['c']) raised "sequence item 1" on the base tree.
    p = "('" + _FRAG1 + "').concat('" + _FRAG2 + "',['zz'])"
    return _no_raise(p) and not _blocked(p)


def p1_closure_reflect_arg():
    p = ("('" + _FRAG1 + "').concat("
         "Reflect.construct(Array,['" + _FRAG2 + "']))")
    return _no_raise(p) and not _blocked(p)


def p1_closure_multi_array_args():
    p = "('" + _FRAG1 + "').concat(['" + _FRAG2 + "'],['zz'])"
    return _no_raise(p) and not _blocked(p)


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_string_args_still_decode():
    # ('a').concat('b') -- honest string args unaffected by the guard.
    r = dlp._try_js_expr_decode("('a').concat('b','c')", 0)
    return r is not None and r[0] == "abc"


def p2_control_spread_still_decodes():
    # F462: spread args still decode (the guard only rejects non-str).
    r = dlp._try_js_expr_decode("''.concat(...['a','b'])", 0)
    return r is not None and r[0] == "ab"


def p2_control_reflect_apply_still_decodes():
    # F469: Reflect.apply(Array.prototype.concat,...) still decodes.
    return _blocked(
        "Reflect.apply(Array.prototype.concat,[],[['" + _A + "'],['"
        + _B + "']]).join('')")


def p2_control_junk_quiet():
    return not _blocked("('ab').concat('cd')")


# ---------------------------------------------------------------- P3: decoder pins

def p3_node_direction_pinned():
    # Node coerces the array arg (String(['b']) == 'b'); the decoder
    # deliberately fails closed instead of modeling implicit coercion.
    got = _node_eval(["('a').concat(['b'])", "('a').concat(['b','c'])"])
    ok = got[0] == json.dumps("ab") and got[1] == json.dumps("ab,c")
    r = dlp._try_js_expr_decode("('a').concat(['b'])", 0)
    return ok and r is None


def p3_no_new_regexes():
    # Functional pin: the F474 fix is a pure isinstance guard -- no
    # anchor change. The anchor pattern is pinned as the exact pattern
    # string (same pin as the w354_f472close battery; legitimate
    # additions since F463: F469 widened Reflect to (construct|apply),
    # F471 added the Object.assign alternative -- both character-class
    # only). Wave-356 lane 1: F476 added the Array['of'] bracket
    # alternative (character-class only, no new re.compile). Wave-356
    # lane 2: F477 added the String( constructor alternative. Wave-357
    # lane 1: F478 added the X.prototype dispatch-target alternatives
    # (character class only, no new re.compile).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String[ \t\n\r]*(\(|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect([ \t\n\r]*\.[ \t\n\r]*(construct|apply)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf)|[ \t\n\r]*\[[ \t\n\r]*['\"])|\(")
    # F480 (wave-358 lane 1): anchor widened for the constructor-function
    # dispatch (Array.apply/call) and the bracket-string member forms
    # F488 (wave-359 lane 3): Object alternative gains getPrototypeOf
    # (constructor callee via prototype chain) -- a new member-name
    # alternative, not character-class-only; pinned exactly.
    # (Array[/String[/Object[/Reflect[) -- character classes only;
    # re.compile count unchanged.
    for s in ["'", '"', "`", "[", "String.fromCharCode",
              "Array(", "Array.of", "Array.prototype.concat",
              "String.prototype.concat", "String(",
              "Reflect.construct", "Reflect.apply",
              "Object.assign", "("]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    return True


def p3_f441_ordering_untouched():
    # _try_bslash_unescape_all still precedes the _ESC_RUN layers.
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return True


# ---------------------------------------------------------------- P4: discrimination

_FP_BASELINE = {
    'README.md': 'dlp-github-token',
    'SITUATION_MATRIX.md': 'dlp-aws-access-key',
    'docs/decision-code-coverage.md': 'dlp-entropy-tripwire',
    'evals/FINDINGS.md': 'dlp-aws-access-key',
    'evals/SITUATION_MATRIX.md': 'dlp-aws-access-key',
}  # Wave-355 lane 2: computed on closed tree, verified byte-identical on base


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


def p4_discr_innocent_concat_quiet():
    cases = [
        "x.concat(y)",
        "'hello'.concat(' world')",
        "s.concat()",
        "''.concat('a', 'b')",
    ]
    return all(not _blocked(c) for c in cases)


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        "'a'.concat(" + "['b']" * 2000,
        "'a'.concat(" + "['b'," * 2000,
        "('a').concat(" + "Array.of('b')," * 500,
        "'a'" + ".concat(['b'])" * 200,
        "'a'.concat(..." + "['b']" * 2000,
        "'a'.concat(['" + "b" * 9000 + "'])",
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

def p6_noreg_f462_spread():
    return _blocked("''.concat(...['" + _A + "','" + _B + "'])")


def p6_noreg_f469_reflect_apply():
    return _blocked(
        "Reflect.apply(Array.prototype.concat,[],[['" + _A + "'],['"
        + _B + "']]).join('')")


def p6_noreg_f463_join_tagged():
    bt = chr(96)
    return _blocked("['" + _A + "','" + _B + "'].join" + bt + bt)


def p6_noreg_f434_array_join():
    return _blocked("['" + _A + "','" + _B + "'].join('')")


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('" + _A + "').join('')")


def p6_noreg_f446_array_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f461_reverse():
    return _blocked("['" + _B + "','" + _A + "'].reverse().join('')")


def p6_noreg_f464_tostring_replace():
    return _blocked("['" + _A + "','" + _B + "'].toString().replace(/,/g,'')")


def p6_noreg_f465_padstart():
    return _blocked("'89abcdef'.padStart(21,'" + _A + "')")


def p6_noreg_f466_slice():
    return _blocked("['" + _A + "','" + _B + "'].slice(0,2).join('')")


def p6_noreg_f467_null_filter():
    return _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null)"
                    ".join('')")


def p6_noreg_f468_reflect_construct():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B
                    + "']).join('')")


def p6_noreg_f470_match_filter():
    return _blocked("['" + _A + "','" + _B + "',''].filter(x=>x.match(/[a-z]/))"
                    ".join('')")


def p6_noreg_f471_spread_copy():
    return _blocked("[...['" + _A + "','" + _B + "']].join('')")


def p6_noreg_f472_repeat_tagged():
    bt = chr(96)
    return _blocked("'" + _A[:8] + "'.repeat" + bt + "2" + bt)


def p6_noreg_f473_attack_lane_documented():
    # F473 (array-receiver paren .concat) was a wave-354 attack-lane
    # filing; CLOSED by wave-355 lane 1 (_js_apply_array_concat) and
    # merged. Pinned as blocked, not silently regressed.
    return _blocked("['" + _A + "'].concat(['" + _B + "']).join('')")


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    ok = ok and len(set(TAXONOMY)) == TAXONOMY_PIN
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
              encoding="utf-8") as f:
        # Footer is the LAST "Next free finding:" line (entries may follow it).
        footer = [l for l in f.read().splitlines() if "Next free finding:" in l][-1]
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and "**Status: CLOSED 2026-10-06 wave-355 lane 2.**" in open(
        os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
        encoding="utf-8").read()
    return ok


# ---------------------------------------------------------------- PZ: fuzz

_FUZZ_CASES = [
    "('a').concat(['b'])",
    "('a').concat(Array.of('b'))",
    "('a').concat(Reflect.construct(Array,['b']))",
    "('a').concat(...['b'])",
    "('a').concat('b', ['c'])",
    "('a').concat()",
    "('a').concat(",
    "('a').concat(['b'",
    "['a'].concat('b')",
    "('a').concat(['b']).join('')",
    "x.concat(['b'])",
    "('a').concat(['b'],)",
    "('a').concat(...42)",
    "('a').fill(['b'])",
    "['a','b'].join(['c'])",
    "('a').repeat(['b'])",
    "('a').padStart(5,['b'])",
    "('a,b').replace(/,/g,['b'])",
    "['a',1].filter(x=>x.length>0).join('')",
    "Object.assign([],['a']).concat(['b'])",
    "[...['a']].concat(['b'])",
    "Reflect.apply(Array.prototype.concat,[],[['a']])",
    "('a').concat(['b'],['c'])",
    "''.concat(['a'])",
]


def pz_fuzz_public_seam_no_raise():
    bad = []
    for c in _FUZZ_CASES:
        try:
            dlp.find_credential(c)
        except Exception as e:  # noqa: BLE001
            bad.append((c, type(e).__name__))
    if bad:
        print("raises: %s" % bad)
    return not bad


# ---------------------------------------------------------------- PG: green check

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
               "w353_f461f462close_probes.py",
               "w353_f463close_probes.py")
    # This lane flipped the F474 open pin to a closed assertion and
    # repointed every adjacent battery's footer probe in-tree, so no
    # stale-footer tolerance remains.
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
        # A nonzero rc is expected when only the tolerated stale-footer
        # probe breaks (attack batteries return 1 on any BREAK).
        if r.returncode != 0 and not breaks <= allowed:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


_PROBES = [
    ("p1-closure-filed-shape-no-raise", p1_closure_filed_shape_no_raise),
    ("p1-closure-filed-shape-decoder-level",
     p1_closure_filed_shape_decoder_level),
    ("p1-closure-array-of-arg", p1_closure_array_of_arg),
    ("p1-closure-mixed-args", p1_closure_mixed_args),
    ("p1-closure-reflect-arg", p1_closure_reflect_arg),
    ("p1-closure-multi-array-args", p1_closure_multi_array_args),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-string-args-still-decode",
     p2_control_string_args_still_decode),
    ("p2-control-spread-still-decodes", p2_control_spread_still_decodes),
    ("p2-control-reflect-apply-still-decodes",
     p2_control_reflect_apply_still_decodes),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p3-node-direction-pinned", p3_node_direction_pinned),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f441-ordering-untouched", p3_f441_ordering_untouched),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-innocent-concat-quiet", p4_discr_innocent_concat_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f462-spread", p6_noreg_f462_spread),
    ("p6-noreg-f469-reflect-apply", p6_noreg_f469_reflect_apply),
    ("p6-noreg-f463-join-tagged", p6_noreg_f463_join_tagged),
    ("p6-noreg-f434-array-join", p6_noreg_f434_array_join),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f461-reverse", p6_noreg_f461_reverse),
    ("p6-noreg-f464-tostring-replace", p6_noreg_f464_tostring_replace),
    ("p6-noreg-f465-padstart", p6_noreg_f465_padstart),
    ("p6-noreg-f466-slice", p6_noreg_f466_slice),
    ("p6-noreg-f467-null-filter", p6_noreg_f467_null_filter),
    ("p6-noreg-f468-reflect-construct", p6_noreg_f468_reflect_construct),
    ("p6-noreg-f470-match-filter", p6_noreg_f470_match_filter),
    ("p6-noreg-f471-spread-copy", p6_noreg_f471_spread_copy),
    ("p6-noreg-f472-repeat-tagged", p6_noreg_f472_repeat_tagged),
    ("p6-noreg-f473-attack-lane-documented",
     p6_noreg_f473_attack_lane_documented),
    ("p7-pin-and-footer", p7_pin_and_footer),
    ("pz-fuzz-public-seam-no-raise", pz_fuzz_public_seam_no_raise),
]

_EXPECTED_BREAKS = set()


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
    print("w355_f474close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
