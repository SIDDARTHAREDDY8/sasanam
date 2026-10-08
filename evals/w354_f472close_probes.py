#!/usr/bin/env python3
"""Wave-354 F472 closure battery (lane 4).

F472 (LOW, filed 2026-10-06 wave-353 lane 2): calling `.repeat` as a
tagged template bypassed the bounded static JS-expression decoder --
`'xoxb-0123'.repeat`2`` (repeat invoked as a tag with a literal-only
template) node-evaluates to 'xoxb-0123xoxb-0123', which trips the
dlp-slack-token rule: the tag receives the TemplateStringsArray ['2']
as the repeat count (ToNumber(String(['2'])) == 2). The F463 closure
modeled the tag-call site for .join/.concat/.fill only; repeat's
ToNumber count conversion is a distinct unmodeled shape.

Closure design (gov/dlp.py, F472): `_js_tag_repeat_count` converts the
literal-only template's cooked string with engine-exact ToNumber +
ToIntegerOrInfinity semantics (node-verified, v24.20.0):
  decimal via float64 -- exactly the engine's own literal parsing,
    including its round-to-nearest at the truncation boundary
    ('0.99..9' -> 1.0, '63.99..9' -> 64.0); truncates toward zero
  0x/0b/0o radix forms (no sign -- '-0x2' is NaN in ToNumber)
  NaN ('', ' ', 'abc', 'NaN', '0x', '1_0') -> 0 reps (the '' result is
    gated exactly like the F463 fill`` empty case)
  negative / +-Infinity -> fail closed (the engine throws RangeError;
    the shape produces no text)
Interpolation fails closed in `_js_parse_tag_template` (F463); the
receiver must be a string (the engine throws TypeError on arrays, so
_JSArr fails closed); counts above _JS_EXPR_MAX_REPEAT fail closed
exactly like the paren form's standing bound. Wired into
`_js_apply_tag_method` and the `_js_parse_postfix` tag tuple
("join", "concat", "fill", "repeat"). No new regexes; static; never
evals.

Documented residuals (NOT filed, disclosed here): the paren form
`.repeat(2.5)` still fails closed (pre-existing F430 integer-literal
scope -- `_js_parse_number` is shared with padStart/slice/etc. and was
not widened); counts above the standing 64-bound fail closed on both
forms (engine produces text -- accepted DoS bound, same as paren).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed F472 shapes block (repeat tagged, ws-tolerant
      call site, float/hex/plus-sign counts, chained tag repeats,
      join-tag composition); decoder-level bound edge (64) and
      float64 boundary pinned.
  P2  controls: plain credential blocks; junk tagged repeat quiet;
      interpolated tag quiet (fail-closed); unterminated tag quiet;
      negative / Infinity counts quiet (RangeError); over-bound (65)
      quiet at decoder level; array receiver quiet (TypeError);
      unmodeled method tag quiet; paren repeat still blocks.
  P3  decoder pins: byte-fidelity vs node v24.20.0 on every claimed
      shape (subprocess); float64 literal-parsing boundary pinned
      ('0.99..9' -> 1.0, '63.99..9' -> 64.0); NaN -> 0 reps gated;
      no new regexes (anchor pattern unchanged); F441 _decode_layer
      ordering untouched.
  P4  discrimination: FP corpus (repo docs) hit-set identical to base;
      innocent repeat tags quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F463 join tagged,
      F457 template interp, F434 array join, F443 Array fill,
      F446 Array.of, F461 reverse, F462 spread concat, F464
      toString-replace, F465 padStart, F466 slice, F467 null-cmp
      filter, F468 Reflect.construct); F469-F471 attack-lane filings
      pinned open as documented entries.
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      footer open F469, F470, F471 / next F473, F472 CLOSED entry
      present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w354_f472close_probes.py
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

TAXONOMY_PIN = 2140  # Wave-354: F472 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F612, F614, F615, F616, F617, F618, F619, F620"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-355 lanes 1+2: F473, F474 CLOSED; open none / next F475 (merge intermediate)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 lane 1: F476 CLOSED  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED

FOOTER_NEXT = "F621"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xox" + "b-abc123" + "def" + "456"
_A = "xox" + "b-abc123"
_B = "def" + "456"
_FRAG = "xoxb-" + "0123"  # 'xoxb-0123'.repeat`2` -> 'xoxb-0123xoxb-0123'
_BT = chr(96)  # backtick


def _blocked(payload):
    return dlp.find_credential(payload) is not None


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

def p1_closure_filed_repeat_tag():
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "2" + _BT)


def p1_closure_repeat_tag_ws():
    # Engine-tolerated whitespace between the method name and the template.
    return _blocked("'" + _FRAG + "' .repeat " + _BT + "2" + _BT)


def p1_closure_repeat_tag_float():
    # ToIntegerOrInfinity: 2.5 -> 2.
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "2.5" + _BT)


def p1_closure_repeat_tag_hex():
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "0x2" + _BT)


def p1_closure_repeat_tag_plus():
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "+3" + _BT)


def p1_closure_repeat_tag_zeropad():
    # Spec-review catch: a >64-char count string with a small value
    # ('000..02' -> 2) must decode -- the bound applies to the VALUE,
    # not the string length.
    r = dlp._try_js_expr_decode("'" + _FRAG + "'.repeat" + _BT + "0" * 63
                                + "2" + _BT, 0)
    return r is not None and r[0] == _FRAG * 2


def p1_closure_repeat_tag_chain():
    # Chained tag repeats compose.
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "2" + _BT
                    + ".repeat" + _BT + "2" + _BT)


def p1_closure_repeat_tag_compose():
    # F463 join-tag result flows into the repeat tag-call site.
    return _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT
                    + ".repeat" + _BT + "2" + _BT)


def p1_closure_repeat_bound_edge():
    # Decoder-level: the 64 bound is inclusive (same as the paren form).
    r = dlp._try_js_expr_decode("'x'.repeat" + _BT + "64" + _BT, 0)
    return r is not None and r[0] == "x" * 64


def p1_closure_float64_boundary():
    # Decoder-level: the engine parses the count literal as float64,
    # including its round-to-nearest at the truncation boundary.
    r = dlp._try_js_expr_decode(
        "'x'.repeat" + _BT + "0." + "9" * 55 + _BT, 0)
    ok = r is not None and r[0] == "x"  # float64('0.99..9') == 1.0
    r2 = dlp._try_js_expr_decode(
        "'x'.repeat" + _BT + "63." + "9" * 55 + _BT, 0)
    ok = ok and r2 is not None and r2[0] == "x" * 64
    return ok


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_tag_quiet():
    return not _blocked("'ab'.repeat" + _BT + "2" + _BT)


def p2_control_interp_tag_quiet():
    # Interpolated tag fails closed (the engine evaluates it to '',
    # so there is nothing to surface either way).
    return not _blocked("'ab'.repeat" + _BT + "${'2'}" + _BT)


def p2_control_unterminated_quiet():
    return not _blocked("'ab'.repeat" + _BT + "2")


def p2_control_negative_quiet():
    # The engine throws RangeError; the decoder yields no variant.
    return not _blocked("'ab'.repeat" + _BT + "-1" + _BT)


def p2_control_infinity_quiet():
    return not _blocked("'ab'.repeat" + _BT + "Infinity" + _BT)


def p2_control_overbound_quiet():
    # Decoder-level: counts above the standing 64 bound fail closed
    # (same as the paren form).
    return dlp._try_js_expr_decode("'x'.repeat" + _BT + "65" + _BT,
                                  0) is None


def p2_control_array_receiver_quiet():
    # The engine throws TypeError on arrays; the decoder fails closed.
    return not _blocked("['a','b'].repeat" + _BT + "2" + _BT)


def p2_control_map_tag_quiet():
    # .map is not a modeled tag-call site.
    return not _blocked("'ab'.map" + _BT + "2" + _BT)


def p2_control_paren_repeat_blocks():
    # Neighbor contract: the paren form of repeat still blocks.
    return _blocked("'" + _FRAG + "'.repeat(2)")


# ---------------------------------------------------------------- P3: decoder pins

def _decode_cases():
    # (payload, expected decoded value or None for fail-closed,
    #  node ground-truth value or None if the decoder must diverge)
    return [
        ("'x'.repeat" + _BT + "2" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "2.5" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "+3" + _BT, "xxx", "xxx"),
        ("'x'.repeat" + _BT + "0x2" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "0b10" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "0o10" + _BT, "x" * 8, "x" * 8),
        ("'x'.repeat" + _BT + "2e0" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + " 2 " + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "\\x32" + _BT, "xx", "xx"),
        ("'x'.repeat" + _BT + "2" + _BT + ".repeat" + _BT + "2" + _BT,
         "xxxx", "xxxx"),
        # Fail-closed shapes: the decoder yields no variant.
        ("'x'.repeat" + _BT + "-1" + _BT, None, None),  # THROWS
        ("'x'.repeat" + _BT + "Infinity" + _BT, None, None),  # THROWS
        ("'x'.repeat" + _BT + "-Infinity" + _BT, None, None),  # THROWS
        ("'x'.repeat" + _BT + "65" + _BT, None, "x" * 65),  # bound
        ("'x'.repeat" + _BT + "${'2'}" + _BT, None, ""),  # interp: ''
        ("['a','b'].repeat" + _BT + "2" + _BT, None, None),  # THROWS
        ("'x'.map" + _BT + "2" + _BT, None, None),
        ("'x'.repeat" + _BT + "abc" + _BT, None, ""),  # NaN -> ''
        ("'x'.repeat" + _BT + "1_0" + _BT, None, ""),  # NaN -> ''
    ]


def p3_pin_node_byte_fidelity():
    cases = _decode_cases()
    node_vals = _node_eval([p for p, _, _ in cases])
    for (payload, expect, nval), got_n in zip(cases, node_vals):
        r = dlp._try_js_expr_decode(payload, 0)
        got = r[0] if r else None
        if expect is None:
            assert got is None, (payload, got)
            if nval is not None:
                assert got_n == json.dumps(nval), (payload, got_n)
        else:
            assert got == expect, (payload, got, expect)
            assert got_n == json.dumps(expect), (payload, got_n)
    return True


def p3_pin_float64_literal_parsing():
    # The count literal parses exactly as the engine parses it
    # (float64 round-to-nearest), not as an exact decimal: an exact
    # decimal truncation would give 0 / 63 reps here; the engine (and
    # the decoder) give 1 / 64.
    for cooked, want in (("0." + "9" * 55, "x"),
                         ("63." + "9" * 55, "x" * 64)):
        payload = "'x'.repeat" + _BT + cooked + _BT
        r = dlp._try_js_expr_decode(payload, 0)
        assert r is not None and r[0] == want, (cooked, r)
        assert _node_eval([payload])[0] == json.dumps(want), cooked
    return True


def p3_pin_nan_gated():
    # NaN counts produce '' in the engine; the decoder's '' result is
    # gated exactly like the F463 fill`` empty case (no variant).
    for cooked in ("", " ", "abc", "NaN", "0x", "1_0"):
        payload = "'x'.repeat" + _BT + cooked + _BT
        assert dlp._try_js_expr_decode(payload, 0) is None, cooked
    return True


def p3_pin_no_new_regexes():
    # Functional pin: the repeat tag-call site needed no anchor change
    # -- it lives inside _js_parse_postfix. The anchor pattern is pinned
    # here as the exact pattern string. Legitimate additions since F463:
    # wave-354 lane 1 (F469) widened Reflect to (construct|apply); wave-354
    # lane 3 (F471) added the Object.assign alternative (F468 precedent,
    # character class only). The F472 closure itself added no regex.
    # Wave-356 lane 1: F476 added the Array['of'] bracket alternative
    # (character-class only, no new re.compile). Wave-356 lane 2: F477
    # added the String( constructor alternative. Wave-357 lane 1: F478
    # added the X.prototype dispatch-target alternatives (character
    # class only, no new re.compile). Wave-360 lane 2 (F491/F493):
    # Reflect -> (construct|apply|get), Object gains
    # getOwnPropertyDescriptor, String gains .raw( / .raw.call(
    # (literal-alternation only, no new re.compile).
    # Wave-361 lane 1 (F496): Reflect alternative widened \. -> (\?\.|\.) for optional-chaining dispatch (literal alternation only, F468 precedent).
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
    # F539 (wave-368 lane 2): the Object dot-member alternative gains
    # freeze (identity-preserving builtin on object literals) -- new
    # member-name alternative, pinned exactly here; re.compile count
    # unchanged (28).
    # F565 (wave-369 lane 5): the Object dot-member alternative gains
    # fromEntries (deserializing builtin on literal pair lists / Map)
    # -- new member-name alternative, pinned exactly here; re.compile
    # count unchanged (28).
    # Wave-369 lane 5 (F565): re-pinned to the live anchor --
    # the pin had gone stale (structuredClone (F536, wave-367 lane 4); JSON (F541, wave-368 lane 3); new WeakRef (F539, wave-368 lane 2)
    # added without re-pin); exactness restored and the
    # fromEntries member alternative added. re.compile count
    # unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String\.fromCodePoint|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call|from)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"`\[])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor|getOwnPropertyNames|getOwnPropertyDescriptors|values|keys|entries|freeze|fromEntries)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"structuredClone(?![_$A-Za-z0-9])|JSON(?![_$A-Za-z0-9])|new[ \t\n\r]+WeakRef(?![_$A-Za-z0-9])|"
        r"\("
    )
    # F480 (wave-358 lane 1): anchor widened for the constructor-function
    # dispatch (Array.apply/call) and the bracket-string member forms
    # (Array[/String[/Object[/Reflect[) -- character classes only;
    # re.compile count unchanged.
    # F483 (wave-359 lane 1): Function.prototype added for the
    # double-dispatch shapes -- character classes only;
    # re.compile count unchanged (28).
    for s in ["'", '"', "`", "[", "String.fromCharCode", "String.fromCodePoint",
              "Array(", "Array.of", "Array.from",
              "Array.prototype.concat",
              "String.prototype.concat", "String(",
              "Reflect.construct", "Reflect.apply",
              "Object.assign", "Object.fromEntries(", "("]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
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


def p4_discr_innocent_tags_quiet():
    cases = [
        "repeat" + _BT + "2" + _BT,
        "x.repeat" + _BT + "0" + _BT,
        "s.repeat" + _BT + "times" + _BT,
        "'hello'.repeat" + _BT + "3" + _BT,
    ]
    return all(not _blocked(c) for c in cases)


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        _BT + "9" * 9000,
        "'a'.repeat" + _BT + "9" * 9000 + _BT,
        "'a'.repeat" + _BT + "${" * 500 + _BT,
        "'a'.repeat" + _BT + "9." + "9" * 5000 + _BT,
        "'a'.repeat" + _BT + "0x" + "f" * 5000 + _BT,
        "'a'.repeat" + _BT + "\\x" * 5000,
        "'a'" + (".repeat" + _BT + "2" + _BT) * 200,
        "'a'.repeat" + _BT + "1e" + "9" * 60 + _BT,
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

def p6_noreg_f463_join_tagged():
    return _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT)


def p6_noreg_f457_template_interp():
    return _blocked("`" + _A + "${'" + _B + "'}`")


def p6_noreg_f434_array_join():
    return _blocked("['" + _A + "','" + _B + "'].join('')")


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('" + _A + "').join('')")


def p6_noreg_f446_array_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f461_reverse():
    return _blocked("['" + _B + "','" + _A + "'].reverse().join('')")


def p6_noreg_f462_spread_concat():
    return _blocked("''.concat(...['" + _A + "','" + _B + "'])")


def p6_noreg_f464_tostring_replace():
    return _blocked("['" + _A + "','" + _B + "'].toString().replace(/,/g,'')")


def p6_noreg_f465_padstart():
    return _blocked("'" + _B + "'.padStart(21,'" + _A + "xoxb-')")


def p6_noreg_f466_slice():
    return _blocked("['" + _A + "','" + _B + "',''].slice(0,2).join('')")


def p6_noreg_f467_null_filter():
    return _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null).join('')")


def p6_noreg_f468_reflect_construct():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B
                    + "']).join('')")


def p6_noreg_f469f470f471_attack_lane_documented():
    # F469/F470/F471 are wave-353 attack-lane filings (round 21);
    # their full entries and red-first batteries live in the merged tree.
    # This probe pins the documentation contract: the footer lists them
    # open with their filing notes, and no behavioral claim is
    # made about their shapes from this tree.
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    ok = ("(F469 filed 2026-10-06, wave-353 lane 5 (continuous real-model attack"
          in footer)
    ok = ok and ("(F470 filed 2026-10-06, wave-353 lane 5 (continuous real-model attack"
                 in footer)
    ok = ok and ("(F471 filed 2026-10-06, wave-353 lane 5 (continuous real-model attack"
                 in footer)
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return ok


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-354 lane 4" in footer
    return ok


_PROBES = [
    ("p1-closure-filed-repeat-tag", p1_closure_filed_repeat_tag),
    ("p1-closure-repeat-tag-ws", p1_closure_repeat_tag_ws),
    ("p1-closure-repeat-tag-float", p1_closure_repeat_tag_float),
    ("p1-closure-repeat-tag-hex", p1_closure_repeat_tag_hex),
    ("p1-closure-repeat-tag-plus", p1_closure_repeat_tag_plus),
    ("p1-closure-repeat-tag-zeropad", p1_closure_repeat_tag_zeropad),
    ("p1-closure-repeat-tag-chain", p1_closure_repeat_tag_chain),
    ("p1-closure-repeat-tag-compose", p1_closure_repeat_tag_compose),
    ("p1-closure-repeat-bound-edge", p1_closure_repeat_bound_edge),
    ("p1-closure-float64-boundary", p1_closure_float64_boundary),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-tag-quiet", p2_control_junk_tag_quiet),
    ("p2-control-interp-tag-quiet", p2_control_interp_tag_quiet),
    ("p2-control-unterminated-quiet", p2_control_unterminated_quiet),
    ("p2-control-negative-quiet", p2_control_negative_quiet),
    ("p2-control-infinity-quiet", p2_control_infinity_quiet),
    ("p2-control-overbound-quiet", p2_control_overbound_quiet),
    ("p2-control-array-receiver-quiet", p2_control_array_receiver_quiet),
    ("p2-control-map-tag-quiet", p2_control_map_tag_quiet),
    ("p2-control-paren-repeat-blocks", p2_control_paren_repeat_blocks),
    ("p3-pin-node-byte-fidelity", p3_pin_node_byte_fidelity),
    ("p3-pin-float64-literal-parsing", p3_pin_float64_literal_parsing),
    ("p3-pin-nan-gated", p3_pin_nan_gated),
    ("p3-pin-no-new-regexes", p3_pin_no_new_regexes),
    ("p3-pin-f441-ordering-untouched", p3_pin_f441_ordering_untouched),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-innocent-tags-quiet", p4_discr_innocent_tags_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f463-join-tagged", p6_noreg_f463_join_tagged),
    ("p6-noreg-f457-template-interp", p6_noreg_f457_template_interp),
    ("p6-noreg-f434-array-join", p6_noreg_f434_array_join),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f461-reverse", p6_noreg_f461_reverse),
    ("p6-noreg-f462-spread-concat", p6_noreg_f462_spread_concat),
    ("p6-noreg-f464-tostring-replace", p6_noreg_f464_tostring_replace),
    ("p6-noreg-f465-padstart", p6_noreg_f465_padstart),
    ("p6-noreg-f466-slice", p6_noreg_f466_slice),
    ("p6-noreg-f467-null-filter", p6_noreg_f467_null_filter),
    ("p6-noreg-f468-reflect-construct", p6_noreg_f468_reflect_construct),
    ("p6-noreg-f469f470f471-attack-lane-documented",
     p6_noreg_f469f470f471_attack_lane_documented),
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
    scripts = ("w353_attack_probes.py",
               "w353_f461f462close_probes.py",
               "w353_f463close_probes.py",
               "w353_f464f465f466close_probes.py",
               "w353_f467f468close_probes.py",
               "w352_attack_probes.py",
               "w352_f457close_probes.py")
    # Attack batteries pin the footer with inline literals (repointed by
    # the merge coordinator's tree-wide footer sweep); this lane
    # repointed every adjacent battery's footer probe in-tree, so no
    # stale-footer tolerance remains.
    stale_footer_ok = {}
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
    print("w354_f472close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
