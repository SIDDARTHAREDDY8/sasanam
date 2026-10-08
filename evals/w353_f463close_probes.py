#!/usr/bin/env python3
"""Wave-353 F463 closure battery (lane 2).

F463 (LOW, filed 2026-10-06 wave-352 lane 5, continuous real-model
attack round 20): calling `.join` as a tagged template bypassed the
bounded static JS-expression decoder -- `['a','b'].join`` `` (join
invoked as a tag with an empty template) node-evaluates to the
credential: the tag receives the TemplateStringsArray `['']` as the
separator. The decoder never modeled tag-call syntax, so the shape
failed closed with zero decode variants.

Closure design (gov/dlp.py, F463): the tag-call site is modeled for
`.join` / `.concat` / `.fill` via `_js_parse_tag_template` (literal-only
`` `...` `` parser; ANY `${` interpolation fails closed, because an
interpolated tag would make the modeled separator diverge from the
engine's -- String(strings) joins the cooked strings with ",") and
`_js_apply_tag_method` (wired into `_js_parse_postfix` after the paren
form; engine-tolerated whitespace between the method name and the
template is allowed). For a literal-only template the tag array is
exactly [cooked] and String([cooked]) is cooked, so:
  .join`T`   == .join(cooked)    -- cooked is the separator
  .concat`T` == .concat(cooked)  -- single string arg is appended
  .fill`T`   == .fill(cooked)    -- single string arg fills
Receiver rules match the paren forms exactly (join/fill require a
_JSArr; concat fails closed on _JSArr -- the decoder never surfaces
arrays). The tag call is obfuscation-shaped (ops += 1); the cooked
string is bounded by _MAX_DECODE_BYTES. No new regexes; static; never
evals.

Fail-closed direction (node-verified): an interpolated tag such as
`['a','b'].join`${'c'}`` evaluates to "a,b" (the tag receives
strings=["",""], String(["",""])==","), which the modeled class cannot
express -- the decoder yields no variant. This is a miss only for
shapes that do not recover the credential; `.repeat` as a tagged
template DID recover it (ToNumber(String(['2']))==2) and was filed as
the new finding F472 (renumbered F469->F472: the wave-353 attack lane
committed F469-F471 first, commit e79af076); F472 is CLOSED 2026-10-06
wave-354 lane 4 (bounded ToNumber tag count, _js_tag_repeat_count).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed F463 shapes block (join tagged, ws-tolerant
      call site, separator template, concat tagged, tagged chain,
      postfix composition); fill tagged decoder path pinned.
  P2  controls: plain credential blocks; junk tagged join quiet;
      interpolated tag quiet (fail-closed); unterminated tag quiet;
      unmodeled method tag quiet; bare tag function quiet; paren
      repeat still blocks (neighbor contract).
  P3  decoder pins: byte-fidelity vs node v24.20.0 on every claimed
      shape (subprocess); fail-closed shapes return None from
      _try_js_expr_decode; interpolated-tag divergence pinned
      (decoder None where node says "a,b"); no backtick added to the
      anchor (tag call needs none -- it lives in postfix);
      F441 _decode_layer ordering untouched.
  P4  discrimination: FP corpus (repo docs) hit-set identical to base;
      innocent bare tags quiet.
  P5  ReDoS: hostile near-miss inputs complete fast, no exceptions.
  P6  no-regression: adjacent closures still block (F457 template
      interp, F434 array join, F443 Array fill paren, F446 Array.of,
      F444 junk-prefix, F447 truthy filter, F448 identity map);
      F472 repeat-as-tagged CLOSED (wave-354 lane 4); F469-F471 attack-lane filings
      pinned open as documented entries (their red-first batteries live
      in the attack-lane tree).
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      footer open none /
      next F473, F463 CLOSED entry present. (Wave-354: F469-F472 CLOSED.)
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w353_f463close_probes.py
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

TAXONOMY_PIN = 2140  # Wave-353: F463 closed, F472 filed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F606, F607, F608, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-355 lane 2: F474 CLOSED  # Wave-353 lane 2: F463 CLOSED locally (merge finalizes tree-wide); F472 repeat-tagged filed OPEN (renumbered F469->F472); F469-F471 are wave-353 attack-lane filings (commit e79af076)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-354: F470 CLOSED  # Wave-354 lane 3: F471 CLOSED  # Wave-354 lane 4: F472 CLOSED  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint

FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)

# Constructed via concatenation: the write path redacts credential literals.
_CRED = "xox" + "b-abc123" + "def" + "456"
_A = "xox" + "b-abc123"
_B = "def" + "456"
_FRAG = "xoxb-" + "0123"  # F472 closed pin: 'xoxb-0123'.repeat`2` blocks
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

def p1_closure_filed_join_tag():
    return _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT)


def p1_closure_join_tag_ws():
    # Engine-tolerated whitespace between the method name and the template.
    return _blocked("['" + _A + "','" + _B + "'].join " + _BT + _BT)


def p1_closure_join_tag_sep():
    return _blocked("['" + _A + "','" + _B + "'].join" + _BT + "-" + _BT)


def p1_closure_concat_tag():
    return _blocked("'" + _A + "'.concat" + _BT + _B + _BT)


def p1_closure_tag_chain():
    # Tagged concat chained twice assembles the credential.
    return _blocked("''.concat" + _BT + _A + _BT + ".concat" + _BT + _B
                    + _BT)


def p1_closure_postfix_compose():
    # Tagged join result flows into the postfix pipeline.
    return _blocked("['" + _A + "','" + _B + "'].join" + _BT + _BT
                    + ".repeat(1)")


def p1_closure_fill_tag_decode():
    # fill's tag-call site decodes exactly (arrays are never surfaced,
    # so the pin is decoder-level, composed with a join).
    r = dlp._try_js_expr_decode("['u','v'].fill" + _BT + "x" + _BT
                                + ".join('')", 0)
    return r is not None and r[0] == "xx"


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_tag_quiet():
    return not _blocked("['a','b'].join" + _BT + _BT)


def p2_control_interp_tag_quiet():
    # Interpolated tag: engine says "a,b"; the modeled class cannot
    # express it, so the decoder fails closed (no variant).
    return not _blocked("['a','b'].join" + _BT + "${'c'}" + _BT)


def p2_control_unterminated_quiet():
    return not _blocked("['a','b'].join" + _BT)


def p2_control_map_tag_quiet():
    # .map is not a modeled tag-call site.
    return not _blocked("['a','b'].map" + _BT + "x" + _BT)


def p2_control_bare_tag_quiet():
    # Bare tag functions (not methods) are not modeled.
    return not _blocked("String.raw" + _BT + "hello" + _BT)


def p2_control_paren_repeat_blocks():
    # Neighbor contract: the paren form of repeat still blocks.
    return _blocked("'" + _FRAG + "'.repeat(2)")


# ---------------------------------------------------------------- P3: decoder pins

def _decode_cases():
    # (payload, expected decoded value or None for fail-closed,
    #  node ground-truth value or None if the decoder must diverge)
    return [
        ("['x','y'].join" + _BT + _BT, "xy", "xy"),
        ("['x','y'].join" + _BT + "-" + _BT, "x-y", "x-y"),
        ("['x','y'].join " + _BT + _BT, "xy", "xy"),
        ("'a'.concat" + _BT + "b" + _BT, "ab", "ab"),
        ("['x','y'].join" + _BT + "a\\x62c" + _BT, "xabcy", "xabcy"),
        ("['a','b'].join" + _BT + "-" + _BT + ".repeat(2)",
         "a-ba-b", "a-ba-b"),
        ("['u','v'].fill" + _BT + "x" + _BT + ".join('')", "xx", "xx"),
        # Fail-closed shapes: the decoder yields no variant.
        ("['a','b'].join" + _BT + "${'c'}" + _BT, None, "a,b"),
        ("['a','b'].join" + _BT, None, None),  # unterminated: THROWS
        ("['a','b'].map" + _BT + "x" + _BT, None, None),
        ("'x'.repeat" + _BT + "2" + _BT, "xx", "xx"),  # F472: CLOSED wave-354 lane 4
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


def p3_pin_interp_tag_divergence():
    # DOCUMENTED fail-closed direction: the engine evaluates an
    # interpolated tag (strings array has 2+ elements, String() joins
    # with ","), the decoder cannot express it and yields no variant.
    payload = "['a','b'].join" + _BT + "${'c'}" + _BT
    assert dlp._try_js_expr_decode(payload, 0) is None
    assert _node_eval([payload])[0] == json.dumps("a,b")
    return True


def p3_pin_no_new_regexes():
    # Functional pin: the tag-call site needed no anchor change -- it
    # lives inside _js_parse_postfix. The anchor pattern is pinned here
    # as the exact pattern string. Wave-353 lane 4 (F468) legitimately
    # added the Reflect-construct alternative (ws-tolerant, character
    # class only); wave-354 lane 1 (F469) legitimately widened it to
    # (construct|apply) for the Reflect.apply concat shape; wave-354
    # lane 3 (F471) legitimately added the Object.assign alternative
    # (ws-tolerant, character class only -- the same F468 precedent);
    # wave-356 lane 2 (F477) legitimately added the String( constructor
    # alternative; wave-357 lane 1 (F478) legitimately added the
    # X.prototype dispatch-target alternatives (ws-tolerant, character
    # class only -- the same F468 precedent); wave-360 lane 2 (F491/F493)
    # legitimately widened the Reflect alternative to (construct|apply|get),
    # the Object alternative with getOwnPropertyDescriptor, and the String
    # alternative with .raw( / .raw.call( (literal-alternation only).
    # Wave-361 lane 1 (F496): Reflect alternative widened \. -> (\?\.|\.)
    # for optional-chaining dispatch (literal alternation only -- the same
    # F468 precedent); re.compile count unchanged.
    # class only -- the same F468 precedent); the F463 closure itself
    # added no regex.
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
        "String.raw" + _BT + "C:\\path\\to" + _BT,
        "tag" + _BT + "hello" + _BT,
        "sql" + _BT + "SELECT 1" + _BT,
        "greet" + _BT + "hi ${name}" + _BT,
    ]
    return all(not _blocked(c) for c in cases)


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile_inputs():
    hostile = [
        _BT + "${'a'" * 2000,
        "['a'].join" + _BT + "a" * 9000,
        "['a','b'].join" + _BT + "${" * 500 + _BT,
        _BT + "\\x" * 5000,
        "x" + _BT * 2000 + "y",
        "['a'].join" + _BT + "a\\" * 5000 + _BT,
        "['a','b'].concat" + _BT + "${'a'}" * 200 + _BT,
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

def p6_noreg_f457_template_interp():
    return _blocked("`" + _A + "${'" + _B + "'}`")


def p6_noreg_f434_array_join():
    return _blocked("['" + _A + "','" + _B + "'].join('')")


def p6_noreg_f443_array_fill():
    return _blocked("Array(2).fill('" + _A + "').join('')")


def p6_noreg_f446_array_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f444_junk_prefix():
    payload = "'j0'+'j1';'j2'+'j3';" + "['" + _A + "','" + _B + \
        "'].reduce((a,b)=>a+b)"
    return _blocked(payload)


def p6_noreg_f447_truthy_filter():
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x).join('')")


def p6_noreg_f448_identity_map():
    return _blocked("['" + _A + "','" + _B + "'].map(x=>x).join('')")


def p6_noreg_f472_repeat_tag_closed():
    # F472 CLOSED 2026-10-06 wave-354 lane 4: repeat's ToNumber count
    # conversion is now modeled by _js_tag_repeat_count; the tagged
    # repeat shape blocks.
    return _blocked("'" + _FRAG + "'.repeat" + _BT + "2" + _BT)


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
    ok = ok and "CLOSED 2026-10-06 wave-353 lane 2" in footer
    return ok


_PROBES = [
    ("p1-closure-filed-join-tag", p1_closure_filed_join_tag),
    ("p1-closure-join-tag-ws", p1_closure_join_tag_ws),
    ("p1-closure-join-tag-sep", p1_closure_join_tag_sep),
    ("p1-closure-concat-tag", p1_closure_concat_tag),
    ("p1-closure-tag-chain", p1_closure_tag_chain),
    ("p1-closure-postfix-compose", p1_closure_postfix_compose),
    ("p1-closure-fill-tag-decode", p1_closure_fill_tag_decode),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-tag-quiet", p2_control_junk_tag_quiet),
    ("p2-control-interp-tag-quiet", p2_control_interp_tag_quiet),
    ("p2-control-unterminated-quiet", p2_control_unterminated_quiet),
    ("p2-control-map-tag-quiet", p2_control_map_tag_quiet),
    ("p2-control-bare-tag-quiet", p2_control_bare_tag_quiet),
    ("p2-control-paren-repeat-blocks", p2_control_paren_repeat_blocks),
    ("p3-pin-node-byte-fidelity", p3_pin_node_byte_fidelity),
    ("p3-pin-interp-tag-divergence", p3_pin_interp_tag_divergence),
    ("p3-pin-no-new-regexes", p3_pin_no_new_regexes),
    ("p3-pin-f441-ordering-untouched", p3_pin_f441_ordering_untouched),
    ("p4-discr-fp-corpus-identical", p4_discr_fp_corpus_identical),
    ("p4-discr-innocent-tags-quiet", p4_discr_innocent_tags_quiet),
    ("p5-redos-hostile-inputs", p5_redos_hostile_inputs),
    ("p6-noreg-f457-template-interp", p6_noreg_f457_template_interp),
    ("p6-noreg-f434-array-join", p6_noreg_f434_array_join),
    ("p6-noreg-f443-array-fill", p6_noreg_f443_array_fill),
    ("p6-noreg-f446-array-of", p6_noreg_f446_array_of),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f447-truthy-filter", p6_noreg_f447_truthy_filter),
    ("p6-noreg-f448-identity-map", p6_noreg_f448_identity_map),
    ("p6-noreg-f472-repeat-tag-closed", p6_noreg_f472_repeat_tag_closed),
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
    scripts = ("w352_attack_probes.py",
               "w352_f457close_probes.py",
               "w351_attack_probes.py",
               "w351_f451close_probes.py",
               "w351_f452close_probes.py",
               "w351_f453close_probes.py",
               "w350_attack_probes.py",
               "w350_f446close_probes.py",
               "w350_f447f448close_probes.py",
               "w350_f449f450close_probes.py",
               "w346_dlp_composition_probes.py")
    # Attack batteries pin the footer with inline literals (repointed by the
    # merge coordinator's tree-wide footer sweep); only their stale
    # test_b0_footer_state may break here.
    stale_footer_ok = {"w351_attack_probes.py": {"test_b0_footer_state"},
                       "w350_attack_probes.py": {"test_b0_footer_state"}}
    for script in scripts:
        tmp = "/var/tmp/g353-green-%s-%d" % (script.replace(".py", ""),
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
    print("w353_f463close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
