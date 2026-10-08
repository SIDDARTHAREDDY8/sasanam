#!/usr/bin/env python3
"""Closure probes for F454 + F455 (wave-352 lane 1).

F454 (LOW): the multi-argument Array constructor bypassed the bounded
static JS-expression decoder -- `_js_parse_array_constructor` modeled
only the single-integer `Array(N)` form (F443) and `Array.of(...)`
(F446); `Array('frag','frag')` / `new Array('frag','frag')` failed
closed ("bad Array args") while node evaluates both to the fragment
list (node-verified). The F446 close-when promised "Array.of (and the
other Array factory forms the decoder claims no model of) decode within
the same budgets". Now modeled: `_js_parse_array_constructor` parses
all-string-literal argument lists (the single string arg is the
1-element list, exactly as the engine evaluates) and composes through
the existing _JSArr pipeline (.join/.fill/.filter(Boolean)/.map/.reduce)
within the part and output budgets. Numeric, mixed, nested, and
additive args fail closed (documented scope boundary: rejected, never
mis-decoded). Node-differential: byte-identical to node v24.20.0 on all
claimed shapes and fail-closed neighbors.

F455 (LOW): whitespace before the dot in `Array .of(...)` evaded the
JS-expression anchor while the parser claimed to tolerate it --
`_js_parse_array_of` skips whitespace after "Array" and its docstring
says "whitespace is tolerated around the dot, the name, and the
parens, exactly as the engine allows", but `_JS_EXPR_START` anchored
the factory as `Array(\\(|\\.of)`. The anchor is now
`Array(\\(|[ \\t\\n\\r]*\\.[ \\t\\n\\r]*of)` -- the same [ \\t\\n\\r]
class the parser skips -- so `Array .of(...)` / tab / newline / CR /
`Array. of(...)` shapes reach the parser and block coded. This
supersedes the F446 honest-residual table entry for `Array .of`
(updated in evals/w350_f446close_probes.py). Notes: `new Array .of`
blocks via the scan though node throws TypeError -- conservative,
consistent with the pre-existing contiguous `new Array.of` scan
behavior (documented, not changed); the `Array (` anchor gap remains
a documented residual (pinned quiet).

Neighbor dispositions (node-verified, documented here and in the
FINDINGS.md closure notes):
- `Array('a','b')` / `new Array('a','b')` / `Array('a')` -- modeled
  (fragment list / 1-element list).
- `Array('a',2)` / `Array(2,'a')` / `Array('a'+'b')` -- fail closed
  (non-string args: documented scope boundary).
- `Array('a',)` (trailing comma) -- fail closed, consistent with the
  F434 array-literal and F446 Array.of parsers (node accepts it per
  ES2017; the decoder's convention is uniform fail-closed).
- `Array('a','b').concat('c')` -- fail closed on the _JSArr, exactly
  like `['a','b'].concat('c')` (F434) and `Array.of('a','b').concat`
  (F446): pre-existing consistent boundary, not a regression.
- `['a',Array('b','c')]` -- fail closed (in-array nesting).
- `Array .of` / `Array\\t.of` / `Array\\n.of` / `Array\\r.of` /
  `Array. of` / `Array . of` -- modeled (F455).
- `Array .off` / `Array .ofx` / `Array . ofx` -- fail closed
  (ident-boundary check; node throws TypeError).
- `new Array .of` -- conservative scan block (node throws TypeError;
  same as the pre-existing contiguous `new Array.of` behavior).
- `Array (2)` -- HONEST RESIDUAL: not scan-anchored (the F443 gap);
  stays quiet, pinned.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: F454 multi-arg/new/single/ws-mixed/fill/filter/map/reduce
      shapes block coded dlp-slack-token; F455 ws-dot variants block.
  P2  controls: plain credential blocks; junk multi-arg quiet; F443
      Array(N) / new Array(N) hole forms intact; F446 Array.of intact.
  P3  decoder pins: exact decode values; fail-closed neighbors yield
      no variant (numeric/mixed/additive/trailing-comma/nested args,
      bare multi-arg, part budget, empty-decode gate); ws-dot
      ident-boundary pins.
  P4  discrimination: prose mentions quiet; Arrayfoo quiet; `Array (`
      residual gap stays quiet.
  P5  ReDoS: hostile near-miss multi-arg / ws-anchor inputs complete
      fast with no exceptions.
  P6  no-regression: adjacent closures still block (F437 reduce,
      F438 entity+NUL, F439 triple-b64, F440 double-entity, F441
      bslash, F443 fill/filter, F444 junk-prefix, F445 short b64,
      F446 of, F451 hex-ws, F452 junk-budget, F453 ws-b64-outer).
  P7  pin + footer: taxonomy pin 2143 (no new decision codes),  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
      footer open F456-F460 / next F461, F454+F455 CLOSED entries
      present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w352_f454f455close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2143  # Wave-352: F454+F455 closed, no new decision codes; pin unchanged 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 lane 1: F454+F455 CLOSED locally (merge finalizes tree-wide); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 1: F461+F462 CLOSED (merge finalizes tree-wide)  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)
FOOTER_NEXT = "F713"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)



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

def p1_closure_multi_join():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p1_closure_new_multi():
    return _blocked("new Array('" + _A + "','" + _B + "').join('')")


def p1_closure_single():
    # Single string arg is the 1-element list in node.
    return _blocked("Array('" + _CRED + "').join('')")


def p1_closure_3frag():
    return _blocked("Array('" + _A + "','x','" + _B + "').join('')")


def p1_closure_ws_mixed():
    return _blocked("Array( '" + _A + "' , '" + _B + "' ).join('')")


def p1_closure_fill():
    return _blocked("Array('" + _A + "','" + _B + "').fill('" + _A
                    + "').join('').concat('" + _B + "')")


def p1_closure_filter():
    return _blocked("Array('" + _A + "','','" + _B + "').filter(Boolean)"
                    ".join('')")


def p1_closure_map():
    return _blocked("Array('" + _A + "','" + _B + "').map(s=>s).join('')")


def p1_closure_reduce():
    return _blocked("Array('" + _A + "','" + _B + "').reduce((a,b)=>a+b)")


def p1_closure_ws_dot_space():
    return _blocked("Array .of('" + _A + "','" + _B + "').join('')")


def p1_closure_ws_dot_tab():
    return _blocked("Array\t.of('" + _A + "','" + _B + "').join('')")


def p1_closure_ws_dot_nl():
    return _blocked("Array\n.of('" + _A + "','" + _B + "').join('')")


def p1_closure_ws_dot_cr():
    return _blocked("Array\r.of('" + _A + "','" + _B + "').join('')")


def p1_closure_dot_ws_of():
    return _blocked("Array. of('" + _A + "','" + _B + "').join('-')")


def p1_closure_ws_both_sides():
    return _blocked("Array . of('" + _A + "','" + _B + "').join('')")


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_quiet():
    return (not _blocked("Array('ab','cd').join('')")
            and not _blocked("new Array('ab','cd').join('')")
            and not _blocked("Array .of('ab','cd').join('')"))


def p2_control_f443_intact():
    # The F443 hole form still decodes through .fill.
    return _blocked("Array(2).fill('" + _A + "').join('').concat('" + _B
                    + "')")


def p2_control_new_array_n():
    return _blocked("new Array(2).fill('" + _A + "').join('')")


def p2_control_f446_intact():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_decode_value():
    r = dlp._try_js_expr_decode("Array('aa','bb').join('')", 0)
    return r is not None and r[0] == "aabb"


def p3_pin_new_multi_value():
    r = dlp._try_js_expr_decode_all("new Array('aa','bb').join('')")
    return r == "new aabb"


def p3_pin_single_is_one():
    # node: Array('aa') is ['aa'], not the hole form.
    r = dlp._try_js_expr_decode("Array('aa').join('')", 0)
    return r is not None and r[0] == "aa"


def p3_pin_numeric_arg_fails():
    return dlp._try_js_expr_decode("Array('a',2).join('')", 0) is None


def p3_pin_mixed_order_fails():
    return dlp._try_js_expr_decode("Array(2,'a').join('')", 0) is None


def p3_pin_additive_arg_fails():
    # Direct constructor decode fails closed on additive args (the
    # whole-text scan may still decode the inner additive -- that
    # variant contains the plaintext, so the verbatim rule catches
    # credential payloads; same convention as F446's Array.of).
    return dlp._try_js_expr_decode("Array('a'+'b').join('')", 0) is None


def p3_pin_trailing_comma_fails():
    # node accepts trailing commas (ES2017); the decoder fails closed,
    # consistent with the F434 array-literal and F446 Array.of parsers.
    return dlp._try_js_expr_decode("Array('a',).join('')", 0) is None


def p3_pin_nested_fails():
    return (dlp._try_js_expr_decode("['a',Array('b','c')].join('')", 0)
            is None)


def p3_pin_bare_no_variant():
    # A bare multi-arg Array with no postfix call is not
    # obfuscation-shaped (F434 convention).
    return dlp._try_js_expr_decode("Array('aa','bb')", 0) is None


def p3_pin_empty_gate():
    return dlp._try_js_expr_decode("Array().join('')", 0) is None


def p3_pin_part_budget():
    big = "Array(" + ",".join(["'x'"] * 66) + ").join('')"
    ok64 = "Array(" + ",".join(["'x'"] * 64) + ").join('')"
    r_big = dlp._try_js_expr_decode(big, 0)
    r_ok = dlp._try_js_expr_decode(ok64, 0)
    return r_big is None and r_ok is not None and r_ok[0] == "x" * 64


def p3_pin_ws_dot_value():
    r = dlp._try_js_expr_decode_all("Array .of('aa','bb').join('')")
    return r == "aabb"


def p3_pin_ws_dot_tab_value():
    r = dlp._try_js_expr_decode_all("Array\t.of('aa','bb').join('-')")
    return r == "aa-bb"


def p3_pin_ws_dot_ident_boundary():
    off = dlp._try_js_expr_decode_all("Array .off('aa','bb').join('')")
    ofx = dlp._try_js_expr_decode_all("Array .ofx('aa','bb').join('')")
    # node throws TypeError on both; the decoder emits no variant.
    return off is None and ofx is None


def p3_pin_array_space_gap_quiet():
    # HONEST RESIDUAL: `Array (` is not scan-anchored (the F443 gap);
    # stays quiet.
    return not _blocked("Array (2).fill('aa').join('')")


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_prose_quiet():
    return not _blocked("Use Array('a','b') to build arrays in JS.")


def p4_discr_arrayfoo_quiet():
    return not _blocked("Arrayfoo('aa','bb').join('')")


def p4_discr_junk_ws_dot_quiet():
    return not _blocked("Array .of('xx','yy').join('-')")


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile():
    hostiles = [
        "Array(" + "'" * 5000,
        "Array('a'," * 2000,
        "Array(" + "'aa','bb'" * 1500,
        "Array" + " " * 3000 + ".of(",
        "Array ." + "of" * 2000 + "(",
        "Array" + "\t\n\r" * 1000 + ".of('a','b').join('')",
        "new Array(" + "'a'," * 3000,
    ]
    t0 = time.time()
    for h in hostiles:
        dlp._try_js_expr_decode_all(h)
    dt = time.time() - t0
    assert dt < 5.0, "too slow: %.2fs" % dt
    return True


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

def p6_noreg_f437_reduce():
    return _blocked("['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)")


def p6_noreg_f438_entity_nul():
    payload = "".join("&#x%02x;\x00" % b for b in _CRED.encode())
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f439_triple_b64():
    b3 = base64.b64encode(base64.b64encode(
        base64.b64encode(_CRED.encode()))).decode()
    assert _CRED not in b3
    return _blocked(b3)


def p6_noreg_f440_double_entity():
    payload = "".join("&amp;#x%x;" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f441_bslash():
    payload = "".join("\\\\u%04x" % ord(c) for c in _CRED)
    assert _CRED not in payload
    return _blocked(payload)


def p6_noreg_f443_fill():
    return _blocked("Array(2).fill('" + _A + "').join('').concat('" + _B
                    + "')")


def p6_noreg_f444_junk_prefix():
    junk = "'j0'+'k0';'j1'+'k1';'j2'+'k2';"
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    return _blocked(junk + real)


def p6_noreg_f445_short_b64():
    run = base64.b64encode(_CRED.encode()).decode()
    assert _CRED not in run
    return _blocked(run)


def p6_noreg_f446_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f451_hex_ws():
    hx = _CRED.encode().hex()
    return _blocked(hx[:20] + " " + hx[20:])


def p6_noreg_f452_junk_budget():
    junk = "".join("'%s';" % ("j%d" % i) for i in range(32))
    real = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"
    return _blocked(junk + real)


def p6_noreg_f453_wsb64_outer():
    inner = base64.b64encode(_CRED.encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    return _blocked(outer[:10] + " " + outer[10:])


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2143  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-352 lane 1" in footer
    return ok


_PROBES = [
    ("p1-closure-multi-join", p1_closure_multi_join),
    ("p1-closure-new-multi", p1_closure_new_multi),
    ("p1-closure-single", p1_closure_single),
    ("p1-closure-3frag", p1_closure_3frag),
    ("p1-closure-ws-mixed", p1_closure_ws_mixed),
    ("p1-closure-fill", p1_closure_fill),
    ("p1-closure-filter", p1_closure_filter),
    ("p1-closure-map", p1_closure_map),
    ("p1-closure-reduce", p1_closure_reduce),
    ("p1-closure-ws-dot-space", p1_closure_ws_dot_space),
    ("p1-closure-ws-dot-tab", p1_closure_ws_dot_tab),
    ("p1-closure-ws-dot-nl", p1_closure_ws_dot_nl),
    ("p1-closure-ws-dot-cr", p1_closure_ws_dot_cr),
    ("p1-closure-dot-ws-of", p1_closure_dot_ws_of),
    ("p1-closure-ws-both-sides", p1_closure_ws_both_sides),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p2-control-f443-intact", p2_control_f443_intact),
    ("p2-control-new-array-n", p2_control_new_array_n),
    ("p2-control-f446-intact", p2_control_f446_intact),
    ("p3-pin-decode-value", p3_pin_decode_value),
    ("p3-pin-new-multi-value", p3_pin_new_multi_value),
    ("p3-pin-single-is-one", p3_pin_single_is_one),
    ("p3-pin-numeric-arg-fails", p3_pin_numeric_arg_fails),
    ("p3-pin-mixed-order-fails", p3_pin_mixed_order_fails),
    ("p3-pin-additive-arg-fails", p3_pin_additive_arg_fails),
    ("p3-pin-trailing-comma-fails", p3_pin_trailing_comma_fails),
    ("p3-pin-nested-fails", p3_pin_nested_fails),
    ("p3-pin-bare-no-variant", p3_pin_bare_no_variant),
    ("p3-pin-empty-gate", p3_pin_empty_gate),
    ("p3-pin-part-budget", p3_pin_part_budget),
    ("p3-pin-ws-dot-value", p3_pin_ws_dot_value),
    ("p3-pin-ws-dot-tab-value", p3_pin_ws_dot_tab_value),
    ("p3-pin-ws-dot-ident-boundary", p3_pin_ws_dot_ident_boundary),
    ("p3-pin-array-space-gap-quiet", p3_pin_array_space_gap_quiet),
    ("p4-discr-prose-quiet", p4_discr_prose_quiet),
    ("p4-discr-arrayfoo-quiet", p4_discr_arrayfoo_quiet),
    ("p4-discr-junk-ws-dot-quiet", p4_discr_junk_ws_dot_quiet),
    ("p5-redos-hostile", p5_redos_hostile),
    ("p5-redos-f171-module", p5_redos_f171_module),
    ("p6-noreg-f437-reduce", p6_noreg_f437_reduce),
    ("p6-noreg-f438-entity-nul", p6_noreg_f438_entity_nul),
    ("p6-noreg-f439-triple-b64", p6_noreg_f439_triple_b64),
    ("p6-noreg-f440-double-entity", p6_noreg_f440_double_entity),
    ("p6-noreg-f441-bslash", p6_noreg_f441_bslash),
    ("p6-noreg-f443-fill", p6_noreg_f443_fill),
    ("p6-noreg-f444-junk-prefix", p6_noreg_f444_junk_prefix),
    ("p6-noreg-f445-short-b64", p6_noreg_f445_short_b64),
    ("p6-noreg-f446-of", p6_noreg_f446_of),
    ("p6-noreg-f451-hex-ws", p6_noreg_f451_hex_ws),
    ("p6-noreg-f452-junk-budget", p6_noreg_f452_junk_budget),
    ("p6-noreg-f453-wsb64-outer", p6_noreg_f453_wsb64_outer),
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
    scripts = ("w346_dlp_composition_probes.py",
               "w347_attack_probes.py",
               "w348_attack_probes.py",
               "w349_attack_probes.py",
               "w350_attack_probes.py",
               "w351_attack_probes.py",
               "w347_f437close_probes.py",
               "w347_f438close_probes.py",
               "w347_f439close_probes.py",
               "w347_f440close_probes.py",
               "w347_f441close_probes.py",
               "w347_f442close_probes.py",
               "w348_f443close_probes.py",
               "w349_f444close_probes.py",
               "w349_f445close_probes.py",
               "w350_f446close_probes.py",
               "w350_f447f448close_probes.py",
               "w350_f449f450close_probes.py",
               "w351_f451close_probes.py",
               "w351_f452close_probes.py",
               "w351_f453close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g352-green-%s-%d" % (script.replace(".py", ""),
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
    print("w352_f454f455close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
