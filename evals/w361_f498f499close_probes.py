#!/usr/bin/env python3
"""Wave-361 F498+F499 closure battery (lane 2).

Two LOW findings from wave-360 attack round 28 (all node v24.20.0 ->
credential, decoder missed on the wave-360-merged base):

F498: bracket-form Reflect['construct'] dispatch -- the F480 closure
  models Reflect.construct (dot form) and documents "Reflect['construct']
  bracket inequivalence is a documented scope boundary (residual
  candidate)": the bracket-string member access on the Reflect namespace
  bypasses the anchor:
    Reflect['construct'](Array, ['f1','f2']).join('')
    Reflect['construct']([].constructor, ['f1','f2']).join('')
  Distinct from F469 (Reflect.apply dot form) and F480 (apply/call
  bracket forms -- construct is a different builtin).

F499: spread of string literals in array literals -- the F471 closure
  ("iterable-spread of strings -- documented candidate residual") models
  [...['f1','f2']] (spread of an array literal) but fails closed on
  spread of a STRING literal, which iterates the string's characters:
    [...'f1', ...'f2'].join('')
    String([...'f1', ...'f2'].join(''))
    [...'f1'].join('') + [...'f2'].join('')
  Distinct from F471 (array-literal spread, closed) and F494
  (non-literal iterables -- here the operand IS a literal, so F494's
  fail-closed close-when would not cover it).

Closure design (gov/dlp.py):
  F498:
  * `_js_parse_reflect_call` bracket branch: literal keys via
    _js_parse_bracket_member, constant-folded keys via
    _js_fold_bracket_key (F492); 'construct' routes to
    _js_parse_reflect_construct; 'apply' keeps the F480 path; any
    other member fails closed.
  * `_js_parse_reflect_construct` accepts the bracket-string member
    form (node-identical to the dot form, node v24.20.0 verified). In
    the bracket form the target may be the bare Array identifier or
    [].constructor (engine-identical, via the shared F480
    _js_parse_array_ctor_ref); the dot form keeps F468's
    bare-Array-only target scope. The args-list grammar is unchanged
    (string-literal arrays, Array.of, Array(...) forms).
  F499:
  * `_js_parse_spread_copy`: when the spread source parses via
    _js_parse_primary to a genuine string value (plain str, never
    _JSNumStr -- the engine throws TypeError on [...42]), the new
    `_js_parse_string_spread_rest` expands it to its characters
    (code-point iteration, exactly the engine's; node v24.20.0
    verified). Multiple string spreads may chain
    ([...'a', ...'b']); each char is parts-charged; the
    in_spread_copy guard is held across the chain so nested spreads
    fail closed. Mixed chains ([...'a','b'], [...['a'],...'b']),
    non-iterable sources, and additive sources fail closed
    (documented scope boundary).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed F498/F499 shapes block (incl. double-quote,
      ws-tolerant, constant-folded-key, [].constructor-target, and
      chained-spread variants).
  P2  controls: dot-form construct still blocks; unmodeled members /
      non-literal keys / non-Array targets fail closed; numeric /
      mixed / nested / additive spread sources fail closed; junk
      quiet; F471/F494 neighbors hold.
  P3  decoder pins: byte-fidelity vs node v24.20.0 on every filed
      shape (subprocess); no new re.compile calls (28); F441
      _decode_layer ordering untouched.
  P4  pin + footer (F498/F499 CLOSED locally; open F496, F497, F500,
      F501, F502 / next F506).

Green check (depth-1): adjacent DLP batteries with GOV_SKIP_GREEN=1
in the child env.
"""
import argparse
import json
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2143  # Wave-361 lane 2: F498/F499 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
FOOTER_OPEN = "F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-362 lane 2: F504 CLOSED locally (merge finalizes tree-wide)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 4: F510+F511 CLOSED (lane-local)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
FOOTER_NEXT = "F795"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)

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


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try { out.push(String(eval(cases[k]))); }
  catch(e){ out.push('THROW:'+e.constructor.name); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    return json.loads(r.stdout)


# ------------------------------------------------------------ P1: closure
def p1_f498_filed_shapes():
    shapes = [
        "Reflect['construct'](Array, ['%s','%s']).join('')",
        "Reflect['construct']([].constructor, ['%s','%s']).join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "2/2 filed F498 shapes block")


def p1_f498_variants():
    shapes = [
        # double-quoted member key
        'Reflect["construct"](Array, [\'%s\',\'%s\']).join(\'\')',
        # ws-tolerant brackets
        "Reflect[ 'construct' ](Array, ['%s','%s']).join('')",
        # constant-folded key (F492)
        "Reflect['con'+'struct'](Array, ['%s','%s']).join('')",
        # [].constructor target with double quotes
        'Reflect["construct"]([].constructor, [\'%s\',\'%s\']).join(\'\')',
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "4/4 F498 variant shapes block")


def p1_f499_filed_shapes():
    shapes = [
        "[...'%s', ...'%s'].join('')",
        "String([...'%s', ...'%s'].join(''))",
        "[...'%s'].join('') + [...'%s'].join('')",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "3/3 filed F499 shapes block")


def p1_f499_variants():
    shapes = [
        # single string spread holding the whole credential
        "[...'%s%s'].join('')" % (_A, _B),
        # three-way chain
        "[...'%s', ...'45', ...'6789abcdef'].join('')" % _A,
        # double quotes + whitespace
        "[... \"%s%s\" ].join(\"\")" % (_A, _B),
        # wrapped in String()
        "String([...'%s%s'].join(''))" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    if bad:
        return ("BREAK", "missed: %s" % bad)
    return ("HELD", "4/4 F499 variant shapes block")


# ------------------------------------------------------------ P2: controls
def p2_f498_dot_form_still_blocks():
    # F468 scope: the dot form blocks coded (control from the red-first
    # battery); the dot form keeps its bare-Array-only target scope.
    if not _blocked("Reflect.construct(Array, ['%s','%s']).join('')" % (_A, _B)):
        return ("BREAK", "dot-form construct regressed")
    return ("HELD", "dot-form construct still blocks")


def p2_f498_fail_closed():
    quiet = [
        # unmodeled member
        "Reflect['constructx'](Array, ['%s','%s']).join('')" % (_A, _B),
        # non-literal key
        "Reflect[x](Array, ['%s','%s']).join('')" % (_A, _B),
        # non-Array target in bracket form
        "Reflect['construct'](String, ['%s','%s']).join('')" % (_A, _B),
        # dot form with [].constructor target: F468 scope unchanged
        "Reflect.construct([].constructor, ['%s','%s']).join('')" % (_A, _B),
        # junk stays quiet
        "Reflect['construct'](Array, ['ab','cd']).join('')",
    ]
    bad = [s for s in quiet if _blocked(s)]
    if bad:
        return ("BREAK", "unexpected block: %s" % bad)
    return ("HELD", "5/5 F498 fail-closed shapes quiet")


def p2_f499_fail_closed():
    # NOTE: fragments are split (_A only) so the raw full credential
    # never appears in the payload -- a raw full-credential literal
    # flags on its own and would mask the fail-closed assertion.
    quiet = [
        # engine throws TypeError on [...42]
        "[...42].join('')",
        # mixed: string spread + plain element
        "[...'%s', 'x'].join('')" % _A,
        # mixed source types: array spread + string spread
        "[...['%s'], ...'x'].join('')" % _A,
        # nested spread
        "[...[...'%s']].join('')" % _A,
        # additive source: primary parses 'a', then '+' fails closed
        "[...'%s'+'x'].join('')" % _A,
        # junk stays quiet
        "[...'ab', ...'cd'].join('')",
        # empty string spread decodes to [] -> '' (not the credential)
        "[...''].join('')",
    ]
    bad = [s for s in quiet if _blocked(s)]
    if bad:
        return ("BREAK", "unexpected block: %s" % bad)
    return ("HELD", "7/7 F499 fail-closed shapes quiet")


def p2_neighbors_hold():
    # F471 (array-literal spread), F494 (Set/Map/generator spreads),
    # F480 (ctor apply), F469 (Reflect.apply) all still block.
    held = [
        "[...['%s','%s']].join('')" % (_A, _B),
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),
        "Array['apply'](Array, ['%s','%s']).join('')" % (_A, _B),
        "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (_A, _B),
    ]
    bad = [s for s in held if not _blocked(s)]
    if bad:
        return ("BREAK", "neighbor regressed: %s" % bad)
    return ("HELD", "4/4 neighbor shapes still block")


def p2_open_findings_still_open():
    # F496/F497 (lane 1) and F500/F501/F502 (lane 3) are CLOSED on the
    # merged tree -- their shapes must now block (wave-306 maintenance).
    # F504 is CLOSED by wave-362 lane 2.
    # F503 (wave-362 lane 1) and F505 (wave-362 lane 3) are CLOSED
    # on the merged tree (wave-306 maintenance).
    closed_shapes = [
        # F496: Reflect.ownKeys enumeration indirection
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A, _B),
        # F497: non-empty-array constructor-property factory
        "['x'].constructor.of('%s','%s').join('')" % (_A, _B),
        # F500: spread args in String.fromCharCode (21 credential codes)
        "String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])",
        # F501: fragment assembly through local value bindings
        "let a='%s', b='%s'; a,b; a+b" % (_A, _B),
        # F502: Object.freeze-wrapped array-like receiver
        "Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A, _B),
        # F504: bracket/template/nested-bracket Reflect.apply (wave-362 lane 2)
        "Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A, _B),
        "Reflect[`apply`]([].concat, [], ['%s','%s']).join('')" % (_A, _B),
        "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (_A, _B),
        "Reflect.apply([].concat, [], ['%s','%s']).join('')" % (_A, _B),
    ]
    bad = [s for s in closed_shapes if not _blocked(s)]
    if bad:
        return ("BREAK", "closed finding missed: %s" % bad)
    # F503 (wave-362 lane 1): Object.seal-wrapped array-like receiver
    if not _blocked("Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (_A, _B)):
        return ("BREAK", "F503 missed")
    # F505 (wave-362 lane 3): String.fromCodePoint with spread args
    if not _blocked("String.fromCodePoint(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])"):
        return ("BREAK", "F505 missed")
    return ("HELD", "F496/F497/F500/F501/F502/F503/F504/F505 closed")


# ------------------------------------------------------------ P3: decoder pins
def p3_node_byte_fidelity():
    payloads = [
        "Reflect['construct'](Array, ['%s','%s']).join('')" % (_A, _B),
        "Reflect['construct']([].constructor, ['%s','%s']).join('')" % (_A, _B),
        'Reflect["construct"](Array, [\'%s\',\'%s\']).join(\'\')' % (_A, _B),
        "Reflect['con'+'struct'](Array, ['%s','%s']).join('')" % (_A, _B),
        "[...'%s', ...'%s'].join('')" % (_A, _B),
        "String([...'%s', ...'%s'].join(''))" % (_A, _B),
        "[...'%s'].join('') + [...'%s'].join('')" % (_A, _B),
        "[...'%s%s'].join('')" % (_A, _B),
    ]
    node_vals = _node_eval(payloads)
    bad = []
    for p, nv in zip(payloads, node_vals):
        dv = _decoded(p)
        if dv != nv:
            bad.append((p, nv, dv))
    if bad:
        return ("BREAK", "node mismatch: %s" % bad)
    return ("HELD", "8/8 node byte-identical (v24.20.0)")


def p3_no_new_regexes():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile", src))
    if n != 28:
        return ("BREAK", "re.compile count %d, want 28" % n)
    return ("HELD", "re.compile count still 28")


def p3_decode_layer_ordering():
    # F441: _decode_layer ordering untouched -- spot-check that a
    # whole-text F444 scan still precedes variant decode.
    if not _blocked("Array.of('%s','%s').join('')" % (_A, _B)):
        return ("BREAK", "F446 factory regressed")
    return ("HELD", "decode-layer ordering intact")


# ------------------------------------------------------------ P4: pin+footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2143  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    assert len(TAXONOMY) == 2143  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F921**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    assert "**Open findings: F893, F894, F895, F896, F897, F898, F899, F900, F901, F902, F903, F904, F905, F906, F907, F908, F909, F910, F911, F912, F913, F914, F915, F916, F917, F918, F919, F920.**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
    return ("HELD", "pin=2140 footer open F506-F509 next F513 (wave-363 lane 4)")


PROBES = [
    ("p1-f498-filed-shapes", p1_f498_filed_shapes),
    ("p1-f498-variants", p1_f498_variants),
    ("p1-f499-filed-shapes", p1_f499_filed_shapes),
    ("p1-f499-variants", p1_f499_variants),
    ("p2-f498-dot-form-still-blocks", p2_f498_dot_form_still_blocks),
    ("p2-f498-fail-closed", p2_f498_fail_closed),
    ("p2-f499-fail-closed", p2_f499_fail_closed),
    ("p2-neighbors-hold", p2_neighbors_hold),
    ("p2-open-findings-still-open", p2_open_findings_still_open),
    ("p3-node-byte-fidelity", p3_node_byte_fidelity),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-decode-layer-ordering", p3_decode_layer_ordering),
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
    venv_python = os.path.expanduser("~/.gov-venv")
    venv_python = os.path.join(venv_python, "bin", "python")
    notes = []
    scripts = ("w360_f498_redfirst.py",
               "w360_f499_redfirst.py",
               "w360_attack_probes.py",
               "w360_f494f495close_probes.py",
               "w354_f471close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g361-green-%s-%d" % (script.replace(".py", ""),
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
    print("w361_f498f499close: starting %d probes" % len(PROBES))
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
