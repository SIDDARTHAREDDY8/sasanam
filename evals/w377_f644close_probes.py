#!/usr/bin/env python3
"""Wave-377 lane 1: close F644 -- object/array-pattern destructuring of literal sources.

F644 (LOW, filed attack round 44): F524/F545 model destructuring of
`arguments` sources, but destructuring a LITERAL source had no modeled
path: (function(){var {a,b}={a:'f1',b:'f2'};return a+b;})(), the rename
twin, and the array twin all node-evaluated to the exact credential
(v24.20.0) while the decoder produced zero variants.

Closure (gov/dlp.py, F644): _js_parse_f644_destructure_literal_iife
parses (function(){DECL PAT=LITSRC;return BODY})() with an empty-param
anonymous head, empty call args, one var|const|let destructuring decl
(1-2 element plain-identifier patterns, ident keys only on object
patterns), and a single return. Sources: string-literal object
literals (F510 grammar) for object patterns, string-literal arrays
for array patterns. Desugar binds the names to the literal values via
_js_bind_destructure_arguments and parses the rewritten body with the
additive grammar at depth+1 (node-exact, v24.20.0 verified). Hooked
after F516 in the paren dispatch; disjoint (F516 requires an
arguments-class source, rejected here at the source check).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B
_CRED = _F1 + _F2 + _F3


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F644 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f644_destructure_literal_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_shorthand():
    """Filed shape 1: var {a,b}={a:'f1',b:'f2'}; return a+b."""
    p = ("(function(){var {a,b}={a:'" + _F1 + "',b:'" + _F2 + _F3
         + "'};return a+b;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_rename():
    """Filed shape 2: var {a:x,b:y}={a:'f1',b:'f2'}; return x+y."""
    p = ("(function(){var {a:x,b:y}={a:'" + _F1 + "',b:'" + _F2 + _F3
         + "'};return x+y;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p1_filed_array():
    """Filed shape 3: var [a,b]=['f1','f2']; return a+b."""
    p = ("(function(){var [a,b]=['" + _F1 + "','" + _F2 + _F3
         + "'];return a+b;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_const_let_decl():
    """const/let destructuring decls block (node-exact)."""
    ok = _blocked("(function(){const {a,b}={a:'" + _F1 + "',b:'" + _F2
                  + _F3 + "'};return a+b;})()")
    ok = ok and _blocked("(function(){let [a,b]=['" + _F1 + "','" + _F2
                         + _F3 + "'];return a+b;})()")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_single_element():
    """Single-element patterns block."""
    ok = _decode_exact("(function(){var {a}={a:'" + _A + _B
                       + "'};return a;})()") == _A + _B
    ok = ok and _decode_exact("(function(){var [a]=['" + _A + _B
                              + "'];return a;})()") == _A + _B
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_source_key_order():
    """Source key order does not matter (binding is key-based)."""
    p = ("(function(){var {a,b}={b:'" + _F2 + _F3 + "',a:'" + _F1
         + "'};return a+b;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_duplicate_key_later_wins():
    """Duplicate source keys: later value wins (node-exact)."""
    p = ("(function(){var {a:x}={a:'junk',a:'" + _A + _B
         + "'};return x;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_dquote_and_ws():
    """Double-quoted literals and whitespace-tolerant shapes block."""
    p = ('(function(){ var  { a , b } = { a : "' + _F1 + '" , b : "' + _F2
         + _F3 + '" } ; return a + b ; })()')
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_directive_prologue():
    """'use strict' directive prologue is inert (node-exact)."""
    p = ("(function(){'use strict';var {a,b}={a:'" + _F1 + "',b:'" + _F2
         + _F3 + "'};return a+b;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_mixed_shorthand_rename():
    """Mixed shorthand + rename in one pattern blocks."""
    p = ("(function(){var {a,b:y}={a:'" + _F1 + "',b:'" + _F2 + _F3
         + "'};return a+y;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_extra_source_elements():
    """Extra source elements beyond the pattern are ignored (node-exact)."""
    p = ("(function(){var [a,b]=['" + _F1 + "','" + _F2 + _F3
         + "','junk'];return a+b;})()")
    ok = _decode_exact(p) == _CRED and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_single_return_operand():
    """return a (bare bound name) blocks with the exact value."""
    p = ("(function(){var {a:x}={a:'" + _A + _B + "'};return x;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p2_escaped_value_roundtrip():
    """Escaped quotes in source values round-trip node-exactly."""
    p = "(function(){var {a}={a:'it\\'s'};return a;})()"
    ok = _decode_exact(p) == "it's"
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def _miss(name, payload):
    ok = _misses(payload) and _decode_exact(payload) is None
    return ("HELD" if ok else "BREAK", "%s miss=%s" % (name, ok))


def test_p3_missing_key():
    """Pattern key absent from the source fails closed (node: undefined)."""
    return _miss("missing-key",
                 "(function(){var {a,b}={a:'" + _F1 + "'};return a+b;})()")


def test_p3_short_array():
    """Array source shorter than the pattern fails closed."""
    return _miss("short-array",
                 "(function(){var [a,b]=['" + _F1 + "'];return a+b;})()")


def test_p3_default_value():
    """Destructuring defaults fail closed (out of scope)."""
    return _miss("default",
                 "(function(){var {a='x'}={a:'" + _F1 + "'};return a;})()")


def test_p3_hole():
    """Array holes fail closed (out of scope)."""
    return _miss("hole",
                 "(function(){var [a,,b]=['" + _F1 + "','x','" + _F2
                 + "'];return a+b;})()")


def test_p3_rest():
    """Rest elements fail closed (out of scope)."""
    return _miss("rest",
                 "(function(){var [a,...r]=['" + _F1 + "','" + _F2
                 + "'];return a+r;})()")


def test_p3_nested_pattern():
    """Nested patterns fail closed (out of scope)."""
    return _miss("nested",
                 "(function(){var {a:{b}}={a:{b:'" + _F1
                 + "'}};return b;})()")


def test_p3_string_key_pattern():
    """String-literal pattern keys fail closed (ident keys only)."""
    return _miss("string-key",
                 "(function(){var {'a':x}={a:'" + _F1 + "'};return x;})()")


def test_p3_numeric_key_pattern():
    """Numeric pattern keys fail closed (ident keys only)."""
    return _miss("numeric-key",
                 "(function(){var {0:a}={0:'" + _F1 + "'};return a;})()")


def test_p3_duplicate_names():
    """Duplicate bound names fail closed."""
    return _miss("dup-names",
                 "(function(){var {a,a}={a:'" + _F1 + "'};return a;})()")


def test_p3_arguments_name():
    """Binding the name `arguments` fails closed."""
    return _miss("arguments-name",
                 "(function(){var {a:arguments}={a:'" + _F1
                 + "'};return arguments;})()")


def test_p3_named_function():
    """Named function expressions fail closed (anonymous only)."""
    return _miss("named-fn",
                 "(function f(){var {a}={a:'" + _F1 + "'};return a;})()")


def test_p3_nonempty_params():
    """Non-empty parameter lists fail closed."""
    return _miss("params",
                 "(function(p){var {a}={a:'" + _F1 + "'};return a;})()")


def test_p3_nonliteral_source():
    """Non-literal sources fail closed."""
    return _miss("ident-source",
                 "(function(){var o={a:'" + _F1 + "'};var {a}=o;return a;})()")


def test_p3_nonstring_values():
    """Non-string source values fail closed (F510 discipline)."""
    return _miss("numeric-value",
                 "(function(){var {a}={a:1};return a;})()")


def test_p3_template_element():
    """Template-literal elements fail closed (quote literals only)."""
    return _miss("template",
                 "(function(){var [a]=[`" + _F1 + "`];return a;})()")


def test_p3_extra_statements():
    """Extra statements after the decl fail closed (single return only)."""
    return _miss("extra-stmt",
                 "(function(){var {a}={a:'" + _F1 + "'};var q=1;return a;})()")


def test_p3_member_use():
    """Member/index use of a bound name fails closed (string-value discipline)."""
    return _miss("member-use",
                 "(function(){var {a}={a:'" + _F1 + "'};return a[0];})()")


def test_p3_nonempty_call_args():
    """Non-empty call args fail closed (filed shapes take none)."""
    return _miss("call-args",
                 "(function(){var {a}={a:'" + _F1 + "'};return a;})('x')")


def test_p3_computed_key():
    """Computed source keys fail closed (F510 discipline)."""
    return _miss("computed-key",
                 "(function(){var {a}={['a']:'" + _F1 + "'};return a;})()")


def test_p3_proto_key():
    """__proto__ source keys fail closed (F510 discipline)."""
    return _miss("proto-key",
                 "(function(){var {a}={__proto__:{},a:'" + _F1
                 + "'};return a;})()")


# ------------------------------------------------ composition (must hold)

def test_p4_f545_still_blocks():
    """F545 (arguments destructuring) still blocks."""
    ok = _blocked("(function(){const {0:a,1:b}=arguments;return a+b;})('"
                  + _F1 + "','" + _F2 + _F3 + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f524_still_blocks():
    """F524 (array-pattern arguments destructuring) still blocks."""
    ok = _blocked("(function(){const [a,b]=arguments;return a+b;})('"
                  + _F1 + "','" + _F2 + _F3 + "')")
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_junk_quiet():
    """Junk fragments stay quiet (no credential, no false positive).

    Note: the payload correctly DECODES to 'jxjy' -- the decoder is
    doing its job; the assertion is only that find_credential does
    not flag a non-credential, i.e. no false positive.
    """
    ok = _misses("(function(){var {a,b}={a:'jx',b:'jy'};return a+b;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p4_open_neighbors_still_miss():
    """Former open neighbors F645-F654 are CLOSED at the wave-377 merge: their red-first filed shapes now block (nothing absorbed)."""
    import importlib
    bad = []
    for fnum in (645, 646, 647, 648, 649, 650, 651, 652, 653, 654):
        mod = importlib.import_module("w376_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers and find_credential(payload) is None:
                bad.append("f%d:%s" % (fnum, name))
    ok = not bad
    return ("HELD" if ok else "BREAK", "blocked=%s" % (bad or "all"))


# ------------------------------------------------ pin + footer

def test_p5_pin_and_footer():
    """Pin 2143; merge footer: open F655-F660 / next F661."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    from gov.decision_codes import TAXONOMY  # noqa: E402
    ok = TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F713**" in text  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
    ok = ok and ("Open findings: F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712." in text)  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    ok = ok and "**Status: CLOSED 2026-10-08 wave-377 lane 1.**" in text
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


# ------------------------------------------------ perf

def test_p6_perf():
    """200 destructure sites decode quickly (bounded work)."""
    site = "(function(){var {a,b}={a:'x1',b:'x2'};return a+b;})()"
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    """Depth-1 green check: w376 attack battery stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w376_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w376 battery's footer pin is stale by design: this lane
    # closed F644, so its expected footer (open F644-F654 / next
    # F655) no longer matches. Merge-time repoint (wave-305/306
    # class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w376_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


def test_p7_green_check():
    """Green check: wave-376 attack battery stays green (depth-1)."""
    return _green_check()


def test_p7_redfirst_green():
    """Red-first battery for F644 stays 0 BREAK on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w376_f644_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = "tally: 0 BREAK" in out
    return ("HELD" if ok else "BREAK", "redfirst-0-break=%s" % ok)


def main():
    tests = [
        ("p1_filed_shorthand", test_p1_filed_shorthand),
        ("p1_filed_rename", test_p1_filed_rename),
        ("p1_filed_array", test_p1_filed_array),
        ("p2_const_let_decl", test_p2_const_let_decl),
        ("p2_single_element", test_p2_single_element),
        ("p2_source_key_order", test_p2_source_key_order),
        ("p2_duplicate_key_later_wins", test_p2_duplicate_key_later_wins),
        ("p2_dquote_and_ws", test_p2_dquote_and_ws),
        ("p2_directive_prologue", test_p2_directive_prologue),
        ("p2_mixed_shorthand_rename", test_p2_mixed_shorthand_rename),
        ("p2_extra_source_elements", test_p2_extra_source_elements),
        ("p2_single_return_operand", test_p2_single_return_operand),
        ("p2_escaped_value_roundtrip", test_p2_escaped_value_roundtrip),
        ("p3_missing_key", test_p3_missing_key),
        ("p3_short_array", test_p3_short_array),
        ("p3_default_value", test_p3_default_value),
        ("p3_hole", test_p3_hole),
        ("p3_rest", test_p3_rest),
        ("p3_nested_pattern", test_p3_nested_pattern),
        ("p3_string_key_pattern", test_p3_string_key_pattern),
        ("p3_numeric_key_pattern", test_p3_numeric_key_pattern),
        ("p3_duplicate_names", test_p3_duplicate_names),
        ("p3_arguments_name", test_p3_arguments_name),
        ("p3_named_function", test_p3_named_function),
        ("p3_nonempty_params", test_p3_nonempty_params),
        ("p3_nonliteral_source", test_p3_nonliteral_source),
        ("p3_nonstring_values", test_p3_nonstring_values),
        ("p3_template_element", test_p3_template_element),
        ("p3_extra_statements", test_p3_extra_statements),
        ("p3_member_use", test_p3_member_use),
        ("p3_nonempty_call_args", test_p3_nonempty_call_args),
        ("p3_computed_key", test_p3_computed_key),
        ("p3_proto_key", test_p3_proto_key),
        ("p4_f545_still_blocks", test_p4_f545_still_blocks),
        ("p4_f524_still_blocks", test_p4_f524_still_blocks),
        ("p4_junk_quiet", test_p4_junk_quiet),
        ("p4_open_neighbors_still_miss", test_p4_open_neighbors_still_miss),
        ("p5_pin_and_footer", test_p5_pin_and_footer),
        ("p6_perf", test_p6_perf),
        ("p7_green_check", test_p7_green_check),
        ("p7_redfirst_green", test_p7_redfirst_green),
    ]
    for name, fn in tests:
        _t(name, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
