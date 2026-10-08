#!/usr/bin/env python3
"""Wave-356 F477 closure battery (lane 2).

F477 (LOW, filed 2026-10-06 wave-355 lane 4, attack round 23; renumbered
F475->F477 at the wave-355 merge): implicit String() coercion of
non-string arguments bypasses the bounded static JS-expression decoder.
Real JS engines coerce non-string arguments via String()/ToNumber in
decoder-modeled methods, but the decoder failed closed on all of them:

  ['f1'].concat(123456789,'f2').join('')   numeric concat args
  'frags'.padStart(21,['xoxb-'])           array padString
  'f1,f2'.replace(/,/g,[''])               array replacement
  String(['f1','f2']).replace(/,/g,'')      String() constructor call

(node ground truths verified on node v24.20.0; red-first
evals/w355_f477_redfirst.py: 4 BREAK on base -> 0 BREAK / 8 HELD here.)

Closure design (gov/dlp.py, F477):
  * `_js_parse_primary` digit branch: integer literals too big for the
    count/codepoint bound (<= 0x10FFFF) now parse as coercible
    `_JSNumStr` when node-exact -- i.e. |n| <= 2**53, the
    exactly-representable float64 range (99999999999999999999 parses
    as 1e20 in the engine, so it fails closed). Hex keeps the old
    bound. _JSNumStr provenance is preserved so F475's
    type-dependent predicate guards still fail closed.
  * New `_js_parse_string_ctor`: String(x) constructor -- arrays via
    their F464 toString (comma-join), numbers via decimal repr,
    String() === ''. Null/undefined/object args, 2+ args, nested
    arrays fail closed.
  * New `_js_parse_coerced_string_arg`: padStart/padEnd pad args and
    replace() replacements accept a string literal or a String()-
    coercible array/number (engine-exact String()).
  * `_JS_EXPR_START` anchor extended with `String[ \\t\\n\\r]*\\(`
    (character class only, linear-time, no new regexes).

Documented fail-closed boundaries (NOT bypasses, disclosed here):
  * Integers > 2**53 (float64 rounding diverges from the digit
    string) -- fail closed; the engine's exponent-notation repr is
    not modeled.
  * Floats (1.5), negatives (-1), exponent forms -- fail closed.
  * Null/undefined/object args (String() is 'null'/'undefined'/
    '[object Object]') -- fail closed, not modeled.
  * `String('a','b')` (extra args ignored by the engine) -- fail
    closed.
  * Empty results (String() === '') are gated like the F463 fill``
    empty case -- established convention, not a miss.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 4 filed shapes block; generalizations (numeric pad,
      numeric replace, String(123), String(), additive coercion,
      array-element coercion) block node-exactly.
  P2  controls: literal forms still decode; junk quiet; F475 guard
      intact (big _JSNumStr under type-dependent predicates).
  P3  decoder pins: node byte-fidelity on the differential set
      (subprocess); 2**53 boundary pin; no new regexes (re.compile
      count + anchor pattern string); F475 _JSNumStr provenance pin.
  P4  pin + footer.
"""

import os
import sys
import subprocess
import argparse
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-356: F477 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F606, F607, F608, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 lane 1: F480 CLOSED locally (merge finalizes tree-wide)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint
FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)
FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xox" + "b-0123456789"
_B = "abc" + "def"


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


# ---------------------------------------------------------------- P1: closure
def p1_filed_concat_numeric():
    return _verdict("['%s'].concat(123456789,'%s').join('')" % (_A, _B), True)


def p1_filed_padstart_array():
    return _verdict("'%s'.padStart(21,['%s'])" % (_A + _B, "xoxb-"), True)


def p1_filed_replace_array():
    return _verdict("'%s,%s'.replace(/,/g,[''])" % (_A, _B), True)


def p1_filed_string_ctor():
    return _verdict("String(['%s','%s']).replace(/,/g,'')" % (_A, _B[:3]), True)


def p1_numeric_pad_arg():
    # 'a'.padStart(5,1) -> '1111a' node-exact (credential-bearing)
    payload = "'%s'.padStart(%d,1)" % (_A + _B, len(_A + _B) + 4)
    v, n = _verdict(payload, True)
    d = _decoded(payload)
    ok = (v == "HELD" and d == "1111" + _A + _B)
    return ("HELD" if ok else "BREAK", "padStart numeric pad -> %r" % (d,))


def p1_numeric_replace_arg():
    payload = "'%s,%s'.replace(/,/g,123)" % (_A, _B)
    v, n = _verdict(payload, True)
    d = _decoded(payload)
    ok = (v == "HELD" and d == _A + "123" + _B)
    return ("HELD" if ok else "BREAK", "replace numeric repl -> %r" % (d,))


def p1_string_ctor_forms():
    cases = [("String(123)+'%s'" % _A, "123" + _A),
             ("String('%s')" % _A, _A),
             ("String(['%s','%s'])" % (_A, _B), _A + "," + _B)]
    for payload, want in cases:
        d = _decoded(payload)
        if d != want or not _blocked(payload):
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    return ("HELD", "String() forms node-exact")


def p1_additive_coercion():
    # 'a' + 123456789 is String() coercion via '+' -- same mechanism
    payload = "'%s'+123456789" % _A
    d = _decoded(payload)
    ok = (d == _A + "123456789" and _blocked(payload))
    return ("HELD" if ok else "BREAK", "additive -> %r" % (d,))


def p1_array_element_coercion():
    payload = "['%s',123456789].join('')" % _A
    d = _decoded(payload)
    ok = (d == _A + "123456789" and _blocked(payload))
    return ("HELD" if ok else "BREAK", "array element -> %r" % (d,))


def p1_fail_closed_bigint():
    # > 2**53: float64 rounds (node gives exponent-notation repr) --
    # fail closed, not mis-decoded
    v, _ = _verdict("['a'].concat(99999999999999999999).join('')", False)
    d = _decoded("['a'].concat(99999999999999999999).join('')")
    ok = (v == "HELD" and d is None)
    return ("HELD" if ok else "BREAK", "bigint -> %r" % (d,))


def p1_fail_closed_shapes():
    shapes = ["['a'].concat(1.5).join('')", "['a'].concat(-1).join('')",
              "String('a','b')", "Stringx('a')",
              "'a'.padStart(5,[['b']])", "String(['a',['b']])",
              "'a'.padStart(5,`b`)", "String(`ab`)",
              "String('a'+`b`)", "String((`a`))",
              "'a,b'.replace(/,/g,`c`)"]
    for payload in shapes:
        v, _ = _verdict(payload, False)
        if v != "HELD":
            return ("BREAK", "fail-closed shape decoded: %s" % payload[:50])
    return ("HELD", "11 fail-closed shapes quiet")


def p1_multidigit_numeric_args():
    # Spec-review catch: _js_parse_string treated a leading digit as
    # the quote delimiter ('a'.padStart(5,121) -> '2222a'; node
    # '1211a). Multi-digit numerics must be node-exact.
    cases = [("'a'.padStart(5,121)", "1211a"),
             ("'a'.padStart(5,11)", "1111a"),
             ("'a,b'.replace(/,/g,121)", "a121b"),
             ("'a,b'.replace(/,/g,11)", "a11b"),
             ("'a'.padStart(6,65536)", "65536a"),
             ("'a'.padEnd(6,42)", "a42424")]
    for payload, want in cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload, d, want))
    return ("HELD", "6 multi-digit numerics node-exact")


# ---------------------------------------------------------------- P2: controls
def p2_literal_forms_still_decode():
    cases = [("['%s','%s'].join('')" % (_A, _B), _A + _B),
             ("'%s'.padStart(%d,'xoxb-')" % (_A + _B, len(_A + _B) + 5),
              "xoxb-" + _A + _B),
             ("['%s','%s'].toString().replace(/,/g,'')" % (_A, _B),
              _A + _B)]
    for payload, want in cases:
        d = _decoded(payload)
        if d != want or not _blocked(payload):
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    return ("HELD", "literal forms still decode")


def p2_f475_guard_intact():
    # big _JSNumStr under a type-dependent predicate must fail closed
    v, _ = _verdict(
        "['a',99999999999999999999].filter(x=>x!=='').join('')", False)
    d = _decoded("['a',99999999999999999999].filter(x=>x!=='').join('')")
    ok = (v == "HELD" and d is None)
    return ("HELD" if ok else "BREAK", "F475 guard -> %r" % (d,))


def p2_junk_quiet():
    v, _ = _verdict("['ab'].concat(12,'cd').join('')", False)
    return (v, "junk quiet")


def p2_small_numbers_still_decode():
    # <= 0x10FFFF keeps the old path (regression pin)
    payload = "['%s'].concat(123,'%s').join('')" % (_A, _B)
    d = _decoded(payload)
    ok = (d == _A + "123" + _B and _blocked(payload))
    return ("HELD" if ok else "BREAK", "small numbers -> %r" % (d,))


# ---------------------------------------------------------------- P3: pins
def p3_node_differential():
    """Node byte-fidelity on the differential set (subprocess)."""
    cases = [
        ("['qa'].concat(123456789,'qb').join('')", "qa123456789qb"),
        ("'qaqb'.padStart(21,['zz'])", "z" * 17 + "qaqb"),
        ("'qa,qb'.replace(/,/g,[''])", "qaqb"),
        ("String(['qa','qb'])", "qa,qb"),
        ("'a'.padStart(5,['b'])", "bbbba"),
        ("'a'.padStart(5,1)", "1111a"),
        ("'a,b'.replace(/,/g,123)", "a123b"),
        ("String(123)", "123"),
        ("'a'+123456789", "a123456789"),
        ("['a',123456789].join('')", "a123456789"),
    ]
    src = "const outs=[];\n"
    for payload, _ in cases:
        import json as _json
        src += ("try{outs.push(JSON.stringify(eval(%s)))}"
                "catch(e){outs.push('THROW')}\n" % _json.dumps(payload))
    src += "for (const o of outs) console.log(o);\n"
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    node_outs = r.stdout.strip().split("\n")
    if len(node_outs) != len(cases):
        return ("ERROR", "node produced %d lines" % len(node_outs))
    import json as _json
    for (payload, want), n in zip(cases, node_outs):
        got = _decoded(payload)
        if got != want or n != _json.dumps(want):
            return ("BREAK", "diff %s node=%s dec=%r" % (payload[:40], n, got))
    return ("HELD", "%d shapes node-exact" % len(cases))


def p3_boundary_2p53():
    # 2**53 is exactly representable; 2**53+1 is not
    d_ok = _decoded("['a'].concat(9007199254740992).join('')")
    d_big = _decoded("['a'].concat(9007199254740993).join('')")
    ok = (d_ok == "a9007199254740992" and d_big is None)
    return ("HELD" if ok else "BREAK",
            "2**53 -> %r, 2**53+1 -> %r" % (d_ok, d_big))


def p3_no_new_regexes():
    import re as _re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n_compile = len(_re.findall(r"re\.compile\(", src))
    # F480 (wave-358 lane 1): the String( anchor widened to also cover
    # the bracket-string member form (String['...']); pin the widened
    # shape, still character-class-only.
    anchor_ok = "String[ \\t\\n\\r]*(\\(|\\[[ \\t\\n\\r]*['\\\"])" in src
    ok = (n_compile == 28 and anchor_ok)
    return ("HELD" if ok else "BREAK",
            "re.compile=%d anchor=%s" % (n_compile, anchor_ok))


def p3_f475_provenance_pin():
    # big-number elements keep _JSNumStr provenance (F475 guard sees them)
    st = {"ops": 0, "parts": 0}
    v, _ = dlp._js_parse_primary("9999999999", 0, 0, st)
    ok = isinstance(v, dlp._JSNumStr) and str(v) == "9999999999"
    return ("HELD" if ok else "BREAK", "provenance=%s" % type(v).__name__)


# ---------------------------------------------------------------- P4: pin+footer
def p4_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-356 lane 2" in footer
    ok = ok and "(F477 filed 2026-10-06, wave-355 lane 4" in footer
    return ("HELD" if ok else "BREAK", "pin=%d footer" % len(codes))


_PROBES = [
    ("p1-filed-concat-numeric", p1_filed_concat_numeric),
    ("p1-filed-padstart-array", p1_filed_padstart_array),
    ("p1-filed-replace-array", p1_filed_replace_array),
    ("p1-filed-string-ctor", p1_filed_string_ctor),
    ("p1-numeric-pad-arg", p1_numeric_pad_arg),
    ("p1-numeric-replace-arg", p1_numeric_replace_arg),
    ("p1-string-ctor-forms", p1_string_ctor_forms),
    ("p1-additive-coercion", p1_additive_coercion),
    ("p1-array-element-coercion", p1_array_element_coercion),
    ("p1-fail-closed-bigint", p1_fail_closed_bigint),
    ("p1-fail-closed-shapes", p1_fail_closed_shapes),
    ("p1-multidigit-numeric-args", p1_multidigit_numeric_args),
    ("p2-literal-forms-still-decode", p2_literal_forms_still_decode),
    ("p2-f475-guard-intact", p2_f475_guard_intact),
    ("p2-junk-quiet", p2_junk_quiet),
    ("p2-small-numbers-still-decode", p2_small_numbers_still_decode),
    ("p3-node-differential", p3_node_differential),
    ("p3-boundary-2p53", p3_boundary_2p53),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f475-provenance-pin", p3_f475_provenance_pin),
    ("p4-pin-and-footer", p4_pin_and_footer),
]

_EXPECTED_BREAKS = set()


def _safe(pid, fn):
    try:
        return pid, fn()
    except Exception as e:  # noqa: BLE001 -- loud, never silent
        return pid, ("ERROR", "%s: %s" % (type(e).__name__, e))


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
               "w354_attack_probes.py")
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
        if breaks:
            raise AssertionError("green check failed: %s (breaks=%s)"
                                 % (notes[-1], sorted(breaks)))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe")
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                print(pid, verdict)
                return 0 if verdict[0] == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v[0] == "BREAK")
    held = sum(1 for _, v in results if v[0] == "HELD")
    err = sum(1 for _, v in results if v[0] == "ERROR")
    for pid, v in results:
        print(pid, v[0], v[1] if len(v) > 1 else "")
    print("w356_f477close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v[0] == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v[0] == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
