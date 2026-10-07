#!/usr/bin/env python3
"""Wave-361 F500+F501+F502 closure battery (lane 3).

Three LOW findings from wave-360 attack round 28 (all node v24.20.0 ->
credential, decoder missed on the wave-360-merged base):

F500: spread args in String.fromCharCode -- the decoder models
  String.fromCharCode with literal numeric args (direct form blocks
  coded), but a spread argsList bypasses the arg parser:
    String.fromCharCode(...[120, 111, ...]) + 'f2'
    String.fromCharCode(120, ...[111, ...])   (mixed literal+spread)
    String.fromCharCode(...[120], ...[111])  (double spread)
  Distinct from F462 (spread-args CONCAT -- different call site).

F501: fragment assembly through local VALUE bindings -- F495 covers
  METHOD invocation through bindings; plain fragment assembly through
  let/var/const string bindings joined by additive concatenation:
    let a='f1', b='f2'; a+b   /  let a='f1'; let b='f2'; a+b
    var a='f1'; var b='f2'; a+b / const a='f1'; const b='f2'; a+b

F502: Object.freeze-wrapped receivers at dispatch targets (re-filed at
  the wave-360 merge from wave-360 lane 1's verified MISS -- the
  wave-359 "rides with F487" claim was overstated):
    Array.prototype.join.call(Object.freeze({length:2,0:'f1',1:'f2'}), '')
    Array.prototype.join.call(Object['freeze'](['f1','f2']), '')  (bracket)

Closure design (gov/dlp.py):
  F500:
  * `_js_parse_fromcharcode_args` routes the direct call form through
    `_js_parse_fromcharcode_args_inner(..., allow_spread=True)`, so an
    argument may be a literal codepoint or a spread array-literal
    operand `...[n, n, ...]` in any mixture (node-verified:
    `String.fromCharCode(120, ...[111]) === String.fromCharCode(120,111)`).
    The spread array is parsed by `_js_parse_fromcharcode_spread_inner`
    in the same F458 grammar (same spellings, same codepoint bounds);
    the _JS_EXPR_MAX_CODEPOINTS cap counts decoded codepoints. The
    .call/.apply dispatch forms keep allow_spread=False (spread fails
    closed there, documented boundary). Non-array spread operands and
    floats/exponents fail closed.
  F501:
  * `_js_resolve_value_bindings` consumes one or more leading
    const/let/var statements binding identifiers to string literals
    only, then substitutes every non-property, non-string,
    non-comment use in the remainder with the quoted literal.
    `var` is allowed (string-literal initializers + no reassignment
    makes hoisting value-safe); duplicate names, any reassignment,
    any rebinding (the F495 `_js_remainder_rebinds` detector), and
    non-literal initializers all abort (fail closed). A `with`
    statement anywhere in the remainder aborts the rewrite (the
    shared detector: `with` dynamically scopes identifier uses, so
    substitution would be node-wrong -- this also fixes the same
    hole in F495's rewrite). `_decode_layer`
    decodes the rewritten text as a variant after the F495 variant
    (F441 order preserved).
  * Also fixed a pre-existing crash the work exposed: F495's
    `_js_resolve_local_bindings` indexed `rest` with `n = len(text)`,
    raising IndexError when a bound token sat at the very end of the
    remainder (fail-LOUD, not fail-closed). Now rest-bounded.
  F502:
  * `_js_peek_freeze_head` / `_js_parse_freeze_recv` (generalized by
    wave-362 lane 1 into `_js_peek_integrity_wrap_head` /
    `_js_parse_integrity_wrap_recv` over
    `_JS_INTEGRITY_WRAPPERS = ("freeze", "seal", "preventExtensions")`,
    F503): `Object.freeze(` (and the F480-convention bracket form
    `Object['freeze'](`) peeks commit the parse; the single inner
    argument is parsed by `_js_parse_dispatch_receiver` itself (freeze
    is the identity on the receiver value, node-verified). Extra args,
    non-modeled inners fail closed. Object.seal / preventExtensions
    receivers are modeled by F503 (wave-362 lane 1), no longer
    fail-closed.

Fail-closed boundaries (documented):
  F500: spread of non-arrays; `String.fromCharCode.call/apply` with
    spread; floats/exponents as codepoints; >512 codepoints.
  F501: reassignment or rebinding of any bound name; duplicate
    declarators; non-leading bindings; template literals;
    method+value mixed leading statements (both rewrites decline);
    destructuring/defaults; `with` statements (dynamic scoping).
  F502: freeze with extra args; freeze nesting beyond
    _JS_EXPR_MAX_DEPTH. (Object.seal / Object.preventExtensions moved
    to F503, wave-362 lane 1.)

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""

import argparse
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2140  # Wave-361 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _decoded_value_bound(payload):
    # F501 node-exactness: the value-binding rewrite lives in
    # _decode_layer, so apply it explicitly before the whole-text
    # scan here (same pattern as the F495 battery).
    rw = dlp._js_resolve_value_bindings(payload)
    if rw is None:
        return None
    return dlp._try_js_expr_decode_all(rw)


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:60], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f500_filed_shapes():
    shapes = [
        "String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _A2,
        "String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])",
        # mixed literal+spread and double-spread (spec-review a2)
        "String.fromCharCode(120, ...[111,120,98,45,48,49,50,51]) + '%s'" % _A2,
        "String.fromCharCode(...[120], ...[111,120,98,45,48,49,50,51]) + '%s'" % _A2,
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "4/4 F500 shapes blocked (filed + mixed + double)")


def p1_f501_filed_shapes():
    shapes = [
        "let a='%s', b='%s'; a,b; a+b" % (_A1, _A2),
        "let a='%s'; let b='%s'; a+b" % (_A1, _A2),
        "var a='%s'; var b='%s'; a+b" % (_A1, _A2),
        "const a='%s'; const b='%s'; a+b" % (_A1, _A2),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "4/4 F501 filed shapes blocked")


def p1_f502_filed_shapes():
    shapes = [
        "Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.freeze(['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.freeze(Object.freeze(['%s','%s'])), '')" % (_A1, _A2),
        # bracket-string member form (spec-review a1; F480 convention)
        "Array.prototype.join.call(Object['freeze'](['%s','%s']), '')" % (_A1, _A2),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "4/4 F502 shapes blocked (filed + frozen-array + nested + bracket)")


def p1_compositions():
    cases = [
        # F500 vs F462: concat spread still held (unchanged path).
        ("[].concat(...['%s','%s']).join('')" % (_A1, _A2), True),
        # F501 vs F495: method bindings still held (F495 rewrite).
        ("const {concat} = Array.prototype; concat.call([], '%s','%s').join('')" % (_A1, _A2), True),
        # F502 vs F487: plain (unfrozen) receivers still held.
        ("Array.prototype.join.call({length:2,0:'%s',1:'%s'}, '')" % (_A1, _A2), True),
        # F500 bracket form routes through the same spread parser.
        ("String['fromCharCode'](...[102, 111, 111])", False),
        # F501 x F492: value bindings feed the computed-key folder
        # node-exactly (spec-review c2 -- pinned composition).
        ("const k='con'; Array.prototype[k+'cat'].call([], '%s','%s').join('')" % (_A1, _A2), True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition shapes behave" % (len(cases) - len(bad), len(cases)))


# ---------------------------------------------------- P2: fail-closed bounds
def p2_f500_bounds():
    cases = [
        # spread of a non-array operand
        "String.fromCharCode(...x)",
        "String.fromCharCode(...'ab')",
        # trailing argument after the spread array
        "String.fromCharCode(...[102, 111], 111)",
        # .call/.apply dispatch with spread (documented boundary)
        "String.fromCharCode.call(null, ...[102, 111])",
        "String.fromCharCode.apply(null, ...[[102, 111]])",
        # float / exponent codepoints are not integer literals
        "String.fromCharCode(...[102.0, 111])",
        "String.fromCharCode(...[1e2, 111])",
        # junk stays quiet
        "String.fromCharCode(...[97, 98])",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F500 bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p2_f501_bounds():
    cases = [
        # reassignment of a bound name aborts the rewrite
        "let a='%s'; a='%s'; a" % (_A1, _A2),
        "let a='%s'; a += '%s'; a" % (_A1, _A2),
        "let a='%s'; a++; a" % _A1,
        # rebinding via function parameter
        "const a='%s'; (function(a){return a})('zz')" % _A1,
        # rebinding via for-loop declarator
        "const a='%s'; for (let a of ['x']) { a }" % _A1,
        # nested declaration of the same name
        "const a='%s'; { const a='zz'; }" % _A1,
        # duplicate declarators
        "const a='%s'; const a='%s'; a" % (_A1, _A2),
        # non-literal initializer
        "const a=b; a",
        "const a='x'+'y'; a",
        # template literal initializer
        "const a=`%s`; a" % _A1,
        # declaration without initializer
        "var a; a='%s'; a" % _A1,
        # bindings must be leading
        "a+b; const a='%s'; const b='%s';" % (_A1, _A2),
        # property names are never rewritten (x.a keeps its key)
        "const a='%s'; x.a" % _A1,
        # `with` dynamically scopes identifier uses: the rewrite must
        # decline, so this honest-shadowing shape stays quiet
        # (spec-review c1: node gives 'ZZZZ', not the credential)
        "const a='%s'; const b='%s'; with({a:'ZZ',b:'ZZ'}){ a+b }" % (_A1, _A2),
        # junk stays quiet
        "let a='ab', b='cd'; a+b",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    # method+value mixed leading statements: the value rewrite must
    # decline (None) so the two scopes never merge.
    mixed = "const a='%s', {join} = Array.prototype; join.call([a], '')" % _A1
    if dlp._js_resolve_value_bindings(mixed) is not None:
        bad.append(mixed)
    return ("HELD" if not bad else "BREAK",
            "%d/%d F501 bounds fail closed" % (len(cases) + 1 - len(bad), len(cases) + 1))


def p2_f502_bounds():
    cases = [
        # extra arguments to freeze
        "Array.prototype.join.call(Object.freeze(['%s'], 1), '')" % _A1,
        # non-modeled inner receiver
        "Array.prototype.join.call(Object.freeze(x), '')",
        # freeze nesting beyond the depth cap (9 > _JS_EXPR_MAX_DEPTH=8)
        "Array.prototype.join.call(" + "Object.freeze(" * 9 + "['%s']" % _A1 + ")" * 9 + ", '')",
        # junk stays quiet
        "Array.prototype.join.call(Object.freeze(['ab','cd']), '')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    # F503 (wave-362 lane 1): seal/preventExtensions receivers are now
    # modeled, not fail-closed -- they must block.
    now_modeled = [
        "Array.prototype.join.call(Object.seal(['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.preventExtensions(['%s','%s']), '')" % (_A1, _A2),
    ]
    bad += [c for c in now_modeled if _verdict(c, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F502 bounds fail closed, F503 seal/preventExtensions block"
            % (len(cases) + len(now_modeled) - len(bad),
               len(cases) + len(now_modeled)))


# ------------------------------------------------------- P3: node-exactness
def p3_node_differential():
    """Node v24.20.0 vs decoder, byte-identical on all filed shapes."""
    # Single-expression shapes: decode at 0.
    expr_shapes = [
        "String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % _A2,
        "String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])",
        "String.fromCharCode(...[0x78, 0o170, 0b1111000])",
        "String.fromCharCode(120, ...[111,120,98,45,48,49,50,51]) + '%s'" % _A2,
        "String.fromCharCode(...[120], ...[111,120,98,45,48,49,50,51]) + '%s'" % _A2,
        "Array.prototype.join.call(Object.freeze({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.freeze(['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object['freeze'](['%s','%s']), '')" % (_A1, _A2),
    ]
    # Statement shapes: explicit value-binding rewrite, then whole-text.
    stmt_shapes = [
        "let a='%s', b='%s'; a+b" % (_A1, _A2),
        "let a='%s'; let b='%s'; a+b" % (_A1, _A2),
        "var a='%s'; var b='%s'; a+b" % (_A1, _A2),
        "const a='%s'; const b='%s'; a+b" % (_A1, _A2),
    ]
    js = "const A1=%s,A2=%s;\n" % (json.dumps(_A1), json.dumps(_A2))
    js += "const S=[\n" + ",\n".join(
        "eval(%r)" % s for s in expr_shapes + stmt_shapes) + "\n];\n"
    js += "console.log(JSON.stringify(S));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[-200:])
    node_vals = json.loads(r.stdout)
    bad = []
    for shape, nv in zip(expr_shapes, node_vals[:len(expr_shapes)]):
        dec = dlp._try_js_expr_decode(shape, 0)
        dv = dec[0] if dec else None
        if dv != nv:
            bad.append(shape[:40])
    for shape, nv in zip(stmt_shapes, node_vals[len(expr_shapes):]):
        dv = _decoded_value_bound(shape)
        if dv != nv:
            bad.append(shape[:40])
    return ("HELD" if not bad else "BREAK",
            "%d/%d node byte-identical" % (
                len(expr_shapes) + len(stmt_shapes) - len(bad),
                len(expr_shapes) + len(stmt_shapes)))


def p3_no_new_regexes():
    n = sum(1 for line in open(os.path.join(REPO_ROOT, "gov", "dlp.py"))
            if "re.compile" in line)
    assert n == 28, "re.compile count=%d, want 28" % n
    return ("HELD", "28 re.compile (no new regexes)")


def p3_binding_crash_regression():
    """The F495 IndexError fix: a bound token at the very end of the
    remainder must fail closed (None), never raise."""
    crashers = [
        "const {concat} = Array.prototype; concat",
        "const {join} = Array.prototype; join",
        "let c = [].concat; c",
        "const a='x'; a",
        "var a='x'; var b='y'; b",
    ]
    for payload in crashers:
        try:
            dlp._js_resolve_local_bindings(payload)
            dlp._js_resolve_value_bindings(payload)
            dlp.find_credential(payload)
        except Exception as e:  # noqa: BLE001
            return ("BREAK", "raised on %r: %r" % (payload[:40], e))
    return ("HELD", "%d end-token payloads fail closed without raising"
            % len(crashers))


# ------------------------------------------------------- P4: pin and footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    for f in ("F500", "F501", "F502"):
        assert f in text, "%s missing from FINDINGS.md" % f
    return ("HELD", "pin=2140; F500/F501/F502 in FINDINGS.md (wave-361 lane 3)")


PROBES = [
    ("p1-f500-filed-shapes", p1_f500_filed_shapes),
    ("p1-f501-filed-shapes", p1_f501_filed_shapes),
    ("p1-f502-filed-shapes", p1_f502_filed_shapes),
    ("p1-compositions", p1_compositions),
    ("p2-f500-bounds", p2_f500_bounds),
    ("p2-f501-bounds", p2_f501_bounds),
    ("p2-f502-bounds", p2_f502_bounds),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-binding-crash-regression", p3_binding_crash_regression),
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
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    if not os.path.exists(venv_python):
        venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w360_f500_redfirst.py",
               "w360_f501_redfirst.py",
               "w360_f489f490close_probes.py",
               "w360_attack_probes.py")
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
    print("w361_f500f501f502close: starting %d probes" % len(PROBES))
    results = []
    for pid, fn in PROBES:
        v, note = _safe(pid, fn)
        results.append((pid, v, note))
        print("%-28s %s | %s" % (pid, v, note))
    green = _green_check()
    print("p9-green-check: %s" % green.split("\n")[0])
    breaks = sorted(pid for pid, v, _ in results
                    if v == "BREAK" and pid not in _EXPECTED_BREAKS)
    errors = sorted(pid for pid, v, _ in results if v == "ERROR")
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v, _ in results if v == "BREAK"))
    print("w361_f500f501f502close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(results) - len(breaks) - len(errors),
             len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    if missing:
        print("missing expected BREAKs: %s" % missing)
    if "FAILED" in green:
        print("GREEN CHECK FAILED")
        return 1
    return 1 if (breaks or errors or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
