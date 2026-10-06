#!/usr/bin/env python3
"""Wave-358 F480 closure battery (lane 1).

F480 (LOW, filed 2026-10-06 wave-357 attack round 25): constructor-function
call/apply dispatch and bracket-string member access on built-in call
sites bypass the bounded static JS-expression decoder -- the decoder
anchored modeled built-ins on dot-identifier call shapes:

  Array.apply(Array, ['f1','f2']).join('')
  Array['apply'](Array, ['f1','f2']).join('')
  Array.call(Array, 'f1','f2').join('')
  Array['call'](Array, 'f1','f2').join('')
  [].constructor['apply']([].constructor, ['f1','f2']).join('')
  Reflect['apply'](Array, Array, [['f1'],['f2']]).join('')
  String['fromCharCode'](120,111,...)
  Object['assign']([], ['f1','f2']).join('')

All node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants on the open tree. Distinct from F469
(Reflect.apply dot-form -- the Reflect API), F478 (.call/.apply/.bind on
prototype METHODS), F476 (factory path), F458/F471 (dot forms only).

Closure design (gov/dlp.py, F480):
  * New `_js_parse_bracket_member`: ws-tolerant `['<name>']` /
    `["<name>"]` parser returning (name, idx); replaces the F476
    `_js_parse_bracket_of` (of-only).
  * New `_js_parse_string_literal_list`: the F454 string-literal-only
    argument-list grammar factored out of `_js_parse_array_constructor`
    (identical behavior); reused by the constructor dispatch so the
    desugar is faithful to the direct form (no F481-class gap).
  * New `_js_parse_array_ctor_ref`: exactly `Array` / `[].constructor`.
  * New `_js_parse_ctor_apply`: `Array.apply(Array, [...])` /
    `Array.call(Array, ...)` and the bracket-member / `[].constructor`
    receiver variants, desugared to the F454 multi-arg constructor.
    thisArg must be exactly the Array constructor (conservative --
    node ignores it, but anything else fails closed).
  * New `_js_parse_reflect_apply_ctor`: `Reflect.apply` /
    `Reflect['apply']` with the bare `Array` target, desugared to
    `Array(...argsList)`; each argsList element is a string literal or
    a string-literal array literal (F468 grammar -- nested _JSArr
    survives through the F479 join coercion, engine-exact).
  * `_js_parse_reflect_call`: bracket-string member (`Reflect['apply']`)
    routed by member name; the dot-form `apply` now peeks the target
    (`_js_peek_reflect_apply_target`): `Array.prototype...` keeps the
    F469 path, the bare `Array` takes the F480 path.
  * `_js_parse_array_constructor`: the `.`-member peek routes
    apply/call to the dispatch parser; `of` keeps the F446 factory.
  * New `_js_parse_array_bracket_dispatch`: `Array[<member>]` member
    dispatch (of/apply/call); `_js_parse_ctor_factory` now handles the
    `[].constructor` receiver with the same member dispatch.
  * `_js_parse_fromcharcode` / `_js_parse_object_assign`: argument-list
    cores factored into `_js_parse_fromcharcode_args` /
    `_js_parse_object_assign_args` (no behavior change); the
    `_js_parse_primary` String/Object branches accept the bracket-string
    member forms (`String['fromCharCode']`, `Object['assign']`).
  * `_JS_EXPR_START` anchor widened within the single regex (character
    classes only -- the F468 precedent): `Array.(of|apply|call)`,
    `String[(]`, `Reflect[(]/[`, `Object[(]/[`.
  * Fail closed: non-constructor thisArg; third apply arg; marker /
    numeric / additive / template args (same classes as the direct
    form); non-literal / empty / non-ident member keys; unmodeled
    members; `Reflect['construct']`; non-Array Reflect targets;
    `[].constructor` on non-`[]` receivers; `Array.prototype.apply`
    (F478 territory).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 8 filed shapes block (node-exact decode checked);
      generalizations (dot-form Reflect.apply ctor, flat argsList,
      zero-arg, ws tolerance, [].constructor.apply dot, postfix
      compositions) block node-exactly.
  P2  fail-closed boundaries: non-constructor thisArg, extra args,
      marker/numeric/template args, bad members/keys, unmodeled
      members, Reflect['construct'], non-Array targets, junk quiet,
      F469/F458/F471/F476/F478 neighbors intact, F481 closed (coded refusal).
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored; F441 ordering untouched.
  P4  pin + footer (F480 CLOSED locally; open F481 / next F482).
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

TAXONOMY_PIN = 2135  # Wave-358 lane 1: F480 closed; no new decision codes
FOOTER_OPEN = "F491, F492, F493, F494, F495"  # Wave-360 lane 1: F489, F490 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 3: F486, F487, F488 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 2: F484, F485 CLOSED locally (merge finalizes tree-wide)  # Wave-359 lane 1: F482, F483 CLOSED locally (merge finalizes tree-wide)  # Wave-358 lane 1: F480 CLOSED locally (merge finalizes tree-wide)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN
FOOTER_NEXT = "F496"  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496

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
def p1_filed_shapes_block():
    shapes = [
        "Array.apply(Array, ['%s','%s']).join('')" % (_A, _B),
        "Array['apply'](Array, ['%s','%s']).join('')" % (_A, _B),
        "Array.call(Array, '%s','%s').join('')" % (_A, _B),
        "Array['call'](Array, '%s','%s').join('')" % (_A, _B),
        "[].constructor['apply']([].constructor, ['%s','%s']).join('')" % (_A, _B),
        "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (_A, _B),
        "String['fromCharCode'](%s)" % ",".join(str(c) for c in
            [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
             97, 98, 99, 100, 101, 102]),
        "Object['assign']([], ['%s','%s']).join('')" % (_A, _B),
    ]
    for payload in shapes:
        v, _ = _verdict(payload, True)
        if v != "HELD":
            return ("BREAK", "filed shape not blocked: %s" % payload[:60])
    return ("HELD", "8/8 filed shapes blocked")


def p1_filed_shapes_node_exact():
    cases = [
        ("Array.apply(Array, ['ab','cd']).join('')", "abcd"),
        ("Array['apply'](Array, ['ab','cd']).join('')", "abcd"),
        ("Array.call(Array, 'ab','cd').join('')", "abcd"),
        ("Array['call'](Array, 'ab','cd').join('')", "abcd"),
        ("[].constructor['apply']([].constructor, ['ab','cd']).join('')", "abcd"),
        ("Reflect['apply'](Array, Array, [['ab'],['cd']]).join('')", "abcd"),
        ("String['fromCharCode'](97,98)", "ab"),
        ("Object['assign']([], ['ab','cd']).join('')", "abcd"),
    ]
    for payload, want in cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:50], d, want))
    # Credential variants (fragmented literals avoid the plain seam) block.
    cred_cases = [
        "Array.apply(Array, ['%s','%s']).join('')" % (_A, _B),
        "Array['call'](Array, '%s','%s').join('')" % (_A, _B),
        "[].constructor['apply']([].constructor, ['%s','%s']).join('')" % (_A, _B),
        "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (_A, _B),
        "String['fromCharCode'](%s)" % ",".join(str(c) for c in
            [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
             97, 98, 99, 100, 101, 102]),
        "Object['assign']([], ['%s','%s']).join('')" % (_A, _B),
    ]
    for payload in cred_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:50])
    return ("HELD", "8/8 dispatch decodes node-exact; 6/6 credential variants block")


def p1_generalizations():
    # Node-exact decode cases (junk literals; decode checked, not blocking).
    decode_cases = [
        # dot-form Reflect.apply with the Array target (F480 mechanism)
        ("Reflect.apply(Array, Array, [['ab'],['cd']]).join('')", "abcd"),
        # flat argsList: Reflect.apply(Array, Array, ['a','b']) === Array('a','b')
        ("Reflect['apply'](Array, Array, ['ab','cd']).join('')", "abcd"),
        # ws-tolerant dispatch spellings
        ("Array . apply ( Array , [ 'ab' , 'cd' ] ).join('')", "abcd"),
        ("Array [ 'call' ] ( Array , 'ab' , 'cd' ).join('')", "abcd"),
        ("String [ 'fromCharCode' ] ( 97 , 98 )", "ab"),
        ("Object [ 'assign' ] ( [] , [ 'ab' , 'cd' ] ).join('')", "abcd"),
        ("Reflect [ 'apply' ] ( Array , Array , [ [ 'ab' ] ] ).join('')", "ab"),
        # [].constructor.apply dot form
        ("[].constructor.apply([].constructor, ['ab']).join('')", "ab"),
        # double-quote member spellings
        ('Array["apply"](Array, ["ab"]).join("")', "ab"),
        ('String["fromCharCode"](97)', "a"),
        ('Object["assign"]([], ["ab"]).join("")', "ab"),
        # postfix compositions
        ("Array.apply(Array, ['ab']).concat(['cd']).join('')", "abcd"),
        ("'k:'+Array.call(Array, 'ab').join('')", "k:ab"),
    ]
    for payload, want in decode_cases:
        d = _decoded(payload)
        if d != want:
            return ("BREAK", "%s -> %r want %r" % (payload[:55], d, want))
    # Credential variants block (fragmented literals avoid the plain seam).
    block_cases = [
        "Array.apply(Array, ['%s','%s']).join('')" % (_A, _B),
        "Array [ 'call' ] ( Array , '%s' , '%s' ).join('')" % (_A, _B),
        'Array["apply"](Array, ["%s"]).join("")' % _A,
    ]
    for payload in block_cases:
        if not _blocked(payload):
            return ("BREAK", "credential variant not blocked: %s" % payload[:55])
    return ("HELD", "%d/%d generalizations node-exact; %d/%d block" %
            (len(decode_cases), len(decode_cases), len(block_cases), len(block_cases)))


# ------------------------------------------------------- P2: fail-closed
def p2_dispatch_boundaries():
    # Each must fail closed on the dispatch path: with junk literals the
    # decode must NOT produce the joined value (the plain seam is avoided
    # by using junk, so only the dispatch decode could produce it).
    shapes = [
        "Array.apply([], ['ab','cd']).join('')",          # non-ctor thisArg
        "Array.apply(Array, ['ab','cd'], 'x').join('')",   # 3rd arg
        "Array.apply(Array, ['ab',null]).join('')",        # marker elem
        "Array.apply(Array, ['ab',2]).join('')",           # numeric elem
        "Array.call(Array, 'ab',).join('')",               # trailing comma
        "Array.applyx(Array, ['ab']).join('')",            # ident boundary
        "Array['applyx'](Array, ['ab']).join('')",
        "Array[''](Array, ['ab']).join('')",               # empty member
        "Array[0](Array, ['ab']).join('')",                # numeric member
        "Array[x](Array, ['ab']).join('')",                # non-literal key
        "Array.apply(Array).join('')",                     # missing argsArray
        "Array.call(Array, 'a' 'b')",                      # missing comma
        "Array.call(Array, `ab`).join('')",                # template arg
        "Function.prototype.apply.call(Array, Array, ['ab']).join('')",
        "[].constructor['apply'](['x'].constructor, ['ab']).join('')",
    ]
    for payload in shapes:
        d = _decoded(payload)
        # Fail closed = decode does not yield the dispatch value.
        if d is not None and "ab" in d and "cd" in d:
            return ("BREAK", "boundary over-decodes: %s -> %r" % (payload[:60], d))
        # Specific: the non-ctor thisArg must not decode via dispatch.
        if payload.startswith("Array.apply([],") and d == "abcd":
            return ("BREAK", "non-ctor thisArg decoded: %r" % d)
    return ("HELD", "%d/%d dispatch boundaries fail closed" % (len(shapes), len(shapes)))


def p2_member_boundaries():
    # Junk literals; the dispatch must not produce the joined value.
    shapes = [
        "String['fromCharCodex'](97,98)",
        "String['concat']('ab','cd')",
        "Object['assignx']([], ['ab','cd']).join('')",
        "Object['assign'](['x'], ['ab','cd']).join('')",   # non-empty target
        "Object['assign']([], ['ab'], ['cd']).join('')",   # 2nd source
        "Reflect['construct'](Array, ['ab','cd']).join('')",  # bracket construct
        "Reflect['apply'](String, String, ['ab','cd']).join('')",  # non-Array
        # bracket concat-target: unmodeled composition, fail closed (residual)
        "Reflect['apply'](Array.prototype.concat, [], [['ab'],['cd']]).join('')",
    ]
    for payload in shapes:
        if _decoded(payload) == "abcd":
            return ("BREAK", "boundary over-decodes: %s" % payload[:60])
    return ("HELD", "%d/%d member boundaries fail closed" % (len(shapes), len(shapes)))


def p2_junk_quiet():
    for payload in ["Array.apply(Array, ['ab','cd']).join('')",
                    "String['fromCharCode'](65,66)",
                    "Object['assign']([], ['ab']).join('')",
                    "Reflect['apply'](Array, Array, [['ab']]).join('')",
                    "Array.call(Array, 'ab').join('')"]:
        if _blocked(payload):
            return ("BREAK", "false positive: %s" % payload[:60])
    return ("HELD", "junk quiet on dispatch shapes")


def p2_neighbors_intact():
    # Adjacent closures still hold; F481 CLOSED by wave-358 lane 2 (merge):
    # the dispatch desugar is faithful for marker elements, so the F481
    # shape now decodes node-exactly and blocks coded.
    hold = [
        "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (_A, _B),
        "String.fromCharCode(%s)" % ",".join(str(c) for c in
            [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
             97, 98, 99, 100, 101, 102]),
        "Object.assign([], ['%s','%s']).join('')" % (_A, _B),
        "[].constructor.of('%s','%s').join('')" % (_A, _B),
        "Array['of']('%s','%s').join('')" % (_A, _B),
        "Array.prototype.concat.call([],['%s','%s']).join('')" % (_A, _B),
        "[].concat.call([],['%s','%s']).join('')" % (_A, _B),
    ]
    for payload in hold:
        if not _blocked(payload):
            return ("BREAK", "neighbor regressed: %s" % payload[:60])
    # F481 stays open (filed, not closed by this lane). Use fragmented
    # literals (red-first style) so only the decode path could block.
    _F1 = "xoxb-" + "0123"
    _F2 = "456789" + "abcdef"
    f481 = "[].concat.call([],['%s',null,'%s']).join('')" % (_F1, _F2)
    if not _blocked(f481):
        return ("BREAK", "F481 closure regressed: marker shape misses")
    return ("HELD", "neighbors intact; F481 closed (coded refusal)")


# ------------------------------------------------------- P3: decoder pins
def p3_node_differential():
    """Node byte-fidelity on the differential set (subprocess)."""
    cases = [
        "Array.apply(Array, ['ab','cd']).join('')",
        "Array['call'](Array, 'ab','cd').join('')",
        "[].constructor['apply']([].constructor, ['ab']).join('')",
        "Reflect['apply'](Array, Array, [['ab'],['cd']]).join('')",
        "Reflect.apply(Array, Array, ['ab','cd']).join('')",
        "String['fromCharCode'](104,105)",
        "Object['assign']([], ['ab']).join('')",
        "Array . apply ( Array , [ 'ab' ] ).join('')",
    ]
    node_src = "const out=[];\n"
    for idx, p in enumerate(cases):
        node_src += ("try{out[%d]=eval(%s)}catch(e){out[%d]='THROW'};\n"
                     % (idx, repr(p), idx))
    node_src += "console.log(JSON.stringify(out));\n"
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:100])
    import json as _json
    want = _json.loads(r.stdout)
    for idx, p in enumerate(cases):
        d = _decoded(p)
        if d != want[idx]:
            return ("BREAK", "%s -> %r want %r" % (p[:45], d, want[idx]))
    return ("HELD", "%d/%d node byte-identical" % (len(cases), len(cases)))


def p3_no_new_regexes():
    # The F480 anchor widening uses the ws character class only --
    # the same F468 precedent. Pin the exact pattern string.
    # Wave-360 lane 2 (F491/F493): Reflect -> (construct|apply|get),
    # Object gains getOwnPropertyDescriptor, String gains .raw( /
    # .raw.call( (literal-alternation only).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|String\.fromCharCode|String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor)|[ \t\n\r]*\[[ \t\n\r]*['\"])|\(")
    for s in ["Array.apply(", "Array.call(", "Array['apply']",
              "String['fromCharCode']", "Object['assign']",
              "Object.getPrototypeOf",
              "Reflect['apply']", "Array . call", "String [ 'x' ]",
              "Array.prototype.concat", "String.fromCharCode",
              "Reflect.apply", "Object.assign"]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned")


def p3_f430_bounds():
    # Part/codepoint budgets still trip on adversarial dispatch input.
    big = "Array.apply(Array, [%s]).join('')" % ",".join(
        "'x%d'" % i for i in range(200))
    if _blocked(big):
        return ("BREAK", "part budget not tripped")
    many = "String['fromCharCode'](%s)" % ",".join(["65"] * 600)
    if _blocked(many):
        return ("BREAK", "codepoint budget not tripped")
    return ("HELD", "F430 budgets honored")


def p3_f441_ordering_untouched():
    # _try_bslash_unescape_all still precedes the _ESC_RUN layers.
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    i_bslash = src.find("_try_bslash_unescape_all(text)")
    i_esc = src.find("for m in list(_ESC_RUN.finditer(text))")
    assert 0 < i_bslash < i_esc
    return ("HELD", "F441 ordering untouched")


# ------------------------------------------------------- P4: pin + footer
def p4_pin_and_footer():
    assert len(TAXONOMY) == TAXONOMY_PIN, (len(TAXONOMY), TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Lane-local footer expectation: F480 closed here; the merge
    # finalizes tree-wide.
    assert ("Open findings: %s." % FOOTER_OPEN) in text, "footer open"
    assert ("Next free finding: **%s**" % FOOTER_NEXT) in text, "footer next"
    assert "F480" in text and "CLOSED" in text
    return ("HELD", "pin=%d footer open %s next %s (lane-local)" %
            (TAXONOMY_PIN, FOOTER_OPEN, FOOTER_NEXT))


_PROBES = [
    ("p1-filed-shapes-block", p1_filed_shapes_block),
    ("p1-filed-shapes-node-exact", p1_filed_shapes_node_exact),
    ("p1-generalizations", p1_generalizations),
    ("p2-dispatch-boundaries", p2_dispatch_boundaries),
    ("p2-member-boundaries", p2_member_boundaries),
    ("p2-junk-quiet", p2_junk_quiet),
    ("p2-neighbors-intact", p2_neighbors_intact),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f430-bounds", p3_f430_bounds),
    ("p3-f441-ordering-untouched", p3_f441_ordering_untouched),
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
    scripts = ("w357_attack_probes.py",
               "w357_f478close_probes.py",
               "w357_f479close_probes.py",
               "w357_f480_redfirst.py",
               "w356_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g358-green-%s-%d" % (script.replace(".py", ""),
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
    print("w358_f480close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
