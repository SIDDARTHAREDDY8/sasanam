#!/usr/bin/env python3
"""Wave-360 F489+F490 closure battery (lane 1).

Two LOW findings from wave-359 attack round 27 (all node v24.20.0 ->
credential, decoder missed on the wave-359-merged base):

F489: array-like receiver edge spellings beyond F487 -- the F487
  closure parses {length, indexed} object literals, but the engine
  accepts wilder array-likes as .call receivers:
    new Proxy({length:2,0:'f1',1:'f2'}, {}) -- empty handler forwards
    new Proxy(..., {get:(t,p)=>...}) -- get-trap (FAIL CLOSED, boundary)
    {0:'f1',1:'f2', get length() { return 2; }} -- accessor length
    (function(){return arguments})('f1','f2') -- arguments exotic object
  Distinct from F487 (plain object literals hold).

F490: optional-chaining spellings at dispatch targets -- the F478/F482
  dispatch paths anchor on `.` member access, but the engine's `?.`
  is identical when the target is provably non-null:
    Array.prototype.concat?.call / ?.apply (dot and bracket-string)
    ([]?.concat)?.call -- method reference then dispatch
    [].concat?.call -- postfix dispatch through ?.
    ([].concat ?? Array.prototype.join).call -- nullish pick
    ([].constructor?.of)(...) -- factory reference then apply
    Reflect?.apply(Array, null, [...]) -- optional chaining on Reflect
  Distinct from F478/F482 (dot-form dispatch holds).

Closure design (gov/dlp.py):
  F489:
  * New `_js_parse_accessor_length`: parses exactly
    `get length() { return N; }` (ws-tolerant, optional `;`); only the
    constant-numeric-return shape is modeled (node-verified: the engine
    calls the getter and ToLength()s the result). Any other getter body
    fails closed.
  * `_js_parse_arraylike_recv` tries the accessor before the plain
    ident key; duplicate length or length > _JS_EXPR_MAX_PARTS fails
    closed.
  * New `_js_parse_proxy_recv`: `new Proxy(TARGET, {})` -- TARGET is
    parsed by the F487/F489 grammar; the handler must be exactly `{}`
    (ws-tolerant). Any trap fails closed (documented boundary: the
    engine evaluates arbitrary trap code).
  * New `_js_parse_arguments_iife_recv`: `(function(){return
    arguments})(args...)` -- exact shape; args are string literals or
    F479 markers, giving the _JSArr directly (engine-exact: the
    arguments exotic object has length == arg count).
  * New `_js_parse_dispatch_receiver`: tries `{`, `new Proxy(`, and
    `(function` heads before the additive grammar.
  F490:
  * New `_JSMethodRef` (kind in {'array','string','factory'}): a
    bound-method reference, created only for provably-non-null bases
    with a table-validated method (never undefined). A bare reference
    is not a decodable value: `_ascii_printable_or_none` refuses
    non-str, `_js_parse_additive` raises on method-ref operands.
  * New `_js_parse_opt_member_ref`: `?.METHOD` / `?['METHOD']` on a
    value -> _JSMethodRef (adjacent `?.` only; _JSNumStr base refused).
  * `_js_parse_postfix`: `?` added to loop chars; method-ref steps go
    through `_js_parse_methodref_step` (dispatch via
    `_js_apply_fn_dispatch`, or factory application for kind ==
    'factory').
  * `_js_peek_dispatch_call`: accepts leading `?.` (adjacent only);
    guards in `_js_parse_prototype_dispatch` and
    `_js_parse_postfix_dispatch` include `"?"`.
  * Paren branch: `(LEFT ?? RIGHT)` via `_js_peek_nullish_pick` /
    `_js_parse_nullish_pick` -- LEFT must be a method reference
    (provably non-null, so ?? takes LEFT); RIGHT is a
    dispatch-target ref, parsed and discarded (engine short-circuits).
  * `_js_parse_ctor_factory`: `?.` before the member name; `of` not
    followed by `(` returns the factory reference (applied by postfix).
  * Reflect: `Reflect?.apply` accepted (adjacent `?.`; Reflect is
    provably non-null; the decoder has no binding forms so shadowing
    cannot arise). thisArg may be null/undefined (target is provably
    Array, which ignores thisArg).
  * `_JS_EXPR_START`: the Reflect anchor gains `(?./.)`
    (re.compile count unchanged at 28).

Fail-closed boundaries (documented):
  F489: non-empty proxy handlers (get-trap and any other trap); the
    Object.freeze receiver shape (verified MISS on the base tree -- the
    wave-359 attack report's "rides with F487 (validated)" claim is
    overstated; NOT closed here per lane instructions, recommended
    for a new finding number at merge).
  F490: `?.` with a space (`? .` is a SyntaxError in the engine);
    `?.` on possibly-null bases; a bare unapplied method reference;
    method references in additive position.

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

TAXONOMY_PIN = 2144  # Wave-360 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


def _blocked(payload):
    r = dlp._try_js_expr_decode(payload, 0)
    return r[0] if r else None


def _verdict(payload, want_block):
    try:
        hit = _blocked(payload)
    except Exception as e:  # noqa: BLE001 -- loud is a failure here
        return ("BREAK", "raised %r" % (e,))
    if want_block:
        # The decoded variant must be byte-identical to the node
        # evaluation (checked in p3-node-differential for the filed
        # shapes; here we assert the credential is recovered).
        ok = hit is not None and _A1 in hit and _A2 in hit
    else:
        ok = hit is None
    return ("HELD" if ok else "BREAK",
            "hit=%s want_block=%s" % (bool(hit), want_block))


# ------------------------------------------------------------- P1: closure
def p1_f489_filed_shapes():
    cases = [
        # proxy with empty handler -- join / slice / filter
        ("Array.prototype.join.call(new Proxy({length:2,0:'" + _A1 + "',1:'" + _A2 + "'}, {}), '')", True),
        ("Array.prototype.slice.call(new Proxy({length:2,0:'" + _A1 + "',1:'" + _A2 + "'},{}), 0).join('')", True),
        ("Array.prototype.filter.call(new Proxy({length:3,0:'" + _A1 + "',1:'" + _A2 + "',2:''},{}), x=>x!=='').join('')", True),
        # proxy with F479 null marker in the target
        ("Array.prototype.join.call(new Proxy({length:3,0:'" + _A1 + "',1:null,2:'" + _A2 + "'},{}), '')", True),
        # accessor-property length
        ("Array.prototype.join.call({0:'" + _A1 + "',1:'" + _A2 + "', get length() { return 2; }}, '')", True),
        # arguments-IIFE receivers
        ("Array.prototype.join.call((function(){return arguments})('" + _A1 + "','" + _A2 + "'), '')", True),
        ("Array.prototype.slice.call((function(){return arguments})('" + _A1 + "','" + _A2 + "'), 0).join('')", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed F489 shapes block" % (len(cases) - len(bad), len(cases)))


def p1_f490_filed_shapes():
    cases = [
        "Array.prototype.concat?.call([], '" + _A1 + "','" + _A2 + "').join('')",
        "([]?.concat)?.call([], ['" + _A1 + "','" + _A2 + "']).join('')",
        "[].concat?.call([], '" + _A1 + "','" + _A2 + "').join('')",
        "Array.prototype['concat']?.call([], '" + _A1 + "','" + _A2 + "').join('')",
        "Array.prototype.concat?.apply([], ['" + _A1 + "','" + _A2 + "']).join('')",
        "Array.prototype['concat']?.apply([], ['" + _A1 + "','" + _A2 + "']).join('')",
        "(([].concat ?? Array.prototype.join).call([], ['" + _A1 + "','" + _A2 + "'])).join('')",
        "([].constructor?.of)('" + _A1 + "','" + _A2 + "').join('')",
        "Reflect?.apply(Array, null, ['" + _A1 + "','" + _A2 + "']).join('')",
    ]
    bad = [c for c in cases if _verdict(c, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed F490 shapes block" % (len(cases) - len(bad), len(cases)))


def p1_compositions():
    # F489 x F479 (null/undefined markers inside the proxy target),
    # F490 x F482 (bracket-string + optional chaining).
    cases = [
        ("Array.prototype.join.call(new Proxy({length:3,0:'" + _A1 + "',1:undefined,2:'" + _A2 + "'},{}), '')", True),
        ("([]?.['concat'])?.call([], ['" + _A1 + "','" + _A2 + "']).join('')", True),
    ]
    bad = [c for c, w in cases if _verdict(c, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition shapes behave" % (len(cases) - len(bad), len(cases)))


# ---------------------------------------------------- P2: fail-closed bounds
def p2_f489_bounds():
    cases = [
        # get-trap proxy: the engine evaluates trap code -- unmodelable
        "Array.prototype.join.call(new Proxy({length:2}, {get:(t,p)=>p==='length'?2:({0:'" + _A1 + "',1:'" + _A2 + "'})[p]}), '')",
        # non-empty handler (any trap)
        "Array.prototype.join.call(new Proxy({length:2,0:'" + _A1 + "',1:'" + _A2 + "'}, {get:(t,p)=>'x'}), '')",
        # proxy target not an object literal
        "Array.prototype.join.call(new Proxy(arr, {}), '')",
        # non-constant getter
        "Array.prototype.join.call({0:'" + _A1 + "',1:'" + _A2 + "', get length(){return n}}, '')",
        # duplicate length (data + accessor)
        "Array.prototype.join.call({length:2, 0:'" + _A1 + "',1:'" + _A2 + "', get length(){return 2}}, '')",
        # IIFE with parameters
        "Array.prototype.join.call((function(x){return arguments})('" + _A1 + "','" + _A2 + "'), '')",
        # IIFE returning something else
        "Array.prototype.join.call((function(){return args})('" + _A1 + "','" + _A2 + "'), '')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F489 bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p1_f502_closed_shape():
    # F502 (filed at the wave-360 merge from this lane's verified MISS,
    # closed wave-361 lane 3): the freeze-wrapped receiver now blocks.
    c = ("Array.prototype.join.call(Object.freeze({length:2,0:'" + _A1
         + "',1:'" + _A2 + "'}), '')")
    v, note = _verdict(c, True)
    return (v, "F502 filed shape blocks" if v == "HELD" else note)


def p2_f490_bounds():
    cases = [
        # `? .` with a space is a SyntaxError in the engine
        "Array.prototype.concat? .call([], '" + _A1 + "','" + _A2 + "').join('')",
        # `?.` on a possibly-null base (short-circuit semantics)
        "Array.prototype.join.call(null?.length, '')",
        # bare unapplied method reference (not a value)
        "([]?.concat).join('')",
        # method reference in additive position
        "([]?.concat) + 'x'",
        # bare unapplied factory reference
        "([].constructor?.of).join('')",
        # numeric base has no concat (engine: undefined)
        "(1)?.concat.call([], ['" + _A1 + "'])",
        # ?? with a non-method LEFT
        "(('a' ?? Array.prototype.join).call([], ['" + _A1 + "'])).join('')",
        # ?? with a non-dispatch-target RIGHT
        "(([].concat ?? foo).call([], ['" + _A1 + "'])).join('')",
        # generator receiver (F494) stays distinct from proxy receivers
        "Array.prototype.join.call((function*(){yield '" + _A1 + "';yield '" + _A2 + "'})(), '')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F490 bounds fail closed" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P3: node-exactness
def p3_node_differential():
    """Node v24.20.0 vs decoder, byte-identical on all filed shapes."""
    shapes = [
        "Array.prototype.join.call(new Proxy({length:2,0:'%s',1:'%s'}, {}), '')",
        "Array.prototype.slice.call(new Proxy({length:2,0:'%s',1:'%s'},{}), 0).join('')",
        "Array.prototype.filter.call(new Proxy({length:3,0:'%s',1:'%s',2:''},{}), x=>x!=='').join('')",
        "Array.prototype.join.call(new Proxy({length:3,0:'%s',1:null,2:'%s'},{}), '')",
        "Array.prototype.join.call({0:'%s',1:'%s', get length() { return 2; }}, '')",
        "Array.prototype.join.call((function(){return arguments})('%s','%s'), '')",
        "Array.prototype.slice.call((function(){return arguments})('%s','%s'), 0).join('')",
        "Array.prototype.concat?.call([], '%s','%s').join('')",
        "([]?.concat)?.call([], ['%s','%s']).join('')",
        "[].concat?.call([], '%s','%s').join('')",
        "Array.prototype['concat']?.call([], '%s','%s').join('')",
        "Array.prototype.concat?.apply([], ['%s','%s']).join('')",
        "Array.prototype['concat']?.apply([], ['%s','%s']).join('')",
        "(([].concat ?? Array.prototype.join).call([], ['%s','%s'])).join('')",
        "([].constructor?.of)('%s','%s').join('')",
        "Reflect?.apply(Array, null, ['%s','%s']).join('')",
    ]
    js = "const A1=%s,A2=%s;\n" % (json.dumps(_A1), json.dumps(_A2))
    js += "const S=[\n" + ",\n".join(
        "eval(%r)" % (s % (_A1, _A2)) for s in shapes) + "\n];\n"
    js += "console.log(JSON.stringify(S));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[-200:])
    node_vals = json.loads(r.stdout)
    bad = []
    for shape, nv in zip(shapes, node_vals):
        payload = shape % (_A1, _A2)
        dec = dlp._try_js_expr_decode(payload, 0)
        dv = dec[0] if dec else None
        if dv != nv:
            bad.append(shape[:40])
    return ("HELD" if not bad else "BREAK",
            "%d/%d node byte-identical" % (len(shapes) - len(bad), len(shapes)))


def p3_no_new_regexes():
    import re
    n = sum(1 for line in open(os.path.join(REPO_ROOT, "gov", "dlp.py"))
            if "re.compile" in line)
    assert n == 28, "re.compile count=%d, want 28" % n
    # The Reflect anchor alternative pins the F490 (?./.) widening.
    assert "(\\?\\.|\\.)" in dlp._JS_EXPR_START.pattern, "anchor missing F490 widening"
    return ("HELD", "28 re.compile; anchor pins F490 widening")


# ------------------------------------------------------- P4: pin and footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2144, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F489" in text and "F490" in text, "F489/F490 missing from FINDINGS.md"
    return ("HELD", "pin=2140; F489/F490 in FINDINGS.md (wave-360 lane 1)")


PROBES = [
    ("p1-f489-filed-shapes", p1_f489_filed_shapes),
    ("p1-f490-filed-shapes", p1_f490_filed_shapes),
    ("p1-f502-closed-shape", p1_f502_closed_shape),
    ("p1-compositions", p1_compositions),
    ("p2-f489-bounds", p2_f489_bounds),
    ("p2-f490-bounds", p2_f490_bounds),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
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
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w359_f489_redfirst.py",
               "w359_f490_redfirst.py",
               "w359_f486f487f488close_probes.py",
               "w359_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g360-green-%s-%d" % (script.replace(".py", ""),
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
    print("w360_f489f490close: starting %d probes" % len(PROBES))
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
    print("w360_f489f490close: %d BREAK / %d HELD / %d ERROR"
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
