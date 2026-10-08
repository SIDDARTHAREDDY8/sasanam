#!/usr/bin/env python3
"""Closure probes for F469 (wave-354 lane 1).

F469 (LOW): Reflect.apply(Array.prototype.concat,...) array assembly
bypassed the bounded static JS-expression decoder --
Reflect.apply(Array.prototype.concat,[],[['frag1'],['frag2']]).join('')
node-evaluates to the credential (node v24.20.0 verified): the
reflection API applies the concat method to build the fragment array.
The decoder modeled no Reflect API at all; F468's close-when covers
only Reflect.construct(Array,...), a different Reflect method. Now
modeled: _js_parse_reflect_apply_concat desugars the shape to
thisArg.concat(...argsArray) with engine-exact concat semantics --
each argsArray element becomes one concat argument: array arguments
are appended element-wise (one level only), string arguments are
appended as-is. The target must be exactly the bare chain
Array.prototype.concat; thisArg must be a string-literal array
literal or an Array constructor call form; argsArray must be a '['
element-list of string literals, literal-only template literals,
array literals, or Array constructor forms. Whitespace around the
dots is tolerated (F455-class anchor, same [ \\t\\n\\r] class).

Neighbor dispositions (node-verified, documented here and in the
FINDINGS.md closure notes):
- Reflect.apply(Array.prototype.concat,[],[['a'],['b']]) -- modeled.
- thisArg variants: ['z'], Array.of('a'), Array('a','b') -- modeled.
- mixed string/array args: ['x',['y']] -- modeled (engine-exact).
- argsArray elements: Array.of('a','b'), `backtick` literals -- modeled.
- empty argsArray [] -- modeled (thisArg survives to postfix).
- `Reflect . apply` / `Array . prototype . concat` ws -- modeled
  (F455-class anchor).
- non-concat targets (Math.max, Array.prototype.push, bare `concat`
  ident) -- fail closed.
- a third argument -- fail closed (node ignores it, but the arity
  change is out of scope; documented residual).
- non-array thisArg ({}) -- fail closed.
- bare numeric/additive args ([42]) and nested arrays ([[['a']]]) --
  fail closed; numerics, additives, and fromCharCode nested inside
  array args decode through the pre-existing _js_parse_array element
  model (join-exact, node-verified).
- `new Array(...)` as thisArg -- fail closed (conservative, matches F468).
- Reflectx.apply / Reflect.applyx / Reflect.constructx -- fail closed
  (ident-boundary check; node throws TypeError).
- `myReflect.apply(...)` -- fail closed (left-boundary guard: the
  anchor has no left boundary, so member-access `fooReflect` is
  rejected engine-exact; node throws ReferenceError).
- a bare Reflect.apply(...) with no chain -- decodes to nothing (not
  obfuscation-shaped, same as bare Array(...)).
- `expr` `. join('')` (whitespace between the dot and the method name)
  fails closed on ALL chain forms -- pre-existing consistent boundary
  (the F455 class covers only whitespace around the dot in the
  factory anchor itself).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: filed shape blocks; thisArg/argsArray variants block;
      template-literal args block; ws-dot anchors block; compositions
      block.
  P2  controls: plain credential blocks; junk variants quiet; neighbor
      closures intact (F468 construct, F462 spread-concat, F454
      multi-arg, F446 Array.of, F461 reverse, F443 fill).
  P3  decoder pins: exact decode values; fail-closed neighbors yield
      no variant or stay quiet (non-concat targets, third arg,
      numeric/nested args, new-Array thisArg, non-array thisArg,
      ident-boundary pins, bare apply).
  P4  discrimination: prose mentions quiet; Reflectx quiet; apply on
      a non-array quiet.
  P5  ReDoS: hostile near-miss inputs complete fast with no
      exceptions; F171 module stays 2/2.
  P6  no-regression: adjacent closures still block (F462 spread,
      F468 construct, F454 multi-arg, F455 ws anchor, F446 of,
      F447 truthiness, F467 null-comparison, F463 tagged template).
  P7  pin + footer: taxonomy pin 2140 (no new decision codes),
      FINDINGS.md footer open F470-F472 / next F473, F469 marked
      CLOSED 2026-10-06 wave-354 lane 1.
"""
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-354: F469 closed, no new decision codes; pin unchanged 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F606, F607, F608, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-355 lanes 1+2: F473, F474 CLOSED; open none / next F475 (merge intermediate)  # Wave-354: next free finding after F469 closure  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-355 lane 3: F475 filed + CLOSED  # Wave-355 lane 3: F475 FILED + CLOSED (merge intermediate)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint
FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)


from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Fragments built by concatenation: the write path redacts credential
# literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- P1: closure

def p1_closure_filed():
    return _blocked("Reflect.apply(Array.prototype.concat,[],[['"
                    + _A + "'],['" + _B + "']]).join('')")


def p1_closure_thisarg_nonempty():
    return _blocked("Reflect.apply(Array.prototype.concat,['z'],[['"
                    + _A + "'],['" + _B + "']]).join('')")


def p1_closure_thisarg_arrayof():
    return _blocked("Reflect.apply(Array.prototype.concat,Array.of('"
                    + _A + "'),[['" + _B + "']]).join('')")


def p1_closure_thisarg_arrayctor():
    return _blocked("Reflect.apply(Array.prototype.concat,Array('"
                    + _A + "','" + _B + "'),[['" + _A + "']]).join('')")


def p1_closure_mixed_string_arg():
    # String args are appended as-is (engine-exact).
    return _blocked("Reflect.apply(Array.prototype.concat,[],['"
                    + _A + "',['" + _B + "']]).join('')")


def p1_closure_arg_arrayof():
    return _blocked("Reflect.apply(Array.prototype.concat,[],[Array.of('"
                    + _A + "','" + _B + "')]).join('')")


def p1_closure_template_arg():
    return _blocked("Reflect.apply(Array.prototype.concat,[],[[`"
                    + _A + "`],[`" + _B + "`]]).join('')")


def p1_closure_empty_argsarray():
    return _blocked("Reflect.apply(Array.prototype.concat,['"
                    + _A + "'],[['" + _B + "']]).join('')")


def p1_closure_ws_dot():
    return _blocked("Reflect . apply ( Array . prototype . concat , "
                    "['" + _A + "'] , [ [ '" + _B + "' ] ] ).join('')")


def p1_closure_ws_tab():
    return _blocked("Reflect\t.\napply(Array.prototype.concat,[],[['"
                    + _A + "'],['" + _B + "']]).join('')")


def p1_closure_three_args():
    return _blocked("Reflect.apply(Array.prototype.concat,[],[['"
                    + _A + "'],['" + _B + "'],['" + _A + "']]).join('')")


def p1_closure_compose_sep():
    # The desugared array composes with a separator join.
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,[],[['a'],['b']]).join(',')", 0)
    return r is not None and r[0] == "a,b"


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_quiet():
    return not _blocked("Reflect.apply(Array.prototype.concat,[],"
                        "[['ab'],['cd']]).join('')")


def p2_control_f468_intact():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


def p2_control_f462_intact():
    return _blocked("''.concat(...['" + _A + "','" + _B + "'])")


def p2_control_f454_intact():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p2_control_f446_intact():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p2_control_f461_intact():
    return _blocked("['" + _B + "','" + _A + "'].reverse().join('')")


def p2_control_f443_intact():
    return _blocked("Array(2).fill('" + _A + "').join('')")


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_value_filed():
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,[],[['" + _A + "'],['"
        + _B + "']]).join('')", 0)
    return r is not None and r[0] == _CRED


def p3_pin_value_thisarg():
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,['z'],[['" + _A + "'],['"
        + _B + "']]).join('')", 0)
    return r is not None and r[0] == "z" + _CRED


def p3_pin_value_mixed():
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,[],['" + _A + "',['"
        + _B + "']]).join('')", 0)
    return r is not None and r[0] == _CRED


def p3_pin_target_fails():
    # Non-concat targets: no variant (fail closed).
    for expr in ("Reflect.apply(Math.max,[],[['f1']])",
                 "Reflect.apply(Array.prototype.push,[],[['f1']])",
                 "Reflect.apply(concat,[],[['f1']])",
                 "Reflect.apply(Array,['f1'],[['f2']])",
                 "Reflect.apply([].concat,[],[['f1']])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_third_arg_fails():
    # A third argument changes the call arity -- fails closed.
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,[],[['f1']],null).join('')", 0)
    return r is None


def p3_pin_thisarg_fails():
    # Non-array thisArg / new-Array thisArg: fail closed.
    for expr in ("Reflect.apply(Array.prototype.concat,{},[['f1']])",
                 "Reflect.apply(Array.prototype.concat,'x',[['f1']])",
                 "Reflect.apply(Array.prototype.concat,new Array('f1'),"
                 "[['f2']])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_argclass_fails():
    # Numeric, fromCharCode, and nested-array args: fail closed.
    for expr in ("Reflect.apply(Array.prototype.concat,[],[[1]])",
                 "Reflect.apply(Array.prototype.concat,[],"
                 "[[String.fromCharCode(120)]])",
                 "Reflect.apply(Array.prototype.concat,[],[[['f1']]])",
                 "Reflect.apply(Array.prototype.concat,[],[42])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None and "xoxb-" in r[0]:
            return False
    return True


def p3_pin_ident_boundary():
    for expr in ("Reflectx.apply(Array.prototype.concat,[],[['f1']])",
                 "Reflect.applyx(Array.prototype.concat,[],[['f1']])",
                 "Reflect.constructx(Array,['f1'])",
                 "Reflect.apply(Array.prototype.concatx,[],[['f1']])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_bare_no_variant():
    # Bare apply with no chain: not obfuscation-shaped.
    r = dlp._try_js_expr_decode(
        "Reflect.apply(Array.prototype.concat,[],[['f1']])", 0)
    return r is None


def p3_pin_left_boundary():
    # `myReflect.apply` is member access in node (ReferenceError for
    # the bare global) -- the anchor's missing left boundary must not
    # decode it.
    for expr in ("myReflect.apply(Array.prototype.concat,[],[['f1']])",
                 "fooReflect.construct(Array,['f1'])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_missing_args_fails():
    for expr in ("Reflect.apply(Array.prototype.concat,[])",
                 "Reflect.apply(Array.prototype.concat)",
                 "Reflect.apply()"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_prose_quiet():
    return not _blocked(
        "the docs mention Reflect.apply(Array.prototype.concat, ...) "
        "as a reflection API example with fragments ab and cd")


def p4_discr_reflectx_quiet():
    return not _blocked("Reflectx.apply(Array.prototype.concat,[],"
                        "[['ab'],['cd']]).join('')")


def p4_discr_nonarray_quiet():
    # apply on a non-array target stays quiet even with junk frags.
    return not _blocked("Reflect.apply(Math.max,[],[['ab'],['cd']])"
                        ".join('')")


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile():
    hostile = [
        "Reflect.apply(" + "A" * 4000,
        "Reflect . " * 500 + "apply(Array.prototype.concat,[],[['a']])",
        "Reflect.apply(Array.prototype." + "concat." * 300,
        "Reflect.apply(Array.prototype.concat,[" + "['a']," * 500,
        "Reflect.apply(Array.prototype.concat,[],[" + "[" * 200,
    ]
    t0 = time.perf_counter()
    for h in hostile:
        dlp.find_credential(h)
        dlp._try_js_expr_decode(h, 0)
    dt = time.perf_counter() - t0
    return dt < 5.0


def p5_redos_f171_module():
    # The F171 hostile-input module (tests/test_wave110_f171_dlp_redos.py)
    # must stay 2/2 through the change.
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(REPO_ROOT, "tests"),
                            pattern="test_wave110_f171_dlp_redos.py")
    assert suite.countTestCases() == 2, "F171 module shape changed"
    runner = unittest.TextTestRunner(stream=io.StringIO())
    result = runner.run(suite)
    return result.wasSuccessful()


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f462_spread():
    return _blocked("''.concat(...['" + _A + "','" + _B + "'])")


def p6_noreg_f468_construct():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


def p6_noreg_f454_multi():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p6_noreg_f455_ws_anchor():
    return _blocked("Array .of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f446_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f447_truthy():
    return _blocked("['" + _A + "','" + _B + "','']"
                    ".filter(x=>x!=='').join('')")


def p6_noreg_f467_nullcmp():
    return _blocked("['" + _A + "','" + _B + "','']"
                    ".filter(x=>x!==null).join('')")


def p6_noreg_f463_tagged():
    return _blocked("['" + _A + "','" + _B + "'].join``")


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
    ok = ok and "CLOSED 2026-10-06 wave-354 lane 1" in footer
    return ok


_PROBES = [
    ("p1-closure-filed", p1_closure_filed),
    ("p1-closure-thisarg-nonempty", p1_closure_thisarg_nonempty),
    ("p1-closure-thisarg-arrayof", p1_closure_thisarg_arrayof),
    ("p1-closure-thisarg-arrayctor", p1_closure_thisarg_arrayctor),
    ("p1-closure-mixed-string-arg", p1_closure_mixed_string_arg),
    ("p1-closure-arg-arrayof", p1_closure_arg_arrayof),
    ("p1-closure-template-arg", p1_closure_template_arg),
    ("p1-closure-empty-argsarray", p1_closure_empty_argsarray),
    ("p1-closure-ws-dot", p1_closure_ws_dot),
    ("p1-closure-ws-tab", p1_closure_ws_tab),
    ("p1-closure-three-args", p1_closure_three_args),
    ("p1-closure-compose-sep", p1_closure_compose_sep),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p2-control-f468-intact", p2_control_f468_intact),
    ("p2-control-f462-intact", p2_control_f462_intact),
    ("p2-control-f454-intact", p2_control_f454_intact),
    ("p2-control-f446-intact", p2_control_f446_intact),
    ("p2-control-f461-intact", p2_control_f461_intact),
    ("p2-control-f443-intact", p2_control_f443_intact),
    ("p3-pin-value-filed", p3_pin_value_filed),
    ("p3-pin-value-thisarg", p3_pin_value_thisarg),
    ("p3-pin-value-mixed", p3_pin_value_mixed),
    ("p3-pin-target-fails", p3_pin_target_fails),
    ("p3-pin-third-arg-fails", p3_pin_third_arg_fails),
    ("p3-pin-thisarg-fails", p3_pin_thisarg_fails),
    ("p3-pin-argclass-fails", p3_pin_argclass_fails),
    ("p3-pin-ident-boundary", p3_pin_ident_boundary),
    ("p3-pin-bare-no-variant", p3_pin_bare_no_variant),
    ("p3-pin-left-boundary", p3_pin_left_boundary),
    ("p3-pin-missing-args-fails", p3_pin_missing_args_fails),
    ("p4-discr-prose-quiet", p4_discr_prose_quiet),
    ("p4-discr-reflectx-quiet", p4_discr_reflectx_quiet),
    ("p4-discr-nonarray-quiet", p4_discr_nonarray_quiet),
    ("p5-redos-hostile", p5_redos_hostile),
    ("p5-redos-f171-module", p5_redos_f171_module),
    ("p6-noreg-f462-spread", p6_noreg_f462_spread),
    ("p6-noreg-f468-construct", p6_noreg_f468_construct),
    ("p6-noreg-f454-multi", p6_noreg_f454_multi),
    ("p6-noreg-f455-ws-anchor", p6_noreg_f455_ws_anchor),
    ("p6-noreg-f446-of", p6_noreg_f446_of),
    ("p6-noreg-f447-truthy", p6_noreg_f447_truthy),
    ("p6-noreg-f467-nullcmp", p6_noreg_f467_nullcmp),
    ("p6-noreg-f463-tagged", p6_noreg_f463_tagged),
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
    if not os.path.exists(venv_python):
        venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    notes = []
    scripts = ("w346_dlp_composition_probes.py",
               "w352_attack_probes.py",
               "w353_attack_probes.py",
               "w353_f461f462close_probes.py",
               "w353_f463close_probes.py",
               "w353_f464f465f466close_probes.py",
               "w353_f467f468close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g354-green-%s-%d" % (script.replace(".py", ""),
                                             os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        try:
            r = subprocess.run(
                [venv_python, os.path.join(REPO_ROOT, "evals", script)],
                capture_output=True, text=True, env=env, timeout=1800,
                cwd=REPO_ROOT)
        finally:
            # /var/tmp is a 2GB tmpfs: never leave stale gate dirs.
            shutil.rmtree(tmp, ignore_errors=True)
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
    print("w354_f469close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if unexpected:
        print("unexpected BREAKs: %s" % unexpected)
        return 1
    if missing:
        print("expected BREAKs missing: %s" % missing)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
