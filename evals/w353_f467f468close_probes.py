#!/usr/bin/env python3
"""Closure probes for F467 + F468 (wave-353 lane 4).

F467 (LOW): a constant-true comparison predicate bypassed the bounded
static JS-expression decoder -- ['frag1','frag2',''].filter(x=>x!==null)
node-evaluates to the credential (''!==null and 'frag'!==null are all
true over the string domain, so the filter is the identity), but the
decoder modeled only bare-Boolean (F443) and truthiness (F447: x!=='',
!!x, x.length>0, x) predicates, so the shape failed closed with zero
decode variants while the plain credential blocked coded. Now modeled:
x!==null | x!==undefined | x!=null (abstract equality also matches
undefined; parsed elements are string literals, never null/undefined,
so all three are provably constant-true -- node-verified v24.20.0) in
both arrow and function(x){return ...;} callback forms, returning the
("all",) spec (keep EVERY element, including "" -- distinct from
("truthy",) which drops ""). Distinct from F459 (positional index
predicates) and F447 (free-variable exclusion).

F468 (LOW): Reflect.construct(Array,['frag1','frag2']) bypassed the
decoder -- the reflection-API factory builds the fragment array
(node: Reflect.construct(Array, X) calls new Array(...X)), but the
decoder modeled neither Reflect nor the construct dispatch. Now
modeled: _js_parse_reflect_construct desugars the bare-Array target
with a fragment-array args list -- a string-literal array literal, the
F446 Array.of(...) factory, or the F443/F454 Array constructor forms
(they compose through the existing parsers, within their own budgets).
Whitespace around the dot is tolerated (F455-class anchor, same
[ \\t\\n\\r] class), matching _JS_EXPR_START. Distinct from F454
(direct multi-arg syntax) and F446 (Array.of).

Neighbor dispositions (node-verified, documented here and in the
FINDINGS.md closure notes):
- x!==null / x!==undefined / x!=null -- modeled (constant-true).
- function(x){return x!==null;} -- modeled (rides with F467's scope note).
- x!=undefined / x!==0 / x!=='a' / x==null / x===null / x!==nullx --
  fail closed (documented scope boundary: rejected, never mis-decoded).
- x==null is constant-FALSE over strings, not a bypass; fails closed.
- Reflect.construct(Array,['a','b']) / (Array,Array.of(...)) /
  (Array,Array('a','b')) -- modeled; desugars to the fragment list.
- Reflect.construct(Array,['a','b'], Array) (newTarget 3rd arg) --
  fail closed.
- Reflect.construct(String, ...) / Reflect.construct(Array) /
  Reflect.construct(Array,[1,2]) -- fail closed (non-Array target /
  missing args / non-string args).
- Reflectx.construct / Reflect.constructx -- fail closed
  (ident-boundary check; node throws TypeError).
- Reflect.apply -- modeled only for the Array.prototype.concat target
  (F469, wave-354); bare-Array or other targets fail closed.
- A bare Reflect.construct(Array,['a','b']) with no chain decodes to
  nothing (not obfuscation-shaped, same as bare Array(...)).
- Reflect.construct(Array,[]) -- the empty join fails closed, exactly
  like the plain [].join(',') literal (pre-existing consistent
  boundary, not a regression).
- `expr . join('')` (whitespace between the dot and the method name)
  fails closed on ALL chain forms -- pre-existing consistent boundary
  (the F455 class covers only whitespace around the dot in the
  factory anchor itself).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: F467 arrow/function/parenthesized forms block coded
      dlp-slack-token; F468 literal/of/constructor args forms block;
      ws-dot anchors block; compositions block.
  P2  controls: plain credential blocks; junk variants quiet; neighbor
      closures intact (F443 .filter(Boolean), F447 truthiness,
      F454 multi-arg, F446 Array.of, F459 positional).
  P3  decoder pins: exact decode values; fail-closed neighbors yield
      no variant or stay quiet (out-of-scope comparisons, non-Array
      targets, third arg, numeric args, bare-Array Reflect.apply target,
      bare construct, ident-boundary pins).
  P4  discrimination: prose mentions quiet; Reflectx quiet;
      comparison on non-array quiet.
  P5  ReDoS: hostile near-miss inputs complete fast with no
      exceptions; F171 module stays 2/2.
  P6  no-regression: adjacent closures still block (F454 multi-arg,
      F455 ws anchor, F446 of, F447 truthiness, F443 fill/filter,
      F459 positional, F460 map-String).
  P7  pin + footer: taxonomy pin 2135 (no new decision codes),
      footer open F461-F466 / next F469, F467+F468 CLOSED entries
      present.
  PZ  green check: adjacent DLP batteries green (depth-1).

Usage:
  ~/workspace/.gov-venv/bin/python evals/w353_f467f468close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-353: F467+F468 closed, no new decision codes; pin unchanged 2135
FOOTER_OPEN = "F471, F472"  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide); wave-352 merge: F454-F460 CLOSED, F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 lane 1: F469 CLOSED locally (merge finalizes tree-wide)  # Wave-354: F470 CLOSED

FOOTER_NEXT = "F473"  # Wave-353: next free finding after F467/F468 closure  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)


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

def p1_closure_f467_arrow():
    return _blocked("['" + _A + "','" + _B + "',''].filter(x=>x!==null)"
                    ".join('')")


def p1_closure_f467_keeps_empty():
    # The identity filter keeps "" -- still assembles the credential.
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x!==null)"
                    ".join('')")


def p1_closure_f467_undefined():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x!==undefined)"
                    ".join('')")


def p1_closure_f467_loose():
    return _blocked("['" + _A + "','" + _B + "'].filter(x=>x!=null)"
                    ".join('')")


def p1_closure_f467_function():
    return _blocked("['" + _A + "','" + _B + "'].filter(function(x)"
                    "{return x!==null;}).join('')")


def p1_closure_f467_paren_param():
    return _blocked("['" + _A + "','" + _B + "'].filter((x)=>x!==null)"
                    ".join('')")


def p1_closure_f467_ws():
    return _blocked("['" + _A + "','" + _B + "'].filter( x => x !== null )"
                    ".join('')")


def p1_closure_f468_literal():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


def p1_closure_f468_of():
    return _blocked("Reflect.construct(Array,Array.of('" + _A + "','" + _B
                    + "')).join('')")


def p1_closure_f468_ctor():
    return _blocked("Reflect.construct(Array,Array('" + _A + "','" + _B
                    + "')).join('')")


def p1_closure_f468_ws_dot():
    return _blocked("Reflect .construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


def p1_closure_f468_ws_both():
    return _blocked("Reflect . construct(Array,['" + _A + "','" + _B + "'])"
                    ".join('')")


def p1_closure_f468_tab():
    return _blocked("Reflect\t.\tconstruct(Array,['" + _A + "','" + _B
                    + "']).join('')")


def p1_closure_f468_compose_filter():
    return _blocked("Reflect.construct(Array,['" + _A + "','" + _B + "'])"
                    ".filter(x=>x!==null).join('')")


def p1_closure_f468_compose_fill():
    return _blocked("Reflect.construct(Array,['" + _A + "','x'])"
                    ".fill('" + _A + "').join('').concat('" + _B + "')")


# ---------------------------------------------------------------- P2: controls

def p2_control_plain():
    return _blocked(_CRED)


def p2_control_junk_quiet():
    return (not _blocked("['ab','cd'].filter(x=>x!==null).join('')")
            and not _blocked("['ab','cd'].filter(x=>x!==undefined).join('')")
            and not _blocked("['ab','cd'].filter(function(x)"
                             "{return x!=null;}).join('')")
            and not _blocked("Reflect.construct(Array,['ab','cd']).join('')")
            and not _blocked("Reflect .construct(Array,['ab','cd'])"
                             ".join('')"))


def p2_control_f443_intact():
    return _blocked("['" + _A + "','','" + _B + "'].filter(Boolean)"
                    ".join('')")


def p2_control_f447_intact():
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x!=='')"
                    ".join('')")


def p2_control_f454_intact():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p2_control_f446_intact():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p2_control_f459_intact():
    return _blocked("['" + _A + "','" + _B + "','x'].filter((x,i)=>i<2)"
                    ".join('')")


# ---------------------------------------------------------------- P3: decoder pins

def p3_pin_f467_value():
    r = dlp._try_js_expr_decode("['f1','f2',''].filter(x=>x!==null)"
                                ".join('')", 0)
    return r is not None and r[0] == "f1f2"


def p3_pin_f467_keeps_empty_value():
    # The "" element is KEPT (identity), unlike ("truthy",) which drops it.
    r = dlp._try_js_expr_decode("['f1','','f2'].filter(x=>x!==null)"
                                ".join('-')", 0)
    return r is not None and r[0] == "f1--f2"


def p3_pin_f468_value():
    r = dlp._try_js_expr_decode("Reflect.construct(Array,['f1','f2'])"
                                ".join('')", 0)
    return r is not None and r[0] == "f1f2"


def p3_pin_f468_of_value():
    r = dlp._try_js_expr_decode("Reflect.construct(Array,Array.of('f1','f2'))"
                                ".join('-')", 0)
    return r is not None and r[0] == "f1-f2"


def p3_pin_f467_scope_fails():
    # Out-of-scope comparisons fail closed: no decode variant at all.
    for body in ("x=>x!==0", "x=>x!=='a'", "x=>x!=undefined",
                 "x=>x==null", "x=>x===null", "x=>x!==nullx",
                 "x=>x!=nullx"):
        r = dlp._try_js_expr_decode("['f1','f2'].filter(" + body
                                    + ").join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_f467_shadow_fails():
    # A param named `undefined` shadows the keyword: node reads
    # `undefined!==undefined` as param-vs-param (always false), so the
    # constant-true reading fails closed rather than mis-decoding.
    # (`undefined=>undefined!==null` is constant-true in node, but the
    # guard conservatively fails it closed too -- documented.)
    for body in ("undefined=>undefined!==undefined",
                 "undefined=>undefined!==null",
                 "null=>null!==null"):
        r = dlp._try_js_expr_decode("['f1','f2'].filter(" + body
                                    + ").join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_f468_target_fails():
    # Non-Array targets / missing args / numeric args: no variant.
    for expr in ("Reflect.construct(String,['f1','f2'])",
                 "Reflect.construct(Object,['f1','f2'])",
                 "Reflect.construct(Array)",
                 "Reflect.construct(Array,[1,2])",
                 "Reflect.construct(Array,['f1',2])",
                 "Reflect.construct(Array,['f1','f2'], Array)"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


def p3_pin_f468_apply_quiet():
    # Reflect.apply with a bare-Array target is still out of scope: no
    # variant, stays quiet (F469 models only Array.prototype.concat).
    r = dlp._try_js_expr_decode("Reflect.apply(Array,['f1','f2'])"
                                ".join('')", 0)
    return r is None


def p3_pin_f468_bare_no_variant():
    # Bare construct with no chain: not obfuscation-shaped.
    r = dlp._try_js_expr_decode("Reflect.construct(Array,['f1','f2'])", 0)
    return r is None


def p3_pin_f468_ident_boundary():
    for expr in ("Reflectx.construct(Array,['f1','f2'])",
                 "Reflect.constructx(Array,['f1','f2'])",
                 "Reflect.construct(Arrayx,['f1','f2'])"):
        r = dlp._try_js_expr_decode(expr + ".join('')", 0)
        if r is not None:
            return False
    return True


# ---------------------------------------------------------------- P4: discrimination

def p4_discr_prose_quiet():
    return (not _blocked("the filter(x=>x!==null) predicate is constant")
            and not _blocked("use Reflect.construct(Array, xs) here")
            and not _blocked("x!==null is true for every string"))


def p4_discr_reflectx_quiet():
    return not _blocked("Reflectx.construct(Array,['" + _A + "','" + _B
                        + "']).join('')")


def p4_discr_cmp_on_string_quiet():
    # The comparison predicate only parses as a .filter callback.
    return not _blocked("'ab'.filter(x=>x!==null)")


# ---------------------------------------------------------------- P5: ReDoS

def p5_redos_hostile():
    hostile = [
        "Reflect." + " " * 5000 + "construct(",
        "Reflect.construct(Array," + "['a'," * 2000,
        "['a','b'].filter(x=>x!" + "=" * 5000 + "null)",
        "Reflect.construct(" * 200,
        "['a'].filter(" + "x=>x!==null).filter(" * 200,
        "Reflect.construct(Array,['a'" + ",'b'" * 5000 + "])",
    ]
    t0 = time.perf_counter()
    for h in hostile:
        dlp.find_credential(h)
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
    runner = unittest.TextTestRunner(stream=open(os.devnull, "w"))
    result = runner.run(suite)
    return result.wasSuccessful()


# ---------------------------------------------------------------- P6: no-regression

def p6_noreg_f454_multi():
    return _blocked("Array('" + _A + "','" + _B + "').join('')")


def p6_noreg_f455_ws_anchor():
    return _blocked("Array .of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f446_of():
    return _blocked("Array.of('" + _A + "','" + _B + "').join('')")


def p6_noreg_f447_truthy():
    return _blocked("['" + _A + "','','" + _B + "'].filter(x=>x!=='')"
                    ".join('')")


def p6_noreg_f443_filter_boolean():
    return _blocked("['" + _A + "','','" + _B + "'].filter(Boolean)"
                    ".join('')")


def p6_noreg_f443_fill():
    return _blocked("Array(2).fill('" + _A + "').join('').concat('" + _B
                    + "')")


def p6_noreg_f459_positional():
    return _blocked("['" + _A + "','" + _B + "','x'].filter((x,i)=>i!==2)"
                    ".join('')")


def p6_noreg_f460_map_string():
    return _blocked("['" + _A + "','" + _B + "'].map(String).join('')")


# ---------------------------------------------------------------- P7: pin + footer

def p7_pin_and_footer():
    footer_path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(footer_path, encoding="utf-8") as f:
        footer = f.read()
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2135
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    ok = ok and "CLOSED 2026-10-06 wave-353 lane 4" in footer
    return ok


_PROBES = [
    ("p1-closure-f467-arrow", p1_closure_f467_arrow),
    ("p1-closure-f467-keeps-empty", p1_closure_f467_keeps_empty),
    ("p1-closure-f467-undefined", p1_closure_f467_undefined),
    ("p1-closure-f467-loose", p1_closure_f467_loose),
    ("p1-closure-f467-function", p1_closure_f467_function),
    ("p1-closure-f467-paren-param", p1_closure_f467_paren_param),
    ("p1-closure-f467-ws", p1_closure_f467_ws),
    ("p1-closure-f468-literal", p1_closure_f468_literal),
    ("p1-closure-f468-of", p1_closure_f468_of),
    ("p1-closure-f468-ctor", p1_closure_f468_ctor),
    ("p1-closure-f468-ws-dot", p1_closure_f468_ws_dot),
    ("p1-closure-f468-ws-both", p1_closure_f468_ws_both),
    ("p1-closure-f468-tab", p1_closure_f468_tab),
    ("p1-closure-f468-compose-filter", p1_closure_f468_compose_filter),
    ("p1-closure-f468-compose-fill", p1_closure_f468_compose_fill),
    ("p2-control-plain", p2_control_plain),
    ("p2-control-junk-quiet", p2_control_junk_quiet),
    ("p2-control-f443-intact", p2_control_f443_intact),
    ("p2-control-f447-intact", p2_control_f447_intact),
    ("p2-control-f454-intact", p2_control_f454_intact),
    ("p2-control-f446-intact", p2_control_f446_intact),
    ("p2-control-f459-intact", p2_control_f459_intact),
    ("p3-pin-f467-value", p3_pin_f467_value),
    ("p3-pin-f467-keeps-empty-value", p3_pin_f467_keeps_empty_value),
    ("p3-pin-f468-value", p3_pin_f468_value),
    ("p3-pin-f468-of-value", p3_pin_f468_of_value),
    ("p3-pin-f467-scope-fails", p3_pin_f467_scope_fails),
    ("p3-pin-f467-shadow-fails", p3_pin_f467_shadow_fails),
    ("p3-pin-f468-target-fails", p3_pin_f468_target_fails),
    ("p3-pin-f468-apply-quiet", p3_pin_f468_apply_quiet),
    ("p3-pin-f468-bare-no-variant", p3_pin_f468_bare_no_variant),
    ("p3-pin-f468-ident-boundary", p3_pin_f468_ident_boundary),
    ("p4-discr-prose-quiet", p4_discr_prose_quiet),
    ("p4-discr-reflectx-quiet", p4_discr_reflectx_quiet),
    ("p4-discr-cmp-on-string-quiet", p4_discr_cmp_on_string_quiet),
    ("p5-redos-hostile", p5_redos_hostile),
    ("p5-redos-f171-module", p5_redos_f171_module),
    ("p6-noreg-f454-multi", p6_noreg_f454_multi),
    ("p6-noreg-f455-ws-anchor", p6_noreg_f455_ws_anchor),
    ("p6-noreg-f446-of", p6_noreg_f446_of),
    ("p6-noreg-f447-truthy", p6_noreg_f447_truthy),
    ("p6-noreg-f443-filter-boolean", p6_noreg_f443_filter_boolean),
    ("p6-noreg-f443-fill", p6_noreg_f443_fill),
    ("p6-noreg-f459-positional", p6_noreg_f459_positional),
    ("p6-noreg-f460-map-string", p6_noreg_f460_map_string),
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
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    notes = []
    scripts = ("w346_dlp_composition_probes.py",
               "w350_attack_probes.py",
               "w351_attack_probes.py",
               "w352_attack_probes.py",
               "w350_f446close_probes.py",
               "w350_f447f448close_probes.py",
               "w350_f449f450close_probes.py",
               "w351_f451close_probes.py",
               "w351_f452close_probes.py",
               "w351_f453close_probes.py",
               "w352_f454f455close_probes.py",
               "w352_f456close_probes.py",
               "w352_f457close_probes.py",
               "w352_f458f459f460close_probes.py")
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
    print("w353_f467f468close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
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
