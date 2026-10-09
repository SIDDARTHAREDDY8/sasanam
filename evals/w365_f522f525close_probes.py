#!/usr/bin/env python3
"""Wave-365 F522/F525 closure battery (lane 2).

Two LOW findings from wave-364 attack round 32 (node v24.20.0 ->
credential, decoder missed on the wave-364-merged base):

F522: Reflect.apply with an IIFE-evaluated function target. F519 models
  Reflect.apply with arrow/fn-expr LITERAL targets, but the target can
  be the result of an immediately-invoked function expression:
    Reflect.apply((() => (a,b)=>a+b)(), null, ['f1','f2'])
    Reflect.apply((function(){return (a,b)=>a+b})(), null, ['f1','f2'])
  Both node-evaluate to the exact credential. Distinct from F519
  (literal targets -- an IIFE call result is a different
  value-production mechanism) and F521 (.bind-bound targets).

F525: Object.getOwnPropertyNames / Object.getOwnPropertyDescriptors
  enumeration indirection. F517 models Object.entries/Object.keys/for-in,
  but the sibling enumeration builtins are separate (F500/F505
  precedent, different builtins are separate findings):
    Object.getOwnPropertyNames({'f1':'x','f2':'y'}).join('')
    Object.values(Object.getOwnPropertyDescriptors({0:'f1',1:'f2'})).map(d=>d.value).join('')
  Both node-evaluate to the exact credential. Distinct from F517
  (different builtins) and F510 (Object.values on plain objects).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

F522 -- `_js_parse_iife_fn_target`, tried first at the Reflect.apply
  target position inside `_js_parse_reflect_apply_fn` (falls through to
  the F519 literal-target parse on _JSExprFail; the IIFE parse only
  succeeds where the literal parse fails, so no previously-decoded
  input changes behavior). Node-exact desugar: `(() => FN)()` and
  `(function(){return FN})()` evaluate to FN itself, so the result is
  the F519 parameter-ordered concatenation. The IIFE must have an
  EMPTY parameter list and a zero-argument immediate invocation; FN
  is parsed by `_js_parse_fn_target` (literal arrow or fn-expr only).
  Fail closed: non-empty IIFE params, invocation with arguments,
  nested IIFEs, IIFEs returning non-functions, async/generator IIFEs.

F525 -- `_js_parse_object_gopn` parses `Object.getOwnPropertyNames(OBJ)`
  / `Object['getOwnPropertyNames'](OBJ)` on the F510/F517
  enumeration-source classes, desugared to the ordered key list
  (integer indices ascending, then insertion order -- the same
  permutation Object.keys uses; the modeled sources are
  all-enumerable, so the non-enumerable distinction cannot arise).
  `_js_parse_object_gopds_values` parses the chain
  `Object.values(Object.getOwnPropertyDescriptors(OBJ)).map(D=>D.value)`
  (dot and F480 bracket-string forms), desugared to the ordered value
  list: the modeled sources are data-descriptor-only (getters/setters/
  methods fail closed in the literal parser), so `d.value` is exactly
  the literal value. The `.map` projection is mandatory (F517 entries
  discipline) and accepts `d=>d.value`, `(d)=>d.value`,
  `d=>{return d.value;}`, `function(d){return d.value;}` -- anything
  else fails closed. `_JS_EXPR_START`'s Object alternative gains
  `getOwnPropertyNames`/`getOwnPropertyDescriptors`
  (literal-alternation only); 12 anchor-pin batteries repointed.

Fail-closed boundaries (documented): F522 -- see above; F525 -- bare
  `Object.values(Object.getOwnPropertyDescriptors(OBJ))` without the
  map, non-`.value` projections, getters in the literal, non-literal
  sources, extra args; `Object.getOwnPropertySymbols` unmodeled
  (out-of-filed-scope). F522 additionally fails closed on IIFEs calling
  other functions (the FN position must be a literal). Junk stays quiet.

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

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2144  # Wave-365 lane 2; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


# ------------------------------------------------------------- P1: closure
def p1_f522_filed_shapes():
    shapes = [
        "Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((function(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F522 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f522_variants():
    shapes = [
        # Named function-expression IIFE.
        "Reflect.apply((function foo(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (_A1, _A2),
        # Arrow IIFE returning a function-expression literal.
        "Reflect.apply((() => function(a,b){return a+b})(), null, ['%s','%s'])" % (_A1, _A2),
        # Trailing semicolon in the IIFE body.
        "Reflect.apply((function(){return (a,b)=>a+b;})(), null, ['%s','%s'])" % (_A1, _A2),
        # Whitespace-tolerant.
        "Reflect.apply( ( () => (a , b) => a+b ) ( ) , null , [ '%s' , '%s' ] )" % (_A1, _A2),
        # Bracket-string apply member (F504 form).
        "Reflect['apply']((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A1, _A2),
        # Parameter reordering through the IIFE path (body a+b over
        # params (b,a) with args ['f2','f1']).
        "Reflect.apply((() => (b,a)=>a+b)(), null, ['%s','%s'])" % (_A2, _A1),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F522 variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_f525_filed_shapes():
    shapes = [
        "Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F525 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f525_variants():
    shapes = [
        "Object['getOwnPropertyNames']({'%s':'x','%s':'y'}).join('')" % (_A1, _A2),
        "Object.getOwnPropertyNames(Object.freeze({'%s':'x','%s':'y'})).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map((d)=>d.value).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>{return d.value;}).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(function(d){return d.value;}).join('')" % (_A1, _A2),
        "Object['values'](Object['getOwnPropertyDescriptors']({0:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A1, _A2),
        # Integer-index ordering (node: indices ascending, then insertion).
        "Object.values(Object.getOwnPropertyDescriptors({b:'x',2:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A2, _A1),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F525 variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_compositions():
    # Previously-closed behavior unchanged; sibling wave-365 closures
    # (F521/F523/F524) now block (merge).
    held = [
        # F519 literal targets (independence).
        "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (_A1, _A2),
        # F517 enumeration (independence).
        "Object.keys({'%s':'x','%s':'y'}).join('')" % (_A1, _A2),
        "Object.entries({0:'%s',1:'%s'}).map(p=>p[1]).join('')" % (_A1, _A2),
        "(function(){var r='';var o={m:'%s',n:'%s'};for(var k in o)r+=o[k];return r})()" % (_A1, _A2),
        # F510 values (independence).
        "Object.values({0:'%s',1:'%s'}).join('')" % (_A1, _A2),
        # F489 string-returning IIFE (independence -- F522 only models
        # function-returning IIFEs at the Reflect.apply target).
        "(function(){return '%s'+'%s'})()" % (_A1, _A2),
        # F496 Reflect.ownKeys dispatch (independence).
        "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (_A1, _A2),
        # F521 .bind-bound targets (CLOSED wave-365 lane 1).
        "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        # F523 triple-nested bracket keys (CLOSED wave-365 lane 3).
        "'%s'[[[['concat'][0]]][0]]('%s')" % (_A1, _A2),
        # F524 destructured arguments (CLOSED wave-365 lane 3).
        "(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A1, _A2),
    ]
    open_misses = [
    ]
    bad = [s for s in held if not _blocked(s)]
    bad += [s for s in open_misses if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions behave" % (len(held) + len(open_misses) - len(bad),
                                           len(held) + len(open_misses)))


# ---------------------------------------------------------- P2: boundaries
def p2_f522_bounds():
    # All fail closed (miss): the decoder never mis-decodes.
    bounds = [
        # Nested IIFE -- FN must be a literal arrow/fn-expr.
        "Reflect.apply((() => (() => (a,b)=>a+b)())(), null, ['%s','%s'])" % (_A1, _A2),
        # IIFE with params.
        "Reflect.apply(((x) => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A1, _A2),
        # Invocation with arguments.
        "Reflect.apply((() => (a,b)=>a+b)(1), null, ['%s','%s'])" % (_A1, _A2),
        # Async IIFE (engine: Promise target, Reflect.apply throws).
        "Reflect.apply((async () => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A1, _A2),
        # Generator IIFE (engine: generator target, Reflect.apply throws).
        "Reflect.apply((function*(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (_A1, _A2),
        # IIFE returning a non-function (engine: Reflect.apply throws).
        "Reflect.apply((() => 'f1')(), null, ['%s','%s'])" % (_A1, _A2),
        # IIFE returning an additive expression, not a function.
        "Reflect.apply((() => (a+b))(), null, ['%s','%s'])" % (_A1, _A2),
        # IIFE calling another function (the FN position must be a
        # literal arrow/fn-expr, not a call).
        "Reflect.apply((() => foo((a,b)=>a+b))(), null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((function(){return bar((a,b)=>a+b)})(), null, ['%s','%s'])" % (_A1, _A2),
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F522 bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


def p2_f525_bounds():
    bounds = [
        # Bare descriptors without the mandatory map projection.
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).join('')" % (_A1, _A2),
        # Identity projection (engine keeps descriptors).
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d).join('')" % (_A1, _A2),
        # Non-.value projection.
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d.writable).join('')" % (_A1, _A2),
        # Getter in the literal (engine: d.value undefined).
        "Object.values(Object.getOwnPropertyDescriptors({get x(){return '%s'}})).map(d=>d.value).join('')" % _A1,
        # Non-literal source.
        "Object.values(Object.getOwnPropertyDescriptors(foo)).map(d=>d.value).join('')",
        "Object.getOwnPropertyNames(foo).join('')",
        # Extra args.
        "Object.getOwnPropertyNames({'%s':'x'}, 1).join('')" % _A1,
        # getOwnPropertySymbols: out-of-filed-scope, unmodeled.
        "Object.getOwnPropertySymbols({}).length",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F525 bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


def p2_junk_quiet():
    junks = [
        "Reflect.apply((() => (a,b)=>a+b)(), null, ['ab','cd'])",
        "Object.getOwnPropertyNames({'ab':'x','cd':'y'}).join('')",
        "Object.values(Object.getOwnPropertyDescriptors({0:'ab',1:'cd'})).map(d=>d.value).join('')",
    ]
    bad = [s for s in junks if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d junk quiet" % (len(junks) - len(bad), len(junks)))


# ------------------------------------------------- P3: differential / pins
def _node_eval(shapes):
    js = ("const out=[];\n" +
          "".join("try{out.push(JSON.stringify(%s))}catch(e){out.push('THROWS')}\n" % s
                  for s in shapes) +
          "console.log(out.join('\\n'))")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=120)
    if r.returncode != 0:
        raise RuntimeError("node failed: " + r.stderr[:300])
    return r.stdout.split("\n")


def p3_node_differential():
    shapes = [
        "Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((function(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (_A1, _A2),
        "Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A1, _A2),
        "Object.values(Object.getOwnPropertyDescriptors({b:'x',2:'%s',1:'%s'})).map(d=>d.value).join('')" % (_A2, _A1),
        "Object.getOwnPropertyNames({b:'x',2:'q',10:'y',1:'%s',a:'z'}).join('')" % _A1,
    ]
    expected = _node_eval(shapes)
    bad = []
    for s, node_out in zip(shapes, expected):
        want = json.loads(node_out)
        got = _decoded(s)
        if got != want:
            bad.append((s, got, want))
    return ("HELD" if not bad else "BREAK",
            "%d/%d node byte-identical" % (len(shapes) - len(bad), len(shapes)))


def p3_no_new_regexes():
    n = sum(1 for line in open(os.path.join(REPO_ROOT, "gov", "dlp.py"))
            if "re.compile" in line)
    assert n == 28, "re.compile count=%d, want 28" % n
    # The Object anchor alternative pins the F525 widening exactly
    # (literal-alternation only).
    assert ("getOwnPropertyNames|getOwnPropertyDescriptors" in
            dlp._JS_EXPR_START.pattern), "anchor missing F525 widening"
    return ("HELD", "28 re.compile; anchor pins F525 widening")


def p3_perf_bound():
    """F512: the new parse sites stay inside the attempt budget."""
    import time
    payload = '"a".concat(' * 600 + "['%s','%s'].join('')" % (_A1, _A2)
    t0 = time.time()
    hit = _blocked(payload)
    dt = time.time() - t0
    ok = (not hit) and dt < 5.0
    return ("HELD" if ok else "BREAK",
            "starved=%s dt=%.2f" % (not hit, dt))


# ------------------------------------------------------- P4: pin and footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2144, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F522" in text and "F525" in text, "F522/F525 missing from FINDINGS.md"
    assert "Status: CLOSED 2026-10-07 wave-365 lane 2" in text, "close status missing"
    assert "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text, "lane-local footer wrong"  # Wave-367 merge: F537-F546 open, next F547; was: Wave-366 lane 3: F528, F529 CLOSED locally  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    assert "Next free finding: **F795**" in text, "next-free wrong"  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD", "pin=2140; F522/F525 closed; footer open F526,F527,F530/next F531")


PROBES = [
    ("p1-f522-filed-shapes", p1_f522_filed_shapes),
    ("p1-f522-variants", p1_f522_variants),
    ("p1-f525-filed-shapes", p1_f525_filed_shapes),
    ("p1-f525-variants", p1_f525_variants),
    ("p1-compositions", p1_compositions),
    ("p2-f522-bounds", p2_f522_bounds),
    ("p2-f525-bounds", p2_f525_bounds),
    ("p2-junk-quiet", p2_junk_quiet),
    ("p3-node-differential", p3_node_differential),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-perf-bound", p3_perf_bound),
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
    scripts = ("w364_f522_redfirst.py",
               "w364_f525_redfirst.py",
               "w364_attack_probes.py",
               "w363_attack_probes.py",
               "w360_f489f490close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g365-green-%s-%d" % (script.replace(".py", ""),
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
    print("w365_f522f525close: starting %d probes" % len(PROBES))
    results = []
    for pid, fn in PROBES:
        v, note = _safe(pid, fn)
        print("%s: %s (%s)" % (pid, v, note))
        results.append((pid, v, note))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if n_break or n_err:
        print("green check: skipped (red)")
        return 1
    gc = _green_check()
    print("green check: %s" % gc)
    if gc.startswith("green check FAILED"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
