#!/usr/bin/env python3
"""Wave-364 F513/F519 closure battery (lane 1).

Two LOW findings from wave-363 attack round 31 (node v24.20.0 ->
credential, decoder missed on the wave-363-merged base):

F513: Reflect.apply reached through .bind indirection. F506 models
  Reflect.apply invoked through Function.prototype.call/.apply
  higher-order dispatch, but .bind never invokes -- it returns a
  bound callable that is then invoked directly, so the dispatch-target
  anchor never appears:
    Reflect.apply.bind(Reflect)([].concat, [], ['f1','f2']).join('')
    Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['f1','f2']).join('')
  Both node-evaluate to the exact credential. Distinct from F506
  (call/apply dispatch -- different builtin, different mechanism).

F519: Reflect.apply with a function-valued target. F469/F504/F506 all
  model Reflect.apply with Array.prototype.concat-family targets, but
  the TARGET itself can be an arrow function or function expression:
    Reflect.apply((a,b)=>a+b, null, ['f1','f2'])
    Reflect.apply(function(a,b){return a+b}, null, ['f1','f2'])
  Both node-evaluate to the exact credential. Distinct from F506
  (indirection reaching Reflect.apply) and F469 (concat targets).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

F513 -- two parse sites, one desugar:
  * `_js_parse_reflect_call` gains a `.bind(` intercept after the
    `apply` member is confirmed (dot, `?.`, or F504 bracket-string
    member -- engine-identical): `_js_parse_f513_reflect_bind`
    parses `.bind(Reflect)` then requires the immediate invocation,
    whose `(T, thisArg, argsList)` triple is parsed by
    `_js_parse_f506_triple` (the F469/F504 target and argument
    classes). The bind receiver must be the literal `Reflect`
    namespace (the engine ignores Reflect.apply's this-value).
  * `_js_parse_function_dispatch` accepts `bind` as the inner
    dispatch member: `_js_parse_f513_bind_dispatch` parses
    `Function.prototype.bind.call(Reflect.apply, Reflect)` /
    `.bind.apply(Reflect.apply, [Reflect])` (the outer call/apply
    pair only changes how the bind arguments arrive -- node v24.20.0
    verified), then the immediate invocation triple, again via
    `_js_parse_f506_triple`. A non-Reflect.apply target falls
    through (None) to the normal primary path.

F519 -- `_js_peek_reflect_apply_target` returns "fn" for `(`/`function`
  target heads; `_js_parse_reflect_apply_fn` re-parses the
  `Reflect.apply` head (dot or F504 bracket member), then
  `_js_parse_fn_target` parses `(p1, p2) => BODY` (parenthesized
  params required) or `function(p1, p2){return BODY}` (optional name,
  optional trailing `;`; generators fail closed). The body must be
  exactly `operand (+ operand)*` over declared parameter names
  (`_js_parse_fn_additive_body`); the thisArg is parsed and discarded
  (the modeled bodies cannot observe `this` -- F483 precedent); the
  argsArray is a string-literal-only list whose arity must match the
  parameter count (node coerces missing params to undefined --
  conservative fail-closed). The result is the parameter-ordered
  concatenation (all-string `+` is pure concat, node-exact).

Fail-closed boundaries (documented): F513 -- bind with bound args
  (shifts the triple's argument positions, so the static triple grammar
  no longer applies -- conservative), bind with no immediate
  call, non-Reflect receivers, non-concat targets, Reflect.get /
  Reflect.construct targets, extra args; F519 -- arity mismatch,
  non-string args, body literals / `this` / calls / member access /
  parens, duplicate params, undeclared names, generators, async,
  bare `p =>` params, object-literal thisArgs (the additive grammar
  cannot parse object literals). `Reflect?.apply` on the F519 path misses --
  exact parity with the direct form (both miss on the base too).
  Junk stays quiet.

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

TAXONOMY_PIN = 2135  # Wave-364 lane 1; pin stays 2135


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f513_filed_shapes():
    shapes = [
        "Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F513 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f519_filed_shapes():
    shapes = [
        "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F519 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_combos_and_variants():
    shapes = [
        # F513: outer=apply variant (bind args arrive as one array)
        "Function.prototype.bind.apply(Reflect.apply, [Reflect])([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: bracket-string member on the Reflect.apply head (F482)
        "Reflect['apply'].bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: ?.bind (F490 -- Reflect.apply provably non-null)
        "Reflect.apply?.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: whitespace between the bound call and the invocation
        "Reflect.apply.bind(Reflect) ([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: F504 member-key forms on the bind-dispatch target
        "Function.prototype.bind.call(Reflect['apply'], Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: F469 prototype-concat target class through bind
        "Reflect.apply.bind(Reflect)(Array.prototype.concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F513: Array-constructor thisArg (direct-form class)
        "Reflect.apply.bind(Reflect)([].concat, Array('%s','%s'), ['a']).join('')" % (_A1, _A2),
        # F519: single param, reversed params (args swapped so the
        # assembly still recovers the credential -- param-order fidelity),
        # repeated param
        "Reflect.apply((a)=>a, null, ['%s'])" % (_A1 + _A2),
        "Reflect.apply((a,b)=>b+a, null, ['%s','%s'])" % (_A2, _A1),
        "Reflect.apply((a)=>a+a, null, ['%s'])" % (_A1,),
        # F519: three params
        "Reflect.apply((a,b,c)=>a+b+c, null, ['%s','%s','%s'])" % (_A1, _A2, "zz"),
        # F519: named function expression + trailing semicolon
        "Reflect.apply(function foo(a,b){return a+b;}, null, ['%s','%s'])" % (_A1, _A2),
        # F519: whitespace tolerance
        "Reflect.apply( ( a , b ) => a + b , null , [ '%s' , '%s' ] )" % (_A1, _A2),
        # F519: bracket member on the apply head (F504)
        "Reflect['apply']((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d combos/variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_compositions():
    # F506 call/apply indirection still blocks; F469/F504 direct forms
    # intact; F491 computed-key get stays fail-closed; F518 and F514
    # (narrowed) stay OPEN; F469 concat target on the F519 path misses
    # (unmodeled target class -- the direct form handles it).
    cases = [
        ("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2), True),
        ("Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (_A1, _A2), True),
        ("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A1, _A2), True),
        ("Function.prototype.call.call(Array.prototype.concat, [], '%s', '%s').join('')" % (_A1, _A2), True),
        ("Reflect.get(Reflect, ['ap'+'ply'])", False),  # F491 boundary
        ("var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (_A1, _A2), False),  # F518 OPEN
        ("new String('%s')[['concat'][0]]('%s')" % (_A1, _A2), False),  # F514 narrowed OPEN
        # .length on a decoded string flags -- parity with the F454
        # direct form (verified on the base tree).
        ("Reflect.apply((a,b)=>a+b, null, ['%s','%s']).length" % (_A1, _A2), True),
    ]
    bad = [c for c, want in cases if _verdict(c, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions hold" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P2: fail-closed
def p2_f513_bounds():
    cases = [
        # bind with bound args shifts the triple's argument positions
        # (conservative miss)
        "Reflect.apply.bind(Reflect, 'x')([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # bound function with no immediate call: not a decodable value
        "Reflect.apply.bind(Reflect)",
        # non-Reflect bind receiver (conservative)
        "Reflect.apply.bind({})([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflectx)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # non-concat targets through bind
        "Reflect.apply.bind(Reflect)(Math.max, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)(['x'].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # Reflect.get / Reflect.construct are not apply targets
        "Function.prototype.bind.call(Reflect.get, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.bind.call(Reflect.construct, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # non-Reflect.apply dispatch target falls through (miss)
        "Function.prototype.bind.call(Array.prototype.concat, [], '%s', '%s').join('')" % (_A1, _A2),
        # bind as the OUTER dispatch: bound fn with no invocation
        "Function.prototype.call.bind(Reflect.apply, Reflect)",
        # missing / extra invocation args
        "Reflect.apply.bind(Reflect)().join('')",
        "Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s'], 1).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)([].concat, []).join('')",
        # deeper chain: one double dispatch only (documented residual)
        "Function.prototype.bind.call.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # xReflect prefix is member access, never the global (F469)
        "xReflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # junk stays quiet
        "Reflect.apply.bind(Reflect)([].concat, [], ['ab','cd']).join('')",
        "Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['ab','cd']).join('')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F513 bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p2_f519_bounds():
    cases = [
        # arity mismatch: node coerces to undefined (conservative miss)
        "Reflect.apply((a,b)=>a+b, null, ['%s'])" % _A1,
        "Reflect.apply((a)=>a, null, ['%s','%s'])" % (_A1, _A2),
        # body with a literal / this / call / member: arbitrary code
        "Reflect.apply((a,b)=>a+'x', null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((a,b)=>this+a, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((a,b)=>a.concat(b), null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((a,b)=>(a+b), null, ['%s','%s'])" % (_A1, _A2),
        # duplicate params (node: SyntaxError for arrows, last-wins for
        # sloppy functions; conservative miss)
        "Reflect.apply((a,a)=>a, null, ['%s','%s'])" % (_A1, _A2),
        # undeclared name in body
        "Reflect.apply((a)=>b, null, ['%s'])" % _A1,
        # generator / async: not modeled
        "Reflect.apply(function*(a,b){return a+b}, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply(async (a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2),
        # bare single param without parens: outside filed scope --
        # verified fail-closed by the white-box probe below (a literal
        # credential here would trip the strict rule directly)
        # non-string args
        "Reflect.apply((a,b)=>a+b, null, [42, 'x'])",
        # non-function target heads still fail closed
        "Reflect.apply(Math.max, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply(null, null, ['%s','%s'])" % (_A1, _A2),
        # extra args
        "Reflect.apply((a,b)=>a+b, null, ['%s','%s'], 1)" % (_A1, _A2),
        # object-literal thisArg: the additive grammar cannot parse
        # object literals (documented -- the filed shapes use null)
        "Reflect.apply((a,b)=>a+b, {x:1}, ['%s','%s'])" % (_A1, _A2),
        # junk stays quiet (reversed assembly is not the credential)
        "Reflect.apply((a,b)=>b+a, null, ['ab','cd'])",
        "Reflect.apply((a,b)=>a+b, null, ['ab','cd'])",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F519 bounds fail closed" % (len(cases) - len(bad), len(cases)))


def p2_f519_bare_arrow_rejected():
    """White-box: `a=>a` (bare param, no parens) is rejected by the
    function-target parser -- the F519 filed scope requires the
    parenthesized parameter list."""
    try:
        dlp._js_parse_fn_target("a=>a, null", 0, 0, {"ops": 0, "parts": 0})
    except dlp._JSExprFail:
        return ("HELD", "bare a=>a rejected by _js_parse_fn_target")
    return ("BREAK", "bare a=>a parsed as function target")


# ------------------------------------------------------- P3: node-exactness
def p3_node_differential():
    """Node v24.20.0 vs decoder, byte-identical on F513/F519 shapes."""
    shapes = [
        "Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.bind.apply(Reflect.apply, [Reflect])([].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)(Array.prototype.concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (_A1, _A2),
        "Reflect.apply((a,b,c)=>a+b+c, null, ['%s','%s','%s'])" % (_A1, _A2, "zz"),
        "Reflect.apply((a)=>a, null, ['%s'])" % (_A1 + _A2),
    ]
    js = "const S=[\n" + ",\n".join(
        "eval(%r)" % s for s in shapes) + "\n];\n"
    js += "console.log(JSON.stringify(S));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[-200:])
    node_vals = json.loads(r.stdout)
    bad = []
    for shape, nv in zip(shapes, node_vals):
        dec = dlp._try_js_expr_decode(shape, 0)
        dv = dec[0] if dec else None
        if dv != nv:
            bad.append(shape[:48])
    return ("HELD" if not bad else "BREAK",
            "%d/%d node byte-identical" % (len(shapes) - len(bad), len(shapes)))


def p3_no_new_regexes():
    n = sum(1 for line in open(os.path.join(REPO_ROOT, "gov", "dlp.py"))
            if "re.compile" in line)
    assert n == 28, "re.compile count=%d, want 28" % n
    return ("HELD", "28 re.compile (no new regexes)")


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
    assert TAXONOMY_PIN == 2135, "pin moved"
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F513" in text and "F519" in text, "F513/F519 missing from FINDINGS.md"
    return ("HELD", "pin=2135; F513/F519 in FINDINGS.md (wave-363 lane 5)")


PROBES = [
    ("p1-f513-filed-shapes", p1_f513_filed_shapes),
    ("p1-f519-filed-shapes", p1_f519_filed_shapes),
    ("p1-combos-and-variants", p1_combos_and_variants),
    ("p1-compositions", p1_compositions),
    ("p2-f513-bounds", p2_f513_bounds),
    ("p2-f519-bounds", p2_f519_bounds),
    ("p2-f519-bare-arrow-rejected", p2_f519_bare_arrow_rejected),
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
    scripts = ("w363_f513_redfirst.py",
               "w363_f519_redfirst.py",
               "w363_f506close_probes.py",
               "w363_attack_probes.py",
               "w362_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g364-green-%s-%d" % (script.replace(".py", ""),
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
        if script == "w362_attack_probes.py":
            # The w362 battery's footer pin is stale by design: wave-363
            # lane 5 filed F513-F520, so its expected footer (open
            # F506-F511 / next F513) no longer matches. Merge-time
            # repoint (wave-305/306 class). Tolerate exactly one
            # test_b0_footer_state BREAK and nothing else.
            breaks = [l for l in out.splitlines()
                      if ": BREAK" in l]
            others = [l for l in breaks
                      if not l.startswith("test_b0_footer_state: BREAK")]
            if r.returncode != 0 and not others and breaks:
                notes.append("(w362 footer stale tolerated by design)")
                continue
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w364_f513f519close: starting %d probes" % len(PROBES))
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
