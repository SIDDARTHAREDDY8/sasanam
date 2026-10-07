#!/usr/bin/env python3
"""Wave-365 F521 closure battery (lane 1).

One LOW finding from wave-364 attack round 32 (node v24.20.0 ->
credential, decoder missed on the wave-364-merged base):

F521: Reflect.apply with a .bind-bound function target. F506 models
  Reflect.apply invoked through Function.prototype.call/.apply
  higher-order dispatch with concat-family targets, F513 models .bind
  indirection with plain concat targets, and F519 models arrow/fn-expr
  literal targets -- but a target that is itself .bind-bound is a new
  target class:
    Reflect.apply([].concat.bind([], 'f1'), null, ['f2']).join('')
    Reflect.apply.call(Reflect, [].concat.bind([], 'f1'), [], ['f2']).join('')
    Reflect.apply.bind(Reflect)([].concat.bind([], 'f1'), [], ['f2']).join('')
  All three node-evaluate to the exact credential. Distinct from F506
  (call/apply indirection with unbound targets), F513 (bind indirection
  with plain targets), and F519 (unbound literal targets).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f521_bound_target` parses the bound function value:
    `[].concat.bind(BINDTHIS, ...ARGS)` or
    `Array.prototype.concat.bind(BINDTHIS, ...ARGS)` (node:
    [].concat === Array.prototype.concat, v24.20.0). The `.bind`
    member accepts the dot form, the F490 `?.` form, and the F482
    bracket-string form (engine-identical); the inner `concat`
    member is dot-only (F506 precedent). BINDTHIS is an array
    literal or Array-constructor form with all-string elements (the
    F506 thisArg classes); every bound ARG is a string literal
    (F454 grammar). A second `.bind` on the bound function fails
    closed structurally (the caller expects `,` after the bind
    call) -- one hop only, documented residual.
  * `_js_parse_f521_bound_triple` parses `BOUND, thisArg, argsList`:
    thisArg is parsed and discarded (the bound function's this is
    fixed by .bind, so Reflect.apply's thisArg is ignored by the
    engine -- node-verified, F483 precedent); argsList is a
    string-literal-only list (F519 grammar). The result is the
    parameter-ordered concatenation
    BINDTHIS.concat(...BOUNDARGS, ...ARGSLIST) -- bound args precede
    call args, node-exact.
  * Three dispatch sites route to it:
    - direct: `_js_parse_reflect_call` gains a "bound" target class
      in `_js_peek_reflect_apply_target` (pure lookahead for the
      `[].concat.bind(` / `Array.prototype.concat.bind(` head) ->
      `_js_parse_reflect_apply_bound`.
    - call-indirect: `Reflect.apply.call(Reflect, BOUND, thisArg,
      argsList)` -> `_js_parse_f521_call_dispatch` (the literal
      `Reflect` receiver is required; anything else fails closed).
    - bind-indirect: `_js_parse_f513_reflect_bind` falls back to the
      F521 bound triple when the F506 triple raises (clean: the F506
      raise commits nothing).

Fail-closed boundaries (documented): `.bind` on non-concat targets
  ([].join.bind node-evaluates to "" -- not a decodable credential
  variant), numeric/template/additive bound args, non-array BINDTHIS,
  deeper `.bind` chains, extra Reflect.apply args, unbound targets
  through the call-indirect form (documented residual -- not filed),
  nested-bracket dispatch members (`[['bind'][0]]` -- pre-existing
  F513 boundary, never modeled). Junk stays quiet.

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

TAXONOMY_PIN = 2140  # Wave-365 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f521_filed_shapes():
    shapes = [
        "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)([].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F521 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_combos_and_variants():
    shapes = [
        # Array.prototype.concat receiver (F469 class, node-identical)
        "Reflect.apply(Array.prototype.concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        # BINDTHIS with elements (prepended, node-exact)
        "Reflect.apply([].concat.bind(['x','y'], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        # multiple bound args / zero bound args
        "Reflect.apply([].concat.bind([], '%s', '%s'), null, []).join('')" % (_A1, _A2),
        "Reflect.apply([].concat.bind([]), null, ['%s','%s']).join('')" % (_A1, _A2),
        # Array-constructor BINDTHIS (F506 thisArg class)
        "Reflect.apply([].concat.bind(Array('%s'), '%s'), null, ['%s']).join('')" % (_A1, _A1, _A2),
        # whitespace tolerance (F455 class)
        "Reflect . apply ( [].concat . bind ( [], '%s' ) , null , [ '%s' ] ).join('')" % (_A1, _A2),
        # ?.call dispatch member (F490 -- provably non-null)
        "Reflect.apply?.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        # ['call'] bracket-string dispatch member (F482)
        "Reflect.apply['call'](Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        # Reflect['apply'] bracket member on the direct head (F480/F504)
        "Reflect['apply']([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        # bind-indirect with Array.prototype.concat receiver
        "Reflect.apply.bind(Reflect)(Array.prototype.concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        # thisArg variants on the direct form (parsed and discarded)
        "Reflect.apply([].concat.bind([], '%s'), ['zz'], ['%s']).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d combos/variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_compositions():
    # F506 call/apply indirection still blocks; F513 bind indirection
    # still blocks; F519 literal targets still block; F504 nested keys
    # intact; F523 (triple-nested) now blocks (lane 3); F522 IIFE-target
    # .join('') variant is a node TypeError (no credential), still misses honestly.
    cases = [
        ("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2), True),
        ("Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (_A1, _A2), True),
        ("Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2), True),  # F519 desugars to a string (no .join)
        ("Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (_A1, _A2), True),
        ("Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s']).join('')" % (_A1, _A2), False),  # F522 OPEN
        ("'%s'[[[['concat'][0]]][0]]('%s')" % (_A1, _A2), True),  # F523 CLOSED (wave-365 lane 3)
        ("Reflect.apply.call(Reflect, Array.prototype.concat, [], [['%s'],['%s']]).join('')" % (_A1, _A2), False),  # F521 residual: unbound target via call
    ]
    bad = [c for c, want in cases if _verdict(c, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions hold" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P2: fail-closed
def p2_f521_bounds():
    cases = [
        # .bind on a non-concat function: node-evaluates to "" (not a
        # decodable credential variant) -- fail closed, never mis-decoded
        "Reflect.apply([].join.bind([], ','), null, ['%s']).join('')" % _A1,
        "Reflect.apply(Math.max.bind(null, 1), null, [2]).join('')",
        # numeric bound arg / non-array BINDTHIS
        "Reflect.apply([].concat.bind([], 1), null, ['%s']).join('')" % _A2,
        "Reflect.apply([].concat.bind('x', '%s'), null, ['%s']).join('')" % (_A1, _A2),
        # deeper .bind chain: two hops now decode (F526 CLOSED wave-366
        # lane 1); three hops fail closed (documented residual)
        "Reflect.apply([].concat.bind([], '%s').bind([], 'x').bind([]), null, ['%s']).join('')" % (_A1, _A2),
        # extra Reflect.apply argument
        "Reflect.apply([].concat.bind([], '%s'), null, ['%s'], 'x').join('')" % (_A1, _A2),
        # nested-bracket dispatch member: pre-existing F513 boundary
        "Reflect.apply[['bind'][0]](Reflect)([].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        # junk stays quiet
        "Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries fail closed" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------- P3: node differential
def p3_node_differential():
    shapes = [
        "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply.bind(Reflect)([].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply(Array.prototype.concat.bind([], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply([].concat.bind(['x','y'], '%s'), null, ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply([].concat.bind([], '%s', '%s'), null, []).join('')" % (_A1, _A2),
        "Reflect.apply([].concat.bind([]), null, ['%s','%s']).join('')" % (_A1, _A2),
        "Reflect.apply['call'](Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply?.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2),
        "Reflect.apply([].concat.bind(Array('%s'), '%s'), null, ['%s']).join('')" % (_A1, _A1, _A2),
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
        dec = dlp._try_js_expr_decode(shape, shape.index("Reflect"))
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
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F521" in text, "F521 missing from FINDINGS.md"
    return ("HELD", "pin=2140; F521 in FINDINGS.md (wave-365 lane 1)")


PROBES = [
    ("p1-f521-filed-shapes", p1_f521_filed_shapes),
    ("p1-combos-and-variants", p1_combos_and_variants),
    ("p1-compositions", p1_compositions),
    ("p2-f521-bounds", p2_f521_bounds),
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
    scripts = ("w364_f521_redfirst.py",
               "w364_attack_probes.py",
               "w363_f506close_probes.py",
               "w363_attack_probes.py")
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
        if script in ("w363_attack_probes.py",):
            # The w363 battery's footer pin is stale by design in this
            # lane tree: wave-364 lane 5 filed F521-F525 and this lane
            # closes F521, so its expected footer (open F521-F525 /
            # next F526) no longer matches. Merge-time repoint
            # (wave-305/306 class). Tolerate exactly one
            # test_b0_footer_state BREAK and nothing else.
            breaks = [l for l in out.splitlines()
                      if ": BREAK" in l]
            others = [l for l in breaks
                      if not l.startswith("test_b0_footer_state: BREAK")]
            if r.returncode != 0 and not others and breaks:
                notes.append("(w363 footer stale tolerated by design)")
                continue
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w365_f521close: starting %d probes" % len(PROBES))
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
