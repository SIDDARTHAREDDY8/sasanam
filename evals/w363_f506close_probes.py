#!/usr/bin/env python3
"""Wave-363 F506 closure battery (lane 1).

One LOW finding from wave-362 attack round 30 (node v24.20.0 ->
credential, decoder missed on the wave-362-merged base):

F506: Reflect.apply invoked through Function.prototype.call/apply
  indirection. F469 models dot-form Reflect.apply(Array.prototype.concat,
  ...), F491 models Reflect.get named reads, and F504 models bracket
  member access on the Reflect namespace -- but the apply function
  reached through a HIGHER-ORDER dispatch bypasses all three anchors:
    Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['f1','f2']]).join('')
    Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['f1','f2']).join('')
  The dispatch target is Function.prototype.apply/.call, not the
  Reflect namespace. Distinct from F469 (direct dot-form), F491
  (named reads), and F504 (member-access spellings). Control:
  Reflect.apply(Array.prototype.concat,[],[['f1'],['f2']]).join('')
  blocks coded.

Closure design (gov/dlp.py): the F483 `_js_parse_function_dispatch`
double-dispatch parser gains an F506 branch. When the dispatch target
is not an Array/String prototype method, the target is tried as
`Reflect.apply` (dot form, F490 `?.` form, or the F504
literal/template/folded/nested-bracket member-key forms --
engine-identical, node v24.20.0 verified; anything else, including
`Reflect.get` / `Reflect.construct`, falls through and fails closed).
The receiver must be the literal `Reflect` namespace (the engine
ignores Reflect.apply's this-value, so only the namespace is modeled
-- conservative). The inner/outer call/apply pair only changes how
the three arguments arrive (text list vs single array); all four
combinations desugar to exactly `Reflect.apply(T, thisArg,
argsList)` (node v24.20.0 verified). The triple is parsed by
`_js_parse_f506_triple` with exactly the F469/F504 target classes
(`[].concat` / `Array.prototype.concat`) and argument classes (array
literal or Array-constructor thisArg, all-string elements; the
argsArray extends through the shared `_js_extend_concat_apply_args`
element grammar -- the same grammar the direct form uses, extracted
without change). The result desugars to thisArg.concat(...argsList).

Fail-closed boundaries (documented): non-Reflect receivers; non-concat
targets (`Math.max`, non-empty-array receivers, `['x'].concat`);
missing/extra arguments; `Reflect.get` / `Reflect.construct` targets
(F491's computed-key get stays fail-closed); a deeper
`.call.call.call` chain (one double dispatch only); `.bind` as the
outer dispatch; non-array thisArg; non-string elements; junk stays
quiet. `Reflect?.apply` IS modeled (F490, Reflect provably non-null).

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

TAXONOMY_PIN = 2140  # Wave-363 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f506_filed_shapes():
    shapes = [
        "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F506 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_combos_and_variants():
    # All four inner/outer call/apply combinations are the same
    # desugar (node v24.20.0 verified); member-key and target variants.
    shapes = [
        # outer=apply equivalents (arguments arrive as an array)
        "Function.prototype.call.apply(Reflect.apply, [Reflect, [].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        "Function.prototype.apply.apply(Reflect.apply, [Reflect, [[].concat, [], ['%s','%s']]]).join('')" % (_A1, _A2),
        # F504 member-key forms on the F506 target
        "Function.prototype.call.call(Reflect['apply'], Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect[`apply`], Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect['ap'+'ply'], Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F490 ?. form (Reflect provably non-null)
        "Function.prototype.call.call(Reflect?.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # F469 prototype-concat target class
        "Function.prototype.call.call(Reflect.apply, Reflect, Array.prototype.concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # Array-constructor thisArg (F446/F454, direct-form class)
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, Array('%s','%s'), ['a']).join('')" % (_A1, _A2),
        # whitespace tolerance (F455-class)
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s', '%s']).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F506 combos/variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_compositions():
    # F469 / F504 direct forms must not regress; F483 prototype-method
    # double dispatch intact; F511 CLOSED by wave-363 lane 4 (merge flips
    # the expectation -- wave-306 class).
    cases = [
        ("Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (_A1, _A2), True),
        ("Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (_A1, _A2), True),
        ("Function.prototype.call.call(Array.prototype.concat, [], '%s', '%s').join('')" % (_A1, _A2), True),
        ("Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A1, _A2), True),  # F511 CLOSED (lane 4)
        ("Function.prototype.call.call(Reflect.get, Reflect, ['%s']) " % _A1, False),  # F491 boundary
    ]
    bad = [c for c, want in cases if _verdict(c, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions hold" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P2: fail-closed
def p2_f506_bounds():
    cases = [
        # non-Reflect receiver (conservative: only the namespace is modeled)
        "Function.prototype.call.call(Reflect.apply, {}, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflectx, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # non-concat targets
        "Function.prototype.call.call(Reflect.apply, Reflect, Math.max, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, Array.prototype.push, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, ['x'].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # missing / extra arguments
        "Function.prototype.call.call(Reflect.apply, Reflect).join('')",
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s'], 1).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, []).join('')",
        # Reflect.get / Reflect.construct targets stay fail-closed
        "Function.prototype.call.call(Reflect.get, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.construct, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect['get'], Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # deeper chain: one double dispatch only (documented residual)
        "Function.prototype.call.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        # non-array thisArg / non-string elements
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, 'x', ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], [42]).join('')",
        # malformed: .apply with three text args (engine throws too)
        "Function.prototype.apply.apply(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        # junk stays quiet
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['ab','cd']).join('')",
        "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['ab','cd']]).join('')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F506 bounds fail closed" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P3: node-exactness
def p3_node_differential():
    """Node v24.20.0 vs decoder, byte-identical on F506 shapes."""
    shapes = [
        "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect.apply, Reflect, [].concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.apply(Reflect.apply, [Reflect, [].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        "Function.prototype.apply.apply(Reflect.apply, [Reflect, [[].concat, [], ['%s','%s']]]).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect['apply'], Reflect, Array.prototype.concat, [], ['%s','%s']).join('')" % (_A1, _A2),
        "Function.prototype.call.call(Reflect?.apply, Reflect, [].concat, Array('%s'), ['%s']).join('')" % (_A1, _A2),
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


# ------------------------------------------------------- P4: pin and footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F506" in text, "F506 missing from FINDINGS.md"
    return ("HELD", "pin=2140; F506 in FINDINGS.md (wave-362 lane 5)")


PROBES = [
    ("p1-f506-filed-shapes", p1_f506_filed_shapes),
    ("p1-combos-and-variants", p1_combos_and_variants),
    ("p1-compositions", p1_compositions),
    ("p2-f506-bounds", p2_f506_bounds),
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
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    if not os.path.exists(venv_python):
        venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w362_f506_redfirst.py",
               "w362_f504close_probes.py",
               "w362_f503close_probes.py",
               "w362_attack_probes.py",
               "w361_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g363-green-%s-%d" % (script.replace(".py", ""),
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
    print("w363_f506close: starting %d probes" % len(PROBES))
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
    print("w363_f506close: %d BREAK / %d HELD / %d ERROR"
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
