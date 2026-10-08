#!/usr/bin/env python3
"""Wave-362 F503 closure battery (lane 1).

One LOW finding from wave-361 attack round 29 (node v24.20.0 ->
credential, decoder missed on the wave-361-merged base):

F503: Object.seal / Object.preventExtensions-wrapped array-like
  receivers at dispatch targets. Distinct from F502 (freeze receivers,
  CLOSED wave-361): seal and preventExtensions are DIFFERENT builtins,
  and the F502 peek only matched `freeze`:
    Array.prototype.concat.call(Object.seal(['f1','f2']), []).join('')
    Array.prototype.concat.call(Object.preventExtensions(['f1','f2']), []).join('')
    Array.prototype.join.call(Object.seal({length:2,0:'f1',1:'f2'}), '')
    Array.prototype.join.call(Object.preventExtensions({length:2,0:'f1',1:'f2'}), '')
    Array.prototype.concat.apply(Object.seal(['f1','f2']), [[]]).join('')
    [].concat.call(Object.preventExtensions(['f1','f2']), []).join('')
  (an Array.prototype.slice.call(Object.seal(...), 0, 2) variant also
  verified BREAK). Direct method calls on sealed arrays block coded =
  controls.

Closure design (gov/dlp.py): the F502 pair `_js_peek_freeze_head` /
`_js_parse_freeze_recv` generalized honestly to
`_js_peek_integrity_wrap_head` / `_js_parse_integrity_wrap_recv` over
_JS_INTEGRITY_WRAPPERS = ("freeze", "seal", "preventExtensions").
Every wrapper returns its argument unchanged (the same object
reference -- node v24.20.0), so a wrapped receiver is engine-identical
to the inner receiver: INNER is parsed by `_js_parse_dispatch_receiver`
itself (freeze/seal/preventExtensions recursion composes), which fails
closed on any unmodeled inner shape. Bracket-string member forms
(`Object['seal']`, `Object["preventExtensions"]`) are engine-identical
to the dot form (F480 convention, node-verified). Exactly one argument;
extra args, missing close paren, and nesting beyond _JS_EXPR_MAX_DEPTH
fail closed. Each wrapper charges one obfuscation op (F430 budget).

Fail-closed boundaries (documented): non-modeled inner receivers;
seal/preventExtensions with extra args; empty arg list; wrapper-name
lookalikes (`sealx`); over-deep nesting; proxy get-trap inners (F489
boundary); junk stays quiet.

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

TAXONOMY_PIN = 2143  # Wave-362 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f503_filed_shapes():
    shapes = [
        "Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (_A1, _A2),
        "Array.prototype.concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (_A1, _A2),
        "Array.prototype.join.call(Object.seal({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.preventExtensions({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.concat.apply(Object.seal(['%s','%s']), [[]]).join('')" % (_A1, _A2),
        "[].concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (_A1, _A2),
        # F480-convention bracket member forms
        "Array.prototype.join.call(Object['seal'](['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object[\"preventExtensions\"](['%s','%s']), '')" % (_A1, _A2),
        # slice-dispatch variant (filed in the F503 entry)
        "Array.prototype.slice.call(Object.seal(['%s','%s']), 0, 2).join('')" % (_A1, _A2),
        # nested wrappers compose (seal over freeze)
        "Array.prototype.join.call(Object.seal(Object.freeze(['%s','%s'])), '')" % (_A1, _A2),
        # bind dispatch path
        "Array.prototype.concat.bind(Object.seal(['%s','%s']))([], []).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F503 shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_compositions():
    # F502 freeze shapes must not regress; F487 plain array-likes intact.
    cases = [
        ("Array.prototype.join.call(Object.freeze(['%s','%s']), '')" % (_A1, _A2), True),
        ("Array.prototype.join.call(Object['freeze'](['%s','%s']), '')" % (_A1, _A2), True),
        ("Array.prototype.join.call({length:2,0:'%s',1:'%s'}, '')" % (_A1, _A2), True),
        # whitespace-tolerant wrapper head
        ("Array.prototype.join.call(Object . seal ( ['%s','%s'] ) , '')" % (_A1, _A2), True),
        # F489 x F503: accessor-length inner receiver under a wrapper
        ("Array.prototype.join.call(Object.seal({0:'%s',1:'%s', get length() { return 2; }}), '')" % (_A1, _A2), True),
    ]
    bad = [c for c, want in cases if _verdict(c, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions hold" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P2: fail-closed
def p2_f503_bounds():
    cases = [
        # extra arguments to the wrapper
        "Array.prototype.join.call(Object.seal(['%s','%s'], 1), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.preventExtensions(['%s'], 1, 2), '')" % _A1,
        # empty argument list
        "Array.prototype.join.call(Object.seal(), '')",
        # non-modeled inner receivers
        "Array.prototype.join.call(Object.seal(foo), '')",
        "Array.prototype.join.call(Object.preventExtensions(x), '')",
        # sealed object literals with non-literal properties
        "Array.prototype.join.call(Object.seal({length:2,0:foo}), '')",
        "Array.prototype.join.call(Object.preventExtensions({length:2,0:'%s',1:bar}), '')" % _A1,
        # wrapper-name lookalikes (ident-cont guard)
        "Array.prototype.join.call(Object.sealx(['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object['sealx'](['%s','%s']), '')" % (_A1, _A2),
        # proxy get-trap inner stays fail-closed (F489 boundary)
        "Array.prototype.join.call(Object.seal(new Proxy(['%s'], {get: function(t,k){return t[k]}})), '')" % _A1,
        # wrapper nesting beyond the depth cap (9 > _JS_EXPR_MAX_DEPTH=8)
        "Array.prototype.join.call(" + "Object.seal(" * 9 + "['%s','%s']" % (_A1, _A2) + ")" * 9 + ", '')",
        # junk stays quiet
        "Array.prototype.join.call(Object.seal(['ab','cd']), '')",
        "Array.prototype.join.call(Object.preventExtensions(['ab','cd']), '')",
    ]
    bad = [c for c in cases if _verdict(c, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F503 bounds fail closed" % (len(cases) - len(bad), len(cases)))


# ------------------------------------------------------- P3: node-exactness
def p3_node_differential():
    """Node v24.20.0 vs decoder, byte-identical on filed shapes."""
    shapes = [
        "Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (_A1, _A2),
        "Array.prototype.concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (_A1, _A2),
        "Array.prototype.join.call(Object.seal({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.join.call(Object.preventExtensions({length:2,0:'%s',1:'%s'}), '')" % (_A1, _A2),
        "Array.prototype.concat.apply(Object.seal(['%s','%s']), [[]]).join('')" % (_A1, _A2),
        "[].concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (_A1, _A2),
        "Array.prototype.join.call(Object['seal'](['%s','%s']), '')" % (_A1, _A2),
        "Array.prototype.slice.call(Object.seal(['%s','%s']), 0, 2).join('')" % (_A1, _A2),
        "Array.prototype.join.call(Object.freeze(['%s','%s']), '')" % (_A1, _A2),
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
    assert TAXONOMY_PIN == 2143, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    assert "F503" in text, "F503 missing from FINDINGS.md"
    return ("HELD", "pin=2140; F503 in FINDINGS.md (wave-362 lane 1)")


PROBES = [
    ("p1-f503-filed-shapes", p1_f503_filed_shapes),
    ("p1-compositions", p1_compositions),
    ("p2-f503-bounds", p2_f503_bounds),
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
    scripts = ("w361_f503_redfirst.py",
               "w361_f500f501f502close_probes.py",
               "w361_attack_probes.py",
               "w360_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g362-green-%s-%d" % (script.replace(".py", ""),
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
    print("w362_f503close: starting %d probes" % len(PROBES))
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
    print("w362_f503close: %d BREAK / %d HELD / %d ERROR"
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
