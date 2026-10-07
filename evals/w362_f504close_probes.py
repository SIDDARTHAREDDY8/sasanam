#!/usr/bin/env python3
"""Wave-362 F504 closure battery (lane 2).

F504 (LOW, filed 2026-10-07 wave-361 attack round 29): bracket/template/
nested-bracket member access on Reflect.apply, and dot-form Reflect.apply
with a non-prototype method target, bypass the bounded static JS-expression
decoder -- F469 models Reflect.apply(Array.prototype.concat,...) (dot form,
prototype method target) and F480 models Reflect.apply/Reflect['apply']
with the bare Array target (desugared to Array(...argsList)); the Reflect
NAMESPACE member access in non-dot spellings, and array-literal method
targets, bypass both anchors:

  Reflect['apply']([].concat, [], ['f1','f2']).join('')
  Reflect[`apply`]([].concat, [], ['f1','f2']).join('')
  Reflect[['apply'][0]]([].concat, [], ['f1','f2']).join('')
  Reflect.apply([].concat, [], ['f1','f2']).join('')

All node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants. Distinct from F469 (dot-form prototype target)
and F480 (bare-Array target).

Close-when: the decoder resolves non-dot member access on the Reflect
namespace and method-target Reflect.apply forms equivalently to the
modeled forms (or refuses obfuscation-shaped runs coded) such that
find_credential flags them, red-first verified, honest text unaffected.

This lane:
- extends the _JS_EXPR_START Reflect bracket-member class with backtick
  and nested-bracket (literal-alternation only; re.compile count
  unchanged at 28);
- adds _js_parse_nested_bracket_key for [['name'][idx]] keys
  (engine-identical to the literal key, node-verified);
- routes template / folded / nested-bracket member names through the
  existing F480/F498 fallback chain in _js_parse_reflect_call,
  _js_parse_reflect_apply_ctor, _js_parse_reflect_construct, and the
  F469 concat callee;
- models the `[].concat` apply target (node: [].concat ===
  Array.prototype.concat) in _js_peek_reflect_apply_target and
  _js_parse_reflect_apply_concat.
Fail-closed boundaries: non-foldable keys, non-empty-array receivers,
non-concat methods, non-Array targets.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov.dlp import find_credential, _try_js_expr_decode  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2135
FOOTER_OPEN = "F506, F509, F510, F511"  # F504 CLOSED locally (merge finalizes tree-wide)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 2: F507+F508 CLOSED locally
FOOTER_NEXT = "F513"  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decoded(payload):
    r = _try_js_expr_decode(payload, 0)
    return r[0] if r else None


# ------------------------------------------------------------ P1: filed shapes
def p1_filed_shapes_block():
    shapes = [
        "Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[`apply`]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect.apply([].concat, [], ['%s','%s']).join('')" % (A1, A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    if bad:
        return ("BREAK", "filed shape missed: %s" % bad[0][:60])
    return ("HELD", "4/4 filed shapes block")


def p1_node_byte_fidelity():
    import json
    import subprocess
    shapes = [
        "Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[`apply`]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect.apply([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[ [ 'apply' ] [ 0 ] ]( [ ] . concat , [ ] , [ '%s' , '%s' ] ).join( '' )" % (A1, A2),
    ]
    node_src = "var out=[];\n"
    for s in shapes:
        node_src += "out.push(JSON.stringify(eval(%s)));\n" % json.dumps(s)
    node_src += "console.log(out.join(String.fromCharCode(10)));"
    with open("/tmp/w362_f504_node.js", "w") as fh:
        fh.write(node_src)
    r = subprocess.run(["node", "/tmp/w362_f504_node.js"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node threw: %s" % r.stderr[:80])
    for s, nv in zip(shapes, r.stdout.strip().split("\n")):
        if _decoded(s) != json.loads(nv):
            return ("BREAK", "differential mismatch: %s" % s[:55])
    return ("HELD", "%d/%d shapes byte-identical to node v24.20.0"
            % (len(shapes), len(shapes)))


# ------------------------------------------------------------ P2: boundaries (fail closed)
def p2_fail_closed_boundaries():
    misses = [
        # non-foldable member keys
        "Reflect[x]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[('apply')]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[['a','b'][5]]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        # non-empty-array receivers
        "Reflect.apply(['x'].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect['apply'](['x'].concat, [], ['%s','%s']).join('')" % (A1, A2),
        # non-concat methods / non-Array targets
        "Reflect.apply([].map, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect.apply(Math.max, Math, ['%s','%s']).join('')" % (A1, A2),
        # F491 composition: computed keys on Reflect.get stay fail-closed
        "Reflect['g'+'et'](Array.prototype,'con'+'cat').call([],['%s','%s']).join('')" % (A1, A2),
        "Reflect[`get`](Array.prototype,'concat').call([],['%s','%s']).join('')" % (A1, A2),
    ]
    bad = [s for s in misses if not _misses(s)]
    if bad:
        return ("BREAK", "boundary decoded (should fail closed): %s" % bad[0][:60])
    return ("HELD", "%d/%d boundaries fail closed" % (len(misses), len(misses)))


def p2_compositions():
    held = [
        # F469: dot-form prototype target still held
        "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2),
        # F480: Array-target forms still held (dot, bracket, template, nested)
        "Reflect.apply(Array, Array, [['%s'],['%s']]).join('')" % (A1, A2),
        "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (A1, A2),
        "Reflect[`apply`](Array, Array, [['%s'],['%s']]).join('')" % (A1, A2),
        "Reflect[['apply'][0]](Array, Array, [['%s'],['%s']]).join('')" % (A1, A2),
        # F498: construct forms still held (dot, bracket, template, nested)
        "Reflect.construct(Array, ['%s','%s']).join('')" % (A1, A2),
        "Reflect['construct'](Array, ['%s','%s']).join('')" % (A1, A2),
        "Reflect[`construct`](Array, ['%s','%s']).join('')" % (A1, A2),
        "Reflect[['construct'][0]](Array, ['%s','%s']).join('')" % (A1, A2),
        # F492 x F504: folded keys on the new target
        "Reflect['ap'+'ply']([].concat, [], ['%s','%s']).join('')" % (A1, A2),
        "Reflect[`ap${'ply'}`]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
    ]
    bad = [s for s in held if not _blocked(s)]
    if bad:
        return ("BREAK", "composition regressed: %s" % bad[0][:60])
    return ("HELD", "%d/%d compositions hold" % (len(held), len(held)))


def p2_junk_quiet():
    if _blocked("Reflect['apply']([].concat, [], ['ab','cd']).join('')"):
        return ("BREAK", "junk flagged")
    return ("HELD", "junk quiet")


# ------------------------------------------------------------ P3: decoder pins
def p3_no_new_regexes():
    import re
    # F488: the Object anchor alternative gains getPrototypeOf (a new
    # member-name alternative, pinned exactly) -- re.compile count
    # unchanged. Wave-360 lane 1 (F490): the Reflect alternative gains
    # (\?\.|\.) for Reflect?.apply shapes. Wave-360 lane 2
    # (F491/F493): the Reflect alternative gains `get`, the Object
    # alternative gains `getOwnPropertyDescriptor`, and the String
    # alternative gains `.raw(` / `.raw.call(` -- literal-alternation
    # only, pinned exactly; re.compile count unchanged.
    # Wave-362 lane 2 (F504): the Reflect bracket-member class gains
    # backtick and nested-bracket (literal-alternation only);
    # re.compile count unchanged.
    # F505 (wave-362 lane 3): String.fromCodePoint alternative
    # added (literal-alternation only -- the same F468
    # precedent); re.compile count unchanged (28).
    # F508 (wave-363 lane 2): Array.from alternative added (literal-alternation only); re.compile count unchanged (28).
    assert dlp._JS_EXPR_START.pattern == (
        r"['\"`\[]|"
        r"String\.fromCharCode|"
        r"String\.fromCodePoint|"
        r"String[ \t\n\r]*(\(|\.[ \t\n\r]*raw([ \t\n\r]*\(|[ \t\n\r]*\.[ \t\n\r]*call[ \t\n\r]*\()|\[[ \t\n\r]*['\"])|"
        r"Array(\(|[ \t\n\r]*(\.[ \t\n\r]*(of|apply|call|from)|\[[ \t\n\r]*['\"]))|"
        r"Array[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"String[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Function[ \t\n\r]*\.[ \t\n\r]*prototype|"
        r"Reflect([ \t\n\r]*(\?\.|\.)[ \t\n\r]*(construct|apply|get)|[ \t\n\r]*\[[ \t\n\r]*['\"`\[])|"
        r"Object([ \t\n\r]*\.[ \t\n\r]*(assign|getPrototypeOf|getOwnPropertyDescriptor)|[ \t\n\r]*\[[ \t\n\r]*['\"])|"
        r"\("
    )
    for s in ["Array.apply(", "Array.of.call", "Array.from(", "[].constructor.of.call",
              "String.fromCharCode.apply", "Object.getPrototypeOf",
              "Array.prototype.concat", "Object.assign"]:
        assert dlp._JS_EXPR_START.search(s) is not None, s
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    assert len(re.findall(r"re\.compile\(", src)) == 28
    return ("HELD", "no new regexes; anchor pinned with F504 widening")

def p3_f430_bounds():
    # The new parsers charge the part budget; many-element key arrays trip it.
    many = ", ".join(["'a'"] * 60)
    payload = "Reflect[[%s][0]]([].concat, [], ['%s','%s']).join('')" % (many, A1, A2)
    if _blocked(payload):
        return ("BREAK", "parts budget not enforced on key arrays")
    return ("HELD", "parts budget enforced")


# ------------------------------------------------------------ P4: pin and footer
def p4_pin_and_footer():
    from gov.decision_codes import TAXONOMY
    assert len(TAXONOMY) == TAXONOMY_PIN, (len(TAXONOMY), TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Lane-local footer expectation: F504 closed here; the merge
    # finalizes tree-wide.
    assert ("Open findings: %s." % FOOTER_OPEN) in text, "footer open"
    assert ("Next free finding: **%s**" % FOOTER_NEXT) in text, "footer next"
    assert "F504" in text and "CLOSED" in text
    return ("HELD", "pin=%d footer open %s next %s (lane-local)" %
            (TAXONOMY_PIN, FOOTER_OPEN, FOOTER_NEXT))


_PROBES = [
    ("p1-filed-shapes-block", p1_filed_shapes_block),
    ("p1-node-byte-fidelity", p1_node_byte_fidelity),
    ("p2-fail-closed-boundaries", p2_fail_closed_boundaries),
    ("p2-compositions", p2_compositions),
    ("p2-junk-quiet", p2_junk_quiet),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-f430-bounds", p3_f430_bounds),
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
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    notes = []
    scripts = ("w361_attack_probes.py",
               "w361_f504_redfirst.py",
               "w361_f498f499close_probes.py",
               "w360_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g362-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, GOV_SKIP_GREEN="1",
                   TMPDIR=tmp, GOV_DEPLOYMENT_MODE="staging")
        import subprocess
        r = subprocess.run([venv_python,
                            os.path.join(REPO_ROOT, "evals", script)],
                           capture_output=True, text=True, env=env,
                           timeout=600, cwd=REPO_ROOT)
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
    print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    breaks = [pid for pid, (v, _) in results if v == "BREAK"]
    errors = [pid for pid, (v, _) in results if v == "ERROR"]
    held = [pid for pid, (v, _) in results if v == "HELD"]
    for pid, (v, msg) in results:
        print("%-28s %s %s" % (pid, v, msg))
    unexpected = sorted(set(breaks) - _EXPECTED_BREAKS)
    missing = sorted(_EXPECTED_BREAKS - set(breaks))
    print("w362_f504close: %d BREAK / %d HELD / %d ERROR" %
          (len(breaks), len(held), len(errors)))
    if unexpected:
        print("unexpected BREAKs: %s" % unexpected)
    if missing:
        print("missing expected BREAKs: %s" % missing)
    if errors:
        print("ERRORs: %s" % errors)
    return 1 if (unexpected or missing or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
