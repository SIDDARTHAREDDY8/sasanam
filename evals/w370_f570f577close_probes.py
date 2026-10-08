#!/usr/bin/env python3
"""Close battery for F570, F577 (entry-point family).

F570 (directive prologues in DIRECT Reflect.apply targets): F546 closed
arguments-enumerating bodies (bare-alias, for-of, for-in) in function-valued
direct Reflect.apply targets, but its body grammar expected the binding
declaration first, so a "use strict" directive prologue escaped all three
idioms. Closed (wave-370 lane 1): `_js_parse_fn_enum_body_target` now
skips a leading directive prologue node-exactly via
`_js_skip_directive_prologue` (F560) before the decl match; with no
directives the behavior is unchanged (the helper starts at
`_js_skip_ws(stmts, 0)`). The same skip is applied in
`_js_parse_fn_destructure_body_target` (F558) -- same mechanism, F560
precedent. Boundaries: directives mid-body are never skipped; backtick
"directives" fail closed (not directives in the engine); non-enum body
shapes stay fail-closed.

F577 (arrow-IIFE rest-parameter bindings): F516 closed arguments
bindings in function-expression IIFEs, but arrow IIFEs bind via rest
parameters -- a different binding production. Closed (wave-370 lane 1):
new `_js_parse_f577_arrow_rest_iife` parses `((...A)=>BODY)(lit, ...)`
and `((...A)=>BODY).call(T, lit, ...)` (F511 precedent for the .call
dispatch class); the rest param IS the args array (node v24.20.0), so
the body is rewritten by `_js_bind_iife_arguments` with
`member_ok=True` (exactly the F516 rest-param binding) and parsed by
the normal additive grammar at depth+1. The body is an expression or a
single-return block body (F448 precedent). Boundaries: named leading
params + rest fail closed (distinct binding production, documented
residual); `this`/`arguments`/`super` in the body fail closed (lexical
scope, unknowable statically); rest named `arguments` fails closed;
`.apply` dispatch, non-literal args, and uninvoked arrows fail closed.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
Zero paid API calls: this battery shells only to adjacent in-repo
batteries (green check). $0 spend by construction.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


FILED = [
    # F570: directive prologues in direct Reflect.apply targets
    ("f570-bare-alias",
     'Reflect.apply(function(){"use strict";var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-forof",
     'Reflect.apply(function(){"use strict";var a=arguments;var s=\'\';'
     'for(var x of a){s+=x;}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-single-quote",
     "Reflect.apply(function(){'use strict';var a=arguments;"
     "return a[0]+a[1];},null,['%(A1)s','%(A2)s'])"
     % {"A1": _A1, "A2": _A2}),
    # F577: arrow-IIFE rest-parameter bindings
    ("f577-direct",
     "((...a)=>a[0]+a[1])('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-call",
     "((...a)=>a[0]+a[1]).call(null,'%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
]

VARIANTS = [
    # F570: directive variants across the target classes
    ("f570-forin",
     'Reflect.apply(function(){"use strict";var a=arguments;var s=\'\';'
     'for(var i in a){s+=a[i];}return s;},null,'
     '[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f570-two-directives",
     'Reflect.apply(function(){"use strict";"x";var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-asi-directive",
     'Reflect.apply(function(){\n"use strict"\nvar a=arguments;'
     'return a[0]+a[1];\n},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-destructure-target",
     'Reflect.apply(function(){"use strict";const {0:a,1:b}=arguments;'
     'return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-call-indirect",
     'Reflect.apply.call(Reflect,function(){"use strict";'
     'var a=arguments;return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f570-spread-args",
     'Reflect.apply(function(){"use strict";var a=arguments;'
     'return a[0]+a[1];},null,[...[\'%(A1)s\',\'%(A2)s\']])'
     % {"A1": _A1, "A2": _A2}),
    # F577: body/dispatch variants
    ("f577-block-body",
     "((...a)=>{return a[0]+a[1];})('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-member-join",
     "((...a)=>a.join(''))('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-extra-args",
     "((...a)=>a[0]+a[2])('%(A1)s','zz','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-postfix",
     "((...a)=>a[0]+a[1])('%(A1)s','%(A2)s')+''"
     % {"A1": _A1, "A2": _A2}),
    ("f577-ws",
     "( ( ...a ) => a[ 0 ] + a[ 1 ] ) ( '%(A1)s' , '%(A2)s' )"
     % {"A1": _A1, "A2": _A2}),
]

BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these
    # F570: directive mid-body is NOT a prologue (never skipped)
    ("f570-mid-body-directive",
     'Reflect.apply(function(){var a=arguments;"use strict";'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    # F570: backtick "directive" is not a directive in the engine
    ("f570-backtick-directive",
     'Reflect.apply(function(){`use strict`;var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    # F570: directive + unmodeled body shape stays fail-closed
    ("f570-directive-unmodeled-body",
     'Reflect.apply(function(){"use strict";var a=arguments;'
     'return a.length;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    # F577: named leading params + rest is a distinct production
    ("f577-named-plus-rest",
     "((a,...r)=>r[0])('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    # F577: lexical-scope names the decoder cannot resolve
    ("f577-this-in-body",
     "((...a)=>this.x)('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-arguments-in-body",
     "((...a)=>arguments[0])('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-rest-named-arguments",
     "((...arguments)=>arguments[0])('%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    # F577: dispatch/arg boundaries
    ("f577-nonliteral-arg",
     "((...a)=>a[0]+a[1])(f1,'%(A2)s')"
     % {"A2": _A2}),
    # object-literal .call thisArgs are unmodeled (fail closed,
    # documented -- the filed shape is .call(null,...))
    ("f577-call-obj-thisarg",
     "((...a)=>a[0]+a[1]).call({},'%(A1)s','%(A2)s')"
     % {"A1": _A1, "A2": _A2}),
    ("f577-apply-dispatch",
     "((...a)=>a[0]+a[1]).apply(null,['%(A1)s','%(A2)s'])"
     % {"A1": _A1, "A2": _A2}),
    ("f577-no-invocation",
     "((...a)=>a[0]+a[1])"),
    ("f577-junk-quiet",
     "((...a)=>a[0]+a[1])('zz','yy')"),
    # honest text stays quiet
    ("honest-text-quiet",
     "the quarterly report was reviewed by the compliance team"),
]


def p1_filed_shapes_held():
    bad = [n for n, p in FILED if not _hit(p)]
    return ("HELD", "%d/%d filed shapes held" % (len(FILED) - len(bad),
                                                len(FILED))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p2_variants_held():
    bad = [n for n, p in VARIANTS if not _hit(p)]
    return ("HELD", "%d/%d variants held" % (len(VARIANTS) - len(bad),
                                            len(VARIANTS))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p3_fail_closed_boundaries():
    bad = [n for n, p in BOUNDARIES if _hit(p)]
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(BOUNDARIES) - len(bad), len(BOUNDARIES))) \
        if not bad else ("BREAK", "leaked: %s" % bad)


def p4_node_differential():
    # Node-exact expectations established on node v24.20.0.
    pairs = [
        # (decoder input template, node-evaluated expected decode)
        ('Reflect.apply(function(){"use strict";var a=arguments;'
         'return a[0]+a[1];},null,[\'f1\',\'f2\'])', "f1f2"),
        ('Reflect.apply(function(){\'use strict\';var a=arguments;'
         'var s=\'\';for(var x of a){s+=x;}return s;},'
         'null,[\'f1\',\'f2\'])', "f1f2"),
        ('Reflect.apply(function(){"use strict";"x";var a=arguments;'
         'return a[1]+a[0];},null,[\'f1\',\'f2\'])', "f2f1"),
        ('Reflect.apply(function(){"use strict";const {0:a,1:b}=arguments;'
         'return a+b;},null,[\'f1\',\'f2\'])', "f1f2"),
        ('Reflect.apply.call(Reflect,function(){"use strict";'
         'var a=arguments;return a[0]+a[1];},null,[\'f1\',\'f2\'])', "f1f2"),
        ('Reflect.apply(function(){"use strict";var a=arguments;'
         'return a[0]+a[1];},null,[...[\'f1\',\'f2\']])', "f1f2"),
        ("((...a)=>a[0]+a[1])('f1','f2')", "f1f2"),
        ("((...a)=>a[0]+a[1]).call(null,'f1','f2')", "f1f2"),
        ("((...a)=>{return a[1]+a[0];})('f1','f2')", "f2f1"),
        ("((...a)=>a.join(''))('f1','f2')", "f1f2"),
        ("((...a)=>a[0]+a[2])('f1','zz','f2')", "f1f2"),
    ]
    import gov.dlp as dlp
    bad = []
    for payload, want in pairs:
        st = {"parts": 0, "ops": 0}
        try:
            val, _ = dlp._js_parse_primary(payload, 0, 0, st)
        except Exception as e:  # noqa: BLE001
            bad.append((payload[:40], "raise %s" % e))
            continue
        if val != want:
            bad.append((payload[:40], "%r != node %r" % (val, want)))
    return ("HELD", "%d/%d decoder==node" % (len(pairs) - len(bad),
                                            len(pairs))) \
        if not bad else ("BREAK", "diffs: %s" % bad)


def p5_compositions():
    # Neighbor findings stay closed; honest anchors still decode.
    must_hit = [
        ("f546-bare-alias-still",
         "Reflect.apply(function(){var a=arguments;"
         "return a[0]+a[1];},null,['%s','%s'])"
         % (_A1, _A2)),
        ("f546-forof-still",
         "Reflect.apply(function(){var a=arguments;var s='';"
         "for(var x of a){s+=x;}return s;},null,['%s','%s'])"
         % (_A1, _A2)),
        ("f558-destructure-still",
         "Reflect.apply(function(){const {0:a,1:b}=arguments;"
         "return a+b;},null,['%s','%s'])"
         % (_A1, _A2)),
        ("f519-additive-still",
         "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])"
         % (_A1, _A2)),
        ("f560-iife-directive-still",
         "(function(){'use strict';var a=arguments;return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2)),
        ("f516-iife-still",
         "(function(){var a=arguments;return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2)),
        ("f522-iife-target-still",
         "Reflect.apply((function(){return (a,b)=>a+b;})(),"
         "null,['%s','%s'])" % (_A1, _A2)),
        ("f567-anchor-still-quiet",
         "xJSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')"
         % (_A1, _A2)),
    ]
    bad_hit = [n for n, p in must_hit[:7] if not _hit(p)]
    bad_quiet = ["f567-anchor-still-quiet"] if _hit(must_hit[7][1]) else []
    bad = bad_hit + bad_quiet
    return ("HELD", "%d/%d neighbor compositions hold"
            % (len(must_hit) - len(bad), len(must_hit))) \
        if not bad else ("BREAK", "regressed: %s" % bad)


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = (text.count("CLOSED 2026-10-07 wave-370 lane 1") >= 2
                 and "Next free finding: **F655**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
                 and "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." in text)  # Wave-373 merge: footer-rot repair (was wave-370-era open list)  # Wave-374 lane 2: F613 CLOSED  # Wave-374 lane 4: F615 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return ("HELD", detail) if (pin_ok and footer_ok) \
        else ("BREAK", detail)


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w369_f570_redfirst.py",
               "w369_f577_redfirst.py",
               "w369_f558f567f568f569close_probes.py",
               "w368_f543f545f546close_probes.py",
               "w369_f553f554f555f556close_probes.py",
               "w369_f560f562f563close_probes.py",
               "w369_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g370-green-%s-%d" % (script.replace(".py", ""),
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
        m = re.search(r"tally:\s*(\d+)\s*BREAK", out)
        if m is None:
            m = re.search(r"(\d+) BREAK / \d+ HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_filed_shapes_held, p2_variants_held,
              p3_fail_closed_boundaries, p4_node_differential,
              p5_compositions, p6_pin_and_footer]
    breaks, held, errors = 0, 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (fn.__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    gc = _green_check()
    print("green-check: %s" % gc)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
