#!/usr/bin/env python3
"""Close battery for F558, F567, F568, F569 (apply-target + anchor family).

F558 (object-pattern destructuring in Reflect.apply targets): F545 closed
object-pattern destructuring in IIFE dispatch and F546 closed
arguments-enumerating bodies in Reflect.apply dispatch, but the composition
(object patterns in a Reflect.apply TARGET) escaped both. Closed
(wave-369 lane 7): `_js_parse_fn_destructure_body_target` reuses the
F524/F545 `_js_split_destructure_var_decl` grammar (array patterns
positional, object patterns key-based, 1-2 elements, canonical keys) in
`_js_parse_reflect_apply_fn`'s target dispatch; the caller binds names to
the argsArray elements via `_js_bind_destructure_arguments` and parses
the rewritten body with the additive grammar at depth+1. Node-exact
(v24.20.0). Also wired into the F544 call-indirect fallback (the
F544xF558 composition is the same engine operation -- node-verified).
Boundaries: 3+ element patterns, non-canonical keys, defaults, string
keys, nested patterns, duplicate names/keys, out-of-range keys, `a[0]`
member uses, generators, declared params, rebound aliases.

F568 (entries/values-idiom bodies in function-valued Reflect.apply
targets): F546 closed for-of/for-in/bare-alias enumerating bodies and
F543 closed entries/values enumeration on aliased arguments in IIFE
dispatch, but the composition escaped both. Closed: `_js_parse_f568_
entries_values_body` reuses the F543 `_js_parse_f543_entries_values_head`
/ pair-projection / identity-map helpers inside `_js_parse_fn_enum_body_
target`; `Object.entries(a).map(e=>e[1]).join(SEP)` and
`Object.values(a)(.map(x=>x))?.join(SEP)` desugar to SEP.join(elements)
(node v24.20.0). Boundaries: entries without the e[1] map, values
without join, non-literal join separators, `.join()` with no separator
(node inserts "," -- modeled only for literal seps, documented).

F569 (call-indirect arguments-enumerating Reflect.apply targets): F544
closed `Reflect.apply.call(Reflect, FN, thisArg, argsArray)` for
F519-class additive targets and F546 closed enumerating bodies in DIRECT
targets, but the composition escaped both. Closed: the F544 fallback in
`_js_parse_f521_call_dispatch` now also tries `_js_parse_fn_enum_body_
target` (F546/F568 idioms) and `_js_parse_fn_destructure_body_target`
(F558, same-engine-operation extension). The F544 spread argsArray
composes with all of them (node-verified). Boundaries: non-Reflect
receivers, declared params, rebound aliases, bare `arguments` sources.

F567 (anchor left-boundary false positives): `_JS_EXPR_START` carried no
left ident-boundary, so `xJSON.parse(...)` / `xstructuredClone(...)`
flagged HIT while node throws ReferenceError. Closed: shared helper
`_js_left_boundary_ok(text, i)` applied in both finditer loops
(`_try_js_expr_decode_all` and the `_decode_layer` per-run loop) --
only to matches STARTING with an identifier char (quote/bracket/paren
anchors keep their behavior); an ident char immediately left means the
anchor is a longer identifier's suffix. Node-exact (v24.20.0).
Boundaries: honest `JSON.parse` / `structuredClone` / `Reflect.apply`
at text start or after non-ident chars still decode.

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
_WANT = _A1 + _A2


def _hit(payload):
    return find_credential(payload) is not None


FILED = [
    # F558: object-pattern destructuring in Reflect.apply targets
    ("f558-const",
     'Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-var",
     'Reflect.apply(function(){var {0:x,1:y}=arguments;return x+y;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    # F568: entries/values idiom bodies in Reflect.apply targets
    ("f568-entries",
     'Reflect.apply(function(){var a=arguments;return Object.entries(a)'
     '.map(e=>e[1]).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f568-values",
     'Reflect.apply(function(){var a=arguments;return Object.values(a)'
     '.join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-values-map",
     'Reflect.apply(function(){var a=arguments;return Object.values(a)'
     '.map(x=>x).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    # F569: call-indirect arguments-enumerating Reflect.apply targets
    ("f569-bare-alias",
     'Reflect.apply.call(Reflect,function(){var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-forof",
     'Reflect.apply.call(Reflect,function(){var a=arguments;var s=\'\';'
     'for(var x of a){s+=x;}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-forin",
     'Reflect.apply.call(Reflect,function(){var a=arguments;var s=\'\';'
     'for(var i in a){s+=a[i];}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-spread-alias",
     'Reflect.apply.call(Reflect,function(){var a=arguments;'
     'return a[0]+a[1];},null,[...[\'%(A1)s\',\'%(A2)s\']])'
     % {"A1": _A1, "A2": _A2}),
]

VARIANTS = [
    ("f558-named-fn",
     'Reflect.apply(function f(){let {1:b,0:a}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-array-pattern",
     'Reflect.apply(function(){const [a,b]=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-single-key",
     'Reflect.apply(function(){var {0:a}=arguments;return a+a;},'
     'null,[\'xoxb-0123456789\'])'),
    ("f558-call-indirect",
     'Reflect.apply.call(Reflect,function(){const {0:a,1:b}=arguments;'
     'return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-ws",
     'Reflect.apply( function ( ) { const { 0 : a , 1 : b } = arguments ; '
     'return a + b ; } , null , [ \'%(A1)s\' , \'%(A2)s\' ] )'
     % {"A1": _A1, "A2": _A2}),
    ("f568-entries-fn-callback",
     'Reflect.apply(function(){var a=arguments;return Object.entries(a)'
     '.map(function(e){return e[1];}).join(\'\');},null,'
     '[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-entries-sep",
     'Reflect.apply(function(){var a=arguments;return Object.entries(a)'
     '.map(e=>e[1]).join(\'-\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f568-bracket-member",
     'Reflect.apply(function(){var a=arguments;return Object[\'values\'](a)'
     '.join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-call-indirect",
     'Reflect.apply.call(Reflect,function(){var a=arguments;return '
     'Object.values(a).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-entries-spread",
     'Reflect.apply.call(Reflect,function(){var a=arguments;return '
     'Object.entries(a).map(e=>e[1]).join(\'\');},null,'
     '[...[\'%(A1)s\',\'%(A2)s\']])' % {"A1": _A1, "A2": _A2}),
    ("f569-forof-const-x",
     'Reflect.apply.call(Reflect,function(){let a=arguments;let s=\'\';'
     'for(const x of a){s+=x;}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
]

BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these
    ("f558-three-pattern",
     'Reflect.apply(function(){const {0:a,1:b,2:c}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-leading-zero-key",
     'Reflect.apply(function(){const {01:a,1:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-default",
     'Reflect.apply(function(){const {0:a=\'x\',1:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-string-key",
     'Reflect.apply(function(){const {\'0\':a,\'1\':b}=arguments;'
     'return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-key-beyond-args",
     'Reflect.apply(function(){const {0:a,5:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-member-use",
     'Reflect.apply(function(){const {0:a,1:b}=arguments;return a[0]+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-generator",
     'Reflect.apply(function*(){const {0:a,1:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f558-declared-params",
     'Reflect.apply(function(p){const {0:a,1:b}=arguments;return a+b;},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-entries-no-map",
     'Reflect.apply(function(){var a=arguments;return Object.entries(a)'
     '.join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-entries-e0",
     'Reflect.apply(function(){var a=arguments;return Object.entries(a)'
     '.map(e=>e[0]).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f568-values-no-join",
     'Reflect.apply(function(){var a=arguments;return Object.values(a);},'
     'null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-join-no-sep",
     'Reflect.apply(function(){var a=arguments;return Object.values(a)'
     '.join();},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f568-nonliteral-sep",
     'Reflect.apply(function(){var a=arguments;return Object.values(a)'
     '.join(s);},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    ("f569-nonreflect-receiver",
     'Reflect.apply.call(Object,function(){var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-declared-params",
     'Reflect.apply.call(Reflect,function(p){var a=arguments;'
     'return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": _A1, "A2": _A2}),
    ("f569-bare-arguments-source",
     'Reflect.apply.call(Reflect,function(){for(var x of arguments){}'
     'return \'\';},null,[\'%(A1)s\',\'%(A2)s\'])' % {"A1": _A1, "A2": _A2}),
    # F567: identifier-suffixed anchors stay quiet (node throws)
    ("f567-xjson",
     'xJSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": _A1, "A2": _A2}),
    ("f567-xclone",
     'xstructuredClone({c:\'%(A1)s\'}).c+\'%(A2)s\''
     % {"A1": _A1, "A2": _A2}),
    ("f567-xreflect",
     'xReflect.apply(function(){return \'%(A1)s\';},null,[])'
     % {"A1": _A1}),
    ("f567-xarray",
     'xArray(\'%(A1)s\',\'%(A2)s\').join(\'\')'
     % {"A1": _A1, "A2": _A2}),
    ("f567-xobject",
     'xObject.values({c:\'%(A1)s\'}).join(\'\')+\'%(A2)s\''
     % {"A1": _A1, "A2": _A2}),
    ("f567-dollar-json",
     '$JSON.parse(\'{"x":["%(A1)s"]}\')' % {"A1": _A1}),
    ("f567-unicode-json",
     'éJSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": _A1, "A2": _A2}),
    ("f567-unicode-clone",
     'αstructuredClone({c:\'%(A1)s\'}).c+\'%(A2)s\''
     % {"A1": _A1, "A2": _A2}),
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
        ("Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},"
         "null, ['f1','f2'])", "f1f2"),
        ("Reflect.apply(function(){var {1:b,0:a}=arguments;return a+b;},"
         "null, ['f1','f2'])", "f1f2"),
        ("Reflect.apply(function(){const [a,b]=arguments;return b+a;},"
         "null, ['f1','f2'])", "f2f1"),
        ("Reflect.apply(function(){var a=arguments;return Object.entries(a)"
         ".map(e=>e[1]).join('');}, null, ['f1','f2'])", "f1f2"),
        ("Reflect.apply(function(){var a=arguments;return Object.values(a)"
         ".map(x=>x).join('-');}, null, ['f1','f2'])", "f1-f2"),
        ("Reflect.apply.call(Reflect,function(){var a=arguments;"
         "return a[1]+a[0];}, null, ['f1','f2'])", "f2f1"),
        ("Reflect.apply.call(Reflect,function(){var a=arguments;"
         "return Object.values(a).join('');}, null, [...['f1','f2']])",
         "f1f2"),
        ("Reflect.apply.call(Reflect,function(){const {0:a,1:b}=arguments;"
         "return a+b;}, null, ['f1','f2'])", "f1f2"),
        # re-quote round-trip: quote/backslash in elements (H3)
        ("Reflect.apply(function(){const {0:x,1:y}=arguments;return x+y;},"
         "null, ['a\\'b','c\\\\d'])", "a'bc\\d"),
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
        ("f545-objpattern-iife-still",
         "(function(){const {0:a,1:b}=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        ("f543-entries-iife-still",
         "(function(){var a=arguments;return Object.entries(a).map("
         "e=>e[1]).join('');})('%s','%s')" % (_A1, _A2)),
        ("f546-forof-still",
         "Reflect.apply(function(){var a=arguments;var s='';"
         "for(var x of a){s+=x;}return s;},null,['%s','%s'])"
         % (_A1, _A2)),
        ("f519-additive-still",
         "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])"
         % (_A1, _A2)),
        ("f541-json-still",
         "JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')"
         % (_A1, _A2)),
        ("f536-clone-still",
         "structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2)),
        ("f544-spread-still",
         "Reflect.apply.call(Reflect,function(a,b){return a+b;},"
         "null,[...['%s','%s']])" % (_A1, _A2)),
        ("f524-array-iife-still",
         "(function(){const [a,b]=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        ("f522-iife-target-still",
         "Reflect.apply((function(){return (a,b)=>a+b;})(),"
         "null,['%s','%s'])" % (_A1, _A2)),
    ]
    bad = [n for n, p in must_hit if not _hit(p)]
    return ("HELD", "%d/%d neighbor compositions hold"
            % (len(must_hit) - len(bad), len(must_hit))) \
        if not bad else ("BREAK", "regressed: %s" % bad)


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-07 wave-369 lane 7" in text
                 and text.count("CLOSED 2026-10-07 wave-369 lane 7") >= 4
                 and "Next free finding: **F606**" in text)
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
    scripts = ("w368_f558_redfirst.py",
               "w368_f567_redfirst.py",
               "w368_f568_redfirst.py",
               "w368_f569_redfirst.py",
               "w368_f543f545f546close_probes.py",
               "w368_f541f544close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g369-green-%s-%d" % (script.replace(".py", ""),
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
