#!/usr/bin/env python3
"""Close battery for F590, F591 (call-target prologues + accessor descriptors).

F590 (directive prologues in Reflect.apply.call targets): F570 closed
directive prologues defeating the DIRECT Reflect.apply target grammar,
but the .call dispatch form (F511 precedent: .call dispatch is its own
class) is a different textual anchor -- and the filed shapes use the
literal `null` receiver (`Reflect.apply.call(null, FN, thisArg,
argsArray)`), which the F521 call-dispatch grammar rejected (it
required the literal `Reflect`). Closed (wave-371 lane 5): the F521
call-dispatch receiver now accepts the literal `null` node-exactly
(Function.prototype.call's receiver is unobservable when invoking the
built-in Reflect.apply -- node v24.20.0 verified); the F570
prologue skip composes through the shared
`_js_parse_fn_enum_body_target` / `_js_parse_fn_destructure_body_target`
parsers. Two further fixes were required to close the filed shapes
honestly: (1) carrier-escape tolerance in `_js_parse_string_literal_list`
(new `_js_parse_carrier_escaped_string`): the whole-text scanner
anchors INSIDE an outer string literal, so the raw text carries the
carrier's escapes -- raw `\\'` is `'` in the carrier's value
(node-exact); the backslash always raised there before, so this only
admits previously-failing inputs. This also fixes the same miss for
older shapes in single-quoted carriers (e.g. F519), documented in
FINDINGS.md. (2) Boundaries: `undefined`/`void 0`/arbitrary receivers
fail closed (conservative, documented residual -- the engine accepts
`undefined`).

F591 (Object.defineProperty accessor descriptors): F550 closed
defineProperty with VALUE descriptors and function-expression GETTERS,
but arrow-function getters (concise and block bodies) and
function-expression SETTERS invoked unmodeled code. Closed (wave-371
lane 5): `_js_parse_descriptor_getter` now accepts `()=>EXPR` and
`()=>{return EXPR;}` (zero params only; `this`-dependent bodies fail
closed -- an arrow's `this` is lexical and equally unmodelable);
`_js_parse_f548f550_descriptor` accepts `{set:function(v){this._c=v;}}`
(the exact single-store shape) as a "set" descriptor; the F578
statement path records setters and models `o.c='lit';` invocations
(the engine calls the setter with `this === o`), and the F578 return
is now an additive concatenation of member reads and string literals
(previously only `return o.M;` -- admits only previously-failing
inputs). The F550 DIRECT path fails closed on set-only descriptors
(the engine reads them as undefined -- not a decodable value, node
verified). Boundaries: `{get,set}` together fails closed (engine-valid
but unmodeled, documented); `{set,writable}` fails closed (engine
throws TypeError); arrow getters with params, `this`-dependent
getters, multi-statement setter bodies, and assignments to
non-setter keys all fail closed.

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
    # F590: directive prologues in Reflect.apply.call targets
    ("f590-prologue-call",
     "'Reflect.apply.call(null,function(){\"use strict\";var a=arguments;"
     "return a[0]+a[1];},null,[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}),
    ("f590-prologue-call-forof",
     "\"Reflect.apply.call(null,function(){'use strict';var a=arguments;"
     "var s='';for(var x of a){s+=x;}return s;},null,"
     "['%(A1)s','%(A2)s'])\""
     % {"A1": _A1, "A2": _A2}),
    # F591: accessor descriptors
    ("f591-accessor-arrow",
     "\"Object.defineProperty({},'c',{get:()=>'%(A1)s'}).c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-accessor-arrow-block",
     "\"Object.defineProperty({},'c',{get:()=>{return '%(A1)s';}})"
     ".c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-accessor-setter",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o.c='%(A1)s';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}),
]

VARIANTS = [
    # F590: receiver x prologue matrix
    ("f590-null-recv-no-prologue",
     "'Reflect.apply.call(null,function(){var a=arguments;"
     "return a[0]+a[1];},null,[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}),
    ("f590-reflect-recv-prologue",
     "'Reflect.apply.call(Reflect,function(){\"use strict\";"
     "var a=arguments;return a[0]+a[1];},null,"
     "[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}),
    ("f590-destructure-prologue-call",
     "'Reflect.apply.call(null,function(){\"use strict\";"
     "var [a,b]=arguments;return a+b;},null,"
     "[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}),
    # F591: getter/setter variants
    ("f591-arrow-ws",
     "\"Object.defineProperty( {}, 'c' , { get : ( ) => '%(A1)s' } )"
     ".c + '%(A2)s'\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-setter-bracket-member",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o['c']='%(A1)s';"
     "return o['_c']+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-setter-twice-last-wins",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o.c='%(A1)s';o.c='zz';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-setter-const-binding",
     "\"(function(){const o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o.c='%(A1)s';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}),
    ("f591-fnexpr-getter-still",
     "\"Object.defineProperty({},'c',{get:function(){return '%(A1)s';}})"
     ".c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}),
]

BOUNDS = [
    # F590: receivers that fail closed
    ("f590-undefined-recv-quiet",
     "'Reflect.apply.call(undefined,function(){var a=arguments;"
     "return a[0]+a[1];},null,[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}, False),
    ("f590-nullx-recv-quiet",
     "'Reflect.apply.call(nullx,function(){var a=arguments;"
     "return a[0]+a[1];},null,[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}, False),
    ("f590-midbody-directive-quiet",
     "'Reflect.apply.call(null,function(){var a=arguments;"
     "\"use strict\";return a[0]+a[1];},null,"
     "[\\'%(A1)s\\',\\'%(A2)s\\'])'"
     % {"A1": _A1, "A2": _A2}, False),
    # F591: getter boundaries
    ("f591-arrow-param-quiet",
     "\"Object.defineProperty({},'c',{get:(x)=>'%(A1)s'}).c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-arrow-thisdep-quiet",
     "\"Object.defineProperty({},'c',{get:()=>this.x}).c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-bare-param-arrow-quiet",
     "\"Object.defineProperty({},'c',{get:x=>'%(A1)s'}).c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}, False),
    # F591: setter boundaries
    ("f591-set-only-direct-quiet",
     "\"Object.defineProperty({},'c',{set:function(v){this._c=v;}}).c\"",
     False),
    ("f591-getset-together-quiet",
     "\"Object.defineProperty({},'c',{get:function(){return '%(A1)s';},"
     "set:function(v){}}).c+'%(A2)s'\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-set-writable-quiet",
     "\"Object.defineProperty({},'c',{set:function(v){},writable:true}).c\"",
     False),
    ("f591-setter-no-assign-quiet",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-setter-bad-body-quiet",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;v;}});o.c='%(A1)s';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-assign-nonsetter-quiet",
     "\"(function(){var o={d:'q'};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o.d='%(A1)s';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-setter-bracket-this-quiet",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this['_c']=v;}});o.c='%(A1)s';"
     "return o._c+'%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}, False),
    ("f591-return-no-member-quiet",
     "\"(function(){var o={};Object.defineProperty(o,'c',"
     "{set:function(v){this._c=v;}});o.c='%(A1)s';"
     "return '%(A2)s';})()\""
     % {"A1": _A1, "A2": _A2}, False),
    # junk stays quiet
    ("junk-quiet",
     "'Reflect.apply.call(null,function(){\"use strict\";var a=arguments;"
     "return a[0]+a[1];},null,[\\'zz\\',\\'yy\\'])'",
     False),
]


def p1_filed_shapes_held():
    bad = [n for n, p in FILED if not _hit(p)]
    return (("HELD", "%d/%d filed shapes block" % (len(FILED) - len(bad),
                                                  len(FILED)))
            if not bad else ("BREAK", "missed: %s" % bad))


def p2_variants_held():
    # The last-wins variant decodes to zz+A2 (partial credential) --
    # verified separately via the direct parser; here it must at
    # least not crash and the others must block.
    bad = [n for n, p in VARIANTS if n != "f591-setter-twice-last-wins"
           and not _hit(p)]
    # setter-twice-last-wins: decode target is zz+A2 (node-verified);
    # assert the decoder produces exactly that via the IIFE parser.
    from gov.dlp import _js_parse_f578_defineprop_iife
    probe = ("(function(){var o={};Object.defineProperty(o,'c',"
             "{set:function(v){this._c=v;}});o.c='%s';o.c='zz';"
             "return o._c+'%s';})()" % (_A1, _A2))
    val, _ = _js_parse_f578_defineprop_iife(
        probe, 0, 1, {"ops": 0, "parts": 0})
    if val != "zz" + _A2:
        bad.append("f591-setter-twice-last-wins(decode=%r)" % val)
    return (("HELD", "%d/%d variants hold" % (len(VARIANTS) - len(bad),
                                             len(VARIANTS)))
            if not bad else ("BREAK", "missed: %s" % bad))


def p3_fail_closed_boundaries():
    bad = ["%s(want_quiet)" % n for n, p, want in BOUNDS
           if _hit(p) != want]
    return (("HELD", "%d/%d bounds fail closed" % (len(BOUNDS) - len(bad),
                                                  len(BOUNDS)))
            if not bad else ("BREAK", "bad: %s" % bad))


def p4_node_differential():
    # Every filed shape, variant, and boundary above was verified
    # against node v24.20.0 during the lane (see REPORT.md): the
    # decoder blocks exactly the shapes node evaluates to the exact
    # credential, and stays quiet exactly where node throws,
    # yields undefined, or produces a non-credential value. Spot
    # re-verification of the load-bearing equivalences:
    from gov.dlp import _js_parse_f521_call_dispatch, _js_peek_dispatch_call
    from gov.dlp import _js_skip_ws
    # null receiver desugars identically to the Reflect receiver
    t_null = ("Reflect.apply.call(null,function(){var a=arguments;"
              "return a[0]+a[1];},null,['a','b'])")
    t_reflect = ("Reflect.apply.call(Reflect,function(){var a=arguments;"
                 "return a[0]+a[1];},null,['a','b'])")
    results = []
    for t in (t_null, t_reflect):
        j = _js_skip_ws(t, len("Reflect"))
        j = _js_skip_ws(t, j + 1) + len("apply")
        paren = _js_peek_dispatch_call(t, j)[1]
        val, _ = _js_parse_f521_call_dispatch(
            t, paren, 1, {"ops": 0, "parts": 0})
        results.append(val)
    ok = results[0] == results[1] == "ab"
    detail = "null-recv == reflect-recv == 'ab'" if ok else str(results)
    return ("HELD", detail) if ok else ("BREAK", detail)


def p5_compositions():
    # Neighbor findings stay closed; honest anchors still decode.
    must_hit = [
        ("f521-call-still",
         "Reflect.apply.call(Reflect,function(){var a=arguments;"
         "return a[0]+a[1];},null,['%s','%s'])" % (_A1, _A2)),
        ("f570-direct-still",
         "Reflect.apply(function(){\"use strict\";var a=arguments;"
         "return a[0]+a[1];},null,['%s','%s'])" % (_A1, _A2)),
        ("f546-direct-still",
         "Reflect.apply(function(){var a=arguments;"
         "return a[0]+a[1];},null,['%s','%s'])" % (_A1, _A2)),
        ("f550-value-still",
         "Object.defineProperty({},'c',{value:'%s'}).c+'%s'"
         % (_A1, _A2)),
        ("f550-fnexpr-getter-still",
         "Object.defineProperty({},'c',{get:function(){return '%s';}})"
         ".c+'%s'" % (_A1, _A2)),
        ("f578-var-target-still",
         "(function(){var o={};Object.defineProperty(o,'c',"
         "{value:'%s%s'});return o.c;})()" % (_A1, _A2)),
        ("f519-additive-still",
         "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (_A1, _A2)),
        ("f511-call-null-recv-still",
         "((...a)=>a[0]+a[1]).call(null,'%s','%s')" % (_A1, _A2)),
    ]
    bad_hit = [n for n, p in must_hit if not _hit(p)]
    return (("HELD", "%d/%d neighbor compositions hold"
             % (len(must_hit) - len(bad_hit), len(must_hit)))
            if not bad_hit else ("BREAK", "regressed: %s" % bad_hit))


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = (text.count("CLOSED 2026-10-07 wave-371 lane 5") >= 2
                 and "Next free finding: **F672**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
                 and "Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671." in text)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail) if (pin_ok and footer_ok)
            else ("BREAK", detail))


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w370_f590_redfirst.py",
               "w370_f591_redfirst.py",
               "w368_f550_redfirst.py",
               "w369_f578_redfirst.py",
               "w370_f570f577close_probes.py",
               "w370_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g371-green-%s-%d" % (script.replace(".py", ""),
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
