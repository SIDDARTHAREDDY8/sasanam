#!/usr/bin/env python3
"""Wave-366 lane 3: F528/F529 closure probes.

F528 (LOW, filed wave-365 attack round 33, OPEN on base):
Reflect.apply with complex IIFE-evaluated function targets --
`Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['f1','f2'])`
(nested IIFE) and
`Reflect.apply((() => { var f = (a,b)=>a+b; return f; })(), null,
['f1','f2'])` (block-bodied IIFE with an intermediate var). F522
covers single expression-bodied IIFEs.

F529 (LOW, filed wave-365 attack round 33, OPEN on base):
arguments-alias enumerated via Object.keys/for-in --
`(function(){const a=arguments;return
Object.keys(a).map(i=>a[i]).join('');})('f1','f2')` and
`(function(){const a=arguments;var s='';for(var i in
a){s+=a[i];}return s;})('f1','f2')`. Composition of F516 x F517 --
neither closure's source grammar accepts the other's model.

Closure (gov/dlp.py):
- F528: `_js_parse_iife_fn_inner` (with the `_f528_ok` flag) parses
  the IIFE without its invocation; `_js_parse_iife_fn_target` adds
  the zero-arg invocation. With `_f528_ok` true it accepts, beyond
  the strict F522 grammar: (a) one nesting level of parens around
  the F522 shape, either placement -- `((F522-IIFE))()` (filed) or
  `((F522-IIFE)())` (parenthesized invoked IIFE, a trivial
  re-parenthesization an attacker would try); the nested attempt
  recurses strict (`_f528_ok=False`), so deeper nesting fails
  closed; (b) a block body `{ var|const|let f = FN; return f; }`
  (`_js_parse_iife_block_body`) on the arrow and the
  function-expression IIFE forms. Node-exact desugars (v24.20.0):
  the nested IIFE evaluates its inner to FN, the block binds FN to
  one name and returns it, so every shape evaluates to FN itself --
  engine-identical to the literal-FN target F519 models. Fail
  closed: 2+ nesting levels, IIFEs with args, block bodies with
  more statements / another returned ident / non-FN initializers,
  reassigned intermediates (the exact-shape grammar has no room
  for reassignment). Zero new regexes (re.compile stays 28).
- F529: `_js_parse_args_enumerated_iife` (hooked into the
  `(`-dispatch before F516, after F509) composes the F516 binding
  model with the F517 enumeration model: `(function(){DECL
  a=arguments; BODY})(lit, ...)` with DECL in var/const/let (all
  three bind identically, node verified) and BODY either
  `return Object.keys(a).map(CB)POSTFIX;` (CB in
  `p=>a[p]`/`(p)=>a[p]`/`p=>{return a[p];}`/`function(p){return
  a[p];}`, the F517 callback discipline with the alias indexed by
  its own parameter; the postfix parses over the rebuilt argument
  array via the normal postfix grammar) or `var
  s='';for(var K in a){s+=a[K];}return s;` (loop braces optional;
  for-in over the arguments exotic yields the ascending integer
  indices, so the accumulator is the argument join). Node-exact
  (v24.20.0): Object.keys on arguments is ['0',...] ascending;
  both shapes rebuild the argument values in order. Fail closed:
  non-`arguments` sources, rebound aliases, non-identity
  projections, params shadowing the alias, enumerating bare
  `arguments`, non-literal call args, non-empty accumulators.
  Zero new regexes.

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed
shape misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-366 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

FILED_F528 = [
    ("nested-iife-target",
     "Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, "
     "['%s','%s'])" % (_A1, _A2)),
    ("block-bodied-iife-target",
     "Reflect.apply((() => { var f = (a,b)=>a+b; return f; })(), null, "
     "['%s','%s'])" % (_A1, _A2)),
]

FILED_F529 = [
    ("alias-keys-indexed",
     "(function(){const a=arguments;return "
     "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')" % (_A1, _A2)),
    ("alias-forin-accum",
     "(function(){const a=arguments;var s='';for(var i in a)"
     "{s+=a[i];}return s;})('%s','%s')" % (_A1, _A2)),
]

F528_VARIANTS = [
    ("nested-paren-invoked",
     "Reflect.apply((() => ((() => (a,b)=>a+b)()))(), null, "
     "['%s','%s'])" % (_A1, _A2)),
    ("block-const",
     "Reflect.apply((() => { const f = (a,b)=>a+b; return f; })(), null, "
     "['%s','%s'])" % (_A1, _A2)),
    ("block-let",
     "Reflect.apply((() => { let f = (a,b)=>a+b; return f; })(), null, "
     "['%s','%s'])" % (_A1, _A2)),
    ("block-function-expr",
     "Reflect.apply((function(){ var g = function(a,b){return a+b;}; "
     "return g; })(), null, ['%s','%s'])" % (_A1, _A2)),
]

F529_VARIANTS = [
    ("alias-var",
     "(function(){var a=arguments;return "
     "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')" % (_A1, _A2)),
    ("alias-let-bracket-keys",
     "(function(){let a=arguments;return "
     "Object['keys'](a).map((i)=>a[i]).join('');})('%s','%s')"
     % (_A1, _A2)),
    ("alias-function-callback",
     "(function(){const a=arguments;return "
     "Object.keys(a).map(function(i){return a[i];}).join('');})"
     "('%s','%s')" % (_A1, _A2)),
    ("alias-braced-callback",
     "(function(){const a=arguments;return "
     "Object.keys(a).map(i=>{return a[i];}).join('');})('%s','%s')"
     % (_A1, _A2)),
    ("alias-forin-unbraced",
     "(function(){const a=arguments;var s='';for(var i in a)"
     "s+=a[i];return s;})('%s','%s')" % (_A1, _A2)),
    ("alias-other-name",
     "(function(){const b=arguments;return "
     "Object.keys(b).map(i=>b[i]).join('');})('%s','%s')" % (_A1, _A2)),
    ("alias-postfix-slice",
     "(function(){const a=arguments;return "
     "Object.keys(a).map(i=>a[i]).slice(0,2).join('');})('%s','%s')"
     % (_A1, _A2)),
]


def _hit(payload):
    return dlp.find_credential(payload) is not None


def p1_f528_filed_shapes_held():
    """The two filed F528 shapes decode (HELD)."""
    misses = [n for n, p in FILED_F528 if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "2/2 filed F528 shapes decode")


def p2_f529_filed_shapes_held():
    """The two filed F529 shapes decode (HELD)."""
    misses = [n for n, p in FILED_F529 if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "2/2 filed F529 shapes decode")


def p3_node_differential():
    """The desugars are node-exact (node v24.20.0 byte-identical)."""
    js = r"""
const A1='xoxb-0123', A2='456789abcdef';
const out = [];
out.push(Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, [A1,A2]) === A1+A2);
out.push(Reflect.apply((() => { var f = (a,b)=>a+b; return f; })(), null, [A1,A2]) === A1+A2);
out.push(Reflect.apply((() => ((() => (a,b)=>a+b)()))(), null, [A1,A2]) === A1+A2);
out.push(Reflect.apply((() => { const f = (a,b)=>a+b; return f; })(), null, [A1,A2]) === A1+A2);
out.push((function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})(A1,A2) === A1+A2);
out.push((function(){const a=arguments;var s='';for(var i in a){s+=a[i];}return s;})(A1,A2) === A1+A2);
out.push((function(){var a=arguments;return Object.keys(a).map(i=>a[i]).join('');})(A1,A2) === A1+A2);
out.push(JSON.stringify(Object.keys((function(){return arguments})(A1,A2))) === JSON.stringify(['0','1']));
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr.strip()[:200])
    import json
    try:
        vals = json.loads(r.stdout.strip())
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node parse: %s" % e)
    if not all(vals) or len(vals) != 8:
        return ("BREAK", "node mismatch: %s" % vals)
    return ("HELD", "8/8 node byte-identical")


def p4_fail_closed_boundaries():
    """Documented fail-closed boundaries miss (HELD = correctly missed)."""
    # (name, payload, want_hit)
    bounds = [
        # F528 boundaries: deeper nesting / arg-carrying IIFEs /
        # multi-statement or mis-bound block bodies
        ("nest2-beyond-one",
         "Reflect.apply((() => (((() => (a,b)=>a+b))())())(), null, "
         "['%s','%s'])" % (_A1, _A2), False),
        ("iife-with-params",
         "Reflect.apply(((p) => (a,b)=>a+b)(), null, "
         "['%s','%s'])" % (_A1, _A2), False),
        ("block-two-statements",
         "Reflect.apply((() => { var f = (a,b)=>a+b; var h = f; "
         "return h; })(), null, ['%s','%s'])" % (_A1, _A2), False),
        ("block-returns-other-ident",
         "Reflect.apply((() => { var f = (a,b)=>a+b; return g; })(), "
         "null, ['%s','%s'])" % (_A1, _A2), False),
        ("block-non-fn-init",
         "Reflect.apply((() => { var f = 42; return f; })(), null, "
         "['%s','%s'])" % (_A1, _A2), False),
        ("iife-invoked-with-args",
         "Reflect.apply((() => (a,b)=>a+b)(1), null, "
         "['%s','%s'])" % (_A1, _A2), False),
        # F529 boundaries: rebound aliases / non-identity projections /
        # shadowing params / wrong sources / non-empty accumulators
        ("non-identity-projection",
         "(function(){const a=arguments;return "
         "Object.keys(a).map(i=>i).join('');})('%s','%s')" % (_A1, _A2),
         False),
        ("param-shadows-alias",
         "(function(){const a=arguments;return "
         "Object.keys(a).map(a=>a[a]).join('');})('%s','%s')"
         % (_A1, _A2), False),
        ("keys-of-other-ident",
         "(function(){const a=arguments;return "
         "Object.keys(b).map(i=>a[i]).join('');})('%s','%s')"
         % (_A1, _A2), False),
        ("forin-nonempty-accum",
         "(function(){const a=arguments;var s='x';for(var i in a)"
         "{s+=a[i];}return s;})('%s','%s')" % (_A1, _A2), False),
        ("forin-iterates-other",
         "(function(){const a=arguments;var o={};var s='';"
         "for(var i in o){s+=o[i];}return s;})('%s','%s')"
         % (_A1, _A2), False),
        ("alias-rebound",
         "(function(){let a=arguments;a='x';return "
         "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
         % (_A1, _A2), False),
        ("src-not-arguments",
         "(function(){const a=Array.from(arguments);return "
         "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
         % (_A1, _A2), False),
        ("junk", "(function(){const a=arguments;return "
         "Object.keys(a).map(i=>a[i]).join('');})('ab','cd')", False),
    ]
    wrong = [n for n, p, want in bounds if _hit(p) != want]
    if wrong:
        return ("BREAK", "boundary wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d boundaries node-honest" % (len(bounds),
                                                      len(bounds)))


def p5_compositions():
    """Adjacent closures stay HELD; F528/F529 close independently."""
    comps = [
        # F528 vs F522: single-IIFE targets stay HELD both directions
        ("f522-arrow-iife",
         "Reflect.apply((() => (a,b)=>a+b)(), null, "
         "['%s','%s'])" % (_A1, _A2), True),
        ("f522-function-iife",
         "Reflect.apply((function(){return (a,b)=>a+b})(), null, "
         "['%s','%s'])" % (_A1, _A2), True),
        # F528 vs F519: literal targets stay HELD
        ("f519-arrow-target",
         "Reflect.apply((a,b)=>a+b, null, "
         "['%s','%s'])" % (_A1, _A2), True),
        ("f519-function-target",
         "Reflect.apply(function(a,b){return a+b}, null, "
         "['%s','%s'])" % (_A1, _A2), True),
        # F529 vs F516: bare alias dispatch stays HELD (var form; the
        # const-alias form is a documented F516 var-only boundary)
        ("f516-alias",
         "(function(){var a=arguments;return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2), True),
        ("f516-const-alias-boundary",
         "(function(){const a=arguments;return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2), False),
        # F529 vs F517: keys/for-in over literals stay HELD
        ("f517-keys",
         "Object.keys({'%s':'x','%s':'y'}).map(k=>k).join('')"
         % (_A1, _A2), True),
        ("f517-forin",
         "(function(){var s='';var o={'a':'%s','b':'%s'};"
         "for(var k in o)s+=o[k];return s})()" % (_A1, _A2), True),
        # F529 vs F524: destructured variants stay HELD / fail-closed
        ("f524-destructure",
         "(function(){const [a,b]=arguments;return a+b})"
         "('%s','%s')" % (_A1, _A2), True),
        ("f524-destructure-enumerated-fail-closed",
         "(function(){const [a,b]=arguments;return "
         "Object.keys(a).map(i=>a[i]).join('');})"
         "('%s','%s')" % (_A1, _A2), False),
        # F529 x F496: indexed-key member over the enumeration
        ("f496-member",
         "(function(){const a=arguments;return "
         "Object.keys(a).map(i=>a[i])['join']('');})"
         "('%s','%s')" % (_A1, _A2), True),
    ]
    wrong = [n for n, p, want in comps if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest" % (len(comps),
                                                   len(comps)))


def p6_pin_and_footer():
    """Pin stays 2140; no new regexes; F528/F529 CLOSED in FINDINGS;
    lane-local footer."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if text.count("CLOSED 2026-10-07 wave-366 lane 3") < 2:
        return ("BREAK", "F528/F529 CLOSED entries missing")
    # Wave-367 merge: F537-F546 open, next F547.
    if "Open findings: F595, F606, F608, F609, F610, F611." not in text:  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **F612**" not in text:  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2140; 28 re.compile; F528/F529 CLOSED; "
            "footer F531,F533,F535,F536/next F537")


def p7_f528_variants_held():
    """The F528 variant shapes decode (HELD) -- node-exact extensions."""
    misses = [n for n, p in F528_VARIANTS if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F528 variants decode" % (len(F528_VARIANTS),
                                                    len(F528_VARIANTS)))


def p8_f529_variants_held():
    """The F529 variant shapes decode (HELD) -- node-exact extensions."""
    misses = [n for n, p in F529_VARIANTS if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F529 variants decode" % (len(F529_VARIANTS),
                                                    len(F529_VARIANTS)))


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w365_f528_redfirst.py",
               "w365_f529_redfirst.py",
               "w365_f522f525close_probes.py",
               "w364_f513f519close_probes.py",
               "w364_f516f517close_probes.py",
               "w365_f523f524close_probes.py",
               "w361_f496f497close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g366-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_f528_filed_shapes_held, p2_f529_filed_shapes_held,
              p3_node_differential, p4_fail_closed_boundaries,
              p5_compositions, p6_pin_and_footer,
              p7_f528_variants_held, p8_f529_variants_held]
    breaks, held, errors = 0, 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "ERROR":
            errors += 1
        else:
            breaks += 1
    print("green check: %s" % _green_check())
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
