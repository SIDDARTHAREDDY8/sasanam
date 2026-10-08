#!/usr/bin/env python3
"""Close battery for F543, F545, F546 (arguments family).

F543 (entries/values on aliased arguments): F517 models
Object.entries/Object.values on LITERAL objects, F516 models them on
BARE arguments, F529 models Object.keys/for-in on ALIASES -- but
entries/values on the ALIAS escaped all three. Closed (wave-368 lane
4): `_js_parse_args_entries_values_iife` (+ `_js_parse_f543_*
helpers`), hooked between F533 and F529. `Object.entries(a).map(e=>
e[1])POSTFIX` and `Object.values(a)POSTFIX` (POSTFIX required) parse
over the argument array via the normal postfix grammar. Node-exact
(v24.20.0). Boundaries (documented, all fail closed): entries
without the e[1] map, non-[1] projections, values without postfix,
non-alias receivers, rebound aliases.

F545 (object-pattern destructuring of arguments): F524 modeled only
ARRAY patterns (`const [a,b]=arguments`). Closed: `_js_split_
destructure_var_decl` accepts `{K0:n0(,K1:n1)?}=arguments` with
canonical decimal-int keys, binding key-based via `_js_bind_
destructure_arguments`' new keys parameter. Node-exact (v24.20.0).
Boundaries: string keys, leading-zero keys, negative keys, defaults,
rest, nested patterns, 3+ keys, duplicate keys/names, out-of-range
keys (node coerces undefined -- fail closed).

F546 (arguments-enumerating bodies in function-valued Reflect.apply
targets): F519 modeled additive bodies over declared params; F529/
F533 modeled the IIFE dispatch form. Closed: `_js_parse_fn_enum_
body_target` (+ `_js_parse_f546_aliasadd_body`) extends
`_js_parse_reflect_apply_fn` with a third target form --
`function(){DECL a=arguments; BODY}` where BODY is the F533 for-of
idiom, the F529 for-in idiom, or the bare-alias additive body
(`return a[0]+a[1];`), with the argsArray elements as the arguments.
Node-exact (v24.20.0). Boundaries: declared params, generators,
arrows, bare `arguments`, out-of-range indices (node coerces
undefined -- fail closed), rebound aliases.

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
TAXONOMY_PIN = 2140  # Wave-368 lane 4; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


F543_FILED = [
    ("filed-entries",
     "(function(){var a=arguments;return Object.entries(a).map("
     "function(e){return e[1];}).join('');})('%s','%s')" % (_A1, _A2)),
    ("filed-values",
     "(function(){var a=arguments;return Object.values(a).join('');})"
     "('%s','%s')" % (_A1, _A2)),
]

F543_VARIANTS = [
    ("const-alias-arrow",
     "(function(){const a=arguments;return Object.entries(a).map("
     "e=>e[1]).join('');})('%s','%s')" % (_A1, _A2)),
    ("let-alias-block-arrow",
     "(function(){let a=arguments;return Object.entries(a).map("
     "(e)=>{return e[1];}).join('');})('%s','%s')" % (_A1, _A2)),
    ("bracket-member",
     "(function(){var a=arguments;return Object['entries'](a).map("
     "e=>e[1]).join('');})('%s','%s')" % (_A1, _A2)),
    ("values-bracket",
     "(function(){var a=arguments;return Object['values'](a)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("values-identity-map",
     "(function(){var a=arguments;return Object.values(a).map(x=>x)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("values-identity-map-fn",
     "(function(){var a=arguments;return Object.values(a)"
     ".map(function(x){return x;}).join('');})('%s','%s')"
     % (_A1, _A2)),
    ("three-args",
     "(function(){var a=arguments;return Object.values(a)"
     ".join('');})('%s','%s','zz')" % (_A1, _A2)),
]

F543_BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these
    ("entries-no-map",
     "(function(){var a=arguments;return Object.entries(a)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("entries-e0-projection",
     "(function(){var a=arguments;return Object.entries(a).map("
     "e=>e[0]).join('');})('%s','%s')" % (_A1, _A2)),
    ("entries-whole-pair-projection",
     "(function(){var a=arguments;return Object.entries(a).map("
     "e=>e).join('');})('%s','%s')" % (_A1, _A2)),
    ("values-no-postfix",
     "(function(){var a=arguments;return Object.values(a);})"
     "('%s','%s')" % (_A1, _A2)),
    ("other-receiver",
     "(function(){var a=arguments;return Object.values(b)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("rebound-alias",
     "(function(){var a=arguments;a=['zz'];return Object.values(a)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("entries-identity-map",
     "(function(){var a=arguments;return Object.entries(a).map(x=>x)"
     ".join('');})('%s','%s')" % (_A1, _A2)),
    ("values-nonidentity-map",
     "(function(){var a=arguments;return Object.values(a).map(x=>x[0])"
     ".join('');})('%s','%s')" % (_A1, _A2)),
]

F545_FILED = [
    ("filed-const",
     "(function(){const {0:a,1:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("filed-var",
     "(function(){var {0:x,1:y}=arguments;return x+y;})"
     "('%s','%s')" % (_A1, _A2)),
]

F545_VARIANTS = [
    ("let-decl",
     "(function(){let {0:a,1:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("unsorted-keys-cred-order",
     "(function(){let {1:a,0:b}=arguments;return b+a;})"
     "('%s','%s')" % (_A1, _A2)),
    ("single-key",
     "(function(){const {0:a}=arguments;return a;})"
     "('xoxb-0123456789abcdef')"),
    ("reversed-body",
     "(function(){const {0:a,1:b}=arguments;return b+a;})"
     "('zz','xoxb-0123456789abcdef')"),
    ("ws-noisy",
     "(function(){const { 0 : a , 1 : b }=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
]

F545_BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these.
    # NOTE: credential material is split across two args so a MISS
    # proves the decoder failed closed (a single full-credential
    # literal would HIT via the direct regex regardless of decode).
    ("string-keys",
     "(function(){const {'0':a,'1':b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("leading-zero-key",
     "(function(){const {00:a,01:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("out-of-range-key",
     "(function(){const {0:a,2:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("default",
     "(function(){const {0:a='z',1:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("rest",
     "(function(){const {0:a,...r}=arguments;return a;})"
     "('%s','%s')" % (_A1, _A2)),
    ("nested",
     "(function(){const {0:{a},1:b}=arguments;return b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("three-keys",
     "(function(){const {0:a,1:b,2:c}=arguments;return a+b+c;})"
     "('%s','%s','zz')" % (_A1, _A2)),
    ("duplicate-keys",
     "(function(){const {0:a,0:b}=arguments;return a+b;})"
     "('%s','%s')" % (_A1, _A2)),
    ("duplicate-names",
     "(function(){const {0:a,1:a}=arguments;return a;})"
     "('%s','%s')" % (_A1, _A2)),
    ("shorthand",
     "(function(){const {a,b}=arguments;return a;})"
     "('%s','%s')" % (_A1, _A2)),
]

F546_FILED = [
    ("filed-forof",
     "Reflect.apply(function(){var a=arguments;var s='';"
     "for(var x of a){s+=x;}return s;}, null, ['%s','%s'])"
     % (_A1, _A2)),
    ("filed-forin",
     "Reflect.apply(function(){var a=arguments;var s='';"
     "for(var i in a){s+=a[i];}return s;}, null, ['%s','%s'])"
     % (_A1, _A2)),
    ("filed-bare-alias",
     "Reflect.apply(function(){var a=arguments;return a[0]+a[1];},"
     " null, ['%s','%s'])" % (_A1, _A2)),
]

F546_VARIANTS = [
    ("const-alias-forof",
     "Reflect.apply(function(){const a=arguments;var s='';"
     "for(const x of a){s+=x;}return s;}, null, ['%s','%s'])"
     % (_A1, _A2)),
    ("named-fn-forin-nobraces",
     "Reflect.apply(function f(){var a=arguments;var s='';"
     "for(var k in a)s+=a[k];return s;}, null, ['%s','%s'])"
     % (_A1, _A2)),
    ("let-alias-additive-three",
     "Reflect.apply(function(){let a=arguments;return a[0]+a[1]"
     "+a[2];}, null, ['%s','%s','zz'])" % (_A1, _A2)),
    ("empty-argsarray",
     "Reflect.apply(function(){var a=arguments;return a[0];},"
     " null, ['xoxb-0123456789abcdef'])"),
    ("additive-single",
     "Reflect.apply(function(){var a=arguments;return a[0];},"
     " null, ['xoxb-0123456789abcdef'])"),
    ("ws-noisy",
     "Reflect.apply( function(){ var a = arguments ; var s = '' ;"
     "for( var x of a ){ s += x ; } return s ; } , null ,"
     " [ '%s' , '%s' ] )" % (_A1, _A2)),
]

F546_BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these.
    # NOTE: credential material is split across two args so a MISS
    # proves the decoder failed closed (a single full-credential
    # literal would HIT via the direct regex regardless of decode).
    ("declared-params",
     "Reflect.apply(function(x){var a=arguments;var s='';"
     "for(var k of a){s+=k;}return s;}, null, ['%s','%s'])"
     % (_A1, _A2)),
    ("out-of-range-index",
     "Reflect.apply(function(){var a=arguments;return a[0]+a[5];},"
     " null, ['%s','%s'])" % (_A1, _A2)),
    ("generator-target",
     "Reflect.apply(function*(){var a=arguments;return a[0]+a[1];},"
     " null, ['%s','%s'])" % (_A1, _A2)),
    ("arrow-target",
     "Reflect.apply(()=>{var a=arguments;return a[0]+a[1];},"
     " null, ['%s','%s'])" % (_A1, _A2)),
    ("bare-arguments",
     "Reflect.apply(function(){var s='';for(var k of arguments)"
     "{s+=k;}return s;}, null, ['%s','%s'])" % (_A1, _A2)),
    ("rebound-alias",
     "Reflect.apply(function(){var a=arguments;a=['zz'];"
     "return a[0]+a[1];}, null, ['%s','%s'])" % (_A1, _A2)),
    ("non-canonical-index",
     "Reflect.apply(function(){var a=arguments;return a[00]+a[01];},"
     " null, ['%s','%s'])" % (_A1, _A2)),
    ("additive-non-alias",
     "Reflect.apply(function(){var a=arguments;return a[0]+b;},"
     " null, ['%s','%s'])" % (_A1, _A2)),
    ("keys-body-still-miss",
     "Reflect.apply(function(){var a=arguments;return Object.keys(a)"
     ".map(k=>a[k]).join('');}, null, ['%s','%s'])" % (_A1, _A2)),
]


def p1_filed_shapes_held():
    bad = [n for n, p in F543_FILED + F545_FILED + F546_FILED
           if not _hit(p)]
    return ("HELD", "%d/%d filed shapes block"
            % (len(F543_FILED + F545_FILED + F546_FILED) - len(bad),
               len(F543_FILED + F545_FILED + F546_FILED))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p2_variants_held():
    bad = [n for n, p in F543_VARIANTS + F545_VARIANTS + F546_VARIANTS
           if not _hit(p)]
    return ("HELD", "%d/%d variants block"
            % (len(F543_VARIANTS + F545_VARIANTS + F546_VARIANTS)
               - len(bad),
               len(F543_VARIANTS + F545_VARIANTS + F546_VARIANTS))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p3_fail_closed_boundaries():
    bad = [n for n, p in F543_BOUNDARIES + F545_BOUNDARIES
           + F546_BOUNDARIES if _hit(p)]
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(F543_BOUNDARIES + F545_BOUNDARIES + F546_BOUNDARIES)
               - len(bad),
               len(F543_BOUNDARIES + F545_BOUNDARIES + F546_BOUNDARIES))) \
        if not bad else ("BREAK", "leaked: %s" % bad)


def p4_node_differential():
    # Node-exact expectations established on node v24.20.0.
    pairs = [
        # (decoder input template, node-evaluated expected decode)
        ("(function(){let {1:a,0:b}=arguments;return a+b;})('f1','f2')",
         "f2f1"),
        ("(function(){const {0:a}=arguments;return a;})('f1','f2')",
         "f1"),
        ("Reflect.apply(function(){var a=arguments;return a[1]+a[0];},"
         " null, ['f1','f2'])", "f2f1"),
        ("Reflect.apply(function(){var a=arguments;var s='';"
         "for(var x of a){s+=x;}return s;}, null, [])", ""),
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
    # Neighbor findings stay closed; compositions stay honest.
    must_hit = [
        ("f524-array-still",
         "(function(){const [a,b]=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        ("f529-keys-still",
         "(function(){var a=arguments;return Object.keys(a).map("
         "k=>a[k]).join('');})('%s','%s')" % (_A1, _A2)),
        ("f519-additive-still",
         "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])"
         % (_A1, _A2)),
        ("f516-alias-still",
         "(function(){var a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f533-forof-iife-still",
         "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
         "return s;})('%s','%s')" % (_A1, _A2)),
        ("f517-entries-literal-still",
         "(function(){var o={c:'%s'+'%s'};return Object.entries(o)"
         ".map(e=>e[1]).join('');})()" % (_A1, _A2)),
    ]
    bad = [n for n, p in must_hit if not _hit(p)]
    return ("HELD", "%d/%d neighbor compositions hold"
            % (len(must_hit) - len(bad), len(must_hit))) \
        if not bad else ("BREAK", "regressed: %s" % bad)


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("F543 CLOSED" in text and "F545 CLOSED" in text
                 and "F546 CLOSED" in text
                 and "Next free finding: **F644**" in text)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
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
    scripts = ("w367_f543_redfirst.py",
               "w367_f545_redfirst.py",
               "w367_f546_redfirst.py",
               "w367_f531close_probes.py",
               "w367_f533close_probes.py",
               "w367_f534close_probes.py",
               "w367_f535f536close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g368-green-%s-%d" % (script.replace(".py", ""),
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
