#!/usr/bin/env python3
"""Close battery for F581 (Reflect.apply-dispatch of entries/values on aliased args).

F581 (LOW, filed 2026-10-07 wave-369 attack round 37): F543 closed
Object.entries(a)/Object.values(a) on aliased arguments in DIRECT form,
but dispatching the builtin through Reflect.apply escaped its grammar:
  Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('f1','f2')])[0][1]
  +Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('f1','f2')])[1][1]
  Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('f1','f2')]).join('')
both node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. F481-class composition gap of the F543 closure
(F511 precedent: .apply dispatch is its own class).

Closed (wave-370 lane 7): `_js_parse_reflect_apply_enumb` (routed by the
new "enumbapply" peek in `_js_peek_reflect_apply_target`) desugars
Reflect.apply(Object.entries, thisArg, [X]) /
Reflect.apply(Object.values, thisArg, [X]) to Object.entries(X) /
Object.values(X) node-exactly (thisArg parsed-and-discarded --
node-verified ignored; dot, F490 `?.`, and F480 bracket-string member
forms). X must parse via `_js_parse_primary` to a _JSArr of all-string
elements; entries desugar to the [index-string, value] pairs in
ascending index order, values to the elements (node v24.20.0). The
filed alias-return IIFE element is newly modeled by
`_js_parse_args_alias_return_iife`:
(function(){DECL a=arguments;return a;})(lit...) -> _JSArr(args),
wired into `_js_parse_primary` after F529 (disjoint from F516's
additive bodies -- verified F516 fails closed on it).

Boundaries: argsArray not exactly one element, non-_JSArr elements,
non-all-string elements (no ToString guessing), non-entries/values
targets (Object.keys), ident-boundary violations (Objectx, entriesx),
rebound aliases, non-alias return bodies, non-literal call args,
trailing statements in the IIFE body.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov import decision_codes  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def p1_filed_shapes_held():
    """F581 filed shapes now block coded."""
    shapes = [
        "Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%s','%s')])[0][1]"
        "+Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%s','%s')])[1][1]"
        % (_A, _B, _A, _B),
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Filed-shape variants: member forms, decl forms, prologues, direct arrays."""
    variants = [
        # F480 bracket-string member
        "Reflect.apply(Object['entries'],null,[(function(){var a=arguments;return a;})('%s','%s')])[0][1]"
        "+Reflect.apply(Object['entries'],null,[(function(){var a=arguments;return a;})('%s','%s')])[1][1]"
        % (_A, _B, _A, _B),
        # F490 ?. member
        "Reflect.apply(Object?.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        # F490 ?. Reflect
        "Reflect?.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        # const / let decl in the alias IIFE (node-identical binding)
        "Reflect.apply(Object.values,null,[(function(){const a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        "Reflect.apply(Object.values,null,[(function(){let a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        # F560 directive prologue in the alias IIFE (node-exact, inert)
        "Reflect.apply(Object.values,null,[(function(){'use strict';var a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        # direct array-literal element (engine-identical to the exotic)
        "Reflect.apply(Object.entries,null,[['%s','%s']])[0][1]"
        "+Reflect.apply(Object.entries,null,[['%s','%s']])[1][1]"
        % (_A, _B, _A, _B),
        # non-empty join separator on values
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('-')"
        % (_A, _B),
        # ws tolerance
        "Reflect.apply( Object.entries , null , [ (function(){var a=arguments;return a;})('%s','%s') ] )[0][1]"
        "+Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%s','%s')])[1][1]"
        % (_A, _B, _A, _B),
        # three-arg exotic
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s','zz')]).join('')"
        % (_A, _B),
    ]
    bad = [s for s in variants if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(variants) - len(bad),
                                        len(variants)))


def p3_fail_closed_boundaries():
    """Non-filed shapes stay quiet (fail closed, never mis-decoded)."""
    bounds = [
        # argsArray with two elements (Object.entries takes exactly one arg)
        "Reflect.apply(Object.entries,null,[['%s'],['%s']])[0][1]" % (_A, _B),
        # non-array element
        "Reflect.apply(Object.entries,null,['%s'])[0][1]" % (_A,),
        # non-entries/values target
        "Reflect.apply(Object.keys,null,[['%s','%s']])[0]" % (_A, _B),
        # ident-boundary violations
        "Reflect.apply(Object.entriesx,null,[['%s','%s']])[0][1]" % (_A, _B),
        "Reflect.apply(Objectx.entries,null,[['%s','%s']])[0][1]" % (_A, _B),
        # rebound alias in the IIFE
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;var b=a;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        # returns another ident
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return b;})('%s','%s')]).join('')"
        % (_A, _B),
        # trailing statements after return
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;var z=1;})('%s','%s')]).join('')"
        % (_A, _B),
        # non-literal call args
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})(x+y)]).join('')",
        # alias named `arguments` itself
        "Reflect.apply(Object.values,null,[(function(){var arguments=arguments;return arguments;})('%s','%s')]).join('')"
        % (_A, _B),
        # missing thisArg
        "Reflect.apply(Object.entries,[['%s','%s']])[0][1]" % (_A, _B),
        # extra args after the call
        "Reflect.apply(Object.entries,null,[['%s','%s']],[1])[0][1]" % (_A, _B),
        # object-literal element (not a _JSArr)
        "Reflect.apply(Object.entries,null,[{c:'%s'}])[0][1]" % (_A,),
    ]
    bad = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(bounds) - len(bad), len(bounds)))


def p4_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every variant."""
    cases = [
        "Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%s','%s')])[0][1]"
        "+Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%s','%s')])[1][1]"
        % (_A, _B, _A, _B),
        "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        "Reflect.apply(Object['values'],null,[(function(){const a=arguments;return a;})('%s','%s')]).join('')"
        % (_A, _B),
        "Reflect.apply(Object.entries,null,[['%s','%s']])[0][1]"
        "+Reflect.apply(Object.entries,null,[['%s','%s']])[1][1]"
        % (_A, _B, _A, _B),
        # open-neighbor controls: node yields the credential, decoder must miss
        "Reflect.apply(Object.keys,null,[['%s','%s']]).join('')" % (_A, _B),
        "Reflect.apply(Object.entries,null,[['%s'],['%s']])[0][1]" % (_A, _B),
    ]
    # node truth: does node evaluate to exactly the credential?
    js = "const R=[];\n" + "\n".join(
        "try{R.push(eval(%s)===%s)}catch(e){R.push('err')}"
        % (repr(c), repr(_CRED)) for c in cases) + "\nconsole.log(JSON.stringify(R));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for c, truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        if dec_hit != bool(truth):
            bad.append(c[:60])
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement" % (len(cases) - len(bad),
                                              len(cases)))


def p5_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F543 direct entries/values on aliased args
        "(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');})('%s','%s')"
        % (_A, _B),
        # F546 for-of in direct Reflect.apply target
        "Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%s','%s'])"
        % (_A, _B),
        # F568 entries-idiom body in Reflect.apply target
        "Reflect.apply(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');},null,['%s','%s'])"
        % (_A, _B),
        # F569 call-indirect enum body
        "Reflect.apply.call(Reflect,function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%s','%s'])"
        % (_A, _B),
        # F519 additive arrow target
        "Reflect.apply((a,b)=>a+b,null,['%s','%s'])" % (_A, _B),
        # F547 index reads on plain arrays
        "['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    # open neighbors (real filed shapes) must still miss
    open_neigh = [
        # F570: directive prologue in direct Reflect.apply target
        "Reflect.apply(function(){\"use strict\";var a=arguments;return a[0]+a[1];},null,['%s','%s'])"
        % (_A, _B),
        # F575: String.raw with indexed-object raw
        "String.raw({raw:{0:'%s',1:'%s',length:2}})" % (_A, _B),
        # F582: extra call args beyond arity
        "Reflect.apply((a,b)=>a+b,null,['%s','%s','junk'])" % (_A, _B),
        # F579: Reflect.ownKeys terminal index reads
        "({c:'%s',d:'%s'})[Reflect.ownKeys({c:'%s',d:'%s'})[0]]+'%s'" % (_A, _B, _A, _B, _B),
    ]
    bad_open = [s for s in open_neigh if not _quiet(s)]
    ok = not bad_held and not bad_open
    return ("HELD" if ok else "BREAK",
            "held=%d/%d open-miss=%d/%d" % (len(held) - len(bad_held),
                                            len(held),
                                            len(open_neigh) - len(bad_open),
                                            len(open_neigh)))


def p6_honest_text_quiet():
    """Honest text mentioning the new constructs stays quiet."""
    honest = [
        # prose about the builtins (no credential, no exfiltration)
        "See the Object.entries docs for how to enumerate keys.",
        "Reflect.apply is equivalent to Function.prototype.apply.",
        # code samples over junk fragments
        "Reflect.apply(Object.entries,null,[['zz']])[0][1]",
        "Reflect.apply(Object.values,null,[['zz','yy']]).join('')",
        # alias IIFE over junk
        "(function(){var a=arguments;return a;})('zz','yy').join('')",
        # entries of a junk object via direct form (F517 boundary)
        "Object.entries({c:'zz'})[0][1]",
    ]
    bad = [s for s in honest if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest payloads quiet" % (len(honest) - len(bad),
                                             len(honest)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F581 closed, next F583."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-07 wave-370 lane 7" in text
                 and "Open findings: F595, F606, F608, F609, F610, F611." in text  # Wave-372 merge: footer repoint open F606-F611 / next F612
                 and "Next free finding: **F612**" in text)  # Wave-372 merge: footer repoint next F612
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
    scripts = ("w369_f581_redfirst.py",
               "w368_f543f545f546close_probes.py",
               "w369_f558f567f568f569close_probes.py",
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
              p5_compositions, p6_honest_text_quiet, p7_pin_and_footer]
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
