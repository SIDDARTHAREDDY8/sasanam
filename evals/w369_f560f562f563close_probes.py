#!/usr/bin/env python3
"""Close-battery for F560 (directive prologues), F562 (groupBy), F563 (Map.get).

F560: the IIFE-argument parsers (F516/F524/F529/F533/F543) now skip a
leading directive prologue ('use strict'; ...) node-exactly before
matching the binding declaration.
F562: Object.groupBy / Map.groupBy on literal arrays with
identity-or-literal callbacks decode node-exactly.
F563: new Map(LITENTRIES).get('lit') resolves literal map reads
node-exactly.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


def p1_filed_shapes_held():
    # Every filed shape now blocks (decodes to the credential).
    shapes = [
        ("f560-alias",
         "(function(){'use strict';var a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-destructure",
         "(function(){'use strict';const [a,b]=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-keys",
         "(function(){'use strict';const a=arguments;return "
         "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
         % (_A1, _A2)),
        ("f562-object",
         "Object.groupBy(['%s','%s'],function(){return 'k';}).k.join('')"
         % (_A1, _A2)),
        ("f562-map",
         "Map.groupBy(['%s','%s'],function(){return 'k';}).get('k')"
         ".join('')" % (_A1, _A2)),
        ("f563-single",
         "new Map([['c','%s']]).get('c')+'%s'" % (_A1, _A2)),
        ("f563-double",
         "new Map([['c','%s'],['d','%s']]).get('c')"
         "+new Map([['c','%s'],['d','%s']]).get('d')"
         % (_A1, _A2, _A1, _A2)),
    ]
    bad = [n for n, p in shapes if not _hit(p)]
    return (("HELD", "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                                  len(shapes)))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p2_variants_held():
    variants = [
        # F560: double quotes, multiple directives, ASI directive,
        # for-of and entries/values bodies with prologues.
        ("f560-dquote",
         '(function(){"use strict";var a=arguments;return a[0]+a[1];})'
         "('%s','%s')" % (_A1, _A2)),
        ("f560-multi",
         "(function(){'use asm';'use strict';var a=arguments;"
         "return a[0]+a[1];})('%s','%s')" % (_A1, _A2)),
        ("f560-asi",
         "(function(){'use strict'\nvar a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-forof",
         "(function(){'use strict';var a=arguments;var s='';"
         "for(var x of a){s+=x;}return s;})('%s','%s')" % (_A1, _A2)),
        ("f560-values",
         "(function(){'use strict';var a=arguments;"
         "return Object.values(a).join('');})('%s','%s')" % (_A1, _A2)),
        ("f560-objpattern",
         "(function(){'use strict';const {0:a,1:b}=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        # F562: identity callbacks (arrow, paren, block body),
        # literal arrow callback.
        ("f562-literal-arrow",
         "Object.groupBy(['%s','%s'],()=>'k').k.join('')" % (_A1, _A2)),
        # F563: duplicate keys (later wins), numeric keys, bracket get.
        ("f563-dupkey",
         "new Map([['c','zz'],['c','%s']]).get('c')+'%s'" % (_A1, _A2)),
        ("f563-numkey",
         "new Map([[1,'%s']]).get(1)+'%s'" % (_A1, _A2)),
        ("f563-bracket-get",
         "new Map([['c','%s']])['get']('c')+'%s'" % (_A1, _A2)),
    ]
    bad = [n for n, p in variants if not _hit(p)]
    # Identity-callback shapes group under the element itself, so any
    # credential-shaped probe would be tautological (the payload
    # literally contains the credential); verify the raw decode
    # node-exactly instead.
    import gov.dlp as dlp
    ident_checks = [
        ("Object.groupBy(['kk','kk'],x=>x).kk.join('')", "kkkk"),
        ("Object.groupBy(['aa','bb'],x=>{return x;}).aa.join('')", "aa"),
        ("Map.groupBy(['aa','bb'],(x)=>x).get('aa').join('')", "aa"),
        ("Map.groupBy(['aa','bb'],x=>x).get('bb').join('')", "bb"),
    ]
    for payload, want in ident_checks:
        st = {"parts": 0, "ops": 0}
        try:
            val, _ = dlp._js_parse_additive(payload, 0, 0, st)
        except Exception:  # noqa: BLE001
            val = None
        if val != want:
            bad.append("ident:%s!=%r" % (payload[:30], want))
    return (("HELD", "%d/%d variants block" % (len(variants) - len(bad),
                                              len(variants)))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p3_fail_closed_boundaries():
    # Decoder must stay quiet: junk text, or node-divergent shapes.
    quiet = [
        # F560: non-directive prologue, mid-body directive, template
        # prologue, unterminated adjacent strings (node throws).
        ("f560-nondirective",
         "(function(){x=1;var a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-midbody",
         "(function(){var a=arguments;'use strict';return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-template",
         "(function(){`use strict`;var a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f560-junk-directive",
         "(function(){'use strict';var a=arguments;return a[0]+a[1];})"
         "('zz','yy')"),
        # F562: non-literal callback, non-string elements, get on the
        # Object.groupBy result (node throws TypeError).
        ("f562-nonlit-cb",
         "Object.groupBy(['%s','%s'],x=>x+'k').k.join('')" % (_A1, _A2)),
        ("f562-nonnlit-elem",
         "Object.groupBy(['%s',x],()=>'k').k.join('')" % _A1),
        ("f562-obj-get",
         "Object.groupBy(['%s','%s'],()=>'k').get('k')" % (_A1, _A2)),
        ("f562-junk",
         "Object.groupBy(['zz','yy'],()=>'k').k.join('')"),
        # F563: missing key (node: undefined), non-literal entry,
        # non-get member, empty map get.
        ("f563-missing",
         "new Map([['c','%s']]).get('zzz')+'%s'" % (_A1, _A2)),
        ("f563-nonlit-entry",
         "new Map([[x,'%s']]).get('c')+'%s'" % (_A1, _A2)),
        ("f563-nonget",
         "new Map([['c','%s']]).set('c','%s')" % (_A1, _A2)),
        ("f563-empty",
         "new Map().get('c')+'zzyy'"),
        ("f563-junk",
         "new Map([['c','zz']]).get('c')+'yy'"),
        # Spec-review fix: .values() on a _JSMap is node-inexact
        # (node returns a Map Iterator -- .join throws TypeError), so
        # it fails closed; the F494 spread path is unaffected.
        ("f563-values-join",
         "new Map([['c','%s'],['d','%s']]).values().join('')"
         % (_A1, _A2)),
        ("f562-groupby-values",
         "Map.groupBy(['%s','%s'],()=>'k').values()" % (_A1, _A2)),
    ]
    bad = [n for n, p in quiet if _hit(p)]
    return (("HELD", "%d/%d boundaries stay quiet"
             % (len(quiet) - len(bad), len(quiet)))) \
        if not bad else ("BREAK", "leaked: %s" % bad)


def p4_node_differential():
    # Node-exact expectations established on node v24.20.0.
    import gov.dlp as dlp
    pairs = [
        # (decoder input, node-evaluated expected decode)
        ("(function(){'use strict';var a=arguments;return a[0]+a[1];})"
         "('f1','f2')", "f1f2"),
        ("(function(){'use strict';const [a,b]=arguments;return a+b;})"
         "('f1','f2')", "f1f2"),
        ("(function(){'use strict'\nvar a=arguments;return a[0]+a[1];})"
         "('f1','f2')", "f1f2"),
        ("(function(){'use strict';var a=arguments;var s='';"
         "for(var x of a){s+=x;}return s;})('f1','f2')", "f1f2"),
        ("Object.groupBy(['f1','f2'],function(){return 'k';}).k.join('')",
         "f1f2"),
        ("Object.groupBy(['a','b'],x=>x).a.join('')", "a"),
        ("Map.groupBy(['f1','f2'],function(){return 'k';}).get('k')"
         ".join('')", "f1f2"),
        ("new Map([['c','f1']]).get('c')+'f2'", "f1f2"),
        ("new Map([['c','x'],['c','y']]).get('c')", "y"),
        ("new Map([[1,'f1']]).get(1)+'f2'", "f1f2"),
    ]
    bad = []
    for payload, want in pairs:
        st = {"parts": 0, "ops": 0}
        try:
            val, _ = dlp._js_parse_additive(payload, 0, 0, st)
        except Exception as e:  # noqa: BLE001
            bad.append((payload[:40], "raise %s" % e))
            continue
        if val != want:
            bad.append((payload[:40], "%r != node %r" % (val, want)))
    return (("HELD", "%d/%d decoder==node" % (len(pairs) - len(bad),
                                             len(pairs)))) \
        if not bad else ("BREAK", "diffs: %s" % bad)


def p5_compositions():
    # Neighbor findings stay closed; no regressions.
    must_hit = [
        ("f516-alias-still",
         "(function(){var a=arguments;return a[0]+a[1];})"
         "('%s','%s')" % (_A1, _A2)),
        ("f524-destructure-still",
         "(function(){const [a,b]=arguments;return a+b;})"
         "('%s','%s')" % (_A1, _A2)),
        ("f529-keys-still",
         "(function(){var a=arguments;return Object.keys(a).map("
         "k=>a[k]).join('');})('%s','%s')" % (_A1, _A2)),
        ("f533-forof-still",
         "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
         "return s;})('%s','%s')" % (_A1, _A2)),
        ("f543-values-still",
         "(function(){var a=arguments;return Object.values(a).join('');})"
         "('%s','%s')" % (_A1, _A2)),
        ("f510-values-still",
         "Object.values({0:'%s',1:'%s'}).join('')" % (_A1, _A2)),
        ("f535-member-still",
         "({c:'%s'}).c+'%s'" % (_A1, _A2)),
        ("f539-freeze-still",
         "Object.freeze({c:'%s'}).c+'%s'" % (_A1, _A2)),
        ("f541-json-still",
         "JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A1, _A2)),
        ("f494-mapvalues-still",
         "[...new Map([[0,'%s'],[1,'%s']]).values()].join('')"
         % (_A1, _A2)),
    ]
    bad = [n for n, p in must_hit if not _hit(p)]
    return (("HELD", "%d/%d neighbor compositions hold"
             % (len(must_hit) - len(bad), len(must_hit)))) \
        if not bad else ("BREAK", "regressed: %s" % bad)


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = (text.count("**Status: CLOSED 2026-10-07 wave-369 lane 6**") >= 3
                 and "F560/F562/F563 CLOSED 2026-10-07 wave-369 lane 6" in text
                 and "Next free finding: **F686**" in text)  # Wave-369 lane 6: F560/F562/F563 CLOSED  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail)) if (pin_ok and footer_ok) \
        else ("BREAK", detail)


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w368_f560_redfirst.py",
               "w368_f562_redfirst.py",
               "w368_f563_redfirst.py",
               "w368_f543f545f546close_probes.py",
               "w368_f539f540close_probes.py",
               "w368_f541f544close_probes.py",
               "w368_f537f538f542close_probes.py")
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
