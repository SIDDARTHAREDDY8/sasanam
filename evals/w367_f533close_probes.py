#!/usr/bin/env python3
"""Close battery for F533: for-of enumeration of aliased arguments.

F529 closed arguments-alias enumeration via Object.keys/for-in
(`Object.keys(a).map(i=>a[i])`, `for(var i in a){s+=a[i];}`). F533
closes the for-of value-iteration form
(`for(var x of a){s+=x;}`), which iterates VALUES directly (the
arguments exotic's Symbol.iterator) -- a different construct neither
F529's nor F517's grammar covers.

Closure (wave-367 lane 2): gov/dlp.py `_js_parse_args_forof_iife`
(+ `_js_parse_f533_forof_accum`), hooked before F529. Node-exact
(v24.20.0): `var|let s='';for(var|let|const x of a){s+=x;}return s;`
over `DECL a=arguments` (DECL in var/const/let) desugars to the
argument join. Boundaries (documented, all fail closed): bare
`arguments` for-of (F529 precedent), shadowed loopvar/accumulator,
destructuring targets, undeclared loopvar, non-`+=` bodies,
non-empty/`const` accumulators, extra statements, rebound aliases.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
Zero paid API calls: this battery shells only to `node` and to
adjacent in-repo batteries (green check). $0 spend by construction.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2135  # Wave-367 lane 2; pin stays 2135

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


F533_FILED = [
    ("filed-var",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("filed-let-alias",
     "(function(){let a=arguments;let s='';for(let x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
]

F533_VARIANTS = [
    ("const-alias-loopvar",
     "(function(){const a=arguments;var s='';for(const x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("nobraces",
     "(function(){var a=arguments;var s='';for(var x of a)s+=x;"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("let-accum",
     "(function(){var a=arguments;let s='';for(var x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("mixed-decl",
     "(function(){let a=arguments;var s='';for(const x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("ws-noisy",
     "(function(){var a=arguments;var s='';for( var x of a ){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("three-args",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
     "return s;})('%s','%s','zz')" % (_A1, _A2)),
]

F533_BOUNDARIES = [
    # documented fail-closed: the decoder must MISS these
    ("bare-arguments",
     "(function(){var s='';for(var x of arguments){s+=x;}return s;})"
     "('%s','%s')" % (_A1, _A2)),
    ("shadow-alias",
     "(function(){var a=arguments;var s='';for(var a of a){s+=a;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("destructuring",
     "(function(){var a=arguments;var s='';for(var [x] of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("nodecl-loopvar",
     "(function(){var a=arguments;var s='';for(x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("assign-plus",
     "(function(){var a=arguments;var s='';for(var x of a){s=s+x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("nonempty-accum",
     "(function(){var a=arguments;var s='z';for(var x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("const-accum",
     "(function(){var a=arguments;const s='';for(var x of a){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("extra-stmt",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
     "s+='';return s;})('%s','%s')" % (_A1, _A2)),
    ("rebound",
     "(function(){var a=arguments;a=['x'];var s='';"
     "for(var x of a){s+=x;}return s;})('%s','%s')" % (_A1, _A2)),
    ("body-reads-other",
     "(function(){var a=arguments;var s='';var y='q';"
     "for(var x of a){s+=y;}return s;})('%s','%s')" % (_A1, _A2)),
    ("iterates-other-object",
     "(function(){var a=arguments;var s='';for(var x of ['f1']){s+=x;}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("nosemi-loop-body",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x}"
     "return s;})('%s','%s')" % (_A1, _A2)),
    ("symbol-iterator-override",
     "(function(){var a=arguments;a[Symbol.iterator]=function*(){yield 'zzz';};"
     "var s='';for(var x of a){s+=x;}return s;})('%s','%s')" % (_A1, _A2)),
    ("nonliteral-call-args",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
     "return s;})(zz1,zz2)"),
]


def p1_f533_filed_shapes_held():
    """The two filed F533 shapes decode (HELD)."""
    misses = [n for n, p in F533_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d filed shapes decode" % (len(F533_FILED),
                                                   len(F533_FILED)))


def p2_f533_variants_held():
    """The F533 variant shapes decode (HELD) -- node-exact extensions."""
    misses = [n for n, p in F533_VARIANTS if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d variants decode" % (len(F533_VARIANTS),
                                               len(F533_VARIANTS)))


def p3_node_differential():
    """The desugars are node-exact (node v24.20.0 byte-identical)."""
    js = r"""
const A1='xoxb-0123', A2='456789abcdef';
const out = [];
out.push((function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})(A1,A2) === A1+A2);
out.push((function(){let a=arguments;let s='';for(let x of a){s+=x;}return s;})(A1,A2) === A1+A2);
out.push((function(){const a=arguments;var s='';for(const x of a){s+=x;}return s;})(A1,A2) === A1+A2);
out.push((function(){var a=arguments;var s='';for(var x of a)s+=x;return s;})(A1,A2) === A1+A2);
out.push((function(){var a=arguments;let s='';for(var x of a){s+=x;}return s;})(A1,A2) === A1+A2);
out.push((function(){let a=arguments;var s='';for(const x of a){s+=x;}return s;})(A1,A2) === A1+A2);
out.push((function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})(A1,A2,'zz') === A1+A2+'zz');
// boundaries: node-evaluated truth the decoder must NOT model
out.push((function(){var s='';for(var x of arguments){s+=x;}return s;})(A1,A2) === A1+A2); // bare-args: real, residual
out.push((function(){var a=arguments;var s='';for(var a of a){s+=a;}return s;})(A1,A2) === A1+A2); // shadow: real, guarded
out.push((function(){var a=arguments;var s='z';for(var x of a){s+=x;}return s;})(A1,A2) === 'z'+A1+A2); // nonempty
out.push((function(){var a=arguments;a[Symbol.iterator]=function*(){yield 'zzz';};var s='';for(var x of a){s+=x;}return s;})(A1,A2) === 'zzz'); // iterator override: real, guarded
out.push((()=>{try{(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})(zz1);return false;}catch(e){return e instanceof ReferenceError;}})()); // non-literal args: throws
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
    if not all(vals) or len(vals) != 12:
        return ("BREAK", "node mismatch: %s" % vals)
    return ("HELD", "12/12 node byte-identical")


def p4_fail_closed_boundaries():
    """The documented F533 boundaries fail closed (MISS)."""
    hits = [n for n, p in F533_BOUNDARIES if _hit(p)]
    if hits:
        return ("BREAK", "wrongly decoded: %s" % ",".join(hits))
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(F533_BOUNDARIES), len(F533_BOUNDARIES)))


def p5_compositions():
    """Adjacent closures stay HELD; F533 closes independently."""
    comps = [
        # F533 vs F529: key-enumeration forms stay HELD
        ("f529-keys",
         "(function(){const a=arguments;return "
         "Object.keys(a).map(i=>a[i]).join('');})('%s','%s')"
         % (_A1, _A2), True),
        ("f529-forin",
         "(function(){var a=arguments;var s='';for(var i in a){s+=a[i];}"
         "return s;})('%s','%s')" % (_A1, _A2), True),
        ("f529-forin-nobraces",
         "(function(){var a=arguments;var s='';for(var i in a)s+=a[i];"
         "return s;})('%s','%s')" % (_A1, _A2), True),
        # F533 vs F516: bare alias dispatch stays HELD
        ("f516-alias",
         "(function(){var a=arguments;return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2), True),
        # F533 vs F517: keys/for-in over literals stay HELD
        ("f517-keys",
         "Object.keys({'%s':'x','%s':'y'}).map(k=>k).join('')"
         % (_A1, _A2), True),
        ("f517-forin",
         "(function(){var s='';var o={'a':'%s','b':'%s'};"
         "for(var k in o)s+=o[k];return s})()" % (_A1, _A2), True),
        # F533 vs F524: destructured arguments stay HELD / fail-closed
        ("f524-destructure",
         "(function(){const [a,b]=arguments;return a+b})"
         "('%s','%s')" % (_A1, _A2), True),
        ("f524-destructure-forof-fail-closed",
         "(function(){const [a,b]=arguments;var s='';"
         "for(var x of a){s+=x;}return s;})('%s','%s')"
         % (_A1, _A2), False),
        # F533 for-of must not steal F529's for-in (chargeless reject)
        ("f533-rejects-forin-chargeless",
         "(function(){var a=arguments;var s='';for(var i in a){s+=a[i];}"
         "return s;})('%s','%s')" % (_A1, _A2), True),
    ]
    wrong = [n for n, p, want in comps if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest" % (len(comps),
                                                   len(comps)))


def p6_pin_and_footer():
    """Pin stays 2135; no new regexes; F533 CLOSED in FINDINGS;
    lane-local footer."""
    if TAXONOMY_PIN != 2135:
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "CLOSED 2026-10-07 wave-367 lane 2" not in text:
        return ("BREAK", "F533 CLOSED entry missing")
    if "Open findings: F531, F534, F535, F536." not in text:
        return ("BREAK", "merged footer wrong")
    if "Next free finding: **F537**" not in text:
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2135; 28 re.compile; F533 CLOSED; "
            "footer F531,F534-F536/next F537")


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w366_f533_redfirst.py",
               "w366_f528f529close_probes.py",
               "w366_f527f530close_probes.py",
               "w366_f526close_probes.py",
               "w365_f523f524close_probes.py",
               "w364_f516f517close_probes.py",
               "w365_f522f525close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g367-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_f533_filed_shapes_held, p2_f533_variants_held,
              p3_node_differential, p4_fail_closed_boundaries,
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
