#!/usr/bin/env python3
"""Wave-363 lane 3: F509 closure probes.

F509 (LOW, filed wave-362 attack round 30, OPEN on base): the bare
`arguments` exotic object as a dispatch receiver bypasses the bounded
static JS-expression decoder -- F489 closed arguments-IIFE receivers
((function(){return arguments})('f1','f2') -> _JSArr), but the bare
`arguments` identifier inside a function invoked with literal args
bypasses the IIFE-pattern anchor: the decoder has no call-site
argument binding.

Closure (gov/dlp.py): the F509 call-site argument binding desugar --
`(function(){return BODY})(lit, ...)` (anonymous, zero params, single
`return EXPR;`) rewrites the three node-exact `arguments` forms
(`...arguments` -> `...['lits']`, `arguments[N]` -> the Nth literal,
bare `arguments` -> `['lits']`) and parses the rewritten body with the
normal additive grammar at depth+1. Also hooked in dispatch-receiver
position (array-like results only). Zero new regexes (re.compile stays
28); all guards are plain string scans.

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed shape
misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import json
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-363 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

FILED = [
    ("filed-join",
     "(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (_A1, _A2)),
    ("filed-slice",
     "(function(){return Array.prototype.slice.call(arguments, 0).join('')})('%s','%s')" % (_A1, _A2)),
    ("filed-index",
     "(function(){return arguments[0]+arguments[1]})('%s','%s')" % (_A1, _A2)),
    ("filed-spread",
     "(function(){return [].concat(...arguments).join('')})('%s','%s')" % (_A1, _A2)),
    ("filed-reduce",
     "(function(){return Array.prototype.reduce.call(arguments,(a,b)=>a+b)})('%s','%s')" % (_A1, _A2)),
]


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decoded(payload):
    return dlp._try_js_expr_decode_all(payload)


def _node_eval(shapes):
    js = ("const out=[];\n" +
          "".join("try{out.push(JSON.stringify(%s))}catch(e){out.push('THROWS')}\n" % s
                  for s in shapes) +
          "console.log(out.join('\\n'))")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=120)
    if r.returncode != 0:
        raise RuntimeError("node failed: %s" % r.stderr[:200])
    return r.stdout.splitlines()


def p1_filed_shapes_held():
    """The five F509 filed shapes now block (were 5 BREAK on base)."""
    bad = [name for name, payload in FILED if not _blocked(payload)]
    if bad:
        return ("BREAK", "filed shapes still miss: %s" % bad)
    return ("HELD", "5/5 filed shapes block")


def p2_node_differential():
    """Decoder output byte-identical to node v24.20.0 on all filed shapes,
    plus whitespace/quote/escape variants."""
    shapes = [p for _, p in FILED] + [
        "( function ( ) { return arguments [ 0 ] + arguments [ 1 ] } ) ( '%s' , '%s' )" % (_A1, _A2),
        "(function(){return arguments[0]+arguments[1];})('%s','%s')" % (_A1, _A2),
        "(function(){return arguments[0]+arguments[1]})(\"%s\",\"%s\")" % (_A1, _A2),
        "(function(){return arguments[0]+arguments[1]})('xoxb-\\u0030123','%s')" % _A2,
    ]
    node = _node_eval(shapes)
    for payload, n in zip(shapes, node):
        dec = _decoded(payload)
        want = json.loads(n)
        if dec != want:
            return ("BREAK", "differential mismatch: %s dec=%r node=%r"
                    % (payload[:60], dec, want))
    return ("HELD", "%d/%d shapes byte-identical to node" % (len(shapes), len(shapes)))


def p3_fail_closed_boundaries():
    """Every documented fail-closed boundary still misses (never mis-decodes)."""
    miss = [
        # nested function: inner `arguments` is a different binding
        ("nested-function",
         "(function(){return (function(){return arguments[0]})()})('%s','%s')" % (_A1, _A2)),
        # writes through the arguments object break the binding model
        ("assign-index",
         "(function(){return (arguments[0]='x', arguments[0])})('%s','%s')" % (_A1, _A2)),
        ("assign-bare",
         "(function(){return (arguments='x', 'a')})('%s','%s')" % (_A1, _A2)),
        # unmodeled arguments uses
        ("args-length", "(function(){return arguments.length})('%s','%s')" % (_A1, _A2)),
        ("args-call", "(function(){return arguments()})('%s','%s')" % (_A1, _A2)),
        ("args-oor", "(function(){return arguments[5]})('%s','%s')" % (_A1, _A2)),
        ("args-str-index", "(function(){return arguments['0']})('%s','%s')" % (_A1, _A2)),
        ("member-args", "(function(){return x.arguments})('%s','%s')" % (_A1, _A2)),
        # arrow parameter shadowing
        ("arrow-param",
         "(function(){return Array.prototype.map.call(arguments,(arguments)=>arguments)})('%s','%s')" % (_A1, _A2)),
        ("bare-arrow-param",
         "(function(){return (arguments => arguments[0])(arguments)})('%s','%s')" % (_A1, _A2)),
        # body grammar limits
        ("template-body", "(function(){return `a`})('%s','%s')" % (_A1, _A2)),
        ("slash-body", "(function(){return arguments[0]/arguments[1]})('%s','%s')" % (_A1, _A2)),
        ("delete-body", "(function(){return delete arguments[0]})('%s','%s')" % (_A1, _A2)),
        ("new-body", "(function(){return new String(arguments[0])})('%s','%s')" % (_A1, _A2)),
        # shape limits
        ("named-fn", "(function foo(){return arguments[0]})('%s','%s')" % (_A1, _A2)),
        ("params-fn", "(function(x){return arguments[0]})('%s','%s')" % (_A1, _A2)),
        ("numeric-arg", "(function(){return arguments[0]})('f1',2)",),
        ("marker-arg", "(function(){return arguments[0]})('f1',null)",),
        # 'arguments' inside a string literal is not a binding
        ("string-word", "(function(){return 'arguments'})('%s','%s')" % (_A1, _A2)),
        # junk stays quiet
        ("junk-quiet", "(function(){return Array.prototype.join.call(arguments, '')})('ab','cd')"),
    ]
    bad = []
    for item in miss:
        name, payload = item[0], item[1]
        if _blocked(payload):
            bad.append(name)
    if bad:
        return ("BREAK", "boundaries decoded (should miss): %s" % bad)
    return ("HELD", "%d/%d fail-closed boundaries miss" % (len(miss), len(miss)))


def p4_compositions():
    """Neighbor findings unchanged: F489 IIFE shapes HELD; F506/F507/F508/
    F510/F511 CLOSED by wave-363 lanes 1/2/4 (merge flips -- wave-306);
    F505 still HELD."""
    # F489 (closed wave-360): exact-IIFE receiver still blocks
    if not _blocked("Array.prototype.join.call((function(){return arguments})('%s','%s'), '')" % (_A1, _A2)):
        return ("BREAK", "F489 regression: exact-IIFE receiver misses")
    # F489 bounds still fail closed (parameters, non-arguments body)
    if _blocked("Array.prototype.join.call((function(x){return arguments})('%s','%s'), '')" % (_A1, _A2)):
        return ("BREAK", "F489 bound widened: parameterized IIFE decodes")
    if _blocked("Array.prototype.join.call((function(){return args})('%s','%s'), '')" % (_A1, _A2)):
        return ("BREAK", "F489 bound widened: non-arguments body decodes")
    # F509 in receiver position: array-like body decodes
    if not _blocked("Array.prototype.join.call((function(){return [...arguments]})('%s','%s'), '')" % (_A1, _A2)):
        return ("BREAK", "F509 receiver position: spread body misses")
    # F506/F507/F508/F510/F511 CLOSED by wave-363 lanes 1/2/4 (merge flips
    # the expectations -- wave-306 class): they must now block.
    now_closed = [
        "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (_A1, _A2),
        "''['concat']('%s','%s')" % (_A1, _A2),
        "Array.from(['%s','%s'], x=>x).join('')" % (_A1, _A2),
        "Object.values({0:'%s',1:'%s'}).join('')" % (_A1, _A2),
        "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A1, _A2),
    ]
    for payload in now_closed:
        if not _blocked(payload):
            return ("BREAK", "closure regression (misses): %s" % payload[:50])
    # F505 (closed wave-362): fromCodePoint spread still blocks (full-credential codes)
    if not _blocked("String.fromCodePoint(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])"):
        return ("BREAK", "F505 regression")
    return ("HELD", "F489 HELD; F506/F507/F508/F510/F511 CLOSED; F505 HELD")


def p5_pin_and_footer():
    """Pin stays 2140; no new regexes; F509 CLOSED in FINDINGS; lane-local footer."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "F509" not in text or "CLOSED 2026-10-07 wave-363 lane 3" not in text:
        return ("BREAK", "F509 CLOSED entry missing")
    if "Open findings: F595, F606, F608, F609, F610, F611." not in text:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526); Wave-365 lane 2: F522, F525 CLOSED  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **F612**" not in text:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2140; 28 re.compile; F509 CLOSED; footer open F506,F507,F508,F510,F511/next F513")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w362_f509_redfirst.py",
               "w360_f489f490close_probes.py",
               "w362_attack_probes.py",
               "w360_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g363-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_filed_shapes_held, p2_node_differential,
              p3_fail_closed_boundaries, p4_compositions, p5_pin_and_footer]
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
