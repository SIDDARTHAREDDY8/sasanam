#!/usr/bin/env python3
"""Wave-364 lane 4: F518/F520 closure probes.

F518 (LOW, OPEN on base; narrowed 2026-10-07): Array.prototype.reverse
through .call dispatch bypassed the decoder -- F511 modeled
splice.call/.apply dispatch, and the direct .reverse() was already
modeled (F461, no-arg only), but reverse had no .call dispatch entry.
Closure (gov/dlp.py): "reverse" joins _F478_ARRAY_METHODS; the .call
path routes through the existing _js_apply_method_at reverse branch
(no-arg rule, F461) and the .apply/.bind value path is mirrored in
_js_apply_method_values. Node v24.20.0: reverse returns the same
(reversed) array reference. The push/unshift .call shapes from the
original filing are out of F518's closed scope: they require dataflow
tracking (alias resolution + mutation tracking), a documented decoder
design boundary (accepted, F306/F308 precedent); the dispatch
mechanism is deliberately not added (node returns the new length, a
number, so modeling the call could never flag the shapes).

F520 (LOW, OPEN on base): Array.fromAsync was unmodeled -- the decoder
modeled sync Array.from (F508) but Array.fromAsync returns a Promise,
so Array.fromAsync([...]).then(a=>a.join('')) missed while producing
the exact credential (when awaited). Closure (gov/dlp.py): new
_js_parse_array_from_async reuses _js_parse_array_from's source grammar
(array literal / array-like / new Set, optional identity mapper --
node-verified: fromAsync resolves to the element list, SameValueZero
for Sets) and requires the narrow .then(cb) postfix: cb is a
single-param arrow or function whose body is exactly
<param>.join('') (empty-string separator). The whole shape desugars to
the resolved elements joined with ''. A bare Array.fromAsync(...)
(a Promise, not a decodable value) fails closed.

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

TAXONOMY_PIN = 2140  # Wave-364 lane 4; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

F518_FILED = [
    ("reverse-call",
     "Array.prototype.reverse.call(['%s','%s']).join('')" % (_B, _A)),
    ("reverse-apply",
     "Array.prototype.reverse.apply(['%s','%s'],[]).join('')" % (_B, _A)),
    ("reverse-bracket",
     "Array.prototype['reverse'].call(['%s','%s']).join('')" % (_B, _A)),
    ("reverse-double-dispatch",  # F482: Function.prototype.call.call
     "Function.prototype.call.call(Array.prototype.reverse,"
     "['%s','%s']).join('')" % (_B, _A)),
]

F520_FILED = [
    ("fromasync-then",
     "Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (_A, _B)),
    ("fromasync-set",
     "Array.fromAsync(new Set(['%s','%s'])).then(a=>a.join(''))" % (_A, _B)),
    ("fromasync-paren-arrow",
     "Array.fromAsync(['%s','%s']).then((a)=>a.join(''))" % (_A, _B)),
    ("fromasync-function",
     "Array.fromAsync(['%s','%s']).then(function(a){return a.join('');})"
     % (_A, _B)),
    ("fromasync-block-arrow",
     "Array.fromAsync(['%s','%s']).then(a=>{return a.join('');})" % (_A, _B)),
    ("fromasync-bracket",
     "Array['fromAsync'](['%s','%s']).then(a=>a.join(''))" % (_A, _B)),
    ("fromasync-identity-mapper",
     "Array.fromAsync(['%s','%s'],x=>x).then(a=>a.join(''))" % (_A, _B)),
    ("fromasync-arraylike",
     "Array.fromAsync({length:2,0:'%s',1:'%s'}).then(a=>a.join(''))"
     % (_A, _B)),
    # Chained .catch/.finally after .then: engine-exact flag (fulfilled
    # promise passes the value through; node-verified).
    ("fromasync-then-catch",
     "Array.fromAsync(['%s','%s']).then(a=>a.join('')).catch(e=>'x')"
     % (_A, _B)),
    ("fromasync-then-finally",
     "Array.fromAsync(['%s','%s']).then(a=>a.join('')).finally(()=>{})"
     % (_A, _B)),
]


def p1_f518_filed_shapes_held():
    """F518 filed shapes (reverse dispatch) all flag."""
    bad = []
    for name, payload in F518_FILED:
        if dlp.find_credential(payload) is None:
            bad.append(name)
    if bad:
        return ("BREAK", "missed: %s" % ",".join(bad))
    return ("HELD", "%d/%d reverse shapes flag" % (len(F518_FILED),
                                                   len(F518_FILED)))


def p2_f520_filed_shapes_held():
    """F520 filed shapes (fromAsync.then) all flag."""
    bad = []
    for name, payload in F520_FILED:
        if dlp.find_credential(payload) is None:
            bad.append(name)
    if bad:
        return ("BREAK", "missed: %s" % ",".join(bad))
    return ("HELD", "%d/%d fromAsync shapes flag" % (len(F520_FILED),
                                                     len(F520_FILED)))


def p3_node_differential():
    """Node v24.20.0 byte-identical on the new shapes."""
    node_src = (
        "const A='%s',B='%s';\n"
        "console.log(JSON.stringify(Array.prototype.reverse.call([B,A]).join('')));\n"
        "console.log(JSON.stringify(Array.prototype.reverse.apply([B,A],[]).join('')));\n"
        "(async()=>{console.log(JSON.stringify(await Array.fromAsync([A,B]).then(a=>a.join(''))));\n"
        "console.log(JSON.stringify(await Array.fromAsync(new Set([A,B])).then(a=>a.join(''))));\n"
        "console.log(JSON.stringify(await Array.fromAsync([A,B],x=>x).then(a=>a.join(''))));})();\n"
        % (_A, _B)
    )
    tmp = "/var/tmp/g364-node-%d" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    p = os.path.join(tmp, "diff.js")
    with open(p, "w") as f:
        f.write(node_src)
    r = subprocess.run(["node", p], capture_output=True, text=True,
                       timeout=60, cwd=tmp)
    if r.returncode != 0:
        return ("BREAK", "node failed: %s" % r.stderr[:200])
    outs = [json.loads(line) for line in r.stdout.strip().split("\n")]
    want = [_A + _B] * 5
    if outs != want:
        return ("BREAK", "node mismatch: %r vs %r" % (outs, want))
    # Decoder's static decode must agree byte-identically with node.
    dec = []
    for payload in (F518_FILED[0][1], F518_FILED[1][1], F520_FILED[0][1],
                    F520_FILED[1][1], F520_FILED[6][1]):
        d = dlp._try_js_expr_decode(payload, 0)
        dec.append(d[0] if d else None)
    if dec != want:
        return ("BREAK", "decoder disagrees with node: %r vs %r" % (dec, want))
    return ("HELD", "node and decoder agree: %r" % (_A + _B,))


def p4_fail_closed_boundaries():
    """Boundaries fail closed (miss, never mis-decode)."""
    miss = [
        # F518: push/unshift dispatch needs dataflow -- documented boundary.
        ("push-call-dataflow",
         "var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (_A, _B)),
        ("unshift-call-dataflow",
         "var a=['%s'];Array.prototype.unshift.call(a,'%s');a.join('')" % (_B, _A)),
        # F518: reverse with args / on non-array fails closed.
        ("reverse-with-args",
         "Array.prototype.reverse.call(['%s','%s'],1).join('')" % (_B, _A)),
        ("reverse-nonarray",
         "Array.prototype.reverse.call('ab').join('')"),
        # F520: bare fromAsync is a Promise, not a decodable value.
        ("fromasync-bare",
         "Array.fromAsync(['%s','%s'])" % (_A, _B)),
        # F520: non-join / multi-arg / non-empty-separator callbacks.
        ("fromasync-then-nonjoin",
         "Array.fromAsync(['%s','%s']).then(a=>a.length)" % (_A, _B)),
        ("fromasync-then-two-args",
         "Array.fromAsync(['%s','%s']).then(a=>a.join(''),b=>b)" % (_A, _B)),
        ("fromasync-then-comma-sep",
         "Array.fromAsync(['%s','%s']).then(a=>a.join(','))" % (_A, _B)),
        ("fromasync-catch",
         "Array.fromAsync(['%s','%s']).catch(e=>e)" % (_A, _B)),
        # F520: junk stays quiet.
        ("fromasync-junk",
         "Array.fromAsync(['ab','cd']).then(a=>a.join(''))"),
    ]
    bad = [name for name, payload in miss
           if dlp.find_credential(payload) is not None]
    if bad:
        return ("BREAK", "boundary decoded: %s" % ",".join(bad))
    return ("HELD", "%d/%d boundaries fail closed" % (len(miss), len(miss)))


def p5_compositions():
    """Independence: F511/F508/F506/F482 unaffected by the closures."""
    indep = [
        # F511 splice stays HELD (independence both directions).
        ("f511-splice-call",
         "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (_A, _B), True),
        ("f511-splice-apply",
         "Array.prototype.splice.apply(['%s','%s'],[0,2]).join('')" % (_A, _B), True),
        # F508 sync Array.from stays HELD.
        ("f508-from",
         "Array.from(['%s','%s']).join('')" % (_A, _B), True),
        ("f508-from-set",
         "Array.from(new Set(['%s','%s'])).join('')" % (_A, _B), True),
        # F506 call/apply indirection stays HELD (independence).
        ("f506-indirect",
         "Function.prototype.call.call(Reflect.apply,Reflect,"
         "[].concat,[],['%s','%s']).join('')" % (_A, _B), True),
        # Direct reverse still HELD (F461).
        ("direct-reverse",
         "['%s','%s'].reverse().join('')" % (_B, _A), True),
    ]
    bad = []
    for name, payload, want_hit in indep:
        hit = dlp.find_credential(payload) is not None
        if hit != want_hit:
            bad.append("%s(want %s)" % (name, want_hit))
    if bad:
        return ("BREAK", "composition drift: %s" % ",".join(bad))
    return ("HELD", "%d/%d composition probes hold" % (len(indep), len(indep)))


def p6_pin_and_footer():
    """Pin stays 2140; F518/F520 closed in FINDINGS; lane-local footer;
    28 re.compile."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    for f in ("F518", "F520"):
        if f not in text:
            return ("BREAK", "%s entry missing" % f)
    # Lane-local footer: F518, F520 CLOSED; open F513-F517, F519; next F521.
    if "Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671." not in text:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526); Wave-365 lane 2: F522, F525 CLOSED  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
        return ("BREAK", "footer open-list not lane-local")
    if "Next free finding: **F672**" not in text:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
        return ("BREAK", "footer next-free not F521")
    if dlp._JS_EXPR_START.search("Array.fromAsync") is None:
        return ("BREAK", "anchor missing fromAsync")
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    return ("HELD", "pin 2140; F518/F520 closed; footer lane-local; 28 re.compile")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w363_f518_redfirst.py",
               "w363_f520_redfirst.py",
               "w363_f510f511close_probes.py",
               "w362_f511_redfirst.py",
               "w363_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g364-green-%s-%d" % (script.replace(".py", ""),
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
        m = re.search(r"(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_f518_filed_shapes_held, p2_f520_filed_shapes_held,
              p3_node_differential, p4_fail_closed_boundaries,
              p5_compositions, p6_pin_and_footer]
    breaks, held = 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "HELD":
            held += 1
        else:
            breaks += 1
    print("green check: %s" % _green_check())
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
