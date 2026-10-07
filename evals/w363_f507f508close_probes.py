#!/usr/bin/env python3
"""Wave-363 lane 2: F507/F508 closure probes.

F507 (LOW, OPEN on base): bracket-form member access on STRING LITERAL
receivers bypasses the bounded static JS-expression decoder -- F482
closed bracket-string member access on prototype methods
(Array.prototype['concat']), but the same bracket spelling on a string
literal receiver (''['concat']('f1','f2'), 'f1'['c'+'oncat']('f2'))
bypassed the dispatch anchors: the receiver grammar modeled dot-form
string dispatch and bracket-form prototype dispatch, never
bracket-form literal dispatch.

Closure (gov/dlp.py): _js_parse_postfix routes EXPR['METHOD'](...) to
the dot-form method path (_js_apply_method / _js_apply_tag_method)
for the same method-name set -- literal keys via
_js_parse_bracket_member, computed keys via _js_fold_bracket_key
(F492). Dispatch shapes (.call/.apply/bind) were already handled by
_js_parse_postfix_dispatch (F478/F482); a non-literal key or unmodeled
name ends the chain (F461 principle).

F508 (LOW, OPEN on base): Array.from with a mapping function or
non-literal source bypasses the bounded static JS-expression decoder
-- the decoder modeled the plain Array.from(['f1','f2']) call site
only via the inner array literal, never the mapper or the
array-like / Set sources.

Closure (gov/dlp.py): _js_parse_array_from parses Array.from(src[,
mapFn]) node-exactly -- array-literal sources (_js_parse_array),
array-like object literals (_js_parse_arraylike_recv, F487), and
new Set([...]) (_js_parse_new_set, F494); the mapper must be an
identity callback (x=>x / (x)=>x / function(x){return x;} /
s=>{return s;}, via _js_parse_map_callback, F437/F448). The bare
String mapper, a thisArg, and non-literal sources (generators, Map,
strings) fail closed (documented). The _JS_EXPR_START anchor gains
the `from` alternative (literal-alternation only); Array['from'] is
routed identically (F480 precedent).

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

TAXONOMY_PIN = 2140  # Wave-363 lane 2; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

F507_FILED = [
    ("filed-bracket",
     "''['concat']('%s','%s')" % (A1, A2)),
    ("filed-computed-key",
     "'%s'['c'+'oncat']('%s')" % (A1, A2)),
]

F508_FILED = [
    ("filed-mapper",
     "Array.from(['%s','%s'], x=>x).join('')" % (A1, A2)),
    ("filed-arraylike",
     "Array.from({length:2, 0:'%s', 1:'%s'}).join('')" % (A1, A2)),
    ("filed-set",
     "Array.from(new Set(['%s','%s'])).join('')" % (A1, A2)),
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
    """The 2 F507 + 3 F508 filed shapes now block (were 2+3 BREAK on base)."""
    bad = [name for name, payload in F507_FILED + F508_FILED
           if not _blocked(payload)]
    if bad:
        return ("BREAK", "filed shapes still miss: %s" % bad)
    return ("HELD", "5/5 filed shapes block")


def p2_node_differential():
    """Decoder output byte-identical to node v24.20.0 on the filed and
    variant shapes."""
    shapes = [
        "''['concat']('%s','%s')" % (A1, A2),
        "'%s'['c'+'oncat']('%s')" % (A1, A2),
        "['%s','%s']['concat']('zz').join('')" % (A1, A2),
        "Array.from(['%s','%s'], x=>x).join('')" % (A1, A2),
        "Array.from(['%s','%s'], (x)=>x).join('')" % (A1, A2),
        "Array.from({length:2, 0:'%s', 1:'%s'}).join('')" % (A1, A2),
        "Array.from(new Set(['%s','%s'])).join('')" % (A1, A2),
        "Array.from(new Set(['%s','%s','%s'])).join('')" % (A1, A1, A2),
        "Array['from'](['%s','%s']).join('')" % (A1, A2),
    ]
    node = _node_eval(shapes)
    for payload, n in zip(shapes, node):
        dec = _decoded(payload)
        want = json.loads(n)
        if dec != want:
            return ("BREAK", "differential mismatch: %s dec=%r node=%r"
                    % (payload[:55], dec, want))
    return ("HELD", "9/9 shapes byte-identical to node")


def p3_fail_closed_boundaries():
    """Fail-closed boundaries miss (quiet), never mis-decode."""
    quiet = [
        # F507: non-literal keys end the chain quietly
        "''[x]('%s')" % A1,
        "''['con'+x]('%s')" % A1,
        # F507: unmodeled method names end the chain quietly
        "'%s'['bogus']('%s')" % (A1, A2),
        # F507: junk stays quiet
        "''['concat']('ab','cd')",
        # F508: non-identity mapper fails closed
        "Array.from(['%s','%s'], x=>x+'!').join('')" % (A1, A2),
        # F508: bare String mapper fails closed (documented)
        "Array.from(['%s','%s'], String).join('')" % (A1, A2),
        # F508: thisArg fails closed (documented)
        "Array.from(['%s','%s'], x=>x, null).join('')" % (A1, A2),
        # F508: Map source fails closed (documented)
        "Array.from(new Map([[0,'%s']])).join('')" % A1,
        # F508: generator source fails closed (documented)
        "Array.from(function*(){yield '%s'}()).join('')" % A1,
        # F508: junk stays quiet
        "Array.from(['ab','cd'], x=>x).join('')",
        # F508: ident-boundary guards
        "Array.fromx(['%s'])" % A1,
    ]
    bad = [p for p in quiet if _blocked(p)]
    if bad:
        return ("BREAK", "boundaries decoded (want quiet): %s"
                % [p[:40] for p in bad])
    return ("HELD", "%d/%d boundaries quiet" % (len(quiet), len(quiet)))


def p4_compositions():
    """Composition seams: neighbors hold their filed states."""
    checks = [
        # F482 prototype-method receivers stay HELD
        ("f482-dot",
         "Array.prototype.concat(['%s','%s']).join('')" % (A1, A2), True),
        ("f482-bracket",
         "Array.prototype['concat'](['%s','%s']).join('')" % (A1, A2), True),
        # F507 x F492: template-literal folded key on string receiver
        ("f507-template-key",
         "'%s'[`con${'cat'}`]('%s')" % (A1, A2), True),
        # F507: other modeled string methods via bracket
        ("f507-repeat",
         "'%s'['repeat'](2)" % A1, True),
        ("f507-replace",
         "'%s'['replace']('x','y')" % (A1 + A2), True),
        # F507: string-method dispatch (F482) still routes
        ("f507-dot-control",
         "'%s'.concat('%s')" % (A1, A2), True),
        # F508 x mapper on array-like and Set sources
        ("f508-arraylike-mapper",
         "Array.from({length:2, 0:'%s', 1:'%s'}, x=>x).join('')" % (A1, A2),
         True),
        ("f508-set-mapper",
         "Array.from(new Set(['%s','%s']), x=>x).join('')" % (A1, A2), True),
        # F510 CLOSED by wave-363 lane 4 (merge flips -- wave-306 class)
        ("f510-closed",
         "Object.values({0:'%s',1:'%s'}).join('')" % (A1, A2), True),
        # F506/F509/F511 CLOSED by wave-363 lanes 1/3/4 (merge flips)
        ("f506-closed",
         "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (A1, A2),
         True),
    ]
    bad = [name for name, payload, want in checks
           if _blocked(payload) != want]
    if bad:
        return ("BREAK", "composition drift: %s" % bad)
    return ("HELD", "%d/%d compositions hold" % (len(checks), len(checks)))


def p5_pin_and_footer():
    """Pin stays 2140; F507/F508 entries present; anchor covers
    Array.from; no new regexes."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "CLOSED 2026-10-07 wave-363 lane 2" not in text:
        return ("BREAK", "F507/F508 closure entries missing")
    if "Open findings: F582, F583, F584, F585, F586, F587, F588, F589, F590, F591, F592, F593, F594, F595, F596." not in text:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526); Wave-365 lane 2: F522, F525 CLOSED  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
        return ("BREAK", "footer wrong")  # Wave-364 merge: F513-F517, F519 CLOSED; merge finalizes
    if dlp._JS_EXPR_START.search("Array.from(") is None:
        return ("BREAK", "anchor missing Array.from")
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    return ("HELD", "pin 2140; F507/F508 closed; anchor covers Array.from")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w362_f507_redfirst.py",
               "w362_f508_redfirst.py",
               "w362_f503close_probes.py",
               "w362_f504close_probes.py",
               "w362_f505close_probes.py",
               "w362_attack_probes.py")
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
        m = re.search(r"(\d+)\s+BREAK\s*/", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_filed_shapes_held, p2_node_differential,
              p3_fail_closed_boundaries, p4_compositions, p5_pin_and_footer]
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
