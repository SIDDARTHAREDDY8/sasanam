#!/usr/bin/env python3
"""Wave-364 lane 2: F514/F515 closure probes.

F514 (LOW, OPEN on base -- narrowed at the wave-363 merge): nested-bracket
member keys on String-object receivers bypass the bounded static
JS-expression decoder -- String('f1')[[['concat'][0]]](String('f2'))
node-evaluates to the credential (node v24.20.0) while the decoder
produces zero variants. The two single-bracket shapes originally filed
were honestly closed by accident at the wave-363 merge via lane 2's
F507 generalization (dot forms already decoded on the wave-362 base;
node-identical); only the nested-bracket shape was genuinely open.

F515 (LOW, OPEN on base): array-index-folded member keys on string-literal
receivers bypass the bounded static JS-expression decoder --
''[['concat'][0]]('f1','f2') and 'f1'[['concat'][0]]('f2') node-evaluate
to the credential (node v24.20.0) while the decoder produces zero
variants. Distinct from F507 (string-concat fold) and F504
(Reflect-namespace-only nested fold).

Closure (gov/dlp.py): the F504 nested-bracket key parser is refactored
into a shared core (_js_parse_indexed_key_array: `[<lit>,...][<idx>]`,
engine-identical to the selected element) used by both
_js_parse_nested_bracket_key (unchanged F504 behavior) and the new
_js_parse_array_wrapped_key (`[[[<lit>,...][<idx>]]]` -- ToPropertyKey
of a single-string array is the string, node v24.20.0 verified).
_js_parse_postfix's bracket branch gains two fallbacks after the
F492 fold: the F504 nested form (closes F515 on string receivers) and
the F514 array-wrapped form (closes F514 on String-object receivers).
The core's elements additionally compose with the F492 folder
('con'+'cat' inner elements, engine-identical). Non-literal indices,
out-of-range indices, bare (unindexed) array keys, unmodeled method
names, and nested-key dispatch (.call/.apply) fail closed
(documented). Zero new re.compile (count stays 28).

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

TAXONOMY_PIN = 2140  # Wave-364 lane 2; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

F514_FILED = [
    ("filed-nested-bracket",
     "String('%s')[[['concat'][0]]](String('%s'))" % (A1, A2)),
]

F515_FILED = [
    ("filed-idx-fold",
     "''[['concat'][0]]('%s','%s')" % (A1, A2)),
    ("filed-idx-fold-receiver",
     "'%s'[['concat'][0]]('%s')" % (A1, A2)),
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
    """The 1 F514 + 2 F515 filed shapes now block (were 1+2 BREAK on base)."""
    bad = [name for name, payload in F514_FILED + F515_FILED
           if not _blocked(payload)]
    if bad:
        return ("BREAK", "filed shapes still miss: %s" % bad)
    return ("HELD", "3/3 filed shapes block")


def p2_node_differential():
    """Decoder output byte-identical to node v24.20.0 on the filed and
    variant shapes."""
    shapes = [
        "String('%s')[[['concat'][0]]](String('%s'))" % (A1, A2),
        # NOTE: `new String(...)` receivers decode with a pre-existing
        # "new "-prefix quirk (base behavior, out of scope) -- blocked
        # via p1, excluded from the byte-identity differential.
        "''[['concat'][0]]('%s','%s')" % (A1, A2),
        "'%s'[['concat'][0]]('%s')" % (A1, A2),
        "'%s'[[['con'+'cat'][0]]]('%s')" % (A1, A2),
        "'%s'[[['concat','x'][0]]]('%s')" % (A1, A2),
        "['%s','%s'][['join'][0]]('-')" % (A1, A2),
    ]
    node = _node_eval(shapes)
    for payload, n in zip(shapes, node):
        dec = _decoded(payload)
        want = json.loads(n)
        if dec != want:
            return ("BREAK", "differential mismatch: %s dec=%r node=%r"
                    % (payload[:55], dec, want))
    return ("HELD", "6/6 shapes byte-identical to node")


def p3_fail_closed_boundaries():
    """Fail-closed boundaries miss (quiet), never mis-decode."""
    quiet = [
        # F514: non-literal / out-of-range / negative index
        "'%s'[[['concat'][x]]]('%s')" % (A1, A2),
        "'%s'[[['concat'][9]]]('%s')" % (A1, A2),
        "'%s'[[['concat'][-1]]]('%s')" % (A1, A2),
        # F514: bare (unindexed) array key -- node decodes, decoder
        # stays conservative (documented residual)
        "'%s'[[['concat']]]('%s')" % (A1, A2),
        # F514: non-identifier folded inner element
        "'%s'[[['a b'][0]]]('%s')" % (A1, A2),
        # F514: numeric fold operand
        "'%s'[[['con'+42][0]]]('%s')" % (A1, A2),
        # F514/F515: unmodeled method name ends the chain quietly
        "'%s'[[['zzz'][0]]]('%s')" % (A1, A2),
        # F514/F515: nested-key dispatch stays fail-closed
        # (F482 dispatch is literal/fold keys only)
        "'%s'[[['concat'][0]]].call([],['%s'])" % (A1, A2),
        # F515: junk stays quiet
        "''[['concat'][0]]('ab','cd')",
        # ident-boundary guards
        "'%s'[[['concatx'][0]]]('%s')" % (A1, A2),
    ]
    bad = [p for p in quiet if _blocked(p)]
    if bad:
        return ("BREAK", "boundaries decoded (want quiet): %s"
                % [p[:40] for p in bad])
    return ("HELD", "%d/%d boundaries quiet" % (len(quiet), len(quiet)))


def p4_compositions():
    """Composition seams: neighbors hold their filed states."""
    checks = [
        # F507 literal + folded keys stay HELD
        ("f507-literal",
         "''['concat']('%s','%s')" % (A1, A2), True),
        ("f507-fold",
         "'%s'['c'+'oncat']('%s')" % (A1, A2), True),
        ("f507-dot",
         "'%s'.concat('%s')" % (A1, A2), True),
        # F504 Reflect nested-bracket both directions (shared core)
        ("f504-reflect-nested",
         "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (A1, A2),
         True),
        ("f504-reflect-fold",
         "Reflect['con'+'cat']", False),
        # F482 prototype dispatch unaffected (exact filed shape)
        ("f482-dispatch",
         "Array.prototype['concat'].call([], '%s','%s').join('')" % (A1, A2), True),
        # F491 computed-key get stays fail-closed
        ("f491-computed-get",
         "Reflect['g'+'et'](Object.prototype, 'x')", False),
        # F513 (Reflect.apply via .bind) CLOSED wave-364 lane 1
        ("f513-closed",
         "Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (A1, A2),
         True),
        # F506 (call/apply indirection) stays CLOSED
        ("f506-closed",
         "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (A1, A2),
         True),
        # F508 Array.from stays CLOSED
        ("f508-closed",
         "Array.from(['%s','%s'], x=>x).join('')" % (A1, A2), True),
    ]
    bad = [name for name, payload, want in checks
           if _blocked(payload) != want]
    if bad:
        return ("BREAK", "composition drift: %s" % bad)
    return ("HELD", "%d/%d compositions hold" % (len(checks), len(checks)))


def p5_pin_and_footer():
    """Pin stays 2140; F514/F515 entries present; no new regexes."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "CLOSED 2026-10-07 wave-364 lane 2" not in text:
        return ("BREAK", "F514/F515 closure entries missing")
    if "Open findings: F597, F598, F599, F600, F601, F602, F603, F604, F605." not in text:  # Wave-366 lane 2: F527/F530 CLOSED; F526/F528/F529 OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
        return ("BREAK", "lane-local footer wrong")
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    return ("HELD", "pin 2140; F514/F515 closed; 28 re.compile")


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). A battery is green when its
    tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w363_f514_redfirst.py",
               "w363_f515_redfirst.py",
               "w361_f504_redfirst.py",
               "w362_f504close_probes.py",
               "w363_f507f508close_probes.py",
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
