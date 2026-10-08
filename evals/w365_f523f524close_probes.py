#!/usr/bin/env python3
"""Wave-365 lane 3: F523/F524 closure probes.

F523 (LOW, filed wave-364 attack round 32, OPEN on base):
triple-nested bracket member keys on string receivers --
`'f1'[[[['concat'][0]]][0]]('f2')` and
`String('f1')[[[['concat'][0]]][0]](String('f2'))` (2 shapes; F515
covers double-nested, F514 covers nested on String-objects).

F524 (LOW, filed wave-364 attack round 32, OPEN on base):
destructured `arguments` laundering --
`(function(){const [a,b]=arguments;return a+b})('f1','f2')` and
`(function(){var [x,y]=arguments;return x+y})('f1','f2')` (2 shapes;
F509 covers bare `arguments`, F516 covers whole-object alias).

Closure (gov/dlp.py):
- F523: `_js_parse_triple_nested_bracket_key` folds
  `[[[['concat'][0]]][0]]` at the `_js_parse_postfix` member-key
  chain (new fallback tried BEFORE `_js_parse_array_wrapped_key`:
  the triple parser fails chargeless on the F514/F504 shapes, so
  each shape charges exactly its documented parts -- the reverse
  order would double-charge the shared indexed fold on triple
  input). With E = `['concat'][0]` (F504 indexed-key fold,
  engine-identical to the string `'concat'`), `[[E]]` is the
  single-element array `[['concat']]`, and `[[E]][0]` is the array
  `['concat']` (node v24.20.0 verified) -- whose ToPropertyKey is
  `'concat'`. `_js_parse_array_wrapped_array` is the F514 core
  extracted behavior-identically from
  `_js_parse_array_wrapped_key` (verified: F504 nested shapes
  decode identically on base and lane trees). Fail closed: 4+
  nestings, non-literal index, index != 0 (the double-wrapped
  array has exactly one element), malformed structure. The
  double-wrap layer charges one part. Zero new regexes
  (re.compile stays 28).
- F524: `_js_split_destructure_var_decl` splits
  `(var|const|let) [n0(, n1)?] = arguments;` and
  `_js_bind_destructure_arguments` binds the pattern names to the
  call-site literals (bare-identifier use only). A destructured
  element is a STRING in the engine, so the F509 three-form
  grammar is NOT node-exact here -- `a[0]` is string indexing and
  `...a` spreads characters (node v24.20.0 verified) -- and every
  non-bare use fails closed. Hooked into
  `_js_parse_args_laundered_iife` as the `src_kind ==
  "destructure"` branch. Fail closed: 3+ element patterns, holes,
  defaults, rest elements, nested patterns, duplicate names, a
  name of `arguments`, non-`arguments` sources, pattern longer
  than the call args. Zero new regexes.

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

TAXONOMY_PIN = 2140  # Wave-365 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

FILED_F523 = [
    ("triple-nested-string-literal",
     "'%s'[[[['concat'][0]]][0]]('%s')" % (_A1, _A2)),
    ("triple-nested-boxed-string",
     "String('%s')[[[['concat'][0]]][0]](String('%s'))" % (_A1, _A2)),
]

FILED_F524 = [
    ("destructure-const",
     "(function(){const [a,b]=arguments;return a+b})('%s','%s')"
     % (_A1, _A2)),
    ("destructure-var",
     "(function(){var [x,y]=arguments;return x+y})('%s','%s')"
     % (_A1, _A2)),
]


def _hit(payload):
    return dlp.find_credential(payload) is not None


def p1_f523_filed_shapes_held():
    """The two filed F523 shapes decode (HELD)."""
    misses = [n for n, p in FILED_F523 if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "2/2 filed F523 shapes decode")


def p2_f524_filed_shapes_held():
    """The two filed F524 shapes decode (HELD)."""
    misses = [n for n, p in FILED_F524 if not _hit(p)]
    if misses:
        return ("BREAK", "missed: %s" % ",".join(misses))
    return ("HELD", "2/2 filed F524 shapes decode")


def p3_node_differential():
    """The desugars are node-exact (node v24.20.0 byte-identical)."""
    js = r"""
const A1='xoxb-0123', A2='456789abcdef';
const out = [];
out.push(A1[[[['concat'][0]]][0]](A2) === A1['concat'](A2));
out.push(String(A1)[[[['concat'][0]]][0]](String(A2)) === String(A1)['concat'](String(A2)));
out.push((function(){const [a,b]=arguments;return a+b})(A1,A2) === A1+A2);
out.push((function(){var [x,y]=arguments;return x+y})(A1,A2) === A1+A2);
out.push((function(){let [p,q]=arguments;return p+q})(A1,A2) === A1+A2);
out.push((function(){const [a]=arguments;return a})(A1) === A1);
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
    if not all(vals) or len(vals) != 6:
        return ("BREAK", "node mismatch: %s" % vals)
    return ("HELD", "6/6 node byte-identical")


def p4_fail_closed_boundaries():
    """Documented fail-closed boundaries miss (HELD = correctly missed)."""
    # (name, payload, want_hit)
    bounds = [
        # F523 boundaries
        ("idx1", "'%s'[[[['concat'][0]]][1]]('%s')" % (_A1, _A2), False),
        ("nest4", "'%s'[[[[['concat'][0]]]][0]]('%s')" % (_A1, _A2), False),
        ("nonlit-idx", "'%s'[[[['concat'][0]]][x]]('%s')" % (_A1, _A2),
         False),
        ("bad-elem", "'%s'[[[[x][0]]][0]]('%s')" % (_A1, _A2), False),
        # F524 boundaries
        ("three-elem",
         "(function(){const [a,b,c]=arguments;return a+b+c})"
         "('%s','%s','z')" % (_A1, _A2), False),
        ("hole",
         "(function(){const [a,,b]=arguments;return a+b})"
         "('%s','%s','z')" % (_A1, _A2), False),
        ("default",
         "(function(){const [a='x',b]=arguments;return a+b})"
         "('%s','%s')" % (_A1, _A2), False),
        ("rest-elem",
         "(function(){const [a,...r]=arguments;return a+r[0]})"
         "('%s','%s')" % (_A1, _A2), False),
        ("nested-pattern",
         "(function(){const [[a]]=arguments;return a})"
         "('%s','%s')" % (_A1, _A2), False),
        ("dup-names",
         "(function(){var [a,a]=arguments;return a})"
         "('%s','%s')" % (_A1, _A2), False),
        ("src-not-arguments",
         "(function(){var [a,b]=Array.from(arguments);return a+b})"
         "('%s','%s')" % (_A1, _A2), False),
        ("elem-index",
         "(function(){const [a]=arguments;return a[0]})('%s')" % _A1,
         False),
        ("elem-spread",
         "(function(){const [a]=arguments;return [...a].join('')})"
         "('%s')" % _A1, False),
        ("elem-member",
         "(function(){const [a]=arguments;return a.length})('%s')"
         % _A1, False),
        ("pattern-longer-than-args",
         "(function(){const [a,b]=arguments;return a+b})('%s')" % _A1,
         False),
        ("junk", "(function(){const [a,b]=arguments;return a+b})"
         "('ab','cd')", False),
    ]
    wrong = [n for n, p, want in bounds if _hit(p) != want]
    if wrong:
        return ("BREAK", "boundary wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d boundaries node-honest" % (len(bounds),
                                                      len(bounds)))


def p5_compositions():
    """Adjacent closures stay HELD; F523/F524 close independently."""
    comps = [
        # F523 independence: F504/F514/F515/F507 all stay HELD
        ("f504-reflect-nested",
         "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')"
         % (_A1, _A2), True),
        ("f504-reflect-nested-multi-elem",
         "Reflect[['x','apply'][1]]([].concat, [], ['%s','%s']).join('')"
         % (_A1, _A2), True),
        ("f504-reflect-nested-fold-elem",
         "Reflect[['ap'+'ply'][0]]([].concat, [], ['%s','%s']).join('')"
         % (_A1, _A2), True),
        ("f514-boxed-nested",
         "String('%s')[[['concat'][0]]](String('%s'))" % (_A1, _A2),
         True),
        ("f515-double-nested",
         "'%s'[[['concat'][0]]]('%s')" % (_A1, _A2), True),
        ("f507-single", "''['concat']('%s','%s')" % (_A1, _A2), True),
        # F524 independence: F509/F516 family stays HELD
        ("f509-bare",
         "(function(){return arguments[0]+arguments[1]})('%s','%s')"
         % (_A1, _A2), True),
        ("f516-alias",
         "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')"
         % (_A1, _A2), True),
        ("f516-rest",
         "(function(...r){return r[0]+r[1]})('%s','%s')" % (_A1, _A2),
         True),
        ("f516-from",
         "(function(){var a=Array.from(arguments);return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2), True),
        ("f516-values",
         "(function(){var a=Object.values(arguments);return a[0]+a[1]})"
         "('%s','%s')" % (_A1, _A2), True),
        # F524 x F489: the arguments-IIFE receiver still works (the
        # F524 destructure desugar must not disturb F489's IIFE
        # call-site handling -- verified identical on the base tree)
        ("f489-iife-join-receiver",
         "Array.prototype.join.call((function(){return arguments})"
         "('%s','%s'), '')" % (_A1, _A2), True),
        # F524 x F517: laundered args enumerated -- fail-closed beyond
        # the modeled bound (documented residual)
        ("f524-x-f517-enumerate",
         "(function(){const [a,b]=arguments;return "
         "Object.keys({0:a,1:b}).join('')})('%s','%s')" % (_A1, _A2),
         False),
    ]
    wrong = [n for n, p, want in comps if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest" % (len(comps),
                                                   len(comps)))


def p6_pin_and_footer():
    """Pin stays 2140; no new regexes; F523/F524 CLOSED in FINDINGS;
    lane-local footer."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "F523" not in text or "CLOSED 2026-10-07 wave-365 lane 3" not in text:
        return ("BREAK", "F523 CLOSED entry missing")
    if "F524" not in text or text.count("CLOSED 2026-10-07 wave-365 lane 3") < 2:
        return ("BREAK", "F524 CLOSED entry missing")
    if "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." not in text:  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **F655**" not in text:  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2140; 28 re.compile; F523/F524 CLOSED; "
            "footer F521,F522,F525/next F526")


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w364_f523_redfirst.py",
               "w364_f524_redfirst.py",
               "w364_f516f517close_probes.py",
               "w364_f514f515close_probes.py",
               "w364_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g365-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_f523_filed_shapes_held, p2_f524_filed_shapes_held,
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
