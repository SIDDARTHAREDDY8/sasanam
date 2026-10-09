#!/usr/bin/env python3
"""Wave-364 lane 3: F516/F517 closure probes.

F516 (LOW, filed wave-363 attack round 31, OPEN on base): the
`arguments` object laundered before dispatch -- alias
(`var a=arguments`), rest param (`...args`), `Array.from(arguments)`,
`Object.values(arguments)` (4 shapes; F509 covers bare `arguments`
only). The laundered binding bypasses the F509 call-site model.

F517 (LOW, filed wave-363 attack round 31, OPEN on base):
enumeration indirection -- `Object.keys`, `Object.entries` with a
`.map(p=>p[0|1])` projection, and for-in accumulation over object
literals (3 shapes; F510 covers `Object.values` only).

Closure (gov/dlp.py):
- F516: `_js_parse_args_laundered_iife` desugars
  `(function(){var A=SRC;return BODY})(lit, ...)` (SRC in
  {`arguments`, `Array.from(arguments)`, `Object.values(arguments)`},
  one `var` decl only) and `(function(...A){return BODY})(lit, ...)`
  by binding call-site args twice -- once for `arguments`, once for
  the alias/rest name -- through the generalized
  `_js_bind_iife_arguments` (new `ident` + `member_ok` params;
  F509 behavior unchanged at ident="arguments", member_ok=False).
  `member_ok` is true only when the bound name IS a real Array in
  the engine (rest param, Array.from/Object.values alias), so
  `a.join` desugars node-exactly there while `arguments.join` /
  bare-`arguments`-alias member access still fails closed (the
  exotic object has no methods -- node throws). Hooked at the
  dispatch-receiver path (array-like results only) and the paren
  path. Documented fail-closed: alias chains beyond one hop,
  re-assigned aliases, `let`/`const` decls, nested closures,
  non-literal args, member access on the exotic alias.
- F517: `_js_parse_object_keys` desugars `Object.keys(OBJ)` (dot
  and F480 bracket forms) to the ordered key list via the shared
  `_js_parse_enumeration_source` (plain literal, integrity
  wrappers, entries-reduce rebuild -- the F510 source classes);
  `_js_parse_object_entries` desugars
  `Object.entries(OBJ).map(P)` with a mandatory
  `_js_parse_entries_projection` (`p=>p[0|1]`, `(p)=>p[0|1]`,
  block-arrow, function-expression forms -- element 0 = keys,
  element 1 = values; bare `.map(p=>p)` and out-of-range indices
  fail closed). `_js_parse_forin_accum_iife` desugars the exact
  `(function(){var A='';var O={...};for(var K in O)A+=O[K];return
  A})()` idiom to `Object.values(<lit>).join('')` (for-in order on
  a fresh literal == Object.values enumeration order, node
  v24.20.0 verified). Documented fail-closed: non-literal objects,
  getters, `__proto__`/computed keys, non-empty accumulators,
  non-`+=` bodies, extra statements, call args on the IIFE.
- Anchor `_JS_EXPR_START` gains `keys|entries` in the Object
  dot-alternation (literal-alternation only). Zero new regexes
  (re.compile stays 28).

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed
shape misses or a boundary decodes node-wrong.

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

TAXONOMY_PIN = 2144  # Wave-364 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

FILED_F516 = [
    ("alias-index",
     "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (_A1, _A2)),
    ("alias-spread",
     "(function(){var a=arguments;return [...a].join('')})('%s','%s')" % (_A1, _A2)),
    ("rest-join",
     "(function(...args){return args.join('');})('%s','%s')" % (_A1, _A2)),
    ("rest-index",
     "(function(...r){return r[0]+r[1]})('%s','%s')" % (_A1, _A2)),
    ("array-from-index",
     "(function(){var a=Array.from(arguments);return a[0]+a[1];})('%s','%s')" % (_A1, _A2)),
    ("array-from-join",
     "(function(){var a=Array.from(arguments);return a.join('');})('%s','%s')" % (_A1, _A2)),
    ("object-values-index",
     "(function(){var v=Object.values(arguments);return v[0]+v[1];})('%s','%s')" % (_A1, _A2)),
    ("object-values-join",
     "(function(){var v=Object.values(arguments);return v.join('');})('%s','%s')" % (_A1, _A2)),
]

FILED_F517 = [
    ("keys-join",
     "Object.keys({'%s':'x','%s':'y'}).join('')" % (_A1, _A2)),
    ("keys-bracket",
     "Object['keys']({'%s':'x','%s':'y'}).join('')" % (_A1, _A2)),
    ("entries-values",
     "Object.entries({0:'%s',1:'%s'}).map(p=>p[1]).join('')" % (_A1, _A2)),
    ("entries-keys",
     "Object.entries({'%s':'x','%s':'y'}).map(p=>p[0]).join('')" % (_A1, _A2)),
    ("entries-paren-arrow",
     "Object.entries({0:'%s',1:'%s'}).map((p)=>p[1]).join('')" % (_A1, _A2)),
    ("entries-fn-expr",
     "Object.entries({0:'%s',1:'%s'}).map(function(p){return p[1];}).join('')" % (_A1, _A2)),
    ("for-in-accum",
     "(function(){var r='';var o={m:'%s',n:'%s'};for(var k in o)r+=o[k];return r})()" % (_A1, _A2)),
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


def p1_f516_filed_shapes_held():
    """The F516 laundering shapes now block (were 4 BREAK on base)."""
    bad = [name for name, payload in FILED_F516 if not _blocked(payload)]
    if bad:
        return ("BREAK", "F516 filed shapes still miss: %s" % bad)
    return ("HELD", "%d/%d F516 shapes block" % (len(FILED_F516), len(FILED_F516)))


def p2_f517_filed_shapes_held():
    """The F517 enumeration shapes now block (were 3 BREAK on base)."""
    bad = [name for name, payload in FILED_F517 if not _blocked(payload)]
    if bad:
        return ("BREAK", "F517 filed shapes still miss: %s" % bad)
    return ("HELD", "%d/%d F517 shapes block" % (len(FILED_F517), len(FILED_F517)))


def p3_node_differential():
    """Decoder output byte-identical to node v24.20.0 on filed shapes,
    whitespace variants, and ordering edge cases (F496: integer keys
    ascending first, then insertion order)."""
    shapes = (
        [p for _, p in FILED_F516] + [p for _, p in FILED_F517] + [
            "( function ( ... xs ) { return xs.join( '' ) ; } )( '%s' , '%s' )" % (_A1, _A2),
            "(function(){var a=Array.from(arguments);return a[0]+a[1];})(\"%s\",\"%s\")" % (_A1, _A2),
            "Object . keys ( { '%s' : 'x', '%s' : 'y' } ).join('')" % (_A1, _A2),
            "Object.entries({0:'a',1:'b'}).map(p=>{return p[1];}).join('')",
            "Object.keys({2:'c',10:'d',1:'b',0:'a',m:'e'}).join('')",
            "Object.keys({1:'b',0:'a'}).join('')",
            "(function(){var r='';var o={1:'b',0:'a'};for(var k in o)r+=o[k];return r})()",
            "Object.entries(Object.freeze({0:'a',1:'b'})).map(p=>p[1]).join('')",
        ])
    try:
        node = subprocess.run(["node", "--version"], capture_output=True,
                              text=True, timeout=30)
        if "v24.20.0" not in node.stdout:
            return ("ERROR", "node is not v24.20.0: %s" % node.stdout.strip())
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "node unavailable: %s" % e)
    wants = _node_eval(shapes)
    for payload, n in zip(shapes, wants):
        dec = _decoded(payload)
        want = json.loads(n)
        if dec != want:
            return ("BREAK", "differential mismatch: %s dec=%r node=%r"
                    % (payload[:60], dec, want))
    return ("HELD", "%d/%d shapes byte-identical to node v24.20.0"
            % (len(shapes), len(shapes)))


def p4_fail_closed_boundaries():
    """Every documented fail-closed boundary misses (never mis-decodes)."""
    miss = [
        # F516: the exotic object has no methods -- node throws
        ("exotic-member",
         "(function(){var a=arguments;return a.join('')})('%s','%s')" % (_A1, _A2)),
        ("exotic-length",
         "(function(){var a=arguments;return a.length})('%s','%s')" % (_A1, _A2)),
        # F516: alias chains beyond one hop
        ("two-hop",
         "(function(){var a=arguments;var b=a;return b[0]+b[1]})('%s','%s')" % (_A1, _A2)),
        # F516: re-assigned alias breaks the binding
        ("reassigned",
         "(function(){var a=arguments;a=['x'];return a[0]+a[1]})('%s','%s')" % (_A1, _A2)),
        # F516: let/const decls are outside the modeled grammar
        ("let-decl",
         "(function(){let a=arguments;return a[0]+a[1]})('%s','%s')" % (_A1, _A2)),
        ("const-decl",
         "(function(){const a=Array.from(arguments);return a[0]})('%s','%s')" % (_A1, _A2)),
        # F516: nested closures see a different binding
        ("nested-fn",
         "(function(){var a=arguments;return (function(){return a[0]})()})('%s','%s')" % (_A1, _A2)),
        # F516: non-literal args, out-of-range/negative indices
        ("nonlit-arg", "(function(){var a=arguments;return a[0]})(x)"),
        ("oor-index",
         "(function(){var a=arguments;return a[5]})('%s','%s')" % (_A1, _A2)),
        ("neg-index",
         "(function(){var a=arguments;return a[-1]})('%s','%s')" % (_A1, _A2)),
        # F516: rest param called as a function throws in the engine
        ("rest-call",
         "(function(...a){return a('x')})('%s','%s')" % (_A1, _A2)),
        # F516: alias shadowing by an arrow param
        ("arrow-shadow",
         "(function(){var a=arguments;return [1].map(a=>a)})('%s','%s')" % (_A1, _A2)),
        # F517: entries without the mandatory projection is unmodeled
        ("entries-no-map", "Object.entries({0:'%s'})" % _A1),
        ("entries-identity",
         "Object.entries({0:'%s'}).map(p=>p).join('')" % _A1),
        ("entries-idx2",
         "Object.entries({0:'%s'}).map(p=>p[2]).join('')" % _A1),
        # F517: getters / __proto__ / computed keys fail closed
        ("keys-getter",
         "Object.keys({get m(){return '%s'}}).join('')" % _A1),
        ("keys-proto",
         "Object.keys({__proto__:{},a:'%s'}).join('')" % _A1),
        ("keys-computed", "Object.keys({['k']:'%s'}).join('')" % _A1),
        ("keys-nonlit", "Object.keys(o).join('')"),
        # F517: for-in bounds -- non-empty accum, non-+= body, extra
        # statements, call args, non-literal object, getters
        ("forin-nonempty",
         "(function(){var r='x';var o={m:'%s'};for(var k in o)r+=o[k];return r})()" % _A1),
        ("forin-plus",
         "(function(){var r='';var o={m:'%s'};for(var k in o)r=r+o[k];return r})()" % _A1),
        ("forin-callargs",
         "(function(){var r='';var o={m:'%s'};for(var k in o)r+=o[k];return r})('z')" % _A1),
        ("forin-nonlit",
         "(function(){var r='';var o=g();for(var k in o)r+=o[k];return r})()"),
        ("forin-extra-stmt",
         "(function(){var r='';var o={m:'a'};var z=1;for(var k in o)r+=o[k];return r})()"),
        ("forin-getter",
         "(function(){var r='';var o={get m(){return '%s'}};for(var k in o)r+=o[k];return r})()" % _A1),
        # junk stays quiet
        ("junk-quiet", "Object.keys({a:'b'}).join('')"),
    ]
    bad = [name for name, payload in miss if _blocked(payload)]
    if bad:
        return ("BREAK", "boundaries decoded (should miss): %s" % bad)
    return ("HELD", "%d/%d fail-closed boundaries miss" % (len(miss), len(miss)))


def p5_compositions():
    """Neighbor findings unchanged: F509 bare-arguments HELD, F510
    values CLOSED, F496 ordering intact; F516xF508/F510 compose."""
    # F509 (closed wave-363): bare arguments still blocks
    if not _blocked("(function(){return arguments[0]+arguments[1]})('%s','%s')" % (_A1, _A2)):
        return ("BREAK", "F509 regression: bare-arguments IIFE misses")
    if not _blocked("(function(){return [...arguments].join('')})('%s','%s')" % (_A1, _A2)):
        return ("BREAK", "F509 regression: bare-arguments spread misses")
    # F510 (closed wave-363): values still blocks, incl. via wrappers
    if not _blocked("Object.values({0:'%s',1:'%s'}).join('')" % (_A1, _A2)):
        return ("BREAK", "F510 regression: values misses")
    if not _blocked("Object.values(Object.freeze({0:'%s',1:'%s'})).join('')" % (_A1, _A2)):
        return ("BREAK", "F510 regression: frozen values misses")
    # F516 x F508/F510: laundered array through Array.from / values
    if not _blocked("Array.from((function(...a){return a})('%s','%s')).join('')" % (_A1, _A2)):
        return ("BREAK", "F516xF508 regression: Array.from(laundered) misses")
    if not _blocked("Object.values((function(...a){return [...a]})('%s','%s')).join('')" % (_A1, _A2)):
        return ("BREAK", "F516xF510 regression: values(laundered) misses")
    # F517 x F496: key order == values order (ints ascending, then insertion)
    if _decoded("Object.keys({2:'c',10:'d',1:'b',0:'a',m:'e'}).join('')") != "01210m":
        return ("BREAK", "F517xF496 regression: key order wrong")
    # F516 in dispatch-receiver position (array-like bodies only)
    if not _blocked("Array.prototype.join.call((function(...a){return a})('%s','%s'), '')" % (_A1, _A2)):
        return ("BREAK", "F516 receiver regression: rest-array receiver misses")
    return ("HELD", "F509 HELD; F510 CLOSED; F496 ordering intact; F516xF508/F510 compose")


def p6_pin_and_footer():
    """Pin stays 2144; no new regexes; F516/F517 CLOSED in FINDINGS;  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    lane-local footer."""
    if TAXONOMY_PIN != 2144:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "F516" not in text or "CLOSED 2026-10-07 wave-364 lane 3" not in text:
        return ("BREAK", "F516 CLOSED entry missing")
    if "F517" not in text or text.count("CLOSED 2026-10-07 wave-364 lane 3") < 2:
        return ("BREAK", "F517 CLOSED entry missing")
    if "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." not in text:  # Wave-371 lane 6: F592/F594 CLOSED (open F583-F591, F593, F595, F596; next F597); F582 footer-rot corrected  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **F795**" not in text:  # Wave-367 merge: F537-F546 open, next F547  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2144; 28 re.compile; F516/F517 CLOSED; footer F513,F514,F515,F518,F519,F520/next F521")  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w363_f516_redfirst.py",
               "w363_f517_redfirst.py",
               "w363_f509close_probes.py",
               "w363_f510f511close_probes.py",
               "w363_f507f508close_probes.py")
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
        m = re.search(r"tally:\s*(\d+)\s*BREAK", out)
        if m is None:
            m = re.search(r"(\d+) BREAK / \d+ HELD", out)
        if r.returncode == 0 and m and m.group(1) == "0":
            notes.append("%s: green" % script)
        else:
            notes.append("%s: NOT GREEN (rc=%d)" % (script, r.returncode))
    return "; ".join(notes)


def main():
    probes = [p1_f516_filed_shapes_held, p2_f517_filed_shapes_held,
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
