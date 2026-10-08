#!/usr/bin/env python3
"""Wave-369 F552/F557/F565 closure battery (lane 5) -- object-literal family.

Three LOW findings from wave-368 attack round 36 (node v24.20.0 ->
credential, decoder missed on the wave-368-merged base):

F552: Symbol-keyed member reads on object literals.
  F535 covers string-key member access; computed Symbol keys are a
  different key production the literal model did not resolve:
    ({[Symbol.for('c')]:'f1'})[Symbol.for('c')]+'f2'
    ({get [Symbol.for('c')](){return 'f1';}})[Symbol.for('c')]+'f2'
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct from F535 (string keys) and F540
  (Reflect.get builtin).

F557: object spread copies of literals.
  F535 covers DIRECT literal reads; a spread copy ({...{c:'f1'}})
  builds a NEW object via SpreadElement, which the literal model did
  not resolve:
    ({...{c:'f1'}}).c+'f2'
    ({...Object.freeze({c:'f1'})}).c+'f2'
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct from F535 (direct) and F539
  (identity-preserving BUILTINS -- spread is syntax producing a new
  object).

F565: Object.fromEntries laundering.
  Unmodeled deserializing builtin (F500/F505 precedent):
    Object.fromEntries([['c','f1']]).c+'f2'
    Object.fromEntries(new Map([['c','f1']])).c+'f2'
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct from F541 (JSON.parse -- different
  builtin) and F539 (identity-preserving wrappers -- fromEntries
  TRANSFORMS pairs into an object).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f552_symbol_for` parses `[Symbol.for('K')]` -- only
    the shared-registry form is modeled (Symbol.for returns the same
    symbol on every call, node v24.20.0, so a write and a read
    provably address the same key). Bare `Symbol()` creates a unique
    symbol per call -- a static model can never match a write to a
    read, so it fails closed (documented boundary; engine-exact for
    the static decoder: the two-call shape never resolves in node
    either).
  * Symbol keys are stored as ("symbol", K) tuples in _JSObj.props --
    they can never collide with string keys (node-exact: a symbol key
    is not addressable by a string read, and dot syntax never reaches
    a symbol key). Write side: `_js_parse_f535_object` admits the
    computed key; getter heads admit `get [Symbol.for('k')]()` via
    `_js_parse_f535_getter_head`. Read side: the _JSObj postfix
    branch tries the Symbol.for read when the bracket opens on the
    Symbol keyword, else keeps the original fail-closed error.
  * `_js_parse_f557_spread` parses `...SRC` in object literals: SRC
    is an object literal (recursive, so nested spreads and F552
    symbol keys compose) or an F539 identity builtin
    (`Object.freeze(OBJLIT)` / `Object.assign({}, ...)`); the caller
    merges later-wins (node-exact: spread copies own enumerable
    props in order; getters were already resolved to data props by
    the F535/F539 parsers -- engine-exact, spread invokes [[Get]]).
    Anything else fails closed (documented).
  * `_js_parse_f565_from_entries` parses
    `Object.fromEntries(ENTRIES)`: ENTRIES is a pair list
    `[[k0,v0], ...]` or `new Map([[k0,v0], ...])` (empty Map
    admitted). Keys/values: string literals or canonical decimal
    integers (the engine ToPropertyKey's integer keys to their
    decimal repr). Duplicate keys: later wins (node-exact).
    `__proto__` becomes an OWN data property
    (CreateDataPropertyOnObject -- node-exact; unlike the
    object-literal [[Set]] semantics, so it is stored like any other
    key here). Non-pair iterables, non-literal keys/values, and
    malformed shapes fail closed (documented boundary).
  * The `_JS_EXPR_START` anchor's Object dot-member alternative gains
    `fromEntries` (literal-alternation only); the 12 anchor-pin
    batteries are re-pinned (they had gone stale across waves
    367-368: structuredClone, JSON, new WeakRef, freeze added
    without re-pin -- restored to exactness here).

Fail closed (documented, never mis-decoded): anonymous Symbol()
keys; Symbol.for with non-literal args; symbol/string key
cross-reads (dot or string-bracket reads of symbol keys);
non-literal spread sources (variables, calls, arrays); spread of
non-objects; fromEntries with non-pair/non-literal entries, extra
pair elements, or non-Map/new-X arguments; integer-keyed bracket
reads on _JSObj (pre-existing F535 residual class -- the write side
models integer keys but `[0]` reads fail closed, same as F535).

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"
_CRED = _A1 + _A2

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


def _node_eval(payloads):
    """Ground truth: node v24.20.0 eval of each payload (JSON or THROWS)."""
    src = "var cases=" + json.dumps(payloads) + ";" + """
var out=[];
for (var k=0;k<cases.length;k++){
  try{ out.push(JSON.stringify(eval(cases[k]))); }
  catch(e){ out.push("THROWS"); }
}
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", src], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, "node failed: %s" % r.stderr[-200:]
    return json.loads(r.stdout)


# ------------------------------------------------------------- P1: filed shapes
def p1_f552_filed_shapes():
    shapes = [
        "({[Symbol.for('c')]:'%(A1)s'})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        "({get [Symbol.for('c')](){return '%(A1)s';}})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F552 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f552_variants():
    shapes = [
        # whitespace tolerance
        "({ [ Symbol.for( 'c' ) ] : '%(A1)s' })[ Symbol.for( 'c' ) ]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # duplicate symbol keys: later wins (node-exact)
        "({[Symbol.for('c')]:'zz',[Symbol.for('c')]:'%(A1)s'})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # symbol key alongside string keys
        "({a:'x',[Symbol.for('c')]:'%(A1)s'})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # nested object under a symbol key
        "({[Symbol.for('c')]:{d:'%(A1)s'}})[Symbol.for('c')].d+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F552 variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_f557_filed_shapes():
    shapes = [
        "({...{c:'%(A1)s'}}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        "({...Object.freeze({c:'%(A1)s'})}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F557 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f557_variants():
    shapes = [
        # later-wins merge (node-exact)
        "({...{c:'zz'},...{c:'%(A1)s'}}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # nested spreads compose
        "({...{...{c:'%(A1)s'}}}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # spread alongside direct props
        "({a:'x',...{c:'%(A1)s'},b:'y'}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # getter in the spread source resolves (spread invokes [[Get]])
        "({...{get c(){return '%(A1)s';}}}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # symbol keys ride through spreads
        "({...{[Symbol.for('c')]:'%(A1)s'}})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # Object.assign identity builtin as spread source
        "({...Object.assign({},{c:'%(A1)s'})}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F557 variants block" % (len(shapes) - len(bad), len(shapes)))


def p1_f565_filed_shapes():
    shapes = [
        "Object.fromEntries([['c','%(A1)s']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        "Object.fromEntries(new Map([['c','%(A1)s']])).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F565 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f565_variants():
    shapes = [
        # duplicate keys: later wins (node-exact)
        "Object.fromEntries([['c','zz'],['c','%(A1)s']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # multi-pair lists
        "Object.fromEntries([['a','x'],['c','%(A1)s']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # whitespace tolerance
        "Object.fromEntries( [ [ 'c' , '%(A1)s' ] ] ).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # empty pair list decodes (no credential -- covered in P2)
        # __proto__ is an OWN data property via fromEntries (node-exact)
        "Object.fromEntries([['__proto__','%(A1)s']]).__proto__+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # empty Map input
        "Object.fromEntries(new Map()).c+'%(A2)s'",
    ]
    # the last shape decodes to 'undefined...' -- must NOT claim credential
    filed = shapes[:-1]
    bad = [s for s in filed if _verdict(s, True)[0] == "BREAK"]
    v, _ = _verdict(shapes[-1], False)
    if v == "BREAK":
        bad.append(shapes[-1])
    return ("HELD" if not bad else "BREAK",
            "%d/%d F565 variants behave" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P2: fail-closed bounds
def p2_f552_bounds():
    # Every shape here must NOT decode to the credential: either it
    # fails closed (miss) or it decodes to something != credential.
    shapes = [
        # anonymous Symbol(): unique per call -- fail closed (documented)
        "({[Symbol()]:'%(A1)s'})[Symbol()]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # Symbol.for with non-literal arg -- fail closed
        "({[Symbol.for(x)]:'%(A1)s'})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # registry mismatch: write 'c', read 'd' (node: undefined)
        "({[Symbol.for('c')]:'%(A1)s'})[Symbol.for('d')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # dot read can never address a symbol key (node: undefined)
        "({[Symbol.for('c')]:'%(A1)s'}).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # string-bracket read can never address a symbol key (node: undefined)
        "({[Symbol.for('c')]:'%(A1)s'})['c']+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # junk-quiet control (red-first battery)
        "({[Symbol.for('c')]:'zz'})[Symbol.for('c')]+'yy'",
        # non-Symbol computed key -- fail closed
        "({[x]:'%(A1)s'})[x]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # Symbol.hasInstance etc: not the for-registry -- fail closed
        "({[Symbol.hasInstance]:'%(A1)s'})[Symbol.hasInstance]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F552 bounds quiet" % (len(shapes) - len(bad), len(shapes)))


def p2_f557_bounds():
    shapes = [
        # spread of a variable -- fail closed
        "({...src}).c+'%(A2)s'" % {"A2": _A2},
        # spread of an array -- fail closed
        "({...['a']}).c+'%(A2)s'" % {"A2": _A2},
        # spread of a call result -- fail closed
        "({...f()}).c+'%(A2)s'" % {"A2": _A2},
        # junk-quiet control (red-first battery)
        "({...{c:'zz'}}).c+'yy'",
        # spread with no dots is a syntax error in node too -- decoder
        # must not misread `{..{c:'x'}}`
        "({..{c:'%(A1)s'}}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
    ]
    # deep spread nesting trips the _JS_EXPR_MAX_DEPTH bound (fail closed)
    deep = "({" + "...{" * 10 + "c:'x'" + "}" * 10 + "}).c"
    shapes.append(deep)
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F557 bounds quiet" % (len(shapes) - len(bad), len(shapes)))


def p2_f565_bounds():
    shapes = [
        # non-literal key -- fail closed
        "Object.fromEntries([[k,'%(A1)s']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # non-literal value -- fail closed
        "Object.fromEntries([['c',x]]).c+'yy'",
        # extra pair elements -- fail closed (documented)
        "Object.fromEntries([['c','%(A1)s','x']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # non-pair entry -- fail closed
        "Object.fromEntries(['%(A1)s']).c+'yy'" % {"A1": _A1},
        # non-Map new-X -- fail closed
        "Object.fromEntries(new Set([['c','%(A1)s']])).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
        # variable argument -- fail closed
        "Object.fromEntries(pairs).c+'%(A2)s'" % {"A2": _A2},
        # junk-quiet control (red-first battery)
        "Object.fromEntries([['c','zz']]).c+'yy'",
        # Objectx -- fail closed
        "Objectx.fromEntries([['c','%(A1)s']]).c+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F565 bounds quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P3: pins
def p3_no_new_regexes():
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    # The anchor edit modified the existing _JS_EXPR_START compile; no
    # new re.compile call may appear. F552/F557/F565 add no regexes.
    ok = src.count("re.compile") == 28
    # the anchor carries the new fromEntries member alternative
    # (wave-369 lane 6 extended the alternative with groupBy)
    ok = ok and "fromEntries|groupBy" in dlp._JS_EXPR_START.pattern
    return ("HELD" if ok else "BREAK",
            "re.compile=%d anchor-has-fromEntries=%s"
            % (src.count("re.compile"),
               "fromEntries|groupBy" in dlp._JS_EXPR_START.pattern))


def p3_node_differential():
    # Byte-fidelity vs node v24.20.0 on the filed shapes, key
    # variants, and the documented fail-closed/miss boundaries.
    # Decode cases: decoder must equal node exactly. Miss cases:
    # node yields undefined (or the read is unresolvable) -- the
    # decoder must return None (fail closed, never mis-decoded).
    decode_cases = [
        "({[Symbol.for('c')]:'ab'})[Symbol.for('c')]",
        "({get [Symbol.for('c')](){return 'ab';}})[Symbol.for('c')]",
        "({...{c:'ab'}}).c",
        "({...Object.freeze({c:'ab'})}).c",
        "({...{c:'x'},...{c:'ab'}}).c",
        "Object.fromEntries([['c','ab']]).c",
        "Object.fromEntries(new Map([['c','ab']])).c",
        "Object.fromEntries([['c','x'],['c','ab']]).c",
        "Object.fromEntries([['__proto__','ab']]).__proto__",
    ]
    miss_cases = [
        # node: undefined -- cross-namespace reads never resolve
        "({[Symbol.for('c')]:'ab'}).c",
        "({[Symbol.for('c')]:'ab'})[Symbol.for('d')]",
        "({[Symbol.for('c')]:'ab'})['c']",
    ]
    truth = _node_eval(decode_cases)
    bad = []
    for payload, want in zip(decode_cases, truth):
        if want == "THROWS":
            bad.append((payload, "node threw"))
            continue
        got = dlp._try_js_expr_decode_all(payload)
        if got != json.loads(want):
            bad.append((payload, got, json.loads(want)))
    for payload in miss_cases:
        got = dlp._try_js_expr_decode_all(payload)
        if got is not None:
            bad.append((payload, "decoded but node-undefined", got))
    total = len(decode_cases) + len(miss_cases)
    return ("HELD" if not bad else "BREAK",
            "%d/%d decoder==node (%s)"
            % (total - len(bad), total, bad[:1]))


# ------------------------------------------------------------- P4: discrimination
def p4_discrimination():
    # Honest text mentioning the new builtins must stay quiet; the
    # decoder must not hallucinate credentials from innocent shapes.
    shapes = [
        # prose about the builtin
        ("the Object.fromEntries call builds an object from pairs", False),
        # empty fromEntries decodes to {} -- no credential
        ("Object.fromEntries([])", False),
        # spread of empty object
        ("({...{}}).c", False),
        # symbol-keyed junk (red-first control)
        ("({[Symbol.for('c')]:'zz'})[Symbol.for('c')]+'yy'", False),
        # integer-keyed write with string read misses (node: undefined;
        # pre-existing F535 residual class -- integer bracket reads
        # fail closed on _JSObj)
        ("Object.fromEntries([[0,'%(A1)s']]).c+'%(A2)s'"
         % {"A1": _A1, "A2": _A2}, False),
    ]
    bad = ["%r" % s for s, want in shapes if _verdict(s, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d discrimination quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P5: perf bound
def p5_perf_bound():
    # Hostile inputs: many symbol keys / spreads / entries -- must
    # starve fast (F452 lesson: fail-closed matches consume scan
    # budget; the _MAX_WHOLETEXT_ATTEMPTS cap applies).
    junk = ("({[Symbol.for('c')]:'ab'})[Symbol.for('c')]"
            "({...{c:'ab'}}).c"
            "Object.fromEntries([['c','ab']]).c") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor symbol/spread/fromEntries corpus: hit=%s %.2fs"
            % (hit is not None, dt))


# ------------------------------------------------------------- P6: no regression
def p6_no_regression():
    # Neighbor findings stay HELD: F535 (direct literal reads), F536
    # (structuredClone), F539 (freeze/assign identity), F510
    # (Object.values), F540 (Reflect.get).
    shapes = [
        "({c:'%(A1)s'}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        "structuredClone({c:'%(A1)s'}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        "Object.freeze({c:'%(A1)s'}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        "Object.assign({},{c:'%(A1)s'}).c+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        "Object.values({c:'%(A1)s'}).join('')+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        "Reflect.get({c:'%(A1)s'},'c')+'%(A2)s'" % {"A1": _A1, "A2": _A2},
        # symbol-keyed literal still composes with the F536 deep copy
        "structuredClone({[Symbol.for('c')]:'%(A1)s'})[Symbol.for('c')]+'%(A2)s'"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d neighbors still HELD" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P7: pin and footer
def p7_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Lane-local footer: wave-369 lane 5 closes F552/F557/F565; the
    # merge reconciles with sibling lanes.
    ok = ("Next free finding: **F606**" in text  # Wave-369 lane 5: F552/F557/F565 CLOSED; F547-F551, F553-F556, F558-F564, F566-F569 OPEN (next F570)
          and "**Open findings: F597, F598, F599, F600, F601, F602, F603, F604, F605.**" in text  # Wave-369 lane 5: F552/F557/F565 CLOSED (next F570); wave-370 lane 4: F573/F578 CLOSED; wave-371 lane 2: F584, F588 CLOSED (F582 footer-stale corrected)
          and "**Status: CLOSED 2026-10-07 wave-369 lane 5.**" in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


GREEN_ADJACENT = [
    "evals/w368_f552_redfirst.py",
    "evals/w368_f557_redfirst.py",
    "evals/w368_f565_redfirst.py",
    "evals/w368_f539f540close_probes.py",
    "evals/w367_f535f536close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g369lane5-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" %
                  (rel, line[-1] if line else "rc=%d" % r.returncode,
                   time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f552-filed", p1_f552_filed_shapes),
    ("p1-f552-variants", p1_f552_variants),
    ("p1-f557-filed", p1_f557_filed_shapes),
    ("p1-f557-variants", p1_f557_variants),
    ("p1-f565-filed", p1_f565_filed_shapes),
    ("p1-f565-variants", p1_f565_variants),
    ("p2-f552-bounds", p2_f552_bounds),
    ("p2-f557-bounds", p2_f557_bounds),
    ("p2-f565-bounds", p2_f565_bounds),
    ("p3-no-new-regexes", p3_no_new_regexes),
    ("p3-node-differential", p3_node_differential),
    ("p4-discrimination", p4_discrimination),
    ("p5-perf-bound", p5_perf_bound),
    ("p6-no-regression", p6_no_regression),
    ("p7-pin-and-footer", p7_pin_and_footer),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    rows = []
    for name, fn in PROBES:
        try:
            v, msg = fn()
        except Exception as e:  # noqa: BLE001
            v, msg = "ERROR", "%s: %s" % (type(e).__name__, e)
        rows.append((name, v, msg))
        if v == "HELD":
            held += 1
        else:
            brk += 1
        print("%-22s %s -- %s" % (name, v, msg))
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (brk, held))
    g = green_check()
    print("green-check: %s" % ("PASS" if g else "FAIL"))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": g,
                          "probes": rows}))
    return 1 if (brk or not g) else 0


if __name__ == "__main__":
    sys.exit(main())
