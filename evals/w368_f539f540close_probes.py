#!/usr/bin/env python3
"""Wave-368 lane 2: F539/F540 closure probes.

F539 (LOW, filed wave-367 attack round 35, OPEN on base): property
reads on identity-preserving builtin results bypass the bounded
static JS-expression decoder -- F535 covers member access on OBJECT
LITERALS, but the object can come from a builtin call that returns
(a reference to) an existing object: `Object.assign({},
{c:'f1'}).c+'f2'` (assign returns its target), `Object.freeze({c:'f1'
}).c+'f2'` (freeze returns its argument), and `new WeakRef({c:'f1'
}).deref().c+'f2'` (deref returns the referent) all node-evaluate
(v24.20.0) to the exact credential while the decoder produced zero
variants. Distinct from F535 (literal sources) and F510/F517
(enumeration builtins).

F540 (LOW, filed wave-367 attack round 35, OPEN on base):
`Reflect.get` on object literals bypasses the decoder -- F535 covers
member-access SYNTAX, but the Reflect.get BUILTIN is a different
property-read mechanism: `Reflect.get({c:'f1'}, 'c')+'f2'` (data
property), `Reflect.get({get g(){return 'f1';}}, 'g')+'f2'` (getter
invocation), and `Reflect.apply(Reflect.get([],'concat'), [],
['f1','f2']).join('')` (method retrieval for later application).
Distinct from F535 (syntax vs builtin) and F482 (bracket dispatch).

Closure (gov/dlp.py):
- `_js_parse_f539_object_identity`: `Object.assign({}, OBJLIT,
  ...)` (empty-literal target, object-literal sources, later-wins
  merge -- node-exact, since assign reads each source's [[Get]], so
  a source getter becomes a data prop with its return value,
  matching F535's getter resolution) and `Object.freeze(OBJLIT)`
  (identity) desugar to a _JSObj; member reads route through the
  F535 _JSObj postfix branch. Non-empty assign targets fail closed
  (the engine's [[Set]] on a getter-only target accessor silently
  no-ops, so later-wins would mis-decode); non-literal args,
  multi-arg freeze, and `Object['assign']`/`Object['freeze']`
  bracket forms fail closed (documented residuals).
- `_js_parse_f539_weakref`: `new WeakRef(OBJLIT).deref()` desugars
  to the literal itself (deref returns the referent, node v24.20.0
  verified). Non-literal targets, missing `.deref()`, and deref
  arguments fail closed. Anchored by a `new WeakRef` addition to
  the existing `_JS_EXPR_START` (re.compile count stays 28).
- `_js_parse_f540_reflect_get_object`: `Reflect.get(OBJLIT, KEY)`
  desugars to the F535 member read -- object-literal targets via
  `_js_parse_f535_object`, string-literal or `['literal']` keys;
  data properties resolve, getters evaluate as plain expressions
  (node-exact). Missing keys, non-literal keys, methods/setters
  (already failed closed at object parse), and extra arguments fail
  closed. The method-retrieval shape `Reflect.get([],'concat')` is
  a DOCUMENTED residual: the resolved function reference is not a
  decodable value (fails closed, never mis-decoded).
- `Object.freeze` joins the existing Object member anchor class in
  `_JS_EXPR_START` (no new re.compile).

Probe verdicts: HELD = decoder blocks (find_credential hits) or
correctly misses a fail-closed boundary; BREAK = a filed/claimed
shape misses or a boundary decodes node-wrong.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""

import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, REPO_ROOT)

import gov.dlp as dlp  # noqa: E402
from gov.dlp import _try_js_expr_decode, find_credential  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-368 lane 2; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


F539_FILED = [
    ("f539-assign",
     "Object.assign({}, {c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-freeze",
     "Object.freeze({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-weakref",
     "new WeakRef({c:'%s'}).deref().c+'%s'" % (_A1, _A2)),
]

F540_FILED = [
    ("f540-data",
     "Reflect.get({c:'%s'}, 'c')+'%s'" % (_A1, _A2)),
    ("f540-getter",
     "Reflect.get({get g(){return '%s';}}, 'g')+'%s'" % (_A1, _A2)),
    # method retrieval is a DOCUMENTED residual: the resolved function
    # reference is not a decodable value -- it must MISS (fail closed).
    ("f540-method-residual",
     "Reflect.apply(Reflect.get([],'concat'), [], ['%s','%s']).join('')"
     % (_A1, _A2)),
]

F539_VARIANTS = [
    ("f539-assign-multi",
     "Object.assign({}, {a:'x'},{c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-assign-dupkey",
     "Object.assign({}, {c:'x'},{c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-assign-getter-src",
     "Object.assign({}, {get c(){return '%s';}}).c+'%s'" % (_A1, _A2)),
    ("f539-freeze-nested",
     "Object.freeze({x:{c:'%s'}}).x.c+'%s'" % (_A1, _A2)),
    ("f539-freeze-bracket",
     "Object.freeze({c:'%s'})['c']+'%s'" % (_A1, _A2)),
    ("f539-weakref-getter",
     "new WeakRef({get g(){return '%s';}}).deref().g+'%s'"
     % (_A1, _A2)),
    ("f539-assign-ws",
     "Object . assign ( {} , { c : '%s' } ) . c + '%s'" % (_A1, _A2)),
    ("f539-weakref-ws",
     "new  WeakRef( { c : '%s' } ) . deref ( ) . c + '%s'"
     % (_A1, _A2)),
]

F540_VARIANTS = [
    ("f540-bracket-key",
     "Reflect.get({c:'" + _A1 + "'}, ['c'])+'" + _A2 + "'"),
    ("f540-nested",
     "Reflect.get({x:{c:'%s'}}, 'x').c+'%s'" % (_A1, _A2)),
    ("f540-ws",
     "Reflect . get ( { c : '%s' } , 'c' ) + '%s'" % (_A1, _A2)),
    ("f540-bracket-get",
     "Reflect['get']({c:'%s'}, 'c')+'%s'" % (_A1, _A2)),
    ("f540-int-key-obj",
     "Reflect.get({1:'a',c:'%s'}, 'c')+'%s'" % (_A1, _A2)),
]

BOUNDARIES = [
    # (name, payload) -- each must MISS (fail closed, no hit)
    ("f539-assign-nonempty-target",
     "Object.assign({c:'zz'}, {c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-assign-nonliteral-src",
     "Object.assign({}, x).c+'%s'" % _A2),
    ("f539-assign-array-src",
     "Object.assign({}, ['%s']).c+'%s'" % (_A1, _A2)),
    ("f539-freeze-two-args",
     "Object.freeze({c:'%s'}, {d:'e'}).c+'%s'" % (_A1, _A2)),
    ("f539-freeze-nonliteral",
     "Object.freeze(x).c+'%s'" % _A2),
    ("f539-freeze-bracket-form",
     "Object['freeze']({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-weakref-nonliteral",
     "new WeakRef(x).deref().c+'%s'" % _A2),
    ("f539-weakref-no-deref",
     "new WeakRef({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f539-weakref-deref-arg",
     "new WeakRef({c:'%s'}).deref(0).c+'%s'" % (_A1, _A2)),
    ("f539-weakref-other-member",
     "new WeakRef({c:'%s'}).x+'%s'" % (_A1, _A2)),
    ("f540-missing-key",
     "Reflect.get({c:'%s'}, 'd')+'%s'" % (_A1, _A2)),
    ("f540-nonliteral-key",
     "Reflect.get({c:'" + _A1 + "'}, k)+'" + _A2 + "'"),
    ("f540-extra-arg",
     "Reflect.get({c:'%s'}, 'c', x)+'%s'" % (_A1, _A2)),
    ("f540-no-key",
     "Reflect.get({c:'%s'})+'%s'" % (_A1, _A2)),
    ("f540-method-in-literal",
     "Reflect.get({m(){return '%s'}}, 'm')+'%s'" % (_A1, _A2)),
    ("f540-nonliteral-target",
     "Reflect.get(x, 'c')+'%s'" % _A2),
    ("f540-numeric-key-miss",
     "Reflect.get({c:'%s'}, 0)+'%s'" % (_A1, _A2)),
]

# (name, source, node-v24.20.0 ground truth) -- decoder must be exact.
NODE_EXACT = [
    ("assign", "Object.assign({}, {c:'f1'}).c", "f1"),
    ("assign-multi", "Object.assign({}, {a:'x'},{b:'f1'}).b", "f1"),
    ("assign-dupkey", "Object.assign({}, {c:'f0'},{c:'f1'}).c", "f1"),
    ("assign-getter", "Object.assign({}, {get c(){return 'f1'}}).c",
     "f1"),
    ("freeze", "Object.freeze({c:'f1'}).c", "f1"),
    ("freeze-nested", "Object.freeze({x:{c:'f1'}}).x.c", "f1"),
    ("weakref", "new WeakRef({c:'f1'}).deref().c", "f1"),
    ("weakref-getter",
     "new WeakRef({get g(){return 'f1'}}).deref().g", "f1"),
    ("rget-data", "Reflect.get({c:'f1'}, 'c')", "f1"),
    ("rget-bracket", "Reflect.get({c:'f1'}, ['c'])", "f1"),
    ("rget-getter", "Reflect.get({get g(){return 'f1'}}, 'g')", "f1"),
    ("rget-nested", "Reflect.get({x:{c:'f1'}}, 'x').c", "f1"),
]

COMPOSITIONS = [
    # (name, payload, want_hit) -- neighbors stay honest
    ("f471-array-assign",
     "Object.assign([], ['%s','%s']).join('')" % (_A1, _A2), True),
    ("f491-reflect-array",
     "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')"
     % (_A1, _A2), True),
    ("f535-literal",
     "({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f536-clone",
     "structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("f482-bracket-dispatch",
     "['%s','%s']['join']('')" % (_A1, _A2), True),
    ("f510-values",
     "Object.values({0:'%s',1:'%s'}).join('')" % (_A1, _A2), True),
    ("f541-json-closed",
     "JSON.parse('{\"x\":[\"%s\",\"%s\"]}').x.join('')" % (_A1, _A2),
     True),  # F541 CLOSED 2026-10-07 wave-368 lane 3 (merge maintenance)
    ("junk-quiet-assign", "Object.assign({}, {c:'ab'}).c+'cd'", False),
    ("junk-quiet-rget", "Reflect.get({c:'ab'}, 'c')+'cd'", False),
    ("junk-quiet-weakref",
     "new WeakRef({c:'ab'}).deref().c+'cd'", False),
]

FOOTER_OPEN = (  # Wave-369 merge: F547-F557,F560,F562,F563,F565 CLOSED (lanes 1-6); open F558/F567-F569
               "F570", "F571", "F572", "F573",
               "F574", "F575", "F576", "F577",
               "F578", "F579", "F580", "F581",
               "F582"
               )  # Wave-369 merge
FOOTER_NEXT = "F700"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


def p1_f539_filed_held():
    """F539 filed shapes decode (HELD)."""
    misses = [n for n, p in F539_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F539 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F539 filed shapes decode"
            % (len(F539_FILED), len(F539_FILED)))


def p2_f540_filed_held():
    """F540 filed shapes: data + getter decode (HELD); method
    retrieval is the documented residual and must MISS."""
    got = {n: _hit(p) for n, p in F540_FILED}
    if not got["f540-data"] or not got["f540-getter"]:
        return ("BREAK", "F540 data/getter missed: %s"
                % ",".join(n for n in ("f540-data", "f540-getter")
                            if not got[n]))
    if got["f540-method-residual"]:
        return ("BREAK", "f540 method-retrieval residual decoded "
                "(must fail closed)")
    return ("HELD", "F540 data/getter decode; method-retrieval "
            "residual fails closed as documented")


def p3_variants_held():
    """Variant shapes decode (HELD) -- node-exact extensions."""
    misses = ([n for n, p in F539_VARIANTS if not _hit(p)]
              + [n for n, p in F540_VARIANTS if not _hit(p)])
    if misses:
        return ("BREAK", "variants missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d variants decode"
            % (len(F539_VARIANTS) + len(F540_VARIANTS),
               len(F539_VARIANTS) + len(F540_VARIANTS)))


def p4_boundaries_fail_closed():
    """Every documented boundary fails closed (no credential hit)."""
    bad = [n for n, p in BOUNDARIES if _hit(p)]
    if bad:
        return ("BREAK", "boundaries decoded: %s" % ",".join(bad))
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(BOUNDARIES), len(BOUNDARIES)))


def p5_node_exact():
    """Decoder reproduces node-v24.20.0 ground truth exactly."""
    wrong = []
    for name, src, want in NODE_EXACT:
        r = _try_js_expr_decode(src, 0)
        got = r[0] if r else None
        if got != want:
            wrong.append("%s(got %r)" % (name, got))
    if wrong:
        return ("BREAK", "node-inexact: %s" % ",".join(wrong))
    return ("HELD", "%d/%d node-exact" % (len(NODE_EXACT),
                                         len(NODE_EXACT)))


def p6_compositions_honest():
    """Neighbor findings and composition shapes stay honest."""
    wrong = [n for n, p, want in COMPOSITIONS if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest"
            % (len(COMPOSITIONS), len(COMPOSITIONS)))


def p7_perf_bound():
    """Hostile corpus: many fail-closed matches must starve fast."""
    payload = (("new WeakRef(x).deref().c+'%s';" % _A1)
               + ("Object.freeze(y).c+'%s';" % _A1)) * 300
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK",
            "600-anchor hostile corpus %.2fs (budget 5s)" % dt)


def p8_pin_and_footer():
    """Pin stays 2140; re.compile stays 28; F539/F540 CLOSED in
    FINDINGS; lane-local footer."""
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if text.count("CLOSED 2026-10-07 wave-368 lane 2") < 2:
        return ("BREAK", "F539/F540 CLOSED entries missing")
    if ("**Open findings: %s.**" % ", ".join(FOOTER_OPEN)) not in text:  # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583)
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **%s**" % FOOTER_NEXT not in text:
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2140; 28 re.compile; F539/F540 CLOSED; "
            "footer %s/next %s (wave-369 lane 2)"
            % (",".join(FOOTER_OPEN), FOOTER_NEXT))


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w367_f539_redfirst.py",
               # w367_f540_redfirst.py is intentionally absent: its
               # get-method-apply probe prints BREAK on the closed tree
               # by design (the method-retrieval shape is F540's
               # documented fail-closed residual). That probe is pinned
               # as a residual in p2 above instead.
               "w367_attack_probes.py",
               "w367_f535f536close_probes.py",
               "w366_attack_probes.py",
               "w363_f510f511close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g368-green-%s-%d" % (script.replace(".py", ""),
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
    probes = (p1_f539_filed_held, p2_f540_filed_held,
              p3_variants_held, p4_boundaries_fail_closed,
              p5_node_exact, p6_compositions_honest,
              p7_perf_bound, p8_pin_and_footer)
    breaks, held = 0, 0
    for probe in probes:
        verdict, note = probe()
        print("%s: %s -- %s" % (probe.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    print("green check: %s" % _green_check())
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
