#!/usr/bin/env python3
"""Wave-367 lane 4: F535/F536 closure probes.

F535 (LOW, filed wave-366 attack round 34, OPEN on base): member
access on object literals bypasses the bounded static JS-expression
decoder -- the decoder resolved no property reads on literals:
`({c:'f1'}).c+'f2'` (data property), `({get g(){return 'f1';}}).g+'f2'`
(getter invocation), and
`(new Proxy({c:'f1'},{get:(t,k)=>t[k]})).c+'f2'` (Proxy get-trap)
all node-evaluate (v24.20.0) to the exact credential while the
decoder produced zero variants. Distinct from F510/F517
(enumeration builtins) and F482 (method dispatch).

F536 (LOW, filed wave-366 attack round 34, OPEN on base):
structuredClone laundering -- `structuredClone({c:'f1'}).c+'f2'` and
`structuredClone({x:{c:'f1'}}).x.c+'f2'` node-evaluate to the exact
credential while the decoder (which did not model the builtin)
produced zero variants. Distinct per the F500/F505 precedent
(unmodeled builtin).

Closure (gov/dlp.py):
- `_JSObj`: a statically-resolved object literal (props: key ->
  str | _JSObj). It only ever flows through the new `_JSObj`
  branch of `_js_parse_postfix`, which resolves dot and
  string-literal bracket member reads against the parsed
  properties; a missing key, a non-literal member, or any other
  step fails closed -- the _JSObj never escapes as a value.
- `_js_parse_f535_object` (+ `_js_parse_f535_value`,
  `_js_parse_f535_getter_head`): parses `{k:v, ...}` with string /
  canonical-decimal-integer / identifier keys (`__proto__` fails
  closed), string-literal / canonical-decimal-integer / nested-object
  values, and `get name(){return VAL;}` getters (the engine invokes
  the getter on read; the static model evaluates the return
  expression -- `this`-dependent bodies fail closed because the
  value grammar has no `this`). Setters, methods, spread elements,
  computed keys, arrays, and non-canonical numbers (`042`, `0x10`,
  `1e3` are engine-different) fail closed. Duplicate keys: later
  wins (engine-exact). Each property charges the F430 parts budget.
- `_js_parse_f535_proxy`: `new Proxy(TARGET, {get:(P1,P2)=>P1[P2]})`
  -- only the direct-passthrough get-trap is modeled (the trap body
  must be exactly `P1[P2]` with the arrow's own parameter names, so
  the read resolves to TARGET's property node-exactly; the engine
  invokes TARGET's own getter during `P1[P2]`, and the resolved map
  already holds the getter's value). Method-form handlers,
  non-passthrough bodies, and extra handler keys fail closed.
- `_js_parse_f535_member_read`: `({OBJ}).member` /
  `(new Proxy(T,H)).member` at a GROUPING paren. A `(` that opens a
  call's argument list (preceded by an identifier char, `)`, or
  `]`) is not a parenthesized object literal -- decoding it would
  misread `fn({c:'f1'}).c` (the `.c` reads the CALL's unknown
  result) as `({c:'f1'}).c`. Doubly-grouped `(({...})).c` fails
  closed (documented out of scope).
- F536: `structuredClone(OBJ)` primary branch -- deep-copy of a
  JSON-literal object graph (data properties, getters, nested
  objects) via `_js_f535_deepcopy` (fresh nested structures, no
  aliasing with the source -- the node-verified deep-copy
  identity). Only object-literal args; every other arg class fails
  closed. Anchored by a `structuredClone(?![_$A-Za-z0-9])` addition
  to the existing `_JS_EXPR_START` (re.compile count stays 28).

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

from gov.dlp import (  # noqa: E402
    _JSObj,
    _js_f535_deepcopy,
    _js_parse_f535_object,
    _try_js_expr_decode,
    find_credential,
)

TAXONOMY_PIN = 2143  # Wave-367 lane 4; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


F535_FILED = [
    ("f535-data", "({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f535-getter", "({get g(){return '%s';}}).g+'%s'" % (_A1, _A2)),
    ("f535-proxy", "(new Proxy({c:'%s'},{get:(t,k)=>t[k]})).c+'%s'"
     % (_A1, _A2)),
]

F536_FILED = [
    ("f536-direct", "structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f536-nested", "structuredClone({x:{c:'%s'}}).x.c+'%s'"
     % (_A1, _A2)),
]

F535_VARIANTS = [
    # (name, payload, expected_decoded_suffix_note)
    ("f535-bracket", "({c:'%s'})['c']+'%s'" % (_A1, _A2)),
    ("f535-nested-chain", "({x:{c:'%s'}}).x.c+'%s'" % (_A1, _A2)),
    ("f535-int-key", "({1:'a',c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f535-dup-key", "({c:'x',c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("f535-proxy-getter-target",
     "(new Proxy({get g(){return '%s';}},{get:(t,k)=>t[k]})).g+'%s'"
     % (_A1, _A2)),
    ("f535-ws", "( { c : '%s' } ).c + '%s'" % (_A1, _A2)),
    ("f535-data-named-get", "({get:'%s'}).get+'%s'" % (_A1, _A2)),
    ("f535-data-named-set", "({set:'%s'}).set+'%s'" % (_A1, _A2)),
    ("f535-getter-additive", "({get g(){return '%s'+'%s';}}).g"
     % (_A1, _A2)),
]

F536_VARIANTS = [
    ("f536-getter", "structuredClone({get g(){return '%s';}}).g+'%s'"
     % (_A1, _A2)),
    ("f536-deep", "structuredClone({a:{b:{c:'%s'}}}).a.b.c+'%s'"
     % (_A1, _A2)),
    ("f536-trailing-comma", "structuredClone({c:'%s',}).c+'%s'"
     % (_A1, _A2)),
]

# Boundaries: the decoder must NOT recover the credential here.
BOUNDARIES = [
    ("b-bare-object", "({c:'%s'})" % _A1),
    ("b-missing-key", "({c:'%s'}).d+'%s'" % (_A1, _A2)),
    ("b-nonliteral-value", "({c:foo}).c+'%s'" % _A2),
    ("b-setter", "({set c(v){},d:'%s'}).d+'%s'" % (_A1, _A2)),
    ("b-method", "({m(){return '%s';}}).m()+'%s'" % (_A1, _A2)),
    ("b-spread", "({...x,c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("b-computed-key", "({['c']:'%s'}).c+'%s'" % (_A1, _A2)),
    ("b-proto", "({__proto__:{c:'%s'}}).c+'%s'" % (_A1, _A2)),
    ("b-trap-nonpassthrough",
     "(new Proxy({c:'%s'},{get:(t,k)=>t.x})).c+'%s'" % (_A1, _A2)),
    ("b-trap-method-form",
     "(new Proxy({c:'%s'},{get(t,k){return t[k];}})).c+'%s'"
     % (_A1, _A2)),
    ("b-trap-extra-key",
     "(new Proxy({c:'%s'},{get:(t,k)=>t[k],set:0})).c+'%s'"
     % (_A1, _A2)),
    ("b-optional-chain", "({c:'%s'})?.c+'%s'" % (_A1, _A2)),
    ("b-getter-this",
     "({get g(){return this.c;},c:'%s'}).g+'%s'" % (_A1, _A2)),
    ("b-octal-number", "({c:042}).c+'%s'" % _A2),
    ("b-hex-number", "({c:0x10}).c+'%s'" % _A2),
    ("b-clone-nonliteral", "structuredClone(x).c+'%s'" % _A2),
    ("b-clone-ident-boundary",
     "structuredClonex({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("b-clone-unbalanced", "structuredClone({c:'%s'}.c+'%s'" % (_A1, _A2)),
    ("b-call-paren-object", "someFn({c:'%s'}).c+'%s'" % (_A1, _A2)),
    ("b-getter-args", "({get g(v){return '%s';}}).g+'%s'" % (_A1, _A2)),
    ("b-getter-noreturn", "({get g(){'%s';}}).g+'%s'" % (_A1, _A2)),
    ("b-getter-bare-return", "({get g(){return;}}).g+'%s'" % _A2),
    ("b-getter-array-return", "({get g(){return ['%s'];}}).g+'%s'"
     % (_A1, _A2)),
    # Arrays as object values fail closed (documented F536 residual:
    # node evaluates structuredClone({a:['f1']}).a[0] to 'f1', the
    # decoder models no indexed reads on resolved values).
    ("b-array-value", "structuredClone({a:['%s']}).a[0]+'%s'"
     % (_A1, _A2)),
    ("b-double-grouped", "(({c:'%s'})).c+'%s'" % (_A1, _A2)),
    ("b-junk-quiet", "({c:'ab'}).c+'cd'"),
]

# (name, source, expected decoded value) -- expected values are
# node-v24.20.0 ground truth, verified independently before the
# closure; the decoder must reproduce them exactly.
NODE_EXACT = [
    ("n-data", "({c:'%s'}).c" % _A1, _A1),
    ("n-bracket", "({c:'%s'})['c']" % _A1, _A1),
    ("n-getter", "({get g(){return '%s';}}).g" % _A1, _A1),
    ("n-proxy", "(new Proxy({c:'%s'},{get:(t,k)=>t[k]})).c" % _A1, _A1),
    ("n-proxy-getter",
     "(new Proxy({get g(){return '%s';}},{get:(t,k)=>t[k]})).g" % _A1,
     _A1),
    ("n-clone", "structuredClone({c:'%s'}).c" % _A1, _A1),
    ("n-clone-nested", "structuredClone({x:{c:'%s'}}).x.c" % _A1, _A1),
    ("n-clone-getter",
     "structuredClone({get g(){return '%s';}}).g" % _A1, _A1),
    ("n-nested", "({x:{c:'%s'}}).x.c" % _A1, _A1),
    ("n-int-key", "({1:'a',c:'%s'}).c" % _A1, _A1),
    ("n-dup-key", "({c:'x',c:'%s'}).c" % _A1, _A1),
    ("n-number", "({n:42}).n", "42"),
    ("n-neg-number", "({n:-5}).n", "-5"),
    ("n-named-get", "({ get : '%s' }).get" % _A1, _A1),
    ("n-named-set", "({set:'%s'}).set" % _A1, _A1),
    ("n-clone-deep", "structuredClone({a:{b:{c:'%s'}}}).a.b.c" % _A1,
     _A1),
]

# Neighbor compositions that must stay honest.
COMPOSITIONS = [
    ("c-f482-held", "[].concat('%s')" % (_A1 + _A2), True),
    ("c-f510-held", "Object.values({c:'%s'}).join('')" % (_A1 + _A2),
     True),
    ("c-f517-held",
     "Object.keys({c:'%s'}).map(k=>({c:'%s'})[k]).join('')"
     % (_A1 + _A2, _A1 + _A2), True),
    ("c-additive-held", "'%s'+'%s'" % (_A1, _A2), True),
    # F434 array-join through the unknown-callee wrapper is a true
    # positive (node genuinely evaluates it to the credential).
    ("c-clone-array-join-truepos",
     "structuredClone(['%s','%s']).join('')" % (_A1, _A2), True),
    ("c-grouped-after-op", "x=({c:'%s'}).c+'%s'" % (_A1, _A2), True),
    ("c-grouped-as-arg", "foo(({c:'%s'}).c+'%s')" % (_A1, _A2), True),
]


def p1_f535_filed_held():
    """The three filed F535 shapes decode (HELD)."""
    misses = [n for n, p in F535_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F535 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F535 filed shapes decode"
            % (len(F535_FILED), len(F535_FILED)))


def p2_f536_filed_held():
    """The two filed F536 shapes decode (HELD)."""
    misses = [n for n, p in F536_FILED if not _hit(p)]
    if misses:
        return ("BREAK", "F536 filed missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F536 filed shapes decode"
            % (len(F536_FILED), len(F536_FILED)))


def p3_f535_variants_held():
    """F535 variant shapes decode (HELD) -- node-exact extensions."""
    misses = [n for n, p in F535_VARIANTS if not _hit(p)]
    if misses:
        return ("BREAK", "F535 variants missed: %s" % ",".join(misses))
    # the number-value variant decodes to the decimal repr (it is not
    # credential-shaped, so find_credential cannot flag it -- assert
    # the decode directly, node-v24.20.0 ground truth)
    r = _try_js_expr_decode("({n:42}).n", 0)
    if r is None or r[0] != "42":
        return ("BREAK", "number value variant mis-decoded: %r" % (r,))
    return ("HELD", "%d/%d F535 variants decode (+number value exact)"
            % (len(F535_VARIANTS), len(F535_VARIANTS)))


def p4_f536_variants_held():
    """F536 variant shapes decode (HELD) -- node-exact extensions."""
    misses = [n for n, p in F536_VARIANTS if not _hit(p)]
    if misses:
        return ("BREAK", "F536 variants missed: %s" % ",".join(misses))
    return ("HELD", "%d/%d F536 variants decode"
            % (len(F536_VARIANTS), len(F536_VARIANTS)))


def p5_boundaries_fail_closed():
    """Every documented boundary fails closed (no credential hit)."""
    bad = [n for n, p in BOUNDARIES if _hit(p)]
    if bad:
        return ("BREAK", "boundaries decoded: %s" % ",".join(bad))
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(BOUNDARIES), len(BOUNDARIES)))


def p6_node_exact():
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


def p7_deepcopy_identity():
    """structuredClone's deep-copy identity: fresh structures.

    Parsing the same object shape twice must yield independent
    nested structures (no aliasing with the source) -- the static
    counterpart of node's `p.c='x'` not aliasing `o.c`.
    """
    state = {"ops": 0, "parts": 0}
    p1, _ = _js_parse_f535_object("{x:{c:'f1'}}", 0, 0, state)
    state = {"ops": 0, "parts": 0}
    p2, _ = _js_parse_f535_object("{x:{c:'f1'}}", 0, 0, state)
    c1 = _js_f535_deepcopy(p1)
    c2 = _js_f535_deepcopy(p2)
    if c1 is p1 or c2 is p2:
        return ("BREAK", "deepcopy aliased the source map")
    if c1["x"] is p1["x"] or c2["x"] is p2["x"]:
        return ("BREAK", "deepcopy aliased nested structure")
    if not isinstance(c1["x"], _JSObj) or c1["x"].props["c"] != "f1":
        return ("BREAK", "deepcopy lost values")
    if c1["x"] is c2["x"]:
        return ("BREAK", "two clones share structure")
    return ("HELD", "deepcopy rebuilds fresh nested structures")


def p8_compositions_honest():
    """Neighbor findings and composition shapes stay honest."""
    wrong = [n for n, p, want in COMPOSITIONS if _hit(p) != want]
    if wrong:
        return ("BREAK", "composition wrong: %s" % ",".join(wrong))
    return ("HELD", "%d/%d compositions honest"
            % (len(COMPOSITIONS), len(COMPOSITIONS)))


def p9_pin_and_footer():
    """Pin stays 2143; re.compile stays 28; F535/F536 CLOSED in  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    FINDINGS; lane-local footer (repointed wave-369 lane 2)."""
    if TAXONOMY_PIN != 2143:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
        return ("BREAK", "pin moved: %s" % TAXONOMY_PIN)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    if len(re.findall(r"re\.compile\(", src)) != 28:
        return ("BREAK", "re.compile count moved")
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if text.count("CLOSED 2026-10-07 wave-367 lane 4") < 2:
        return ("BREAK", "F535/F536 CLOSED entries missing")
    if "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" not in text:  # Wave-369 merge: lanes 1-5 (F547-F557,F565) CLOSED  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
        return ("BREAK", "lane-local footer wrong")
    if "Next free finding: **F762**" not in text:  # Wave-369 lane 2 local: F548/F549/F550 CLOSED (merge finalizes)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
        return ("BREAK", "next-free footer wrong")
    return ("HELD", "pin 2143; 28 re.compile; F535/F536 CLOSED; "  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
            "footer F547,F551-F569/next F570 (wave-369 lane 2)")


def _green_check():
    """Depth-1 green check: red-first + adjacent DLP batteries, green
    checks skipped in the child env (GOV_SKIP_GREEN=1). A battery is
    green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w366_f535_redfirst.py",
               "w366_f536_redfirst.py",
               "w359_f482f483close_probes.py",
               "w363_f510f511close_probes.py",
               "w364_f516f517close_probes.py",
               "w366_f527f530close_probes.py",
               "w366_f528f529close_probes.py")
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
    probes = (p1_f535_filed_held, p2_f536_filed_held,
              p3_f535_variants_held, p4_f536_variants_held,
              p5_boundaries_fail_closed, p6_node_exact,
              p7_deepcopy_identity, p8_compositions_honest,
              p9_pin_and_footer)
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
