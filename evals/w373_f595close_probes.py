#!/usr/bin/env python3
"""Wave-373 lane 1 close probes: F595 (JSON.stringify of nested array values).

F595 (filed wave-370 merge, LOW, honestly OPEN after the wave-372 merge audit:
wave-371 overstated its closure; the decoder still misses): F571 (wave-370
lane 2, CLOSED) models the stringify/parse round-trip for string literals,
arrays of string literals, and F535 object literals, but array VALUES nested
inside objects or arrays are not serialized:
  JSON.parse(JSON.stringify({a:['f1','f2']})).a.join('')
  JSON.parse(JSON.stringify([['f1'],['f2']])).flat().join('')
both node-evaluate to the exact credential (v24.20.0) while the decoder
produces zero variants. Distinct from F571 (flat arrays, CLOSED) and F598
(derived arrays, CLOSED).

Closed by two composable, previously-fail-closed extensions of the F571
stringify VALUE grammar (node-exact; no previously-decoded input changes
behavior because both branches raised _JSExprFail before):
1. `_js_parse_f595_json_array` -- JSON-literal arrays whose elements are
   string literals (incl. `...` templates, F468 element class) or nested
   arrays (recursive, _JS_EXPR_MAX_DEPTH-bounded); numerics, objects,
   non-literals fail closed.
2. `_js_parse_f535_object(..., nested_arrays=True)` (stringify VALUE position
   only) -- object values may be `_js_parse_f595_json_array` arrays;
   propagates through nested objects; spread sources stay strict
   (documented boundary). All other F535 callers keep the default
   (arrays fail closed there, F535/F536 boundary preserved).
The nested _JSArr/_JSObj then serializes through the UNCHANGED
_js_f571_stringify + F541 json.loads tail.

Seams under test (tdd): find_credential at the public seam for every probe;
node v24.20.0 differential (subprocess) for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
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

TAXONOMY_PIN = 2143  # Wave-372 merge: pin 2143 (F597-F605 closed); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ---------------------------------------------------------- P1: filed shapes
def p1_f595_filed_shapes():
    """The two filed F595 shapes must decode (HELD after closure)."""
    shapes = [
        "JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')" % (_A1, _A2),
        "JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')"
        % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return (("HELD", "2/2 filed shapes decode") if not bad
            else ("BREAK", "miss: %r" % ([b[:50] for b in bad],)))


# ---------------------------------------------------------- P2: variants
def p2_f595_variants():
    """Node-exact twins of the filed shapes (all verified v24.20.0)."""
    variants = [
        # multi-prop object: .a selects the nested array
        ("multi-prop", "JSON.parse(JSON.stringify({a:['%s','%s'],b:'zz'}))"
         ".a.join('')" % (_A1, _A2)),
        # double-quoted literals
        ("dq", 'JSON.parse(JSON.stringify({a:["%s","%s"]})).a.join("")'
         % (_A1, _A2)),
        # ws-tolerant
        ("ws", "JSON.parse( JSON.stringify( { a : [ '%s' , '%s' ] } ) )"
         ".a.join( '' )" % (_A1, _A2)),
        # flat(1) twin of the arr-in-arr shape
        ("flat1", "JSON.parse(JSON.stringify([['%s'],['%s']])).flat(1)"
         ".join('')" % (_A1, _A2)),
        # empty inner array (JSON.stringify([]) -> '[]', node-exact)
        ("empty-inner", "JSON.parse(JSON.stringify([[],['%s','%s']]))"
         ".flat().join('')" % (_A1, _A2)),
        # one deeper nesting (recursive grammar, depth-bounded)
        ("deeper", "JSON.parse(JSON.stringify([[['%s']],[['%s']]]))"
         ".flat(2).join('')" % (_A1, _A2)),
        # nested object carrying the array value
        ("obj-in-obj", "JSON.parse(JSON.stringify({o:{c:['%s','%s']}}))"
         ".o.c.join('')" % (_A1, _A2)),
        # both halves in one inner array
        ("one-inner", "JSON.parse(JSON.stringify([['%s','%s']]))"
         ".flat().join('')" % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P3: bounds
def p3_f595_bounds():
    """Boundaries of the F595 grammar must stay fail-closed (quiet)."""
    deep = "[" * 12 + "'%s'" % _A1 + "]" * 12  # past _JS_EXPR_MAX_DEPTH
    bounds = [
        # numerics in nested arrays fail closed (F468 element class)
        "JSON.parse(JSON.stringify([['%s'],[1]])).flat().join('')"
        % _A1,
        # objects inside nested arrays fail closed
        "JSON.parse(JSON.stringify([{'a':'%s'}])).flat().join('')" % _A1,
        # non-literal elements fail closed
        "JSON.parse(JSON.stringify([[%s]])).flat().join('')" % _A1,
        # replacer/space args fail closed (F571 boundary)
        "JSON.parse(JSON.stringify([['%s']],null)).flat().join('')" % _A1,
        # bracket-string member form fails closed
        "JSON.parse(JSON['stringify']([['%s']])).flat().join('')" % _A1,
        # too-deep nesting fails closed
        "JSON.parse(JSON.stringify(%s)).flat(11).join('')" % deep,
        # spread sources stay strict: array-valued spread props fail closed
        "JSON.parse(JSON.stringify({...{a:['%s']}})).a.join('')" % _A1,
        # getter returning an array fails closed (F535 getter boundary)
        ("JSON.parse(JSON.stringify({get a(){return ['%s'];}}))"
         ".a.join('')" % _A1),
    ]
    bad = [s for s in bounds if _blocked(s)]
    return (("HELD", "%d/%d bounds quiet" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "decoded: %r" % ([b[:50] for b in bad],)))


# ---------------------------------------------------------- P4: compositions
def p4_compositions():
    """F571/F598 stay held; F595 does not absorb F606-F611's shapes."""
    held = [
        # F571: top-level literal array still decodes
        "JSON.parse(JSON.stringify(['%s','%s'])).join('')" % (_A1, _A2),
        # F571: nested object (no arrays) still decodes
        "JSON.parse(JSON.stringify({o:{c:'%s'}})).o.c+'%s'" % (_A1, _A2),
        # F598: derived arrays still decode
        "JSON.parse(JSON.stringify([...new Set(['%s','%s'])]))"
        ".join('')" % (_A1, _A2),
        # F595 closed shape composes with the F541 tail: nested .a after
        # a top-level key on a two-prop object
        "JSON.parse(JSON.stringify({z:'q',a:['%s','%s']})).a.join('')"
        % (_A1, _A2),
    ]
    quiet = [
        # junk never decodes
        "JSON.parse(JSON.stringify({a:['zz','yy']})).a.join('')",
        # honest nested values (no credential) stay quiet: no false
        # positives from the F595 grammar on benign nested structures
        "JSON.parse(JSON.stringify({a:['hello','world']})).a.join('')",
        "JSON.parse(JSON.stringify([['a'],['b']])).flat().join('')",
        "JSON.parse(JSON.stringify({o:{c:['x','y']}})).o.c.join('')",
        # F595 grammar does not touch F606-F611 (still open, verified miss)
        "JSON.parse(JSON.stringify({a:['%s']}))).a.join('')" % _A1,
    ]
    bad_h = [s for s in held if not _blocked(s)]
    bad_q = [s for s in quiet if _blocked(s)]
    bad = bad_h + bad_q
    return (("HELD", "compositions green") if not bad
            else ("BREAK", "bad: %r" % ([b[:50] for b in bad],)))


# ---------------------------------------------------------- P5: node differential
_DIFF_CASES = [
    "JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')",
    "JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')",
    "JSON.parse(JSON.stringify({o:{c:['%s','%s']}})).o.c.join('')",
    "JSON.parse(JSON.stringify([[['%s']],[['%s']]])).flat(2).join('')",
]


def p5_node_differential():
    """node v24.20.0 must yield the exact credential for every case."""
    import json as _json  # noqa: E402
    want = _A1 + _A2
    cases = [t % (_A1, _A2) for t in _DIFF_CASES]
    script = ("const cases=" + _json.dumps(cases) +
              ";const want=" + _json.dumps(want) + ";" +
              "for(const s of cases){let v;try{v=eval(s)}catch(e)"
              "{console.log('THROW');continue}"
              "console.log(v===want?'EXACT':'DIFF:'+v);}")
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                       timeout=60)
    lines = [l for l in (r.stdout or "").splitlines() if l]
    bad = [l for l in lines if l != "EXACT"]
    if r.returncode != 0 or len(lines) != len(_DIFF_CASES):
        return "BREAK", "node run failed rc=%d" % r.returncode
    return (("HELD", "%d/%d node-exact" % (len(_DIFF_CASES), len(_DIFF_CASES)))
            if not bad else ("BREAK", "diffs: %r" % (bad,)))


# ---------------------------------------------------------- P6: pin + footer
def p6_pin_footer():
    assert TAXONOMY_PIN == 2143, "pin moved"  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    from gov import guac_graph  # noqa: E402
    # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    assert guac_graph.TAXONOMY_PIN == 2143, \
        "guac_graph.TAXONOMY_PIN=%r want 2143" % (guac_graph.TAXONOMY_PIN,)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F921**" in text  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          # Wave-373 lane 1: F595 CLOSED
          and "**Open findings: F893, F894, F895, F896, F897, F898, F899, F900, F901, F902, F903, F904, F905, F906, F907, F908, F909, F910, F911, F912, F913, F914, F915, F916, F917, F918, F919, F920.**" in text  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
          and text.count("**Status: CLOSED 2026-10-08 wave-373 lane 1.**")
              == 1)
    return ("HELD" if ok else "BREAK", "pin+footer")


# ---------------------------------------------------------- P7: perf bound
def p7_perf_bound():
    # The F595 branches add at most one extra bounded decode attempt per
    # `[` / `JSON` anchor; the hostile corpus must stay under the 5s pin.
    corpus = ("\"JSON.parse(JSON.stringify([[['x']]]))\";" * 60 +
              "\"JSON.parse(JSON.stringify({a:['x','y']}))\";" * 60)
    t0 = time.time()
    dlp.find_credential(corpus)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "corpus %.2fs" % dt)


GREEN_ADJACENT = [
    "evals/w370_f595_redfirst.py",
    "evals/w370_f571f576close_probes.py",
    "evals/w372_f598close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g373lane1-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            out = (r.stdout or "") + (r.stderr or "")
            line = [l for l in out.splitlines() if "tally:" in l]
            tag = line[-1] if line else "rc=%d" % r.returncode
            # w370_f595_redfirst is the open-tree red-first: after closure it
            # must show 0 BREAK (0/5 tally). w370_f571f576's p0/p7 were
            # stale on the base (footer + F570-F582 open-neighbor list,
            # wave-305/306 debt from wave-370) -- fixed lane-locally by
            # this lane (footer repointed; the 11 closed-neighbor shapes
            # flipped to held), so the green check stays strict.
            # w372_f598's footer is repointed lane-locally. Tolerate only
            # a sole footer BREAK in batteries this lane did not repair.
            footer_only = ("test_b0_footer_state: BREAK" in out
                           and "BREAKS: ['test_b0_footer_state']" in out)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, tag, time.time() - t0,
                   " (footer-only tolerated)" if footer_only else ""))
            if r.returncode != 0 and not footer_only:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f595-filed", p1_f595_filed_shapes),
    ("p2-f595-variants", p2_f595_variants),
    ("p3-f595-bounds", p3_f595_bounds),
    ("p4-compositions", p4_compositions),
    ("p5-node-differential", p5_node_differential),
    ("p6-pin-footer", p6_pin_footer),
    ("p7-perf-bound", p7_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.skip_green:
        os.environ["GOV_SKIP_GREEN"] = "1"
    breaks, held, names = 0, 0, []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-22s %s (%s)" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        else:
            breaks += 1
            names.append(name)
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    green_ok = green_check()
    print("green checks: %s" % ("GREEN" if green_ok else "NOT GREEN"))
    if names:
        print("BREAKS: %r" % (names,))
    rc = 0 if (breaks == 0 and green_ok) else 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
