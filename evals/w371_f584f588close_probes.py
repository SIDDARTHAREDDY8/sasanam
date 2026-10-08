#!/usr/bin/env python3
"""Close battery for F584, F588 (params/reflect family).

F584 (URLSearchParams.getAll multi-value reads): F576 closed `.get()`
on statically-resolved URLSearchParams (first match, engine-exact),
but `.getAll(name)` returns the value ARRAY -- a different method the
decoder did not model: `new URLSearchParams('q=f1&q=f2').getAll('q')`
node-evaluates to ['f1','f2'] (node v24.20.0) while the decoder
produced zero variants. Closed (wave-371 lane 2): the `_JSURLParams`
postfix branch now accepts `getAll` alongside `get`; getAll collects
ALL values for the name in insertion order into a `_JSArr`
(node-exact, including the missing-name `[]` case and
percent-decoded names/values via the F576 parse_qsl differential).
Boundaries: non-literal keys, extra args, and non-params receivers
fail closed; `.get`'s missing-name-fails-closed behavior is
unchanged (engine returns null there, a real array here).

F588 (Reflect.get with Symbol.for keys, F540 x F552 composition):
F540 closed Reflect.get on literals with string-literal keys and F552
closed Symbol.for member reads, but their composition missed:
`Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for('c'))` node-evaluates
to 'f1' (v24.20.0) while the decoder produced zero variants. Closed
(wave-371 lane 2): `_js_parse_f540_reflect_get_object` now accepts a
`Symbol.for('K')` key expression (no-bracket form, shared parser with
F552's bracket form) and looks it up via `_js_symbol_key` in the
F535 props (separate symbol namespace, node-exact). Boundaries: bare
`Symbol()`, non-literal registry keys, unregistered symbols, and
string-key/symbol-key mixing all fail closed (F552 precedent); extra
args still fail closed (F540 precedent); `Reflect.get([],'concat')`
residual still fail-closed.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
Zero paid API calls: this battery shells only to adjacent in-repo
batteries (green check). $0 spend by construction.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"


def _hit(payload):
    return find_credential(payload) is not None


FILED = [
    # F584: URLSearchParams.getAll multi-value reads
    ("f584-getall",
     "new URLSearchParams('q=%(A1)s&q=%(A2)s').getAll('q').join('')"
     % {"A1": _A1, "A2": _A2}),
    ("f584-getall-slice",
     "new URLSearchParams('q=%(A1)s&q=%(A2)s&q=zz')"
     ".getAll('q').slice(0,2).join('')"
     % {"A1": _A1, "A2": _A2}),
    # F588: Reflect.get with Symbol.for keys
    ("f588-reflectget-sym",
     "Reflect.get({[Symbol.for('c')]:'%(A1)s'},Symbol.for('c'))+'%(A2)s'"
     % {"A1": _A1, "A2": _A2}),
    ("f588-reflectget-sym-nest",
     "Reflect.get({[Symbol.for('k')]:{c:'%(A1)s'}},Symbol.for('k')).c"
     "+'%(A2)s'" % {"A1": _A1, "A2": _A2}),
]

VARIANTS = [
    # F584: dispatch/member variants
    ("f584-bracket-member",
     "new URLSearchParams('q=%(A1)s&q=%(A2)s')['getAll']('q').join('')"
     % {"A1": _A1, "A2": _A2}),
    ("f584-ws",
     "new URLSearchParams('q=%(A1)s&q=%(A2)s').getAll( 'q' ).join('')"
     % {"A1": _A1, "A2": _A2}),
    ("f584-dquote",
     'new URLSearchParams("q=%(A1)s&q=%(A2)s").getAll("q").join("")'
     % {"A1": _A1, "A2": _A2}),
    # F584: percent-encoded values decode node-exactly (the interesting
    # evasion: encoding at the URL layer). Verified against node.
    ("f584-encoded",
     "new URLSearchParams('q=%78%6f%78%62-%30%31%32%33"
     "&q=%34%35%36%37%38%39%61%62%63%64%65%66')"
     ".getAll('q').join('')"),
    # F584: repeated name, first/second/third values all present
    ("f584-three-values",
     "new URLSearchParams('q=%(A1)s&q=&q=%(A2)s')"
     ".getAll('q').join('')"
     % {"A1": _A1, "A2": _A2}),
    # F588: key-expression variants
    ("f588-reflectget-bracket-member",
     "Reflect['get']({[Symbol.for('c')]:'%(A1)s'},Symbol.for('c'))+'%(A2)s'"
     % {"A1": _A1, "A2": _A2}),
    ("f588-dquote",
     'Reflect.get({[Symbol.for("c")]:"%(A1)s"},Symbol.for("c"))+"%(A2)s"'
     % {"A1": _A1, "A2": _A2}),
    ("f588-ws",
     "Reflect.get( { [ Symbol.for( 'c' ) ] : '%(A1)s' } , "
     "Symbol.for( 'c' ) ) + '%(A2)s'" % {"A1": _A1, "A2": _A2}),
    ("f588-nest-deeper",
     "Reflect.get({[Symbol.for('k')]:{c:'%(A1)s'}},Symbol.for('k'))"
     ".c+'%(A2)s'" % {"A1": _A1, "A2": _A2}),
]

BOUNDARIES = [
    # documented fail-closed: the decoder must stay quiet on these
    # (junk payloads -- no credential anywhere, so any variant or
    # crash is a leak; the house convention from w370_f571f576close).
    # F584: non-literal key
    ("f584-nonliteral-key",
     "new URLSearchParams('q=aa&q=bb').getAll(q).join('')"),
    # F584: extra args fail closed (engine ignores them; the decoder
    # stays conservative like the .get branch)
    ("f584-extra-arg",
     "new URLSearchParams('q=aa&q=bb').getAll('q','x').join('')"),
    # F584: unmodeled member on params
    ("f584-has-member",
     "new URLSearchParams('q=aa&q=bb').has('q')"),
    # F584: getAll on a non-params receiver
    ("f584-getall-on-string",
     "'q=aa'.getAll('q')"),
    # F584: missing close paren
    ("f584-unterminated",
     "new URLSearchParams('q=aa').getAll('q'"),
    # F576 boundary preserved: .get with a missing name still fails
    # closed (engine returns null)
    ("f576-get-missing-still-closed",
     "new URLSearchParams('q=aa').get('zz')"),
    # F588: bare Symbol() is unique per call -- never resolvable
    ("f588-bare-symbol",
     "Reflect.get({[Symbol('c')]:'aa'},Symbol('c'))"),
    # F588: unregistered symbol read misses (separate namespace)
    ("f588-unregistered-symbol",
     "Reflect.get({[Symbol.for('c')]:'aa'},Symbol.for('zz'))"),
    # F588: non-literal registry key
    ("f588-nonliteral-key",
     "Reflect.get({[Symbol.for('c')]:'aa'},Symbol.for(k))"),
    # F588: string key / symbol key namespaces do not mix (node-exact)
    ("f588-string-key-symbol-read",
     "Reflect.get({c:'aa'},Symbol.for('c'))"),
    ("f588-symbol-key-string-read",
     "Reflect.get({[Symbol.for('c')]:'aa'},'c')"),
    # F588: extra args still fail closed (F540 precedent)
    ("f588-extra-arg",
     "Reflect.get({[Symbol.for('c')]:'aa'},Symbol.for('c'),'x')"),
    # F588: non-object target
    ("f588-nonobject-target",
     "Reflect.get('aa',Symbol.for('c'))"),
    # F540 documented residual: method-retrieval shape stays closed
    ("f540-method-residual-still-closed",
     "Reflect.get([],'concat')"),
    # honest text stays quiet
    ("honest-text-quiet",
     "the quarterly report was reviewed by the compliance team"),
]


def p1_filed_shapes_held():
    bad = [n for n, p in FILED if not _hit(p)]
    return ("HELD", "%d/%d filed shapes held" % (len(FILED) - len(bad),
                                                len(FILED))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p2_variants_held():
    bad = [n for n, p in VARIANTS if not _hit(p)]
    return ("HELD", "%d/%d variants held" % (len(VARIANTS) - len(bad),
                                            len(VARIANTS))) \
        if not bad else ("BREAK", "missed: %s" % bad)


def p3_fail_closed_boundaries():
    bad = [n for n, p in BOUNDARIES if _hit(p)]
    return ("HELD", "%d/%d boundaries fail closed"
            % (len(BOUNDARIES) - len(bad), len(BOUNDARIES))) \
        if not bad else ("BREAK", "leaked: %s" % bad)


def p4_node_differential():
    # Node-exact expectations established on node v24.20.0.
    pairs = [
        # (decoder input template, node-evaluated expected decode)
        ("new URLSearchParams('q=f1&q=f2').getAll('q').join('')", "f1f2"),
        # insertion order is significant (node-exact)
        ("new URLSearchParams('q=f2&q=f1').getAll('q').join('')", "f2f1"),
        ("new URLSearchParams('q=f1&q=f2&q=zz').getAll('q')"
         ".slice(0,2).join('')", "f1f2"),
        ("new URLSearchParams('q=f1&q=zz&q=f2').getAll('q').join('|')",
         "f1|zz|f2"),
        ("new URLSearchParams('q=%66%31&q=f2').getAll('q').join('')",
         "f1f2"),
        ("new URLSearchParams('q=ab').getAll('zz').join('')", ""),
        ("new URLSearchParams('q=f1')['getAll']('q').join('')", "f1"),
        # F461: unmodeled step on a non-params receiver ends the chain
        # with the value unchanged (no new information decoded, so no
        # laundering -- pre-existing principle, not an F584 behavior)
        ("'q=f1'.getAll('q')", "q=f1"),
        ("Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for('c'))", "f1"),
        ("Reflect.get({[Symbol.for('k')]:{c:'f1'}},Symbol.for('k')).c",
         "f1"),
        ('Reflect["get"]({[Symbol.for("c")]:"f1"},Symbol.for("c"))', "f1"),
    ]
    # Boundary inputs that must fail closed at the seam: the decoder
    # must RAISE (never a wrong value). Node-exactness of the raise
    # was established per case (engine returns null/undefined or the
    # shape is unresolvable statically).
    must_raise = [
        "new URLSearchParams('q=f1').getAll(q)",          # non-literal key
        "new URLSearchParams('q=f1').getAll('q','x')",    # extra arg
        "new URLSearchParams('q=f1').has('q')",           # unmodeled member
        "new URLSearchParams('q=f1').getAll('q'",         # unterminated
        "new URLSearchParams('q=f1').get('zz')",          # F576 missing
        "Reflect.get({[Symbol('c')]:'f1'},Symbol('c'))",  # bare Symbol()
        "Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for('zz'))",  # unreg
        "Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for(k))",  # non-lit
        "Reflect.get({c:'f1'},Symbol.for('c'))",          # ns mixing
        "Reflect.get({[Symbol.for('c')]:'f1'},'c')",      # ns mixing
        "Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for('c'),'x')",  # args
        "Reflect.get('str',Symbol.for('c'))",             # non-obj target
        "Reflect.get([],'concat')",                      # F540 residual
    ]
    import gov.dlp as dlp
    bad = []
    for payload, want in pairs:
        st = {"parts": 0, "ops": 0}
        try:
            val, _ = dlp._js_parse_primary(payload, 0, 0, st)
        except Exception as e:  # noqa: BLE001
            bad.append((payload[:40], "raise %s" % e))
            continue
        if val != want:
            bad.append((payload[:40], "%r != node %r" % (val, want)))
    for payload in must_raise:
        st = {"parts": 0, "ops": 0}
        try:
            val, _ = dlp._js_parse_primary(payload, 0, 0, st)
        except Exception:  # noqa: BLE001
            continue  # fail-closed: the raise IS the correct outcome
        bad.append((payload[:40], "decoded %r, want raise" % (val,)))
    total = len(pairs) + len(must_raise)
    return ("HELD", "%d/%d decoder==node" % (total - len(bad), total)) \
        if not bad else ("BREAK", "diffs: %s" % bad)


def p5_compositions():
    # Neighbor findings stay closed; honest anchors still decode.
    must_hit = [
        ("f576-get-still",
         "new URLSearchParams('q=%s').get('q')+'%s'" % (_A1, _A2)),
        ("f576-url-searchparams-still",
         "new URL('https://h/?q=%s').searchParams.get('q')+'%s'"
         % (_A1, _A2)),
        ("f540-string-key-still",
         "Reflect.get({c:'%s'},'c')+'%s'" % (_A1, _A2)),
        ("f540-nested-still",
         "Reflect.get({k:{c:'%s'}},'k').c+'%s'" % (_A1, _A2)),
        ("f552-bracket-read-still",
         "({[Symbol.for('c')]:'%s'})[Symbol.for('c')]+'%s'"
         % (_A1, _A2)),
        ("f552-getter-still",
         "({get [Symbol.for('c')](){return '%s';}})"
         "[Symbol.for('c')]+'%s'" % (_A1, _A2)),
    ]
    bad_hit = [n for n, p in must_hit if not _hit(p)]
    bad = bad_hit
    return ("HELD", "%d/%d neighbor compositions hold"
            % (len(must_hit) - len(bad), len(must_hit))) \
        if not bad else ("BREAK", "regressed: %s" % bad)


def p6_pin_and_footer():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = (text.count("CLOSED 2026-10-07 wave-371 lane 2") >= 2
                 and "Next free finding: **F662**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F655-F661 / next F662
                 and "Open findings: F655, F656, F657, F658, F659, F660, F661." in text)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F655-F661 / next F662
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return ("HELD", detail) if (pin_ok and footer_ok) \
        else ("BREAK", detail)


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w370_f584_redfirst.py",
               "w370_f588_redfirst.py",
               "w370_f571f576close_probes.py",
               "w369_f552f557f565close_probes.py",
               "w368_f539f540close_probes.py",
               "w370_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g371l2-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_filed_shapes_held, p2_variants_held,
              p3_fail_closed_boundaries, p4_node_differential,
              p5_compositions, p6_pin_and_footer]
    breaks, held, errors = 0, 0, 0
    for fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (fn.__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    gc = _green_check()
    print("green-check: %s" % gc)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
