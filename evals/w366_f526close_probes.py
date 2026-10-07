#!/usr/bin/env python3
"""Wave-366 F526 closure battery (lane 1).

One LOW finding from wave-365 attack round 33 (node v24.20.0 ->
credential, decoder missed on the wave-365-merged base):

F526: Reflect.apply with a two-hop .bind-chained function target.
  F521 models Reflect.apply with a single-.bind-bound target
  ([].concat.bind([], 'f1')), and F513 models .bind indirection on
  the dispatch -- but a target produced by a CHAIN of two .bind
  calls is a new target-production mechanism: the bound thisArg and
  the pre-bound args accumulate across hops:
    Reflect.apply([].concat.bind([],'f1').bind([]), null, ['f2']).join('')
    Reflect.apply([].concat.bind([],'f1').bind([],'f2'), null, []).join('')
    Reflect.apply.call(Reflect, [].concat.bind([],'f1').bind([]), [], ['f2']).join('')
  All three node-evaluate to the exact credential. Distinct from F521
  (single bind -- the wave-365 lane 1 brief fails closed on chains
  beyond one hop) and F513 (bind on the dispatch, not the target).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f521_bound_target` parses an optional exactly-one
    additional `.bind` hop after the first hop's closing paren (the
    member accepts the same dot / F490 `?.` / F482 bracket-string
    forms via _js_peek_dispatch_call). Node-exact (v24.20.0): the
    FIRST hop's BINDTHIS wins -- B2's [[BoundThis]] is discarded when
    the call reaches B1, itself a bound function that ignores its
    receiver (the wave-365 lane 1 brief's "final bind wins" guess was
    wrong per spec; verified in node); args accumulate
    hop1-then-hop2-then-call, so the desugar is
    BINDTHIS1.concat(...ARGS1, ...ARGS2, ...ARGSLIST). Hop2's
    BINDTHIS is parsed with the same bounded array grammar (fail
    closed) and its value discarded. A third `.bind` hop fails closed
    structurally (the triple caller expects `,` after the bound
    target). The F521 docstring's deeper-chain residual is narrowed
    accordingly, and its stale "bound join filed as F526" note is
    corrected to F530 (the wave-365 merge renumber).
  * All three dispatch sites (direct / Reflect.apply.call /
    Reflect.apply.bind fallback) inherit the two-hop target via
    `_js_parse_f521_bound_triple`; no dispatch-site changes.

Fail closed (documented, never mis-decoded): 3+ hops, non-literal
bound args at any hop, non-array hop2 BINDTHIS, numeric/template
bound args, `.bind` on non-concat targets (F530's bound-join scope).

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2135  # Wave-366 lane 1; pin stays 2135


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f526_filed_shapes():
    shapes = [
        "Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply([].concat.bind([],'%(A1)s').bind([],'%(A2)s'), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, [].concat.bind([],'%(A1)s').bind([]), [], ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F526 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_two_hop_variants():
    shapes = [
        # bind-indirect dispatch with two-hop target (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].concat.bind([],'%(A1)s').bind([]), [], ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.concat receiver (F469 class, node-identical)
        "Reflect.apply(Array.prototype.concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # whitespace tolerance around the second hop
        "Reflect.apply( [].concat.bind([], '%(A1)s') .bind([]) , null , ['%(A2)s'] ).join('')"
        % {"A1": _A1, "A2": _A2},
        # F490 ?.bind as the second hop (provably non-null)
        "Reflect.apply([].concat.bind([],'%(A1)s')?.bind([]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # BINDTHIS1 with elements (prepended, node-exact)
        "Reflect.apply([].concat.bind(['x'],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array-constructor BINDTHIS2 (F506 thisArg class, discarded)
        "Reflect.apply([].concat.bind([],'%(A1)s').bind(Array('%(A1)s')), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # first hop's BINDTHIS wins over hop2's (node-exact; hop2 discarded)
        "Reflect.apply([].concat.bind([],'%(A1)s').bind(['zz']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d two-hop variants block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------- P2: fail-closed bounds
def p2_two_hop_bounds():
    # All of these must NOT flag: fail closed, honest misses.
    shapes = [
        # three-hop chain (documented residual)
        "Reflect.apply([].concat.bind([],'%(A1)s').bind([]).bind([]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal bound arg at hop2
        "Reflect.apply([].concat.bind([],'%(A1)s').bind([], 1), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-array BINDTHIS2
        "Reflect.apply([].concat.bind([],'%(A1)s').bind('str'), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # numeric bound arg at hop1
        "Reflect.apply([].concat.bind([], 1).bind([]), null, ['%(A1)s','%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # bound JOIN target is F530's scope, not F526's
        "Reflect.apply([].join.bind(['%(A1)s','%(A2)s'], ''), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # junk stays quiet
        "Reflect.apply([].concat.bind([],'ab').bind([]), null, ['cd']).join('')",
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d fail-closed bounds hold" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------- P3: compositions
def p3_compositions():
    pairs = [
        # F521 single-bind still blocks (independence)
        ("Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F519 literal function target still blocks (filed shape, no .join)
        ("Reflect.apply((a,b)=>a+b, null, ['%(A1)s','%(A2)s'])"
         % {"A1": _A1, "A2": _A2}, True),
        # F513 bind-indirection (bind on the dispatch) still blocks
        ("Reflect.apply.bind(Reflect)(Array.prototype.concat, [], [['%(A1)s'],['%(A2)s']]).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F506 Function.prototype.call indirection still blocks
        ("Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%(A1)s','%(A2)s']]).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F530 (bound join) CLOSED wave-366 lane 2
        ("Reflect.apply([].join.bind(['%(A1)s','%(A2)s'], ''), null, [])"
         % {"A1": _A1, "A2": _A2}, True),
        # F527 (quadruple-nested) CLOSED wave-366 lane 2
        ("'%(A1)s'[[[[['concat'][0]]][0]][0]]('%(A2)s')"
         % {"A1": _A1, "A2": _A2}, True),
        # F528 (complex IIFE target) CLOSED wave-366 lane 3 (nested IIFE filed shape;
        # no .join: Reflect.apply returns the string directly)
        ("Reflect.apply((() => ((() => (a,b)=>a+b))())(), [], ['%(A1)s','%(A2)s'])"
         % {"A1": _A1, "A2": _A2}, True),
        # F529 (alias enumerated) CLOSED wave-366 lane 3
        ("(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%(A1)s','%(A2)s')"
         % {"A1": _A1, "A2": _A2}, True),
        # F522 (IIFE target) CLOSED and unaffected by this diff; the
        # .join('') variant is a node TypeError (no credential exists),
        # so it misses honestly (wave-365 lane-2 closure edge)
        ("Reflect.apply((() => (a,b)=>a+b)(), [], ['%(A1)s','%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, False),
    ]
    bad = [s for s, want in pairs if _verdict(s, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition probes agree" % (len(pairs) - len(bad), len(pairs)))


# ------------------------------------------------------- P4: pin + footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2135, "pin moved"
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2135, \
        "guac_graph.TAXONOMY_PIN=%r want 2135" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    # Wave-367 merge repoint: F531/F533/F534 CLOSED (lanes 1-3); open F535, F536.
    ok = ("Next free finding: **F537**" in text
          and "**Open findings: F535, F536.**" in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


PROBES = [
    ("p1-f526-filed-shapes", p1_f526_filed_shapes),
    ("p1-two-hop-variants", p1_two_hop_variants),
    ("p2-two-hop-bounds", p2_two_hop_bounds),
    ("p3-compositions", p3_compositions),
    ("p4-pin-and-footer", p4_pin_and_footer),
]


def _safe(pid, fn):
    try:
        return fn()
    except AssertionError as e:
        return ("BREAK", "assert: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%r" % (e,))


def _green_check():
    """Depth-1 green check: adjacent batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/.gov-venv/bin/python")
    if not os.path.exists(venv_python):
        venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w365_f526_redfirst.py",
               "w365_attack_probes.py",
               "w364_f513f519close_probes.py",
               "w365_f521close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g366-green-%s-%d" % (script.replace(".py", ""),
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
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w366_f526close: starting %d probes" % len(PROBES))
    results = []
    for pid, fn in PROBES:
        v, note = _safe(pid, fn)
        print("%s: %s (%s)" % (pid, v, note))
        results.append((pid, v, note))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if n_break or n_err:
        print("green check: skipped (red)")
        return 1
    gc = _green_check()
    print("green check: %s" % gc)
    if gc.startswith("green check FAILED"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
