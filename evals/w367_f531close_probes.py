#!/usr/bin/env python3
"""Wave-367 F531 closure battery (lane 1).

One LOW finding from wave-366 attack round 34 (node v24.20.0 ->
credential, decoder missed on the wave-366-merged base):

F531: Reflect.apply with a SPREAD bound arg. F521 models
  Reflect.apply with .bind-bound concat targets where the bound args
  are string literals ([].concat.bind([], 'f1')) -- but a bound arg
  written as a SPREAD of a literal array ([].concat.bind([], ...['f1']))
  is node-identical to the literal form while escaping the F521
  literal-arg grammar:
    Reflect.apply([].concat.bind([], ...['f1']), null, ['f2']).join('')
    Reflect.apply.call(Reflect, [].concat.bind([], ...['f1']), null, ['f2']).join('')
  Both node-evaluate to the exact credential. Distinct from F521
  (literal bound args -- F521's fail-closed list covers
  numeric/template/additive bound args but not spread).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * New `_js_parse_f531_spread_bound_args` parses `...['lit', ...]`
    as the bound-arg list inside `_js_parse_f521_bound_target`'s
    first-hop arg position: the spread array is parsed with the same
    bounded string-literal-only grammar (`_js_parse_string_literal_list`;
    parts-budget charged per element, the spread itself charges one
    extra part), and the desugar is exactly the spread elements (empty
    spread == no bound args -- node-exact, v24.20.0 verified). The
    spread must be the SOLE and FINAL bound arg (a literal arg list
    never mixes with a spread at either hop): multiple spreads,
    mid-list spreads, and literal+spread combinations fail closed
    (documented -- node accepts them, the lane rejects rather than
    mis-decodes). Non-literal spread sources (`...x`, `...[...1]`)
    fail closed; the array itself is never evaluated.
  * The F526 second hop is untouched: a spread at hop two fails
    closed as today (scope boundary); a hop-one spread followed by
    a literal hop two (F526 x F531 composition) models via the
    existing hop-two path (node-exact: args accumulate
    hop1-then-hop2-then-call; hop2's BINDTHIS is parsed and discarded).
  * All three dispatch sites (direct / Reflect.apply.call /
    Reflect.apply.bind fallback) inherit via
    `_js_parse_f521_bound_triple`; no dispatch-site changes.

Fail closed (documented, never mis-decoded): mid-list spreads,
multiple spreads, literal+spread mixes, non-literal spread sources
(`...x`, `...['f1', 1]`, `...{'0':'f1'}`), spread as BINDTHIS,
3+ `.bind` hops after a spread (F526 residual), `.bind` on
non-concat targets (F530's bound-join scope is untouched).

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

TAXONOMY_PIN = 2140  # Wave-367 lane 1; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f531_filed_shapes():
    shapes = [
        "Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, [].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F531 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_spread_variants():
    shapes = [
        # bind-indirect dispatch with spread target (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].concat.bind([], ...['%(A1)s']), [], ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.concat receiver (F469 class, node-identical)
        "Reflect.apply(Array.prototype.concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # whitespace tolerance inside the spread array
        "Reflect.apply( [].concat.bind( [], ...[ '%(A1)s' ] ) , null , ['%(A2)s'] ).join('')"
        % {"A1": _A1, "A2": _A2},
        # empty spread == no bound args (node-exact)
        "Reflect.apply([].concat.bind([], ...[]), null, ['%(A1)s','%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # multi-element spread array
        "Reflect.apply([].concat.bind([], ...['%(A1)s','%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # BINDTHIS with elements (prepended, node-exact)
        "Reflect.apply([].concat.bind(['x'], ...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # F526 x F531: spread at hop one, literal hop two (args accumulate)
        "Reflect.apply([].concat.bind([], ...['%(A1)s']).bind([], '%(A2)s'), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d spread variants block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------- P2: fail-closed bounds
def p2_spread_bounds():
    # All of these must NOT flag: fail closed, honest misses.
    shapes = [
        # spread mid-list (node accepts; lane rejects)
        "Reflect.apply([].concat.bind([], ...['%(A1)s'], '%(A2)s'), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # literal arg then spread (node accepts; lane rejects)
        "Reflect.apply([].concat.bind([], 'x', ...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # two spreads (node accepts; lane rejects)
        "Reflect.apply([].concat.bind([], ...['%(A1)s'], ...['%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal spread source
        "Reflect.apply([].concat.bind([], ...x), null, ['%(A1)s','%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal spread element (numeric)
        "Reflect.apply([].concat.bind([], ...['%(A1)s', 1]), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # spread of an object, not an array
        "Reflect.apply([].concat.bind([], ...{'0':'%(A1)s'}), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # spread as BINDTHIS (thisArg would be 'f1'; fail closed)
        "Reflect.apply([].concat.bind(...['%(A1)s']), null, ['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        # spread at hop two (F526 residual -- today fails closed)
        "Reflect.apply([].concat.bind([], '%(A1)s').bind([], ...['%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # junk stays quiet
        "Reflect.apply([].concat.bind([], ...['ab']), null, ['cd']).join('')",
        # empty spread with junk argsList stays quiet
        "Reflect.apply([].concat.bind([], ...[]), null, ['ab','cd']).join('')",
        # honest prose walking the new spread path with non-credential
        # literals stays quiet
        "The ...['f1'] spread in [].concat.bind([], ...['f1']) is documented",
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d fail-closed bounds hold" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------- P3: compositions
def p3_compositions():
    pairs = [
        # F521 single-bind literal still blocks (independence)
        ("Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F526 two-hop literal still blocks (independence)
        ("Reflect.apply([].concat.bind([], '%(A1)s').bind([]), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F530 (bound join) CLOSED wave-366 -- untouched by this diff
        ("Reflect.apply([].join.bind(['%(A1)s','%(A2)s'], ''), null, [])"
         % {"A1": _A1, "A2": _A2}, True),
        # F532 (quad bracket on array receivers) CLOSED at wave-366 merge
        ("['%(A1)s'][[[[['concat'][0]]][0]][0]]('%(A2)s').join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F534 (bound slice) CLOSED wave-367 lane 3 -- merge update
        ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F519xF533 composition: for-of over arguments-alias inside a function-valued
        # Reflect.apply target -- filed as F546 at the wave-367 merge, CLOSED
        # wave-368 lane 4. Must now BLOCK.
        ("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;}, null, ['%(A1)s','%(A2)s'])"
         % {"A1": _A1, "A2": _A2}, True),
    ]
    bad = [s for s, want in pairs if _verdict(s, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition probes agree" % (len(pairs) - len(bad), len(pairs)))


# ------------------------------------------------------- P4: pin + footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F612**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612
          and "**Open findings: F606, F607, F608, F609, F610, F611.**" in text)  # wave-368 merge lanes 1-4: F543/F545/F546 CLOSED  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


PROBES = [
    ("p1-f531-filed-shapes", p1_f531_filed_shapes),
    ("p1-spread-variants", p1_spread_variants),
    ("p2-spread-bounds", p2_spread_bounds),
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
    scripts = ("w366_f531_redfirst.py",
               "w366_f526close_probes.py",
               "w366_f527f530close_probes.py",
               "w365_attack_probes.py",
               "w366_attack_probes.py")
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
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w367_f531close: starting %d probes" % len(PROBES))
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
