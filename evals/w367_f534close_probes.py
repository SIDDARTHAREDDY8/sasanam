#!/usr/bin/env python3
"""Wave-367 F534 closure battery (lane 3).

One LOW finding from wave-366 attack round 34 (node v24.20.0 ->
credential, decoder missed on the wave-366-merged base):

F534: Reflect.apply with a .bind-bound SLICE target.
  F530 models Reflect.apply with .bind-bound JOIN targets
  ([].join.bind(BINDTHIS, SEP)), but the bound function can be any
  builtin -- `[].slice.bind(['f1','f2'], 0, 2)` is a bound SLICE
  target: Reflect.apply invokes it, the result array is postfix-joined
  to the credential. F530's closure documents "bound non-join
  builtins" as fail-closed (F500/F505 precedent: different builtins
  are separate findings):
    Reflect.apply([].slice.bind(['f1','f2'], 0, 2), null, []).join('')
    Reflect.apply.call(Reflect, [].slice.bind(['f1','f2'], 0, 2), null, []).join('')
  Both node-evaluate to the exact credential. Distinct from F530
  (join -- F521's closure documents concat-family scope only) and
  F521 (concat).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f534_bound_slice_target` parses `[].slice.bind` /
    `Array.prototype.slice.bind` (node-identical: [].slice ===
    Array.prototype.slice) with a literal-array BINDTHIS (the F506
    thisArg classes) and exactly TWO non-negative integer-literal
    bound args (decimal or 0x; the _js_parse_number grammar admits
    no sign, so `-` never parses). Node-exact clamp: min(bound,
    len) per index, start > end yields [] (v24.20.0). The `.bind`
    member accepts the dot, F490 `?.`, and F482 bracket-string forms
    (node-identical, F530 precedent). Unlike F530's join target
    (which yields a string), slice yields an array, so the value is
    a _JSArr and the caller's postfix chain applies (.join('')
    assembles the credential).
  * `_js_parse_f534_bound_slice_triple` parses the `BOUND, thisArg,
    argsList` triple (thisArg parsed-and-discarded per the F483
    precedent; argsList string-literal-only and discarded -- the
    engine ignores post-bound slice args, node v24.20.0 verified).
  * `_js_parse_reflect_apply_bound_slice` is the direct-call
    parser, routed from `_js_parse_reflect_call` via the new
    "boundslice" peek in `_js_peek_reflect_apply_target` (both
    receiver classes, bind-lookahead only). F513
    (`Reflect.apply.bind(Reflect)(...)`) and F521
    (`Reflect.apply.call(Reflect, ...)`) gain F534 fallbacks nested
    after the F530 fallback; the F530 raise commits nothing on slice
    input (it rejects at the non-join member check before any value
    parse), so the fallback is clean.

Fail closed (documented, never mis-decoded): negative literals (the
engine counts negative indices from the end -- direction never
re-implemented), zero/extra bound args, non-literal or decimal-point
start/end fail closed (documented -- the decoder never guesses the
bounds), non-array BINDTHIS, non-string elements, `.bind` on
non-slice builtins (F521/F530 scopes).

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

TAXONOMY_PIN = 2140  # Wave-367 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f534_filed_shapes():
    shapes = [
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply.call(Reflect, [].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F534 filed shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_slice_variants():
    shapes = [
        # bind-indirect dispatch (F513 fallback path)
        "Reflect.apply.bind(Reflect)([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array.prototype.slice receiver (F469 class, node-identical)
        "Reflect.apply(Array.prototype.slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # node-exact clamp: end > len takes the whole array
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 10), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # 0x integer literals (node-valid; _js_parse_number grammar)
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0x0, 0x2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # whitespace tolerance
        "Reflect.apply( [].slice.bind( ['%(A1)s','%(A2)s'] , 0 , 2 ) , null , [] ).join('')"
        % {"A1": _A1, "A2": _A2},
        # F490 ?.bind (provably non-null)
        "Reflect.apply([].slice?.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # F482 bracket-string .bind form (engine-identical)
        "Reflect.apply([].slice['bind'](['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # Array-constructor BINDTHIS (F506 thisArg class)
        "Reflect.apply([].slice.bind(Array('%(A1)s','%(A2)s'), 0, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # three-element BINDTHIS, sub-range
        "Reflect.apply([].slice.bind(['zz','%(A1)s','%(A2)s'], 1, 3), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d slice variants block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------- P2: fail-closed bounds
def p2_slice_bounds():
    # All of these must NOT flag: fail closed, honest misses.
    shapes = [
        # negative index: engine counts from the end (direction never
        # re-implemented); node yields only A2 here (not the full
        # credential), and the decoder misses honestly
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], -1, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # zero bound args (start/end via argsList -- scope boundary)
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s']), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # extra bound args (engine ignores; decoder refuses to guess)
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2, 9), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-literal start
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], x, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # decimal start (not an integer literal)
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 1.5, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # non-array BINDTHIS
        "Reflect.apply([].slice.bind('str', 0, 2), null, []).join('')",
        # non-string element in BINDTHIS
        "Reflect.apply([].slice.bind(['%(A1)s', 1], 0, 2), null, []).join('')"
        % {"A1": _A1},
        # start > end yields [] in node -- not the credential
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 2, 0), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # sub-range that only yields A2 -- not the full credential
        "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 1, 2), null, []).join('')"
        % {"A1": _A1, "A2": _A2},
        # junk stays quiet
        "Reflect.apply([].slice.bind(['ab','cd'], 0, 2), null, []).join('')",
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d fail-closed bounds hold" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------- P3: compositions
def p3_compositions():
    pairs = [
        # F530 (bound join) CLOSED wave-366 lane 2 -- independent
        ("Reflect.apply([].join.bind(['%(A1)s','%(A2)s'], ''), null, [])"
         % {"A1": _A1, "A2": _A2}, True),
        # F521 (single-bind concat) CLOSED -- independent
        ("Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F526 (two-hop bind) CLOSED wave-366 lane 1 -- independent
        ("Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # direct-slice control still blocks (F534 finding's control)
        ("['%(A1)s','%(A2)s'].slice(0,2).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F531 (spread bound args) CLOSED wave-367 lane 1 -- merge update
        ("Reflect.apply([].concat.bind([], ...['%(A1)s']), null, ['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F533 (for-of alias enumeration) CLOSED wave-367 lane 2 -- merge update
        ("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%(A1)s','%(A2)s')"
         % {"A1": _A1, "A2": _A2}, True),
        # F535 (literal member access) CLOSED wave-367 lane 4 -- merge update
        ("({c:'%(A1)s'}).c+'%(A2)s'"
         % {"A1": _A1, "A2": _A2}, True),
        # F536 (structuredClone) CLOSED wave-367 lane 4 -- merge update
        ("structuredClone({c:'%(A1)s'}).c+'%(A2)s'"
         % {"A1": _A1, "A2": _A2}, True),
        # F513 bind-indirection (bind on the dispatch) still blocks
        ("Reflect.apply.bind(Reflect)(Array.prototype.concat, [], [['%(A1)s'],['%(A2)s']]).join('')"
         % {"A1": _A1, "A2": _A2}, True),
    ]
    bad = [s for s, want in pairs if _verdict(s, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition probes agree" % (len(pairs) - len(bad), len(pairs)))


# ------------------------------------------------- P4: node differential
_NODE_EXPRS = [
    # (js inner-expr template, node result equals credential?)
    ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')", True),
    ("Reflect.apply.call(Reflect, [].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')", True),
    ("Reflect.apply.bind(Reflect)([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')", True),
    ("Reflect.apply(Array.prototype.slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')", True),
    ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 10), null, []).join('')", True),
    ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0x0, 0x2), null, []).join('')", True),
    ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 1, 2), null, []).join('')", False),
    ("Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 2, 0), null, []).join('')", False),
    ("Reflect.apply([].slice.bind(['ab','cd'], 0, 2), null, []).join('')", False),
]


def p4_node_differential():
    mismatches = []
    for template, node_has_cred in _NODE_EXPRS:
        js = template % {"A1": _A1, "A2": _A2}
        try:
            r = subprocess.run(["node", "-e", "console.log(JSON.stringify(%s))" % js],
                               capture_output=True, text=True, timeout=30)
            node_val = json.loads(r.stdout.strip())
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "node failed on %s: %r" % (js[:60], e))
        node_cred = (node_val == _CRED)
        if node_cred != node_has_cred:
            return ("ERROR",
                    "node disagrees with expected on %s: node=%r" % (js[:60], node_val))
        decoder_blocks = _blocked(js)
        if decoder_blocks != node_cred:
            mismatches.append(js[:72])
    if mismatches:
        return ("BREAK", "%d decoder/node mismatches: %s"
                % (len(mismatches), "; ".join(mismatches)))
    return ("HELD", "%d/%d decoder agrees with node v24.20.0"
            % (len(_NODE_EXPRS), len(_NODE_EXPRS)))


# ------------------------------------------------------- P5: pin + footer
def p5_pin_and_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F597**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and "**Open findings: F582, F583, F584, F585, F586, F587, F588, F589, F590, F591, F592, F593, F594, F595, F596.**" in text)  # wave-368 merge lanes 1-4: F543/F545/F546 CLOSED  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ----------------------------------------------------------- P6: perf
def p6_perf_bound():
    # Hostile input: many bound-slice-shaped anchors -- must starve fast.
    junk = "Reflect.apply([].slice.bind(['ab','cd'], 0, 2), null, []).join('')" * 2000
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2000-anchor bound-slice corpus: hit=%s %.2fs" % (hit is not None, dt))


PROBES = [
    ("p1-f534-filed-shapes", p1_f534_filed_shapes),
    ("p1-slice-variants", p1_slice_variants),
    ("p2-slice-bounds", p2_slice_bounds),
    ("p3-compositions", p3_compositions),
    ("p4-node-differential", p4_node_differential),
    ("p5-pin-and-footer", p5_pin_and_footer),
    ("p6-perf-bound", p6_perf_bound),
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
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w366_f534_redfirst.py",
               "w366_attack_probes.py",
               "w366_f527f530close_probes.py",
               "w365_f521close_probes.py")
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
    print("w367_f534close: starting %d probes" % len(PROBES))
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
