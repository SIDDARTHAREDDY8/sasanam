#!/usr/bin/env python3
"""Wave-368 F541/F544 closure battery (lane 3).

Two LOW findings from wave-367 attack round 35 (node v24.20.0 ->
credential, decoder missed on the wave-367-merged base):

F541: JSON.parse laundering + member read. structuredClone (F536) is
  not the only deserializing builtin: JSON.parse builds an object
  graph from a string, and the decoder modeled neither the parse nor
  the subsequent member read:
    JSON.parse('{"x":["f1","f2"]}').x.join('')
    JSON.parse('{"a":{"x":["f1","f2"]}}').a.x.join('')
  Both node-evaluate to the exact credential. Distinct per the
  F500/F505 precedent (unmodeled builtin); distinct from F539
  (identity-preserving wrappers -- parse TRANSFORMS a string into a
  new object).

F544: spread in the Reflect.apply ARGS ARRAY. F519 models
  Reflect.apply with a literal args array and F531 models spread in
  the .bind ARGUMENTS, but a spread in the apply args array itself
  escapes the F519 literal-array grammar:
    Reflect.apply(function(a,b){return a+b;}, null, [...['f1','f2']])
    Reflect.apply.call(Reflect, function(a,b){return a+b;}, null, [...['f1','f2']])
  Both node-evaluate to the exact credential. Distinct from F519
  (literal args) and F531 (spread in bind args -- this is spread in
  the apply args array, a different position).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * F541: new `JSON.parse('LITERAL')` branch in `_js_parse_primary`
    (ident-boundary-checked `JSON`, ws-tolerant `.parse(`, single
    string-literal argument -- no reviver) plus `_js_f541_json_value`
    converting the stdlib json.loads result into the internal value
    graph: dict -> _JSObj (duplicate keys later-wins, engine-exact),
    list -> _JSArr, str -> str, canonical int -> str. The parse is
    deterministic and side-effect-free -- a value conversion, not
    evaluation. The F535 member-read model resolves the subsequent
    chain in _js_parse_postfix. Anchor extended: `JSON(?![...])`
    added to the existing _JS_EXPR_START (no new regex).
  * F544: new `_js_parse_f544_spread_apply_args` parses
    `...['lit', ...]` as the SOLE argsArray element (F531-precedent
    desugar), shared via `_js_parse_f519_apply_args_array` by the
    F519 direct path; `_js_parse_f521_call_dispatch` gains an
    F519-class fn-target fallback (additive body over declared
    params) so the call-indirect form desugars to the direct form.
    F546 arguments-enumerating bodies still fail the additive-body
    parse and stay fail-closed.

Fail closed (documented, never mis-decoded):
  F541: non-literal args, reviver args, invalid JSON, bool/null/float
    leaves, ints beyond 2**53-1, __proto__ keys, JSON['parse']
    bracket form, JSONx.
  F544: multiple spreads, mid-list spreads, literal+spread mixes,
    non-literal spread sources, nested spreads, arity mismatch.

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

TAXONOMY_PIN = 2143  # Wave-368 lane 3; pin stays 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:64], want_block, hit))


# ------------------------------------------------------------- P1: closure
def p1_f541_filed_shapes():
    shapes = [
        # filed flat shape
        'JSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # filed nested shape
        'JSON.parse(\'{"a":{"x":["%(A1)s","%(A2)s"]}}\').a.x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # bracket-string member read (F507 form, node-identical)
        'JSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\')["x"].join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # root-level array result joined directly
        'JSON.parse(\'["%(A1)s","%(A2)s"]\').join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # whitespace tolerance in the JSON branch (F455 class; the
        # postfix method loop keeps its pre-existing `.METHOD`
        # adjacency requirement)
        'JSON . parse ( \'{"x":["%(A1)s","%(A2)s"]}\' ).x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # double-quoted JS string arg (JSON text unchanged)
        'JSON.parse("{\\"x\\":[\\"%(A1)s\\",\\"%(A2)s\\"]}").x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # canonical int leaves join node-exactly (full token across leaves)
        'JSON.parse(\'{"x":[42,"%(A1)s","%(A2)s"]}\').x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
        # duplicate keys: later wins (engine-exact)
        'JSON.parse(\'{"x":"zz","x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F541 shapes block" % (len(shapes) - len(bad), len(shapes)))


def p1_f544_filed_shapes():
    shapes = [
        # filed direct shape
        "Reflect.apply(function(a,b){return a+b;}, null, [...['%(A1)s','%(A2)s']])"
        % {"A1": _A1, "A2": _A2},
        # filed call-indirect shape
        "Reflect.apply.call(Reflect, function(a,b){return a+b;}, null, [...['%(A1)s','%(A2)s']])"
        % {"A1": _A1, "A2": _A2},
        # arrow fn target with spread args
        "Reflect.apply((a,b)=>a+b, null, [...['%(A1)s','%(A2)s']])"
        % {"A1": _A1, "A2": _A2},
        # call-indirect with LITERAL args (previously a residual miss;
        # now desugars to the direct form, node-exact)
        "Reflect.apply.call(Reflect, function(a,b){return a+b;}, null, ['%(A1)s','%(A2)s'])"
        % {"A1": _A1, "A2": _A2},
        # ws tolerance inside the spread
        "Reflect.apply(function(a,b){return a+b;}, null, [...[ '%(A1)s' , '%(A2)s' ]])"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F544 shapes block" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P2: bounds
def p2_f541_bounds():
    # All fail closed (want_block=False): rejected, never mis-decoded.
    shapes = [
        "JSON.parse(x).x.join('')",                                  # non-literal arg
        'JSON.parse(\'{"x":["%s"]}\', function(){}).x.join(\'\')' % _A1,  # reviver
        'JSON.parse(\'{bad json}\').x.join(\'\')',                   # invalid JSON
        'JSON.parse(\'{"x":[true,"a"]}\').x.join(\'\')',             # bool leaf
        'JSON.parse(\'{"x":[null,"a"]}\').x.join(\'\')',             # null leaf
        'JSON.parse(\'{"x":[1.5,"a"]}\').x.join(\'\')',              # float leaf
        'JSON.parse(\'{"x":[9007199254740993,"a"]}\').x.join(\'\')',  # beyond 2**53-1
        'JSON.parse(\'{"__proto__":"%s"}\').x' % _A1,                # __proto__ key
        'JSON.parse(\'{}\').x',                                      # missing key
        'JSONx.parse(\'{"x":["%s"]}\').x.join(\'\')' % _A1,          # JSONx
        'JSON.parse',                                                # no call
        'JSON["parse"](\'{"x":["%s"]}\').x.join(\'\')' % _A1,       # bracket member
        'JSON.parse(`{"x":["%s"]}`).x.join(\'\')' % _A1,             # template arg
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F541 bounds fail closed" % (len(shapes) - len(bad), len(shapes)))


def p2_f544_bounds():
    shapes = [
        # multiple spreads
        "Reflect.apply(function(a,b){return a+b;}, null, [...['%s'],...['%s']])" % (_A1, _A2),
        # mid-list spread
        "Reflect.apply(function(a,b){return a+b;}, null, ['%s',...['%s']])" % (_A1, _A2),
        # non-literal spread source
        "Reflect.apply(function(a,b){return a+b;}, null, [...x])",
        # nested spread (elements not string literals)
        "Reflect.apply(function(a,b){return a+b;}, null, [...[['%s']]])" % _A1,
        # numeric element in the spread array
        "Reflect.apply(function(a,b){return a+b;}, null, [...['%s',1]])" % _A1,
        # arity mismatch (spread yields 1, params need 2)
        "Reflect.apply(function(a,b){return a+b;}, null, [...['%s']])" % _A1,
        # spread in the F521 bind-arg position is F531's scope, not this one's;
        # here it is the argsArray after a plain target -- still one spread only
        "Reflect.apply(function(a,b){return a+b;}, null, [...['%s'], '%s'])" % (_A1, _A2),
    ]
    bad = [s for s in shapes if _verdict(s, False)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F544 bounds fail closed" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------- P3: compositions
def p3_compositions():
    pairs = [
        # F536 (structuredClone) CLOSED wave-367 -- untouched by this diff
        ("structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2), True),
        # F531 (spread bound args) CLOSED wave-367 -- untouched
        ("Reflect.apply([].concat.bind([], ...['%s']), null, ['%s']).join('')" % (_A1, _A2), True),
        # F535 (literal member reads) CLOSED wave-367 -- untouched
        ("({c:'%s'}).c+'%s'" % (_A1, _A2), True),
        # F519 literal argsArray still blocks (independence)
        ("Reflect.apply(function(a,b){return a+b;}, null, ['%s','%s'])" % (_A1, _A2), True),
        # F521 bound-concat call-indirect still blocks (independence)
        ("Reflect.apply.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (_A1, _A2), True),
        # F533 (for-of alias enumeration) CLOSED wave-367 -- untouched
        ("(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%s','%s')" % (_A1, _A2), True),
        # F534 (bound slice) CLOSED wave-367 -- untouched
        ("Reflect.apply([].slice.bind(['%s','%s'], 0, 2), null, []).join('')" % (_A1, _A2), True),
        # F546 (arguments-enumerating bodies in Reflect.apply targets) CLOSED
        # 2026-10-07 wave-368 lane 4 -- the three filed shapes must now HIT.
        ("Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;}, null, ['%s','%s'])" % (_A1, _A2), True),
        ("Reflect.apply(function(){var a=arguments;var s='';for(var i in a){s+=a[i];}return s;}, null, ['%s','%s'])" % (_A1, _A2), True),
        ("Reflect.apply(function(){var a=arguments;return a[0]+a[1];}, null, ['%s','%s'])" % (_A1, _A2), True),
        # F569 (call-indirect enum-body targets) CLOSED 2026-10-07
        # wave-369 lane 7 -- must now HIT (coded refusal).
        ("Reflect.apply.call(Reflect, function(){var a=arguments;return a[0]+a[1];}, null, ['%s','%s'])" % (_A1, _A2), True),
        # junk-quiet: JSON.parse of junk stays quiet
        ('JSON.parse(\'{"x":["ab"]}\').x.join(\'\')', False),
    ]
    bad = [s for s, want in pairs if _verdict(s, want)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d composition probes agree" % (len(pairs) - len(bad), len(pairs)))


# ------------------------------------------------------- P4: pin + footer
def p4_pin_and_footer():
    assert TAXONOMY_PIN == 2143, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    from gov import guac_graph  # noqa: E402
    # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    assert guac_graph.TAXONOMY_PIN == 2143, \
        "guac_graph.TAXONOMY_PIN=%r want 2143" % (guac_graph.TAXONOMY_PIN,)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F921**" in text  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: ." in text)  # Wave-369 merge: lanes 1-7 (F547-F569) CLOSED; open set finalized in maintenance
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


PROBES = [
    ("p1-f541-filed-shapes", p1_f541_filed_shapes),
    ("p1-f544-filed-shapes", p1_f544_filed_shapes),
    ("p2-f541-bounds", p2_f541_bounds),
    ("p2-f544-bounds", p2_f544_bounds),
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
    scripts = ("w367_f541_redfirst.py",
               "w367_f544_redfirst.py",
               "w367_attack_probes.py",
               "w367_f535f536close_probes.py",
               "w367_f531close_probes.py",
               "w364_f513f519close_probes.py")
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
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            return "green check FAILED:\n" + "\n".join(notes)
    return "green check passed:\n" + "\n".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w368_f541f544close: starting %d probes" % len(PROBES))
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
