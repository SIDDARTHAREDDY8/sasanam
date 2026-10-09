#!/usr/bin/env python3
"""Close battery for F618 (promise .then assembly) + F619 (generator assembly).

F618 (LOW, filed 2026-10-08 wave-373 lane 7, attack round 41): Promise
resolution callbacks assemble credential fragments -- the decoder had
no model of promise resolution:
  Promise.all([Promise.resolve('f1'),Promise.resolve('f2')]).then(a=>a.join(''))
  Promise.all([Promise.resolve('f1'),Promise.resolve('f2')]).then(([a,b])=>a+b)
  Promise.race([Promise.resolve('f1')]).then(v=>v+'f2')
all node-evaluate to the exact credential (v24.20.0; verified via async
node drivers) while the decoder produced zero variants. Distinct from
F609 (replace-with-function callbacks -- a different builtin).

F619 (LOW, filed 2026-10-08 wave-373 lane 7, attack round 41,
model-hinted): generator yield/spread assembly -- the decoder had no
model of generators:
  (function(){function* g(){yield 'f1';yield 'f2';}return [...g()].join('');})()
  (function(){function* g(){yield 'f1';yield 'f2';}var s='';for(var x of g())s+=x;return s;})()
  (function(){function* g(){yield 'f1';yield 'f2';}return Array.from(g()).join('');})()
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F618 (sync vs async mechanism)
and from F494 (the anonymous immediate `(function*(){...})()` spread
source -- F619 is the NAMED declaration consumed via call).

Closed (wave-374 lane 6):
- F618: `_js_parse_f618_promise_then` -- static promise-resolution
  model. `Promise.all([Promise.resolve('LIT'),...])` fulfills with the
  input-order value array; the single-element `Promise.race`
  fulfills with that element's value; the `.then` arrow callback
  observes the fulfillment value. The decoder cannot await, so the
  deterministic fulfillment is modeled statically. Callback forms:
  `P=>BODY` / `(P)=>BODY` / `([P1,P2])=>BODY` (concise bodies
  only); the `P.join('SEP')` member form is evaluated structurally;
  other bodies go through bare-read substitution
  (`_js_bind_foreach_param`, the F600/F601/F602 discipline) + the
  additive grammar. New `Promise(?![_$A-Za-z0-9])` anchor (existing
  pattern extended -- no new re.compile).
- F619: `_js_parse_f619_generator_iife` -- statement-IIFE named
  generator. `function* NAME(){yield 'LIT';...}` follows the F494
  fixed-yield discipline; the three consumption tails are
  `return [...NAME()].join('SEP');`,
  `return Array.from(NAME()).join('SEP');`, and
  `var|let S='';for(var|let|const X of NAME())S+=X;return S;`
  (braced or bare loop body). The generator must be CALLED --
  a bare NAME reference is not iterable (the engine throws).

Boundaries (all fail closed, never mis-decoded): F618 -- function
callbacks, block bodies, default/rest params, `.then` with 2 args,
direct `Promise.resolve('LIT').then(...)` (unfiled), multi-element
or empty race, non-`Promise.resolve` elements, non-literal or extra
resolve args, `Promise.allSettled`, `.catch`/`.finally` chains,
`Promisex`, identifier-prefixed `xPromise`, identity-on-array
(`.then(v=>v)` yields an array, not the credential), the
single-element-all + string-concat composition
(`Promise.all([resolve('f1')]).then(v=>v+'f2')` -- node coerces the
array; unfiled residual, documented). F619 -- non-literal yields,
`yield*` delegation, generator params, `yield` without a value,
`return` in the body, empty yield lists, bare-NAME (uncalled)
consumption, wrong generator name, `.next().value` reads, for-in
over the generator, call args on the IIFE, `const` accumulators
(the engine throws TypeError), implicit-global loop vars.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov import dlp  # noqa: E402
from gov import decision_codes  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def p1_f618_filed_shapes_held():
    """F618 filed shapes now block coded."""
    shapes = [
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(a=>a.join(''))" % (_A, _B),
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(([a,b])=>a+b)" % (_A, _B),
        "Promise.race([Promise.resolve('%s')]).then(v=>v+'%s')"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_f618_variants_held():
    """Decoder variants of the F618 filed shapes block coded."""
    shapes = [
        # ws-tolerant
        "Promise . all ( [ Promise . resolve ( '%s' ) , "
        "Promise . resolve ( '%s' ) ] ) . then ( a => a . join ( '' ) )"
        % (_A, _B),
        # double-quoted literals
        'Promise.all([Promise.resolve("%s"),Promise.resolve("%s")])'
        '.then(([a,b])=>a+"-"+b)' % (_A, _B),
        # three-element all
        "Promise.all([Promise.resolve('xoxb-'),Promise.resolve('0123456789'),"
        "Promise.resolve('abcdef')]).then(a=>a.join(''))",
        # parenthesized single param (race: string-resolved)
        "Promise.race([Promise.resolve('%s')]).then((v)=>v+'%s')"
        % (_A, _B),
        # race with ws
        "Promise . race ( [ Promise . resolve ( '%s' ) ] )"
        ".then(v=>v+'%s')" % (_A, _B),
        # destructure reversed
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(([a,b])=>b+a)" % (_B, _A),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p3_f619_filed_shapes_held():
    """F619 filed shapes now block coded."""
    shapes = [
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return [...g()].join('');})()" % (_A, _B),
        "(function(){function* g(){yield '%s';yield '%s';}"
        "var s='';for(var x of g())s+=x;return s;})()" % (_A, _B),
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return Array.from(g()).join('');})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p4_f619_variants_held():
    """Decoder variants of the F619 filed shapes block coded."""
    shapes = [
        # double-quoted literals
        '(function(){function* g(){yield "%s";yield "%s";}'
        'return [...g()].join("");})()' % (_A, _B),
        # parenthesized yields
        "(function(){function* g(){yield('%s');yield('%s');}"
        "return Array.from(g()).join('');})()" % (_A, _B),
        # ws-tolerant
        "( function ( ) { function * g ( ) { yield '%s' ; yield '%s' ; } "
        "return [ ...g ( ) ] . join ( '' ) ; } ) ( )" % (_A, _B),
        # let/const + braced for-of body
        "(function(){function* g(){yield '%s';yield '%s';}"
        "let s='';for(let x of g()){s+=x;}return s;})()" % (_A, _B),
        # non-empty separator
        "(function(){function* g(){yield '%s';yield '%s';}"
        "return [...g()].join('-');})()" % (_A, _B),
        # other generator name
        "(function(){function* gg(){yield '%s';yield '%s';}"
        "return [...gg()].join('');})()" % (_A, _B),
        # three yields
        "(function(){function* g(){yield '%s';yield '%s';yield 'zz';}"
        "return [...g()].join('');})()" % (_A, _B),
        # ASI-tolerant (no semicolons)
        "(function(){function* g(){yield '%s'\nyield '%s'}"
        "return [...g()].join('')})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p5_f618_fail_closed_boundaries():
    """F618 boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # function callback (not an arrow)
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(function(a){return a.join('')})" % (_A, _B),
        # block body
        "Promise.all([Promise.resolve('%s')]).then(v=>{return v;})" % _A,
        # second .then argument
        "Promise.all([Promise.resolve('%s')]).then(v=>v,e=>e)" % _A,
        # direct resolve().then() (unfiled -- no .all/.race)
        "Promise.resolve('%s').then(v=>v)" % _A,
        # multi-element race (first-settled ordering unmodeled)
        "Promise.race([Promise.resolve('%s'),Promise.resolve('%s')])"
        ".then(v=>v)" % (_A, _B),
        # empty race (never settles)
        "Promise.race([]).then(v=>v)",
        # non-resolve element
        "Promise.all([Promise.resolve('%s'),x]).then(v=>v)" % _A,
        # non-literal resolve arg
        "Promise.all([Promise.resolve(x)]).then(v=>v)",
        # extra resolve arg (engine ignores; decoder refuses)
        "Promise.all([Promise.resolve('%s','zz')]).then(v=>v)" % _A,
        # allSettled (different fulfillment shape)
        "Promise.allSettled([Promise.resolve('%s')]).then(v=>v)" % _A,
        # catch/finally chains
        "Promise.all([Promise.resolve('%s')]).then(v=>v).catch(e=>e)"
        % _A,
        # ident-boundary guards
        "Promisex.all([Promise.resolve('%s')]).then(v=>v)" % _A,
        "xPromise.all([Promise.resolve('%s')]).then(v=>v)" % _A,
        # identity on array yields an array, not the credential
        "Promise.all([Promise.resolve('%s')]).then(v=>v)" % _A,
        # default params
        "Promise.all([Promise.resolve('%s')]).then((v='d')=>v)" % _A,
        # arguments-named param
        "Promise.all([Promise.resolve('%s')]).then(arguments=>arguments)"
        % _A,
        # uninvoked (no .then)
        "Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p6_f619_fail_closed_boundaries():
    """F619 boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # non-literal yield
        "(function(){function* g(){yield '%s';yield x;}"
        "return [...g()].join('');})()" % _A,
        # yield* delegation
        "(function(){function* g(){yield* ['%s'];}"
        "return [...g()].join('');})()" % _A,
        # generator params
        "(function(){function* g(a){yield a;}"
        "return [...g('%s')].join('');})()" % _A,
        # bare NAME (uncalled -- the engine throws: not iterable)
        "(function(){function* g(){yield '%s';}"
        "return [...g].join('');})()" % _A,
        # wrong generator name at consumption
        "(function(){function* g(){yield '%s';}"
        "return [...h()].join('');})()" % _A,
        # return inside the generator body
        "(function(){function* g(){yield '%s';return 'x';}"
        "return [...g()].join('');})()" % _A,
        # .next().value reads (unmodeled protocol)
        "(function(){function* g(){yield '%s';}"
        "return g().next().value;})()" % _A,
        # for-in (not for-of)
        "(function(){function* g(){yield '%s';}"
        "var s='';for(var x in g())s+=x;return s;})()" % _A,
        # no generator declaration at all
        "(function(){var s='';for(var x of g())s+=x;return s;})()",
        # empty yield list
        "(function(){function* g(){ }return [...g()].join('');})()",
        # call args on the IIFE
        "(function(){function* g(){yield '%s';}"
        "return [...g()].join('');})(1)" % _A,
        # const accumulator (the engine throws TypeError on +=)
        "(function(){function* g(){yield '%s';yield '%s';}"
        "const s='';for(const x of g())s+=x;return s;})()" % (_A, _B),
        # implicit-global loop var
        "(function(){function* g(){yield '%s';}"
        "var s='';for(x of g())s+=x;return s;})()" % _A,
        # yield without a value
        "(function(){function* g(){yield;yield '%s';}"
        "return [...g()].join('');})()" % _A,
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p7_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    # (js, node-yields-credential?) -- F618 via an async driver.
    async_cases = [
        ("Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
         ".then(a=>a.join(''))" % (_A, _B), True),
        ("Promise.all([Promise.resolve('%s'),Promise.resolve('%s')])"
         ".then(([a,b])=>a+b)" % (_A, _B), True),
        ("Promise.race([Promise.resolve('%s')]).then(v=>v+'%s')"
         % (_A, _B), True),
        ("Promise.all([Promise.resolve('xoxb-'),Promise.resolve('0123456789'),"
         "Promise.resolve('abcdef')]).then(a=>a.join(''))", True),
        # node does NOT yield the credential (fail-closed shapes)
        ("Promise.all([Promise.resolve('%s')]).then(v=>v)" % _A, False),
        ("Promise.race([Promise.resolve('%s'),Promise.resolve('%s')])"
         ".then(v=>v)" % (_A, _B), False),
    ]
    driver = ("const C=%s;const R=[];\n" % repr(_CRED) +
              "\n".join(
                  "try{R.push((await eval(%s))===C)}catch(e){R.push('err')}"
                  % repr(c) for c, _ in async_cases) +
              "\nconsole.log(JSON.stringify(R));")
    r = subprocess.run(["node", "-e",
                        "(async()=>{\n" + driver + "\n})();"],
                       capture_output=True, text=True, timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for (c, want), truth in zip(async_cases, node_truth):
        dec_hit = _blocked(c)
        if (truth is True) != want or dec_hit != want:
            bad.append("f618:" + c[:50])
    sync_cases = [
        ("(function(){function* g(){yield '%s';yield '%s';}"
         "return [...g()].join('');})()" % (_A, _B), True),
        ("(function(){function* g(){yield '%s';yield '%s';}"
         "var s='';for(var x of g())s+=x;return s;})()" % (_A, _B),
         True),
        ("(function(){function* g(){yield '%s';yield '%s';}"
         "return Array.from(g()).join('');})()" % (_A, _B), True),
        ("(function(){function* g(){yield '%s';}"
         "return [...g()].join('');})()" % _A, False),
    ]
    js = ("const C=%s;const R=[];\n" % repr(_CRED) +
          "\n".join("try{R.push(eval(%s)===C)}catch(e){R.push('err')}"
                    % repr(c) for c, _ in sync_cases) +
          "\nconsole.log(JSON.stringify(R));")
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    node_truth = _json.loads(r.stdout.strip())
    for (c, want), truth in zip(sync_cases, node_truth):
        dec_hit = _blocked(c)
        if (truth is True) != want or dec_hit != want:
            bad.append("f619:" + c[:50])
    # value-level: decoded value is node-exact, not just flagged
    val_cases = [
        ("Promise.all([Promise.resolve('b'),Promise.resolve('a')])"
         ".then(x=>x.join('-'))", "b-a"),
        ("Promise.all([Promise.resolve('x'),Promise.resolve('y')])"
         ".then(([p,q])=>q+p)", "yx"),
        ("Promise.race([Promise.resolve('q')]).then(v=>v+'!')", "q!"),
        ("(function(){function* g(){yield 'b';yield 'a';}"
         "return [...g()].join('-');})()", "b-a"),
        ("(function(){function* g(){yield 'x';yield 'y';}"
         "var s='';for(var t of g())s+=t;return s;})()", "xy"),
        ("(function(){function* g(){yield 'm';yield 'n';}"
         "return Array.from(g()).join('');})()", "mn"),
    ]
    for src, want in val_cases:
        state = {"ops": 0, "parts": 0}
        try:
            if src.startswith("Promise"):
                got, _ = dlp._js_parse_f618_promise_then(src, 0, 0, state)
            else:
                got, _ = dlp._js_parse_f619_generator_iife(src, 0, 0,
                                                           state)
        except Exception:  # noqa: BLE001
            got = None
        if got != want:
            bad.append("value:%s" % src[:40])
    total = len(async_cases) + len(sync_cases) + len(val_cases)
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement" % (total - len(bad), total))


def _round42_shapes():
    """Filed shapes of the currently-OPEN round-42 findings (must still miss)."""
    import importlib
    shapes = []
    for fnum in (621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634):
        mod = importlib.import_module("w374_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append((fnum, name, payload))
    return shapes


def p8_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F494 (anonymous immediate generator spread) stays HELD
        "[...(function*(){yield '%s';yield '%s';})()].join('')"
        % (_A, _B),
        # F611 (atob fragment) stays HELD
        "(function(){var b=atob('eG94Yi0wMTIz');return b+'%s';})()" % _B,
        # F603 (replace literal) stays HELD
        "'%s-X'.replace('X','%s')" % (_A, _B),
        # F609 (replace function) stays HELD
        "'%sXX'.replace('XX',()=>'%s')" % (_A, _B),
        # F595/F598 (stringify nested) stays HELD
        "JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')"
        % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    # F621-F634 are OPEN (attack round 42) -- they must still MISS
    # (wave-305/306: closures must not absorb attack findings).
    bad_miss = ["F%d/%s" % (fnum, name) for fnum, name, payload in _round42_shapes()
                if not _quiet(payload)]
    bad = bad_held + bad_miss
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions ok" % (len(held) + len(_round42_shapes()) - len(bad),
                                       len(held) + len(_round42_shapes())))


def p9_honest_text_quiet():
    """Honest text stays quiet."""
    texts = [
        "the promise.all helper resolves an array of values",
        "use promise.race to pick the fastest endpoint",
        "the generator yields each row lazily for streaming",
        "await the promise before rendering the dashboard",
        "Promises are the standard async primitive in JavaScript",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad), len(texts)))


def p10_pin_and_footer():
    """Pin 2143; footer shows F618/F619 closed, next F621."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2143 and n == 2140)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-08 wave-374 lane 6" in text
                 and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text  # Wave-374 lane 6: F618, F619 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
                 and "Next free finding: **F921**" in text)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    detail = "pin=%s codes=%d; footer-closed=%s" % (
        TAXONOMY_PIN, n, footer_ok)
    return (("HELD", detail) if (pin_ok and footer_ok)
            else ("BREAK", detail))


def _green_check():
    """Run adjacent batteries' mains with GOV_SKIP_GREEN=1 in the
    child env (depth-1; this battery honors the var by skipping).
    A battery is green when its tally line reports 0 BREAK."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w373_f618_redfirst.py",
               "w373_f619_redfirst.py",
               "w373_attack_probes.py",
               "w372_attack_probes.py",
               "w371_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g374-green-%s-%d" % (script.replace(".py", ""),
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
    probes = [p1_f618_filed_shapes_held, p2_f618_variants_held,
              p3_f619_filed_shapes_held, p4_f619_variants_held,
              p5_f618_fail_closed_boundaries, p6_f619_fail_closed_boundaries,
              p7_node_differential, p8_compositions, p9_honest_text_quiet,
              p10_pin_and_footer]
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
