#!/usr/bin/env python3
"""Close battery for F583 (key-laundering via terminal key reads) and
F589 (Map entries iteration reads).

F583 (LOW, filed 2026-10-07 wave-370 attack round 38): object key names
are attacker-controlled strings but the decoder modeled no
key-terminal reads over non-string literal values:
  Object.keys({'f1':1,'f2':1}).join('')
  Object.entries({'f1':1,'f2':1}).map(e=>e[0]).join('')
  Object.entries({'f1':1,'f2':1}).map(([k])=>k).join('')
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Root cause: `_js_parse_object_literal_keys_values`
required string-literal VALUES ("object literal value not a string"),
but Object.keys ignores values entirely; and `_js_parse_entries_projection`
had no destructured-param form.

F589 (LOW, filed 2026-10-07 wave-370 attack round 38): F563 closed
Map.get on literal Maps, but entries-iteration is a different read path:
  [...new Map([['c','f1']]).entries()][0][1]+'f2'
  [...new Map([['a','f1'],['b','f2']]).entries()].map(e=>e[1]).join('')
both node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants.

Closed (wave-371 lane 1):
- F583: `_js_parse_object_literal_keys_values(..., _keys_only=True)`
  skips values via `_js_skip_f583_literal_value`
  (string/numeric/true/false/null; nested fail closed); threaded
  through `_js_parse_enumeration_source`/`_js_parse_enumeration_wrapper`
  into the `Object.keys` (F517) and `Object.getOwnPropertyNames` (F525)
  paths, whose results cannot depend on values (node-verified).
  `Object.entries(OBJ).map(...)` (F517) does a strict-then-keys-only
  two-pass: the keys-only source is only valid for a KEYS projection
  (a values projection re-raises, fail closed).
  `_js_parse_entries_projection` gains the destructured pair-param
  forms `([p0])=>p0`, `([p0,p1])=>p0|p1` (+ block/function twins);
  duplicate names, elisions, rest, 3+ names fail closed.
- F589: `.entries()` on a `_JSMap` yields the opaque `_JSMapEntries`
  (the engine returns a Map Iterator -- no index reads or methods on
  it); only the F471 spread-copy factory consumes it (unwrapping to
  the insertion-ordered _JSArr of [k,v] pairs, numeric keys keeping
  _JSNumStr provenance per SameValueZero). Terminal reads chain via
  F547; `.map(p=>p[0|1])` over pair arrays via the F517 projection
  grammar (incl. the F583 destructured forms) in the general `.map`
  branch. `[...new Map(...).entries()]` routes through a fail-closed
  fallback in `_js_parse_spread_copy` (the F494 `.values()` fast path
  raises "not .values()", the primary path resolves `.entries()`).

Boundaries (all fail closed, never mis-decoded): non-literal values
(calls, idents, nested) in keys-only mode; `Object.entries` with
numeric values + VALUES projection; unspread `.entries()` index reads
/ method calls (engine-undefined); `.entries(1)`; additive pair
assembly `.map(e=>e[0]+e[1])` (documented F589 residual); `.map`
projection over non-pair / hole elements.

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
TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def p1_filed_shapes_held():
    """F583/F589 filed shapes now block coded."""
    shapes = [
        # F583
        "Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(e=>e[0]).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([k])=>k).join('')" % (_A, _B),
        # F589
        "[...new Map([['c','%s']]).entries()][0][1]+'%s'" % (_A, _B),
        "[...new Map([['a','%s'],['b','%s']]).entries()].map(e=>e[1]).join('')"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Filed-shape variants: member forms, separators, orderings, wrappers."""
    variants = [
        # F583: F480 bracket-string member
        "Object['keys']({'%s':1,'%s':1}).join('')" % (_A, _B),
        # F583: bool/null/float/ident values are skipped, keys still decode
        "Object.keys({'%s':true,'%s':null}).join('')" % (_A, _B),
        "Object.keys({'%s':1.5,'%s':-2}).join('')" % (_A, _B),
        "Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B),
        # F583: non-empty separator
        "Object.keys({'%s':1,'%s':1}).join('-')" % (_A, _B),
        # F583: integer keys sort numerically in the engine (node-exact,
        # verified by value in p4; they cannot be credential-shaped)
        # F583: integrity-wrapper source composes with keys-only mode
        "Object.keys(Object.freeze({'%s':1,'%s':1})).join('')" % (_A, _B),
        # F583: getOwnPropertyNames shares the keys-only grammar
        "Object.getOwnPropertyNames({'%s':1,'%s':1}).join('')" % (_A, _B),
        # F583: destructured projection twins
        "Object.entries({'%s':1,'%s':1}).map(([k,v])=>k).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([k])=>{return k;}).join('')"
        % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(function([k]){return k;}).join('')"
        % (_A, _B),
        # F583: parenthesized plain projection still works on num values
        "Object.entries({'%s':1,'%s':1}).map((e)=>e[0]).join('')" % (_A, _B),
        # F589: keys projection over map entries
        "[...new Map([['%s','x'],['%s','y']]).entries()].map(e=>e[0]).join('')"
        % (_A, _B),
        # F589: destructured projection over map entries pairs
        "[...new Map([['%s','x'],['%s','y']]).entries()].map(([k])=>k).join('')"
        % (_A, _B),
        # F589: numeric keys keep SameValueZero distinctness, project fine
        "[...new Map([[1,'%s'],[2,'%s']]).entries()].map(e=>e[1]).join('')"
        % (_A, _B),
        # F589: bracket-string member form
        "[...new Map([['a','%s'],['b','%s']])['entries']()].map(e=>e[1]).join('')"
        % (_A, _B),
        # F589: terminal index reads chain across both pairs
        "[...new Map([['a','%s'],['b','%s']]).entries()][0][1]"
        "+[...new Map([['a','%s'],['b','%s']]).entries()][1][1]"
        % (_A, _B, _A, _B),
        # F589: ws tolerance
        "[...new Map( [ ['a','%s'] , ['b','%s'] ] ).entries( )].map(e=>e[1]).join('')"
        % (_A, _B),
    ]
    bad = [s for s in variants if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(variants) - len(bad),
                                        len(variants)))


def p3_fail_closed_boundaries():
    """Non-filed shapes stay quiet (fail closed, never mis-decoded)."""
    bounds = [
        # keys-only value grammar: calls / nested / idents fail closed
        "Object.keys({'%s':fn(),'%s':1}).join('')" % (_A, _B),
        "Object.keys({'%s':[1],'%s':1}).join('')" % (_A, _B),
        "Object.keys({'%s':x,'%s':1}).join('')" % (_A, _B),
        # entries with numeric values + VALUES projection: unrecoverable
        "Object.entries({'a':1,'b':2}).map(e=>e[1]).join('')",
        # destructured projection: elision / duplicate / 3-arity
        "Object.entries({'%s':1,'%s':1}).map(([,v])=>v).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([k,k])=>k).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([a,b,c])=>a).join('')" % (_A, _B),
        # F589: unspread iterator has no index reads / methods in the engine
        "new Map([['%s','x'],['%s','y']]).entries()[0][1]+'!'" % (_A, _B),
        "new Map([['a','%s'],['b','%s']]).entries().map(e=>e[1]).join('')"
        % (_A, _B),
        # F589: .entries takes no args
        "[...new Map([['a','%s'],['b','%s']]).entries(1)][0][1]" % (_A, _B),
        # F589 residual: additive pair assembly (documented, fail closed)
        "[...new Map([['a','%s'],['b','%s']]).entries()].map(e=>e[0]+e[1]).join('')"
        % (_A, _B),
        # general .map projection: non-pair / hole elements fail closed
        "[['a','b'],'%s'].map(e=>e[0]).join('')" % (_B,),
        "[['a','b'],,'%s'].map(e=>e[0]).join('')" % (_B,),
        # spread of non-literal map
        "[...m.entries()].map(e=>e[1]).join('')",
    ]
    bad = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(bounds) - len(bad), len(bounds)))


def p4_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every variant."""
    cases = [
        "Object.keys({'%s':1,'%s':1}).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(e=>e[0]).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([k])=>k).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(([k,v])=>k).join('')" % (_A, _B),
        "Object.entries({'%s':1,'%s':1}).map(function([k]){return k;}).join('')"
        % (_A, _B),
        "Object.keys({2:'%s',1:'%s'}).join('')" % (_B, _A),
        "[...new Map([['c','%s']]).entries()][0][1]+'%s'" % (_A, _B),
        "[...new Map([['a','%s'],['b','%s']]).entries()].map(e=>e[1]).join('')"
        % (_A, _B),
        "[...new Map([[1,'%s'],['1','%s']]).entries()].map(e=>e[0]).join('')"
        % (_A, _B),
        # open-neighbor controls: node does NOT yield the credential here
        # (unspread .entries() throws; numeric-values projection yields '12')
        "new Map([['%s','x'],['%s','y']]).entries()[0][1]+'!'" % (_A, _B),
        "Object.entries({'a':1,'b':2}).map(e=>e[1]).join('')",
    ]
    # node truth: does node evaluate to exactly the credential?
    # ('err' and non-credential values both count as "does not yield")
    js = "const R=[];\n" + "\n".join(
        "try{R.push(eval(%s)===%s)}catch(e){R.push('err')}"
        % (repr(c), repr(_CRED)) for c in cases) + "\nconsole.log(JSON.stringify(R));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for c, truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        if dec_hit != (truth is True):
            bad.append(c[:60])
    # value-level checks: integer-key ordering and SameValueZero pair order
    val_cases = [
        ("Object.keys({2:'x',10:'y',1:'z'}).join('-')", "1-2-10"),
        ("[...new Map([[1,'a'],['1','b']]).entries()].map(e=>e[0]).join('')", "11"),
    ]
    for src, want in val_cases:
        state = {"ops": 0, "parts": 0}
        try:
            got, _ = dlp._js_parse_additive(src, 0, 0, state)
        except Exception:  # noqa: BLE001
            got = None
        if got != want:
            bad.append("value:%s" % src[:40])
    total = len(cases) + len(val_cases)
    return ("HELD" if not bad else "BREAK",
            "%d/%d node-decoder agreement" % (total - len(bad), total))


def p5_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F510: Object.values on string-literal values
        "Object.values({c:'%s'})[0]+'%s'" % (_A, _B),
        # F517: Object.keys on string values (strict path unchanged)
        "Object.keys({'%s':'x','%s':'y'}).join('')" % (_A, _B),
        # F517: entries+map values projection on string values
        "Object.entries({a:'%s',b:'%s'}).map(e=>e[1]).join('')" % (_A, _B),
        # F525: getOwnPropertyNames on string values
        "Object.getOwnPropertyNames({'%s':'x'}).join('')+'%s'" % (_A, _B),
        # F563: Map.get on literal maps
        "new Map([['c','%s']]).get('c')+'%s'" % (_A, _B),
        # F573: bare entries on string-valued literals, index reads
        "Object.entries({'%s':'x'})[0][0]+'%s'" % (_A, _B),
        # F543: entries on aliased arguments (must stay HELD)
        "(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');})('%s','%s')"
        % (_A, _B),
        # F572: WeakMap.get reads (must stay HELD)
        "(function(){var k={};var m=new WeakMap([[k,'%s']]);return m.get(k);})()+'%s'"
        % (_A, _B),
        # F547: index reads on plain arrays
        "['%s','%s'][0]+['%s','%s'][1]" % (_A, _B, _A, _B),
        # F535: literal member reads
        "({c:'%s'}).c+'%s'" % (_A, _B),
        # F494: spread of .values() unchanged
        "[...new Map([['a','%s'],['b','%s']]).values()].join('')" % (_A, _B),
        # F437: identity .map on string arrays unchanged
        "['%s','%s'].map(s=>s).join('')" % (_A, _B),
        # general .map projection over nested pair arrays (node-exact)
        "[['%s','x'],['%s','y']].map(e=>e[0]).join('')" % (_A, _B),
        # Wave-371 merge: sibling lanes closed these; moved from open_neigh
        # F584: URLSearchParams.getAll
        "new URLSearchParams('q=%s&q=%s').getAll('q').join('')" % (_A, _B),
        # F585: structuredClone of Map
        "structuredClone(new Map([['c','%s']])).get('c')+'%s'" % (_A, _B),
        # F586: parenthesized new-expression receiver
        "(new Map([['c','%s']])).get('c')+'%s'" % (_A, _B),
        # F587: new Proxy member-read receiver
        "new Proxy({c:'%s'},{}).c+'%s'" % (_A, _B),
        # F588: Reflect.get with Symbol.for keys
        "Reflect.get({[Symbol.for('c')]:'%s'},Symbol.for('c'))+'%s'" % (_A, _B),
        # F591: defineProperty arrow getter
        "Object.defineProperty({},'c',{get:()=>'%s'}).c+'%s'" % (_A, _B),
        # F592: for-in over object literal
        "(function(){var s='';var o={a:'%s',b:'%s'};for(var k in o){s+=o[k];}return s;})()"
        % (_A, _B),
        # F593: WeakMap variable-identity keys
        "(function(){var r={};return new WeakMap([[r,{c:'%s'}]]).get(r).c+'%s';})()"
        % (_A, _B),
        # F596: WeakMap multi-statement var-bound set
        "(function(){var k={};var m=new WeakMap();m.set(k,'%s');return m.get(k);})()+'%s'"
        % (_A, _B),
        # F594: for-in over bare arguments
        "(function(){var s='';for(var k in arguments){s+=arguments[k];}return s;})('%s','%s')"
        % (_A, _B),
        # F590: directive prologue in Reflect.apply.call target
        "Reflect.apply.call(null,function(){\"use strict\";var a=arguments;return a[0]+a[1];},null,['%s','%s'])"
        % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    # open neighbors (real filed shapes) must still miss
    open_neigh = [
        # F595: stringify nested array values
        "JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (_A, _B),
    ]
    bad_open = [s for s in open_neigh if not _quiet(s)]
    ok = not bad_held and not bad_open
    return ("HELD" if ok else "BREAK",
            "held=%d/%d open-miss=%d/%d" % (len(held) - len(bad_held),
                                            len(held),
                                            len(open_neigh) - len(bad_open),
                                            len(open_neigh)))


def p6_honest_text_quiet():
    """Honest text mentioning the new constructs stays quiet."""
    honest = [
        # prose about the builtins (no credential, no exfiltration)
        "See the Object.keys docs for how to enumerate keys.",
        "Map.prototype.entries returns an iterator of pairs.",
        # code samples over junk fragments
        "Object.keys({'a':1,'b':2}).join('')",
        "[...new Map([['a','zz']]).entries()].map(e=>e[1]).join('')",
        "Object.entries({'a':1}).map(([k])=>k).join('')",
    ]
    bad = [s for s in honest if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest payloads quiet" % (len(honest) - len(bad),
                                             len(honest)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F583/F589/F600/F601/F602 closed, next F606."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-07 wave-371 lane 1" in text
                 and "CLOSED 2026-10-07 wave-372 lane 4" in text
                 and "Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)
                 and "Next free finding: **F700**" in text)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
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
    scripts = ("w370_f583_redfirst.py",
               "w370_f589_redfirst.py",
               "w370_attack_probes.py",
               "w369_f560f562f563close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g371-green-%s-%d" % (script.replace(".py", ""),
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
              p5_compositions, p6_honest_text_quiet, p7_pin_and_footer]
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
