#!/usr/bin/env python3
"""Wave-370 lane 2 closure battery: F571 + F576 (serialization family).

F571 (LOW): JSON.stringify round-trip laundering -- JSON.parse of a
string literal is closed (F541), but the round-trip
JSON.parse(JSON.stringify(X)) rebuilds the credential-bearing value
from a call result the decoder never interpreted. Closed by
serializing JSON-literal inputs node-exactly (_js_f571_stringify)
and feeding the text through the identical F541 parse tail.

F576 (LOW): URL / URLSearchParams laundering -- new
URLSearchParams('a=f1').get('a') and
new URL('https://h/?a=f1').searchParams.get('a') node-evaluate to
the credential while the decoder had no model. Closed with
_JSURLParams/_JSURL value classes, node-exact form-urlencoded
decoding (differential-verified against urllib.parse.parse_qsl),
and literal-only arguments.

Every probe runs at the public seam (find_credential); expected
values come from node v24.20.0, never from the implementation.
Red-first: evals/w369_f571_redfirst.py and
evals/w369_f576_redfirst.py print BREAK on the open tree.
"""
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

TAXONOMY_PIN = 2143  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Credential fragments via concatenation: the write path redacts literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"
_CRED = _A1 + _A2

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _quiet(payload):
    # Honest-quiet: the decoder must produce NO variant (not even a
    # wrong one) -- used for F567-class left-boundary probes.
    return find_credential(payload) is None


# ------------------------------------------------------- P0: pin/footer
def p0_pin_footer():
    assert TAXONOMY_PIN == 2143, "pin moved"  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F762**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-373 lane 1: F595 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- P1: F571 filed shapes
def p1_f571_filed():
    shapes = [
        "JSON.parse(JSON.stringify({c:'%s'})).c+'%s'" % (_A1, _A2),
        "JSON.parse(JSON.stringify('%s'))+'%s'" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


# ------------------------------------------------- P2: F576 filed shapes
def p2_f576_filed():
    shapes = [
        "new URLSearchParams('a=%s').get('a')+'%s'" % (_A1, _A2),
        "new URL('https://h.test/?a=%s&b=%s').searchParams.get('a')"
        "+new URL('https://h.test/?a=%s&b=%s').searchParams.get('b')"
        % (_A1, _A2, _A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


# ------------------------------------------------------- P3: F571 variants
def p3_f571_variants():
    variants = [
        # nested object / array round-trips
        "JSON.parse(JSON.stringify({o:{c:'%s'}})).o.c+'%s'" % (_A1, _A2),
        "JSON.parse(JSON.stringify(['%s','%s'])).join('')" % (_A1, _A2),
        # integer-like keys serialize numerically-first (node-exact);
        # reads go through string keys (F535 scope)
        "JSON.parse(JSON.stringify({c:'%s','10':'a','2':'b'})).c+'%s'"
        % (_A1, _A2),
        # duplicate keys: later wins, engine-exact
        "JSON.parse(JSON.stringify({c:'zz',c:'%s'})).c+'%s'" % (_A1, _A2),
        # escapes survive the round trip (in a non-credential property)
        "JSON.parse(JSON.stringify({c:'%s',e:'a\\n\\t\"q\"\\\\'})).c+'%s'"
        % (_A1, _A2),
        # honest shapes (no credential): must stay quiet, never crash
        "JSON.parse(JSON.stringify({})).x",
        "JSON.parse(JSON.stringify(['%s'])).length" % (_A1,),
    ]
    blocked = variants[:5]
    bad = [s for s in blocked if not _blocked(s)]
    # honest shapes must stay quiet (no credential variant, no crash)
    loud = [s for s in variants[5:] if find_credential(s) is not None]
    ok = not bad and not loud
    return ("HELD" if ok else "BREAK",
            "variants blocked %d/%d, honest-quiet %d/%d"
            % (len(blocked) - len(bad), len(blocked),
               len(variants[5:]) - len(loud), len(variants[5:])))


# ------------------------------------------------------- P4: F576 variants
def p4_f576_variants():
    variants = [
        # duplicate names: first wins, engine-exact
        "new URLSearchParams('a=%s&a=zz').get('a')+'%s'" % (_A1, _A2),
        # percent-decoding: ' A' carries no credential -> quiet
        "new URLSearchParams('a=%20%41').get('a')",
        # missing name -> quiet (engine returns null)
        "new URLSearchParams('').get('a')",
        # empty value pairs coexist with credential pairs
        "new URLSearchParams('b=&a=%s').get('a')+'%s'" % (_A1, _A2),
        # bracket-string member forms
        "new URLSearchParams('a=%s')['get']('a')+'%s'" % (_A1, _A2),
        "new URL('https://h.test/?a=%s')['searchParams']['get']('a')+'%s'"
        % (_A1, _A2),
        # URL with port and fragment
        "new URL('https://h.test:8443/p?a=%s#frag').searchParams.get('a')"
        "+'%s'" % (_A1, _A2),
        # '&' separates pairs; ';' does not (node-exact)
        "new URLSearchParams('x=%s&y=zz').get('x')+'%s'" % (_A1, _A2),
        "new URLSearchParams('a=b;c=d').get('a')",  # -> 'b;c=d', quiet
    ]
    blocked = [variants[0], variants[3], variants[4], variants[5],
               variants[6], variants[7]]
    bad = [s for s in blocked if not _blocked(s)]
    quiet = [variants[1], variants[2], variants[8]]
    loud = [s for s in quiet if not _quiet(s)]
    ok = not bad and not loud
    return ("HELD" if ok else "BREAK",
            "variants blocked %d/%d, honest-quiet %d/%d"
            % (len(blocked) - len(bad), len(blocked),
               len(quiet) - len(loud), len(quiet)))


# ------------------------------------------------------ P5: F571 bounds
def p5_f571_bounds():
    # All fail closed: never a decoded variant, never a crash.
    bounds = [
        "JSON.parse(JSON.stringify(x)).c",          # non-literal arg
        "JSON.parse(JSON.stringify({c:'a'}),null)",  # replacer arg
        "JSON['parse'](JSON.stringify({c:'a'}))",    # bracket member
        "JSON.parse(`{\"c\":\"a\"}`)",               # template arg
        "JSON.parse(x)",                            # identifier arg
        "JSON.stringify()",                         # no args
        "JSON.parse(JSON.stringify({c:true})).c",   # bool leaf
        "JSON.parse(JSON.stringify({c:null})).c",    # null leaf
        "JSON.parse(JSON.stringify({__proto__:{c:'a'}})).c",  # proto key
        "JSON.parse(JSON.stringify(42))",            # number arg
        "JSON.parse(JSON.stringify({c:'a'}), )",     # trailing comma arg
        "JSON.parse(JSON.stringify(['a'],['b']))",   # extra array arg
    ]
    loud = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(loud),
                                          len(bounds)))


# ------------------------------------------------------ P6: F576 bounds
def p6_f576_bounds():
    bounds = [
        "new URLSearchParams(x).get('a')",            # non-literal
        "new URL('https://h/?a=b','https://base/')",  # base arg
        "new URL('/rel?a=b')",                        # relative URL
        "new URL('not a url')",                       # no scheme/host
        "new URL",                                    # no call
        "new URLSearchParams()",                      # no args
        "new URLSearchParams('a=b').get(x)",          # non-literal key
        "new URLSearchParams('a=b').post('a')",       # unmodeled member
        "new URL('https://h/?a=b').pathname",         # unmodeled member
        "new URLSearchParams('a=b').get('a','b')",    # extra get arg
        # F567: identifier-suffixed anchors stay honest-quiet
        "xnew URLSearchParams('a=%s').get('a')+'%s'" % (_A1, _A2),
        "xnew URL('https://h/?a=%s').searchParams.get('a')+'%s'"
        % (_A1, _A2),
    ]
    loud = [s for s in bounds if not _quiet(s)]
    return ("HELD" if not loud else "BREAK",
            "%d/%d bounds fail closed/quiet" % (len(bounds) - len(loud),
                                               len(bounds)))


# ------------------------------------------------- P7: compositions
def p7_compositions():
    # Closed neighbors stay HELD (no regression from the new branches).
    held = [
        ("F541", "JSON.parse('{\"c\":\"%s\"}').c+'%s'" % (_A1, _A2)),
        ("F536", "structuredClone({c:'%s'}).c+'%s'" % (_A1, _A2)),
        ("F563", "new Map([['c','%s']]).get('c')+'%s'" % (_A1, _A2)),
        ("F539", "new WeakRef({c:'%s'}).deref().c+'%s'" % (_A1, _A2)),
        ("F551", "String.raw({raw:['','','']},'%s','%s')" % (_A1, _A2)),
        # Wave-373 lane 1: F570-F582 closed in wave-370 (verified push
        # ec2773b2), but this battery's open-neighbor list was never
        # flipped (wave-305/306 debt -- the shapes all decode on the
        # current tree, proven by the pre-existing p7 BREAK). They join
        # the held list; the open list is empty.
        ("F570", "Reflect.apply(function(){\"use strict\";var a=arguments;"
                 "return a[0]+a[1];},null,['%s','%s'])" % (_A1, _A2)),
        ("F572", "(function(){var k={};var m=new WeakMap();m.set(k,'%s');"
                 "return m.get(k);})()+'%s'" % (_A1, _A2)),
        ("F573", "Object.entries({a:'%s'})[0][1]+'%s'" % (_A1, _A2)),
        ("F574", "[[['%s']],[['%s']]].flat(Infinity).join('')" % (_A1, _A2)),
        ("F575", "String.raw({raw:{0:'%s',1:'%s',length:2}})" % (_A1, _A2)),
        ("F577", "((...a)=>a[0]+a[1])('%s','%s')" % (_A1, _A2)),
        ("F578", "(function(){var o={c:'x'};Object.defineProperty(o,'c',"
                 "{get:function(){return '%s';}});return o.c;})()+'%s'"
                 % (_A1, _A2)),
        ("F579", "({c:'%s'})[Reflect.ownKeys({c:'%s'})[0]]+'%s'"
                 % (_A1, _A1, _A2)),
        ("F580", "['%s','%s'].sort((a,b)=>a.length-b.length).join('')"
                 % (_A2, _A1)),
        ("F581", "Reflect.apply(Object.values,null,"
                 "[(function(){var a=arguments;return a;})('%s','%s')])"
                 ".join('')" % (_A1, _A2)),
        ("F582", "Reflect.apply((a,b)=>a+b,null,['%s','%s','junk'])"
                 % (_A1, _A2)),
    ]
    # No open neighbors remain in this battery's scope (F570-F582 closed
    # wave-370; F595 closed wave-373 lane 1). Empty by design: a future
    # open neighbor re-pins here.
    open_ = []
    # honest URLSearchParams read with no credential stays quiet
    honest_quiet = _quiet("new URLSearchParams('a=b').get('a')")
    bad_held = [n for n, s in held if not _blocked(s)]
    bad_open = [n for n, s in open_ if not _misses(s)]
    ok = not bad_held and not bad_open and honest_quiet
    return ("HELD" if ok else "BREAK",
            "closed-held %d/%d, open-miss %d/%d"
            % (len(held) - len(bad_held), len(held),
               len(open_) - len(bad_open), len(open_)))


# ------------------------------------------------- P8: node differential
_NODE_EXPRS = [
    # (js template, node_has_cred)
    ("JSON.parse(JSON.stringify({c:'%(A1)s'})).c+'%(A2)s'", True),
    ("JSON.parse(JSON.stringify('%(A1)s'))+'%(A2)s'", True),
    ("JSON.parse(JSON.stringify(['%(A1)s','%(A2)s'])).join('')", True),
    ("JSON.parse(JSON.stringify({c:'zz'})).c+'yy'", False),
    ("new URLSearchParams('a=%(A1)s').get('a')+'%(A2)s'", True),
    ("new URL('https://h.test/?a=%(A1)s&b=%(A2)s').searchParams.get('a')"
     "+new URL('https://h.test/?a=%(A1)s&b=%(A2)s').searchParams.get('b')",
     True),
    ("new URLSearchParams('a=%(A1)s&a=zz').get('a')+'%(A2)s'", True),
    ("new URLSearchParams('q=zz').get('q')+'yy'", False),
]

# (python value-spec, js literal) pairs for the serializer differential:
# the python value is built as _JSObj/_JSArr/str and serialized with
# _js_f571_stringify; the js literal is stringified by node. The two
# texts must be byte-identical.
_SERIALIZER_CASES = [
    ({"c": "v"}, "{c:'v'}"),
    ({"2": "a", "1": "b", "c": "d"}, "{2:'a',1:'b',c:'d'}"),
    ({"10": "x", "2": "y"}, "{10:'x',2:'y'}"),
    ({"01": "lead", "1": "one"}, "{'01':'lead',1:'one'}"),
    (["a", "b"], "['a','b']"),
    ({"q": "\"\\"}, "{q:'\"\\\\'}"),
    ({"u": "caf\u00e9"}, "{u:'caf\u00e9'}"),
    ({"n": {"m": ["x"]}}, "{n:{m:['x']}}"),
    ({"s": "\ud800"}, "{s:'\\ud800'}"),          # lone surrogate: escaped
    ({"s": "\ud800\udc00"}, "{s:'\\ud800\\udc00'}"),  # pair: astral raw
]


def _py_val(spec):
    # Build the decoder-side value from a plain python spec.
    from gov.dlp import _JSArr, _JSObj
    if isinstance(spec, dict):
        return _JSObj({k: _py_val(v) for k, v in spec.items()})
    if isinstance(spec, list):
        return _JSArr([_py_val(v) for v in spec])
    return spec


def p8_node_differential():
    from gov.dlp import _js_f571_stringify
    mismatches = []
    for template, node_has_cred in _NODE_EXPRS:
        js = template % {"A1": _A1, "A2": _A2}
        try:
            r = subprocess.run(
                ["node", "-e",
                 "console.log(JSON.stringify(%s))" % js],
                capture_output=True, text=True, timeout=30)
            node_val = json.loads(r.stdout.strip())
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "node failed on %s: %r" % (js[:60], e))
        node_cred = (node_val == _CRED)
        if node_cred != node_has_cred:
            return ("ERROR",
                    "node disagrees with expected on %s: node=%r"
                    % (js[:60], node_val))
        if _blocked(js) != node_cred:
            mismatches.append(js[:72])
    # serializer differential: byte-identical to node's JSON.stringify
    ser_bad = []
    for spec, js_lit in _SERIALIZER_CASES:
        state = {"parts": 0, "ops": 0}
        try:
            mine = _js_f571_stringify(_py_val(spec), state)
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "serializer raised on %r: %r" % (spec, e))
        try:
            r = subprocess.run(
                ["node", "-e", "console.log(JSON.stringify(%s))" % js_lit],
                capture_output=True, text=True, timeout=30)
            node_text = r.stdout.strip()
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "node failed on %s: %r" % (js_lit[:60], e))
        if mine != node_text:
            ser_bad.append("%r: mine=%r node=%r"
                           % (spec, mine, node_text))
    if mismatches or ser_bad:
        return ("BREAK", "%d decoder/node mismatches: %s; %d serializer "
                "mismatches: %s"
                % (len(mismatches), "; ".join(mismatches),
                   len(ser_bad), "; ".join(ser_bad)))
    total = len(_NODE_EXPRS) + len(_SERIALIZER_CASES)
    return ("HELD", "%d/%d decoder+serializer agree with node v24.20.0"
            % (total, total))


# ------------------------------------------------- P9: green checks
def p9_green_checks():
    if os.environ.get("GOV_SKIP_GREEN"):
        return ("HELD", "green checks skipped (GOV_SKIP_GREEN)")
    notes = []
    for bat in ("evals/w369_f571_redfirst.py",
                "evals/w369_f576_redfirst.py"):
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, bat)],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "GOV_SKIP_GREEN": "1",
                 "TMPDIR": os.environ.get("TMPDIR", "/tmp")})
        ok = "0 BREAK" in r.stdout
        notes.append("%s:%s" % (bat, "ok" if ok else "FAIL"))
        if not ok:
            return ("BREAK", "; ".join(notes) + "\n" + r.stdout[-500:])
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                     "w369_attack_probes.py")],
        capture_output=True, text=True, timeout=600,
        env={**os.environ, "GOV_SKIP_GREEN": "1",
             "TMPDIR": os.environ.get("TMPDIR", "/tmp")})
    ok = "0 BREAK" in r.stdout and "0 ERROR" in r.stdout
    notes.append("w369_attack:%s" % ("ok" if ok else "FAIL"))
    if not ok:
        return ("BREAK", "; ".join(notes) + "\n" + r.stdout[-800:])
    return ("HELD", "; ".join(notes))


PROBES = [p0_pin_footer, p1_f571_filed, p2_f576_filed, p3_f571_variants,
          p4_f576_variants, p5_f571_bounds, p6_f576_bounds,
          p7_compositions, p8_node_differential, p9_green_checks]


def main():
    breaks, held, errors = 0, 0, 0
    for fn in PROBES:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
