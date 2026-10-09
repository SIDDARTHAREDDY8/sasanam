#!/usr/bin/env python3
"""Wave-369 lane 3 close probes: F551 (String.raw substitutions),
F559 (string-literal spread bound args), F564 (String.split).

F551: String.raw WITH substitutions bypasses the bounded static
JS-expression decoder -- F493 closed the no-substitution call form,
but the substitution form is a different production:
String.raw({raw:['','','']},'f1','f2') and
String.raw.call(String,{raw:['','','']},'f1','f2') node-evaluate to the
exact credential (v24.20.0) with zero decoder variants. Closed by
modeling the substitution interleave node-exactly
(_js_parse_raw_substitutions + _js_interleave_raw_substitutions):
raw[0] + sub[0] + raw[1] + ... + raw[n-1]; missing subs contribute
nothing, extra subs are dropped, the last sub is always dropped.
Only string-literal substitutions; .apply/.bind and non-literal
subs fail closed. The .call thisArg accepts the additive grammar or
a bare identifier (the engine ignores it -- F551's filed shape uses
`String`); anything else fails closed.

F559: string-literal spread in .bind args (char expansion) bypasses
the decoder -- F531 models spread of ARRAY literals (elements become
bound args), but spread of a STRING literal expands to CHARS:
Reflect.apply([].concat.bind([],...'f1'),null,['f2']).join('')
node-evaluates to the exact credential with zero decoder variants.
Closed by extending _js_parse_f531_spread_bound_args to string
sources (chars become bound args, parts-charged per char -- F452
lesson); the sole-and-final-arg constraint is unchanged.

F564: String.split laundering bypasses the decoder -- the decoder
models match/replace but not split: 'f1,f2'.split(',').join(''),
'f1;f2'.split(';').join(''), and 'f1,f2'.split(',',2).join('') all
node-evaluate to the exact credential with zero decoder variants.
Closed by adding "split" to _JS_POSTFIX_METHOD_NAMES with a
node-exact branch in _js_apply_method_at: string-literal separator
only (empty separator splits into chars), optional numeric-literal
limit (ToUint32 is the identity on _js_parse_number's non-negative
ints), no-arg form returns [value]. Regex/non-literal separators
and non-literal limits fail closed.

Seams under test (tdd): find_credential at the public seam for
every probe; node v24.20.0 differential for engine-exactness.

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

TAXONOMY_PIN = 2144  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: F551 filed
def p1_f551_filed_shapes():
    shapes = [
        "String.raw({raw:['','','']},'%(A1)s','%(A2)s')"
        % {"A1": _A1, "A2": _A2},
        "String.raw.call(String,{raw:['','','']},'%(A1)s','%(A2)s')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F551 filed shapes block" % (len(shapes) - len(bad),
                                               len(shapes)))


def p2_f551_variants():
    shapes = [
        # F493 no-substitution forms stay held (incl. the newly-fixed
        # bare-identifier thisArg on the .call form)
        ("String.raw({raw:['%(A1)s','%(A2)s']})"
         % {"A1": _A1, "A2": _A2}, True),
        ("String.raw.call(String,{raw:['%(A1)s','%(A2)s']})"
         % {"A1": _A1, "A2": _A2}, True),
        ("String.raw.call(null,{raw:['%(A1)s','%(A2)s']})"
         % {"A1": _A1, "A2": _A2}, True),
        # extra substitutions are dropped by the engine -> still the
        # credential
        ("String.raw({raw:['%(CRED)s']},'zz','yy')" % {"CRED": _CRED},
         True),
        # whitespace tolerance
        ("String.raw( { raw : [ '' , '' , '' ] } , '%(A1)s' , '%(A2)s' )"
         % {"A1": _A1, "A2": _A2}, True),
        # single substitution between two segments
        ("String.raw({raw:['%(A1)s-%(A2)s']},'zz')" % {"A1": _A1,
                                                       "A2": _A2}, True),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F551 variants block" % (len(shapes) - len(bad),
                                            len(shapes)))


def p3_f551_bounds():
    shapes = [
        # non-literal substitution fails closed (engine ToString-coerces)
        ("String.raw({raw:['','','']},'%(A1)s',x)" % {"A1": _A1}, False),
        # .apply form fails closed (filed scope: direct + .call only)
        ("String.raw.apply(String,[{raw:['','','']},'%(A1)s','%(A2)s'])"
         % {"A1": _A1, "A2": _A2}, False),
        # .bind form fails closed
        ("String.raw.bind(String,{raw:['','','']})('%(A1)s','%(A2)s')"
         % {"A1": _A1, "A2": _A2}, False),
        # trailing comma fails closed (same as the F454 literal-list
        # grammar)
        ("String.raw({raw:['%(A1)s','%(A2)s']},)" % {"A1": _A1,
                                                     "A2": _A2}, False),
        # dotted thisArg fails closed (only bare ident / additive)
        ("String.raw.call(a.b,{raw:['','','']},'%(A1)s','%(A2)s')"
         % {"A1": _A1, "A2": _A2}, False),
        # missing substitution contributes nothing (never "undefined"):
        # junk in, junk out -- no credential, no hit
        ("String.raw({raw:['qq','-','ww']},'zz')", False),
        # tag form keeps its F463 coded-refusal behavior
        ("String.raw`%(A1)s${'%(A2)s'}`" % {"A1": _A1, "A2": _A2}, True),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F551 bounds behave" % (len(shapes) - len(bad),
                                           len(shapes)))


# ------------------------------------------------------------- P4: F559 filed
def p4_f559_filed_shapes():
    shapes = [
        "Reflect.apply([].concat.bind([],...'%(A1)s'),null,['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
        "Reflect.apply([].concat['bind']([],...'%(A1)s'),null,['%(A2)s']).join('')"
        % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F559 filed shapes block" % (len(shapes) - len(bad),
                                               len(shapes)))


def p5_f559_variants():
    shapes = [
        # F531 array spread stays held
        ("Reflect.apply([].concat.bind([],...['%(A1)s']),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # empty string spread binds nothing -- still the credential
        ("Reflect.apply([].concat.bind([],...''),null,['%(CRED)s']).join('')"
         % {"CRED": _CRED}, True),
        # literal bound args (F521) stay held
        ("Reflect.apply([].concat.bind([],'%(A1)s'),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # whitespace tolerance around the spread
        ("Reflect.apply([].concat.bind([], ... '%(A1)s' ),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # Array.prototype.concat receiver with string spread
        ("Reflect.apply(Array.prototype.concat.bind([],...'%(A1)s'),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F559 variants block" % (len(shapes) - len(bad),
                                            len(shapes)))


def p6_f559_bounds():
    shapes = [
        # non-literal spread source fails closed
        ("Reflect.apply([].concat.bind([],...x),null,['%(A2)s']).join('')"
         % {"A2": _A2}, False),
        # mid-list spread fails closed (sole-and-final constraint)
        ("Reflect.apply([].concat.bind([],'zz',...'%(A1)s'),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, False),
        # object spread source fails closed
        ("Reflect.apply([].concat.bind([],...{'0':'%(A1)s'}),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, False),
        # template spread source fails closed
        ("Reflect.apply([].concat.bind([],...`%(A1)s`),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, False),
        # double spread fails closed
        ("Reflect.apply([].concat.bind([],...'%(A1)s',...'%(A2)s'),null,[]).join('')"
         % {"A1": _A1, "A2": _A2}, False),
        # huge string spread starves on the parts budget (F452) --
        # quiet, never a hit, never loud
        ("Reflect.apply([].concat.bind([],...'%s'),null,[]).join('')"
         % ("q" * 5000), False),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F559 bounds behave" % (len(shapes) - len(bad),
                                          len(shapes)))


# ------------------------------------------------------------- P7: F564 filed
def p7_f564_filed_shapes():
    shapes = [
        "'%(A1)s,%(A2)s'.split(',').join('')" % {"A1": _A1, "A2": _A2},
        "'%(A1)s;%(A2)s'.split(';').join('')" % {"A1": _A1, "A2": _A2},
        "'%(A1)s,%(A2)s'.split(',',2).join('')" % {"A1": _A1, "A2": _A2},
    ]
    bad = [s for s in shapes if _verdict(s, True)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F564 filed shapes block" % (len(shapes) - len(bad),
                                               len(shapes)))


def p8_f564_variants():
    shapes = [
        # no-arg form returns [value]
        ("'%(CRED)s'.split().join('')" % {"CRED": _CRED}, True),
        # bracket-string member form (F507)
        ("'%(A1)s,%(A2)s'['split'](',').join('')" % {"A1": _A1,
                                                      "A2": _A2}, True),
        # multi-char separator
        ("'%(A1)s::%(A2)s'.split('::').join('')" % {"A1": _A1,
                                                    "A2": _A2}, True),
        # separator not found -> [value]
        ("'%(CRED)s'.split(',').join('')" % {"CRED": _CRED}, True),
        # limit larger than the segment count -> all segments
        ("'%(A1)s,%(A2)s'.split(',',9).join('')" % {"A1": _A1,
                                                    "A2": _A2}, True),
        # NOTE: whitespace between '.' and the method name is a
        # pre-existing postfix-chain limitation for ALL methods
        # (verified quiet on the base tree for .replace/.concat) --
        # not asserted here.
        # empty separator on junk stays quiet (chars, no credential)
        ("'ab,cd'.split('').join(',')", False),
        # limit 0 -> [] -> '' (quiet)
        ("'%(A1)s,%(A2)s'.split(',',0).join('')" % {"A1": _A1,
                                                    "A2": _A2}, False),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F564 variants behave" % (len(shapes) - len(bad),
                                             len(shapes)))


def p9_f564_bounds():
    shapes = [
        # regex separator fails closed
        ("'%(A1)s,%(A2)s'.split(/,/).join('')" % {"A1": _A1,
                                                   "A2": _A2}, False),
        # non-literal separator fails closed
        ("'%(A1)s,%(A2)s'.split(x).join('')" % {"A1": _A1,
                                                 "A2": _A2}, False),
        # non-literal limit fails closed
        ("'%(A1)s,%(A2)s'.split(',',x).join('')" % {"A1": _A1,
                                                    "A2": _A2}, False),
        # negative limit fails closed (_js_parse_number takes no sign)
        ("'%(A1)s,%(A2)s'.split(',',-1).join('')" % {"A1": _A1,
                                                     "A2": _A2}, False),
        # split on a non-string fails closed
        ("['a','b'].split(',').join('')", False),
        # junk stays quiet
        ("'zz,yy'.split(',').join('')", False),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F564 bounds behave" % (len(shapes) - len(bad),
                                          len(shapes)))


# ------------------------------------------------------- P10: compositions
def p10_compositions():
    shapes = [
        # F493: no-substitution raw stays held
        ("String.raw({raw:['%(A1)s','%(A2)s']})" % {"A1": _A1,
                                                    "A2": _A2}, True),
        # F531: array spread in bind args stays held
        ("Reflect.apply([].concat.bind([],...['%(A1)s']),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F521: literal bound args stay held
        ("Reflect.apply([].concat.bind([],'%(A1)s'),null,['%(A2)s']).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F530: bound join stays held
        ("Reflect.apply([].join.bind(['%(A1)s','%(A2)s'],''),null,[])"
         % {"A1": _A1, "A2": _A2}, True),
        # F499: chained string spreads in array literals stay held
        # (spread + plain element fails closed by F499's documented
        # design -- only spread chains are modeled)
        ("[...'%(A1)s',...'%(A2)s'].join('')" % {"A1": _A1,
                                                  "A2": _A2}, True),
        # F464: match/replace stays held
        ("'--%(A1)s--%(A2)s--'.match(/--(.*)--(.*)--/).slice(1).join('')"
         % {"A1": _A1, "A2": _A2}, True),
        # F463: tag form stays a coded refusal
        ("String.raw`%(A1)s${'%(A2)s'}`" % {"A1": _A1, "A2": _A2}, True),
        # split chains honestly into the modeled comma-replace
        ("'%(A1)s,%(A2)s'.split(',').join(',').replace(/,/g,'')"
         % {"A1": _A1, "A2": _A2}, True),
    ]
    bad = [s for s, w in shapes if _verdict(s, w)[0] == "BREAK"]
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions hold" % (len(shapes) - len(bad),
                                         len(shapes)))


# ------------------------------------------------- P11: node differential
_NODE_EXPRS = [
    ("String.raw({raw:['','','']},'%(A1)s','%(A2)s')", True),
    ("String.raw.call(String,{raw:['','','']},'%(A1)s','%(A2)s')", True),
    ("String.raw({raw:['%(A1)s','%(A2)s']})", True),
    ("String.raw({raw:['%(CRED)s']},'zz','yy')", True),
    ("String.raw({raw:['a','b','c']},'x')", False),
    # missing substitution contributes nothing (never "undefined"):
    # junk fragments stay quiet
    ("String.raw({raw:['qq','-','ww']},'zz')", False),
    ("Reflect.apply([].concat.bind([],...'%(A1)s'),null,['%(A2)s']).join('')",
     True),
    ("Reflect.apply([].concat.bind([],...''),null,['%(CRED)s']).join('')",
     True),
    ("Reflect.apply([].concat.bind([],...['%(A1)s']),null,['%(A2)s']).join('')",
     True),
    ("'%(A1)s,%(A2)s'.split(',').join('')", True),
    ("'%(A1)s,%(A2)s'.split(',',2).join('')", True),
    ("'%(A1)s,%(A2)s'.split(',',9).join('')", True),
    ("'%(A1)s,%(A2)s'.split(',',1).join('')", False),
    ("'%(A1)s,%(A2)s'.split(',',0).join('')", False),
    ("'%(CRED)s'.split().join('')", True),
    ("'ab'.split('').join('-')", False),
    ("'%(A1)s::%(A2)s'.split('::').join('')", True),
]


def p11_node_differential():
    mismatches = []
    for template, node_has_cred in _NODE_EXPRS:
        js = template % {"A1": _A1, "A2": _A2, "CRED": _CRED}
        try:
            r = subprocess.run(
                ["node", "-e", "console.log(JSON.stringify(%s))" % js],
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
    if mismatches:
        return ("BREAK", "%d decoder/node mismatches: %s"
                % (len(mismatches), "; ".join(mismatches)))
    return ("HELD", "%d/%d decoder agrees with node v24.20.0"
            % (len(_NODE_EXPRS), len(_NODE_EXPRS)))


# ------------------------------------------------------------- P12: pin/footer
def p12_pin_footer():
    assert TAXONOMY_PIN == 2144, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    from gov import guac_graph  # noqa: E402
    # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    assert guac_graph.TAXONOMY_PIN == 2144, \
        "guac_graph.TAXONOMY_PIN=%r want 2144" % (guac_graph.TAXONOMY_PIN,)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F795**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**"  # wave-370 lane 4: F573/F578 CLOSED  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
              in text  # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583)
          and "**Status: CLOSED 2026-10-07 wave-369 lane 3**" in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P13: perf bound
def p13_perf_bound():
    # Hostile input: many string-spread / split / raw anchors -- must
    # starve fast (F452 lesson: fail-closed matches must consume scan
    # budget; the _MAX_WHOLETEXT_ATTEMPTS cap applies).
    junk = ("Reflect.apply([].concat.bind([],...'ab'),null,['cd']).join('')"
            "'ab,cd'.split(',').join('')"
            "String.raw({raw:['ab','cd']},'ef')") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor spread/split/raw corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w368_f551_redfirst.py",
    "evals/w368_f559_redfirst.py",
    "evals/w368_f564_redfirst.py",
    "evals/w367_f531close_probes.py",
    "evals/w368_f537f538f542close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g369lane3-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" %
                  (rel, line[-1] if line else "rc=%d" % r.returncode,
                   time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f551-filed", p1_f551_filed_shapes),
    ("p2-f551-variants", p2_f551_variants),
    ("p3-f551-bounds", p3_f551_bounds),
    ("p4-f559-filed", p4_f559_filed_shapes),
    ("p5-f559-variants", p5_f559_variants),
    ("p6-f559-bounds", p6_f559_bounds),
    ("p7-f564-filed", p7_f564_filed_shapes),
    ("p8-f564-variants", p8_f564_variants),
    ("p9-f564-bounds", p9_f564_bounds),
    ("p10-compositions", p10_compositions),
    ("p11-node-differential", p11_node_differential),
    ("p12-pin-footer", p12_pin_footer),
    ("p13-perf-bound", p13_perf_bound),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", default=None)
    args = parser.parse_args()
    breaks, held, errors = 0, 0, 0
    for name, fn in PROBES:
        if args.probe and args.probe != name:
            continue
        try:
            verdict, msg = fn()
        except Exception as e:  # noqa: BLE001
            verdict, msg = "ERROR", "%r" % e
        print("%-22s %s: %s" % (name, verdict, msg))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
        else:
            held += 1
    green_ok = green_check()
    print("tally: %d BREAK / %d HELD / %d ERROR%s" %
          (breaks, held, errors, "" if green_ok else " GREEN-FAIL"))
    return 1 if (breaks or errors or not green_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
