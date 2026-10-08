#!/usr/bin/env python3
"""Close battery for F615 (Map.values() spread into call arguments).

F615 (LOW, filed 2026-10-08 wave-373 attack round 41): F608 (CLOSED,
wave-373 lane 4) covers Set spread into call arguments, but the spread
SOURCE production matters per the F500/F505 precedent -- spreading
Map.values() is a different iterable source with no modeled path:
  ((...a)=>a.join(''))(...new Map([['a','f1'],['b','f2']]).values())
  ((a,b)=>a+b)(...new Map([['a','f1'],['b','f2']]).values())
  ((a,b)=>a+b).call(null,...new Map([['a','f1'],['b','f2']]).values())
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F608 (Set spread sources; F608's
filed shapes and close-when are Set-specific). Controls:
[...new Map([['a','f1'],['b','f2']]).values()].join('') blocks coded;
junk-quiet control passes.

Closed (wave-374 lane 4):
- `_js_parse_f615_mapspread_args`: `...new Map([[k,v],...]).values()`
  expands to the F494 later-wins insertion-ordered value list
  (delegates to `_js_parse_new_map_values`, so the
  plain-string-literal rule and F452 part/ops charging apply
  unchanged), recovering each surviving value's raw literal source
  text in values-iteration order (later-wins agreement asserted
  against the F494 `_JSArr`, fail-closed on divergence). Key
  identity mirrors the F494 validator (`("s", k)` / `("n", str(num))`
  per JS SameValueZero: string '0' and number 0 are distinct keys).
- F577's rest-param arrow-IIFE arg grammar extended: call args may be
  string literals, `...new Set([LITS])` spreads (F608), or
  `...new Map([[k,v],...]).values()` spreads (F615).
- `_js_parse_f608_fixed_arrow_spread_iife` extended the same way for
  fixed-param arrows `((P1,...,Pn)=>BODY)(ARGS)` /
  `((P1,...,Pn)=>BODY).call(T, ARGS)` with at least one spread arg.

Boundaries (all fail closed, never mis-decoded): bare Map spreads
(`...new Map(...)`); array spreads (`...['a']`); `.apply`; var-bound
Maps; non-literal keys or values; empty/malformed entry arrays;
arity shortfalls; named-leading-rest `(a,...r)` params;
`arguments`-named or duplicate params; `this`/`arguments`/`super`/
template-literal bodies; non-bare param uses; default params;
uninvoked arrows. (`.keys()`/`.entries()` spreads are F625-modeled
since wave-375 -- see the F625-takeover probe below.)

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
TAXONOMY_PIN = 2140

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def _msrc(pairs):
    return "new Map([%s]).values()" % pairs


def p1_filed_shapes_held():
    """F615 filed shapes now block coded."""
    shapes = [
        "((...a)=>a.join(''))(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        "((a,b)=>a+b)(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        "((a,b)=>a+b).call(null,...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Decoder variants of the filed shapes block coded."""
    shapes = [
        # later-wins: duplicate key, surviving order a->A1 (pos0), b->A2 (pos1)
        "((...a)=>a.join(''))(...%s)" % _msrc(
            "['a','%s'],['b','%s'],['a','%s']" % (_A, _B, _A)),
        "((a,b)=>a+b)(...%s)" % _msrc(
            "['a','%s'],['b','%s'],['a','%s']" % (_A, _B, _A)),
        "((a,b)=>a+b).call(null,...%s)" % _msrc(
            "['a','%s'],['b','%s'],['a','%s']" % (_A, _B, _A)),
        # numeric keys, incl. later-wins on a numeric duplicate
        "((a,b)=>a+b)(...%s)" % _msrc("[0,'%s'],[1,'%s']" % (_A, _B)),
        "((a,b)=>a+b)(...%s)" % _msrc(
            "[0,'%s'],[1,'%s'],[0,'%s']" % (_A, _B, _A)),
        # string '0' and number 0 are DISTINCT keys (SameValueZero)
        "((a,b)=>a+b)(...%s)" % _msrc(
            "['0','%s'],[0,'%s']" % (_A, _B)),
        # param order binds by position, not source order
        "((a,b)=>b+a)(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_B, _A)),
        # rest-param .call twin (F577 composition)
        "((...a)=>a.join('')).call(null,...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # .call with ident thisArg (F577 precedent: discarded)
        "((a,b)=>a+b).call(thisArg,...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # block body (F448 precedent)
        "((a)=>{return a+a;})(...%s)" % _msrc("['a','%s']" % _A),
        # ws-tolerant
        "(( a , b ) => a+b)( ...%s )" % _msrc(
            "[ 'a' , '%s' ] , [ 'b' , '%s' ]" % (_A, _B)),
        # mixed literal + spread args
        "((a,b,c)=>a+b+c)('xx',...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # extra args dropped engine-exactly
        "((a,b)=>a+b)(...%s)" % _msrc(
            "['a','%s'],['b','%s'],['c','zz']" % (_A, _B)),
        # double-quoted literals
        "((a,b)=>a+b)(...%s)" % _msrc(
            '[\"a\",\"%s\"],[\"b\",\"%s\"]' % (_A, _B)),
        # mixed body expression
        "((a,b)=>a+'-'+b)(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # three params
        "((a,b,c)=>a+b+c)(...%s)" % _msrc(
            "['a','%s'],['b','%s'],['c','zz']" % (_A, _B)),
        # hex numeric key
        "((a,b)=>a+b)(...%s)" % _msrc(
            "[0x0,'%s'],[0x1,'%s']" % (_A, _B)),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p2b_f625_takeover_blocked():
    """F625 (wave-375) takeover: `.keys()`/`.entries()` spreads now coded."""
    shapes = [
        # F625 (wave-375): `.keys()`/`.entries()` spreads are now
        # coded blocks, not misses -- the F625 takeover.
        "((a,b)=>a+b)(...%s)" % "new Map([['%s','x'],['%s','y']]).keys()"
        % (_A, _B),
        "((a,b)=>a[1]+b[1])(...%s)"
        % "new Map([['a','%s'],['b','%s']]).entries()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d F625-takeover shapes blocked" % (len(shapes) - len(bad),
                                                   len(shapes)))


def p3_fail_closed_boundaries():
    """Boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # wrong iterator / wrong spread source
        "((a)=>a)(...new Map([['a','%s']]))" % _A,
        "((a,b)=>a+b)(...['%s','%s'])" % (_A, _B),
        # var-bound Map (literal-only scope, documented residual)
        "(function(){var m=new Map([['a','%s'],['b','%s']]);"
        "return ((a,b)=>a+b)(...m.values());})()" % (_A, _B),
        # non-literal keys / values
        "((a)=>a)(...%s)" % _msrc("[x,'%s']" % _A),
        "((a)=>a)(...%s)" % _msrc("['a',x]"),
        # negative numeric keys: the F494 validator itself rejects
        # them, so both Map.values() consumers stay quiet together
        "((a,b)=>a+b)(...%s)" % _msrc("[-1,'%s'],[2,'%s']" % (_A, _B)),
        # empty / malformed entry arrays
        "((a)=>a)(...%s)" % _msrc(""),
        "((a)=>a)(...%s)" % _msrc("['a']"),
        "((a)=>a)(...%s)" % _msrc("['a','%s','zz']" % _A),
        # .apply (documented residual, F614's family)
        "((a,b)=>a+b).apply(null,...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # arity shortfall (engine coerces undefined -- never guessed)
        "((a,b,c)=>a+b+c)(...%s)" % _msrc("['a','%s']" % _A),
        # named-leading-rest belongs to no production (F577 residual)
        "((a,...r)=>a)(...%s)" % _msrc("['a','%s']" % _A),
        # arguments-named / duplicate params
        "((arguments)=>arguments)(...%s)" % _msrc("['a','%s']" % _A),
        "((a,a)=>a)(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)),
        # lexically-scoped names in body
        "((a)=>this+a)(...%s)" % _msrc("['a','%s']" % _A),
        "((a)=>arguments[0]+a)(...%s)" % _msrc("['a','%s']" % _A),
        # template literal body
        "((a)=>`x`+a)(...%s)" % _msrc("['a','%s']" % _A),
        # non-bare param uses (params are strings in the engine)
        "((a)=>a[0])(...%s)" % _msrc("['a','%s']" % _A),
        "((a)=>a.length)(...%s)" % _msrc("['a','%s']" % _A),
        "((a)=>a('x'))(...%s)" % _msrc("['a','%s']" % _A),
        # default params
        "((a='d')=>a)(...%s)" % _msrc("['a','%s']" % _A),
        # uninvoked arrow (no call)
        "((a,b)=>a+b)",
    ]
    bad = [s for s in shapes if not _quiet(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d boundaries quiet" % (len(shapes) - len(bad),
                                        len(shapes)))


def p4_node_differential():
    """Decoder verdict agrees with node v24.20.0 on every case."""
    cases = [
        # (js, node-yields-credential?)
        ("((...a)=>a.join(''))(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)), True),
        ("((a,b)=>a+b)(...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)), True),
        ("((a,b)=>a+b).call(null,...%s)" % _msrc(
            "['a','%s'],['b','%s']" % (_A, _B)), True),
        # later-wins order is decoder-exact
        ("((...a)=>a.join(''))(...%s)" % _msrc(
            "['a','%s'],['b','%s'],['a','%s']" % (_A, _B, _A)), True),
        # open-neighbor controls: node does NOT yield the credential
        # (fail-closed shapes stay quiet)
        ("((a)=>a[0])(...%s)" % _msrc("['a','%s']" % _A), False),
        ("((a,b,c)=>a+b+c)(...%s)" % _msrc("['a','%s']" % _A), False),
        ("((a,b)=>a+b)(...%s)" % "new Map([['a','%s']]).keys()" % _A,
         False),
    ]
    js = "const R=[];\n" + "\n".join(
        "try{R.push(eval(%s)===%s)}catch(e){R.push('err')}"
        % (repr(c), repr(_CRED)) for c, _ in cases) + \
        "\nconsole.log(JSON.stringify(R));"
    r = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                       timeout=60)
    import json as _json
    node_truth = _json.loads(r.stdout.strip())
    bad = []
    for (c, want), truth in zip(cases, node_truth):
        dec_hit = _blocked(c)
        agree = (truth is True) == want and dec_hit == want
        if not agree:
            bad.append(c[:60])
    # value-level: decoded value is node-exact, not just flagged
    val_cases = [
        ("((a,b)=>a+'-'+b)(...%s)" % _msrc("['x','b'],['y','a']"),
         "b-a"),
        ("((...a)=>a.join(''))(...%s)" % _msrc(
            "['k','x'],['k','y'],['j','z']"), "yz"),
        ("((a,b)=>a+b)(...%s)" % _msrc("['0','x'],[0,'y']"), "xy"),
        ("((a)=>a+a)(...%s)" % _msrc("['q','q']"), "qq"),
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


def _open_neighbor_shapes():
    """Filed shapes of the still-OPEN round-42 findings (must stay BREAK).

    Imported from their red-first batteries: F621-F634 except F625
    (this lane closes F625 -- its own shapes now block by design).
    This lane must not absorb them. (Wave-374 merge: F612-F620 are
    now CLOSED.)
    """
    import importlib
    shapes = []
    for fnum in (621, 622, 623, 624, 626, 627, 628, 629, 630, 631,
                 632, 633, 634):
        mod = importlib.import_module("w374_f%d_redfirst" % fnum)
        for name, payload, recovers in mod.SHAPES:
            if recovers:
                shapes.append((fnum, name, payload))
    return shapes
def p5_compositions():
    """Neighbor closures stay HELD; open neighbors still BREAK."""
    held = [
        # F608 (Set spread into call args) stays HELD
        "((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B),
        "((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B),
        # F600 (Map keys iteration) stays HELD
        "Array.from(new Map([['%s',1],['%s',2]]).keys()).join('')"
        % (_A, _B),
        # F494/F598 (Map.values array spread) stays HELD
        "[...new Map([['a','%s'],['b','%s']]).values()].join('')"
        % (_A, _B),
        # F577 (rest-param arrow, literal args) stays HELD
        "((...a)=>a.join(''))('%s','%s')" % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    bad_open = []
    for fnum, name, payload in _open_neighbor_shapes():
        if _blocked(payload):
            bad_open.append("F%d/%s" % (fnum, name))
    bad = bad_held + bad_open
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions ok" % (len(held) + len(_open_neighbor_shapes())
                                       - len(bad),
                                       len(held) +
                                       len(_open_neighbor_shapes())))


def p6_honest_text_quiet():
    """Honest text stays quiet."""
    texts = [
        "the meeting notes mention spreading map values into calls",
        "forward the map's value iterator into the function arguments",
        "use new Map entries to configure the request parameters",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad), len(texts)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F615 closed, next F621."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-08 wave-374 lane 4" in text
                 and "Open findings: F640, F641, F642, F643." in text  # Wave-374 lane 4: F615 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
                 and "Next free finding: **F644**" in text)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640
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
    scripts = ("w373_f615_redfirst.py",
               "w373_f608close_probes.py",
               "w373_attack_probes.py",
               "w372_attack_probes.py",
               "w370_f570f577close_probes.py",
               "w372_f600f601f602close_probes.py")
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
    probes = [p1_filed_shapes_held, p2_variants_held, p2b_f625_takeover_blocked,
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
