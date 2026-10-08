#!/usr/bin/env python3
"""Close battery for F608 (Set spread into call arguments).

F608 (LOW, filed 2026-10-07 wave-372 attack round 40 as F607, renumbered
at the wave-372 merge per the wave-272 rule -- lane 3 filed F606 first
at 02:24 UTC, the attack filed at 02:48 UTC): F602's filed entry
documents the [...new Set(...)] ARRAY spread as modeled (blocks coded),
but spreading a Set into CALL ARGUMENTS is a different dispatch shape
with no modeled path:
  ((...a)=>a.join(''))(...new Set(['f1','f2']))
  ((a,b)=>a+b)(...new Set(['f1','f2']))
  ((a,b)=>a+b).call(null,...new Set(['f1','f2']))
all node-evaluate to the exact credential (v24.20.0) while the decoder
produced zero variants. Distinct from F602 (Set iteration, CLOSED
wave-372 lane 4), F516 (arguments laundering, CLOSED), F541
(Reflect.apply spread argsArray, CLOSED), and F471 (array-copy
factories, CLOSED). Controls: [...new Set(['f1','f2'])].join('')
blocks coded; junk-quiet control passes.

Closed (wave-373 lane 4):
- `_js_parse_f608_setspread_args`: `...new Set([LITS])` expands to the
  F602 SameValueZero-deduped insertion-ordered element list (delegates
  to `_js_parse_f602_set_elements`, so the F494 plain-string-literal
  rule and F452 part charging apply unchanged), recovering each
  element's raw literal source text in dedupe order (dedupe agreement
  asserted, fail-closed on divergence).
- F577's rest-param arrow-IIFE arg grammar extended: call args may be
  string literals or `...new Set([LITS])` spreads (node-exact: f(...set)
  spreads iteration order), bound through `_js_bind_iife_arguments`
  with member_ok=True exactly as before.
- New `_js_parse_f608_fixed_arrow_spread_iife`: fixed-param arrows
  `((P1,...,Pn)=>BODY)(ARGS)` / `((P1,...,Pn)=>BODY).call(T, ARGS)`
  with at least one Set-spread arg; params bind positionally via
  `_js_bind_destructure_arguments` (bare-ident use only -- a param is
  a STRING value in the engine, so `a[0]`/`a.M`/`a(` fail closed);
  extra args dropped engine-exactly; fewer args than params fail
  closed (the F524 discipline). The `.call` thisArg is parsed and
  discarded (F577 precedent: the engine ignores it for arrows).

Boundaries (all fail closed, never mis-decoded): pure-literal
fixed-param arrow IIFEs (unfiled residual, documented); non-Set
spreads (`...['a']`, `...ident`); Map spreads (CLOSED 2026-10-08
wave-374 lane 4 as F615 -- Map.values() spreads now modeled);
`.apply`;
named-leading-rest `(a,...r)` params; `arguments`-named or duplicate
params; non-bare param uses (`a[0]`, `a.M`, `a(`); `this`/`arguments`/
`super`/template-literal bodies; non-literal Set members; arity
shortfalls.

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


def p1_filed_shapes_held():
    """F608 filed shapes now block coded."""
    shapes = [
        "((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B),
        "((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B),
        "((a,b)=>a+b).call(null,...new Set(['%s','%s']))" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


def p2_variants_held():
    """Decoder variants of the filed shapes block coded."""
    shapes = [
        # dedupe + insertion order (SameValueZero, first wins)
        "((...a)=>a.join(''))(...new Set(['%s','%s','%s']))"
        % (_A, _A, _B),
        "((a,b)=>a+b)(...new Set(['%s','%s','%s']))" % (_A, _A, _B),
        # param order binds by position, not source order
        "((a,b)=>b+a)(...new Set(['%s','%s']))" % (_B, _A),
        # rest-param .call twin (F577 composition)
        "((...a)=>a.join('')).call(null,...new Set(['%s','%s']))"
        % (_A, _B),
        # .call with ident thisArg (F577 precedent: discarded)
        "((a,b)=>a+b).call(thisArg,...new Set(['%s','%s']))" % (_A, _B),
        # block body (F448 precedent)
        "((a)=>{return a+a;})(...new Set(['%s']))" % _A,
        # ws-tolerant
        "(( a , b ) => a+b)( ...new Set( [ '%s' , '%s' ] ) )" % (_A, _B),
        # mixed literal + spread args
        "((a,b,c)=>a+b+c)('xx',...new Set(['%s','%s']))" % (_A, _B),
        # extra args dropped engine-exactly
        "((a,b)=>a+b)(...new Set(['%s','%s','zz']))" % (_A, _B),
        # double-quoted literals
        "((a,b)=>a+b)(...new Set([\"%s\",\"%s\"]))" % (_A, _B),
        # mixed body expression
        "((a,b)=>a+'-'+b)(...new Set(['%s','%s']))" % (_A, _B),
        # three params
        "((a,b,c)=>a+b+c)(...new Set(['%s','%s','%s']))"
        % (_A, _B, "zz"),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad),
                                        len(shapes)))


def p3_fail_closed_boundaries():
    """Boundaries fail closed: no variant, never mis-decoded."""
    shapes = [
        # non-Set spreads
        "((a,b)=>a+b)(...['%s','%s'])" % (_A, _B),
        "((a,b)=>a+b)(...new Map([['k','%s']]))" % _A,
        # .apply (documented residual)
        "((a,b)=>a+b).apply(null,...new Set(['%s','%s']))" % (_A, _B),
        # arity shortfall (engine coerces undefined -- never guessed)
        "((a,b,c)=>a+b+c)(...new Set(['%s','%s']))" % (_A, _B),
        # pure-literal fixed-param call (unfiled residual, documented)
        "((a,b)=>a+b)('%s','%s')" % (_A, _B),
        # named-leading-rest belongs to no production (F577 residual)
        "((a,...r)=>a)(...new Set(['%s']))" % _A,
        # rest param rejected by the F608 production (F577 owns it,
        # but F577 needs literal args -- the spread form is unmodeled
        # there for mixed param lists; stays quiet)
        # arguments-named / duplicate params
        "((arguments)=>arguments)(...new Set(['%s']))" % _A,
        "((a,a)=>a)(...new Set(['%s','%s']))" % (_A, _B),
        # lexically-scoped names in body
        "((a)=>this+a)(...new Set(['%s']))" % _A,
        "((a)=>arguments[0]+a)(...new Set(['%s']))" % _A,
        # template literal body
        "((a)=>`x`+a)(...new Set(['%s']))" % _A,
        # non-bare param uses (params are strings in the engine)
        "((a)=>a[0])(...new Set(['%s']))" % _A,
        "((a)=>a.length)(...new Set(['%s']))" % _A,
        "((a)=>a('x'))(...new Set(['%s']))" % _A,
        # non-literal Set members
        "((a)=>a)(...new Set([x]))",
        "((a)=>a)(...new Set(['%s',1]))" % _A,
        # default params
        "((a='d')=>a)(...new Set(['%s']))" % _A,
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
        ("((...a)=>a.join(''))(...new Set(['%s','%s']))" % (_A, _B),
         True),
        ("((a,b)=>a+b)(...new Set(['%s','%s']))" % (_A, _B), True),
        ("((a,b)=>a+b).call(null,...new Set(['%s','%s']))" % (_A, _B),
         True),
        ("((...a)=>a.join(''))(...new Set(['%s','%s','%s']))"
         % (_A, _A, _B), True),
        ("((a,b)=>a+b)(...new Set(['%s','%s','%s']))" % (_A, _A, _B),
         True),
        # open-neighbor controls: node does NOT yield the credential
        # (fail-closed shapes stay quiet)
        ("((a)=>a[0])(...new Set(['%s']))" % _A, False),
        ("((a,b,c)=>a+b+c)(...new Set(['%s','%s']))" % (_A, _B),
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
        ("((...a)=>a.join('-'))(...new Set(['b','a','b']))", "b-a"),
        ("((b,a)=>a+b)(...new Set(['x','y']))", "yx"),
        ("((a,b)=>a+b)(...new Set(['x','y','z']))", "xy"),
        ("((a)=>a+a)(...new Set(['q']))", "qq"),
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
        # F602 (Set iteration) stays HELD
        "(function(){var s='';for(var x of new Set(['%s','%s'])){s+=x;}"
        "return s;})()" % (_A, _B),
        # F471/F494 (array spread of Set) stays HELD
        "[...new Set(['%s','%s'])].join('')" % (_A, _B),
        # F577 (rest-param arrow, literal args) stays HELD
        "((...a)=>a.join(''))('%s','%s')" % (_A, _B),
        # F516 (arguments laundering) stays HELD
        "(function(){return arguments[0]+arguments[1];})('%s','%s')"
        % (_A, _B),
    ]
    bad_held = [s for s in held if not _blocked(s)]
    # F606 (USP mutation guards), F607 (filter predicates), F609 (replace
    # function) all CLOSED wave-373 lanes 2/3/5 -- they must now BLOCK.
    # (wave-306: open-neighbor lists updated after sibling closures)
    must_block = [
        # F606: USP mutation guards (CLOSED wave-373 lane 2)
        "(function(){var p=new URLSearchParams('q=%s');"
        "p.append('q','%s');p.sort();"
        "return p.getAll('q').join('');})()" % (_A, _B),
        # F607: filter with non-trivial predicates (CLOSED wave-373 lane 3)
        "['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A, _B),
        # F609: replace with function replacements (CLOSED wave-373 lane 5)
        "'%sXX'.replace('XX',()=>'%s')" % (_A, _B),
    ]
    bad_block = [s for s in must_block if not _blocked(s)]
    bad = bad_held + bad_block
    return ("HELD" if not bad else "BREAK",
            "%d/%d compositions ok" % (len(held) + len(must_block) - len(bad),
                                       len(held) + len(must_block)))


def p6_honest_text_quiet():
    """Honest text stays quiet."""
    texts = [
        "the meeting notes mention set spread into call arguments",
        "spread the iterable into the function call for forwarding",
        "use rest parameters to collect variadic arguments safely",
    ]
    bad = [t for t in texts if not _quiet(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad), len(texts)))


def p7_pin_and_footer():
    """Pin 2140; footer shows F608 closed, next F612."""
    n = len(decision_codes.TAXONOMY)
    pin_ok = (TAXONOMY_PIN == 2140 and n == 2140)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        text = fh.read()
    footer_ok = ("CLOSED 2026-10-08 wave-373 lane 4" in text
                 and "Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654." in text  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 lane 4: F615 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
                 and "Next free finding: **F655**" in text)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
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
    scripts = ("w372_f608_redfirst.py",
               "w371_attack_probes.py",
               "w372_attack_probes.py",
               "w370_f570f577close_probes.py",
               "w372_f600f601f602close_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g373-green-%s-%d" % (script.replace(".py", ""),
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
