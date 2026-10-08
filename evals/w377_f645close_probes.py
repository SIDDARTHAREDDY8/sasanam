#!/usr/bin/env python3
"""Wave-377 lane 2: close F645 -- function default-parameter fragment assembly.

F645 (LOW, filed 2026-10-08, attack round 44, local node validation,
$0 spend): function default-parameter fragment assembly (no-arg IIFE)
bypassed the bounded static JS-expression decoder. F612 (CLOSED)
documents 'named functions/params' as a fail-closed residual of its
var-binding production, but default parameter values in a no-arg IIFE
are a distinct binding production with no modeled path:
(function(s='f1',t='f2'){return s+t;})(), the explicit-undefined twin
(function(s='f1',t='f2'){return s+t;})(undefined,undefined), and the
destructured-default twin
(function({a,b}={a:'f1',b:'f2'}){return a+b;})() all node-evaluated to
the exact credential (v24.20.0) while the decoder produced zero
variants.

Closure (gov/dlp.py, F645): _js_parse_f645_params parses the
default-parameter list (`IDENT='LIT'`, bare idents bound to the
string "undefined" -- node-exact for the string-only body, object
patterns `{a,b}={k:'LIT',...}`); _js_parse_f645_default_param_iife
parses `(function(PARAMS){return ADD;})()` /
`(...)(undefined, ...)`; _js_parse_f645_default_param_arrow_iife
parses the arrow twin `((PARAMS)=>ADD)()` (same mechanism,
node-verified, disjoint from F577/F608). Node-exact (v24.20.0):
defaults apply for `undefined`/missing args; extra `undefined` args
ignored; duplicate param names are a SyntaxError (fail closed);
non-`undefined` args fail closed (the documented F612 'non-empty
call args' residual -- the with-args twin stays missed). Hooked
after F612 (disjoint: F612 requires the empty param list) and before
F577 (disjoint: F577 requires `...rest`, F608 requires Set-spread
args). Zero new re.compile (plain-text scanning only).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g377-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_C = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(payload):
    """Exact decoded value via the F645 IIFE parsers (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    for fn in (_dlp._js_parse_f645_default_param_iife,
               _dlp._js_parse_f645_default_param_arrow_iife):
        r = fn(payload, 0, 0, dict(state))
        if r is not None:
            val, _ = r
            return val if isinstance(val, str) else None
    return None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_noarg():
    """(function(s='f1',t='f2'){return s+t;})() blocks, exact decode."""
    p = "(function(s='%s',t='%s'){return s+t;})()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s exact=%s" % (_blocked(p), _decode_exact(p) == _C))


def test_p1_filed_undefined_args():
    """(function(s='f1',t='f2'){return s+t;})(undefined,undefined) blocks."""
    p = "(function(s='%s',t='%s'){return s+t;})(undefined,undefined)" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s exact=%s" % (_blocked(p), _decode_exact(p) == _C))


def test_p1_filed_destructured():
    """(function({a,b}={a:'f1',b:'f2'}){return a+b;})() blocks, exact."""
    p = "(function({a,b}={a:'%s',b:'%s'}){return a+b;})()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s exact=%s" % (_blocked(p), _decode_exact(p) == _C))


# ------------------------------------------------ variants (must block)

def test_p2_single_param():
    """(function(s='f1f2'){return s;})() blocks."""
    p = "(function(s='%s'){return s;})()" % _C
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_partial_undefined():
    """(function(s='f1',t='f2'){return s+t;})(undefined) blocks."""
    p = "(function(s='%s',t='%s'){return s+t;})(undefined)" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_extra_undefined_args():
    """(function(s='f1f2'){return s;})(undefined,undefined) blocks."""
    p = "(function(s='%s'){return s;})(undefined,undefined)" % _C
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_destructured_undefined():
    """(function({a,b}={a:'f1',b:'f2'}){return a+b;})(undefined) blocks."""
    p = "(function({a,b}={a:'%s',b:'%s'}){return a+b;})(undefined)" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_mixed_pattern_ident():
    """(function({a}={a:'f1'},b='f2'){return a+b;})() blocks."""
    p = "(function({a}={a:'%s'},b='%s'){return a+b;})()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_extra_default_key():
    """(function({a,b}={a:'f1',b:'f2',c:'zz'}){return a+b;})() blocks."""
    p = "(function({a,b}={a:'%s',b:'%s',c:'zz'}){return a+b;})()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_bare_param():
    """(function(s='f1f2',t){return s+t;})() blocks ('t' -> 'undefined')."""
    p = "(function(s='%s',t){return s+t;})()" % _C
    ok = _decode_exact(p) == _C + "undefined"
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_dquote():
    """Double-quoted defaults block."""
    p = '(function(s="%s",t="%s"){return s+t;})()' % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_ws():
    """Whitespace-tolerant form blocks."""
    p = "( function ( s = '%s' , t = '%s' ) { return s + t ; } ) ( )" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_trailing_comma():
    """(function(s='f1',t='f2',){return s+t;})() blocks (node-legal)."""
    p = "(function(s='%s',t='%s',){return s+t;})()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_arrow():
    """((s='f1',t='f2')=>s+t)() blocks (arrow twin, node-verified)."""
    p = "((s='%s',t='%s')=>s+t)()" % (_A, _B)
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_arrow_undefined():
    """((s='f1f2')=>s)(undefined) blocks."""
    p = "((s='%s')=>s)(undefined)" % _C
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


def test_p2_arrow_single():
    """((s='f1f2')=>s)() blocks."""
    p = "((s='%s')=>s)()" % _C
    ok = _blocked(p) and _decode_exact(p) == _C
    return ("HELD" if ok else "BREAK", "hit=%s" % _blocked(p))


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_with_args_twin():
    """(function(s,t='f2'){return s+t;})('f1') misses (F612 residual)."""
    miss = _decode_exact("(function(s,t='%s'){return s+t;})('%s')" % (_B, _A)) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_call_twin():
    """(function(s='f1f2'){return s;}).call(null) misses (residual)."""
    miss = _decode_exact("(function(s='%s'){return s;}).call(null)" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_array_pattern():
    """(function([x,y]=['f1','f2']){return x+y;})() misses (residual)."""
    miss = _decode_exact("(function([x,y]=['%s','%s']){return x+y;})()" % (_A, _B)) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_rest_param():
    """(function(s='f1f2',...r){return s;})() misses."""
    miss = _decode_exact("(function(s='%s',...r){return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_template_default():
    """(function(s=`f1f2`){return s;})() misses."""
    miss = _decode_exact("(function(s=`%s`){return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_named_function():
    """(function foo(s='f1f2'){return s;})() misses (F612 precedent)."""
    miss = _decode_exact("(function foo(s='%s'){return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_non_undefined_arg():
    """(function(s='f1f2'){return s;})('junk') misses."""
    miss = _decode_exact("(function(s='%s'){return s;})('junk')" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_null_arg():
    """(function(s='f1f2'){return s;})(null) misses (null != undefined)."""
    miss = _decode_exact("(function(s='%s'){return s;})(null)" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_duplicate_param():
    """(function(s='a',s='b'){return s;})() misses (engine SyntaxError)."""
    miss = _decode_exact("(function(s='a',s='b'){return s;})()") is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_unbound_body_ident():
    """(function(s='f1f2'){return s+t;})() misses (engine ReferenceError)."""
    miss = _decode_exact("(function(s='%s'){return s+t;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_proto_key():
    """__proto__ default key misses."""
    miss = _decode_exact("(function({a}={__proto__:{x:1},a:'%s'}){return a;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_quoted_key():
    """Quoted default key misses (ident-only)."""
    miss = _decode_exact("(function({a}={'a':'%s'}){return a;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_extra_statement():
    """Extra statement before return misses."""
    miss = _decode_exact("(function(s='%s'){var x=1;return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_default_refs_earlier():
    """(function(a='f1',b=a+'f2'){return b;})() misses (non-literal default)."""
    miss = _decode_exact("(function(a='%s',b=a+'%s'){return b;})()" % (_A, _B)) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_arrow_block_body():
    """((s='f1f2')=>{return s;})() misses (block body)."""
    miss = _decode_exact("((s='%s')=>{return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_arrow_call():
    """((s='f1f2')=>s).call(null) misses (residual)."""
    miss = _decode_exact("((s='%s')=>s).call(null)" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_this_operand():
    """(function(s='f1f2'){return s+this;})() misses."""
    miss = _decode_exact("(function(s='%s'){return s+this;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_generator():
    """(function*(s='f1f2'){yield s;})() misses."""
    miss = _decode_exact("(function*(s='%s'){yield s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_async():
    """(async function(s='f1f2'){return s;})() misses."""
    miss = _decode_exact("(async function(s='%s'){return s;})()" % _C) is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_nested_pattern():
    """(function({a:{b}}={a:{b:'x'}}){return b;})() misses."""
    miss = _decode_exact("(function({a:{b}}={a:{b:'x'}}){return b;})()") is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def test_p3_number_default():
    """(function(s=1){return s;})() misses (non-string default)."""
    miss = _decode_exact("(function(s=1){return s;})()") is None
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------ neighbors (still miss / still hold)

def test_p4_f644_still_misses():
    """F644 CLOSED (wave-377 lane 1): destructuring of literal sources now blocks."""
    hit = _blocked("(function(){var {a,b}={a:'%s',b:'%s'};return a+b;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p4_f646_still_misses():
    """F646 CLOSED (wave-377 lane 3): Array.forEach accumulation now blocks."""
    hit = _blocked("(function(){var s='';['%s','%s'].forEach(function(x){s+=x;});return s;})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p4_f652_still_misses():
    """F652 CLOSED (wave-377 lane 4): additive-position comma expressions now block."""
    hit = _blocked("(function(){var x;return (x='%s',x)+'%s';})()" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


def test_p4_f661_closed_by_sibling():
    """F661 CLOSED by wave-378 lane 6: declaration-position comma sequences now block."""
    blocked = not _misses("(function(){var s=('jx','%s');return s+'%s';})()" % (_A, _B))
    return ("HELD" if blocked else "BREAK", "block=%s" % blocked)


def test_p4_f612_still_blocks():
    """F612 CLOSED (var-bound values) still blocks."""
    ok = _blocked("(function(){var o={a:'%s',b:'%s'};return Object.values(o).join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p4_f577_still_blocks():
    """F577 CLOSED (arrow rest params) still blocks."""
    ok = _blocked("((...a)=>a[0]+a[1])('%s','%s')" % (_A, _B))
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ junk-quiet

def test_p5_junk_quiet():
    """Junk defaults stay quiet."""
    miss = _misses("(function(s='jx',t='jy'){return s+t;})()")
    miss = miss and _misses("((s='jx')=>s)()")
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


# ------------------------------------------------ composition

def test_p6_postfix_concat():
    """F645 decode feeds the postfix chain: (...)+'-tail' blocks."""
    p = "(function(s='%s'){return s;})()+'-tail'" % _C
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def test_p6_nested_parens():
    """F645 inside a parenthesized additive blocks."""
    p = "('x'+(function(s='%s'){return s;})())" % _C
    ok = _blocked(p)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ node differential (spot)

def test_p7_node_exact():
    """Internal-seam decodes match node on the filed shapes."""
    import json as _json
    import subprocess as _sp
    shapes = [
        "(function(s='%s',t='%s'){return s+t;})()" % (_A, _B),
        "(function({a,b}={a:'%s',b:'%s'}){return a+b;})()" % (_A, _B),
        "((s='%s')=>s)()" % _C,
    ]
    with open("/tmp/g377-f645-node.json", "w") as f:
        _json.dump(shapes, f)
    code = ('const fs=require("fs");const ps=JSON.parse('
            'fs.readFileSync("/tmp/g377-f645-node.json","utf8"));'
            'for(const p of ps){console.log(JSON.stringify(eval(p)));}')
    r = _sp.run(["node", "-e", code], capture_output=True, text=True)
    vals = r.stdout.splitlines()
    bad = []
    for shape, nv in zip(shapes, vals):
        if _json.loads(nv) != _decode_exact(shape):
            bad.append(shape[:40])
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % bad)


# ------------------------------------------------ pin + footer

def test_p8_pin_and_footer():
    """Pin 2143 and merge footer (open F655-F660; next F661)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    pin_ok = TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    next_ok = "Next free finding: **F762**" in text  # Wave-377 lane 2  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    open_ok = "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text  # Wave-377 merge: F644-F654 CLOSED; F655-F660 OPEN  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    closed_ok = "**Status: CLOSED 2026-10-08 wave-377 lane 2.**" in text
    ok = pin_ok and next_ok and open_ok and closed_ok
    return ("HELD" if ok else "BREAK",
            "pin=%s next=%s open=%s closed=%s" % (pin_ok, next_ok, open_ok, closed_ok))


# ------------------------------------------------ perf

def test_p9_perf():
    """200 F645 sites decode in well under the budget."""
    p = "(function(s='%s',t='%s'){return s+t;})()" % (_A, _B)
    blob = ("var x='%s';" % _A) + p * 200
    t0 = time.time()
    _blocked(blob)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ green check

def test_p10_green_check():
    """Depth-1 green check: F645 red-first + wave-376 attack battery."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w376_f645_redfirst.py", 0),
                               ("evals/w376_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g377-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        _t(name, globals()[name])
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
