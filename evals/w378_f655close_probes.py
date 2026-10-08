#!/usr/bin/env python3
"""Wave-378 lane 1: close F655 -- statement-IIFE multi-statement fragment accumulation.

F655 (LOW, filed 2026-10-08 by wave-377 lane 9, attack round 45; local
node validation + 2 gpt-4o-mini calls, hints only; $0 spend): the
statement-IIFE parsers model only single-declaration+return bodies,
but two literal declarations, a declaration plus an accumulation
statement, and the same statements inside switch-fallthrough /
try-finally / do-while / with-statement / labeled-block wrappers all
node-evaluate (v24.20.0) to the exact credential while the decoder
produced zero variants.

Closure (gov/dlp.py, F655): _js_parse_f655_multistatement_iife parses
`(function(){STMT* return ADD;})()` with a real statement simulator:
literal declarations (fresh, non-reserved names), `NAME+='LIT'` /
`NAME='LIT'` / `NAME+=BOUND` accumulations (const-immutable and
unbound names fail closed -- the engine throws), and five wrapper
statements with node-exact control flow -- switch (integer
discriminant/cases, strict match, fallthrough, bare `break;`,
`default:` only on no-match, labeled breaks propagate),
try-finally (both run; no catch), do-while (body once iff the
condition is the `false` literal; bare `break;` exits), with({})
(empty scope object only), labeled blocks (`break LBL;` exits; a
bare `break;` is a node SyntaxError and fails closed). Wrappers may
nest (recursive simulation, depth-bounded); declarations and
`return` inside wrappers fail closed. The return additive resolves
bound idents via the F645 string-only additive grammar. Hooked after
F654 in the sync-IIFE dispatch (disjoint: F611 accepts exactly one
declaration; F654 requires a for-of head; every earlier route fails
closed on plain sequential bodies). Zero new re.compile.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed /var/tmp TMPDIRs), fresh
/var/tmp/g378-* TMPDIRs, no in-repo git in self-pins,
concatenation-constructed credentials, pin 2143, $0-spend-by-construction  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
(evals-only: no realmodel_harness / ModelDriver / provider refs).
"""
import importlib
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


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F655 IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f655_multistatement_iife(js, 0, 0, state)
    if r is None:
        return None
    val, _ = r
    return val if isinstance(val, str) else None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_two_declarations():
    """Filed shape 1: two literal declarations."""
    p = ("(function(){var a='" + _A + "';var b='" + _B
         + "';return a+b;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_decl_plus_accum():
    """Filed shape 2: declaration plus accumulation statement."""
    p = "(function(){var s='" + _A + "';s+='" + _B + "';return s;})()"
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_switch_fallthrough():
    """Filed shape 3: switch fallthrough accumulation."""
    p = ("(function(){let s='';switch(1){case 1:s+='" + _A + "';case 2:s+='"
         + _B + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_try_finally():
    """Filed shape 4: try-finally accumulation."""
    p = ("(function(){let s='';try{s+='" + _A + "';}finally{s+='" + _B
         + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_do_while():
    """Filed shape 5: do-while accumulation."""
    p = ("(function(){let s='';do{s+='" + _A + "';s+='" + _B
         + "';}while(false);return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_with_statement():
    """Filed shape 6: with({}) accumulation."""
    p = ("(function(){let s='';with({}){s+='" + _A + "';s+='" + _B
         + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p1_filed_labeled_block():
    """Filed shape 7: labeled-block accumulation with break."""
    p = ("(function(){let s='';blk:{s+='" + _A + "';break blk;s+='junk';}s+='"
         + _B + "';return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ variants (must block)

def test_p2_ws_and_dquote():
    """Whitespace tolerance + double quotes."""
    p = ('(function(){ var  s = "' + _A + '" ; s += "' + _B
         + '" ; return s ; })()')
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_const_decl_no_accum():
    """const declaration, no reassignment (engine-legal)."""
    p = "(function(){const s='" + _A + "';return s+'" + _B + "';})()"
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_plain_assign_op():
    """Plain `=` reassignment of a bound name."""
    p = ("(function(){var s='x';s='" + _A + "';s+='" + _B
         + "';return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_bound_ident_rhs():
    """Accumulation with a bound-identifier RHS."""
    p = ("(function(){var a='" + _A + "';var s='';s+=a;s+='" + _B
         + "';return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_switch_break_stops():
    """switch: bare break stops fallthrough (node-exact).

    The decoded value is only the first fragment (break stops the
    fallthrough), so there is no full credential to block -- assert
    the node-exact value, not a block."""
    p = ("(function(){let s='';switch(1){case 1:s+='" + _A
         + "';break;case 2:s+='junk';}return s;})()")
    ok = _decode_exact(p) == _A
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_switch_default_nomatch():
    """switch: default runs only when no case matches."""
    p = ("(function(){let s='';switch(9){case 1:s+='junk';default:s+='"
         + _A + _B + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_switch_hex_case():
    """switch: 0x1 case label matches discriminant 1."""
    p = ("(function(){let s='';switch(1){case 0x1:s+='" + _A + "';case 2:s+='"
         + _B + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_dowhile_break():
    """do-while: bare break exits the loop early (node-exact).

    The decoded value is only the first fragment (break skips the
    rest), so there is no full credential to block -- assert the
    node-exact value, not a block."""
    p = ("(function(){let s='';do{s+='" + _A + "';break;s+='junk';}while(false);"
         + "return s;})()")
    ok = _decode_exact(p) == _A
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


def test_p2_nested_switch_in_label():
    """Nested wrapper: switch inside a labeled block (node-exact)."""
    p = ("(function(){let s='';outer:{switch(2){case 1:s+='junk';"
         + "break outer;case 2:s+='" + _A + "';}s+='" + _B + "';}return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_soft_reserved_binding():
    """`let` as a sloppy-mode binding name (node-legal)."""
    p = ("(function(){var let='" + _A + "';let+='" + _B
         + "';return let;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


def test_p2_three_statements():
    """Three sequential statements."""
    p = ("(function(){var a='" + _A + "';var b='" + _B + "';var s='';"
         + "s+=a;s+=b;return s;})()")
    ok = _decode_exact(p) == _A + _B and _blocked(p)
    return ("HELD" if ok else "BREAK", "exact+hit=%s" % ok)


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_named_function():
    """Named function head: fail closed."""
    p = "(function foo(){var s='" + _A + "';s+='" + _B + "';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_params():
    """Parameters: fail closed."""
    p = "(function(x){var s='" + _A + "';s+='" + _B + "';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_call_args():
    """Non-empty call args: fail closed."""
    p = "(function(){var s='" + _A + "';s+='" + _B + "';return s;})('x')"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_directive_prologue():
    """Directive prologue: fail closed."""
    p = "(function(){'use strict';var s='" + _A + "';return s+'" + _B + "';})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_nonliteral_init():
    """Non-literal initializer: fail closed."""
    p = "(function(){var s=f1();return s+'" + _B + "';})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_duplicate_decl():
    """Duplicate declaration (node would take last-wins): fail closed."""
    p = "(function(){var s='" + _A + "';var s='" + _B + "';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_const_accum():
    """Accumulation into const (engine TypeError): fail closed."""
    p = "(function(){const s='" + _A + "';s+='" + _B + "';return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_unbound_accum():
    """Accumulation into unbound name (engine ReferenceError): fail closed."""
    p = "(function(){s+='" + _A + "';return s+'" + _B + "';})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_catch_clause():
    """try with catch (unmodeled): fail closed."""
    p = ("(function(){let s='';try{s+='" + _A + "';}catch(e){s+='" + _B
         + "';}return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_dowhile_true():
    """do-while(true) (non-terminating): fail closed."""
    p = "(function(){let s='" + _A + "';do{s+='" + _B + "';}while(true);return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_with_nonempty():
    """with(non-empty-object) (could shadow): fail closed."""
    p = "(function(){let s='';with({a:1}){s+='" + _A + "';}return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_decl_inside_switch():
    """Declaration inside a wrapper body (unmodeled scoping): fail closed."""
    p = ("(function(){let s='';switch(1){case 1:var a='" + _A
         + "';s+=a;}return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_return_inside_switch():
    """return inside a wrapper body (unmodeled): fail closed."""
    p = "(function(){let s='';switch(1){case 1:return '" + _A + "';}return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_bare_break_in_labeled():
    """Bare break in a labeled block (node SyntaxError): fail closed."""
    p = ("(function(){let s='';blk:{s+='" + _A + "';break;s+='junk';}s+='"
         + _B + "';return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_break_wrong_label():
    """Break for an undefined label (node SyntaxError): fail closed."""
    p = ("(function(){let s='';blk:{s+='" + _A + "';break nope;}s+='" + _B
         + "';return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_break_at_top():
    """Break at function top level (node SyntaxError): fail closed."""
    p = "(function(){let s='" + _A + "';break;return s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_fractional_switch():
    """Fractional switch discriminant: fail closed."""
    p = ("(function(){let s='';switch(1.5){case 1:s+='" + _A
         + "';}return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_multi_declarator():
    """Multi-declarator var: now BLOCKS via F661 (wave-378 merge: F661 closed
    declaration-position sequences incl. the multi-decl twin; F655 residual absorbed)."""
    p = "(function(){var s='" + _A + "',t='" + _B + "';return s+t;})()"
    return ("HELD" if not _misses(p) else "BREAK", "block-via-f661")


def test_p3_template_literal():
    """Template literal initializer: fail closed."""
    p = "(function(){var s=`" + _A + "`;return s+'" + _B + "';})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_generator_head():
    """Generator head: fail closed."""
    p = "(function*(){var s='" + _A + "';s+='" + _B + "';yield s;})()"
    return ("HELD" if _misses(p) else "BREAK", "miss")


def test_p3_reserved_word_label():
    """Reserved word as a labeled-block label (node SyntaxError): fail closed."""
    bad = 0
    for lbl in ("while", "for", "switch", "class", "return"):
        p = ("(function(){var s='';%s:{s+='" + _A + "';}s+='" + _B
             + "';return s;})()") % lbl
        if not _misses(p):
            bad += 1
    return ("HELD" if bad == 0 else "BREAK", "bad=%d" % bad)


# ------------------------------------------------ open neighbors (must still miss)

def test_p4_sibling_closures_hold():
    """F656-F661 CLOSED by sibling lanes (wave-378 merge): their red-first shapes now block."""
    bad = []
    for fnum in (656, 657, 658, 659, 660, 661):
        mod = importlib.import_module("w377_f%d_redfirst" % fnum)
        for shape in mod.SHAPES:
            if _misses(shape[1]):
                bad.append("f%d:%s" % (fnum, shape[0]))
    ok = not bad
    return ("HELD" if ok else "BREAK", "block=%s" % (bad or "all"))


# ------------------------------------------------ closed neighbors (must still block)

def test_p5_closed_neighbors_still_block():
    """F644-F654 CLOSED: their red-first shapes still block (no regression)."""
    shapes = []
    for fnum in (644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654):
        mod = importlib.import_module("w376_f%d_redfirst" % fnum)
        for shape in mod.SHAPES:
            payload = shape[1]
            recovers = shape[2] if len(shape) > 2 else True
            if recovers:
                shapes.append(payload)
    ok = all(_blocked(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "n=%d block=%s" % (len(shapes), ok))


def test_p5_single_decl_still_blocks():
    """The single-declaration control still blocks (F611 territory)."""
    p = "(function(){var s='" + _A + "';return s+'" + _B + "';})()"
    return ("HELD" if _blocked(p) else "BREAK", "control")


# ------------------------------------------------ junk-quiet control

def test_p6_junk_quiet():
    """Junk that must stay quiet."""
    p = "\"(function(){var a='jx';var b='jy';return a+b;})()\""
    return ("HELD" if _misses(p) else "BREAK", "quiet")


def test_p6_wrapper_junk_quiet():
    """Junk inside wrappers must stay quiet."""
    p = ("(function(){let s='';switch(1){case 1:s+='jx';case 2:s+='jy';}"
         + "return s;})()")
    return ("HELD" if _misses(p) else "BREAK", "quiet")


# ------------------------------------------------ pin + footer

def test_p7_pin_taxonomy():
    """Taxonomy pin 2143."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


def test_p8_lane_footer():
    """Lane-local footer: F655 CLOSED; open F662-F671 / next F672."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("**Status: CLOSED 2026-10-08 wave-378 lane 1.**" in text
          and "Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737." in text  # Wave-379 lane 6: F668 CLOSED (lane-local)
          and "Next free finding: **F672**." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ perf + pins

def test_p9_perf():
    """Perf bound: 200 sites under 5s."""
    t0 = time.time()
    for _ in range(200):
        _blocked("(function(){var s='" + _A + "';s+='" + _B + "';return s;})()")
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


def test_p10_recompile_count():
    """re.compile count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "n=%d" % n)


def test_p11_green_check():
    """Depth-1 green check: F655 red-first + F654 close battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w377_f655_redfirst.py", 0),
                               ("evals/w377_f654close_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
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
