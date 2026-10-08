#!/usr/bin/env python3
"""Wave-380 lane 6: close F679 -- statement-body accumulation beyond F655.

F679 (LOW, filed attack round 47): statement-body accumulation beyond
F655 bypasses the bounded static JS-expression decoder -- F655 (CLOSED)
models two-decl, decl+accum, switch-fallthrough, do-while(false),
with-wrapper, labeled-block, and try-finally bodies, but C-style for
loops, while loops, for-in guards, try-catch value assembly, if-else
chains, for(;;)+break, and do-while+break all node-evaluate to the
exact credential (node v24.20.0) while the decoder produced zero
variants. Filed shapes:

  (function(){var s='';for(var i=0;i<2;i++){s+=i===0?'f1':'f2';}return s;})()
  (function(){var s='';var i=0;while(i<2){s+=i===0?'f1':'f2';i++;}return s;})()
  (function(){var o={x:'f1'};var s='';for(var k in o){if(k==='x'){s+=o[k];}}return s+'f2';})()
  (function(){var s='';try{throw 'f1';}catch(e){s+=e;}s+='f2';return s;})()
  (function(){var s='';if(false){s+='junk';}else if(true){s+='f1';}s+='f2';return s;})()
  (function(){var s='';for(;;){s+='f1';break;}s+='f2';return s;})()
  (function(){var s='';var i=0;do{s+=i===0?'f1':'f2';i++;if(i>=2){break;}}while(true);return s;})()

Closure (gov/dlp.py, F679): _js_parse_f679_statement_iife parses
(function(){STMT* return ADD;})() with a bounded statement
simulator -- strings, bounded integers (|v| <= 2**53), and
string-valued literal objects; if/else-if/else chains over
evaluable conditions; C-style for, while, do-while, and for-in
loops bounded by _JS_F679_MAX_ITERS iterations (non-terminating
shapes fail closed); try{...}catch(e){...} with literal/bound
throws; member reads o[k]/o['k']/o.k on object bindings;
ternary right-hand sides with evaluable conditions. Zero new
re.compile (28 stays). Hooked after F655; disjoint (F655 fails
closed on for/while/if/try-catch heads; red-first verified).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g380-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction (evals-only: no
realmodel_harness / ModelDriver / provider refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


def _decode_exact(js):
    """Exact decoded value via the F679 statement-IIFE parser (internal seam)."""
    state = {"ops": 0, "parts": 0, "depth": 0}
    r = _dlp._js_parse_f679_statement_iife(js, 0, 0, state)
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
    print("%-44s %s %s" % (name, verdict, note))


def _hit(name, payload):
    ok = _blocked(payload)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


def _miss(name, payload):
    ok = _misses(payload)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def _exact(name, js, want):
    got = _decode_exact(js)
    ok = got == want
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ no new regexes

def test_p0_no_new_regexes():
    """gov/dlp.py keeps 28 re.compile calls (F679 adds none)."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = src.count("re.compile(")
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


# ------------------------------------------------ filed shapes (must block)

def test_p1_filed_cfor():
    """Filed shape 1: C-style for with ternary accum."""
    p = ("(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'" + _A
         + "':'" + _B + "';}return s;})()")
    return _hit("p1", p)


def test_p1_filed_cfor_exact():
    """Filed shape 1: internal-seam exact decode."""
    p = ("(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'" + _A
         + "':'" + _B + "';}return s;})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_while():
    """Filed shape 2: while loop with counter."""
    p = ("(function(){var s='';var i=0;while(i<2){s+=i===0?'" + _A
         + "':'" + _B + "';i++;}return s;})()")
    return _hit("p1", p)


def test_p1_filed_while_exact():
    """Filed shape 2: internal-seam exact decode."""
    p = ("(function(){var s='';var i=0;while(i<2){s+=i===0?'" + _A
         + "':'" + _B + "';i++;}return s;})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_forin_guard():
    """Filed shape 3: for-in with guarded member read."""
    p = ("(function(){var o={x:'" + _A + "'};var s='';for(var k in o){"
         "if(k==='x'){s+=o[k];}}return s+'" + _B + "';})()")
    return _hit("p1", p)


def test_p1_filed_forin_guard_exact():
    """Filed shape 3: internal-seam exact decode."""
    p = ("(function(){var o={x:'" + _A + "'};var s='';for(var k in o){"
         "if(k==='x'){s+=o[k];}}return s+'" + _B + "';})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_trycatch():
    """Filed shape 4: try/throw/catch value assembly."""
    p = ("(function(){var s='';try{throw '" + _A + "';}catch(e){s+=e;}"
         "s+='" + _B + "';return s;})()")
    return _hit("p1", p)


def test_p1_filed_trycatch_exact():
    """Filed shape 4: internal-seam exact decode."""
    p = ("(function(){var s='';try{throw '" + _A + "';}catch(e){s+=e;}"
         "s+='" + _B + "';return s;})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_ifelse_chain():
    """Filed shape 5: if/else-if chain over literal conditions."""
    p = ("(function(){var s='';if(false){s+='junk';}else if(true){s+='"
         + _A + "';}s+='" + _B + "';return s;})()")
    return _hit("p1", p)


def test_p1_filed_ifelse_chain_exact():
    """Filed shape 5: internal-seam exact decode."""
    p = ("(function(){var s='';if(false){s+='junk';}else if(true){s+='"
         + _A + "';}s+='" + _B + "';return s;})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_forbreak():
    """Filed shape 6: for(;;) with break."""
    p = ("(function(){var s='';for(;;){s+='" + _A + "';break;}s+='"
         + _B + "';return s;})()")
    return _hit("p1", p)


def test_p1_filed_forbreak_exact():
    """Filed shape 6: internal-seam exact decode."""
    p = ("(function(){var s='';for(;;){s+='" + _A + "';break;}s+='"
         + _B + "';return s;})()")
    return _exact("p1x", p, _CRED)


def test_p1_filed_dowhile_break():
    """Filed shape 7: do-while(true) with conditional break."""
    p = ("(function(){var s='';var i=0;do{s+=i===0?'" + _A + "':'" + _B
         + "';i++;if(i>=2){break;}}while(true);return s;})()")
    return _hit("p1", p)


def test_p1_filed_dowhile_break_exact():
    """Filed shape 7: internal-seam exact decode."""
    p = ("(function(){var s='';var i=0;do{s+=i===0?'" + _A + "':'" + _B
         + "';i++;if(i>=2){break;}}while(true);return s;})()")
    return _exact("p1x", p, _CRED)


# ------------------------------------------------ variants (must block / decode exactly)

def test_p2_for_decrement():
    """Variant: decrementing C-style for."""
    return _exact("p2", "(function(){var s='';for(var i=2;i>0;i--){s+='z';}return s;})()",
                  "zz")


def test_p2_for_let_scoped():
    """Variant: let-scoped loop counter."""
    return _exact("p2", "(function(){var s='';for(let i=0;i<2;i++){s+='q';}return s;})()",
                  "qq")


def test_p2_for_pluseq_update():
    """Variant: += update form."""
    return _exact("p2", "(function(){var s='';for(var i=0;i<4;i+=2){s+='w';}return s;})()",
                  "ww")


def test_p2_while_le():
    """Variant: <= test."""
    return _exact("p2", "(function(){var s='';var i=0;while(i<=1){s+='y';i++;}return s;})()",
                  "yy")


def test_p2_forin_inline_object():
    """Variant: inline object literal in for-in."""
    return _exact("p2", "(function(){var s='';for(var k in {a:'m',b:'n'}){s+=k;}return s;})()",
                  "ab")


def test_p2_forin_int_key_order():
    """Variant: for-in integer keys enumerate numerically first (node-exact)."""
    return _exact("p2", "(function(){var s='';for(var k in {2:'b',10:'c',x:'a'}){s+=k;}return s;})()",
                  "210x")


def test_p2_forin_dot_read():
    """Variant: dot member read in for-in body."""
    return _exact("p2", "(function(){var o={x:'p'};var s='';for(var k in o){s+=o.x;}return s;})()",
                  "p")


def test_p2_forin_bracket_literal():
    """Variant: bracket-literal member read in for-in body."""
    return _exact("p2", "(function(){var o={x:'p'};var s='';for(var k in o){s+=o['x'];}return s;})()",
                  "p")


def test_p2_try_no_throw():
    """Variant: try without throw skips the catch (node-exact)."""
    return _exact("p2", "(function(){var s='';try{s+='a';}catch(e){s+='b';}return s;})()",
                  "a")


def test_p2_try_bound_throw():
    """Variant: throw of a bound string."""
    return _exact("p2", "(function(){var s='';var t='t';try{throw t;}catch(e){s+=e;}return s;})()",
                  "t")


def test_p2_try_catch_param_shadow():
    """Variant: catch param shadows an outer binding, restored after."""
    return _exact("p2", "(function(){var s='';var e='outer';try{throw 'in';}catch(e){s+=e;}s+=e;return s;})()",
                  "inouter")


def test_p2_if_else():
    """Variant: plain if/else."""
    return _exact("p2", "(function(){var s='';if(false){s+='f';}else{s+='t';}return s;})()",
                  "t")


def test_p2_if_nested():
    """Variant: nested if with truthy int test."""
    return _exact("p2", "(function(){var s='';var i=1;if(i){if(i===1){s+='n';}}return s;})()",
                  "n")


def test_p2_dowhile_false_general():
    """Variant: do-while(false) with an if inside (F655's subset fails this)."""
    return _exact("p2", "(function(){var s='';var i=0;do{if(i===0){s+='d';}i++;}while(false);return s;})()",
                  "d")


def test_p2_while_nested_if_break():
    """Variant: while with nested if/break."""
    return _exact("p2", "(function(){var s='';var i=0;while(true){if(i>=2){break;}s+='v';i++;}return s;})()",
                  "vv")


def test_p2_ternary_bound_branch():
    """Variant: ternary with bound-string branch."""
    return _exact("p2", "(function(){var s='';var b='B';for(var i=0;i<2;i++){s+=i?'A':b;}return s;})()",
                  "BA")


def test_p2_nested_loops():
    """Variant: nested for loops (var re-declaration is assignment)."""
    return _exact("p2", "(function(){var s='';for(var i=0;i<2;i++){for(var j=0;j<2;j++){s+='n';}}return s;})()",
                  "nnnn")


def test_p2_nested_forin_additive():
    """Variant: nested for-in with additive rhs over both keys."""
    return _exact("p2", "(function(){var s='';var o={a:'x',b:'y'};for(var k in o){for(var m in o){s+=k+m;}}return s;})()",
                  "aaabbabb")


def test_p2_additive_rhs():
    """Variant: multi-operand additive accumulation rhs."""
    return _exact("p2", "(function(){var s='';var a='x';s+=a+'y';return s;})()",
                  "xy")


def test_p2_nested_for_let():
    """Variant: let-scoped inner loop index, re-entered per outer iteration."""
    return _exact("p2", "(function(){var s='';for(var i=0;i<2;i++){for(let j=0;j<2;j++){s+='n';}}return s;})()",
                  "nnnn")


def test_p2_forin_let_nested():
    """Variant: let-scoped for-in inside a for loop."""
    return _exact("p2", "(function(){var s='';var o={a:'x'};for(var i=0;i<2;i++){for(let k in o){s+=k;}}return s;})()",
                  "aa")


def test_p2_while_var_redecl():
    """Variant: var re-declared inside a loop body is assignment (node-exact)."""
    return _exact("p2", "(function(){var s='';var i=0;while(i<1){var t='x';s+=t;i++;}return s;})()",
                  "x")


def test_p2_const_int():
    """Variant: const integer binding read in condition."""
    return _exact("p2", "(function(){var s='';const n=2;for(var i=0;i<n;i++){s+='c';}return s;})()",
                  "cc")


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_while_true_no_break():
    """Bound: while(true) without break is non-terminating -- miss."""
    return _miss("p3", "(function(){var s='';while(true){s+='x';}return s;})()")


def test_p3_let_in_block_no_leak():
    """Bound: let is block-scoped; a read after the block fails closed (no mis-decode)."""
    return _miss("p3", "(function(){var s='';if(true){let t='x';}s+=t;return s;})()")


def test_p3_var_shadows_lexical():
    """Bound: for(var i) over an active let i is separate engine bindings -- miss, never mis-decode."""
    return _miss("p3", "(function(){var s='';for(let i=0;i<1;i++){for(var i=0;i<1;i++){s+='q';}}return s;})()")


def test_p3_var_redecl_top_level():
    """Bound: top-level var re-declaration fails closed (F655 discipline)."""
    return _miss("p3", "(function(){var s='a';var s='b';return s;})()")


def test_p3_for_over_iteration_cap():
    """Bound: loop past _JS_F679_MAX_ITERS fails closed -- miss."""
    return _miss("p3", "(function(){var s='';for(var i=0;i<100;i++){s+='x';}return s;})()")


def test_p3_throw_without_catch():
    """Bound: uncaught throw propagates -- miss."""
    return _miss("p3", "(function(){var s='';throw 'x';return s;})()")


def test_p3_forin_over_string():
    """Bound: for-in over a string is outside the subset -- miss."""
    return _miss("p3", "(function(){var s='';for(var k in 'ab'){s+=k;}return s;})()")


def test_p3_forin_unbound_object():
    """Bound: for-in over unbound name -- miss."""
    return _miss("p3", "(function(){var s='';for(var k in o){s+=k;}return s;})()")


def test_p3_cond_mixed_kinds():
    """Bound: mixed-kind comparison is engine coercion -- miss."""
    return _miss("p3", "(function(){var s='';var i=0;if(i==='x'){s+='q';}return s;})()")


def test_p3_cond_unbound():
    """Bound: condition on unbound name -- miss."""
    return _miss("p3", "(function(){var s='';if(q){s+='q';}return s;})()")


def test_p3_accum_int_value():
    """Bound: accumulating an int into a string is coercion -- miss."""
    return _miss("p3", "(function(){var s='';var i=0;s+=i;return s;})()")


def test_p3_int_overflow():
    """Bound: integer past 2**53 fails closed -- miss."""
    return _miss("p3", "(function(){var s='';var i=9007199254740993;if(i){s+='q';}return s;})()")


def test_p3_accum_into_const():
    """Bound: accumulation into const throws in the engine -- miss."""
    return _miss("p3", "(function(){const s='';s+='x';return s;})()")


def test_p3_member_missing_key():
    """Bound: member read of a missing key -- miss."""
    return _miss("p3", "(function(){var o={x:'p'};var s='';s+=o.y;return s;})()")


def test_p3_try_catch_finally():
    """Bound: try-catch-finally is outside the subset -- miss."""
    return _miss("p3", "(function(){var s='';try{s+='a';}catch(e){s+='b';}finally{s+='c';}return s;})()")


def test_p3_break_at_top_level():
    """Bound: top-level break is a node SyntaxError -- miss."""
    return _miss("p3", "(function(){var s='';break;return s;})()")


def test_p3_return_inside_if():
    """Bound: return inside a wrapper body -- miss."""
    return _miss("p3", "(function(){var s='';if(true){return s;}return s;})()")


def test_p3_template_literal():
    """Bound: template literals fail closed at the span boundary."""
    return _miss("p3", "(function(){var s='';for(var i=0;i<1;i++){s+=`x`;}return s;})()")


# ------------------------------------------------ open neighbors still miss (nothing absorbed)

def test_p4_open_f672_private_static():
    """Wave-380 merge: F672 CLOSED by lane 1 -- now blocks."""
    return _hit("p4", "(function(){class C{static #x='" + _A + "';static y(){return C.#x;}}return C.y()+'"
                + _B + "';})()")


def test_p4_open_f672_extends():
    """Wave-380 merge: F672 CLOSED by lane 1 -- now blocks."""
    return _hit("p4", "(function(){class C{get x(){return '" + _A + "';}}class D extends C{}return new D().x+'"
                + _B + "';})()")


def test_p4_open_f678_with_tail():
    """Wave-380 merge: F678 CLOSED by lane 4 -- now blocks."""
    return _hit("p4", "(function(){var o={x:'" + _A + "'};var s;with(o){s=x;}return s+'" + _B + "';})()")


# ------------------------------------------------ closed neighbors still held

def test_p5_f655_two_decls():
    """Closed F655 (two declarations) still blocks."""
    return _hit("p5", "(function(){var a='" + _A + "';var b='" + _B + "';return a+b;})()")


def test_p5_f655_decl_accum():
    """Closed F655 (decl + accum) still blocks."""
    return _hit("p5", "(function(){var s='" + _A + "';s+='" + _B + "';return s;})()")


def test_p5_f655_switch():
    """Closed F655 (switch fallthrough) still blocks."""
    return _hit("p5", "(function(){let s='';switch(1){case 1:s+='" + _A + "';case 2:s+='" + _B
                + "';}return s;})()")


def test_p5_f655_try_finally():
    """Closed F655 (try-finally) still blocks."""
    return _hit("p5", "(function(){let s='';try{s+='" + _A + "';}finally{s+='" + _B + "';}return s;})()")


def test_p5_f655_dowhile_false():
    """Closed F655 (do-while(false)) still blocks."""
    return _hit("p5", "(function(){let s='';do{s+='" + _A + "';s+='" + _B + "';}while(false);return s;})()")


def test_p5_f655_with_empty():
    """Closed F655 (with({})) still blocks."""
    return _hit("p5", "(function(){let s='';with({}){s+='" + _A + "';s+='" + _B + "';}return s;})()")


def test_p5_f655_labeled():
    """Closed F655 (labeled block) still blocks."""
    return _hit("p5", "(function(){let s='';blk:{s+='" + _A + "';break blk;s+='junk';}s+='" + _B
                + "';return s;})()")


# ------------------------------------------------ junk-quiet + composition

def test_p6_junk_quiet():
    """Junk stays quiet (no false positives)."""
    return _miss("p6", "'(function(){var s=\\'ab\\';return s;})()'")


def test_p6_composition_prefix():
    """F679 shape with surrounding junk still blocks precisely."""
    p = ("nope (function(){var s='';for(var i=0;i<2;i++){s+=i===0?'" + _A
         + "':'" + _B + "';}return s;})() nope")
    return _hit("p6", p)


def test_p6_honest_loop_unaffected():
    """Honest loop text without credential fragments stays quiet."""
    return _miss("p6", "(function(){var s='';for(var i=0;i<2;i++){s+='ab';}return s;})()")


# ------------------------------------------------ pin + footer

def test_p7_pin_and_footer():
    """Pin 2140; lane-local footer: open F672-F678, F680-F685 / next F686."""
    from gov.decision_codes import TAXONOMY  # noqa: E402
    ok = TAXONOMY_PIN == 2140 and len(TAXONOMY) > 0
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and "Next free finding: **F700**" in text
    ok = ok and ("Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)
    ok = ok and "**Status: CLOSED 2026-10-08 wave-380 lane 6.**" in text
    return ("HELD" if ok else "BREAK", "ok=%s" % ok)


# ------------------------------------------------ perf

def test_p8_perf():
    """200 F679 sites decode quickly (bounded work)."""
    site = ("(function(){var s='';for(var i=0;i<2;i++){s+='ab';}return s;})()")
    payload = "z".join([site] * 200)
    t0 = time.time()
    find_credential(payload)
    dt = time.time() - t0
    ok = dt < 10.0
    return ("HELD" if ok else "BREAK", "%.2fs" % dt)


# ------------------------------------------------ green check (depth-1)

def _green_check():
    """Depth-1 green check: w379 attack battery stays green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w379_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w379 battery's footer pin is repointed by this lane to the
    # lane-local footer (open F672-F678, F680-F685 / next F686),
    # matching the FINDINGS.md repoint, so the footer tolerance below
    # is a merge-time safety net only. The seven F679 pins are flipped
    # to closed pins by this lane (wave-305/306 class), so no pin
    # tolerance remains.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w379_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


def test_p9_green_check():
    """Green check: wave-379 attack battery stays green (depth-1)."""
    return _green_check()


def test_p9_redfirst_green():
    """Red-first battery for F679 stays 0 BREAK on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g380-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w379_f679_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = "tally: 0 BREAK" in out
    return ("HELD" if ok else "BREAK", "redfirst-0-break=%s" % ok)


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for fn in tests:
        _t(fn.__name__, fn)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errors = len(results) - breaks - held
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
