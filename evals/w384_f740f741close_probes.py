#!/usr/bin/env python3
"""Wave-384 lane 2: close F740 + F741.

F740 (LOW, filed 2026-10-08 21:09 UTC by wave-383 lane 14 as F738,
renumbered at the wave-383 merge -- lane 6 filed F738/F739 first
~17:30/~17:45 UTC): try/catch value flows -- the decoder modeled
straight-line IIFE bodies but not exception edges: a fragment thrown
and caught (or accumulated across the throw boundary) left the
credential readable while the decoder produced zero variants:
(function(){var r;try{throw 'f1';}catch(e){r=e;}return r+'f2';})()
and (function(){var r='';try{r+='f1';throw 0;}catch(e){r+='f2';}
return r;})() both node-evaluate to the exact credential (node
v24.20.0). Distinct from straight-line accumulation (F679, F709,
both CLOSED).

F741 (LOW, filed 2026-10-08 21:09 UTC by wave-383 lane 14 as F739,
renumbered at the wave-383 merge): switch fallthrough value flows --
the decoder modeled switch WITH break (F655, integer labels) but not
string-literal fallthrough: (function(){var x='f1';switch('k'){
case 'k':x+='f2';}return x;})() and (function(){var x='f1';
switch('z'){default:x+='f2';}return x;})() both node-evaluate to the
exact credential (node v24.20.0).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F740: (a) `_js_f679_decl` accepts `var|let NAME;` -- the binding
  starts as `undefined`, modeled as the string "undefined"
  (node-exact for concatenation: `var r;r+='x'` -> "undefinedx");
  `const NAME;` is a node SyntaxError -- fail closed; a `var`
  re-declaration without initializer is a no-op (node-verified).
  (b) `_js_f679_sim_throw` accepts integer throws (`throw 0;` /
  `throw BOUNDINT;`); a non-string throw binds the catch parameter
  to the `_JS_F679_POISON` sentinel when the parameter is never
  referenced in the catch body (unobservable -- node-exact), and
  the shape fails closed when `_js_f679_catch_param_referenced`
  finds any identifier occurrence (conservative: property names
  and comments count). Every read path fails closed on kind "p".
- F741: `_js_f655_switch_disc` parses integer OR string-literal
  discriminants/labels; matching is on the tagged (type, value)
  pair (switch uses ===, so '1' never matches 1 -- node-exact).
- F733 lesson (wave-383 merge): the F655 hook dispatch now
  snapshot/restores parts/ops on miss, like F679's -- a failed
  F655 attempt must not starve later disjoint hooks.

Red-first: evals/w383_f740_redfirst.py and w383_f741_redfirst.py
printed 2 BREAK / 1 HELD on the open tree, 0 BREAK / 3 HELD after.
Node differential v24.20.0: 16/16 byte-exact. Bounds: 15/16 fail
closed (the 16th is the pre-existing whole-text inner-additive
fold, verified identical on the base tree -- it flags in the
correct direction).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    ok = (_misses("the quick brown fox jumps over the lazy dog")
          and _misses("(function(){var s='ab';return s;})()")
          and _misses("(function(){var r;return r;})()"))  # decodes "undefined", not credential-shaped
    return ("HELD" if ok else "BREAK", "junk=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)


@_t
def test_p1_f740_s1():
    """F740 filed shape 1 (uninit var + string throw) blocks."""
    ok = _blocked("(function(){var r;try{throw '%s';}catch(e){r=e;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f740_s2():
    """F740 filed shape 2 (int throw, unreferenced param) blocks."""
    ok = _blocked("(function(){var r='';try{r+='%s';throw 0;}catch(e){r+='%s';}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f741_s1():
    """F741 filed shape 1 (string case match) blocks."""
    ok = _blocked("(function(){var x='%s';switch('k'){case 'k':x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f741_s2():
    """F741 filed shape 2 (default) blocks."""
    ok = _blocked("(function(){var x='%s';switch('z'){default:x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- node-exact variants (p2)


@_t
def test_p2_uninit_concat():
    """`var r;r+='f1'` decodes node-exactly ("undefinedf1...")."""
    ok = _blocked("(function(){var r;r+='%s';return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_undef_falsy():
    """Uninitialized binding is falsy (spec-review catch)."""
    ok = _blocked("(function(){var r;var s='';if(r){s='xx';}else{s='%s';}return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_undef_neq():
    """`r!=='undefined'` is True for an uninitialized binding."""
    ok = _blocked("(function(){var r;if(r!=='undefined'){r='%s';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_undef_eq_branch():
    """`u===v` is True for two uninitialized bindings."""
    ok = _blocked("(function(){var u;var v;var s='';if(u===v){s='%s';}else{s='xx';}return s+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_undef_alias_falsy():
    """`s=r` keeps `s` undefined (falsy) -- aliasing is node-exact."""
    ok = _blocked("(function(){var r;var s;s=r;var t='';if(s){t='xx';}else{t='%s';}return t+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_undef_str_plus_undef():
    """`'x'+undefined` renders "xundefined" (real string on the left)."""
    ok = _blocked("(function(){var r;var s='x';s+=r;return s+'%s%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_throw_bound_string():
    """`throw BOUND` (string) still decodes."""
    ok = _blocked("(function(){var t='%s';var r='';try{throw t;}catch(e){r=e;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_throw_bound_int():
    """`throw BOUNDINT` with unreferenced param decodes."""
    ok = _blocked("(function(){var n=0;var r='';try{throw n;}catch(e){r+='%s';}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_let_uninit():
    """`let r;` twin of the filed shape decodes."""
    ok = _blocked("(function(){let r;try{throw '%s';}catch(e){r=e;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_var_redecl_noop():
    """Nested `var r;` re-declaration is a no-op (node-exact)."""
    ok = _blocked("(function(){var r='%s';for(var i=0;i<1;i++){var r;}return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_switch_fallthrough():
    """String-switch fallthrough across cases decodes."""
    ok = _blocked("(function(){var x='%s';switch('k'){case 'z':x+='xx';case 'k':x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_switch_break():
    """String-switch with break decodes."""
    ok = _blocked("(function(){var x='%s';switch('k'){case 'k':x+='%s';break;case 'z':x+='xx';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_switch_int_still():
    """Integer switch (F655) still decodes after the extension."""
    ok = _blocked("(function(){var x='%s';switch(1){case 1:x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_switch_int_fallthrough():
    """Integer fallthrough (F655) still decodes."""
    ok = _blocked("(function(){var x='%s';switch(2){case 1:x+='xx';case 2:x+='%s';}return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p2_switch_dq():
    """Double-quoted string switch twin decodes."""
    ok = _blocked('(function(){var x="%s";switch("k"){case "k":x+="%s";}return x;})()' % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------------- fail-closed (p3)


@_t
def test_p3_const_uninit():
    """`const r;` is a node SyntaxError -- no decode."""
    ok = _misses("(function(){const r;return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_undef_eq_quiet():
    """`r==='undefined'` is False; uninitialized return stays quiet."""
    ok = _misses("(function(){var r;if(r==='undefined'){r='xx';}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_undef_member():
    """`undefined.length` throws in the engine -- no decode."""
    ok = _misses("(function(){var r;var s='';s=r.length;return s;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_undef_plus_undef():
    """`undefined+undefined` is NaN (unrepresentable) -- no decode."""
    ok = _misses("(function(){var r;r+=r;return r+'!';})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_undef_incr():
    """`r++` on undefined is NaN (unrepresentable) -- no decode."""
    ok = _misses("(function(){var r;r++;return r+'!';})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_referenced_int_param():
    """Non-string catch param that IS read fails closed."""
    ok = _misses("(function(){var r='';try{throw 0;}catch(e){r=e;}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_param_in_concat():
    """Catch param referenced in a concatenation fails closed."""
    ok = _misses("(function(){var r='';try{throw 0;}catch(e){r='x'+e;}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_param_in_cond():
    """Catch param referenced in a condition fails closed."""
    ok = _misses("(function(){var r='';try{throw 0;}catch(e){if(e===0){r='f1';}}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_rethrow_poison():
    """Rethrow of a poisoned catch param fails closed."""
    ok = _misses("(function(){var r='';try{throw 0;}catch(e){throw e;}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_bool_throw():
    """`throw true;` (unmodeled throw kind) fails closed."""
    ok = _misses("(function(){var r='';try{throw true;}catch(e){r+='f1';}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_uncaught_throw():
    """Uncaught throw never decodes."""
    ok = _misses("(function(){var r='f1';throw r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_throw_unbound():
    """`throw UNBOUND;` fails closed."""
    ok = _misses("(function(){var r='';try{throw zzz;}catch(e){r+='f1';}return r;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_switch_nonlit_disc():
    """Non-literal switch discriminant fails closed."""
    ok = _misses("(function(){var x='f1';var d='k';switch(d){case 'k':x+='f2';}return x;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_switch_fractional():
    """Fractional switch discriminant fails closed."""
    ok = _misses("(function(){var x='f1';switch(1.5){case 1:x+='f2';}return x;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_switch_dup_default():
    """Duplicate default fails closed (node SyntaxError)."""
    ok = _misses("(function(){var x='f1';switch('k'){case 'k':x+='f2';default:x+='f2';default:x+='f2';}return x;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_switch_decl_in_case():
    """Declaration inside a case body fails closed."""
    ok = _misses("(function(){var x='f1';switch('k'){case 'k':var y='f2';}return x;})()")
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_additive_throw_direction():
    """Additive throw: the whole-text inner fold flags credential-shaped
    fragments in the correct direction (pre-existing base behavior,
    verified identical via git stash)."""
    ok = _blocked("(function(){var r='';try{throw '%s'+'%s';}catch(e){r=e;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------- sibling integrity (p4)


@_t
def test_p4_f655_try_finally():
    """F655 try-finally still blocks."""
    ok = _blocked("(function(){var r='';try{r+='%s';}finally{r+='%s';}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4_f679_string_throw():
    """F679 string-throw try/catch still blocks."""
    ok = _blocked("(function(){var r='';try{r+='%s';throw 'zz';}catch(e){r+='%s';}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4_f679_for_loop():
    """F679 for-loop accumulation still blocks."""
    ok = _blocked("(function(){var r='';for(var i=0;i<2;i++){r+='%s';}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4_f655_dowhile():
    """F655 do-while(false) still blocks."""
    ok = _blocked("(function(){var r='%s';do{r+='%s';}while(false);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p4_open_neighbors_miss():
    """Adjacent unmodeled shapes still miss (not claimed by this lane)."""
    ok = (_misses("(function(){var x='f1';var d='k';switch(d){case 'k':x+='f2';}return x;})()")
          and _misses("(function(){var r='';try{throw {};}catch(e){r+='f1';}return r;})()"))
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------------------------ green


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs)
    for batt, expect_break in (("evals/w383_attack_probes.py", 1),
                               ("evals/w380_f679close_probes.py", 1),
                               ("evals/w378_f655close_probes.py", 2)):
        # All expected BREAKs are footer-pin only (the lane-local
        # footer repoint is merge-owned -- wave-382 lane-5
        # precedent): w383_attack test_b0_footer_state asserts the
        # base footer; w380_f679close test_p7_pin_and_footer likewise;
        # w378_f655close test_p8_lane_footer likewise, plus the
        # PRE-EXISTING test_p4_sibling_closures_hold NameError
        # (_js_parse_f659_yield_star_array -- a battery defect,
        # identical on the base tree, verified via git stash,
        # unrelated to F740/F741).
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green: %s" % ("ok" if ok else bad))


@_t
def test_p9_green_check():
    """Green check: adjacent batteries stay green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
