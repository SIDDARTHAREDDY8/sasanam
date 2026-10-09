#!/usr/bin/env python3
"""Wave-387 lane 2: close F833 + F834 + F835 + F836.

F833 (LOW; filed 2026-10-09 05:26 UTC, wave-386 lane 16): braced
if(BOOL) consequents in labeled FOR bodies -- F826 (CLOSED) models
braced consequents in labeled BLOCKS and F827 (CLOSED) models
for(;;), but `if(1){break outer;}` inside a labeled FOR body
(counted or for(;;)) resolves node-exactly while the decoder
produces zero variants.

F834 (LOW; filed 2026-10-09 05:30 UTC, attack round 54):
method-shorthand invocation -- `var o={m(){return 'f1';}};o.m()` and
the this-bound twin resolve node-exactly while the decoder produces
zero variants.

F835 (LOW; filed 2026-10-09 05:30 UTC, attack round 54):
zero-parameter arrow var-binding calls -- `var f=()=>'f1';f()` and
the block-body twin resolve node-exactly while the decoder produces
zero variants.

F836 (LOW; filed 2026-10-09 05:30 UTC, attack round 54): curried
call-result invocation -- `f('f1')('f2')` and `(()=>()=>'f1')()()`
resolve node-exactly while the decoder produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F833: braced-consequent extension of _js_parse_f784_labeled_for_iife
  (in place): `if(BOOL){ACCUM;...}` / `if(BOOL){break [LBL];...}` /
  `if(BOOL){continue [LBL];...}` expand to for-body ops under the
  outer guard. Node-exact (v24.20.0); empty braces, nested `if`,
  other statement kinds, and wrong-label jumps fail closed (the
  F826 precedent). F452: one part per inner statement.
- F834: incidentally closed on the wave-386 tree by lane 9's
  _js_parse_f674_this_bound_iife (verified node-exact on the filed
  shapes plus this-binding generalizations).
- F835: incidentally closed on the wave-386 tree by
  _js_parse_f821_arrow_default_iife (verified node-exact on the
  filed shapes plus a whitespace generalization).
- F836: s1 incidentally closed by F809's curry hook;
  _js_parse_f836_double_arrow_iife (hooked after F809) parses
  `(function(){return ADD;})()` with double-invoked
  parenthesized-arrow terms `(()=>INNER)()()`. Node-exact
  (v24.20.0); params, non-literal bodies, non-arrow outer bodies,
  single/triple invoke, and `this` fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_re_compile():
    """Zero new re.compile( in gov/dlp.py (still 28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_pin_verifier_taxonomy():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    path = os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py")
    ok = "VERIFIER_TAXONOMY_PIN = 33" in open(path).read()
    return ("HELD" if ok else "BREAK", "vpin=%s" % ok)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F833-F836 closed; next F893)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F893**" in foot[-1]
          and "F829, F830, F831, F832, F837" in foot[-1]
          and ", F833," not in foot[-1]
          and ", F836," not in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f833_s1():
    """F833 filed shape 1 (counted for, braced break) blocks + exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A + "';"
         "if(1){break outer;}r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f833_s2():
    """F833 filed shape 2 (for(;;), braced accum+break) blocks + exact."""
    s = ("(function(){var r='';outer:for(;;){if(1){r+='" + _A + "';"
         "break outer;}r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f834_s1():
    """F834 filed shape 1 (method shorthand) blocks + exact."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f834_s2():
    """F834 filed shape 2 (this-bound method) blocks + exact."""
    s = ("(function(){var o={k:'" + _A + "',m(){return this.k;}};"
         "return o.m()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f835_s1():
    """F835 filed shape 1 (zero-param arrow) blocks + exact."""
    s = "(function(){var f=()=>'%s';return f()+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f835_s2():
    """F835 filed shape 2 (block-body arrow) blocks + exact."""
    s = "(function(){var f=()=>{return '%s';};return f()+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f836_s1():
    """F836 filed shape 1 (curried decl call, F809) blocks + exact."""
    s = ("(function(){function f(a){return function(b){return a+b;};}"
         "return f('" + _A + "')('" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f836_s2():
    """F836 filed shape 2 (double-invoked arrow) blocks + exact."""
    s = "(function(){return (()=>()=>'%s')()()+'%s';})()" % (_A, _B)
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f833_accum_break():
    """Braced accum-then-break decodes node-exactly."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(1){r+='" + _A + "';break outer;}r+='x';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "a" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f833_continue():
    """Braced continue (labeled + unlabeled) decodes node-exactly."""
    s = ("(function(){var r='';outer:for(var i=0;i<3;i++){r+='a';"
         "if(1){continue outer;}r+='x';}return r+'" + _A + "';})()")
    ok = _decodes_exact(s, "aaa" + _A)
    s2 = ("(function(){var r='';outer:for(var i=0;i<3;i++){r+='a';"
          "if(1){continue;}r+='x';}return r+'" + _B + "';})()")
    ok = ok and _decodes_exact(s2, "aaa" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f833_falsy_guard():
    """Falsy-guarded braced break is skipped node-exactly."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(0){break outer;}r+='x';}return r+'" + _A + "';})()")
    ok = _decodes_exact(s, "axax" + _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f834_this_additive():
    """this-bound method with additive body decodes node-exactly.

    (Exact-decode only: the '!' join breaks the credential token
    shape, so the credential rule itself does not fire -- the
    decoder value is what this pins.)
    """
    s = ("(function(){var o={a:'" + _A + "',m(){return this.a+'!';}};"
         "return o.m()+'" + _B + "';})()")
    ok = _decodes_exact(s, _A + "!" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f834_bracket_call():
    """Bracket-string method call twin decodes node-exactly."""
    s = ("(function(){var o={m(){return '" + _A + "';}};"
         "return o['m']()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f835_ws():
    """Whitespace-tolerant zero-param arrow decodes node-exactly."""
    s = ("(function(){var f=()=> '" + _A + "' ;return f()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f836_outer_block():
    """Block-bodied outer arrow double-invoke decodes node-exactly."""
    s = ("(function(){return (()=>{return ()=>'" + _A + "';})()()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f836_two_terms():
    """Two double-call terms in one additive decode node-exactly."""
    s = ("(function(){return (()=>()=>'%s')()()+(()=>()=>'%s')()();})()"
         % (_A, _B))
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f833_wrong_label():
    """Braced break for another label fails closed (node: SyntaxError)."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(1){break other;}r+='x';}return r+'z';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f833_empty_braces():
    """Empty braced consequent fails closed (F826 precedent)."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(1){}r+='x';}return r+'z';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f833_nested_if():
    """Nested if inside braced consequent fails closed."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(1){if(1){break outer;}}r+='x';}return r+'z';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f833_inf_continue():
    """Truthy continue in for(;;) braced consequent fails closed (hang)."""
    s = ("(function(){var r='';outer:for(;;){r+='a';"
         "if(1){continue outer;}}return r+'z';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f836_single_invoke():
    """Single-invoke arrow fails closed (F835-family residual)."""
    s = "(function(){return (()=>'%s')()+'%s';})()" % (_A, _B)
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f836_params():
    """Arrow params fail closed."""
    s = "(function(){return ((a)=>()=>a)('f1')('f2');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f836_nonarrow_body():
    """Non-arrow outer body fails closed (node: TypeError)."""
    s = "(function(){return (()=>'%s')()()+'%s';})()" % (_A, _B)
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f836_triple_invoke():
    """Triple invoke fails closed (node: TypeError)."""
    s = "(function(){return (()=>()=>'%s')()()()+'%s';})()" % (_A, _B)
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f836_this_body():
    """`this` in arrow body fails closed."""
    s = "(function(){return (()=>()=>this.x)()();})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sib_f784_bare():
    """F784 bare-consequent twin still decodes (sibling, unchanged)."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A + "';"
         "if(1)break outer;r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_sib_f826_block():
    """F826 braced-consequent labeled block still decodes (sibling)."""
    s = ("(function(){var r='';outer:{r+='" + _A + "';"
         "if(1){break outer;}r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sib_f827_inf():
    """F827 for(;;) bare twin still decodes (sibling, unchanged)."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A + "';"
         "break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sib_f809_curry():
    """F809 curried declaration still decodes (sibling, unchanged)."""
    s = ("(function(){function f(a){return function(b){return a+b;};}"
         "return f('" + _A + "')('" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_sib_f735_fndecl():
    """F735 function-declaration call still decodes (sibling)."""
    s = ("(function(){function f(){return '" + _A + "';}"
         "return f()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    ok = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_plain_text_quiet():
    """Plain prose stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay linear (F452)."""
    sites = []
    for k in range(200):
        sites.append("if(1){r+='x%d';break outer;}" % k)
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){%s}return r;})()"
         % "".join(sites))
    t0 = time.time()
    hit = _blocked(s)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The four red-firsts must be 0 BREAK (F833-F836 closed). The
    # wave-386 attack battery is expected to report exactly 1 BREAK:
    # its test_b0_footer_state asserts the base footer (lane-local
    # footer differs -- merge-owned, wave-305 lesson). All functional
    # probes must HELD (its F834/F835/F836 open pins use bare
    # fragments that miss regardless -- stable).
    for batt, expect_break in (("evals/w387_f833_redfirst.py", 0),
                               ("evals/w387_f834_redfirst.py", 0),
                               ("evals/w387_f835_redfirst.py", 0),
                               ("evals/w387_f836_redfirst.py", 0),
                               ("evals/w386_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g387-green-", dir="/var/tmp")
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
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: four red-firsts 0 BREAK + w386_attack 1
    BREAK (footer pin only, lane-local/merge-owned)."""
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
