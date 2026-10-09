#!/usr/bin/env python3
"""Wave-385 lane 12: close F784 + F785 (labeled break/continue value
flows; boolean-flag while-loop accumulation).

F784 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack
round 52): the decoder had no labeled-control-flow production:
`break lbl` / `continue lbl` out of labeled blocks and loops
resolved node-exactly while the decoder produced zero variants.

F785 (LOW; filed 2026-10-09 00:07 UTC by wave-384 lane 13, attack
round 52): F709/F727 residual -- F709 (for-accumulation, CLOSED)
and F727 (do-while, CLOSED) cover their loop forms, but
boolean-flag while loops missed: `while(go){...;go=false;}`
accumulates node-exactly while the decoder produced zero variants
(counter-bounded `while(n<1)` blocks).

Fix (gov/dlp.py, zero new re.compile):
- F784: `_js_parse_f784_labeled_block_iife` -- labeled blocks
  `LBL:{BODY}` where BODY carries >=1 `if(BOOL)` head (F655 owns
  the unconditional-break-only subset and cannot parse `if(`);
  statements run in order, a taken `break LBL;` skips the rest
  via the brace-matched span; `if(BOOL)ACCUM;` guarded
  accumulation twins. `_js_parse_f784_labeled_for_iife` --
  `LBL:for(var|let I=INIT;I<BOUND;I++){BODY}` with labeled or
  unlabeled `continue`/`break` (optionally `if(BOOL)`-guarded)
  plus guarded accums; the counter runs the F709 integer
  sequence. Wrong-label jumps, `continue` in a block, and a
  LineTerminator between a jump keyword and its label fail
  closed (all node SyntaxErrors -- the decoder never decodes a
  throw).
- F785: `_js_parse_f785_flagwhile_iife` --
  `var|let FLAG=true|!0|!1|false; while(FLAG){BODY}` where BODY
  is accums plus exactly one unconditional `FLAG=false;` /
  `FLAG=!1;` clear: a truthy initializer runs the body exactly
  once, a falsy one zero times. A missing clear (the engine
  would spin forever), a re-armed flag, or any other flag
  mutation fails closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

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
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F784/F785 closed; F826/F827 filed;
    next F797)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F797**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, "
              "F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, "
              "F779, F780, F781, F782, F783, F786, F787, F788, F789, F790, "
              "F791, F792, F793, F794. F826, F827." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f784_s1():
    """F784 filed shape 1 (labeled block, if(1)break) blocks + exact."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1)break lbl;"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f784_s2():
    """F784 filed shape 2 (labeled continue in for) blocks + exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A
         + "';continue outer;r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f785_s1():
    """F785 filed shape 1 (go=true) blocks + exact."""
    s = ("(function(){var r='';var go=true;while(go){r+='" + _A
         + "';go=false;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f785_s2():
    """F785 filed shape 2 (go=!0) blocks + exact."""
    s = ("(function(){var r='';var go=!0;while(go){r+='" + _A
         + "';go=false;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f784_if0():
    """F784 if(0)break: no break taken, rest runs, node-exact."""
    s = ("(function(){var r='';lbl:{r+='a';if(0)break lbl;r+='xx';}"
         "return r;})()")
    ok = _decodes_exact(s, "axx")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_if_true_false():
    """F784 if(true)/if(false) twins, node-exact."""
    s1 = ("(function(){var r='';lbl:{r+='a';if(true)break lbl;r+='xx';}"
          "return r;})()")
    s2 = ("(function(){var r='';lbl:{r+='a';if(false)break lbl;r+='xx';}"
          "return r;})()")
    ok = _decodes_exact(s1, "a") and _decodes_exact(s2, "axx")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_if_bang():
    """F784 if(!0)/if(!1) twins, node-exact."""
    s1 = ("(function(){var r='';lbl:{r+='a';if(!0)break lbl;r+='xx';}"
          "return r;})()")
    s2 = ("(function(){var r='';lbl:{r+='a';if(!1)break lbl;r+='xx';}"
          "return r;})()")
    ok = _decodes_exact(s1, "a") and _decodes_exact(s2, "axx")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_if_accum():
    """F784 if(BOOL)-guarded accumulation, node-exact."""
    s = ("(function(){var r='';lbl:{r+='a';if(1)r+='b';if(0)r+='c';}"
         "return r;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_multi_break():
    """F784 multiple conditional breaks in one block, node-exact."""
    s = ("(function(){var r='';lbl:{r+='a';if(0)break lbl;r+='b';"
         "if(1)break lbl;r+='c';}return r;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_for_3iter():
    """F784 labeled continue over 3 iterations, node-exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<3;i++){r+='a';"
         "continue outer;r+='xx';}return r;})()")
    ok = _decodes_exact(s, "aaa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_for_break():
    """F784 labeled break exits the loop, node-exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<5;i++){r+='a';"
         "if(1)break outer;r+='xx';}return r;})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_for_unlabeled():
    """F784 unlabeled continue/break target the loop, node-exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "continue;r+='xx';}return r;})()")
    ok = _decodes_exact(s, "aa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_for_le():
    """F784 <= bound on the labeled for, node-exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<=1;i++){r+='a';"
         "continue outer;r+='xx';}return r;})()")
    ok = _decodes_exact(s, "aa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f784_for_if_accum():
    """F784 if(BOOL)-guarded accum in the for body, node-exact."""
    s = ("(function(){var r='';outer:for(var i=0;i<2;i++){r+='a';"
         "if(1)r+='b';if(0)r+='c';}return r;})()")
    ok = _decodes_exact(s, "abab")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f785_falsy_inits():
    """F785 go=false / go=!1: zero iterations, node-exact."""
    s1 = ("(function(){var r='';var go=false;while(go){r+='a';go=false;}"
          "return r+'b';})()")
    s2 = ("(function(){var r='';var go=!1;while(go){r+='a';go=false;}"
          "return r+'b';})()")
    ok = _decodes_exact(s1, "b") and _decodes_exact(s2, "b")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f785_clear_first():
    """F785 clear before accums: still one iteration, node-exact."""
    s = ("(function(){var r='';var go=true;while(go){go=false;r+='a';}"
         "return r;})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f785_concat_twin():
    """F785 R=R+'LIT' and go=!1 clear twins, node-exact."""
    s = ("(function(){var r='';var go=true;while(go){r=r+'a';go=!1;}"
         "return r;})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f785_let():
    """F785 let-declared accum and flag, node-exact."""
    s = ("(function(){let r='';let go=true;while(go){r+='a';go=false;}"
         "return r;})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_folded_operands():
    """Folded 'A'+'B' operands decode via the hooks (H1 fix)."""
    s1 = ("(function(){var r='';lbl:{r+='" + _A + "'+'" + _B
          + "';if(1)break lbl;}return r;})()")
    s2 = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A
          + "'+'" + _B + "';continue outer;}return r;})()")
    s3 = ("(function(){var r='';var go=true;while(go){r+='" + _A + "'+'"
          + _B + "';go=false;}return r;})()")
    ok = (_blocked(s1) and _decodes_exact(s1, _A + _B)
          and _blocked(s2) and _decodes_exact(s2, _A + _B)
          and _blocked(s3) and _decodes_exact(s3, _A + _B))
    return ("HELD" if ok else "BREAK", "fold=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_f784_continue_in_block():
    """F784 continue in a labeled block: node SyntaxError -> closed."""
    s = "(function(){var r='';lbl:{r+='a';if(1)continue lbl;}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_break_wrong_label():
    """F784 break for another label: node SyntaxError -> closed."""
    s = "(function(){var r='';lbl:{r+='a';if(1)break nope;}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_if_nonliteral():
    """F784 if(x)break with a non-literal condition -> closed."""
    s = "(function(){var r='';lbl:{r+='a';if(x)break lbl;}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_if_braced():
    """F784 if(1){break lbl;} braced consequent -> closed."""
    s = "(function(){var r='';lbl:{r+='a';if(1){break lbl;}}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_break_line_terminator():
    """F784 break<newline>lbl: restricted production -> closed."""
    s = "(function(){var r='';lbl:{r+='a';if(1)break\nlbl;}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_for_wrong_label():
    """F784 continue for another label: node SyntaxError -> closed."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){"
         "if(1)continue nope;}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_for_huge_bound():
    """F784 gigantic bound: iteration cap -> closed, never hangs."""
    s = ("(function(){var r='';outer:for(var i=0;i<9999999999;i++){"
         "r+='a';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_for_empty_body():
    """F784 empty loop body -> closed."""
    s = "(function(){var r='';outer:for(var i=0;i<1;i++){}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f784_for_bad_update():
    """F784 non-++ update -> closed."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i+=1){r+='a';}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_no_clear():
    """F785 body without a clear: the engine would spin -> closed."""
    s = "(function(){var r='';var go=true;while(go){r+='a';}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_rearm():
    """F785 flag re-armed in the body: the engine would spin -> closed."""
    s = ("(function(){var r='';var go=true;while(go){r+='a';go=true;}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_clear_truthy():
    """F785 go=1 clear (truthy): the engine would spin -> closed."""
    s = ("(function(){var r='';var go=true;while(go){r+='a';go=1;}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_const_flag():
    """F785 const flag: the engine throws on clear -> closed."""
    s = ("(function(){var r='';const go=true;while(go){r+='a';go=false;}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_negated_cond():
    """F785 while(!go): outside the modeled condition -> closed."""
    s = ("(function(){var r='';var go=true;while(!go){r+='a';go=false;}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_double_clear():
    """F785 two clears: outside the modeled body -> closed."""
    s = ("(function(){var r='';var go=true;while(go){go=false;go=false;"
         "r+='a';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f785_foreign_stmt():
    """F785 foreign body statement -> closed."""
    s = ("(function(){var r='';var go=true;while(go){r+='a';go=false;"
         "x();}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings still block


@_t
def test_p4_sibling_f709():
    """F709 counted for-loop pin still decodes."""
    s = ("(function(){var r='';for(var i=0;i<2;i++){r+=['a','b'][i];}"
         "return r;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "f709=%s" % ok)


@_t
def test_p4_sibling_f709_while():
    """F709 counted while-loop pin still decodes."""
    s = ("(function(){var r='';var i=0;while(i<2){r+=['a','b'][i];i++;}"
         "return r;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "f709w=%s" % ok)


@_t
def test_p4_sibling_f727():
    """F727 do-while pin still decodes."""
    s = ("(function(){var r='';var i=0;do{r+=['a','b'][i];i++;}"
         "while(i<2);return r;})()")
    ok = _decodes_exact(s, "ab")
    return ("HELD" if ok else "BREAK", "f727=%s" % ok)


@_t
def test_p4_sibling_f655_uncond_break():
    """F655 unconditional-break labeled block still decodes (its own)."""
    s = ("(function(){var r='';lbl:{r+='a';break lbl;r+='xx';}"
         "return r;})()")
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "f655=%s" % ok)


@_t
def test_p4_sibling_f756():
    """F756 ternary pin still decodes."""
    s = "(function(){var b=true;var r=(b?'a':'xx');return r;})()"
    ok = _decodes_exact(s, "a")
    return ("HELD" if ok else "BREAK", "f756=%s" % ok)


@_t
def test_p4_neighbor_f786_open():
    """Neighbor F786 (for-of continue) still misses -- open shape."""
    s = ("(function(){var r='';for(var x of ['" + _A + "','xx','" + _B
         + "']){if(x==='xx')continue;r+=x;}return r;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f786-open=%s" % ok)


@_t
def test_p4_neighbor_f826_open():
    """New F826 (braced if consequent) misses -- open residual."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){break lbl;}"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f826-open=%s" % ok)


@_t
def test_p4_neighbor_f827_open():
    """New F827 (for(;;)) misses -- open residual."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f827-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_while_unaffected():
    """Honest while loop without the flag idiom still misses."""
    s = "(function(){var r='';var i=0;while(i<1){r+='a';i++;}return r;})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_label_unaffected():
    """Honest labeled block without control flow still misses decode."""
    s = "(function(){var r='';lbl:{r+='a';}return r;})()"
    # F655 may decode this; the honest-text property is that a
    # non-credential payload never flags.
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){var r='';lbl:{r+='a%d';if(1)break lbl;r+='xx';}"
            "return r;})()" % k)
        sites.append(
            "(function(){var r='';outer:for(var i=0;i<2;i++){r+='a%d';"
            "continue outer;r+='xx';}return r;})()" % k)
        sites.append(
            "(function(){var r='';var go=true;while(go){r+='a%d';go=false;}"
            "return r;})()" % k)
        sites.append(
            "(function(){var r='';lbl:{r+='a%d';if(1)break nope;}return r;})()"
            % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The red-firsts expect 0 BREAK on the closed tree; the attack
    # battery expects exactly 1 BREAK (its footer probe on the
    # lane-local footer -- tree-wide repoint is merge-owned,
    # wave-305 lesson). All functional probes must HELD.
    for batt, expect_break in (("evals/w384_f784_redfirst.py", 0),
                               ("evals/w384_f785_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
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
    """Depth-1 green check: F784/F785 red-firsts (0 BREAK) + wave-384
    attack battery (1 BREAK: the footer pin only, lane-local repoint;
    tree-wide repoint is merge-owned)."""
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
