"""Wave-385 lane 2: close F764 + F765 (slice/regex-family residuals).

F764 (LOW, attack round 52): slice-family residuals -- the decoder had
no substr/substring production, so argument-swap shapes
(substring(9,0), substr(-9)) missed.
F765 (LOW, attack round 52): match/matchAll extraction over
character-class / `+`-quantifier regex bodies -- F694 modeled only
F603 regex-plain bodies; /xoxb-[0-9]+/ missed.

Closure (gov/dlp.py, node v24.20.0 exact):
- F764: substring(start[,end]) clamps both bounds at 0/len then swaps
  if start>end; substr(start[,length]) takes start from the end
  (negative ok), length>=0. Non-literal/non-numeric bounds fail
  closed. Dispatched in _js_apply_method_at via the postfix method
  allowlist; var-bound receivers work.
- F765: bounded char-class regex grammar (literals, [...] classes
  with ranges/negation, one group level, `+` on a single term),
  node-exact backtracking matcher (greedy, first-success-wins,
  groups by `(` order, last-iteration-wins), tried when the F603
  parse raises (disjoint by construction). match flags "" (match
  array [full,g1..gn]) / "g" (full matches); matchAll requires "g".
  The F694 IIFE's bound index read now resolves the matchAll twin
  m[i][j] through one nested _JSArr level.

Every probe returns HELD on the closed tree; a literal BREAK verdict
means the closure regressed or a new break appeared.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (local node only).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from gov import dlp  # noqa: E402
from gov.guac_graph import TAXONOMY_PIN as _REGISTRY_PIN  # noqa: E402

TAXONOMY_PIN = 2143  # no new decision codes this lane

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
FULL = _A + _B

_TESTS = []


def _t(fn):
    _TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _decodes_to(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


# ------------------------------------------------- p0 pins / footer

@_t
def test_p0_taxonomy_pin():
    """Pin 2143 unchanged (wave-385 lane 2); registry loads."""
    from gov.decision_codes import TAXONOMY
    ok = TAXONOMY_PIN == 2143 and _REGISTRY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_footer_state():
    """Lane-local footer: F764/F765 CLOSED; open F762,F763,F766-F794;
    next free F795."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    open_list = ("F762, F763, F766, F767, F768, F769, F770, F771, F772, "
                 "F773, F774, F775, F776, F777, F778, F779, F780, F781, "
                 "F782, F783, F784, F785, F786, F787, F788, F789, F790, "
                 "F791, F792, F793, F794.")
    ok = ("Next free finding: **F795**" in text
          and ("Open findings: " + open_list) in text
          and "(F764 filed" in text and "CLOSED 2026-10-09 wave-385 lane 2" in text
          and "(F765 filed" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------- p1 filed shapes

@_t
def test_p1_f764_substr_filed():
    """F764 filed s1: substr(-9) blocks and decodes node-exactly."""
    p = "(function(){var s='xx%s';return s.substr(-9)+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f764_substring_filed():
    """F764 filed s2: substring(9,0) swap blocks, node-exact."""
    p = "(function(){var s='%sxx';return s.substring(9,0)+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f764_substr_variant():
    """F764 variant: substr(2,9) blocks, node-exact."""
    p = "(function(){var s='ab%s';return s.substr(2,9)+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f764_substring_variant():
    """F764 variant: substring(11,2) swap blocks, node-exact."""
    p = "(function(){var s='ab%szz';return s.substring(11,2)+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f765_match_filed():
    """F765 filed s1: char-class match blocks, node-exact."""
    p = ("(function(){var m='xx%syy'.match(/xoxb-[0-9]+/);"
         "return m[0]+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f765_matchall_filed():
    """F765 filed s2: char-class matchAll blocks, node-exact."""
    p = ("(function(){var m=[...'xx%syy'.matchAll(/xoxb-[0-9]+/g)];"
         "return m[0][0]+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f765_match_group():
    """F765 variant: capture group, m[1] recovers."""
    p = ("(function(){var m='xx%syy'.match(/(xoxb-[0-9]+)/);"
         "return m[1]+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f765_matchall_group():
    """F765 variant: capture group under matchAll, m[0][1] recovers."""
    p = ("(function(){var m=[...'xx%syy'.matchAll(/(xoxb-[0-9]+)/g)];"
         "return m[0][1]+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, FULL)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------- p2 generalizations

@_t
def test_p2_substring_noarg():
    """substring() with no args returns the whole string."""
    p = "(function(){var s='%s';return s.substring();})()" % _A
    return ("HELD" if _decodes_to(p, _A) else "BREAK", "noarg")


@_t
def test_p2_substring_negative():
    """substring(-5,4) clamps negative to 0, node-exact."""
    p = "(function(){var s='xxx%s';return s.substring(-5,4);})()" % _A
    return ("HELD" if _decodes_to(p, "xxxx") else "BREAK", "neg-clamp")


@_t
def test_p2_substr_noarg():
    """substr() with no args returns the whole string."""
    p = "(function(){var s='%s';return s.substr();})()" % _A
    return ("HELD" if _decodes_to(p, _A) else "BREAK", "noarg")


@_t
def test_p2_substr_neglength():
    """substr(3,-2) yields empty (negative length), node-exact."""
    p = "(function(){var s='xxx%s';return 'Q'+s.substr(3,-2);})()" % _A
    return ("HELD" if _decodes_to(p, "Q") else "BREAK", "neg-len")


@_t
def test_p2_match_negated_class():
    """[^!] negated class blocks, node-exact."""
    p = ("(function(){var m='%s!!'.match(/[^!]+/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) and _decodes_to(p, FULL) else "BREAK",
            "neg-class")


@_t
def test_p2_match_greedy_backtrack():
    """Greedy a+ab backtracks node-exactly (aaab, not aab)."""
    p = ("(function(){var m='xxaaabyy'.match(/a+ab/);"
         "return m[0];})()")
    return ("HELD" if _decodes_to(p, "aaab") else "BREAK", "backtrack")


@_t
def test_p2_matchall_multi():
    """matchAll /g over repeated credentials returns both."""
    p = ("(function(){var m=[...'%s,%s'.matchAll(/xoxb-[0-9]+/g)];"
         "return m[0][0]+m[1][0];})()" % (_A, _A))
    return ("HELD" if _decodes_to(p, _A + _A) else "BREAK", "multi")


# ------------------------------------------------- p3 bounds fail closed

@_t
def test_p3_substring_nonliteral_bound():
    """substring(i,4) with non-literal bound fails closed (miss)."""
    p = ("(function(){var s='xxx%s';var i=1;return s.substring(i,4);})()"
         % _A)
    return ("HELD" if not _blocked(p) else "BREAK", "nonlit-bound")


@_t
def test_p3_substr_fractional():
    """substr(1.5) fails closed (engine truncates; we refuse coded)."""
    p = "(function(){var s='xxx%s';return s.substr(1.5);})()" % _A
    return ("HELD" if not _blocked(p) else "BREAK", "fractional")


@_t
def test_p3_match_unmodeled_star():
    """x* quantifier fails closed (miss)."""
    p = ("(function(){var m='xx%syy'.match(/xoxb-[0-9]*/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "star")


@_t
def test_p3_match_dot_anychar():
    """Top-level . (any-char) fails closed."""
    p = ("(function(){var m='xx%syy'.match(/xoxb.+/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "dot")


@_t
def test_p3_match_escaped():
    """Escaped \\d fails closed."""
    p = ("(function(){var m='xx%syy'.match(/xoxb-\\d+/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "escape")


@_t
def test_p3_match_bad_range():
    """Out-of-order class range fails closed (engine throws)."""
    p = ("(function(){var m='xx%syy'.match(/[z-a]+/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "bad-range")


@_t
def test_p3_match_nested_group():
    """Nested groups fail closed."""
    p = ("(function(){var m='xx%syy'.match(/((xoxb)-[0-9]+)/);"
         "return m[1]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "nested-group")


@_t
def test_p3_matchall_nonglobal():
    """matchAll without /g fails closed (engine TypeError)."""
    p = ("(function(){var m=[...'xx%syy'.matchAll(/xoxb-[0-9]+/)];"
         "return m[0][0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "nonglobal")


@_t
def test_p3_match_nomatch():
    """match with no match fails closed (engine null)."""
    p = ("(function(){var m='qqzz-9999yy'.match(/xoxb-[0-9]+/);"
         "return m[0]+'%s';})()" % _B)
    return ("HELD" if not _blocked(p) else "BREAK", "nomatch")


@_t
def test_p3_match_neged_empty_class():
    """[^] matches any char (engine) -- decodes node-exactly, blocks."""
    p = ("(function(){var m='xx%syy'.match(/xoxb-[^]123/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if _blocked(p) and _decodes_to(p, FULL) else "BREAK",
            "neg-empty")


@_t
def test_p3_match_empty_class():
    """[] never matches (engine) -- miss, fail closed."""
    p = ("(function(){var m='xx%syy'.match(/[]/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "empty-class")


@_t
def test_p3_match_leading_dash_range():
    """[--0] is the U+002D-U+0030 range (engine), node-exact."""
    p = "(function(){var m='a-./0b'.match(/[--0]+/);return m[0];})()"
    return ("HELD" if _decodes_to(p, "-./0") else "BREAK", "dash-range")


@_t
def test_p3_matchall_oob():
    """matchAll m[5][0] out-of-bounds fails closed (engine undefined)."""
    p = ("(function(){var m=[...'xx%syy'.matchAll(/xoxb-[0-9]+/g)];"
         "return m[5][0]+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "oob")


# ------------------------------------------------- p4 siblings

@_t
def test_p4_f694_plain_match():
    """F694 sibling: F603 regex-plain match still decodes (no regress)."""
    p = ("(function(){var m='xx%syy'.match(/xoxb/);"
         "return m[0]+'%s';})()" % (_A, _B))
    return ("HELD" if _decodes_to(p, "xoxb" + _B) else "BREAK", "f694-plain")


@_t
def test_p4_f694_plain_matchall():
    """F694 sibling: F603 regex-plain matchAll m[0][0] still decodes."""
    p = ("(function(){var m=[...'xx%syy'.matchAll(/xoxb/g)];"
         "return m[0][0]+'%s';})()" % (_A, _B))
    return ("HELD" if _decodes_to(p, "xoxb" + _B) else "BREAK",
            "f694-matchall")


@_t
def test_p4_f624_slice():
    """F624 sibling: slice still decodes (no regress)."""
    p = "(function(){var s='xx%s';return s.slice(0,2)+'%s';})()" % (_A, _B)
    return ("HELD" if _decodes_to(p, "xx" + _B) else "BREAK", "f624-slice")


@_t
def test_p4_replace_untouched():
    """replace keeps the F603 grammar: char-class replace misses."""
    p = ("(function(){var s='xx%syy';"
         "return s.replace(/xoxb-[0-9]+/,'Q')+'%s';})()" % (_A, _B))
    return ("HELD" if not _blocked(p) else "BREAK", "replace-scope")


# ------------------------------------------------- p5 quiet / honest

@_t
def test_p5_junk_quiet():
    """Noisy junk with no credential stays quiet."""
    junk = ("lorem ipsum " * 40 + "var s='hello'; s.substring(1,3); "
            "'ab'.match(/x+/); " + "dolor sit " * 40)
    return ("HELD" if not _blocked(junk) else "BREAK", "junk-quiet")


@_t
def test_p5_honest_substring():
    """substring on honest text (no credential) misses."""
    p = "(function(){var s='hello world';return s.substring(0,5);})()"
    return ("HELD" if not _blocked(p) else "BREAK", "honest-substr")


@_t
def test_p5_honest_match():
    """match on honest text misses."""
    p = "(function(){var m='abc123'.match(/[0-9]+/);return m[0];})()"
    return ("HELD" if not _blocked(p) else "BREAK", "honest-match")


# ------------------------------------------------- p6 perf

@_t
def test_p6_perf_200_sites():
    """200 mixed sites decode in well under the budget."""
    sites = []
    for k in range(200):
        if k % 4 == 0:
            sites.append("(function(){var s='xx%s';return s.substr(-9)+'%s';})()"
                         % (_A, _B))
        elif k % 4 == 1:
            sites.append("(function(){var m='xx%syy'.match(/xoxb-[0-9]+/);"
                         "return m[0]+'%s';})()" % (_A, _B))
        elif k % 4 == 2:
            sites.append("lorem ipsum " * 30 + "substring(1,2)" + "dolor " * 30)
        else:
            sites.append("(function(){var m=[...'xx%syy'.matchAll(/(xoxb-[0-9]+)/g)];"
                         "return m[0][1]+'%s';})()" % (_A, _B))
    text = " ".join(sites)
    t0 = time.time()
    hits = sum(1 for _ in [dlp.find_credential(text)])
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK", "200sites %.2fs" % dt)


# ------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    results = []
    for battery in ("w384_attack_probes.py",
                    "w381_f688f694close_probes.py",
                    "w385_f764_redfirst.py",
                    "w385_f765_redfirst.py"):
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        real_break = footer_break = 0
        for line in out.splitlines():
            if "footer" in line and line.rstrip().startswith(
                    ("test_b0_footer_state: BREAK",
                     "test_p8_pin_footer: BREAK")):
                footer_break += 1
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    real_break = int(parts[1])
                except (IndexError, ValueError):
                    pass
        # This lane stamps F764/F765 closed lane-locally; neighbor
        # footer pins are merge-owned (wave-305/306 class).
        real_break -= footer_break
        results.append((battery, real_break))
    bad = [b for b, r in results if r != 0]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green(depth-1): %s" % (results,))


@_t
def test_p7_green_check():
    """Green check: neighbors stay green (depth-1)."""
    return _green_check()


# ------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    brk = held = err = 0
    for fn in _TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            brk += 1
        elif verdict == "HELD":
            held += 1
        else:
            err += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
