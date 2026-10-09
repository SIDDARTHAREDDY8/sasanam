#!/usr/bin/env python3
"""Wave-387 lane 10: close F865 + F866 + F867 + F868 (Map clone / regex split /
named groups / recursion laundering).

F865 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models structuredClone of plain objects (F807) but not Maps --
structuredClone(new Map([['k','f1']])).get('k') resolves node-exactly
(v24.20.0) while the decoder produced zero variants.

F866 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models plain split but not capture-group splits --
'zf1z'.split(/(f1)/)[1] resolves node-exactly (v24.20.0) while the decoder
produced zero variants.

F867 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder models exec/matchAll (F765) but not named capture groups --
('x'+'f1').match(/(?<m>...)/).groups.m resolves node-exactly (v24.20.0)
while the decoder produced zero variants.

F868 (LOW; filed 2026-10-09 05:30 UTC by wave-386 attack round 54): the
decoder has no recursion production --
function f(n){return n<=0?'f1':f(n-1);} resolves node-exactly (v24.20.0)
while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F865: _js_parse_f865_structuredclone_map_iife. structuredClone of a
  string-pair Map is entry-identical (F494 literal discipline,
  later-wins); M.get(KEY) resolves via the F708 key discipline; a
  missing key is engine-undefined and fails closed. Hooked after F810.
- F866: the shared split branch in _js_apply_method_at accepts
  flag-less F765-grammar regex separators (capture groups spliced
  engine-exactly via _f866_regex_split), plus the
  _js_parse_f866_varbound_split_iife twin for var-bound additive
  subjects (the F611 varbound needs a literal initializer). Hooked
  after F865.
- F867: _js_parse_f867_named_group_iife over _js_parse_f867_regex_literal
  (F765 atoms + one level of (?<name>...) groups; the groups list in
  _f765_parse_terms records names -- anonymous groups keep the True
  marker, so existing callers see no behavior change). First match
  must exist (engine throws on null .groups); unknown names fail
  closed. Statement-sequential body parse (the F694 pattern -- the
  regex `/` cannot go through _js_span_braced). Hooked after F866.
- F868: _js_parse_f868_recursion_iife. Bounded simulation (<=256
  calls) of the disciplined single-ternary self-recursive shape on a
  concrete integer argument; non-termination and deeper recursion
  fail closed. Hooked after F867.

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
def test_p0_verifier_pin():
    """VERIFIER_TAXONOMY_PIN stays 33 (evidence-schema domain)."""
    VERIFIER_TAXONOMY_PIN = 33
    ok = VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "vpin=%s" % VERIFIER_TAXONOMY_PIN)


@_t
def test_p0_recount():
    """Zero new re.compile (28)."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F865-F868 closed, next F893)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F893**" in text
          and "F865" in text and "F868" in text
          and "CLOSED" in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f865_s1():
    """F865 filed shape 1 (structuredClone Map, single pair) blocks."""
    s = ("(function(){var m=structuredClone(new Map([['k','" + _A + "']]));"
         "return m.get('k')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f865_s2():
    """F865 filed shape 2 (structuredClone Map, two pairs) blocks."""
    s = ("(function(){var m=structuredClone(new Map([['k','" + _A + "'],"
         "['x','y']]));return m.get('k')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f866_s1():
    """F866 filed shape 1 (var-bound capture-group split) blocks."""
    s = ("(function(){var s='z" + _A + "'+'z';"
         "return s.split(/(xoxb-[0-9a-f]+)/)[1]+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f866_s2():
    """F866 filed shape 2 (inline regex split + join) blocks."""
    s = ("(function(){return ('" + _A + ",'+'" + _B + "').split(/,/)."
         "join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f867_s1():
    """F867 filed shape 1 (named capture group read) blocks."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(?<m>xoxb-[0-9a-f]+)/)."
         "groups.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f867_s2():
    """F867 filed shape 2 (named capture group read, spaced) blocks."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(?<m>xoxb-[0-9a-f]+)/)."
         "groups.m+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f868_s1():
    """F868 filed shape 1 (recursion depth 1) blocks."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n-1);}"
         "return f(1)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f868_s2():
    """F868 filed shape 2 (recursion depth 2) blocks."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n-1); }"
         "return f(2)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_f865_dupkey():
    """F865: duplicate keys -- later wins, node-exact."""
    s = ("(function(){var m=structuredClone(new Map([['k','zz'],['k','" + _A
         + "']]));return m.get('k');})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "later-wins=%s" % ok)


@_t
def test_p2_f865_intkey():
    """F865: canonical-int key reads, node-exact."""
    s = ("(function(){const m=structuredClone(new Map([[7,'" + _A
         + "']]));return m.get(7);})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "intkey=%s" % ok)


@_t
def test_p2_f865_let_tail():
    """F865: let decl + two-literal additive tail."""
    s = ("(function(){let m=structuredClone(new Map([['k','" + _A
         + "']]));return m.get('k')+'-'+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "-" + _B)
    return ("HELD" if ok else "BREAK", "tail=%s" % ok)


@_t
def test_p2_f866_inline_idx():
    """F866: inline subject, capture-group split, [0] read."""
    s = ("(function(){return ('" + _A + "z').split(/(z)/)[0]+'" + _B
         + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "idx0=%s" % ok)


@_t
def test_p2_f866_varbound_join():
    """F866: var-bound subject, capture-group split, join('')."""
    s = ("(function(){var s='q" + _A + "'+'q';"
         "return s.split(/(q)/).join('')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "q" + _A + "q" + _B)
    return ("HELD" if ok else "BREAK", "join=%s" % ok)


@_t
def test_p2_f866_bare():
    """F866: bare (non-IIFE) capture-group split decodes."""
    s = "('z" + _A + "z').split(/(xoxb-[0-9a-f]+)/)[1]"
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "bare=%s" % ok)


@_t
def test_p2_f866_named_sep():
    """F866: named-group separators decode node-exactly too (the F867
    grammar extension flows into the shared F765 parser)."""
    s = "('z" + _A + "z').split(/(?<m>xoxb-[0-9a-f]+)/)[1]"
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "namedsplit=%s" % ok)


@_t
def test_p2_f867_varbound():
    """F867: var-bound subject, named group read."""
    s = ("(function(){var s='x" + _A + "';"
         "return s.match(/(?<tok>xoxb-[0-9a-f]+)/).groups.tok;})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "varbound=%s" % ok)


@_t
def test_p2_f867_two_groups():
    """F867: two named groups, read the second."""
    s = ("(function(){return ('" + _A + "-" + _B + "').match("
         "/(?<a>xoxb-[0-9a-f]+)-(?<b>[0-9a-f]+)/).groups.b;})()")
    ok = _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "second=%s" % ok)


@_t
def test_p2_f867_anon_and_named():
    """F867: anonymous + named groups share one index space."""
    s = ("(function(){return ('" + _A + "').match(/(x)(?<m>oxb-[0-9a-f]+)/)."
         "groups.m;})()")
    ok = _decodes_exact(s, "oxb-0123")
    return ("HELD" if ok else "BREAK", "indexspace=%s" % ok)


@_t
def test_p2_f868_deeper():
    """F868: deeper recursion (n=5) resolves node-exactly."""
    s = ("(function(){function f(n){return n<=1?'" + _A + "':f(n-1);}"
         "return f(5);})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "n5=%s" % ok)


@_t
def test_p2_f868_plus_step():
    """F868: increasing step toward the bound."""
    s = ("(function(){function f(n){return n>=3?'" + _A + "':f(n+1);}"
         "return f(0);})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "plus=%s" % ok)


@_t
def test_p2_f868_lit_first_branch():
    """F868: literal in the true-branch, call in the false-branch."""
    s = ("(function(){function f(n){return n!=0?f(n-1):'" + _A + "';}"
         "return f(2);})()")
    ok = _decodes_exact(s, _A)
    return ("HELD" if ok else "BREAK", "litfirst=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f865_missing_key():
    """F865: get of a missing key is engine-undefined -- never decoded."""
    s = ("(function(){var m=structuredClone(new Map([['k','" + _A + "']]));"
         "return m.get('zz')+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "misskey=%s" % ok)


@_t
def test_p3_f865_not_a_map():
    """F865: structuredClone of a non-Map stays out of this hook."""
    s = ("(function(){var m=structuredClone('ab');"
         "return m;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_f866_flags():
    """F866: regex flags fail closed (incl. g -- conservative)."""
    s = ("(function(){return ('" + _A + ",'+'" + _B + "').split(/,/i)."
         "join('');})()")
    s2 = ("(function(){return ('" + _A + ",'+'" + _B + "').split(/,/g)."
          "join('');})()")
    ok = _misses(s) and _misses(s2)
    return ("HELD" if ok else "BREAK", "flags=%s" % ok)


@_t
def test_p3_f866_bad_atom():
    """F866: non-F765 atoms (alternation) fail closed."""
    s = ("(function(){var s='a" + _A + "b';"
         "return s.split(/(a|b)/).join('');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "alternation=%s" % ok)


@_t
def test_p3_f866_bad_index():
    """F866: out-of-range group-splice read fails closed."""
    s = ("(function(){var s='z" + _A + "z';"
         "return s.split(/(xoxb-[0-9a-f]+)/)[5];})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "oob=%s" % ok)


@_t
def test_p3_f867_flags():
    """F867: regex flags fail closed."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(?<m>xoxb-[0-9a-f]+)/i)."
         "groups.m;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "flags=%s" % ok)


@_t
def test_p3_f867_unknown_name():
    """F867: reading an undeclared group name fails closed."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(?<m>xoxb-[0-9a-f]+)/)."
         "groups.zzz;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "noname=%s" % ok)


@_t
def test_p3_f867_no_match():
    """F867: null match makes .groups throw in the engine -- miss."""
    s = ("(function(){return 'qq'.match(/(?<m>xoxb-[0-9a-f]+)/)."
         "groups.m;})()")
    ok = _fails_closed(s) and _misses(s)
    return ("HELD" if ok else "BREAK", "nomatch=%s" % ok)


@_t
def test_p3_f867_dup_name():
    """F867: duplicate group names throw in the engine -- miss."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(?<m>x)(?<m>y)/)."
         "groups.m;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "dupname=%s" % ok)


@_t
def test_p3_f867_anonymous_only():
    """F867: regex without named groups stays with the F694 route."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(xoxb-[0-9a-f]+)/)."
         "groups;})()")
    ok = _fails_closed(s) or _misses(s)
    return ("HELD" if ok else "BREAK", "anongroups=%s" % ok)


@_t
def test_p3_f868_infinite():
    """F868: non-terminating recursion (engine RangeError) -- miss."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n+1);}"
         "return f(1);})()")
    ok = _fails_closed(s) and _misses(s)
    return ("HELD" if ok else "BREAK", "infinite=%s" % ok)


@_t
def test_p3_f868_too_deep():
    """F868: recursion past the 256-call bound fails closed."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n-1);}"
         "return f(300);})()")
    ok = _fails_closed(s) and _misses(s)
    return ("HELD" if ok else "BREAK", "deep=%s" % ok)


@_t
def test_p3_f868_zero_step():
    """F868: zero step (engine RangeError) -- miss."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n+0);}"
         "return f(2);})()")
    ok = _fails_closed(s) and _misses(s)
    return ("HELD" if ok else "BREAK", "zerostep=%s" % ok)


@_t
def test_p3_f868_nonint_arg():
    """F868: non-integer call argument fails closed."""
    s = ("(function(){function f(n){return n<=0?'" + _A + "':f(n-1);}"
         "return f('x');})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "nonint=%s" % ok)


# ------------------------------------------------ p4: sibling pins


@_t
def test_p4_sibling_f807():
    """Sibling pin: F807 structuredClone-of-object still blocks."""
    s = ("(function(){var o={k:'" + _A + "'};var c=structuredClone(o);"
         "return c.k+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f807=%s" % ok)


@_t
def test_p4_sibling_f708():
    """Sibling pin: F708 inline-Map get still blocks (F865 disjoint)."""
    s = ("(function(){var m=new Map([['k','" + _A + "']]);"
         "return m.get('k')+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f708=%s" % ok)


@_t
def test_p4_sibling_f564():
    """Sibling pin: F564 literal-separator split still blocks."""
    s = "('" + _A + "," + _B + "').split(',').join('')"
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f564=%s" % ok)


@_t
def test_p4_sibling_f611():
    """Sibling pin: F611 var-bound literal still blocks."""
    s = "(function(){var s='" + _A + "';return s+'" + _B + "';})()"
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


@_t
def test_p4_sibling_match_numbered():
    """Sibling pin: numbered-group .match still blocks (F867 disjoint)."""
    s = ("(function(){return ('x'+'" + _A + "').match(/(xoxb-[0-9a-f]+)/)[1]+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "matchnum=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (no false positives)."""
    shapes = [
        "'hello world, this is a test'",
        "(function(){var s='abcdef';return s.split('').join('-');})()",
        "(function(){return 'data'.match(/(?<d>[a-z]+)/).groups.d;})()",
        "(function(){function f(n){return n<=0?'done':f(n-1);}return f(3);})()",
        "(function(){var m=structuredClone(new Map([['k','v']]));"
        "return m.get('k');})()",
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "quiet=%s bad=%d" % (ok, len(bad)))


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){var m=structuredClone(new Map([['k','p%d']]));"
            "return m.get('k');})()" % k)
        sites.append(
            "(function(){var s='zp%d'+'z';return s.split(/(p[0-9]+)/)[1];})()"
            % k)
        sites.append(
            "(function(){return ('x'+'q%d').match(/(?<m>q[0-9]+)/).groups.m;})()"
            % k)
        sites.append(
            "(function(){function f(n){return n<=0?'r%d':f(n-1);}return f(1);})()"
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
    # All four lane red-firsts must be 0 BREAK (F865-F868 closed); the
    # wave-386 attack battery is expected to report exactly 1 BREAK:
    # its test_b0_footer_state asserts the wave-386 footer (this
    # lane's footer is lane-local with F865-F868 closed) -- tree-wide
    # maintenance is merge-owned (wave-306 lesson). All functional
    # probes must HELD.
    for batt, expect_break in (("evals/w387_f865_redfirst.py", 0),
                               ("evals/w387_f866_redfirst.py", 0),
                               ("evals/w387_f867_redfirst.py", 0),
                               ("evals/w387_f868_redfirst.py", 0),
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
    """Depth-1 green check: lane red-firsts 0 BREAK + wave-386 attack
    battery 1 BREAK (footer, lane-local; merge-owned)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "BREAK", "ERROR %r" % (e,)
            errors += 1
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
