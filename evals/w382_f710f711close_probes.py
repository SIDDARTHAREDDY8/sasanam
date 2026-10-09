#!/usr/bin/env python3
"""Wave-382 lane 6: close F710 + F711 (Set.has and integer-precision residuals).

F710 (LOW; filed 2026-10-08 by wave-381 lane 8, attack round 49): F687
residual -- Set.has conditional reads bypass the bounded static
JS-expression decoder -- F687 (CLOSED) models WeakSet membership
markers, but a Set built from string literals with a string-literal
.has() key selects the fragment node-exactly (v24.20.0):
  (function(){var s=new Set(['k']);var f=s.has('k')?'f1':'xx';
   return f+'f2';})()
and the inline twin both node-evaluate to the exact credential while
the decoder produces zero variants. Distinct from F687
(WeakSet-specific shapes).

F711 (LOW; filed 2026-10-08 by wave-381 lane 7 as F700, renumbered at
the wave-381 merge -- the attack lane filed F700 first, wave-272
first-filing): integer object members above 2**53 mis-decode in F535
direct member-read positions -- the same bug class as F699
(with-scope positions, closed wave-381 lane 7):
  ({x:9007199254740993}).x+'f2'
node-evaluates (v24.20.0) to '9007199254740992f2' (IEEE-754 rounding)
while the decoder produced '9007199254740993f2': _js_parse_canonical_int
returns plain `str`, so integer provenance was lost and the F535
member-read path emitted the canonical text. Distinct from F699
(direct member reads vs with-scope resolution) and from F664/F698
(accessor descriptors).

Fix (gov/dlp.py, zero new re.compile):
- F710: _js_parse_f710_set_has_iife (+2 helpers), hooked after F687
  with its hook and trailing return intact (wave-379 lesson);
  disjoint by `new Set` vs `new WeakSet` head. Set keys are
  SameValueZero -- for string keys the static literal set is exact.
- F711: _js_parse_f535_value now wraps canonical-int values above
  2**53 in _JSNumStr (integer-literal provenance; small ints and
  quoted strings stay plain str, node-exact), and _jsobj_lookup
  raises _JSExprFail on _JSNumStr values -- the engine's float64
  diverges from the canonical text there, so any member read would
  mis-decode; fail closed. This is uniformly honest: node never
  produces the canonical text for >2**53 integer literals, so no
  legitimate decode is lost. F535 stays as it was -- only the
  residual is closed here.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
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


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f710_filed_var_binding():
    """F710 filed shape 1: var-bound Set.has conditional blocks + exact."""
    s = ("(function(){var s=new Set(['k']);var f=s.has('k')?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f710_filed_inline():
    """F710 filed shape 2: inline Set.has ternary blocks + exact."""
    s = ("(function(){var s=new Set(['q']);return (s.has('q')?'" + _A
         + "':'xx')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f711_filed_dot():
    """F711 filed shape 1: >2^53 dot member read fails closed (no mis-decode)."""
    s = "({x:9007199254740993}).x+'" + _B + "'"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p1_f711_filed_bracket():
    """F711 filed shape 2: >2^53 bracket member read fails closed."""
    s = "({x:9007199254740993})['x']+'" + _B + "'"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


# ------------------------------------------------ p2: node-exact variants


@_t
def test_p2_f710_negation():
    """F710 variant: !s.has selects the else branch, node-exact + blocks."""
    s = ("(function(){var s=new Set(['k']);return (!s.has('k')?'xx':'" + _A
         + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f710_miss_branch():
    """F710 variant: absent key selects the else branch, node-exact + blocks."""
    s = ("(function(){var s=new Set(['k']);return (s.has('zz')?'xx':'" + _A
         + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f710_multi_element():
    """F710 variant: multi-element Set, node-exact."""
    s = ("(function(){var s=new Set(['a','b']);return (s.has('b')?'" + _A
         + "':'xx')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f710_empty_set():
    """F710 variant: empty Set always misses, node-exact + blocks."""
    s = ("(function(){var s=new Set();return (s.has('k')?'xx':'" + _A
         + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f710_dedup():
    """F710 variant: duplicate literals collapse SameValueZero-exact."""
    s = ("(function(){var s=new Set(['k','k']);var f=s.has('k')?'" + _A
         + "':'xx';return f+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f710_const_let_ws():
    """F710 variant: const/let + whitespace tolerance, node-exact."""
    s = ("(function(){const s = new Set( [ 'k' ] ) ; let f = s.has( 'k' ) ? '"
         + _A + "' : 'xx' ; return f + '" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f711_negative_unsafe():
    """F711 variant: negative >2^53 int member fails closed (node rounds)."""
    s = "({x:-9007199254740993}).x+'" + _B + "'"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p2_f711_boundary_exact():
    """F711 variant: exactly 2^53 stays node-exact (boundary)."""
    s = "({x:9007199254740992}).x+'" + _B + "'"
    ok = _decodes_exact(s, "9007199254740992" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f711_sibling_safe():
    """F711 variant: safe sibling member still decodes exactly."""
    s = "({a:'" + _A + "',x:9007199254740993}).a+'" + _B + "'"
    ok = _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f711_small_int_exact():
    """F711 honest: small int member stays node-exact."""
    s = "({x:42}).x+'" + _B + "'"
    ok = _decodes_exact(s, "42" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f711_quoted_exact():
    """F711 honest: quoted >2^53 numeric string stays node-exact."""
    s = "({x:'9007199254740993'}).x+'" + _B + "'"
    ok = _decodes_exact(s, "9007199254740993" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f710_add_statement():
    """F710 bound: statement-form s.add() is out of scope, fails closed."""
    s = ("(function(){var s=new Set(['k']);s.add('q');return (s.has('q')?'"
         + _A + "':'xx')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f710_nonliteral_element():
    """F710 bound: non-literal Set element fails closed."""
    s = ("(function(){var k='k';var s=new Set([k]);return (s.has('k')?'"
         + _A + "':'xx')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f710_non_set_has():
    """F710 bound: .has on a non-Set binding fails closed."""
    s = ("(function(){var s={};return (s.has('k')?'" + _A + "':'xx')+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f710_nonliteral_key():
    """F710 bound: non-literal has() key fails closed."""
    s = ("(function(){var s=new Set(['k']);var k='k';return (s.has(k)?'"
         + _A + "':'xx')+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f710_weakset_disjoint():
    """F710 bound: WeakSet heads are F687's, not F710's (disjoint)."""
    s = ("(function(){var s=new WeakSet();var k={};s.add(k);"
         "return (s.has(k)?'" + _A + "':'xx')+'" + _B + "';})()")
    # F687 (CLOSED) owns this shape -- it must still decode exactly,
    # proving F710 did not steal or break it.
    ok = _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "f687-intact=%s" % ok)


@_t
def test_p3_f711_values_join():
    """F711 bound: Object.values join over unsafe int fails closed."""
    s = "Object.values({x:9007199254740993}).join('')"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f711_nested_member():
    """F711 bound: nested unsafe int member read fails closed."""
    s = "({o:{x:9007199254740993}}).o.x+'" + _B + "'"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


@_t
def test_p3_f711_withscope_still_closed():
    """F711 bound: F699 with-scope guard still fails closed (no regress)."""
    s = ("(function(){var o={x:9007199254740993};with(o){return x+'"
         + _B + "';}})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "fail-closed=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_f687_still_blocks():
    """Sibling: F687 WeakSet conditional still blocks + exact."""
    s = ("(function(){var w=new WeakSet();var k={};w.add(k);"
         "return (w.has(k)?'" + _A + "':'xx')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f535_basic_member():
    """Sibling: F535 basic member read still exact."""
    s = "({x:'" + _A + "'}).x+'" + _B + "'"
    ok = _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_f667_withscope_smallint():
    """Sibling: F667 with-scope small-int member still exact."""
    s = ("(function(){var o={x:42};with(o){return x+'" + _B + "';}})()")
    ok = _decodes_exact(s, "42" + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_open_neighbors_still_miss():
    """Neighbors F700/F701/F708/F709/F712 now CLOSED by sibling lanes (merge) -- their shapes block coded."""
    shapes = [
        # F700 flatMap residual
        "(function(){return ['" + _A + "','" + _B
        + "'].flatMap(function(f){return [f,''];}).join('');})()",
        # F701 getter on spread
        "(function(){var o={get x(){return '" + _A + "';}};"
        "return {...o}.x+'" + _B + "';})()",
        # F708 Map.get
        "(function(){var m=new Map([['k','" + _A + "']]);"
        "return m.get('k')+'" + _B + "';})()",
        # F709 loop += accum
        "(function(){var r='';var i=0;while(i<2){r+=['" + _A + "','" + _B
        + "'][i];i++;}return r;})()",
        # F712 (var-bound Map iteration reads)
        "(function(){var m=new Map([['k','" + _A + "']]);"
        "return [...m.entries()][0][1]+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "unblocked=%d" % len(bad))

# ------------------------------------------------ p5: junk-quiet, composition


@_t
def test_p5_junk_quiet():
    """Junk inputs stay quiet (no spurious decode)."""
    junks = [
        "(function(){var s=new Set(['k']);return (s.has('k')?'a':'b');})()",
        "({x:9007199254740993}).x",
        "(function(){var s=new Set();return s.has('k');})()",
        "({}).x",
    ]
    bad = [s for s in junks if _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "junk-blocks=%d" % len(bad))


@_t
def test_p5_composition():
    """Composition: F710 result feeds a second conditional, node-exact."""
    s = ("(function(){var s=new Set(['k']);var f=s.has('k')?'" + _A
         + "':'xx';var t=new Set([f]);return (t.has('" + _A + "')?'"
         + _B + "':'yy');})()")
    # t.has(_A) is true -> _B. Both Sets modeled; node-exact. (_B alone
    # is not credential-shaped, so this pins decoder exactness, not
    # the public-seam block -- p1 covers blocking.)
    ok = _decodes_exact(s, _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p6: pin, footer, no new regexes


@_t
def test_p6_pin_footer():
    """Pin 2143; lane-local footer (open F700-F709, F712 / next F713)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F921**" in text)  # Wave-382 lane 6: F710, F711 CLOSED; open F700-F709, F712 / next F713  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-382 lane 6: F710, F711 CLOSED; open F700-F709, F712 / next F713  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf


@_t
def test_p7_perf():
    """200 mixed F710/F711 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var s=new Set(['k%d']);return "
                      "(s.has('k%d')?'x%d':'y');})()" % (k, k, k))
        corpus.append("({x%d:9007199254740993}).x%d" % (k, k))
    big = "+".join("'%s'" % c for c in corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w381_f710_redfirst.py", 0),
                               ("evals/w381_f711_redfirst.py", 0),
                               ("evals/w381_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
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
def test_p8_green_check():
    """Depth-1 green check: F710/F711 red-firsts + wave-381 attack battery."""
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
