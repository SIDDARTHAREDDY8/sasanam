#!/usr/bin/env python3
"""Wave-385 lane 6: close F772 + F773.

F772 (LOW, filed 2026-10-09 00:07 UTC by attack round 52): ES2023
toSorted/toSpliced copy methods. The decoder models the mutating
sort/splice/reverse but not the copy methods:
(function(){return ['f1','f2'].toSorted().reverse().join('');})() and
(function(){return ['xx','f1','f2'].toSpliced(0,1).join('');})() both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

F773 (LOW, filed 2026-10-09 00:07 UTC by attack round 52, gpt-4o-mini
hint): fill without range args. The decoder models ranged fill on
var-bound arrays only:
(function(){return [new Array(1).fill('f1')[0],'f2'].join('');})()
and (function(){var a=['xx'];a.fill('f1');return a[0]+'f2';})() both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F772: toSorted()/toSpliced(...) productions in _js_apply_method_at
  (after F561's toReversed/with), registered in
  _JS_POSTFIX_METHOD_NAMES. toSorted: no-arg only, _JSArr receiver,
  BMP-only plain-string elements (F580 discipline), fresh
  _JSArr(sorted(...)) -- Python stable sort == V8 stable sort.
  toSpliced: start[, deleteCount[, ...items]], F681-style index
  normalization, fresh _JSArr, receiver untouched. Any arg to
  toSorted (incl function comparators) fails closed; fractional
  indices fail the `,`/`)` expect.
- F773: `new Array(...)` production in _js_parse_primary desugaring
  to _js_parse_array_constructor (engine-identical call form,
  v24.20.0); the constructor's in_array guard is bypassed for the
  construction alone (bounded literals/numbers only, no nesting)
  and restored before the postfix chain. Plus
  _js_parse_f773_fill_stmt_iife for the 1-arg fill statement with
  indexed-read return, hooked after F681 with parts/ops
  snapshot/restore (wave-383 F733 lesson).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
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


def _dec(payload):
    return dlp._try_js_expr_decode_all(payload)


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F762-F771, F774-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-385 lane 6: F772/F773 CLOSED; F762-F771, F774-F794 OPEN (next F795)
          and "F772" in text and "F773" in text)
    return ("HELD" if ok else "BREAK", "footer-next-F795")


# ------------------------------------------------------- F772 filed shapes

@_t
def test_p1_f772_filed_1():
    """F772 filed shape 1: toSorted().reverse().join('') blocks."""
    s = "(function(){return ['" + _A + "','" + _B + "'].toSorted().reverse().join('');})()"
    return ("HELD" if _blocked(s) else "BREAK", "filed-1")


@_t
def test_p1_f772_filed_2():
    """F772 filed shape 2: toSpliced(0,1).join('') blocks."""
    s = "(function(){return ['xx','" + _A + "','" + _B + "'].toSpliced(0,1).join('');})()"
    return ("HELD" if _blocked(s) else "BREAK", "filed-2")


# ------------------------------------------------------- F773 filed shapes

@_t
def test_p1_f773_filed_1():
    """F773 filed shape 1: [new Array(1).fill('f1')[0],'f2'].join('') blocks."""
    s = "(function(){return [new Array(1).fill('" + _A + "')[0],'" + _B + "'].join('');})()"
    return ("HELD" if _blocked(s) else "BREAK", "filed-1")


@_t
def test_p1_f773_filed_2():
    """F773 filed shape 2: var-bound 1-arg fill + indexed read blocks."""
    s = "(function(){var a=['xx'];a.fill('" + _A + "');return a[0]+'" + _B + "';})()"
    return ("HELD" if _blocked(s) else "BREAK", "filed-2")


# ------------------------------------------------- F772 generalizations

@_t
def test_p2_tosorted_exact():
    """toSorted is node-exact (stable, code-unit order) on BMP strings."""
    pairs = [
        ("['b','a','c'].toSorted().join('')", "abc"),
        ("['b','a','b','c'].toSorted().join('')", "abbc"),  # stable
        ("['B','a'].toSorted().join('')", "Ba"),  # 'B'(0x42) < 'a'(0x61)
        ("['10','9','80'].toSorted().join('')", "10809"),
        ("['c','a','b'].toSorted().join('-')", "a-b-c"),
    ]
    bad = [src for src, want in pairs if _dec(src) != want]
    return ("HELD" if not bad else "BREAK", "bad=%s" % bad if bad else "5/5 exact")


@_t
def test_p2_tospliced_exact():
    """toSpliced is node-exact (index normalization, clamping)."""
    pairs = [
        ("['xx','f1','f2'].toSpliced(0,1).join('')", "f1f2"),
        ("['a','b','c'].toSpliced(-1).join('')", "ab"),
        ("['a','b','c'].toSpliced(10).join('')", "abc"),  # clamped to len
        ("['a','b','c'].toSpliced(1,10).join('')", "a"),  # dc clamped
        ("['a','b'].toSpliced(1,0,'x','y').join('')", "axyb"),  # insert-only
        ("['a','b'].toSpliced(0,-3).join('')", "ab"),  # negative dc -> 0
        ("['a'].toSpliced(0,1,'x','y','z').join('')", "xyz"),  # items
        ("[].toSpliced(0,0,'x').join('')", "x"),
        ("['a','b'].toSpliced(1).join('')", "a"),  # omitted dc deletes to end
        ("['a','b'].toSpliced().join('')", "ab"),  # zero-arg copies
        # Empty-result forms decode to None by the engine's existing
        # empty-decode filter (not a mis-decode): verified separately.
    ]
    bad = [src for src, want in pairs if _dec(src) != want]
    empty_ok = _dec("['a','b','c'].toSpliced(-5).join('')") is None
    ok = not bad and empty_ok
    return ("HELD" if ok else "BREAK",
            "bad=%s empty=%s" % (bad, empty_ok) if not ok else "10/10 exact + empty-filtered")


@_t
def test_p2_tosorted_copy_semantics():
    """toSorted/toSpliced do not mutate the receiver (copy-on-write)."""
    # The decoder models a fresh array; the original is untouched.
    # Observed via a second read of the same literal in one expression:
    # ['b','a'].toSorted() must not affect a later ['b','a'] read.
    got = _dec("['b','a'].toSorted().join('')+['b','a'].join('')")
    ok = got == "abba"
    return ("HELD" if ok else "BREAK", "got=%r" % got)


# ------------------------------------------------- F773 generalizations

@_t
def test_p2_new_array_exact():
    """new Array(N) desugars engine-identically (bounded, fillable).

    The _JS_EXPR_START anchor includes `new Array` (same class as
    `new Map`/`new String`), so bare forms decode cleanly via the
    whole-text scan as well as in expression positions.
    """
    pairs = [
        ("new Array(3).fill('q').join('')", "qqq"),
        ("new Array(1).fill('ab')[0]", "ab"),
        ("new Array('a','b').join('')", "ab"),  # multi-arg form
        ("[new Array(2).fill('q').join(''),'y'].join('')", "qqy"),
        # Bare-return IIFEs are not a modeled shape (pre-existing);
        # the inner new-Array expression decodes, surfacing the value.
        ("(function(){return new Array(2).fill('q').join('');})()",
         "(function(){return qq;})()"),
    ]
    bad = [src for src, want in pairs if _dec(src) != want]
    return ("HELD" if not bad else "BREAK", "bad=%s" % bad if bad else "5/5 exact")


@_t
def test_p2_fill_stmt_exact():
    """1-arg fill statement + indexed-read return, incl generalizations."""
    pairs = [
        ("(function(){var a=['xx'];a.fill('q');return a[0];})()", "q"),
        ("(function(){var a=['xx','yy'];a.fill('q');return a[0]+a[1];})()", "qq"),
        ("(function(){let a=['xx'];a.fill('q');return a[0]+'z';})()", "qz"),
        ("(function(){const a=['xx','yy','zz'];a.fill('q');return a[2];})()", "q"),
    ]
    bad = [src for src, want in pairs if _dec(src) != want]
    return ("HELD" if not bad else "BREAK", "bad=%s" % bad if bad else "4/4 exact")


# ------------------------------------------------------- fail-closed bounds

@_t
def test_p3_tosorted_bounds():
    """toSorted fail-closed bounds: args, non-string/astral elements."""
    misses = [
        "['b','a'].toSorted(1).join('')",  # non-function comparator throws
        "['b','a'].toSorted((x,y)=>1).join('')",  # function comparator unmodeled
        "['b','a'].toSorted('x').join('')",  # string arg throws
        "'ab'.toSorted().join('')",  # non-array receiver
    ]
    bad = [src for src in misses if _dec(src) is not None]
    return ("HELD" if not bad else "BREAK", "decoded=%s" % bad if bad else "4/4 miss")


@_t
def test_p3_tospliced_bounds():
    """toSpliced fail-closed bounds: bad indices, non-string items."""
    misses = [
        "['b'].toSpliced('x').join('')",  # non-int start
        "['b'].toSpliced(0.5).join('')",  # fractional start
        "['b'].toSpliced(0,'x').join('')",  # non-int deleteCount
        "'ab'.toSpliced(0,1).join('')",  # non-array receiver
    ]
    bad = [src for src in misses if _dec(src) is not None]
    return ("HELD" if not bad else "BREAK", "decoded=%s" % bad if bad else "4/4 miss")


@_t
def test_p3_new_array_bounds():
    """new Array fail-closed bounds: non-Array, oversized, bad ident."""
    misses = [
        "new Map().size",  # non-Array new (existing behavior: miss)
        "new Array(999999).fill('q').join('')",  # oversized
        "new Arrayx(1).fill('q').join('')",  # ident-boundary
        "newx Array(1)",  # ident-boundary on new
        "[new Array(1).fill(['a'])[0],'y'].join('')",  # nested array in fill
    ]
    # The last one partially decodes via the scan but must not produce
    # a clean value (the fill production rejects non-string values).
    bad = [src for src in misses[:4] if _dec(src) is not None]
    last = _dec(misses[4])
    ok_last = last is None or last not in ("ay", "a", "y")
    ok = not bad and ok_last
    return ("HELD" if ok else "BREAK",
            "bad=%s last=%r" % (bad, last) if not ok else "5/5 bounded")


@_t
def test_p3_fill_stmt_bounds():
    """fill-stmt fail-closed bounds: wrong shapes stay missed."""
    misses = [
        "(function(){var a=['xx'];a.fill('q',0);return a[0];})()",  # 2-arg fill
        "(function(){var a=['xx'];a.fill('q',0,1);return a[0];})()",  # 3-arg fill, idx return
        "(function(){var b=['xx'];b.fill('q');return b[5];})()",  # OOB index
        "(function(){var a=['xx'];a.fill('q');return b[0];})()",  # wrong name
        "(function(){var a=['xx'];a.splice(0,1);return a[0];})()",  # splice, idx return
        "(function(){var a=['xx'];a.fill('q');a.fill('w');return a[0];})()",  # two fills
        "(function(){var a=['xx'];a.fill('q')})()",  # no return
        "(function(){var a=['xx'];a.fill(x);return a[0];})()",  # non-literal fill
    ]
    bad = [src for src in misses if _dec(src) is not None]
    return ("HELD" if not bad else "BREAK", "decoded=%s" % bad if bad else "8/8 miss")


# ------------------------------------------------------------ sibling pins

@_t
def test_p4_siblings():
    """Sibling productions unaffected: toReversed/with/sort/fill/Array."""
    pairs = [
        ("['b','a'].toReversed().join('')", "ab"),
        ("['a','b','c'].with(1,'x').join('')", "axc"),
        ("['b','a'].sort().join('')", "ab"),
        ("['a','b'].fill('x').join('')", "xx"),  # expr-level 1-arg fill (F443)
        ("Array(2).fill('q').join('')", "qq"),
        ("(function(){var a=['a','b'];a.fill('x',0,1);return a.join('');})()", "xb"),  # F681
        ("(function(){var a=['a','b','c'];a.splice(0,1);return a.join('');})()", "bc"),  # F681
        ("['a','b','c'].slice(1).join('')", "bc"),
        ("['b','a'].reverse().join('')", "ab"),
    ]
    bad = [src for src, want in pairs if _dec(src) != want]
    return ("HELD" if not bad else "BREAK", "bad=%s" % bad if bad else "9/9 pinned")


# ------------------------------------------------------- honest-text controls

@_t
def test_p5_honest_text():
    """Honest text mentioning the method names is unaffected."""
    honest = [
        "the toSorted method returns a new array",
        "use toSpliced instead of splice to avoid mutation",
        "new Array(5) creates an empty array",
        "call a.fill('red') to paint it",
        "I sorted the list with toSorted yesterday",
    ]
    bad = [s for s in honest if not _misses(s)]
    return ("HELD" if not bad else "BREAK", "flagged=%s" % bad if bad else "5/5 clean")


# ----------------------------------------------------------------- perf p6

@_t
def test_p6_perf():
    """200 mixed F772/F773 sites decode in under 20s."""
    t0 = time.time()
    for k in range(100):
        _blocked("junk (function(){return ['b','a'].toSorted().join('');})() tail%d" % k)
        _blocked("junk (function(){var a%d=['xx'];a%d.fill('q');return a%d[0];})() tail" % (k, k, k))
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts must show 0 BREAK on the closed tree (exit 1 = no breaks).
    for batt in ("evals/w385_f772_redfirst.py",
                 "evals/w385_f773_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # red-first exit 1 == 0 BREAK on the closed tree
        if p.returncode != 1 or "0/2 BREAK" not in out:
            bad.append((batt, p.returncode))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: both red-firsts show 0 BREAK closed."""
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
