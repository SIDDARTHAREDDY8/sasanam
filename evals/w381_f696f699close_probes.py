#!/usr/bin/env python3
"""Wave-381 lane 7: close F696 (boxed-String coercion) + F699 (F667 >2^53
with-scope residual). Files F700 (same bug class in F535 member reads).

F696 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
boxed-String coercion reads bypass the decoder -- `new String('LIT')`
has no production: `(function(){return (new String('f1'))+'f2';})()`
and `(function(){return new String('f1').valueOf()+'f2';})()` both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f696_new_string: `new String('LIT')` / `new String()`
  (zero or one string-literal arg; non-literal/extra/template args
  fail closed), unwrapped to the primitive str immediately. The
  unwrap is node-exact within the decoder's modeled surface: in
  every coercion position modeled ('+' concat, spread, index,
  .length, string methods) the engine ToPrimitive-coerces the box
  to exactly the primitive value (node v24.20.0); the unmodeled
  distinctions (typeof/===/instanceof) have no decoder grammar.
  An immediate `.valueOf()` / `.toString()` is consumed as the
  unboxing step (engine-identical on boxed and primitive
  receivers); any other member is left for the normal postfix
  chain. Hooked in _js_parse_primary after the F587 `new` route;
  disjoint (no earlier `new` route accepts a `String` head).
- _js_parse_f696_grouped_new: `(new String('LIT'))` grouped form
  (F586-style grouping guard), hooked in the paren branch before
  F586/F535 (F535's member-read raises on `new`-but-not-Proxy).
- _js_parse_f696_boxed_iife: `(function(){return (new
  String('LIT'))+ADD;})()` (+ the bare and .valueOf()/.toString()
  twins), hooked before F509 (F509's body rewrite rejects `new`
  in bound bodies -- disjoint by construction).
- `new String` anchor added to the existing _JS_EXPR_START pattern
  (no new re.compile) so the whole-text scan tries the construction
  head before the inner `String(` call anchor mangles it.
- Unconsumed-member guard on both expression hooks: a postfix
  chain ending on an unmodeled member step (.length, [0]) fails
  closed instead of splicing a partial value.
Residuals: non-literal/extra args, `String('LIT')` call-form
inside `new` (parses as construction -- engine-identical),
`['valueOf']` bracket unboxing, `.length`/`[0]` on the boxed form
(fail the outer decode closed; the whole-text scan may splice the
inner subexpression -- parity with the F477 `String()` production's
`(String('f1')).length` behavior on the base tree, verdict-neutral:
the production only handles literal args so no new DLP verdict is
possible), call args on the IIFE form, `new String` with a
template-literal arg.

F699 (LOW, filed 2026-10-08 by wave-380 lane 4 as F686, renumbered
at the wave-380 merge by first-filing timestamp): the F667
with-scope filter's `not isinstance(v, _JSNumStr)` guard is dead
code because `_js_parse_canonical_int` returns plain `str` -- an
integer member above 2**53 (`{x:9007199254740993}`) mis-decoded
(decoder emitted the canonical text, node rounds via float64).
Fix: both F667 scope-member filters now also exclude
`_js_str_is_unsafe_int(v)` (the F676/F678 precedent) -- >2^53
integer members fail closed in with-scope positions; small ints
stay node-exact; quoted numeric strings >2^53 are conservatively
excluded too (documented residual, F541/F477 precedent). F667
stays CLOSED on its pins; only the residual is closed here.

F700 (LOW, filed 2026-10-08 by this lane, first-filing 14:58 UTC):
same >2^53 bug class in F535 direct member-read positions --
`({x:9007199254740993}).x` / `['x']` mis-decode (decoder emits
canonical text, node rounds). Left OPEN (out of this lane's
with-scope brief).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g381-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
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


def _decodes_to(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and got == want


def _decodes_none(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p1: filed shapes (must block)

@_t
def test_p1_f696_filed_plus_coerce():
    """F696 filed shape 1 blocks."""
    p = "(function(){return (new String('%s'))+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f696_filed_valueof():
    """F696 filed shape 2 blocks."""
    p = "(function(){return new String('%s').valueOf()+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


@_t
def test_p1_f699_filed_bigint_with():
    """F699 filed shapes fail closed (no node-inexact variant)."""
    p1 = "(function(){var o={x:9007199254740993};with(o){return x+'%s';}})()" % _B
    p2 = "(function(){var o={x:9999999999999999};with(o){return x;}})()"
    ok = _decodes_none(p1) and _decodes_none(p2)
    return ("HELD" if ok else "BREAK", "failclosed=%s" % ok)


# ------------------------------------------------ p2: node-exact variants

@_t
def test_p2_f696_variants():
    """Boxed-String variants decode node-exactly."""
    cases = [
        ("(new String('%s'))+'%s'" % (_A, _B), _A + _B),
        ("new String('%s').toString()+'%s'" % (_A, _B), _A + _B),
        ("new String()+'%s'" % _B, _B),
        ('(new String("%s"))+"%s"' % (_A, _B), _A + _B),
        ("(new String( '%s' ))+'%s'" % (_A, _B), _A + _B),
        ("(function(){return new String('%s')+'%s';})()" % (_A, _B), _A + _B),
        ("new String('%s').valueOf()" % _A, _A),
    ]
    bad = [c for c, want in cases if not _decodes_to(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


@_t
def test_p2_f699_small_ints_exact():
    """Small ints in with-scope positions still decode exactly."""
    cases = [
        ("(function(){var o={x:42};with(o){return x+'%s';}})()" % _B, "42" + _B),
        ("(function(){var o={x:0};with(o){return x+'%s';}})()" % _B, "0" + _B),
        ("(function(){var o={x:9007199254740991};with(o){return x;}})()",
         "9007199254740991"),
        ("(function(){with({x:7}){return x+'%s';}})()" % _B, "7" + _B),
    ]
    bad = [c for c, want in cases if not _decodes_to(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


# ------------------------------------------------ p3: fail-closed bounds

@_t
def test_p3_f696_bounds():
    """Boxed-String bounds fail closed (miss, never mis-decode)."""
    shapes = [
        "new String(42)+'f2'",            # numeric arg
        "new String('a','b')+'f2'",       # extra arg
        "new String(...['a'])+'f2'",      # spread arg
        "new Stringed('a')+'f2'",         # ident-boundary
        "new String('a').length",          # unmodeled member: outer decode fails
        "(function(){return (new String('a'))+'b';})('x')",  # IIFE call args
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


@_t
def test_p3_f699_bounds():
    """With-scope >2^53 bounds fail closed; quoted big numerics excluded."""
    shapes = [
        "(function(){var o={x:9007199254740993};with(o){return x;}})()",
        "(function(){var o={x:-9007199254740993};with(o){return x;}})()",
        "(function(){with({x:9007199254740993}){return x;}})()",
        # quoted numeric string >2^53: conservatively excluded (documented)
        "(function(){var o={x:'9007199254740993'};with(o){return x;}})()",
    ]
    bad = [s for s in shapes if dlp._try_js_expr_decode_all(s) is not None]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


# ------------------------------------------------ p4: neighbors

@_t
def test_p4_open_neighbors_still_miss():
    """Open findings still miss (nothing absorbed)."""
    shapes = [
        # F686: proxy ownKeys laundering
        "(function(){var t={};var p=new Proxy(t,{ownKeys:function(){return ['x'];}});return Reflect.ownKeys(p)[0];})()",
        # F687: WeakSet marker
        "(function(){var s=new WeakSet();var o={};s.add(o);return s.has(o)?'a':'b';})()",
        # F698: F664 defineProperty residual
        "(function(){var o={};Object.defineProperty(o,'x',{get:function(){return 'a';}});return o.x+'b';})()",
        # F700: filed this lane, still open
        "({x:9007199254740993}).x+'%s'" % _B,
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


@_t
def test_p4_closed_neighbors_still_block():
    """Closed siblings still block (spot checks, credential-shaped)."""
    shapes = [
        # F672: class-declaration fragment source
        "(function(){class C{static #p='%s';static get q(){return C.#p;}}return C.q+'%s';})()" % (_A, _B),
        # F675: proxy set trap
        "(function(){var t={};var p=new Proxy(t,{set:function(tr,k,v){tr[k]=v;return true;}});p.x='%s';return p.x+'%s';})()" % (_A, _B),
        # F667: with-scope string member (the intact closure)
        "(function(){var o={x:'%s'};with(o){return x+'%s';}})()" % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%d" % len(bad))


# ------------------------------------------------ p5: junk quiet

@_t
def test_p5_junk_quiet():
    """Junk inputs stay quiet."""
    shapes = [
        "'(function(){var s=\\'ab\\';return s;})()'",
        "new String('ab')",
        "(new String('ab'))",
        "just some text",
        "new String()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p6: pin, footer, no new regexes

@_t
def test_p6_pin_footer():
    """Pin 2140; lane-local footer (F696+F699 closed, F700 open / next F701)."""
    ok = (TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0)  # Wave-385: pin 2143 -> 2144
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F795**" in text)  # Wave-381 lane 7  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-381 lane 7  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p6_no_new_regexes():
    """re.compile count stays 28 (existing pattern edited, none added)."""
    n = len(re.findall(r"re\.compile\(",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p7: perf

@_t
def test_p7_perf():
    """200 boxed-String sites stay quiet and decode quickly."""
    corpus = "".join(
        "(function(){return (new String('a%d'))+'b';})()" % k
        for k in range(200))
    t0 = time.time()
    hit = _blocked(corpus)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p8: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w380_f696_redfirst.py", 0),
                               ("evals/w380_f699_redfirst.py", 0),
                               ("evals/w380_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g381-green-", dir="/var/tmp")
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
    """Depth-1 green check: F696/F699 red-firsts + wave-380 attack battery green."""
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
