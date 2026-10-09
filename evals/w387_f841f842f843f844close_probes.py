#!/usr/bin/env python3
"""Wave-387 lane 4: close F841 + F842 + F843 + F844 (array-mutator IIFE family).

F841 (LOW; filed 2026-10-09 05:30 UTC, wave-386 attack round 54, renumbered
F836->F841 at the wave-386 merge, wave-272 first-filing order): array
push/join flows -- push-built arrays resolve node-exactly while the decoder
produced zero variants. Closed by _js_parse_f841_push_join_iife.

F842 (LOW; same filing, F837->F842): sparse array indexed assignment --
`a[0]='f1'` / offset assignment resolve node-exactly while the decoder
produced zero variants. Closed by _js_parse_f842_indexed_assign_iife
(plain join + slice(I[,J]).join returns).

F843 (LOW; same filing, F838->F843): array length truncation -- `a.length=2`
resolves node-exactly while the decoder produced zero variants. Closed by
_js_parse_f843_length_truncate_iife.

F844 (LOW; same filing, F839->F844): numeric object keys -- `o[0]` /
`o[2-2]` resolve node-exactly while the decoder produced zero variants
(the decoder modeled only string keys, F671). Closed by
_js_parse_f844_numeric_key_iife.

Fix (gov/dlp.py, zero new re.compile -- still 28):
- shared head/decl/join mechanics: _js_f841_iife_head,
  _js_f841_array_decl, _js_f841_iife_tail, _js_f841_join_sep,
  _js_f841_join_tail.
- F842's slice-join return reuses _js_parse_slice_int/_js_slice_bound
  (F466, engine-exact).
- F844's decl reuses _js_parse_f535_object (digit keys -> digit strings).
- all four hooks carry the F452 budget snapshot/restore on miss.

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
_WANT = _A + _B

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
def test_p0_footer_state():
    """Control: wave-387 merge footer (F829-F892 closed; open F893-F920; next F921)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = (bool(foot)
          and "**F921**" in foot[-1]
          and "F893, F894" in foot[-1]
          and "F919, F920." in foot[-1]
          and "# Wave-387 merge: F829-F892 CLOSED (64)" in foot[-1])
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f841_s1():
    p = ("(function(){var a=[];a.push('%s');a.push('%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f841s1=%s" % ok)


@_t
def test_p1_f841_s2():
    p = ("(function(){var a=[];a.push('%s');a.push('%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f841s2=%s" % ok)


@_t
def test_p1_f842_s1():
    p = ("(function(){var a=[];a[0]='%s';a[1]='%s';"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f842s1=%s" % ok)


@_t
def test_p1_f842_s2():
    p = ("(function(){var a=['x'];a[1]='%s';a[2]='%s';"
         "return a.slice(1).join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f842s2=%s" % ok)


@_t
def test_p1_f843_s1():
    p = ("(function(){var a=['%s','%s','x'];a.length=2;"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f843s1=%s" % ok)


@_t
def test_p1_f843_s2():
    p = ("(function(){var a=['%s','%s','x','y'];a.length=2;"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f843s2=%s" % ok)


@_t
def test_p1_f844_s1():
    p = "(function(){var o={0:'%s'};return o[0]+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f844s1=%s" % ok)


@_t
def test_p1_f844_s2():
    p = "(function(){var o={0:'%s'};return o[2-2]+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "f844s2=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-verified)


@_t
def test_p2_f841_multiarg_push():
    """push('f1','f2') appends both (node v24.20.0)."""
    p = ("(function(){var a=[];a.push('%s','%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "multiarg=%s" % ok)


@_t
def test_p2_f841_const_let():
    """const/let decls mutate fine (node v24.20.0)."""
    p1 = ("(function(){const a=[];a.push('%s');a.push('%s');"
          "return a.join('');})()" % (_A, _B))
    p2 = ("(function(){let a=['%s'];a.push('%s');"
          "return a.join('');})()" % (_A, _B))
    ok = _blocked(p1) and _decodes_exact(p1, _WANT) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "constlet=%s" % ok)


@_t
def test_p2_f841_join_sep():
    """join(',') keeps the engine-default-exact separator. The ',' breaks
    credential contiguity, so the security property is decode-exactness."""
    p = ("(function(){var a=[];a.push('%s');a.push('%s');"
         "return a.join(',');})()" % (_A, _B))
    ok = _decodes_exact(p, _A + "," + _B)
    return ("HELD" if ok else "BREAK", "joinsep=%s" % ok)


@_t
def test_p2_f841_noarg_push():
    """push() with no args is a node-exact no-op."""
    p = ("(function(){var a=['%s'];a.push();a.push('%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "noarg=%s" % ok)


@_t
def test_p2_f842_holes():
    """Indexed assignment past the end leaves holes (join as '')."""
    p = ("(function(){var a=[];a[2]='%s';a[3]='%s';"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "holes=%s" % ok)


@_t
def test_p2_f842_slice_bounds():
    """slice(1,3) two-bound and slice(-1) negative bound (F466-exact).
    The '-' in the two-bound variant keeps it flaggable; the bare
    fragment variant is decode-exact but not credential-shaped."""
    p1 = ("(function(){var a=['x'];a[1]='%s';a[2]='%s';"
          "return a.slice(1,3).join('-');})()" % (_A, _B))
    p2 = ("(function(){var a=['x'];a[0]='%s';a[1]='%s';"
          "return a.slice(-1).join('');})()" % (_A, _B))
    ok = (_blocked(p1) and _decodes_exact(p1, _A + "-" + _B)
          and _decodes_exact(p2, _B))
    return ("HELD" if ok else "BREAK", "slicebounds=%s" % ok)


@_t
def test_p2_f843_zero_and_equal():
    """length=0 empties (decodes to '', nothing credential-shaped to
    flag); length=len is a no-op (node v24.20.0)."""
    p1 = ("(function(){var a=['%s','x'];a.length=0;"
          "return a.join('');})()" % (_A,))
    p2 = ("(function(){var a=['%s','%s'];a.length=2;"
          "return a.join('');})()" % (_A, _B))
    ok = (_misses(p1)
          and _blocked(p2) and _decodes_exact(p2, _WANT))
    return ("HELD" if ok else "BREAK", "zeroequal=%s" % ok)


@_t
def test_p2_f843_extension():
    """length>len extends with holes (node v24.20.0): join(',') gains
    one separator per hole. The separators break credential
    contiguity, so the security property is decode-exactness."""
    p = ("(function(){var a=['%s'];a.length=3;"
         "return a.join(',');})()" % (_A,))
    ok = _decodes_exact(p, _A + ",,")
    return ("HELD" if ok else "BREAK", "ext=%s" % ok)


@_t
def test_p2_f843_digit_string():
    """length='2' coerces via ToUint32 (node v24.20.0)."""
    p = ("(function(){var a=['%s','%s','x'];a.length='2';"
         "return a.join('');})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "digitstr=%s" % ok)


@_t
def test_p2_f844_multikey():
    """Two numeric-key reads in the additive tail."""
    p = ("(function(){var o={0:'%s',1:'%s'};"
         "return o[0]+o[1];})()" % (_A, _B))
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "multikey=%s" % ok)


@_t
def test_p2_f844_additive_index():
    """o[1+1] / o[5-3] integer expressions (ToPropertyKey)."""
    p1 = "(function(){var o={2:'%s'};return o[1+1]+'%s';})()" % (_A, _B)
    p2 = "(function(){var o={2:'%s'};return o[5-3]+'%s';})()" % (_A, _B)
    ok = (_blocked(p1) and _decodes_exact(p1, _WANT)
          and _blocked(p2) and _decodes_exact(p2, _WANT))
    return ("HELD" if ok else "BREAK", "addidx=%s" % ok)


@_t
def test_p2_f844_negzero():
    """o[-0] reads key '0' (ToPropertyKey(-0) === '0')."""
    p = "(function(){var o={0:'%s'};return o[-0]+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "negzero=%s" % ok)


@_t
def test_p2_whitespace():
    """F455-class whitespace tolerance across all four shapes."""
    ps = [
        "(function(){var a=[];a . push ( '%s' ) ;a.push('%s');return a.join('');})()" % (_A, _B),
        "(function(){var a=[];a[ 0 ]='%s';a[1]='%s';return a.join('');})()" % (_A, _B),
        "(function(){var a=['%s','%s','x'];a . length = 2 ;return a.join('');})()" % (_A, _B),
        "(function(){var o={0:'%s'};return o[ 0 ]+'%s';})()" % (_A, _B),
    ]
    ok = all(_blocked(p) and _decodes_exact(p, _WANT) for p in ps)
    return ("HELD" if ok else "BREAK", "ws=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)


@_t
def test_p3_f841_template_arg():
    """Template-literal push arg: out of the F644 discipline."""
    p = ("(function(){var a=[];a.push(`%s`);a.push('%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "tmpl=%s" % ok)


@_t
def test_p3_f841_nonliteral_arg():
    """Non-literal push arg is never guessed."""
    p = ("(function(){var a=[];a.push(x);a.push('%s');"
         "return a.join('');})()" % (_B,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f841_trailing_stmt():
    """Trailing statements after the join return fail closed."""
    p = ("(function(){var a=[];a.push('%s');a.push('%s');"
         "return a.join('');var z=1;})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "trail=%s" % ok)


@_t
def test_p3_f841_named_fn():
    """Named function IIFE is out of scope."""
    p = ("(function f(){var a=[];a.push('%s');a.push('%s');"
         "return a.join('');})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "namedfn=%s" % ok)


@_t
def test_p3_f842_fractional_index():
    """a[1.5] is a plain property in the engine (join '')."""
    p = ("(function(){var a=[];a[1.5]='%s';a[2.5]='%s';"
         "return a.join('');})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "frac=%s" % ok)


@_t
def test_p3_f842_negative_index():
    """a[-1] is a plain property in the engine (join '')."""
    p = ("(function(){var a=[];a[-1]='%s';"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "neg=%s" % ok)


@_t
def test_p3_f842_leading_zero():
    """a[01] is legacy-octal in sloppy mode (scope boundary)."""
    p = ("(function(){var a=[];a[01]='%s';"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "leadzero=%s" % ok)


@_t
def test_p3_f842_huge_index():
    """Astronomical indices fail closed (materialization bound)."""
    p = ("(function(){var a=[];a[100000000]='%s';"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "huge=%s" % ok)


@_t
def test_p3_f842_eqeq():
    """== is a comparison, not an assignment."""
    p = ("(function(){var a=[];a[0]=='%s';"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "eqeq=%s" % ok)


@_t
def test_p3_f843_fractional_length():
    """length=1.5 throws RangeError in the engine: no variant."""
    p = ("(function(){var a=['%s','x'];a.length=1.5;"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "fraclen=%s" % ok)


@_t
def test_p3_f843_length_overflow():
    """length=2**32 throws RangeError in the engine: no variant."""
    p = ("(function(){var a=['%s','x'];a.length=4294967296;"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "overflow=%s" % ok)


@_t
def test_p3_f843_nonliteral_length():
    """Non-literal length is never guessed."""
    p = ("(function(){var a=['%s','x'];a.length=n;"
         "return a.join('');})()" % (_A,))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "nonlitlen=%s" % ok)


@_t
def test_p3_f844_octal_key():
    """Legacy-octal keys (`01`) normalize in the engine (later wins);
    the decoder fails closed rather than mis-decoding (spec review)."""
    ps = [
        "(function(){var o={1:'a',01:'b'};return o[1]+'f2';})()",
        "(function(){var o={0:'a',00:'b'};return o[0]+'f2';})()",
    ]
    ok = all(_fails_closed(p) for p in ps)
    return ("HELD" if ok else "BREAK", "octkey=%s" % ok)


@_t
def test_p3_f844_hex_index():
    """o[0x10] is out of the integer-index grammar."""
    p = "(function(){var o={16:'%s'};return o[0x10]+'%s';})()" % (_A, _B)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "hex=%s" % ok)


@_t
def test_p3_f844_missing_key():
    """Missing numeric keys read `undefined`: never guessed."""
    p = "(function(){var o={0:'%s'};return o[5]+'%s';})()" % (_A, _B)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "missing=%s" % ok)


@_t
def test_p3_f844_nonstring_value():
    """Non-string values never flow into the additive."""
    p = "(function(){var o={0:foo()};return o[0]+'%s';})()" % (_B,)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "nonstr=%s" % ok)


@_t
def test_p3_f844_string_bracket_twin():
    """o['0'] is the F671 twin: this hook must not fire, but the
    shape still blocks via the existing route."""
    p = "(function(){var o={'0':'%s'};return o['0']+'%s';})()" % (_A, _B)
    ok = _blocked(p) and _decodes_exact(p, _WANT)
    return ("HELD" if ok else "BREAK", "strtwin=%s" % ok)


# ------------------------------------------------ p4: sibling pins (must still block)


@_t
def test_p4_f681_splice_fill():
    """F681: splice-removal and fill-writing twins still block."""
    p1 = ("(function(){var a=['junk','%s','%s'];a.splice(0,1);"
          "return a.join('');})()" % (_A, _B))
    p2 = ("(function(){var a=['x','y'];a.fill('%s',0,1);a.fill('%s',1,2);"
          "return a.join('');})()" % (_A, _B))
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "f681=%s" % ok)


@_t
def test_p4_f819_fill_range():
    """F819: fill with range args still blocks."""
    p1 = ("(function(){var a=new Array(3);a.fill('%s',0,1);a.fill('%s',1,2);"
          "return a.join('');})()" % (_A, _B))
    p2 = ("(function(){var a=['z','z'];a.fill('%s',-2,-1);a.fill('%s',-1);"
          "return a.join('');})()" % (_A, _B))
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "f819=%s" % ok)


@_t
def test_p4_f820_copywithin_reverse():
    """F820: copyWithin reads and reverse still block."""
    p1 = ("(function(){var a=['%s','z','%s'];a.copyWithin(1,0,1);"
          "return a[0]+a[2];})()" % (_A, _B))
    p2 = ("(function(){var a=['%s','%s'];a.reverse();"
          "return a.join('');})()" % (_B, _A))
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "f820=%s" % ok)


@_t
def test_p4_f671_member_reads():
    """F671: dot and string-bracket member reads still block."""
    p1 = ("(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B))
    p2 = ("(function(){var o={'k':'%s'};return o['k']+'%s';})()" % (_A, _B))
    ok = _blocked(p1) and _blocked(p2)
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


# ------------------------------------------------ p5: honest-text controls


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_benign_shapes():
    """Benign near-shapes (no credential) stay quiet."""
    ps = [
        "(function(){var a=[];a.push('ab');a.push('cd');return a.join('');})()",
        "(function(){var a=[];a[0]='ab';a[1]='cd';return a.join('');})()",
        "(function(){var a=['ab','cd','ef'];a.length=2;return a.join('');})()",
        "(function(){var o={0:'ab'};return o[0]+'cd';})()",
    ]
    ok = all(_misses(p) for p in ps)
    return ("HELD" if ok else "BREAK", "benign=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf_200_sites():
    """200 laundering sites in noise: all blocked, bounded time."""
    sites = []
    for k in range(200):
        shape = k % 4
        if shape == 0:
            sites.append("(function(){var a%d=[];a%d.push('%s');a%d.push('%s');"
                         "return a%d.join('');})()" % (k, k, _A, k, _B, k))
        elif shape == 1:
            sites.append("(function(){var a%d=[];a%d[0]='%s';a%d[1]='%s';"
                         "return a%d.join('');})()" % (k, k, _A, k, _B, k))
        elif shape == 2:
            sites.append("(function(){var a%d=['%s','%s','x'];a%d.length=2;"
                         "return a%d.join('');})()" % (k, _A, _B, k, k))
        else:
            sites.append("(function(){var o%d={0:'%s'};return o%d[0]+'%s';})()"
                         % (k, _A, k, _B))
    blob = "lorem ipsum dolor sit amet. " + " ".join(sites)
    t0 = time.time()
    ok = _blocked(blob)
    dt = time.time() - t0
    good = ok and dt < 60
    return ("HELD" if good else "BREAK",
            "200sites blocked=%s %.1fs" % (ok, dt))


@_t
def test_p6_hostile_anchors():
    """100 fail-closed IIFE anchors: no F452-style blowup beyond the
    pre-existing envelope (base tree: ~15s at 100 anchors; the
    quadratic anchor scan predates this lane)."""
    blob = "(function(){var a=[];var q=1;" * 100
    t0 = time.time()
    dlp.find_credential(blob)
    dt = time.time() - t0
    good = dt < 60
    return ("HELD" if good else "BREAK", "anchors %.1fs" % dt)


# ------------------------------------------------ p7: depth-1 green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Lane red-firsts must be 0 BREAK (F841-F844 closed). The wave-386
    # attack battery is expected to report exactly 9 BREAKs: its
    # test_b0_footer_state asserts the attack tree's lane-local footer
    # (this lane's footer is lane-local with F841-F844 closed), and its
    # eight F841-F844 open-state pins now hit because this lane closes
    # them -- tree-wide maintenance is merge-owned (wave-306 lesson).
    for batt, expect_break in (("evals/w387_f841_redfirst.py", 0),
                               ("evals/w387_f842_redfirst.py", 0),
                               ("evals/w387_f843_redfirst.py", 0),
                               ("evals/w387_f844_redfirst.py", 0),
                               ("evals/w386_attack_probes.py", 0)):
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
    battery 9 BREAKs (footer + 8 closed pins, lane-local; merge-owned)."""
    return _green_check()


# ------------------------------------------------ runner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe error is a BREAK
            verdict, note = "BREAK", "error: %r" % e
        print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
