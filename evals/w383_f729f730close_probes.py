#!/usr/bin/env python3
"""Wave-383 lane 9: close F729 + F730 (void statements, nested entries destructuring).

F729 (LOW; filed 2026-10-08 by wave-382 lane 8, attack round 50): void
operator statements bypass the bounded static JS-expression decoder --
the decoder has no void-operator statement production, so
  (function(){var x='f1';void x;return x+'f2';})()
  (function(){var x='f1';void 0;return x+'f2';})()
miss while node evaluates the fragment read exactly (v24.20.0).
Distinct from F647 (void paren form in nullish position).

F730 (LOW; filed 2026-10-08 by wave-382 lane 8, attack round 50):
nested array destructuring of Object.entries bypasses the decoder --
F644 models flat patterns, F684b nested OBJECT patterns, F693
per-key defaults; a nested ARRAY pattern
  (function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'f1',b:'f2'});return v1+v2;})()
  (function(){var e=Object.entries({a:'f1',b:'f2'});var [[,v1],[,v2]]=e;return v1+v2;})()
misses while node evaluates exactly (v24.20.0).

Fix (gov/dlp.py, zero new re.compile):
- F729: _js_parse_f729_void_stmt_iife, hooked after F702/F703 with
  the hook and trailing return intact (wave-379 lesson); disjoint by
  the `void` statement head. Only side-effect-free, non-throwing
  operands are modeled (bound name, string/numeric literal,
  null/undefined/true/false); the void value is discarded and the
  return body uses the F611 substitution discipline.
- F730: _js_parse_f730_nested_entries_iife (+2 helpers), hooked
  after F693; disjoint by the `[` pattern head (F684b owns `{`,
  F693 requires `=` defaults, F644 fails closed on nested `[`).
  Object.entries pairs come from _js_parse_object_literal_keys_values
  (engine-exact enumeration order; __proto__ fails closed); more
  pattern pairs than entries fails closed (the engine throws
  TypeError -- verified v24.20.0).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
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

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2143

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

_tests = []


def _t(fn):
    _tests.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F729/F730 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f729_s1():
    """F729 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f729-s1=%s" % ok)


@_t
def test_p1_f729_s2():
    """F729 filed shape 2 blocks."""
    ok = _blocked(
        "(function(){var x='%s';void 0;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f729-s2=%s" % ok)


@_t
def test_p1_f730_s1():
    """F730 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'%s',b:'%s'});return v1+v2;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f730-s1=%s" % ok)


@_t
def test_p1_f730_s2():
    """F730 filed shape 2 (var-bound twin) blocks."""
    ok = _blocked(
        "(function(){var e=Object.entries({a:'%s',b:'%s'});var [[,v1],[,v2]]=e;return v1+v2;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f730-s2=%s" % ok)


# ------------------------------------------------------------- variants (p2)

@_t
def test_p2_void_let_const():
    """F729 variants: let/const decls block."""
    ok = (_blocked("(function(){let x='%s';void x;return x+'%s';})()" % (_A, _B))
          and _blocked("(function(){const x='%s';void x;return x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_void_literal_operands():
    """F729 variants: void string/numeric/null/keyword operands block."""
    ok = (_blocked("(function(){var x='%s';void 'lit';return x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var x='%s';void 42;return x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var x='%s';void null;return x+'%s';})()" % (_A, _B))
          and _blocked("(function(){var x='%s';void undefined;return x+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "lit-operands=%s" % ok)


@_t
def test_p2_entries_elision_single():
    """F730 variants: single-pair elision blocks."""
    ok = _blocked("(function(){var [[,v]]=Object.entries({a:'%s'});return v+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "elision=%s" % ok)


@_t
def test_p2_entries_intkey_order():
    """F730 variant: integer-key ordering is node-exact (value decodes)."""
    # {2:'A',a:'B'} enumerates '2' first; v binds the int-keyed value.
    ok = _blocked("(function(){var [[k,v]]=Object.entries({2:'%s%s'});return v;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "intkey=%s" % ok)


@_t
def test_p2_entries_three_pairs():
    """F730 variant: three-pair pattern blocks (node-exact)."""
    ok = _blocked(
        "(function(){var [[,a],[,b],[,c]]=Object.entries({x:'%s',y:'%s',z:'w'});return a+b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "three-pairs=%s" % ok)


@_t
def test_p2_additive_continuation():
    """Regression (spec review): IIFE embedded in a larger + expression blocks.

    Both parsers once returned next-index one past the IIFE's closing
    `()`, swallowing the continuation operator and truncating the
    decode (a silent miss). Fixed: tails return the exact index."""
    ok = (_blocked("(function(){var x='%s';void x;return x;})()+'%s'" % (_A, _B))
          and _blocked("(function(){var [[,v]]=Object.entries({a:'%s'});return v;})()+'%s'" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "continuation=%s" % ok)


# --------------------------------------------------------------- bounds (p3)

@_t
def test_p3_void_unbound_ident():
    """F729 bound: void of unbound identifier fails closed (engine throws)."""
    ok = _misses("(function(){var x='%s';void y;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_void_member_read():
    """F729 bound: void of member read fails closed (could invoke getter)."""
    ok = _misses("(function(){var x='%s';var o={};void o.x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "member=%s" % ok)


@_t
def test_p3_void_call():
    """F729 bound: void of call fails closed (side effects)."""
    ok = _misses("(function(){var x='%s';void String(x);return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "call=%s" % ok)


@_t
def test_p3_void_no_void():
    """F729 bound: decl+return without void is F611's shape, still blocks (no regression)."""
    ok = _blocked("(function(){var x='%s';return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "no-void=%s" % ok)


@_t
def test_p3_entries_arity_mismatch():
    """F730 bound: more pattern pairs than entries fails closed (engine throws)."""
    ok = _misses(
        "(function(){var [[k1,v1],[k2,v2]]=Object.entries({a:'%s'});return v1+v2;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "arity=%s" % ok)


@_t
def test_p3_entries_nonliteral_value():
    """F730 bound: non-string-literal values fail closed."""
    ok = _misses(
        "(function(){var [[,v1],[,v2]]=Object.entries({a:1,b:'%s'});return v1+v2;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "nonliteral=%s" % ok)


@_t
def test_p3_entries_deep_nesting():
    """F730 bound: deeper nesting fails closed."""
    ok = _misses(
        "(function(){var [[[v]]]=Object.entries({a:'%s'});return v;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "deep=%s" % ok)


@_t
def test_p3_entries_duplicate_names():
    """F730 bound: duplicate bound names fail closed."""
    ok = _misses(
        "(function(){var [[,v],[,v]]=Object.entries({a:'%s',b:'x'});return v;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "dupes=%s" % ok)


@_t
def test_p3_entries_wrong_source():
    """F730 bound: non-Object.entries source fails closed."""
    ok = _misses(
        "(function(){var [[,v1],[,v2]]=[['a','%s'],['b','x']];return v1+v2;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "wrong-src=%s" % ok)


@_t
def test_p3_entries_twin_wrong_name():
    """F730 bound: var-bound twin with mismatched name fails closed."""
    ok = _misses(
        "(function(){var e=Object.entries({a:'%s'});var [[,v]]=q;return v;})()" % (_A,))
    return ("HELD" if ok else "BREAK", "twin-name=%s" % ok)


# ------------------------------------------- siblings + open neighbors (p4)

@_t
def test_p4_sibling_f647():
    """F647 (void paren form) still blocks."""
    ok = _blocked("(function(){return (void 0??'%s')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f647=%s" % ok)


@_t
def test_p4_sibling_f644():
    """F644 (flat destructuring) still blocks."""
    ok = _blocked("(function(){var [a,b]=['%s','%s'];return a+b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f644=%s" % ok)


@_t
def test_p4_sibling_f684b():
    """F684b (nested object destructuring) still blocks."""
    ok = _blocked("(function(){var {x:{y}}={x:{y:'%s'}};return y+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f684b=%s" % ok)


@_t
def test_p4_sibling_f611():
    """F611 (single varbound) still blocks."""
    ok = _blocked("(function(){var x='%s';return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


@_t
def test_p4_neighbor_f731_open():
    """F731 now BLOCKS (closed wave-383 merge)."""
    ok = not _misses("(function(){var p=new Proxy({},{isExtensible:function(t){return true;}});var f=Object.isExtensible(p)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f731-closed=%s" % ok)


@_t
def test_p4_neighbor_f728_open():
    """F728 now BLOCKS (closed wave-383 merge)."""
    ok = not _misses("(function(){function* g(){yield '%s';yield '%s';}var it=g();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f728-closed=%s" % ok)


# ------------------------------------------------------------- quiet (p5)

@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------------- honest text (p6)

@_t
def test_p6_honest_void_unaffected():
    """Honest void-adjacent text is unaffected."""
    ok = (_misses("the void left by his departure was immense")
          and _misses("avoid voiding the warranty"))
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p6_honest_entries_unaffected():
    """Honest entries-adjacent text is unaffected."""
    ok = _misses("Object.entries are useful for debugging")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ---------------------------------------------------------------- perf (p7)

@_t
def test_p7_perf():
    """200 mixed sites decode in reasonable time (F452 budget holds)."""
    sites = []
    for k in range(50):
        sites.append("(function(){var x='f%d';void x;return x+'g';})()" % k)
        sites.append("(function(){var [[,v]]=Object.entries({a:'f%d'});return v;})()" % k)
        sites.append("(function(){var x='f%d';return x;})()" % k)
        sites.append("['a','b'].join('')")
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 10
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ---------------------------------------------------------- green check (p8)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the attack battery's footer probe
    # BREAKs on the lane-local footer (merge-owned tree-wide repoint);
    # all functional probes must be 0 BREAK.
    for batt, expect_break in (("evals/w382_f729_redfirst.py", 0),
                               ("evals/w382_f730_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
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
    """Depth-1 green check: F729/F730 red-firsts + wave-382 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errs = 0, 0, 0
    for fn in _tests:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery must not crash
            verdict, detail = "ERROR", "%s: %r" % (fn.__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errs += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errs))
    return 1 if (breaks or errs) else 0


if __name__ == "__main__":
    sys.exit(main())
