#!/usr/bin/env python3
"""Wave-378 lane 5: close F660 (env-threaded tail reads after F647/F652 fragments).

F660 (LOW; filed by wave-377 lane 4 as F655, renumbered at the wave-377 merge
per wave-272 first-filing -- attack lane 9 filed F655 first at 09:57:52 UTC):
the F647/F652 term parsers fell back to plain primaries that did not know the
local bindings, so a fragment whose assigned ident is read AGAIN in a later
tail additive operand had no modeled path:
  (function(){var x;return (x='f1',x)+'f2'+x;})()  -> node "f1f2f1"
  (function(){var z;return (z??'f1')+'f2'+z;})()   -> node "f1f2undefined"

Fix (gov/dlp.py, zero new re.compile): F660 branches in the two term
parsers -- _js_parse_f652_term resolves a bare ident bound in the threaded
env (node-exact read of the sequence's assignment); _js_parse_f647_term
resolves a bare read of the declared-uninitialized ident to "undefined"
(node-exact under string concatenation; F645 precedent). Both branches only
convert fail-closed into a node-exact decode (the pre-change
_js_parse_primary fallback fails closed on a bare ident), so no
previously-decoded input changes behavior.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
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

TAXONOMY_PIN = 2143  # no new decision codes this lane; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

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


# ------------------------------------------------ p1: filed shapes (must block)

@_t
def test_p1_f652_filed_tail_read():
    """F660 filed shape 1: (x='A',x)+'B'+x blocks."""
    s = ("(function(){var x;return (x='" + _A + "',x)+'" + _B + "'+x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f647_filed_tail_read():
    """F660 filed shape 2: (z??'A')+'B'+z blocks (node: AB + 'undefined')."""
    s = ("(function(){var z;return (z??'" + _A + "')+'" + _B + "'+z;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + "undefined")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: variants (must block)

@_t
def test_p2_f652_multi_tail():
    """F652 multi-tail: (x='A',x)+'B'+x+'jx'+x blocks."""
    s = ("(function(){var x;return (x='" + _A + "',x)+'" + _B
         + "'+x+'jx'+x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + _A + "jx" + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f652_let_twin():
    """F652 let twin: tail read through a let-bound env blocks."""
    s = ("(function(){let x;return (x='" + _A + "',x)+'" + _B + "'+x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f652_nested_group_tail():
    """F652 nested-group tail: ((x='A',x))+'B'+x blocks."""
    s = ("(function(){var x;return ((x='" + _A + "',x))+'" + _B + "'+x;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + _A)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f652_tail_only_exact():
    """F652 tail-only: (x='A',x)+x decodes node-exact 'AA' (no full cred)."""
    s = "(function(){var x;return (x='" + _A + "',x)+x;})()"
    ok = _decodes_exact(s, _A + _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f647_tail_only_exact():
    """F647 tail-only: (z??'A')+z decodes node-exact 'Aundefined'."""
    s = "(function(){var z;return (z??'" + _A + "')+z;})()"
    ok = _decodes_exact(s, _A + "undefined")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f647_void_left_tail():
    """F647 void-LEFT + tail ident: (void 0??'A')+'B'+z blocks."""
    s = ("(function(){var z;return (void 0??'" + _A + "')+'" + _B
         + "'+z;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B + "undefined")
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f647_first_term_ident():
    """F647 first-term ident: z+(z??'A')+'B' decodes 'undefinedAB'."""
    s = ("(function(){var z;return z+(z??'" + _A + "')+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, "undefined" + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds (must miss)

@_t
def test_p3_f652_unassigned_first_term():
    """Declared-but-unassigned first term stays fail-closed (conservative)."""
    s = ("(function(){var x,y;return x+(y='" + _A + "',y);})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f652_undeclared_tail():
    """Undeclared tail ident stays fail-closed (engine ReferenceError)."""
    s = ("(function(){var x;return (x='" + _A + "',x)+'" + _B + "'+y;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f647_foreign_tail_ident():
    """Tail ident that is not the declared one stays fail-closed."""
    s = ("(function(){var z;return (z??'" + _A + "')+'" + _B + "'+w;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f647_multi_decl():
    """F647 multi-decl stays fail-closed (single uninitialized ident only)."""
    s = ("(function(){var z,w;return (z??'" + _A + "')+'" + _B + "'+z;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f652_const_decl():
    """F652 const declaration stays fail-closed."""
    s = ("(function(){const x;return (x='" + _A + "',x)+'" + _B + "'+x;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: open neighbors still miss

@_t
def test_p4_sibling_closures_hold():
    """F655-F659/F661 CLOSED by sibling lanes (wave-378 merge): filed shapes now block."""
    shapes = [
        "(function(){var a='" + _A + "';var b='" + _B + "';return a+b;})()",
        "(function*(){yield '" + _A + "';})().next().value+'" + _B + "'",
        ("(function(){var m=new Map([['k','" + _A + "'],['j','" + _B
          + "']]);var s='';m.forEach(function(v){s+=v;});return s;})()"),
        "['x'].flatMap(function(){return ['" + _A + "','" + _B + "'];}).join('')",
        "[...(function*(){yield* ['" + _A + "','" + _B + "'];})()].join('')",
        "(function(){var s=('jx','" + _A + "');return s+'" + _B + "';})()",
    ]
    got = [dlp.find_credential(s) is not None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "block=%s" % got)


# ------------------------------------------------ p5: composition (closed neighbors held)

@_t
def test_p5_closed_neighbors_held():
    """F647/F652 bare shapes and F490/F612 still block."""
    shapes = [
        "(function(){var z;return (z??'" + _A + "')+'" + _B + "';})()",
        "(function(){var x;return (x='" + _A + "',x)+'" + _B + "';})()",
        ("(function(){var o={a:'" + _A + "',b:'" + _B
         + "'};return Object.values(o).join('');})()"),
    ]
    got = [dlp.find_credential(s) is not None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "held=%s" % got)


# ------------------------------------------------ p6: junk quiet

@_t
def test_p6_junk_quiet():
    """No-credential shapes stay quiet."""
    shapes = [
        "(function(){var x;return (x='jx',x)+'jy'+x;})()",
        "(function(){var z;return (z??'jx')+'jy'+z;})()",
        "(function(){var x;return (x='jx',x)+'jy';})()",
    ]
    got = [dlp.find_credential(s) is None for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p7: pin, footer, no new regexes

@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (open F662-F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-378 lane 5: F660 CLOSED; open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-378 lane 5: F660 CLOSED; open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p7_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p8: perf

@_t
def test_p8_perf():
    """200 mixed F660 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var x;return (x='a%d',x)+'b'+x;})()" % k)
        corpus.append("(function(){var z;return (z??'a%d')+'b'+z;})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p9: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w377_f660_redfirst.py", 0),
                               ("evals/w377_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
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
def test_p9_green_check():
    """Depth-1 green check: F660 red-first + wave-377 attack battery green."""
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
