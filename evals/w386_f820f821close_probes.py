#!/usr/bin/env python3
"""Wave-386 lane 13: close F820 + F821.

F820 (LOW, filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
Array copyWithin/reverse statement reads -- the decoder had no
copyWithin/reverse statement production: both resolved node-exactly
while the decoder produced zero variants (splice is F767, fill is
F773/F681).

F821 (LOW, filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
arrow function default parameters -- the decoder models
function-declaration defaults (F736) but `(a='f1')=>a` had no
production: it resolved node-exactly while the decoder produced
zero variants.

CORRECTIONS (2026-10-09, wave-386 lane 13): both filed s2 shapes
were factually wrong -- they do not recover the credential at
runtime (node v24.20.0):
- F820 s2 `var a=['xoxb-0123','456789abcdef'];a.reverse()` yields
  '456789abcdefxoxb-0123' (no contiguous credential). Corrected to
  `var a=['456789abcdef','xoxb-0123']` so reverse()+join recovers.
- F821 s2 `(a,b='xoxb-0123')=>a+b` called as `f('456789abcdef')`
  yields '456789abcdefxoxb-0123' (a/b swapped). Corrected to
  `(a,b='456789abcdef')=>a+b` called as `f('xoxb-0123')`.
The findings themselves (no copyWithin/reverse statement
production; no arrow-default production) are genuine; the shapes
are corrected here, in w386_f820/f821_redfirst.py, in the
w385_attack closed pins, and in the FINDINGS.md entries.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F820: `_js_parse_f820_copywithin_iife` (decl, one
  `A.copyWithin(T[,S[,E]])` statement with engine-exact
  clamp/copy semantics incl. snapshot overlap handling, indexed
  `A[INT](+ADD)*` return) and `_js_parse_f820_reverse_iife`
  (decl, one `A.reverse()` statement, `A.join('SEP')/A.join()`
  return), hooked after F773 with parts/ops snapshot-restore.
- F821: `_js_parse_f821_arrow_default_iife` (+
  `_js_f821_parse_arrow`, `_js_f821_parse_additive`,
  `_js_f821_eval_operands`): var-bound arrow with string-literal
  defaults; concise or `{return ADD;}` body; terminal additive of
  literals, bound idents, and arrow calls (explicit `undefined`
  arg takes the default, engine-exact). Hooked after F735/F736
  with snapshot-restore. F735/F736's decl-RHS branch fails closed
  on the `(` head, so the routes are disjoint.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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
_CRED = _A + _B

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
def test_b0_footer_state():
    """Control: lane-local footer (F820/F821 closed, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, "
              "F801, F802, F803, F804, F805, F806, F807, F808, F809, "
              "F810, F811, F812, F813, F814, F815, F816, F817, F819, "
              "F822, F823, F824, F825, F826, F827, F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f820_s1():
    """F820 filed shape 1 (copyWithin) blocks + decodes node-exact."""
    s = ("(function(){var a=['" + _A + "','z','" + _B
         + "'];a.copyWithin(1,0,1);return a[0]+a[2];})()")
    ok = _blocked(s) and _decodes_exact(s, _CRED)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f820_s2():
    """F820 filed shape 2 (reverse, corrected order) blocks."""
    s = ("(function(){var a=['" + _B + "','" + _A
         + "'];a.reverse();return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _CRED)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f821_s1():
    """F821 filed shape 1 (single arrow default) blocks."""
    s = ("(function(){var f=(a='" + _A + "')=>a;return f()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _CRED)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f821_s2():
    """F821 filed shape 2 (second-param default, corrected) blocks."""
    s = ("(function(){var f=(a,b='" + _B + "')=>a+b;return f('"
         + _A + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _CRED)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_copywithin_variants():
    """copyWithin 2-arg / negative / overlap / end-omitted decode."""
    cases = [
        ("(function(){var a=['p','q','r'];a.copyWithin(0,2);"
         "return a[0]+a[1];})()", "rq"),
        ("(function(){var a=['p','q','r','s'];a.copyWithin(-1,0,-1);"
         "return a[3];})()", "p"),
        ("(function(){var a=['p','q'];a.copyWithin(5,0,1);"
         "return a[0]+a[1];})()", "pq"),
        ("(function(){var a=['p','q','r'];a.copyWithin(1,0);"
         "return a[2];})()", "q"),
        ("(function(){let a=['p','q'];a.copyWithin(0,1);"
         "return a[0];})()", "q"),
    ]
    bad = [c for c, want in cases if not _decodes_exact(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % bad)


@_t
def test_p2_reverse_variants():
    """reverse with default/dash separator, const decl."""
    cases = [
        ("(function(){var a=['p','q'];a.reverse();return a.join();})()",
         "q,p"),
        ("(function(){var a=['p','q'];a.reverse();return a.join('-');})()",
         "q-p"),
        ("(function(){const a=['p','q','r'];a.reverse();return a.join('');})()",
         "rqp"),
    ]
    bad = [c for c, want in cases if not _decodes_exact(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % bad)


@_t
def test_p2_arrow_variants():
    """Arrow block body, explicit undefined, trailing comma,
    no-param arrow, no-default arrow with full args."""
    cases = [
        ("(function(){var f=(a='" + _A + "')=>{return a;};return f()+'"
          + _B + "';})()", _CRED),
        ("(function(){var f=(a='" + _A + "')=>a;return f(undefined)+'"
          + _B + "';})()", _CRED),
        ("(function(){var f=(a='" + _A + "',)=>a;return f()+'" + _B
          + "';})()", _CRED),
        ("(function(){var f=()=>'lit';return f();})()", "lit"),
        ("(function(){var f=(a,b)=>a+b;return f('" + _A + "','" + _B
          + "');})()", _CRED),
        ("(function(){var s='-t';var f=(a)=>a+s;return f('v');})()",
         "v-t"),
    ]
    bad = [c for c, want in cases if not _decodes_exact(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % bad)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_copywithin_bounds():
    """Fractional / string / 4-arg copyWithin, non-array, reassign,
    OOB index, extra statements all fail closed."""
    cases = [
        "(function(){var a=['p','q','r'];a.copyWithin(1.5,0);return a[0];})()",
        "(function(){var a=['p','q','r'];a.copyWithin('1','0');return a[0];})()",
        "(function(){var a=['p','q','r'];a.copyWithin(0,0,1,9);return a[0];})()",
        "(function(){var a='pq';a.copyWithin(0,1);return a[0];})()",
        "(function(){var a=['p','q'];a=['r'];a.copyWithin(0,1);return a[0];})()",
        "(function(){var a=['p','q'];a.copyWithin(0,1);return a[9];})()",
        ("(function(){var a=['p','q'];a.copyWithin(0,1);var b=1;"
         "return a[0];})()"),
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "decoded=%s" % bad)


@_t
def test_p3_reverse_bounds():
    """reverse with args, non-literal separator, extra statements,
    reassignment all fail closed."""
    cases = [
        "(function(){var a=['p','q'];a.reverse(1);return a.join('');})()",
        "(function(){var s='-';var a=['p','q'];a.reverse();return a.join(s);})()",
        ("(function(){var a=['p','q'];a.reverse();var b=1;"
         "return a.join('');})()"),
        ("(function(){var a=['p','q'];a=['r'];a.reverse();"
         "return a.join('');})()"),
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "decoded=%s" % bad)


@_t
def test_p3_arrow_bounds():
    """Arrow missing-default args, extra args, non-literal default,
    unbound/this/async/dup/second-arrow all fail closed."""
    cases = [
        "(function(){var f=(a,b)=>a+b;return f('x');})()",
        "(function(){var f=(a='x')=>a;return f('x','y');})()",
        "(function(){var x='d';var f=(a=x)=>a;return f();})()",
        "(function(){var f=(a='x')=>a+z;return f();})()",
        "(function(){var f=(a='x')=>this.a;return f();})()",
        "(function(){var f=async (a='x')=>a;return f();})()",
        "(function(){var f=(a='x',a='y')=>a;return f();})()",
        ("(function(){var f=(a='x')=>a;var g=(b)=>b;"
         "return f();})()"),
        # H1 (spec review 2026-10-09): sloppy-mode `var undefined`
        # shadows the undefined value -- `f(undefined)` passes the
        # shadow, not the undefined value; must fail closed.
        ("(function(){var undefined='junk';var f=(a='x')=>a;"
         "return f(undefined);})()"),
        # S5: an arrow named `undefined` is likewise a read, not the
        # undefined value.
        ("(function(){var undefined=(a='d')=>a;var f=(b)=>b;"
         "return f(undefined);})()"),
    ]
    # NOTE: `(function(){function g(a='x'){return a;}return g();})()`
    # is F735/F736's domain (function declaration, not arrow) and
    # correctly decodes there -- it is a sibling pin (p4), not an
    # F821 bound.
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "decoded=%s" % bad)


# ------------------------------------------------ p4: sibling pins


@_t
def test_p4_sibling_f681():
    """F681 splice/fill + join still decode (credential survives)."""
    s = ("(function(){var a=['" + _A + "','z','" + _B
         + "'];a.splice(1,1);return a.join('');})()")
    ok = _blocked(s) and _decodes_exact(s, _CRED)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_sibling_f773():
    """F773 1-arg fill + indexed read still decodes."""
    s = ("(function(){var a=['z','z'];a.fill('" + _A
         + "');return a[0]+a[1];})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f735f736():
    """F735/F736 nested-function defaults still decode."""
    s = ("(function(){function h(a='" + _A + "'){return a;}return h()+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f767():
    """F767 splice expression still blocked (raw-text credential)."""
    s = ("(function(){var a=['" + _A + _B + "','z'];"
         "return a.splice(0,1)[0];})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ p5: honest text


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    cases = [
        "hello world, nothing to see here",
        "(function(){var s='ab';return s;})()",
        "the quick brown fox jumps over the lazy dog",
        "(function(){var a=['p','q'];a.reverse();return a.join(',');})()",
        "(function(){var f=(a='x')=>a;return f();})()",
    ]
    bad = [c for c in cases if not _misses(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "flagged=%s" % bad)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in reasonable time."""
    sites = []
    for k in range(50):
        sites.append("(function(){var a=['p','q','r'];a.copyWithin(0,2);"
                     "return a[0];})()")
        sites.append("(function(){var a=['p','q'];a.reverse();"
                     "return a.join('');})()")
        sites.append("(function(){var f=(a='x')=>a;return f();})()")
        sites.append("(function(){var s='ab';return s;})()")
    t0 = time.time()
    for s in sites:
        dlp._try_js_expr_decode_all(s)
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200sites=%.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w386_f820_redfirst.py", 0),
                               ("evals/w386_f821_redfirst.py", 0),
                               ("evals/w385_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts (0 BREAK) + w385 attack battery
    (1 BREAK: the footer pin only, lane-local repoint; tree-wide
    repoint is merge-owned)."""
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
