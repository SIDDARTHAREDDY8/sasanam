#!/usr/bin/env python3
"""Wave-387 lane 13: close F877 + F878 + F879 + F880 (JS class-fragment
laundering residuals).

F877 (LOW; filed 2026-10-09 by wave-386 attack round 54): static
initialization blocks with try/catch -- the decoder models
straight-line static blocks (F662) but not
`static{try{...}catch(e){...}}`, and not `C.k='LIT'` static-field
writes through the class name.

F878 (LOW; filed 2026-10-09 by wave-386 attack round 54): arrow
function class fields -- the decoder models constructor
this-binding (F780) but not `class C{m=()=>this.k;}`; the arrow
captures the instance's `this`, so `new C('f1').m()` resolves
node-exactly.

F879 (LOW; filed 2026-10-09 by wave-386 attack round 54): anonymous
class expressions -- `var C=class{...}` / `var C=class D{...}`
are not modeled (only declarations).

F880 (LOW; filed 2026-10-09 by wave-386 attack round 54): toSorted
with a comparator -- the decoder models no-arg `toSorted` (F772)
but not `.toSorted(function(x,y){return 0;})`; the always-zero
comparator is node-exactly the identity (V8 stable sort).

Fix (gov/dlp.py, zero new re.compile):
- F877: `_js_f662_static_block` refactored around a
  `_js_f662_static_stmt` single-statement helper; new
  `_js_f877_parse_try` (try/catch with throw control-flow;
  uncaught throw fails closed; finally fails closed) and
  `_js_f877_skip_to_semi`; `CNAME.MEMBER='LIT'/+='LIT'` writes
  via new cname/static_dict params (F662 call site passes
  them; F672 passes neither).
- F878: new `_js_f878_parse_ctor_members` (constructor +
  `NAME=()=>this.MEMBER;` fields); F780 `ctors` become
  (params, assigns, methods) 3-tuples; arrow fields carried on
  the instance dict under ("arrow", name) keys;
  `_js_f780_member_read` dispatches `o.m()` calls.
- F879: `var|let|const NAME=class[INNER]{...};` in the F780
  hook's decl branch, sharing `_js_f878_parse_ctor_members`.
- F880: `_js_f880_parse_zero_comparator` (always-zero function /
  arrow); the F772 toSorted postfix branch accepts it as
  identity; new `_js_parse_f880_varr_iife` (after F802) for
  `DECL A=[...].toSorted([FN]);return A[I]+...;`.

Residuals filed by this lane (red-first verified, left OPEN):
none -- all four findings close cleanly within the narrow
grammars; documented fail-closed bounds below.

Two-axis review: Standards + Spec via subagents; all hard
findings actioned (see REPORT.md).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh
/var/tmp/g387-* TMPDIRs, no in-repo git in self-pins,
concatenation-constructed credentials, pin 2143,
VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction.
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
VERIFIER_PIN = 33
RE_COMPILE_COUNT = 28  # zero new re.compile(

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


def _findings_text():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        return fh.read()


# --------------------------------------------------------------------------
# p1: pin and taxonomy pins
# --------------------------------------------------------------------------

@_t
def test_p1_pin_and_taxonomy():
    """Pin 2143, VERIFIER_TAXONOMY_PIN=33, zero new re.compile (28)."""
    notes = []
    ok = True
    if len(TAXONOMY) != TAXONOMY_PIN:
        ok = False
        notes.append("taxonomy=%d" % len(TAXONOMY))
    with open(os.path.join(REPO_ROOT, "evals",
                           "w318_evidence_schema_probes.py")) as fh:
        m = re.search(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", fh.read())
    if not m or int(m.group(1)) != VERIFIER_PIN:
        ok = False
        notes.append("verifier-pin=%s" % (m.group(1) if m else None))
    n = 0
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as fh:
        for line in fh:
            if "re.compile(" in line:
                n += 1
    if n != RE_COMPILE_COUNT:
        ok = False
        notes.append("re.compile=%d" % n)
    notes.append("pin=%d verifier=%d recomp=%d" % (TAXONOMY_PIN, VERIFIER_PIN, n))
    return ("HELD" if ok else "BREAK", "; ".join(notes))


# --------------------------------------------------------------------------
# p2: filed shapes
# --------------------------------------------------------------------------

@_t
def test_p2_f877_filed_shapes():
    """F877 filed shapes block."""
    shapes = [
        "(function(){class C{static k;static{try{C.k='" + _A
        + "';}catch(e){}}}return C.k+'" + _B + "';})()",
        "(function(){var r='';class C{static{try{throw 0;}catch(e){r='"
        + _A + "';}}}return r+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f878_filed_shapes():
    """F878 filed shapes block."""
    shapes = [
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}"
        "return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){class C{constructor(x){this.k=x;}get=()=>this['k'];}"
        "return new C('" + _A + "').get()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f879_filed_shapes():
    """F879 filed shapes block."""
    shapes = [
        "(function(){var C=class{constructor(x){this.k=x;}};"
        "return new C('" + _A + "').k+'" + _B + "';})()",
        "(function(){var C=class D{constructor(x){this.k=x;}};"
        "return new C('" + _A + "').k+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f880_filed_shapes():
    """F880 filed shapes block."""
    shapes = [
        "['" + _A + "','" + _B + "'].toSorted(function(x,y){return 0;}).join('')",
        "(function(){var a=['" + _A + "','" + _B + "','x']"
        ".toSorted(function(x,y){return 0;});return a[0]+a[1];})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p3: generalizations
# --------------------------------------------------------------------------

@_t
def test_p3_f877_generalizations():
    """F877 generalizations: no-throw, pre-throw stmts, catch w/o
    binding, +=, nested try, decl in try."""
    shapes = [
        # no throw: handler never runs
        "(function(){var r='';class C{static{try{r='" + _A
        + "';}catch(e){r='BAD';}}}return r+'" + _B + "';})()",
        # pre-throw statements execute; post-throw do not
        "(function(){var r='';class C{static{try{r='" + _A
        + "';throw 0;r='BAD';}catch(e){r+='" + _B
        + "';}}}return r;})()",
        # catch without binding
        "(function(){var r='';class C{static{try{throw 0;}catch{r='"
        + _A + "';}}}return r+'" + _B + "';})()",
        # C.k += on initialized static
        "(function(){class C{static k='" + _A + "';static{C.k+='" + _B
        + "';}}return C.k;})()",
        # nested try: inner catches
        "(function(){var r='';class C{static{try{try{throw 0;}"
        "catch(e){r='" + _A + "';}}catch(e){r='BAD';}}}return r+'"
        + _B + "';})()",
        # var decl inside try
        "(function(){class C{static{try{var t='" + _A
        + "';C.k=t;}catch(e){}}}return C.k+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f878_generalizations():
    """F878 generalizations: var-bound instance, multi-field,
    bracket member, ws variants, Reflect."""
    shapes = [
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}"
        "var o=new C('" + _A + "');return o.m()+'" + _B + "';})()",
        "(function(){class C{constructor(x,y){this.k=x;this.j=y;}"
        "m=()=>this.k;n=()=>this['j'];}"
        "return new C('" + _A + "','q').m()+new C('x','" + _B + "').n();})()",
        "(function(){class C{constructor(x){this.k=x;}m = ( ) => this.k ;}"
        "return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}"
        "return Reflect.construct(C,['" + _A + "']).m()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f879_generalizations():
    """F879 generalizations: let/const, arrow field combo,
    var-bound instance, multi-param."""
    shapes = [
        "(function(){let C=class{constructor(x){this.k=x;}};"
        "return new C('" + _A + "').k+'" + _B + "';})()",
        "(function(){const C=class{constructor(x){this.k=x;}};"
        "return new C('" + _A + "').k+'" + _B + "';})()",
        # class expression + arrow field (F878 x F879)
        "(function(){var C=class{constructor(x){this.k=x;}m=()=>this.k;};"
        "return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){var C=class{constructor(x,y){this.k=x;}};"
        "var o=new C('" + _A + "','q');return o.k+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f880_generalizations():
    """F880 generalizations: arrow, named fn, -0, no-arg var-bound,
    ws variants, bracket call."""
    shapes = [
        "['" + _A + "','" + _B + "'].toSorted(()=>0).join('')",
        "['" + _A + "','" + _B + "'].toSorted(function cmp(x,y){return 0;}).join('')",
        "['" + _A + "','" + _B + "'].toSorted(function(x,y){return -0;}).join('')",
        "['" + _A + "','" + _B + "'].toSorted( (x,y) => 0 ).join('')",
        "(function(){var a=['" + _A + "','" + _B + "','x']"
        ".toSorted((x)=>0);return a[0]+a[1];})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p4: fail-closed bounds
# --------------------------------------------------------------------------

@_t
def test_p4_f877_fail_closed():
    """F877 bounds: finally, uncaught throw, this-write, non-literal
    RHS, += on undeclared, junk."""
    bounds = [
        # finally fails closed
        "(function(){var r='';class C{static{try{r='a';}catch(e){}"
        "finally{r='b';}}}return r+'x';})()",
        # uncaught throw: class definition throws, no value
        "(function(){class C{static{throw 0;}}return 'x';})()",
        # this.k= fails closed
        "(function(){class C{static k;static{this.k='a';}}return C.k+'x';})()",
        # non-literal RHS fails closed
        "(function(){var z='a';class C{static k;static{C.k=z;}}return C.k+'x';})()",
        # += on undeclared static fails closed
        "(function(){class C{static{try{C.k+='a';}catch(e){}}}return 'x';})()",
        # throw without catch fails closed
        "(function(){class C{static{try{throw 0;}}}return 'x';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f878_fail_closed():
    """F878 bounds: arrow params, non-this body, bare read, field
    named static, call args, shadowed key."""
    bounds = [
        # arrow with params fails closed
        "(function(){class C{constructor(x){this.k=x;}m=(y)=>this.k;}"
        "return new C('a').m()+'x';})()",
        # non-this body fails closed
        "(function(){class C{constructor(x){this.k=x;}m=()=>x;}"
        "return new C('a').m()+'x';})()",
        # bare read without call fails closed (function object)
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}"
        "var o=new C('a');return o.m+'x';})()",
        # call with args fails closed
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.k;}"
        "return new C('a').m('x')+'x';})()",
        # field colliding with ctor-assign fails closed
        "(function(){class C{constructor(x){this.m=x;m=()=>this.m;}}"
        "return new C('a').m()+'x';})()",
        # spec review H-1: arrow targeting never-assigned member
        # must fail closed, not crash
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.zzz;}"
        "return new C('a').m()+'x';})()",
        # spec review H-1: arrow reading another arrow field
        "(function(){class C{constructor(x){this.k=x;}m=()=>this.n;"
        "n=()=>this.k;}return new C('a').m()+'x';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f879_fail_closed():
    """F879 bounds: extends, no constructor, redeclared name,
    non-class initializer."""
    bounds = [
        # extends fails closed
        "(function(){var C=class extends{constructor(x){this.k=x;}};"
        "return new C('a').k+'x';})()",
        # no constructor fails closed
        "(function(){var C=class{};return new C('a').k+'x';})()",
        # redeclared name fails closed
        "(function(){var C=class{constructor(x){this.k=x;}};"
        "var C=class{constructor(x){this.k=x;}};"
        "return new C('a').k+'x';})()",
        # class decl (not expr) with same shape still works via
        # the declaration path -- so use a junky variant here:
        # `var C=5` is not a class
        "(function(){var C=5;return new C('a').k+'x';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f880_fail_closed():
    """F880 bounds: nonzero comparator, non-function arg,
    out-of-range index, non-literal index, astral."""
    bounds = [
        # nonzero comparator fails closed
        "['" + _A + "','" + _B + "'].toSorted(function(x,y){return 1;}).join('')",
        # non-function comparator fails closed
        "['" + _A + "','" + _B + "'].toSorted(0).join('')",
        # arrow with nonzero body fails closed
        "['" + _A + "','" + _B + "'].toSorted(()=>1).join('')",
        # out-of-range index fails closed
        "(function(){var a=['" + _A + "'].toSorted(()=>0);return a[5];})()",
        # non-literal index fails closed
        "(function(){var i=0;var a=['" + _A + "'].toSorted(()=>0);return a[i];})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


# --------------------------------------------------------------------------
# p5: sibling pins
# --------------------------------------------------------------------------

@_t
def test_p5_sibling_pins():
    """Siblings unaffected: F662 straight static, F780 decl, F772
    no-arg postfix, F802 flat, F690, honest quiet."""
    pins = [
        # F662 straight-line static block still blocks
        ("(function(){var s='';class C{static{s='" + _A
         + "';}}return s+'" + _B + "';})()", True),
        # F780 class declaration member reads still block
        ("(function(){class C{constructor(x){this.k=x;}}"
         "return new C('" + _A + "').k+'" + _B + "';})()", True),
        # F772 no-arg toSorted postfix still blocks (filed shape)
        ("(function(){return ['" + _A + "','" + _B
         + "'].toSorted().reverse().join('');})()", True),
        # F802 var-bound flat still blocks
        ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat().join('');})()", True),
        # F690 zero-param ctor still blocks
        ("(function(){function C(){this.x='" + _A + "';}var o=new C();"
         "return o.x+'" + _B + "';})()", True),
        # honest text stays quiet
        ("'the quick brown fox jumps over the lazy dog'", False),
    ]
    bad = []
    for payload, want_hit in pins:
        hit = _blocked(payload)
        if hit != want_hit:
            bad.append(payload[:40])
    return ("HELD" if not bad else "BREAK",
            "%d/%d sibling pins hold" % (len(pins) - len(bad), len(pins)))


# --------------------------------------------------------------------------
# p6: honest-text controls
# --------------------------------------------------------------------------

@_t
def test_p6_honest_text():
    """Honest text: no false positives on benign JS."""
    honest = [
        "'hello world'",
        "var x = [1,2,3].join(',');",
        "(function(){class C{static{s='x';}}return 42;})()",
        "'the quick brown fox'",
        "['a','b'].toSorted().join('-')",
        "(function(){var C=class{};return 1;})()",
    ]
    bad = [s for s in honest if _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest quiet" % (len(honest) - len(bad), len(honest)))


# --------------------------------------------------------------------------
# p7: perf (200 sites)
# --------------------------------------------------------------------------

@_t
def test_p7_perf_200_sites():
    """200 decode sites complete in bounded time (F452)."""
    sites = []
    for k in range(50):
        sites.append("['" + _A + "','" + _B + "'].toSorted(()=>0).join('')")
        sites.append("(function(){class C{static k;static{try{C.k='" + _A
                     + "';}catch(e){}}}return C.k+'" + _B + "';})()")
        sites.append("(function(){class C{constructor(x){this.k=x;}"
                     "m=()=>this.k;}return new C('" + _A + "').m()+'"
                     + _B + "';})()")
        sites.append("(function(){var C=class{constructor(x){this.k=x;}};"
                     "return new C('" + _A + "').k+'" + _B + "';})()")
    text = "junk " + " junk ".join(sites) + " junk"
    t0 = time.time()
    dlp.find_credential(text)
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs (budget ok=%s)" % (dt, ok))


# --------------------------------------------------------------------------
# p8: FINDINGS.md stamps
# --------------------------------------------------------------------------

@_t
def test_p8_findings_stamps():
    """F877-F880 stamped CLOSED; F829-F876/F881-F892 OPEN; footer next F893."""
    text = _findings_text()
    bad = []
    for fid in ("F877", "F878", "F879", "F880"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F829", "F876", "F881", "F892"):
        if "(%s filed" % fid not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F893**" not in text:
        bad.append("footer-next-not-F893")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


# --------------------------------------------------------------------------
# p9: depth-1 green check
# --------------------------------------------------------------------------

def _green_check():
    """Depth-1: the four w386 red-firsts are 0 BREAK on this tree."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w386_f877_redfirst.py", 0),
                               ("evals/w386_f878_redfirst.py", 0),
                               ("evals/w386_f879_redfirst.py", 0),
                               ("evals/w386_f880_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g387-l13-green-", dir="/var/tmp")
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
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w387_f877f878f879f880close: starting %d probes" % len(TESTS))
    results = []
    for fn in TESTS:
        name = fn.__name__
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "BREAK", "ERROR %s: %s" % (type(e).__name__, e)
        results.append((name, verdict, note))
        print("%-38s %s %s" % (name, verdict, note))
    breaks = [r for r in results if r[1] != "HELD"]
    held = [r for r in results if r[1] == "HELD"]
    print("tally: %d BREAK / %d HELD / %d total"
          % (len(breaks), len(held), len(results)))
    if breaks:
        print("unexpected BREAKs: %s" % [r[0] for r in breaks])
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
