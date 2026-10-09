#!/usr/bin/env python3
"""Wave-387 lane 1: close F829 + F830 + F831 + F832.

F829 (LOW; filed 2026-10-09 04:15 UTC by wave-386 lane 14): prototype
method returning a `this`-bound member -- F823 (CLOSED) models
prototype methods with literal returns, but `C.prototype.m=
function(){return this.x;}` dispatches node-exactly while the decoder
produces zero variants.

F830 (LOW; filed 2026-10-09 04:16 UTC by wave-386 lane 14): zero-param
non-empty-ctor + prototype-method hybrid -- F823 requires a param'd
constructor; F780 needs params; F781 needs an empty body; F690 fails
closed on installs. `(function(){function C(){this.x='f1';}
C.prototype.m=function(){return 'f1';};return new C().m()+'f2';})()`
node-evaluates to the exact credential with zero variants.

F831 (LOW; filed 2026-10-09 04:17 UTC by wave-386 lane 14):
Reflect.construct(C,['f1']) + prototype-method hybrid -- F823 models
`new C(...)` instantiations; the reflection-API form dispatches
node-exactly with zero variants (F780's member reads model
Reflect.construct but fail closed on installs).

F832 (LOW; filed 2026-10-09 05:21 UTC by wave-386 lane 4): plain
`.join` reads on a var-bound array -- the F434 join production fires
for inline literals and F802 (CLOSED) models flat/flatMap on
var-bound arrays, but `(function(){var a=['f1','f2'];
return a.join('');})()` has no production.

Fix (gov/dlp.py, zero new re.compile -- still 28):
- New parameterized core `_js_f82x_hybrid_iife(text,i,depth,state,
  ctor_kind, method_kind, bind_kind)` (ctor_kind: "param"/"zero";
  method_kind: "lit"/"thisread" or a tuple of both -- F830/F831
  accept both, staying disjoint via ctor_kind/bind_kind;
  bind_kind: "new"/"reflect") combining F780-style ctor decls (function/class twins, ctor map
  pre-pass), F781-style prototype installs, and F780-style
  instantiations (new / Reflect.construct). The landed F823 helper
  `_js_parse_f823_hybrid_iife` is byte-identical; three thin wrappers
  (`_js_parse_f829_thisread_method_iife`,
  `_js_parse_f830_zeroctor_hybrid_iife`,
  `_js_parse_f831_reflect_hybrid_iife`) pass the per-finding
  parameters. Disjoint by construction: F829 requires a
  `return this.K` body (F823 fails closed -- F781 body parser needs
  a literal), F830 requires a zero-param ctor head (F823/F829 need
  >=1 param), F831 requires a Reflect.construct instantiation
  (earlier hooks accept only `new`/var-bound receivers).
- `_js_parse_f832_join_varbound_iife` (modeled on F802): var-bound
  array whose return terms' FIRST method step is join (F802
  requires a flat/flatMap first step; F769 requires `.at()`; the
  F434 inline routes require the literal at the read site).
- Fail-closed bounds: unset `this.K` -> undefined (not modeled);
  own-member shadow -> TypeError; named method reads fail closed;
  arg-carrying method calls fail closed; Reflect 3rd-arg / non-array
  arg fail closed; ctor after same-named var fails closed (HARD-1
  class); bare `a.join` (no call) fails closed.
- F452 per-attempt budget charging with snapshot/restore of
  state["parts"]/state["ops"] on every hook miss (wave-379 tails,
  wave-383 restore kept).

Residual note (battery, not product): the wave-386 red-firsts
evals/w386_f830_redfirst.py and evals/w386_f831_redfirst.py carry a
defective s1 shape -- the method body keeps the literal 'f1' while
the constructor binds _A, so the payload decodes to "f1"+_B which
is not credential-shaped and can never block on any tree. Those two
batteries therefore read 1 BREAK with or without this fix; the green
check below encodes that pre-existing expectation. The filed shapes
(themselves correct) are covered here with consistent fragment
substitution.

Two-axis review: Standards axis + Spec axis via subagents; hard
findings actioned (recorded in REPORT.md).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction
(grep-clean: no realmodel_harness/ModelDriver/--provider/ledger refs).
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
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as fh:
        n = fh.read().count("re.compile(")
    if n != RE_COMPILE_COUNT:
        ok = False
        notes.append("re.compile=%d" % n)
    return ("HELD" if ok else "BREAK",
            "pins %s" % ("ok" if ok else notes))


# --------------------------------------------------------------------------
# p2: filed shapes (f1/f2 placeholders -> _A/_B consistently)
# --------------------------------------------------------------------------

@_t
def test_p2_f829_filed_shapes():
    """F829 filed shapes block (this-bound member reads)."""
    shapes = [
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.x;};return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.x;};var o=new C('" + _A + "');return o['m']()+'"
        + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f830_filed_shapes():
    """F830 filed shape blocks (zero-param non-empty ctor hybrid)."""
    shapes = [
        "(function(){function C(){this.x='" + _A + "';}C.prototype.m=function()"
        "{return '" + _A + "';};return new C().m()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f831_filed_shapes():
    """F831 filed shape blocks (Reflect.construct hybrid)."""
    shapes = [
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect.construct(C,['" + _B
        + "']).m()+'" + _A + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f832_filed_shapes():
    """F832 filed shapes block (plain join on var-bound array)."""
    shapes = [
        "(function(){var a=['" + _A + "','" + _B + "'];return a.join('');})()",
        "(function(){var a=['" + _A + "','" + _B + "'];return a['join']('');})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p3: generalizations
# --------------------------------------------------------------------------

@_t
def test_p3_f829_generalizations():
    """F829 generalizations: bracket body, multi-param, multi-install,
    var forms, lit-mix hybrids."""
    shapes = [
        # bracket-string this-read body
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this['x'];};return new C('" + _A + "').m()+'" + _B + "';})()",
        # multi-param ctor
        "(function(){function C(x,y){this.x=x;this.y=y;}C.prototype.m=function()"
        "{return this.x;};return new C('" + _A + "','q').m()+'" + _B + "';})()",
        # multi-install hybrid (one literal, one this-read)
        "(function(){function C(x){this.x=x;}C.prototype.a=function()"
        "{return '" + _A + "';};C.prototype.m=function(){return this.x;};"
        "return new C('" + _B + "').a()+new C('" + _A + "').m();})()",
        # var-bound this-read call
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.x;};var o=new C('" + _A + "');return o.m()+'" + _B + "';})()",
        # class twin
        "(function(){class C{constructor(x){this.x=x;}}C.prototype.m=function()"
        "{return this.x;};return new C('" + _A + "').m()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f830_generalizations():
    """F830 generalizations: class twin, var/let forms, two assigns,
    bracket install, this-read hybrid."""
    shapes = [
        "(function(){class C{constructor(){this.x='" + _A + "';}}C.prototype.m="
        "function(){return '" + _A + "';};return new C().m()+'" + _B + "';})()",
        "(function(){function C(){this.x='" + _A + "';}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C();return o.m()+'" + _B + "';})()",
        "(function(){function C(){this.x='" + _A + "';this.y='q';}C.prototype.m="
        "function(){return '" + _A + "';};let o=new C();return o.m()+'" + _B + "';})()",
        "(function(){function C(){this.x='" + _A + "';}C.prototype['m']=function()"
        "{return '" + _A + "';};return new C()['m']()+'" + _B + "';})()",
        # zero-param ctor + this-read method (F829 x F830 corner)
        "(function(){function C(){this.x='" + _A + "';}C.prototype.m=function()"
        "{return this.x;};return new C().m()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f831_generalizations():
    """F831 generalizations: var-bound, bracket forms, bracket args,
    this-read hybrid, multi-param."""
    shapes = [
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=Reflect.construct(C,['" + _B
        + "']);return o.m()+'" + _A + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect['construct'](C,['" + _B
        + "'])['m']()+'" + _A + "';})()",
        # this-read method hybrid
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.x;};return Reflect.construct(C,['" + _A + "']).m()+'"
        + _B + "';})()",
        # multi-param through Reflect
        "(function(){function C(x,y){this.x=x;this.y=y;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect.construct(C,['" + _B
        + "','q']).m()+'" + _A + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f832_generalizations():
    """F832 generalizations: separators, chains, let/const, bracket decl,
    concat tails, multi-element."""
    shapes = [
        "(function(){var a=['" + _A + "','" + _B + "'];return a.join('-');})()",
        "(function(){var a=['" + _A + "','" + _B
        + "'];return a.join(',').split(',').join('');})()",
        "(function(){let a=['" + _A + "','" + _B + "'];return a.join('');})()",
        "(function(){const a=['" + _A + "','" + _B + "'];return a.join('');})()",
        "(function(){var a=['" + _A + "','" + _B
        + "'];return a.join('')+'" + _A + "';})()",
        "(function(){var a=['" + _A + "','x','" + _B + "'];return a.join('');})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p4: fail-closed bounds
# --------------------------------------------------------------------------

@_t
def test_p4_f829_fail_closed():
    """F829 bounds: unset member, shadow, named, arg-call, junk body."""
    bounds = [
        # unset this.y -> undefined in node: no decode
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.y;};return new C('" + _A + "').m()+'" + _B + "';})()",
        # own-member shadow -> TypeError in node: no decode
        "(function(){function C(x){this.m=x;}C.prototype.m=function()"
        "{return this.x;};return new C('" + _A + "').m()+'" + _B + "';})()",
        # named function expression: not modeled
        "(function(){function C(x){this.x=x;}C.prototype.m=function mm()"
        "{return this.x;};return new C('" + _A + "').m()+'" + _B + "';})()",
        # arg-carrying call: not modeled
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return this.x;};return new C('" + _A + "').m('q')+'" + _B + "';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f830_fail_closed():
    """F830 bounds: unbound RHS, bare read, junk junk, shadow install."""
    bounds = [
        # unbound this-assign RHS: no decode
        "(function(){function C(){this.x=q;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C().m()+'" + _B + "';})()",
        # bare method read (no call): no decode
        "(function(){function C(){this.x='" + _A + "';}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C();return o.m+'" + _B + "';})()",
        # junk junk
        "'(function(){var s=\\\\'ab\\\\';return s;})()'",
        # install shadowed by own member -> TypeError in node
        "(function(){function C(){this.m='" + _A + "';}C.prototype.m=function()"
        "{return '" + _A + "';};return new C().m()+'" + _B + "';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f831_fail_closed():
    """F831 bounds: 3rd arg, non-array arg, anonymous ctor, unbound arg."""
    bounds = [
        # Reflect.construct 3-arg form: not modeled (TypeError-class)
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect.construct(C,['" + _B
        + "'],Object).m()+'" + _A + "';})()",
        # non-array args: not modeled
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect.construct(C,'" + _B
        + "').m()+'" + _A + "';})()",
        # anonymous ctor arg: not modeled
        "(function(){C.prototype.m=function(){return '" + _A + "';};"
        "return Reflect.construct(function(x){this.x=x;},['" + _B
        + "']).m()+'" + _A + "';})()",
        # unbound arg element: no decode
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return Reflect.construct(C,[q]).m()+'"
        + _B + "';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f832_fail_closed():
    """F832 bounds: bare join ref, unbound array, non-string elements,
    junk junk."""
    bounds = [
        # bare join reference (no call): not obfuscation-shaped
        "(function(){var a=['" + _A + "','" + _B + "'];return a.join;})()",
        # unbound array variable: no decode
        "(function(){return a.join('');})()",
        # non-string elements: fail closed
        "(function(){var a=['" + _A + "',42];return a.join('');})()",
        "'(function(){var s=\\\\'ab\\\\';return s;})()'",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


# --------------------------------------------------------------------------
# p5: sibling pins
# --------------------------------------------------------------------------

@_t
def test_p5_sibling_pins():
    """Siblings unaffected: F823 hybrid, F780 member reads, F781 proto
    reads, F690 zero-ctor reads, F802 flat-first join, F769 .at(),
    F434 inline join, F692 var IIFE."""
    pins = [
        # F823 param'd hybrid still blocks
        ("(function(){function C(x){this.x=x;}C.prototype.m=function()"
         "{return '" + _A + "';};return new C('" + _A + "').m()+'" + _B + "';})()",
         True),
        # F780 param'd ctor member reads still block
        ("(function(){function C(x){this.x=x;}var o=new C('" + _A
         + "');return o.x+'" + _B + "';})()", True),
        # F781 zero-param proto reads still block
        ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return new C().m()+'" + _B + "';})()", True),
        # F690 zero-param ctor reads still block
        ("(function(){function C(){this.x='" + _A + "';}var o=new C();"
         "return o.x+'" + _B + "';})()", True),
        # F802 flat-first var-bound join still blocks
        ("(function(){var a=[['" + _A + "'],['" + _B + "']];"
         "return a.flat().join('');})()", True),
        # F769 .at() still blocks
        ("(function(){var a=['" + _A + "','" + _B + "'];return a.at(0)+a.at(1);})()",
         True),
        # F434 inline join still blocks
        ("['" + _A + "','" + _B + "'].join('')", True),
        # F692 plain var IIFE still blocks
        ("(function(){var s='" + _A + "';return s+'" + _B + "';})()", True),
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
        "(function(){function C(x){this.x=x;}return 42;})()",
        "(function(){var a=['x','y'];return a.join('-');})()",
        "'the quick brown fox'",
        "(function(){function C(){this.x='q';}return new C();})()",
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
    for _ in range(50):
        sites.append("(function(){function C(x){this.x=x;}C.prototype.m=function()"
                     "{return this.x;};return new C('" + _A + "').m()+'" + _B + "';})()")
        sites.append("(function(){function C(){this.x='" + _A + "';}C.prototype.m="
                     "function(){return '" + _A + "';};return new C().m()+'" + _B + "';})()")
        sites.append("(function(){function C(x){this.x=x;}C.prototype.m=function()"
                     "{return '" + _A + "';};return Reflect.construct(C,['" + _B
                     + "']).m()+'" + _A + "';})()")
        sites.append("(function(){var a=['" + _A + "','" + _B + "'];return a.join('');})()")
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
    """F829/F830/F831/F832 stamped CLOSED; F833-F892 filed OPEN;
    lane-local footer (open F833-F892 / next F893)."""
    text = _findings_text()
    bad = []
    for fid in ("F829", "F830", "F831", "F832"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        # entry runs to the next "\n(" at line start or EOF
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F833", "F892"):
        if ("(%s filed" % fid) not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F893**" not in text:
        bad.append("footer-next-not-F893")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


# --------------------------------------------------------------------------
# p9: depth-1 green check
# --------------------------------------------------------------------------

def _green_check():
    """Depth-1: the four w387 red-firsts 0 BREAK; the four w386
    red-firsts at their post-fix expectations (w386_f830/f831 keep
    1 BREAK from their defective s1 shapes -- battery defect, not a
    product gap; see module docstring); the adjacent close battery
    w386_f822f823close_probes expects 1 BREAK -- its p8 asserts
    wave-386 lane 14's lane-local footer ("Next free finding:
    F833"), which this lane legitimately superseded (F893); all
    11 of its product probes still HELD, so this is footer
    evolution, not a regression."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w387_f829_redfirst.py", 0),
                               ("evals/w387_f830_redfirst.py", 0),
                               ("evals/w387_f831_redfirst.py", 0),
                               ("evals/w387_f832_redfirst.py", 0),
                               ("evals/w386_f829_redfirst.py", 0),
                               ("evals/w386_f830_redfirst.py", 1),
                               ("evals/w386_f831_redfirst.py", 1),
                               ("evals/w386_f832_redfirst.py", 0),
                               ("evals/w386_f822f823close_probes.py", 1)):
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
            # close batteries print a summary line, not "tally:"
            m = re.search(r"(\d+) BREAK / (\d+) HELD", out)
            if m:
                nbreak = int(m.group(1))
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
    print("w387_f829f830f831f832close: starting %d probes" % len(TESTS))
    results = []
    for fn in TESTS:
        pid = fn.__name__
        try:
            v, note = fn()
        except Exception as e:  # noqa: BLE001
            v, note = "ERROR", "%s: %s" % (type(e).__name__, str(e)[:120])
        results.append((pid, v, note))
        print("%-28s %s | %s" % (pid, v, note))
    breaks = sorted(pid for pid, v, _ in results if v == "BREAK")
    errors = sorted(pid for pid, v, _ in results if v == "ERROR")
    held = sorted(pid for pid, v, _ in results if v == "HELD")
    print("w387_f829f830f831f832close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
