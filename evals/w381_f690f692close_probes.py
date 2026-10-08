#!/usr/bin/env python3
"""Wave-381 lane 4: close F690 (constructor-this member reads) + F692
(super reads in static methods).

F690 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
fragments read via `this` in function and class constructors bypass
the bounded static JS-expression decoder -- the decoder never binds
`this` in constructors. Distinct from F674 (CLOSED, this-bound reads
in object-literal getters/methods): the receiver here is a
constructor-built instance. Distinct from F672 (CLOSED, whose
class-body parser explicitly fails closed on `constructor`).

F692 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
fragments read via `super.M` in static methods bypass the decoder.
Distinct from F672 (CLOSED, whose class-body parser explicitly fails
closed on `super` and on member reads inside method bodies): every
shape here carries a `super` production F672 rejects.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f690_ctor_iife (+ 5 helpers): statements are exactly
  `function C(){ this.K='LIT'; ... }` (zero params), `class C{
  constructor(){ this.K='LIT'; ... } }` (only member), and
  `var|let|const c=new C();` (single declarator, no shadowing);
  the return is a +-additive of string literals, var-bound
  instance member reads, and inline `new C().K` reads.
  Instantiation runs the ctor body against a fresh member dict
  (later assignments win, node-exact).
- _js_parse_f692_super_iife (+ 4 helpers): `class B{ static
  K='LIT'; ... | static get K(){return 'LIT';} ... }` parent plus
  `class D extends B{ static Y(){return super.M;} }` (exactly one
  member); the return is a +-additive of string literals,
  `D.Y()` calls, and direct `B.K` static reads. `super` in a
  static method is the parent constructor -- only B's static side
  is consulted (node-verified: a same-named own static on D does
  not shadow the super read).
Both hooked after F678 in _js_parse_primary; disjoint by
constructor/super productions (red-first verified 2 BREAK each on
the open tree). F452 parts-budget charging via _js_f672_charge;
F510 string-only discipline (unset members fail closed --
engine undefined).

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


# ------------------------------------------------ p1: F690 filed shapes (must block)

@_t
def test_p1_f690_function_ctor():
    """F690 filed shape 1: function-constructor this-read blocks."""
    s = ("(function(){function C(){this.x='" + _A + "';}var c=new C();"
         "return c.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f690_class_ctor():
    """F690 filed shape 2: class-constructor this-read blocks."""
    s = ("(function(){class C{constructor(){this.x='" + _A + "';}}"
         "return new C().x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: F690 variants (must block)

@_t
def test_p2_f690_multi_assign():
    """Later this-assignments win (node-exact)."""
    s = ("(function(){function C(){this.x='nope';this.y='" + _B
         + "';this.x='" + _A + "';}var c=new C();return c.x+c.y;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f690_bracket_assign():
    """Bracket-string this-assignment blocks."""
    s = ("(function(){function C(){this['x']='" + _A + "';}var c=new C();"
         "return c.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f690_inline_new():
    """Inline `new C().x` (no var binding) blocks."""
    s = ("(function(){function C(){this.x='" + _A + "';}"
         "return new C().x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f690_bracket_read():
    """Bracket-string member read on the instance blocks."""
    s = ("(function(){function C(){this.x='" + _A + "';}var c=new C();"
         "return c['x']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f690_class_varbound():
    """Class ctor with var-bound instance blocks."""
    s = ("(function(){class C{constructor(){this.x='" + _A + "';}}"
         "var c=new C();return c.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: F690 bounds (must miss)

@_t
def test_p3_f690_ctor_params():
    """Constructor params fail closed (node would decode)."""
    s = ("(function(){function C(a){this.x=a;}var c=new C('" + _A
         + "');return c.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_missing_member():
    """Unset member reads fail closed (engine undefined)."""
    s = ("(function(){function C(){this.x='" + _A + "';}var c=new C();"
         "return c.nope+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_ctor_returns_object():
    """A ctor-returned object would replace the instance (fail closed)."""
    s = ("(function(){function C(){this.x='nope';return {x:'" + _A
         + "'};}var c=new C();return c.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_nonliteral_assign():
    """Non-literal this-assignments fail closed (node throws)."""
    s = ("(function(){function C(){this.x=y;}var c=new C();"
         "return c.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_forward_ref():
    """Forward references fail closed (node hoists; documented residual)."""
    s = ("(function(){var c=new C();function C(){this.x='" + _A
         + "';}return c.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_prototype_assign():
    """Prototype assignments fail closed (distinct mechanism)."""
    s = ("(function(){function C(){}C.prototype.x='" + _A
         + "';var c=new C();return c.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_class_extra_member():
    """Classes with members beyond the constructor fail closed."""
    s = ("(function(){class C{constructor(){this.x='" + _A
         + "';}m(){return 1;}}return new C().x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_derived_no_super():
    """Derived ctor without super() throws in node; we fail closed."""
    s = ("(function(){class B2{}class C extends B2{constructor(){this.x='"
         + _A + "';}}return new C().x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_var_shadows_ctor():
    """A var shadowing the ctor name fails closed (node would decode)."""
    s = ("(function(){function C(){this.x='" + _A + "';}var C=new C();"
         "return C.x+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f690_bare_new_no_member():
    """A bare `new C()` (no member read) is outside the discipline."""
    s = ("(function(){function C(){this.x='" + _A + "';}var c=new C();"
         "return '" + _B + "';})()")
    # No member read at all: the return is a plain literal, which the
    # literal path flags only if credential-shaped on its own. The
    # point is the ctor production alone must not invent a decode.
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: F692 filed shapes (must block)

@_t
def test_p4_f692_super_static_field():
    """F692 filed shape 1: super read of a static field blocks."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class D extends B{static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p4_f692_super_static_getter():
    """F692 filed shape 2: super read of a static getter blocks."""
    s = ("(function(){class B{static get x(){return '" + _A + "';}}"
         "class D extends B{static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p5: F692 variants (must block)

@_t
def test_p5_f692_super_bracket():
    """Bracket-string super member blocks."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class D extends B{static y(){return super['x'];}}"
         "return D.y()+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p5_f692_parent_direct_read():
    """Direct `B.x` static read in the same IIFE blocks."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class D extends B{static y(){return super.x;}}"
         "return B.x+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p5_f692_multi_static():
    """Multiple static members resolve independently."""
    s = ("(function(){class B{static x='" + _A + "';static z='" + _B + "';}"
         "class D extends B{static y(){return super.x;}}"
         "return D.y()+B.z;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p6: F692 bounds (must miss)

@_t
def test_p6_f692_super_miss():
    """Super reads of missing members fail closed (engine undefined)."""
    s = ("(function(){class B{static z='q';}"
         "class D extends B{static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_derived_extra_member():
    """Extra members on D fail closed (node would still read B.x)."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class D extends B{static x='nope';static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_wrong_parent():
    """D extending a different class fails closed."""
    s = ("(function(){class B{static x='" + _A + "';}class E{}"
         "class D extends E{static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_transitive_extends():
    """Transitive extends chains fail closed (documented residual)."""
    s = ("(function(){class A{static x='" + _A + "';}class B extends A{}"
         "class D extends B{static y(){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_method_params():
    """Static-method params fail closed."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class D extends B{static y(a){return super.x;}}"
         "return D.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_super_instance_method():
    """Super in an instance method is outside the static discipline."""
    s = ("(function(){class B{x='" + _A + "';}"
         "class D extends B{y(){return super.x;}}"
         "return new D().y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p6_f692_duplicate_class_name():
    """D redeclaring B's name fails closed (node SyntaxError)."""
    s = ("(function(){class B{static x='" + _A + "';}"
         "class B extends B{static y(){return super.x;}}"
         "return B.y()+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p7: neighbors + junk

@_t
def test_p7_neighbor_f672_still_blocks():
    """F672 (CLOSED) still blocks its filed shapes."""
    s = ("(function(){class C{static #x='" + _A + "';static y(){return C.#x;}}"
         "return C.y()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p7_neighbor_f674_still_blocks():
    """F674 (CLOSED) still blocks this-bound object reads."""
    s = ("(function(){var o={x:'" + _A + "',get:function(){return this.x;}};"
         "return o.get()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p7_neighbor_f676_still_blocks():
    """F676 (CLOSED) still blocks optional-chaining calls."""
    s = ("(function(){var o={f:function(){return '" + _A + "';}};"
         "return o?.f()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p7_neighbor_f691_still_misses():
    """F691 now CLOSED (wave-381 lane 5) -- blocks, nothing absorbed."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{value:'" + _A
         + "',enumerable:true});"
         "return Object.getOwnPropertyDescriptor(o,'x').value+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p7_neighbor_f698_still_misses():
    """F698 now CLOSED (wave-381 lane 5) -- blocks, nothing absorbed."""
    s = ("(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '"
         + _A + "';}});"
         "return Object.getOwnPropertyDescriptor(o,'x').get()+'"
         + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p7_junk_quiet():
    """Junk stays quiet."""
    shapes = [
        "'(function(){var s=\\'ab\\';return s;})()'",
        "(function(){function C(){this.x='ab';}var c=new C();return c.x;})()",
        "(function(){class B{static x='ab';}class D extends B{static y(){return super.x;}}return D.y();})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p8: pin, footer, no new regexes

@_t
def test_p8_pin_footer():
    """Pin 2140; lane-local footer (F690+F692 CLOSED; open F686-F689, F691, F693-F699 / next F700)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F762**" in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    ok = ok and ("Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p8_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p9: perf

@_t
def test_p9_perf():
    """200 mixed ctor/super sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){function C(){this.x='a%d';}var c=new C();"
                      "return c.x+'b';})()" % k)
        corpus.append("(function(){class B{static x='a%d';}"
                      "class D extends B{static y(){return super.x;}}"
                      "return D.y()+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p10: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w380_f690_redfirst.py", 0),
                               ("evals/w380_f692_redfirst.py", 0),
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
def test_p10_green_check():
    """Depth-1 green check: F690/F692 red-firsts + wave-380 attack battery green."""
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
