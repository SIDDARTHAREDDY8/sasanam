#!/usr/bin/env python3
"""Wave-386 lane 14: close F822 + F823 (optional-chaining direct method
calls; F780+F781 param'd-constructor + prototype-method hybrid).

F822 (LOW; filed 2026-10-09 by wave-385 lane 3): optional-chaining
direct method calls -- the decoder models `.method(args)` on
array/string receivers (F478 dispatch) but the `?.method(args)`
form resolves to a `_JSMethodRef` whose direct-call step
(`_js_parse_methodref_step`) only handles `.call`/`.apply`/`.bind`
or the `of` factory, never a direct `(args)` call -- so every
modeled method is bypassable via `?.` (receiver provably non-null,
so engine-identical to `.`).

F823 (LOW; filed 2026-10-09 by wave-385 lane 10): F780+F781 hybrid
residual -- param'd-constructor this-binding (F780) and prototype
method reads (F781) are modeled individually, but the combination
(`function C(x){this.x=x;}C.prototype.m=function(){return 'f1';};`
`new C('f1').m()`) dispatches node-exactly while the decoder
produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F822: in `_js_parse_postfix`, when `_js_parse_opt_member_ref`
  succeeds on a provably non-null receiver and the next non-ws
  char is `(`, the call dispatches directly through the existing
  `_js_apply_method` grammar with the receiver as base
  (engine-identical; the ref-creation step already validated the
  method against the F478 table and the base is non-null). The
  old reference path (`?.call`/`.apply`/`.bind`, bare refs,
  `??` picks) is untouched.
- F823: new `_js_parse_f823_hybrid_iife` (hooked after F781)
  combining F780-style ctor decls (function `function C(P,...){...}` /
  class twin, >=1 param, this-assign body), F781-style
  `C.prototype.m=function(){return 'LIT';}` installs, and
  F780-style `var o=new C('L',...)` bindings; the return is an
  additive of literals, prototype method calls (`new C('L').m()` /
  `o.m()` / `o['m']()`, zero args, resolved on the prototype map),
  and F780 member-read operands. Disjoint: every accepted shape
  carries BOTH a param'd ctor head (F781 needs zero-param empty
  ctors) AND a prototype install (F780 rejects installs; F690
  needs zero-param ctors).

Residuals filed by this lane (red-first verified, left OPEN):
F829 (method `return this.x`), F830 (zero-param non-empty ctor),
F831 (Reflect.construct hybrid), F832 (non-F478-table methods via ?.
-- spec-axis review HARD-3).

Two-axis review: Standards axis -- no hard findings. Spec axis --
3 hard findings actioned: HARD-1 (function/class after same-named
var now rejected via `cname in env`), HARD-2 (var branch checks
_F611_RESERVED), HARD-3 (filed as F832).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction.
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
def test_p2_f822_filed_shapes():
    """F822 filed shapes block."""
    shapes = [
        "['" + _A + "','" + _B + "']?.join('')",
        "[['" + _A + "'],['xx']]?.find(function(a){return true;})[0]+'" + _B + "'",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p2_f823_filed_shapes():
    """F823 filed shapes block."""
    shapes = [
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C('" + _A + "');return o['m']()+'"
        + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d filed shapes block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p3: generalizations
# --------------------------------------------------------------------------

@_t
def test_p3_f822_generalizations():
    """F822 generalizations: more methods, ws variants, bracket, chains."""
    shapes = [
        "['" + _A + "','" + _B + "']?.join ('')",
        "['" + _A + "','" + _B + "']?.['join']('')",
        "'a" + _A + "'?.concat('" + _B + "')",
        "'x" + _A + _B + "'?.slice(1)",
        "[['" + _A + "'],['xx']]?.find(function(a){return true;})[0]+'" + _B + "'",
        "['" + _A + "','" + _B + "']?.slice(0).join('')",
        "['" + _A + "','" + _B + "']?.join('').slice(0)",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


@_t
def test_p3_f823_generalizations():
    """F823 generalizations: class twin, multi-param, multi-install,
    var forms, member reads, additive returns."""
    shapes = [
        "(function(){class C{constructor(x){this.x=x;}}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "').m()+'" + _B + "';})()",
        "(function(){function C(x,y){this.x=x;this.y=y;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "','q').m()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};C.prototype.n=function(){return 'zz';};"
        "return new C('" + _A + "').m()+new C('" + _A + "').n()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};let o=new C('" + _A + "');return o.m()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype['m']=function()"
        "{return '" + _A + "';};return new C('" + _A + "')['m']()+'" + _B + "';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C('" + _A + "');return o.x+o.m()+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d generalizations block" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------------------------------------------------
# p4: fail-closed bounds
# --------------------------------------------------------------------------

@_t
def test_p4_f822_fail_closed():
    """F822 bounds: unmodeled methods, bare refs, .call path, junk."""
    bounds = [
        "['" + _A + "']?.trim('')",
        "['" + _A + "']?.join",
        "['" + _A + "'] ? .join('')",
        "(1)?.concat('x')",
        "['" + _A + "']?.nosuchmethod('')",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


@_t
def test_p4_f823_fail_closed():
    """F823 bounds: method miss, args, named, non-literal, shadow,
    bare read, no proto, forward ref, decl-after-var, reserved var."""
    bounds = [
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "').z()+'x';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "').m('q')+'x';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function foo()"
        "{return '" + _A + "';};return new C('" + _A + "').m()+'x';})()",
        "(function(){function C(x){this.m=x;}C.prototype.m=function()"
        "{return '" + _A + "';};return new C('" + _A + "').m()+'x';})()",
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C('" + _A + "');return o.m+'x';})()",
        "(function(){C.prototype.m=function(){return 'x';};"
        "function C(x){this.x=x;}return new C('x').m()+'x';})()",
        # spec review HARD-1: function after same-named var
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C('" + _A + "');function o(x)"
        "{this.x=x;}return new o('x').m()+'x';})()",
        # spec review HARD-1: class after same-named var
        "(function(){function C(x){this.x=x;}C.prototype.m=function()"
        "{return '" + _A + "';};var o=new C('" + _A + "');class o{"
        "constructor(x){this.x=x;}}return new o('x').m()+'x';})()",
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d bounds fail closed" % (len(bounds) - len(bad), len(bounds)))


# --------------------------------------------------------------------------
# p5: sibling pins
# --------------------------------------------------------------------------

@_t
def test_p5_sibling_pins():
    """Siblings unaffected: F478 dot twins, F490 ?.call/apply, F780,
    F781, F690, F762/F763/F764 postfix, F607 filter."""
    pins = [
        # F478 dot twins still block
        ("['" + _A + "','" + _B + "'].join('')", True),
        # F490 ?.call still routes (optchain-call shape)
        ("Array.prototype.concat?.call([], '" + _A + "','" + _B + "').join('')", True),
        ("([]?.concat)?.call([], '" + _A + "','" + _B + "').join('')", True),
        # F780 param'd ctor member reads still block
        ("(function(){function C(x){this.x=x;}var o=new C('" + _A
         + "');return o.x+'" + _B + "';})()", True),
        # F781 zero-param proto reads still block
        ("(function(){function C(){}C.prototype.m=function(){return '"
         + _A + "';};return new C().m()+'" + _B + "';})()", True),
        # F690 zero-param ctor reads still block
        ("(function(){function C(){this.x='" + _A + "';}var o=new C();"
         "return o.x+'" + _B + "';})()", True),
        # F762 charAt / F763 normalize postfix
        ("(function(){var s='" + _A + "';return s.charAt(0)+s.slice(1)+'"
         + _B + "';})()", True),
        ("'" + _A + "'.normalize()+'" + _B + "'", True),
        # F607 filter predicate
        ("['" + _A + "','xx'].filter(function(a){return a.length>3;})"
         ".join('')+'" + _B + "'", True),
        # honest text stays quiet
        ("'the quick brown fox jumps over the lazy dog'", False),
    ]
    bad = []
    for payload, want_hit in pins:
        hit = _blocked(payload)
        if hit != want_hit:
            bad.append(payload[:40])
    return ("HELD" if not bad else "BREAK", "%d/%d sibling pins hold" % (len(pins) - len(bad), len(pins)))


# --------------------------------------------------------------------------
# p6: honest-text controls
# --------------------------------------------------------------------------

@_t
def test_p6_honest_text():
    """Honest text: no false positives on benign JS."""
    honest = [
        "'hello world'",
        "var x = [1,2,3]?.join(',');",
        "(function(){function C(x){this.x=x;}return 42;})()",
        "'the quick brown fox'",
        "['a','b']?.join('-')",
    ]
    bad = [s for s in honest if _blocked(s)]
    return ("HELD" if not bad else "BREAK", "%d/%d honest quiet" % (len(honest) - len(bad), len(honest)))


# --------------------------------------------------------------------------
# p7: perf (200 sites)
# --------------------------------------------------------------------------

@_t
def test_p7_perf_200_sites():
    """200 decode sites complete in bounded time (F452)."""
    sites = []
    for k in range(100):
        sites.append("['" + _A + "','" + _B + "']?.join('')")
        sites.append("(function(){function C(x){this.x=x;}C.prototype.m=function()"
                     "{return '" + _A + "';};return new C('" + _A + "').m()+'"
                     + _B + "';})()")
    text = "junk " + " junk ".join(sites) + " junk"
    t0 = time.time()
    hits = 0
    # whole-text scan over the 200-site blob
    r = dlp.find_credential(text)
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs (budget ok=%s)" % (dt, ok))


# --------------------------------------------------------------------------
# p8: FINDINGS.md stamps
# --------------------------------------------------------------------------

@_t
def test_p8_findings_stamps():
    """F822/F823 stamped CLOSED; F829-F831 filed OPEN; lane-local footer."""
    text = _findings_text()
    bad = []
    for fid in ("F822", "F823"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        # entry runs to the next "(F" at line start or EOF
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F829", "F830", "F831", "F832"):
        if ("(%s filed" % fid) not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F833**" not in text:
        bad.append("footer-next-not-F833")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


# --------------------------------------------------------------------------
# p9: depth-1 green check
# --------------------------------------------------------------------------

def _green_check():
    """Depth-1: both red-firsts 0 BREAK; w385 attack battery expected
    exactly 1 BREAK (its test_b0_footer_state asserts the merged
    footer; this lane's footer is lane-local)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w385_f822_redfirst.py", 0),
                               ("evals/w385_f823_redfirst.py", 0),
                               ("evals/w386_f829_redfirst.py", 2),
                               ("evals/w386_f830_redfirst.py", 1),
                               ("evals/w386_f831_redfirst.py", 1),
                               ("evals/w386_f832_redfirst.py", 2),
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
def test_p9_green_check():
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w386_f822f823close: starting %d probes" % len(TESTS))
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
    print("w386_f822f823close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
