#!/usr/bin/env python3
"""Wave-383 lane 3: close F717 + F718.

F717 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
Reflect.defineProperty fragment writes bypass the bounded static
JS-expression decoder -- the decoder has no Reflect.defineProperty
production: the fragment is installed as a data-descriptor value
and a later direct member read recovers it while the decoder
produces zero variants. Distinct from F698 (Object.defineProperty
accessor residual, filed round 48).
Shapes: (function(){var o={};Reflect.defineProperty(o,'x',
{value:'f1'});return o.x+'f2';})() /
(function(){var o={};Reflect.defineProperty(o,'y',
{value:'f1',enumerable:true});return o['y']+'f2';})().

F718 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
Reflect.has conditional reads bypass the decoder -- the decoder
has no Reflect.has production: the membership test selects the
fragment branch of a ternary while the decoder produces zero
variants. Vehicle: the general ternary is unmodeled (same vehicle
as F687/F710); the novel contribution is the unmodeled
Reflect.has API.
Shapes: (function(){var o={x:1};var f=Reflect.has(o,'x')?
'f1':'xx';return f+'f2';})() /
(function(){var f=Reflect.has({a:1},'a')?'f1':'xx';
return f+'f2';})().

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f717_reflect_defineproperty_iife: the statement-IIFE
  body grammar is `var|let|const o={};` then 1+
  `Reflect.defineProperty(o,'KEY',DESC);` installs (dot form
  only; target must be the bound ident; KEY a plain string
  literal; `__proto__`/re-install fail closed; DESC via the
  shared _js_parse_f548f550_descriptor -- data descriptors
  install the plain-string value, get-accessors install a
  _JSAccessor (F698 parity), set-only fails closed), then
  `return (LIT|o.MEM|o['KEY'])(+...)*;` with direct member reads
  resolved against the installed map (uninstalled keys fail
  closed -- the engine yields undefined). Hooked after F691/F698
  in _js_parse_primary; disjoint by the Reflect statement head.
- _js_parse_f718_reflect_has_cond/_js_parse_f718_ternary/
  _js_parse_f718_reflect_has_iife: COND = `[!]Reflect.has(OBJ,
  'KEY')` (OBJ a bound ident or inline F535 literal, KEY a plain
  string literal); the condition decodes only when KEY is
  provably present as an own prop (absent keys fail closed --
  the prototype chain is unmodeled, documented residual).
  The ternary selects the plain-string-literal branch;
  the IIFE binds plain object literals and optional ternary
  results, returning the bound ternary or a parenthesized
  ternary plus a plain-string tail. Hooked after F710;
  disjoint by decl grammar (plain object vs new Set).

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

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

import gov.dlp as dlp  # noqa: E402
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


# ------------------------------------------------------- p0: pin control

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s len=%s" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F717/F718 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- p1: filed shapes

@_t
def test_p1_f717_s1():
    """F717 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f717-s1=%s" % ok)


@_t
def test_p1_f717_s2():
    """F717 filed shape 2 (enumerable flag, bracket read) blocks."""
    ok = _blocked(
        "(function(){var o={};Reflect.defineProperty(o,'y',{value:'%s',enumerable:true});return o['y']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f717-s2=%s" % ok)


@_t
def test_p1_f718_s1():
    """F718 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f718-s1=%s" % ok)


@_t
def test_p1_f718_s2():
    """F718 filed shape 2 (inline literal) blocks."""
    ok = _blocked(
        "(function(){var f=Reflect.has({a:1},'a')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f718-s2=%s" % ok)


# ------------------------------------------------------- p2: generalizations

@_t
def test_p2_multi_install():
    """F717: multiple installs accumulate node-exactly."""
    ok = _blocked(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});Reflect.defineProperty(o,'y',{value:'%s'});return o.x+o.y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "multi=%s" % ok)


@_t
def test_p2_accessor_install():
    """F717: get-accessor install reads node-exactly (F698 parity)."""
    ok = _blocked(
        "(function(){var o={};Reflect.defineProperty(o,'x',{get:function(){return '%s';}});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "accessor=%s" % ok)


@_t
def test_p2_const_let():
    """F717/F718: const/let decls work."""
    ok = (_blocked(
        "(function(){const o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
        and _blocked(
        "(function(){let o={x:1};let f=Reflect.has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "constlet=%s" % ok)


@_t
def test_p2_paren_ternary():
    """F718: parenthesized inline ternary decodes."""
    ok = _blocked(
        "(function(){var o={x:1};return (Reflect.has(o,'x')?'%s':'xx')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "paren=%s" % ok)


@_t
def test_p2_negated():
    """F718: negated provably-false condition selects the else branch."""
    # !has on a present key is provably false -> else branch 'B'.
    got = dlp._try_js_expr_decode(
        "(function(){var o={x:1};var f=!Reflect.has(o,'x')?'%s':'%s';return f;})()" % (_A, _B), 0)
    ok = got is not None and got[0] == _B
    return ("HELD" if ok else "BREAK", "neg=%s" % ok)


@_t
def test_p2_whitespace():
    """F717/F718: free whitespace tolerated."""
    ok = (_blocked(
        "(function(){ var o = {}; Reflect.defineProperty( o , 'x' , { value : '%s' } ); return o.x + '%s'; })()" % (_A, _B))
        and _blocked(
        "(function(){ var o = { x : 1 }; var f = Reflect.has( o , 'x' ) ? '%s' : 'xx'; return f + '%s'; })()" % (_A, _B)))
    return ("HELD" if ok else "BREAK", "ws=%s" % ok)


# ------------------------------------------------------- p3: bounds (fail closed)

@_t
def test_p3_f717_proto_key():
    """F717: __proto__ install fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'__proto__',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proto=%s" % ok)


@_t
def test_p3_f717_reinstall():
    """F717: re-install fails closed (engine keeps first value)."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});Reflect.defineProperty(o,'x',{value:'%s'});return o.x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "reinstall=%s" % ok)


@_t
def test_p3_f717_set_only():
    """F717: set-only descriptor reads undefined -> fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{set:function(v){}});return o.x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "setonly=%s" % ok)


@_t
def test_p3_f717_wrong_target():
    """F717: install on a non-bound ident fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(p,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "target=%s" % ok)


@_t
def test_p3_f717_nonliteral_key():
    """F717: non-literal key fails closed."""
    ok = _misses(
        "(function(){var o={};var k='x';Reflect.defineProperty(o,k,{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f717_bracket_head():
    """F717: Reflect['defineProperty'] fails closed (dot form only)."""
    ok = _misses(
        "(function(){var o={};Reflect['defineProperty'](o,'x',{value:'%s'});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p3_f717_value_get_clash():
    """F717: {value, get} together throws in the engine -> fails closed."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s',get:function(){return 'g';}});return o.x;})()" % _A)
    return ("HELD" if ok else "BREAK", "clash=%s" % ok)


@_t
def test_p3_f717_uninstalled_read():
    """F717: read of an uninstalled key fails closed (engine: undefined)."""
    ok = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'%s'});return o.z+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "uninstalled=%s" % ok)


@_t
def test_p3_f717_nonempty_target():
    """F717: non-empty install target fails closed (documented residual)."""
    ok = _misses(
        "(function(){var o={x:1};Reflect.defineProperty(o,'y',{value:'%s'});return o.y;})()" % _A)
    return ("HELD" if ok else "BREAK", "nonempty=%s" % ok)


@_t
def test_p3_f718_absent_key():
    """F718: absent key fails closed (prototype chain unmodeled)."""
    ok = _misses(
        "(function(){var o={x:1};var f=Reflect.has(o,'y')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "absent=%s" % ok)


@_t
def test_p3_f718_proto_member():
    """F718: inherited member (toString) fails closed -- not provably own."""
    ok = _misses(
        "(function(){var o={x:1};var f=Reflect.has(o,'toString')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "proto=%s" % ok)


@_t
def test_p3_f718_bracket_head():
    """F718: Reflect['has'] fails closed (dot form only)."""
    ok = _misses(
        "(function(){var o={x:1};var f=Reflect['has'](o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p3_f718_nonliteral_key():
    """F718: non-literal key fails closed."""
    ok = _misses(
        "(function(){var o={x:1};var k='x';var f=Reflect.has(o,k)?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f718_unbound_obj():
    """F718: has() on an unbound ident fails closed."""
    ok = _misses(
        "(function(){var o={x:1};var f=Reflect.has(p,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "unbound=%s" % ok)


@_t
def test_p3_f718_nonstring_branch():
    """F718: non-string branch fails closed."""
    ok = _misses(
        "(function(){var o={x:1};var f=Reflect.has(o,'x')?'%s':1;return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "branch=%s" % ok)


@_t
def test_p3_f718_bare_has():
    """F718: bare has() (not Reflect.has) fails closed."""
    ok = _misses(
        "(function(){var o={x:1};var f=has(o,'x')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bare=%s" % ok)


# ------------------------------------------------------- p4: siblings + neighbors

@_t
def test_p4_sibling_f698():
    """F698 (Object.defineProperty) still blocks."""
    ok = _blocked(
        "(function(){var o={};Object.defineProperty(o,'x',{value:'%s'});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f698=%s" % ok)


@_t
def test_p4_sibling_f710():
    """F710 (Set.has ternary) still blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['k']);var f=s.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f710=%s" % ok)


@_t
def test_p4_sibling_f705():
    """F705 (Reflect.get) still blocks."""
    ok = _blocked(
        "(function(){var o={x:'%s'};return Reflect.get(o,'x')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f705=%s" % ok)


@_t
def test_p4_sibling_f691():
    """F691 (defineProperty data .value) still blocks."""
    ok = _blocked(
        "(function(){var o={};Object.defineProperty(o,'x',{value:'%s'});return Object.getOwnPropertyDescriptor(o,'x').value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f691=%s" % ok)


@_t
def test_p4_neighbor_f716_open():
    """F716 (Reflect.set) now BLOCKS (closed wave-383 merge)."""
    ok = not _misses(
        "(function(){var o={};var k='x';Reflect.set(o,k,'%s');return o[k]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f716-closed=%s" % ok)


@_t
def test_p4_neighbor_f719_open():
    """F719 (for-of over Set) now BLOCKS (closed wave-383 merge)."""
    ok = not _misses(
        "(function(){var r='';var s=new Set(['%s','%s']);for(var x of s){r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f719-closed=%s" % ok)


@_t
def test_p4_neighbor_f713_open():
    """F713 (setPrototypeOf-trap) now BLOCKS (closed wave-383 merge)."""
    ok = not _misses(
        "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tr,pr){tr.x='%s';return true;}});Object.setPrototypeOf(p,{});return t.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f713-closed=%s" % ok)


# ------------------------------------------------------- p5/p6: quiet + honest

@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\';return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p6_honest_reflect_unaffected():
    """Honest Reflect text without credential fragments stays quiet."""
    quiet = _misses(
        "(function(){var o={};Reflect.defineProperty(o,'x',{value:'plain'});return o.x;})()")
    return ("HELD" if quiet else "BREAK", "honest=%s" % quiet)


# ------------------------------------------------------- p8: perf

@_t
def test_p8_perf():
    """200 mixed sites decode in reasonable time (F452 charging intact)."""
    sites = []
    for k in range(50):
        sites.append(
            "(function(){var o={};Reflect.defineProperty(o,'x%d',{value:'v'});return o.x%d;})()" % (k, k))
        sites.append(
            "(function(){var o={a:1};var f=Reflect.has(o,'a')?'y':'n';return f;})()")
        sites.append("['a','b'].join('')")
        sites.append("(function(){var s='ab';return s;})()")
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- p9: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs). The attack battery's footer pin
    # still asserts the base footer (merge-owned tree-wide repoint),
    # so 0 BREAKs (footer repointed at merge).
    for batt, expect_break in (("evals/w382_f717_redfirst.py", 0),
                               ("evals/w382_f718_redfirst.py", 0),
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
def test_p9_green_check():
    """Depth-1 green check: F717/F718 red-firsts + wave-382 attack battery green."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in _tests:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %r" % (fn.__name__, e)
        print("%s: %s (%s)" % (fn.__name__, verdict, detail))
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
