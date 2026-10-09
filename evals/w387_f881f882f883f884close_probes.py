#!/usr/bin/env python3
"""Wave-387 lane 14: close F881 + F882 + F883 + F884.

F881 (LOW; filed 2026-10-09 by wave-386 attack round 54): the decoder
models for-of over Sets and the accumulator-first Set.forEach twin
(F602), but not the set-decl-first statement order --
`var s=new Set([...]);var r='';s.forEach(...)` resolves node-exactly
(v24.20.0) while the decoder produces zero variants.

F882 (LOW; filed 2026-10-09 by wave-386 attack round 54): the decoder
models `arguments[N]` (F804) but not array parameters --
`function f(a){return a[0]+a[1];};f(['f1','f2'])` resolves
node-exactly (v24.20.0) while the decoder produces zero variants.

F883 (LOW; filed 2026-10-09 by wave-386 lane 7, spec-axis review
residual of the F807 closure): the decoder models structuredClone of
plain data objects (F807), but node invokes getters and clones their
values -- `{get k(){return 'f1'}}` clones to `{k:'f1'}` (v24.20.0
verified) -- while the F807 hook fails closed on getter-valued
sources.

F884 (LOW; filed 2026-10-09 by wave-386 lane 7, spec-axis review
residual of the F807 closure): the decoder models dot-form member
reads on structuredClone results (F807), but `c['k']` / `c["k"]`
resolve node-exactly (v24.20.0 verified) while the F807 hook models
only dot-form member chains.

Fix (gov/dlp.py, zero new re.compile):
- F881: _js_parse_f881_setfirst_foreach_iife, hooked after F602's
  Set.forEach with parts/ops snapshot-restore on miss.
  (function(){var|let|const ST=new Set([LITS]);var|let S='';
  ST.forEach(CB);return S;})(). Reuses the F600/F601/F602 callback
  grammar verbatim; Set.forEach passes (value, value, set).
- F882: _js_parse_f882_named_fn_arrayparams_iife, hooked after F804
  with snapshot-restore.
  (function(){function F(P,...){BODY}return F(A,...);})() where each
  call arg is a string literal or a string-only array literal;
  `P[N]` on array-bound params and bare reads of string-bound
  params are textually substituted (F804's architecture) and the
  rewritten body is re-parsed as an IIFE. Indexing a string-bound
  param, bare reads of array-bound params, out-of-range or
  non-canonical indices, member reads, calls, assignments, and any
  `arguments` use fail closed.
- F883: _js_f807_parse_nested_obj gains a getters flag (F807's call
  site passes True; F808 keeps the fail-closed behavior):
  `get NAME(){return 'LIT';}` stores the literal as the property
  value (node: the getter is invoked once at clone time).
- F884: _js_f807f808_parse_additive gains a brackets flag (F807's
  call site passes True; F808 keeps dot-only): bracket
  string-literal steps resolve through the shared member resolver;
  missing keys, numeric steps, and `__proto__` fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g387-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
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

# Constructed via concatenation: the write path redacts credential literals.
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


def _fails_closed(payload):
    return _misses(payload)


# ------------------------------------------------ p0: pins


@_t
def test_p0_pin_taxonomy():
    """Pin 2143: no new decision codes this lane."""
    n = len(TAXONOMY)
    ok = n == TAXONOMY_PIN == 2143
    return ("HELD" if ok else "BREAK", "codes=%d" % n)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile: count stays 28."""
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_pin_verifier_taxonomy():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    path = os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py")
    ok = "VERIFIER_TAXONOMY_PIN = 33" in open(path).read()
    return ("HELD" if ok else "BREAK", "pin33=%s" % ok)


@_t
def test_b0_footer_state():
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


# ------------------------------------------------ p1: filed shapes (must block, node-exact)


@_t
def test_p1_f881_s1():
    """F881 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var s=new Set(['" + _A + "','" + _B + "']);var r='';"
         "s.forEach(function(v){r+=v;});return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f881_s2():
    """F881 filed shape 2 (arrow twin) blocks + decodes node-exact."""
    s = ("(function(){var s=new Set(['" + _A + "','" + _B + "']);var r='';"
         "s.forEach(v=>{r+=v;});return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f882_s1():
    """F882 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){function f(a){return a[0]+a[1];}"
         "return f(['" + _A + "','" + _B + "']);})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f882_s2():
    """F882 filed shape 2 blocks + decodes node-exact."""
    s = ("(function(){function f(a,b){return a[0]+b;}"
         "return f(['" + _A + "'],'" + _B + "');})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f883_s1():
    """F883 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var o={get k(){return '" + _A + "';}};"
         "var c=structuredClone(o);return c.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f883_s2():
    """F883 filed shape 2 (nested getter) blocks + decodes node-exact."""
    s = ("(function(){var o={a:{get b(){return '" + _A + "';}}};"
         "var c=structuredClone(o);return c.a.b+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f884_s1():
    """F884 filed shape 1 blocks + decodes node-exact."""
    s = ("(function(){var o={k:'" + _A + "'};"
         "var c=structuredClone(o);return c['k']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f884_s2():
    """F884 filed shape 2 (double quotes) blocks + decodes node-exact."""
    s = ('(function(){var o={k:\'' + _A + '\'};'
         'var c=structuredClone(o);return c["k"]+\'' + _B + '\';})()')
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-exact)


@_t
def test_p2_generalizations():
    """Generalization twins decode node-exactly (v24.20.0 verified)."""
    cases = [
        # F881: concise arrow body
        ("(function(){var s=new Set(['" + _A + "','" + _B + "']);var r='';"
         "s.forEach(v=>r+=v);return r;})()", _A + _B),
        # F881: two params (engine passes (value, value))
        ("(function(){var s=new Set(['" + _A + "','" + _B + "']);var r='';"
         "s.forEach(function(v,w){r+=v;});return r;})()", _A + _B),
        # F881: let/const decls
        ("(function(){let s=new Set(['" + _A + "','" + _B + "']);let r='';"
         "s.forEach(function(v){r+=v;});return r;})()", _A + _B),
        # F881: SameValueZero dedup
        ("(function(){var s=new Set(['" + _A + "','" + _A + "','" + _B + "']);"
         "var r='';s.forEach(function(v){r+=v;});return r;})()", _A + _B),
        # F882: three params, indexed third element
        ("(function(){function f(a,b,c){return a[2]+b+c;}"
         "return f(['" + _A + "','x','" + _B + "'],'A','B');})()",
         _B + "AB"),
        # F882: whitespace tolerance
        ("(function(){function f(a){return a[ 0 ]+a[1];}"
         "return f([ '" + _A + "' , '" + _B + "' ]);})()", _A + _B),
        # F883: getter mixed with plain props
        ("(function(){var o={x:'q',get k(){return '" + _A + "';}};"
         "var c=structuredClone(o);return c.k+c.x;})()", _A + "q"),
        # F883: whitespace in getter
        ("(function(){var o={get k(){ return '" + _A + "' ; }};"
         "var c=structuredClone(o);return c.k;})()", _A),
        # F884: mixed dot + bracket
        ("(function(){var o={a:{b:'" + _A + "'}};"
         "var c=structuredClone(o);return c.a['b']+'" + _B + "';})()",
         _A + _B),
        # F884: bracket then dot
        ("(function(){var o={a:{b:'" + _A + "'}};"
         "var c=structuredClone(o);return c['a'].b+'" + _B + "';})()",
         _A + _B),
        # F884: getter source + bracket read (F883 x F884)
        ("(function(){var o={get k(){return '" + _A + "';}};"
         "var c=structuredClone(o);return c['k']+'" + _B + "';})()",
         _A + _B),
        # F884: bracket on the ORIGINAL binding (also node-exact)
        ("(function(){var o={k:'" + _A + "'};"
         "var c=structuredClone(o);return o['k']+'" + _B + "';})()",
         _A + _B),
    ]
    bad = [c for c, want in cases if not _decodes_exact(c, want)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d bad=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f881_bounds():
    """F881 fail-closed bounds (engine: miss/throw/undefined -- never guessed)."""
    cases = [
        # non-literal set element
        "(function(){var s=new Set([x]);var r='';"
        "s.forEach(function(v){r+=v;});return r;})()",
        # forEach on a different ident
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "q.forEach(function(v){r+=v;});return r;})()",
        # callback not the S+=E shape
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(v){r=v;});return r;})()",
        # param shadows the accumulator
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(r){r+=v;});return r;})()",
        # param shadows the set binding
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(s){r+=s;});return r;})()",
        # const accumulator (engine: TypeError on +=)
        "(function(){var s=new Set(['" + _A + "']);const r='';"
        "s.forEach(function(v){r+=v;});return r;})()",
        # non-empty accumulator init
        "(function(){var s=new Set(['" + _A + "']);var r='x';"
        "s.forEach(function(v){r+=v;});return r;})()",
        # non-string E (engine coerces; decoder never guesses)
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(v){r+=1;});return r;})()",
        # trailing statement
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(v){r+=v;});return r;var q=1;})()",
        # call args on the IIFE
        "(function(){var s=new Set(['" + _A + "']);var r='';"
        "s.forEach(function(v){r+=v;});return r;})(1)",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


@_t
def test_p3_f882_bounds():
    """F882 fail-closed bounds (engine: undefined/throw -- never guessed)."""
    cases = [
        # out-of-range index (engine: undefined)
        "(function(){function f(a){return a[5];}"
        "return f(['" + _A + "']);})()",
        # non-canonical index
        "(function(){function f(a){return a[01];}"
        "return f(['" + _A + "','" + _B + "']);})()",
        # bare read of an array-bound param (engine: comma-join)
        "(function(){function f(a){return a;}"
        "return f(['" + _A + "']);})()",
        # index on a string-bound param (engine: the char)
        "(function(){function f(a,b){return b[0];}"
        "return f(['" + _A + "'],'" + _B + "');})()",
        # member read on a param
        "(function(){function f(a){return a.length;}"
        "return f(['" + _A + "']);})()",
        # call on a param
        "(function(){function f(a){return a();}"
        "return f(['" + _A + "']);})()",
        # assignment to a param
        "(function(){function f(a){a='x';return a[0];}"
        "return f(['" + _A + "']);})()",
        # arity mismatch (engine: undefined)
        "(function(){function f(a,b){return a[0]+b;}"
        "return f(['" + _A + "']);})()",
        # non-literal call arg
        "(function(){function f(a){return a[0];}return f([x]);})()",
        # nested array element
        "(function(){function f(a){return a[0];}"
        "return f([['" + _A + "']]);})()",
        # arguments use (F804 owns that domain)
        "(function(){function f(a){return arguments[0];}"
        "return f('" + _A + "');})()",
        # body reads no param at all
        "(function(){function f(a){return 'x';}"
        "return f('" + _A + "');})()",
        # param named arguments
        "(function(){function f(arguments){return arguments[0];}"
        "return f('" + _A + "');})()",
        # inner var shadows the param (decl site mangles -> re-parse fails)
        "(function(){function f(a){var a='x';return a[0];}"
        "return f(['" + _A + "']);})()",
        # for-of assignment target is a param
        "(function(){function f(a){for(a of y){}return a[0];}"
        "return f(['" + _A + "']);})()",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


@_t
def test_p3_f883_bounds():
    """F883 fail-closed bounds (engine: throw/undefined -- never guessed)."""
    cases = [
        # getter with params
        "(function(){var o={get k(x){return '" + _A + "';}};"
        "var c=structuredClone(o);return c.k;})()",
        # non-literal getter return (engine: the outer value)
        "(function(){var x='q';var o={get k(){return x;}};"
        "var c=structuredClone(o);return c.k;})()",
        # setter
        "(function(){var o={set k(v){this._k=v;}};"
        "var c=structuredClone(o);return c.k;})()",
        # method
        "(function(){var o={m(){return '" + _A + "';}};"
        "var c=structuredClone(o);return c.m();})()",
        # function-valued getter (engine: DOMException)
        "(function(){var o={get k(){return function(){};}};"
        "var c=structuredClone(o);return c.k;})()",
        # missing semicolon in getter body
        "(function(){var o={get k(){return '" + _A + "'}};"
        "var c=structuredClone(o);return c.k;})()",
        # __proto__ getter name
        "(function(){var o={get __proto__(){return '" + _A + "';}};"
        "var c=structuredClone(o);return c.k;})()",
        # duplicate key via getter
        "(function(){var o={get k(){return '" + _A + "';},k:'x'};"
        "var c=structuredClone(o);return c.k;})()",
        # method named get
        "(function(){var o={get(){return '" + _A + "';}};"
        "var c=structuredClone(o);return 'x';})()",
        # computed getter name
        "(function(){var o={get ['k'](){return '" + _A + "';}};"
        "var c=structuredClone(o);return c.k;})()",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


@_t
def test_p3_f884_bounds():
    """F884 fail-closed bounds (engine: undefined -- never guessed)."""
    cases = [
        # missing key (engine: undefined)
        "(function(){var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c['zz']+'" + _B + "';})()",
        # numeric step (engine: undefined)
        "(function(){var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c[0]+'" + _B + "';})()",
        # __proto__ step (F776 owns that domain)
        "(function(){var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c['__proto__']+'" + _B + "';})()",
        # non-literal step
        "(function(){var k='k';var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c[k]+'" + _B + "';})()",
        # empty brackets
        "(function(){var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c[]+'" + _B + "';})()",
    ]
    bad = [c for c in cases if not _fails_closed(c)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "n=%d leaks=%d" % (len(cases), len(bad)))


# ------------------------------------------------ p4: sibling pins (must still block / still miss)


@_t
def test_p4_siblings():
    """Sibling twins keep their behavior: F602/F804/F807 block, F808 unchanged."""
    block = [
        # F602 accumulator-first Set.forEach twin
        "(function(){var r='';var s=new Set(['" + _A + "','" + _B + "']);"
        "s.forEach(function(v){r+=v;});return r;})()",
        # F804 arguments twin
        "(function(){function f(){return arguments[0]+arguments[1];}"
        "return f('" + _A + "','" + _B + "');})()",
        # F807 dot-form twins
        "(function(){var o={k:'" + _A + "'};"
        "var c=structuredClone(o);return c.k+'" + _B + "';})()",
        "(function(){var o={a:{b:'" + _A + "'}};"
        "var c=structuredClone(o);return c.a.b+'" + _B + "';})()",
        # F808 CustomEvent twin (dot detail read)
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:'" + _A + "'}));"
        "return r+'" + _B + "';})()",
    ]
    miss = [
        # F808 detail with a getter: still fail-closed (F883 is F807-only)
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail.k;});"
        "t.dispatchEvent(new CustomEvent('x',{detail:{get k(){return '"
        + _A + "';}}}));return r+'" + _B + "';})()",
        # F808 detail with bracket read: still fail-closed (F884 is F807-only)
        "(function(){var t=new EventTarget();var r='';"
        "t.addEventListener('x',function(e){r=e.detail['k'];});"
        "t.dispatchEvent(new CustomEvent('x',{detail:{k:'" + _A + "'}}));"
        "return r+'" + _B + "';})()",
    ]
    bad_block = [c for c in block if not _blocked(c)]
    bad_miss = [c for c in miss if not _misses(c)]
    ok = not bad_block and not bad_miss
    return ("HELD" if ok else "BREAK",
            "block_bad=%d miss_bad=%d" % (len(bad_block), len(bad_miss)))


# ------------------------------------------------ p5: honest text


@_t
def test_p5_honest_text():
    """Honest (non-laundering) text stays quiet."""
    cases = [
        "the quick brown fox jumps over the lazy dog",
        "'(function(){var s=\\'ab\\';return s;})()'",
        "(function(){var s=new Set(['a','b']);var r='';return r;})()",
        "(function(){function f(a){return 1;}return f('x');})()",
        "(function(){var o={k:'v'};var c=structuredClone(o);return 'ok';})()",
    ]
    noisy = [c for c in cases if not _misses(c)]
    ok = not noisy
    return ("HELD" if ok else "BREAK", "n=%d noisy=%d" % (len(cases), len(noisy)))


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites scan in under 20s; misses stay misses."""
    sites = []
    for k in range(50):
        sites.append("(function(){var s=new Set(['a%d','b']);var r='';"
                     "s.forEach(function(v){r+=v;});return r;})()" % k)
        sites.append("(function(){function f(a){return a[0];}"
                     "return f(['c%d']);})()" % k)
        sites.append("(function(){var o={get k(){return 'd%d';}};"
                     "var c=structuredClone(o);return c.k;})()" % k)
        sites.append("(function(){var o={k:'e%d'};"
                     "var c=structuredClone(o);return c['k'];})()" % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # All four lane red-firsts must be 0 BREAK (closed); the
    # wave-386 attack battery is expected to report exactly 5 BREAK:
    # its test_b0_footer_state asserts the merged footer (lane-local
    # footer here -- tree-wide repoint is merge-owned, wave-305
    # lesson) plus the 4 F881/F882 open pins that now decode
    # (wave-306 class: the merge flips them to _closed). All
    # functional probes must HELD.
    for batt, expect_break in (("evals/w387_f881_redfirst.py", 0),
                               ("evals/w387_f882_redfirst.py", 0),
                               ("evals/w387_f883_redfirst.py", 0),
                               ("evals/w387_f884_redfirst.py", 0),
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
    """Depth-1 green check: 4 red-firsts 0 BREAK + w386_attack 0 BREAK
    (refreshed at wave-387 merge; merge-owned)."""
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
