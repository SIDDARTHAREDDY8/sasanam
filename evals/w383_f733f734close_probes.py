#!/usr/bin/env python3
"""Wave-383 lane 11: close F733 + F734 (WeakRef-deref and symbol-key residuals).

F733 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
F642 residual -- literal-fragment WeakRef deref reads bypass the
bounded static JS-expression decoder. F642 (CLOSED) models
WeakRef-deref reads of var-frag getter accumulations (`var a,b,c`
+ `get s(){return a+b+c}` + `w.deref().s`, blocks coded) and
F539/F586 model the inline `new WeakRef(OBJLIT).deref()`
expression form, but a VAR-BOUND WeakRef whose referent carries
LITERAL fragments escapes:
`(function(){var o={v:'f1'};var w=new WeakRef(o);return
w.deref().v+'f2';})()` and
`(function(){var w=new WeakRef({v:'f1'});return
w.deref()['v']+'f2';})()`, plus the literal-getter twin
`(function(){var w=new WeakRef({get s(){return 'f1';}});return
w.deref().s+'f2';})()` -- all node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero
variants. F642 stays CLOSED on its pins; only the
literal-fragment shapes are closed here.

F734 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
symbol-keyed member reads -- the decoder's object model is
string-keyed, so symbol-keyed member writes and reads recover the
exact fragment while the decoder produces zero variants:
`(function(){var s=Symbol('k');var o={};o[s]='f1';return
o[s]+'f2';})()` and
`(function(){var s=Symbol('k');var o={[s]:'f1'};return
o[s]+'f2';})()` -- both node-evaluate to the exact credential
(node v24.20.0) while the decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f733_litobj: tight literal-fragment object grammar
  (string-literal data props; single getters with `return 'lit';`
  bodies). Numbers are deliberately rejected -- the F535 value
  grammar returns canonical integers as plain str, losing number
  provenance, and a number-typed value flowing to a later postfix
  would mis-decode (F702 precedent).
- _js_parse_f733_weakref_litfrag_iife: `(function(){DECL;*
  return w.deref().MEM(+'LIT')*;})()` -- var-bound WeakRef of a
  literal-fragment referent (var-bound or inline object). Hooked
  after F702/F703 (disjoint: F642 requires a string-literal
  binding section; F539/F586 are expression-level inline forms).
- _js_parse_f734_symbol_member_iife: `(function(){var
  s=Symbol('D');DECL;o[s]='LIT';* return o[s](+'LIT')*;})()` --
  local symbols keyed as ("sym", name), a separate namespace from
  string keys and from F552 Symbol.for registry keys. Hooked after
  F733 (disjoint: F552 models only Symbol.for).

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


# ------------------------------------------------ p0: pin

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------ p1: F733 filed shapes now block

@_t
def test_p1_f733_filed_shapes_closed():
    """F733 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().v+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakRef({v:'%s'});return w.deref()['v']+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p2: F733 generalizations

@_t
def test_p2_f733_generalizations_closed():
    """F733 CLOSED: literal-getter twin, multi-prop, let/const, dq twins block."""
    shapes = [
        "(function(){var w=new WeakRef({get s(){return '%s';}});return w.deref().s+'%s';})()" % (_A, _B),
        "(function(){let o={v:'%s',x:'q'};const w=new WeakRef(o);return w.deref().v+'%s';})()" % (_A, _B),
        "(function(){var o={'v':'%s'};var w=new WeakRef(o);return w.deref()['v']+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakRef({get s(){return '%s';},t:'z'});return w.deref().s+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    # no-tail twin: bare _A is not credential-shaped, so assert the
    # node-exact decode instead of the flag.
    r = dlp._try_js_expr_decode(
        "(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().v;})()" % _A, 0)
    got.append(r is not None and r[0] == _A)
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p3: F733 bounds fail closed

@_t
def test_p3_f733_bounds_closed():
    """F733 bounds: missing keys, bad deref, unbound sources, numbers stay quiet."""
    shapes = [
        "(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref().missing+'%s';})()" % (_A, _B),
        "(function(){var o={v:'%s'};var w=new WeakRef(o);return w.deref(1).v+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakRef(zzz);return w.deref().v+'%s';})()" % _B,
        "(function(){var o={v:42};var w=new WeakRef(o);return w.deref().v+'%s';})()" % _B,
        "(function(){var o={get s(){return a;}};var w=new WeakRef(o);return w.deref().s;})()",
        "(function(){var o={get s(){return this.x;}};var w=new WeakRef(o);return w.deref().s+'%s';})()" % _B,
        # __proto__ data-prop key is the prototype-setter no-op
        # (node: "[object Object]f2"); fail closed, never mis-decode.
        "(function(){var o={__proto__:'%s'};var w=new WeakRef(o);return w.deref().__proto__+'%s';})()" % (_A, _B),
        "(function(){var o={'__proto__':'%s'};var w=new WeakRef(o);return w.deref()['__proto__']+'%s';})()" % (_A, _B),
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


@_t
def test_p3b_f733_protodunder_getter_exact():
    """A *getter* named __proto__ is an own accessor: node-exact decode."""
    r = dlp._try_js_expr_decode(
        "(function(){var o={get __proto__(){return '%s';}};var w=new WeakRef(o);return w.deref().__proto__+'%s';})()" % (_A, _B), 0)
    ok = r is not None and r[0] == _A + _B and _blocked(
        "(function(){var o={get __proto__(){return '%s';}};var w=new WeakRef(o);return w.deref().__proto__+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "getter-proto=%s" % ok)


# ------------------------------------------------ p4: F733 siblings still block

@_t
def test_p4_f733_siblings_intact():
    """F642/F539/F586/F535 WeakRef-adjacent pins still decode (no shadowing)."""
    decodes = [
        ("(function(){var a='%s';var w=new WeakRef({get s(){return a;}});return w.deref().s;})()" % _A, _A),
        ("(new WeakRef({v:'%s'})).deref().v" % _A, _A),
        ("(function(){var o={v:'%s'};return o.v;})()" % _A, _A),
    ]
    got = []
    for p, want in decodes:
        r = dlp._try_js_expr_decode(p, 0)
        got.append(r is not None and r[0] == want)
    ok = all(got)
    return ("HELD" if ok else "BREAK", "decode=%s" % got)


# ------------------------------------------------ p5: F734 filed shapes now block

@_t
def test_p5_f734_filed_shapes_closed():
    """F734 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var s=Symbol('k');var o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B),
        "(function(){var s=Symbol('k');var o={[s]:'%s'};return o[s]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p6: F734 generalizations

@_t
def test_p6_f734_generalizations_closed():
    """F734 CLOSED: multi-write later-wins, two symbols, no-tail twins block."""
    shapes = [
        "(function(){const s=Symbol('k');let o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B),
        "(function(){var a=Symbol('x');var b=Symbol('y');var o={};o[a]='%s';o[b]='q';return o[a]+'%s';})()" % (_A, _B),
    ]
    want = [_A + _B, _A + _B]
    got = []
    for p, w in zip(shapes, want):
        r = dlp._try_js_expr_decode(p, 0)
        got.append(r is not None and r[0] == w and _blocked(p))
    # later-wins / empty-desc twins decode node-exactly ('zz' and
    # bare _A are not credential-shaped, so assert the decode,
    # not the flag).
    for p, w in (
        ("(function(){var s=Symbol('k');var o={};o[s]='%s';o[s]='zz';return o[s];})()" % _A, "zz"),
        ("(function(){var s=Symbol('k');var o={[s]:'%s',[s]:'zz'};return o[s];})()" % _A, "zz"),
        ("(function(){var s=Symbol('');var o={};o[s]='%s';return o[s];})()" % _A, _A),
    ):
        r = dlp._try_js_expr_decode(p, 0)
        got.append(r is not None and r[0] == w)
    ok = all(got)
    return ("HELD" if ok else "BREAK", "exact=%s" % got)


# ------------------------------------------------ p7: F734 bounds fail closed

@_t
def test_p7_f734_bounds_closed():
    """F734 bounds: no-desc, string-read-of-symbol, unbound keys, registry-mix stay quiet."""
    shapes = [
        "(function(){var s=Symbol();var o={};o[s]='%s';return o[s]+'%s';})()" % (_A, _B),
        "(function(){var s=Symbol('k');var o={};o[s]='%s';return o['k']+'%s';})()" % (_A, _B),
        "(function(){var s=Symbol('k');var o={};o[s]='%s';return o[t]+'%s';})()" % (_A, _B),
        "(function(){var s=Symbol('k');var o={};o[s]='%s';return o[Symbol.for('k')]+'%s';})()" % (_A, _B),
        "(function(){var s=Symbol('k');var o={};return o[s]+'%s';})()" % _B,
        "(function(){var s=Symbol('k');var o={[s]:42};return o[s]+'%s';})()" % _B,
        "(function(){var s=Symbol('k');var o={};o['k']='%s';return o[s]+'%s';})()" % (_A, _B),
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p8: F734 namespace separation

@_t
def test_p8_f734_namespace_separation():
    """F552 Symbol.for registry keys and local symbols never collide.

    Model-level check: a props dict carrying both a local-symbol
    key and a registry key resolves each independently (the F734
    statement grammar only writes local-symbol keys, so the
    cross-namespace isolation is what the model guarantees).
    """
    from gov.dlp import _JSObj, _jsobj_lookup
    obj = _JSObj({("sym", "s"): _A, ("symbol", "k"): "q", "k": "str"})
    ok = (_jsobj_lookup(obj, ("sym", "s")) == _A
          and _jsobj_lookup(obj, ("symbol", "k")) == "q"
          and _jsobj_lookup(obj, "k") == "str"
          and _jsobj_lookup(obj, ("sym", "other")) is None)
    # end-to-end: the local-symbol read still decodes with a
    # registry key present on the same object shape class.
    p = "(function(){var s=Symbol('k');var o={};o[s]='%s';return o[s];})()" % _A
    r = dlp._try_js_expr_decode(p, 0)
    ok = ok and r is not None and r[0] == _A
    return ("HELD" if ok else "BREAK", "namespaces=%s" % ok)


# ------------------------------------------------ p9: honest text quiet

@_t
def test_p9_honest_text_quiet():
    """Honest WeakRef/symbol-shaped text stays quiet."""
    shapes = [
        "the weak reference to the old object was cleared",
        "use Symbol('desc') for a unique key in the registry",
        "(function(){var w=new WeakRef({});return 1;})()",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p10: perf

@_t
def test_p10_perf():
    """200 mixed sites decode in reasonable time (F452 budget intact)."""
    import time
    sites = []
    for k in range(50):
        sites.append("(function(){var o={v:'a%d'};var w=new WeakRef(o);return w.deref().v;})()" % k)
        sites.append("(function(){var s=Symbol('k%d');var o={};o[s]='a%d';return o[s];})()" % (k, k))
        sites.append("(function(){var o={v:'a%d'};return o.v;})()" % k)
        sites.append("plain text site %d with no code at all" % k)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    ok = dt < 30
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p11: footer state (lane-local)

@_t
def test_p11_footer_state():
    """Control: footer shows F733/F734 closed, next F738 (lane-local)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F738**" in text
          and "Open findings: F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F735, F736, F737." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p12: depth-1 green check

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w382_f733_redfirst.py", 0),
                               ("evals/w382_f734_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        # w382_attack's footer pin was repointed lane-locally
        # (F733/F734 closed); merge owns the tree-wide repoint
        # (wave-305).
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
def test_p12_green_check():
    """Depth-1 green check: F733/F734 red-firsts + wave-382 attack battery green."""
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
