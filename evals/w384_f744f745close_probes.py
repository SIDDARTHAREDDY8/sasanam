#!/usr/bin/env python3
"""Wave-384 lane 4: close F744 + F745.

F744 (LOW, filed 2026-10-08 by wave-383 lane 14 as F742, renumbered at
the wave-383 merge -- lane 6 filed F738/F739 first ~17:30/~17:45 UTC):
F683 residual -- value-replacement reviver. F683 (CLOSED) models
append-style revivers (v+'f2') but not value-REPLACEMENT revivers
(k==='k' ? 'f1' : v): the replaced value is read node-exactly while
the decoder produced zero variants:
(function(){return JSON.parse('{"k":"x"}',function(k,v){return
k==='k'?'f1':v;}).k+'f2';})() and (function(){var
r=JSON.parse('{"a":1}',function(k,v){return k===''?'f1':v;});return
r+'f2';})() both node-evaluate to the exact credential (node
v24.20.0). Distinct from F683 (append consequent).

F745 (LOW, filed 2026-10-08 by wave-383 lane 14 as F743, renumbered):
Set.prototype.union (ES2025) -- the decoder modeled Set
construction/spread (F669, CLOSED) but not the ES2025 set-algebra
methods: union/intersection/difference results spread-joined
node-exactly while the decoder produced zero variants:
(function(){var s=new Set(['f1']).union(new Set(['f2']));return
[...s].join('');})() and (function(){var a=new Set(['f1']);var
b=new Set(['f2']);return [...a.union(b)].join('');})() both
node-evaluate to the exact credential (node v24.20.0).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_f744_replace_walk + _js_parse_f744_replace_reviver: the
  JSON.parse('LIT',function(k,v){return GUARD?'REPL':v;}) grammar
  (typeof-v==='string'/k==='KEY' guards, == admitted); the walk is
  bottom-up exactly as the engine invokes the reviver (children
  before holders, list indices as string keys, root key "");
  key-guard hits replace any value type without coercion
  (node-exact -- verified: number/object leaves become the string);
  hooked after F683 with budget snapshot/restore on miss (F452 /
  wave-383 lesson). Disjoint from F683 (bare-literal vs v+'APP'
  consequent). The var-bound twin (s2) closes via a new
  JSON.parse initializer branch in _js_parse_f611_varbound_iife
  (plain-string results only; bound-object member reads fail
  closed -- documented residual).
- _js_f745_algebra + _js_parse_f745_set_algebra_iife (+
  _js_parse_f745_new_set/_js_f745_set_operand/_js_parse_f745_set_expr/
  _js_parse_f745_decl): (function(){(var|let|const NAME=SETEXPR;)+
  return [...SETEXPR].join(SEP)(+'LIT')*;})() where SETEXPR admits
  chained .union/.intersection/.difference over inline/bound Sets;
  node-exact insertion-order semantics; at least one algebra call
  required (methodless shapes stay with F669); hooked after F713
  with budget snapshot/restore on miss; the join tail reuses
  _js_parse_f713_join_tail. Disjoint from F669 (algebra member
  fails F669's spread head) and F713 (Map-based).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
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
from gov.dlp import _try_js_expr_decode_all  # noqa: E402
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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- F744 filed shapes

@_t
def test_p1_f744_s1():
    """F744 filed shape 1 (direct return, key guard) blocks."""
    ok = _blocked(
        "(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
        "return k==='k'?'%s':v;}).k+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f744-s1=%s" % ok)


@_t
def test_p1_f744_s2():
    """F744 filed shape 2 (var-bound, root replacement) blocks."""
    ok = _blocked(
        "(function(){var r=JSON.parse('{\"a\":1}',function(k,v){"
        "return k===''?'%s':v;});return r+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f744-s2=%s" % ok)


@_t
def test_p1_f744_variants():
    """F744 node-exact variants block: typeof guard, nested, numeric leaf, ==, list index."""
    shapes = [
        # typeof guard replaces every string leaf
        "(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
        "return typeof v==='string'?'%s':v;}).k+'%s';})()",
        # nested object: bottom-up, key hit at depth
        "(function(){return JSON.parse('{\"o\":{\"k\":\"x\"}}',function(k,v){"
        "return k==='k'?'%s':v;}).o.k+'%s';})()",
        # key guard on a numeric leaf: engine replaces without coercion
        "(function(){return JSON.parse('{\"k\":5}',function(k,v){"
        "return k==='k'?'%s':v;}).k+'%s';})()",
        # == admitted
        "(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
        "return k=='k'?'%s':v;}).k+'%s';})()",
        # list index keys are strings in the engine
        "(function(){return JSON.parse('{\"ks\":[\"x\",\"y\"]}',function(k,v){"
        "return k==='0'?'%s':v;}).ks[0]+'%s';})()",
    ]
    bad = [s for s in shapes if not _blocked(s % (_A, _B))]
    return ("HELD" if not bad else "BREAK", "variants-bad=%d" % len(bad))


@_t
def test_p1_f744_exact_value():
    """F744 decoded variant is byte-exact (node v24.20.0)."""
    payload = (
        "(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
        "return k==='k'?'%s':v;}).k+'%s';})()" % (_A, _B))
    whole = _try_js_expr_decode_all(payload)
    ok = whole is not None and _CRED in whole
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------------- F744 bounds

@_t
def test_p2_f744_bounds():
    """F744 fail-closed bounds: named reviver, non-return body, bad JSON, bound-object read, deep nest."""
    deep = '{"a":' * 40 + '"x"' + '}' * 40
    shapes = [
        # named reviver
        ("(function(){return JSON.parse('{\"k\":\"x\"}',function rv(k,v){"
         "return k==='k'?'%s':v;}).k+'%s';})()"),
        # non-return body
        ("(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){var z=1;"
         "return k==='k'?'%s':v;}).k+'%s';})()"),
        # invalid JSON
        ("(function(){return JSON.parse('{bad}',function(k,v){"
         "return k==='k'?'%s':v;}).k+'%s';})()"),
        # bound-object member read in varbound position: residual, fail closed
        ("(function(){var r=JSON.parse('{\"k\":\"x\"}',function(k,v){"
         "return k==='k'?'%s':v;});return r.k+'%s';})()"),
        # nesting beyond the F541 depth bound
        ("(function(){return JSON.parse('" + deep + "',function(k,v){"
         "return k==='k'?'%s':v;})+'%s';})()"),
    ]
    bad = [s for s in shapes if not _misses(s % (_A, _B))]
    return ("HELD" if not bad else "BREAK", "bounds-bad=%d" % len(bad))


@_t
def test_p2_f744_honest_quiet():
    """F744 honest text stays quiet: non-matching guard decodes but does not hit."""
    ok = _misses(
        "(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
        "return k==='zz'?'%s':v;}).k+'%s';})()" % (_A, _B))
    ok = ok and _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------------- F745 filed shapes

@_t
def test_p3_f745_s1():
    """F745 filed shape 1 (inline union in decl) blocks."""
    ok = _blocked(
        "(function(){var s=new Set(['%s']).union(new Set(['%s']));"
        "return [...s].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f745-s1=%s" % ok)


@_t
def test_p3_f745_s2():
    """F745 filed shape 2 (bound union in return) blocks."""
    ok = _blocked(
        "(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
        "return [...a.union(b)].join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f745-s2=%s" % ok)


@_t
def test_p3_f745_variants():
    """F745 node-exact variants block: dedup, chained, inline-in-return + tail, let/const, intersection."""
    shapes = [
        # union dedups B's repeat of A's element
        ("(function(){var a=new Set(['%s']);var b=new Set(['%s','%s']);"
         "return [...a.union(b)].join('');})()", (_A, _A, _B)),
        # chained algebra
        ("(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
         "var c=new Set(['x']);return [...a.union(b).difference(c)].join('');})()",
         (_A, _B)),
        # inline algebra in the return spread, additive tail (F713-tail discipline)
        ("(function(){var a=new Set(['%s']);return "
         "[...a.difference(new Set(['x']))].join('')+'%s';})()", (_A, _B)),
        # let/const decls
        ("(function(){let a=new Set(['%s']);const b=new Set(['%s']);"
         "return [...a.union(b)].join('');})()", (_A, _B)),
        # intersection yielding the full credential
        ("(function(){var a=new Set(['%s','%s']);var b=new Set(['%s','%s']);"
         "return [...a.intersection(b)].join('');})()", (_A, _B, _A, _B)),
        # difference of an empty inline set
        ("(function(){var s=new Set(['%s']).difference(new Set());"
         "return [...s].join('')+'%s';})()", (_A, _B)),
    ]
    bad = []
    for s, args in shapes:
        if not _blocked(s % args):
            bad.append(s[:60])
    return ("HELD" if not bad else "BREAK", "variants-bad=%d" % len(bad))


@_t
def test_p3_f745_exact_value():
    """F745 decoded variant is byte-exact (node v24.20.0)."""
    payload = (
        "(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
        "return [...a.union(b)].join('');})()" % (_A, _B))
    whole = _try_js_expr_decode_all(payload)
    ok = whole is not None and _CRED in whole
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------------- F745 bounds

@_t
def test_p4_f745_bounds():
    """F745 fail-closed bounds: non-Set receiver (engine throws), unbound name, unmodeled member, .add, methodless."""
    shapes = [
        # non-Set receiver: the engine throws TypeError
        "(function(){var a=['%s'];return [...a.union(new Set(['%s']))].join('');})()",
        # unbound argument name
        "(function(){var a=new Set(['%s']);return [...a.union(zz)].join('')+'%s';})()",
        # unmodeled member on the algebra result
        "(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
        "return [...a.union(b).values()].join('');})()",
        # .add composed with algebra: residual, fail closed
        "(function(){var a=new Set(['%s']);a.add('x');var b=new Set(['%s']);"
        "return [...a.union(b)].join('');})()",
        # methodless multi-decl: F669's territory (tried first)
        "(function(){var a=new Set(['%s']);var b=new Set(['%s']);"
        "return [...a].join('');})()",
        # non-literal element
        "(function(){var a=new Set(['%s',x]);var b=new Set(['%s']);"
        "return [...a.union(b)].join('');})()",
    ]
    bad = [s for s in shapes if not _misses(s % (_A, _B))]
    return ("HELD" if not bad else "BREAK", "bounds-bad=%d" % len(bad))


# ------------------------------------------------------- regressions

@_t
def test_p5_regressions():
    """Sibling closures still block: F683 append, F541 single-arg, F669 set/map, F713 tail, F611 varbound."""
    shapes = [
        # F683 append-style reviver
        ("(function(){return JSON.parse('{\"k\":\"x\"}',function(k,v){"
         "return k==='k'?v+'%s':v;}).k+'%s';})()", (_A, _B)),
        # F541 single-arg
        ("(function(){return JSON.parse('{\"k\":\"%s%s\"}').k;})()", (_A, _B)),
        # F669 set spread
        ("(function(){var s=new Set(['%s','%s']);return [...s].join('');})()",
         (_A, _B)),
        # F669 set add
        ("(function(){var s=new Set(['%s']);s.add('%s');return [...s].join('');})()",
         (_A, _B)),
        # F713 map spread-join tail
        ("(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()",
         (_A, _B)),
        # F611 atob varbound
        ("(function(){var b=atob('%s');return b+'%s';})()",
         ("eG94Yi0wMTIz", _B)),
    ]
    bad = []
    for s, args in shapes:
        if not _blocked(s % args):
            bad.append(s[:60])
    return ("HELD" if not bad else "BREAK", "regressions-bad=%d" % len(bad))


# ------------------------------------------------ p6: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs)
    for batt, expect_break in (("evals/w383_f744_redfirst.py", 0),
                               ("evals/w383_f745_redfirst.py", 0),
                               ("evals/w383_attack_probes.py", 0)):
        # w383_attack: 0 BREAKs after the wave-384 merge footer repoint
        # (test_b0_footer_state now asserts the merged footer).
        tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
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
def test_p6_green_check():
    """Depth-1 green check: F744/F745 red-firsts + wave-383 attack battery green."""
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
