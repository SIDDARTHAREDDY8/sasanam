#!/usr/bin/env python3
"""Wave-382 lane 1: close F700 + F701 (array-method and spread residuals).

F700 (LOW, filed 2026-10-08 by wave-381 lane 8, attack round 49):
F658 residual -- flatMap mapping-fn returning 2-element arrays with
an empty-string sibling bypasses the bounded static JS-expression
decoder -- the F658 closure (wave-380 lane 7) models flatMap only
for [x]-identity mapping arrays:
`(function(){return ['f1','f2'].flatMap(function(f){return
[f,''];}).join('');})()` and the prefix twin
`(function(){return ['f1','f2'].flatMap(function(f){return
['',f];}).join('');})()` both node-evaluate to the exact credential
(node v24.20.0) while the decoder produced zero variants. Distinct
from F658 ([x] identity form, which blocks).

F701 (LOW, filed 2026-10-08 by wave-381 lane 8, attack round 49):
getter invocation on object spread bypasses the bounded static
JS-expression decoder -- the decoder models spread-copy (F471) as a
copy but not accessor invocation on spread:
`(function(){var o={get x(){return 'f1';}};return
{...o}.x+'f2';})()` and the two-getter two-statement twin
`(function(){var o={get x(){return 'f1';},get y(){return
'f2';}};var c={...o};return c.x+c.y;})()` both node-evaluate to the
exact credential (node v24.20.0) while the decoder produced zero
variants. Distinct from F664 (descriptor .get() invocation) and
F698 (defineProperty-installed accessor .get()).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f700_flatmap_empty_sibling: exactly-one-param flatMap
  callbacks whose return array's elements are each the param ident
  or the empty-string literal (>= 1 of each, >= 2 elements), the
  F543/F597/F658 four-form precedent (arrow expr/block, function,
  optional name). Hooked between F658 and F597 (pairwise disjoint:
  F574 owns [P]-only, F658 owns all-literal, F597 owns scalar
  heads). Each element e maps to the template with the param
  substituted, then flat(1) via _js_flatten_f574 (node-exact:
  [e,'']/['',e] interleave the empty string).
- F701 (1): _js_parse_f535_object/_js_parse_f557_spread take
  optional spread_env=None (default: every existing caller
  byte-identical); `...NAME` bound to a _JSObj merges its resolved
  data props (the engine's [[Get]]-on-spread; getters already
  resolved at source-parse time; _JSAccessor unwraps defensively;
  proto not copied). Unbound idents and non-object bindings fail
  closed. Threaded from _js_parse_f671_member_term, so F671's
  single-decl shape covers the inline-spread filed shape.
- F701 (2): _js_parse_f701_getter_spread_iife, hooked after F697
  with the `return _js_parse_postfix(...)` tail intact (wave-379
  lesson): `(function(){DECL N={LIT};DECL N2={...N};return
  ADD;})()` -- the second decl must be exactly `{...FIRST}`; the
  return is the F649m additive of member reads on either binding.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
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


# ------------------------------------------------ p1: F700 filed shapes now block

@_t
def test_p1_f700_filed_shapes_closed():
    """F700 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){return ['%s','%s'].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B),
        "(function(){return ['%s','%s'].flatMap(function(f){return ['',f];}).join('');})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p2: F700 four-form generalizations

@_t
def test_p2_f700_generalizations_closed():
    """F700 CLOSED: arrow/block/named/3-element/dq/nested twins block."""
    shapes = [
        "['%s','%s'].flatMap(f=>[f,'']).join('')" % (_A, _B),
        "['%s','%s'].flatMap((f)=>['',f]).join('')" % (_A, _B),
        "['%s','%s'].flatMap(f=>{return [f,''];}).join('')" % (_A, _B),
        "['%s','%s'].flatMap(function g(f){return ['',f];}).join('')" % (_A, _B),
        "['%s','%s'].flatMap(f=>[f,'',f]).join('')" % (_A, _B),
        "['%s','%s'].flatMap(f=>[f,\"\"]).join('')" % (_A, _B),
        "(function(){return [['%s'],['%s']].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p3: F700 flatMap siblings still block

@_t
def test_p3_f700_flatmap_siblings_block():
    """F574/F658/F597 flatMap grammars still block (no absorption)."""
    shapes = [
        "['%s','%s'].flatMap(x=>[x]).join('')" % (_A, _B),
        "['%s','%s'].flatMap(()=>'%s%s').join('')" % (_A, _B, _A, _B),
        "(function(){return ['%s','%s'].flatMap(function(){return ['%s','%s'];}).join('');})()" % (_A, _B, _A, _B),
        "['%s','%s'].flatMap(x=>x).join('')" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p4: F700 residuals fail closed

@_t
def test_p4_f700_residuals_miss():
    """F700 residuals fail closed (documented scope boundary)."""
    shapes = [
        # [f,f] doubling -- not an empty-sibling mix
        "(function(){return ['%s','%s'].flatMap(function(f){return [f,f];}).join('');})()" % (_A, _B),
        # non-empty sibling literal
        "(function(){return ['%s','%s'].flatMap(function(f){return [f,'x'];}).join('');})()" % (_A, _B),
        # two params
        "(function(){return ['%s','%s'].flatMap(function(f,i){return [f,''];}).join('');})()" % (_A, _B),
        # other ident
        "(function(){return ['%s','%s'].flatMap(function(f){return [g,''];}).join('');})()" % (_A, _B),
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "miss=%s" % got)


# ------------------------------------------------ p5: F701 filed shapes now block

@_t
def test_p5_f701_filed_shapes_closed():
    """F701 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';},get y(){return '%s';}};var c={...o};return c.x+c.y;})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p6: F701 generalizations

@_t
def test_p6_f701_generalizations_closed():
    """F701 CLOSED: let/const/paren/bracket/data/mixed twins block."""
    shapes = [
        "(function(){let o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B),
        "(function(){const o={get x(){return '%s';}};return ({...o}).x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';}};return {...o}['x']+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';}};return {...o}?.x+'%s';})()" % (_A, _B),
        "(function(){var o={x:'%s'};return {...o}.x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';},y:'%s'};var c={...o};return c.x+c.y;})()" % (_A, _B),
        "(function(){var o={x:'%s',y:'%s'};var c={...o};return c.x+c.y;})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p7: F701 siblings still block

@_t
def test_p7_f701_siblings_block():
    """F671/F664/F698 + literal-spread shapes still block (no absorption)."""
    shapes = [
        "(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B),
        "(function(){return {x:'%s'}.x+'%s';})()" % (_A, _B),
        "(function(){return {...{x:'%s'}}.x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B),
        "(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p8: F701 residuals fail closed

@_t
def test_p8_f701_residuals_miss():
    """F701 residuals fail closed (documented scope boundary)."""
    shapes = [
        # spread of an unbound name
        "(function(){var o={get x(){return '%s';}};return {...q}.x+'%s';})()" % (_A, _B),
        # second decl with extra keys -- not exactly {...FIRST}
        "(function(){var o={get x(){return '%s';}};var c={...o,z:'zz'};return c.x+'%s';})()" % (_A, _B),
        # spread of a non-object binding
        "(function(){var o='st';return {...o}.x+'%s';})()" % (_B,),
        # spread of a different binding than the getter object
        "(function(){var o={get x(){return '%s';}};var p={x:'q'};var c={...p};return c.x+'%s';})()" % (_A, _B),
        # three declarations -- outside the two-decl grammar
        "(function(){var o={get x(){return '%s';}};var p={z:'zz'};var c={...o};return c.x+'%s';})()" % (_A, _B),
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "miss=%s" % got)


# ------------------------------------------------ p9: open neighbors still miss

@_t
def test_p9_open_neighbors_miss():
    """F702-F705 now CLOSED by sibling lanes (merge): their shapes block coded."""
    shapes = [
        "(function(){var o={get x(){return '%s';}};return Object.assign({},o).x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';}};var c=Object.assign({z:1},o);return c.x+'%s';})()" % (_A, _B),
        "(function(){var o={};o.__defineGetter__('x',function(){return '%s';});return o.x+'%s';})()" % (_A, _B),
        "(function(){var o=Object.create(null,{x:{get:function(){return '%s';}}});return o.x+'%s';})()" % (_A, _B),
        "(function(){var o={get x(){return '%s';}};return Reflect.get(o,'x',{})+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p10: F700 node-exact values

@_t
def test_p10_f700_node_exact_values():
    """F700 decodes node-exactly (value-level, node v24.20.0)."""
    pairs = [
        ("['alpha','beta'].flatMap(f=>[f,'']).join('')", "alphabeta"),
        ("['alpha','beta'].flatMap((f)=>['',f]).join('')", "alphabeta"),
        ("['alpha','beta'].flatMap(f=>{return [f,''];}).join('')", "alphabeta"),
        ("['alpha','beta'].flatMap(f=>[f,'',f]).join('')", "alphaalphabetabeta"),
    ]
    got = [dlp._try_js_expr_decode_all(p) == v for p, v in pairs]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "exact=%s" % got)


# ------------------------------------------------ p11: F701 node-exact values

@_t
def test_p11_f701_node_exact_values():
    """F701 decodes node-exactly (value-level, node v24.20.0)."""
    pairs = [
        ("(function(){var o={get x(){return 'alpha';}};return {...o}.x+'beta';})()",
         "alphabeta"),
        ("(function(){var o={get x(){return 'alpha';},get y(){return 'beta';}};var c={...o};return c.x+c.y;})()",
         "alphabeta"),
        ("(function(){let o={get x(){return 'alpha';}};return {...o}.x+'beta';})()",
         "alphabeta"),
    ]
    got = [dlp._try_js_expr_decode_all(p) == v for p, v in pairs]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "exact=%s" % got)


# ------------------------------------------------ p12: footer state

@_t
def test_p12_footer_state():
    """Control: footer shows F702-F712 open, next F713 (lane-local)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p13: junk quiet

@_t
def test_p13_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------ p14: depth-1 green check

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w381_f700_redfirst.py", 0),
                               ("evals/w381_f701_redfirst.py", 0),
                               ("evals/w381_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g382-green-", dir="/var/tmp")
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
def test_p14_green_check():
    """Depth-1 green check: F700/F701 red-firsts + wave-381 attack battery green."""
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
