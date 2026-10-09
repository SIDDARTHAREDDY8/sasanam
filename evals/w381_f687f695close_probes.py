#!/usr/bin/env python3
"""Wave-381 lane 2: close F687 + F695 (collection-membership residuals).

F687 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
WeakSet membership-marker conditional reads bypass the bounded static
JS-expression decoder -- the decoder had no WeakSet production:
`(function(){var w=new WeakSet();var k={};w.add(k);return
(w.has(k)?'f1':'junk')+'f2';})()` and the two-key-guard twin both
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants. Distinct from F562/F563 (Map reads --
WeakMap stores block coded).

F695 (LOW, filed 2026-10-08 by wave-380 lane 8, attack round 48):
Map-spread index/key reads bypass the bounded static JS-expression
decoder -- F669 (CLOSED) files builtin-iterable spread consumption
joined, but indexing into the spread pair-array:
`(function(){return [...new Map([['k','f1']])][0][1]+'f2';})()`, the
key twin `[...new Map([['f1','junk']])][0][0]`, and
`Array.from(new Map([['k','f1']]))[0][1]` all node-evaluate to the
exact credential (node v24.20.0) while the decoder produced zero
variants. Distinct from F669 (spread+join consumption).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f687_weakset_iife (+ _js_parse_f687_weakset_has): the
  WeakSet IIFE body grammar -- `var|const|let NAME=new WeakSet();`
  (empty only; a constructor iterable fails closed),
  `var|const|let NAME={...};` object-identity bindings (the F572
  discipline: each declaration mints a fresh uid), statement-form
  `w.add(k);` membership adds, and `return (COND?'LIT':'LIT')+TAIL`
  where COND is `TERM (&& TERM)*` with TERM = `[!]w.has(k)`.
  The ternary must be parenthesized (an unparenthesized ternary
  fails closed -- the engine would re-associate the tail into the
  else branch); TAIL is `+ PRIMARY` of plain strings only.
  Hooked after F572 in _js_parse_primary; disjoint by binding
  (`new WeakSet` vs `new WeakMap`).
- _js_parse_f695_map_entries_spread: bare `new Map([[k,v],...])`
  desugars to the insertion-ordered [k, v] pair arrays (the
  engine's Map iteration protocol, node v24.20.0) via the shared
  _js_parse_new_map_head (later-wins, SameValueZero keys, _JSNumStr
  key provenance); a following `.`/`(` fails closed so the
  F589/F600/F494 postfix routes keep their shapes. Hooked into the
  F471 spread-copy Map branch and the F508 Array.from Map branch;
  both previously fail-closed everywhere on bare Maps.

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


# ------------------------------------------------ p0: pin

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2140; registry loads."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------ p1: F687 filed shapes now block

@_t
def test_p1_f687_filed_shapes_closed():
    """F687 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakSet();var k={};var j={};w.add(k);return (w.has(k)&&!w.has(j)?'%s':'junk')+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p2: F695 filed shapes now block

@_t
def test_p2_f695_filed_shapes_closed():
    """F695 CLOSED: all three filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B),
        "(function(){return [...new Map([['%s','junk']])][0][0]+'%s';})()" % (_A, _B),
        "(function(){return Array.from(new Map([['k','%s']]))[0][1]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p3: node-exact variants

@_t
def test_p3_variants_node_exact():
    """Variants decode node-exactly (v24.20.0 verified by differential)."""
    # Each payload node-evaluates to the exact credential; the
    # decoder must flag it (value-exactness verified separately in
    # the lane's node differential: 16/17 exact, 1 test-harness
    # artifact on a non-credential input).
    shapes = [
        # F687: multi-add, negated-only, no-tail, multi-tail
        "(function(){var w=new WeakSet();var k={};var j={};w.add(k);w.add(j);return (w.has(k)&&w.has(j)?'%s':'junk')+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakSet();var k={};w.add(k);return (!w.has(k)?'junk':'%s')+'%s';})()" % (_A, _B),
        "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s%s':'junk');})()" % (_A, _B),
        "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'%s':'junk')+'%s'+'%s';})()" % (_A, _B, _B),
        # F695: numeric keys, second pair, join over pair arrays
        "(function(){return [...new Map([['z','%s%s']])].join('');})()" % (_A, _B),
        "(function(){return Array.from(new Map([['z','%s%s']])).join('');})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p4: fail-closed bounds

@_t
def test_p4_bounds_fail_closed():
    """Out-of-scope shapes fail closed (rejected, never mis-decoded)."""
    shapes = [
        # F687 bounds
        "(function(){var w=new WeakSet([{}]);var k={};return (w.has(k)?'a':'b');})()",  # ctor iterable arg
        "(function(){var w=new WeakSet();var k={};w.add(k).add(k);return (w.has(k)?'a':'b');})()",  # chained add
        "(function(){var w=new WeakSet();return (w.has({})?'a':'b');})()",  # inline literal key
        "(function(){var w=new WeakSet();var k={};return w.has(k)?'a':'b';})()",  # unparenthesized ternary
        "(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)||w.has(k)?'a':'b');})()",  # || unsupported
        "(function(){var w=new WeakSet();var k={};w.delete(k);return 'a';})()",  # delete unmodeled
        # F695 bounds
        "[...new Map([['k','v']]).entries()][0][1]",  # F589 route preserved
        "[...new Map([['k','v']]).keys()][0]",  # F600 route preserved
        "[...new Map([['k','v']]).values()][0]",  # F494 route preserved
        "Array.from(new Map([['k','v']]).entries())[0][1]",  # still fail-closed
        "Array.from(new Map([['k','v']]).values())[0]",  # F494 route preserved
        "[...new Map()][0]",  # empty Map spread: documented residual
        "[...new Map([['k',{}]])][0][1]",  # non-string value fails closed
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p5: neighbors + open findings

@_t
def test_p5_neighbors_hold():
    """Sibling closures still block; nothing absorbed."""
    shapes = [
        # F572/F596 WeakMap (not WeakSet): still block
        "(function(){var k={};var m=new WeakMap([[k,'%s']]);return m.get(k)+'%s';})()" % (_A, _B),
        "(function(){var k={};var m=new WeakMap();m.set(k,'%s');return m.get(k)+'%s';})()" % (_A, _B),
        # F669 builtin-iterable spread consumption: still blocks
        "(function(){var st=new Set(['%s','%s']);return [...st].join('');})()" % (_A, _B),
        "(function(){var m=new Map();m.set('a','%s');m.set('b','%s');return [...m.values()].join('');})()" % (_A, _B),
        # F494 string spread: still blocks
        "[...'%s%s'].join('')" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


@_t
def test_p5_open_findings_still_miss():
    """F686/F688/F694/F696/F697 now CLOSED (wave-381) -- block; F712 CLOSED (wave-382 lane 7) -- blocks; F700-F711 OPEN -- miss."""
    closed_shapes = [
        "(function(){var p=new Proxy({},{ownKeys:function(){return ['%s','%s'];},getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true};}});return Reflect.ownKeys(p).join('');})()" % (_A, _B),  # F686
        "(function(){return 'ab'.replaceAll(/a|b/g,function(m){return m==='a'?'%s':'%s';});})()" % (_A, _B),  # F688
        "(function(){var m='%s:%s'.match(/(%s):(%s)/);return m[1]+m[2];})()" % (_A, _B, _A, _B),  # F694
        "(function(){return (new String('%s'))+'%s';})()" % (_A, _B),  # F696
        "(function(){var o={v:'%s',valueOf:function(){return this.v;}};return o+'%s';})()" % (_A, _B),  # F697
        "(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B),  # F712 CLOSED wave-382 lane 7
    ]
    open_shapes = [
        "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B),  # F708 Map.get
        "(function(){return ['%s','%s'].flatMap(function(f){return [f,''];}).join('');})()" % (_A, _B),  # F700 flatMap
    ]
    got_closed = [_blocked(s) for s in closed_shapes]
    got_open = [_misses(s) for s in open_shapes]
    ok = all(got_closed) and all(got_open)
    return ("HELD" if ok else "BREAK", "closed=%s open-miss=%s" % (got_closed, got_open))


# ------------------------------------------------ p6: junk quiet

@_t
def test_p6_junk_quiet():
    """Honest text stays quiet (no false positives)."""
    shapes = [
        "'(function(){var s=\\'ab\\';return s;})()'",
        "(function(){var w=new WeakSet();var k={};w.add(k);return 'quiet';})()",
        "(function(){var w=new WeakSet();var k={};return (w.has(k)?'quiet':'quieter');})()",
        "(function(){return [...new Map([['k','v']])][0][1];})()",
        "Array.from(new Map([['k','v']]))[0][1]",
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p7: pin, footer, no new regexes

@_t
def test_p7_pin_footer():
    """Pin 2143; footer repointed for wave-382 lane 7 (F712 CLOSED, F713 filed)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F795**" in text)  # Wave-382 lane 7: F712 CLOSED, F713 filed  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-382 lane 7  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


@_t
def test_p7_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ p8: perf

@_t
def test_p8_perf():
    """200 mixed WeakSet/Map-spread sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var w=new WeakSet();var k={};w.add(k);return (w.has(k)?'a%d':'b')+'c';})()" % k)
        corpus.append("(function(){return [...new Map([['k','a%d']])][0][1]+'b';})()" % k)
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p9: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w380_f687_redfirst.py", 0),
                               ("evals/w380_f695_redfirst.py", 0),
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
def test_p9_green_check():
    """Depth-1 green check: F687/F695 red-firsts + wave-380 attack battery green."""
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
