#!/usr/bin/env python3
"""Wave-382 lane 5: close F708 + F709 (Map.get and loop-accumulation residuals).

F708 (LOW, filed 2026-10-08 by wave-381 lane 8, attack round 49):
Map.get fragment reads bypass the bounded static JS-expression
decoder -- the decoder modeled Map-spread index reads (F695) and
Map.forEach accumulation (F657, CLOSED) but had no Map.get
production: `(function(){var m=new Map([['k','f1']]);return
m.get('k')+'f2';})()` and the set/keyvar twin
`(function(){var m=new Map();m.set('k','f1');var
k='k';return m.get(k)+'f2';})()` both node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero
variants. Distinct from F695 (spread indexing) and F657 (forEach).

F709 (LOW, filed 2026-10-08 by wave-381 lane 8, attack round 49):
loop += accumulation bypasses the bounded static JS-expression
decoder -- the decoder modeled straight-line concatenation (F655,
CLOSED) and statement-body loops with ternary/member operands
(F679, CLOSED) but failed closed on counted loops accumulating
over a literal string array indexed by the counter:
`(function(){var r='';for(var i=0;i<2;i++){r+=['f1','f2'][i];}return
r;})()` and the while twin both node-evaluate to the exact
credential (node v24.20.0) while the decoder produced zero
variants. Distinct from F655 (straight-line) and F679 (no
literal-array-index operand production).

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f708_map_get_iife (+ _js_f708_map_key): the
  var-bound Map.get IIFE grammar -- `var|let|const
  M=new Map([PAIRS]);` (the shared F657 bound-map decl),
  `(M.set(K,V);|var|let|const K='LIT';)*` middle statements, and
  `return M.get(KEY)(+'LIT')*;`. SameValueZero key identity
  (("s",key)/("n",key), later-wins, reusing the F563 entries
  discipline); the get value flows through the normal postfix
  chain with an additive literal tail (the F610 return
  discipline). Hooked after F679 in _js_parse_primary; disjoint
  (F679 has no Map production; F657 requires forEach; F669
  requires spread-consume).
- _js_parse_f709_loop_accum_iife (+ _js_f709_int,
  _js_f709_indexed_accum): counted-loop `+=` accumulation over a
  literal string array -- the for twin and the while twin (counter
  decl up front, `I++` as the last body statement). The counter
  runs the exact integer sequence (canonical safe ints only,
  F699 discipline); each iteration appends the element at the
  counter (out-of-bounds is engine `undefined` -- never decoded,
  fail closed). Bounded by _JS_F679_MAX_ITERS iterations, F452
  per-iteration part charge, _MAX_DECODE_BYTES on the result.
  Hooked after F708 (after F679); disjoint (F679's operand
  grammar has no literal-array-index production).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g382-*
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


def _decode_exact(payload):
    """The strict JS-expression decode of *payload* (None on fail-closed)."""
    r = dlp._try_js_expr_decode(payload, 0)
    return r[0] if r else None


# ------------------------------------------------ p0: pin

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


# ------------------------------------------------ p1: F708 filed shapes now block

@_t
def test_p1_f708_filed_shapes_closed():
    """F708 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B),
        "(function(){var m=new Map();m.set('k','%s');var k='k';return m.get(k)+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p2: F709 filed shapes now block

@_t
def test_p2_f709_filed_shapes_closed():
    """F709 CLOSED: both filed shapes decode node-exactly -> coded refusal."""
    shapes = [
        "(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B),
        "(function(){var r='';var i=0;while(i<2){r+=['%s','%s'][i];i++;}return r;})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p3: node-exact variants

@_t
def test_p3_variants_node_exact():
    """Generalizations decode node-exactly (v24.20.0 verified by differential)."""
    # (payload, node value); credential-shaped ones must also flag.
    cases = [
        ("(function(){var m=new Map([['k','%s'],['k','junk']]);return m.get('k');})()" % _A,
         "junk"),
        ("(function(){const m=new Map([[1,'%s']]);return m.get(1);})()" % _A,
         _A),
        ("(function(){let m=new Map();m.set('a','x');m.set('a','%s');return m.get('a');})()" % _A,
         _A),
        ("(function(){var m=new Map([['k','%s']]);return m.get('k').slice(0,4);})()" % _A,
         _A[:4]),
        ("(function(){var m=new Map([['k','%s']]);var j='k';return m.get(j);})()" % _A,
         _A),
        ("(function(){let r='';for(let i=0;i<=1;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B),
         _A + _B),
        ("(function(){var r='';for(var i=1;i<3;i++){r+=['a','%s','z'][i];}return r;})()" % _A,
         _A + "z"),
        ("(function(){var m=new Map([['k','%s']]);return m.get('k')+'%s';})()" % (_A, _B),
         _A + _B),
    ]
    bad = []
    for src, want in cases:
        got = _decode_exact(src)
        if got != want:
            bad.append((src[:50], want, got))
    ok = not bad
    return ("HELD" if ok else "BREAK", "exact=%s" % (bad if bad else "8/8"))


# ------------------------------------------------ p4: bounds fail closed

@_t
def test_p4_bounds_fail_closed():
    """Out-of-scope shapes fail closed (rejected, never mis-decoded)."""
    shapes = [
        # F708 bounds
        "(function(){var m=new Map([['k','%s']]);return m.get('missing')+'%s';})()" % (_A, _B),  # missing key
        "(function(){var m=new Map([['k','%s']]);return m.get(9007199254740993);})()" % _A,  # unsafe int key
        "(function(){var m=new Map([['k','%s']]);var n=m;return n.get('k');})()" % _A,  # aliased receiver
        "(function(){var m=new Map();m.set('k',123);return m.get('k');})()",  # non-string set value
        "(function(){var m=new Map([['k','%s']]);return m.get(k);})()" % _A,  # unbound key
        "(function(){var m=new Map();m='x';return m.get('k');})()",  # rebound map
        "(function(){var m=new Map([['k','%s']]);return m.get();})()" % _A,  # no key arg
        "(function(){var m={};return m.get('k');})()",  # not a Map
        "(function(){var m=new Map([['k','%s']]);m.delete('k');return m.get('k');})()" % _A,  # delete unmodeled
        # F709 bounds
        "(function(){var r='';for(var i=0;i<33;i++){r+=['a','b'][i];}return r;})()",  # over-cap iterations
        "(function(){var r='';for(var i=0;i<2;i--){r+=['a','b'][i];}return r;})()",  # wrong update
        "(function(){var r='';for(var i=0;i<2;i++){r+=['a','b'][i+1];}return r;})()",  # index not the counter
        "(function(){var r='';var i=0;while(true){r+=['a','b'][i];i++;if(i>2)break;}return r;})()",  # unbounded
        "(function(){var r='';for(var i=0;i<3;i++){r+=['a','b'][i];}return r;})()",  # out-of-bounds index
        "(function(){var r='';for(var i=0;i<2;i++){r+=[[1],[2]][i];}return r;})()",  # non-string elements
        "(function(){var r='';for(var i=0;i<9007199254740993;i++){r+=['a'][i];}return r;})()",  # unsafe bound
        "(function(){var r='';for(var i=-1;i<1;i++){r+=['a','b'][i];}return r;})()",  # negative index
        "(function(){var r='';for(var r=0;r<2;r++){r+=['a','b'][r];}return r;})()",  # counter shadows accum
        "(function(){var r='';for(var i=0;i<2;i++){r+=['a','b'][i];r+='x';}return r;})()",  # extra body stmt
        "(function(){var r='';for(var i=0;i<2;i++){s+=['a','b'][i];}return r;})()",  # wrong accum name
    ]
    got = [_misses(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "quiet=%s" % got)


# ------------------------------------------------ p5: neighbors + open findings

@_t
def test_p5_neighbors_hold():
    """Sibling closures still block; nothing absorbed."""
    shapes = [
        # F657 var-bound Map.forEach: still blocks
        "(function(){var m=new Map([['k','%s'],['j','%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()" % (_A, _B),
        # F695 inline Map-spread indexing: still blocks
        "(function(){return [...new Map([['k','%s']])][0][1]+'%s';})()" % (_A, _B),
        # F679 ternary-operand loop: still blocks
        "(function(){var s='';for(var i=0;i<2;i++){s+=i===0?'%s':'%s';}return s;})()" % (_A, _B),
        # F655 straight-line accum: still blocks
        "(function(){var a='%s';var b='%s';return a+b;})()" % (_A, _B),
        # F601 inline Map.forEach: still blocks
        "(function(){var s='';new Map([['k','%s'],['j','%s']]).forEach(function(v){s+=v;});return s;})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


@_t
def test_p5_open_findings_still_miss():
    """F700/F701/F706/F710/F712 now CLOSED by sibling lanes (merge) -- their shapes block coded."""
    shapes = [
        # F700 flatMap residual
        "(function(){return ['%s','%s'].flatMap(function(x){return [x,''];}).join('');})()" % (_A, _B),
        # F701 getter on spread
        "(function(){var o={get x(){return '%s';}};var c={...o};return c.x+'%s';})()" % (_A, _B),
        # F706 defineProperty-trap write (filed shape: TR[PR]=RHS trap body)
        "(function(){var t={};var p=new Proxy(t,{defineProperty:function(tr,pr,de){tr[pr]='%s';return true;}});Object.defineProperty(p,'x',{value:1});return t.x+'%s';})()" % (_A, _B),
        # F710 Set.has residual
        "(function(){var s=new Set(['k']);var f=s.has('k')?'%s':'xx';return f+'%s';})()" % (_A, _B),
        # F712 var-bound Map iteration
        "(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B),
    ]
    got = [_blocked(s) for s in shapes]
    ok = all(got)
    return ("HELD" if ok else "BREAK", "blocked=%s" % got)


# ------------------------------------------------ p6: junk quiet

@_t
def test_p6_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------ p7: pin + footer + regex budget

@_t
def test_p7_pin_footer():
    """Pin 2143; lane-local footer (F708+F709 CLOSED; open F700-F707,F710-F712 / next F713)."""
    ok = (TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F921**" in text)  # Wave-382 lane 5: F708, F709 CLOSED  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    ok = ok and ("Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-382 lane 5: F708, F709 CLOSED  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
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
    """200 mixed Map.get/loop-accum sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var m=new Map([['k','a%d']]);return m.get('k')+'b';})()" % k)
        corpus.append("(function(){var r='';for(var i=0;i<2;i++){r+=['a%d','b'][i];}return r;})()" % k)
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
    # w381_attack_probes expects 0 BREAK: merge repointed its footer
    # tree-wide (wave-305/306 class); anything other than exactly
    # 0 BREAKs fails the check.
    for batt, expect_break in (("evals/w381_f708_redfirst.py", 0),
                               ("evals/w381_f709_redfirst.py", 0),
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
def test_p9_green_check():
    """Depth-1 green check: F708/F709 red-firsts + wave-381 attack battery green."""
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
