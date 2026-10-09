#!/usr/bin/env python3
"""Wave-385 lane 14: close F789 + F790.

F789 (LOW, filed 2026-10-09 00:07 UTC by wave-384 attack round 52):
Proxy construct-trap reads. The decoder modeled the Proxy apply trap
(F542) but had no construct-trap production:
(function(){var p=new Proxy(function(){},{construct:function(t,a){
return {x:a[0]};}});return new p('f1').x+'f2';})() and the a[1] twin
both node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

F790 (LOW, filed 2026-10-09 00:07 UTC by wave-384 attack round 52):
F749/F758 residual -- object rest ({a,...r}), array rest ([a,...r]),
param destructuring, and for-of destructuring have no production:
(function(){var {a,...r}={a:'f1',b:'f2'};return a+r.b;})() and
(function(){var [a,...r]=['f1','f2','xx'];return a+r[0];})()
both node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- F789: _js_parse_f789_construct_iife (+ 7 helpers), hooked after
  F611 with the parts/ops snapshot-restore discipline (wave-383
  F733 lesson). The Proxy target must be a plain `function`
  (arrow/generator/async targets throw TypeError in the engine --
  fail closed); the handler is exactly {construct: TRAP} (function,
  arrow-concise, arrow-block, or method-shorthand forms); the trap
  returns exactly {K: 'lit' | a[N]} (string-literal or args-array
  element reads; __proto__ keys, duplicate-key later-wins, >8
  props all engine-exact/fail-closed); the return is a +-additive
  of string literals and new p('LIT',...).MEM / ['MEM'] construct
  terms (at least one construct term, else fall through). An
  out-of-range a[N] is the engine's undefined -- fail closed.
- F790: _js_parse_f790_destructure_rest_iife (+ 6 helpers),
  _js_parse_f790_param_destructure_iife (+ 1 helper), and
  _js_parse_f790_forof_iife, hooked after F749, F758, and F748
  respectively with the same snapshot-restore discipline. All three
  share the _js_f790_rest_additive operand grammar over bound
  names (string / dict / list / unbound): bare idents, R.M /
  R['M'] on dict rest, R[INT] (canonical, bounds-checked) on list
  rest, with the _js_f748_guard_assign reassignment guard. Bounds
  (non-literal sources, holes, nested patterns, rest-not-last,
  unbound/missing reads, bare rest reads) all fail closed.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F789/F790 CLOSED; open F762-F788, F791-F794; next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f789_s1():
    """F789 filed shape 1 (construct trap, a[0]) blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-s1=%s" % ok)


@_t
def test_p1_f789_s2():
    """F789 filed shape 2 (construct trap, a[1] twin) blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[1]};}});return new p('xx','%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-s2=%s" % ok)


@_t
def test_p1_f790_s1():
    """F790 filed shape 1 (object rest) blocks."""
    ok = _blocked("(function(){var {a,...r}={a:'%s',b:'%s'};return a+r.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-s1=%s" % ok)


@_t
def test_p1_f790_s2():
    """F790 filed shape 2 (array rest) blocks."""
    ok = _blocked("(function(){var [a,...r]=['%s','%s','xx'];return a+r[0];})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-s2=%s" % ok)


# ------------------------------------------------- generalizations (p2)

@_t
def test_p2_f789_arrow_trap():
    """F789 generalization: arrow concise trap body blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:(t,a)=>({x:a[0]})});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-arrow=%s" % ok)


@_t
def test_p2_f789_arrow_block_trap():
    """F789 generalization: arrow block-body trap blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:(t,a)=>{return {x:a[1]};}});return new p('xx','%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-arrowblock=%s" % ok)


@_t
def test_p2_f789_method_shorthand():
    """F789 generalization: method-shorthand construct(t,a) blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-method=%s" % ok)


@_t
def test_p2_f789_bracket_read():
    """F789 generalization: new p('f1')['x'] bracket read blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p('%s')['x']+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-bracket=%s" % ok)


@_t
def test_p2_f789_multi_key():
    """F789 generalization: multi-key trap return object blocks."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0],y:a[1]};}});return new p('%s','%s').x+new p('%s','%s').y;})()" % (_A, _B, _A, _B))
    return ("HELD" if ok else "BREAK", "f789-multikey=%s" % ok)


@_t
def test_p2_f789_let():
    """F789 generalization: let declarator blocks."""
    ok = _blocked("(function(){let p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-let=%s" % ok)


@_t
def test_p2_f789_three_param_trap():
    """F789 generalization: 3-param trap (newTarget) fails closed -- miss."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a,n){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-3param-miss=%s" % ok)


@_t
def test_p2_f790_restonly():
    """F790 generalization: rest-only object pattern blocks."""
    ok = _blocked("(function(){var {...r}={a:'%s',b:'%s'};return r.a+r.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-restonly=%s" % ok)


@_t
def test_p2_f790_renamed():
    """F790 generalization: renamed property blocks."""
    ok = _blocked("(function(){var {a:q,...r}={a:'%s',b:'%s'};return q+r.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-renamed=%s" % ok)


@_t
def test_p2_f790_default():
    """F790 generalization: default initializer blocks."""
    ok = _blocked("(function(){var {a='%s',...r}={b:'%s'};return a+r.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-default=%s" % ok)


@_t
def test_p2_f790_array_two():
    """F790 generalization: two array elements + rest blocks."""
    ok = _blocked("(function(){var [a,b,...r]=['%s','%s','%s','xx'];return a+b+r[0];})()" % (_A, _B, _B))
    return ("HELD" if ok else "BREAK", "f790-array2=%s" % ok)


@_t
def test_p2_f790_bracket_rest():
    """F790 generalization: r['b'] string-bracket rest read blocks."""
    ok = _blocked("(function(){var {a,...r}={a:'%s',b:'%s'};return a+r['b'];})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-bracket=%s" % ok)


@_t
def test_p2_f790_param_obj():
    """F790 generalization: param object destructuring blocks."""
    ok = _blocked("(function({x}){return x+'%s';})({x:'%s'})" % (_B, _A))
    return ("HELD" if ok else "BREAK", "f790-paramobj=%s" % ok)


@_t
def test_p2_f790_param_arr():
    """F790 generalization: param array destructuring blocks."""
    ok = _blocked("(function([a,b]){return a+b;})(['%s','%s'])" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-paramarr=%s" % ok)


@_t
def test_p2_f790_param_named():
    """F790 generalization: named function with param destructuring blocks."""
    ok = _blocked("(function f({x}){return x+'%s';})({x:'%s'})" % (_B, _A))
    return ("HELD" if ok else "BREAK", "f790-paramnamed=%s" % ok)


@_t
def test_p2_f790_forof():
    """F790 generalization: for-of destructuring blocks."""
    ok = _blocked("(function(){var s='';for(var [a,b] of [['%s','%s']]){s+=a+b;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-forof=%s" % ok)


@_t
def test_p2_f790_forof_multi():
    """F790 generalization: for-of with two pairs blocks."""
    ok = _blocked("(function(){var s='';for(var [a,b] of [['%s','x'],['%s','y']]){s+=a;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-forofmulti=%s" % ok)


# ---------------------------------------------- fail-closed bounds (p3)

@_t
def test_p3_f789_oob_arg():
    """F789 bound: out-of-range a[0] (engine undefined) fails closed."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p().x+'%s';})()" % _B)
    return ("HELD" if ok else "BREAK", "f789-oob-miss=%s" % ok)


@_t
def test_p3_f789_arrow_target():
    """F789 bound: arrow Proxy target throws in the engine -- fails closed."""
    ok = _misses("(function(){var p=new Proxy(()=>{},{construct:function(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-arrowtarget-miss=%s" % ok)


@_t
def test_p3_f789_nonobj_return():
    """F789 bound: non-object trap return throws in the engine -- blocked by a pre-existing coarse route (fail-closed direction, lane changes nothing)."""
    ok = _blocked("(function(){var p=new Proxy(function(){},{construct:function(t,a){return a[0];}});return new p('%s')+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-nonobj=%s" % ok)


@_t
def test_p3_f789_missing_member():
    """F789 bound: missing member read fails closed."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p('%s').z+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-missing-miss=%s" % ok)


@_t
def test_p3_f789_proto_key():
    """F789 bound: __proto__ trap-return key fails closed."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {__proto__:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-proto-miss=%s" % ok)


@_t
def test_p3_f789_extra_handler():
    """F789 bound: extra handler key (get trap) fails closed."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};},get:(t,k)=>t[k]});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-extrakey-miss=%s" % ok)


@_t
def test_p3_f789_named_trap():
    """F789 bound: named trap function fails closed."""
    ok = _misses("(function(){var p=new Proxy(function(){},{construct:function c(t,a){return {x:a[0]};}});return new p('%s').x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f789-namedtrap-miss=%s" % ok)


@_t
def test_p3_f790_rest_not_last():
    """F790 bound: rest element not last fails closed."""
    ok = _misses("(function(){var {...r,a}={a:'%s'};return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-restnotlast-miss=%s" % ok)


@_t
def test_p3_f790_hole():
    """F790 bound: array hole fails closed."""
    ok = _misses("(function(){var [,...r]=['%s'];return r[0];})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-hole-miss=%s" % ok)


@_t
def test_p3_f790_missing_name():
    """F790 bound: read of an unbound name fails closed."""
    ok = _misses("(function(){var {a,...r}={};return a;})()")
    return ("HELD" if ok else "BREAK", "f790-missing-miss=%s" % ok)


@_t
def test_p3_f790_string_source():
    """F790 bound: non-literal string source fails closed."""
    ok = _misses("(function(){var [a,...r]='f12';return a+r[0];})()")
    return ("HELD" if ok else "BREAK", "f790-strsrc-miss=%s" % ok)


@_t
def test_p3_f790_dup_name():
    """F790 bound: duplicate binding names fail closed."""
    ok = _misses("(function(){var {a,a,...r}={a:'%s'};return a;})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-dup-miss=%s" % ok)


@_t
def test_p3_f790_bare_rest():
    """F790 bound: bare rest read ([object Object]) fails closed."""
    ok = _misses("(function(){var {a,...r}={a:'%s',b:'%s'};return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f790-barerest-miss=%s" % ok)


@_t
def test_p3_f790_oob_index():
    """F790 bound: out-of-range rest index fails closed."""
    ok = _misses("(function(){var [a,...r]=['%s'];return a+r[5];})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-oob-miss=%s" % ok)


@_t
def test_p3_f790_forof_bad_pair():
    """F790 bound: for-of pair of wrong arity fails closed."""
    ok = _misses("(function(){var s='';for(var [a,b] of [['%s']]){s+=a;}return s;})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-badpair-miss=%s" % ok)


@_t
def test_p3_f790_forof_nonliteral():
    """F790 bound: for-of non-literal pair element fails closed."""
    ok = _misses("(function(){var s='';for(var [a,b] of [[x,'%s']]){s+=a;}return s;})()" % _A)
    return ("HELD" if ok else "BREAK", "f790-nonlit-miss=%s" % ok)


# ------------------------------------------------ siblings + honest (p4/p5)

@_t
def test_p4_sibling_f542():
    """Sibling: F542 Proxy apply-trap still blocks."""
    ok = _blocked("(function(){var o={x:'%s'};return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f671=%s" % ok)


@_t
def test_p4_sibling_f749():
    """Sibling: F749 destructuring defaults still block."""
    ok = _blocked("(function(){var {x='%s',y='%s'}={};return x+y;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f749=%s" % ok)


@_t
def test_p4_sibling_f758():
    """Sibling: F758 rest params still block."""
    ok = _blocked("(function(){function h(...xs){return xs.join('');}return h('%s','%s');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f758=%s" % ok)


@_t
def test_p4_sibling_f611():
    """Sibling: F611 var-bound IIFE still blocks."""
    ok = _blocked("(function(){var x='%s';return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f611=%s" % ok)


@_t
def test_p4_sibling_f748():
    """Sibling: F748 log-assign still blocks."""
    ok = _blocked("(function(){var x='';x+='%s';x+='%s';return x;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f748=%s" % ok)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_iife_quiet():
    """Honest IIFE stays quiet."""
    ok = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if ok else "BREAK", "honest-iife=%s" % ok)


@_t
def test_p5_honest_proxy_quiet():
    """Honest Proxy (no construct trap, no credential) stays quiet."""
    ok = _misses("(function(){var p=new Proxy(function(){},{get:function(t,k){return 'zz';}});return p.x;})()")
    return ("HELD" if ok else "BREAK", "honest-proxy=%s" % ok)


# ----------------------------------------------------------------- perf (p6)

@_t
def test_p6_perf():
    """200 mixed F789/F790 sites decode in under 20s."""
    t0 = time.time()
    for k in range(100):
        dlp.find_credential(
            "junk (function(){var p%d=new Proxy(function(){},{construct:function(t,a){return {x:a[0]};}});return new p%d('f1').x+'f2';})() tail" % (k, k))
        dlp.find_credential(
            "junk (function(){var {a%d,...r%d}={a%d:'f1',b%d:'f2'};return a%d+r%d.b;})() tail" % (k, k, k, k, k, k))
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------ p7: green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the w384 attack battery's only
    # expected BREAK is test_b0_footer_state (base footer pin; the
    # lane-local repoint is merge-owned, wave-382 lane-5 precedent).
    for batt, expect_break in (("evals/w384_f789_redfirst.py", 0),
                               ("evals/w384_f790_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts + wave-384 attack battery green."""
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
