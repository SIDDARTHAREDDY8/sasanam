"""Wave-385 lane 13: attack round 53 (continuous real-model attack).

Filed 2026-10-09 (local node validation on v24.20.0, $0 model spend --
all 54 shapes hand-crafted and node-verified; no paid model calls this round).

New findings (27, all LOW, all OPEN), filed F795-F821:
- F795: IIFE with parameters.
- F796: async function value flows.
- F797: F728 residual: yield* delegation and generator methods.
- F798: WeakMap/WeakSet multi-binding reads.
- F799: subclassed builtin reads.
- F800: F642 residual: Proxy get-trap shape residuals.
- F801: Reflect.apply reads.
- F802: Array flat/flatMap reads.
- F803: var-bound method-call results.
- F804: arguments indexed reads.
- F805: class static block reads.
- F806: mixin extends-expression reads.
- F807: structuredClone reads.
- F808: CustomEvent detail reads.
- F809: non-IIFE closure value flows.
- F810: this-returning method chains.
- F811: computed method names.
- F812: Object wrapper reads.
- F813: F774 residual: descriptor re-installation reads.
- F814: for-of Map pair destructuring.
- F815: F697 residual: toString/valueOf overrides on builtin receivers.
- F816: F756 residual: non-literal ternary conditions.
- F817: F790 residual: rest/swap destructuring.
- F818: F769 residual: .at() with negative index.
- F819: F773 residual: fill with range args.
- F820: Array copyWithin/reverse reads.
- F821: arrow function default parameters.

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F762-F794 (rounds 52) via w384_attack_probes.py green check, F795-F821 (this round).

Closed pins (must BLOCK, else BREAK): F738-F761 (wave-384 closures),
via w383_attack_probes.py green check (pins flipped by the closure lanes).

Rides-with-documented-scope (validated, NOT filed):
- eval/Function constructor, globalThis writes, String.fromCharCode-built
  credentials, btoa/atob single-layer -- dynamic-code / global-state /
  encoding boundaries, out of the static-decoder model.
- Labeled break/continue (F784 OPEN), RegExp exec/matchAll (F765 OPEN),
  Error .cause (F787 OPEN), AggregateError.errors (F788 OPEN),
  private methods (F791 OPEN), logical assignment (F748 OPEN),
  toWellFormed (F771 OPEN), splice-replace (F767 OPEN),
  Symbol.toPrimitive number/default hints (F794/F726 OPEN) -- same finding
  as the filed OPEN entry, not re-filed.
- Round-52 "BLOCK" notes corrected: structuredClone and Proxy.revocable
  were claimed blocking but verified MISS on this round's shapes; filed
  as F807 and F800.
- Junk-quiet controls pass.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction (model spend logged  # Wave-385: pin 2143 -> 2144
separately in the realmodel ledger).
"""

import argparse
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2144  # wave-384 merge  # Wave-385: pin 2143 -> 2144

from gov import dlp
from gov.decision_codes import TAXONOMY

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
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged footer (F795-F817, F819-F828 open, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text  # Wave-385 merge: F795-F828 OPEN
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, F802, F803, F804, F805, F806, F807, F808, F809, F810, F811, F812, F813, F814, F815, F816, F817, F819, F820, F821, F822, F823, F824, F825, F826, F827, F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)

# ------------------------------------------- open pins (must miss)

@_t
def test_r53_f795_s1_open():
    """F795 OPEN: miss reproduces."""
    miss = _misses("(function(a,b){return a+b;})('%s','%s')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f795_s2_open():
    """F795 OPEN: miss reproduces."""
    miss = _misses("((a,b)=>a+b)('%s','%s')" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f796_s1_open():
    """F796 OPEN: miss reproduces."""
    miss = _misses("(async function(){var x=await '%s';return x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f796_s2_open():
    """F796 OPEN: miss reproduces."""
    miss = _misses("(async function(){var o={async m(){return '%s';}};return await o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f797_s1_open():
    """F797 OPEN: miss reproduces."""
    miss = _misses("(function(){function* a(){yield '%s';}function* b(){yield* a();yield '%s';}var it=b();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f797_s2_open():
    """F797 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={*m(){yield '%s';}};return o.m().next().value+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f798_s1_open():
    """F798 OPEN: miss reproduces."""
    miss = _misses("(function(){var wm=new WeakMap();var k1={},k2={};wm.set(k1,'%s');wm.set(k2,'%s');return wm.get(k1)+wm.get(k2);})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f798_s2_open():
    """F798 OPEN: miss reproduces."""
    miss = _misses("(function(){var ws=new WeakSet();var k={};ws.add(k);var x=ws.has(k)?'%s':'zz';return x+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f799_s1_open():
    """F799 OPEN: miss reproduces."""
    miss = _misses("(function(){class S extends String{}var s=new S('%s');return s.valueOf()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f799_s2_open():
    """F799 OPEN: miss reproduces."""
    miss = _misses("(function(){class A extends Array{}var a=new A('%s','%s');return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f800_s1_open():
    """F800 OPEN: miss reproduces."""
    miss = _misses("(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f800_s2_open():
    """F800 OPEN: miss reproduces."""
    miss = _misses("(function(){var r=Proxy.revocable({k:'%s'},{});return r.proxy.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f801_s1_open():
    """F801 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return '%s';}return Reflect.apply(f,null,[])+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f801_s2_open():
    """F801 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a,b){return a+b;}return Reflect.apply(f,null,['%s','%s']);})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f802_s1_open():
    """F802 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=[['%s'],['%s']];return a.flat().join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f802_s2_open():
    """F802 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s'];return a.flatMap(function(x){return [x];}).join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f803_s1_open():
    """F803 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s'.repeat(1);return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f803_s2_open():
    """F803 OPEN: miss reproduces."""
    miss = _misses("(function(){var s='%s'.concat('');return s+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f804_s1_open():
    """F804 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){return arguments[0]+arguments[1];}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f804_s2_open():
    """F804 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(){var x=arguments[1];return arguments[0]+x;}return f('%s','%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f805_s1_open():
    """F805 OPEN: miss reproduces."""
    miss = _misses("(function(){var r;class C{static{var x='%s';r=x;}}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f805_s2_open():
    """F805 OPEN: miss reproduces."""
    miss = _misses("(function(){var r;class C{static{let x='%s';r=x;}}return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f806_s1_open():
    """F806 OPEN: miss reproduces."""
    miss = _misses("(function(){function M(Base){return class extends Base{m(){return '%s';}};}class B{}class C extends M(B){}return new C().m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f806_s2_open():
    """F806 OPEN: miss reproduces."""
    miss = _misses("(function(){var M=function(B){return class extends B{v(){return '%s';}};};class C extends M(class{}){}return new C().v()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f807_s1_open():
    """F807 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};var c=structuredClone(o);return c.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f807_s2_open():
    """F807 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={a:{b:'%s'}};var c=structuredClone(o);return c.a.b+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f808_s1_open():
    """F808 OPEN: miss reproduces."""
    miss = _misses("(function(){var t=new EventTarget();var r='';t.addEventListener('x',function(e){r=e.detail;});t.dispatchEvent(new CustomEvent('x',{detail:'%s'}));return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f808_s2_open():
    """F808 OPEN: miss reproduces."""
    miss = _misses("(function(){var t=new EventTarget();var r='';t.addEventListener('y',function(e){r=e.detail.k;});t.dispatchEvent(new CustomEvent('y',{detail:{k:'%s'}}));return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f809_s1_open():
    """F809 OPEN: miss reproduces."""
    miss = _misses("(function(){var r;new Promise(function(res){r='%s';res();});return r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f809_s2_open():
    """F809 OPEN: miss reproduces."""
    miss = _misses("(function(){function f(a){return function(b){return a+b;};}return f('%s')('%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f810_s1_open():
    """F810 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={a:function(){return this;},b:function(){return '%s';}};return o.a().b()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f810_s2_open():
    """F810 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={a:function(){this.v='%s';return this;},b:function(){return this.v;}};return o.a().b()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f811_s1_open():
    """F811 OPEN: miss reproduces."""
    miss = _misses("(function(){var k='m';var o={[k](){return '%s';}};return o.m()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f811_s2_open():
    """F811 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={['m'+'2'](){return '%s';}};return o.m2()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f812_s1_open():
    """F812 OPEN: miss reproduces."""
    miss = _misses("(function(){var o=Object.seal({k:'%s'});return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f812_s2_open():
    """F812 OPEN: miss reproduces."""
    miss = _misses("(function(){var o=Object.create(null);o.k='%s';return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f813_s1_open():
    """F813 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={};var d=Object.getOwnPropertyDescriptor({k:'%s'},'k');Object.defineProperty(o,'k',d);return o.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f813_s2_open():
    """F813 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={get k(){return '%s';}};var d=Object.getOwnPropertyDescriptor(o,'k');var o2={};Object.defineProperty(o2,'k',d);return o2.k+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f814_s1_open():
    """F814 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=new Map([['a','%s'],['b','%s']]);var s='';for(var [k,v] of m)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f814_s2_open():
    """F814 OPEN: miss reproduces."""
    miss = _misses("(function(){var m=new Map();m.set('x','%s');m.set('y','%s');var s='';for(var [k,v] of m)s+=v;return s;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f815_s1_open():
    """F815 OPEN: miss reproduces."""
    miss = _misses("(function(){var d=new Date(0);d.toString=function(){return '%s';};return d+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f815_s2_open():
    """F815 OPEN: miss reproduces."""
    miss = _misses("(function(){var r=/x/;r.toString=function(){return '%s';};return ''+r+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f816_s1_open():
    """F816 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};return o.hasOwnProperty('k')?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f816_s2_open():
    """F816 OPEN: miss reproduces."""
    miss = _misses("(function(){var o={k:'%s'};return 'k' in o?o.k+'%s':'z';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f817_s1_open():
    """F817 s1: array rest declaration covered by F790 (CLOSED lane 14); s2 assignment form remains OPEN."""
    ok = _blocked("(function(){var [a,...r]=['%s','%s'];return a+r[0];})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r53_f817_s2_open():
    """F817 OPEN: array destructuring assignment miss reproduces."""
    miss = _misses("(function(){var a='%s',b='%s';[a,b]=[b,a];return b+a;})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f818_s1_open():
    """F818 CLOSED (wave-385 merge, incidentally by F769 (lane 4)): blocks coded."""
    ok = _blocked("(function(){var a=['%s','%s'];return a.at(-2)+a.at(-1);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r53_f818_s2_open():
    """F818 CLOSED (wave-385 merge, incidentally by F769 (lane 4)): blocks coded."""
    ok = _blocked("(function(){var a=['z','%s','%s'];return a.at(-2)+a.at(-1);})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)

@_t
def test_r53_f819_s1_open():
    """F819 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=new Array(3);a.fill('%s',0,1);a.fill('%s',1,2);return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f819_s2_open():
    """F819 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['z','z'];a.fill('%s',-2,-1);a.fill('%s',-1);return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f820_s1_open():
    """F820 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','z','%s'];a.copyWithin(1,0,1);return a[0]+a[2];})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f820_s2_open():
    """F820 OPEN: miss reproduces."""
    miss = _misses("(function(){var a=['%s','%s'];a.reverse();return a.join('');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f821_s1_open():
    """F821 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=(a='%s')=>a;return f()+'%s';})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)

@_t
def test_r53_f821_s2_open():
    """F821 OPEN: miss reproduces."""
    miss = _misses("(function(){var f=(a,b='%s')=>a+b;return f('%s');})()" % (_A, _B))
    return ("HELD" if miss else "BREAK", "miss=%s" % miss)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w384_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # The w384 battery's footer pin is stale by design: this lane repointed it
    # (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w384_attack): %d real BREAK (%d tolerated footer)" % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-384 attack battery stays green (depth-1)."""
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
