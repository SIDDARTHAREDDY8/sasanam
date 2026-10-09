#!/usr/bin/env python3
"""Wave-386 lane 10: close F813 + F814.

F813 (LOW; filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
F774 residual -- descriptor re-installation reads. F774 (CLOSED)
covers getOwnPropertyDescriptor().value reads, but re-installing a
captured descriptor via defineProperty had no production:
  (function(){var o={};var d=Object.getOwnPropertyDescriptor({k:'f1'},'k');Object.defineProperty(o,'k',d);return o.k+'f2';})()
  (function(){var o={get k(){return 'f1';}};var d=Object.getOwnPropertyDescriptor(o,'k');var o2={};Object.defineProperty(o2,'k',d);return o2.k+'f2';})()

F814 (LOW; filed 2026-10-09 03:25 UTC by wave-385 attack round 53):
for-of Map pair destructuring -- the decoder had no Map-iteration
production for for(var [k,v] of map):
  (function(){var m=new Map([['a','f1'],['b','f2']]);var s='';for(var [k,v] of m)s+=v;return s;})()
  (function(){var m=new Map();m.set('x','f1');m.set('y','f2');var s='';for(var [k,v] of m)s+=v;return s;})()

Fix (gov/dlp.py, zero new re.compile):
- F813: _js_parse_f813_capture_decl +
  _js_parse_f813_reinstall_stmt + _js_parse_f813_return_term +
  _js_parse_f813_gopd_reinstall_iife, hooked after F774 (hook +
  trailing return intact, wave-379; F452 parts/ops snapshot/restore
  on miss, wave-383 lesson). Descriptor capture preserves the
  data-vs-accessor distinction (the _JSAccessor survives, so
  re-installation re-binds the getter; F738 _JSThisMember markers
  resolve against the read's receiver via _jsobj_lookup,
  node-exact). Copy-on-install (F550 parity).
- F814: _js_parse_f814_map_decl + _js_parse_f814_set_tail +
  _js_parse_f814_forof_head + _js_parse_f814_map_forof_iife, hooked
  after F746 (map family). Reuses _js_parse_new_map_head (F494
  discipline), _js_parse_f6xx_accum_decl / _js_parse_f6xx_iife_head /
  _js_parse_f6xx_iife_tail (F600/F601/F602), F746's S+=X/S=S+X
  body discipline. Numeric keys fail closed (F711).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_footer_state():
    """Control: lane-local footer (F813/F814 closed, next F829)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F829**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, "
              "F801, F802, F803, F804, F805, F806, F807, F808, F809, "
              "F810, F811, F812, F815, F816, F817, F819, F820, F821, "
              "F822, F823, F824, F825, F826, F827, F828." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f813_s1():
    """F813 filed shape 1 (data descriptor reinstall) blocks + exact."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object.defineProperty(o,'k',d);return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f813_s2():
    """F813 filed shape 2 (accessor descriptor reinstall) blocks + exact."""
    s = ("(function(){var o={get k(){return '" + _A + "';}};var "
         "d=Object.getOwnPropertyDescriptor(o,'k');var o2={};"
         "Object.defineProperty(o2,'k',d);return o2.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f814_s1():
    """F814 filed shape 1 (literal Map for-of) blocks + exact."""
    s = ("(function(){var m=new Map([['a','" + _A + "'],['b','" + _B
         + "']]);var s='';for(var [k,v] of m)s+=v;return s;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f814_s2():
    """F814 filed shape 2 (set-tail Map for-of) blocks + exact."""
    s = ("(function(){var m=new Map();m.set('x','" + _A + "');"
         "m.set('y','" + _B + "');var s='';for(var [k,v] of m)s+=v;"
         "return s;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_f813_bracket_read():
    """F813 o['k'] bracket read blocks + exact."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object.defineProperty(o,'k',d);return o['k']+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f813_let_const():
    """F813 let/const decls blocks + exact."""
    s = ("(function(){let o={};const "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object.defineProperty(o,'k',d);return o.k+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f813_this_getter():
    """F813 re-installed this-getter resolves against new receiver."""
    s = ("(function(){var o={x:'" + _A + _B + "',get k(){return this.x;}};"
         "var d=Object.getOwnPropertyDescriptor(o,'k');var o2={x:'"
         + _A + _B + "'};Object.defineProperty(o2,'k',d);"
         "return o2.k;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f813_two_reinstalls():
    """F813 two reinstall statements on one target: exact."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object.defineProperty(o,'k',d);Object.defineProperty(o,'j',d);"
         "return o.k+o.j+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_keys():
    """F814 s+=k key accumulation blocks + exact."""
    s = ("(function(){var m=new Map([['" + _A + "','a'],['" + _B
         + "','b']]);var s='';for(var [k,v] of m)s+=k;return s;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_let_loopvar():
    """F814 let loop var + return tail blocks + exact."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(let [k,v] of m)s+=v;return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_braced():
    """F814 braced body blocks + exact."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(var [k,v] of m){s+=v;}return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_ssv():
    """F814 s=s+v body blocks + exact."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(var [k,v] of m)s=s+v;return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_const_map():
    """F814 const map binding blocks + exact."""
    s = ("(function(){const m=new Map([['a','" + _A + "']]);var s='';"
         "for(var [k,v] of m)s+=v;return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f814_dupkey():
    """F814 duplicate keys later-wins: exact."""
    s = ("(function(){var m=new Map([['a','x'],['a','" + _A + "']]);"
         "var s='';for(var [k,v] of m)s+=v;return s+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f813_missing_key():
    """F813 gopd missing key: engine throws -> fail closed."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'zzz');"
         "Object.defineProperty(o,'k',d);return o.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_set_only():
    """F813 set-only accessor reinstall reads undefined -> fail closed."""
    s = ("(function(){var o={set k(v){}};var "
         "d=Object.getOwnPropertyDescriptor(o,'k');var o2={};"
         "Object.defineProperty(o2,'k',d);return o2.k+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_proto_key():
    """F813 __proto__ install key fails closed (F550 parity)."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object.defineProperty(o,'__proto__',d);return 'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_bracket_defineProperty():
    """F813 Object['defineProperty'] bracket head fails closed."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k');"
         "Object['defineProperty'](o,'k',d);return o.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_unbound_desc():
    """F813 unbound descriptor name fails closed."""
    s = ("(function(){var o={};Object.defineProperty(o,'k',dd);"
         "return o.k+'x';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_extra_args():
    """F813 gopd extra args fail closed (F549 precedent)."""
    s = ("(function(){var o={};var "
         "d=Object.getOwnPropertyDescriptor({k:'" + _A + "'},'k','z');"
         "Object.defineProperty(o,'k',d);return o.k+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f813_this_concat_getter():
    """F813 this-getter with concatenation is a documented F738 residual."""
    s = ("(function(){var o={x:'" + _A + "',get k(){return this.x+'23';}};"
         "var d=Object.getOwnPropertyDescriptor(o,'k');var o2={x:'"
         + _A + "'};Object.defineProperty(o2,'k',d);return o2.k+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_numeric_key():
    """F814 s+=k with numeric key fails closed (F711)."""
    s = ("(function(){var m=new Map([[1,'" + _A + "']]);var s='';"
         "for(var [k,v] of m)s+=k;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_single_destructure():
    """F814 [k]-only destructure is a documented residual."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(var [k] of m)s+=k;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_entries():
    """F814 for-of over m.entries() is a documented residual."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(var [k,v] of m.entries())s+=v;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_const_loopvar():
    """F814 const loop var fails closed (F746 precedent)."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "for(const [k,v] of m)s+=v;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_wrong_accum():
    """F814 body accumulating the wrong var fails closed."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='';"
         "var t='';for(var [k,v] of m)t+=v;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_f814_nonempty_accum():
    """F814 non-empty accumulator initializer fails closed."""
    s = ("(function(){var m=new Map([['a','" + _A + "']]);var s='x';"
         "for(var [k,v] of m)s+=v;return s;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: sibling pins


@_t
def test_p4_sibling_f774():
    """F774 descriptor .value reads still block."""
    s = ("(function(){var o={x:'" + _A + _B + "'};return "
         "Object.getOwnPropertyDescriptor(o,'x').value;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f549():
    """F549 inline-literal gopd still blocks."""
    s = "Object.getOwnPropertyDescriptor({k:'" + _A + _B + "'},'k').value"
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f550():
    """F550 defineProperty expression form still blocks."""
    s = ("Object.defineProperty({},'k',{value:'" + _A + _B + "'}).k")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f746():
    """F746 for-of over m.values() still blocks."""
    s = ("(function(){var m=new Map();m.set('x','" + _A + _B + "');"
         "var s='';for(var v of m.values())s+=v;return s;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f712():
    """F712 var-bound Map iteration reads still block."""
    s = ("(function(){var m=new Map([['a','" + _A + _B + "']]);"
         "return [...m.values()][0];})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_sibling_f601():
    """F601 Map forEach still blocks."""
    s = ("(function(){var s='';new Map([['a','" + _A + _B + "']])"
         ".forEach(function(v){s+=v;});return s;})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_gopd_unaffected():
    """Honest getOwnPropertyDescriptor on an array still misses."""
    s = "Object.getOwnPropertyDescriptor([], 'length').value"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_map_unaffected():
    """Honest Map for-of without credential stays quiet."""
    s = ("(function(){var m=new Map([['a','x']]);var s='';"
         "for(var [k,v] of m)s+=v;return s;})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var o={};var d=Object.getOwnPropertyDescriptor("
            "{k:'a%d'},'k');Object.defineProperty(o,'k',d);"
            "return o.k;})()" % k)
        sites.append(
            "(function(){var m=new Map([['a','v%d']]);var s='';"
            "for(var [k,v] of m)s+=v;return s;})()" % k)
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
    # The w385 attack battery's footer pin is stale by design: this
    # lane repointed the footer lane-locally (wave-305/306 class,
    # merge-owned). Its 4 F813/F814 pins were flipped to closed by
    # this lane. All other probes must HELD.
    for batt, expect_break in (("evals/w385_f813_redfirst.py", 0),
                               ("evals/w385_f814_redfirst.py", 0),
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
def test_p7_green_check():
    """Depth-1 green check: F813/F814 red-firsts (0 BREAK) + wave-385
    attack battery (1 BREAK: the footer pin only, lane-local repoint;
    tree-wide repoint is merge-owned)."""
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
