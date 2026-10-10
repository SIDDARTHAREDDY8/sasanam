#!/usr/bin/env python3
"""Wave-394 lane 1 close battery: F1005/F1006/F1007/F1008 CLOSED.

F1005 = proto-chain member reads without the getOwnPropertyDescriptor line
        (wave-393 lane-4 spec-review residual of F1002).
F1006 = Proxy apply-trap reads on String.fromCharCode (F990 residual --
        novel vs F990's get-trap; F542's Reflect.apply bodies disjoint).
F1007 = parseInt(x,16) code ints into String.fromCharCode.
F1008 = class instance field reads.

All filed shapes BLOCK (0 BREAK) on the closed tree; generalizations
node-verified (v24.20.0); fail-closed bounds stay quiet (miss, never
mis-decode); sibling pins unaffected (F1009-F1012/F1022/F1023 still OPEN,
F990/F1002/F1004 still CLOSED); honest text quiet; 200-site perf;
depth-1 green check on w393_attack_probes.py (only the 3 now-closed
open pins may BREAK there -- the merge flips them, wave-393 precedent).

Pins: TAXONOMY_PIN 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28.
$0-spend-by-construction (no harness/paid refs).

NOTE on the F1008 finding text: it shows `class A{p:"frag"}` (colon),
but the filed red-first battery (the contract) uses the node-exact
`class A{p="frag"}` (equals) form -- the colon form does not assemble
(node yields undefined). The hook models the battery's shape.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-393 merge (no code-count change)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_C = "xoxb-" + "0123456789abcdef0123456789abcdef012"

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
def test_b0_pin_taxonomy():
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) == 2143
    return ("HELD" if ok else "BREAK", "pin=%s codes=%d" % (TAXONOMY_PIN, len(TAXONOMY)))


@_t
def test_b0_pin_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "w318", os.path.join(REPO_ROOT, "evals", "w318_evidence_schema_probes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ok = mod.VERIFIER_TAXONOMY_PIN == 33
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % mod.VERIFIER_TAXONOMY_PIN)


@_t
def test_b0_recompile_count():
    n = len(re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    return ("HELD" if n == 28 else "BREAK", "re.compile=%d" % n)


@_t
def test_b0_footer_state():
    """Lane-local footer: F1005-F1008 CLOSED; open F1009-F1024 (16); next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("[CLOSED 2026-10-10 wave-394 lane 1" in text
          and "open F1009-F1024 (16)" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "lane_footer=%s" % ok)


@_t
def test_b0_junk_quiet():
    quiet = _misses("(function(){var s='ab';return s;})()")
    return ("HELD" if quiet else "BREAK", "junk=%s" % quiet)


# ------------------------------------------------------- P1 filed shapes


@_t
def test_p1_filed_shapes():
    shapes = [
        # F1005 (2 shapes, short + 40-char)
        'var p={v:"%s"};var o=Object.create(p);o.x="%s";var RESULT=o.v+o.x;' % (_A, _B),
        'var p={v:"xox"};var o=Object.create(p);o.x="b-0123456789abcdef0123456789abcdef012";var RESULT=o.v+o.x;',
        # F1006 (2 shapes)
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);',
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50);',
        # F1007 (2 shapes)
        "var RESULT=String.fromCharCode(parseInt('78',16),parseInt('6f',16),parseInt('78',16),parseInt('62',16),parseInt('2d',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16));",
        "var RESULT=String.fromCharCode(parseInt('78',16),parseInt('6f',16),parseInt('78',16),parseInt('62',16),parseInt('2d',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16),parseInt('30',16),parseInt('31',16),parseInt('32',16));",
        # F1008 (1 filed shape)
        'class A{p="xoxb-012"};var RESULT=new A().p+"3456789abcdef";',
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/7" % len(missed))


# ------------------------------------------------------ P2 generalizations


@_t
def test_p2_generalizations():
    # All node-verified (v24.20.0) via /var/tmp/w394_diffcheck.py.
    # Every shape assembles the 20-char credential -- all must block.
    codes20 = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"
    hex20 = ",".join("parseInt('%x',16)" % b for b in (_A + _B).encode())
    dec20 = ",".join("parseInt('%d',10)" % b for b in (_A + _B).encode())
    shapes = [
        # F1005: inline proto, shadowing, bracket reads, proto-var reads, let
        'var o=Object.create({v:"%s"});o.x="%s";var RESULT=o.v+o.x;' % (_A, _B),
        'var p={v:"A"};var o=Object.create(p);o.v="%s";var RESULT=o.v+"%s";' % (_A, _B),
        'var p={v:"%s"};var o=Object.create(p);var RESULT=o["v"]+"%s";' % (_A, _B),
        'var p={v:"%s"};var o=Object.create(p);var RESULT=p.v+"%s";' % (_A, _B),
        'let p={v:"%s"};let o=Object.create(p);let RESULT=o.v+"%s";' % (_A, _B),
        # F1006: arrow forms, named fn, .apply dispatch, bracket target
        'var f=new Proxy(String.fromCharCode,{apply:(p1,p2,p3)=>p1.apply(p2,p3)});var RESULT=f(%s);' % codes20,
        'var f=new Proxy(String.fromCharCode,{apply:(a,b,c)=>{return a.apply(b,c);}});var RESULT=f(%s);' % codes20,
        'var f=new Proxy(String.fromCharCode,{apply:function t(x,y,z){return x.apply(y,z);}});var RESULT=f(%s);' % codes20,
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a);}});var RESULT=f.apply(null,[%s]);' % codes20,
        'var f=new Proxy(String["fromCharCode"],{apply:function(t,th,a){return t.apply(th,a);}});var RESULT=f(%s);' % codes20,
        # F1007: radix 10, 0x prefix, whitespace, trailing junk, bracket form
        'var RESULT=String.fromCharCode(%s);' % dec20,
        'var RESULT=String.fromCharCode(%s);' % ",".join("parseInt('0x%x',16)" % b for b in (_A + _B).encode()),
        'var RESULT=String.fromCharCode(' + ",".join("parseInt( '%x' , 16 )" % b for b in (_A + _B).encode()) + ');',
        'var RESULT=String.fromCharCode(' + ",".join("parseInt('%xzz',16)" % b for b in (_A + _B).encode()) + ');',
        'var RESULT=String["fromCharCode"](%s);' % hex20,
        # F1008: multi-field, quoted key, two classes, dup fields, field named static, no-semi
        'class A{p="%s";q="%s"};var RESULT=new A().p+new A().q;' % (_A, _B),
        'class A{"p"="%s"};var RESULT=new A()["p"]+"%s";' % (_A, _B),
        'class A{p="%s"};class B{q="%s"};var RESULT=new A().p+new B().q;' % (_A, _B),
        'class A{p="x";p="%s"};var RESULT=new A().p+"%s";' % (_A, _B),
        'class A{static="%s"};var RESULT=new A().static+"%s";' % (_A, _B),
        'class A{p="%s"}var RESULT=new A().p+"%s";' % (_A, _B),
    ]
    missed = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not missed else "BREAK", "missed=%d/%d" % (len(missed), len(shapes)))


# ------------------------------------------------------ P3 fail-closed bounds


@_t
def test_p3_fail_closed():
    # Outside the modeled subset: must stay quiet (miss), never mis-decode.
    # Fragments are split so a hit would prove a decode happened.
    f1, f2 = "xoxb-012", "3456789abcde"
    quiet_shapes = [
        # F1005
        'var p={v:"A"};var o=Object.create(p);var RESULT=o.zzz+"%s";' % f2,
        'var o=Object.create(null);o.x="%s";var RESULT=o.x+"%s";' % (f1, f2),
        'var p={v:"%s"};var o=Object.create(p);o.w=o.v;var RESULT=o.w+"%s";' % (f1, f2),
        'var p={v:"\\141"};var o=Object.create(p);var RESULT=o.v+"%s";' % f2,  # octal: node "a", never mis-decode
        # F1006
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return "zz";}});var RESULT=f(72,105)+"%s";' % f2,
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(a,th);}});var RESULT=f(72,105)+"%s";' % f2,
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a);},get:function(t,k){return t[k];}});var RESULT=f(120,111)+"%s";' % f2,
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a);}});var RESULT=f.apply(x,[120,111])+"%s";' % f2,  # unbound thisArg: node ReferenceError
        # F1007
        'var RESULT=String.fromCharCode(parseInt("78"));',  # no radix: NaN -> "\x00"
        'var RESULT=String.fromCharCode(parseInt("78",17));',
        'var RESULT=String.fromCharCode(parseInt("zz",16));',
        'var RESULT=String.fromCharCode(parseInt("\\141",16));',  # octal escape: fail closed
        "var RESULT=String.fromCharCode(parseInt('00000000000078',16));",  # 14 digits: past double-exact bound
        # F1008
        'class A{p="x"+"y"};var RESULT=new A().p+"%s";' % f2,
        'class A{p="x"};var RESULT=new A().zzz+"%s";' % f2,
        'class A{p="\\141"};var RESULT=new A().p+"%s";' % f2,  # octal: fail closed
        'class A{constructor="x"};var RESULT=new A().p+"%s";' % f2,  # node SyntaxError: fail closed
    ]
    flagged = [s for s in quiet_shapes if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/17" % len(flagged))


# ------------------------------------------------------ P4 sibling pins


@_t
def test_p4_sibling_pins():
    # Still OPEN (must keep missing): lane 2's F1009-F1012, F1022, F1023.
    # F1024 is the instruction_provenance seam (not dlp) -- covered by the
    # attack battery's own pins.
    still_open = [
        'class A{static p="xoxb-012"};var RESULT=A.p+"3456789abcdef";',  # F1009 (lane 2)
        'var o={};o.__defineGetter__("p",function(){return "xoxb-012";});var RESULT=o.p+"3456789abcdef";',  # F1010 (lane 2)
        'var r="";["xoxb-012","3456789abcdef"].forEach(function(x){r+=x});var RESULT=r;',  # F1011 (lane 2)
        'var r="";for(var kv of [["a","xoxb-012"],["b","3456789abcdef"]])r+=kv[1];var RESULT=r;',  # F1012 (lane 2)
        'var RESULT=Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["a"]+Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["b"];',  # F1022
    ]
    # Already CLOSED: must stay blocked (my hooks must not break them).
    still_closed = [
        'var p=new Proxy({a:"%s"},{get:function(t,k){return t[k];}});var RESULT=p.a+"%s";' % (_A, _B),  # F990
        'var p={v:"%s"};var o=Object.create(p);var d=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+"%s";' % (_A, _B),  # F1002
        'var o={a:"%s"};o.b=o.a;var RESULT=o.b+"%s";' % (_A, _B),  # F1004
    ]
    bad_open = [s for s in still_open if _blocked(s)]
    closed_ok = all(_blocked(s) for s in still_closed)
    ok = not bad_open and closed_ok
    return ("HELD" if ok else "BREAK",
            "overblocked=%d closed_ok=%s" % (len(bad_open), closed_ok))


# ------------------------------------------------------ P5 honest text


@_t
def test_p5_honest_text():
    honest = [
        'class A{p="hello"};var r=new A().p;',
        'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a);}});var r=f(72,105);',
        'var r=String.fromCharCode(parseInt("48",16));',
        'var p={v:"a"};var o=Object.create(p);var r=o.v;',
        "var s='hello';var r=s+' world';",
    ]
    flagged = [s for s in honest if _blocked(s)]
    return ("HELD" if not flagged else "BREAK", "flagged=%d/5" % len(flagged))


# ------------------------------------------------------ P6 perf


@_t
def test_p6_perf():
    sites = []
    tmpl = ['var p={v:"%s"};var o=Object.create(p);var RESULT=o.v;',
            'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a);}});var RESULT=f(%s);',
            "var RESULT=String.fromCharCode(parseInt('%x',16));",
            'class A{p="%s"};var RESULT=new A().p;']
    for i in range(200):
        frag = "ab" * (i % 7 + 1)
        k = i % 4
        if k == 0:
            sites.append(tmpl[0] % frag)
        elif k == 1:
            sites.append(tmpl[1] % ",".join(str(b) for b in frag.encode()))
        elif k == 2:
            sites.append(tmpl[2] % ord("a"))
        else:
            sites.append(tmpl[3] % frag)
    t0 = time.time()
    for s in sites:
        dlp.find_credential(s)
    dt = time.time() - t0
    return ("HELD" if dt < 30 else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------ P7 green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g394l1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    target = os.path.join(REPO_ROOT, "evals", "w393_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, target],
                           capture_output=True, text=True, timeout=900,
                           env=env, cwd=REPO_ROOT)
        lines = (r.stdout or "").strip().split("\n")
        broken = []
        for ln in lines[:-1]:
            if ": BREAK" in ln:
                broken.append(ln.split(":")[0])
        # My closures legitimately break the 3 now-closed open pins;
        # the merge flips them (wave-393 precedent). Nothing else may BREAK.
        expected = {"test_r61_f1006_open", "test_r61_f1007_open",
                    "test_r61_f1008_open"}
        ok = set(broken) == expected
        return (("HELD" if ok else "BREAK"),
                "green(w393_attack): broken=%s" % sorted(broken))
    finally:
        pass


@_t
def test_p7_green_check():
    """Depth-1 green check on the round-61 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            verdict, note = "BREAK", "probe raised %r" % (e,)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
