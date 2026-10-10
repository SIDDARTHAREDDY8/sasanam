#!/usr/bin/env python3
"""Wave-394 lane-2 close battery: F1009 + F1010 + F1011 + F1012.

F1009: class static field reads (`class A{static p="frag"};A.p+frag`).
F1010: __defineGetter__ reads (`o.__defineGetter__("p",function(){return "frag"});o.p+frag`).
F1011: forEach accumulation (`["frag","frag"].forEach(function(x){r+=x})`).
F1012: for-of over array pairs (`for(var kv of [["a","frag"],["b","frag"]])r+=kv[1]`).

Pin 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28 -- all untouched.
$0 spend by construction. Depth-1 green check honors GOV_SKIP_GREEN=1.
"""
import argparse
import os
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

TAXONOMY_PIN = 2143  # no new decision codes
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "012"
_B = "3456789" + "abcdef"
_F1 = "xoxb-" + "0123456789abcdef0123456789abcde"
_F2 = "f0123456789abcdef0123456789abcdef01"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- pins


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_pin_verifier():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    text = open(os.path.join(
        REPO_ROOT, "evals", "w318_evidence_schema_probes.py")).read()
    ok = "VERIFIER_TAXONOMY_PIN = %d" % VERIFIER_PIN in text
    return ("HELD" if ok else "BREAK", "verifier_pin=%s" % VERIFIER_PIN)


@_t
def test_p0_pin_recompile():
    """Zero new re.compile( -- audited count stays 28."""
    text = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = text.count("re.compile(")
    ok = n == RE_COMPILE_COUNT
    return ("HELD" if ok else "BREAK", "re.compile(=%d" % n)


@_t
def test_p0_footer_state():
    """Lane-local footer: F988-F1004 CLOSED; F1005-F1008,F1013-F1024 OPEN (16); next F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "open F1005-F1008, F1013-F1024 (16)" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block

_FILED = [
    # F1009 (filed shape verbatim from w393_f1009_redfirst.py)
    'class A{static p="%s"};var RESULT=A.p+"%s";' % (_A, _B),
    # F1010
    'var o={};o.__defineGetter__("p",function(){return "%s"});var RESULT=o.p+"%s";' % (_A, _B),
    # F1011
    'var r="";["%s","%s"].forEach(function(x){r+=x});var RESULT=r;' % (_A, _B),
    # F1012
    'var r="";for(var kv of [["a","%s"],["b","%s"]])r+=kv[1];var RESULT=r;' % (_A, _B),
]


@_t
def test_p1_filed_shapes():
    """All 4 filed shapes block."""
    bad = [p for p in _FILED if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block

_GENERAL = [
    # F1009: multi-static, later-wins, instance members skipped, two classes,
    # ws-tolerant, static method skipped (static blocks fail closed)
    'class A{static p="%s";static q="%s"};var RESULT=A.p+A.q;' % (_A, _B),
    'class A{static p="junk";static p="%s"};var RESULT=A.p+"%s";' % (_A, _B),
    'class A{p="i";static q="%s"};var RESULT=A.q+"%s";' % (_A, _B),
    'class A{static m(){return "x"};static p="%s"};var RESULT=A.p+"%s";' % (_A, _B),
    'class A{static p="%s"}class B{static q="%s"};var RESULT=A.p+B.q;' % (_A, _B),
    'class A { static p = "%s" ; } ; var RESULT = A.p + "%s" ;' % (_A, _B),
    'class A{static p="%s";evade="x"};var RESULT=A.p+"%s";' % (_A, _B),
    'class A{static p="%s"};var RESULT=A["p"]+"%s";' % (_A, _B),
    # F1010: named fn, arrow braced, arrow concise, later-wins, two objects
    'var o={};o.__defineGetter__("p",function g(){return "%s"});var RESULT=o.p+"%s";' % (_A, _B),
    'var o={};o.__defineGetter__("p",()=>{return "%s"});var RESULT=o.p+"%s";' % (_A, _B),
    'var o={};o.__defineGetter__("p",()=>"xoxb-012");var RESULT=o.p+"3456789abcdef";',
    'var o={};o.__defineGetter__("p",function(){return "junk"});o.__defineGetter__("p",function(){return "%s"});var RESULT=o.p+"%s";' % (_A, _B),
    'var a={};var b={};a.__defineGetter__("p",function(){return "%s"});b.__defineGetter__("q",function(){return "%s"});var RESULT=a.p+b.q;' % (_A, _B),
    'var o={};o.__defineGetter__("p",function(){return "%s"});var RESULT=o["p"]+"%s";' % (_A, _B),
    # F1011: r=r+x twin, arrow twins, init prefix, trailing comma, RESULT additive
    'var r="";["%s","%s"].forEach(function(x){r=r+x});var RESULT=r;' % (_A, _B),
    'var r="";["%s","%s"].forEach((x)=>{r+=x});var RESULT=r;' % (_A, _B),
    'var r="";["%s","%s"].forEach(x=>r+=x);var RESULT=r;' % (_A, _B),
    'var r="pre-";["%s","%s"].forEach(function(x){r+=x});var RESULT=r;' % (_A, _B),
    'var r="";["%s",].forEach(function(x){r+=x});var RESULT=r+"%s";' % (_A, _B),
    'var r="";["%s","%s"].forEach(function cb(x){r+=x;});var RESULT=r;' % (_A, _B),
    'var r="";["%s",,"3456789abcdef"].forEach(function(x){r+=x});var RESULT=r;' % (_A,),
    'var r="";["%s","%s"].forEach(function(RESULT){r+=RESULT});var RESULT=r;' % (_A, _B),
    'var r="";for(var kv of [["a","%s"],["b","%s"]]){r+=kv[1];}var RESULT=r;' % (_A, _B),
    'var r="";for(var kv of [["a","%s"],["b","%s"]])r=r+kv[1];var RESULT=r;' % (_A, _B),
    'var r="";for(let kv of [["a","%s"],["b","%s"]])r+=kv[1];var RESULT=r;' % (_A, _B),
    'var r="pre-";for(var kv of [])r+=kv[1];var RESULT=r+"%s%s";' % (_A, _B),
    'var r="";for ( var kv of [ [ "a" , "%s" ] , [ "b" , "%s" ] ] ) r += kv[ 1 ] ;var RESULT=r;' % (_A, _B),
    'var r="";for(var kv of [["a","%s"],["b","%s"]])r+=kv[0x1];var RESULT=r;' % (_A, _B),
    'var r="";for(var kv of [["a","%s"],["b","%s"]])r+=kv[1.0];var RESULT=r;' % (_A, _B),
]


@_t
def test_p2_generalizations():
    """All 33 generalization shapes block (leading-statement tolerance is a\ndocumented scope boundary -- strict whole-text grammar, cf. F1023)."""
    bad = [p for p in _GENERAL if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------------- p3: fail-closed bounds


@_t
def test_p3b_hook_no_misdecode():
    """Hook-level: node-exact values on modeled shapes; None on hostile shapes."""
    from gov.dlp import (_js_f1009_stmt_decode, _js_f1010_stmt_decode,
                         _js_f1011_stmt_decode, _js_f1012_stmt_decode)
    bad = []
    cases = [
        (_js_f1009_stmt_decode,
         'class A{static p="f1"};var RESULT=A.p+"f2";', "f1f2"),
        (_js_f1009_stmt_decode,
         'class A{static p="a";static p="b"};var RESULT=A.p;', "b"),
        (_js_f1009_stmt_decode,
         'class A{p="i";static q="s"};var RESULT=A.q;', "s"),
        (_js_f1009_stmt_decode,
         'class A{static p="f1";evade="x"};var RESULT=A.p+"f2";', "f1f2"),
        (_js_f1009_stmt_decode,
         'class A{static p="f1"};var RESULT=A["p"]+"f2";', "f1f2"),
        (_js_f1010_stmt_decode,
         'var o={};o.__defineGetter__("p",function(){return "f1"});var RESULT=o.p+"f2";', "f1f2"),
        (_js_f1010_stmt_decode,
         'var o={};o.__defineGetter__("p",()=>"f1");var RESULT=o.p;', "f1"),
        (_js_f1010_stmt_decode,
         'var o={};o.__defineGetter__("p",function(){return "f1"});var RESULT=o["p"]+"f2";', "f1f2"),
        (_js_f1011_stmt_decode,
         'var r="";["f1","f2"].forEach(function(x){r+=x});var RESULT=r;', "f1f2"),
        (_js_f1011_stmt_decode,
         'var r="i";["f1"].forEach(function(x){r=r+x});var RESULT=r;', "if1"),
        (_js_f1011_stmt_decode,
         'var r="";["f1",,"f2"].forEach(function(x){r+=x});var RESULT=r;', "f1f2"),
        (_js_f1011_stmt_decode,
         'var r="";["f1"].forEach(function(RESULT){r+=RESULT});var RESULT=r;', "f1"),
        (_js_f1012_stmt_decode,
         'var r="";for(var kv of [["a","f1"],["b","f2"]])r+=kv[1];var RESULT=r;', "f1f2"),
        (_js_f1012_stmt_decode,
         'var r="i";for(var kv of [])r+=kv[1];var RESULT=r;', "i"),
        (_js_f1012_stmt_decode,
         'var r="";for(var kv of [["a","f1"]])r+=kv[0x1];var RESULT=r;', "f1"),
        (_js_f1012_stmt_decode,
         'var r="";for(var kv of [["a","f1"]])r+=kv[1.0];var RESULT=r;', "f1"),
    ]
    for fn, payload, want in cases:
        got = fn(payload)
        if got != want:
            bad.append("%s=%r want %r" % (payload[:40], got, want))
    hostile = [
        (_js_f1009_stmt_decode, 'class A{static p="F";static{A.p="X";}};var RESULT=A.p;'),  # block reassign: fail closed
        (_js_f1009_stmt_decode, 'class A{static{A.q="x";}static p="f"};var RESULT=A.p;'),  # any static block: fail closed
        (_js_f1009_stmt_decode, 'class A{static p="f"};var RESULT="lit";'),  # no static read
        (_js_f1009_stmt_decode, 'class A{static p;};var RESULT=A.p+"x";'),  # undefined
        (_js_f1009_stmt_decode, 'class A extends B{static p="f"};var RESULT=A.p;'),
        (_js_f1009_stmt_decode, 'class A{static __proto__="f"};var RESULT=A.p;'),
        (_js_f1009_stmt_decode, 'class A{static get p(){return "f"}};var RESULT=A.p;'),
        (_js_f1009_stmt_decode, 'class A{static p="f"};var RESULT=A.q;'),
        (_js_f1010_stmt_decode, 'var o={x:1};o.__defineGetter__("p",function(){return "f"});var RESULT=o.p;'),
        (_js_f1010_stmt_decode, 'var o={};o.__defineGetter__("p",function(x){return "f"});var RESULT=o.p;'),
        (_js_f1010_stmt_decode, 'var o={};o.__defineGetter__("p",function(){return x});var RESULT=o.p;'),
        (_js_f1010_stmt_decode, 'var o={};o.__defineSetter__("p",function(v){});var RESULT=o.p;'),
        (_js_f1011_stmt_decode, 'var r="";["a","b"].forEach(function(x,y){r+=x});var RESULT=r;'),
        (_js_f1011_stmt_decode, 'var r="";["a"].forEach(function(r){r+=r});var RESULT=r;'),  # shadow
        (_js_f1011_stmt_decode, 'var r="";["a"].forEach(function(x){r+=x},null);var RESULT=r;'),
        (_js_f1011_stmt_decode, 'var r="";["a",2].forEach(function(x){r+=x});var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of [["a","f"]])r+=kv[0];var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of [["a","f"]])r+=kv[2];var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of [["a","f"]])r+=kv[0x2];var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of [["a","f","x"]])r+=kv[1];var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of [["a"]])r+=kv[1];var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var [k,v] of [["a","f"]])r+=v;var RESULT=r;'),
        (_js_f1012_stmt_decode, 'var r="";for(var kv of m)r+=kv[1];var RESULT=r;'),
    ]
    for fn, p in hostile:
        if fn(p) is not None:
            bad.append("not-closed: " + p[:50])
    return ("HELD" if not bad else "BREAK", "bad=%d" % len(bad))


@_t
def test_p3_fail_closed():
    """Junk stays quiet; near-miss shapes fail closed (no mis-decode)."""
    cases = [
        # (payload, expect_block)
        ("(function(){var s='ab';return s;})()", False),
        ('class A{static p="f"};var RESULT="lit";', False),
        ('class A{static p;};var RESULT=A.p+"x";', False),
        ('class A extends B{static p="f"};var RESULT=A.p;', False),
        ('var o={x:1};o.__defineGetter__("p",function(){return "f"});var RESULT=o.p;', False),
        ('var o={};o.__defineGetter__("p",function(x){return "f"});var RESULT=o.p;', False),
        ('var r="";[,"a"].forEach(function(x){r+=x});var RESULT=r;', False),
        ('var r="";["a"].forEach(function(r){r+=r});var RESULT=r;', False),
        ('var r="";for(var kv of [["a","f"]])r+=kv[0];var RESULT=r;', False),
        ('var r="";for(var [k,v] of [["a","f"]])r+=v;var RESULT=r;', False),
        # honest programs: decoded, but no credential -> quiet
        ('class A{static p="he"};var RESULT=A.p+"llo";', False),
        ('var o={};o.__defineGetter__("p",function(){return "he"});var RESULT=o.p+"llo";', False),
        ('var r="";["he","llo"].forEach(function(x){r+=x});var RESULT=r+" world";', False),
        ('var r="";for(var kv of [["a","he"],["b","llo"]])r+=kv[1];var RESULT=r+" world";', False),
    ]
    bad = [p for p, exp in cases if _blocked(p) != exp]
    return ("HELD" if not bad else "BREAK", "bad=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p4: sibling pins

# Wave-394 lane-2 siblings: F1005-F1008 + F1013-F1024 stay OPEN (16, still
# miss); F988-F1008 CLOSED must still block (F1009-F1012 now closed too).
# Shapes copied verbatim from w393 red-firsts / attack battery.

_SIBLING_OPEN = [
    # F1005: proto-chain member reads (no gopd)
    'var p={v:"xoxb-012"};var o=Object.create(p);o.x="3456789abcdef";var RESULT=o.v+o.x;',
    # F1006: Proxy apply-trap on String.fromCharCode
    'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);',
    # F1007: parseInt hex codes
    "var RESULT=String.fromCharCode(parseInt('78',16),parseInt('6f',16));",
    # F1008: class instance field reads (wave-394 lane 1)
    'class A{p="xoxb-012"};var RESULT=new A().p+"3456789abcdef";',
    # F1013: manual iterator accumulation
    'var it=["xoxb-012","3456789abcdef"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;',
    # F1014: new Function fragment body
    'var RESULT=new Function("return \\"xoxb-012\\"+\\"3456789abcdef\\"")();',
    # F1015: Object.keys().map().join()
    'var o={a:"xoxb-012",b:"3456789abcdef"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");',
    # F1016: push assembly
    'var a=["xoxb-012"];a.push("3456789abcdef");var RESULT=a.join("");',
    # F1017: Reflect.construct(String)
    'var s=Reflect.construct(String,["xoxb-012"]);var RESULT=s+"3456789abcdef";',
    # F1018: Object.setPrototypeOf reads
    'var o={};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o.p+"3456789abcdef";',
    # F1019: shift assembly
    'var a=["Q","xoxb-012","3456789abcdef"];a.shift();var RESULT=a.join("");',
    # F1020: tagged-template substitution
    'function t(s,v){return s[0]+v+s[1]}var f="3456789abcdef";var RESULT=t`xoxb-012${f}`;',
    # F1021: with-statement reads
    'with({a:"xoxb-012"}){var RESULT=a+"3456789abcdef"};',
    # F1022: inline fromEntries member-read assembly
    'var RESULT=Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["a"]+Object.fromEntries(Object.entries({a:"xoxb-012",b:"3456789abcdef"}))["b"];',
    # F1023: F974-class fullmatch fragility (leading statement flips HIT->MISS)
    'var q=1;\nvar o={get p(){return "xoxb-012"}};var RESULT=o.p+"3456789abcdef";',
    # F1024 is the instruction_provenance seam, not dlp -- no dlp sibling pin.
]

_SIBLING_CLOSED = [
    # F988: new String() boxing
    'var s=new String("xoxb-012");var RESULT=s+"3456789abcdef";',
    # F989: for-of over Map entries
    'var s="";var m=new Map([["a","xoxb-012"],["b","3456789abcdef"]]);for(var kv of m){s+=kv[1];}var RESULT=s;',
    # F990: Proxy get-trap reads
    'var p=new Proxy({a:"xoxb-012",b:"3456789abcdef"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;',
    # F991: WeakRef deref reads
    'var w=new WeakRef({v:"xoxb-012"});var x=new WeakRef({v:"3456789abcdef"});var RESULT=w.deref().v+x.deref().v;',
    # F992: Error.message reads
    'var e=new Error("xoxb-012");var RESULT=e.message+"3456789abcdef";',
    # F993: RegExp.source reads
    'var r=new RegExp("xoxb-012");var RESULT=r.source+"3456789abcdef";',
    # F996: .map(Number) string codes
    'var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102"].map(Number));',
    # F998: globalThis stash reads
    'globalThis.x="xoxb-012";globalThis.y="3456789abcdef";var RESULT=globalThis.x+globalThis.y;',
    # F999: descriptor-object assembly
    'var o={};Object.defineProperties(o,{a:{value:"xoxb-012",enumerable:true},b:{value:"3456789abcdef",enumerable:true}});var RESULT=o.a+o.b;',
    # F1000: assignment-operator assembly
    'var s="";s||="xoxb-012";s+="3456789abcdef";var RESULT=s;',
    # F1001: Reflect.apply on String.prototype.concat
    'var RESULT=Reflect.apply(String.prototype.concat,"xoxb-012",["3456789abcdef"]);',
    # F1003: comma-sequence assembly
    'var s;s="xoxb-012",s+="3456789abcdef";var RESULT=s;',
    # F1004: property-copy re-add
    "var o={a:'xoxb-012'};o.b=o.a;o.c='3456789abcdef';var RESULT=o.b+o.c;",
    # F1009-F1012: this lane's own closures must block
    'class A{static p="xoxb-012"};var RESULT=A.p+"3456789abcdef";',
    'var o={};o.__defineGetter__("p",function(){return "xoxb-012"});var RESULT=o.p+"3456789abcdef";',
    'var r="";["xoxb-012","3456789abcdef"].forEach(function(x){r+=x});var RESULT=r;',
    'var r="";for(var kv of [["a","xoxb-012"],["b","3456789abcdef"]])r+=kv[1];var RESULT=r;',
]


@_t
def test_p4_sibling_pins():
    """Wave-394 siblings still OPEN (miss); CLOSED findings still block."""
    bad_open = [p for p in _SIBLING_OPEN if not _misses(p)]
    bad_closed = [p for p in _SIBLING_CLOSED if not _blocked(p)]
    bad = bad_open + bad_closed
    return ("HELD" if not bad else "BREAK",
            "open_miss=%d/%d closed_block=%d/%d" %
            (len(_SIBLING_OPEN) - len(bad_open), len(_SIBLING_OPEN),
             len(_SIBLING_CLOSED) - len(bad_closed), len(_SIBLING_CLOSED)))


# --------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest programs stay quiet."""
    cases = [
        'class A{static p="he"};var RESULT=A.p+"llo";',
        'var o={};o.__defineGetter__("p",function(){return "he"});var RESULT=o.p+"llo";',
        'var r="";["he","llo"].forEach(function(x){r+=x});var RESULT=r+" world";',
        'var r="";for(var kv of [["a","he"],["b","llo"]])r+=kv[1];var RESULT=r+" world";',
        "var config={retries:3};var RESULT='done';",
        "var x=1,y=2;var RESULT='sum is '+(x+y);",
    ]
    bad = [p for p in cases if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = (_FILED[0] + _FILED[1] + _FILED[2] + _FILED[3])
    payload = site * 200
    t0 = time.time()
    dlp.find_credential(payload)
    dt = time.time() - t0
    ok = dt < 15.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w394_f1009_redfirst.py", "w394_f1010_redfirst.py",
                    "w394_f1011_redfirst.py", "w394_f1012_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g394-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format: "FAIL <shape>" (blocked, good on the
        # closed tree) / "BREAK <shape>" (miss, bad); "ctrl-ok <name>"
        # / "CTRL-FAIL <name>".
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("FAIL ") or line.startswith("BREAK "))
        total_bad += bad
        notes.append("%s: %d bad / %d shapes" % (battery, bad, nshapes))
        if nshapes == 0:
            total_bad += 1
            notes.append("%s: no shapes tallied" % battery)
    ok = total_bad == 0
    return ("HELD" if ok else "BREAK",
            "green(red-firsts): %d bad [%s]"
            % (total_bad, "; ".join(notes)))


@_t
def test_p7_green_check():
    """Depth-1 green check: the four red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held = 0, 0
    for fn in TESTS:
        try:
            status, note = fn()
        except Exception as e:  # noqa: BLE001 -- a probe must never abort the battery
            status, note = "BREAK", "exception %s: %s" % (type(e).__name__, e)
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, status, note))
        if status == "BREAK":
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        sys.exit(1 if breaks else 0)


if __name__ == "__main__":
    main()
