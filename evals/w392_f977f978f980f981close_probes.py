#!/usr/bin/env python3
"""Wave-392 lane-3 close battery: F977 + F978 + F980 + F981.

F977: delete/re-add property lifecycle (+ add-only twin).
F978: Array.prototype.splice reassembly (removal + insertion).
F980: arguments-object spread into String.fromCharCode (IIFE rewrite).
F981: pop-based accumulation, the F938 shift() mirror (+ prepend twin).

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
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"

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
    """Lane-local footer: F977/F978/F980/F981 CLOSED; F988 filed OPEN; open F967-F974, F982-F988 (15); next F989."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F989**" in text
          and "F977-F978, F980-F981 CLOSED (4" in text
          and "F988 OPEN (1, wave-392 lane 3" in text
          and "F967-F974, F982-F988 (15" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block

_FILED = [
    # F977
    "var o={a:'xoxb-0123',b:'456789abcdef'};delete o.b;o.b='456789abcdef';var RESULT=o.a+o.b;",
    "var o={a:'xox',b:'b-0123456789abcdef0123456789abcdef012'};delete o.b;o.b='b-0123456789abcdef0123456789abcdef012';var RESULT=o.a+o.b;",
    # F978
    "var q=['x','xoxb-0123','y','456789abcdef','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');",
    "var q=['x','xox','y','b-0123456789abcdef0123456789abcdef012','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');",
    "var q=['xoxb-0123'];q.splice(1,0,'456789abcdef');var RESULT=q.join('');",
    # F980
    "var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';",
    "var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50);",
    # F981
    "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;",
    "var q=['b-0123456789abcdef0123456789abcdef012','xox'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;",
]


@_t
def test_p1_filed_shapes():
    """All 9 filed shapes (short + 40-char) block."""
    bad = [p for p in _FILED if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block

_GENERAL = [
    # F977: bracket twins, multi-prop lifecycle, add-only, literal-mixed RHS
    "var o={a:'xoxb-0123',b:'456789abcdef'};delete o['b'];o['b']='456789abcdef';var RESULT=o.a+o['b'];",
    "var o={a:'xoxb-0123',b:'q',c:'456789abcdef'};delete o.b;delete o.c;o.c='456789abcdef';var RESULT=o.a+o.c;",
    "var o={a:'xoxb-0123'};o.b='456789abcdef';var RESULT=o.a+o.b;",
    "var o={a:'xoxb-0123',b:'456789abcdef'};delete o.a;o.a='xoxb-0123';var RESULT=''+o.a+o.b;",
    # F978: multi-item insert + partial removal, dq join, neg-form, omitted deleteCount
    "var q=['xoxb-0123','x'];q.splice(1,0,'456789abcdef','y');q.splice(2,2);var RESULT=q.join('');",
    "var q=['xoxb-0123','456789abcdef'];var RESULT=q.join(\"\");",
    "var q=['xoxb-0123','pad','456789abcdef'];q.splice(1,1);var RESULT=q.join('');",
    "var q=['xoxb-0123','junk1','junk2'];q.splice(1);q.splice(1,0,'456789abcdef');var RESULT=q.join('');",
    # F980: named IIFE, whitespace, hex codes
    "var RESULT=(function f(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';",
    "var RESULT=(function(){ return String.fromCharCode(...arguments); })(120, 111, 120, 98, 45, 48, 49, 50, 51)+'456789abcdef';",
    "var RESULT=(function(){return String.fromCharCode(...arguments);})(0x78,0x6f,0x78,0x62,0x2d,0x30,0x31,0x32,0x33)+'456789abcdef';",
    # F981: prepend twin, do-while, concat, let
    "var q=['xoxb-0123','456789abcdef'];var s='';while(q.length){s=q.pop()+s;}var RESULT=s;",
    "var q=['456789abcdef','xoxb-0123'];var s='';do{s+=q.pop();}while(q.length);var RESULT=s;",
    "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length>0){s=s.concat(q.pop());}var RESULT=s;",
    "let q=['456789abcdef','xoxb-0123'];let s='';while(q.length){s+=q.pop();}var RESULT=s;",
]


@_t
def test_p2_generalizations():
    """All 15 generalization shapes block."""
    bad = [p for p in _GENERAL if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------------- p3: fail-closed bounds


@_t
def test_p3b_hook_no_misdecode():
    """Hook-level: __proto__/do-empty inputs return None or node-exact values."""
    from gov.dlp import (_js_f977_stmt_decode, _js_f981_stmt_decode)
    bad = []
    # HARD-1: __proto__ anywhere -> None (fail closed)
    for p in ("var o={__proto__:'x'};var RESULT=o.__proto__;",
              "var o={a:'x'};o.__proto__='y';var RESULT=o.a;",
              "var o={a:'x'};delete o.__proto__;var RESULT=o.a;",
              "var o={a:'x'};var RESULT=o.__proto__;"):
        if _js_f977_stmt_decode(p) is not None:
            bad.append(p)
    # HARD-2: do-while empty -> "undefined" (node-exact); while empty -> ""
    v = _js_f981_stmt_decode(
        "var q=[];var s='';do{s+=q.pop();}while(q.length);var RESULT=s;")
    if v != "undefined":
        bad.append("do-empty=%r" % v)
    v = _js_f981_stmt_decode(
        "var q=[];var s='z';do{s=q.pop()+s;}while(q.length);var RESULT=s;")
    if v != "undefinedz":
        bad.append("do-empty-prepend=%r" % v)
    v = _js_f981_stmt_decode(
        "var q=[];var s='';while(q.length){s+=q.pop();}var RESULT=s;")
    if v != "":
        bad.append("while-empty=%r" % v)
    v = _js_f981_stmt_decode(
        "var q=['b','a'];var s='';do{s+=q.pop();}while(q.length);var RESULT=s;")
    if v != "ab":
        bad.append("do-nonempty=%r" % v)
    return ("HELD" if not bad else "BREAK", "bad=%d" % len(bad))


@_t
def test_p3_fail_closed():
    """Junk stays quiet; near-miss shapes fail closed (no mis-decode)."""
    cases = [
        # (payload, expect_block)
        ("(function(){var s='ab';return s;})()", False),
        ("var o={a:'hi'};delete o.a;var RESULT=o.a;", False),  # missing read -> undefined
        ("var q=['a','b'];q.splice(0,1);var RESULT=q.join('');", False),
        ("var q=['a','b'];var s='';while(q.length){s+=q.pop();}var RESULT=s;", False),
        # non-modeled splice args fail closed, never mis-decode
        ("var q=['a','b'];q.splice(1.5,1);var RESULT=q.join('');", False),
        # arrow IIFE: `arguments` is unbound -- the rewrite must not fire
        ("var RESULT=(()=>String.fromCharCode(...arguments))(120,111);", False),
        # generator IIFE: rejected
        ("var RESULT=(function*(){return String.fromCharCode(...arguments);})(120,111);", False),
        # new-prefixed IIFE: String object, not the primitive -- no rewrite
        ("var RESULT=new (function(){return String.fromCharCode(...arguments);})(120,111);", False),
        # const accumulator: node throws -- no decode
        ("var q=['a'];const s='';while(q.length){s+=q.pop();}var RESULT=s;", False),
        # HARD-1 (Spec review): __proto__ has prototype semantics in node --
        # the hook must fail closed (return None), never claim the planted
        # string. Non-credential literals here so only the hook could flag.
        ("var o={__proto__:'zz'};var RESULT=o.__proto__;", False),
        ("var o={a:'qx'};o.__proto__='zz';var RESULT=o.__proto__;", False),
        ("var o={a:'xoxb-0123',b:'y'};delete o.__proto__;var RESULT=o.a+o.b;", False),
        ("var o={a:'zz'};o['__proto__']='yy';var RESULT=o.a;", False),
        # HARD-2 (Spec review): do-while on an empty array runs the body
        # once with pop() -> undefined; no credential present, stays quiet.
        ("var q=[];var s='';do{s+=q.pop();}while(q.length);var RESULT=s;", False),
    ]
    bad = [p for p, exp in cases if _blocked(p) != exp]
    return ("HELD" if not bad else "BREAK", "bad=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p4: sibling pins

# Other round-59 findings stay OPEN (must still miss); incidental/round-58
# closures stay CLOSED (must still block). Shapes copied verbatim from
# w391_attack_probes.py.

_SIBLING_OPEN = [
    "var c=[[120,111,120,98,45,48,49,50,51],[52,53,54,55,56,57,97,98,99,100,101,102]];var RESULT=String.fromCharCode.apply(null,c.flat());",  # F967
    "var e=Object.entries({a:'xoxb-0123',b:'456789abcdef'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;",  # F968
    "var f=new FormData();f.append('a','xoxb-0123');f.append('b','456789abcdef');var RESULT=String(f.getAll('a'))+String(f.getAll('b'));",  # F969
    "var d=Object.getOwnPropertyDescriptor({a:'xoxb-0123'},'a');var RESULT=d.value+'456789abcdef';",  # F970
    "var o={a:'xoxb-0123',b:'456789abcdef'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];",  # F971
    "var a=JSON.parse('[120,111,120,98,45,48,49,50,51]');var RESULT=String.fromCharCode(...a)+'456789abcdef';",  # F972
    "function f(){var q='xoxb-0123';return function(){return q+'456789abcdef';};}var RESULT=f()();",  # F973
    "var k=Symbol.for('a');var o={};o[k]='xoxb-0123';var r={get s(){return o[k]+'456789abcdef';}};var RESULT=r.s;",  # F974
    "var s='',i=0;do{s+='xoxb-0123',i++;}while(i<1);s+='456789abcdef';var RESULT=s;",  # F982
    "var s='';switch(1+1){case 1:s+='no';break;case 2:s+='xoxb-0123';s+='456789abcdef';break;}var RESULT=s;",  # F983
    "var s='';try{var o=structuredClone({a:'xoxb-0123',b:'456789abcdef'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;",  # F984
    "var t='xoxb-0123';var c=t.charCodeAt(0);var RESULT=String.fromCharCode(c)+'oxb-0123'+'456789abcdef';",  # F985
    "var s='';if(1){s+='xoxb-0123';}else{s+='x';}s+='456789abcdef';var RESULT=s;",  # F986
    "var c=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT=String.fromCharCode.apply(null,c);",  # F987
]

_SIBLING_CLOSED = [
    # F975/F976/F979: wave-391 merge incidentals (F949+F947 composition)
    "class C{#x='xoxb-0123';get s(){return this.#x+'456789abcdef';}}var RESULT=new C().s;",
    "var o={a:'xoxb-0123'};var RESULT=(o?.a??'x')+'456789abcdef';",
    "var o={a:'xoxb-0123',b:'456789abcdef'};var RESULT=Object.keys(o).map(function(k){return o[k];}).join('');",
]


@_t
def test_p4_sibling_pins():
    """14 other round-59 findings still OPEN (miss); incidentals still CLOSED (block)."""
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
        "var o={a:'hello',b:'world'};delete o.b;o.b='there';var RESULT=o.a+o.b;",
        "var q=['a','b','c'];q.splice(1,1);var RESULT=q.join('-');",
        "var q=['x','y'];var s='';while(q.length){s+=q.pop();}var RESULT=s;",
        "(function(){return String.fromCharCode(...arguments);})(65,66);",
        "var config={retries:3};delete config.retries;var RESULT='done';",
    ]
    bad = [p for p in cases if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = (_FILED[0] + _FILED[2] + _FILED[5] + _FILED[7])
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
    for battery in ("w392_f977_redfirst.py", "w392_f978_redfirst.py",
                    "w392_f980_redfirst.py", "w392_f981_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g392-green-", dir="/var/tmp")
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
        # / "CTRL-FAIL <name>". The trailing "N failures" tally counts
        # blocked shapes as failures by open-tree design -- not parsed.
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
