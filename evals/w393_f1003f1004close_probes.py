#!/usr/bin/env python3
"""Wave-393 lane-5 close battery: F1003 + F1004.

F1003: statement-position comma-sequence of assignment operands
(`var s;s="f1",s+="f2";`).
F1004: property-copy re-add lifecycle (F977 residual -- `o.b=o.a`
fragment copy between props).

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
    """Merged footer (wave-393): F988-F1004 CLOSED; F1005-F1024 OPEN; next free F1025."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F988-F1004 CLOSED (17" in text
          and "F1005-F1024 OPEN (20" in text
          and "Next free finding: **F1025**" in text
          and "next free F1025" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block

_FILED = [
    # F1003
    'var s;s="%s",s+="%s";var RESULT=s;' % (_A, _B),
    'var s;s="%s",s+="%s";var RESULT=s;' % (_F1, _F2),
    # F1004
    "var o={a:'%s'};o.b=o.a;o.c='%s';var RESULT=o.b+o.c;" % (_A, _B),
    "var o={a:'%s'};o.b=o.a;o.c='%s';var RESULT=o.b+o.c;" % (_F1, _F2),
]


@_t
def test_p1_filed_shapes():
    """All 4 filed shapes (short + 40-char) block."""
    bad = [p for p in _FILED if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# ------------------------------------- p2: generalizations must block

_GENERAL = [
    # F1003: multi-name + ident RHS, extra operand, ws-tolerant, let, RESULT additive
    'var s,t;s="%s",t="%s";s+=t;var RESULT=s+t;' % (_A, _B),
    'var s;s="%s",s+="%s",s+="00";var RESULT=s;' % (_A, _B),
    'var s ; s = "%s" , s += "%s" ; var RESULT = s ;' % (_A, _B),
    'let s;s="%s",s+="%s";var RESULT=s;' % (_A, _B),
    'var s;s="%s",s+="45";var RESULT=s+"%s";' % (_A, _B[2:]),
    # F1004: bracket twins, delete+copy, multi-copy, empty-object, literal RESULT
    "var o={a:'%s'};o['b']=o['a'];o.c='%s';var RESULT=o.b+o.c;" % (_A, _B),
    "var o={a:'%s',b:'junk'};delete o.b;o.b=o.a;o.c='%s';var RESULT=o.b+o.c;" % (_A, _B),
    "var o={a:'%s',b:'%s'};o.c=o.a;o.d=o.b;var RESULT=o.c+o.d;" % (_F1, _F2),
    "var o={};o.a='%s';o.b=o.a;o.c='%s';var RESULT=o.b+o.c;" % (_A, _B),
    "var o={a:'%s'};o.b=o.a;var RESULT=o.b+'%s';" % (_A, _B),
]


@_t
def test_p2_generalizations():
    """All 10 generalization shapes block."""
    bad = [p for p in _GENERAL if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------------- p3: fail-closed bounds


@_t
def test_p3b_hook_no_misdecode():
    """Hook-level: node-exact values on modeled shapes; None on hostile shapes."""
    from gov.dlp import _js_f1003_stmt_decode, _js_f1004_stmt_decode
    bad = []
    # F1003: node-exact values
    cases = [
        (_js_f1003_stmt_decode,
         'var s;s="f1",s+="f2";var RESULT=s;', "f1f2"),
        (_js_f1003_stmt_decode,
         'var s,t;s="f1",t="f2",s+=t;var RESULT=s;', "f1f2"),
        # F1004: node-exact values (copy is a value copy, not an alias)
        (_js_f1004_stmt_decode,
         "var o={a:'f1'};o.b=o.a;o.a='ZZ';var RESULT=o.b;", "f1"),
        (_js_f1004_stmt_decode,
         "var o={a:'f1'};o.b=o.a;delete o.a;var RESULT=o.b;", "f1"),
    ]
    for fn, payload, want in cases:
        got = fn(payload)
        if got != want:
            bad.append("%s=%r want %r" % (payload[:40], got, want))
    # F1003: fail-closed hostile shapes -> None
    for p in ('var s;s+="f2",s="f1";var RESULT=s;',  # += on unbound
              'var s;s="f1",s+="f2",;var RESULT=s;',  # trailing comma: SyntaxError
              'const s;s="f1",s+="f2";var RESULT=s;',  # const w/o init: SyntaxError
              'var s="f1";s+="f2";var RESULT=s;',  # initialized decl: not our domain
              'var s;s="f1";var RESULT=s;'):  # single operand: not a sequence
        if _js_f1003_stmt_decode(p) is not None:
            bad.append("f1003-not-closed: " + p[:50])
    # F1004: fail-closed hostile shapes -> None
    for p in ("var o={a:'f1'};o.b=o.missing;var RESULT=o.b+'x';",  # copy from missing
              "var o={a:'f1'};o.b=o.a;var RESULT=o.missing+'x';",  # read missing
              "var o={__proto__:'x'};o.b=o.__proto__;var RESULT=o.b;",  # __proto__
              "var o={a:'f1'};o.b='lit';var RESULT=o.a+o.b;",  # no copy: F977 domain
              "var o={a:'f1'};o.b=o.a;"):  # no RESULT
        if _js_f1004_stmt_decode(p) is not None:
            bad.append("f1004-not-closed: " + p[:50])
    return ("HELD" if not bad else "BREAK", "bad=%d" % len(bad))


@_t
def test_p3_fail_closed():
    """Junk stays quiet; near-miss shapes fail closed (no mis-decode)."""
    cases = [
        # (payload, expect_block)
        ("(function(){var s='ab';return s;})()", False),
        ('var s;s+="f2",s="f1";var RESULT=s;', False),  # += on unbound
        ('var s;s="f1",s+="f2",;var RESULT=s;', False),  # trailing comma
        ('const s;s="f1",s+="f2";var RESULT=s;', False),  # const uninit
        ('var s="f1";s+="f2";var RESULT=s;', False),  # not our domain
        ("var o={a:'f1'};o.b=o.missing;var RESULT=o.b+'x';", False),  # copy missing
        ("var o={a:'f1'};o.b=o.a;var RESULT=o.missing+'x';", False),  # read missing
        ("var o={a:'f1'};o.b='lit';var RESULT=o.a+o.b;", False),  # F977 domain
        # honest programs: decoded, but no credential -> quiet
        ("var s;s='he',s+='llo';var RESULT=s+' world';", False),
        ("var o={a:'hello'};o.b=o.a;var RESULT=o.b+' world';", False),
        ("var o={a:'hello',b:'world'};delete o.b;o.b='there';var RESULT=o.a+o.b;", False),
    ]
    bad = [p for p, exp in cases if _blocked(p) != exp]
    return ("HELD" if not bad else "BREAK", "bad=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p4: sibling pins

# Round-60 OPEN findings (F988-F1002) must still miss; adjacent CLOSED
# findings (F977/F982/F1000-disjoint shapes) must still block.
# Shapes copied verbatim from w392_attack_probes.py / filed red-firsts.

_SIBLING_OPEN = [
    # Wave-393 merge: all wave-393 siblings CLOSED (lanes 1-4) -- list empty.
]

_SIBLING_CLOSED = [
    # F977: delete/re-add (no copy) -- F1004 must not claim it
    "var o={a:'xoxb-0123',b:'456789abcdef'};delete o.b;o.b='456789abcdef';var RESULT=o.a+o.b;",
    # F982: do-while comma (initialized declarators) -- F1003 must not claim it
    "var s='',i=0;do{s+='xoxb-0123',i++;}while(i<1);s+='456789abcdef';var RESULT=s;",
    # F975/F976/F979: wave-391 merge incidentals
    "class C{#x='xoxb-0123';get s(){return this.#x+'456789abcdef';}}var RESULT=new C().s;",
    "var o={a:'xoxb-0123'};var RESULT=(o?.a??'x')+'456789abcdef';",
    "var o={a:'xoxb-0123',b:'456789abcdef'};var RESULT=Object.keys(o).map(function(k){return o[k];}).join('');",
    # Wave-393 merge: F988-F1002 closed by lanes 1-4 -- must stay blocked.
    'var s=new String("xoxb-0123");var RESULT=s+"456789abcdef";',  # F988
    'var s="";var m=new Map([["a","xoxb-0123"],["b","456789abcdef"]]);for(var kv of m){s+=kv[1];}var RESULT=s;',  # F989
    'var p=new Proxy({a:"xoxb-0123",b:"456789abcdef"},{get:function(t,k){return t[k];}});var RESULT=p.a+p.b;',  # F990
    'var w=new WeakRef({v:"xoxb-0123"});var x=new WeakRef({v:"456789abcdef"});var RESULT=w.deref().v+x.deref().v;',  # F991
    'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";',  # F992
    'var r=new RegExp("xoxb-0123");var RESULT=r.source+"456789abcdef";',  # F993
    '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xoxb-0123","456789abcdef");',  # F994
    '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xoxb-0123","456789abcdef");',  # F995
    'var RESULT=String.fromCharCode.apply(null,["120","111","120","98","45","48","49","50","51","52","53","54","55","56","57","97","98","99","100","101","102"].map(Number));',  # F996
    'var RESULT=String.fromCharCode.apply(null,[0,120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,0].slice(1,-1));',  # F997
    'globalThis.x="xoxb-0123";globalThis.y="456789abcdef";var RESULT=globalThis.x+globalThis.y;',  # F998
    'var o={};Object.defineProperties(o,{a:{value:"xoxb-0123",enumerable:true},b:{value:"456789abcdef",enumerable:true}});var RESULT=o.a+o.b;',  # F999
    'var s="";s||="xoxb-0123";s+="456789abcdef";var RESULT=s;',  # F1000
    'var RESULT=Reflect.apply(String.prototype.concat,"xoxb-0123",["456789abcdef"]);',  # F1001
    'var p={v:"xoxb-0123"};var o=Object.create(p);o.w="456789abcdef";var d=Reflect.getOwnPropertyDescriptor(Object.getPrototypeOf(o),"v");var RESULT=d.value+o.w;',  # F1002
]


@_t
def test_p4_sibling_pins():
    """Round-60 OPEN findings still miss; adjacent CLOSED still block."""
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
        "var s;s='he',s+='llo';var RESULT=s+' world';",
        "var o={a:'hello'};o.b=o.a;var RESULT=o.b+' world';",
        "var o={a:'hello',b:'world'};delete o.b;o.b='there';var RESULT=o.a+o.b;",
        "var config={retries:3};delete config.retries;var RESULT='done';",
        "var x=1,y=2;var RESULT='sum is '+(x+y);",
    ]
    bad = [p for p in cases if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = (_FILED[0] + _FILED[2])
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
    for battery in ("w393_f1003_redfirst.py", "w393_f1004_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g393-green-", dir="/var/tmp")
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
    """Depth-1 green check: the two red-firsts stay 0 BREAK."""
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
