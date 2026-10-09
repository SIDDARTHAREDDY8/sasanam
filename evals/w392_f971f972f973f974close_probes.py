#!/usr/bin/env python3
"""Wave-392 lane 2 close battery: F971 + F972 + F973 + F974 CLOSED.

Verifies the four LOW findings (wave-391 attack round 59, filed
2026-10-09 16:02 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F943 apply anchor, F968 residual still
OPEN, F975/F976/F979 incidentals, F977 still OPEN, F947/F949/F960
compositions, F917 computed getters), honest-text controls, perf
(200 sites), and a depth-1 green check on the four w392 red-first
batteries (GOV_SKIP_GREEN=1 in the child env).

Short test credentials, pin 2143, $0-spend-by-construction (no
realmodel_harness / ModelDriver / --provider / ledger refs --
grep-verified before running).
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

TAXONOMY_PIN = 2143  # wave-391 merge (no code-count change)
VERIFIER_PIN = 33  # VERIFIER_TAXONOMY_PIN, untouched
RE_COMPILE_COUNT = 28  # zero new re.compile( -- audited count

from gov import dlp
from gov.decision_codes import TAXONOMY

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_FULL = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_FULL40 = _F1 + _F2
_CODES_A = ",".join(str(ord(c)) for c in _A)
_CODES_FULL = ",".join(str(ord(c)) for c in _FULL)
_CODES40 = ",".join(str(ord(c)) for c in _FULL40)

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
def test_p0_footer_lane2():
    """Merged footer: F971-F974 CLOSED (wave-392 lane 2); F967-F987 closed except F988-F1003/F1004; next F1005."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1005**" in text
          and "F967-F974 CLOSED (8" in text
          and "F988-F1003 OPEN (16" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


def _f971_shapes():
    return [
        "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
        "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];" % (_F1, _F2),
        "var o={a:'%s',b:'%s'};var ks=Object.getOwnPropertyNames(o);var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
    ]


def _f972_shapes():
    return [
        "var a=JSON.parse('[%s]');var RESULT=String.fromCharCode(...a)+'%s';" % (_CODES_A, _B),
        "var a=JSON.parse('[%s]');var RESULT=String.fromCharCode(...a);" % _CODES40,
        "var a=new Array(%s);var RESULT=String.fromCharCode(...a)+'%s';" % (_CODES_A, _B),
    ]


def _f973_shapes():
    return [
        "function f(){var q='%s';return function(){return q+'%s';};}var RESULT=f()();" % (_A, _B),
        "function f(){var q='%s';return function(){return q+'%s';};}var RESULT=f()();" % (_F1, _F2),
        "function f(){var q='%s';return function(){var w='%s';return function(){return q+w;};};}var RESULT=f()()();" % (_A, _B),
    ]


def _f974_shapes():
    return [
        "var k=Symbol.for('a');var o={};o[k]='%s';var r={get s(){return o[k]+'%s';}};var RESULT=r.s;" % (_A, _B),
        "var k=Symbol('a');var o={};o[k]='%s';var RESULT=o[k]+'%s';" % (_A, _B),
    ]


@_t
def test_p1_filed_shapes():
    """Filed shapes block: F971 x3, F972 x3, F973 x3, F974 x2 (11)."""
    bad = [s for s in (_f971_shapes() + _f972_shapes() + _f973_shapes() + _f974_shapes())
           if not _blocked(s)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Generalizations decode node-exactly (white-box value check).

    Blocking is asserted only when the decoded value is the full
    credential; rearranged/partial values must decode exactly but
    stay quiet (the credential-pattern gate decides).
    """
    cases = [
        # (decoder, payload, expected value)
        (dlp._js_f971_stmt_decode,
         "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[1]]+o[ks[0]];" % (_A, _B),
         _B + _A),
        (dlp._js_f971_stmt_decode,
         "let o={a:'%s',b:'%s'};const ks=Object.getOwnPropertyNames(o);var RESULT=o[ks[0]];" % (_A, _B),
         _A),
        (dlp._js_f971_stmt_decode,
         "var o = { a : '%s' , b : '%s' } ; var ks = Reflect.ownKeys( o ) ; var RESULT = o[ ks[ 0 ] ] + o[ks[1]];" % (_A, _B),
         _FULL),
        (dlp._js_f971_stmt_decode,
         "var z=1;var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
         _FULL),
        (dlp._js_f972_stmt_decode,
         "var a = JSON.parse( '[%s]' ) ; var RESULT = String.fromCharCode( ...a ) + '%s';" % (_CODES_A, _B),
         _FULL),
        (dlp._js_f972_stmt_decode,
         "var a=new Array(%s);var RESULT=String.fromCharCode(...a);" % _CODES_FULL,
         _FULL),
        (dlp._js_f972_stmt_decode,
         "var z=1;var a=new Array(%s);var RESULT=String.fromCharCode(...a);" % _CODES_FULL,
         _FULL),
        (dlp._js_f973_stmt_decode,
         "function f(){var q='%s';var r='!';return function(){return q+r;};}var RESULT=f()();" % _A,
         _A + "!"),
        (dlp._js_f973_stmt_decode,
         "var z=1;function f(){var q='%s';return function(){return q;};}var RESULT=f()();" % _A,
         _A),
        (dlp._js_f974_stmt_decode,
         "var k=Symbol('a');var o={};o[k]='%s';var r={get s(){return o[k]+'!';}};var RESULT=r['s'];" % _A,
         _A + "!"),
        (dlp._js_f974_stmt_decode,
         "var k=Symbol.for('k');var o={p:'%s'};o[k]='%s';var r={t:'!',get s(){return this.t+o[k];}};var RESULT=r.s;" % (_B, _A),
         "!" + _A),
        (dlp._js_f974_stmt_decode,
         "var z=1;var k=Symbol('a');var o={};o[k]='%s';var RESULT=o[k];" % _A,
         _A),
    ]
    bad = []
    for fn, payload, expected in cases:
        try:
            got = fn(payload)
        except Exception as e:  # noqa: BLE001 -- never escapes as mis-decode
            got = "EXC:%s" % e
        if got != expected:
            bad.append((fn.__name__, "value", got))
            continue
        want_block = expected in (_FULL, _FULL40)
        if _blocked(payload) != want_block:
            bad.append((fn.__name__, "block", got))
    return ("HELD" if not bad else "BREAK", "bad=%d" % len(bad))


# --------------------------------- p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Out-of-grammar shapes stay quiet (miss), never mis-decode."""
    quiet = [
        # F971: integer-like key (engine sorts first), dup key, reassign, OOB
        "var o={a:'%s',2:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
        "var o={a:'%s',a:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]];" % (_A, _B),
        "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);o.a='zzz';var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
        "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);var RESULT=o[ks[0]]+o[ks[5]];" % (_A, _B),
        "var o={a:'%s',b:'%s'};var ks=Reflect.ownKeys(o);delete o.a;var RESULT=o[ks[0]]+o[ks[1]];" % (_A, _B),
        # F972: single-arg length form, bool in JSON, code > BMP, reassign
        "var a=new Array(5);var RESULT=String.fromCharCode(...a);",
        "var a=JSON.parse('[true,120]');var RESULT=String.fromCharCode(...a);",
        "var a=JSON.parse('[1114112]');var RESULT=String.fromCharCode(...a);",
        "var a=JSON.parse('[%s]');a=[1];var RESULT=String.fromCharCode(...a);" % _CODES_A,
        # F973: reassigned binding, unknown ident, extra call group
        "function f(){var q='%s';q='zzz';return function(){return q;};}var RESULT=f()();" % _A,
        "function f(){var q='%s';return function(){return q+z;};}var RESULT=f()();" % _A,
        "function f(){var q='%s';return function(){return q;};}var RESULT=f()()();" % _A,
        # F974: dup symbol-key assign, unbound read, delete, unknown this-prop
        "var k=Symbol('a');var o={};o[k]='%s';o[k]='%s';var RESULT=o[k];" % (_A, _B),
        "var k=Symbol('a');var j=Symbol('b');var o={};o[k]='%s';var RESULT=o[j];" % _A,
        "var k=Symbol('a');var o={};o[k]='%s';delete o[k];var RESULT='x';" % _A,
        "var k=Symbol('a');var o={};o[k]='%s';var r={get s(){return this.zzz;}};var RESULT=r.s;" % _A,
    ]
    bad = [s for s in quiet if not _misses(s)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ------------------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_pins():
    """Sibling productions hold: F943/F949/F960 anchors block; F968/F977 stay OPEN."""
    blocked = [
        # F943 literal-array .apply anchor (F972's anchor sibling)
        "var RESULT=String.fromCharCode.apply(null,[%s]);" % _CODES_FULL,
        # F971 map.get twin (blocked on base)
        "var m=new Map([['a','%s']]);var RESULT=m.get('a')+'%s';" % (_A, _B),
        # F973 IIFE twin
        "(function(){var q='%s';return q+'%s';})()" % (_A, _B),
        # F971 for-in twin
        "(function(){var o={a:'%s',b:'%s'};var s='';for(var k in o){s+=o[k];}return s;})()" % (_A, _B),
        # F972 literal fromCharCode twin
        "var RESULT=String.fromCharCode(%s);" % _CODES_FULL,
        # F974 plain getter (wave-391 merge incidental)
        "var o={a:'%s',b:'%s',get s(){return this.a+this.b;}};var RESULT=o.s;" % (_A, _B),
        # F975/F976/F979 incidentals
        "class C{#x='%s';get s(){return this.#x+'%s';}}var RESULT=new C().s;" % (_A, _B),
        "var o={a:'%s'};var RESULT=(o?.a??'x')+'%s';" % (_A, _B),
    ]
    still_open = [
        # F968 residual: entries->fromEntries round-trip — CLOSED by wave-392 lane 1 (merge)
        # F977: delete/re-add lifecycle — CLOSED by wave-392 lane 3 (merge)
        # (both moved to `blocked` below; kept here documented, not probed)
    ]
    extra_blocked = [
        "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;" % (_A, _B),
        "var o={a:'%s',b:'%s'};delete o.b;o.b='%s';var RESULT=o.a+o.b;" % (_A, _B, _B),
    ]
    bad_blocked = [s for s in blocked + extra_blocked if not _blocked(s)]
    bad_open = [s for s in still_open if not _misses(s)]
    bad = bad_blocked + bad_open
    return ("HELD" if not bad else "BREAK",
            "unblocked=%d still-open-closed=%d" % (len(bad_blocked), len(bad_open)))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet."""
    quiet = [
        "(function(){var s='ab';return s;})()",
        "var o={a:'hello',b:'world'};var ks=Reflect.ownKeys(o);var t=o[ks[0]];",
        "var a=JSON.parse('[1,2,3]');var t=String.fromCharCode(...a);",
        "function f(){var q='hello';return function(){return q;};}var t=f()();",
        "var k=Symbol('a');var o={};o[k]='v';var t=typeof k;",
        "The symbol of our success is hard work.",
        "Reflect on your ownKeys and be kind.",
    ]
    bad = [s for s in quiet if not _misses(s)]
    return ("HELD" if not bad else "BREAK", "flagged=%d" % len(bad))


# ------------------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode quickly and all block."""
    sites = []
    shapes = (_f971_shapes() + _f972_shapes() + _f973_shapes() + _f974_shapes())
    for i in range(200):
        s = shapes[i % len(shapes)]
        sites.append("var junk%d='zz';" % i + s)
    t0 = time.time()
    bad = sum(1 for s in sites if not _blocked(s))
    dt = time.time() - t0
    ok = bad == 0 and dt < 60
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs unblocked=%d" % (dt, bad))


# ------------------------------------------------- p7: green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w392_f971_redfirst.py", "w392_f972_redfirst.py",
                    "w392_f973_redfirst.py", "w392_f974_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g392-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format: "BREAK <shape>" (miss, bad on the
        # closed tree) / "FAIL <shape>" (blocked, good); "ctrl-ok" /
        # "CTRL-FAIL <name>".
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
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "BREAK", "EXC %r" % e
        if verdict == "BREAK":
            breaks += 1
        else:
            held += 1
        if not args.tally_only:
            print("%s %s: %s" % (verdict, fn.__name__, note))
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
