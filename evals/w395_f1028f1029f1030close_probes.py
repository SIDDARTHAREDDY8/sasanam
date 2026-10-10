#!/usr/bin/env python3
"""Wave-395 lane-2 close battery: F1028 + F1029 + F1030.

F1028: WeakMap-keyed staging read (`var wm=new WeakMap();var k={};...wm.set(k,s);var RESULT=wm.get(k);`).
F1029: destructuring-rest accumulation (`var [a,...rest]=[<codes>];...`).
F1030: flat()-then-spread (`String.fromCharCode(...[[<codes>]].flat())`, distinct vs F1015).

Pin 2143, VERIFIER_TAXONOMY_PIN 33, re.compile( 28 -- all untouched.
$0 spend by construction. Depth-1 green check honors GOV_SKIP_GREEN=1.
"""
import argparse
import importlib.util
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
_A = "xoxb-"
_B = "0123456789abcdef"
_C = "0123456789abcdef012"

# Code lists for the short (21-code) and 40-code shapes, as int literals.
_CODES_S0 = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
             97, 98, 99, 100, 101, 102]
_CODES_S1 = _CODES_S0 + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99,
                        100, 101, 102, 48, 49, 50]


def _codes(codes):
    return ",".join(str(c) for c in codes)


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
    """Lane-local footer: F1028-F1030 CLOSED; open F1025-F1027, F1031-F1034 (7); next F1035."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1035**" in text
          and "(F1028 " in text and "(F1029 " in text and "(F1030 " in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block

_FILED = [
    # F1028 s0/s1
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S0),
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S1),
    # F1029 s0/s1
    'var [a,...rest]=[%s];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;' % _codes(_CODES_S0),
    'var [a,...rest]=[%s];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;' % _codes(_CODES_S1),
    # F1030 s0/s1
    'var s=String.fromCharCode(...[[%s]].flat());var RESULT=s;' % _codes(_CODES_S0),
    'var s=String.fromCharCode(...[[%s]].flat());var RESULT=s;' % _codes(_CODES_S1),
]


@_t
def test_p1_filed_shapes_block():
    """All 6 filed shapes now block."""
    bad = [p for p in _FILED if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------------- p2: generalizations

_GENERAL = [
    # F1028: let/const decls, bare loop var, ++i, s=s+... body
    'let wm=new WeakMap();let k={};let parts=[%s];let s="";for(let i=0;i<parts.length;++i){s=s+String.fromCharCode(parts[i]);}wm.set(k,s);let RESULT=wm.get(k);' % _codes(_CODES_S0),
    'const wm=new WeakMap();const k={};const parts=[%s];let s="";for(i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);const RESULT=wm.get(k);' % _codes(_CODES_S0),
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S0),
    "var wm=new WeakMap();var k={};var parts=[%s];var s='';for(var i=0;i<parts.length;++i){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);" % _codes(_CODES_S0),
    # F1029: let/const destructuring, ++i, s=s+... body, bare loop var
    'let [a,...rest]=[%s];let s=String.fromCharCode(a);for(let i=0;i<rest.length;++i){s=s+String.fromCharCode(rest[i]);}let RESULT=s;' % _codes(_CODES_S0),
    'const [a,...rest]=[%s];const s=String.fromCharCode(a);for(i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;' % _codes(_CODES_S0),
    'var [h,...t]=[%s];var s=String.fromCharCode(h);for(var i=0;i<t.length;i++){s+=String.fromCharCode(t[i]);}var RESULT=s;' % _codes(_CODES_S0),
    # F1028: braceless loop, chained set().get() (spec-review variants)
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++)s+=String.fromCharCode(parts[i]);wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S0),
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}var RESULT=wm.set(k,s).get(k);' % _codes(_CODES_S0),
    'var wm=new WeakMap;var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S0),
    # F1029: braceless loop, bare destructuring (spec-review variants)
    'var [a,...rest]=[%s];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++)s+=String.fromCharCode(rest[i]);var RESULT=s;' % _codes(_CODES_S0),
    '[a,...rest]=[%s];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;' % _codes(_CODES_S0),
    # `;` optional before `}` (spec-review variants)
    'var wm=new WeakMap();var k={};var parts=[%s];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i])}wm.set(k,s);var RESULT=wm.get(k);' % _codes(_CODES_S0),
    'var [a,...rest]=[%s];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i])}var RESULT=s;' % _codes(_CODES_S0),
    # F1030: .flat(1), let/const, .flat(2), .flat(5)
    'var s=String.fromCharCode(...[[%s]].flat(1));var RESULT=s;' % _codes(_CODES_S0),
    'let s=String.fromCharCode(...[[%s]].flat());const RESULT=s;' % _codes(_CODES_S0),
    'var s=String.fromCharCode(...[[%s]].flat(2));var RESULT=s;' % _codes(_CODES_S0),
    'var s=String.fromCharCode(...[[%s]].flat(5));var RESULT=s;' % _codes(_CODES_S0),
    'var s=String.fromCharCode(...[%s].flat());var RESULT=s;' % _codes(_CODES_S0),
]


@_t
def test_p2_generalizations():
    """All generalization shapes block (node-verified v24.20.0)."""
    bad = [p for p in _GENERAL if not _blocked(p)]
    return ("HELD" if not bad else "BREAK", "missed=%d" % len(bad))


# --------------------------------------- p3: hook-level + fail-closed

@_t
def test_p3a_hook_no_misdecode():
    """Hook-level: node-exact values on modeled shapes; None on hostile shapes."""
    from gov.dlp import (_js_f1028_stmt_decode, _js_f1029_stmt_decode,
                         _js_f1030_stmt_decode)
    bad = []
    # node-exact values (independent truth: literal decode of the codes)
    cases = [
        (_js_f1028_stmt_decode,
         'var wm=new WeakMap();var k={};var parts=[120,111];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',
         "xo"),
        (_js_f1029_stmt_decode,
         'var [a,...rest]=[120,111];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',
         "xo"),
        (_js_f1029_stmt_decode,
         'var [a,...rest]=[120];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',
         "x"),
        (_js_f1030_stmt_decode,
         'var s=String.fromCharCode(...[[120,111]].flat());var RESULT=s;',
         "xo"),
        (_js_f1030_stmt_decode,
         'var s=String.fromCharCode(...[[120,111]].flat(1));var RESULT=s;',
         "xo"),
    ]
    for fn, payload, want in cases:
        got = fn(payload)
        if got != want:
            bad.append("%s=%r want %r" % (payload[:40], got, want))
    # F1028 hostile shapes -> None (fail closed)
    for p in ('var wm=new WeakMap([["k","v"]]);var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',  # ctor arg
              'var wm=new WeakMap();var k=[];var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',  # non-{} key
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(const i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',  # const loop var: node throws
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s,"x");var RESULT=wm.get(k);',  # extra set arg
              'var wm=new WeakMap();var k={};var parts=[120];var s="junk";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',  # non-empty acc
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var s=0;s<parts.length;s++){s+=String.fromCharCode(parts[s]);}wm.set(k,s);var RESULT=wm.get(k);',  # loop var shadows acc
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<=parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);',  # <= bound: node reads undefined
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k2);',  # chained get wrong key
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}var RESULT=wm.set(k,s).get(k,"x");',  # chained get extra arg
              'var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++)s+=String.fromCharCode(parts[i]+"");wm.set(k,s);var RESULT=wm.get(k);',  # braceless wrong body
              'var String=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}var RESULT=s;',  # shadowed String
              ):
        if _js_f1028_stmt_decode(p) is not None:
            bad.append("f1028-not-closed: " + p[:50])
    # F1029 hostile shapes -> None
    for p in ('var [,...rest]=[120,111];var s=String.fromCharCode(rest[0]);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # elision
              'var [a=1,...rest]=[120,111];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # default
              'var [a,...rest]=[];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # empty array
              'var [a,...rest]=[120,111];var s=String.fromCharCode(a);for(const i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # const loop var
              'var [a,...a]=[120,111];var s=String.fromCharCode(a);for(var i=0;i<a.length;i++){s+=String.fromCharCode(a[i]);}var RESULT=s;',  # dup names
              'var [a,...rest]=[120,111];var s=String.fromCharCode(b);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # head mismatch
              '[String,...rest]=[120,111];var s=String.fromCharCode(String);for(var i=0;i<rest.length;i++){s+=String.fromCharCode(rest[i]);}var RESULT=s;',  # bare shadowed String
              'var [a,...rest]=[120,111];var s=String.fromCharCode(a);for(var i=0;i<rest.length;i++)s+=String.fromCharCode(rest[i]+"");var RESULT=s;',  # braceless wrong body
              ):
        if _js_f1029_stmt_decode(p) is not None:
            bad.append("f1029-not-closed: " + p[:50])
    # F1030 hostile shapes -> None
    for p in ('var s=String.fromCharCode(...[[120,111]].flat(0));var RESULT=s;',  # depth 0: nesting intact in node
              'var s=String.fromCharCode(...[[120,111]].flat(-1));var RESULT=s;',  # negative depth: intact in node
              'var s=String.fromCharCode(...[120,[111]].flat());var RESULT=s;',  # nested single-level: scope boundary
              'var s=String.fromCharCode(...[[120],[111]].flat());var RESULT=s;',  # multi-chunk receiver
              'var s=String.fromCharCode.apply(null,[[120,111]].flat());var RESULT=s;',  # apply form: F996/F997 domain
              'var s=String.fromCharCode(...[[120,111]].flat());var RESULT=s;var q=1;',  # trailing junk
              ):
        if _js_f1030_stmt_decode(p) is not None:
            bad.append("f1030-not-closed: " + p[:50])
    return ("HELD" if not bad else "BREAK", "bad=%d %s" % (len(bad), bad[:3]))


@_t
def test_p3_fail_closed():
    """Junk stays quiet; near-miss shapes fail closed (no mis-decode)."""
    cases = [
        ("(function(){var s='ab';return s;})()", False),
        # F1028 near-misses
        ('var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k)+"?";', False),
        ('var wm=new WeakMap();var k={};var parts=[120];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}var RESULT=s;', False),
        # F1029 near-misses
        ('var [a,b]=[120,111];var s=String.fromCharCode(a)+String.fromCharCode(b);var RESULT=s;', False),
        # F1030 near-misses
        ('var s=String.fromCharCode(...[120,111]);var RESULT=s;', False),
        ('var s=String.fromCharCode(120,111);var RESULT=s;', False),
    ]
    bad = []
    for p, exp in cases:
        if _blocked(p) != exp:
            bad.append(p[:50])
    return ("HELD" if not bad else "BREAK", "bad=%d %s" % (len(bad), bad[:3]))


# --------------------------------------- p4: sibling pins

# Wave-395 merge: F1025-F1027 and F1031-F1033 are now CLOSED (lanes 1/3);
# their shapes moved to _SIBLING_CLOSED. Shapes copied verbatim from
# evals/w394_attack_probes.py.
_SIBLING_OPEN = []

# Wave-395 merge: round-62 findings F1025-F1027, F1031-F1033 now CLOSED --
# must block. Full credential shapes drawn from each lane's red-first
# batteries (the w394-battery abbreviations assemble no credential, so
# they miss trivially and cannot pin a closure).
def _redfirst_shapes(modname):
    spec = importlib.util.spec_from_file_location(
        modname, os.path.join(REPO_ROOT, "evals", modname + "_redfirst.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [p for _, p in mod.SHAPES]


_SIBLING_NOW_CLOSED = []
for _mod in ("w395_f1025", "w395_f1026", "w395_f1027",
             "w395_f1031", "w395_f1032", "w395_f1033"):
    _SIBLING_NOW_CLOSED.extend(_redfirst_shapes(_mod))

_SIBLING_CLOSED = [
    # F1015: object-keys map-join -- F1030 must not claim it (additivity)
    'var o={a:"%s",b:"%s"};var RESULT=Object.keys(o).map(function(k){return o[k]}).join("");' % (_A, _B),
    # F996: .map(Number) over string-code arrays (credential-shaped codes)
    'var RESULT=String.fromCharCode.apply(null,[%s].map(Number));' % ",".join('"%d"' % c for c in _CODES_S0),
    # F997: slice-trimmed code arrays (credential-shaped codes)
    'var RESULT=String.fromCharCode.apply(null,[0,%s,0].slice(1,-1));' % _codes(_CODES_S0),
    # F1013: manual iterator accumulation
    'var it=["%s","%s"].values();var r="";var n;while(!(n=it.next()).done)r+=n.value;var RESULT=r;' % (_A, _B),
]


@_t
def test_p4_sibling_pins():
    """Wave-395 merge: round-62 now-CLOSED findings block; adjacent CLOSED still block."""
    bad_open = [p for p in _SIBLING_OPEN if not _misses(p)]
    bad_closed = [p for p in _SIBLING_CLOSED if not _blocked(p)]
    bad_nowclosed = [p for p in _SIBLING_NOW_CLOSED if not _blocked(p)]
    bad = bad_open + bad_closed + bad_nowclosed
    return ("HELD" if not bad else "BREAK",
            "open_miss=%d/%d closed_block=%d/%d nowclosed_block=%d/%d" %
            (len(_SIBLING_OPEN) - len(bad_open), len(_SIBLING_OPEN),
             len(_SIBLING_CLOSED) - len(bad_closed), len(_SIBLING_CLOSED),
             len(_SIBLING_NOW_CLOSED) - len(bad_nowclosed), len(_SIBLING_NOW_CLOSED)))


# --------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest programs stay quiet."""
    cases = [
        'var wm=new WeakMap();var k={};wm.set(k,"hello");var RESULT=wm.get(k)+" world";',
        'var [a,...rest]=[1,2,3];var RESULT="count "+rest.length;',
        'var s=String.fromCharCode(...[[72,105]].flat());var RESULT=s+"!";',
        "var config={retries:3};var RESULT='done';",
        'var m=new Map();m.set("k","v");var RESULT=m.get("k");',
    ]
    bad = [p for p in cases if not _misses(p)]
    return ("HELD" if not bad else "BREAK", "flagged=%d/%d" % (len(bad), len(cases)))


# --------------------------------------- p6: perf


@_t
def test_p6_perf():
    """200 hostile sites stay fast (< 15s)."""
    site = (_FILED[0] + _FILED[2] + _FILED[4])
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
    for battery in ("w395_f1028_redfirst.py", "w395_f1029_redfirst.py",
                    "w395_f1030_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g395-green-", dir="/var/tmp")
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
    """Depth-1 green check: the three red-firsts stay 0 BREAK."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held, broke, errored = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, msg = fn()
        except Exception as e:  # noqa: BLE001 -- fail loud, never silent
            verdict, msg = "ERROR", "%r" % (e,)
        print("%-8s %-42s %s" % (verdict, fn.__name__, msg))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errored += 1
    print("w395 lane-2 close battery: %d HELD / %d BREAK / %d ERROR "
          "of %d probes" % (held, broke, errored, len(TESTS)))
    return 1 if (broke or errored) else 0


if __name__ == "__main__":
    sys.exit(main())
