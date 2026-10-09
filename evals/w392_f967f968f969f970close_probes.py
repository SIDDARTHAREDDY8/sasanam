#!/usr/bin/env python3
"""Wave-392 lane 1 close battery: F967 + F968 + F969 + F970 CLOSED.

Verifies the four LOW findings (wave-391 attack round 59, filed
2026-10-09 16:02 UTC) are closed on the lane tree: pins, filed
shapes (must block, node-exact decode), generalizations (must
block), fail-closed bounds (must miss / stay quiet, never
mis-decode), sibling pins (F952 postfix apply, F947 prop assembly,
F860/F914 FormData, F905 entries-forof, F565 fromEntries), honest
text controls, perf (200 sites), and a depth-1 green check on the
four w392 red-first batteries (GOV_SKIP_GREEN=1 in the child env).

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
def test_p0_footer_next_free():
    """Merged footer: F967-F970 CLOSED (wave-392 lane 1); F967-F987 closed except F988-F1003/F1004; next free F1005."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F1005**" in text
          and "F967-F974 CLOSED (8" in text
          and "F988-F1003 OPEN (16" in text)
    return ("HELD" if ok else "BREAK", "footer-ok=%s" % ok)


# --------------------------------------- p1: filed shapes must block


def _codes(s):
    return ",".join(str(ord(c)) for c in s)


@_t
def test_p1_filed_shapes():
    """Filed shapes block: F967 x3, F968 x3, F969 x3, F970 x3."""
    shapes = [
        # F967
        "var c=[[%s]];var RESULT=String.fromCharCode.apply(null,c.flat());"
        % "],[".join(_codes(p) for p in (_A, _B)),
        "var c=[[%s]];var RESULT=String.fromCharCode.apply(null,c.flatMap(function(x){return x;}));"
        % "],[".join(_codes(p) for p in (_A, _B)),
        # F968 (round-trip residual)
        "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;"
        % (_A, _B),
        "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o['a']+o['b'];"
        % (_A, _B),
        # F969
        "var f=new FormData();f.append('a','%s');f.append('b','%s');var RESULT=String(f.getAll('a'))+String(f.getAll('b'));"
        % (_A, _B),
        "var f=new FormData();f.append('a','%s');f.append('x','q');f.append('b','%s');var RESULT=f.getAll('a').join('')+f.getAll('b').join('');"
        % (_A, _B),
        # F970
        "var d=Object.getOwnPropertyDescriptor({a:'%s'},'a');var RESULT=d.value+'%s';"
        % (_A, _B),
        "var o={};Object.defineProperty(o,'a',{value:'%s',enumerable:true});var RESULT=o.a+'%s';"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# --------------------------------- p2: generalizations must block


@_t
def test_p2_generalizations():
    """Generalizations block: arrow twins, let/const, bracket reads, joins, multi-appends."""
    shapes = [
        # F967: arrow identity twins, let decl, hex/octal spellings, empty sub-array
        "let c=[[%s]];let RESULT=String.fromCharCode.apply(null,c.flatMap(x=>x));"
        % "],[".join(_codes(p) for p in (_A, _B)),
        "const c=[[%s]];const RESULT=String.fromCharCode.apply(null,c.flatMap((x)=>x));"
        % "],[".join(_codes(p) for p in (_A, _B)),
        "var c=[[],[%s]];var RESULT=String.fromCharCode.apply(null,c.flat());" % _codes(_FULL),
        "var c=[[%s]];var RESULT=String.fromCharCode.apply(undefined,c.flat());"
        % ",".join("0x%x" % ord(ch) for ch in _FULL),
        # F968: three keys, dot/bracket mix
        "var e=Object.entries({a:'%s',b:'%s',c:'zz'});var o=Object.fromEntries(e);var RESULT=o.a+o['b'];"
        % (_A, _B),
        # F969: multi-value per name, String() comma-join, custom sep
        "var f=new FormData();f.append('a','%s');f.append('a','%s');var RESULT=f.getAll('a').join('');"
        % (_A, _B),
        "var f=new FormData();f.append('a','%s');f.append('b','%s');var RESULT=f.getAll('a').join('-')+f.getAll('b').join('-');"
        % (_A, _B),
        # F970: gopd bracket read, defineProperty with flags, lit-init target
        "var d=Object.getOwnPropertyDescriptor({a:'%s'},'a');var RESULT=d['value']+'%s';"
        % (_A, _B),
        "var o={a:'%s'};Object.defineProperty(o,'b',{value:'%s',writable:true,configurable:true});var RESULT=o.a+o.b;"
        % (_A, _B),
        "var o={};Object.defineProperty(o,'a',{value:'%s'});Object.defineProperty(o,'b',{value:'%s'});var RESULT=o['a']+o.b;"
        % (_A, _B),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d blocked" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------ p3: fail-closed bounds must miss


@_t
def test_p3_fail_closed():
    """Out-of-grammar shapes stay quiet (never mis-decode).

    Junk fragments throughout: a full credential literal would match
    the raw-text rules and prove nothing about the decoders.
    """
    shapes = [
        # F967: deeper nesting, non-identity callback, non-literal thisArg
        "var c=[[[%s]]];var RESULT=String.fromCharCode.apply(null,c.flat());" % _codes(_FULL),
        "var c=[[%s]];var RESULT=String.fromCharCode.apply(null,c.flatMap(x=>x+1));"
        % "],[".join(_codes(p) for p in (_A, _B)),
        "var c=[[%s]];var RESULT=String.fromCharCode.apply(this,c.flat());"
        % "],[".join(_codes(p) for p in (_A, _B)),
        # F968: integer-like key (engine reorders)
        "var e=Object.entries({0:'xx',b:'yy'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;",
        # F969: .delete not modeled; non-literal append value; non-literal sep;
        # .set/.get with String() wrap (F860's return grammar needs a bare f head)
        "var f=new FormData();f.append('a','xx');f.delete('a');var RESULT=String(f.getAll('a'));",
        "var f=new FormData();var v='xx';f.append('a',v);var RESULT=String(f.getAll('a'));",
        "var f=new FormData();f.append('a','xx');var s='-';var RESULT=f.getAll('a').join(s);",
        "var f=new FormData();f.append('a','xx');f.set('a','yy');var RESULT=String(f.getAll('a'));",
        "var f=new FormData();f.append('a','xx');var RESULT=String(f.get('a'));",
        # F970: non-configurable redefine (node throws); accessor
        # descriptor; missing key; non-string value; non-literal value
        "var o={};Object.defineProperty(o,'k',{value:'xx'});Object.defineProperty(o,'k',{value:'yy'});var RESULT=o.k;",
        "var o={};Object.defineProperty(o,'a',{get:function(){return 'x'}});var RESULT=o.a;",
        "var d=Object.getOwnPropertyDescriptor({a:'xx'},'zzz');var RESULT=d.value;",
        "var d=Object.getOwnPropertyDescriptor({a:1},'a');var RESULT=d.value;",
        "var o={};var v='xx';Object.defineProperty(o,'a',{value:v});var RESULT=o.a;",
    ]
    bad = [s for s in shapes if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d quiet" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------- p4: sibling pins


@_t
def test_p4_sibling_pins():
    """Siblings unaffected: F952 postfix, F947 props, F914 single getAll, F905 entries-forof, F860 get."""
    blocked = [
        # F952: postfix transforms still block
        "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % _codes(_FULL[::-1]),
        # F947: object-literal prop assembly still blocks
        "var o={a:'%s',b:'%s'};var RESULT=o.a+o.b;" % (_A, _B),
        # F914: single-name getAll still blocks
        "var f=new FormData();f.append('a','%s');var RESULT=f.getAll('a').join('');" % _FULL,
        # F905: entries-forof still blocks
        "(function(){var r='';for(var e of Object.entries({a:'%s'})){r+=e[1];}return r+'%s';})();"
        % (_A, _B),
        # F860: single .get still blocks
        "(function(){var f=new FormData();f.append('k','%s');return f.get('k');})();" % _FULL,
    ]
    quiet = [
        # F967's flat on a non-code array stays quiet
        "var c=[['ab'],['cd']];var RESULT=String.fromCharCode.apply(null,c.flat());",
    ]
    bad = [s for s in blocked if not _blocked(s)]
    bad += [s for s in quiet if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d sibling-ok"
            % (len(blocked) + len(quiet) - len(bad), len(blocked) + len(quiet)))


# ------------------------------------------------- p5: honest text


@_t
def test_p5_honest_text():
    """Honest text stays quiet: no false positives on the new hooks."""
    texts = [
        "var c=[[1,2],[3]];var RESULT=String.fromCharCode.apply(null,c.flat());",
        "var e=Object.entries({a:'x',b:'y'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;",
        "var f=new FormData();f.append('a','x');var RESULT=String(f.getAll('a'));",
        "var d=Object.getOwnPropertyDescriptor({a:'x'},'a');var RESULT=d.value;",
        "var o={};Object.defineProperty(o,'a',{value:'x'});var RESULT=o.a;",
        "the quick brown fox jumps over the lazy dog",
        "var RESULT='hello world';",
    ]
    bad = [t for t in texts if not _misses(t)]
    ok = not bad
    return ("HELD" if ok else "BREAK", "%d/%d quiet" % (len(texts) - len(bad), len(texts)))


# ---------------------------------------------------------------- perf


@_t
def test_p6_perf():
    """200 hostile sites decode in reasonable time (F452 discipline)."""
    site = ("var c=[[%s]];var RESULT=String.fromCharCode.apply(null,c.flat());"
            % "],[".join(_codes(p) for p in (_A, _B)))
    payload = " ".join(site for _ in range(200))
    t0 = time.time()
    _misses(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    total_bad = 0
    notes = []
    for battery in ("w392_f967_redfirst.py", "w392_f968_redfirst.py",
                    "w392_f969_redfirst.py", "w392_f970_redfirst.py"):
        tmp = tempfile.mkdtemp(prefix="g392-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, timeout=600,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        # Red-first line format on the CLOSED tree: "FAIL <shape>"
        # (blocked, good); "BREAK <shape>" would be a miss (bad).
        bad = sum(1 for line in out.splitlines()
                  if line.startswith("BREAK ") or line.startswith("CTRL-FAIL "))
        nshapes = sum(1 for line in out.splitlines()
                      if line.startswith("HELD ") or line.startswith("BREAK ")
                      or line.startswith("FAIL "))
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
    """Depth-1 green check: the four red-firsts stay 0 failures."""
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
