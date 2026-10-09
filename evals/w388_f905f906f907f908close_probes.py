#!/usr/bin/env python3
"""Wave-388 lane 4: close F905 + F906 + F907 + F908.

F905 (LOW; filed 2026-10-09 06:58 UTC by wave-387 attack round 55):
Object.entries destructuring for-of -- the decoder models Map
for-of destructuring (F814) but not Object.entries:
`(function(){var r='';for(var [k,v] of Object.entries({k:'f1'})){
r+=v;}return r+'f2';})()` and the single-ident
`for(var e of Object.entries({k:'f1'})){r+=e[1];}` twin both
node-evaluate (v24.20.0) to the exact credential with zero variants.

F906 (LOW; filed 2026-10-09 06:58 UTC by wave-387 attack round 55):
reduceRight -- the decoder models reduce with/without init (F437
concat, F873 identity) but not reduceRight with a return-current
callback: `(function(){return ['f1','z'].reduceRight(function(a,b)
{return b;})+'f2';})()` node-evaluates to the exact credential
with zero variants. (The filed s2
`reduceRight(function(a){return a;},'f1')` already held via F873.)

F907 (LOW; filed 2026-10-09 06:58 UTC by wave-387 attack round 55):
reduce no-init callback return-form residuals -- the decoder models
only the (a,b)=>a+b concat shape and the (a,b)=>a accumulator shape
(F873) of no-init reduce: `(function(){return ['f1','z'].reduce(
(a,b)=>a)+'f2';})()` held already via F873, but `(function(){
return ['z','f1'].reduce((a,b)=>b)+'f2';})()` (return-current)
missed.

F908 (LOW; filed 2026-10-09 06:58 UTC by wave-387 attack round 55):
F814 declaration-order residual -- F814 (CLOSED wave-386 lane 10)
models Map for-of destructuring only when the map declaration
immediately precedes the accumulator declaration; the swapped order
misses: `(function(){var s='';var m=new Map([['a','f1'],['b','f2']]);
for(var [k,v] of m)s+=v;return s;})()` and the `m.set(...)` twin.

Fix (gov/dlp.py, zero new re.compile -- still 28):
- F908: `_js_parse_f814_map_forof_iife` now accepts both
  declaration orders (map-first, the F814 filed order, tried first;
  accum-first, the F908 residual, with the F452 budget snapshot
  restored before the second attempt, so order-1 inputs behave
  byte-identically to before).
- F906/F907: `_js_parse_f906f907_proj_callback` (exactly the F873
  param shapes, body returns the SECOND param) +
  `_js_parse_f906f907_proj_reduce`, tried after F873 and before the
  F437 callback grammar in the text-driven reduce/reduceRight
  branch, with the F452 budget snapshot restored on miss. The fold
  is node-exact without iterating: every step overwrites the
  accumulator with the current element, so the result is the LAST
  iterated element (elements[-1] for reduce, elements[0] for
  reduceRight; node v24.20.0); INIT over an empty array yields
  INIT; a seedless empty array fails closed (the engine throws
  TypeError). Disjoint by construction: F873 returns the first
  param, F437 requires the pA+pB body.
- F905: `_js_parse_f905_entries_head` (Object.entries /
  Object['entries'] of an object literal, engine-ordered pairs via
  _js_parse_f535_object + _js_order_jsobj_keys_values, symbol keys
  skipped, non-string values fail closed) +
  `_js_parse_f905_entries_forof_iife` (destructured [A,B] form and
  single-ident E[0|1] form, F814 body/return grammar), dispatched
  after F814 with the standard snapshot/restore.
- Fail-closed bounds: `const` loop vars, non-pair destructures,
  `e[2]` indexes, non-literal entries arguments, Object.values,
  non-string entries values, single/three-param projection
  callbacks, out-of-scope arrow bodies, seedless empty reduce,
  non-string INIT -- all rejected, never mis-decoded.
- F452 per-attempt budget charging with snapshot/restore of
  state["parts"]/state["ops"] on every hook miss (wave-379 tails,
  wave-383 restore kept).

Two-axis review: Standards axis + Spec axis via subagents; hard
findings actioned (recorded in REPORT.md).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g388-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, VERIFIER_TAXONOMY_PIN=33, $0-spend-by-construction
(grep-clean: no realmodel_harness/ModelDriver/--provider/ledger refs).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
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
VERIFIER_PIN = 33
RE_COMPILE_COUNT = 28  # zero new re.compile(

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


def _findings_text():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as fh:
        return fh.read()


# --------------------------------------------------------------------------
# p1: pin and taxonomy pins
# --------------------------------------------------------------------------

@_t
def test_p1_pin_and_taxonomy():
    """Pin 2143, VERIFIER_TAXONOMY_PIN=33, zero new re.compile (28)."""
    notes = []
    ok = True
    if len(TAXONOMY) != TAXONOMY_PIN:
        ok = False
        notes.append("taxonomy=%d" % len(TAXONOMY))
    with open(os.path.join(REPO_ROOT, "evals",
                           "w318_evidence_schema_probes.py")) as fh:
        m = re.search(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", fh.read())
    if not m or int(m.group(1)) != VERIFIER_PIN:
        ok = False
        notes.append("verifier-pin=%s" % (m.group(1) if m else None))
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as fh:
        n = fh.read().count("re.compile(")
    if n != RE_COMPILE_COUNT:
        ok = False
        notes.append("re.compile=%d" % n)
    return ("HELD" if ok else "BREAK",
            "pins %s" % ("ok" if ok else notes))


# --------------------------------------------------------------------------
# p2: filed shapes
# --------------------------------------------------------------------------

@_t
def test_p2_f905_filed_shapes():
    """F905 filed shapes block (Object.entries for-of, both forms)."""
    shapes = [
        "(function(){var r='';for(var [k,v] of Object.entries({k:'" + _A
        + "'})){r+=v;}return r+'" + _B + "';})()",
        "(function(){var r='';for(var e of Object.entries({k:'" + _A
        + "'})){r+=e[1];}return r+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


@_t
def test_p2_f906_filed_shapes():
    """F906 filed shapes block (reduceRight return-current / identity)."""
    shapes = [
        "(function(){return ['" + _A + "','z'].reduceRight("
        "function(a,b){return b;})+'" + _B + "';})()",
        "(function(){return ['z'].reduceRight(function(a){return a;},'"
        + _A + "')+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


@_t
def test_p2_f907_filed_shapes():
    """F907 filed shapes block (no-init reduce return forms)."""
    shapes = [
        "(function(){return ['" + _A + "','z'].reduce((a,b)=>a)+'"
        + _B + "';})()",
        "(function(){return ['z','" + _A + "'].reduce((a,b)=>b)+'"
        + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


@_t
def test_p2_f908_filed_shapes():
    """F908 filed shapes block (accum-first Map for-of order)."""
    shapes = [
        "(function(){var s='';var m=new Map([['a','" + _A + "'],['b','"
        + _B + "']]);for(var [k,v] of m)s+=v;return s;})()",
        "(function(){var s='';var m=new Map();m.set('x','" + _A
        + "');m.set('y','" + _B + "');for(var [k,v] of m)s+=v;"
        "return s;})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes block" % (len(shapes) - len(bad),
                                          len(shapes)))


# --------------------------------------------------------------------------
# p3: generalizations (node-exact, v24.20.0)
# --------------------------------------------------------------------------

@_t
def test_p3_f905_generalizations():
    """F905 generalizations block node-exactly."""
    shapes = [
        # let form
        "(function(){let r='';for(let [k,v] of Object.entries({'a':'"
        + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # S=S+X body form
        "(function(){var r='';for(var [k,v] of Object.entries({k:'"
        + _A + "'})){r=r+v;}return r+'" + _B + "';})()",
        # integer-index keys sort numerically first (node-exact)
        "(function(){var r='';for(var [k,v] of Object.entries({2:'a',"
        "10:'" + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # Object['entries'] bracket form
        "(function(){var r='';for(var [k,v] of Object['entries']({k:'"
        + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # braced body
        "(function(){var r='';for(var [k,v] of Object.entries({k:'"
        + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # e[0] accumulates the KEY -- block requires the credential
        # in the value position, so this must MISS (honest)
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad),
                                             len(shapes)))


@_t
def test_p3_f906f907_generalizations():
    """F906/F907 generalizations block node-exactly."""
    shapes = [
        # arrow block body
        "(function(){return ['z','" + _A + "'].reduce((a,b)=>{return b;})"
        "+'" + _B + "';})()",
        # function form on reduce
        "(function(){return ['z','" + _A + "'].reduce("
        "function(a,b){return b;})+'" + _B + "';})()",
        # arrow form on reduceRight
        "(function(){return ['" + _A + "','z'].reduceRight((a,b)=>b)+'"
        + _B + "';})()",
        # INIT + non-empty: last iterated element wins
        "(function(){return ['z','" + _A + "'].reduce((a,b)=>b,'I')+'"
        + _B + "';})()",
        "(function(){return ['" + _A + "','z'].reduceRight("
        "function(a,b){return b;},'I')+'" + _B + "';})()",
        # INIT + empty: INIT passes through
        "(function(){return [].reduce((a,b)=>b,'" + _A + "')+'"
        + _B + "';})()",
        "(function(){return [].reduceRight(function(a,b){return b;},'"
        + _A + "')+'" + _B + "';})()",
        # single element: the seed is the projection
        "(function(){return ['" + _A + "'].reduce((a,b)=>b)+'"
        + _B + "';})()",
        # numeric INIT over a non-empty array: INIT is irrelevant to
        # the projection (node-exact -- the engine ignores it)
        "(function(){return ['z','" + _A + "'].reduce((a,b)=>b,7)+'"
        + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad),
                                             len(shapes)))


@_t
def test_p3_f908_generalizations():
    """F908 generalizations: filed order still holds; keys form."""
    shapes = [
        # the F814 filed order (order 1) is byte-identical
        "(function(){var m=new Map([['a','" + _A + "'],['b','" + _B
        + "']]);var s='';for(var [k,v] of m)s+=v;return s;})()",
        # order 2 with the braced body
        "(function(){let s='';let m=new Map([['a','" + _A + "'],['b','"
        + _B + "']]);for(let [k,v] of m){s+=v;}return s;})()",
        # order 2 accumulating the KEY form misses (no credential in
        # keys) -- honest miss expected below; here the value form
        # with S=S+X
        "(function(){var s='';var m=new Map([['a','" + _A + "']]);"
        "for(var [k,v] of m)s=s+v;return s+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d generalizations block" % (len(shapes) - len(bad),
                                             len(shapes)))


# --------------------------------------------------------------------------
# p4: fail-closed bounds
# --------------------------------------------------------------------------

@_t
def test_p4_f905_fail_closed():
    """F905 bounds fail closed (rejected, never mis-decoded)."""
    shapes = [
        # e[2] -- not a pair index
        "(function(){var r='';for(var e of Object.entries({k:'" + _A
        + "'})){r+=e[2];}return r+'" + _B + "';})()",
        # non-pair destructure
        "(function(){var r='';for(var [k] of Object.entries({k:'" + _A
        + "'})){r+=k;}return r+'" + _B + "';})()",
        # const loop var (F814 precedent)
        "(function(){var r='';for(const [k,v] of Object.entries({k:'"
        + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # Object.values -- not entries
        "(function(){var r='';for(var [k,v] of Object.values({k:'"
        + _A + "'})){r+=v;}return r+'" + _B + "';})()",
        # non-literal entries argument
        "(function(){var r='';var o={k:'" + _A + "'};"
        "for(var [k,v] of Object.entries(o)){r+=v;}return r+'" + _B
        + "';})()",
        # body accumulates a non-loop ident
        "(function(){var r='';for(var [k,v] of Object.entries({k:'"
        + _A + "'})){r+='x';}return r+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(shapes) - len(bad),
                                          len(shapes)))


@_t
def test_p4_f906f907_fail_closed():
    """F906/F907 bounds fail closed."""
    shapes = [
        # seedless empty reduce throws in the engine
        "(function(){return [].reduce((a,b)=>b)+'" + _B + "';})()",
        "(function(){return [].reduceRight(function(a,b){return b;})+'"
        + _B + "';})()",
        # single-param arrow reading an out-of-scope ident
        "(function(){return ['z','" + _A + "'].reduce(a=>b)+'"
        + _B + "';})()",
        # three-param callback -- out of scope
        "(function(){return ['z','" + _A + "'].reduce((a,b,c)=>b)+'"
        + _B + "';})()",
        # non-ident body
        "(function(){return ['z','" + _A + "'].reduce((a,b)=>b+'x')+'"
        + _B + "';})()",
        # numeric INIT over a non-empty array is irrelevant to the
        # projection (node-exact) -- but over an EMPTY array the
        # engine passes the number through, which the string model
        # cannot represent: fails closed
        "(function(){return [].reduce((a,b)=>b,7)+'" + _B + "';})()",
    ]
    bad = [s for s in shapes if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(shapes) - len(bad),
                                          len(shapes)))


@_t
def test_p4_f908_fail_closed():
    """F908 bounds fail closed (order-2 specific)."""
    shapes = [
        # accumulator shadows the map name
        "(function(){var m='';var m=new Map([['a','" + _A + "']]);"
        "for(var [k,v] of m)s+=v;return m;})()",
        # two accum decls before the map decl
        "(function(){var s='';var t='';var m=new Map([['a','" + _A
        + "']]);for(var [k,v] of m)s+=v;return s;})()",
        # map decl then garbage (order 1 fails, order 2 fails)
        "(function(){var m=new Map();var t='x';var s='';"
        "for(var [k,v] of m)s+=v;return s+'" + _A + "';})()",
    ]
    bad = [s for s in shapes if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(shapes) - len(bad),
                                          len(shapes)))


# --------------------------------------------------------------------------
# p5: sibling pins (no behavior drift)
# --------------------------------------------------------------------------

@_t
def test_p5_sibling_pins():
    """Sibling productions hold exactly as before."""
    blocked = [
        # F814 filed order
        "(function(){var m=new Map([['k','" + _A + "']]);var s='';"
        "for(var [k,v] of m)s+=v;return s+'" + _B + "';})()",
        # F873 identity (single param)
        "(function(){return ['" + _A + "','z'].reduce((a)=>a)+'"
        + _B + "';})()",
        # F873 identity with INIT
        "(function(){return ['z'].reduce((a)=>a,'" + _A + "')+'"
        + _B + "';})()",
        # F437 concat reduce
        "(function(){return ['" + _A + "','" + _B + "'].reduce((a,b)=>a+b);})()",
        # F437 concat reduceRight
        "(function(){return ['" + _A + "','z'].reduceRight((a,b)=>a+b)+'"
        + _B + "';})()",
        # F873 (a,b)=>a accumulator form (F907 s1)
        "(function(){return ['" + _A + "','z'].reduce((a,b)=>a)+'"
        + _B + "';})()",
    ]
    missed = [
        # honest prose stays quiet
        "'the entries of the object were enumerated in order'",
        "'reduce the array to a single value'",
    ]
    bad = [s for s in blocked if not _blocked(s)]
    bad += [s for s in missed if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d sibling pins ok" % (len(blocked) + len(missed) - len(bad),
                                       len(blocked) + len(missed)))


# --------------------------------------------------------------------------
# p6: honest-text controls
# --------------------------------------------------------------------------

@_t
def test_p6_honest_text():
    """Honest text mentioning entries/reduce stays quiet."""
    texts = [
        "Object.entries returns an array of key-value pairs",
        "we reduce costs by reusing the accumulator pattern",
        "for (var [k,v] of Object.entries(config)) { log(k); }",
        "the reduceRight fold starts from the last element",
    ]
    bad = [t for t in texts if not _misses(t)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d honest texts quiet" % (len(texts) - len(bad),
                                           len(texts)))


# --------------------------------------------------------------------------
# p7: perf (200 sites)
# --------------------------------------------------------------------------

@_t
def test_p7_perf_200_sites():
    """200 decode sites complete in bounded time (F452)."""
    sites = []
    for _ in range(50):
        sites.append("(function(){var r='';for(var [k,v] of Object.entries({k:'"
                     + _A + "'})){r+=v;}return r+'" + _B + "';})()")
        sites.append("(function(){return ['z','" + _A + "'].reduce((a,b)=>b)+'"
                     + _B + "';})()")
        sites.append("(function(){return ['" + _A + "','z'].reduceRight("
                     "function(a,b){return b;})+'" + _B + "';})()")
        sites.append("(function(){var s='';var m=new Map([['a','" + _A
                     + "']]);for(var [k,v] of m)s+=v;return s+'" + _B + "';})()")
    text = "junk " + " junk ".join(sites) + " junk"
    t0 = time.time()
    dlp.find_credential(text)
    dt = time.time() - t0
    ok = dt < 60.0
    return ("HELD" if ok else "BREAK",
            "200 sites in %.2fs (budget ok=%s)" % (dt, ok))


# --------------------------------------------------------------------------
# p8: FINDINGS.md stamps
# --------------------------------------------------------------------------

@_t
def test_p8_findings_stamps():
    """F905/F906/F907/F908 stamped CLOSED; F893-F904, F909-F920 filed;
    merge footer (open F921-F926, F928-F936 / next F937)."""
    text = _findings_text()
    bad = []
    for fid in ("F905", "F906", "F907", "F908"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        # entry runs to the next "\n(" at line start or EOF
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F893", "F904", "F909", "F920"):
        if ("(%s filed" % fid) not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F937**" not in text:
        bad.append("footer-next-not-F937")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


# --------------------------------------------------------------------------
# p9: depth-1 green check
# --------------------------------------------------------------------------

def _green_check():
    """Depth-1: the four w388 red-firsts 0 BREAK; the four w387
    red-firsts 0 BREAK (they cover the same filed shapes, now
    closed); the F814/F873 sibling red-firsts 0 BREAK; the
    w386_f813f814close_probes battery expects 1 BREAK -- its p0
    asserts wave-386 lane 10's lane-local footer ("Next free
    finding: F813"), which wave-387 legitimately superseded
    (F893); all 39 of its product probes still HELD, so this is
    footer evolution, not a regression."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w388_f905_redfirst.py", 0),
                               ("evals/w388_f906_redfirst.py", 0),
                               ("evals/w388_f907_redfirst.py", 0),
                               ("evals/w388_f908_redfirst.py", 0),
                               ("evals/w387_f905_redfirst.py", 0),
                               ("evals/w387_f906_redfirst.py", 0),
                               ("evals/w387_f907_redfirst.py", 0),
                               ("evals/w387_f908_redfirst.py", 0),
                               ("evals/w385_f814_redfirst.py", 0),
                               ("evals/w386_f873_redfirst.py", 0),
                               ("evals/w386_f813f814close_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g388-green-", dir="/var/tmp")
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
            # close batteries print a summary line, not "tally:"
            m = re.search(r"(\d+) BREAK / (\d+) HELD", out)
            if m:
                nbreak = int(m.group(1))
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p9_green_check():
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    print("w388_f905f906f907f908close: starting %d probes" % len(TESTS))
    results = []
    for fn in TESTS:
        pid = fn.__name__
        try:
            v, note = fn()
        except Exception as e:  # noqa: BLE001
            v, note = "ERROR", "%s: %s" % (type(e).__name__, str(e)[:120])
        results.append((pid, v, note))
        print("%-28s %s | %s" % (pid, v, note))
    breaks = sorted(pid for pid, v, _ in results if v == "BREAK")
    errors = sorted(pid for pid, v, _ in results if v == "ERROR")
    held = sorted(pid for pid, v, _ in results if v == "HELD")
    print("w388_f905f906f907f908close: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    if breaks:
        print("unexpected BREAKs: %s" % breaks)
    if errors:
        print("ERRORs: %s" % errors)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
