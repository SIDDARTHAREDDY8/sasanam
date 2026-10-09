#!/usr/bin/env python3
"""Wave-384 lane 3: close F742 (DataView byte laundering) + F743 (assigned Symbol.toPrimitive).

F742 (LOW, filed 2026-10-08 by wave-383 lane 14/attack round 51, renumbered
at the wave-383 merge -- lane 6 filed F738/F739 first ~17:30/~17:45 UTC):
the decoder models String.fromCharCode (F434, CLOSED) but not DataView byte
reads: fragment bytes written via setUint8 and read back via getUint8 flow
into fromCharCode node-exactly (v24.20.0) while the decoder produces zero
variants:
(function(){var v=new DataView(new ArrayBuffer(4));v.setUint8(0,120);
v.setUint8(1,111);return String.fromCharCode(v.getUint8(0),
v.getUint8(1))+'xb-0123'+'f2';})() and
(function(){var v=new DataView(new ArrayBuffer(2));v.setUint8(0,120);
v.setUint8(1,111);return String.fromCharCode(v.getUint8(0))+'o'+'xb-0123'
+'f2';})(). Distinct from F434 (integer-literal args, CLOSED).
Controls: plain String.fromCharCode twins block coded; junk-quiet passes.

F743 (LOW, filed 2026-10-08 by wave-383 lane 14/attack round 51, renumbered
at the wave-383 merge): F697 residual -- assigned Symbol.toPrimitive.
F697 (CLOSED wave-381) models valueOf and the literal
{[Symbol.toPrimitive]:...} form, but not the ASSIGNED form
o[Symbol.toPrimitive]=function: the coercion fires node-exactly (v24.20.0)
while the decoder produces zero variants:
(function(){var o={};o[Symbol.toPrimitive]=function(){return 'f1';};
return o+'f2';})() and
(function(){var o={};o[Symbol.toPrimitive]=function(hint){return 'f1';};
return String(o)+'f2';})(). Distinct from F697 (literal form, CLOSED)
and F761 (own non-callable @@toPrimitive throws -- kept OPEN).
Controls: the F697 valueOf and literal-toPrimitive twins block coded;
junk-quiet passes.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f742_dataview_iife (+ _js_parse_f742_getuint8_arg): the
  statement-IIFE grammar `var|let|const v=new DataView(new
  ArrayBuffer(N));v.setUint8(i,b);*return ADD;`. The buffer is
  zero-initialized like the engine; integer-literal setUint8 writes
  apply with ToUint8 wrap (node-exact for ints, negatives included);
  the env is stashed in state["_f742_dataviews"] while the return
  additive parses, and the shared fromCharCode arg grammar
  (_js_parse_fromcharcode_args_inner) resolves `v.getUint8(k)` reads
  against it. Without the env the arg alternative fails closed
  exactly as the F458 grammar did before, so no previously-decoded
  input changes behavior (base-vs-lane differential: only the 2
  filed F742 shapes MISS->DECODE). Hooked after F735/F736; disjoint
  (no earlier route binds `new DataView`). Budget snapshot/restore
  on miss (wave-383 lesson).
- _js_parse_f743_toprimitive_assign_iife: `var o={...};` (parsed by
  the shared _js_parse_f697_object) followed by one or more
  `o[Symbol.toPrimitive]=function[(name)][(params)]{return ADD;};`
  statements (later-wins, node-exact), then `return ADD2;` with
  string-literal, bare-bound-ident, and `String(o)` terms coerced
  via the shared _js_f697_toprimitive. Param-referencing bodies
  fail closed in the shared F67x evaluator; non-function assigned
  values fail closed (the engine throws -- F761's residual).
  Hooked after F697; disjoint (F697 fails closed on the assignment
  statement; this fails closed without it). Budget
  snapshot/restore on miss (wave-383 lesson).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g384-*
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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: merged wave-384 footer (F738-F761 CLOSED; F762-F794 OPEN, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f742_s1():
    """F742 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var v=new DataView(new ArrayBuffer(4));"
        "v.setUint8(0,120);v.setUint8(1,111);"
        "return String.fromCharCode(v.getUint8(0),v.getUint8(1))"
        "+'xb-0123'+'%s';})()" % (_A,))
    return ("HELD" if ok else "BREAK", "f742-s1=%s" % ok)


@_t
def test_p1_f742_s2():
    """F742 filed shape 2 blocks."""
    ok = _blocked(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,120);v.setUint8(1,111);"
        "return String.fromCharCode(v.getUint8(0))+'o'+'xb-0123'"
        "+'%s';})()" % (_A,))
    return ("HELD" if ok else "BREAK", "f742-s2=%s" % ok)


@_t
def test_p1_f743_s1():
    """F743 filed shape 1 blocks."""
    ok = _blocked(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f743-s1=%s" % ok)


@_t
def test_p1_f743_s2():
    """F743 filed shape 2 (hint param, String(o)) blocks."""
    ok = _blocked(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(hint){return '%s';};"
        "return String(o)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f743-s2=%s" % ok)


# ------------------------------------------------------------- variants p2

@_t
def test_p2_f742_let_const():
    """F742 let/const twins block (node-exact)."""
    ok = _blocked(
        "(function(){let v=new DataView(new ArrayBuffer(4));"
        "v.setUint8(0,120);v.setUint8(1,111);"
        "return String.fromCharCode(v.getUint8(0),v.getUint8(1))"
        "+'xb-0123'+'%s';})()" % (_A,))
    ok = ok and _blocked(
        "(function(){const v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,120);v.setUint8(1,111);"
        "return String.fromCharCode(v.getUint8(0),v.getUint8(1))"
        "+'xb-0123'+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "let-const=%s" % ok)


@_t
def test_p2_f742_wrap_neg_hex():
    """F742 byte wrap (376->120), negative (-136->120), hex literals block."""
    ok = _blocked(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,376);v.setUint8(1,0x6f);"
        "return String.fromCharCode(v.getUint8(0),v.getUint8(1))"
        "+'xb-0123'+'%s';})()" % (_B,))
    ok = ok and _blocked(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,-136);v.setUint8(1,0x6f);"
        "return String.fromCharCode(v.getUint8(0),v.getUint8(1))"
        "+'xb-0123'+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "wrap=%s" % ok)


@_t
def test_p2_f742_overwrite_mixed():
    """F742 later-wins overwrite + mixed literal/getUint8 args block."""
    ok = _blocked(
        "(function(){var w=new DataView(new ArrayBuffer(2));"
        "w.setUint8(0,120);w.setUint8(0,111);"
        "return String.fromCharCode(120,w.getUint8(0))"
        "+'xb-0123'+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "overwrite-mixed=%s" % ok)


@_t
def test_p2_f743_named_params():
    """F743 named function + multi-param (unreferenced) twins block."""
    ok = _blocked(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function named(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _blocked(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(a,b){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "named-params=%s" % ok)


@_t
def test_p2_f743_reassign_data():
    """F743 reassignment later-wins + literal data props block."""
    ok = _blocked(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(){return 'xx';};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _blocked(
        "(function(){var o={x:'q'};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "reassign-data=%s" % ok)


@_t
def test_p2_f743_valueof_pair():
    """F743 literal valueOf + assigned toPrimitive: toPrimitive wins (node)."""
    ok = _blocked(
        "(function(){var o={valueOf:function(){return 'xx';}};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "valueof-pair=%s" % ok)


# ---------------------------------------------------------------- bounds p3

@_t
def test_p3_f742_oor():
    """F742 out-of-range get/set fail closed (engine RangeError)."""
    ok = _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,120);"
        "return String.fromCharCode(v.getUint8(5))+'%s';})()" % (_B,))
    ok = ok and _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(9,120);return 'q'+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "oor=%s" % ok)


@_t
def test_p3_f742_widths():
    """F742 other widths (setInt8/getInt8/getUint16/...) fail closed."""
    ok = _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,120);"
        "return String.fromCharCode(v.getInt8(0))+'%s';})()" % (_B,))
    ok = ok and _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setInt8(0,120);"
        "return String.fromCharCode(v.getUint8(0))+'%s';})()" % (_B,))
    ok = ok and _misses(
        "(function(){var v=new DataView(new ArrayBuffer(4));"
        "v.setUint8(0,120);"
        "return String.fromCharCode(v.getUint16(0))+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "widths=%s" % ok)


@_t
def test_p3_f742_foreign_stmt():
    """F742 foreign statements fail closed."""
    ok = _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "var x=1;"
        "return String.fromCharCode(v.getUint8(0))+'%s';})()" % (_B,))
    ok = ok and _misses(
        "(function(){var v=new DataView(new ArrayBuffer(2));"
        "v.setUint8(0,120);v=new DataView(new ArrayBuffer(2));"
        "return String.fromCharCode(v.getUint8(0))+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "foreign=%s" % ok)


@_t
def test_p3_f742_no_env():
    """F742 getUint8 args without the DataView env fail closed (F458)."""
    ok = _misses("String.fromCharCode(v.getUint8(0))+'%s'" % (_B,))
    ok = ok and _misses(
        "(function(){return String.fromCharCode(v.getUint8(0))+'%s';})()"
        % (_B,))
    return ("HELD" if ok else "BREAK", "no-env=%s" % ok)


@_t
def test_p3_f743_nonfunction():
    """F743 non-function assigned value fails closed (engine TypeError)."""
    ok = _misses(
        "(function(){var o={};o[Symbol.toPrimitive]='x';"
        "return o+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "nonfunction=%s" % ok)


@_t
def test_p3_f743_forms():
    """F743 arrow, bracket-string key, hint-referencing body fail closed."""
    ok = _misses(
        "(function(){var o={};o[Symbol.toPrimitive]=()=>'%s';"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _misses(
        "(function(){var o={};o[Symbol['toPrimitive']]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _misses(
        "(function(){var o={};o[Symbol.toPrimitive]=function(hint){return hint;};"
        "return o+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "forms=%s" % ok)


@_t
def test_p3_f743_nonstring_body():
    """F743 non-string primitive body fails closed (F762: engine String()-coerces, no throw)."""
    ok = _misses(
        "(function(){var o={};o[Symbol.toPrimitive]=function(){return 42;};"
        "return o+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "nonstring=%s" % ok)


@_t
def test_p3_f743_foreign():
    """F743 data-assign statements and member terms fail closed."""
    ok = _misses(
        "(function(){var o={};o.x='q';"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _misses(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return o.x+'%s';})()" % (_A, _B))
    ok = ok and _misses(
        "(function(){var o={};"
        "o[Symbol.toPrimitive]=function(){return '%s';};"
        "return String(o.x)+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "foreign=%s" % ok)


# --------------------------------------------------------------- siblings p4

@_t
def test_p4_f697_siblings():
    """F697 literal/valueOf/toString twins still block; F674 intact."""
    ok = _blocked(
        "(function(){var o={valueOf:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B))
    ok = ok and _blocked(
        "(function(){var o={[Symbol.toPrimitive]:function(){return '%s';}};"
        "return o+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f697=%s" % ok)


@_t
def test_p4_f434_siblings():
    """F434 fromCharCode literal/dispatch/spread twins still block."""
    ok = _blocked("String.fromCharCode(120,111)+'xb-0123'+'%s'" % (_B,))
    ok = ok and _blocked("String.fromCharCode(...[120,111])+'xb-0123'+'%s'" % (_B,))
    ok = ok and _blocked(
        "String.fromCharCode.call(null,120,111)+'xb-0123'+'%s'" % (_B,))
    return ("HELD" if ok else "BREAK", "f434=%s" % ok)


@_t
def test_p4_open_neighbors():
    """Neighbors: F740/F744 now block (closed wave-384); F794 (numeric toPrimitive) still misses."""
    ok = _blocked(
        "(function(){var r;try{throw '%s';}catch(e){r=e;}"
        "return r+'%s';})()" % (_A, _B))
    ok = ok and _blocked(
        "(function(){var s=new Set(['%s']).union(new Set(['%s']));"
        "return [...s].join('');})()" % (_A, _B))
    ok = ok and _misses(
        "(function(){var o={};o[Symbol.toPrimitive]=function(){return 120;};"
        "return String.fromCharCode(o)+'xb-0123'+'%s';})()" % (_B,))
    return ("HELD" if ok else "BREAK", "neighbors=%s" % ok)


@_t
def test_p4_honest_quiet():
    """Honest text stays quiet."""
    ok = _misses("'(function(){var s=\\\\'ab\\\\';return s;})()'")
    ok = ok and _misses("the quick brown fox")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------------------------ perf p5

@_t
def test_p5_perf():
    """200 F742/F743-shaped sites decode in <20s (F452 charging sane)."""
    t0 = time.time()
    for k in range(100):
        dlp._try_js_expr_decode_all(
            "(function(){var v=new DataView(new ArrayBuffer(4));"
            "v.setUint8(0,120);v.setUint8(1,111);"
            "return String.fromCharCode(v.getUint8(0),v.getUint8(1));})()")
        dlp._try_js_expr_decode_all(
            "(function(){var o={};"
            "o[Symbol.toPrimitive]=function(){return 'f1';};"
            "return o+'f2';})()")
    dt = time.time() - t0
    ok = dt < 20.0
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


# ------------------------------------------------------- green check (depth-1)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # w383_attack: 4 pins flipped open->closed by this lane; the footer
    # pin was repointed at the wave-384 merge. Expect 0 BREAKs.
    tmp = tempfile.mkdtemp(prefix="g384-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w383_attack_probes.py")],
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
        bad.append(("w383_attack_probes", "no-tally"))
    elif nbreak != 0:
        bad.append(("w383_attack_probes", nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p6_green_check():
    """Green check: w383 attack battery shows only the footer BREAK."""
    return _green_check()


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    breaks = held = errors = 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
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
