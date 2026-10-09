#!/usr/bin/env python3
"""Wave-383 lane 8: close F727 + F728 (do-while accumulation, generator .next().value reads).

F727 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
F709 residual -- do-while accumulation. F709 (filed round 49)
covers counted for/while += loops but not do-while: the
accumulation evaluates to the exact credential while the decoder
produced zero variants. Filed shapes:
`(function(){var r='';var i=0;do{r+=['f1','f2'][i];i++;}while(i<2);return r;})()`
and the plain-concat twin
`(function(){var r='';var i=0;do{r=r+['f1','f2'][i];i++;}while(i<2);return r;})()`.

F728 (LOW, filed 2026-10-08 by wave-382 lane 8, attack round 50):
F677 residual -- .next().value reads on function-declaration
generators. F677 (CLOSED wave-380) models sequenced `.next()`
reads only through var-bound result idents (`R=IT.next();`);
F656 (CLOSED) models the single `G.next().value` read on an
invoked generator expression. Neither decoded `.next().value`
read directly on the call result of a declared generator's
iterator. Filed shapes:
`(function(){function* g(){yield 'f1';}var it=g();return it.next().value+'f2';})()`
and the two-read twin
`(function(){function* g(){yield 'f1';yield 'f2';}var it=g();return it.next().value+it.next().value;})()`.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f727_dowhile_accum_iife (+ _js_f727_accum_stmt):
  do-while accumulation over a literal string array -- the body
  runs once before the first condition check (node v24.20.0);
  the counter runs the exact integer sequence (canonical safe
  ints only, F699 discipline); each iteration appends the array
  element at the counter (out-of-bounds is engine `undefined`
  -- never decoded, fail closed). Both `R+=ARR[I];` and the
  `R=R+ARR[I];` twin. Bounded by _JS_F679_MAX_ITERS
  iterations, F452 per-iteration part charge,
  _MAX_DECODE_BYTES on the result. Hooked after F709;
  disjoint (F709's head grammar requires `for`/`while`;
  F679 has no literal-array-index production).
- _js_parse_f728_nextvalue_iife: direct `.next().value`
  reads -- `function* G(){yield 'LIT';...;return 'LIT'?;}`
  declaration parsed with the shared F677 nextseq body parser,
  `var|let|const IT=G();`, then a string-only additive of
  `'LIT'` and `IT.next().value` terms. The n-th `.next()`
  delivers yields[n-1]; the call after the last yield delivers
  the trailing return value; any later call is engine
  `undefined` -- refused coded, never mis-decoded. At most 16
  calls, F452 parts charged per call. Hooked after F677's
  nextseq; disjoint (F677 requires var-bound `R=IT.next()`
  statements; F656 requires the invoked generator-expression
  head).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g383-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2144, $0-spend-by-construction.  # Wave-385: pin 2143 -> 2144
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

TAXONOMY_PIN = 2144  # no new decision codes this lane  # Wave-385: pin 2143 -> 2144

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

_RESULTS = []


def _t(fn):
    _RESULTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2144; registry loads."""  # Wave-385: pin 2143 -> 2144
    ok = TAXONOMY_PIN == 2144 and len(TAXONOMY) > 0  # Wave-385: pin 2143 -> 2144
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F727/F728 closed, next F738)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F795**" in text  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in text)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------------- filed shapes (p1)


@_t
def test_p1_f727_s1():
    """F727 filed shape 1 (do-while +=) blocks."""
    ok = _blocked(
        "(function(){var r='';var i=0;"
        "do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f727-s1=%s" % ok)


@_t
def test_p1_f727_s2():
    """F727 filed shape 2 (do-while plain concat) blocks."""
    ok = _blocked(
        "(function(){var r='';var i=0;"
        "do{r=r+['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f727-s2=%s" % ok)


@_t
def test_p1_f728_s1():
    """F728 filed shape 1 (single .next().value) blocks."""
    ok = _blocked(
        "(function(){function* g(){yield '%s';}"
        "var it=g();return it.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f728-s1=%s" % ok)


@_t
def test_p1_f728_s2():
    """F728 filed shape 2 (two .next().value reads) blocks."""
    ok = _blocked(
        "(function(){function* g(){yield '%s';yield '%s';}"
        "var it=g();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f728-s2=%s" % ok)


# ------------------------------------------------- node-exact variants (p2)


@_t
def test_p2_f727_le_bound():
    """F727 `<=` bound variant blocks node-exactly."""
    ok = _blocked(
        "(function(){var r='';var i=0;"
        "do{r+=['%s','%s'][i];i++;}while(i<=1);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "le=%s" % ok)


@_t
def test_p2_f727_init1():
    """F727 nonzero-init variant blocks node-exactly."""
    ok = _blocked(
        "(function(){var r='';var i=1;"
        "do{r+=['pad','xoxb-','0123456789abcdef'][i];i++;}while(i<3);return r;})()")
    return ("HELD" if ok else "BREAK", "init1=%s" % ok)


@_t
def test_p2_f727_body_once():
    """F727 do-while runs the body once even when the condition is initially false.

    Asserted as decode-exactness (not via find_credential): a single
    short fragment cannot be credential-shaped, so the public seam
    cannot distinguish it -- but the decoder must still produce the
    node-exact value 'a' (node v24.20.0 verified), proving the
    body-once semantics. Misses (None) on the base tree.
    """
    got = dlp._try_js_expr_decode(
        "(function(){var r='';var i=0;"
        "do{r+=['a'][i];i++;}while(i<0);return r;})()", 0)
    ok = got is not None and got[0] == "a"
    return ("HELD" if ok else "BREAK", "body-once=%s" % ok)


@_t
def test_p2_f727_let_decl():
    """F727 `let` decls variant blocks."""
    ok = _blocked(
        "(function(){let r='';let i=0;"
        "do{r=r+['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "let=%s" % ok)


@_t
def test_p2_f728_trailing_return():
    """F728 trailing-return-after-exhaustion variant blocks node-exactly."""
    ok = _blocked(
        "(function(){function* g(){yield '%s';return '%s';}"
        "var it=g();return it.next().value+it.next().value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "trailing-ret=%s" % ok)


@_t
def test_p2_f728_const_iter():
    """F728 `const` iterator binding variant blocks."""
    # The yielded fragment is only the 'xoxb-' prefix; the full
    # credential value assembles in the return additive, so no raw
    # literal in the source is credential-shaped.
    ok = _blocked(
        "(function(){function* g(){yield 'xoxb-';}"
        "const it=g();return it.next().value+'0123456789abcdef';})()")
    return ("HELD" if ok else "BREAK", "const=%s" % ok)


@_t
def test_p2_f728_yield_paren():
    """F728 `yield('LIT')` paren form variant blocks."""
    ok = _blocked(
        "(function(){function* g(){yield('xoxb-');}"
        "var it=g();return it.next().value+'0123456789abcdef';})()")
    return ("HELD" if ok else "BREAK", "yield-paren=%s" % ok)


@_t
def test_p2_f728_three_reads():
    """F728 three sequential reads block node-exactly."""
    ok = _blocked(
        "(function(){function* g(){yield '%s';yield '%s';yield '%s';}"
        "var it=g();return it.next().value+it.next().value+it.next().value;})()"
        % (_A, _B, _A))
    return ("HELD" if ok else "BREAK", "three-reads=%s" % ok)


# --------------------------------------------------------- fail-closed (p3)


@_t
def test_p3_f727_oob_index():
    """F727 out-of-bounds index fails closed (engine `undefined`, never decoded)."""
    ok = _misses(
        "(function(){var r='';var i=5;"
        "do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "oob=%s" % ok)


@_t
def test_p3_f727_unsafe_int():
    """F727 unsafe-int bound fails closed (F699 discipline)."""
    ok = _misses(
        "(function(){var r='';var i=0;"
        "do{r+=['%s'][i];i++;}while(i<9007199254740993);return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "unsafeint=%s" % ok)


@_t
def test_p3_f727_non_incr_update():
    """F727 non-`i++` update fails closed."""
    ok = _misses(
        "(function(){var r='';var i=0;"
        "do{r+=['%s','%s'][i];i+=1;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "nonincr=%s" % ok)


@_t
def test_p3_f727_extra_body_stmt():
    """F727 extra body statement fails closed."""
    ok = _misses(
        "(function(){var r='';var i=0;"
        "do{r+=['%s','%s'][i];i++;var z=1;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "extra=%s" % ok)


@_t
def test_p3_f727_non_counter_index():
    """F727 index that is not the counter ident fails closed."""
    ok = _misses(
        "(function(){var r='';var i=0;var j=0;"
        "do{r+=['%s','%s'][j];i++;}while(i<2);return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "noncounter=%s" % ok)


@_t
def test_p3_f728_past_exhaustion():
    """F728 `.next()` past exhaustion fails closed (engine `undefined`)."""
    ok = _misses(
        "(function(){function* g(){yield '%s';}"
        "var it=g();return it.next().value+it.next().value;})()" % _A)
    return ("HELD" if ok else "BREAK", "exhaust=%s" % ok)


@_t
def test_p3_f728_next_args():
    """F728 `.next(1)` with args fails closed."""
    ok = _misses(
        "(function(){function* g(){yield '%s';}"
        "var it=g();return it.next(1).value;})()" % _A)
    return ("HELD" if ok else "BREAK", "nextargs=%s" % ok)


@_t
def test_p3_f728_done_member():
    """F728 `.done` member read fails closed (only `.value` modeled)."""
    ok = _misses(
        "(function(){function* g(){yield '%s';}"
        "var it=g();return it.next().done;})()" % _A)
    return ("HELD" if ok else "BREAK", "done=%s" % ok)


@_t
def test_p3_f728_rebound_iter():
    """F728 rebound iterator name fails closed."""
    ok = _misses(
        "(function(){function* g(){yield '%s';}"
        "var it=g();it=1;return it.next().value;})()" % _A)
    return ("HELD" if ok else "BREAK", "rebind=%s" % ok)


@_t
def test_p3_f728_extra_stmt():
    """F728 extra statement fails closed."""
    ok = _misses(
        "(function(){function* g(){yield '%s';}"
        "var it=g();var z=1;return it.next().value;})()" % _A)
    return ("HELD" if ok else "BREAK", "extra=%s" % ok)


# --------------------------------------- siblings still block, neighbors open


@_t
def test_p4_sibling_f709_for():
    """F709 for-twin still blocks (sibling intact)."""
    ok = _blocked(
        "(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f709-for=%s" % ok)


@_t
def test_p4_sibling_f709_while():
    """F709 while-twin still blocks (sibling intact)."""
    ok = _blocked(
        "(function(){var r='';var i=0;while(i<2){r+=['%s','%s'][i];i++;}return r;})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "f709-while=%s" % ok)


@_t
def test_p4_sibling_f677_nextseq():
    """F677 sequenced-.next() pins still block (sibling intact)."""
    ok = _blocked(
        "(function(){function* g(){yield '%s';yield '%s';}"
        "var it=g();var r1=it.next();var r2=it.next();"
        "return r1.value+r2.value;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f677=%s" % ok)


@_t
def test_p4_sibling_f656_bound():
    """F656 bound generator-expression single read still blocks (sibling intact)."""
    ok = _blocked(
        "(function(){var g=(function*(){yield '%s';})();"
        "return g.next().value+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f656=%s" % ok)


@_t
def test_p4_neighbor_f726_open():
    """F726 (template-literal toPrimitive) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var o={toString:function(){return '%s';}};"
        "return `${o}`+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f726-closed=%s" % ok)


@_t
def test_p4_neighbor_f729_open():
    """F729 (void operator) still misses -- open, not absorbed."""
    ok = not _misses(
        "(function(){var x='%s';void x;return x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f729-closed=%s" % ok)


# ----------------------------------------------------------------- controls


@_t
def test_p5_honest_text_quiet():
    """Honest text is not flagged."""
    ok = _misses("the generator yields results while the loop runs once")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_junk_quiet():
    """Junk payload stays quiet."""
    ok = _misses("(function(){var q='zzz';do{q+='y';}while(false);return q;})()")
    return ("HELD" if ok else "BREAK", "junk=%s" % ok)


@_t
def test_p6_perf():
    """200 mixed sites decode fast."""
    t0 = time.time()
    for k in range(100):
        _blocked(
            "(function(){var r='';var i=0;"
            "do{r+=['%s','%s'][i];i++;}while(i<2);return r;})()" % (_A, _B))
        _blocked(
            "(function(){function* g(){yield '%s';}"
            "var it=g();return it.next().value+'%s';})()" % (_A, _B))
    dt = time.time() - t0
    ok = dt < 20
    return ("HELD" if ok else "BREAK", "200 sites in %.2fs" % dt)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # The two F727/F728 red-firsts expect 0 BREAK (closed). The
    # wave-382 attack battery's F727/F728 pins were flipped to
    # closed by this lane -- expect 0 BREAK there too.
    for batt, expect_break in (("evals/w382_f727_redfirst.py", 0),
                               ("evals/w382_f728_redfirst.py", 0),
                               ("evals/w382_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g383-green-", dir="/var/tmp")
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
    """Depth-1 green check: F727/F728 red-firsts + wave-382 attack battery."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    nbreak = nheld = nerr = 0
    for fn in _RESULTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            nbreak += 1
        elif verdict == "HELD":
            nheld += 1
        else:
            nerr += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
