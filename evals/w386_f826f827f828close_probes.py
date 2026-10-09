#!/usr/bin/env python3
"""Wave-386 lane 16: close F826 + F827 + F828 (labeled-control residuals).

F826 (LOW; filed 2026-10-09 03:43 UTC by wave-385 lane 12, renumbered
F795->F826 at the wave-385 merge): F784 (CLOSED) modeled `if(BOOL)break
LBL;` with a bare consequent, but a braced consequent `if(1){break lbl;}`
resolved node-exactly while the decoder produced zero variants.

F827 (LOW; filed 2026-10-09 03:43 UTC by wave-385 lane 12, renumbered
F796->F827 at the wave-385 merge): F784 modeled counted
`for(var I=INIT;I<BOUND;I++)` loops, but `for(;;)` with a labeled break
exited node-exactly while the decoder produced zero variants.

F828 (LOW; filed 2026-10-09 03:43:50 UTC by wave-385 lane 10, renumbered
F796->F828 at the wave-385 merge): F781 class-ctor overstatement --
empty-class prototype method reads had no production. Closed in wave-385
by the empty-class branch; this lane verifies the closure holds on the
merged tree (entry already stamped CLOSED; footer corrected).

Fix (gov/dlp.py, zero new re.compile):
- F826: `_js_f826_consequent` helper shared by bare and braced
  consequents; the F784 labeled-block `if(BOOL)` branch accepts a
  braced consequent block of ordered accum/break statements
  (`if(BOOL){ACCUM;break LBL;}`), node-exact under the outer guard.
  Empty braces, nested `if`, or other statement kinds fail closed.
- F827: the F784 labeled-for header accepts the empty `for(;;)`
  form; the body is single-iteration-deterministic (no counter, no
  mutable state besides the accumulator): the loop breaks on
  iteration 1 or the engine hangs -- a truthy `continue` or no
  reachable break fails closed.
- F828: verified closed (no code change).

New finding filed: F829 (braced if-consequents in labeled FOR bodies;
both counted and for(;;)) -- 2026-10-09 05:26 UTC.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g386-*
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


def _decodes_exact(payload, want):
    got = dlp._try_js_expr_decode_all(payload)
    return got is not None and want in got


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F826/F827 closed, F828 corrected,
    F829 filed; next F830)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F830**" in text
          and "Open findings: F795, F796, F797, F798, F799, F800, F801, "
              "F802, F803, F804, F805, F806, F807, F808, F809, F810, F811, "
              "F812, F813, F814, F815, F816, F817, F819, F820, F821, F822, "
              "F823, F824, F825, F829." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f826_s1():
    """F826 filed shape (braced break, truthy) blocks + exact."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){break lbl;}"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f826_s2():
    """F826 falsy-guard braced break falls through + exact."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(0){break lbl;}"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "xx" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f826_s3():
    """F826 braced accum consequent blocks + exact."""
    s = ("(function(){var r='';lbl:{if(1){r+='" + _A + "';}r+='" + _B
         + "';}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f826_s4():
    """F826 multi-statement braced consequent blocks + exact."""
    s = ("(function(){var r='';lbl:{if(1){r+='" + _A + "';r+='" + _B
         + "';break lbl;}r+='xx';}return r;})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f827_s1():
    """F827 filed shape (for(;;) + labeled break) blocks + exact."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f827_s2():
    """F827 truthy-guarded break in for(;;) blocks + exact."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';if(1)break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f827_s3():
    """F827 unlabeled break in for(;;) blocks + exact."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';break;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f828_s1():
    """F828 shape 1 (empty-class proto method) still blocks."""
    s = ("(function(){class C{}C.prototype.m=function(){return '" + _A
         + "';};return new C().m()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p1_f828_s2():
    """F828 shape 2 (bracket proto method) still blocks."""
    s = ("(function(){class C{}C.prototype['m']=function(){return '" + _A
         + "';};var o=new C();return o['m']()+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


# ------------------------------------------------ p2: generalizations


@_t
def test_p2_f826_let():
    """F826 let-decl twin blocks."""
    s = ("(function(){let r='';lbl:{r+='" + _A + "';if(!0){break lbl;}"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f826_ws():
    """F826 ws-tolerant braces block."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1) { break lbl ; } "
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f826_bang_guard():
    """F826 !1 falsy guard falls through."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(!1){break lbl;}"
         "r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "xx" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f827_ws():
    """F827 ws-tolerant for(;;) blocks."""
    s = ("(function(){var r='';outer:for( ; ; ){r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f827_falsy_guarded_accum():
    """F827 falsy-guarded accum skipped, break taken."""
    s = ("(function(){var r='';outer:for(;;){if(0)r+='x';r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_f827_let():
    """F827 let-decl twin blocks."""
    s = ("(function(){let r='';outer:for(;;){r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f826_empty_braces():
    """F826 empty braced consequent fails closed."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){}r+='" + _B
         + "';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f826_nested_if():
    """F826 nested if inside braces fails closed."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){if(0)break lbl;}"
         "r+='" + _B + "';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f826_wrong_label():
    """F826 break for another label fails closed."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){break nope;}"
         "r+='" + _B + "';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f826_continue_in_braces():
    """F826 continue inside braced block consequent fails closed."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(1){continue lbl;}"
         "r+='" + _B + "';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f826_nonliteral_guard():
    """F826 non-literal guard fails closed."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';if(x){break lbl;}"
         "r+='" + _B + "';}return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f827_no_break():
    """F827 for(;;) with no reachable break fails closed (hang)."""
    s = "(function(){var r='';outer:for(;;){r+='x';}return r;})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f827_truthy_continue():
    """F827 truthy continue in for(;;) fails closed (hang)."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';continue outer;}return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f827_falsy_break_only():
    """F827 for(;;) with only falsy-guarded breaks fails closed."""
    s = ("(function(){var r='';outer:for(;;){if(0){break outer;}r+='x';}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f827_wrong_label():
    """F827 break for another label fails closed."""
    s = ("(function(){var r='';outer:for(;;){r+='" + _A
         + "';break nope;}return r+'" + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f827_unlabeled_continue():
    """F827 unlabeled continue in for(;;) fails closed (hang)."""
    s = ("(function(){var r='';outer:for(;;){r+='a';continue;break outer;}"
         "return r;})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_f784_bare_twins_intact():
    """F784 bare-consequent twins still block."""
    s1 = ("(function(){var r='';lbl:{r+='" + _A + "';if(1)break lbl;"
          "r+='xx';}return r+'" + _B + "';})()")
    s2 = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A
          + "';continue outer;r+='xx';}return r+'" + _B + "';})()")
    ok = _blocked(s1) and _blocked(s2)
    return ("HELD" if ok else "BREAK", "twins=%s" % ok)


@_t
def test_p4_f784_counted_for_intact():
    """F784 counted-for break twin still blocks."""
    s = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A
         + "';break outer;}return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f655_intact():
    """F655 unconditional-break-only subset still blocks."""
    s = ("(function(){var r='';lbl:{r+='" + _A + "';break lbl;r+='xx';}"
         "return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f785_intact():
    """F785 flag-while twin still blocks."""
    s = ("(function(){var r='';var go=true;while(go){r+='" + _A
         + "';go=false;}return r+'" + _B + "';})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "hit=%s" % ok)


@_t
def test_p4_f829_still_open():
    """F829 (braced if in for body) still misses -- open by design."""
    s1 = ("(function(){var r='';outer:for(var i=0;i<1;i++){r+='" + _A
          + "';if(1){break outer;}r+='xx';}return r+'" + _B + "';})()")
    s2 = ("(function(){var r='';outer:for(;;){if(1){r+='" + _A
          + "';break outer;}r+='xx';}return r+'" + _B + "';})()")
    ok = _misses(s1) and _misses(s2)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p5: junk / honest quiet


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    honest = ("the outer for loop breaks when the label matches and "
              "the braced block runs once")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in <20s with zero hits."""
    sites = []
    for k in range(200):
        if k % 4 == 0:
            sites.append(
                "(function(){var r='';lbl:{r+='a%d';if(1){break lbl;}"
                "r+='xx';}return r;})()" % k)
        elif k % 4 == 1:
            sites.append(
                "(function(){var r='';outer:for(;;){r+='a%d';break outer;}"
                "return r;})()" % k)
        elif k % 4 == 2:
            sites.append(
                "(function(){var r='';lbl:{r+='a%d';if(1)break nope;}"
                "return r;})()" % k)
        else:
            sites.append(
                "(function(){var r='';outer:for(;;){r+='a%d';}return r;})()"
                % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts: F826/F827/F828 expect 0 BREAK (closed); F829 expects
    # 2 BREAK (open by design). All functional probes must HELD.
    for batt, expect_break in (("evals/w386_f826_redfirst.py", 0),
                               ("evals/w386_f827_redfirst.py", 0),
                               ("evals/w386_f828_redfirst.py", 0),
                               ("evals/w386_f829_redfirst.py", 2)):
        tmp = tempfile.mkdtemp(prefix="g386-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts at expected tallies."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
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
