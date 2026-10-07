#!/usr/bin/env python3
"""Wave-351 F452 closure battery: fail-closed JS-expression matches must
not consume the whole-text scan's attempt budget.

F452 (LOW, filed 2026-10-06 wave-350 lane 4 (continuous real-model
attack, round 18, gpt-4o-mini); CLOSED 2026-10-06 wave-351 lane 2):
gov/dlp.py `_try_js_expr_decode_all` (F444) incremented its attempt
counter for EVERY `_JS_EXPR_START` match -- including matches that fail
closed. Bare string-literal statements (`'j0';`) are valid JS expression
statements that the static decoder rejects (not obfuscation-shaped:
`state["ops"] == 0`), so each one burned an attempt without decoding
anything. With 32 such statements (64 quote matches) ahead of a real
`['frag','frag'].reduce((a,b)=>a+b)` assembly (a verified F437 shape)
the 64-attempt budget was exhausted before the scan reached the real
expression, and the per-match fallback (`[:_MAX_CANDIDATES]`) saw only
junk -- find_credential missed while node evaluates the whole payload
to the credential (last statement wins; node-verified on the exact
red-first shape). Distinct from F444 (decodable junk consuming the
2-layer budget; documented residual ~130+): this needed only 64
matches -- below the residual -- via attempt consumption by undecodable
matches, not layer exhaustion.

Close-when: fail-closed matches do not starve decodable expressions out
of the scan budget. Fix: the `_MAX_WHOLETEXT_ITEMS` (64) budget now
counts only DECODE-PRODUCING attempts -- a match that fails closed
returns None, consumes no budget, and is copied verbatim. The budget
remains a DoS guard on actual decoding work: each counted attempt
splices decoded text into the output and advances the scan past it, so
output growth and splice count stay bounded; a fail-closed attempt
costs only one internally-bounded `_try_js_expr_decode` call
(literal/run/ops budgets), so provably-undecodable junk can neither
starve the real expression nor buy unbounded work. F444 guarantees
preserved: decodable junk still consumes the budget (~130+ decodable
junk remains the documented residual), the 70-decodable-junk
composition still blocks via the 2-layer mechanism, the 31-junk
threshold pin still holds, and the F441 `_decode_layer` ordering is
untouched. Red-first verified (w350_f452_redfirst.py: BREAK -> HELD).

Honest residual (documented, not a finding): junk that DOES decode
still consumes the 64-per-layer budget -- same F444 residual as before.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: junk32/junk64/junk200 fail-closed statements + real
      reduce all block coded dlp-slack-token; mixed fail-closed junk
      (bare literals + constant-false filter + undecodable) + real
      blocks.
  P2  controls: plain credential blocks; junk alone quiet; honest
      non-credential JS text quiet; scan no-op on non-JS text and on
      a bare credential.
  P3  budget-semantics pins: fail-closed matches consume no budget
      (whole-text variant decodes the real past 200 junk statements);
      decode-producing matches still consume it (70 decodable junk:
      first 64 decode, 65th+ verbatim); matches inside decoded spans
      skipped; F441 _decode_layer ordering intact.
  P4  node fidelity: whole-text variant contains the node-verified
      final value; threshold pins (31 junk still blocks, 32
      fail-closed junk + real now blocks); whole-text agrees with
      per-match on a single expression.
  P5  discrimination: junk never manufactures a credential-shaped
      string.
  P6  ReDoS: hostile near-miss inputs (long fail-closed junk runs,
      quote soup, long concat) complete fast, no exceptions (no new
      regexes -- reuses _JS_EXPR_START).
  P7  no-regression: adjacent closures still block (F437 reduce, F443
      fill, F441 bslash, F439 triple-b64, F440 double-entity, F438
      entity+NUL, F444 junk3+real).
  P8  pin + footer: taxonomy pin 2140 (no new decision codes), footer
      open F451, F453 / next F454, F452 CLOSED entry present.
  PZ  green check: adjacent DLP batteries green (depth-1); footer-pin
      failures are expected-for-merge (tree-wide sweep left for the
      wave-351 merge coordinator) and are isolated from behavioral
      failures.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w351_f452close_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-351: F452 closed, no new decision codes; pin unchanged 2135; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F570, F571, F572, F573, F574, F575, F576, F577, F578, F579, F580, F581, F582"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (4/5): F454-F460 CLOSED; open none (next F461)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # Wave-352 merge (2/5): F456+F457 CLOSED; F458-F460 still OPEN (next F461)  # Wave-351: F452 CLOSED locally (merge finalizes tree-wide); F451+F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 lane 4: F458-F460 CLOSED (merge finalizes tree-wide); Wave-351: F452 CLOSED locally (merge finalizes tree-wide); F451+F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 2: F463 CLOSED, F469 filed OPEN (next F470)  # Wave-353 lane 2 renumber: F469->F472 (attack lane committed F469-F471 first, e79af076); footer next F473  # Wave-353 lane 4: F467+F468 CLOSED locally (merge finalizes tree-wide)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 lane 2: F507+F508 CLOSED locally (merge finalizes tree-wide)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
FOOTER_NEXT = "F583"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-351: next free finding after F452's closure  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 lane 2: F463 CLOSED, F469 filed OPEN (next F470)  # Wave-353 lane 2 renumber: F469->F472 (attack lane committed F469-F471 first, e79af076); footer next F473  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)

from gov import dlp  # noqa: E402
from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xox" + "b-abc123"
_B = "def" + "456"
_CRED = _A + _B

_REAL = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"


def _failclosed_junk(n):
    # bare string-literal statements: valid JS, statically rejected
    # (ops == 0) -- the F452 junk class
    return "".join("'%s';" % ("j%d" % i) for i in range(n))


def _decodable_junk(n):
    return "".join("'j%d'+'k%d';" % (i, i) for i in range(n))


_JUNK32 = _failclosed_junk(32)
_JUNK64 = _failclosed_junk(64)
_JUNK200 = _failclosed_junk(200)
_JUNK_MIXED = ("'j0';"                    # bare literal: fail closed
               "['" + _A + "'].filter(()=>false).join('');"  # const-false: fail closed
               "'a'+undefined;")          # undecodable run: fail closed


# ---------------------------------------------------------------- P1: closure

def _blocks(payload):
    return find_credential(payload) == "dlp-slack-token"


def p1_closure_junk32():
    return _blocks(_JUNK32 + _REAL)


def p1_closure_junk64():
    return _blocks(_JUNK64 + _REAL)


def p1_closure_junk200():
    # 400 quote matches, far beyond the old 64-attempt budget
    return _blocks(_JUNK200 + _REAL)


def p1_closure_junk_mixed():
    return _blocks(_JUNK_MIXED + _REAL)


# ---------------------------------------------------------------- P2: controls

def p2_plain_credential_blocks():
    return _blocks(_CRED)


def p2_junk_alone_quiet():
    return find_credential(_JUNK32) is None


def p2_honest_js_quiet():
    return find_credential("var total = prices.reduce((a,b)=>a+b, 0);") is None


def p2_noop_on_non_js():
    return dlp._try_js_expr_decode_all("hello world, no js here") is None


def p2_noop_on_plain_credential():
    # a bare credential is not obfuscation-shaped: scan must not rewrite
    return dlp._try_js_expr_decode_all(_CRED) is None


# ---------------------------------------------------------------- P3: budget-semantics pins

def p3_failclosed_consume_no_budget():
    # F452 core pin: the whole-text scan walks past 200 fail-closed
    # statements WITHOUT budget exhaustion and still decodes the real
    # expression -- the variant must contain the credential.
    v = dlp._try_js_expr_decode_all(_JUNK200 + _REAL)
    return v is not None and _CRED in v


def p3_decodable_still_consume_budget():
    # F444 guarantee: decode-producing attempts still count -- 70
    # decodable junk: first 64 decode, 65th+ copied verbatim.
    junk70 = _decodable_junk(70)
    v = dlp._try_js_expr_decode_all(junk70)
    return (v is not None and "j63k63" in v
            and "'j64'+'k64'" in v and "'j69'+'k69'" in v)


def p3_spans_skipped():
    v = dlp._try_js_expr_decode_all(_decodable_junk(3))
    return v == "j0k0;j1k1;j2k2;"


def p3_failclosed_copied_verbatim():
    # a fail-closed shape is copied verbatim by the scan, never "fixed"
    v = dlp._try_js_expr_decode_all("'j0';" + _REAL)
    return v is not None and "'j0';" in v and _CRED in v


def p3_f441_ordering_intact():
    import inspect
    src = inspect.getsource(dlp._decode_layer)
    i_bslash = src.find("_try_bslash_unescape_all")
    i_esc = src.find("_ESC_RUN.finditer")
    i_whole = src.find("_try_js_expr_decode_all")
    return 0 < i_whole < i_bslash < i_esc


# ---------------------------------------------------------------- P4: node fidelity

# node v24.20.0-verified final values (verified live 2026-10-06;
# canned here so the battery stays hermetic).

def p4_variant_contains_node_final():
    v = dlp._try_js_expr_decode_all(_JUNK32 + _REAL)
    return v is not None and _CRED in v


def p4_threshold_31_still_blocks():
    # the filed threshold pin: 31 junk statements (62 matches, under
    # the old budget) still block
    return _blocks(_failclosed_junk(31) + _REAL)


def p4_threshold_32_now_blocks():
    # the F452 minimized shape: 32 junk statements + real now blocks
    return _blocks(_JUNK32 + _REAL)


def p4_wholetext_agrees_with_permatch():
    v = dlp._try_js_expr_decode_all(_REAL)
    r = dlp._try_js_expr_decode(_REAL, 0)
    return v == r[0] and v == _CRED


# ---------------------------------------------------------------- P5: discrimination

def p5_junk_never_manufactures_credential():
    # 20 fail-closed junk statements, no credential anywhere
    v = dlp._try_js_expr_decode_all(_failclosed_junk(20))
    return v is None or find_credential(v) is None


def p5_decodable_junk_never_manufactures():
    junk = _decodable_junk(20)
    v = dlp._try_js_expr_decode_all(junk)
    return v is not None and find_credential(v) is None


# ---------------------------------------------------------------- P6: ReDoS

def _fast(fn, limit=2.0):
    t0 = time.time()
    try:
        fn()
    except Exception:
        return False
    return (time.time() - t0) < limit


def p6_redos_long_concat():
    return _fast(lambda: dlp._try_js_expr_decode_all("'a'" + "+'a'" * 5000 + ";"))


def p6_redos_long_literal():
    return _fast(lambda: dlp._try_js_expr_decode_all("'" + "j" * 20000 + "'"))


def p6_redos_failclosed_junk():
    # the F452 junk class itself: 2000 fail-closed statements, each a
    # now-unbudgeted match -- must stay fast
    return _fast(lambda: dlp._try_js_expr_decode_all(_failclosed_junk(2000)))


def p6_redos_quote_soup():
    return _fast(lambda: dlp._try_js_expr_decode_all("'" * 5000))


def p6_redos_many_expr_find():
    return _fast(lambda: find_credential("['a','b'];" * 2000))


# ---------------------------------------------------------------- P7: no-regression

def p7_noreg_f437_reduce():
    return _blocks(_REAL)


def p7_noreg_f443_fill():
    return _blocks("Array(2).fill('" + _A + _B + "').join('')")


def p7_noreg_f444_junk3_real():
    return _blocks(_decodable_junk(3) + _REAL)


def p7_noreg_f441_bslash():
    # double-backslash production still first: this shape needs it
    return _blocks("\\\\xox" + "b-abc123def" + "456")


def p7_noreg_f439_triple_b64():
    import base64
    # long credential: base64 runs clear the 24-char gate (F445 is the
    # short-credential gate, still OPEN -- not this probe's concern)
    long_cred = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"
    c = long_cred.encode()
    for _ in range(3):
        c = base64.b64encode(c)
    return _blocks(c.decode())


def p7_noreg_f440_double_entity():
    ent = "".join("&#x%x;" % o for o in _CRED.encode())
    dbl = ent.replace("&", "&amp;")
    return _blocks(dbl)


def p7_noreg_f438_entity_nul():
    ent = "".join("&#x%x;" % o for o in _CRED.encode())
    return _blocks("\x00".join(ent))


# ---------------------------------------------------------------- P8: pin + footer

def p8_pin_and_footer():
    import re
    from gov import decision_codes
    pin = len(decision_codes.TAXONOMY)
    if pin != TAXONOMY_PIN:
        print("    len(TAXONOMY)=%s want %s" % (pin, TAXONOMY_PIN))
        return False
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path, encoding="utf-8").read()
    # live footer is the LAST "Next free finding:" line (history above it)
    live = text[text.rfind("Next free finding:"):]
    m = re.search(r"Next free finding: \*\*(F\d+)\*\*\.", live)
    mo = re.search(r"Open findings: ([^.]*)\.", live)
    if not m or m.group(1) != FOOTER_NEXT:
        print("    footer next: %s want %s" % (m.group(1) if m else None,
                                              FOOTER_NEXT))
        return False
    open_seg = mo.group(1).replace("*", "") if mo else ""
    if not mo or open_seg.strip() != FOOTER_OPEN:
        print("    footer open mismatch: %s" % (mo.group(1) if mo else None))
        return False
    if "F452" in open_seg:
        print("    F452 still listed open")
        return False
    # F452 entry must carry a CLOSED status line
    idx = text.find("F452 filed")
    if idx < 0:
        print("    F452 entry missing")
        return False
    seg = text[idx:idx + 12000]
    if "**Status: CLOSED" not in seg:
        print("    F452 entry lacks CLOSED status")
        return False
    return True


_PROBES = [
    ("p1-closure-junk32", p1_closure_junk32),
    ("p1-closure-junk64", p1_closure_junk64),
    ("p1-closure-junk200", p1_closure_junk200),
    ("p1-closure-junk-mixed", p1_closure_junk_mixed),
    ("p2-plain-credential-blocks", p2_plain_credential_blocks),
    ("p2-junk-alone-quiet", p2_junk_alone_quiet),
    ("p2-honest-js-quiet", p2_honest_js_quiet),
    ("p2-noop-on-non-js", p2_noop_on_non_js),
    ("p2-noop-on-plain-credential", p2_noop_on_plain_credential),
    ("p3-failclosed-consume-no-budget", p3_failclosed_consume_no_budget),
    ("p3-decodable-still-consume-budget",
     p3_decodable_still_consume_budget),
    ("p3-spans-skipped", p3_spans_skipped),
    ("p3-failclosed-copied-verbatim", p3_failclosed_copied_verbatim),
    ("p3-f441-ordering-intact", p3_f441_ordering_intact),
    ("p4-variant-contains-node-final", p4_variant_contains_node_final),
    ("p4-threshold-31-still-blocks", p4_threshold_31_still_blocks),
    ("p4-threshold-32-now-blocks", p4_threshold_32_now_blocks),
    ("p4-wholetext-agrees-with-permatch",
     p4_wholetext_agrees_with_permatch),
    ("p5-junk-never-manufactures-credential",
     p5_junk_never_manufactures_credential),
    ("p5-decodable-junk-never-manufactures",
     p5_decodable_junk_never_manufactures),
    ("p6-redos-long-concat", p6_redos_long_concat),
    ("p6-redos-long-literal", p6_redos_long_literal),
    ("p6-redos-failclosed-junk", p6_redos_failclosed_junk),
    ("p6-redos-quote-soup", p6_redos_quote_soup),
    ("p6-redos-many-expr-find", p6_redos_many_expr_find),
    ("p7-noreg-f437-reduce", p7_noreg_f437_reduce),
    ("p7-noreg-f443-fill", p7_noreg_f443_fill),
    ("p7-noreg-f444-junk3-real", p7_noreg_f444_junk3_real),
    ("p7-noreg-f441-bslash", p7_noreg_f441_bslash),
    ("p7-noreg-f439-triple-b64", p7_noreg_f439_triple_b64),
    ("p7-noreg-f440-double-entity", p7_noreg_f440_double_entity),
    ("p7-noreg-f438-entity-nul", p7_noreg_f438_entity_nul),
    ("p8-pin-and-footer", p8_pin_and_footer),
]

_EXPECTED_BREAKS = set()  # F452 closed: no expected BREAKs


def _safe(pid, fn):
    try:
        ok = fn()
    except Exception as e:  # noqa: BLE001 - battery harness reports
        print("%-36s ERROR %s: %s" % (pid, type(e).__name__, e))
        return (pid, "ERROR")
    print("%-36s %s" % (pid, "HELD" if ok else "BREAK"))
    return (pid, "HELD" if ok else "BREAK")


def _is_footer_break(line):
    """A BREAK/ERROR line is footer-related (expected-for-merge) when the
    probe is a footer-state probe: its id or function name carries
    'footer', or its note mentions the footer state."""
    low = line.lower()
    return "footer" in low


_FOOTER_SKIP_PREFIXES = ("tally:", "green check:", "unexpected",
                         "expected", "unknown")


def _is_failing_probe_line(line):
    """True when *line* reports one probe's BREAK/ERROR verdict, in
    either battery output format ('BREAK fn: note' or 'pid BREAK').
    Summary lines (tally, green check notes, mismatch notes) are
    excluded."""
    import re
    s = line.strip()
    if s.startswith(_FOOTER_SKIP_PREFIXES):
        return False
    if re.search(r"\d+\s+(BREAK|HELD|ERROR)\s*/", s):
        return False  # "<battery>: N BREAK / M HELD / K ERROR" tally line
    return re.search(r"(^|\s)(BREAK|ERROR)(\s|:|$)", s) is not None


def _green_check():
    """Depth-1 green check: adjacent DLP batteries, green checks skipped
    in the child env (GOV_SKIP_GREEN=1). Footer-pin failures are
    expected-for-merge (the wave-351 merge coordinator owns the
    tree-wide footer sweep); only behavioral failures fail the check.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    scripts = ("w346_dlp_composition_probes.py",
               "w349_f444close_probes.py",
               "w348_f443close_probes.py",
               "w347_f437close_probes.py",
               "w347_f438close_probes.py",
               "w347_f439close_probes.py",
               "w347_f440close_probes.py",
               "w347_f441close_probes.py",
               "w347_f442close_probes.py",
               "w350_f446close_probes.py",
               "w350_f447f448close_probes.py",
               "w350_f449f450close_probes.py",
               "w347_attack_probes.py",
               "w348_attack_probes.py",
               "w349_attack_probes.py",
               "w350_attack_probes.py")
    for script in scripts:
        tmp = "/var/tmp/g351-green-%s-%d" % (script.replace(".py", ""),
                                            os.getpid())
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        out = r.stdout + r.stderr
        bad = []
        for line in out.splitlines():
            if _is_failing_probe_line(line) and not _is_footer_break(line):
                bad.append(line.strip()[:120])
        tail = out[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d behavioral_bad=%d %s"
                     % (script, r.returncode, len(bad), tail))
        if bad:
            raise AssertionError("green check behavioral failure in %s: %s"
                                 % (script, bad[:3]))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                pid2, verdict = _safe(pid, fn)
                return 0 if verdict == "HELD" else 1
        print("unknown probe", args.probe)
        return 2
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = [_safe(pid, fn) for pid, fn in _PROBES]
    brk = sum(1 for _, v in results if v == "BREAK")
    held = sum(1 for _, v in results if v == "HELD")
    err = sum(1 for _, v in results if v == "ERROR")
    print("w351_f452close: %d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    unexpected = [pid for pid, v in results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - set(
        pid for pid, v in results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
