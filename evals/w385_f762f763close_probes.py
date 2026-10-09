#!/usr/bin/env python3
"""Wave-385 lane 1: close F762 + F763 (charAt/.at indexed reads; normalize identity).

F762 (LOW; filed 2026-10-09 by wave-384 lane 13, attack round 52): indexed
character reads -- the decoder models slice/substring/split string methods
but has no production for indexed character reads: charAt() and the ES2022
.at() method resolve node-exactly while the decoder produces zero variants.

F763 (LOW; filed 2026-10-09 by wave-384 lane 13, attack round 52): String
prototype normalize identity -- Unicode normalization is the identity on
already-normal ASCII, but the decoder has no normalize production:
s.normalize() passes the fragment through node-exactly while the decoder
produces zero variants.

Fix (gov/dlp.py, zero new re.compile):
- F762: "charAt" added to _JS_POSTFIX_METHOD_NAMES; the new
  `if name == "charAt":` branch (plain-str receiver; integer-literal
  index, zero-arg = index 0; negative/out-of-range -> "" engine-exact;
  non-BMP receivers fail closed -- UTF-16 code-unit vs code-point
  divergence, F624 slice parity); string-receiver branch at the top of
  the F547 `if name == "at":` branch (negative counts back from end;
  out-of-range returns undefined in the engine -> fail closed, the
  decoder has no undefined value; disjoint by receiver type).
- F763: "normalize" added to _JS_POSTFIX_METHOD_NAMES; the new
  `if name == "normalize":` branch -- ASCII-only receivers are
  the identity for all four forms (NFC/NFD/NFKC/NFKD have no effect on
  ASCII); non-ASCII receivers fail closed; FORM must be a canonical
  string literal (engine throws RangeError otherwise); zero args = NFC.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
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
    """Control: lane-local footer (F762/F763 closed, next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text
          and "Open findings: F764, F765, F766, F767, F768, F769, F770, "
              "F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, "
              "F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, "
              "F791, F792, F793, F794." in text)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f762_s1():
    """F762 filed shape 1 (charAt) blocks + decodes node-exact."""
    s = ("(function(){var s='" + _A + "';return s.charAt(0)+s.slice(1)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f762_s2():
    """F762 filed shape 2 (.at) blocks + decodes node-exact."""
    s = ("(function(){var s='" + _A + "';return s.at(0)+s.at(1)"
         "+s.slice(2)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f763_s1():
    """F763 filed shape 1 (normalize()) blocks + decodes node-exact."""
    s = ("(function(){var s='" + _A + "';return s.normalize()+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p1_f763_s2():
    """F763 filed shape 2 (normalize('NFD')) blocks + exact."""
    s = ("(function(){var s='" + _A + "';return s.normalize('NFD')+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (must block)


@_t
def test_p2_charat_noarg():
    """charAt() with no args reads index 0, node-exact."""
    s = ("(function(){var s='" + _A + "';return s.charAt()+s.slice(1)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_charat_last():
    """charAt on a longer string: s.slice(1) + s.charAt(0), node-exact."""
    s = ("(function(){var s='x" + _A + "';return s.slice(1)+s.charAt(0)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "x" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_at_negative():
    """.at(-1) counts back from the end, node-exact."""
    s = ("(function(){var s='" + _A + "x';return s.slice(0,-1)+s.at(-1)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + "x" + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_at_noarg():
    """.at() with no args reads index 0, node-exact."""
    s = ("(function(){var s='" + _A + "';return s.at()+s.slice(1)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_normalize_forms():
    """normalize('NFC'/'NFKC'/'NFKD') all identity on ASCII."""
    ok = True
    for form in ("NFC", "NFKC", "NFKD"):
        s = ("(function(){var s='" + _A + "';return s.normalize('"
             + form + "')+'" + _B + "';})()")
        ok = ok and _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "all-forms=%s" % ok)


@_t
def test_p2_chain():
    """charAt().normalize().at() chain resolves node-exactly."""
    s = ("(function(){var s='" + _A + "';return s.charAt(0).normalize()"
         "+s.slice(1).at(0)+s.slice(2)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


@_t
def test_p2_bracket_form():
    """s['charAt'](0) bracket-call twin blocks + exact."""
    s = ("(function(){var s='" + _A + "';return s['charAt'](0)"
         "+s.slice(1)+'" + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "hit+exact=%s" % ok)


# ------------------------------------------------ p3: bounds (must fail closed)


@_t
def test_p3_charat_fractional():
    """charAt(1.5): non-integer index fails closed."""
    s = ("(function(){var s='" + _A + "';return s.charAt(1.5)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_charat_nonliteral():
    """charAt(x): non-literal index fails closed."""
    s = ("(function(){var s='" + _A + "';return s.charAt(x)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_charat_extra_arg():
    """charAt(0,1): extra args fail closed."""
    s = ("(function(){var s='" + _A + "';return s.charAt(0,1)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_at_out_of_range():
    """.at(99): engine returns undefined -> the credential is not
    recovered. (The whole-text scanner's inner `(99)` anchor may still
    emit a credential-free variant -- pre-existing F444 behavior,
    identical on base; the security property is no recovery.)"""
    s = ("(function(){var s='" + _A + "';return s.at(99)+'"
         + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_at_negative_oob():
    """.at(-99): engine returns undefined -> fail closed."""
    s = ("(function(){var s='" + _A + "';return s.at(-99)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_charat_nonbmp():
    """charAt on a non-BMP string fails closed (code-unit vs
    code-point divergence)."""
    s = "(function(){var s='\\u{10000}';return s.charAt(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_at_nonbmp():
    """.at on a non-BMP string fails closed."""
    s = "(function(){var s='\\u{10000}';return s.at(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_charat_on_number():
    """(123).charAt(0): engine throws -> fail closed."""
    s = "(function(){return (123).charAt(0);})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_normalize_bad_form():
    """normalize('nfc'): engine throws RangeError -> the credential is
    not recovered. (Same pre-existing inner-anchor note as
    test_p3_at_out_of_range.)"""
    s = ("(function(){var s='" + _A + "';return s.normalize('nfc')+'"
         + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "no-recovery=%s" % ok)


@_t
def test_p3_normalize_nonliteral_form():
    """normalize(x): non-literal form fails closed."""
    s = ("(function(){var s='" + _A + "';return s.normalize(x)+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_normalize_extra_arg():
    """normalize('NFC','x'): extra args fail closed."""
    s = ("(function(){var s='" + _A + "';return s.normalize('NFC','x')+'"
         + _B + "';})()")
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


@_t
def test_p3_normalize_nonascii():
    """normalize('NFD') on non-ASCII fails closed (combining marks
    change the string)."""
    s = "(function(){var s='caf\\u00e9';return s.normalize('NFD');})()"
    ok = _fails_closed(s)
    return ("HELD" if ok else "BREAK", "closed=%s" % ok)


# ------------------------------------------------ p4: siblings + open neighbors


@_t
def test_p4_sibling_slice():
    """F624 slice pin still blocks (full credential recovered)."""
    s = ("(function(){var s='" + _A + "';return s.slice(0,9)+'"
         + _B + "';})()")
    ok = _blocked(s) and _decodes_exact(s, _A + _B)
    return ("HELD" if ok else "BREAK", "slice=%s" % ok)


@_t
def test_p4_sibling_array_at():
    """F547 array-literal .at() pin still blocks."""
    s = ("(function(){return ['" + _A + "','" + _B + "'].at(0)+['"
         + _A + "','" + _B + "'].at(-1);})()")
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "array-at=%s" % ok)


@_t
def test_p4_neighbor_f764_open():
    """Neighbor F764 (substr) still misses -- honest open shape."""
    s = ("(function(){var s='xx" + _A + "';return s.substr(-9)+'"
         + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f764-open=%s" % ok)


@_t
def test_p4_neighbor_f794_open():
    """Neighbor F794 (non-string toPrimitive) still misses."""
    s = ("(function(){var o={};o[Symbol.toPrimitive]=function(){return 120;};"
         "return String.fromCharCode(o)+'" + _B + "';})()")
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "f794-open=%s" % ok)


# ------------------------------------------------ p5: quiet + honest


@_t
def test_p5_junk_quiet():
    """Junk stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_charat_unaffected():
    """Honest charAt without a credential still misses."""
    s = "(function(){var s='abcdef';return s.charAt(2);})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


@_t
def test_p5_honest_normalize_unaffected():
    """Honest normalize without a credential still misses."""
    s = "(function(){var s='hello';return s.normalize('NFC');})()"
    ok = _misses(s)
    return ("HELD" if ok else "BREAK", "honest=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in under 20s with zero hits."""
    sites = []
    for k in range(100):
        sites.append(
            "(function(){var s='a%d';return s.charAt(0)+s.at(-1);})()" % k)
        sites.append(
            "(function(){var t='b%d';return t.normalize()+t.charAt(1);})()"
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
    # The two red-firsts must be 0 BREAK (F762/F763 closed); the
    # wave-384 attack battery is expected to report exactly 1 BREAK:
    # its test_b0_footer_state asserts the base footer, while this
    # lane's footer is lane-local (F762/F763 closed) -- tree-wide
    # repoint is merge-owned (wave-305 lesson). All functional
    # probes must HELD.
    for batt, expect_break in (("evals/w384_f762_redfirst.py", 0),
                               ("evals/w384_f763_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 1)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
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
    """Depth-1 green check: both red-firsts 0 BREAK + wave-384 attack
    battery 1 BREAK (footer pin only, lane-local; merge-owned)."""
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
