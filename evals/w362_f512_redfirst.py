"""F512 red-first battery: whole-text JS-expression scan DoS guard.

Wave-352 (via wave-351 lane 2's F452 closure) changed
_try_js_expr_decode_all to count only DECODE-PRODUCING attempts
against _MAX_WHOLETEXT_ITEMS. That fixes the F452 starvation class
but removed the DoS guard on fail-closed attempts: a hostile input
with thousands of obfuscation-shaped-but-undecodable anchor matches
(e.g. '"a".concat(' * 2000 -> 6000 _JS_EXPR_START matches) forces one
deep recursive _try_js_expr_decode per match. Measured on the base
tree: 13.45s for the w344 P5 corpus (5s threshold RED), 0.12s at the
wave-344 merge -- a ~100x decoder perf regression, bisected to
wave-352. The merge report's "environmental" verdict was wrong.

The fix (f506_patch.diff, NOT applied here): _MAX_WHOLETEXT_ATTEMPTS
= 512 counts EVERY match attempt, fail-closed included, against an
independent cap. 512 = 8x the item budget and above the F452
battery's pinned 200-statement (400-match) scenario, so the F452
closure is not regressed.

Red-first contract (deterministic, host-independent -- counts, not
wall time):
  p1  BREAK on base (6000 decode attempts), HELD on fixed (<= 512)
  p2  F452 battery pin: 200 fail-closed statements + real decodes
      (HELD on both -- guards the fix against reintroducing F452)
  p3  F452 filing scenario: 32 fail-closed + real decodes
  p4  control: single real expression decodes; junk alone is quiet

Usage:
  ~/workspace/.gov-venv/bin/python evals/w362_f506_redfirst.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import gov.dlp as dlp  # noqa: E402

# F512 cap proposed by the fix; the base tree has no total cap.
F512_TOTAL_ATTEMPT_CAP = 512

_HOSTILE_MANY_MATCH = "token=" + '"a".concat(' * 2000  # 6000 matches

_JUNK1 = "".join("'%s';" % ("j%d" % i) for i in range(200))  # 400 matches
_JUNK32 = "".join("'%s';" % ("j%d" % i) for i in range(32))  # 64 matches
# Constructed via concatenation (matches the w351 F452 battery).
_A = "xox" + "b-abc123"
_B = "def" + "456"
_CRED = _A + _B
_REAL = "['" + _A + "','" + _B + "'].reduce((a,b)=>a+b)"


def _counted_scan(text):
    """Run the whole-text scan counting _try_js_expr_decode calls."""
    calls = [0]
    orig = dlp._try_js_expr_decode

    def _wrapped(t, s):
        calls[0] += 1
        return orig(t, s)

    dlp._try_js_expr_decode = _wrapped
    try:
        return dlp._try_js_expr_decode_all(text), calls[0]
    finally:
        dlp._try_js_expr_decode = orig


def p1_attempts_capped():
    _, n = _counted_scan(_HOSTILE_MANY_MATCH)
    return n <= F512_TOTAL_ATTEMPT_CAP


def p2_f452_200_junk_still_decodes():
    # F452 battery pin: 200 fail-closed statements (400 matches) must
    # not starve the real expression -- the fix cap (512) is above
    # this, so the F452 closure is preserved.
    v = dlp._try_js_expr_decode_all(_JUNK1 + _REAL)
    return v is not None and _CRED in v


def p3_f452_32_junk_still_decodes():
    v = dlp._try_js_expr_decode_all(_JUNK32 + _REAL)
    return v is not None and _CRED in v


def p4_controls():
    v = dlp._try_js_expr_decode_all(_REAL)
    real_ok = v is not None and _CRED in v
    junk_quiet = dlp.find_credential(_JUNK32) is None
    return real_ok and junk_quiet


_PROBES = [
    ("p1-attempts-capped-512", p1_attempts_capped),
    ("p2-f452-200-junk-still-decodes", p2_f452_200_junk_still_decodes),
    ("p3-f452-32-junk-still-decodes", p3_f452_32_junk_still_decodes),
    ("p4-controls", p4_controls),
]

_EXPECTED_BREAKS = set()  # wave-362 merge: fix applied, p1 now HELD (wave-306 class)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    from gov.decision_codes import TAXONOMY
    assert len(TAXONOMY) == 2135, "taxonomy pin"
    return "pin 2135 HELD"


def main():
    print("green check: %s" % _green_check())
    breaks, held, errors = [], [], []
    for pid, fn in _PROBES:
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001 - battery reports
            print("%-36s ERROR %s: %s" % (pid, type(e).__name__, e))
            errors.append(pid)
            continue
        print("%-36s %s" % (pid, "HELD" if ok else "BREAK"))
        (held if ok else breaks).append(pid)
    print("w362_f512_redfirst: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    unexpected = [b for b in breaks if b not in _EXPECTED_BREAKS]
    missing = [b for b in _EXPECTED_BREAKS if b not in breaks]
    if unexpected or missing or errors:
        print("MISMATCH: unexpected=%s missing=%s errors=%s"
              % (unexpected, missing, errors))
        sys.exit(1)


if __name__ == "__main__":
    main()
