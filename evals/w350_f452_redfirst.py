#!/usr/bin/env python3
"""Red-first for F452: fail-closed JS-expression matches consume the
whole-text scan's attempt budget.

gov/dlp.py `_try_js_expr_decode_all` (F444) increments its attempt
counter for EVERY `_JS_EXPR_START` match -- including matches that fail
closed (return None). Bare string-literal statements (`'j0';`) are valid
JS expression statements that the static decoder rejects (not
obfuscation-shaped: `state["ops"] == 0`), so each one burns an attempt
without decoding anything. With 32 such statements (64 quote matches)
ahead of a real `['frag','frag'].reduce((a,b)=>a+b)` assembly (a verified
F437 shape), the 64-attempt budget is exhausted before the scan reaches
the real expression, and the per-match fallback (`[:_MAX_CANDIDATES]`)
sees only junk -- so the real expression is never decoded and
find_credential misses. A real JS engine evaluates the whole payload to
the credential (last statement wins; node-verified).

Distinct from F444: F444 was DECODABLE junk consuming the 2-layer
budget (each layer decodes the leftmost junk first); its honest residual
was documented as ~130+ junk expressions. This needs only 64 matches
(32 bare statements) -- below the documented residual -- via a different
mechanism (attempt consumption by undecodable matches, not layer
exhaustion).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: the real reduce alone blocks (F437 shape); 31 junk statements
(62 matches, under the budget) still block -- pinning the exact
threshold; 70 DECODABLE junk expressions + real still block (the F444
whole-text 2-layer composition is intact); junk alone is quiet; plain
credential blocks coded.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-abc123"
B = "def" + "456"
CRED = A + B
REAL = "['" + A + "','" + B + "'].reduce((a,b)=>a+b)"


def _junk(n):
    return "".join("'%s';" % ("j%d" % i) for i in range(n))


def _decodable_junk(n):
    return "".join("'j%d'+'k%d';" % (i, i) for i in range(n))


SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("junk32-real", _junk(32) + REAL, True),  # 64 matches: budget exhausted
    ("junk64-real", _junk(64) + REAL, True),  # 128 matches: budget exhausted
]

CONTROLS = [
    # (name, payload, want_hit)
    ("real-alone", REAL, True),  # F437 shape blocks
    ("junk31-real", _junk(31) + REAL, True),  # 62 matches: under budget
    ("decodable-junk70-real", _decodable_junk(70) + REAL, True),  # F444 intact
    ("junk-alone", _junk(32), False),  # no credential: quiet
    ("plain-credential", CRED, True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        # BREAK = genuine miss: real engine recovers, scanner misses.
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
