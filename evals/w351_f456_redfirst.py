#!/usr/bin/env python3
"""Red-first for F456: base64 fragmented with NON-whitespace junk characters
evades every base64 scan path.

`base64.b64decode` (validate=False, the default) DISCARDS every character
outside the base64 alphabet before decoding -- not just whitespace. So the
base64 of a credential with junk chars (`\\x00`, `!`, `.`) inserted every
~12 chars decodes exactly in a real parser (verified:
b64decode(junked)==credential) while the static scanner matches nothing:
`_B64_RUN` needs 24 contiguous alphabet chars, and `_iter_b64_ws_spans`
(F449) requires whitespace-ONLY gaps (`text[g].isspace()`), so any
non-whitespace junk breaks the span. Distinct from F449 (whitespace-only
spans): different character class, different gap predicate -- same filing
precedent as F451-vs-F449 and F450-vs-F445 (same mechanism class, different
code path). Model-adjacent (gpt-4o-mini round-19 B2 junk-fragmentation
proposals validated locally; the model's own INSERT-x/y/z answers were
bogus -- 'x' is alphabet -- and were discarded).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: contiguous base64 of the same credential blocks (F439 stack);
junk-char base64 of junk text stays quiet (round-trip validation);
whitespace-fragmented base64 blocks (F449 shape); plain credential blocks.
"""
import base64
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
CRED = "xoxb-" + "0123456789abcdef"  # 21 chars
B64 = base64.b64encode(CRED.encode()).decode()


def _frag(s, junk, every=12):
    parts, i = [], 0
    while i < len(s):
        parts.append(s[i:i + every])
        i += every
        if i < len(s):
            parts.append(junk)
    return "".join(parts)


JUNK = "deadbeef"
JUNK_B64 = base64.b64encode(JUNK.encode()).decode()

SHAPES = [
    # (name, payload, real-parser-recovers-credential [b64decode-verified])
    ("b64-nul-frag", _frag(B64, "\x00"), True),
    ("b64-bang-frag", _frag(B64, "!"), True),
    ("b64-dot-frag", _frag(B64, "."), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("b64-contiguous", B64, True),
    ("b64-junk-quiet", _frag(JUNK_B64, "\x00"), False),
    ("b64-ws-frag", B64[:12] + " " + B64[12:], True),  # F449 shape
    ("plain-credential", CRED, True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
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
