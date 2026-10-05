#!/usr/bin/env python3
"""w344 red-first: F431 bidi-override + Cyrillic-homoglyph residuals evade DLP.

Wave-343 merge filed F431 (LOW, OPEN): two F429-closure residuals still
miss find_credential on the F429-closed tree, 2/2 verified:

  plain credential                      -> BLOCKS coded dlp-slack-token (control)
  U+202E RLO interleaved + reversed tail -> MISS (no bidi-control normalization)
  Cyrillic U+043E for 'o'                -> MISS (does NOT NFKC-fold to ASCII)

The F429 close-when covered text-escape transforms, HTML entities,
UTF-16 null-interleave, fullwidth confusables, and zero-width joiners --
but not bidi-override controls (U+202A-U+202E, U+2066-U+2069) and not
homoglyphs outside NFKC's fold set.

Expected on the OPEN tree: prints BREAK (F431 is OPEN).
After the F431 closure (decode layer strips bidi controls / reverses
RLO-governed runs to visual order, and applies a bounded static
Cyrillic-homoglyph map): prints HELD.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402

_CRED = "xoxb-abc123def456"


def _bidi_rlo(s):
    """Interleave U+202E (RLO) and reverse the governed run, the way a
    renderer displays it: the BYTES read 'xoxb-<reversed>' while the
    VISUAL rendering shows the credential."""
    head, tail = s.split("-", 1)
    return head + "-\u202e" + tail[::-1]


def _cyrillic_o(s):
    """Substitute Cyrillic small letter O (U+043E) for ASCII 'o'."""
    assert "\u043e" not in s
    return s.replace("o", "\u043e")


def main():
    transforms = {
        "bidi-rlo-reversed": _bidi_rlo(_CRED),
        "cyrillic-homoglyph-o": _cyrillic_o(_CRED),
    }
    # Discipline: no transform may smuggle the plaintext credential.
    for name, t in transforms.items():
        assert _CRED not in t, "transform %s smuggles plaintext" % name

    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    print("control plain credential: blocked=%s rule=%s" % (blocked, rule))
    assert blocked and rule == "dlp-slack-token", "control drifted"

    misses = 0
    for name, t in transforms.items():
        hit = dlp.find_credential("token=" + t)
        print("%-20s find_credential=%s" % (name, hit))
        misses += hit is None
    broke = (misses == len(transforms)) and blocked
    print("F431 bidi/homoglyph decode-layer gap reproduces: %s -> %s"
          % (broke, "BREAK" if broke else "HELD"))


if __name__ == "__main__":
    main()
