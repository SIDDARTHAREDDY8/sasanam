#!/usr/bin/env python3
"""Red-first for F676: optional-chaining beyond F665.

Optional-chaining shapes beyond F665 (bare ?. member reads): ?.() method calls, ?.[] bracket reads, nullish combos (o?.x ?? lit), and chained ?. reads have no modeled path.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("opt-call",
     "(function(){var o={f:function(){return 'xoxb-0123';}};return o?.f()+'456789abcdef';})()", True),
    ("opt-bracket",
     "(function(){var o={x:'xoxb-0123'};return o?.['x']+'456789abcdef';})()", True),
    ("opt-nullish",
     "(function(){var o=null;return (o?.x ?? 'xoxb-0123')+'456789abcdef';})()", True),
    ("opt-chain",
     "(function(){var o={x:{y:'xoxb-0123'}};return o?.x?.y+'456789abcdef';})()", True),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
