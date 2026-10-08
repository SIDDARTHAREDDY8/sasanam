#!/usr/bin/env python3
"""Red-first for F644: sync for-of fragment assembly over sync iterables.

F640 (this lane) closes `for await...of` over sync iterables, but the
SYNC `for...of` twin is a different production with no modeled path:
the loop accumulates fragments synchronously while node evaluates
exactly. Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("forof-accumulate",
     "(function(){var s='';for (const x of ['%s','%s','%s']) s+=x; return s;})()"
     % (_F1, _F2, _F3), True),
    ("forof-push-join",
     "(function(){var p=[];for (const x of ['%s','%s','%s']) p.push(x); return p.join('');})()"
     % (_F1, _F2, _F3), True),
    ("forof-map-values",
     "(function(){var s='';for (const x of new Map([['a','%s'],['b','%s'],['c','%s']]).values()) s+=x; return s;})()"
     % (_F1, _F2, _F3), True),
]

CONTROLS = [
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
