#!/usr/bin/env python3
"""Red-first for F640: for-await over sync iterables fragment assembly.

F619 (CLOSED) covers SYNC generator (function*) yield/spread/for-of/Array.from;
F631 (OPEN) covers ASYNC generators. But `for await...of` over a SYNC iterable
(array literal, Map.values()) is a different production with no modeled path:
the loop accumulates fragments asynchronously while node evaluates exactly.
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("forawait-accumulate",
     "(async()=>{var s='';for await (const x of ['%s','%s','%s']) s+=x; return s;})()"
     % (_F1, _F2, _F3), True),
    ("forawait-push-join",
     "(async()=>{var p=[];for await (const x of ['%s','%s','%s']) p.push(x); return p.join('');})()"
     % (_F1, _F2, _F3), True),
    ("forawait-map-values",
     "(async()=>{var s='';for await (const x of new Map([['a','%s'],['b','%s'],['c','%s']]).values()) s+=x; return s;})()"
     % (_F1, _F2, _F3), True),
]

CONTROLS = [
    # F631 (OPEN) still misses -- open-pin control, not a closure.
    ("f631-still-open",
     "(async function(){async function* g(){yield '%s';yield '%s';}var s='';for await (var x of g()){s+=x;}return s;})()"
     % (_F1, _F2), False),
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
