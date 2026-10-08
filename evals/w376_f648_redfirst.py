#!/usr/bin/env python3
"""Red-first for F648: URLSearchParams no-arg constructor with append mutations and getAll().join().

F599 (CLOSED) models append/set mutations on `new URLSearchParams('LIT')`
-- the grammar requires a literal constructor string. The no-argument
constructor form `new URLSearchParams()` with the same appends and a
getAll('k').join('') terminal has no modeled path. (set/get terminals on the
no-arg form already block; the gap is specifically getAll().join().)
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
    ("usp-noarg-getall-join",
     "(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s%s');return p.getAll('q').join('');})()" % (_F1, _F2, _F3), True),
    ("usp-noarg-three-appends",
     "(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s');p.append('q','%s');return p.getAll('q').join('');})()" % (_F1, _F2, _F3), True),
    ("usp-noarg-getall-map",
     "(function(){var p=new URLSearchParams();p.append('q','%s');p.append('q','%s%s');return p.getAll('q').map(function(x){return x;}).join('');})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f599-emptystr-ctor-still-blocks",
     "(function(){var p=new URLSearchParams('');p.append('q','%s');p.append('q','%s%s');return p.getAll('q').join('');})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var p=new URLSearchParams();p.append('q','jx');return p.getAll('q').join('');})()", False),
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
