#!/usr/bin/env python3
"""Red-first for F646: Array.prototype.forEach fragment accumulation.

F601 (CLOSED) models Map.prototype.forEach with value-accumulating
callbacks, but Array.prototype.forEach is a different receiver with a
different callback signature and has no modeled path: push-into-array and
string-accumulator twins both escape.
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
    ("foreach-push-join",
     "(function(){var p=[];['%s','%s%s'].forEach(function(x){p.push(x);});return p.join('');})()" % (_F1, _F2, _F3), True),
    ("foreach-accumulate",
     "(function(){var s='';['%s','%s%s'].forEach(function(x){s+=x;});return s;})()" % (_F1, _F2, _F3), True),
    ("foreach-arrow",
     "(function(){var s='';['%s','%s%s'].forEach((x)=>{s+=x;});return s;})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f601-map-foreach-still-blocks",
     "(function(){var s='';new Map([['a','%s'],['b','%s%s']]).forEach(function(v){s+=v;});return s;})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var s='';['jx','jy'].forEach(function(x){s+=x;});return s;})()", False),
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
