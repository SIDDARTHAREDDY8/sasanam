#!/usr/bin/env python3
"""Red-first for F657: var-bound Map receiver in forEach accumulation.

F601 (CLOSED) models Map.prototype.forEach value-accumulation but its grammar requires an INLINE `new Map(...)` receiver. A var-bound Map receiver misses node-exactly (v24.20.0) -- unlisted in F601's residuals.
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
    ("var-bound-map-foreach",
     "(function(){var m=new Map([['k','" + _A + "'],['j','" + _B + "']]);var s='';m.forEach(function(v){s+=v;});return s;})()"),
    ("let-bound-map-foreach-arrow",
     "(function(){let m=new Map([['k','" + _A + "'],['j','" + _B + "']]);let s='';m.forEach((v)=>{s+=v;});return s;})()"),
]

CONTROLS = [
    ("f601-inline-still-blocks",
     "(function(){var s='';new Map([['k','" + _A + "'],['j','" + _B + "']]).forEach(function(v){s+=v;});return s;})()", True),
    ("junk-quiet",
     "(function(){var m=new Map([['k','jx']]);var s='';m.forEach(function(v){s+=v;});return s;})()", False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
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
