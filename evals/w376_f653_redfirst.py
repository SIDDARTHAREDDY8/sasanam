#!/usr/bin/env python3
"""Red-first for F653: custom Symbol.iterator spread/for-of fragment assembly.

The decoder models spread/join of array literals, but a custom iterable
protocol -- an object literal defining [Symbol.iterator] whose next()
yields bound fragments -- has no modeled path: spread, for-of, and Array.from
all consume it while the static parse sees only the object literal.
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
    ("symbol-iterator-spread",
     "(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};return [...o].join('');})()" % (_F1, _F2, _F3), True),
    ("symbol-iterator-forof",
     "(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};var s='';for(var x of o){s+=x;}return s;})()" % (_F1, _F2, _F3), True),
    ("symbol-iterator-arrayfrom",
     "(function(){var fr=['%s','%s%s'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};return Array.from(o).join('');})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("array-spread-still-blocks",
     "(function(){return [...['%s','%s%s']].join('');})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var fr=['jx','jy'];var o={i:0};o[Symbol.iterator]=function(){var self=this;return{next:function(){return self.i<2?{value:fr[self.i++],done:false}:{done:true};}};};return [...o].join('');})()", False),
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
