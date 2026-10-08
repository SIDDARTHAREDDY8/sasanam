#!/usr/bin/env python3
"""Red-first for F677: iterator protocols beyond F653/F656/F659/F669.

Iterator protocol shapes beyond F653 (custom Symbol.iterator), F656 (.next().value), F659 (yield* over arrays), and F669 (builtin spread): manual iterator objects, custom Symbol.asyncIterator, generator return delegation, multi-.next() sequencing, yield* over generators, and for-await over promise arrays.
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
    ("manual-obj",
     "(function(){var o={i:0,next:function(){this.i++;return this.i<=2?{value:this.i===1?'xoxb-0123':'456789abcdef',done:false}:{done:true};}};var s='';var r=o.next();s+=r.value;r=o.next();s+=r.value;return s;})()", True),
    ("async-custom",
     "(async function(){var o={vals:['xoxb-0123','456789abcdef'],[Symbol.asyncIterator]:async function*(){yield this.vals[0];yield this.vals[1];}};var s='';for await(var x of o){s+=x;}return s;})()", True),
    ("gen-return",
     "(function(){function* g(){yield 'xoxb-0123';return '456789abcdef';}var it=g();var a=it.next();var b=it.next();return a.value+b.value;})()", True),
    ("next-seq",
     "(function(){var g=(function*(){yield 'xoxb-0123';yield '456789abcdef';})();var a=g.next();var b=g.next();return a.value+b.value;})()", True),
    ("yieldstar-gen",
     "(function(){function* h(){yield 'xoxb-0123';}function* g(){yield* h();yield '456789abcdef';}return [...g()].join('');})()", True),
    ("forawait-promises",
     "(async function(){var s='';for await(var x of [Promise.resolve('xoxb-0123'),Promise.resolve('456789abcdef')]){s+=x;}return s;})()", True),
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
