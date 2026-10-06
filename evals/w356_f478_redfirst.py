#!/usr/bin/env python3
"""Red-first for F478: .call/.apply/.bind dispatch on prototype methods.

The static JS-expression decoder models direct method calls
(''.concat(...), ['a'].concat(...), Reflect.apply(...)) but has no model of
indirect invocation through Function.prototype.call / .apply / .bind. Every
shape below node-evaluates (v24.20.0) to the exact credential while the
decoder produces zero variants.

Distinct from F469 (Reflect.apply -- the Reflect API, a different dispatch
path) and from F468 (Reflect.construct).

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("call-concat-array",
     "Array.prototype.concat.call([], '%s', '%s').join('')" % (A1, A2), True),
    ("call-concat-string",
     "String.prototype.concat.call('%s','%s')" % (A1, A2), True),
    ("call-concat-arrlit",
     "[].concat.call([], '%s', '%s').join('')" % (A1, A2), True),
    ("call-join",
     "Array.prototype.join.call(['%s','%s'], '')" % (A1, A2), True),
    ("call-slice",
     "Array.prototype.slice.call(['%s','%s'],0,2).join('')" % (A1, A2), True),
    ("apply-concat",
     "Array.prototype.concat.apply([], ['%s','%s']).join('')" % (A1, A2), True),
    ("call-reduce",
     "Array.prototype.reduce.call(['%s','%s'], (acc,curr)=>acc+curr, '')" % (A1, A2), True),
    ("call-filter",
     "Array.prototype.filter.call(['%s','%s',''], x=>x!=='').join('')" % (A1, A2), True),
    ("bind-concat",
     "String.prototype.concat.bind('%s')('%s')" % (A1, A2), True),
    ("call-map-string",
     "[].map.call(['%s','%s'], String).join('')" % (A1, A2), True),
    ("call-replace",
     "String.prototype.replace.call('%s,%s', /,/g, '')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "Array.prototype.concat.call([], 'ab', 'cd').join('')", False),
    ("neighbor-f469-closed",
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("neighbor-f473-closed",
     "['%s'].concat(['%s']).join('')" % (A1, A2), True),
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
