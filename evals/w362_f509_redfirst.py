#!/usr/bin/env python3
"""Red-first for F509: the BARE arguments exotic object as a dispatch receiver.
F489 closed arguments-IIFE receivers ((function(){return arguments})('f1','f2')
-> _JSArr), but the bare `arguments` identifier inside a function invoked with
literal args bypasses the IIFE-pattern anchor: the decoder has no call-site
argument binding, so Array.prototype.join.call(arguments, ''),
Array.prototype.slice.call(arguments, 0), arguments[i] indexing,
[...arguments] spread, and Array.prototype.reduce.call(arguments, ...) all
node-evaluate (v24.20.0) to the exact credential while the decoder produces
zero variants. Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
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
    ("bare-args-join",
     "(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (A1, A2), True),
    ("bare-args-slice",
     "(function(){return Array.prototype.slice.call(arguments, 0).join('')})('%s','%s')" % (A1, A2), True),
    ("bare-args-index",
     "(function(){return arguments[0]+arguments[1]})('%s','%s')" % (A1, A2), True),
    ("bare-args-spread",
     "(function(){return [].concat(...arguments).join('')})('%s','%s')" % (A1, A2), True),
    ("bare-args-reduce",
     "(function(){return Array.prototype.reduce.call(arguments,(a,b)=>a+b)})('%s','%s')" % (A1, A2), True),
]

CONTROLS = [
    ("iife-args-held",
     "Array.prototype.join.call((function(){return arguments})('%s','%s'), '')" % (A1, A2), True),
    ("junk-quiet",
     "(function(){return Array.prototype.join.call(arguments, '')})('ab','cd')", False),
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
