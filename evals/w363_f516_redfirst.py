#!/usr/bin/env python3
"""Red-first for F516: the arguments object laundered before dispatch.

F509 models the BARE arguments object as a dispatch receiver (with
call-site arg binding as the close direction), but the arguments object
can be laundered first: bound to a local alias, captured by a rest
parameter, converted with Array.from, or enumerated with Object.values.
All four shapes node-evaluate (v24.20.0) to the exact credential while
the decoder produces zero variants. Prints BREAK when a payload MISSES
(open tree), HELD when blocked.
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
    ("args-alias",
     "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (A1, A2), True),
    ("args-rest",
     "(function(...args){return args.join('');})('%s','%s')" % (A1, A2), True),
    ("args-array-from",
     "(function(){var a=Array.from(arguments);return a[0]+a[1];})('%s','%s')" % (A1, A2), True),
    ("args-object-values",
     "(function(){var a=Object.values(arguments);return a[0]+a[1];})('%s','%s')" % (A1, A2), True),
]

CONTROLS = [
    ("f509-bare-args-open",
     "(function(){return Array.prototype.join.call(arguments, '')})('%s','%s')" % (A1, A2), False),
    ("junk-quiet",
     "(function(){var a=arguments;return a[0]+a[1]})('ab','cd')", False),
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
