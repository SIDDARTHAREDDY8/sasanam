#!/usr/bin/env python3
"""Red-first for F496: Reflect.ownKeys key-enumeration indirection at dispatch
targets. F491 covers Reflect.get / property-descriptor reads of a NAMED
property; enumerating all keys with Reflect.ownKeys and selecting by predicate
is a different mechanism -- the decoder anchors neither the enumeration nor
the computed-index member access. All shapes node-evaluate (v24.20.0) to the
exact credential while the decoder produces zero variants.
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
    ("ownkeys-filter-concat",
     "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], '%s','%s').join('')" % (A1, A2), True),
    ("ownkeys-find-concat",
     "Array.prototype[Reflect.ownKeys(Array.prototype).find(k=>k==='concat')].call([], '%s','%s').join('')" % (A1, A2), True),
    ("ownkeys-ctor-of",
     "[].constructor[Reflect.ownKeys([].constructor).filter(k=>k==='of')[0]]('%s','%s').join('')" % (A1, A2), True),
    ("ownkeys-filter-join",
     "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='join')[0]].call(['%s','%s'], '')" % (A1, A2), True),
]

CONTROLS = [
    ("direct-dispatch-held",
     "Array.prototype.concat.call([], '%s','%s').join('')" % (A1, A2), True),  # F478 closed
    ("junk-quiet",
     "Array.prototype[Reflect.ownKeys(Array.prototype).filter(k=>k==='concat')[0]].call([], 'ab','cd').join('')", False),
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
