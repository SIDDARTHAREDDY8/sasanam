#!/usr/bin/env python3
"""Red-first for F513: Reflect.apply reached through .bind indirection.

F506 models Reflect.apply invoked through Function.prototype.call/.apply
higher-order dispatch, but .bind does not invoke -- it returns a bound
callable that is then invoked directly. Reflect.apply.bind(Reflect)(...)
and Function.prototype.bind.call(Reflect.apply, Reflect)(...) both
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
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
    ("bind-reflect",
     "Reflect.apply.bind(Reflect)([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
    ("fn-bind-call",
     "Function.prototype.bind.call(Reflect.apply, Reflect)([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f506-call-indirect-closed",  # F506 CLOSED wave-363 lane 1 (merge; wave-306)
     "Function.prototype.apply.call(Reflect.apply, Reflect, [[].concat, [], ['%s','%s']]).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply.bind(Reflect)([].concat, [], ['ab','cd']).join('')", False),
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
