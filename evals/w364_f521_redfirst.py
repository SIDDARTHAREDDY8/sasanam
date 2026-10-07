#!/usr/bin/env python3
"""Red-first for F521: Reflect.apply with .bind-bound function targets.

F506 models Reflect.apply reached through Function.prototype.call/.apply
higher-order dispatch with concat-family targets; F513 models .bind
indirection with plain concat targets; F519 models arrow/fn-expr targets.
A target that is itself .bind-bound ([].concat.bind([], 'f1')) is a new
target class: the direct, call-indirect, and bind-indirect dispatches all
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
    ("bound-target-direct",
     "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (A1, A2), True),
    ("bound-target-call-indirect",
     "Reflect.apply.call(Reflect, [].concat.bind([], '%s'), [], ['%s']).join('')" % (A1, A2), True),
    ("bound-target-bind-indirect",
     "Reflect.apply.bind(Reflect)([].concat.bind([], '%s'), [], ['%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f469-concat-target-held",  # F469 CLOSED (exact filed control form)
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply([].concat.bind([], 'ab'), null, ['cd']).join('')", False),
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
