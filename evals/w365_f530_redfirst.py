#!/usr/bin/env python3
"""Red-first for F530: Reflect.apply with .bind-bound JOIN targets.

F521 models Reflect.apply with .bind-bound CONCAT targets, but the
bound function can be any builtin -- `[].join.bind(['f1','f2'], '')`
is a bound join whose invocation returns the joined credential
directly (a string, not an array). The F521 parser fails closed on
non-concat receivers by design (documented scope), so all three
dispatch variants node-evaluate (v24.20.0) to the exact credential
while the decoder produces zero variants. Distinct from F521
(concat-family bound targets -- different builtin, different value
shape: join returns a string). Prints BREAK when a payload MISSES
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
    ("join-bound-direct",
     "Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (A1, A2), True),
    ("join-bound-call-indirect",
     "Reflect.apply.call(Reflect, [].join.bind(['%s','%s'], ''), null, [])" % (A1, A2), True),
    ("join-bound-bind-indirect",
     "Reflect.apply.bind(Reflect)([].join.bind(['%s','%s'], ''), null, [])" % (A1, A2), True),
]

CONTROLS = [
    ("f521-concat-bound-held",  # F521 CLOSED (wave-365 lane 1)
     "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply([].join.bind(['ab','cd'], ''), null, [])", False),
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
