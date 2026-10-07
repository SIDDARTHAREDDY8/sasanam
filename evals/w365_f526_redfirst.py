#!/usr/bin/env python3
"""Red-first for F526: Reflect.apply with two-hop .bind-chained function targets.

F521 models Reflect.apply with a single-.bind-bound target
([].concat.bind([], 'f1')). A target produced by a CHAIN of two .bind
calls is a different target-production mechanism: the bound thisArg and
the pre-bound args accumulate across hops, and the F521 single-bind
model does not compose. All three shapes node-evaluate (v24.20.0) to
the exact credential while the decoder produces zero variants.
Distinct from F521 (single bind) and F513 (bind on the dispatch, not
the target). Prints BREAK when a payload MISSES (open tree), HELD when
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
    ("twohop-bind-direct",
     "Reflect.apply([].concat.bind([],'%(A1)s').bind([]), null, ['%(A2)s']).join('')"
     % {"A1": A1, "A2": A2}, True),
    ("twohop-bind-split-args",
     "Reflect.apply([].concat.bind([],'%(A1)s').bind([],'%(A2)s'), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),
    ("twohop-bind-call-indirect",
     "Reflect.apply.call(Reflect, [].concat.bind([],'%(A1)s').bind([]), [], ['%(A2)s']).join('')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f521-single-bind-closed",  # F521 CLOSED (wave-365 lane 1) -- now blocks coded
     "Reflect.apply([].concat.bind([], '%s'), null, ['%s']).join('')" % (A1, A2), True),
    ("f469-concat-target-held",  # F469 CLOSED
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply([].concat.bind([],'ab').bind([]), null, ['cd']).join('')", False),
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
