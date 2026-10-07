#!/usr/bin/env python3
"""Red-first for 538: Reflect.apply with .bind-bound MAP target.

Same family as F537: the bound builtin can be [].map. F521/F530/F534 cover
concat/join/slice-bound targets; map (element transform) is a different builtin
with different value semantics (F500/F505 precedent).
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
    ('map-direct',
     "Reflect.apply([].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('map-call-indirect',
     "Reflect.apply.call(Reflect, [].map.bind(['%(A1)s','%(A2)s'], function(e){return e;}), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f521-literal-bind-closed',
     "Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply([].map.bind(['ab'], function(e){return e;}), null, []).join('')"
    , False),

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
