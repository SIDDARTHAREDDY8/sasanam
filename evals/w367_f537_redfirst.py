#!/usr/bin/env python3
"""Red-first for 537: Reflect.apply with .bind-bound FILTER target.

F521 models .bind-bound CONCAT targets, F530 JOIN, F534 SLICE -- but the bound
function can be any builtin (F500/F505 precedent: different builtins are separate
findings). [].filter.bind(['f1','f2','zz'], e=>e.length>2) node-evaluates to the
filtered array while the decoder produces zero variants. F482 covers filter under
.call dispatch with bracket access -- not .bind-bound Reflect.apply targets.
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
    ('filter-direct',
     "Reflect.apply([].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('filter-call-indirect',
     "Reflect.apply.call(Reflect, [].filter.bind(['%(A1)s','%(A2)s','zz'], function(e){return e.length>2;}), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f521-literal-bind-closed',
     "Reflect.apply([].concat.bind([], '%(A1)s'), null, ['%(A2)s']).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply([].filter.bind(['ab'], function(e){return true;}), null, []).join('')"
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
