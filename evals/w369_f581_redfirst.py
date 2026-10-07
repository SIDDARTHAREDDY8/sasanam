#!/usr/bin/env python3
"""Red-first for 581: Reflect.apply-dispatch of entries/values on aliased arguments.

F543 (CLOSED) models Object.entries(a)/Object.values(a) on aliased arguments in DIRECT form, but dispatching the builtin through Reflect.apply escapes its grammar: Reflect.apply(Object.entries,null,[alias]) node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. F481-class composition gap of the F543 closure; F511 precedent (.apply dispatch is its own class). Distinct from F568 (entries-idiom BODIES in apply targets, OPEN).
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
    ('entries-apply',
     "Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%(A1)s','%(A2)s')])[0][1]+Reflect.apply(Object.entries,null,[(function(){var a=arguments;return a;})('%(A1)s','%(A2)s')])[1][1]"
     % {"A1": A1, "A2": A2}, True),
    ('values-apply',
     "Reflect.apply(Object.values,null,[(function(){var a=arguments;return a;})('%(A1)s','%(A2)s')]).join('')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f543-closed',
     "(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply(Object.entries,null,[['zz']])[0][1]+'yy'"
     % {"A1": A1, "A2": A2}, False),
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
