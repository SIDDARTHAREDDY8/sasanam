#!/usr/bin/env python3
"""Red-first for F569: call-indirect enum-body Reflect.apply targets.

F544 (wave-368 lane 3) closed Reflect.apply.call(Reflect, FN, thisArg,
argsArray) for F519-class (additive) targets; F546 (wave-368 lane 4)
closed arguments-enumerating bodies (for-of, for-in, bare-alias) in
DIRECT Reflect.apply targets. The composition -- an
arguments-enumerating body in the CALL-INDIRECT dispatch form --
escapes both: the F544 fallback's additive-body parse rejects enum
bodies chargeless, and the F546 enum-body target is only wired into
the direct _js_parse_reflect_apply_fn path. All shapes node-evaluate
to the exact credential (v24.20.0) while the decoder produces zero
variants. Distinct from F568 (entries/values idioms in direct
targets) and F546 (direct dispatch -- this is the .call dispatch
form, F511 precedent: .call dispatch is its own class).
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
    ('call-bare',
     "Reflect.apply.call(Reflect, function(){var a=arguments;return a[0]+a[1];}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('call-forof',
     "Reflect.apply.call(Reflect, function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('call-forin',
     "Reflect.apply.call(Reflect, function(){var a=arguments;var s='';for(var i in a){s+=a[i];}return s;}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('call-bare-spread',
     "Reflect.apply.call(Reflect, function(){var a=arguments;return a[0]+a[1];}, null, [...['%(A1)s','%(A2)s']])"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f544-closed',
     "Reflect.apply.call(Reflect, function(a,b){return a+b;}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('f546-direct-closed',
     "Reflect.apply(function(){var a=arguments;return a[0]+a[1];}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply.call(Reflect, function(){var a=arguments;return a[0]+a[1];}, null, ['zz','yy'])"
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
