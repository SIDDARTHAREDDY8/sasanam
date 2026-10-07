#!/usr/bin/env python3
"""Red-first for F568: entries/values idioms in Reflect.apply targets.

F546 (wave-368 lane 4) closed arguments-enumerating bodies in
function-valued Reflect.apply targets for the for-of (F533), for-in
(F529), and bare-alias idioms; F543 (wave-368 lane 4) closed
entries/values enumeration on aliased arguments in IIFE dispatch. The
composition -- entries/values-idiom bodies in a Reflect.apply target --
escapes both: the F546 body grammar rejects the entries/values idioms
chargeless, and F543's parser only fires in the IIFE dispatch form.
Node-verified exact (v24.20.0); the decoder produces zero variants.
Distinct from F558 (object-pattern targets -- this is the
enumeration-idiom class, the same F546xF543 gap lane 4 flagged as an
honest residual and the attack lane did not file).
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
    ('entries-idiom',
     "Reflect.apply(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');},null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('values-idiom',
     "Reflect.apply(function(){var a=arguments;return Object.values(a).join('');},null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('values-map-idiom',
     "Reflect.apply(function(){var a=arguments;return Object.values(a).map(x=>x).join('');},null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f546-closed',
     "Reflect.apply(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;},null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('f543-closed',
     "(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join('');})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply(function(){var a=arguments;return Object.values(a).join('');},null,['zz','yy'])"
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
