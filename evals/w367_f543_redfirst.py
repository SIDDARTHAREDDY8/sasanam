#!/usr/bin/env python3
"""Red-first for 543: Enumeration builtins on aliased arguments.

Three-way composition gap: F517 models Object.entries/Object.values on LITERAL
objects, F516 models the builtins on BARE arguments (then aliases the result),
F529 models Object.keys/for-in on ALIASES -- but entries/values applied to the
ALIAS escapes all three (alias first, builtin second -- the reverse data-flow
of F516's filed shapes). The model independently surfaced the values variant.
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
    ('entries-alias',
     "(function(){var a=arguments;return Object.entries(a).map(function(e){return e[1];}).join('');})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('values-alias',
     "(function(){var a=arguments;return Object.values(a).join('');})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f516-alias-closed',
     "(function(){var a=arguments;return a[0]+a[1];})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "(function(){var a=arguments;return Object.values(a).join('');})('ab','cd')"
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
