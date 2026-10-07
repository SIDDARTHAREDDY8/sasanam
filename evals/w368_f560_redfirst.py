#!/usr/bin/env python3
"""Red-first for 560: directive prologues defeat IIFE argument models.

The IIFE-argument parsers (F516/F524/F529/F533) expect the body to open with the binding declaration; a 'use strict' directive prologue is not in any grammar, so all four models miss: alias, destructure, and keys-enumeration prologue forms node-evaluate to the exact credential (v24.20.0) with zero decoder variants. Parser-level gap, not binding-specific.
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
    ('alias',
     '(function(){\'use strict\';var a=arguments;return a[0]+a[1];})(\'%(A1)s\',\'%(A2)s\')'
     % {"A1": A1, "A2": A2}, True),
    ('destructure',
     '(function(){\'use strict\';const [a,b]=arguments;return a+b;})(\'%(A1)s\',\'%(A2)s\')'
     % {"A1": A1, "A2": A2}, True),
    ('keys',
     '(function(){\'use strict\';const a=arguments;return Object.keys(a).map(i=>a[i]).join(\'\');})(\'%(A1)s\',\'%(A2)s\')'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f516-closed',
     "(function(){var a=arguments;return a[0]+a[1];})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "(function(){'use strict';var a=arguments;return a[0]+a[1];})('zz','yy')"
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
