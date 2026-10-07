#!/usr/bin/env python3
"""Red-first for 592: for-in enumeration over object literals.

F529 closed for-in alias enumeration of the ARGUMENTS exotic; for-in over a plain object literal with member reads is a different binding source: (function(){var s='';var o={a:'f1',b:'f2'};for(var k in o){s+=o[k];}return s;})() node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F529 (arguments source) and F535 (literal-key member reads).
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
    ('forin-lit',
     '"(function(){var s=\'\';var o={a:\'%(A1)s\',b:\'%(A2)s\'};for(var k in o){s+=o[k];}return s;})()"'
     % {"A1": A1, "A2": A2}, True),
    ('forin-nest',
     '"(function(){var s=\'\';var o={a:{v:\'%(A1)s\'},b:{v:\'%(A2)s\'}};for(var k in o){s+=o[k].v;}return s;})()"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('forin-args-blocked',
     '"(function(){var s=\'\';for(var k in arguments){s+=arguments[k];}return s;})(\'%(A1)s\',\'%(A2)s\')"'
     % {"A1": A1, "A2": A2}, True),
    ('forin-keyonly-blocked',
     '"(function(){var s=\'\';for(var k in {\'%(A1)s%(A2)s\':1}){s=k;}return s;})()"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'\';var o={a:\'ab\'};for(var k in o){s+=o[k];}return s;})()"'
     % {"A1": A1, "A2": A2}, False)
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
