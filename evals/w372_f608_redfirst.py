#!/usr/bin/env python3
"""Red-first for F608: String.prototype.replace with function replacements.

F603 (OPEN, wave-372 lane 5 closing it) models literal patterns and $-patterns in the replacement STRING, but a function-valued replacement computes the replacement at runtime and has no modeled path: the three shapes below all node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F603 (literal-pattern replace). Verified still missing on the F603-closed lane tree (wave-372 lane 5, commit eed06073).
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
    ('replace-fn-string-pattern',
     '"\'%(A1)sXX\'.replace(\'XX\',()=>\'%(A2)s\')"'
     % {"A1": A1, "A2": A2}, True),
    ('replace-fn-regex-pattern',
     '"\'%(A1)sXX\'.replace(/XX/,()=>\'%(A2)s\')"'
     % {"A1": A1, "A2": A2}, True),
    ('replace-fn-uses-args',
     '"\'%(A1)sXX\'.replace(\'XX\',(m,off)=>off===5?\'%(A2)s\':\'\')"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('replace-literal-empty-blocked',
     '"\'%(A1)sX%(A2)s\'.replace(\'X\',\'\')"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '""(function(){var s=\'ab\';return s;})()""'
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
