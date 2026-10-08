#!/usr/bin/env python3
"""Red-first for F698: defineProperty-installed accessor + descriptor .get().

The F664 closure (wave-379 lane 2) models descriptor .get() invocation only
for literal-getter sources (var o={get x(){...}}); Object.defineProperty-installed
accessors are a distinct source production with no modeled path (node v24.20.0).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("dp-get-fn",
     "(function(){var o={};Object.defineProperty(o,'x',{get:function(){return '%s';}});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B), True),
    ("dp-get-arrow",
     "(function(){var o={};Object.defineProperty(o,'x',{get:()=>'%s'});return Object.getOwnPropertyDescriptor(o,'x').get()+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("literal-getter-still-blocks",
     "(function(){var o={get x(){return 'xoxb-0123';}};return Object.getOwnPropertyDescriptor(o,'x').get()+'456789abcdef';})()", True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
