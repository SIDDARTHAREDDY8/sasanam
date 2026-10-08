#!/usr/bin/env python3
"""Red-first for F619: generator yield/spread assembly.

The bounded static JS-expression decoder has no model of generators:
fragments yielded from a generator function and reassembled via spread,
for-of, or Array.from are invisible -- the three shapes below all
node-evaluate to the exact credential (v24.20.0) while the decoder produces
zero variants. No existing finding covers generators; distinct from F618
(promise callbacks -- sync vs async mechanism).
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
    ("generator-spread-join",
     "(function(){function* g(){yield '" + A1 + "';yield '" + A2 + "';}"
     "return [...g()].join('');})()", True),
    ("generator-forof-accumulate",
     "(function(){function* g(){yield '" + A1 + "';yield '" + A2 + "';}"
     "var s='';for(var x of g())s+=x;return s;})()", True),
    ("generator-arrayfrom-join",
     "(function(){function* g(){yield '" + A1 + "';yield '" + A2 + "';}"
     "return Array.from(g()).join('');})()", True),
]

CONTROLS = [
    ("array-spread-join-blocked",
     "[...['" + A1 + "','" + A2 + "']].join('')", True),
    ("junk-quiet",
     "\"(function(){var s='ab';return s;})()\"", False),
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
