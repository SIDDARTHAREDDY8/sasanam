#!/usr/bin/env python3
"""Red-first for F656: generator .next().value fragment reads.

F619 (CLOSED) models sync-generator yield/spread/for-of/Array.from assembly but documents `.next().value` reads as a fail-closed residual. This finding claims that residual: `.next().value` composed additively assembles the credential node-exactly (v24.20.0) while the decoder misses.
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
    ("next-value-plus",
     "(function*(){yield '" + _A + "';yield 'junk';})().next().value+'" + _B + "'"),
    ("next-value-named",
     "(function(){var g=(function*(){yield '" + _A + "';})();return g.next().value+'" + _B + "';})()"),
]

CONTROLS = [
    ("f619-spread-still-blocks",
     "[...(function*(){yield '" + _A + "';yield '" + _B + "';})()].join('')", True),
    ("junk-quiet",
     "(function*(){yield 'jx';})().next().value+'jy'", False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
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
