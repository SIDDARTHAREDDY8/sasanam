#!/usr/bin/env python3
"""Red-first for F659: yield* spread assembly.

F619 (CLOSED) models sync-generator yield/spread assembly but documents `yield*` as a fail-closed residual. This finding claims that residual: a generator delegating via yield* over a literal array, spread and joined, assembles the credential node-exactly (v24.20.0) while the decoder misses.
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
    ("yieldstar-spread-join",
     "[...(function*(){yield* ['" + _A + "','" + _B + "'];})()].join('')"),
    ("yieldstar-named",
     "(function(){var g=function*(){yield* ['" + _A + "','" + _B + "'];};return [...g()].join('');})()"),
]

CONTROLS = [
    ("f619-spread-still-blocks",
     "[...(function*(){yield '" + _A + "';yield '" + _B + "';})()].join('')", True),
    ("junk-quiet",
     "[...(function*(){yield* ['jx'];})()].join('')", False),
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
