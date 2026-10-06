#!/usr/bin/env python3
"""Red-first for F484: constructor-factory with non-string-literal args.
The wave-357 F476 closure desugars [].constructor.of / Array['of'] for
STRING-LITERAL-ONLY args (documented residual: numeric/nested args fail
closed). Nested-array args bypass it: the engine coerces them in
.join('') while the decoder refuses. Spread args through the factory
miss too. All shapes node-evaluate (v24.20.0) to the exact credential.
Distinct from F476 (its string-literal shapes hold) and F479
(direct-form arrays, no factory).
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
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

SHAPES = [
    ("bracket-of-nested",
     "[].constructor['of']('%s',['%s']).join('')" % (A1, A2), True),
    ("dot-of-nested",
     "[].constructor.of('%s',['%s']).join('')" % (A1, A2), True),
    ("arr-of-two-nested",
     "Array['of'](['%s'],['%s']).join('')" % (A1, A2), True),
    ("bracket-of-two-nested",
     "[].constructor['of'](['%s'],['%s']).join('')" % (A1, A2), True),
    ("dot-of-nested-first",
     "[].constructor.of(['%s'],'%s').join('')" % (A1, A2), True),
    ("of-spread",
     "Array.of(...['%s','%s']).join('')" % (A1, A2), True),
    ("bracket-of-spread",
     "Array['of'](...['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "[].constructor.of('ab','cd').join('')", False),
    ("neighbor-f476-held",
     "[].constructor.of('%s','%s').join('')" % (A1, A2), True),
    ("neighbor-f476-bracket-held",
     "Array['of']('%s','%s').join('')" % (A1, A2), True),
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
