#!/usr/bin/env python3
"""Red-first for F507: bracket-form member access on STRING LITERAL receivers.
F482 closed bracket-string member access on prototype methods
(Array.prototype['concat']), but the same bracket spelling on a string literal
receiver (''['concat']('f1','f2')) bypasses the dispatch anchors: the receiver
grammar models dot-form string dispatch and bracket-form prototype dispatch,
never bracket-form literal dispatch. The computed-key variant ('f1'['c'+'oncat'])
composes with the F492 folder -- the key folds, the receiver still misses. All
shapes node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Prints BREAK when a payload MISSES (open tree), HELD
when blocked.
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
    ("strlit-bracket",
     "''['concat']('%s','%s')" % (A1, A2), True),
    ("strlit-bracket-computed-key",
     "'%s'['c'+'oncat']('%s')" % (A1, A2), True),
]

CONTROLS = [
    ("strlit-dot-held",
     "'%s'.concat('%s')" % (A1, A2), True),
    ("junk-quiet",
     "''['concat']('ab','cd')", False),
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
