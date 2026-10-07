#!/usr/bin/env python3
"""Red-first for F515: array-index-folded member key on a string-literal
receiver.

F507 models bracket-form member access on string literals with a
string-concatenation folded key ('c'+'oncat'); F504 models nested-bracket
folded keys ([['apply'][0]]) on the Reflect namespace only. The
array-index fold on a STRING receiver -- ''[['concat'][0]] -- is neither:
it node-evaluates (v24.20.0) to the exact credential while the decoder
produces zero variants. Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
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
    ("strlit-idx-fold",
     "''[['concat'][0]]('%s','%s')" % (A1, A2), True),
    ("strlit-idx-fold-receiver",
     "'%s'[['concat'][0]]('%s')" % (A1, A2), True),
]

CONTROLS = [
    ("f507-strconcat-fold-closed",  # F507 CLOSED wave-363 lane 2 (merge; wave-306)
     "'%s'['c'+'oncat']('%s')" % (A1, A2), True),
    ("f504-reflect-idx-fold-closed",
     "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
    ("junk-quiet",
     "''[['concat'][0]]('ab','cd')", False),
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
