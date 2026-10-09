"""Red-first battery for F773: fill without range args.

On the OPEN tree (before the F773 closure), both filed shapes BREAK
(miss the credential). On the CLOSED tree, both must HIT.

Node v24.20.0 verified.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov.dlp import find_credential

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("f773-filed-1",
     "(function(){return [new Array(1).fill('" + _A + "')[0],'" + _B + "'].join('');})()"),
    ("f773-filed-2",
     "(function(){var a=['xx'];a.fill('" + _A + "');return a[0]+'" + _B + "';})()"),
]


def main():
    breaks = []
    for name, shape in SHAPES:
        hit = find_credential(shape) is not None
        print(("HIT " if hit else "BREAK ") + name)
        if not hit:
            breaks.append(name)
    print("red-first: %d/%d BREAK on this tree" % (len(breaks), len(SHAPES)))
    return 0 if breaks else 1


if __name__ == "__main__":
    sys.exit(main())
