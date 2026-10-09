"""Red-first battery for F772: ES2023 toSorted/toSpliced copy methods.

On the OPEN tree (before the F772 closure), both filed shapes BREAK
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
    ("f772-filed-1",
     "(function(){return ['" + _A + "','" + _B + "'].toSorted().reverse().join('');})()"),
    ("f772-filed-2",
     "(function(){return ['xx','" + _A + "','" + _B + "'].toSpliced(0,1).join('');})()"),
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
