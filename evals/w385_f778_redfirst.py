#!/usr/bin/env python3
"""Red-first for F778: ?? with computed right operand.

F647 (CLOSED) models ?? with literal right operands only; a
non-literal right operand misses while resolving node-exactly:
  (null??(()=> 'f1'))()          -- IIFE right operand, invoked
  (null??o.x)                    -- member-read right operand
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
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
    # filed shape 1: IIFE right operand, invoked after the pick
    ("s1",
     ("(function(){var f=null;return (f??(function(){return '" + _A
      + "';}))()+'" + _B + "';})()"),
     True),
    # filed shape 2: member-read right operand
    ("s2",
     ("(function(){var o={x:'" + _A + "'};var n=null;return (n??o.x)+'"
      + _B + "';})()"),
     True),
]

CONTROLS = [
    # plain-nullish twin blocks coded (F647 route)
    ("f647-twin",
     "(function(){return (undefined??'" + _A + "')+'" + _B + "';})()",
     True),
    ("junk-quiet", "the quick brown fox jumps over the lazy dog", False),
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
