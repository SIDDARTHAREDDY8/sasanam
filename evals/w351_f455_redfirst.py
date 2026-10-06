#!/usr/bin/env python3
"""Red-first for F455: whitespace before the dot in `Array .of(...)` evades
the JS-expression anchor while the parser claims to tolerate it.

`_js_parse_array_of` (F446) is ws-tolerant: its docstring says "whitespace
is tolerated around the dot, the name, and the parens, exactly as the engine
allows" (`_js_skip_ws` after "Array", then dispatches on "."). But
`_JS_EXPR_START` anchors the factory as `Array(\\(|\\.of)` -- "Array"
immediately followed by ".of" -- so `Array .of('frag','frag')` (space, tab,
or newline before the dot; all valid JS, node-verified) never reaches the
parser and yields zero decode variants. Anchor/parser contradiction: the
parser's ws-tolerance is unreachable. Distinct from F454 (arg-shape gap):
this is the anchor regex, not the argument branch.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: contiguous Array.of blocks (F446 shape); junk ws-dot Array.of
quiet; plain credential blocks coded.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("array-ws-dot-space", "Array .of('%s','%s').join('')" % (A1, A2), True),
    ("array-ws-dot-tab", "Array\t.of('%s','%s').join('')" % (A1, A2), True),
    ("array-ws-dot-nl", "Array\n.of('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("array-of-contig", "Array.of('%s','%s').join('')" % (A1, A2), True),
    ("array-ws-dot-junk", "Array .of('ab','cd').join('')", False),
    ("plain-credential", A1 + A2, True),
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
