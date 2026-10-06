#!/usr/bin/env python3
"""Red-first for F481: .call dispatch drops F479 marker elements in arguments.

The F478 closure desugars `.call`/`.apply` on prototype methods to the
direct-call path ("same grammar, bounds, fail-closed as the direct form").
But the dispatch-argument parser does not use the F479-aware array-element
parser (_js_parse_array_element): an array argument containing null /
undefined fails closed at dispatch-parse time, while the DIRECT form
decodes it (F479 markers) and refuses coded.

Node-verified (v24.20.0): each shape below evaluates to the exact
credential while find_credential produces zero variants.

  - [].concat.call([],['f1',null,'f2']).join('')
  - [].concat.call([],['f1',undefined,'f2']).join('')
  - Array.prototype.concat.call([],['f1',null,'f2']).join('')

Distinct from F478 (the 11 filed string-arg shapes all hold) and F479
(direct-form marker coercion holds): this is the dispatch-argument
parse gap at their composition seam.

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
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("call-null-elem",
     "[].concat.call([],['%s',null,'%s']).join('')" % (A1, A2), True),
    ("call-undefined-elem",
     "[].concat.call([],['%s',undefined,'%s']).join('')" % (A1, A2), True),
    ("proto-call-null-elem",
     "Array.prototype.concat.call([],['%s',null,'%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "[].concat.call([],['ab',null,'cd']).join('')", False),
    ("neighbor-f478-closed",
     "[].concat.call([],['%s','%s']).join('')" % (A1, A2), True),
    ("neighbor-f479-closed",
     "['%s',null,'%s'].join('')" % (A1, A2), True),
    ("direct-form-blocks",
     "[].concat(['%s',null,'%s']).join('')" % (A1, A2), True),
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
