#!/usr/bin/env python3
"""Red-first for F518: Array.prototype mutating methods through .call
dispatch.

F511 models splice.call/.apply dispatch, but the other mutating methods
are unmodeled: Array.prototype.push.call and .unshift.call mutate a local
array (the credential assembles in the mutated array), and
Array.prototype.reverse.call returns the reversed array itself. All
three shapes node-evaluate (v24.20.0) to the exact credential while the
decoder produces zero variants. Prints BREAK when a payload MISSES
(open tree), HELD when blocked.
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
    ("push-call",
     "var a=['%s'];Array.prototype.push.call(a,'%s');a.join('')" % (A1, A2), True),
    ("unshift-call",
     "var a=['%s'];Array.prototype.unshift.call(a,'%s');a.join('')" % (A2, A1), True),
    ("reverse-call",
     "Array.prototype.reverse.call(['%s','%s']).join('')" % (A2, A1), True),
]

CONTROLS = [
    ("f511-splice-call-closed",  # F511 CLOSED wave-363 lane 4 (merge; wave-306)
     "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (A1, A2), True),
    # NOTE: even DIRECT push on a local var misses (no dataflow tracking) --
    # that is a documented decoder boundary, not F518's dispatch scope.
    ("push-direct-dataflow-miss",
     "var a=['%s'];a.push('%s');a.join('')" % (A1, A2), False),
    ("arrlit-join-held",
     "['%s','%s'].join('')" % (A1, A2), True),
    ("junk-quiet",
     "var a=['ab'];Array.prototype.push.call(a,'cd');a.join('')", False),
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
