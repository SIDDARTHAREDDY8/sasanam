#!/usr/bin/env python3
"""Red-first for 539: Property read on identity-preserving builtin results.

F535 (OPEN) covers member access on OBJECT LITERALS, but the object can come from
an identity-preserving builtin call: Object.assign (returns its target),
Object.freeze (returns its argument), new WeakRef(o).deref() (returns the
referent). The decoder resolves no property reads on non-literal sources.
Distinct from F510/F517 (enumeration builtins).
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
    ('assign-member',
     "Object.assign({}, {c:'%(A1)s'}).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ('freeze-member',
     "Object.freeze({c:'%(A1)s'}).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ('weakref-deref-member',
     "new WeakRef({c:'%(A1)s'}).deref().c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f510-values-closed',
     "Object.values({0:'%(A1)s',1:'%(A2)s'}).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Object.assign({}, {c:'ab'}).c+'cd'"
    , False),

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
