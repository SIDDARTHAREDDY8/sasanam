#!/usr/bin/env python3
"""Red-first for 587: new Proxy member-read receivers.

F535 modeled the delegating get-trap proxy only in the parenthesized spelling, and F489 modeled the empty-handler proxy only as a DISPATCH receiver: new Proxy({c:'f1'},{get:(t,k)=>t[k]}).c+'f2' (unparen get-trap), (new Proxy({c:'f1'},{}).c)+'f2' and new Proxy({c:'f1'},{}).c+'f2' (empty handler, both spellings) all node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F535 (paren get-trap, CLOSED) and F489 (dispatch-receiver position, CLOSED).
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
    ('proxy-unparen-gettrap',
     '"new Proxy({c:\'%(A1)s\'},{get:(t,k)=>t[k]}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('proxy-paren-empty',
     '"(new Proxy({c:\'%(A1)s\'},{}).c)+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('proxy-unparen-empty',
     '"new Proxy({c:\'%(A1)s\'},{}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('proxy-paren-gettrap-blocked',
     '"(new Proxy({c:\'%(A1)s\'},{get:(t,k)=>t[k]})).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"new Proxy({c:\'ab\'},{}).c"'
     % {"A1": A1, "A2": A2}, False)
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
