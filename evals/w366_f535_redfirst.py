#!/usr/bin/env python3
"""Red-first for F535: member access on object literals.

The decoder does not resolve property reads on object literals -- not
for data properties, not for accessors. `({c:'f1'}).c` is a plain
value read the decoder never resolves; a getter (`({get g(){...}}).g`)
additionally requires executing code; a Proxy get-trap
(`(new Proxy(...)).c`) interposes on the read. All three shapes
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Distinct from F510/F517 (enumeration
builtins -- these are direct member reads) and F482 (method dispatch).
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
    ("member-data-literal",
     "({c:'%(A1)s'}).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ("member-getter-literal",
     "({get g(){return '%(A1)s';}}).g+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ("member-proxy-get-trap",
     "(new Proxy({c:'%(A1)s'},{get:(t,k)=>t[k]})).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("object-values-held",  # F510 CLOSED -- enumeration builtin blocks coded
     "Object.values({c:'%s'}).join('')+'%s'" % (A1, A2), True),
    ("junk-quiet",
     "({c:'ab'}).c+'cd'", False),
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
