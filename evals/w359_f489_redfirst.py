#!/usr/bin/env python3
"""Red-first for F489: array-like receiver edge spellings beyond F487. F487 filed plain object-literal array-like receivers ({length:2, 0:'f1', 1:'f2'}); the engine also accepts Proxy-wrapped array-likes (trap indirection -- unmodelable by an F487 closure), accessor-property length, and arguments exotic objects. All shapes node-evaluate (v24.20.0) to the exact credential while the decoder produces zero variants. Distinct from F487 (data-property object literals) and F478 (array/string receivers).
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
    ("proxy-join",
     "Array.prototype.join.call(new Proxy({length:2,0:'%s',1:'%s'}, {}), '')" % (A1, A2), True),
    ("proxy-slice",
     "Array.prototype.slice.call(new Proxy({length:2,0:'%s',1:'%s'},{}), 0).join('')" % (A1, A2), True),
    ("proxy-filter",
     "Array.prototype.filter.call(new Proxy({length:3,0:'%s',1:'%s',2:''},{}), x=>x!=='').join('')" % (A1, A2), True),
    ("proxy-join-markers",
     "Array.prototype.join.call(new Proxy({length:3,0:'%s',1:null,2:'%s'},{}), '')" % (A1, A2), True),
    ("accessor-length",
     "Array.prototype.join.call({0:'%s',1:'%s', get length() { return 2; }}, '')" % (A1, A2), True),
    ("arguments-iife",
     "Array.prototype.join.call((function(){return arguments})('%s','%s'), '')" % (A1, A2), True),
    ("arguments-slice",
     "Array.prototype.slice.call((function(){return arguments})('%s','%s'), 0).join('')" % (A1, A2), True),
]

# F489 wave-360: the get-trap proxy is a DOCUMENTED FAIL-CLOSED boundary.
# The engine evaluates arbitrary trap code; the static decoder cannot
# model it. Only the empty-handler Proxy is decoded. This shape MUST
# stay a miss (fail closed, never mis-decoded).
CONTROLS = [
    ("proxy-get-trap-fail-closed",
     "Array.prototype.join.call(new Proxy({length:2}, {get:(t,p)=>p==='length'?2:({0:'%s',1:'%s'})[p]}), '')" % (A1, A2), False),
    ("f487-plain-now-closed",
     "Array.prototype.join.call({length:2,0:'%s',1:'%s'}, '')" % (A1, A2), True),  # F487 CLOSED wave-359 merge
    ("array-receiver-held",
     "Array.prototype.join.call(['%s','%s'], '')" % (A1, A2), True),
    ("junk-quiet",
     "Array.prototype.join.call(new Proxy({length:2,0:'ab',1:'cd'}, {}), '')", False),
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
