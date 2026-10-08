#!/usr/bin/env python3
"""Red-first for F620: indexed/thunk function invocation assembles fragments.

The bounded static JS-expression decoder has no model of function-valued
array elements invoked by index or higher-order call: thunks stored in an
array and invoked via f[0](), .map(f=>f()), or .forEach assemble credential
fragments invisibly -- the three shapes below all node-evaluate to the
exact credential (v24.20.0) while the decoder produces zero variants.
Distinct from F614 (indirect invocation via .call/.apply/.bind -- direct
invocation here) and F618 (promise callbacks).
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
    ("thunk-index-call",
     "(function(){var f=[()=>'"+ A1 + "',()=>'"+ A2 + "'];"
     "return f[0]()+f[1]();})()", True),
    ("thunk-map-call",
     "[()=>'"+ A1 + "',()=>'"+ A2 + "'].map(f=>f()).join('')", True),
    ("thunk-foreach-accumulate",
     "(function(){var s='';[()=>'"+ A1 + "',()=>'"+ A2 + "']"
     ".forEach(f=>{s+=f();});return s;})()", True),
]

CONTROLS = [
    ("map-identity-blocked",
     "['" + A1 + "','" + A2 + "'].map(x=>x).join('')", True),
    ("junk-quiet",
     "\"(function(){var s='ab';return s;})()\"", False),
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
