#!/usr/bin/env python3
"""Red-first for F501: fragment assembly through local VALUE bindings. F495
covers METHOD invocation through bindings (const {concat} = Array.prototype);
no filed finding covers plain fragment assembly: let/var/const bindings of
string fragments joined by additive concatenation. The decoder is
expression-scoped and resolves no statement-level bindings, so all shapes
node-evaluate (v24.20.0) to the exact credential while the decoder produces
zero variants.
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
    ("let-comma",
     "let a='%s', b='%s'; a,b; a+b" % (A1, A2), True),
    ("let-two",
     "let a='%s'; let b='%s'; a+b" % (A1, A2), True),
    ("var-two",
     "var a='%s'; var b='%s'; a+b" % (A1, A2), True),
    ("const-two",
     "const a='%s'; const b='%s'; a+b" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "let a='ab', b='cd'; a,b; a+b", False),
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
