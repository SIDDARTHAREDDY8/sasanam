#!/usr/bin/env python3
"""Red-first for F476: constructor-property Array.of factory path.

The decoder models the Array.of('f1','f2') identifier anchor (F446), but
not the property-lookup factory path:

- [].constructor.of('xoxb-0123','456789abcdef').join('')
- Array['of']('xoxb-0123','456789abcdef').join('')

Both node-evaluate to the credential (node v24.20.0) while the decoder
produces zero variants. F446's entry explicitly documents
`[].constructor.of(...)` / `Array['of'](...)` as "out of F446 scope,
documented not filed" -- a distinct scan shape from the Array.of
identifier anchor. This files that residual as its own finding.

[].constructor.from is BLOCKED (not filed); the round-23 mis-decode note
was fragment-dependent.

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
    ("constructor-dot-of",
     "[].constructor.of('%s','%s').join('')" % (A1, A2), True),
    ("array-bracket-of",
     "Array['of']('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "[].constructor.of('ab','cd').join('')", False),
    ("neighbor-f446-closed", "Array.of('%s','%s').join('')" % (A1, A2), True),
    ("neighbor-from-blocked",
     "[].constructor.from(['%s','%s']).join('')" % (A1, A2), True),
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
