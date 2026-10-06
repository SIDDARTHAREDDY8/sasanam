#!/usr/bin/env python3
"""Red-first for F457: template-literal `${}` interpolation bypasses the
bounded static JS-expression decoder.

"Template literals" are a claimed F430/F434 surface, but the decoder fails
on ANY `${}` interpolation: `` `a${'b'}` `` and `` `${'a'}${'b'}` `` yield
zero decode variants while node evaluates them exactly (node-verified).
The interpolation payloads are string literals -- the simplest
interpolation class -- so this is a gap in the claimed template-literal
surface, not an exotic extension. Model-adjacent (gpt-4o-mini round-19 B4
interpolation proposals validated locally).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: plain template literal with a verbatim credential blocks
(raw-text rule); junk interpolation stays quiet; plain credential blocks.
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
    ("tmpl-interp-tail", "`%s${'%s'}`" % (A1, A2), True),
    ("tmpl-interp-both", "`${'%s'}${'%s'}`" % (A1, A2), True),
    ("tmpl-interp-mid", "`%s${'%s'}`" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("tmpl-verbatim", "`%s%s`" % (A1, A2), True),  # raw-text rule
    ("tmpl-interp-junk", "`a${'b'}`", False),
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
