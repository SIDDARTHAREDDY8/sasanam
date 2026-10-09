#!/usr/bin/env python3
"""Red-first for F883: structuredClone of accessor-valued sources.

The decoder models structuredClone of plain data objects (F807),
but node invokes getters and clones their values: `{get k(){
return 'f1';}}` clones to `{k:'f1'}` (v24.20.0 verified), while the
F807 hook fails closed on getter-valued sources, so the shape
resolves node-exactly while the decoder produces zero variants.
Close-when: the decoder models accessor-valued structuredClone
sources node-exactly (or refuses the laundering coded) such that
find_credential flags them, red-first verified, honest text
unaffected.
Filed 2026-10-09 05:33 UTC wave-386 (lane 7 spec-axis review
residual of the F807 closure; renumbered wave-272: lane-7
F829 -> F883).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("s1",
     "(function(){var o={get k(){return '%s';}};"
     "var c=structuredClone(o);return c.k+'%s';})()" % (_A, _B),
     True),
    ("s2-nested",
     "(function(){var o={a:{get b(){return '%s';}}};"
     "var c=structuredClone(o);return c.a.b+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    # F807 plain-data twin blocks on the open tree (coded).
    ("f807-twin",
     "(function(){var o={k:'%s'};"
     "var c=structuredClone(o);return c.k+'%s';})()" % (_A, _B),
     True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
