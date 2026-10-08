#!/usr/bin/env python3
"""Red-first for F744: class extends builtin construction.

the decoder models new Map()/new Set() literal construction but not subclassed builtins: class M extends Map with literal entries or set() tails spreads node-exactly while the decoder produces zero variants.
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
    ("s1", "(function(){class M extends Map{}var m=new M();m.set('k','§A');return [...m.values()].join('')+'§B';})()".replace("\u00a7A", _A).replace("\u00a7B", _B), True),
    ("s2", "(function(){class M extends Map{}var m=new M([['k','§A']]);var s='';for(var v of m.values())s+=v;return s+'§B';})()".replace("\u00a7A", _A).replace("\u00a7B", _B), True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
