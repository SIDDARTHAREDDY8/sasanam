#!/usr/bin/env python3
"""Red-first for F859: JSON reviver.

the decoder models plain JSON.parse but not revivers: `JSON.parse('{"k":"f1"}',(k,v)=>v)` resolves node-exactly while the decoder produces zero variants. Close-when: the decoder models JSON revivers node-exactly (or refuses the laundering coded).
Filed 2026-10-09 05:27 UTC wave-386 (attack round 54).
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
     "(function(){return JSON.parse('{\"k\":\"%s\"}',function(k,v){return v;}).k+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){return JSON.parse(JSON.stringify({k:'%s'}),function(k,v){return k===''?v:v;}).k+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
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
