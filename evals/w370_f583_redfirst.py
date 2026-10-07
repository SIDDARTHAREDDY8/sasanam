#!/usr/bin/env python3
"""Red-first for 583: key-laundering via terminal key reads.

Object key names are attacker-controlled strings, but the decoder models no key-terminal reads: Object.keys({a:'f1',b:'f2'}).join(''), Object.entries({'f1':1,'f2':1}).map(e=>e[0]).join(''), and the destructuring-param variant all node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F510 (values, CLOSED), F543 (entries/values on aliased arguments), F573 (entries index reads of values on literals).
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
    ('keys-join',
     '"Object.keys({\'%(A1)s\':1,\'%(A2)s\':1}).join(\'\')"'
     % {"A1": A1, "A2": A2}, True),
    ('entries-mapkey',
     '"Object.entries({\'%(A1)s\':1,\'%(A2)s\':1}).map(e=>e[0]).join(\'\')"'
     % {"A1": A1, "A2": A2}, True),
    ('entries-destr',
     '"Object.entries({\'%(A1)s\':1,\'%(A2)s\':1}).map(([k])=>k).join(\'\')"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('keys-single-blocked',
     '"Object.keys({\'%(A1)s%(A2)s\':1})[0]"'
     % {"A1": A1, "A2": A2}, True),
    ('values-blocked',
     '"Object.values({c:\'%(A1)s\'})[0]+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"Object.keys({\'ab\':1}).join(\'\')"'
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
