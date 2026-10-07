#!/usr/bin/env python3
"""Red-first for 554: Reflect.apply with .bind-bound FLATMAP target.

flatMap transforms AND flattens (1:N), distinct from map's 1:1 (F538) and filter's selection (F537): direct and call-indirect forms node-evaluate to the exact credential (v24.20.0) with zero decoder variants. F500/F505 precedent.
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
    ('direct',
     'Reflect.apply([].flatMap.bind([[\'%(A1)s\'],[\'%(A2)s\']],function(e){return e;}),null,[]).join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('call-indirect',
     'Reflect.apply.call(Reflect,[].flatMap.bind([[\'%(A1)s\'],[\'%(A2)s\']],function(e){return e;}),null,[]).join(\'\')'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f521-closed',
     "Reflect.apply([].concat.bind([],'%(A1)s'),null,['%(A2)s']).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply([].flatMap.bind([['zz'],['yy']],function(e){return e;}),null,[]).join('')"
     % {"A1": A1, "A2": A2}, False),
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
