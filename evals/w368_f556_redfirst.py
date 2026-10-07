#!/usr/bin/env python3
"""Red-first for 556: .bind-bound arrow function targets.

F521 models bound CONCAT (builtin) targets and F519 unbound arrow targets; a .bind-bound ARROW target is unmodeled: direct call and Reflect.apply dispatch node-evaluate to the exact credential (v24.20.0) with zero decoder variants. Distinct from F521 (builtin targets) and F519 (unbound arrows).
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
     '((a)=>a+\'%(A2)s\').bind(null,\'%(A1)s\')()'
     % {"A1": A1, "A2": A2}, True),
    ('apply',
     'Reflect.apply(((a)=>a+\'%(A2)s\').bind(null,\'%(A1)s\'),null,[])'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f519-closed',
     "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "((a)=>a+'yy').bind(null,'zz')()"
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
