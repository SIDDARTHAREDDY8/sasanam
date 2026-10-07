#!/usr/bin/env python3
"""Red-first for F534: Reflect.apply with .bind-bound SLICE target.

F530 models Reflect.apply with .bind-bound JOIN targets. The bound
function can be any builtin: `[].slice.bind(['f1','f2'], 0, 2)` is a
bound SLICE target -- Reflect.apply invokes it, the result array joins
to the credential. F530's fail-closed list explicitly documents "bound
non-join builtins" as out of scope (F500/F505 precedent: different
builtins are separate findings). Both shapes node-evaluate (v24.20.0)
to the exact credential while the decoder produces zero variants.
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
    ("bound-slice-direct",
     "Reflect.apply([].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),
    ("bound-slice-call-indirect",
     "Reflect.apply.call(Reflect, [].slice.bind(['%(A1)s','%(A2)s'], 0, 2), null, []).join('')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f530-bound-join-open",  # F530 OPEN -- still misses
     "Reflect.apply([].join.bind(['%s','%s'], ''), null, [])" % (A1, A2), False),
    ("direct-slice-held",
     "['%s','%s'].slice(0,2).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply([].slice.bind(['ab','cd'], 0, 2), null, []).join('')", False),
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
