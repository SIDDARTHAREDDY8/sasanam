#!/usr/bin/env python3
"""Red-first for F533: for-of enumeration of aliased arguments.

F529 models arguments-alias enumeration via Object.keys/for-in
(`Object.keys(a).map(i=>a[i])`, `for(var i in a){s+=a[i];}`). A for-of
loop iterates VALUES directly (`for(var x of a){s+=x;}`) -- a different
iteration construct (no key indexing) that neither F529's nor F517's
grammar covers. Both shapes node-evaluate (v24.20.0) to the exact
credential while the decoder produces zero variants. Prints BREAK when a
payload MISSES (open tree), HELD when blocked.
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
    ("forof-alias",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ("forof-let-alias",
     "(function(){let a=arguments;let s='';for(let x of a){s+=x;}return s;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f529-keys-open",  # F529 OPEN -- still misses
     "(function(){const a=arguments;return Object.keys(a).map(i=>a[i]).join('');})('%s','%s')" % (A1, A2), False),
    ("f516-alias-closed",  # F516 CLOSED -- now blocks coded
     "(function(){var a=arguments;return a[0]+a[1]})('%s','%s')" % (A1, A2), True),
    ("junk-quiet",
     "(function(){var a=arguments;var s='';for(var x of a){s+=x;}return s;})('ab','cd')", False),
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
